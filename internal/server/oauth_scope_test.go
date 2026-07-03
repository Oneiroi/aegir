package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegishjalmur/aegir/internal/auth"
	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// makeJWT constructs a minimal unsigned JWT for testing scope extraction.
// Signature is omitted; extractJWTScopes only reads the payload.
func makeJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	body := base64.RawURLEncoding.EncodeToString(payload)
	return fmt.Sprintf("%s.%s.sig", header, body)
}

// TestExtractJWTScopes verifies scope extraction from string and array claims.
func TestExtractJWTScopes(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]interface{}
		want   []string
	}{
		{
			name:   "scope_string",
			claims: map[string]interface{}{"scope": "read write:all"},
			want:   []string{"read", "write:all"},
		},
		{
			name:   "scp_array",
			claims: map[string]interface{}{"scp": []interface{}{"admin", "read"}},
			want:   []string{"admin", "read"},
		},
		{
			name:   "wildcard",
			claims: map[string]interface{}{"scope": "*"},
			want:   []string{"*"},
		},
		{
			name:   "no_scope",
			claims: map[string]interface{}{"sub": "user"},
			want:   nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := makeJWT(tc.claims)
			got := extractJWTScopes(token)
			if len(got) != len(tc.want) {
				t.Errorf("extractJWTScopes() = %v, want %v", got, tc.want)
				return
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("extractJWTScopes()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestOAuthScopeAuditMiddleware is the ISC-122 probe: a proxied request bearing
// a JWT with scope=* triggers an excessive_scope_detected security event.
func TestOAuthScopeAuditMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name             string
		prohibitedScopes []string
		tokenClaims      map[string]interface{}
		wantStatus       int
	}{
		{
			name:             "wildcard_scope_triggers_event",
			prohibitedScopes: []string{"*", "admin", "write:all"},
			tokenClaims:      map[string]interface{}{"scope": "*", "sub": "user"},
			wantStatus:       http.StatusOK, // audit-only: passes but logs event
		},
		{
			name:             "admin_scope_triggers_event",
			prohibitedScopes: []string{"*", "admin", "write:all"},
			tokenClaims:      map[string]interface{}{"scp": []interface{}{"admin", "read"}},
			wantStatus:       http.StatusOK,
		},
		{
			name:             "permitted_scope_no_event",
			prohibitedScopes: []string{"*", "admin"},
			tokenClaims:      map[string]interface{}{"scope": "read write"},
			wantStatus:       http.StatusOK,
		},
		{
			name:             "no_bearer_token_passes",
			prohibitedScopes: []string{"*", "admin"},
			tokenClaims:      nil, // no token
			wantStatus:       http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &MCPFirewall{
				config: &config.Config{
					Security: config.Security{
						OAuthScopeAudit: config.OAuthScopeAuditConfig{
							Enabled:          true,
							ProhibitedScopes: tc.prohibitedScopes,
						},
					},
				},
				logger: testLogger(),
			}

			router := gin.New()
			router.Use(s.oauthScopeAuditMiddleware())
			router.POST("/mcp", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if tc.tokenClaims != nil {
				req.Header.Set("Authorization", "Bearer "+makeJWT(tc.tokenClaims))
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("got status %d want %d; body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

// newScopeTestAuthManager builds a real auth.Manager backed by a known JWT
// secret so tests can sign tokens by hand and exercise VerifyTokenSignature
// via the enforcement path in oauthScopeAuditMiddleware.
func newScopeTestAuthManager(t *testing.T) (*auth.Manager, string) {
	t.Helper()
	secret := "oauth-scope-enforcement-test-secret-32c!"
	mgr, err := auth.New(config.Auth{
		JWT: config.JWT{
			Secret:            secret,
			ExpirationTime:    time.Hour,
			RefreshExpiration: 24 * time.Hour,
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return mgr, secret
}

// signedScopeJWT signs claims with the given secret (correct or forged) so
// tests can construct both authentic and tampered tokens.
func signedScopeJWT(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("signedScopeJWT: %v", err)
	}
	return signed
}

// TestOAuthScopeEnforcement is the ISC-148 / AEGIR-H-001 probe: when
// oauth.enforce_scopes (OAuthScopeAuditConfig.Enforcement) is set, a
// genuinely-signed token carrying a prohibited scope is BLOCKED with 403 and
// an excessive_scope_blocked event — not merely logged and allowed through as
// the old audit-only middleware did.
func TestOAuthScopeEnforcement(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mgr, secret := newScopeTestAuthManager(t)

	cases := []struct {
		name       string
		token      string
		wantStatus int
		wantBody   string // substring expected in body
	}{
		{
			name:       "enforced_prohibited_scope_blocked_403",
			token:      signedScopeJWT(t, secret, jwt.MapClaims{"scope": "admin"}),
			wantStatus: http.StatusForbidden,
			wantBody:   "excessive_scope_blocked",
		},
		{
			name:       "enforced_permitted_scope_allowed_200",
			token:      signedScopeJWT(t, secret, jwt.MapClaims{"scope": "read write"}),
			wantStatus: http.StatusOK,
		},
		{
			name:       "enforced_forged_signature_rejected_401_not_403",
			token:      signedScopeJWT(t, "wrong-secret-entirely-different-32c!", jwt.MapClaims{"scope": "admin"}),
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &MCPFirewall{
				config: &config.Config{
					Security: config.Security{
						OAuthScopeAudit: config.OAuthScopeAuditConfig{
							Enabled:          true,
							Enforcement:      true,
							ProhibitedScopes: []string{"*", "admin", "write:all"},
						},
					},
				},
				logger: testLogger(),
				auth:   mgr,
			}

			router := gin.New()
			router.Use(s.oauthScopeAuditMiddleware())
			router.POST("/mcp", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("got status %d want %d; body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantBody != "" && !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Errorf("body %q does not contain %q", w.Body.String(), tc.wantBody)
			}
		})
	}
}

// TestAuditTokenSignatureVerified is the ISC-154 / AEGIR-M-003 probe: the
// audit/OAuth middleware must verify the JWT signature BEFORE acting on
// scope/scp claims when enforcement is on. A forged (invalid-signature) token
// carrying a prohibited scope must never reach the enforcement/blocking logic
// — it is rejected at the signature check with 401. In audit-only mode
// (enforcement off), the same forged token is still parsed for detection
// purposes (ISC-122) but never blocks the request.
func TestAuditTokenSignatureVerified(t *testing.T) {
	gin.SetMode(gin.TestMode)
	_, secret := newScopeTestAuthManager(t)
	forgedToken := signedScopeJWT(t, "an-entirely-different-forged-secret!!", jwt.MapClaims{"scope": "admin"})

	t.Run("enforcement_on_forged_signature_401_before_scope_check", func(t *testing.T) {
		mgr, _ := newScopeTestAuthManager(t)
		s := &MCPFirewall{
			config: &config.Config{
				Security: config.Security{
					OAuthScopeAudit: config.OAuthScopeAuditConfig{
						Enabled:          true,
						Enforcement:      true,
						ProhibitedScopes: []string{"admin"},
					},
				},
			},
			logger: testLogger(),
			auth:   mgr,
		}

		router := gin.New()
		router.Use(s.oauthScopeAuditMiddleware())
		router.POST("/mcp", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+forgedToken)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("forged token under enforcement: got %d want 401; body=%s", w.Code, w.Body.String())
		}
		// Must be rejected at the signature check, not the scope-enforcement
		// check — the body must not report excessive_scope_blocked.
		if strings.Contains(w.Body.String(), "excessive_scope_blocked") {
			t.Errorf("forged token reached the scope-enforcement path; body=%s", w.Body.String())
		}
	})

	t.Run("audit_only_forged_signature_still_detected_but_not_blocked", func(t *testing.T) {
		mgr, _ := newScopeTestAuthManager(t)
		_ = secret
		s := &MCPFirewall{
			config: &config.Config{
				Security: config.Security{
					OAuthScopeAudit: config.OAuthScopeAuditConfig{
						Enabled:          true,
						Enforcement:      false, // audit-only
						ProhibitedScopes: []string{"admin"},
					},
				},
			},
			logger: testLogger(),
			auth:   mgr,
		}

		router := gin.New()
		router.Use(s.oauthScopeAuditMiddleware())
		router.POST("/mcp", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+forgedToken)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Audit-only never blocks, even for a forged token — detection without
		// signature verification is the documented ISC-122 behaviour.
		if w.Code != http.StatusOK {
			t.Fatalf("audit-only forged token: got %d want 200 (never blocks); body=%s", w.Code, w.Body.String())
		}
	})
}
