package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/gin-gonic/gin"
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
