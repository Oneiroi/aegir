package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// newTestManager creates an auth Manager wired with a minimal config suitable
// for unit tests. The JWT secret is fixed so we can craft tokens by hand.
func newTestManager(t *testing.T) *Manager {
	t.Helper()

	logger, err := logging.New(config.Logging{
		Level:           "error",
		Format:          "text",
		File:            "",
		HMACKey:         "test-hmac-key-that-is-at-least-32-chars!!",
		IntegrityChecks: false,
	})
	if err != nil {
		t.Fatalf("newTestManager: failed to create logger: %v", err)
	}

	cfg := config.Auth{
		JWT: config.JWT{
			Secret:            "test-secret-key-for-unit-tests-only!",
			Issuer:            "aegir-test",
			ExpirationTime:    time.Hour,
			RefreshExpiration: 24 * time.Hour,
		},
		OAuth: config.OAuth{
			Enabled:  false,
			AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
	}

	mgr, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("newTestManager: failed to create manager: %v", err)
	}
	return mgr
}

// ginTestContext creates a gin.Context backed by an httptest.ResponseRecorder.
func ginTestContext(w http.ResponseWriter) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
	return c
}

// craftExpiredJWT builds a JWT whose exp is 1 second in the past, signed with
// the same secret used by newTestManager.
func craftExpiredJWT(t *testing.T) string {
	t.Helper()
	secret := []byte("test-secret-key-for-unit-tests-only!")
	claims := Claims{
		UserID:   "test-user",
		Username: "testuser",
		Email:    "test@example.com",
		Roles:    []string{"user"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "aegir-test",
			Subject:   "test-user",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Second)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("craftExpiredJWT: %v", err)
	}
	return signed
}

// TestJWTExpiryEnforced verifies that AuthMiddleware returns 401 when the JWT
// exp claim is in the past (ISC-67).
func TestJWTExpiryEnforced(t *testing.T) {
	mgr := newTestManager(t)
	expiredToken := craftExpiredJWT(t)

	w := httptest.NewRecorder()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/probe", mgr.AuthMiddleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired JWT, got %d", w.Code)
	}
}

// TestOAuthLoginRedirects verifies that OAuthLogin returns a 302 redirect whose
// Location header points to the configured provider URL (ISC-68).
func TestOAuthLoginRedirects(t *testing.T) {
	mgr := newTestManager(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/auth/oauth/login", mgr.OAuthLogin)

	tests := []struct {
		provider    string
		urlContains string
	}{
		{"google", "accounts.google.com"},
		{"github", "github.com"},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/auth/oauth/login?provider="+tt.provider, nil)
			router.ServeHTTP(w, req)

			if w.Code != http.StatusFound {
				t.Errorf("provider %s: expected 302 redirect, got %d", tt.provider, w.Code)
			}

			loc := w.Header().Get("Location")
			if loc == "" {
				t.Errorf("provider %s: Location header is empty", tt.provider)
			}
			if !strings.Contains(loc, tt.urlContains) {
				t.Errorf("provider %s: Location %q does not contain %q", tt.provider, loc, tt.urlContains)
			}
		})
	}
}

// TestOAuthLoginRedirects_MissingProvider checks that a missing provider query
// parameter is rejected with 400 (supplementary coverage for ISC-68).
func TestOAuthLoginRedirects_MissingProvider(t *testing.T) {
	mgr := newTestManager(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/auth/oauth/login", mgr.OAuthLogin)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/login", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing provider, got %d", w.Code)
	}
}

// TestAPIKeyAuthentication verifies that a valid API key in the X-API-Key header
// is accepted by AuthMiddleware (ISC-69).
func TestAPIKeyAuthentication(t *testing.T) {
	mgr := newTestManager(t)

	// Extract the default admin API key that createDefaultUsers() inserted.
	var adminKey string
	for k := range mgr.apiKeys {
		adminKey = k
		break
	}
	if adminKey == "" {
		t.Fatal("no API key found in manager after initialisation")
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/probe", mgr.AuthMiddleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("X-API-Key", adminKey)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusUnauthorized {
		t.Errorf("valid API key should not return 401, got %d", w.Code)
	}
}
