package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
)

// newOAuthTestRouter wires both OAuth endpoints for the full login->callback
// round trip PKCE enforcement requires.
func newOAuthTestRouter(t *testing.T) (*Manager, *gin.Engine) {
	t.Helper()
	mgr := newTestManager(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/auth/oauth/login", mgr.OAuthLogin)
	router.GET("/auth/oauth/callback", mgr.OAuthCallback)
	return mgr, router
}

// startOAuthLogin drives OAuthLogin and extracts the "state" query parameter
// from the resulting redirect Location header.
func startOAuthLogin(t *testing.T, router *gin.Engine, query string) (state string, status int) {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/login?"+query, nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		return "", w.Code
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse redirect Location: %v", err)
	}
	return loc.Query().Get("state"), w.Code
}

// TestPKCEEnforced verifies ISC-178: OAuth 2.1 + PKCE (S256) is mandatory, not
// optional, on both the login (code_challenge) and callback (code_verifier)
// legs, and a correct verifier still completes the flow.
func TestPKCEEnforced(t *testing.T) {
	t.Run("login rejects missing code_challenge", func(t *testing.T) {
		_, router := newOAuthTestRouter(t)
		_, status := startOAuthLogin(t, router, "provider=google")
		if status != http.StatusBadRequest {
			t.Errorf("expected 400 for missing code_challenge, got %d", status)
		}
	})

	t.Run("login rejects plain code_challenge_method", func(t *testing.T) {
		_, router := newOAuthTestRouter(t)
		_, status := startOAuthLogin(t, router, "provider=google&code_challenge=abc&code_challenge_method=plain")
		if status != http.StatusBadRequest {
			t.Errorf("expected 400 for code_challenge_method=plain, got %d", status)
		}
	})

	t.Run("callback rejects missing code_verifier", func(t *testing.T) {
		_, router := newOAuthTestRouter(t)
		state, loginStatus := startOAuthLogin(t, router, "provider=google&code_challenge=some-challenge&code_challenge_method=S256")
		if loginStatus != http.StatusFound {
			t.Fatalf("login setup failed: status %d", loginStatus)
		}

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/callback?provider=google&state="+state+"&code=authcode123", nil)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing code_verifier, got %d", w.Code)
		}
	})

	t.Run("callback rejects mismatched code_verifier", func(t *testing.T) {
		_, router := newOAuthTestRouter(t)
		state, loginStatus := startOAuthLogin(t, router, "provider=google&code_challenge="+pkceCodeChallengeS256("correct-verifier")+"&code_challenge_method=S256")
		if loginStatus != http.StatusFound {
			t.Fatalf("login setup failed: status %d", loginStatus)
		}

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/callback?provider=google&state="+state+"&code=authcode123&code_verifier=wrong-verifier", nil)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for mismatched code_verifier, got %d", w.Code)
		}
	})

	t.Run("callback succeeds with correct code_verifier", func(t *testing.T) {
		_, router := newOAuthTestRouter(t)
		verifier := "correct-verifier-with-enough-entropy-1234567890"
		challenge := pkceCodeChallengeS256(verifier)

		state, loginStatus := startOAuthLogin(t, router, "provider=google&code_challenge="+challenge+"&code_challenge_method=S256")
		if loginStatus != http.StatusFound {
			t.Fatalf("login setup failed: status %d", loginStatus)
		}

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet,
			"/auth/oauth/callback?provider=google&state="+state+"&code=authcode123&code_verifier="+verifier, nil)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 for a correct code_verifier, got %d (body: %s)", w.Code, w.Body.String())
		}
	})

	t.Run("state is single-use even after a failed PKCE check", func(t *testing.T) {
		_, router := newOAuthTestRouter(t)
		state, loginStatus := startOAuthLogin(t, router, "provider=google&code_challenge="+pkceCodeChallengeS256("correct-verifier")+"&code_challenge_method=S256")
		if loginStatus != http.StatusFound {
			t.Fatalf("login setup failed: status %d", loginStatus)
		}

		// First callback attempt: wrong verifier, fails PKCE.
		w1 := httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodGet, "/auth/oauth/callback?provider=google&state="+state+"&code=authcode123&code_verifier=wrong-verifier", nil)
		router.ServeHTTP(w1, req1)
		if w1.Code != http.StatusBadRequest {
			t.Fatalf("expected first attempt to fail PKCE with 400, got %d", w1.Code)
		}

		// Second attempt with the *correct* verifier must not succeed — the
		// state was already consumed on the first (failed) attempt.
		w2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodGet, "/auth/oauth/callback?provider=google&state="+state+"&code=authcode123&code_verifier=correct-verifier", nil)
		router.ServeHTTP(w2, req2)
		if w2.Code == http.StatusOK {
			t.Errorf("expected replayed state to be rejected, got 200")
		}
	})
}
