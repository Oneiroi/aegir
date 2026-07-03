// Package webauthn provides WebAuthn/FIDO2 MFA endpoints for Aegir.
// It implements the register-begin/finish and login-begin/finish ceremony pair.
package webauthn

import (
	"net/http"
	"time"

	"github.com/aegishjalmur/aegir/internal/logging"
	"github.com/gin-gonic/gin"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// Handler wires up the WebAuthn ceremonies to Gin routes.
type Handler struct {
	webauthn    *gowebauthn.WebAuthn
	credentials *CredentialStore
	challenges  *ChallengeStore
	users       *UserStore
	logger      *logging.Logger
	// requireJWTBinding, when true, requires the client-supplied X-User-ID /
	// user_id to match the authenticated identity the auth middleware placed in
	// the gin context (key "user_id"). This closes AEGIR-H-003: without it, an
	// attacker can claim any user's pending challenge by spoofing the header.
	requireJWTBinding bool
}

// NewHandler creates a ready-to-use Handler. Returns nil (no error) when rpID is empty
// so the caller can skip WebAuthn registration.
func NewHandler(rpID, rpOrigin string, logger *logging.Logger) (*Handler, error) {
	return NewHandlerWithBinding(rpID, rpOrigin, logger, false)
}

// NewHandlerWithBinding is NewHandler with the AEGIR-H-003 JWT-identity binding
// toggle. When requireJWTBinding is true, register/login finish reject any
// X-User-ID that does not match the authenticated context identity.
func NewHandlerWithBinding(rpID, rpOrigin string, logger *logging.Logger, requireJWTBinding bool) (*Handler, error) {
	if rpID == "" {
		return nil, nil
	}

	wa, err := gowebauthn.New(&gowebauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Aegir MCP Firewall",
		RPOrigins:     []string{rpOrigin},
	})
	if err != nil {
		return nil, err
	}

	return &Handler{
		webauthn:          wa,
		credentials:       NewCredentialStore(),
		challenges:        NewChallengeStore(5 * time.Minute),
		users:             NewUserStore(),
		logger:            logger,
		requireJWTBinding: requireJWTBinding,
	}, nil
}

// resolveUserID extracts the target user ID from the X-User-ID header (or the
// user_id query param fallback) and, when requireJWTBinding is enabled, verifies
// it matches the authenticated identity in the gin context. Returns ("", false)
// and writes the appropriate HTTP error when validation fails.
func (h *Handler) resolveUserID(c *gin.Context) (string, bool) {
	userID := c.GetHeader("X-User-ID")
	if userID == "" {
		userID = c.Query("user_id")
	}
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-User-ID header or user_id query param required"})
		return "", false
	}
	if h.requireJWTBinding {
		authedRaw, ok := c.Get("user_id")
		authed, _ := authedRaw.(string)
		if !ok || authed == "" || authed != userID {
			h.logger.Warn("webauthn identity binding rejected",
				"claimed_user", userID, "authenticated_user", authed)
			c.JSON(http.StatusForbidden, gin.H{"error": "X-User-ID does not match authenticated identity"})
			return "", false
		}
	}
	return userID, true
}

// ---- register ---------------------------------------------------------------

// RegisterBegin handles POST /auth/webauthn/register/begin.
// Body: {"user_id":"…","username":"…","display_name":"…"}
func (h *Handler) RegisterBegin(c *gin.Context) {
	var req struct {
		UserID      string `json:"user_id"      binding:"required"`
		Username    string `json:"username"     binding:"required"`
		DisplayName string `json:"display_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		// AEGIR-L-003: log the parse error server-side only; the client gets a
		// generic message so request-body internals never leak in the response.
		h.logger.Warn("webauthn register-begin: invalid request body", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.DisplayName == "" {
		req.DisplayName = req.Username
	}

	user, ok := h.users.Get(req.UserID)
	if !ok {
		user = NewWebAuthnUser(req.UserID, req.Username, req.DisplayName, nil)
		h.users.Put(user)
	}

	creation, session, err := h.webauthn.BeginRegistration(user)
	if err != nil {
		h.logger.Error("webauthn begin-registration failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "registration ceremony failed"})
		return
	}

	h.challenges.Put(req.UserID, session)
	c.JSON(http.StatusOK, creation)
}

// RegisterFinish handles POST /auth/webauthn/register/finish.
// Body: {"user_id":"…", <PublicKeyCredential JSON>}
// The actual attestation object is embedded in the raw HTTP body per WebAuthn spec.
func (h *Handler) RegisterFinish(c *gin.Context) {
	userID, ok := h.resolveUserID(c)
	if !ok {
		return
	}

	session := h.challenges.Take(userID)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no pending registration challenge or challenge expired"})
		return
	}

	user, ok := h.users.Get(userID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unknown user"})
		return
	}

	credential, err := h.webauthn.FinishRegistration(user, *session, c.Request)
	if err != nil {
		// AEGIR-L-003: the go-webauthn library's error text can include internal
		// ceremony/validation detail; log it server-side and return a generic
		// message to the client.
		h.logger.Warn("webauthn finish-registration failed", "user_id", userID, "error", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "registration verification failed"})
		return
	}

	h.credentials.Add(userID, *credential)

	// Update the user object in the user store so future logins include the new credential.
	updated := NewWebAuthnUser(user.id, user.name, user.displayName, h.credentials.Get(userID))
	h.users.Put(updated)

	h.logger.Info("webauthn credential registered", "user_id", userID)
	c.JSON(http.StatusOK, gin.H{"status": "credential registered"})
}

// ---- login ------------------------------------------------------------------

// LoginBegin handles POST /auth/webauthn/login/begin.
// Body: {"user_id":"…"}
func (h *Handler) LoginBegin(c *gin.Context) {
	var req struct {
		UserID string `json:"user_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("webauthn login-begin: invalid request body", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	user, ok := h.users.Get(req.UserID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unknown user"})
		return
	}

	// Refresh credentials snapshot so the latest registered creds are visible.
	user = NewWebAuthnUser(user.id, user.name, user.displayName, h.credentials.Get(req.UserID))

	assertion, session, err := h.webauthn.BeginLogin(user)
	if err != nil {
		// AEGIR-L-003: generic response to the client; full detail server-side only.
		h.logger.Warn("webauthn begin-login failed", "user_id", req.UserID, "error", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "login ceremony failed"})
		return
	}

	// Key login sessions with a "login:" prefix to avoid collision with registration sessions.
	h.challenges.Put("login:"+req.UserID, session)
	c.JSON(http.StatusOK, assertion)
}

// LoginFinish handles POST /auth/webauthn/login/finish.
// X-User-ID header (or user_id query param) must carry the same user ID used in LoginBegin.
func (h *Handler) LoginFinish(c *gin.Context) {
	userID, ok := h.resolveUserID(c)
	if !ok {
		return
	}

	session := h.challenges.Take("login:" + userID)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no pending login challenge or challenge expired"})
		return
	}

	user, ok := h.users.Get(userID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unknown user"})
		return
	}

	// Snapshot latest credentials so ValidateLogin has the current public key.
	user = NewWebAuthnUser(user.id, user.name, user.displayName, h.credentials.Get(userID))

	credential, err := h.webauthn.FinishLogin(user, *session, c.Request)
	if err != nil {
		// AEGIR-L-003: generic response to the client; full detail server-side only.
		h.logger.Warn("webauthn finish-login failed", "user_id", userID, "error", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "login verification failed"})
		return
	}

	// Sign-counter regression: CloneWarning is set by UpdateCounter when the new count
	// is less-than-or-equal to the stored count (and at least one is non-zero).
	if credential.Authenticator.CloneWarning {
		h.logger.Warn("webauthn sign-counter regression — possible cloned authenticator",
			"user_id", userID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "sign counter regression detected"})
		return
	}

	h.credentials.UpdateCounter(userID, credential)

	h.logger.Info("webauthn login successful", "user_id", userID)
	c.JSON(http.StatusOK, gin.H{
		"access_token": "webauthn-placeholder-token",
		"user_id":      userID,
	})
}
