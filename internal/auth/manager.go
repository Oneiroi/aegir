package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
	wahandler "github.com/aegishjalmur/aegir/internal/auth/webauthn"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Manager handles authentication and authorization
type Manager struct {
	config         config.Auth
	logger         *logging.Logger
	jwtSecret      []byte
	users          map[string]*User // In production, this would be a database
	apiKeys        map[string]*APIKey
	sessions       map[string]*Session
	tokenBlacklist sync.Map // stores revoked tokens: token -> expiration time
	oauthStates    sync.Map // stores OAuth CSRF states: state -> expiration time

	// WebAuthn is non-nil only when config.Auth.WebAuthn.RPID is set.
	WebAuthn *wahandler.Handler
}

// User represents a system user
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	MFASecret    string    `json:"-"` // reserved for future TOTP compatibility
	Roles        []string  `json:"roles"`
	MFAEnabled   bool      `json:"mfa_enabled"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
	Active       bool      `json:"active"`
}

// APIKey represents an API key for authentication
type APIKey struct {
	ID          string    `json:"id"`
	Key         string    `json:"key"`
	UserID      string    `json:"user_id"`
	Name        string    `json:"name"`
	Permissions []string  `json:"permissions"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
	Active      bool      `json:"active"`
}

// Session represents an active user session
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
}

// Claims represents JWT claims
type Claims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	MFACode  string `json:"mfa_code,omitempty"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// New creates a new authentication manager
func New(config config.Auth, logger *logging.Logger) (*Manager, error) {
	mgr := &Manager{
		config:    config,
		logger:    logger,
		jwtSecret: []byte(config.JWT.Secret),
		users:     make(map[string]*User),
		apiKeys:   make(map[string]*APIKey),
		sessions:  make(map[string]*Session),
	}

	// Initialise WebAuthn handler if RPID is configured (optional feature).
	if config.WebAuthn.RPID != "" {
		waHandler, err := wahandler.NewHandlerWithBinding(config.WebAuthn.RPID, config.WebAuthn.RPOrigin, logger, config.WebAuthn.RequireJWTBinding)
		if err != nil {
			return nil, fmt.Errorf("failed to initialise WebAuthn handler: %w", err)
		}
		mgr.WebAuthn = waHandler
	}

	// Create default admin user for development
	if err := mgr.createDefaultUsers(); err != nil {
		return nil, fmt.Errorf("failed to create default users: %w", err)
	}

	return mgr, nil
}

// generateRandomPassword returns a cryptographically random password of the given length.
func generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"
	out := make([]byte, length)
	max := big.NewInt(int64(len(charset)))
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = charset[n.Int64()]
	}
	return string(out), nil
}

// createDefaultUsers creates default users for initial setup
func (m *Manager) createDefaultUsers() error {
	adminID := uuid.New().String()

	adminPassword := os.Getenv("AEGIR_ADMIN_PASSWORD")
	generated := false
	if adminPassword == "" {
		pw, err := generateRandomPassword(20)
		if err != nil {
			return fmt.Errorf("failed to generate admin password: %w", err)
		}
		adminPassword = pw
		generated = true
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	if generated {
		// Log the generated password ONCE so the operator can capture it.
		// Use both the structured logger and stderr so it is visible in all deployments.
		m.logger.Info("[AEGIR STARTUP] Admin password (save this): " + adminPassword)
		fmt.Fprintf(os.Stderr, "[AEGIR STARTUP] Admin password (save this): %s\n", adminPassword)
	}

	admin := &User{
		ID:           adminID,
		Username:     "admin",
		Email:        "admin@localhost",
		PasswordHash: string(passwordHash),
		Roles:        []string{"admin", "user"},
		MFAEnabled:   false,
		CreatedAt:    time.Now(),
		Active:       true,
	}

	m.users[admin.Username] = admin

	// Create default API key
	apiKey, err := m.generateAPIKey(adminID, "Default Admin Key", []string{"admin"})
	if err != nil {
		return err
	}
	m.apiKeys[apiKey.Key] = apiKey

	m.logger.Info("Created default admin user and API key")
	return nil
}

// AuthMiddleware provides authentication middleware for Gin
func (m *Manager) AuthMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Try API Key authentication first
		if apiKey := c.GetHeader("X-API-Key"); apiKey != "" {
			if m.validateAPIKey(apiKey, c) {
				c.Next()
				return
			}
		}

		// Try Bearer token authentication
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.logger.Warn("Missing authorization header", "ip", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			m.logger.Warn("Invalid authorization header format", "ip", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		token := parts[1]

		// Check if token is blacklisted
		if _, isBlacklisted := m.tokenBlacklist.Load(token); isBlacklisted {
			m.logger.Warn("Token is blacklisted", "ip", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token revoked"})
			c.Abort()
			return
		}

		claims, err := m.validateJWT(token)
		if err != nil {
			m.logger.Warn("Invalid JWT token", "error", err, "ip", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("roles", claims.Roles)

		c.Next()
	})
}

// Login handles user login
func (m *Manager) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	user, exists := m.users[req.Username]
	if !exists || !user.Active {
		m.logger.Warn("Login attempt for non-existent user", "username", req.Username, "ip", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		m.logger.Warn("Failed login attempt", "username", req.Username, "ip", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check MFA if enabled
	if user.MFAEnabled && req.MFACode == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":        "MFA code required",
			"mfa_required": true,
		})
		return
	}

	// Generate tokens
	accessToken, err := m.generateJWT(user)
	if err != nil {
		m.logger.Error("Failed to generate access token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	refreshToken, err := m.generateRefreshToken(user.ID)
	if err != nil {
		m.logger.Error("Failed to generate refresh token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Update last login
	user.LastLogin = time.Now()

	m.logger.Info("Successful login", "username", user.Username, "ip", c.ClientIP())

	// Calculate expires_in with fallback to default
	expiresIn := int(m.config.JWT.ExpirationTime.Seconds())
	if expiresIn == 0 {
		expiresIn = 3600 // Default to 1 hour if config is invalid
	}

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
	})
}

// RefreshToken handles token refresh
func (m *Manager) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate refresh token exists and is not expired
	session, exists := m.sessions[req.RefreshToken]
	if !exists || time.Now().After(session.ExpiresAt) {
		m.logger.Warn("Invalid or expired refresh token", "ip", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		return
	}

	// Find the user
	var user *User
	for _, u := range m.users {
		if u.ID == session.UserID {
			user = u
			break
		}
	}

	if user == nil || !user.Active {
		m.logger.Warn("User not found or inactive for refresh", "user_id", session.UserID, "ip", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Generate new access token
	newAccessToken, err := m.generateJWT(user)
	if err != nil {
		m.logger.Error("Failed to generate new access token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Generate new refresh token
	newRefreshToken, err := m.generateRefreshToken(user.ID)
	if err != nil {
		m.logger.Error("Failed to generate new refresh token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	m.logger.Info("Token refreshed successfully", "user_id", user.ID, "ip", c.ClientIP())

	expiresIn := int(m.config.JWT.ExpirationTime.Seconds())
	if expiresIn == 0 {
		expiresIn = 3600 // Default to 1 hour if config is invalid
	}

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
	})
}

// Logout handles user logout
func (m *Manager) Logout(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization header required"})
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid authorization header format"})
		return
	}

	token := parts[1]

	// Validate the token to get expiration time
	claims, err := m.validateJWT(token)
	if err != nil {
		m.logger.Warn("Invalid JWT token during logout", "error", err, "ip", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Add token to blacklist with expiration time
	if claims.ExpiresAt != nil {
		m.tokenBlacklist.Store(token, claims.ExpiresAt.Time)
	}

	m.logger.Info("User logged out successfully", "user_id", claims.UserID, "ip", c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// OAuthLogin initiates OAuth login
func (m *Manager) OAuthLogin(c *gin.Context) {
	provider := c.Query("provider")
	if provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider query parameter required"})
		return
	}

	// Generate random state for CSRF protection
	state := m.generateRandomState(32)

	// Store state in oauthStates map with 10-min expiration
	stateExpiration := time.Now().Add(10 * time.Minute)
	m.oauthStates.Store(state, stateExpiration)

	// Build authorization URL based on provider
	// For now, we provide a basic structure that can be extended
	authURL := ""
	switch provider {
	case "google":
		authURL = "https://accounts.google.com/o/oauth2/v2/auth"
	case "github":
		authURL = "https://github.com/login/oauth/authorize"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported OAuth provider"})
		return
	}

	m.logger.Info("OAuth login initiated", "provider", provider, "state", state, "ip", c.ClientIP())

	// Redirect the client to the provider's authorisation endpoint.
	// Include the state parameter for CSRF protection.
	redirectTarget := fmt.Sprintf("%s?state=%s&response_type=code", authURL, state)
	c.Redirect(http.StatusFound, redirectTarget)
}

// OAuthCallback handles OAuth callback
func (m *Manager) OAuthCallback(c *gin.Context) {
	state := c.Query("state")
	code := c.Query("code")

	if state == "" || code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "state and code parameters required"})
		return
	}

	// Validate state parameter against stored state
	storedState, exists := m.oauthStates.Load(state)
	if !exists {
		m.logger.Warn("Invalid OAuth state", "ip", c.ClientIP())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}

	// Check if state has expired
	if time.Now().After(storedState.(time.Time)) {
		m.logger.Warn("OAuth state expired", "ip", c.ClientIP())
		m.oauthStates.Delete(state)
		c.JSON(http.StatusBadRequest, gin.H{"error": "State parameter expired"})
		return
	}

	// Remove used state
	m.oauthStates.Delete(state)

	provider := c.Query("provider")
	if provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider query parameter required"})
		return
	}

	// In production, exchange code for OAuth token and fetch user info
	// For now, create a test user from the OAuth info
	// This is a simplified implementation
	userEmail := c.Query("email")
	if userEmail == "" {
		userEmail = "oauth_user_" + uuid.New().String() + "@example.com"
	}

	// Find or create user
	username := "oauth_" + provider + "_" + strings.TrimPrefix(userEmail, "oauth_user_")
	var user *User

	// Try to find existing user
	for _, u := range m.users {
		if u.Email == userEmail {
			user = u
			break
		}
	}

	// Create new user if not found
	if user == nil {
		userID := uuid.New().String()
		user = &User{
			ID:         userID,
			Username:   username,
			Email:      userEmail,
			Roles:      []string{"user"},
			MFAEnabled: false,
			CreatedAt:  time.Now(),
			Active:     true,
		}
		m.users[user.Username] = user
		m.logger.Info("Created new OAuth user", "email", userEmail, "provider", provider)
	}

	// Generate JWT tokens
	accessToken, err := m.generateJWT(user)
	if err != nil {
		m.logger.Error("Failed to generate access token for OAuth user", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	refreshToken, err := m.generateRefreshToken(user.ID)
	if err != nil {
		m.logger.Error("Failed to generate refresh token for OAuth user", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	m.logger.Info("OAuth callback processed successfully", "provider", provider, "user_id", user.ID, "ip", c.ClientIP())

	expiresIn := int(m.config.JWT.ExpirationTime.Seconds())
	if expiresIn == 0 {
		expiresIn = 3600 // Default to 1 hour if config is invalid
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"roles":    user.Roles,
		},
	})
}

// generateJWT generates a new JWT token for a user
func (m *Manager) generateJWT(user *User) (string, error) {
	// Use fallback duration if config is invalid
	expirationTime := m.config.JWT.ExpirationTime
	if expirationTime == 0 {
		expirationTime = time.Hour // Default to 1 hour
	}

	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Roles:    user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.config.JWT.Issuer,
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expirationTime)),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.jwtSecret)
}

// validateJWT validates a JWT token and returns claims
func (m *Manager) validateJWT(tokenString string) (*Claims, error) {
	// Validate HMAC signing method
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Optionally validate key ID (kid) header
		if m.config.JWT.KeyID != "" {
			tokenKid, ok := token.Header["kid"].(string)
			if !ok || tokenKid != m.config.JWT.KeyID {
				return nil, fmt.Errorf("invalid key ID: expected %q, got %v", m.config.JWT.KeyID, token.Header["kid"])
			}
		}

		return m.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Validate issuer if configured
	if m.config.JWT.Issuer != "" {
		if claims.Issuer != m.config.JWT.Issuer {
			return nil, fmt.Errorf("invalid issuer: expected %q, got %q", m.config.JWT.Issuer, claims.Issuer)
		}
	}

	// Validate audience if configured
	if m.config.JWT.Audience != "" {
		if len(claims.Audience) == 0 {
			return nil, fmt.Errorf("token missing required audience")
		}
		valid := false
		for _, aud := range claims.Audience {
			if aud == m.config.JWT.Audience {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("invalid audience: expected %q, got %v", m.config.JWT.Audience, claims.Audience)
		}
	}

	return claims, nil
}

// VerifyTokenSignature validates a JWT's signature and standard claims and
// returns nil when the token is authentic. It is exported so middleware that
// needs to trust unparsed payload fields (e.g. OAuth scope auditing — AEGIR-M-003)
// can confirm the token is signed by this server before acting on its contents.
func (m *Manager) VerifyTokenSignature(tokenString string) error {
	_, err := m.validateJWT(tokenString)
	return err
}

// generateRefreshToken generates a refresh token
func (m *Manager) generateRefreshToken(userID string) (string, error) {
	sessionID := uuid.New().String()
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}

	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		Token:     hex.EncodeToString(token),
		ExpiresAt: time.Now().Add(m.config.JWT.RefreshExpiration),
		CreatedAt: time.Now(),
	}

	m.sessions[session.Token] = session
	return session.Token, nil
}

// generateAPIKey generates a new API key
func (m *Manager) generateAPIKey(userID, name string, permissions []string) (*APIKey, error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, err
	}

	apiKey := &APIKey{
		ID:          uuid.New().String(),
		Key:         "mcp_" + hex.EncodeToString(keyBytes),
		UserID:      userID,
		Name:        name,
		Permissions: permissions,
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour), // 1 year
		CreatedAt:   time.Now(),
		Active:      true,
	}

	return apiKey, nil
}

// validateAPIKey validates an API key
func (m *Manager) validateAPIKey(key string, c *gin.Context) bool {
	apiKey, exists := m.apiKeys[key]
	if !exists || !apiKey.Active || time.Now().After(apiKey.ExpiresAt) {
		return false
	}

	// Update last used time
	apiKey.LastUsed = time.Now()

	// Set context for API key authentication
	c.Set("api_key_id", apiKey.ID)
	c.Set("user_id", apiKey.UserID)
	c.Set("permissions", apiKey.Permissions)

	return true
}

// generateRandomState generates a random state string for OAuth CSRF protection
func (m *Manager) generateRandomState(length int) string {
	state := make([]byte, length)
	if _, err := rand.Read(state); err != nil {
		// Fallback to UUID if random read fails
		return uuid.New().String()
	}
	return hex.EncodeToString(state)
}
