package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Manager handles authentication and authorization
type Manager struct {
	config    config.Auth
	logger    *logging.Logger
	jwtSecret []byte
	users     map[string]*User // In production, this would be a database
	apiKeys   map[string]*APIKey
	sessions  map[string]*Session
}

// User represents a system user
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
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

	// Create default admin user for development
	if err := mgr.createDefaultUsers(); err != nil {
		return nil, fmt.Errorf("failed to create default users: %w", err)
	}

	return mgr, nil
}

// createDefaultUsers creates default users for initial setup
func (m *Manager) createDefaultUsers() error {
	adminID := uuid.New().String()
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		return err
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

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(m.config.JWT.ExpirationTime.Seconds()),
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

	// TODO: Implement refresh token validation and new token generation
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Refresh token not implemented"})
}

// Logout handles user logout
func (m *Manager) Logout(c *gin.Context) {
	// TODO: Implement session invalidation
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// OAuthLogin initiates OAuth login
func (m *Manager) OAuthLogin(c *gin.Context) {
	// TODO: Implement OAuth login initiation
	c.JSON(http.StatusNotImplemented, gin.H{"error": "OAuth not implemented"})
}

// OAuthCallback handles OAuth callback
func (m *Manager) OAuthCallback(c *gin.Context) {
	// TODO: Implement OAuth callback handling
	c.JSON(http.StatusNotImplemented, gin.H{"error": "OAuth callback not implemented"})
}

// generateJWT generates a new JWT token for a user
func (m *Manager) generateJWT(user *User) (string, error) {
	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Roles:    user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.config.JWT.Issuer,
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.config.JWT.ExpirationTime)),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.jwtSecret)
}

// validateJWT validates a JWT token and returns claims
func (m *Manager) validateJWT(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
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