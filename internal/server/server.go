package server

import (
	"net/http"
	"time"

	"github.com/aegishjalmur/aegir/internal/anomaly"
	"github.com/aegishjalmur/aegir/internal/auth"
	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/crypto"
	"github.com/aegishjalmur/aegir/internal/dashboard"
	"github.com/aegishjalmur/aegir/internal/logging"
	"github.com/aegishjalmur/aegir/internal/metrics"
	"github.com/aegishjalmur/aegir/internal/sanitizer"
	"github.com/aegishjalmur/aegir/internal/session"
	"github.com/aegishjalmur/aegir/internal/upstream"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// MCPFirewall represents the main server instance
type MCPFirewall struct {
	config            *config.Config
	logger            *logging.Logger
	auth              *auth.Manager
	sanitizer         *sanitizer.Manager
	complianceManager *sanitizer.ComplianceManager
	encryptionManager *crypto.EncryptionManager
	upstreamManager   *upstream.Manager
	sessionAnalyzer   *session.ConversationalThreatAnalyzer
	mcpProxy          *MCPProxy
	rateLimiter       *RateLimiter
	dashboardStats    *dashboard.StatsCollector
	dashboardAPI      *dashboard.DashboardAPI
	metricsCollector  *metrics.Collector
	router            *gin.Engine
}

// New creates a new MCP Firewall server instance
func New(cfg *config.Config) (*MCPFirewall, error) {
	// Initialize logger
	logger, err := logging.New(cfg.Logging)
	if err != nil {
		return nil, err
	}

	// Initialize authentication manager
	authManager, err := auth.New(cfg.Auth, logger)
	if err != nil {
		return nil, err
	}

	// Initialize sanitizer manager
	sanitizerManager := sanitizer.New(cfg.Security, logger)

	// Initialize compliance manager
	complianceManager := sanitizer.NewComplianceManager(cfg.Compliance, logger)

	// Initialize encryption manager
	encryptionManager, err := crypto.NewEncryptionManager(cfg.Security.Encryption, logger)
	if err != nil {
		return nil, err
	}

	// Initialize rate limiter (only if enabled)
	var rateLimiter *RateLimiter
	if cfg.Security.RateLimit.Enabled {
		rateLimiter = NewRateLimiter(cfg.Security.RateLimit, logger)
	}

	// Initialize upstream manager
	upstreamManager := upstream.NewManager(&cfg.Upstream, logger)

	// Initialize session analyzer (only if enabled)
	var sessionAnalyzer *session.ConversationalThreatAnalyzer
	if cfg.SessionAnalysis.Enabled {
		analyzerConfig := session.AnalyzerConfig{
			MaxSessionAge:       cfg.SessionAnalysis.MaxSessionAge,
			MaxHistorySize:      cfg.SessionAnalysis.MaxHistorySize,
			ThreatThreshold:     cfg.SessionAnalysis.ThreatThreshold,
			CleanupInterval:     cfg.SessionAnalysis.CleanupInterval,
			JailbreakThreshold:  cfg.SessionAnalysis.JailbreakThreshold,
			RoleEscalationLimit: cfg.SessionAnalysis.RoleEscalationLimit,
		}
		sessionAnalyzer = session.NewConversationalThreatAnalyzer(analyzerConfig, logger)
	}

	// Initialize anomaly detector (opt-in via config)
	var anomalyDetector anomaly.Detector
	if cfg.Security.AnomalyDetection.Enabled {
		anomalyDetector = anomaly.NewHeuristicDetector()
	}

	// Initialize MCP proxy
	mcpProxy := NewMCPProxy(cfg, logger, sanitizerManager, complianceManager, upstreamManager, sessionAnalyzer, anomalyDetector)

	// Initialize dashboard statistics collector
	dashboardStats := dashboard.NewStatsCollector(logger)
	dashboardAPI := dashboard.NewDashboardAPI(dashboardStats)

	// Initialize Prometheus metrics collector
	metricsCollector := metrics.NewCollector()

	// Create server instance
	server := &MCPFirewall{
		config:            cfg,
		logger:            logger,
		auth:              authManager,
		sanitizer:         sanitizerManager,
		complianceManager: complianceManager,
		encryptionManager: encryptionManager,
		upstreamManager:   upstreamManager,
		sessionAnalyzer:   sessionAnalyzer,
		mcpProxy:          mcpProxy,
		rateLimiter:       rateLimiter,
		dashboardStats:    dashboardStats,
		dashboardAPI:      dashboardAPI,
		metricsCollector:  metricsCollector,
	}

	// Initialize router
	server.setupRouter()

	return server, nil
}

// Handler returns the HTTP handler for the server
func (s *MCPFirewall) Handler() http.Handler {
	return s.router
}

// setupRouter configures the Gin router with middleware and routes
func (s *MCPFirewall) setupRouter() {
	s.router = gin.New()

	// Security middleware
	s.router.Use(s.securityHeaders())
	s.router.Use(s.otelMiddleware())
	s.router.Use(s.loggingMiddleware())
	s.router.Use(gin.Recovery())

	// Dashboard statistics middleware (should be early to capture all requests)
	s.router.Use(s.dashboardStats.Middleware())

	// Rate limiting middleware
	if s.config.Security.RateLimit.Enabled {
		s.router.Use(s.rateLimiter.Middleware())
	}

	// Authentication middleware for protected routes
	protected := s.router.Group("/")
	protected.Use(s.auth.AuthMiddleware())

	// Health check endpoint (unprotected)
	s.router.GET("/health", s.healthCheck)

	// Prometheus metrics endpoint (unprotected for scraping)
	s.router.GET("/metrics", gin.WrapF(promhttp.Handler().ServeHTTP))

	// Security API endpoints
	api := s.router.Group("/api")
	{
		security := api.Group("/security")
		security.Use(s.auth.AuthMiddleware())
		{
			security.GET("/logging/status", s.loggingStatus)
			security.GET("/logging/validate", s.validateLogIntegrity)
			security.GET("/metrics", s.getMetrics)
			security.GET("/sessions", s.getSessions)
			security.GET("/sessions/:id", s.getSession)
			security.DELETE("/sessions/:id", s.deleteSession)
		}

		// Dashboard API endpoints (protected)
		protectedDashboard := api.Group("/")
		protectedDashboard.Use(s.auth.AuthMiddleware())
		s.dashboardAPI.RegisterRoutes(protectedDashboard)
	}

	// Dashboard web interface (unprotected - login handled client-side)
	webDashboard := s.router.Group("/")
	// No auth middleware - login form handles auth client-side
	s.dashboardAPI.RegisterWebRoutes(webDashboard)

	// MCP proxy endpoints
	mcp := protected.Group("/mcp")
	{
		mcp.POST("/", s.mcpProxy.HandleMCPRequest)
		mcp.POST("/resources", s.mcpProxy.HandleMCPRequest)
		mcp.POST("/tools", s.mcpProxy.HandleMCPRequest)
		mcp.POST("/prompts", s.mcpProxy.HandleMCPRequest)
		mcp.GET("/ws", s.mcpProxy.HandleWebSocket)
		mcp.POST("/sse", s.mcpProxy.HandleSSE)
		mcp.GET("/sse", s.mcpProxy.HandleSSEEvents)
		mcp.GET("/status", s.mcpProxy.HandleServiceStatus)
	}

	// Authentication endpoints
	authGroup := s.router.Group("/auth")
	{
		authGroup.POST("/login", s.auth.Login)
		authGroup.POST("/refresh", s.auth.RefreshToken)
		authGroup.POST("/logout", s.auth.Logout)
		if s.config.Auth.OAuth.Enabled {
			authGroup.GET("/oauth/callback", s.auth.OAuthCallback)
			authGroup.GET("/oauth/login", s.auth.OAuthLogin)
		}
		if s.auth.WebAuthn != nil {
			authGroup.POST("/webauthn/register/begin", s.auth.WebAuthn.RegisterBegin)
			authGroup.POST("/webauthn/register/finish", s.auth.WebAuthn.RegisterFinish)
			authGroup.POST("/webauthn/login/begin", s.auth.WebAuthn.LoginBegin)
			authGroup.POST("/webauthn/login/finish", s.auth.WebAuthn.LoginFinish)
		}
	}
}

// otelMiddleware creates an OTEL span for each HTTP request.
func (s *MCPFirewall) otelMiddleware() gin.HandlerFunc {
	tracer := otel.Tracer("aegir-mcp-firewall")
	return func(c *gin.Context) {
		ctx, span := tracer.Start(c.Request.Context(), c.Request.URL.Path,
			oteltrace.WithSpanKind(oteltrace.SpanKindServer),
			oteltrace.WithAttributes(
				attribute.String("http.method", c.Request.Method),
				attribute.String("http.url", c.Request.URL.String()),
				attribute.String("http.client_ip", c.ClientIP()),
			),
		)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
		span.SetAttributes(attribute.Int("http.status_code", c.Writer.Status()))
		span.End()
	}
}

// Security headers middleware
func (s *MCPFirewall) securityHeaders() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		c.Next()
	})
}

// Logging middleware
func (s *MCPFirewall) loggingMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()
		c.Next()

		duration := time.Since(start)
		s.logger.LogRequest(&logging.RequestLog{
			ClientIP:   c.ClientIP(),
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			StatusCode: c.Writer.Status(),
			Duration:   duration,
			UserAgent:  c.Request.UserAgent(),
			Timestamp:  start,
		})
	})
}

// Health check handler
func (s *MCPFirewall) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
	})
}

// Logging status handler
func (s *MCPFirewall) loggingStatus(c *gin.Context) {
	status := s.logger.GetStatus()
	c.JSON(http.StatusOK, status)
}

// Log integrity validation handler
func (s *MCPFirewall) validateLogIntegrity(c *gin.Context) {
	result := s.logger.ValidateIntegrity()
	c.JSON(http.StatusOK, result)
}

// Metrics handler
func (s *MCPFirewall) getMetrics(c *gin.Context) {
	var rateLimitStats *RateLimitStats
	if s.rateLimiter != nil {
		rateLimitStats = s.rateLimiter.GetStats()
	} else {
		rateLimitStats = &RateLimitStats{}
	}

	encryptionStatus := s.encryptionManager.GetKeyRotationStatus()
	logStatus := s.logger.GetStatus()

	c.JSON(http.StatusOK, gin.H{
		"connections": gin.H{
			"active_clients": rateLimitStats.ActiveClients,
			"total_clients":  rateLimitStats.TotalClients,
		},
		"requests": gin.H{
			"per_second":       rateLimitStats.RequestsPerSec,
			"blocked_requests": rateLimitStats.BlockedRequests,
		},
		"security": gin.H{
			"current_key_id":    encryptionStatus.CurrentKeyID,
			"next_key_rotation": encryptionStatus.NextRotation,
			"active_keys":       encryptionStatus.ActiveKeys,
		},
		"logging": gin.H{
			"total_writes":         logStatus.TotalWrites,
			"integrity_status":     logStatus.IntegrityStatus,
			"last_integrity_check": logStatus.LastIntegrityCheck,
		},
		"uptime": gin.H{
			"status": "healthy",
		},
		"anomaly_scores": s.mcpProxy.GetAnomalyStats(),
	})
}

// getSessions returns all active sessions
func (s *MCPFirewall) getSessions(c *gin.Context) {
	if s.sessionAnalyzer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Session analysis is not enabled",
		})
		return
	}

	stats := s.sessionAnalyzer.GetSessionStats()
	c.JSON(http.StatusOK, stats)
}

// getSession returns details for a specific session
func (s *MCPFirewall) getSession(c *gin.Context) {
	if s.sessionAnalyzer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Session analysis is not enabled",
		})
		return
	}

	sessionID := c.Param("id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Session ID is required",
		})
		return
	}

	sessionData := s.sessionAnalyzer.GetSessionContext(sessionID)
	if sessionData == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Session not found",
		})
		return
	}

	c.JSON(http.StatusOK, sessionData)
}

// deleteSession removes a specific session
func (s *MCPFirewall) deleteSession(c *gin.Context) {
	if s.sessionAnalyzer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Session analysis is not enabled",
		})
		return
	}

	sessionID := c.Param("id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Session ID is required",
		})
		return
	}

	s.sessionAnalyzer.DeleteSession(sessionID)
	c.JSON(http.StatusOK, gin.H{
		"message": "Session deleted successfully",
	})
}

// GetLogger returns the logger instance for use in other components
func (s *MCPFirewall) GetLogger() *logging.Logger {
	return s.logger
}

// GetSanitizer returns the sanitizer manager for use in other components
func (s *MCPFirewall) GetSanitizer() *sanitizer.Manager {
	return s.sanitizer
}

// GetComplianceManager returns the compliance manager for use in other components
func (s *MCPFirewall) GetComplianceManager() *sanitizer.ComplianceManager {
	return s.complianceManager
}
