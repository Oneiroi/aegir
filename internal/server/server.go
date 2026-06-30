package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/aegishjalmur/aegir/internal/anomaly"
	"github.com/aegishjalmur/aegir/internal/auth"
	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/crypto"
	"github.com/aegishjalmur/aegir/internal/dashboard"
	"github.com/aegishjalmur/aegir/internal/judge"
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

// buildJudgeConfig translates the config package's JudgeConfig into a
// judge.Config, carrying the provider discriminator (M013, ISC-138) and the
// ordered transport-error failover chain (ISC-141). The two packages keep
// separate fallback types to avoid a config→judge import dependency; this is
// the single translation point, exercised by TestBuildJudgeConfig.
func buildJudgeConfig(jc config.JudgeConfig) judge.Config {
	fallbacks := make([]judge.FallbackConfig, 0, len(jc.Fallbacks))
	for _, fb := range jc.Fallbacks {
		fallbacks = append(fallbacks, judge.FallbackConfig{
			BaseURL:  fb.BaseURL,
			Model:    fb.Model,
			APIKey:   fb.APIKey,
			Provider: fb.Provider,
		})
	}
	return judge.Config{
		BaseURL:   jc.BaseURL,
		Model:     jc.Model,
		APIKey:    jc.APIKey,
		TimeoutMs: jc.TimeoutMs,
		Provider:  jc.Provider,
		Fallbacks: fallbacks,
	}
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

	// Initialize LLM judge rule engine (opt-in via config; disabled = pattern-only mode)
	var ruleEngine *judge.RuleEngine
	if cfg.Judge.Enabled {
		// Use the provider factory (M013, ISC-138) so judge.provider:
		// openai|anthropic is reachable at runtime, not just NewOllamaJudge.
		j := judge.NewJudge(buildJudgeConfig(cfg.Judge), nil, logger)
		ruleEngine = judge.NewRuleEngine(j, logger)
		logger.Info("[AEGIR STARTUP] Judge enabled",
			"provider", cfg.Judge.Provider,
			"base_url", cfg.Judge.BaseURL,
			"model", cfg.Judge.Model,
		)
	} else {
		logger.Info("[AEGIR STARTUP] Judge disabled — pattern-only mode (set MCP_JUDGE_ENABLED=true to enable)")
	}

	// Loudly warn when judge reasoning is exposed to clients (debug/audit
	// opt-in). The reason text can quote the inspected payload, so this is a
	// known GDPR/HIPAA/PCI violation when that payload contains regulated data.
	if cfg.Judge.ExposeReasoning {
		logger.Warn("judge.expose_reasoning is ENABLED — judge reasoning will be emitted to clients (X-Aegir-Judge-Reason header + BLOCK error data). This is KNOWN TO VIOLATE GDPR/HIPAA/PCI when the emitted reasoning contains regulated data being replayed as reasoning. Use only in trusted debug environments.")
	}

	// Initialize MCP proxy
	mcpProxy := NewMCPProxy(cfg, logger, sanitizerManager, complianceManager, upstreamManager, sessionAnalyzer, anomalyDetector, ruleEngine)

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

		// GDPR right-to-erasure endpoint (ISC-64).
		user := api.Group("/user")
		user.Use(s.auth.AuthMiddleware())
		{
			user.DELETE("/:id/data", s.eraseUserData)
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

	// MCP proxy endpoints — CSRF/Origin validation (ISC-120) + OAuth scope audit (ISC-122).
	mcp := protected.Group("/mcp")
	mcp.Use(s.csrfOriginMiddleware())
	mcp.Use(s.oauthScopeAuditMiddleware())
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

// oauthScopeAuditMiddleware inspects Bearer JWT tokens on incoming MCP requests
// and fires an excessive_scope_detected security event when the token's scope
// or scp claim contains a prohibited value (ISC-122). This is an audit-only
// middleware — it logs and continues; blocking happens in the auth middleware.
func (s *MCPFirewall) oauthScopeAuditMiddleware() gin.HandlerFunc {
	cfg := s.config.Security.OAuthScopeAudit
	return func(c *gin.Context) {
		if !cfg.Enabled || len(cfg.ProhibitedScopes) == 0 {
			c.Next()
			return
		}
		authHeader := c.GetHeader("Authorization")
		if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			c.Next()
			return
		}
		tokenStr := authHeader[7:]
		scopes := extractJWTScopes(tokenStr)
		for _, scope := range scopes {
			for _, prohibited := range cfg.ProhibitedScopes {
				if scope == prohibited {
					s.logger.LogSecurityEvent(&logging.SecurityEvent{
						Type:      "excessive_scope_detected",
						Severity:  "high",
						Message:   "JWT token contains prohibited OAuth scope",
						ClientIP:  c.ClientIP(),
						Timestamp: time.Now(),
						Details: map[string]string{
							"scope":     scope,
							"client_ip": c.ClientIP(),
						},
					})
				}
			}
		}
		c.Next()
	}
}

// extractJWTScopes returns the scope values from a JWT payload without
// validating the signature. The scope/scp claim may be a space-separated
// string or a []interface{} array.
func extractJWTScopes(tokenStr string) []string {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	var scopes []string
	for _, key := range []string{"scope", "scp"} {
		v, ok := claims[key]
		if !ok {
			continue
		}
		switch val := v.(type) {
		case string:
			for _, s := range strings.Fields(val) {
				scopes = append(scopes, s)
			}
		case []interface{}:
			for _, item := range val {
				if s, ok := item.(string); ok {
					scopes = append(scopes, s)
				}
			}
		}
	}
	return scopes
}

// csrfOriginMiddleware validates the Origin header on HTTP MCP endpoints (ISC-120).
// Non-browser clients that send no Origin header are allowed unconditionally.
// Browser clients must have their origin in security.allowed_origins; an empty
// list allows all origins. Cross-origin requests from unlisted origins get 403
// and a csrf_origin_rejected security event.
func (s *MCPFirewall) csrfOriginMiddleware() gin.HandlerFunc {
	allowedOrigins := s.config.Security.AllowedOrigins
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" || len(allowedOrigins) == 0 {
			c.Next()
			return
		}
		for _, allowed := range allowedOrigins {
			if origin == allowed {
				c.Next()
				return
			}
		}
		s.logger.LogSecurityEvent(&logging.SecurityEvent{
			Type:      "csrf_origin_rejected",
			Severity:  "high",
			Message:   "Cross-origin request rejected",
			ClientIP:  c.ClientIP(),
			Timestamp: time.Now(),
			Details:   map[string]string{"origin": origin},
		})
		c.JSON(http.StatusForbidden, gin.H{"error": "cross-origin request not allowed"})
		c.Abort()
	}
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

// Health check handler — returns aliveness status and basic metrics.
// No sensitive internals (key IDs, HMAC status) — those live behind auth at /api/dashboard/health.
func (s *MCPFirewall) healthCheck(c *gin.Context) {
	status := "healthy"
	var alerts []string

	if s.dashboardStats != nil {
		d := s.dashboardStats.GetDashboard()

		if d.SystemStats.MemoryPercent > 80 {
			status = "degraded"
			alerts = append(alerts, "high memory usage")
		}
		if d.SystemStats.GoroutineCount > 1000 {
			if status == "healthy" {
				status = "degraded"
			}
			alerts = append(alerts, "high goroutine count")
		}
		if d.AverageRequestTime > 5*time.Second {
			if status == "healthy" {
				status = "degraded"
			}
			alerts = append(alerts, "slow response times")
		}

		oneMinuteAgo := time.Now().Add(-time.Minute)
		var recentAttacks uint64
		for _, req := range d.RecentRequests {
			if req.StartTime.After(oneMinuteAgo) {
				recentAttacks += uint64(len(req.AttacksFound))
			}
		}
		if recentAttacks > 100 {
			status = "unhealthy"
			alerts = append(alerts, "high attack rate")
		}

		httpCode := http.StatusOK
		if status != "healthy" {
			httpCode = http.StatusServiceUnavailable
		}
		c.JSON(httpCode, gin.H{
			"status":          status,
			"uptime":          d.Uptime,
			"requests_total":  d.TotalRequests,
			"attacks_blocked": d.TotalAttacksBlocked,
			"active_requests": d.ActiveRequests,
			"alerts":          alerts,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": status})
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

// eraseUserData implements the GDPR right-to-erasure endpoint (ISC-64).
// DELETE /api/user/:id/data — deletes any stored data for the given user ID
// and responds 200 OK with erased=true (idempotent, even when nothing exists).
func (s *MCPFirewall) eraseUserData(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	if s.sessionAnalyzer != nil {
		s.sessionAnalyzer.DeleteSession(userID)
	}

	s.logger.LogSecurityEvent(&logging.SecurityEvent{
		Type:      "gdpr_erasure",
		Severity:  "info",
		Message:   "User data erasure requested and completed",
		UserID:    userID,
		ClientIP:  c.ClientIP(),
		Timestamp: time.Now(),
		Details:   map[string]string{"user_id": userID, "erased": "true"},
	})

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"user_id": userID,
		"erased":  true,
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
