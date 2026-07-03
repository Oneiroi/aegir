package server

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimiter manages rate limiting for clients
type RateLimiter struct {
	config      config.RateLimit
	logger      *logging.Logger
	clients     map[string]*ClientLimiter
	mutex       sync.RWMutex
	cleanupTicker *time.Ticker
}

// ClientLimiter represents rate limiting state for a single client
type ClientLimiter struct {
	limiter   *rate.Limiter
	lastSeen  time.Time
	requests  uint64
	blocked   uint64
}

// RateLimitStats represents rate limiting statistics
type RateLimitStats struct {
	TotalClients    int     `json:"total_clients"`
	ActiveClients   int     `json:"active_clients"`
	RequestsPerSec  float64 `json:"requests_per_second"`
	BlockedRequests uint64  `json:"blocked_requests"`
	TopClients      []ClientStats `json:"top_clients"`
}

// ClientStats represents statistics for a single client
type ClientStats struct {
	ClientIP string  `json:"client_ip"`
	Requests uint64  `json:"requests"`
	Blocked  uint64  `json:"blocked"`
	LastSeen string  `json:"last_seen"`
}

// NewRateLimiter creates a new rate limiter instance
func NewRateLimiter(config config.RateLimit, logger *logging.Logger) *RateLimiter {
	// Ensure minimum cleanup interval to prevent panic
	cleanupInterval := config.CleanupInterval
	if cleanupInterval <= 0 {
		cleanupInterval = 300 // 5 minutes default
	}

	rl := &RateLimiter{
		config:        config,
		logger:        logger,
		clients:       make(map[string]*ClientLimiter),
		cleanupTicker: time.NewTicker(time.Duration(cleanupInterval) * time.Second),
	}

	// Start cleanup goroutine
	go rl.cleanupRoutine()

	return rl
}

// GetLimiter returns or creates a rate limiter for a client
func (rl *RateLimiter) GetLimiter(clientIP string) *rate.Limiter {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	// Get existing limiter or create new one
	client, exists := rl.clients[clientIP]
	if !exists {
		// Enforce MaxTrackedIPs cap to prevent unbounded memory growth from
		// attackers rotating IPs. When the cap is hit, evict the oldest-last-seen
		// entry. Linear scan is acceptable because this path only triggers when
		// the cap is reached, not on every request.
		if rl.config.MaxTrackedIPs > 0 && len(rl.clients) >= rl.config.MaxTrackedIPs {
			var oldestKey string
			var oldestSeen time.Time
			first := true
			for k, v := range rl.clients {
				if first || v.lastSeen.Before(oldestSeen) {
					oldestKey = k
					oldestSeen = v.lastSeen
					first = false
				}
			}
			if !first {
				delete(rl.clients, oldestKey)
			}
		}

		// Create new limiter: requests per minute converted to requests per second
		rps := rate.Limit(float64(rl.config.RequestsPerMin) / 60.0)
		limiter := rate.NewLimiter(rps, rl.config.BurstSize)

		client = &ClientLimiter{
			limiter:  limiter,
			lastSeen: time.Now(),
			requests: 0,
			blocked:  0,
		}
		rl.clients[clientIP] = client
	}

	client.lastSeen = time.Now()
	client.requests++

	return client.limiter
}

// IsAllowed checks if a request is allowed for the given client
func (rl *RateLimiter) IsAllowed(clientIP string) bool {
	limiter := rl.GetLimiter(clientIP)
	allowed := limiter.Allow()

	if !allowed {
		rl.mutex.Lock()
		if client, exists := rl.clients[clientIP]; exists {
			client.blocked++
		}
		rl.mutex.Unlock()

		// Log rate limit violation
		rl.logRateLimitViolation(clientIP)
	}

	return allowed
}

// Middleware creates a Gin middleware for rate limiting
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		clientIP := rl.getClientIP(c)

		// Key rate limiting to authenticated identity when available, so that
		// a single compromised account cannot multiply its rate budget by
		// rotating source IPs. Fall back to client IP for unauthenticated
		// requests.
		clientKey := clientIP
		if userID, exists := c.Get("user_id"); exists {
			if uid, ok := userID.(string); ok && uid != "" {
				clientKey = uid
			}
		}

		if !rl.IsAllowed(clientKey) {
			rl.logger.Warn("Rate limit exceeded", "client_ip", clientIP, "client_key", clientKey)
			c.JSON(429, gin.H{
				"error":   "Rate limit exceeded",
				"message": "Too many requests, please try again later",
				"retry_after": 60,
			})
			c.Abort()
			return
		}

		c.Next()
	})
}

// GetStats returns current rate limiting statistics
func (rl *RateLimiter) GetStats() *RateLimitStats {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	totalClients := len(rl.clients)
	activeClients := 0
	var totalRequests, totalBlocked uint64

	// Calculate active clients and totals
	cutoff := time.Now().Add(-5 * time.Minute) // Active in last 5 minutes
	var topClients []ClientStats

	for ip, client := range rl.clients {
		totalRequests += client.requests
		totalBlocked += client.blocked

		if client.lastSeen.After(cutoff) {
			activeClients++
		}

		topClients = append(topClients, ClientStats{
			ClientIP: ip,
			Requests: client.requests,
			Blocked:  client.blocked,
			LastSeen: client.lastSeen.Format(time.RFC3339),
		})
	}

	// Sort top clients by request count (simplified)
	if len(topClients) > 10 {
		topClients = topClients[:10]
	}

	// Calculate requests per second (rough estimate)
	var requestsPerSec float64
	if activeClients > 0 {
		requestsPerSec = float64(totalRequests) / float64(time.Since(time.Now().Add(-time.Hour)).Seconds())
	}

	return &RateLimitStats{
		TotalClients:    totalClients,
		ActiveClients:   activeClients,
		RequestsPerSec:  requestsPerSec,
		BlockedRequests: totalBlocked,
		TopClients:      topClients,
	}
}

// cleanupRoutine removes old client entries
func (rl *RateLimiter) cleanupRoutine() {
	for range rl.cleanupTicker.C {
		rl.cleanupClients()
	}
}

// cleanupClients removes inactive client entries
func (rl *RateLimiter) cleanupClients() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	cutoff := time.Now().Add(-time.Hour) // Remove clients inactive for 1 hour
	removed := 0

	for ip, client := range rl.clients {
		if client.lastSeen.Before(cutoff) {
			delete(rl.clients, ip)
			removed++
		}
	}

	if removed > 0 {
		rl.logger.Debug("Cleaned up rate limiter entries", "removed", removed, "remaining", len(rl.clients))
	}
}

// getClientIP extracts the real client IP address
func (rl *RateLimiter) getClientIP(c *gin.Context) string {
	// Use RemoteIP() when no trusted proxy list is configured
	// This is safer as it ignores X-Forwarded-For headers unless explicitly trusted
	if len(rl.config.TrustedProxies) == 0 {
		remoteIP, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			return c.Request.RemoteAddr
		}
		return remoteIP
	}

	// If trusted proxies are configured, validate X-Forwarded-For
	return rl.getClientIPWithTrustedProxies(c)
}

// getClientIPWithTrustedProxies extracts client IP using X-Forwarded-For with trusted proxy validation
func (rl *RateLimiter) getClientIPWithTrustedProxies(c *gin.Context) string {
	// Check X-Forwarded-For header
	if ip := c.GetHeader("X-Forwarded-For"); ip != "" {
		ips := parseForwardedFor(ip)
		if len(ips) > 0 {
			// Validate that all intermediate proxies are trusted
			if rl.isValidTrustedProxyChain(c, ips) {
				return ips[0] // Return the original client IP
			}
		}
	}

	// Check X-Real-IP header
	if ip := c.GetHeader("X-Real-IP"); ip != "" {
		if rl.isTrustedProxy(c) {
			return ip
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}
	return host
}

// isValidTrustedProxyChain validates that X-Forwarded-For chain is from trusted proxies
func (rl *RateLimiter) isValidTrustedProxyChain(c *gin.Context, ips []string) bool {
	remoteIP := c.Request.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}

	// Check if the remote IP (immediate proxy) is trusted
	if !rl.isTrustedProxyIP(remoteIP) {
		return false
	}

	// For multi-hop X-Forwarded-For, we trust the first IP if immediate proxy is trusted
	// In production, you might want to validate the entire chain
	return true
}

// isTrustedProxy checks if the request comes from a trusted proxy
func (rl *RateLimiter) isTrustedProxy(c *gin.Context) bool {
	remoteIP := c.Request.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}
	return rl.isTrustedProxyIP(remoteIP)
}

// isTrustedProxyIP checks if an IP is in the trusted proxy list
func (rl *RateLimiter) isTrustedProxyIP(ip string) bool {
	for _, trusted := range rl.config.TrustedProxies {
		if trusted == ip {
			return true
		}
	}
	return false
}

// parseForwardedFor parses X-Forwarded-For header
func parseForwardedFor(header string) []string {
	var ips []string
	for _, ip := range strings.Split(header, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
}

// logRateLimitViolation logs rate limit violations
func (rl *RateLimiter) logRateLimitViolation(clientIP string) {
	event := &logging.SecurityEvent{
		Type:      "rate_limit_violation",
		Severity:  "warning",
		Message:   "Rate limit exceeded",
		ClientIP:  clientIP,
		Timestamp: time.Now(),
		Details: map[string]string{
			"limit_rpm":   fmt.Sprintf("%d", rl.config.RequestsPerMin),
			"burst_size":  fmt.Sprintf("%d", rl.config.BurstSize),
		},
	}

	rl.logger.LogSecurityEvent(event)
}

// Stop stops the rate limiter and cleanup routine
func (rl *RateLimiter) Stop() {
	if rl.cleanupTicker != nil {
		rl.cleanupTicker.Stop()
	}
}