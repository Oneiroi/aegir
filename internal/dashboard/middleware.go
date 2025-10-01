package dashboard

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// responseWriter wraps gin.ResponseWriter to capture response data
type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriter) Write(data []byte) (int, error) {
	// Write to both the original writer and our buffer
	w.body.Write(data)
	return w.ResponseWriter.Write(data)
}

// Middleware creates a Gin middleware for dashboard statistics collection
func (sc *StatsCollector) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate unique request ID
		requestID := generateRequestID()

		// Get request details
		method := c.Request.Method
		path := c.Request.URL.Path
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")

		// Get request size
		var bytesIn int64
		if c.Request.ContentLength > 0 {
			bytesIn = c.Request.ContentLength
		} else if c.Request.Body != nil {
			// Read body to measure size (for requests without Content-Length)
			bodyBytes, err := io.ReadAll(c.Request.Body)
			if err == nil {
				bytesIn = int64(len(bodyBytes))
				// Restore body for further processing
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}

		// Start tracking request
		sc.RecordRequest(requestID, method, path, clientIP, userAgent)

		// Wrap response writer to capture output
		responseBuffer := &bytes.Buffer{}
		wrappedWriter := &responseWriter{
			ResponseWriter: c.Writer,
			body:          responseBuffer,
		}
		c.Writer = wrappedWriter

		// Store request ID in context for attack tracking
		c.Set("dashboard_request_id", requestID)
		c.Set("dashboard_collector", sc)

		// Process request
		c.Next()

		// Get response details
		statusCode := c.Writer.Status()
		bytesOut := int64(responseBuffer.Len())

		// Collect any attacks found during request processing
		attacksFound := []AttackCategory{}
		if attacks, exists := c.Get("dashboard_attacks"); exists {
			if attackList, ok := attacks.([]AttackCategory); ok {
				attacksFound = attackList
			}
		}

		// Finish tracking request
		sc.FinishRequest(requestID, statusCode, bytesIn, bytesOut, attacksFound)
	}
}

// RecordAttackInContext records an attack for the current request context
func RecordAttackInContext(c *gin.Context, category AttackCategory) {
	// Get existing attacks
	attacks := []AttackCategory{}
	if existing, exists := c.Get("dashboard_attacks"); exists {
		if attackList, ok := existing.([]AttackCategory); ok {
			attacks = attackList
		}
	}

	// Add new attack
	attacks = append(attacks, category)
	c.Set("dashboard_attacks", attacks)

	// Also record globally if collector is available
	if collector, exists := c.Get("dashboard_collector"); exists {
		if sc, ok := collector.(*StatsCollector); ok {
			sc.RecordAttack(category, map[string]interface{}{
				"path":      c.Request.URL.Path,
				"client_ip": c.ClientIP(),
				"method":    c.Request.Method,
			})
		}
	}
}

// generateRequestID generates a unique request identifier
func generateRequestID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

// GetRequestID gets the current request ID from context
func GetRequestID(c *gin.Context) string {
	if id, exists := c.Get("dashboard_request_id"); exists {
		if requestID, ok := id.(string); ok {
			return requestID
		}
	}
	return ""
}