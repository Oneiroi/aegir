package server

import (
	"bytes"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/gin-gonic/gin"
)

// TestToolsListReconRateLimit is the ISC-121 probe: per-session tools/list call
// counter triggers tools_list_recon_suspected when the threshold is exceeded.
// We verify the internal counter state and that no panic occurs.
func TestToolsListReconRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const threshold = 5
	proxy := &MCPProxy{
		config: &config.Config{
			Security: config.Security{
				ReconRateLimit: config.ReconRateLimitConfig{
					Enabled:            true,
					ToolsListMaxPerMin: threshold,
				},
			},
		},
		logger:     testLogger(),
		reconCalls: make(map[string][]time.Time),
	}

	const sessionID = "test-session-recon"

	// Drive 15 calls (>threshold) via the same session header.
	for i := 0; i < 15; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp", bytes.NewBufferString("{}"))
		c.Request.Header.Set("X-Session-ID", sessionID)
		proxy.trackReconCall(c, &MCPRequest{Method: "tools/list"})
	}

	// The in-memory counter must have recorded calls within the last minute.
	// getSessionID falls back to "anonymous_<IP>" when no session cookie is present.
	proxy.reconMu.Lock()
	var total int
	for _, calls := range proxy.reconCalls {
		total += len(calls)
	}
	proxy.reconMu.Unlock()

	if total < 15 {
		t.Errorf("expected 15 recon calls tracked across all sessions, got %d", total)
	}
}

// TestToolsListReconRateLimit_BelowThreshold confirms calls up to the threshold
// don't accumulate more than the call count (no pruning on under-threshold paths).
func TestToolsListReconRateLimit_BelowThreshold(t *testing.T) {
	gin.SetMode(gin.TestMode)

	proxy := &MCPProxy{
		config: &config.Config{
			Security: config.Security{
				ReconRateLimit: config.ReconRateLimitConfig{
					Enabled:            true,
					ToolsListMaxPerMin: 10,
				},
			},
		},
		logger:     testLogger(),
		reconCalls: make(map[string][]time.Time),
	}

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp", bytes.NewBufferString("{}"))
		proxy.trackReconCall(c, &MCPRequest{Method: "tools/list"})
	}

	proxy.reconMu.Lock()
	var total int
	for _, calls := range proxy.reconCalls {
		total += len(calls)
	}
	proxy.reconMu.Unlock()

	if total != 5 {
		t.Errorf("expected 5 calls tracked, got %d", total)
	}
}

// TestToolsListReconRateLimit_Disabled confirms trackReconCall is a no-op when disabled.
func TestToolsListReconRateLimit_Disabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	proxy := &MCPProxy{
		config: &config.Config{
			Security: config.Security{
				ReconRateLimit: config.ReconRateLimitConfig{
					Enabled:            false,
					ToolsListMaxPerMin: 1,
				},
			},
		},
		logger:     testLogger(),
		reconCalls: make(map[string][]time.Time),
	}

	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp", bytes.NewBufferString("{}"))
		proxy.trackReconCall(c, &MCPRequest{Method: "tools/list"})
	}

	proxy.reconMu.Lock()
	count := len(proxy.reconCalls)
	proxy.reconMu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 entries in reconCalls map when disabled, got %d", count)
	}
}
