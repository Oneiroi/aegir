package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/sanitizer"
	"github.com/aegishjalmur/aegir/internal/upstream"
	"github.com/gin-gonic/gin"
)

// newAsyncQuotaTestProxy builds an MCPProxy with AsyncTaskQuota enabled at the given
// per-identity concurrency cap, driven over a real HTTP router so the assertions below
// exercise HandleMCPRequest itself rather than the tasks.Registry in isolation.
func newAsyncQuotaTestProxy(t *testing.T, maxConcurrency int) (*MCPProxy, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	logger := testLogger()
	sanitizerMgr := sanitizer.New(config.Security{}, logger)
	complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
	upstreamMgr := upstream.NewManager(&config.Upstream{}, logger)

	cfg := &config.Config{
		Security: config.Security{
			AsyncTaskQuota: config.AsyncTaskQuotaConfig{
				Enabled:        true,
				MaxConcurrency: maxConcurrency,
			},
		},
	}
	proxy := NewMCPProxy(cfg, logger, sanitizerMgr, complianceMgr, upstreamMgr, nil, nil, nil)

	r := gin.New()
	r.POST("/mcp", proxy.HandleMCPRequest)
	return proxy, r
}

// TestAsyncTaskQuotaEnforcedOverHTTP proves ISC-171 is wired, not just present: a
// tools/call arriving while the caller is already at its registered task capacity is
// rejected with 429 by the real HandleMCPRequest entry point, and the rejection clears
// once the in-flight task is marked finished — closing the "quota check reads a
// registry nothing populates" gap.
func TestAsyncTaskQuotaEnforcedOverHTTP(t *testing.T) {
	proxy, router := newAsyncQuotaTestProxy(t, 1)
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Seed one in-flight task for the identity every unauthenticated test request
	// resolves to ("anonymous", per getUserID's fallback).
	if _, ok := proxy.taskRegistry.StartTask("seed-task", "anonymous", ""); !ok {
		t.Fatal("failed to seed an in-flight task")
	}

	body, _ := json.Marshal(MCPRequest{
		Method: "tools/call",
		Params: map[string]interface{}{"name": "test"},
		ID:     "quota-1",
	})
	resp, err := http.Post(ts.URL+"/mcp", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 while at quota, got %d", resp.StatusCode)
	}

	// Free the seeded task and confirm the same request now proceeds past the quota gate.
	proxy.taskRegistry.MarkFinished("seed-task")

	resp2, err := http.Post(ts.URL+"/mcp", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("expected quota to have cleared, still got 429")
	}

	// The real request's own task must have been registered and unregistered via the
	// defer in HandleMCPRequest — not left dangling in the registry.
	if count := proxy.taskRegistry.GetTaskCount("anonymous"); count != 0 {
		t.Fatalf("expected task registry to be clear after request completed, got count=%d", count)
	}
}

// TestAsyncTaskQuotaDormantByDefault proves the disabled-by-default posture: with no
// AsyncTaskQuota config (the zero value), tools/call is still tracked in the registry
// (for future cancellation accounting) but never rejected, however many are in flight.
func TestAsyncTaskQuotaDormantByDefault(t *testing.T) {
	proxy := createTestMCPProxy(t)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Seed several in-flight tasks for "anonymous" — well past any real quota.
	for i := 0; i < 10; i++ {
		proxy.taskRegistry.StartTask("seed-"+string(rune('a'+i)), "anonymous", "")
	}

	body, _ := json.Marshal(MCPRequest{
		Method: "tools/call",
		Params: map[string]interface{}{"name": "test"},
		ID:     "dormant-1",
	})
	resp, err := http.Post(ts.URL+"/mcp", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("disabled AsyncTaskQuota must never reject a request, got 429")
	}
}
