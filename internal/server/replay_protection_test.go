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

// newReplayProtectionTestProxy builds an MCPProxy with ReplayProtection
// enabled — disabled by default elsewhere in this suite so existing tests
// that reuse a request ID across calls aren't affected.
func newReplayProtectionTestProxy(t *testing.T) *MCPProxy {
	t.Helper()
	logger := testLogger()
	sanitizerMgr := sanitizer.New(config.Security{}, logger)
	complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
	upstreamMgr := upstream.NewManager(&config.Upstream{}, logger)
	cfg := &config.Config{
		Security: config.Security{
			ReplayProtection: config.ReplayProtectionConfig{
				Enabled:    true,
				TTLSeconds: 60,
			},
		},
	}
	return NewMCPProxy(cfg, logger, sanitizerMgr, complianceMgr, upstreamMgr, nil, nil, nil)
}

// TestReplayCacheWorksWithoutSessionId verifies ISC-177: replay protection is
// keyed on the authenticated identity, not Mcp-Session-Id — the request below
// carries no session header at all (the MCP 2026-07-28 spec removes it), and
// a repeated JSON-RPC id from the same identity is still caught.
func TestReplayCacheWorksWithoutSessionId(t *testing.T) {
	gin.SetMode(gin.TestMode)
	proxy := newReplayProtectionTestProxy(t)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)
	ts := httptest.NewServer(router)
	defer ts.Close()

	body, _ := json.Marshal(MCPRequest{
		Method: "tools/list",
		ID:     "replay-1",
	})

	post := func() *http.Response {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("failed to build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		// Deliberately no Mcp-Session-Id header anywhere in this test.
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("HTTP request failed: %v", err)
		}
		return resp
	}

	first := post()
	first.Body.Close()
	if first.StatusCode == http.StatusBadRequest {
		t.Fatalf("expected the first request to succeed, got 400")
	}

	second := post()
	defer second.Body.Close()
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected the replayed request (same id, same identity) to be rejected with 400, got %d", second.StatusCode)
	}

	var result MCPResponse
	if err := json.NewDecoder(second.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.Error == nil || result.Error.Code != -32600 {
		t.Errorf("expected -32600 replay error, got %+v", result.Error)
	}
}

// TestReplayProtectionDisabledByDefault verifies the dormant-by-default
// posture: with the zero-value config, the same request ID sent twice is
// never rejected as a replay.
func TestReplayProtectionDisabledByDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	proxy := createTestMCPProxy(t)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)
	ts := httptest.NewServer(router)
	defer ts.Close()

	body, _ := json.Marshal(MCPRequest{Method: "tools/list", ID: "dup-1"})

	for i := 0; i < 2; i++ {
		resp, err := http.Post(ts.URL+"/mcp", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("HTTP request %d failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusBadRequest {
			t.Fatalf("request %d: replay protection must be dormant by default, got 400", i)
		}
	}
}
