package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/sanitizer"
	"github.com/aegishjalmur/aegir/internal/session"
	"github.com/aegishjalmur/aegir/internal/upstream"
	"github.com/gin-gonic/gin"
)

// createRoundTripProxy builds an MCPProxy wired to a single enabled upstream
// at upstreamURL (may be empty to simulate a dead upstream that was
// configured but never reachable).
func createRoundTripProxy(t *testing.T, upstreamURL string) *MCPProxy {
	t.Helper()
	logger := testLogger()

	sanitizerMgr := sanitizer.New(config.Security{
		CommandInjection: config.CommandInjection{Enabled: true},
		SecretDetection:  config.SecretDetection{Enabled: true},
		Sanitization:     config.Sanitization{Enabled: true},
	}, logger)
	complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)

	upstreamCfg := &config.Upstream{
		Services: []config.UpstreamService{
			{Name: "test-upstream", URL: upstreamURL, Enabled: true, Timeout: 5},
		},
		LoadBalancing: config.LoadBalancing{Strategy: "round_robin"},
	}
	upstreamMgr := upstream.NewManager(upstreamCfg, logger)

	sessionAnalyzer := session.NewConversationalThreatAnalyzer(session.AnalyzerConfig{
		MaxSessionAge:   30 * time.Minute,
		MaxHistorySize:  50,
		ThreatThreshold: 0.5,
		CleanupInterval: 5 * time.Minute,
	}, logger)
	t.Cleanup(sessionAnalyzer.Stop)

	defaultCfg := &config.Config{
		Security: config.Security{
			AnomalyDetection: config.AnomalyDetection{
				Enabled:        false,
				BlockThreshold: 0.95,
				LogThreshold:   0.60,
			},
		},
	}

	return NewMCPProxy(defaultCfg, logger, sanitizerMgr, complianceMgr, upstreamMgr, sessionAnalyzer, nil, nil)
}

// issueToolsCall drives one tools/call through HandleMCPRequest and returns
// the HTTP status code and raw body the client would see.
func issueToolsCall(t *testing.T, proxy *MCPProxy) (int, string) {
	t.Helper()
	req := MCPRequest{
		Method: "tools/call",
		Params: map[string]interface{}{
			"name":      "security_scan",
			"arguments": map[string]interface{}{"content": "hello world"},
		},
		ID: "roundtrip-1",
	}
	reqBody, _ := json.Marshal(req)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/mcp", bytes.NewBuffer(reqBody))
	c.Request.Header.Set("Content-Type", "application/json")

	proxy.HandleMCPRequest(c)
	return w.Code, w.Body.String()
}

// TestProxyRoundTripReachesUpstream is the F1 regression probe: with an
// upstream configured and healthy, the client-visible response must contain
// the upstream's marker body — proving a real round-trip rather than the old
// fabricated "scan complete" fallback.
func TestProxyRoundTripReachesUpstream(t *testing.T) {
	const marker = "UPSTREAM-REAL-RESPONSE-MARKER-7f3a"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in MCPRequest
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": marker},
				},
			},
			"id": in.ID,
		})
	}))
	defer srv.Close()

	proxy := createRoundTripProxy(t, srv.URL)
	code, body := issueToolsCall(t, proxy)

	if code != http.StatusOK {
		t.Fatalf("expected 200 from healthy upstream round-trip, got %d: %s", code, body)
	}
	if !strings.Contains(body, marker) {
		t.Fatalf("expected response to contain upstream marker %q, got: %s", marker, body)
	}
	if strings.Contains(body, "scan complete") {
		t.Fatalf("response came from the fabricated fallback, not the upstream: %s", body)
	}
}

// TestProxyUpstreamUnavailableFailsClosed is the F1 honest-failure probe:
// with an upstream configured but dead, the proxy must return the -32000
// "upstream unavailable" error with HTTP 502 — never a fabricated success.
func TestProxyUpstreamUnavailableFailsClosed(t *testing.T) {
	// Bind and immediately close a listener to get an address that refuses
	// connections without depending on a well-known port.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	proxy := createRoundTripProxy(t, deadURL)
	code, body := issueToolsCall(t, proxy)

	if code != http.StatusBadGateway {
		t.Fatalf("expected 502 for unreachable configured upstream, got %d: %s", code, body)
	}

	var response MCPResponse
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if response.Error == nil {
		t.Fatalf("expected upstream-unavailable error, got success: %s", body)
	}
	if response.Error.Code != -32000 {
		t.Errorf("expected error code -32000, got %d", response.Error.Code)
	}
	if response.Error.Message != "upstream unavailable" {
		t.Errorf("expected message \"upstream unavailable\", got %q", response.Error.Message)
	}
	if strings.Contains(body, "scan complete") {
		t.Fatalf("response fabricated by fallback despite configured upstream: %s", body)
	}
}

// TestProxyForwardPathSSRFArgBlocked is the F2 probe: an SSRF target nested
// anywhere in the tools/call arguments tree must be blocked with 403 on the
// forward path, before any upstream contact.
func TestProxyForwardPathSSRFArgBlocked(t *testing.T) {
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"result": map[string]interface{}{}, "id": "x"})
	}))
	defer srv.Close()

	proxy := createRoundTripProxy(t, srv.URL)

	req := MCPRequest{
		Method: "tools/call",
		Params: map[string]interface{}{
			"name": "fetch",
			"arguments": map[string]interface{}{
				"options": map[string]interface{}{
					"endpoints": []interface{}{"http://example.com", "http://169.254.169.254/latest/meta-data/"},
				},
			},
		},
		ID: "ssrf-fwd",
	}
	reqBody, _ := json.Marshal(req)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/mcp", bytes.NewBuffer(reqBody))
	c.Request.Header.Set("Content-Type", "application/json")

	proxy.HandleMCPRequest(c)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for nested SSRF target, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "SSRF target detected in tool arguments") {
		t.Errorf("expected SSRF block message, got: %s", w.Body.String())
	}
	if reached {
		t.Error("upstream was contacted despite SSRF block")
	}
}

// TestProxyForwardPathHumanApprovalGate is the N1/F8 probe: a destructive
// tool call must be blocked on the forward path when human approval is
// enabled but the webhook never approves (fail closed).
func TestProxyForwardPathHumanApprovalGate(t *testing.T) {
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"result": map[string]interface{}{}, "id": "x"})
	}))
	defer srv.Close()

	proxy := createRoundTripProxy(t, srv.URL)
	proxy.config.Security.HumanApproval = config.HumanApprovalConfig{
		Enabled:  true,
		Patterns: []string{"delete_"},
		// No WebhookURL: fail closed.
		Timeout: 50 * time.Millisecond,
	}

	req := MCPRequest{
		Method: "tools/call",
		Params: map[string]interface{}{
			"name":      "delete_table",
			"arguments": map[string]interface{}{"table": "users"},
		},
		ID: "approval-fwd",
	}
	reqBody, _ := json.Marshal(req)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/mcp", bytes.NewBuffer(reqBody))
	c.Request.Header.Set("Content-Type", "application/json")

	proxy.HandleMCPRequest(c)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unapproved destructive call, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "human approval required for destructive operation") {
		t.Errorf("expected human-approval block message, got: %s", w.Body.String())
	}
	if reached {
		t.Error("upstream was contacted despite human-approval block")
	}
}
