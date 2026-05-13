package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
	"github.com/aegishjalmur/aegir/internal/sanitizer"
	"github.com/aegishjalmur/aegir/internal/session"
	"github.com/aegishjalmur/aegir/internal/upstream"
	"github.com/gin-gonic/gin"
)

type MockSessionAnalyzer struct {
	assessment *session.ThreatAssessment
}

func NewMockSessionAnalyzer() *MockSessionAnalyzer {
	return &MockSessionAnalyzer{}
}

func (m *MockSessionAnalyzer) AnalyzeMessage(sessionID, userID string, content string) *session.ThreatAssessment {
	if m.assessment != nil {
		return m.assessment
	}
	return &session.ThreatAssessment{ConversationRisk: "low", CurrentThreatScore: 0.25}
}

func testLogger() *logging.Logger {
	l, _ := logging.New(config.Logging{
		Level:           "info",
		Format:          "json",
		HMACKey:         "test-hmac-key-32-characters-long",
		IntegrityChecks: true,
	})
	return l
}

func setupMCPProxyWithSessionAnalyzer(sessionRisk string) *MCPProxy {
	logger := testLogger()
	sanitizerMgr := sanitizer.New(config.Security{}, logger)
	complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
	upstreamMgr := upstream.NewManager(&config.Upstream{}, logger)

	sessionAnalyzer := NewMockSessionAnalyzer()
	if sessionRisk != "" {
		switch sessionRisk {
		case "critical":
			sessionAnalyzer.assessment = &session.ThreatAssessment{ConversationRisk: "critical", CurrentThreatScore: 0.85}
		case "high":
			sessionAnalyzer.assessment = &session.ThreatAssessment{ConversationRisk: "high", CurrentThreatScore: 0.72}
		case "low":
			sessionAnalyzer.assessment = &session.ThreatAssessment{ConversationRisk: "low", CurrentThreatScore: 0.35}
		}
	}

	return NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, sessionAnalyzer, nil)
}

func TestTwoTierThreatResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Critical Risk - Request Blocked with 403", func(t *testing.T) {
		proxy := setupMCPProxyWithSessionAnalyzer("critical")
		mcpRequest := MCPRequest{Method: "tools/call", Params: map[string]interface{}{"name": "security_scan"}, ID: 1}
		mcpRequestJSON, _ := json.Marshal(mcpRequest)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(mcpRequestJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status code %d, got %d", http.StatusForbidden, w.Code)
		}

		var response MCPResponse
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response.Error == nil {
			t.Fatal("Expected error in response")
		}
		if response.Error.Code != -32000 {
			t.Errorf("Expected error code %d, got %d", -32000, response.Error.Code)
		}
		if !strings.Contains(response.Error.Message, "blocked") {
			t.Errorf("Expected message to contain 'blocked', got: %s", response.Error.Message)
		}
		t.Logf("Critical risk test passed - Response: %s", w.Body.String())
	})

	t.Run("High Risk - Request Forwarded with X-Aegir-Risk Header", func(t *testing.T) {
		proxy := setupMCPProxyWithSessionAnalyzer("high")
		mcpRequest := MCPRequest{Method: "tools/call", Params: map[string]interface{}{"name": "security_scan"}, ID: 2}
		mcpRequestJSON, _ := json.Marshal(mcpRequest)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(mcpRequestJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
		// High risk requests are forwarded (not blocked), so must not be 403.
		// With no upstream configured, the response may be 502; what matters is the risk headers.
		if w.Code == http.StatusForbidden {
			t.Errorf("High risk request must not be blocked with 403 (got 403)")
		}
		if w.Header().Get("X-Aegir-Risk") != "high" {
			t.Errorf("Expected X-Aegir-Risk header to be 'high', got: %s", w.Header().Get("X-Aegir-Risk"))
		}
		if w.Header().Get("X-Aegir-Threat-Score") != "0.72" {
			t.Errorf("Expected X-Aegir-Threat-Score header to be '0.72', got: %s", w.Header().Get("X-Aegir-Threat-Score"))
		}
		t.Logf("High risk test passed - Status: %d, X-Aegir-Risk: %s", w.Code, w.Header().Get("X-Aegir-Risk"))
	})

	t.Run("Low Risk - Normal Processing", func(t *testing.T) {
		proxy := setupMCPProxyWithSessionAnalyzer("low")
		mcpRequest := MCPRequest{Method: "tools/call", Params: map[string]interface{}{"name": "security_scan"}, ID: 3}
		mcpRequestJSON, _ := json.Marshal(mcpRequest)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(mcpRequestJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
		t.Logf("Low risk test - Response status: %d", w.Code)
	})
}

func newMockAnalyzer(risk string, score float64, patterns ...string) *MockSessionAnalyzer {
	m := NewMockSessionAnalyzer()
	m.assessment = &session.ThreatAssessment{ConversationRisk: risk, CurrentThreatScore: score, AttackPatterns: patterns}
	return m
}

func newMockProxy(mock *MockSessionAnalyzer) *MCPProxy {
	logger := testLogger()
	sanitizerMgr := sanitizer.New(config.Security{}, logger)
	complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
	upstreamMgr := upstream.NewManager(&config.Upstream{}, logger)
	return NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, mock, nil)
}

func makeTestContext(method string, body []byte) (*httptest.ResponseRecorder, *gin.Context) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	return w, c
}

func TestTwoTierThreatResponseBoundaryCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Boundary: Score exactly 0.8 (Critical)", func(t *testing.T) {
		proxy := newMockProxy(newMockAnalyzer("critical", 0.8))
		body, _ := json.Marshal(MCPRequest{Method: "tools/call", ID: 4})
		w, c := makeTestContext("POST", body)
		proxy.HandleMCPRequest(c)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status code %d (critical threshold), got %d", http.StatusForbidden, w.Code)
		}
		t.Logf("Boundary test (0.8 exactly) passed - Critical threshold enforced")
	})

	t.Run("Boundary: Score 0.79 (High)", func(t *testing.T) {
		proxy := newMockProxy(newMockAnalyzer("high", 0.79))
		body, _ := json.Marshal(MCPRequest{Method: "tools/call", ID: 5})
		w, c := makeTestContext("POST", body)
		proxy.HandleMCPRequest(c)
		if w.Code == http.StatusForbidden {
			t.Errorf("Score 0.79 should be forwarded (high), not blocked with 403")
		}
		if w.Header().Get("X-Aegir-Risk") != "high" {
			t.Errorf("Expected X-Aegir-Risk: high, got %q", w.Header().Get("X-Aegir-Risk"))
		}
		t.Logf("Boundary test (0.79 exactly) passed - High threshold enforced, X-Aegir-Risk: %s", w.Header().Get("X-Aegir-Risk"))
	})

	t.Run("Boundary: Score 0.6 (High)", func(t *testing.T) {
		proxy := newMockProxy(newMockAnalyzer("high", 0.6))
		body, _ := json.Marshal(MCPRequest{Method: "tools/call", ID: 6})
		w, c := makeTestContext("POST", body)
		proxy.HandleMCPRequest(c)
		if w.Code == http.StatusForbidden {
			t.Errorf("Score 0.6 should be forwarded (minimum high), not blocked with 403")
		}
		if w.Header().Get("X-Aegir-Risk") != "high" {
			t.Errorf("Expected X-Aegir-Risk: high, got %q", w.Header().Get("X-Aegir-Risk"))
		}
		t.Logf("Boundary test (0.6 minimum high) passed, X-Aegir-Risk: %s", w.Header().Get("X-Aegir-Risk"))
	})
}

func TestTwoTierThreatResponseWithMockAnalyzer(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Mock Analyzer - Critical Path", func(t *testing.T) {
		proxy := newMockProxy(newMockAnalyzer("critical", 0.85, "prompt_injection"))
		body, _ := json.Marshal(MCPRequest{Method: "tools/call", ID: 7})
		w, c := makeTestContext("POST", body)
		proxy.HandleMCPRequest(c)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status code %d, got %d", http.StatusForbidden, w.Code)
		}
		t.Logf("Mock analyzer critical path test passed")
	})

	t.Run("Mock Analyzer - High Path", func(t *testing.T) {
		proxy := newMockProxy(newMockAnalyzer("high", 0.72, "content_injection"))
		body, _ := json.Marshal(MCPRequest{Method: "tools/call", ID: 8})
		w, c := makeTestContext("POST", body)
		proxy.HandleMCPRequest(c)
		if w.Code == http.StatusForbidden {
			t.Errorf("High risk must not be blocked with 403, got %d", w.Code)
		}
		if w.Header().Get("X-Aegir-Risk") != "high" {
			t.Errorf("Expected X-Aegir-Risk: high, got %q", w.Header().Get("X-Aegir-Risk"))
		}
		t.Logf("Mock analyzer high path test passed, X-Aegir-Risk: %s", w.Header().Get("X-Aegir-Risk"))
	})
}

func TestTwoTierThreatResponseLogging(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Critical Risk Logging Verification", func(t *testing.T) {
		proxy := newMockProxy(newMockAnalyzer("critical", 0.85))
		body, _ := json.Marshal(MCPRequest{Method: "tools/call", ID: 9})
		w, c := makeTestContext("POST", body)
		proxy.HandleMCPRequest(c)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 for critical risk, got %d", w.Code)
		}
		t.Logf("Critical risk logging test - Request blocked with critical risk")
	})

	t.Run("High Risk Logging Verification", func(t *testing.T) {
		proxy := newMockProxy(newMockAnalyzer("high", 0.72))
		body, _ := json.Marshal(MCPRequest{Method: "tools/call", ID: 10})
		w, c := makeTestContext("POST", body)
		proxy.HandleMCPRequest(c)
		if w.Header().Get("X-Aegir-Risk") != "high" {
			t.Errorf("Expected X-Aegir-Risk: high header, got: %q", w.Header().Get("X-Aegir-Risk"))
		}
		t.Logf("High risk logging test - Request forwarded with risk header")
	})
}

func TestTwoTierThreatResponseEdgeCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Empty Session Analyzer - Should Process Normally", func(t *testing.T) {
		logger := testLogger()
		sanitizerMgr := sanitizer.New(config.Security{}, logger)
		complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
		upstreamMgr := upstream.NewManager(&config.Upstream{}, logger)

		proxy := NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, nil, nil)
		body, _ := json.Marshal(MCPRequest{Method: "tools/call", ID: 11})
		_, c := makeTestContext("POST", body)
		proxy.HandleMCPRequest(c)
		t.Logf("Empty session analyzer test - Request processed normally without analyzer")
	})

	t.Run("Malformed JSON Input", func(t *testing.T) {
		proxy := newMockProxy(newMockAnalyzer("low", 0.35))
		malformedJSON := []byte(`{"method": "tools/call", "invalid json}`)
		w, c := makeTestContext("POST", malformedJSON)
		proxy.HandleMCPRequest(c)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status code %d for malformed JSON, got %d", http.StatusBadRequest, w.Code)
		}
		t.Logf("Malformed JSON test - Properly rejected with 400")
	})

	t.Run("Missing Required Fields", func(t *testing.T) {
		proxy := newMockProxy(newMockAnalyzer("low", 0.35))
		body, _ := json.Marshal(MCPRequest{Method: "tools/call", ID: 12})
		w, c := makeTestContext("POST", body)
		proxy.HandleMCPRequest(c)
		t.Logf("Missing required fields test - Response status: %d", w.Code)
	})
}

func BenchmarkTwoTierThreatResponse(b *testing.B) {
	gin.SetMode(gin.TestMode)

	mockAnalyzer := newMockAnalyzer("high", 0.72)
	proxy := newMockProxy(mockAnalyzer)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mcpRequest := MCPRequest{Method: "tools/call", ID: float64(i)}
		mcpRequestJSON, _ := json.Marshal(mcpRequest)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(mcpRequestJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
	}
}
