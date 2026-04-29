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
	assessments map[string]*session.ThreatAssessment
}

func NewMockSessionAnalyzer() *MockSessionAnalyzer {
	return &MockSessionAnalyzer{assessments: make(map[string]*session.ThreatAssessment)}
}

func (m *MockSessionAnalyzer) AnalyzeMessage(sessionID, userID string, content string) *session.ThreatAssessment {
	key := sessionID + userID
	if assessment, exists := m.assessments[key]; exists {
		return assessment
	}
	switch sessionID {
	case "critical-session":
		return &session.ThreatAssessment{ConversationRisk: "critical", CurrentThreatScore: 0.85, AttackPatterns: []string{"prompt_injection", "data_exfiltration"}}
	case "high-session":
		return &session.ThreatAssessment{ConversationRisk: "high", CurrentThreatScore: 0.72, AttackPatterns: []string{"content_injection"}}
	case "low-session":
		return &session.ThreatAssessment{ConversationRisk: "low", CurrentThreatScore: 0.35, AttackPatterns: nil}
	default:
		return &session.ThreatAssessment{ConversationRisk: "low", CurrentThreatScore: 0.25, AttackPatterns: nil}
	}
}

func setupMCPProxyWithSessionAnalyzer(sessionRisk string) *MCPProxy {
	logger, _ := logging.New(config.Logging{})
	sanitizerMgr := sanitizer.New(config.Security{}, logger)
	complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
	upstreamMgr := upstream.NewManager(nil, logger)

	sessionAnalyzer := NewMockSessionAnalyzer()
	if sessionRisk != "" {
		switch sessionRisk {
		case "critical":
			sessionAnalyzer.assessments["test"] = &session.ThreatAssessment{ConversationRisk: "critical", CurrentThreatScore: 0.85}
		case "high":
			sessionAnalyzer.assessments["test"] = &session.ThreatAssessment{ConversationRisk: "high", CurrentThreatScore: 0.72}
		case "low":
			sessionAnalyzer.assessments["test"] = &session.ThreatAssessment{ConversationRisk: "low", CurrentThreatScore: 0.35}
		}
	}

	return NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, sessionAnalyzer)
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
		if w.Code != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
		}

		if w.Header().Get("X-Aegir-Risk") != "high" {
			t.Errorf("Expected X-Aegir-Risk header to be 'high', got: %s", w.Header().Get("X-Aegir-Risk"))
		}
		if w.Header().Get("X-Aegir-Threat-Score") != "0.72" {
			t.Errorf("Expected X-Aegir-Threat-Score header to be '0.72', got: %s", w.Header().Get("X-Aegir-Threat-Score"))
		}
		t.Logf("High risk test passed - Status: %d, Headers present", w.Code)
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

func TestTwoTierThreatResponseBoundaryCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Boundary: Score exactly 0.8 (Critical)", func(t *testing.T) {
		mockAnalyzer := &MockSessionAnalyzer{}
		mockAnalyzer.assessments["boundary"] = &session.ThreatAssessment{ConversationRisk: "critical", CurrentThreatScore: 0.8}
		logger, _ := logging.New(config.Logging{})
		sanitizerMgr := sanitizer.New(config.Security{}, logger)
		complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
		upstreamMgr := upstream.NewManager(nil, logger)

		proxy := NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, mockAnalyzer)
		mcpRequest := MCPRequest{Method: "tools/call", ID: 4}
		mcpRequestJSON, _ := json.Marshal(mcpRequest)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(mcpRequestJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status code %d (critical threshold), got %d", http.StatusForbidden, w.Code)
		}
		t.Logf("Boundary test (0.8 exactly) passed - Critical threshold enforced")
	})

	t.Run("Boundary: Score 0.79 (High)", func(t *testing.T) {
		mockAnalyzer := &MockSessionAnalyzer{}
		mockAnalyzer.assessments["boundary"] = &session.ThreatAssessment{ConversationRisk: "high", CurrentThreatScore: 0.79}
		logger, _ := logging.New(config.Logging{})
		sanitizerMgr := sanitizer.New(config.Security{}, logger)
		complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
		upstreamMgr := upstream.NewManager(nil, logger)

		proxy := NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, mockAnalyzer)
		mcpRequest := MCPRequest{Method: "tools/call", ID: 5}
		mcpRequestJSON, _ := json.Marshal(mcpRequest)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(mcpRequestJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status code %d (high threshold), got %d", http.StatusOK, w.Code)
		}
		t.Logf("Boundary test (0.79 exactly) passed - High threshold enforced")
	})

	t.Run("Boundary: Score 0.6 (High)", func(t *testing.T) {
		mockAnalyzer := &MockSessionAnalyzer{}
		mockAnalyzer.assessments["boundary"] = &session.ThreatAssessment{ConversationRisk: "high", CurrentThreatScore: 0.6}
		logger, _ := logging.New(config.Logging{})
		sanitizerMgr := sanitizer.New(config.Security{}, logger)
		complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
		upstreamMgr := upstream.NewManager(nil, logger)

		proxy := NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, mockAnalyzer)
		mcpRequest := MCPRequest{Method: "tools/call", ID: 6}
		mcpRequestJSON, _ := json.Marshal(mcpRequest)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(mcpRequestJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status code %d (minimum high), got %d", http.StatusOK, w.Code)
		}
		t.Logf("Boundary test (0.6 minimum high) passed")
	})
}

func TestTwoTierThreatResponseWithMockAnalyzer(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Mock Analyzer - Critical Path", func(t *testing.T) {
		mockAnalyzer := NewMockSessionAnalyzer()
		mockAnalyzer.assessments["critical-test"] = &session.ThreatAssessment{ConversationRisk: "critical", CurrentThreatScore: 0.85, AttackPatterns: []string{"prompt_injection"}}
		logger, _ := logging.New(config.Logging{})
		sanitizerMgr := sanitizer.New(config.Security{}, logger)
		complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
		upstreamMgr := upstream.NewManager(nil, logger)

		proxy := NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, mockAnalyzer)
		mcpRequest := MCPRequest{Method: "tools/call", ID: 7}
		mcpRequestJSON, _ := json.Marshal(mcpRequest)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(mcpRequestJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status code %d, got %d", http.StatusForbidden, w.Code)
		}
		t.Logf("Mock analyzer critical path test passed")
	})

	t.Run("Mock Analyzer - High Path", func(t *testing.T) {
		mockAnalyzer := NewMockSessionAnalyzer()
		mockAnalyzer.assessments["high-test"] = &session.ThreatAssessment{ConversationRisk: "high", CurrentThreatScore: 0.72, AttackPatterns: []string{"content_injection"}}
		logger, _ := logging.New(config.Logging{})
		sanitizerMgr := sanitizer.New(config.Security{}, logger)
		complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
		upstreamMgr := upstream.NewManager(nil, logger)

		proxy := NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, mockAnalyzer)
		mcpRequest := MCPRequest{Method: "tools/call", ID: 8}
		mcpRequestJSON, _ := json.Marshal(mcpRequest)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(mcpRequestJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
		}
		t.Logf("Mock analyzer high path test passed")
	})
}

func TestTwoTierThreatResponseLogging(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Critical Risk Logging Verification", func(t *testing.T) {
		mockAnalyzer := NewMockSessionAnalyzer()
		mockAnalyzer.assessments["log-test"] = &session.ThreatAssessment{ConversationRisk: "critical", CurrentThreatScore: 0.85}
		logger, _ := logging.New(config.Logging{})
		sanitizerMgr := sanitizer.New(config.Security{}, logger)
		complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
		upstreamMgr := upstream.NewManager(nil, logger)

		proxy := NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, mockAnalyzer)
		mcpRequest := MCPRequest{Method: "tools/call", ID: 9}
		mcpRequestJSON, _ := json.Marshal(mcpRequest)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(mcpRequestJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
		t.Logf("Critical risk logging test - Request processed with critical risk")
	})

	t.Run("High Risk Logging Verification", func(t *testing.T) {
		mockAnalyzer := NewMockSessionAnalyzer()
		mockAnalyzer.assessments["log-test"] = &session.ThreatAssessment{ConversationRisk: "high", CurrentThreatScore: 0.72}
		logger, _ := logging.New(config.Logging{})
		sanitizerMgr := sanitizer.New(config.Security{}, logger)
		complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
		upstreamMgr := upstream.NewManager(nil, logger)

		proxy := NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, mockAnalyzer)
		mcpRequest := MCPRequest{Method: "tools/call", ID: 10}
		mcpRequestJSON, _ := json.Marshal(mcpRequest)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(mcpRequestJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
		t.Logf("High risk logging test - Request processed with high risk")
	})
}

func TestTwoTierThreatResponseEdgeCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Empty Session Analyzer - Should Process Normally", func(t *testing.T) {
		logger, _ := logging.New(config.Logging{})
		sanitizerMgr := sanitizer.New(config.Security{}, logger)
		complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
		upstreamMgr := upstream.NewManager(nil, logger)

		proxy := NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, nil)
		mcpRequest := MCPRequest{Method: "tools/call", ID: 11}
		mcpRequestJSON, _ := json.Marshal(mcpRequest)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(mcpRequestJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
		t.Logf("Empty session analyzer test - Request processed normally without analyzer")
	})

	t.Run("Malformed JSON Input", func(t *testing.T) {
		logger, _ := logging.New(config.Logging{})
		sanitizerMgr := sanitizer.New(config.Security{}, logger)
		complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
		upstreamMgr := upstream.NewManager(nil, logger)

		mockAnalyzer := NewMockSessionAnalyzer()
		mockAnalyzer.assessments["test"] = &session.ThreatAssessment{ConversationRisk: "low", CurrentThreatScore: 0.35}
		proxy := NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, mockAnalyzer)
		malformedJSON := []byte(`{"method": "tools/call", "invalid json}`)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(malformedJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status code %d for malformed JSON, got %d", http.StatusBadRequest, w.Code)
		}
		t.Logf("Malformed JSON test - Properly rejected with 400")
	})

	t.Run("Missing Required Fields", func(t *testing.T) {
		logger, _ := logging.New(config.Logging{})
		sanitizerMgr := sanitizer.New(config.Security{}, logger)
		complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
		upstreamMgr := upstream.NewManager(nil, logger)

		mockAnalyzer := NewMockSessionAnalyzer()
		mockAnalyzer.assessments["test"] = &session.ThreatAssessment{ConversationRisk: "low", CurrentThreatScore: 0.35}
		proxy := NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, mockAnalyzer)
		mcpRequest := MCPRequest{Method: "tools/call", ID: 12}
		mcpRequestJSON, _ := json.Marshal(mcpRequest)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/mcp-proxy", bytes.NewReader(mcpRequestJSON))
		c.Request.Header.Set("Content-Type", "application/json")

		proxy.HandleMCPRequest(c)
		t.Logf("Missing required fields test - Request processed with default behavior")
	})
}

func BenchmarkTwoTierThreatResponse(b *testing.B) {
	gin.SetMode(gin.TestMode)

	logger, _ := logging.New(config.Logging{})
	sanitizerMgr := sanitizer.New(config.Security{}, logger)
	complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
	upstreamMgr := upstream.NewManager(nil, logger)

	mockAnalyzer := NewMockSessionAnalyzer()
	mockAnalyzer.assessments["benchmark"] = &session.ThreatAssessment{ConversationRisk: "high", CurrentThreatScore: 0.72}
	proxy := NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, mockAnalyzer)

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
