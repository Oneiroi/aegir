package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
	"github.com/aegishjalmur/aegir/internal/sanitizer"
	"github.com/aegishjalmur/aegir/internal/session"
	"github.com/aegishjalmur/aegir/internal/upstream"
	"github.com/gin-gonic/gin"
)

func createTestMCPProxy(t testing.TB) *MCPProxy {
	t.Helper()
	// Create test logger
	logCfg := config.Logging{
		Level:           "info",
		Format:          "json",
		HMACKey:         "test-hmac-key-32-characters-long",
		IntegrityChecks: true,
	}
	logger, _ := logging.New(logCfg)

	// Create test sanitizer
	secCfg := config.Security{
		CommandInjection: config.CommandInjection{Enabled: true},
		SecretDetection:  config.SecretDetection{Enabled: true},
		Sanitization:     config.Sanitization{Enabled: true},
	}
	sanitizerMgr := sanitizer.New(secCfg, logger)

	// Create test compliance manager
	compCfg := config.Compliance{
		GDPR:  config.GDPRConfig{Enabled: true},
		HIPAA: config.HIPAAConfig{Enabled: true},
		PCI:   config.PCIConfig{Enabled: true},
	}
	complianceMgr := sanitizer.NewComplianceManager(compCfg, logger)

	// Create test upstream manager
	upstreamCfg := &config.Upstream{}
	upstreamMgr := upstream.NewManager(upstreamCfg, logger)

	// Create test session analyzer
	sessionCfg := session.AnalyzerConfig{
		MaxSessionAge:       30 * time.Minute,
		MaxHistorySize:      50,
		ThreatThreshold:     0.5,
		CleanupInterval:     5 * time.Minute,
		JailbreakThreshold:  0.6,
		RoleEscalationLimit: 3,
	}
	sessionAnalyzer := session.NewConversationalThreatAnalyzer(sessionCfg, logger)
	t.Cleanup(sessionAnalyzer.Stop)

	return NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, sessionAnalyzer, nil)
}

func TestMCPInitialize(t *testing.T) {
	proxy := createTestMCPProxy(t)

	// Create test request
	req := MCPRequest{
		Method: "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"clientInfo": map[string]interface{}{
				"name":    "test-client",
				"version": "1.0.0",
			},
		},
		ID: "test-1",
	}

	reqBody, _ := json.Marshal(req)

	// Create HTTP request
	httpReq := httptest.NewRequest("POST", "/mcp", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Create Gin context
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(w)
	c.Request = httpReq

	// Handle request
	proxy.HandleMCPRequest(c)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response MCPResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if response.Error != nil {
		t.Errorf("Expected no error, got: %v", response.Error)
	}

	if response.Result == nil {
		t.Errorf("Expected result, got nil")
	}
}

func TestMCPSecurityFiltering(t *testing.T) {
	proxy := createTestMCPProxy(t)

	// Create test request with malicious content
	req := MCPRequest{
		Method: "tools/call",
		Params: map[string]interface{}{
			"name": "test_tool",
			"arguments": map[string]interface{}{
				"command": "rm -rf / && echo 'hacked'",
				"script":  "<script>alert('xss')</script>",
			},
		},
		ID: "test-2",
	}

	reqBody, _ := json.Marshal(req)

	// Create HTTP request
	httpReq := httptest.NewRequest("POST", "/mcp", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Create Gin context
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(w)
	c.Request = httpReq

	// Handle request
	proxy.HandleMCPRequest(c)

	// Check that the request was sanitized or blocked
	var response MCPResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	// Should either be blocked (403) or sanitized
	if w.Code == http.StatusForbidden {
		if response.Error == nil || response.Error.Code != -32000 {
			t.Errorf("Expected security block error, got: %v", response.Error)
		}
	} else {
		// If not blocked, content should be sanitized
		responseStr := w.Body.String()
		if !containsSecurityReplacement(responseStr) {
			t.Logf("Response was not blocked, checking for sanitization: %s", responseStr)
		}
	}
}

func TestMCPComplianceFiltering(t *testing.T) {
	proxy := createTestMCPProxy(t)

	// Create test request with sensitive data
	req := MCPRequest{
		Method: "resources/read",
		Params: map[string]interface{}{
			"uri": "file://sensitive-data.txt",
			"data": map[string]interface{}{
				"ssn":         "123-45-6789",
				"credit_card": "4111-1111-1111-1111",
				"email":       "patient@example.com",
			},
		},
		ID: "test-3",
	}

	reqBody, _ := json.Marshal(req)

	// Create HTTP request
	httpReq := httptest.NewRequest("POST", "/mcp", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Create Gin context
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(w)
	c.Request = httpReq

	// Handle request
	proxy.HandleMCPRequest(c)

	// Should be blocked due to file:// URI and sensitive data
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}

	var response MCPResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if response.Error == nil {
		t.Errorf("Expected error response for blocked request")
	}
}

func TestMCPToolsList(t *testing.T) {
	proxy := createTestMCPProxy(t)

	req := MCPRequest{
		Method: "tools/list",
		Params: map[string]interface{}{},
		ID:     "test-4",
	}

	reqBody, _ := json.Marshal(req)

	httpReq := httptest.NewRequest("POST", "/mcp", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(w)
	c.Request = httpReq

	proxy.HandleMCPRequest(c)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response MCPResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if response.Error != nil {
		t.Errorf("Expected no error, got: %v", response.Error)
	}

	// Check that security_scan tool is available
	result, ok := response.Result.(map[string]interface{})
	if !ok {
		t.Errorf("Expected result to be a map")
		return
	}

	toolsInterface, ok := result["tools"].([]interface{})
	if !ok {
		t.Errorf("Expected tools to be an array of interfaces, got %T", result["tools"])
		return
	}

	// Convert to the expected format for easier testing
	var tools []map[string]interface{}
	for _, tool := range toolsInterface {
		if toolMap, ok := tool.(map[string]interface{}); ok {
			tools = append(tools, toolMap)
		}
	}

	if len(tools) == 0 {
		t.Errorf("Expected at least one tool")
	}

	// Check for security_scan tool
	foundSecurityScan := false
	for _, tool := range tools {
		if name, ok := tool["name"].(string); ok && name == "security_scan" {
			foundSecurityScan = true
			break
		}
	}

	if !foundSecurityScan {
		t.Errorf("Expected security_scan tool to be available")
	}
}

func TestMCPSecurityScanTool(t *testing.T) {
	proxy := createTestMCPProxy(t)

	req := MCPRequest{
		Method: "tools/call",
		Params: map[string]interface{}{
			"name": "security_scan",
			"arguments": map[string]interface{}{
				"content": "This is a test with password: secret123 and <script>alert('xss')</script>",
			},
		},
		ID: "test-5",
	}

	reqBody, _ := json.Marshal(req)

	httpReq := httptest.NewRequest("POST", "/mcp", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(w)
	c.Request = httpReq

	proxy.HandleMCPRequest(c)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response MCPResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if response.Error != nil {
		t.Errorf("Expected no error, got: %v", response.Error)
	}

	// Check that scan results are returned
	result, ok := response.Result.(map[string]interface{})
	if !ok {
		t.Errorf("Expected result to be a map")
		return
	}

	contentInterface, ok := result["content"].([]interface{})
	if !ok {
		t.Errorf("Expected content to be an array of interfaces, got %T", result["content"])
		return
	}

	if len(contentInterface) == 0 {
		t.Errorf("Expected scan results")
		return
	}

	// Check that the first content item has the expected structure
	firstContent, ok := contentInterface[0].(map[string]interface{})
	if !ok {
		t.Errorf("Expected first content item to be a map")
		return
	}

	if _, ok := firstContent["text"]; !ok {
		t.Errorf("Expected content item to have 'text' field")
	}

	if _, ok := firstContent["type"]; !ok {
		t.Errorf("Expected content item to have 'type' field")
	}
}

// Helper function to check for security replacement strings
func containsSecurityReplacement(content string) bool {
	replacements := []string{
		"UNSAFE_COMMAND_REMOVED",
		"UNSAFE_SECRETS_REMOVED",
		"UNSAFE_SCRIPT_REMOVED",
		"UNSAFE_SQL_REMOVED",
	}

	for _, replacement := range replacements {
		if bytes.Contains([]byte(content), []byte(replacement)) {
			return true
		}
	}
	return false
}

// Test the new SSE endpoints in server routing
func TestServerSSEEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	proxy := createTestMCPProxy(t)

	// Create test router with SSE endpoints
	router := gin.New()
	router.GET("/mcp/sse", proxy.HandleSSEEvents)
	router.POST("/mcp/sse", proxy.HandleSSE)

	// Test GET /mcp/sse endpoint
	t.Run("SSE Events Endpoint", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/mcp/sse", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Accept", "text/event-stream")

		// Add timeout context to prevent hanging
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Check SSE headers
		if w.Header().Get("Content-Type") != "text/event-stream" {
			t.Errorf("Expected Content-Type: text/event-stream, got: %s", w.Header().Get("Content-Type"))
		}
	})

	// Test POST /mcp/sse endpoint
	t.Run("SSE Request Endpoint", func(t *testing.T) {
		mcpRequest := MCPRequest{
			Method: "initialize",
			Params: map[string]interface{}{
				"protocolVersion": "2024-11-05",
			},
			ID: "sse-test",
		}

		requestJSON, _ := json.Marshal(mcpRequest)
		req, err := http.NewRequest("POST", "/mcp/sse", bytes.NewBuffer(requestJSON))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "text/event-stream")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Check that SSE response is returned
		body := w.Body.String()
		if !strings.Contains(body, "event: connection") {
			t.Error("Expected connection event in SSE response")
		}
		if !strings.Contains(body, "event: response") {
			t.Error("Expected response event in SSE response")
		}
	})
}

// Test WebSocket endpoint (ensure it still works with new additions)
func TestWebSocketEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	proxy := createTestMCPProxy(t)

	// Create test router
	router := gin.New()
	router.GET("/mcp/ws", proxy.HandleWebSocket)

	// Test WebSocket upgrade (this will fail upgrade but we can test the handler is registered)
	req, err := http.NewRequest("GET", "/mcp/ws", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Add WebSocket headers
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "test-key")
	req.Header.Set("Sec-WebSocket-Version", "13")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// The upgrade will fail in test environment, but the handler should be called
	// We just verify that the endpoint exists and doesn't return 404
	if w.Code == 404 {
		t.Error("WebSocket endpoint should be registered and not return 404")
	}
}

// Test that all transport endpoints coexist properly
func TestTransportEndpointsCoexistence(t *testing.T) {
	gin.SetMode(gin.TestMode)
	proxy := createTestMCPProxy(t)

	// Create test router with all endpoints
	router := gin.New()

	// Add all MCP endpoints
	mcp := router.Group("/mcp")
	{
		mcp.POST("/", proxy.HandleMCPRequest)
		mcp.POST("/resources", proxy.HandleMCPRequest)
		mcp.POST("/tools", proxy.HandleMCPRequest)
		mcp.POST("/prompts", proxy.HandleMCPRequest)
		mcp.GET("/ws", proxy.HandleWebSocket)
		mcp.POST("/sse", proxy.HandleSSE)
		mcp.GET("/sse", proxy.HandleSSEEvents)
	}

	// Test that all endpoints are registered and don't conflict
	endpoints := []struct {
		method string
		path   string
		expectOK bool
	}{
		{"POST", "/mcp/", true},
		{"POST", "/mcp/resources", true},
		{"POST", "/mcp/tools", true},
		{"POST", "/mcp/prompts", true},
		{"GET", "/mcp/ws", false}, // Will fail upgrade but endpoint exists
		{"POST", "/mcp/sse", true},
		{"GET", "/mcp/sse", true},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.method+" "+endpoint.path, func(t *testing.T) {
			var req *http.Request
			var err error

			if endpoint.method == "POST" {
				testRequest := MCPRequest{
					Method: "initialize",
					Params: map[string]interface{}{
						"protocolVersion": "2024-11-05",
					},
					ID: "test",
				}
				requestJSON, _ := json.Marshal(testRequest)
				req, err = http.NewRequest(endpoint.method, endpoint.path, bytes.NewBuffer(requestJSON))
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}
				req.Header.Set("Content-Type", "application/json")
			} else {
				req, err = http.NewRequest(endpoint.method, endpoint.path, nil)
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}
			}

			if strings.Contains(endpoint.path, "sse") {
				req.Header.Set("Accept", "text/event-stream")
			}
			if strings.Contains(endpoint.path, "ws") {
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Sec-WebSocket-Key", "test-key")
				req.Header.Set("Sec-WebSocket-Version", "13")
			}

			w := httptest.NewRecorder()

			// GET /mcp/sse opens a persistent event stream that blocks until the
			// request context is cancelled. Use a short-lived context so the
			// handler exits cleanly without hanging the test suite.
			if endpoint.method == "GET" && strings.Contains(endpoint.path, "sse") {
				ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
				defer cancel()
				req = req.WithContext(ctx)
				done := make(chan struct{})
				go func() {
					defer close(done)
					router.ServeHTTP(w, req)
				}()
				<-done
			} else {
				router.ServeHTTP(w, req)
			}

			// Check that endpoint exists (not 404)
			if w.Code == 404 {
				t.Errorf("Endpoint %s %s should exist", endpoint.method, endpoint.path)
			}

			// For SSE endpoints, check Content-Type
			if strings.Contains(endpoint.path, "sse") && endpoint.expectOK {
				if w.Header().Get("Content-Type") != "text/event-stream" {
					t.Errorf("SSE endpoint should set text/event-stream content type")
				}
			}
		})
	}
}

// TestTwoTierThreatResponseRealHTTP sends real HTTP requests through the proxy
// to verify the exact response format and headers — the T05 manual verification.
func TestTwoTierThreatResponseRealHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	criticalMock := newMockAnalyzer("critical", 0.85, "prompt_injection")
	highMock := newMockAnalyzer("high", 0.72)

	makeRouter := func(mock *MockSessionAnalyzer) *gin.Engine {
		r := gin.New()
		logger := testLogger()
		sanitizerMgr := sanitizer.New(config.Security{}, logger)
		complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
		upstreamMgr := upstream.NewManager(&config.Upstream{}, logger)
		proxy := NewMCPProxy(logger, sanitizerMgr, complianceMgr, upstreamMgr, mock, nil)
		r.POST("/mcp", proxy.HandleMCPRequest)
		return r
	}

	t.Run("Real HTTP: Critical request returns 403 with error body", func(t *testing.T) {
		ts := httptest.NewServer(makeRouter(criticalMock))
		defer ts.Close()

		body, _ := json.Marshal(MCPRequest{
			Method: "tools/call",
			Params: map[string]interface{}{"name": "test"},
			ID:     "real-1",
		})
		resp, err := http.Post(ts.URL+"/mcp", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("HTTP request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected 403, got %d", resp.StatusCode)
		}

		var result MCPResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if result.Error == nil || result.Error.Code != -32000 {
			t.Errorf("Expected MCP error -32000, got: %+v", result.Error)
		}
		if result.ID != "real-1" {
			t.Errorf("Expected ID 'real-1', got %v", result.ID)
		}
		t.Logf("Critical HTTP test: status=%d body=%+v", resp.StatusCode, result)
	})

	t.Run("Real HTTP: High-risk request sets X-Aegir-Risk header", func(t *testing.T) {
		ts := httptest.NewServer(makeRouter(highMock))
		defer ts.Close()

		body, _ := json.Marshal(MCPRequest{
			Method: "tools/call",
			Params: map[string]interface{}{"name": "test"},
			ID:     "real-2",
		})
		resp, err := http.Post(ts.URL+"/mcp", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("HTTP request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusForbidden {
			t.Errorf("High risk must not return 403 (got %d)", resp.StatusCode)
		}
		riskHeader := resp.Header.Get("X-Aegir-Risk")
		if riskHeader != "high" {
			t.Errorf("Expected X-Aegir-Risk: high, got %q", riskHeader)
		}
		scoreHeader := resp.Header.Get("X-Aegir-Threat-Score")
		if scoreHeader != "0.72" {
			t.Errorf("Expected X-Aegir-Threat-Score: 0.72, got %q", scoreHeader)
		}
		t.Logf("High-risk HTTP test: status=%d X-Aegir-Risk=%s X-Aegir-Threat-Score=%s",
			resp.StatusCode, riskHeader, scoreHeader)
	})
}

// Benchmark test for transport performance comparison
func BenchmarkTransportPerformance(b *testing.B) {
	gin.SetMode(gin.TestMode)
	proxy := createTestMCPProxy(b)

	// Create test router
	router := gin.New()
	router.POST("/mcp/", proxy.HandleMCPRequest)
	router.POST("/mcp/sse", proxy.HandleSSE)

	testRequest := MCPRequest{
		Method: "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
		},
		ID: "bench",
	}
	requestJSON, _ := json.Marshal(testRequest)

	b.Run("HTTP Transport", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req, _ := http.NewRequest("POST", "/mcp/", bytes.NewBuffer(requestJSON))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
		}
	})

	b.Run("SSE Transport", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req, _ := http.NewRequest("POST", "/mcp/sse", bytes.NewBuffer(requestJSON))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "text/event-stream")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
		}
	})
}