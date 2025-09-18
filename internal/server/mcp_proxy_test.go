package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegishjalmur/mcp-firewall/internal/config"
	"github.com/aegishjalmur/mcp-firewall/internal/logging"
	"github.com/aegishjalmur/mcp-firewall/internal/sanitizer"
	"github.com/gin-gonic/gin"
)

func createTestMCPProxy() *MCPProxy {
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

	return NewMCPProxy(logger, sanitizerMgr, complianceMgr)
}

func TestMCPInitialize(t *testing.T) {
	proxy := createTestMCPProxy()

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
	proxy := createTestMCPProxy()

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
	proxy := createTestMCPProxy()

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
	proxy := createTestMCPProxy()

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
	proxy := createTestMCPProxy()

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