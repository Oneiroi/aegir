package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/aegishjalmur/mcp-firewall/internal/logging"
	"github.com/aegishjalmur/mcp-firewall/internal/sanitizer"
	"github.com/aegishjalmur/mcp-firewall/internal/upstream"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// MCPProxy handles proxying and securing MCP requests
type MCPProxy struct {
	logger            *logging.Logger
	sanitizer         *sanitizer.Manager
	complianceManager *sanitizer.ComplianceManager
	upstreamManager   *upstream.Manager
	upgrader          websocket.Upgrader
}

// MCPRequest represents an incoming MCP request
type MCPRequest struct {
	Method string      `json:"method"`
	Params interface{} `json:"params"`
	ID     interface{} `json:"id"`
}

// MCPResponse represents an MCP response
type MCPResponse struct {
	Result interface{} `json:"result,omitempty"`
	Error  *MCPError   `json:"error,omitempty"`
	ID     interface{} `json:"id"`
}

// MCPError represents an MCP error
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// NewMCPProxy creates a new MCP proxy instance
func NewMCPProxy(logger *logging.Logger, sanitizerMgr *sanitizer.Manager, complianceMgr *sanitizer.ComplianceManager, upstreamMgr *upstream.Manager) *MCPProxy {
	return &MCPProxy{
		logger:            logger,
		sanitizer:         sanitizerMgr,
		complianceManager: complianceMgr,
		upstreamManager:   upstreamMgr,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// In production, implement proper origin checking
				return true
			},
		},
	}
}

// HandleMCPRequest processes incoming MCP requests with security filtering
func (p *MCPProxy) HandleMCPRequest(c *gin.Context) {
	var req MCPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		p.logger.Error("Invalid MCP request format", "error", err)
		c.JSON(http.StatusBadRequest, MCPResponse{
			Error: &MCPError{
				Code:    -32600,
				Message: "Invalid Request",
				Data:    "Malformed JSON-RPC request",
			},
			ID: req.ID,
		})
		return
	}

	// Log the incoming request
	p.logMCPRequest(c, &req)

	// Serialize params for content inspection
	paramsJSON, err := json.Marshal(req.Params)
	if err != nil {
		p.logger.Error("Failed to serialize MCP params", "error", err)
		c.JSON(http.StatusInternalServerError, MCPResponse{
			Error: &MCPError{
				Code:    -32603,
				Message: "Internal error",
			},
			ID: req.ID,
		})
		return
	}

	// Apply security sanitization
	sanitizationResult := p.sanitizer.SanitizeContent(string(paramsJSON))
	if sanitizationResult.Blocked {
		p.logger.Warn("MCP request blocked by security filter",
			"method", req.Method,
			"risk", sanitizationResult.Risk,
			"detections", len(sanitizationResult.Detections))

		c.JSON(http.StatusForbidden, MCPResponse{
			Error: &MCPError{
				Code:    -32000,
				Message: "Request blocked by security policy",
				Data:    fmt.Sprintf("Risk level: %s", sanitizationResult.Risk),
			},
			ID: req.ID,
		})
		return
	}

	// Apply compliance filtering
	complianceResult := p.complianceManager.ScanForCompliance(string(paramsJSON))
	if complianceResult.ComplianceRisk == "critical" || complianceResult.ComplianceRisk == "high" {
		p.logger.Warn("MCP request blocked by compliance filter",
			"method", req.Method,
			"violations", len(complianceResult.Violations))

		c.JSON(http.StatusForbidden, MCPResponse{
			Error: &MCPError{
				Code:    -32001,
				Message: "Request blocked by compliance policy",
				Data:    "Contains regulated data that cannot be processed",
			},
			ID: req.ID,
		})
		return
	}

	// Additional URI validation for resources/read
	if req.Method == "resources/read" {
		if paramsMap, ok := req.Params.(map[string]interface{}); ok {
			if uri, ok := paramsMap["uri"].(string); ok {
				if err := p.validateResourceURI(uri); err != nil {
					c.JSON(http.StatusForbidden, MCPResponse{
						Error: &MCPError{
							Code:    -32000,
							Message: "Resource access denied",
							Data:    err.Error(),
						},
						ID: req.ID,
					})
					return
				}
			}
		}
	}

	// Sanitize the params if needed
	if sanitizationResult.Sanitized != string(paramsJSON) {
		var sanitizedParams interface{}
		if err := json.Unmarshal([]byte(sanitizationResult.Sanitized), &sanitizedParams); err != nil {
			p.logger.Error("Failed to parse sanitized params", "error", err)
			c.JSON(http.StatusInternalServerError, MCPResponse{
				Error: &MCPError{
					Code:    -32603,
					Message: "Internal error",
				},
				ID: req.ID,
			})
			return
		}
		req.Params = sanitizedParams
	}

	// Forward the sanitized request to upstream services
	upstreamReq := &upstream.MCPRequest{
		Method: req.Method,
		Params: req.Params,
		ID:     req.ID,
	}

	upstreamResp, err := p.upstreamManager.ForwardRequest(c.Request.Context(), upstreamReq)
	if err != nil {
		p.logger.Error("Failed to forward request to upstream", "error", err)
		c.JSON(http.StatusBadGateway, MCPResponse{
			Error: &MCPError{
				Code:    -32002,
				Message: "Upstream service unavailable",
				Data:    err.Error(),
			},
			ID: req.ID,
		})
		return
	}

	// Convert upstream response to our response format
	response := &MCPResponse{
		Result: upstreamResp.Result,
		Error:  (*MCPError)(upstreamResp.Error),
		ID:     upstreamResp.ID,
	}

	// Sanitize response before returning
	responseJSON, _ := json.Marshal(response.Result)
	responseSanitized := p.sanitizer.SanitizeContent(string(responseJSON))

	if responseSanitized.Sanitized != string(responseJSON) {
		var sanitizedResult interface{}
		if err := json.Unmarshal([]byte(responseSanitized.Sanitized), &sanitizedResult); err == nil {
			response.Result = sanitizedResult
		}
	}

	c.JSON(http.StatusOK, response)
}

// HandleServiceStatus returns the status of upstream services
func (p *MCPProxy) HandleServiceStatus(c *gin.Context) {
	status := p.upstreamManager.GetServiceStatus()
	c.JSON(http.StatusOK, gin.H{
		"upstream_services": status,
		"timestamp":         time.Now().UTC(),
	})
}

// processMCPMethod handles different MCP method types
func (p *MCPProxy) processMCPMethod(ctx context.Context, req *MCPRequest) *MCPResponse {
	switch req.Method {
	case "initialize":
		return p.handleInitialize(ctx, req)
	case "resources/list":
		return p.handleResourcesList(ctx, req)
	case "resources/read":
		return p.handleResourcesRead(ctx, req)
	case "tools/list":
		return p.handleToolsList(ctx, req)
	case "tools/call":
		return p.handleToolsCall(ctx, req)
	case "prompts/list":
		return p.handlePromptsList(ctx, req)
	case "prompts/get":
		return p.handlePromptsGet(ctx, req)
	default:
		return &MCPResponse{
			Error: &MCPError{
				Code:    -32601,
				Message: "Method not found",
				Data:    fmt.Sprintf("Unknown method: %s", req.Method),
			},
			ID: req.ID,
		}
	}
}

// handleInitialize processes MCP initialize requests
func (p *MCPProxy) handleInitialize(ctx context.Context, req *MCPRequest) *MCPResponse {
	// Return initialization response with security capabilities
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"logging": map[string]interface{}{
				"level": "info",
			},
			"security": map[string]interface{}{
				"content_filtering": true,
				"compliance_scanning": true,
				"rate_limiting": true,
			},
		},
		"serverInfo": map[string]interface{}{
			"name":    "MCP Security Firewall",
			"version": "1.0.0",
		},
	}

	return &MCPResponse{
		Result: result,
		ID:     req.ID,
	}
}

// handleResourcesList processes resources/list requests
func (p *MCPProxy) handleResourcesList(ctx context.Context, req *MCPRequest) *MCPResponse {
	// In a real implementation, this would proxy to upstream MCP servers
	// For now, return empty list with security notice
	result := map[string]interface{}{
		"resources": []interface{}{},
		"_meta": map[string]interface{}{
			"security_filtered": true,
			"compliance_checked": true,
		},
	}

	return &MCPResponse{
		Result: result,
		ID:     req.ID,
	}
}

// handleResourcesRead processes resources/read requests
func (p *MCPProxy) handleResourcesRead(ctx context.Context, req *MCPRequest) *MCPResponse {
	// Validate params
	paramsMap, ok := req.Params.(map[string]interface{})
	if !ok {
		return &MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}
	}

	uri, ok := paramsMap["uri"].(string)
	if !ok {
		return &MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: "Missing required parameter: uri",
			},
			ID: req.ID,
		}
	}

	// Validate URI for security
	if err := p.validateResourceURI(uri); err != nil {
		return &MCPResponse{
			Error: &MCPError{
				Code:    -32000,
				Message: "Resource access denied",
				Data:    err.Error(),
			},
			ID: req.ID,
		}
	}

	// For demo purposes, return a placeholder response
	result := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"uri":      uri,
				"mimeType": "text/plain",
				"text":     "Resource content filtered by MCP Firewall",
			},
		},
	}

	return &MCPResponse{
		Result: result,
		ID:     req.ID,
	}
}

// handleToolsList processes tools/list requests
func (p *MCPProxy) handleToolsList(ctx context.Context, req *MCPRequest) *MCPResponse {
	// Return filtered tools list
	tools := []interface{}{
		map[string]interface{}{
			"name":        "security_scan",
			"description": "Scan content for security issues",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"content": map[string]interface{}{
						"type":        "string",
						"description": "Content to scan",
					},
				},
				"required": []string{"content"},
			},
		},
	}

	result := map[string]interface{}{
		"tools": tools,
	}

	return &MCPResponse{
		Result: result,
		ID:     req.ID,
	}
}

// handleToolsCall processes tools/call requests
func (p *MCPProxy) handleToolsCall(ctx context.Context, req *MCPRequest) *MCPResponse {
	paramsMap, ok := req.Params.(map[string]interface{})
	if !ok {
		return &MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}
	}

	name, ok := paramsMap["name"].(string)
	if !ok {
		return &MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: "Missing required parameter: name",
			},
			ID: req.ID,
		}
	}

	if name == "security_scan" {
		return p.handleSecurityScanTool(ctx, req, paramsMap)
	}

	return &MCPResponse{
		Error: &MCPError{
			Code:    -32601,
			Message: "Tool not found",
			Data:    fmt.Sprintf("Unknown tool: %s", name),
		},
		ID: req.ID,
	}
}

// handleSecurityScanTool implements the security_scan tool
func (p *MCPProxy) handleSecurityScanTool(ctx context.Context, req *MCPRequest, params map[string]interface{}) *MCPResponse {
	arguments, ok := params["arguments"].(map[string]interface{})
	if !ok {
		return &MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: "Invalid arguments",
			},
			ID: req.ID,
		}
	}

	inputContent, ok := arguments["content"].(string)
	if !ok {
		return &MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: "Missing required argument: content",
			},
			ID: req.ID,
		}
	}

	// Perform security scan
	sanitizationResult := p.sanitizer.SanitizeContent(inputContent)
	complianceResult := p.complianceManager.ScanForCompliance(inputContent)

	scanResults := fmt.Sprintf("Security Scan Results:\n"+
		"Risk Level: %s\n"+
		"Detections: %d\n"+
		"Compliance Risk: %s\n"+
		"Violations: %d\n"+
		"Sanitized: %t",
		sanitizationResult.Risk,
		len(sanitizationResult.Detections),
		complianceResult.ComplianceRisk,
		len(complianceResult.Violations),
		sanitizationResult.Sanitized != inputContent)

	responseContent := []interface{}{
		map[string]interface{}{
			"type": "text",
			"text": scanResults,
		},
	}

	result := map[string]interface{}{
		"content": responseContent,
		"isError": false,
	}

	return &MCPResponse{
		Result: result,
		ID:     req.ID,
	}
}

// handlePromptsList processes prompts/list requests
func (p *MCPProxy) handlePromptsList(ctx context.Context, req *MCPRequest) *MCPResponse {
	result := map[string]interface{}{
		"prompts": []map[string]interface{}{
			{
				"name":        "security_analysis",
				"description": "Analyze content for security issues",
				"arguments": []map[string]interface{}{
					{
						"name":        "content",
						"description": "Content to analyze",
						"required":    true,
					},
				},
			},
		},
	}

	return &MCPResponse{
		Result: result,
		ID:     req.ID,
	}
}

// handlePromptsGet processes prompts/get requests
func (p *MCPProxy) handlePromptsGet(ctx context.Context, req *MCPRequest) *MCPResponse {
	paramsMap, ok := req.Params.(map[string]interface{})
	if !ok {
		return &MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}
	}

	name, ok := paramsMap["name"].(string)
	if !ok {
		return &MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: "Missing required parameter: name",
			},
			ID: req.ID,
		}
	}

	if name == "security_analysis" {
		arguments := paramsMap["arguments"].(map[string]interface{})
		content := arguments["content"].(string)

		result := map[string]interface{}{
			"description": "Security analysis prompt",
			"messages": []map[string]interface{}{
				{
					"role": "user",
					"content": map[string]interface{}{
						"type": "text",
						"text": fmt.Sprintf("Please analyze this content for security issues: %s", content),
					},
				},
			},
		}

		return &MCPResponse{
			Result: result,
			ID:     req.ID,
		}
	}

	return &MCPResponse{
		Error: &MCPError{
			Code:    -32601,
			Message: "Prompt not found",
		},
		ID: req.ID,
	}
}

// HandleWebSocket handles WebSocket connections for MCP
func (p *MCPProxy) HandleWebSocket(c *gin.Context) {
	conn, err := p.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		p.logger.Error("WebSocket upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	p.logger.Info("WebSocket connection established", "remote_addr", conn.RemoteAddr())

	// Handle WebSocket messages
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			p.logger.Error("WebSocket read error", "error", err)
			break
		}

		// Process the message through security filters
		sanitized := p.sanitizer.SanitizeContent(string(message))

		if sanitized.Blocked {
			// Send error response for blocked content
			errorResponse := MCPResponse{
				Error: &MCPError{
					Code:    -32000,
					Message: "Message blocked by security policy",
				},
			}

			errorJSON, _ := json.Marshal(errorResponse)
			conn.WriteMessage(messageType, errorJSON)
			continue
		}

		// Echo back the sanitized message (in a real implementation, this would proxy to upstream)
		if err := conn.WriteMessage(messageType, []byte(sanitized.Sanitized)); err != nil {
			p.logger.Error("WebSocket write error", "error", err)
			break
		}
	}

	p.logger.Info("WebSocket connection closed", "remote_addr", conn.RemoteAddr())
}

// HandleSSE handles Server-Sent Events connections for MCP
func (p *MCPProxy) HandleSSE(c *gin.Context) {
	// Set SSE headers
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Headers", "Cache-Control")

	// Get the response writer
	w := c.Writer

	p.logger.Info("SSE connection established", "remote_addr", c.ClientIP())

	// Send initial connection event
	fmt.Fprintf(w, "event: connection\n")
	fmt.Fprintf(w, "data: {\"type\":\"connection\",\"status\":\"established\"}\n\n")
	w.Flush()

	// Handle incoming POST data for requests
	if c.Request.Method == "POST" {
		var mcpRequest MCPRequest
		if err := c.ShouldBindJSON(&mcpRequest); err != nil {
			p.logger.Error("SSE request parsing failed", "error", err)
			fmt.Fprintf(w, "event: error\n")
			fmt.Fprintf(w, "data: {\"error\":\"Invalid JSON request\"}\n\n")
			w.Flush()
			return
		}

		// Process the request through security filters
		requestJSON, _ := json.Marshal(mcpRequest)
		sanitized := p.sanitizer.SanitizeContent(string(requestJSON))

		if sanitized.Blocked {
			errorResponse := MCPResponse{
				Error: &MCPError{
					Code:    -32000,
					Message: "Request blocked by security policy",
				},
				ID: mcpRequest.ID,
			}
			responseJSON, _ := json.Marshal(errorResponse)
			fmt.Fprintf(w, "event: response\n")
			fmt.Fprintf(w, "data: %s\n\n", responseJSON)
			w.Flush()
			return
		}

		// Process the MCP request
		response := p.processMCPMethod(c.Request.Context(), &mcpRequest)
		responseJSON, _ := json.Marshal(response)

		// Send response as SSE event
		fmt.Fprintf(w, "event: response\n")
		fmt.Fprintf(w, "data: %s\n\n", responseJSON)
		w.Flush()
	}

	p.logger.Info("SSE connection closed", "remote_addr", c.ClientIP())
}

// HandleSSEEvents handles bidirectional SSE communication
func (p *MCPProxy) HandleSSEEvents(c *gin.Context) {
	// Set SSE headers
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Headers", "Cache-Control")

	w := c.Writer
	ctx := c.Request.Context()

	p.logger.Info("SSE event stream established", "remote_addr", c.ClientIP())

	// Send initial connection event
	fmt.Fprintf(w, "event: connection\n")
	fmt.Fprintf(w, "data: {\"type\":\"connection\",\"status\":\"established\"}\n\n")
	w.Flush()

	// Keep connection alive and handle context cancellation
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("SSE connection context cancelled", "remote_addr", c.ClientIP())
			return
		case <-ticker.C:
			// Send keep-alive ping
			fmt.Fprintf(w, "event: ping\n")
			fmt.Fprintf(w, "data: {\"type\":\"ping\",\"timestamp\":\"%s\"}\n\n", time.Now().Format(time.RFC3339))
			w.Flush()
		}
	}
}

// validateResourceURI validates resource URIs for security
func (p *MCPProxy) validateResourceURI(uri string) error {
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid URI format")
	}

	// Block dangerous schemes
	switch parsedURL.Scheme {
	case "file":
		return fmt.Errorf("file:// URIs are not allowed")
	case "javascript":
		return fmt.Errorf("javascript: URIs are not allowed")
	case "data":
		return fmt.Errorf("data: URIs are not allowed")
	}

	// Validate hostname if present
	if parsedURL.Host != "" {
		// Could add hostname whitelist/blacklist here
		if parsedURL.Host == "localhost" || parsedURL.Host == "127.0.0.1" {
			return fmt.Errorf("localhost URIs are not allowed")
		}
	}

	return nil
}

// logMCPRequest logs MCP requests for audit purposes
func (p *MCPProxy) logMCPRequest(c *gin.Context, req *MCPRequest) {
	event := &logging.SecurityEvent{
		Type:      "mcp_request",
		Severity:  "info",
		Message:   "MCP request received",
		ClientIP:  c.ClientIP(),
		UserID:    p.getUserID(c),
		Timestamp: time.Now(),
		Details: map[string]string{
			"method":     req.Method,
			"user_agent": c.Request.UserAgent(),
		},
	}

	p.logger.LogSecurityEvent(event)
}

// getUserID extracts user ID from context
func (p *MCPProxy) getUserID(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(string); ok {
			return uid
		}
	}
	return "anonymous"
}