package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/aegishjalmur/aegir/internal/logging"
	"github.com/aegishjalmur/aegir/internal/sanitizer"
	"github.com/aegishjalmur/aegir/internal/session"
	"github.com/aegishjalmur/aegir/internal/upstream"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// MCPProxy handles proxying and securing MCP requests
type MCPProxy struct {
	logger            *logging.Logger
	sanitizer         *sanitizer.Manager
	complianceManager *sanitizer.ComplianceManager
	upstreamManager   *upstream.Manager
	sessionAnalyzer   *session.ConversationalThreatAnalyzer
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
func NewMCPProxy(logger *logging.Logger, sanitizerMgr *sanitizer.Manager, complianceMgr *sanitizer.ComplianceManager, upstreamMgr *upstream.Manager, sessionAnalyzer *session.ConversationalThreatAnalyzer) *MCPProxy {
	return &MCPProxy{
		logger:            logger,
		sanitizer:         sanitizerMgr,
		complianceManager: complianceMgr,
		upstreamManager:   upstreamMgr,
		sessionAnalyzer:   sessionAnalyzer,
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

	// Session analysis (if enabled) - BEFORE sanitization
	if p.sessionAnalyzer != nil {
		sessionID := p.getSessionID(c)
		userID := p.getUserID(c)

		// Serialize params for session analysis
		paramsJSON, _ := json.Marshal(req.Params)
		assessment := p.sessionAnalyzer.AnalyzeMessage(sessionID, userID, string(paramsJSON))

		// Two-tier threat response:
		// Critical risk (score >= 0.8): Hard block with 403
		if assessment.ConversationRisk == "critical" {
			p.logger.Warn("MCP request blocked by session analyzer (CRITICAL)",
				"session_id", sessionID,
				"user_id", userID,
				"threat_score", assessment.CurrentThreatScore,
				"risk_level", "critical",
				"response_path", "block-with-403",
				"decision_rationale", fmt.Sprintf("Score %.2f >= 0.8 threshold - immediate block required", assessment.CurrentThreatScore),
				"patterns", assessment.AttackPatterns)

			c.JSON(http.StatusForbidden, MCPResponse{
				Error: &MCPError{
					Code:    -32000,
					Message: "Request blocked by threat detection",
					Data:    fmt.Sprintf("Risk level: %s (critical)", assessment.ConversationRisk),
				},
				ID: req.ID,
			})
			return
		}

		// High risk (score 0.6-0.79): Maximum sanitization, forward with X-Aegir-Risk header
		if assessment.ConversationRisk == "high" {
			p.logger.Warn("MCP request forwarded with high risk sanitization",
				"session_id", sessionID,
				"user_id", userID,
				"threat_score", assessment.CurrentThreatScore,
				"risk_level", "high",
				"response_path", "sanitize-and-forward-with-header",
				"decision_rationale", fmt.Sprintf("Score %.2f in 0.6-0.79 range - sanitize and forward with risk header", assessment.CurrentThreatScore),
				"patterns", assessment.AttackPatterns)

			// Apply maximum sanitization to params
			maxSanitized := p.sanitizer.SanitizeContent(string(paramsJSON)) // Maximum aggressiveness is default
			if maxSanitized.Sanitized != string(paramsJSON) {
				var sanitizedParams interface{}
				if err := json.Unmarshal([]byte(maxSanitized.Sanitized), &sanitizedParams); err == nil {
					req.Params = sanitizedParams
				}
			}

			// Set X-Aegir-Risk header for downstream awareness
			c.Header("X-Aegir-Risk", "high")
			c.Header("X-Aegir-Threat-Score", fmt.Sprintf("%.2f", assessment.CurrentThreatScore))
		}
	}

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
		// Fall back to local handling for some methods, or return error
		if req.Method == "initialize" {
			// Handle initialization locally since firewall needs to inject its capabilities
			response := p.handleInitialize(c.Request.Context(), &req)
			c.JSON(http.StatusOK, response)
			return
		}

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

	// For initialize method, merge upstream capabilities with firewall capabilities
	if req.Method == "initialize" && response.Result != nil {
		response = p.mergeInitializeCapabilities(response, &req)
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
	// Return initialization response with MCP-compliant capabilities
	result := map[string]interface{}{
		"protocolVersion": "2025-06-18",
		"capabilities": map[string]interface{}{
			"resources": map[string]interface{}{
				"subscribe":    true,
				"listChanged": true,
			},
			"tools": map[string]interface{}{
				"listChanged": true,
			},
			"prompts": map[string]interface{}{
				"listChanged": true,
			},
			"logging": map[string]interface{}{
				"level": "info",
			},
			// Custom security capabilities
			"security": map[string]interface{}{
				"content_filtering":   true,
				"compliance_scanning": true,
				"rate_limiting":      true,
				"threat_detection":   true,
				"data_sanitization":  true,
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

// mergeInitializeCapabilities merges upstream server capabilities with firewall capabilities
func (p *MCPProxy) mergeInitializeCapabilities(upstreamResponse *MCPResponse, req *MCPRequest) *MCPResponse {
	if upstreamResponse.Result == nil {
		return upstreamResponse
	}

	resultMap, ok := upstreamResponse.Result.(map[string]interface{})
	if !ok {
		return upstreamResponse
	}

	// Get existing capabilities or create new ones
	capabilities, ok := resultMap["capabilities"].(map[string]interface{})
	if !ok {
		capabilities = make(map[string]interface{})
	}

	// Add firewall security capabilities
	capabilities["security"] = map[string]interface{}{
		"content_filtering":   true,
		"compliance_scanning": true,
		"rate_limiting":      true,
		"threat_detection":   true,
		"data_sanitization":  true,
	}

	// Update server info to indicate firewall proxy
	serverInfo, ok := resultMap["serverInfo"].(map[string]interface{})
	if !ok {
		serverInfo = make(map[string]interface{})
	}

	// Preserve upstream server info but indicate firewall
	serverInfo["firewall"] = map[string]interface{}{
		"name":    "MCP Security Firewall",
		"version": "1.0.0",
		"proxy":   true,
	}

	resultMap["capabilities"] = capabilities
	resultMap["serverInfo"] = serverInfo

	return &MCPResponse{
		Result: resultMap,
		Error:  upstreamResponse.Error,
		ID:     upstreamResponse.ID,
	}
}

// handleResourcesList processes resources/list requests
func (p *MCPProxy) handleResourcesList(ctx context.Context, req *MCPRequest) *MCPResponse {
	// This method should be handled by the main proxy flow now
	// If we reach here, upstream is unavailable, so return security tools as resources

	// Add firewall's built-in security resources
	resources := []interface{}{
		map[string]interface{}{
			"uri":         "security://scan/content",
			"name":        "content_security_scan",
			"title":       "Content Security Scanner",
			"description": "Scan content for security threats and compliance violations",
			"mimeType":    "application/json",
		},
		map[string]interface{}{
			"uri":         "security://policy/status",
			"name":        "security_policy_status",
			"title":       "Security Policy Status",
			"description": "Current security policy configuration and status",
			"mimeType":    "application/json",
		},
	}

	// Handle pagination
	var nextCursor *string
	paramsMap, ok := req.Params.(map[string]interface{})
	if ok {
		if cursor, exists := paramsMap["cursor"]; exists && cursor != nil {
			// In a real implementation, handle pagination here
			// For now, no additional pages
		}
	}

	result := map[string]interface{}{
		"resources": resources,
	}

	if nextCursor != nil {
		result["nextCursor"] = *nextCursor
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
	// If we reach here, upstream is unavailable, so return firewall's built-in security tools
	tools := []interface{}{
		map[string]interface{}{
			"name":        "security_scan",
			"title":       "Security Content Scanner",
			"description": "Scan content for security threats, compliance violations, and sensitive data",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"content": map[string]interface{}{
						"type":        "string",
						"description": "Content to scan for security issues",
						"maxLength":   100000,
					},
					"scan_type": map[string]interface{}{
						"type":        "string",
						"description": "Type of scan to perform",
						"enum":        []string{"security", "compliance", "all"},
						"default":     "all",
					},
				},
				"required": []string{"content"},
			},
			"outputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"risk_level": map[string]interface{}{
						"type": "string",
						"enum": []string{"low", "medium", "high", "critical"},
					},
					"detections": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"type":        map[string]string{"type": "string"},
								"description": map[string]string{"type": "string"},
								"severity":    map[string]string{"type": "string"},
							},
						},
					},
					"sanitized": map[string]string{"type": "boolean"},
				},
			},
		},
		map[string]interface{}{
			"name":        "compliance_check",
			"title":       "Compliance Checker",
			"description": "Check content for regulatory compliance (GDPR, HIPAA, PCI DSS)",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"content": map[string]interface{}{
						"type":        "string",
						"description": "Content to check for compliance",
						"maxLength":   100000,
					},
					"frameworks": map[string]interface{}{
						"type":        "array",
						"description": "Compliance frameworks to check against",
						"items": map[string]interface{}{
							"type": "string",
							"enum": []string{"gdpr", "hipaa", "pci", "sox", "all"},
						},
						"default": []string{"all"},
					},
				},
				"required": []string{"content"},
			},
		},
	}

	// Handle pagination
	var nextCursor *string
	paramsMap, ok := req.Params.(map[string]interface{})
	if ok {
		if cursor, exists := paramsMap["cursor"]; exists && cursor != nil {
			// In a real implementation, handle pagination here
		}
	}

	result := map[string]interface{}{
		"tools": tools,
	}

	if nextCursor != nil {
		result["nextCursor"] = *nextCursor
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

	switch name {
	case "security_scan":
		return p.handleSecurityScanTool(ctx, req, paramsMap)
	case "compliance_check":
		return p.handleComplianceCheckTool(ctx, req, paramsMap)
	default:
		return &MCPResponse{
			Error: &MCPError{
				Code:    -32601,
				Message: "Tool not found",
				Data:    fmt.Sprintf("Unknown tool: %s", name),
			},
			ID: req.ID,
		}
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

// handleComplianceCheckTool implements the compliance_check tool
func (p *MCPProxy) handleComplianceCheckTool(ctx context.Context, req *MCPRequest, params map[string]interface{}) *MCPResponse {
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

	// Get frameworks to check (default to all)
	frameworks := []string{"all"}
	if fwArray, ok := arguments["frameworks"].([]interface{}); ok {
		frameworks = make([]string, len(fwArray))
		for i, fw := range fwArray {
			if fwStr, ok := fw.(string); ok {
				frameworks[i] = fwStr
			}
		}
	}

	// Perform compliance scan
	complianceResult := p.complianceManager.ScanForCompliance(inputContent)

	complianceReport := fmt.Sprintf("Compliance Check Results:\n"+
		"Overall Risk: %s\n"+
		"Total Violations: %d\n"+
		"Frameworks Checked: %v\n",
		complianceResult.ComplianceRisk,
		len(complianceResult.Violations),
		frameworks)

	responseContent := []interface{}{
		map[string]interface{}{
			"type": "text",
			"text": complianceReport,
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
	// If we reach here, upstream is unavailable, so return firewall's built-in security prompts
	prompts := []interface{}{
		map[string]interface{}{
			"name":        "security_analysis",
			"title":       "Security Content Analysis",
			"description": "Analyze content for security threats and vulnerabilities",
			"arguments": []map[string]interface{}{
				{
					"name":        "content",
					"description": "Content to analyze for security issues",
					"required":    true,
				},
				{
					"name":        "depth",
					"description": "Analysis depth: surface, deep, comprehensive",
					"required":    false,
				},
			},
		},
		map[string]interface{}{
			"name":        "compliance_review",
			"title":       "Compliance Review Prompt",
			"description": "Review content for regulatory compliance requirements",
			"arguments": []map[string]interface{}{
				{
					"name":        "content",
					"description": "Content to review for compliance",
					"required":    true,
				},
				{
					"name":        "framework",
					"description": "Compliance framework (gdpr, hipaa, pci, sox)",
					"required":    false,
				},
			},
		},
		map[string]interface{}{
			"name":        "threat_assessment",
			"title":       "Security Threat Assessment",
			"description": "Assess potential security threats in the provided content",
			"arguments": []map[string]interface{}{
				{
					"name":        "content",
					"description": "Content to assess for threats",
					"required":    true,
				},
				{
					"name":        "context",
					"description": "Context or environment for threat assessment",
					"required":    false,
				},
			},
		},
	}

	// Handle pagination
	var nextCursor *string
	paramsMap, ok := req.Params.(map[string]interface{})
	if ok {
		if cursor, exists := paramsMap["cursor"]; exists && cursor != nil {
			// In a real implementation, handle pagination here
		}
	}

	result := map[string]interface{}{
		"prompts": prompts,
	}

	if nextCursor != nil {
		result["nextCursor"] = *nextCursor
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

	// Get arguments if provided
	var arguments map[string]interface{}
	if args, exists := paramsMap["arguments"]; exists {
		if argsMap, ok := args.(map[string]interface{}); ok {
			arguments = argsMap
		}
	}

	switch name {
	case "security_analysis":
		content := ""
		depth := "surface"
		if arguments != nil {
			if c, ok := arguments["content"].(string); ok {
				content = c
			}
			if d, ok := arguments["depth"].(string); ok {
				depth = d
			}
		}

		promptText := fmt.Sprintf(`Please perform a %s security analysis on the following content. Look for:
1. Potential security vulnerabilities
2. Suspicious patterns or code
3. Data exposure risks
4. Injection attack vectors
5. Authentication/authorization issues

Content to analyze:
%s

Provide a detailed security assessment with risk levels and recommendations.`, depth, content)

		result := map[string]interface{}{
			"description": "Security analysis prompt for identifying threats and vulnerabilities",
			"messages": []map[string]interface{}{
				{
					"role": "user",
					"content": map[string]interface{}{
						"type": "text",
						"text": promptText,
					},
				},
			},
		}

		return &MCPResponse{
			Result: result,
			ID:     req.ID,
		}

	case "compliance_review":
		content := ""
		framework := "general"
		if arguments != nil {
			if c, ok := arguments["content"].(string); ok {
				content = c
			}
			if f, ok := arguments["framework"].(string); ok {
				framework = f
			}
		}

		promptText := fmt.Sprintf(`Please review the following content for %s compliance requirements. Check for:
1. Personal identifiable information (PII)
2. Protected health information (PHI)
3. Payment card data
4. Data handling violations
5. Privacy policy compliance

Framework: %s
Content to review:
%s

Provide a compliance assessment with violation details and remediation steps.`, framework, framework, content)

		result := map[string]interface{}{
			"description": "Compliance review prompt for regulatory framework assessment",
			"messages": []map[string]interface{}{
				{
					"role": "user",
					"content": map[string]interface{}{
						"type": "text",
						"text": promptText,
					},
				},
			},
		}

		return &MCPResponse{
			Result: result,
			ID:     req.ID,
		}

	case "threat_assessment":
		content := ""
		context := "general"
		if arguments != nil {
			if c, ok := arguments["content"].(string); ok {
				content = c
			}
			if ctx, ok := arguments["context"].(string); ok {
				context = ctx
			}
		}

		promptText := fmt.Sprintf(`Please assess the potential security threats in the following content within the context of: %s

Analyze for:
1. Malicious intent indicators
2. Social engineering attempts
3. Phishing patterns
4. Malware signatures
5. Data exfiltration risks

Content to assess:
%s

Provide a threat level assessment with detailed findings and mitigation recommendations.`, context, content)

		result := map[string]interface{}{
			"description": "Threat assessment prompt for security risk evaluation",
			"messages": []map[string]interface{}{
				{
					"role": "user",
					"content": map[string]interface{}{
						"type": "text",
						"text": promptText,
					},
				},
			},
		}

		return &MCPResponse{
			Result: result,
			ID:     req.ID,
		}

	default:
		return &MCPResponse{
			Error: &MCPError{
				Code:    -32601,
				Message: "Prompt not found",
				Data:    fmt.Sprintf("Unknown prompt: %s", name),
			},
			ID: req.ID,
		}
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

// getSessionID extracts or generates a session ID from context
func (p *MCPProxy) getSessionID(c *gin.Context) string {
	if sessionID, exists := c.Get("session_id"); exists {
		if sid, ok := sessionID.(string); ok && sid != "" {
			return sid
		}
	}
	// Generate a session ID from user ID and client IP if not found
	userID := p.getUserID(c)
	clientIP := c.ClientIP()
	return fmt.Sprintf("%s_%s", userID, clientIP)
}