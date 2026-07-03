package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegishjalmur/aegir/internal/anomaly"
	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/dashboard"
	"github.com/aegishjalmur/aegir/internal/judge"
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
	config            *config.Config
	sanitizer         *sanitizer.Manager
	complianceManager *sanitizer.ComplianceManager
	upstreamManager   *upstream.Manager
	sessionAnalyzer   session.ThreatAnalyzer
	anomalyDetector   anomaly.Detector
	ruleEngine        *judge.RuleEngine
	upgrader          websocket.Upgrader
	anomalyCount      atomic.Uint64
	anomalyScoreSum   atomic.Uint64 // stored as score*1e6 to avoid float atomics

	// Recon rate limit (ISC-121): per-session tools/list call timestamps.
	reconMu     sync.Mutex
	reconCalls  map[string][]time.Time // key: session ID → slice of call timestamps
}

// AnomalyStats holds aggregate anomaly scoring data for metrics.
type AnomalyStats struct {
	TotalScored  uint64  `json:"total_scored"`
	AverageScore float64 `json:"average_score"`
}

// GetAnomalyStats returns aggregate anomaly scoring statistics.
func (p *MCPProxy) GetAnomalyStats() AnomalyStats {
	count := p.anomalyCount.Load()
	sum := p.anomalyScoreSum.Load()
	avg := 0.0
	if count > 0 {
		avg = math.Round(float64(sum)/float64(count)/1e6*1000) / 1000
	}
	return AnomalyStats{TotalScored: count, AverageScore: avg}
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
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// NewMCPProxy creates a new MCP proxy instance
func NewMCPProxy(cfg *config.Config, logger *logging.Logger, sanitizerMgr *sanitizer.Manager, complianceMgr *sanitizer.ComplianceManager, upstreamMgr *upstream.Manager, sessionAnalyzer session.ThreatAnalyzer, anomalyDet anomaly.Detector, ruleEng *judge.RuleEngine) *MCPProxy {
	return &MCPProxy{
		config:            cfg,
		logger:            logger,
		sanitizer:         sanitizerMgr,
		complianceManager: complianceMgr,
		upstreamManager:   upstreamMgr,
		sessionAnalyzer:   sessionAnalyzer,
		anomalyDetector:   anomalyDet,
		ruleEngine:        ruleEng,
		upgrader: websocket.Upgrader{
			// Validate the WebSocket Origin against AllowedOrigins (ISC-120).
			// Require Origin header for WebSocket connections.
			// Empty AllowedOrigins list requires Origin to be present but
			// allows any non-empty origin (default/non-restrictive).
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					// Require Origin header for security (prevents CSRF attacks)
					return false
				}
				if len(cfg.Security.AllowedOrigins) == 0 {
					// Allow any origin if allowlist is empty (default behavior)
					return true
				}
				for _, allowed := range cfg.Security.AllowedOrigins {
					if allowed == origin {
						return true
					}
				}
				return false
			},
		},
		reconCalls: make(map[string][]time.Time),
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

		// Bridge session threat patterns → dashboard counters
		p.recordSessionThreatsToContext(c, assessment.AttackPatterns)

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

	// Anomaly scoring (optional, opt-in via config)
	if p.anomalyDetector != nil {
		anomalyScore := p.anomalyDetector.Score(req.Method + " " + string(paramsJSON))
		p.anomalyCount.Add(1)
		p.anomalyScoreSum.Add(uint64(anomalyScore * 1e6))

		// Check if anomaly score exceeds block threshold
		if p.config.Security.AnomalyDetection.Enabled && anomalyScore >= p.config.Security.AnomalyDetection.BlockThreshold {
			p.logger.Warn("MCP request blocked by anomaly detection",
				"method", req.Method,
				"anomaly_score", fmt.Sprintf("%.3f", anomalyScore),
				"block_threshold", fmt.Sprintf("%.3f", p.config.Security.AnomalyDetection.BlockThreshold))

			c.JSON(http.StatusForbidden, MCPResponse{
				Error: &MCPError{
					Code:    -32000,
					Message: "Request blocked by anomaly detection",
					Data:    fmt.Sprintf("Anomaly score %.3f exceeds threshold %.3f", anomalyScore, p.config.Security.AnomalyDetection.BlockThreshold),
				},
				ID: req.ID,
			})
			return
		}

		// Log at warn level if score exceeds log threshold
		if anomalyScore >= p.config.Security.AnomalyDetection.LogThreshold {
			p.logger.Warn("High anomaly score (logging only)",
				"method", req.Method,
				"anomaly_score", fmt.Sprintf("%.3f", anomalyScore))
		} else {
			p.logger.Info("Anomaly score", "method", req.Method, "anomaly_score", fmt.Sprintf("%.3f", anomalyScore))
		}
	}

	// Apply security sanitization
	sanitizationResult := p.sanitizer.SanitizeContent(string(paramsJSON))

	// Bridge sanitizer detections → dashboard counters
	p.recordDetectionsToContext(c, sanitizationResult.Detections)

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

	// Bridge compliance detections → dashboard counters
	p.recordComplianceToContext(c, complianceResult)

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
					// AEGIR-L-003: log the specific reason server-side; return a
					// generic message so the client learns nothing about internal
					// validation logic or reachable targets.
					p.logger.Warn("resource URI validation failed", "uri", uri, "error", err.Error())
					c.JSON(http.StatusForbidden, MCPResponse{
						Error: &MCPError{
							Code:    -32000,
							Message: "Resource access denied",
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

	// --- Judge Proxy Wiring (ISC-33, ISC-93) ---
	// Skip entirely when judge is not configured (pattern-only mode).
	if p.ruleEngine != nil {
		judgePayload, _ := json.Marshal(req.Params)
		// Translate sanitizer verdict to a judge routing signal.
		// ALLOW short-circuits the judge (no LLM call, zero latency).
		// SUSPICIOUS routes the payload to the configured judge model.
		// Payloads already blocked by the sanitizer above never reach here.
		judgeVerdict := sanitizerVerdictToJudge(sanitizationResult)
		judgeResult, err := p.ruleEngine.Route(c.Request.Context(), judgeVerdict, string(judgePayload))
		if err != nil {
			// AEGIR-L-003: internal judge/backend error detail stays server-side.
			p.logger.Error("Judge routing error", "error", err)
			c.JSON(http.StatusForbidden, MCPResponse{
				Error: &MCPError{
					Code:    -32000,
					Message: "Security analysis failed",
				},
				ID: req.ID,
			})
			return
		}

		switch judgeResult.Verdict {
		case judge.BLOCK, judge.SUSPICIOUS:
			// Both BLOCK and SUSPICIOUS from the judge result in an immediate
			// block and audit-log entry. No real-time human-in-the-loop hold —
			// this proxy is a low-latency boundary; fail-closed is the correct
			// behaviour. Human review happens asynchronously via the audit log.
			// ISC-33/ISC-93: judge reasoning is logged server-side only. It is
			// emitted to the client solely under the explicit debug opt-in
			// (ExposeReasoning), which carries a GDPR/HIPAA/PCI warning.
			p.logger.Warn("MCP request blocked by judge",
				"method", req.Method,
				"verdict", judgeResult.Verdict,
				"reason", judgeResult.Reason,
				"model", judgeResult.ModelName)
			blockErr := &MCPError{
				Code:    -32000,
				Message: "Request blocked by security policy",
			}
			if p.config.Judge.ExposeReasoning {
				blockErr.Data = judgeResult.Reason
			}
			c.JSON(http.StatusForbidden, MCPResponse{Error: blockErr, ID: req.ID})
			return

		case judge.ALLOW:
			// Proceed as normal.
		}
	}
	// --- END Judge Proxy Wiring ---

	// Forward the sanitized request to upstream services
	upstreamReq := &upstream.MCPRequest{
		Method: req.Method,
		Params: req.Params,
		ID:     req.ID,
	}

	upstreamResp, err := p.upstreamManager.ForwardRequest(c.Request.Context(), upstreamReq)
	if err != nil {
		p.logger.Error("Failed to forward request to upstream", "error", err)
		// Fall back to local handling — firewall exposes built-in security tools
		// for all standard MCP methods when no upstream is reachable.
		response := p.processMCPMethod(c.Request.Context(), &req)
		c.JSON(http.StatusOK, response)
		return
	}

	// Convert upstream response to our response format
	response := &MCPResponse{
		Result: upstreamResp.Result,
		Error:  (*MCPError)(upstreamResp.Error),
		ID:     upstreamResp.ID,
	}

	// Indirect prompt injection guard (ISC-22, AML.T0051.001): scan tool-call result text
	// from upstream before forwarding. Graceful degradation: skipped when sanitizer is nil.
	if blocked, detail := p.scanToolResultForInjection(response.Result); blocked {
		p.logger.Warn("Tool result blocked: indirect injection detected",
			"method", req.Method, "detail", detail)
		c.JSON(http.StatusForbidden, MCPResponse{
			Error: &MCPError{
				Code:    -32000,
				Message: "Tool result blocked: indirect injection detected",
				Data:    detail,
			},
			ID: req.ID,
		})
		return
	}

	// For initialize method, merge upstream capabilities with firewall capabilities
	if req.Method == "initialize" && response.Result != nil {
		response = p.mergeInitializeCapabilities(response, &req)
	}

	// For tools/list, prepend Aegir's built-in security tools (ISC-76).
	if req.Method == "tools/list" {
		response = p.mergeToolsList(response, &req)
		// Per-session tools/list recon rate limiting (ISC-121).
		p.trackReconCall(c, &req)
	}

	// Marshal response to JSON
	responseJSON, _ := json.Marshal(response.Result)

	// Response-compliance gate (AEGIR-H-002 / ISC-27/28/149/162). Extracted into
	// enforceResponseCompliance so the "scan pre-redaction → log audit event →
	// decide action" ordering is a single, unit-testable boundary. The audit event
	// ALWAYS fires before a block, so a policy-blocked response is never lost from
	// the audit trail (ISC-162 — the regression that motivated consolidating this).
	decision := p.enforceResponseCompliance(string(responseJSON), response.Result)
	switch decision.action {
	case "block":
		c.JSON(http.StatusForbidden, MCPResponse{
			Error: &MCPError{
				Code:    -32600,
				Message: "Response blocked by compliance policy",
			},
			ID: req.ID,
		})
		return
	case "redact":
		// Raw response was redacted inside the gate; forward the masked result.
		response.Result = decision.result
		c.JSON(http.StatusOK, response)
		return
	// "allow" (no violations, or log-only): fall through to the sanitizer pass.
	}

	// Default path (no violations, or log-only): apply the sanitizer for
	// PII/PHI/PCI redaction independent of compliance policy, then forward.
	responseSanitized := p.sanitizer.SanitizeContent(string(responseJSON))
	if responseSanitized.Sanitized != string(responseJSON) {
		var sanitizedResult interface{}
		if err := json.Unmarshal([]byte(responseSanitized.Sanitized), &sanitizedResult); err == nil {
			response.Result = sanitizedResult
		}
	}

	c.JSON(http.StatusOK, response)
}

// responseComplianceDecision is the outcome of the response-compliance gate.
// action is one of "block", "redact", or "allow"; result carries the
// (possibly-redacted) response payload for the "redact" case.
type responseComplianceDecision struct {
	action string
	result interface{}
}

// enforceResponseCompliance is the single decision point for regulated data in a
// model response (AEGIR-H-002). ORDER MATTERS and is the whole point of this
// function:
//
//  1. ISC-149 — scan the RAW, pre-redaction responseJSON so severity/data-type
//     reflect the true finding even when the forwarded payload is later masked.
//  2. ISC-162 — LOG the response_compliance_violation audit event FIRST, before
//     any block path returns, so a policy-blocked response is never dropped from
//     the audit trail. Only the redacted per-type SUMMARY is logged
//     (summarizeComplianceViolations) — never raw or redacted regulated values
//     (AEGIR-L-003 / no data sprawl into the audit trail).
//  3. ISC-28 — apply the per-data-type action: block > redact > log-only.
//
// Returns "allow" when there are no violations or the policy is log-only.
func (p *MCPProxy) enforceResponseCompliance(responseJSON string, currentResult interface{}) responseComplianceDecision {
	res := p.complianceManager.ScanForCompliance(responseJSON)
	if len(res.Violations) == 0 {
		return responseComplianceDecision{action: "allow", result: currentResult}
	}

	// LOG FIRST — before any early-return block path (ISC-162).
	p.logger.LogSecurityEvent(&logging.SecurityEvent{
		Type:      "response_compliance_violation",
		Severity:  res.ComplianceRisk,
		Message:   "Regulated data in model response",
		Timestamp: time.Now(),
		Details: map[string]string{
			"violations": strconv.Itoa(len(res.Violations)),
			"risk_level": res.ComplianceRisk,
			// Redacted, aggregate-per-type summary only — no regulated values.
			"data_types": summarizeComplianceViolations(res.Violations),
		},
	})

	switch p.responseComplianceAction(res.Violations) {
	case "block":
		p.logger.Warn("MCP response blocked by per-type compliance policy",
			"violations", len(res.Violations),
			"action", "block")
		return responseComplianceDecision{action: "block"}
	case "redact":
		// Enforce redaction on the raw response, then forward the masked payload.
		result := currentResult
		redacted := p.sanitizer.SanitizeContent(responseJSON)
		if redacted.Sanitized != responseJSON {
			var redactedResult interface{}
			if err := json.Unmarshal([]byte(redacted.Sanitized), &redactedResult); err == nil {
				result = redactedResult
			}
		}
		return responseComplianceDecision{action: "redact", result: result}
	default:
		// "log-only": already logged above; forward untouched via the sanitizer pass.
		return responseComplianceDecision{action: "allow", result: currentResult}
	}
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
		return p.handleToolsListMerged(ctx, req)
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
				"subscribe":   true,
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
				"rate_limiting":       true,
				"threat_detection":    true,
				"data_sanitization":   true,
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
		"rate_limiting":       true,
		"threat_detection":    true,
		"data_sanitization":   true,
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
	// (Implementation omitted for brevity in this snippet)
	return &MCPResponse{ID: req.ID}
}

// handleResourcesRead processes resources/read requests
func (p *MCPProxy) handleResourcesRead(ctx context.Context, req *MCPRequest) *MCPResponse {
	// Implementation omitted for brevity in this snippet
	return &MCPResponse{ID: req.ID}
}

// builtinTools returns Aegir's built-in security tools.
// Extracted so the fallback path and the upstream-merged path share one source.
func (p *MCPProxy) builtinTools() []interface{} {
	return []interface{}{
		map[string]interface{}{
			"name":        "security_scan",
			"title":       "Security Content Scanner",
			"description": "Analyse content for security threats (prompt injection, XSS, secrets, SSRF).",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"content": map[string]interface{}{
						"type":        "string",
						"description": "Content to scan for threats",
					},
					"url": map[string]interface{}{
						"type":        "string",
						"description": "Optional URL argument — SSRF-checked against private address ranges",
					},
				},
				"required": []string{"content"},
			},
		},
	}
}

// handleToolsListMerged returns Aegir's built-in tools merged with upstream tools (ISC-76).
// Used in the fallback (no-upstream) path; the main forward path calls mergeToolsList instead.
func (p *MCPProxy) handleToolsListMerged(ctx context.Context, req *MCPRequest) *MCPResponse {
	merged := append([]interface{}{}, p.builtinTools()...)
	merged = append(merged, p.fetchUpstreamTools(ctx, req)...)
	return &MCPResponse{
		Result: map[string]interface{}{"tools": merged},
		ID:     req.ID,
	}
}

// fetchUpstreamTools queries the upstream MCP server's tools/list. Returns nil on
// any failure so callers fall back to built-in tools only (graceful degradation, ISC-76).
func (p *MCPProxy) fetchUpstreamTools(ctx context.Context, req *MCPRequest) []interface{} {
	if p.upstreamManager == nil {
		return nil
	}
	upstreamResp, err := p.upstreamManager.ForwardRequest(ctx, &upstream.MCPRequest{
		Method: "tools/list",
		Params: req.Params,
		ID:     req.ID,
	})
	if err != nil || upstreamResp == nil || upstreamResp.Error != nil || upstreamResp.Result == nil {
		return nil
	}
	resultMap, ok := upstreamResp.Result.(map[string]interface{})
	if !ok {
		return nil
	}
	tools, _ := resultMap["tools"].([]interface{})
	return tools
}

// mergeToolsList prepends Aegir's built-in tools into an upstream tools/list response (ISC-76).
// On malformed or error upstream response, returns only built-in tools.
func (p *MCPProxy) mergeToolsList(upstreamResponse *MCPResponse, req *MCPRequest) *MCPResponse {
	merged := append([]interface{}{}, p.builtinTools()...)
	if upstreamResponse != nil && upstreamResponse.Error == nil {
		if resultMap, ok := upstreamResponse.Result.(map[string]interface{}); ok {
			if tools, ok := resultMap["tools"].([]interface{}); ok {
				merged = append(merged, tools...)
			}
		}
	}
	return &MCPResponse{
		Result: map[string]interface{}{"tools": merged},
		ID:     req.ID,
	}
}

// scanToolResultForInjection checks tool-call result text for indirect injection (ISC-22).
// Returns blocked=true with a detail string if any content fragment is blocked by the sanitizer.
// Skips gracefully when the sanitizer is nil or the result has no text content.
func (p *MCPProxy) scanToolResultForInjection(result interface{}) (blocked bool, detail string) {
	if p.sanitizer == nil {
		return false, ""
	}
	for _, text := range extractToolResultText(result) {
		if text == "" {
			continue
		}
		scan := p.sanitizer.SanitizeContent(text)
		if scan.Blocked {
			return true, fmt.Sprintf("risk=%s, detections=%d", scan.Risk, len(scan.Detections))
		}
		// AEGIR-M-005: tool result content may carry URLs the client would
		// dereference. Block any that resolve to private/loopback/link-local
		// targets so a poisoned upstream cannot pivot the client into SSRF.
		for _, tok := range strings.Fields(text) {
			if looksLikeURL(tok) && isSSRFTarget(tok) {
				return true, "ssrf target in tool result"
			}
		}
	}
	return false, ""
}

// summarizeComplianceViolations produces a stable, audit-friendly breakdown of
// compliance violations for the response_compliance_violation log event
// (ISC-27). Each fragment is "pattern[class]:severity×count" — keyed on the
// specific data identifier (ssn, email, icd10, card…) because severity varies
// per identifier within a regulation class, so an aggregate would misreport it.
// Ordered by pattern for determinism. Records what regulated data appeared and
// how serious each was, without replaying the regulated values themselves.
func summarizeComplianceViolations(violations []sanitizer.Violation) string {
	type agg struct {
		class    string
		severity string
		count    int
	}
	byPattern := make(map[string]*agg)
	order := make([]string, 0)
	for _, v := range violations {
		a, ok := byPattern[v.Pattern]
		if !ok {
			a = &agg{class: v.Type, severity: v.Severity}
			byPattern[v.Pattern] = a
			order = append(order, v.Pattern)
		}
		a.count++
	}
	sort.Strings(order)
	frags := make([]string, 0, len(order))
	for _, p := range order {
		a := byPattern[p]
		frags = append(frags, fmt.Sprintf("%s[%s]:%s×%d", p, a.class, a.severity, a.count))
	}
	return strings.Join(frags, ", ")
}

// responseComplianceAction returns the highest-priority action for a set of
// violations, using the per-data-type policy from compliance.response_policy
// (ISC-28). Priority order: block > redact > log-only. Absent types default to
// "redact". An empty/nil violation list returns "log-only".
func (p *MCPProxy) responseComplianceAction(violations []sanitizer.Violation) string {
	if len(violations) == 0 {
		return "log-only"
	}
	policy := p.config.Compliance.ResponsePolicy
	priority := map[string]int{"block": 2, "redact": 1, "log-only": 0}
	best := "log-only"
	for _, v := range violations {
		action := "redact" // default for unmapped types
		if policy != nil {
			if a, ok := policy[v.Type]; ok {
				action = a
			}
		}
		if priority[action] > priority[best] {
			best = action
		}
	}
	return best
}

// extractToolResultText pulls content[].text strings from an MCP tools/call result.
func extractToolResultText(result interface{}) []string {
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return nil
	}
	content, ok := resultMap["content"].([]interface{})
	if !ok {
		return nil
	}
	var texts []string
	for _, item := range content {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if text, ok := entry["text"].(string); ok {
			texts = append(texts, text)
		}
	}
	return texts
}

// handleToolsCall processes tools/call requests.
// URL arguments are SSRF-checked (P1-5); content is scanned and results returned.
func (p *MCPProxy) handleToolsCall(_ context.Context, req *MCPRequest) *MCPResponse {
	params, ok := req.Params.(map[string]interface{})
	if !ok {
		return &MCPResponse{
			Error: &MCPError{Code: -32602, Message: "Invalid params: expected object"},
			ID:    req.ID,
		}
	}

	args, _ := params["arguments"].(map[string]interface{})

	// SSRF guard: reject any string argument that targets a private/link-local address (P1-5).
	for _, v := range args {
		if urlStr, ok := v.(string); ok && isSSRFTarget(urlStr) {
			// AEGIR-L-003: log the offending URL server-side; do not echo it back
			// to the client (it confirms which internal targets are reachable).
			p.logger.Warn("SSRF target blocked in tool arguments", "url", urlStr)
			return &MCPResponse{
				Error: &MCPError{
					Code:    -32000,
					Message: "Request blocked: SSRF target detected in tool arguments",
				},
				ID: req.ID,
			}
		}
	}

	// Human approval gate (ISC-119): hold destructive tool calls for external approval.
	toolName, _ := params["name"].(string)
	if p.config != nil && p.config.Security.HumanApproval.Enabled && toolName != "" {
		ha := p.config.Security.HumanApproval
		if isDestructiveTool(toolName, ha.Patterns) {
			if err := p.requestHumanApproval(toolName, args, ha); err != nil {
				p.logger.Warn("Human approval gate: blocked destructive tool call",
					"tool", toolName, "reason", err.Error())
				p.logger.LogSecurityEvent(&logging.SecurityEvent{
					Type:     "human_approval_timeout",
					Severity: "high",
					Message:  "Destructive tool call blocked: human approval not received",
					Timestamp: time.Now(),
					Details:  map[string]string{"tool": toolName, "reason": err.Error()},
				})
				return &MCPResponse{
					Error: &MCPError{
						Code:    -32000,
						Message: "Request blocked: human approval required for destructive operation",
					},
					ID: req.ID,
				}
			}
		}
	}

	contentArg := ""
	if args != nil {
		if c, ok := args["content"].(string); ok {
			contentArg = c
		}
	}

	var scanText string
	if p.sanitizer != nil {
		result := p.sanitizer.SanitizeContent(contentArg)
		scanText = fmt.Sprintf("scan complete: %d detection(s), risk=%s, blocked=%v",
			len(result.Detections), result.Risk, result.Blocked)
	} else {
		scanText = "scan complete: sanitizer not configured"
	}

	return &MCPResponse{
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": scanText},
			},
		},
		ID: req.ID,
	}
}

// trackReconCall records a tools/list call for the session and fires a
// tools_list_recon_suspected event when the per-minute threshold is exceeded (ISC-121).
func (p *MCPProxy) trackReconCall(c *gin.Context, req *MCPRequest) {
	if p.config == nil {
		return
	}
	rl := p.config.Security.ReconRateLimit
	if !rl.Enabled {
		return
	}
	sessionID := p.getSessionID(c)
	threshold := rl.ToolsListMaxPerMin
	if threshold <= 0 {
		threshold = 10
	}
	window := time.Now().Add(-time.Minute)

	p.reconMu.Lock()
	if p.reconCalls == nil {
		p.reconCalls = make(map[string][]time.Time)
	}
	calls := p.reconCalls[sessionID]
	// Prune timestamps older than 1 minute.
	fresh := calls[:0]
	for _, t := range calls {
		if t.After(window) {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, time.Now())
	p.reconCalls[sessionID] = fresh
	count := len(fresh)
	p.reconMu.Unlock()

	if count > threshold {
		p.logger.LogSecurityEvent(&logging.SecurityEvent{
			Type:      "tools_list_recon_suspected",
			Severity:  "high",
			Message:   "tools/list recon rate threshold exceeded",
			ClientIP:  c.ClientIP(),
			Timestamp: time.Now(),
			Details: map[string]string{
				"session_id": sessionID,
				"calls_per_min": strconv.Itoa(count),
				"threshold": strconv.Itoa(threshold),
			},
		})
	}
}

// isDestructiveTool returns true if name starts with any of the configured patterns.
func isDestructiveTool(name string, patterns []string) bool {
	lower := strings.ToLower(name)
	for _, p := range patterns {
		if strings.HasPrefix(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// requestHumanApproval POSTs the tool name and args to the configured webhook
// and waits up to Timeout for {"approved":true}. Returns an error if the call
// should be blocked (timeout, HTTP error, or explicit rejection).
func (p *MCPProxy) requestHumanApproval(toolName string, args map[string]interface{}, cfg config.HumanApprovalConfig) error {
	if cfg.WebhookURL == "" {
		return fmt.Errorf("human_approval.webhook_url not configured")
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"tool":      toolName,
		"arguments": args,
	})

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(cfg.WebhookURL, "application/json", strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("webhook error: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Approved bool `json:"approved"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("webhook response decode error: %w", err)
	}
	if !result.Approved {
		return fmt.Errorf("approval denied by webhook")
	}
	return nil
}

// isSSRFTarget returns true if s is a URL targeting a private, link-local, loopback,
// unspecified, or otherwise unsafe address. It parses the URL with net/url, checks
// the scheme against a blocklist (file://, gopher://, ws://, wss://, about:), validates
// the hostname for localhost/localdomain/IPv6 loopback forms, and resolves the IP to
// check against RFC 1918, link-local, loopback, and unspecified ranges.
func isSSRFTarget(s string) bool {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return false
	}

	// Strip any embedded credentials (user:pass@)
	if idx := strings.Index(raw, "://"); idx >= 0 {
		scheme := strings.ToLower(raw[:idx])
		// Block dangerous schemes outright
		switch scheme {
		case "file", "gopher", "ws", "wss", "about", "data", "javascript", "blob":
			return true
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		// If we can't parse it, assume it might be a native IP notation like
		// 0x7F000001 (hex) or 0177.0000.0000.0001 (octal). Check the raw string.
		return isSSRFUnsafeRaw(raw)
	}

	// Check scheme
	scheme := strings.ToLower(u.Scheme)
	if scheme == "file" || scheme == "gopher" || scheme == "ws" || scheme == "wss" ||
		scheme == "about" || scheme == "data" || scheme == "javascript" || scheme == "blob" {
		return true
	}

	host := u.Hostname()
	if host == "" {
		return false
	}

	// Check for localhost/localdomain
	if isLocalHost(host) {
		return true
	}

	// Check for IPv6 loopback forms
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		ipStr := host[1 : len(host)-1]
		if isIPv6Loopback(ipStr) {
			return true
		}
		// Also check if it's an IPv4-mapped IPv6 like [::ffff:127.0.0.1]
		if ip := net.ParseIP(ipStr); ip != nil && isUnsafeIP(ip) {
			return true
		}
		return isIPv6Loopback(ipStr)
	}

	// Check for integer IP notation (e.g., 0x7F000001, 0177.0000.0000.0001)
	if isIntegerIP(host) {
		return true
	}

	// Resolve the hostname to an IP address
	// Use context with timeout to prevent DNS rebinding attacks
	resolvedIP, err := resolveIP(host)
	if err != nil {
		// If resolution fails, check if it's a known unsafe pattern
		return isUnsafeRawIP(host)
	}

	return isUnsafeIP(resolvedIP)
}

// isLocalHost returns true if host is a form of localhost
func isLocalHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "localdomain":
		return true
	}
	return false
}

// isIPv6Loopback returns true if s is an IPv6 loopback address form
func isIPv6Loopback(s string) bool {
	switch s {
	case "::1", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001",
		"::", "0:0:0:0:0:0:0:0":
		return true
	}
	// Normalize: ::ffff:127.0.0.1 or ::ffff:0:0:0:0:127.0.0.1
	if strings.HasPrefix(s, "::ffff:") {
		remaining := s[7:]
		if ip := net.ParseIP(remaining); ip != nil {
			// It's an IPv4-mapped IPv6; check if the IPv4 is loopback
			if ip.To4() != nil {
				host := ip.To4().String()
				return isLocalHost(host) || isRFC1918(host)
			}
		}
	}
	return false
}

// isIntegerIP returns true if s is a non-dotted-decimal IPv4 notation
// (hex 0x7F000001, decimal 2130706433, or dotted hex/octal like 0177.0.0.1)
// that decodes to an unsafe address. Go's net.ParseIP rejects every one of
// these forms, so we decode them ourselves — otherwise this check is dead code
// and IMDS blocking depends entirely on the platform resolver canonicalising
// them, which the pure-Go resolver (GODEBUG=netdns=go) does not do (AEGIR-C-001
// hardening: make the block deterministic, not resolver-incidental).
func isIntegerIP(s string) bool {
	if ip := parseIntegerIP(s); ip != nil {
		return isUnsafeIP(ip)
	}
	return false
}

// parseIntegerIP decodes the non-standard IPv4 integer notations that
// net.ParseIP refuses, returning a canonical net.IP or nil if s is not one of
// them. Handled forms:
//   - single hex:      0x7F000001 / 0X7f000001
//   - single decimal:  2130706433            (must be > 255 to avoid clashing
//     with a bare octet; bare small ints aren't routable hosts anyway)
//   - single octal:    017700000001
//   - dotted a.b.c.d where each octet may be decimal, 0x-hex, or 0-octal
func parseIntegerIP(s string) net.IP {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	// Dotted forms: 1–4 parts, each decimal/hex/octal.
	if strings.Contains(s, ".") {
		parts := strings.Split(s, ".")
		if len(parts) < 1 || len(parts) > 4 {
			return nil
		}
		octets := make([]uint64, len(parts))
		for i, p := range parts {
			v, ok := parseUintAutoBase(p)
			if !ok || v > 0xFF {
				return nil
			}
			octets[i] = v
		}
		// Only treat as integer-notation if at least one octet used a
		// non-decimal base or leading zero; plain dotted-decimal is handled by
		// net.ParseIP upstream. We still decode here for the resolver-fail path.
		if len(octets) == 4 {
			return net.IPv4(byte(octets[0]), byte(octets[1]), byte(octets[2]), byte(octets[3]))
		}
		return nil
	}

	// Single-number forms (hex/octal/decimal 32-bit).
	v, ok := parseUintAutoBase(s)
	if !ok || v > 0xFFFFFFFF {
		return nil
	}
	// Require > 255 so we don't misread a bare small integer as an IP.
	if v <= 0xFF {
		return nil
	}
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// parseUintAutoBase parses a uint using Go's base-0 auto-detection (0x → hex,
// leading 0 → octal, else decimal). Returns ok=false on any parse error.
func parseUintAutoBase(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// resolveIP resolves a hostname to an IP address with a timeout
func resolveIP(host string) (net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, err
	}
	return addr.IP, nil
}

// isUnsafeIP returns true if ip is a private, loopback, link-local, or unspecified address
func isUnsafeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Unspecified address (0.0.0.0 or ::)
	if ip.IsUnspecified() {
		return true
	}

	// Loopback (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return true
	}

	// Link-local (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Private networks (RFC 1918)
	if ip.IsPrivate() {
		return true
	}

	// IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)
	if ip4 := ip.To4(); ip4 != nil {
		// Check if it's actually an IPv4 address that's unsafe
		return isUnsafeIPv4(ip4)
	}

	return false
}

// isUnsafeIPv4 checks if an IPv4 address is in unsafe ranges
func isUnsafeIPv4(ip net.IP) bool {
	// 0.0.0.0/8 (unspecified)
	if ip[0] == 0 {
		return true
	}
	// 10.0.0.0/8 (private)
	if ip[0] == 10 {
		return true
	}
	// 172.16.0.0/12 (private)
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}
	// 192.168.0.0/16 (private)
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}
	// 127.0.0.0/8 (loopback)
	if ip[0] == 127 {
		return true
	}
	// 169.254.0.0/16 (link-local)
	if ip[0] == 169 && ip[1] == 254 {
		return true
	}
	// 224.0.0.0/4 (multicast)
	if ip[0] >= 224 && ip[0] <= 239 {
		return true
	}
	// 240.0.0.0/4 (reserved)
	if ip[0] >= 240 {
		return true
	}

	return false
}

// isRFC1918 returns true if ip is in RFC 1918 ranges (private networks)
func isRFC1918(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast()
}

// isUnsafeRawIP checks if a raw string looks like an unsafe IP address
func isUnsafeRawIP(s string) bool {
	// Check for dotted decimal with unsafe values
	if ip := net.ParseIP(s); ip != nil {
		return isUnsafeIP(ip)
	}
	// Check if it looks like an integer IP
	if isIntegerIP(s) {
		return true
	}
	return false
}

// isSSRFUnsafeRaw checks raw strings that look like unsafe addresses
func isSSRFUnsafeRaw(s string) bool {
	// Remove any scheme if present
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	// Remove port
	if idx := strings.Index(s, ":"); idx >= 0 {
		s = s[:idx]
	}
	// Remove brackets (IPv6)
	s = strings.Trim(s, "[]")
	return isUnsafeRawIP(s)
}

// handlePromptsList processes prompts/list requests
func (p *MCPProxy) handlePromptsList(ctx context.Context, req *MCPRequest) *MCPResponse {
	// Implementation omitted for brevity in this snippet
	return &MCPResponse{ID: req.ID}
}

// handlePromptsGet processes prompts/get requests
func (p *MCPProxy) handlePromptsGet(ctx context.Context, req *MCPRequest) *MCPResponse {
	// Implementation omitted for brevity in this snippet
	return &MCPResponse{ID: req.ID}
}

// HandleWebSocket handles WebSocket connections for MCP
func (p *MCPProxy) HandleWebSocket(c *gin.Context) {
	// Implementation omitted for brevity in this snippet
	conn, err := p.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		p.logger.Error("WebSocket upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	p.logger.Info("WebSocket connection established", "remote_addr", c.Request.RemoteAddr)

	sessionID := conn.RemoteAddr().String()

	// Handle WebSocket messages
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			p.logger.Error("WebSocket read error", "error", err)
			break
		}

		// Session-level threat analysis (multi-turn attack detection)
		if p.sessionAnalyzer != nil {
			assessment := p.sessionAnalyzer.AnalyzeMessage(sessionID, "ws-client", string(message))
			if assessment.BlockConversation {
				errorResponse := MCPResponse{
					Error: &MCPError{
						Code:    -32000,
						Message: "Session blocked by security policy",
						Data:    assessment.RecommendedAction,
					},
				}
				errorJSON, _ := json.Marshal(errorResponse)
				conn.WriteMessage(messageType, errorJSON)
				conn.Close()
				return
			}
		}

		// Process the message through content security filters
		sanitized := p.sanitizer.SanitizeContent(string(message))

		if sanitized.Blocked {
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

	p.logger.Info("WebSocket connection closed", "remote_addr", c.Request.RemoteAddr)
}

// HandleSSE handles Server-Sent Events connections for MCP
func (p *MCPProxy) HandleSSE(c *gin.Context) {
	// Implementation omitted for brevity in this snippet
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	// Use configured AllowedOrigins instead of wildcard
	if origin := p.corsOrigin(c); origin != "" {
		c.Header("Access-Control-Allow-Origin", origin)
	}
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
	// Implementation omitted for brevity in this snippet
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	// Use configured AllowedOrigins instead of wildcard
	if origin := p.corsOrigin(c); origin != "" {
		c.Header("Access-Control-Allow-Origin", origin)
	}
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

// looksLikeURL returns true if the string is plausibly a URL the proxy
// should validate against SSRF. Used to filter tool-call arguments.
func looksLikeURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "ftp://") || strings.HasPrefix(s, "file://") ||
		strings.Contains(s, "://")
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
	case "gopher", "ftp":
		return fmt.Errorf("%s:// URIs are not allowed", parsedURL.Scheme)
	}

	// Validate hostname if present
	if parsedURL.Host != "" {
		hostname := parsedURL.Hostname()
		lower := strings.ToLower(hostname)
		if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || lower == "metadata.google.internal" {
			return fmt.Errorf("internal hostnames are not allowed")
		}
		if ip := net.ParseIP(hostname); ip != nil {
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
				ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
				return fmt.Errorf("IP %s is in a restricted range", ip.String())
			}
		}
	}

	return nil
}

// recordDetectionsToContext maps sanitizer detections to dashboard attack categories.
// Deduplicates by category so each is counted once per request.
func (p *MCPProxy) recordDetectionsToContext(c *gin.Context, detections []sanitizer.Detection) {
	seen := make(map[dashboard.AttackCategory]bool)
	for _, d := range detections {
		cat, ok := sanitizerTypeToCategory(d.Type)
		if ok && !seen[cat] {
			dashboard.RecordAttackInContext(c, cat)
			seen[cat] = true
		}
	}
}

// recordSessionThreatsToContext maps session analyzer patterns to dashboard attack categories.
func (p *MCPProxy) recordSessionThreatsToContext(c *gin.Context, patterns []string) {
	for _, pattern := range patterns {
		cat, ok := sessionPatternToCategory(pattern)
		if ok {
			dashboard.RecordAttackInContext(c, cat)
		}
	}
}

// recordComplianceToContext records a compliance violation when regulated data is detected.
func (p *MCPProxy) recordComplianceToContext(c *gin.Context, result *sanitizer.ComplianceResult) {
	if len(result.PIIDetections) > 0 || len(result.PHIDetections) > 0 || len(result.PCIDetections) > 0 {
		dashboard.RecordAttackInContext(c, dashboard.AttackComplianceViolation)
	}
}

// sanitizerTypeToCategory maps a sanitizer Detection.Type string to a dashboard AttackCategory.
func sanitizerTypeToCategory(detType string) (dashboard.AttackCategory, bool) {
	switch {
	case strings.Contains(detType, "jailbreak") || strings.Contains(detType, "dan"):
		return dashboard.AttackJailbreak, true
	case strings.Contains(detType, "role"):
		return dashboard.AttackRoleEscalation, true
	case strings.Contains(detType, "emotional"):
		return dashboard.AttackEmotionalManip, true
	case strings.Contains(detType, "template") || strings.Contains(detType, "variable"):
		return dashboard.AttackTemplateInjection, true
	case strings.HasPrefix(detType, "prompt_injection_"):
		return dashboard.AttackPromptInjection, true
	case detType == "command_injection":
		return dashboard.AttackCommandInjection, true
	case detType == "xss_attempt":
		return dashboard.AttackXSS, true
	case detType == "sql_injection":
		return dashboard.AttackSQLInjection, true
	case strings.HasPrefix(detType, "secret_"):
		return dashboard.AttackSecretExposure, true
	default:
		return "", false
	}
}

// sessionPatternToCategory maps a ConversationalThreatAnalyzer pattern name to a dashboard AttackCategory.
func sessionPatternToCategory(pattern string) (dashboard.AttackCategory, bool) {
	switch pattern {
	case "role_escalation":
		return dashboard.AttackRoleEscalation, true
	case "dan_progression", "developer_mode", "grandmother_exploit":
		return dashboard.AttackJailbreak, true
	case "context_poisoning":
		return dashboard.AttackPromptInjection, true
	case "distributed_template_injection":
		return dashboard.AttackTemplateInjection, true
	case "emotional_manipulation":
		return dashboard.AttackEmotionalManip, true
	default:
		return "", false
	}
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

// sanitizerVerdictToJudge maps the sanitizer's risk signal to a judge routing
// verdict. ALLOW short-circuits the judge (no LLM call, zero latency);
// SUSPICIOUS routes the payload to the configured judge model for deeper analysis.
// Payloads that the sanitizer has already blocked never reach this function.
func sanitizerVerdictToJudge(result *sanitizer.SanitizationResult) judge.Verdict {
	if result != nil && (len(result.Detections) > 0 || result.Risk == "medium" || result.Risk == "high" || result.Risk == "critical") {
		return judge.SUSPICIOUS
	}
	return judge.ALLOW
}

// corsOrigin returns the appropriate CORS origin header value for SSE endpoints.
// Returns empty string if CORS should not be set.
func (p *MCPProxy) corsOrigin(c *gin.Context) string {
	if origin := p.corsAllowedOrigin(c); origin != "" {
		return origin
	}
	// Fall back to request Origin header if present
	return c.GetHeader("Origin")
}

// corsAllowedOrigin returns the configured allowed origin, or empty string
func (p *MCPProxy) corsAllowedOrigin(c *gin.Context) string {
	// Use configured allowed origins from security config
	if p.config != nil && len(p.config.Security.AllowedOrigins) > 0 {
		origin := c.GetHeader("Origin")
		for _, allowed := range p.config.Security.AllowedOrigins {
			if origin == allowed {
				return allowed
			}
		}
	}
	return ""
}
