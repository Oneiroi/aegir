package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/judge"
	"github.com/aegishjalmur/aegir/internal/sanitizer"
	"github.com/aegishjalmur/aegir/internal/upstream"
	"github.com/gin-gonic/gin"
)

// reasonLeakJudge always returns BLOCK carrying a distinctive reason string.
// If that string surfaces anywhere in the client-facing response, the
// client-isolation principle (ISC-33 / ISC-93) has been violated.
type reasonLeakJudge struct{ reason string }

func (j *reasonLeakJudge) Check(_ context.Context, _ string) (judge.CheckResult, error) {
	return judge.CheckResult{
		Verdict:   judge.BLOCK,
		Reason:    j.reason,
		ModelName: "leak-canary-model",
	}, nil
}

// TestJudgeReasonNeverLeaksToClient is the ISC-33 / ISC-93 regression probe:
// the judge's reasoning is logged server-side but must never appear in the
// response body or any response header sent to the client.
func TestJudgeReasonNeverLeaksToClient(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const canary = "JUDGE_CANARY_a17c3e9b_DO_NOT_LEAK"
	logger := testLogger()
	ruleEng := judge.NewRuleEngine(&reasonLeakJudge{reason: canary}, logger)

	proxy := NewMCPProxy(
		&config.Config{},
		logger,
		sanitizer.New(config.Security{}, logger),
		sanitizer.NewComplianceManager(config.Compliance{}, logger),
		upstream.NewManager(&config.Upstream{}, logger),
		nil, // session analyzer not needed for this path
		nil, // anomaly detector not needed
		ruleEng,
	)

	r := gin.New()
	r.POST("/mcp", proxy.HandleMCPRequest)

	body, _ := json.Marshal(MCPRequest{
		Method: "tools/call",
		Params: map[string]interface{}{"name": "test"},
		ID:     "leak-1",
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 BLOCK, got %d (body: %s)", w.Code, w.Body.String())
	}

	if strings.Contains(w.Body.String(), canary) {
		t.Errorf("judge reason leaked into response body: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "leak-canary-model") {
		t.Errorf("judge model name leaked into response body: %s", w.Body.String())
	}
	for name, values := range w.Header() {
		for _, v := range values {
			if strings.Contains(v, canary) || strings.Contains(v, "leak-canary-model") {
				t.Errorf("judge reasoning leaked into response header %q: %q", name, v)
			}
		}
	}
}

// TestJudgeReasonExposedWhenOptedIn verifies the debug/audit opt-in
// (judge.expose_reasoning=true) actually emits the reason in the BLOCK error
// Data — the deliberate, GDPR-violating debug path the operator must enable.
func TestJudgeReasonExposedWhenOptedIn(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const canary = "JUDGE_CANARY_expose_42f"
	logger := testLogger()
	ruleEng := judge.NewRuleEngine(&reasonLeakJudge{reason: canary}, logger)

	proxy := NewMCPProxy(
		&config.Config{Judge: config.JudgeConfig{ExposeReasoning: true}},
		logger,
		sanitizer.New(config.Security{}, logger),
		sanitizer.NewComplianceManager(config.Compliance{}, logger),
		upstream.NewManager(&config.Upstream{}, logger),
		nil, nil, ruleEng,
	)

	r := gin.New()
	r.POST("/mcp", proxy.HandleMCPRequest)

	body, _ := json.Marshal(MCPRequest{Method: "tools/call", Params: map[string]interface{}{"name": "test"}, ID: "expose-1"})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 BLOCK, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), canary) {
		t.Errorf("with expose_reasoning=true the reason should appear in the BLOCK body, got: %s", w.Body.String())
	}
}
