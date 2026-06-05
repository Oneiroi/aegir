package judge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestServer creates an httptest.Server that returns the given status and body.
// The caller is responsible for calling ts.Close().
func newTestServer(status int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
}

// ollamaResp builds the JSON body that OllamaJudge/APIJudge expect.
func ollamaResp(response string) string {
	b, _ := json.Marshal(ollamaGenerateResponse{Response: response, Done: true})
	return string(b)
}

// ---------------------------------------------------------------------------
// ISC-29: Judge interface, Verdict enum, CheckResult struct
// ---------------------------------------------------------------------------

func TestVerdict_String(t *testing.T) {
	cases := []struct {
		v    Verdict
		want string
	}{
		{ALLOW, "ALLOW"},
		{SUSPICIOUS, "SUSPICIOUS"},
		{BLOCK, "BLOCK"},
		{Verdict(99), "UNKNOWN"},
	}
	for _, tc := range cases {
		if got := tc.v.String(); got != tc.want {
			t.Errorf("Verdict(%d).String() = %q, want %q", tc.v, got, tc.want)
		}
	}
}

func TestCheckResult_Fields(t *testing.T) {
	r := CheckResult{
		Verdict:     BLOCK,
		Reason:      "test",
		LatencyMs:   42,
		ModelName:   "llama3",
		PayloadHash: "abc",
	}
	if r.Verdict != BLOCK {
		t.Errorf("expected BLOCK")
	}
}

// Verify Judge interface is satisfied at compile time.
var _ Judge = (*OllamaJudge)(nil)
var _ Judge = (*APIJudge)(nil)

// ---------------------------------------------------------------------------
// ISC-40: OllamaJudge defaults
// ---------------------------------------------------------------------------

func TestOllamaJudge_Defaults(t *testing.T) {
	j := NewOllamaJudge(Config{}, nil, nil)
	if j.cfg.BaseURL != defaultOllamaBase {
		t.Errorf("BaseURL default: got %q, want %q", j.cfg.BaseURL, defaultOllamaBase)
	}
	if j.cfg.Model != defaultModel {
		t.Errorf("Model default: got %q, want %q", j.cfg.Model, defaultModel)
	}
	if j.cfg.TimeoutMs != defaultTimeoutMs {
		t.Errorf("TimeoutMs default: got %d, want %d", j.cfg.TimeoutMs, defaultTimeoutMs)
	}
}

func TestAPIJudge_Defaults(t *testing.T) {
	j := NewAPIJudge(Config{}, nil, nil)
	if j.cfg.BaseURL != defaultOllamaBase {
		t.Errorf("APIJudge BaseURL default: got %q, want %q", j.cfg.BaseURL, defaultOllamaBase)
	}
}

// ---------------------------------------------------------------------------
// ISC-29 / ISC-40: OllamaJudge.Check — happy path returns ALLOW
// ---------------------------------------------------------------------------

func TestOllamaJudge_Check_Allow(t *testing.T) {
	ts := newTestServer(http.StatusOK, ollamaResp("ALLOW"))
	defer ts.Close()

	j := NewOllamaJudge(Config{BaseURL: ts.URL, TimeoutMs: 2000}, ts.Client(), nil)
	result, err := j.Check(context.Background(), "hello world")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != ALLOW {
		t.Errorf("expected ALLOW, got %s", result.Verdict)
	}
	if result.ModelName == "" {
		t.Error("ModelName should be set")
	}
	if result.PayloadHash == "" {
		t.Error("PayloadHash should be set")
	}
}

// ---------------------------------------------------------------------------
// ISC-29 / ISC-40: OllamaJudge.Check — LLM returns BLOCK
// ---------------------------------------------------------------------------

func TestOllamaJudge_Check_Block(t *testing.T) {
	ts := newTestServer(http.StatusOK, ollamaResp("BLOCK"))
	defer ts.Close()

	j := NewOllamaJudge(Config{BaseURL: ts.URL, TimeoutMs: 2000}, ts.Client(), nil)
	result, err := j.Check(context.Background(), "DROP TABLE users;")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != BLOCK {
		t.Errorf("expected BLOCK, got %s", result.Verdict)
	}
}

// ---------------------------------------------------------------------------
// ISC-38: Payload hash, latency, and model name populated
// ---------------------------------------------------------------------------

func TestOllamaJudge_Check_MetadataPopulated(t *testing.T) {
	ts := newTestServer(http.StatusOK, ollamaResp("ALLOW"))
	defer ts.Close()

	payload := "test payload for hashing"
	j := NewOllamaJudge(Config{BaseURL: ts.URL, Model: "mistral", TimeoutMs: 2000}, ts.Client(), nil)
	result, err := j.Check(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantHash := payloadHash(payload)
	if result.PayloadHash != wantHash {
		t.Errorf("PayloadHash: got %q, want %q", result.PayloadHash, wantHash)
	}
	if result.ModelName != "mistral" {
		t.Errorf("ModelName: got %q, want %q", result.ModelName, "mistral")
	}
	if result.LatencyMs < 0 {
		t.Errorf("LatencyMs should be non-negative, got %d", result.LatencyMs)
	}
}

// ---------------------------------------------------------------------------
// ISC-37: Timeout → BLOCK
// ---------------------------------------------------------------------------

func TestOllamaJudge_Check_Timeout_Blocks(t *testing.T) {
	// Server that never responds within the timeout window.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		fmt.Fprint(w, ollamaResp("ALLOW"))
	}))
	defer ts.Close()

	// 50 ms timeout — server takes 500 ms.
	j := NewOllamaJudge(Config{BaseURL: ts.URL, TimeoutMs: 50}, ts.Client(), nil)
	result, err := j.Check(context.Background(), "anything")
	if err == nil {
		t.Fatal("expected error on timeout, got nil")
	}
	if result.Verdict != BLOCK {
		t.Errorf("timeout must yield BLOCK, got %s", result.Verdict)
	}
}

// ---------------------------------------------------------------------------
// ISC-102/103/104: HTTP 4xx → BLOCK (judge_refused)
// ---------------------------------------------------------------------------

func TestOllamaJudge_Check_HTTP4xx_Blocks(t *testing.T) {
	ts := newTestServer(http.StatusForbidden, `{"error":"safety refusal"}`)
	defer ts.Close()

	j := NewOllamaJudge(Config{BaseURL: ts.URL, TimeoutMs: 2000}, ts.Client(), nil)
	result, err := j.Check(context.Background(), "payload")
	if err == nil {
		t.Fatal("expected error on 4xx, got nil")
	}
	if result.Verdict != BLOCK {
		t.Errorf("4xx must yield BLOCK, got %s", result.Verdict)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error message should mention status code, got %q", err.Error())
	}
}

func TestOllamaJudge_Check_HTTP5xx_Blocks(t *testing.T) {
	ts := newTestServer(http.StatusInternalServerError, `{"error":"server error"}`)
	defer ts.Close()

	j := NewOllamaJudge(Config{BaseURL: ts.URL, TimeoutMs: 2000}, ts.Client(), nil)
	result, err := j.Check(context.Background(), "payload")
	if err == nil {
		t.Fatal("expected error on 5xx, got nil")
	}
	if result.Verdict != BLOCK {
		t.Errorf("5xx must yield BLOCK, got %s", result.Verdict)
	}
}

// ---------------------------------------------------------------------------
// ISC-102/103/104: Unrecognised LLM response → BLOCK (fail-closed)
// ---------------------------------------------------------------------------

func TestOllamaJudge_Check_UnrecognisedResponse_Blocks(t *testing.T) {
	ts := newTestServer(http.StatusOK, ollamaResp("I cannot assist with that."))
	defer ts.Close()

	j := NewOllamaJudge(Config{BaseURL: ts.URL, TimeoutMs: 2000}, ts.Client(), nil)
	result, err := j.Check(context.Background(), "jailbreak attempt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != BLOCK {
		t.Errorf("unrecognised response must yield BLOCK, got %s", result.Verdict)
	}
}

// ---------------------------------------------------------------------------
// ISC-30 / ISC-31 / ISC-97: RuleEngine.Route
// ---------------------------------------------------------------------------

// mockJudge records whether Check was called, and returns a preset result.
type mockJudge struct {
	called bool
	result CheckResult
	err    error
}

func (m *mockJudge) Check(_ context.Context, _ string) (CheckResult, error) {
	m.called = true
	return m.result, m.err
}

// ISC-97: ALLOW → no judge call
func TestRuleEngine_Route_Allow_NoJudgeCall(t *testing.T) {
	mj := &mockJudge{result: CheckResult{Verdict: ALLOW}}
	re := NewRuleEngine(mj, nil)

	result, err := re.Route(context.Background(), ALLOW, "clean content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mj.called {
		t.Error("ISC-97: judge must NOT be called for ALLOW verdict")
	}
	if result.Verdict != ALLOW {
		t.Errorf("expected ALLOW, got %s", result.Verdict)
	}
}

// ISC-31: BLOCK → judge never called
func TestRuleEngine_Route_Block_JudgeNotCalled(t *testing.T) {
	mj := &mockJudge{result: CheckResult{Verdict: ALLOW}} // would flip to ALLOW if called
	re := NewRuleEngine(mj, nil)

	result, err := re.Route(context.Background(), BLOCK, "malicious content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mj.called {
		t.Error("ISC-31: judge must NOT be called for BLOCK verdict")
	}
	if result.Verdict != BLOCK {
		t.Errorf("expected BLOCK, got %s", result.Verdict)
	}
}

// ISC-30: SUSPICIOUS → judge called
func TestRuleEngine_Route_Suspicious_CallsJudge(t *testing.T) {
	mj := &mockJudge{result: CheckResult{Verdict: BLOCK, Reason: "llm: block"}}
	re := NewRuleEngine(mj, nil)

	result, err := re.Route(context.Background(), SUSPICIOUS, "suspicious content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mj.called {
		t.Error("ISC-30: judge MUST be called for SUSPICIOUS verdict")
	}
	if result.Verdict != BLOCK {
		t.Errorf("expected judge result BLOCK, got %s", result.Verdict)
	}
}

// ISC-30: SUSPICIOUS where judge says ALLOW
func TestRuleEngine_Route_Suspicious_JudgeAllows(t *testing.T) {
	mj := &mockJudge{result: CheckResult{Verdict: ALLOW, Reason: "llm: allow"}}
	re := NewRuleEngine(mj, nil)

	result, err := re.Route(context.Background(), SUSPICIOUS, "benign but unusual")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mj.called {
		t.Error("judge must be called for SUSPICIOUS")
	}
	if result.Verdict != ALLOW {
		t.Errorf("expected ALLOW from judge, got %s", result.Verdict)
	}
}

// ---------------------------------------------------------------------------
// ISC-97 anti-pattern: ALLOW must produce no judge log entry.
// Verified structurally: mockJudge not called, so no log-side-effects possible.
// ---------------------------------------------------------------------------

func TestRuleEngine_Route_Allow_NoLogEntry(t *testing.T) {
	mj := &mockJudge{}
	re := NewRuleEngine(mj, nil)

	_, _ = re.Route(context.Background(), ALLOW, "definitely fine")
	if mj.called {
		t.Error("ISC-97: no judge call → no judge log entry possible")
	}
}

// ---------------------------------------------------------------------------
// APIJudge — injectable client, bearer token set
// ---------------------------------------------------------------------------

func TestAPIJudge_Check_SetsAuthHeader(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, ollamaResp("ALLOW"))
	}))
	defer ts.Close()

	j := NewAPIJudge(Config{BaseURL: ts.URL, APIKey: "secret-key", TimeoutMs: 2000}, ts.Client(), nil)
	_, err := j.Check(context.Background(), "payload")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer secret-key" {
		t.Errorf("Authorization header: got %q, want %q", gotAuth, "Bearer secret-key")
	}
}

// ---------------------------------------------------------------------------
// parseVerdict — unit tests for edge cases
// ---------------------------------------------------------------------------

func TestParseVerdict(t *testing.T) {
	cases := []struct {
		response string
		want     Verdict
	}{
		{"ALLOW", ALLOW},
		{"BLOCK", BLOCK},
		{"  ALLOW  ", ALLOW},
		{"\nALLOW\n", ALLOW},
		{"I cannot help with that", BLOCK},
		{"", BLOCK},
		{"allow", BLOCK}, // case-sensitive → fail closed
		{"block", BLOCK},
	}
	for _, tc := range cases {
		got := parseVerdict(tc.response, "test").Verdict
		if got != tc.want {
			t.Errorf("parseVerdict(%q): got %s, want %s", tc.response, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// payloadHash — deterministic
// ---------------------------------------------------------------------------

func TestPayloadHash_Deterministic(t *testing.T) {
	h1 := payloadHash("hello")
	h2 := payloadHash("hello")
	if h1 != h2 {
		t.Errorf("hash should be deterministic: %q != %q", h1, h2)
	}
	h3 := payloadHash("world")
	if h1 == h3 {
		t.Errorf("different payloads should produce different hashes")
	}
	if len(h1) != 64 {
		t.Errorf("SHA-256 hex should be 64 chars, got %d", len(h1))
	}
}
