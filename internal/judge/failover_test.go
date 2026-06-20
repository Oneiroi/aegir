package judge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// ---------------------------------------------------------------------------
// ISC-142: Anti-criterion — failover NEVER triggers on a verdict.
// ---------------------------------------------------------------------------

// countingJudge wraps a primary judge and a secondary judge, mirroring the
// failover contract: the secondary is only consulted when the primary fails
// with a TRANSPORT error. It records whether the secondary was ever called.
type countingJudge struct {
	primary       Judge
	secondary     Judge
	secondaryHits int32
}

func (c *countingJudge) Check(ctx context.Context, payload string) (CheckResult, error) {
	res, err := c.primary.Check(ctx, payload)
	if err == nil {
		// Primary returned a verdict → terminal. Secondary MUST NOT be called.
		return res, nil
	}
	if !isTransportError(err) {
		// Refusal / parse failure / non-2xx → terminal. No failover.
		return res, err
	}
	// Only transport errors reach the secondary.
	atomic.AddInt32(&c.secondaryHits, 1)
	return c.secondary.Check(ctx, payload)
}

// verdictJudge always returns the given verdict with no error.
type verdictJudge struct{ v Verdict }

func (j *verdictJudge) Check(_ context.Context, _ string) (CheckResult, error) {
	return CheckResult{Verdict: j.v, Reason: "mock verdict"}, nil
}

// trackingJudge records every call so we can assert it is never invoked.
type trackingJudge struct{ hits int32 }

func (j *trackingJudge) Check(_ context.Context, _ string) (CheckResult, error) {
	atomic.AddInt32(&j.hits, 1)
	return CheckResult{Verdict: ALLOW, Reason: "secondary should never run"}, nil
}

// TestFailoverNeverTriggersOnVerdict is the ISC-142 anti-criterion.
//
// 1. Primary mock judge returns a valid verdict (ALLOW).
// 2. It is wrapped with failover logic.
// 3. The secondary backend must NEVER be called when the primary returns a verdict.
func TestFailoverNeverTriggersOnVerdict(t *testing.T) {
	primary := &verdictJudge{v: ALLOW}
	secondary := &trackingJudge{}

	cj := &countingJudge{primary: primary, secondary: secondary}

	result, err := cj.Check(context.Background(), "any payload")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != ALLOW {
		t.Errorf("expected ALLOW from primary, got %s", result.Verdict)
	}
	if got := atomic.LoadInt32(&secondary.hits); got != 0 {
		t.Errorf("ISC-142: secondary backend must NEVER be called on a verdict, got %d calls", got)
	}
	if got := atomic.LoadInt32(&cj.secondaryHits); got != 0 {
		t.Errorf("ISC-142: failover path must not be taken on a verdict, got %d", got)
	}
}

// TestFailoverNeverTriggersOnVerdict_Block confirms a BLOCK verdict is equally
// terminal — even an "unwanted" verdict does not trigger failover (ISC-141/142).
func TestFailoverNeverTriggersOnVerdict_Block(t *testing.T) {
	cj := &countingJudge{primary: &verdictJudge{v: BLOCK}, secondary: &trackingJudge{}}
	result, err := cj.Check(context.Background(), "payload")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != BLOCK {
		t.Errorf("expected BLOCK, got %s", result.Verdict)
	}
	if got := atomic.LoadInt32(&cj.secondaryHits); got != 0 {
		t.Errorf("ISC-142: BLOCK verdict must not trigger failover, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// ISC-141: end-to-end failover via check() on a real transport error.
// ---------------------------------------------------------------------------

// TestFailover_TransportError_FallsOver verifies that when the PRIMARY backend
// is unreachable (transport error), check() falls over to the secondary and
// returns its verdict.
func TestFailover_TransportError_FallsOver(t *testing.T) {
	// Secondary backend: healthy, returns ALLOW.
	secondary := newTestServer(http.StatusOK, ollamaResp("ALLOW"))
	defer secondary.Close()

	// Primary: an unroutable address → connection failure (transport error).
	cfg := Config{
		BaseURL:   "http://127.0.0.1:1", // refused
		Model:     "primary-model",
		TimeoutMs: 1000,
		Provider:  ProviderOllama,
		Fallbacks: []FallbackConfig{
			{BaseURL: secondary.URL, Model: "fallback-model", Provider: ProviderOllama},
		},
	}

	result, err := check(context.Background(), "payload", resolveConfig(cfg), secondary.Client(), nil)
	if err != nil {
		t.Fatalf("expected failover to succeed, got error: %v", err)
	}
	if result.Verdict != ALLOW {
		t.Errorf("expected ALLOW from fallback, got %s", result.Verdict)
	}
	if result.ModelName != "fallback-model" {
		t.Errorf("expected fallback model to answer, got %q", result.ModelName)
	}
}

// TestFailover_Not_Triggered_On_Non2xx confirms that a 4xx/5xx from the primary
// is a terminal BLOCK and does NOT cascade to the fallback (ISC-141).
func TestFailover_Not_Triggered_On_Non2xx(t *testing.T) {
	var fallbackHits int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fallbackHits, 1)
		fmt.Fprint(w, ollamaResp("ALLOW"))
	}))
	defer fallback.Close()

	// Primary returns 403 — an implicit BLOCK verdict, not a transport error.
	primary := newTestServer(http.StatusForbidden, `{"error":"denied"}`)
	defer primary.Close()

	cfg := Config{
		BaseURL:   primary.URL,
		Model:     "primary",
		TimeoutMs: 1000,
		Provider:  ProviderOllama,
		Fallbacks: []FallbackConfig{
			{BaseURL: fallback.URL, Model: "fallback", Provider: ProviderOllama},
		},
	}

	result, err := check(context.Background(), "payload", resolveConfig(cfg), primary.Client(), nil)
	if err == nil {
		t.Fatal("expected error from 4xx primary, got nil")
	}
	if result.Verdict != BLOCK {
		t.Errorf("4xx must yield BLOCK, got %s", result.Verdict)
	}
	if got := atomic.LoadInt32(&fallbackHits); got != 0 {
		t.Errorf("ISC-141: non-2xx is a verdict, fallback must NOT be called, got %d", got)
	}
}

// TestFailover_Not_Triggered_On_MalformedJSON confirms malformed JSON from the
// primary is a terminal parse failure (BLOCK), not a transport error (ISC-141).
func TestFailover_Not_Triggered_On_MalformedJSON(t *testing.T) {
	var fallbackHits int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fallbackHits, 1)
		fmt.Fprint(w, ollamaResp("ALLOW"))
	}))
	defer fallback.Close()

	primary := newTestServer(http.StatusOK, `{not valid json`)
	defer primary.Close()

	cfg := Config{
		BaseURL:   primary.URL,
		Model:     "primary",
		TimeoutMs: 1000,
		Provider:  ProviderOllama,
		Fallbacks: []FallbackConfig{
			{BaseURL: fallback.URL, Model: "fallback", Provider: ProviderOllama},
		},
	}

	result, err := check(context.Background(), "payload", resolveConfig(cfg), primary.Client(), nil)
	if err == nil {
		t.Fatal("expected parse error from primary, got nil")
	}
	if result.Verdict != BLOCK {
		t.Errorf("malformed JSON must yield BLOCK, got %s", result.Verdict)
	}
	if got := atomic.LoadInt32(&fallbackHits); got != 0 {
		t.Errorf("ISC-141: malformed JSON is a parse failure, fallback must NOT be called, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// ISC-140: Anthropic Messages adapter.
// ---------------------------------------------------------------------------

func TestAnthropicJudge_Check_Allow(t *testing.T) {
	var gotPath, gotKey, gotVersion string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		body, _ := json.Marshal(anthropicResponse{
			Content: []anthropicContentBlock{{Type: "text", Text: "ALLOW"}},
		})
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, string(body))
	}))
	defer ts.Close()

	j := NewAnthropicJudge(Config{BaseURL: ts.URL, APIKey: "sk-ant-123", Model: "claude-x", TimeoutMs: 2000}, ts.Client(), nil)
	result, err := j.Check(context.Background(), "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != ALLOW {
		t.Errorf("expected ALLOW, got %s", result.Verdict)
	}
	if gotPath != "/v1/messages" {
		t.Errorf("expected POST to /v1/messages, got %q", gotPath)
	}
	if gotKey != "sk-ant-123" {
		t.Errorf("x-api-key header: got %q", gotKey)
	}
	if gotVersion != "2023-06-01" {
		t.Errorf("anthropic-version header: got %q", gotVersion)
	}
}

func TestAnthropicJudge_Check_FirstTextBlock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(anthropicResponse{
			Content: []anthropicContentBlock{
				{Type: "thinking", Text: "BLOCK"}, // non-text block must be skipped
				{Type: "text", Text: "ALLOW"},
			},
		})
		fmt.Fprint(w, string(body))
	}))
	defer ts.Close()

	j := NewAnthropicJudge(Config{BaseURL: ts.URL, APIKey: "k", Model: "m", TimeoutMs: 2000}, ts.Client(), nil)
	result, err := j.Check(context.Background(), "payload")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != ALLOW {
		t.Errorf("expected ALLOW from first text block, got %s", result.Verdict)
	}
}

// NewJudge factory routes provider="anthropic" to the anthropic adapter.
func TestNewJudge_RoutesByProvider(t *testing.T) {
	if _, ok := NewJudge(Config{Provider: ProviderAnthropic}, nil, nil).(*AnthropicJudge); !ok {
		t.Error("provider=anthropic should yield *AnthropicJudge")
	}
	if _, ok := NewJudge(Config{Provider: ProviderOpenAI}, nil, nil).(*OpenAICompatJudge); !ok {
		t.Error("provider=openai should yield *OpenAICompatJudge")
	}
	if _, ok := NewJudge(Config{}, nil, nil).(*OpenAICompatJudge); !ok {
		t.Error("empty provider should default to *OpenAICompatJudge (ollama)")
	}
}

// ISC-138: empty provider resolves to "ollama".
func TestResolveConfig_DefaultProvider(t *testing.T) {
	got := resolveConfig(Config{})
	if got.Provider != ProviderOllama {
		t.Errorf("default provider: got %q, want %q", got.Provider, ProviderOllama)
	}
}

// Compile-time interface checks for the new adapters.
var _ Judge = (*OpenAICompatJudge)(nil)
var _ Judge = (*AnthropicJudge)(nil)
