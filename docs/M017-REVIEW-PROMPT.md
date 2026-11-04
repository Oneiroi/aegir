# Review request: Aegir M017 "System-1" judge triage tier — design + Go implementation so far

You are reviewing an in-progress security feature in a Go MCP (Model Context
Protocol) security gateway called **Aegir**. I need a hard technical review:
design correctness, security/fail-closed semantics, Go correctness, and test
quality. Please be adversarial rather than encouraging, and prioritise findings
that would let malicious traffic through or crash/block benign traffic.

## Critical context about how this code was produced

- The implementing agent had **no Go toolchain and no network** in its sandbox:
  nothing here has been compiled or `go vet`-ed by the author. A human runs
  `go build ./... && go test ./...` externally and pastes results back.
- That gate has already caught three real defects in this small package:
  1. `fmt.Errorf("%.3f", json.Number)` — vet type mismatch (fixed).
  2. A test-only `httptest` handler blocking on `<-r.Context().Done()` that
     deadlocked `httptest.Server.Close()` in cleanup (fixed with a raw silent
     `net.Listen` listener + a `done` channel to avoid a `send on closed channel`
     panic).
  3. **The one I most want your eyes on:** `EscalationEnabled bool` defaulting via
     a "fill zero-valued fields" `Defaults()` pass. A plain `bool`'s zero value is
     `false`, so an unset flag silently meant *escalation disabled*, which made
     mid-band malicious confidence (e.g. 0.90) take the **fast-path ALLOW** with no
     System-2 judge call — an accidental fail-open, violating the spec'd
     "default true". `TestDecide` surfaced it via self-contradictory reason
     strings ("malicious 0.90 **below** escalation floor 0.85"). The author's fix
     (below, unverified) makes it a `*bool` tri-state resolved by
     `EscalationOn()`, where nil resolves to true.
- So: assume the author is competent but flying blind. Specifically hunt for
  **more instances of the same class of bug** (zero-value/tri-state defaulting,
  silent coercion, fail-open-by-omission), and for anything that will not compile.

## Repo hard constraints (from AGENTS.md — violations are findings)

- Fail closed: judge/classifier timeout, refusal, or backend error → BLOCK, never
  ALLOW. (`judge.fail_open` is a separate, explicit, operator-opt-in escape hatch
  that already exists in this repo; default false.)
- No new external Go dependencies — stdlib only (`net/http`, `encoding/json`).
- LLM judge (System-2) is invoked **only** on already-SUSPICIOUS-flagged traffic.
- Classifier must not add >10ms p99 to the **non-judge** path; spec'd budget is
  <250ms p95 on the judged path.
- TLS 1.3 minimum; **all log entries HMAC-protected**.
- Classifier output (label/confidence/reasoning) must **never** reach the client.
- Patterns pre-compiled; no catastrophic-backtracking regex.
- Local-first: default provider must be a local endpoint; hosted API (Jev) is
  explicit opt-in only, because MCP payloads may contain regulated data.

## The feature (M017) — intended semantics

A fast "System One" decision model (Kev/Laya class, single non-generative
prefill pass, returns a **calibrated probability per label**) is inserted in
front of the existing System-2 LLM judge. Only on SUSPICIOUS traffic:

```
SUSPICIOUS payload
      |
System-1 Classify(payload) --error/timeout--> escalate to System-2 (fail-closed);
      |                                        if escalation disabled -> failVerdict
      |                                        policy (BLOCK default, ALLOW only if
      |                                        judge.fail_open)
      v  malicious confidence m, top-label confidence t
m >= block_confidence (0.95)                         -> BLOCK now, no System-2 call
t < min_confidence (0.60) [uncertain, either side]   -> escalate; if escalation
                                                        disabled -> BLOCK, never allow
m >= floor(escalation_threshold) (default "critical" = 0.85)  -> escalate to System-2
otherwise                                            -> ALLOW fast path + audit event
```

Severity bands are configurable and `escalation_threshold` is expressed as a band
**name** (default `critical`), i.e. critical>=0.85, high>=0.65, medium>=0.40.
`judge.system1.enabled` defaults **false**, and when disabled the request path
must be byte-identical to pre-M017 (classifier never constructed).

Relevant spec clauses (ISCs) the code claims to satisfy:
- ISC-181 `Classifier` interface exists.
- ISC-182 parse per-label calibrated probability; **malformed/absent probability
  → error, never a fabricated score**.
- ISC-183/184/185 block-shortcut (zero judge calls) / escalate / fast-path allow.
- ISC-186 classifier error → escalate if enabled, else `failVerdict`.
- ISC-187 uncertainty escalates; with escalation disabled it BLOCKs, never allows.
- ISC-188 thresholds configurable; invalid band names or
  `block_confidence <= escalation band floor` rejected **at config load**.
- ISC-189 escalation toggle, default true.
- ISC-190 invoked only on SUSPICIOUS path; non-judge path latency unchanged.
- ISC-191 every classification emits an HMAC audit event with payload hash,
  confidence, band, action, latency, model.
- ISC-192 classifier label/confidence/reasoning never leak to client.
- ISC-193 local-first default.
- ISC-195 classifier <250ms p95 vs mock backend; e2e SUSPICIOUS p95 <2s preserved.
- ISC-196 dormant-by-default byte-identical behavior. ISC-197 no new deps.

## Known open items (do not re-report as new, but do sanity-check the fixes)

- The `*bool` tri-state fix for `EscalationEnabled` is applied but **not yet
  gate-verified**. `Decide()` now calls `cfg.EscalationOn()`; tests assign
  `boolPtr(false)`.
- M017.0 "falsifying spike" (actually serve Kev/Laya on target hardware and verify
  the `/v1/systemone` wire shape and latency) **has not been run** — the wire
  shape below is taken from a planning doc. Parsing was made deliberately strict
  so a divergent real shape errors out rather than inventing a score.
- Config layer (`internal/config`) and wiring into `judge.RuleEngine` /
  `internal/server` are **not written yet** — this is package core only. So some
  ISCs (183,184,185,186,190,191,192,196) are necessarily not yet provable.
## Code under review

### internal/system1/system1.go
```go
// Package system1 provides a thin client for a locally-served System One
// decision model (Kev/Laya class; hosted Jev only as explicit opt-in) used as
// the fast triage tier in front of the System-2 LLM judge (M017, ISC-181/182).
//
// A System One model answers in a single non-generative pass and returns a
// calibrated probability per allowed answer label. That probability drives the
// escalation logic in Decide(): outright BLOCK at or above block_confidence,
// escalation to the System-2 judge inside the severity band, and a fast-path
// ALLOW below it — with uncertainty and classifier failure always failing
// closed (escalate, or BLOCK when escalation is disabled).
//
// The wire shape (POST {base_url}/v1/systemone) is the shape shared by Kev's
// server, ollaya, and TypeSafe's API as recorded in docs/M017-IMPLEMENTATION-
// PLAN.md. NOTE: the M017.0 falsifying spike has not yet been run on target
// hardware; parsing is deliberately strict so a divergent real shape produces
// an error (which escalates/fails closed) rather than a fabricated score.
package system1

import (
	"context"
	"errors"
	"fmt"
)

// Action is the routing decision derived from a Classification.
type Action int

const (
	// Allow routes the payload forward without a System-2 judge call.
	Allow Action = iota
	// Escalate hands the payload to the existing System-2 LLM judge path.
	Escalate
	// Block rejects the payload immediately, without a System-2 judge call.
	Block
)

// String renders the action as the audit vocabulary used across Aegir.
func (a Action) String() string {
	switch a {
	case Allow:
		return "ALLOW"
	case Escalate:
		return "ESCALATE"
	case Block:
		return "BLOCK"
	}
	return "BLOCK" // unreachable for defined values; fail closed if ever hit
}

// Severity band names — the same critical|high|medium|low ladder the rest of
// Aegir uses. escalation_threshold is expressed as one of these names.
const (
	BandCritical = "critical"
	BandHigh     = "high"
	BandMedium   = "medium"
	BandLow      = "low"
)

// SeverityBands maps a band name to its lower malicious-confidence bound.
type SeverityBands map[string]float64

// DefaultSeverityBands returns the M017 plan defaults (critical ≥0.85,
// high ≥0.65, medium ≥0.40; anything below medium is low).
func DefaultSeverityBands() SeverityBands {
	return SeverityBands{
		BandCritical: 0.85,
		BandHigh:     0.65,
		BandMedium:   0.40,
	}
}

// Band maps a malicious confidence to its severity band name.
func (b SeverityBands) Band(m float64) string {
	switch {
	case m >= b[BandCritical]:
		return BandCritical
	case m >= b[BandHigh]:
		return BandHigh
	case m >= b[BandMedium]:
		return BandMedium
	default:
		return BandLow
	}
}

// Floor returns the lower bound of a named band. An unknown name resolves to
// the critical floor (0.85) — the most conservative escalation trigger, so a
// misconfiguration escalates MORE traffic to System-2, never less. Config
// validation rejects unknown band names at load time regardless (ISC-188).
func (b SeverityBands) Floor(name string) float64 {
	if f, ok := b[name]; ok {
		return f
	}
	if name == BandLow {
		return 0.0
	}
	return DefaultSeverityBands()[BandCritical]
}

// ErrNoProbability signals a response that carries no usable calibrated
// probability (no results, a probability outside [0,1], or the expected
// malicious label absent). Never substituted with a fabricated score (ISC-182).
var ErrNoProbability = errors.New("system1: response carries no usable calibrated probability")

// transportError marks connection-level faults (refused, DNS, timeout),
// mirroring judge.transportError so callers can distinguish transport failures
// from verdict-level ones (ISC-141 taxonomy parity).
type transportError struct{ err error }

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

// IsTransportError reports whether err is a connection-level System-1 fault.
func IsTransportError(err error) bool {
	var te *transportError
	return errors.As(err, &te)
}

// Config is the System-1 client + decision configuration. It mirrors the
// judge.Config idiom; internal/config.JudgeSystem1Config maps onto it 1:1
// (M017.2, ISC-188).
type Config struct {
	// Provider: kev | laya | jev. jev is a hosted API — explicit opt-in only
	// (local-first constraint, ISC-193).
	Provider string `json:"provider" mapstructure:"provider"`
	BaseURL  string `json:"base_url" mapstructure:"base_url"`
	Model    string `json:"model" mapstructure:"model"`
	APIKey   string `json:"api_key" mapstructure:"api_key"`
	// TimeoutMs bounds a single classification call. Default 250.
	TimeoutMs int `json:"timeout_ms" mapstructure:"timeout_ms"`

	// EscalationEnabled toggles the System-2 escalation path (ISC-189). It is a
	// *bool, not a bool, ON PURPOSE: the default is TRUE, and a plain bool's zero
	// value is false, so any "fill zero-valued fields" defaulting pass would
	// silently read an unset flag as "escalation off" and fast-path ALLOW
	// mid-band malicious traffic to the client without a System-2 call (an
	// accidental fail-open, caught by TestDecide). nil means "unset" and is
	// resolved by EscalationOn() to true — fail safe, escalate more. Explicit
	// false still disables the path.
	EscalationEnabled *bool `json:"escalation_enabled" mapstructure:"escalation_enabled"`
	// EscalationThreshold is a severity band NAME (default "critical").
	EscalationThreshold string             `json:"escalation_threshold" mapstructure:"escalation_threshold"`
	BlockConfidence     float64            `json:"block_confidence" mapstructure:"block_confidence"`
	MinConfidence       float64            `json:"min_confidence" mapstructure:"min_confidence"`
	SeverityBands       SeverityBands      `json:"severity_bands" mapstructure:"severity_bands"`
}

// Defaults fills zero-valued fields with the M017 plan defaults. Exported for
// use by internal/config defaults and tests.
func (c *Config) Defaults() {
	if c.Provider == "" {
		c.Provider = "kev"
	}
	if c.BaseURL == "" {
		c.BaseURL = "http://localhost:11435"
	}
	if c.Model == "" {
		c.Model = "kev-9b"
	}
	if c.TimeoutMs <= 0 {
		c.TimeoutMs = 250
	}
	if c.EscalationEnabled == nil {
		c.EscalationEnabled = boolPtr(true) // ISC-189 default: escalation on
	}
	if c.EscalationThreshold == "" {
		c.EscalationThreshold = BandCritical
	}
	if c.BlockConfidence <= 0 {
		c.BlockConfidence = 0.95
	}
	if c.MinConfidence <= 0 {
		c.MinConfidence = 0.60
	}
	if len(c.SeverityBands) == 0 {
		c.SeverityBands = DefaultSeverityBands()
	}
}

// boolPtr returns a pointer to b; used for tri-state bool config fields and
// for building them in tests.
func boolPtr(b bool) *bool { return &b }

// EscalationOn reports whether the System-2 escalation path is active. An
// unset flag counts as ON (ISC-189 default true), so a Config built without
// Defaults() — or a config file that never mentions the key — escalates rather
// than silently fast-pathing suspicious traffic past the judge.
func (c Config) EscalationOn() bool {
	return c.EscalationEnabled == nil || *c.EscalationEnabled
}

// Classification is one System-1 verdict: the full per-label calibrated
// probability map plus the derived malicious confidence, severity band, and
// call metadata used for HMAC audit events (ISC-191 field set).
type Classification struct {
	Model               string             `json:"model"`
	Probabilities       map[string]float64 `json:"probabilities"`
	MaliciousConfidence float64            `json:"malicious_confidence"`
	TopLabel            string             `json:"top_label"`
	TopConfidence       float64            `json:"top_confidence"`
	Band                string             `json:"band"`
	PayloadHash         string             `json:"payload_hash"`
	LatencyMs           int64              `json:"latency_ms"`
}

// Classifier is the System-1 contract (ISC-181).
type Classifier interface {
	Classify(ctx context.Context, payload string) (Classification, error)
}

// MaliciousLabel is the answer label carrying malicious confidence. Kev/Laya
// decision vocabularies expose a "malicious" answer; a divergent vocabulary
// surfaces as ErrNoProbability rather than a guess (ISC-182).
const MaliciousLabel = "malicious"

// Decide is the pure M017 decision function (plan flowchart). It performs no
// I/O; call-site wiring enforces that Block/Allow skip the judge and Escalate
// invokes it (ISC-183..187, ISC-189).
func Decide(cfg Config, cls Classification) (Action, string) {
	m := cls.MaliciousConfidence

	// Uncertainty first: a low-confidence label in either direction is not a
	// verdict. Escalate; with escalation disabled, BLOCK — never allow.
	if cls.TopConfidence < cfg.MinConfidence {
		if cfg.EscalationOn() {
			return Escalate, fmt.Sprintf("system1 uncertain: top label %q confidence %.2f < min_confidence %.2f",
				cls.TopLabel, cls.TopConfidence, cfg.MinConfidence)
		}
		return Block, fmt.Sprintf("system1 uncertain and escalation disabled: fail closed (%q %.2f)",
			cls.TopLabel, cls.TopConfidence)
	}

	if m >= cfg.BlockConfidence {
		return Block, fmt.Sprintf("system1 malicious confidence %.2f >= block_confidence %.2f: shortcut block, no System-2 call",
			m, cfg.BlockConfidence)
	}

	floor := cfg.SeverityBands.Floor(cfg.EscalationThreshold)
	if cfg.EscalationOn() && m >= floor {
		return Escalate, fmt.Sprintf("system1 band %s (malicious %.2f >= %s floor %.2f): escalate to System-2",
			cfg.SeverityBands.Band(m), m, cfg.EscalationThreshold, floor)
	}

	return Allow, fmt.Sprintf("system1 malicious %.2f below escalation floor %.2f and label confident: fast-path allow",
		m, floor)
}
```

### internal/system1/client.go
```go
package system1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client speaks the System One wire shape over stdlib net/http: a single
// non-generative POST {base_url}/v1/systemone returning per-label calibrated
// probabilities (ISC-182). No new module dependencies (Anti-ISC-197).
type Client struct {
	cfg        Config
	httpClient *http.Client
}

// compile-time proof *Client satisfies the Classifier interface (ISC-181).
var _ Classifier = (*Client)(nil)

// New builds a Client. Zero-valued config fields take the M017 defaults.
// The HTTP timeout is hard-capped at TimeoutMs so a slow classifier can never
// outlive the caller's context budget (ISC-195 latency guard).
func New(cfg Config) *Client {
	cfg.Defaults()
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.TimeoutMs) * time.Millisecond,
		},
	}
}

// Config exposes the effective (defaulted) configuration for probes.
func (c *Client) Config() Config { return c.cfg }

type classifyRequest struct {
	Model string `json:"model"`
	Input string `json:"input"`
}

type labelProbability struct {
	Label string `json:"label"`
	// json.Number (not float64) so JSON null / strings are REJECTED at parse
	// time instead of silently coercing to 0.0 — a null probability is an
	// absent probability, never a score of zero (ISC-182).
	Probability json.Number `json:"probability"`
}

type classifyResponse struct {
	Results []labelProbability `json:"results"`
}

// Classify performs one System-1 pass. Every failure mode returns an error:
// transport faults wrapped as *transportError, verdict-level faults (non-2xx,
// malformed body, absent/out-of-range probability) as plain errors. There is
// no path that yields a Classification with an invented score (ISC-182); the
// caller maps error → escalate or failVerdict (ISC-186).
func (c *Client) Classify(ctx context.Context, payload string) (Classification, error) {
	start := time.Now()

	body, err := json.Marshal(classifyRequest{Model: c.cfg.Model, Input: payload})
	if err != nil {
		return Classification{}, fmt.Errorf("system1: marshal request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.TimeoutMs)*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.cfg.BaseURL, "/")+"/v1/systemone", bytes.NewReader(body))
	if err != nil {
		return Classification{}, fmt.Errorf("system1: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Refused / DNS / deadline → transport-class fault (parity with judge
		// ISC-141 taxonomy); the caller escalates or applies fail policy.
		return Classification{}, &transportError{fmt.Errorf("system1: http: %w", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Verdict-level fault, NOT transport: no failover implication.
		return Classification{}, fmt.Errorf("system1: backend returned %d", resp.StatusCode)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Classification{}, &transportError{fmt.Errorf("system1: read response: %w", err)}
	}

	var parsed classifyResponse
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return Classification{}, fmt.Errorf("system1: unmarshal response: %w", err)
	}

	cls, err := classificationFrom(parsed, c.cfg.Model)
	if err != nil {
		return Classification{}, err
	}
	cls.LatencyMs = time.Since(start).Milliseconds()
	cls.Band = c.cfg.SeverityBands.Band(cls.MaliciousConfidence)
	return cls, nil
}

// classificationFrom validates the parsed probabilities strictly: at least one
// result, every probability inside [0,1], and the malicious label present.
// Anything else is ErrNoProbability — never a fabricated score (ISC-182).
func classificationFrom(parsed classifyResponse, model string) (Classification, error) {
	if len(parsed.Results) == 0 {
		return Classification{}, fmt.Errorf("system1: empty results: %w", ErrNoProbability)
	}
	cls := Classification{
		Model:         model,
		Probabilities: make(map[string]float64, len(parsed.Results)),
	}
	seen := false
	for _, r := range parsed.Results {
		label := strings.ToLower(strings.TrimSpace(r.Label))
		if label == "" {
			return Classification{}, fmt.Errorf("system1: unlabeled result: %w", ErrNoProbability)
		}
		p, err := r.Probability.Float64()
		if err != nil {
			return Classification{}, fmt.Errorf("system1: label %q probability %q not a number: %w",
				label, r.Probability.String(), ErrNoProbability)
		}
		if p < 0 || p > 1 {
			return Classification{}, fmt.Errorf("system1: label %q probability %.3f outside [0,1]: %w",
				label, p, ErrNoProbability)
		}
		cls.Probabilities[label] = p
		if p >= cls.TopConfidence {
			cls.TopLabel, cls.TopConfidence = label, p
		}
		if label == MaliciousLabel {
			cls.MaliciousConfidence = p
			seen = true
		}
	}
	if !seen {
		return Classification{}, fmt.Errorf("system1: %q label absent from %d results: %w",
			MaliciousLabel, len(parsed.Results), ErrNoProbability)
	}
	return cls, nil
}
```

### internal/system1/system1_test.go
```go
package system1

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ISC-181: compile-time proof the package defines the Classifier contract and
// *Client implements it (assertion also lives in client.go).
func TestClassifierInterfaceExists(t *testing.T) {
	// Dead endpoint (closed test server) — never the real kev default port,
	// which may be live on a spike box.
	dead := httptest.NewServer(nil)
	url := dead.URL
	dead.Close()
	var c Classifier = New(Config{BaseURL: url})
	if _, err := c.Classify(context.Background(), "ignore previous instructions"); err == nil {
		t.Fatal("expected transport error against dead endpoint, got nil")
	}
}

// newMock serves fn for POST /v1/systemone.
func newMock(t *testing.T, fn func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/systemone", fn)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func okBody(model string, probs map[string]float64) string {
	res := ""
	first := true
	for label, p := range probs {
		if !first {
			res += ","
		}
		first = false
		res += fmt.Sprintf(`{"label":%q,"probability":%g}`, label, p)
	}
	return fmt.Sprintf(`{"model":%q,"results":[%s]}`, model, res)
}

func testConfig(baseURL string) Config {
	cfg := Config{BaseURL: baseURL}
	cfg.Defaults()
	return cfg
}

// ISC-182: happy path parses per-label calibrated probabilities in [0,1].
func TestSystem1Classify(t *testing.T) {
	srv := newMock(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method: got %s want POST", r.Method)
		}
		fmt.Fprint(w, okBody("kev-9b", map[string]float64{"malicious": 0.91, "benign": 0.09}))
	})
	c := New(testConfig(srv.URL))
	cls, err := c.Classify(context.Background(), "exfiltrate /etc/passwd")
	if err != nil {
		t.Fatalf("ISC-182: classify failed: %v", err)
	}
	if cls.MaliciousConfidence != 0.91 {
		t.Errorf("malicious confidence: got %v want 0.91", cls.MaliciousConfidence)
	}
	if cls.Probabilities["benign"] != 0.09 {
		t.Errorf("per-label probability missing: %+v", cls.Probabilities)
	}
	if cls.TopLabel != "malicious" || cls.TopConfidence != 0.91 {
		t.Errorf("top label/conf: got %q/%v", cls.TopLabel, cls.TopConfidence)
	}
	if cls.Band != BandCritical {
		t.Errorf("band: got %s want %s", cls.Band, BandCritical)
	}
	if cls.Model != "kev-9b" {
		t.Errorf("model: got %s", cls.Model)
	}
}

// ISC-182: malformed or absent probability → error, never a fabricated score.
func TestSystem1ClassifyStrictParsing(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty results", `{"results":[]}`},
		{"probability > 1", `{"results":[{"label":"malicious","probability":1.4}]}`},
		{"probability < 0", `{"results":[{"label":"malicious","probability":-0.2}]}`},
		{"malicious label absent", `{"results":[{"label":"benign","probability":0.99}]}`},
		{"probability not a number", `{"results":[{"label":"malicious","probability":"high"}]}`},
		{"probability null", `{"results":[{"label":"malicious","probability":null}]}`},
		{"garbage body", `not json at all`},
		{"unlabeled result", `{"results":[{"label":"  ","probability":0.9}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newMock(t, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, tc.body)
			})
			c := New(testConfig(srv.URL))
			cls, err := c.Classify(context.Background(), "payload")
			if err == nil {
				t.Fatalf("ISC-182: want error, got classification %+v", cls)
			}
			if cls.MaliciousConfidence != 0 || len(cls.Probabilities) != 0 {
				t.Errorf("no score may leak on error: %+v", cls)
			}
		})
	}
}

// ISC-186 taxonomy: connection faults are transport-class; non-2xx is a
// verdict-level fault (parity with judge ISC-141 semantics).
func TestSystem1ErrorTaxonomy(t *testing.T) {
	srv := newMock(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := New(testConfig(srv.URL)).Classify(context.Background(), "p")
	if err == nil {
		t.Fatal("want error on 500")
	}
	if IsTransportError(err) {
		t.Errorf("500 must NOT be a transport error (no failover trigger): %v", err)
	}

	// Closed server → transport fault.
	dead := httptest.NewServer(nil)
	url := dead.URL
	dead.Close()
	_, err = New(testConfig(url)).Classify(context.Background(), "p")
	if err == nil {
		t.Fatal("want error against dead endpoint")
	}
	if !IsTransportError(err) {
		t.Errorf("connection refused must be transport-class: %v", err)
	}

	// Classifier slower than the client deadline → transport-class fault. Uses a
	// silent raw listener rather than a blocking httptest handler (see helper).
	cfg := testConfig(silentServer(t))
	cfg.TimeoutMs = 20
	_, err = New(cfg).Classify(context.Background(), "p")
	if err == nil {
		t.Fatal("want timeout error")
	}
	if !IsTransportError(err) {
		t.Errorf("timeout must be transport-class: %v", err)
	}
}

// silentServer returns the URL of a TCP listener that accepts connections and
// never writes a response — a classifier that blows the client deadline, with
// no server goroutine to block teardown. Deliberately NOT the
// `httptest + <-r.Context().Done()` idiom: Go's server only observes a client
// disconnect while reading or writing, so a handler that does neither never
// sees cancellation and httptest.Server.Close() hangs in cleanup.
func silentServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	conns := make(chan net.Conn, 8)
	done := make(chan struct{})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			// Never send on a channel the cleanup may have closed: a
			// goroutine panic would take down the whole test binary.
			select {
			case <-done:
				c.Close()
			case conns <- c:
			}
		}
	}()
	t.Cleanup(func() {
		close(done)
		l.Close()
		for {
			select {
			case c := <-conns:
				c.Close()
			default:
				return
			}
		}
	})
	return "http://" + l.Addr().String()
}

// malformed/absent probability errors unwrap to ErrNoProbability (ISC-182).
func TestSystem1ErrNoProbabilityWrapping(t *testing.T) {
	srv := newMock(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"results":[{"label":"benign","probability":0.7}]}`)
	})
	_, err := New(testConfig(srv.URL)).Classify(context.Background(), "p")
	if !errors.Is(err, ErrNoProbability) {
		t.Errorf("want ErrNoProbability, got %v", err)
	}
}

// Decide table — the pure plan-flowchart. Judge-call suppression itself
// (zero-judge-call probes) is proven at the wiring stage (M017.3).
func TestDecide(t *testing.T) {
	base := Config{}
	base.Defaults() // critical .85 high .65 medium .40; block .95; min .60; esc on @critical

	cls := func(mal, benign float64) Classification {
		c := Classification{Probabilities: map[string]float64{"malicious": mal, "benign": benign}}
		c.MaliciousConfidence = mal
		if mal >= benign {
			c.TopLabel, c.TopConfidence = "malicious", mal
		} else {
			c.TopLabel, c.TopConfidence = "benign", benign
		}
		return c
	}

	cases := []struct {
		name string
		cfg  Config
		cls  Classification
		want Action
	}{
		// ISC-183 shortcut block at/above 0.95, even with escalation enabled.
		{"block shortcut", base, cls(0.97, 0.03), Block},
		{"block at exact boundary", base, cls(0.95, 0.05), Block},
		// ISC-184 escalate inside band [critical floor, block_confidence).
		{"escalate critical band", base, cls(0.90, 0.10), Escalate},
		{"escalate at band floor", base, cls(0.85, 0.15), Escalate},
		// ISC-185 fast-path allow below the escalation floor.
		{"allow high-band no-escalate", base, cls(0.80, 0.20), Allow}, // <0.85 floor
		{"allow clear benign", base, cls(0.05, 0.95), Allow},
		{"allow medium", base, cls(0.50, 0.50), Allow},
		// ISC-187 uncertainty: top label below min_confidence either way.
		{"uncertain malicious side", base, cls(0.55, 0.45), Escalate},
		{"uncertain benign side", base, cls(0.10, 0.55), Escalate},
		{"uncertain blocks when escalation off", func() Config {
			c := base
			c.EscalationEnabled = boolPtr(false)
			return c
		}(), cls(0.55, 0.45), Block},
		// ISC-189 escalation disabled: System-1 decision final.
		{"final block still block", func() Config {
			c := base
			c.EscalationEnabled = boolPtr(false)
			return c
		}(), cls(0.99, 0.01), Block},
		{"final allow still allow", func() Config {
			c := base
			c.EscalationEnabled = boolPtr(false)
			return c
		}(), cls(0.30, 0.70), Allow},
		{"mid band no escalate when off", func() Config {
			c := base
			c.EscalationEnabled = boolPtr(false)
			return c
		}(), cls(0.90, 0.10), Allow},
		// ISC-188 configurable threshold as band NAME: threshold=high -> floor .65.
		{"threshold high escalates mid", func() Config {
			c := base
			c.EscalationThreshold = BandHigh
			return c
		}(), cls(0.70, 0.30), Escalate},
		{"threshold low escalates all confident", func() Config {
			c := base
			c.EscalationThreshold = BandLow
			return c
		}(), cls(0.45, 0.55), Escalate},
		// Unknown band name fails safe to the critical floor (escalate more).
		{"unknown band = critical floor", func() Config {
			c := base
			c.EscalationThreshold = "apocalypse"
			return c
		}(), cls(0.80, 0.20), Allow},
		{"unknown band critical-band escalates", func() Config {
			c := base
			c.EscalationThreshold = "apocalypse"
			return c
		}(), cls(0.87, 0.13), Escalate},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := Decide(tc.cfg, tc.cls)
			if got != tc.want {
				t.Errorf("Decide: got %s want %s (%s)", got, tc.want, reason)
			}
			if reason == "" {
				t.Error("Decide must return an audit-explainable reason")
			}
		})
	}
}

// ISC-193 local-first: defaults point at a localhost endpoint, provider kev.
func TestSystem1LocalFirstDefault(t *testing.T) {
	cfg := Config{}
	cfg.Defaults()
	if cfg.Provider != "kev" {
		t.Errorf("default provider: got %s want kev", cfg.Provider)
	}
	if !strings.Contains(cfg.BaseURL, "localhost") && !strings.Contains(cfg.BaseURL, "127.0.0.1") {
		t.Errorf("default base_url must be local: %s", cfg.BaseURL)
	}
	if cfg.BlockConfidence != 0.95 || cfg.MinConfidence != 0.60 || cfg.EscalationThreshold != BandCritical {
		t.Errorf("plan defaults wrong: %+v", cfg)
	}
}

```

## Evidence: the gate run that exposed the defaulting bug

```
--- PASS: TestClassifierInterfaceExists (0.00s)
--- PASS: TestSystem1Classify (0.01s)
--- PASS: TestSystem1ClassifyStrictParsing (0.00s)          [8 subtests]
--- PASS: TestSystem1ErrorTaxonomy (0.02s)
--- PASS: TestSystem1ErrNoProbabilityWrapping (0.00s)
--- FAIL: TestDecide (0.00s)
    FAIL escalate_critical_band:   got ALLOW want ESCALATE ("malicious 0.90 below escalation floor 0.85")
    FAIL escalate_at_band_floor:   got ALLOW want ESCALATE ("malicious 0.85 below escalation floor 0.85")
    FAIL allow_medium:             got BLOCK  want ALLOW   ("uncertain and escalation disabled ... 0.50")
    FAIL uncertain_malicious_side: got BLOCK  want ESCALATE
    FAIL uncertain_benign_side:    got BLOCK  want ESCALATE
    FAIL threshold_high_escalates_mid:            got ALLOW want ESCALATE
    FAIL threshold_low_escalates_all_confident:   got BLOCK want ESCALATE
    FAIL unknown_band_critical-band_escalates:    got ALLOW want ESCALATE
    (all 8 passing Decide subtests were ones where the verdict is the same
     whether escalation is on or off — i.e. they passed by coincidence)
--- PASS: TestSystem1LocalFirstDefault (0.00s)
```

## What I want from you

Answer in this order. Rank findings **Critical / High / Medium / Low** and give a
concrete patch (real Go, not prose) for each Critical/High.

1. **Compile audit (highest priority, since the author has no compiler).** Go
   through the three files line by line for anything that will not compile or will
   trip `go vet`: type mismatches, unused imports/variables, value-vs-pointer
   receiver mistakes, `Config` copied by value while holding a `map` (`SeverityBands`)
   or `*bool` (aliasing/mutation surprises between `New()`, `Defaults()`,
   `Decide()`), the `Config()` method name colliding with the `Config` type,
   struct-tag/`mapstructure` correctness, format-verb/type agreement.
2. **Attack the `*bool` tri-state fix.** Is `*bool` + `EscalationOn()` the right
   pattern here, or is there a cleaner idiom (explicit `EscalationDisabled`,
   a string enum, a `Set` bitset, viper-aware defaults)? Critically: viper +
   `mapstructure` will usually deliver an *explicit* `false` as `false` and an
   absent key as "unset" — but does that hold for this struct, and can an
   operator ever get "off" or "on" by accident? Are there **other** bool-ish
   defaults in this design (`FailOpen` in the existing `judge.Config` is a plain
   bool that must default false — is that direction safe but this one unsafe, and
   what is the rule?) Propose a repo-wide convention so this bug class cannot
   recur, and say how to *test* it (e.g. a probe that a zero-value `Config{}`
   escalates).
3. **Fail-open audit of the whole decision function.** Enumerate every path
   through `Decide()` + `Classify()` and confirm none can yield ALLOW on: error,
   timeout, empty results, out-of-range probability, missing `malicious` label,
   non-2xx, malformed JSON, unknown band name, zero-value config, nil maps, or an
   all-zeroes classification. Note specifically: `Classification{}` zero value has
   `MaliciousConfidence 0` and `TopConfidence 0`, which routes to *uncertain* — is
   that safe in every escalation mode? Is the ordering right (uncertainty checked
   before the `block_confidence` shortcut)? Should the block shortcut be immune to
   the uncertainty gate?
4. **Semantics of trusting the classifier's own confidence.** The fast-path ALLOW
   fires when the top label is merely 0.60 confident. Published independent numbers
   for this model family range from ~54% (Kev-0.8B) to ~92% (Jev) on injection
   suites. Is a 0.60-confidence *benign* label a sufficient basis to skip the
   System-2 judge entirely? Would you (a) require a separation margin
   (e.g. `benign - malicious >= margin`), (b) require benign-confidence >= a higher
   bar for the ALLOW path, (c) never fast-path ALLOW and only fast-path BLOCK, or
   (d) keep it and tune from the eval corpus? Justify with the fail-closed
   constraint and the fact that a false ALLOW here is a full compromise of the
   gateway's purpose while a false escalate only costs ~seconds of latency.
5. **Robustness/DoS gaps.** `io.ReadAll(resp.Body)` is unbounded — recommend a
   limit. No response `Content-Type` check. No `context` propagation of client
   deadlines beyond `TimeoutMs`. No circuit breaker: if the classifier process is
   down, every SUSPICIOUS request pays the full 250ms before escalating — is that
   acceptable against an end-to-end p95 <2s gate, and what's the cheapest breaker
   design (stdlib only)? Should a sustained-failure state latch to
   always-escalate (fail-open-ish on *latency* grounds) or always-BLOCK?
6. **Calibration/validation correctness.** `classificationFrom` accepts any subset
   of labels with any in-range probabilities: no sum-to-1 check, no
   known-vocabulary check, and `TopConfidence` tie-breaking uses `>=` so the last
   equal label wins. It also assumes a `malicious` label exists, and treats labels
   as mutually exclusive. Recommend what to enforce at parse time vs reject.
7. **Security/compliance gaps vs the repo constraints.** No `tls.Config` with
   `MinVersion: tls.VersionTLS13` even though the repo mandates TLS 1.3 minimum
   (base_url may be https); no SSRF/egress guard and no enforcement that
   `provider: jev` (hosted, payloads may be regulated data) carries an `api_key`
   or logs the loud warning the repo pattern uses for `fail_open`/
   `expose_reasoning`; `Classification.PayloadHash` is declared (ISC-191 wants it
   in the HMAC audit event) but never populated anywhere — where should it be
   computed (client vs wiring), and hashed with what, and does logging the payload
   hash risk a correlation oracle? Also: is logging `TopLabel`/confidence into an
   HMAC audit log safe re ISC-192 (client isolation) given logs are
   operator-visible?
8. **Test quality.** What's missing or weak? I want probes that would have caught
   bug #3 *without* depending on the `Decide` table (e.g. a zero-value-config
   escalation probe, a mutation test that inverts each threshold, a
   "no fabricated score on any malformed input" property test, a fuzz test over
   the response body, `-race` concerns around the silent listener). Call out any
   test that passes for the wrong reason, and any flakiness risk remaining in
   `silentServer`/the dead-listener pattern.
9. **Architecture.** The plan puts this stage inside `judge.RuleEngine` with
   `nil = dormant`, config in `internal/config`, and the decision taken in the MCP
   proxy. Given ISC-196 (dormant must be byte-identical) and that the repo already
   has `Route(verdict, payload)` semantics where ALLOW/BLOCK verdicts never call
   the judge: is `RuleEngine` the right host, or should System-1 be a separate
   stage before `Route`? Where exactly should the "block shortcut skips the judge"
   probe be instrumented so it cannot pass vacuously? Review `Decide()`'s pure
   signature vs an interface-based policy.
10. **Verdict.** Ship / fix-then-ship / redesign, plus the 3 changes you'd make
    before any further milestones. If you think the whole "System-1 fast-path
    ALLOW" idea is wrong for a security gateway, say so plainly and explain the
    threat model.

Also flag anything you think is *good and deliberate* only if it's load-bearing —
I'd rather have 15 real findings than reassurance. Where you're unsure because
you lack a file (e.g. `internal/judge/judge.go`, `internal/config/config.go`,
`internal/server/mcp_proxy.go`), say which file you need rather than guessing.
