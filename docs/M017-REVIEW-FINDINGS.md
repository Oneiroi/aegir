# M017 — Review Findings → Work Order for `internal/system1` package core

> **Audience:** local model (Qwen3.8-Flash-Next class, via pi/OMLX dispatch) executing
> fixes. You have no prior context. Everything you need is in this file. A supervisor
> reviews your diff; David commits. You do NOT run `git` mutations.
>
> **Source:** adversarial review of the uncommitted `internal/system1/` package
> (M017 System-1 triage tier), verified against a live Go 1.25 toolchain on
> 2026-10-14. The gate was actually run: `go build ./...` clean, `go vet` clean,
> **`go test ./...` FAILS in `internal/system1` only** (details in T1).

## Hard rules (violations = rejected diff)

1. **Fail-closed is non-negotiable.** No change you make may turn any error,
   timeout, malformed-response, or uncertainty path into ALLOW. Every parse
   rejection that exists today must remain a rejection.
2. **Do not modify `Decide()`'s policy logic, thresholds, or branch ordering.**
   The one failing test is a wrong test vector, not a code bug. `Decide` behaved
   correctly. If you find yourself editing `Decide` to make a test pass, stop —
   the test is wrong.
3. **Do not touch the `*bool` tri-state.** `EscalationEnabled *bool` +
   `EscalationOn()` (nil → true) is a deliberate fix for a real fail-open bug
   (a plain `bool` zero-valued to `false`, which silently disabled escalation and
   fast-path-ALLOWED 0.90-confidence malicious traffic). Do not "simplify" it.
4. **Stdlib only.** `crypto/tls`, `crypto/sha256`, `encoding/hex` are standard
   library and allowed. No new module dependencies.
5. **Do not touch shared files:** `internal/config/config.go`, `internal/server/*`,
   `internal/judge/*`. Config wiring is a later, serial milestone (M017.2/3).
   Your scope is `internal/system1/` ONLY.
6. **Do not implement a circuit breaker** (deferred — needs supervisor design
   review) and **do not change the fast-path ALLOW policy** (escalation threshold
   defaults, benign-margin ideas — open product decision, plan Open Question #1).
7. **Gate discipline per AGENTS.md:** per-package `go test ./internal/system1/`
   is the floor while iterating; done means whole-repo `go build ./... &&
   go test ./...` exits 0. If you have no Go toolchain, STOP after writing code
   and report "UNVERIFIED, no toolchain" — never claim done.

## Current state (verified)

- `internal/system1/system1.go`, `client.go`, `system1_test.go` — untracked,
  compile clean, vet clean.
- Failing: `TestDecide/allow_medium`:
  `Decide: got ESCALATE want ALLOW (system1 uncertain: top label "malicious"
  confidence 0.50 < min_confidence 0.60)` at `system1_test.go:298`.
- `gofmt -l` flags `system1.go` and `system1_test.go` (non-canonical formatting).
- `go test -race -count=2 ./internal/system1/` — no data races (only the T1
  failure).

---

## T1 — Fix the wrong test vector (the gate is RED because of this)

**Root cause you must understand before editing:** the helper
`cls(mal, benign)` in `TestDecide` sets `TopConfidence = max(mal, benign)`.
The case `cls(0.50, 0.50)` therefore has top confidence 0.50, which is below
`min_confidence` 0.60 → the uncertainty gate fires → `Escalate`. That is
CORRECT behavior (the uncertainty rule is tested two cases later in the same
table). The expectation `Allow` is self-contradictory. A *confident*
medium-band allow needs the benign side ≥ 0.60.

**Edit `internal/system1/system1_test.go`, in `TestDecide`:**

Replace this line:

```go
		{"allow medium", base, cls(0.50, 0.50), Allow},
```

with:

```go
		{"allow medium", base, cls(0.40, 0.60), Allow}, // benign 0.60 >= min_confidence; m=0.40 in medium band, below critical floor
```

## T2 — Fix the pass-for-the-wrong-reason case (same bug class as the tri-state bug)

The case `{"threshold low escalates all confident", ... cls(0.45, 0.55), Escalate}`
passes only because top confidence 0.55 < 0.60 trips the **uncertainty** gate —
it would pass even if `Floor("low")` were broken. It proves nothing about
band-name resolution.

**Edit the same table:** replace that case with a confident vector AND add its
control, so the mechanism is isolated:

```go
		{"threshold low escalates confident low-band", func() Config {
			c := base
			c.EscalationThreshold = BandLow
			return c
		}(), cls(0.30, 0.70), Escalate}, // floor("low")=0.0, m=0.30 >= 0.0; confident benign top
		{"same vector with default critical threshold allows", base, cls(0.30, 0.70), Allow},
```

Also add boundary cases at the uncertainty edge (`<` is strict — exactly 0.60 is
NOT uncertain):

```go
		// min_confidence boundary: 0.60 exactly is confident (strict <), 0.59 is not.
		{"top at exactly min_confidence is confident", base, cls(0.40, 0.60), Allow},
		{"top just below min_confidence is uncertain", base, cls(0.41, 0.59), Escalate},
		// high-band floor boundary with threshold=high.
		{"threshold high at exact floor", func() Config {
			c := base
			c.EscalationThreshold = BandHigh
			return c
		}(), cls(0.65, 0.35), Escalate},
```

(Note "allow medium" and "top at exactly min_confidence is confident" now use the
same vector — keep both; they document different ISCs.)

## T3 — Add the tri-state regression probe (pins the original fail-open bug class)

Every existing `TestDecide` case goes through `base.Defaults()`, so the table
structurally cannot detect a nil `EscalationEnabled` ever again. Add this as a
NEW test function at the end of `system1_test.go`:

```go
// Regression probe for the tri-state defaulting bug class: any Config whose
// EscalationEnabled was never explicitly set must NEVER fast-path ALLOW
// mid-band malicious traffic, however the Config was constructed.
func TestDecide_UnsetEscalationNeverAllowsMidBand(t *testing.T) {
	mid := Classification{
		MaliciousConfidence: 0.90, TopLabel: "malicious", TopConfidence: 0.90,
		Probabilities: map[string]float64{"malicious": 0.90, "benign": 0.10},
	}
	defaulted := Config{}
	defaulted.Defaults()
	thresholdsOnly := Config{ // the original bug's shape: real thresholds, nil *bool, no Defaults()
		BlockConfidence: 0.95, MinConfidence: 0.60,
		EscalationThreshold: BandCritical, SeverityBands: DefaultSeverityBands(),
	}
	for name, cfg := range map[string]Config{
		"zero value (no Defaults)":  {},
		"defaults applied":          defaulted,
		"thresholds set, nil *bool": thresholdsOnly,
	} {
		if got, reason := Decide(cfg, mid); got == Allow {
			t.Errorf("%s: fast-path ALLOWED 0.90-confidence malicious traffic (%s)", name, reason)
		}
	}
	// The explicit-off escape hatch must still work:
	defaulted.EscalationEnabled = boolPtr(false)
	if got, _ := Decide(defaulted, mid); got != Allow {
		t.Errorf("explicit escalation_enabled=false must permit fast-path allow, got %s", got)
	}
	// The tri-state resolver itself: nil means ON (ISC-189 default true).
	if !(Config{}).EscalationOn() {
		t.Error("nil EscalationEnabled must resolve ON")
	}
}
```

Note: the zero-value `Config{}` case lands on **Block** (zero `BlockConfidence`
blocks everything), not Escalate — the asserted invariant is "never Allow", the
only one that matters. Do not "fix" it to Escalate.

## T4 — Add the fuzz/property probe (generalizes the strict-parsing tests)

Add at the end of `system1_test.go`. **Gotcha:** `Classification` contains a map,
so it is NOT comparable — `cls != (Classification{})` does not compile. Compare
fields individually, exactly as written below:

```go
// Property probe: for ANY response body, Classify either (a) errors and returns
// a zero-value Classification (no fabricated score leaks), or (b) returns
// probabilities all inside [0,1] with MaliciousConfidence equal to the
// "malicious" entry. Must never panic.
func FuzzClassifyResponse(f *testing.F) {
	seeds := []string{
		`{"model":"kev-9b","results":[{"label":"malicious","probability":0.91},{"label":"benign","probability":0.09}]}`,
		`{"results":[]}`,
		`{"results":[{"label":"malicious","probability":1.4}]}`,
		`{"results":[{"label":"malicious","probability":-0.2}]}`,
		`{"results":[{"label":"benign","probability":0.99}]}`,
		`{"results":[{"label":"malicious","probability":"high"}]}`,
		`{"results":[{"label":"malicious","probability":null}]}`,
		`{"results":[{"label":"malicious","probability":1e999}]}`,
		`not json at all`,
		`{"results":[{"label":"  ","probability":0.9}]}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		srv := newMock(t, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, body)
		})
		c := New(testConfig(srv.URL))
		cls, err := c.Classify(context.Background(), "payload")
		if err != nil {
			if cls.MaliciousConfidence != 0 || cls.TopConfidence != 0 ||
				cls.TopLabel != "" || len(cls.Probabilities) != 0 {
				t.Fatalf("error must return zero-value Classification, got %+v (body %q)", cls, body)
			}
			return
		}
		for label, p := range cls.Probabilities {
			if p < 0 || p > 1 {
				t.Errorf("label %q probability %v outside [0,1] accepted (body %q)", label, p, body)
			}
		}
		if cls.MaliciousConfidence != cls.Probabilities[MaliciousLabel] {
			t.Errorf("MaliciousConfidence %v != Probabilities[%q] %v (body %q)",
				cls.MaliciousConfidence, MaliciousLabel, cls.Probabilities[MaliciousLabel], body)
		}
	})
}
```

Verify with `go test -run=FuzzClassifyResponse -fuzz=FuzzClassifyResponse -fuzztime=30s ./internal/system1/`
if you have a toolchain; otherwise a plain `go test` run still executes the seed
corpus.

## T5 — Client hardening (`internal/system1/client.go`)

Three independent edits. All stdlib.

### T5a — Bound the response body read (DoS)

Currently `io.ReadAll(resp.Body)` is unbounded — a compromised or buggy
classifier endpoint gets to write an unbounded body into gateway memory on every
SUSPICIOUS request. A probability map is kilobytes; cap at 1 MiB.

Add near the top of `client.go` (after the imports):

```go
// maxClassifyResponseBytes bounds the response body — a per-label probability
// map is kilobytes; anything larger is a misbehaving endpoint, not a verdict.
const maxClassifyResponseBytes = 1 << 20
```

Replace:

```go
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Classification{}, &transportError{fmt.Errorf("system1: read response: %w", err)}
	}
```

with:

```go
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxClassifyResponseBytes+1))
	if err != nil {
		return Classification{}, &transportError{fmt.Errorf("system1: read response: %w", err)}
	}
	if len(respBytes) > maxClassifyResponseBytes {
		return Classification{}, fmt.Errorf("system1: response body exceeds %d bytes", maxClassifyResponseBytes)
	}
```

### T5b — TLS 1.3 floor on the transport (repo constraint)

The repo mandates TLS 1.3 minimum; Go's default client minimum is TLS 1.2. This
matters for `provider: jev` (hosted — payloads may contain regulated data).
Local `http://` endpoints are unaffected (no TLS attempted). In `New()`, add
`"crypto/tls"` to the imports and replace the client construction:

```go
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout:   time.Duration(cfg.TimeoutMs) * time.Millisecond,
			Transport: tr,
		},
	}
```

### T5c — Reject duplicate labels and cap result count (`classificationFrom`)

Today a duplicate label silently last-wins:
`{"label":"malicious","probability":0.05},{"label":"malicious","probability":0.99}`
yields `MaliciousConfidence=0.99`. Ambiguity in the one number that drives
BLOCK/ALLOW is attack surface. In `classificationFrom`, add a cap constant next
to the one from T5a:

```go
// maxResults caps the label array — a decision vocabulary is single-digit.
const maxResults = 64
```

Immediately after the `len(parsed.Results) == 0` check, add:

```go
	if len(parsed.Results) > maxResults {
		return Classification{}, fmt.Errorf("system1: %d results exceeds cap %d: %w",
			len(parsed.Results), maxResults, ErrNoProbability)
	}
```

And inside the loop, immediately before `cls.Probabilities[label] = p`, add:

```go
		if _, dup := cls.Probabilities[label]; dup {
			return Classification{}, fmt.Errorf("system1: duplicate label %q: %w", label, ErrNoProbability)
		}
```

### T5d — Tests for T5

Add the duplicate-label case to the `TestSystem1ClassifyStrictParsing` table:

```go
		{"duplicate label", `{"results":[{"label":"malicious","probability":0.1},{"label":"malicious","probability":0.9}]}`},
```

Add a new test for the result cap (needs a loop-built body — full code, paste
as-is):

```go
// Result-count cap: a valid-but-absurd label array is rejected, not processed.
func TestSystem1ClassifyResultCap(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"results":[`)
	for i := 0; i < 65; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"label":"label%d","probability":0.01}`, i)
	}
	sb.WriteString(`]}`)
	srv := newMock(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, sb.String())
	})
	_, err := New(testConfig(srv.URL)).Classify(context.Background(), "p")
	if !errors.Is(err, ErrNoProbability) {
		t.Errorf("want ErrNoProbability for 65 results, got %v", err)
	}
}
```

## T6 — Populate `PayloadHash` (ISC-191 audit field)

`Classification.PayloadHash` is declared but never set — the M017.3 audit event
cannot satisfy ISC-191 without it. `Classify` has the payload, so compute it
there, SHA-256 hex, matching the judge package's convention.

In `client.go`: add `"crypto/sha256"` and `"encoding/hex"` to the imports, add
the helper at the bottom of the file:

```go
// payloadHash returns the hex-encoded SHA-256 of payload, matching
// judge.payloadHash so System-1 and System-2 audit events for the same payload
// correlate in the HMAC log stream (ISC-191).
func payloadHash(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}
```

In `Classify`, immediately before `return cls, nil` (the success path only),
add:

```go
	cls.PayloadHash = payloadHash(payload)
```

Add to `TestSystem1Classify` (after the existing assertions):

```go
	if len(cls.PayloadHash) != 64 {
		t.Errorf("payload hash must be hex SHA-256 (64 chars), got %q", cls.PayloadHash)
	}
```

## T7 — Format, fingerprint self-check, gate

Run from the repo root, in order:

```bash
gofmt -w internal/system1/ && gofmt -l internal/system1/   # second command must print NOTHING
grep -rn '\\!=' internal/system1/ ; grep -rn '\\"' internal/system1/*.go   # known local-model fingerprints; expect no output
go vet ./internal/system1/
go test ./internal/system1/
go build ./... && go test ./...
```

All must exit 0. The fingerprints to grep for (all have occurred in this repo's
generated code): literal `\!=`, backslash-escaped quotes/backticks in source,
split identifiers (`Tech nique`), duplicate type declarations, invalid recursive
value types, references to config types/fields that don't exist.

If any step fails and you cannot fix it without violating the Hard Rules: STOP,
leave the tree as-is, report exactly which step failed with its output.

## Definition of done

- [ ] Whole-repo `go build ./... && go test ./...` exits 0 (or UNVERIFIED report
      if no toolchain — never a weaker proxy presented as passing).
- [ ] `gofmt -l internal/system1/` prints nothing.
- [ ] `Decide()` is byte-identical to before your diff except gofmt.
- [ ] `EscalationEnabled` is still `*bool`; `EscalationOn()` unchanged.
- [ ] Every pre-existing strict-parsing rejection still rejects (T4 seeds cover).
- [ ] No new entries in `go.mod` / `go.sum`.
- [ ] No edits outside `internal/system1/`.

## Reference: M017.2 entrance criteria (NOT your work — do not implement)

Record these for the config milestone so they don't get lost; the next instance
of the defaulting bug class lives in that layer:

- `JudgeSystem1Config.EscalationEnabled` must be `*bool` carried 1:1 into
  `system1.Config` — a plain bool there resurrects the fail-open regardless of
  what this package does.
- Contract tests to write FIRST (red), before config code: absent key →
  `EscalationOn() == true`; explicit `escalation_enabled: false` → off;
  `MCP_JUDGE_SYSTEM1_ESCALATION_ENABLED=false` env (via `applyDirectEnvOverrides`,
  Viper#584 workaround) → off; invalid band name → load error;
  `block_confidence <= escalation band floor` → load error;
  `block_confidence < min_confidence` → load error (preserves the
  `TopConfidence >= MaliciousConfidence` ordering argument);
  `min_confidence` outside (0,1) → load error; `provider: jev` with empty
  `api_key` or a loopback `base_url` → load error; `provider: jev` at all →
  loud startup WARN (style of the `judge.fail_open` warning in
  `internal/server/server.go`); `system1.enabled=true && judge.enabled=false` →
  load error (the RuleEngine is only built when `judge.enabled`, so this
  combination is incoherent).
- Viper note: `SetDefault("judge.system1.escalation_enabled", true)` +
  `*bool` is belt-and-suspenders — keep both.
- Wiring note for M017.3: a classification ERROR inside `RuleEngine.Route` must
  be consumed there (escalate to judge, or failVerdict policy when escalation is
  disabled) and must NOT propagate as `Route`'s error return — otherwise the
  proxy's `judge.fail_open` branch would ALLOW on a System-1 hiccup without the
  judge ever being consulted.
- Deferred by design (supervisor decision, not local-model work): circuit
  breaker (open → skip classifier → straight to System-2, i.e. degrade to the
  dormant path; never always-ALLOW, never always-BLOCK); fast-path ALLOW policy
  reshape (benign-margin requirement, default threshold `high` vs `critical` —
  plan Open Question #1, pending M017.4 eval data); PayloadHash correlation
  hardening (HMAC-keyed hash — if done, done in judge and system1 together).
