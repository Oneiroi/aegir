# M017 — System-1 Decision-Model Judge Tier — Implementation Plan

> Planning artifact produced under the ISA workflow (Scaffold, project tier E4, 2026-10-06),
> with the SeniorEngineer Playbook/ModelGuidance lenses applied and the engineering-excellence
> Planning standards bound per the ISA skill's EE gate.
> **Status: proposed — ISCs reconciled into `ISA.md` (ISC-181..197), nothing built.**
> EE-CHECK: scope ✓ | non-goals ✓ | classification ✓ | reversibility ✓ | verification-first ✓

## Literal request (anti-reframe check)

David's ask, restated verbatim so the plan is measured against the actual ask:

1. Implement a **System-1 model** for judge/evaluation — a fast decision-model classifier
   (Jev / Laya / Kev class), used as the front end of the LLM judge layer.
2. It **escalates to a larger LLM** (the existing judge, System-2) when malicious confidence
   crosses a **configurable threshold, default severity `critical`**.
3. When malicious confidence is **certain (default ≥ 0.95)** it does **not** escalate — it
   **shortcuts to outright BLOCK**.
4. The escalation path is **operator-optional** ("if the user so chooses").
5. Set **milestones for a local Qwen 27B 4-bit model** (pi, `Qwen3.8-27B-4bit` per the locked
   2026-08-26 dispatch pattern) to complete the implementation.

## What this is (design, decided)

A new Go package `internal/system1/` — a thin client for a locally-served **System One
decision model** (Kev family by default, Laya as alternate, hosted Jev as explicit opt-in) —
inserted into the judge escalation path inside `judge.RuleEngine`. Decision models return a
**calibrated probability per allowed answer** in a single non-generative pass
(`POST /v1/systemone` shape, shared by Kev's server, ollaya, and TypeSafe's API), which is
exactly the signal the escalation logic needs and a generative judge cannot cheaply provide.

Flow (only on traffic the pattern/anomaly layers already flagged SUSPICIOUS — the
`judge-invoked-only-on-SUSPICIOUS` constraint is inherited unchanged):

```
SUSPICIOUS payload
      │
      ▼
System-1 Classify(payload) ──error/timeout──▶ escalate to System-2 judge (fail-closed)
      │                                        (escalation disabled → failVerdict policy: BLOCK default)
      ▼
malicious confidence m
      │
      ├─ m ≥ block_confidence (default 0.95) ──────────────▶ BLOCK now, no System-2 call
      │
      ├─ m in escalation band (default ≥ critical, <0.95) ─▶ existing System-2 judge path
      │
      ├─ classifier uncertain (label confidence < min_confidence) ─▶ escalate
      │    (escalation disabled → BLOCK — never silently allow)
      │
      └─ otherwise ────────────────────────────────────────▶ ALLOW (fast path, audit-logged)
```

Severity bands reuse the repo's existing `critical|high|medium|low` ladder; band boundaries
are configurable (`severity_bands`, defaults critical ≥0.85, high ≥0.65, medium ≥0.40), and
`escalation_threshold` is expressed as a band **name** (default `critical`), matching David's
"defaults to critical" literally.

### Config shape (new `judge.system1` section — mirrors `JudgeConfig` idiom)

```yaml
judge:
  system1:
    enabled: false                 # dormant default (M015 staging convention)
    provider: kev                  # kev | laya | jev  (jev = hosted API, explicit opt-in)
    base_url: http://localhost:11435
    model: kev-9b                  # spike-selected: largest checkpoint meeting the latency budget
    api_key: ""
    timeout_ms: 250
    escalation_enabled: true
    escalation_threshold: critical # band name, resolved against severity_bands
    block_confidence: 0.95
    min_confidence: 0.60           # below this in either direction = uncertain → escalate
    severity_bands:
      critical: 0.85
      high: 0.65
      medium: 0.40
```

Env overrides follow the existing pattern: `MCP_JUDGE_SYSTEM1_ENABLED`, `_PROVIDER`,
`_BASE_URL`, `_MODEL`, `_API_KEY`, `_TIMEOUT_MS`, `_ESCALATION_ENABLED`,
`_ESCALATION_THRESHOLD`, `_BLOCK_CONFIDENCE`, `_MIN_CONFIDENCE`.

## Model choice (researched 2026-10-06 — numbers are vendor/self-reported, treat as leads)

- **Kev** (Jared Palmer, Apache-2.0, open weights, 0.8B/4B/9B/27B on Qwen bases) — decoder run
  prefill-only, serves `POST /v1/systemone`; TypeSafe SDK works unchanged. Self-reported
  accuracy 0.852 vs Jev's 0.857. **Primary default — hardware-sized: Kev-9B** (see below).
- **Laya** (Convai Innovations, Apache-2.0, 421M ModernBERT / 322M mmBERT encoder, single
  forward pass, typed decisions with probabilities; servable via `ollaya`). **Alternate** —
  and the speed fallback if no Kev checkpoint meets the latency budget.

**Hardware sizing (M5 Max, 128GB unified, 2TB — this box, per the PREFERENCES roster).**
Memory is not the constraint at any Kev size: Kev-27B-4bit (~15GB) co-loaded with the
Qwen3.8-27B-4bit judge (~16GB) totals ~31GB, leaving ~95GB for context and OS. The binding
constraint is **latency** on the judged path (ISC-195: <250ms p95 classifier overhead) — and
System-1 calls are prefill-only single forward passes, so on M5 Max even the 27B checkpoint
is a plausible fit, with 9B the expected sweet spot. Accuracy argues against the small end:
on the independent injection suite cited below, Kev-0.8B scored 53.9% (worst measured),
Laya-typed 67.7%; the family's claimed near-Jev parity is the 27B checkpoint's number.
**Selection rule (replaces a pinned size):** M017.0 benchmarks the Kev ladder
(0.8B/4B/9B/27B, 4-bit) + Laya on this hardware, co-loaded with the judge model, and ships
as default the **largest Kev checkpoint with p95 ≤ 250ms** on SUSPICIOUS-class payloads;
`kev-9b` is the placeholder default in config until the spike measures. The size lives in
config (`judge.system1.model`), so the decision is reversible at any time.
- **Jev** (TypeSafe AI, closed hosted API, launched 2026-09-15) — strongest claimed zero-shot,
  but hosted → **opt-in only** under the repo's local-first constraint; MCP payloads may
  contain sensitive data.
- **Calibration honesty caveat:** independent coverage (Cosmonet, 2026-09-21; LangWatch
  comparison, 2026-09-22) warns published numbers mix fine-tuned and unverified third-party
  figures; on one injection suite without SPML the spread was Jev 92.5% / Laya-typed 67.7% /
  Kev-0.8B 53.9%. **Therefore no threshold ships on vendor benchmarks** — M017.4 measures
  precision/recall on this repo's own red-team corpus before defaults are confirmed
  (honest-scope principle).

## Lenses applied (SeniorEngineer / engineering-excellence)

- **Right problem (Playbook §1):** yes — judge calls today are synchronous, seconds-class, on
  every SUSPICIOUS request; a sub-100ms triage tier cuts judge load and client-visible latency
  while preserving fail-closed semantics. This extends the judge layer; it does not replace it.
- **Falsifying slice first:** the whole design rests on one unverified premise — a System One
  model can be served locally on this box with a usable calibrated probability and the
  `/v1/systemone` wire shape. M017.0 is a spike that exists to falsify that before any package
  is written.
- **Reversibility ordering:** spike → new isolated package → config → wiring (shared files,
  serial) → eval → reconcile. The only irreversible-adjacent step (commits) is David's per the
  locked handoff protocol.
- **Wiring gate by construction:** the wiring milestone (M017.3) ships a probe that is shown
  **red with the call site removed** before it counts.
- **Constraint check:** stdlib `net/http` only (no new Go deps); classifier runs only on the
  already-SUSPICIOUS path so the 10ms p99 non-judge gate (ISC-91) is structurally untouched;
  fail-closed preserved at every branch; classifier output never reaches the client (ISC-33
  isolation extended); HMAC audit events for every classification.

## Deliberately NOT in this milestone (non-goals)

- No training, fine-tuning, or weight conversion infrastructure (Out of Scope: "Aegir consumes
  a judge API/binary; it does not train one"). Model serving is an external process.
- No rework of the deferred async-hold flow (ISC-32 stays deferred).
- No changes to pattern/anomaly/session detection layers or their thresholds.
- No new Go module dependencies (stdlib only) — Anti-ISC-197.
- No change to default posture: `system1.enabled` defaults **false**; with it disabled the
  request path is byte-identical to pre-M017 — Anti-ISC-196.

## Precondition (before M017.0)

The working tree currently carries **uncommitted** post-bundle work (`judge.fail_open` across
`internal/judge/judge.go`, `internal/config/config.go`, `internal/server/*`, example YAML).
`go build ./... && go test ./...` is green against the working tree as of 2026-10-06, but per
the handoff protocol uncommitted ≠ progress and M017 builds on committed code only.
**David commits or stashes that work first; M017.0 then re-runs the root gate on committed
HEAD.** Note the interaction: `fail_open` semantics are inherited by the System-1 failure
branches (escalation-disabled classifier failure → `failVerdict(cfg.FailOpen)`), so the
System-1 spec below assumes that diff lands.

## Milestones (executed by pi / Qwen3.8-27B-4bit, supervisor-reviewed, David commits)

Supervision protocol for pi, embedded per the PREFERENCES routing rules for
`Qwen3.8-27B-4bit` (not slot-eligible; usable under supervision):

1. Dispatch per milestone via the locked pattern
   (`pi -ne --session <id> --provider omlx --model Qwen3.8-27B-4bit -p "<prompt>"`, background,
   `disable_timeout=true`); **hard timeout 480s** — on timeout, grade whatever artifact exists
   before any retry (2/5 non-termination tell on this model; timed-out ≠ failed).
2. pi never runs `git` mutations or `rm`; commits are David's. No cleanup/reset requests to
   this model without an explicit confirm step (probe-7 routing rule).
3. Before trusting generated Go, grep for the repo failure fingerprints (`\!=`, escaped
   quotes/backticks, split identifiers, duplicate type decls, recursive array types,
   undefined config fields).
4. Per-package gate `go build ./internal/<pkg>/ && go test ./internal/<pkg>/` while iterating;
   milestone done only at the **root gate** on the code that will be committed.
5. Any milestone failing twice with good prompts defers up to the supervisor (frontier
   session) — second failure, not the fifth.

### M017.0 — Falsifying spike (GO/NO-GO) — owner: supervisor + pi (mechanical runs)

Serve the **Kev ladder** locally on the M5 Max — 0.8B / 4B / 9B / 27B (4-bit), co-loaded with
the Qwen3.8-27B-4bit judge — plus Laya-via-ollaya as the speed fallback, and verify:

- the `/v1/systemone` request/response shape is reachable and returns a **per-label calibrated
  probability**;
- p50/p95 classification latency per checkpoint on representative SUSPICIOUS-class payloads,
  measured **with the judge model resident** (co-load contention is the real condition);
- resident memory per checkpoint within the 128GB budget alongside the judge;
- selection: largest Kev checkpoint with **p95 ≤ 250ms** becomes the shipped default
  (`judge.system1.model`); if none meets budget, fall to Laya; if the wire shape or
  calibrated probabilities aren't obtainable at all → NO-GO, milestone aborts, recorded in
  ISA Decisions (nothing is lost; the judge layer works today without System-1).

Deliverable: `docs/M017-SPIKE-RESULTS.md` (verbatim curl transcripts + per-checkpoint latency
table + the selected default with its evidence).

### M017.1 — `internal/system1` package core — owner: pi (solo package, worktree off green HEAD)

Types (`Classification`, `SeverityBand`, `Action`), stdlib `net/http` client speaking the
spike-verified wire shape, confidence/band mapping, pure `Decide()` decision function,
fail-closed error taxonomy mirroring `judge.transportError`. Probes: table-driven unit tests
against `httptest.NewServer` mocks (judge-test idiom). Satisfies ISC-181, ISC-182.

### M017.2 — Config — owner: pi (**serial**: `internal/config/config.go` is a shared file)

`JudgeSystem1Config` struct + `setDefaults` entries + env bindings + validation (band names
resolve, `block_confidence > escalation band floor`, `0 < min_confidence < 1`) + update
`aegir.omlx-judge.example.yaml`. Satisfies ISC-188, ISC-193.

### M017.3 — Wiring — owner: pi implements, supervisor verifies call site (**serial**: touches
`internal/judge` + `internal/server/server.go` + `internal/server/mcp_proxy.go`)

`RuleEngine` gains an optional classifier stage (nil = dormant, pre-M017 behavior);
construction in `buildJudgeConfig`/`server.go`; SUSPICIOUS path runs Classify → Decide;
Block → existing opaque 403 path; Escalate → existing judge call unchanged; Allow → forward.
Audit events via existing `LogSecurityEvent`. Wiring probe shown **red with the stage
removed**, then green. Satisfies ISC-183, ISC-184, ISC-185, ISC-186, ISC-187, ISC-189,
ISC-190, ISC-191, ISC-192, ISC-196.

### M017.4 — Evaluation harness — owner: pi + supervisor review

Replay harness (`benchmark/` or `redteam/` script, not a shipped package) driving System-1
over the repo's red-team corpus (`redteam/aegir` payloads, `logs/traces/`) plus a benign
control set; reports precision/recall/Brier per severity band and per candidate threshold.
Output: `docs/M017-EVAL-REPORT.md`; defaults in M017.2 confirmed or adjusted **from this
data**, with the change logged in ISA Decisions. Satisfies ISC-194.

### M017.5 — Perf gates, docs, reconcile — owner: pi, supervisor closes

Perf probes (ISC-195); README + `aegir-scope.json`/SCOPE note that System-1 is a triage tier,
not a detector of record; ISA Verification entries populated; CheckCompleteness pass;
handoff per repo protocol. Satisfies ISC-195, ISC-197.

## Features and ISCs

Probe-test names below are **assigned, not verified** — they resolve only once M017.1+ lands;
the wiring/eval milestones must grep each cited handle before marking its ISC (verification
gate). Full ISC text lives in `ISA.md` §M017.

| Feature | ISCs | Depends on | Owner |
|---|---|---|---|
| m017-system1-core | ISC-181, ISC-182 | M017.0 GO | pi (solo package) |
| m017-config | ISC-188, ISC-193 | m017-system1-core | pi (serial, config.go) |
| m017-decision-wiring | ISC-183–187, ISC-189, ISC-190, ISC-196 | m017-config | pi + supervisor call-site review |
| m017-audit-isolation | ISC-191, ISC-192 | m017-decision-wiring | pi |
| m017-eval-harness | ISC-194 | m017-decision-wiring | pi + supervisor |
| m017-perf-reconcile | ISC-195, ISC-197 | all above | pi, supervisor closes |

## Open questions for David (not assumed)

1. Default `escalation_threshold: critical` means high/medium-band malicious confidence is
   fast-pathed to ALLOW by default (with uncertainty still escalating). That is the literal
   ask; M017.4's measured precision/recall is the evidence for whether the shipped default
   stays `critical` or drops to `high`. Flagging, not silently deciding.
2. Hosted Jev opt-in: acceptable as a `provider: jev` config-only path (same wire shape), or
   out entirely for v1 of this milestone? Plan assumes config-only opt-in is acceptable.
