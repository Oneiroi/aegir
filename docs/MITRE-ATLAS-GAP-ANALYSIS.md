# MITRE ATLAS Gap Analysis — Aegir MCP Firewall

> **⚠ Historical baseline — read this notice first.**
> This analysis was generated at HEAD `2c2f056` (M004, 2026-05-18). Its central finding —
> that large portions of the detection pipeline were dead code — was accurate at that commit.
> Milestones M006, M007, M008, and M009 have since shipped; the P1 gaps in this document are
> mostly resolved. See SCOPE.md for the current technique coverage table, and the
> "Recommended Milestones" section below for resolved/open status on each item.
> The detailed technique map and severity analysis remain valid as historical context.

> Generated: 2026-05-18
> Version: 1.0
> Source: PAI Research Team (Technical Evaluator code audit + IOC pattern analysis)
> Codebase: `main` branch, HEAD `2c2f056` (M004 complete, 33/34 ISCs)

---

## Executive Summary

Aegir's defensive architecture is structurally sound for a transport-layer MCP proxy. The sanitizer and IOC pattern library are well-designed and comprehensively cover the relevant ATLAS attack surface on paper. The critical problem is that **a substantial portion of the implemented defences are not wired into the live request pipeline** — they exist as correct code that never executes.

Three critical findings dominate:

1. **Dead IOC patterns**: `ioc_patterns.go` contains 40+ ATLAS-mapped regex patterns (including all AML.T0054 jailbreak sub-techniques, AML.T0051.001 indirect injection, AML.T0056 prompt extraction, AML.T0053 agent tool abuse, SSRF patterns, and polymorph bypass patterns). `GetIOCPatterns()` is defined but called from nowhere in the request pipeline. These patterns never run.

2. **Anomaly detector produces telemetry only**: `anomaly/detector.go` computes Shannon entropy and non-ASCII ratios, scores every request [0,1], and logs the result. No threshold gate exists in `mcp_proxy.go`. A score of 0.99 produces a log line and the request proceeds. The detector is wired for observability, not defence.

3. **Response compliance gap**: `ScanForCompliance()` is applied to inbound requests but not to upstream responses. PII, PHI, and PCI data leaking in model output passes through Aegir undetected.

**Estimated overall ATLAS coverage: ~35% of in-scope techniques with active enforcement.** Rising to ~65% if dead-code patterns were activated (M006 scope). Remaining gaps require new capabilities.

---

## Scope Boundary

Aegir is a **transport-layer proxy**. It sees MCP message content, headers, and connection metadata. It does not have access to:

- ML model weights, embeddings, or internal activations
- Training data pipelines or fine-tuning infrastructure
- Model output generation process (only the final output)
- Cross-deployment infrastructure or supply chain

Techniques targeting these surfaces are **structurally out of scope** for Aegir and belong to other system layers (model hosting, MLOps, deployment infrastructure). These are marked `OUT_OF_SCOPE` in the coverage map and will not appear in gap recommendations.

---

## ATLAS Coverage Map

### Tactic: Reconnaissance

| ID | Technique | Coverage | Mechanism | Notes |
|----|-----------|----------|-----------|-------|
| AML.T0000 | Search for Victim's Publicly Available Research | OUT_OF_SCOPE | — | Attacker prep phase, not network-detectable |
| AML.T0001 | Search Victim-Owned Websites | OUT_OF_SCOPE | — | Recon of public surfaces, not proxy-detectable |
| AML.T0003 | Gather ML Model Information | PARTIAL | Rate limiting reduces inference-based enumeration | No behavioral fingerprinting for model enumeration queries |

### Tactic: Resource Development

| ID | Technique | Coverage | Mechanism | Notes |
|----|-----------|----------|-----------|-------|
| AML.T0017 | Develop Adversarial ML Attacks | OUT_OF_SCOPE | — | Attacker-side preparation |
| AML.T0018 | Obtain ML Attack Capabilities | OUT_OF_SCOPE | — | Attacker-side preparation |

### Tactic: Initial Access

| ID | Technique | Coverage | Mechanism | Notes |
|----|-----------|----------|-----------|-------|
| AML.T0010 | ML Supply Chain Compromise | OUT_OF_SCOPE | — | GPU/library/model supply chain |
| AML.T0011 | Phishing / Social Engineering LLM | PARTIAL | Auth layer validates token identity | No semantic phishing detection in prompts |
| AML.T0012 | Valid Accounts | COVERED | `auth/manager.go` — JWT, OAuth2/OIDC, API key, bcrypt | MFA plumbed but not implemented (critical — see Gaps) |

### Tactic: ML Model Access

| ID | Technique | Coverage | Mechanism | Notes |
|----|-----------|----------|-----------|-------|
| AML.T0040 | ML Model Inference API Access | COVERED | Auth layer + rate limiting | Authenticated access controlled |
| AML.T0041 | Full ML Model Access | OUT_OF_SCOPE | — | Model hosting infrastructure |
| AML.T0042 | Physical Environment Access | OUT_OF_SCOPE | — | Physical security |

### Tactic: Execution

| ID | Technique | Coverage | Mechanism | Notes |
|----|-----------|----------|-----------|-------|
| AML.T0050 | Execute LLM Prompt | PARTIAL | Auth controls who can submit; rate limiting | No semantic intent classification |
| AML.T0051.000 | LLM Prompt Injection — Direct | PARTIAL | `manager.go:detectPromptInjection()` — 22 active patterns + `collapseSpacingVariant()` | IOC pattern AML.T0051.000 is dead; active patterns cover most common variants but miss base64-encoded payloads and token-split attacks |
| AML.T0051.001 | LLM Prompt Injection — Indirect | COVERED | M008: `scanToolResultForInjection()` (`mcp_proxy.go`) runs the full detection suite over `tools/call` result `content[].text` before forwarding, fail-closed block on critical; judge layer (M009) adds semantic coverage | Standalone IOC pattern `INSERT.*INJECTION` stays narrow, but real coverage is the response-path scan. Probes `TestToolResultInjectionBlocked`/`TestToolResultCleanAllowed` (`415b9f4`). SCOPE.md / ISA.md are system of record |
| AML.T0051.002 | LLM Prompt Injection — Triggered | NOT COVERED | IOC pattern exists but is dead | No live detection of conditional/triggered injection |
| AML.T0053 | AI Agent Tool Invocation Abuse | PARTIAL | `mcp_proxy.go:validateResourceURI()` blocks explicit bad schemes; `manager.go:function_call_injection` partially active | `validateResourceURI()` not called on tool argument URL values; SSRF.001-004 IOC patterns are dead; no tool arg inspection |
| AML.T0061 | Prompt Self-Replication | NOT COVERED | IOC pattern AML.T0061.001 defined but dead | — |

### Tactic: Persistence

| ID | Technique | Coverage | Mechanism | Notes |
|----|-----------|----------|-----------|-------|
| AML.T0020 | Poison Training Data | OUT_OF_SCOPE | — | Training pipeline |
| AML.T0026 | Backdoor ML Model | OUT_OF_SCOPE | — | Model weights |

### Tactic: Defense Evasion

| ID | Technique | Coverage | Mechanism | Notes |
|----|-----------|----------|-----------|-------|
| AML.T0015 | Evade ML Model | OUT_OF_SCOPE | — | Adversarial perturbations of model inputs at embedding level |
| AML.T0054.001 | Jailbreak — DAN | PARTIAL | `manager.go:dan_mode` active; IOC AML.T0054.001 dead | IOC pattern is more comprehensive than active pattern |
| AML.T0054.002 | Jailbreak — Developer Mode | PARTIAL | `manager.go:jailbreak_mode` catches some variants; IOC AML.T0054.002 dead | Same issue |
| AML.T0054.003 | Jailbreak — System Prompt Override | NOT COVERED | IOC AML.T0054.003 dead | Active patterns cover override in different framing but not SYSTEM-prefixed messages |
| AML.T0054.004 | Jailbreak — Roleplay Scenario | NOT COVERED | IOC AML.T0054.004 dead | `(?i)(?:role play\|act as\|pretend to be)` never executes |
| AML.T0054.005 | Jailbreak — Hypothetical Scenario | NOT COVERED | IOC AML.T0054.005 dead | `(?i)(?:imagine\|hypothetically\|suppose)` never executes |
| AML.T0054.006 | Jailbreak — Test Environment | NOT COVERED | IOC AML.T0054.006 dead | Never executes |
| AML.T0054.007 | Jailbreak — Crescendo (slow escalation) | PARTIAL | `session/analyzer.go:analyzeJailbreakProgression()` detects `dan_progression` and `grandmother_exploit` via substring match | LLM.CR.001/002 IOC patterns dead; session analyzer uses substring matching, not regex; genuine Crescendo (no explicit keywords) bypasses all detection |
| POLY.001 | Case Variation Bypass | COVERED | `manager.go:detectPromptInjection()` uses `(?i)` throughout | Case-insensitive matching active |
| POLY.002 | Spacing Variation Bypass | COVERED | `manager.go:collapseSpacingVariant()` active | Normalises "i g n o r e" before pattern matching |
| POLY.003 | Leet Speak Bypass | COVERED | Live: `manager.go:normalizeLeet()` in detectPromptInjection + `detection.go:Normalize()` rule 1 (0→o 1→i 3→e 4→a 5→s @→a); IOC POLY.003 regex still dead | Leet covered by the normalisation passes, not by the IOC |
| POLY.004 | Emoji Obfuscation | PARTIAL | IOC POLY.004 dead; bundle-4 `FoldConfusables` (detection.go) covers Cyrillic/fullwidth/math; the old 4-rune replace is superseded | Emoji and format chars within words still unnormalised on the regex path (POLY.007 follow-up) |
| POLY.005 | Mixed Script (Cyrillic) | COVERED | Bundle-4 `FoldConfusables` folds the full Cyrillic lookalike set (case-paired; pre-bundle-4 `detectHomoglyphs` replace covered 4 chars: а,е,о,р); IOC POLY.005 regex still dead | F5 B04 class (Cyrillic homoglyphs) caught post-fold |
| POLY.006 | RTL Override | COVERED | `manager.go:detectPromptInjection()` has explicit `‮` RTL char detection | Active |
| POLY.007 | Zero-Width Characters | PARTIAL | IOC LLM.JB.003 covers some zero-width chars; manager.go RTL detection active | Full zero-width character set in IOC is dead |
| POLY.008 | Homoglyph (full Cyrillic) | COVERED | Same bundle-4 fold as POLY.005; the 4-rune replace (а,е,о,р) in `detectHomoglyphs` is superseded/inert | See POLY.005 |
| LLM.ML.001 | Low-Resource Language Attack | NOT COVERED | IOC LLM.ML.001 dead; pattern is too narrow anyway (keyword matching on language names) | Genuine low-resource language attacks don't announce their language |
| LLM.ML.002 | Language Mixing / Code-Switching | PARTIAL | IOC LLM.ML.004 dead; anomaly detector may score high-non-ASCII but doesn't block | No live detection |
| LLM.ML.004 | Code-Switching Mid-Sentence | NOT COVERED | IOC LLM.ML.004 dead | — |
| LLM.PY.001 | Poetry Format Attack | NOT COVERED | IOC LLM.PY.001 dead | — |
| LLM.PY.002 | Acrostic Attack | NOT COVERED | IOC LLM.PY.002 dead | — |

### Tactic: Credential Access

| ID | Technique | Coverage | Mechanism | Notes |
|----|-----------|----------|-----------|-------|
| AML.T0056 | LLM Meta Prompt Extraction | PARTIAL | `manager.go:system_prompt_override` catches extraction-as-override; IOC AML.T0056.001 dead | Pure extraction requests ("what are your instructions?") without an override verb pass through |

### Tactic: Exfiltration / Collection

| ID | Technique | Coverage | Mechanism | Notes |
|----|-----------|----------|-----------|-------|
| AML.T0005 | Infer Model Internals (Model Extraction) | PARTIAL | Rate limiting per IP; anomaly scoring | No cross-IP correlation; anomaly score never blocks; no repetition-pattern detection across sessions |
| AML.T0006 | Exfiltration via ML Inference API | PARTIAL | Rate limiting | Same limitations as T0005; no systematic query pattern detection |
| AML.T0025 | Exfiltration via Cyber Means | PARTIAL | HMAC audit logs; TLS 1.3 | Detects tampering after the fact; no real-time exfil detection in response content |
| AML.T0035 | Steal ML Model Artifacts | OUT_OF_SCOPE | — | Model weight theft; not a proxy concern |
| AML.T0057 | LLM Data Leakage | PARTIAL | Response path: `mcp_proxy.go:307` applies `SanitizeContent()` detecting secrets and injections in model output; `detectSecrets()` catches API keys, JWTs, SSH keys, AWS keys, GitHub tokens, Stripe keys | Compliance scan (`ScanForCompliance()`) NOT applied to responses — PII, PHI, PCI in model output passes through; `detectSecrets()` misses Azure SAS tokens, GCP service account JSON, Slack tokens (`xoxb-`), generic bearer tokens |
| AML.T0063 | Model Output Discovery | NOT COVERED | IOC AML.T0063.001 dead | Score/confidence extraction not detected |
| AML.T0070 | RAG Poisoning | NOT COVERED | IOC AML.T0070.001 dead; no semantic awareness of write targets | Pattern `RAG.*poison` only matches if attacker announces intent |

### Tactic: Impact

| ID | Technique | Coverage | Mechanism | Notes |
|----|-----------|----------|-----------|-------|
| AML.T0021 | Corrupt ML Model | OUT_OF_SCOPE | — | Model weights |
| AML.T0022 | Denial of ML Service | COVERED | Rate limiting + burst protection; `internal/metrics` for monitoring | Per-IP; no cross-IP coordination detection |
| AML.T0023 | Erode ML Model Integrity | OUT_OF_SCOPE | — | Model fine-tuning/training |
| AML.T0047 | Backdoor ML Model | OUT_OF_SCOPE | — | Model internals |
| AML.T0048 | Compromise Privacy of Training Data | OUT_OF_SCOPE | — | Training pipeline |

### Template / Infrastructure Injection

| ID | Technique | Coverage | Mechanism | Notes |
|----|-----------|----------|-----------|-------|
| TMP.INJ.001 | Jinja2 Template Injection | PARTIAL | `manager.go:template_injection` matches `{{.*dangerous_keyword.*}}`; IOC TMP.INJ.001 dead | Active pattern requires dangerous keyword; SSTI probe `{{7*7}}` does not match; full Jinja2 class traversal pattern is dead |
| TMP.INJ.002 | Handlebars Template Injection | NOT COVERED | IOC TMP.INJ.002 dead | — |
| TMP.INJ.003 | Velocity Template Injection | NOT COVERED | IOC TMP.INJ.003 dead | — |
| TMP.INJ.004 | JS Template Literal Injection | PARTIAL | `manager.go:variable_injection` matches `${.*dangerous_keyword.*}`; full pattern dead | Same issue as TMP.INJ.001 |
| SSRF.001 | AWS Metadata SSRF | NOT COVERED | IOC pattern dead; `validateResourceURI()` not called on tool argument URL values | Explicit `localhost` blocked in URI scheme validation, but tool arg URLs not inspected |
| SSRF.002 | Localhost Bypass SSRF | NOT COVERED | IOC dead; `validateResourceURI()` blocks `localhost` in resource URIs only | Tool call arguments with URL values are not validated |
| SSRF.003 | IP Obfuscation SSRF | NOT COVERED | IOC dead | — |
| SSRF.004 | XXE SSRF | NOT COVERED | IOC dead | — |
| LDAP.INJ.001 | LDAP Auth Bypass | PARTIAL | `manager.go:ldap_injection` pattern exists; test failures documented in M005 ISA | Tests failing per M005 ISA; pattern correctness uncertain |
| PATH.TRAV.001 | Unix Path Traversal | PARTIAL | `manager.go:path_traversal` pattern exists; test failures documented in M005 ISA | Same |
| PATH.TRAV.002 | Null Byte Injection | PARTIAL | `manager.go:null_byte` pattern exists; test failures documented in M005 ISA | Same |

---

## Critical Gaps (P1)

These gaps are in scope for Aegir, actively exploitable, and fixable with minimal code changes.

### P1-1: Dead IOC Pattern Pipeline
**ATLAS:** AML.T0054.001–.006, AML.T0051.001–.002, AML.T0056, AML.T0053, AML.T0061, SSRF.001–.004, TMP.INJ.002–.004, POLY.003–.008, LLM.ML.001–.005, LLM.CR.001–.002
**Code:** `sanitizer/ioc_patterns.go` — `GetIOCPatterns()` never called in request path
**Fix:** In `manager.go:detectPromptInjection()`, after the local patterns array loop, iterate `GetIOCPatterns()` and compile/apply each pattern. Compilation should happen at Manager construction in `initializePatterns()` (currently a no-op).
**Impact:** Activates 40+ additional patterns with zero new detection logic.

### P1-2: Anomaly Detector Never Blocks
**ATLAS:** AML.T0005, AML.T0006, AML.T0057 (high-entropy encoded payloads)
**Code:** `server/mcp_proxy.go` line ~192 — score logged, request proceeds regardless
**Fix:** Add configurable threshold gate:
```go
if anomalyScore > cfg.Security.AnomalyDetection.BlockThreshold {
    http.Error(w, "Request blocked: anomaly score exceeded threshold", http.StatusForbidden)
    return
}
```
**Impact:** Activates the entropy-based defence that was already built and tested.

### P1-3: Response Compliance Not Scanned
**ATLAS:** AML.T0057 (PII/PHI/PCI leakage in model output)
**Code:** `server/mcp_proxy.go` line 307 — `SanitizeContent()` runs on response but `ScanForCompliance()` does not
**Fix:** After the existing `SanitizeContent()` call on the response, call `complianceManager.ScanForCompliance(responseSanitized.Sanitized)` and either redact or log violations.
**Impact:** Closes the most direct data leakage path for regulated data.

### P1-4: Hardcoded Default Admin Credential
**ATLAS:** AML.T0012 (Valid Accounts)
**Code:** `auth/manager.go:createDefaultUsers()` — password "admin123" hardcoded at startup
**Fix:** Require `AEGIR_ADMIN_PASSWORD` env var; fail startup if absent. Alternatively, generate and print a random credential once at first boot.
**Impact:** Eliminates a trivially exploitable default credential in production deployments.

### P1-5: SSRF via Tool Argument URLs
**ATLAS:** AML.T0053 (AI Agent Tool Invocation)
**Code:** `server/mcp_proxy.go:handleToolsCall()` — tool argument values not inspected; `validateResourceURI()` only called on MCP resource URIs
**Fix:** In `handleToolsCall()`, iterate tool call `arguments` for any string value matching URL format and pass through `validateResourceURI()`.
**Impact:** Closes SSRF via legitimate-looking tool calls where the tool accepts URL arguments.

---

## Significant Gaps (P2)

These gaps are in scope, significant, but require new capability rather than just wiring.

### P2-1: MFA Not Implemented
**ATLAS:** AML.T0012 (Valid Accounts — credential bypass)
**Code:** `auth/manager.go:Login()` line ~222 — MFA code accepted but not validated against any TOTP store
**Fix:** Add `github.com/pquerna/otp/totp` (or equivalent), store TOTP secret per user, validate `req.MFACode` against current TOTP window.
**Impact:** MFA field is plumbed throughout; this is the missing final step.

### P2-2: Pattern Recompilation on Every Request
**ATLAS:** Performance degradation enabling DoS (AML.T0022)
**Code:** `manager.go:initializePatterns()` is a no-op; all `regexp.MustCompile()` calls happen inline on each request
**Fix:** Compile all regex patterns into `Manager` struct fields in `initializePatterns()`. Called once at startup. Eliminates per-request regex compilation overhead.
**Impact:** Significant latency reduction under load; also required for efficient IOC pattern activation (P1-1).

### P2-3: Model Extraction — No Cross-Session or Cross-IP Correlation
**ATLAS:** AML.T0005, AML.T0006
**Code:** Rate limiter is per-IP token bucket; no session-history repetition detection across separate connections; anomaly detector is single-message only
**Fix:** (a) Rate limiting keyed on authenticated user identity, not just IP. (b) Track repetitive uniform query patterns across sessions with sliding window counter. (c) Flag when anomaly score is consistently elevated across a session (not just per-message).
**Impact:** Closes the primary model extraction vector (distributed low-rate queries).

### P2-4: Indirect Prompt Injection (Tool Result Content) — ✅ RESOLVED (M008 / ISC-22)
**ATLAS:** AML.T0051.001
**Status:** RESOLVED — `scanToolResultForInjection()` applies the full detection suite to tool-call results, fail-closed on critical, before forwarding (probes at `415b9f4`).
**Code:** `mcp_proxy.go` inspects inbound requests but does not semantically analyse content returned by upstream tool calls before it reaches the model. Current IOC pattern for T0051.001 (`INSERT.*INJECTION`) only matches if attacker labels their payload.
**Fix:** Apply the full prompt injection detection suite to tool call results flowing back from upstream, treating external content as untrusted data. Requires a response-path sanitization pass before forwarding tool results.
**Impact:** Closes indirect injection via documents, fetched URLs, database responses fed into the model context.

### P2-5: Prompt Extraction (Pure Extraction, No Override Verb)
**ATLAS:** AML.T0056
**Code:** `manager.go:system_prompt_override` catches extraction-as-override. Pure extraction ("repeat your instructions verbatim", "what are you told to do?") with no override keyword passes through.
**Fix:** Add patterns for extraction intent independent of override: `(?i)(?:what.*(?:instructions|told|rules|guidelines)|repeat.*(?:system|initial|first).*(?:prompt|instruction)|verbatim.*(?:system|prompt|instruction))`.
**Impact:** Catches a common class of system prompt extraction attempts that don't include override language.

### P2-6: detectSecrets() Missing Token Types
**ATLAS:** AML.T0057
**Code:** `manager.go:detectSecrets()` patterns miss: Azure SAS tokens, GCP service account JSON keys, Slack tokens (`xoxb-`, `xoxp-`, `xoxa-`), private RSA keys with non-standard PEM headers, generic bearer tokens
**Fix:** Add patterns for each missing type. Low-risk addition — additive to existing secret detection.

---

## Longer Horizon (P3)

These require architectural additions or semantic capabilities not currently in scope.

### P3-1: Crescendo / Slow Escalation Detection
**ATLAS:** AML.T0054.007 (Crescendo)
**Current:** `session/analyzer.go` detects `dan_progression` and `grandmother_exploit` by substring matching. Genuine Crescendo (gradual topic drift without explicit keywords) is not detectable.
**Approach:** Session-level semantic drift scoring — track topic distance between successive messages; escalating drift toward sensitive topics without explicit jailbreak keywords.

### P3-2: RAG Pipeline Write Awareness
**ATLAS:** AML.T0070
**Current:** No detection. IOC pattern only matches if attacker announces "RAG poisoning". Aegir has no awareness of which tool calls target vector stores.
**Approach:** Tool schema inspection — identify write operations to knowledge bases, vector stores, or document repositories; apply heightened scrutiny to content being written.

### P3-3: Adversarial Examples in Structured Inputs
**ATLAS:** AML.T0043
**Current:** Pattern-based detection works on text; adversarial perturbations in structured data (JSON values, embeddings, base64-encoded blobs) are not semantically inspected.
**Approach:** Decode and inspect all base64/URL-encoded values in tool arguments; flag anomalous numeric distributions in embedding-valued parameters.

---

## Recommended Milestones

> **Status update (2026-06-23):** M006, M007, M008, and M009 have all shipped since this
> analysis was generated. Each entry below notes its current status.

### M006 — Activate Dead Defences — **SHIPPED**

**Goal:** Make existing code actually execute. No new detection logic required.

**Status (2026-06-23):** All six deliverables shipped. IOC patterns compiled at startup via
Aho-Corasick trie (M012). Anomaly block threshold active. Response compliance scan active.
SSRF tool-argument URL validation active. Hardcoded `admin123` removed; startup guard enforces
strong secrets for both JWT and HMAC keys.

---

### M007 — Authentication Hardening + Model Extraction Resistance — **SHIPPED**

**Goal:** Close the authentication gaps and make inference-based attacks economically infeasible.

**Status (2026-06-23):** All deliverables shipped. WebAuthn/FIDO2 MFA implemented for the
admin management interface. Rate limiter refactored to identity-keyed. Extended secret
detection (Azure SAS, GCP SA JSON, Slack tokens) shipped. **Open items carried forward:**
cross-session model extraction detection (P2-3) and DNS rebinding SSRF (BUG-2) remain open.

---

### M008 — Response Integrity + Indirect Injection — **MOSTLY SHIPPED (ISC-22 open)**

**Goal:** Treat model output and tool results as untrusted data, not pass-through.

**Status (2026-06-23):** Pure extraction patterns, leet-speak normalisation, and base64
decode-then-scan shipped. Response compliance scan coverage active. **Open:** Tool-result
scanning (item 1 — indirect injection via upstream content, ISC-22) shipped in M008 via
`scanToolResultForInjection()`, closing the primary P2 gap. AML.T0051.001 (indirect prompt
injection) is now COVERED — see SCOPE.md / ISA.md.

---

## Implementation Notes

### Pattern Compilation (Required for M006)

`initializePatterns()` at `sanitizer/manager.go` line 803 is currently:
```go
func (m *Manager) initializePatterns() {
    // TODO: compile patterns
}
```

This must be populated before IOC pattern activation is safe at volume. All `regexp.MustCompile()` calls that currently appear inside detection functions should be compiled once here and stored as `Manager` fields.

### Anomaly Block Threshold (Required for M006)

Suggested config addition to `aegir.yaml`:
```yaml
security:
  anomaly_detection:
    enabled: true
    block_threshold: 0.85   # block requests scoring above this
    log_threshold: 0.60     # log-only below block_threshold
```

### Response Sanitization Call Point (Required for M006)

`server/mcp_proxy.go` line 307:
```go
responseSanitized, err := p.sanitizer.SanitizeContent(string(responseJSON))
// ADD: compliance scan on response
if compResult := p.complianceManager.ScanForCompliance(responseSanitized.Sanitized); len(compResult.Violations) > 0 {
    p.logger.LogSecurityEvent("response_compliance_violation", compResult.Violations)
    // apply redaction or block per policy
}
```

---

## Coverage Summary

> **Historical figures at HEAD `2c2f056` (M004, 2026-05-18). See SCOPE.md for current state.**

| Status | Count | Examples |
|--------|-------|---------|
| COVERED (active enforcement) | 8 | Rate limiting, auth/JWT, HMAC logs, TLS, case/spacing/RTL normalisation |
| PARTIAL (active but incomplete) | 18 | Direct prompt injection, DAN, Crescendo (session), homoglyph (4 chars), data leakage (secrets only) |
| NOT COVERED (in scope, no enforcement) | 16 | Indirect injection, roleplay/hypothetical jailbreak, model extraction, SSRF via tools, RAG poisoning |
| OUT OF SCOPE (structural boundary) | 14 | Training data poisoning, model weights, supply chain, physical access |
| **Total in-scope techniques assessed** | **42** | |

**Active enforcement rate at M004: 19% (8/42)**
**With M006–M009 shipped: ~62% (26/42) pattern-layer coverage + inline LLM judge for semantic attacks above the ceiling**
**Remaining genuine open gaps: ISC-22 (indirect injection via tool results), BUG-2 (DNS rebinding), ISC-52 (Crescendo session-level)**

---

*Analysis generated at HEAD `2c2f056` (M004). Current technique-by-technique coverage in SCOPE.md.*
