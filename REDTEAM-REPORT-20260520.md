# Aegir MCP Gateway — Red Team Assessment Report

**Date:** 2026-05-20  
**Methodology:** PAI RedTeam ParallelAnalysis + AR-7 Scalability Deep-Dive  
**Agents deployed:** 32 (8 engineers, 8 architects, 8 pentesters, 8 interns) + 1 specialist (AR-7)  
**Scope:** Aegir security posture vs. MITRE ATLAS framework, post-M005  
**HEAD at analysis:** `131796d`  

---

## Executive Summary

Aegir's transport-layer architecture is sound for its stated scope — parse-time inspection, pattern-based IOC detection, compliance redaction, and auth enforcement. M005 closes all P1 ATLAS gaps. The **hard ceiling is ~62% ATLAS coverage** — the remaining 38% requires semantic/behavioral capabilities not achievable at the transport layer without a fundamental architecture addition.

Three concrete implementation bugs were confirmed (not hypothetical): compliance pattern recompilation per-call, parse-time-only SSRF validation (DNS rebinding exposure), and per-IP rate limiter susceptibility to unbounded memory growth under IP rotation attacks.

A determined adversary who has read ATLAS and targets Aegir specifically will step around the regex layer. Aegir's correct positioning is as a **necessary first line** in a defence-in-depth stack, not a sufficient one.

---

## Methodology

**Phase 1:** 24 atomic claims extracted from Aegir's security architecture thesis  
**Phase 2:** 32 parallel agents (haiku, background) — each assigned adversarial perspective, read claims, produced independent analyses  
**Phase 3:** Convergent findings synthesised across all 32 analyses  
**Phase 4:** Steelman — strongest 8-point case for Aegir  
**Phase 5:** Counter-argument — strongest 8-point rebuttal  
**AR-7:** Specialist scalability analysis targeting throughput, memory, and distributed-attack failure modes  

---

## Steelman (8 Points)

1. **Transport boundary is correct.** Intercepting at the MCP protocol layer catches attacks before they reach the model — the only position where gateway enforcement is meaningful and complete.
2. **Auth substrate is sound.** JWT/OAuth2/API key validation with HMAC-signed audit logs provides a cryptographically verifiable chain of custody.
3. **Pattern library is operationally sophisticated.** 49 ATLAS-mapped IOC patterns covering jailbreak, role escalation, indirect injection framing, and extraction probing — case-insensitive, spacing-collapse normalized.
4. **Anomaly scoring adds a second detection axis.** Shannon entropy + non-ASCII ratio catches encoding obfuscation (base64, hex) that pattern matching misses. Configurable thresholds.
5. **Compliance-first design.** PCI/HIPAA/GDPR detection and redaction on both request and response paths — not bolted on. Response compliance scan added in M005.
6. **SSRF blocked at known-bad categories.** Loopback, link-local (169.254.x.x / IMDS), RFC1918, multicast, metadata.google.internal all blocked at parse time.
7. **P1 ATLAS gaps fully closed in M005.** IOC patterns wired, anomaly blocking live, response compliance scanning active, hardcoded credential removed, SSRF categories extended.
8. **Correct scope humility.** MITRE-ATLAS-GAP-ANALYSIS.md acknowledges the ~62% ceiling and defers semantic detection to later milestones — no false confidence.

---

## Counter-Argument / Red Team Verdict (8 Points)

1. **Pattern matching has a hard ~62% ATLAS ceiling.** Crescendo attacks (AML.T0054.007 — slow escalation without explicit keywords), indirect injection via tool results, and distributed model extraction cannot be detected by regex at the transport layer. This is not a bug; it is an architectural limit.
2. **SSRF validation is parse-time only.** `validateResourceURI()` validates the hostname at URL parse time. DNS can resolve differently at connection time — DNS rebinding bypasses this entirely. An attacker registers `attacker.com` which resolves to `192.168.1.1` after the parse-time check passes.
3. **Compliance patterns recompiled per call.** `detectPII()`, `detectPHI()`, `detectPCI()` each defined inline pattern maps and called `regexp.MustCompile()` on every invocation. Confirmed at lines 143, 223, 303 of compliance.go (at HEAD `131796d`). At scale: ~300k pattern compilations/sec on the response path. **[FIXED in post-M005 patch — see Resolution section]**
4. **Per-IP rate limiting is trivially bypassed at distributed scale.** A botnet of 100 IPs × 100 req/sec each sends 10k req/sec total — all pass the per-IP gate. No cross-IP correlation exists. Additionally, the per-IP map is unbounded; 1M unique IPs × ~200 bytes = ~200MB growth before cleanup.
5. **MFA not implemented.** JWT/OAuth/API key auth accepts a single factor. Compromised credential = full access. MFA field is parsed but not validated.
6. **Anomaly threshold is globally fixed.** 0.95 block threshold applies identically to a finance API (where high-entropy input is normal) and a casual assistant. Technical users (code, cryptographic content) will produce false positives; adversaries who mix attack content with legitimate content will dilute the score below threshold.
7. **Pattern updates require restart.** IOC patterns are compiled at startup with no hot-reload. New ATLAS technique discovered → patch → restart → seconds of unavailability at 10k req/sec.
8. **Scope boundary is implicit.** Aegir presents as an MCP security gateway without a machine-readable statement of what it does NOT protect against. Operators may deploy it as a sole defence when it is a first layer.

---

## Confirmed Implementation Bugs

### BUG-1: Compliance Pattern Recompilation Per Call
**Severity:** HIGH (performance, correctness-adjacent at scale)  
**Location:** `internal/sanitizer/compliance.go` — `detectPII()` line 143, `detectPHI()` line 223, `detectPCI()` line 303  
**Root cause:** `initializePatterns()` was a stub comment. All three detection methods defined inline pattern maps and called `regexp.MustCompile()` on every invocation, ignoring pre-allocated struct fields.  
**Impact:** ~300k regex compilations/sec on response path at 10k req/sec. Added significant latency to every response.  
**Resolution:** **FIXED** — `initializePatterns()` now populates `piiPatterns`, `phiPatterns`, `pciPatterns` as `map[string]compiledPattern` (struct pairing `*regexp.Regexp` + severity string). Detection methods iterate pre-compiled maps. `digitRe` also pre-compiled for `tokenizeCardData()`. All tests pass post-fix.  
**Commit:** pending  

### BUG-2: SSRF DNS Rebinding (Parse-Time Validation Only)
**Severity:** HIGH (security)  
**Location:** `internal/server/mcp_proxy.go:1393` — `validateResourceURI()`  
**Root cause:** Hostname/IP validation occurs at URL parse time only. DNS resolves at connection time. An attacker-controlled hostname can pass parse-time validation then resolve to a private IP.  
**Resolution:** Implement custom `DialContext` on the upstream HTTP transport that re-validates the resolved IP at connection time.  
**Status:** Pending — delegated to implementation agent.  

### BUG-3: Per-IP Rate Limiter Unbounded Memory Growth
**Severity:** MEDIUM (availability)  
**Location:** `internal/` rate limiter (clients map)  
**Root cause:** Attacker-controlled IP rotation creates new limiter entries continuously. Cleanup evicts IPs idle >5min, but IP rotation at 1 req/5min per IP prevents eviction.  
**Resolution:** Cap the clients map at a configurable maximum (`max_tracked_ips`); evict oldest entry (LRU or random) when cap is reached.  
**Status:** Pending — delegated to implementation agent.  

---

## Improvement Priority Stack

| ID | Priority | Finding | Status (2026-06-23) | Target |
|----|----------|---------|---------------------|--------|
| F1 | CRITICAL | Compliance patterns recompiled per call | **FIXED** (M005 post-patch) | Done |
| F2 | HIGH | SSRF DNS rebinding bypass | **OPEN** — parse-time only; see SECURITY.md | Pending |
| F3 | MEDIUM | Rate limiter unbounded memory growth | **FIXED** (LRU cap shipped M006) | Done |
| F4 | MEDIUM | Rate limiting by IP, not user identity | **FIXED** (identity-keyed M007) | Done |
| F5 | MEDIUM | Entropy threshold globally fixed, no per-context tuning | **PARTIAL** — configurable threshold shipped; per-context tuning deferred | Partial |
| F6 | LOW | MFA field parsed but not enforced | **FIXED** (WebAuthn/FIDO2 MFA shipped M007 for admin interface) | Done |
| F7 | LOW | Pattern updates require restart (no hot-reload) | **OPEN** (deferred) | Deferred |
| F8 | ARCH | ~62% ATLAS ceiling on pattern-based detection | **ACKNOWLEDGED** — inline LLM judge (M009) shipped for semantic attacks above ceiling | Addressed |
| F9 | ARCH | Crescendo attacks (AML.T0054.007) undetectable at transport layer | **OPEN** — session-level context not yet available to judge | Pending |
| F10 | DOCS | No machine-readable scope boundary statement | **FIXED** (SCOPE.md + aegir-scope.json shipped M006) | Done |

**Additional findings resolved post-M005 (discovered during M009 pre-launch audit):**

| ID | Finding | Status |
|----|---------|--------|
| F11 | Judge mis-wiring: `Route()` called with hardcoded `SUSPICIOUS`, sanitizer verdict ignored | **FIXED** (`sanitizerVerdictToJudge()` helper, correct verdict routing) |
| F12 | HMAC key (`LOG_HMAC_KEY`) not validated at startup; `CheckProductionSecrets` only checked JWT | **FIXED** (both JWT secret and HMAC key validated at startup) |
| F13 | WebSocket `CheckOrigin` was fail-open for any origin; no validation | **FIXED** (`AllowedOrigins` enforced; documented as fail-open when list is empty) |
| F14 | `security.detection.enabled` defaulted to `false`, disabling all IOC detection unless explicitly enabled | **FIXED** (defaults to `true`) |

---

## ATLAS Coverage Assessment (Post-M005)

At HEAD `131796d`:
- **Active enforcement:** ~40-60% (gap analysis generated at `2c2f056`; M005 wired previously-dead IOC patterns, raising active coverage — exact re-measurement required)
- **Hard ceiling:** ~62% (pattern-based transport proxy maximum)
- **Remaining 38%:** Crescendo (AML.T0054.007), indirect injection via tool results, distributed cross-session extraction, adversarial structured inputs — require semantic/behavioral layer

---

## Recommended Next Milestones

| Milestone | Scope |
|-----------|-------|
| **M006** | F2 (SSRF connection-time), F3 (rate limiter cap), F4 (identity-keyed rate limit), F10 (scope docs) |
| **M007** | F5 (per-context entropy tuning), F6 (MFA TOTP enforcement) |
| **M008** | F7 (hot-reload patterns), indirect injection via tool results scan |
| **M009+** | Semantic crescendo detection, cross-session behavioral clustering |

---

## AR-7 Scalability Verdict

Aegir's pattern-based architecture CAN sustain ~10k req/sec on modern hardware **if** all patterns are pre-compiled (IOC patterns were ✓; compliance patterns now ✓ post-fix) and no distributed attack model is assumed.

It **will not** sustain distributed attack (>100 concurrent attacker IPs at rate limit), high-entropy response throughput (>5k req/sec with large payloads and un-pre-compiled compliance patterns), or IP-rotation-based resource exhaustion without the M006 fixes.

---

*Generated by PAI RedTeam ParallelAnalysis + AR-7 Scalability specialist. Execution logged to `~/.claude/PAI/MEMORY/SKILLS/execution.jsonl`.*
