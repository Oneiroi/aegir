# Aegir — Security Scope Boundary

**Version:** 1.0  
**Generated:** 2026-06-02  
**Machine-readable companion:** `aegir-scope.json`  
**Satisfies:** ISC-13, ISC-101, ISC-113

---

## What Aegir Is

Aegir is a transport-layer security proxy for MCP (Model Context Protocol) servers. It sits between clients and upstream MCP servers, enforcing authentication, applying MITRE ATLAS-mapped threat detection, performing compliance redaction, and invoking an inline LLM judge for semantic attacks that pattern matching cannot catch.

Aegir is a **necessary first layer**, not a sufficient one. This document states exactly what it covers, what it partially covers, and what it does not cover.

---

## Transport-Layer Coverage Ceiling

Pattern-based detection at the transport layer has a **hard ceiling of approximately 62% of in-scope MITRE ATLAS techniques for an MCP transport-layer proxy** (the denominator is the technique surface addressable at this layer — not the full ATLAS corpus, which includes training-pipeline, supply-chain, and infrastructure techniques structurally out of scope for a runtime proxy). The remaining ~38% requires semantic and behavioural analysis that cannot be done at the regex/trie level — specifically:

- **Crescendo (AML.T0054.007):** Slow multi-turn escalation without explicit keywords. No individual message triggers detection; only the session-level pattern does.
- **Indirect injection via tool results:** Injected directives embedded in upstream tool call response bodies.
- **Distributed model extraction:** Cross-session behavioural clustering to detect systematic capability probing across many sessions and IPs.

These three classes are **above the ceiling**. The LLM judge layer (M009, shipped) evaluates SUSPICIOUS-flagged traffic inline and issues a BLOCK or ALLOW verdict. Crescendo (session-level escalation) and RAG poisoning require cross-request context that the judge does not yet have access to; indirect injection via tool result content (ISC-22) is in progress.

---

## MITRE ATLAS Technique Coverage

| Technique ID | Name | Status | Mechanism |
|---|---|---|---|
| AML.T0012 | Valid Accounts | implemented | JWT + OAuth2 + API key + WebAuthn/FIDO2 MFA (M007) |
| AML.T0022 | Denial of ML Service | implemented | Per-identity rate limiting with LRU memory cap (M007) |
| AML.T0050 | Execute LLM Prompt | implemented | JWT auth on all MCP endpoints; 401 on unauthenticated requests |
| AML.T0051.000 | Direct Prompt Injection | implemented | 61 IOC patterns via Aho-Corasick trie; case/spacing/unicode normalisation pre-match |
| AML.T0051.001 | Indirect Prompt Injection | planned | Tool result scanning pending M008 (ISC-22) |
| AML.T0051.002 | Triggered Injection | implemented | IOC pattern active post-M006 (ISC-47) |
| AML.T0053 | Agent Tool Invocation Abuse | implemented | validateResourceURI() on URL-typed tool arguments (ISC-12) |
| AML.T0054.001 | Jailbreak DAN | implemented | IOC pattern + anomaly scoring (ISC-49) |
| AML.T0054.003 | System Prompt Override | implemented | IOC pattern post-M006 (ISC-8, ISC-50) |
| AML.T0054.004 | Roleplay Jailbreak | implemented | IOC pattern post-M006 (ISC-51) |
| AML.T0054.007 | Crescendo | planned | Requires LLM judge (M009, ISC-52) — above 62% ceiling |
| AML.T0056 | Meta Prompt Extraction | implemented | Pure extraction patterns shipped (M008, ISC-25) |
| AML.T0057 | LLM Data Leakage | partial | Response compliance scan active (ISC-11); extended secret patterns pending M007 (ISC-17–19) |
| AML.T0070 | RAG Poisoning | planned | Requires LLM judge (M009, ISC-55) — above 62% ceiling |
| SSRF.001-004 | SSRF via Tool Arguments | partial | Parse-time validation active (ISC-12); DNS rebinding fix pending (BUG-2, ISC-1) |
| POLY.001-002 | Case/Spacing Bypass | implemented | Pre-match normalisation: case folding, spacing collapse, unicode (ISC-58) |
| POLY.003 | Leet Speak Bypass | implemented | Leet normalisation pass shipped (M008, ISC-24) |

**Status key:** `implemented` = active and confirmed in code | `partial` = mechanism exists with documented gaps | `planned` = scheduled in a named milestone | `not_covered` = out of scope by design

---

## A2A (Agent-to-Agent) Protocol Gap

**Covered: NO**

Aegir cannot distinguish agent-sourced from human-sourced requests and does not provide trust verification for delegated agent authority.

All requests arriving at the MCP transport layer are treated identically regardless of whether they originate from:
- A human operator
- An orchestrating agent acting on behalf of a human
- A sub-agent in a multi-hop delegation chain

Aegir has no mechanism to:
- Verify that a claimed agent identity is authorised to act on behalf of a principal
- Detect authority escalation in agent delegation chains
- Enforce per-principal scope restrictions in multi-agent pipelines
- Validate delegation tokens or signed authority proofs

This is a structural gap at the current architecture level. Closing it requires an A2A trust layer — signed delegation tokens, verified agent identity, per-principal scope enforcement — that is not planned in any current milestone.

Operators deploying Aegir in agentic pipelines should implement A2A trust enforcement upstream of Aegir or at the orchestration layer.

---

## Explicit Out-of-Scope Boundaries

The following are explicitly outside Aegir's scope by design:

- ML model weights, training pipelines, or fine-tuning infrastructure — Aegir is a transport-layer proxy
- Supply chain or physical environment security
- Attacks that require access to model internals or embeddings
- Cross-deployment infrastructure correlation
- SIEM functionality — Aegir produces HMAC-protected audit logs suitable for SIEM ingestion; it is not a SIEM
- The LLM judge's training or alignment — Aegir consumes a judge API/binary; it does not train one
- NHI (Non-Human Identity) lifecycle management
- Network segmentation and process-level least privilege
- Confused Deputy attacks
- OBO (On-Behalf-Of) authentication flows
- Agent-to-agent trust verification (see A2A section above)

---

## Path to Surpassing the 62% Ceiling

The judge layer (M009, shipped) sits inline on the request path. Architecture:

1. Rule engine issues SUSPICIOUS verdict on traffic that scores above the anomaly threshold but below hard-BLOCK
2. Judge evaluates the request synchronously, inline on the request goroutine — adds latency for SUSPICIOUS traffic only; clean traffic is unaffected
3. Judge backend: Ollama local by default; OpenAI-compatible (OMLX) and Anthropic Messages API are opt-in — MCP payloads may contain sensitive data and must not leave your perimeter by default
4. On ALLOW: Aegir forwards the request to the upstream MCP server
5. On BLOCK, TIMEOUT, or judge error: Aegir returns a clean error response; judge reasoning never reaches the client (`judge.expose_reasoning: false` by default)
6. Judge refusal (judge's own safety guardrails triggered) is treated as an implicit BLOCK

The judge addresses semantic attacks above the pattern-matching ceiling. Crescendo (AML.T0054.007) and RAG poisoning (AML.T0070) detection require session-level context and are pending. Indirect injection via tool result content (AML.T0051.001, ISC-22) is in progress.

---

*Aegir is a necessary first layer in a defence-in-depth stack. Deploy it as one component of a broader security posture, not as a sole defence.*
