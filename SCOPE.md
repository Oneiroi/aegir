# Aegir — Security Scope Boundary

**Version:** 1.2  
**Generated:** 2026-07-02  
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

These three classes were above the ceiling. The LLM judge layer (M009, shipped) evaluates SUSPICIOUS-flagged traffic inline and issues a BLOCK or ALLOW verdict. **Single-session Crescendo and RAG poisoning are now covered by the judge (ISC-52, ISC-55).** Indirect injection via tool result content is implemented (ISC-22, scanToolResultForInjection). **Remaining gap:** cross-session distributed Crescendo requires session-level context the judge does not yet have.

---

## MITRE ATLAS Technique Coverage

| Technique ID | Name | Status | Mechanism |
|---|---|---|---|
| AML.T0012 | Valid Accounts | implemented | JWT + OAuth2 + API key + WebAuthn/FIDO2 MFA (M007) |
| AML.T0022 | Denial of ML Service | implemented | Per-identity rate limiting with LRU memory cap (M007) |
| AML.T0050 | Execute LLM Prompt | implemented | JWT auth on all MCP endpoints; 401 on unauthenticated requests |
| AML.T0051.000 | Direct Prompt Injection | implemented | 61 IOC patterns via Aho-Corasick trie; case/spacing/unicode normalisation pre-match |
| AML.T0051.001 | Indirect Prompt Injection | implemented | scanToolResultForInjection() applies full detection suite to tools/call result content before forwarding (M008, ISC-22) |
| AML.T0051.002 | Triggered Injection | implemented | IOC pattern active post-M006 (ISC-47) |
| AML.T0053 | Agent Tool Invocation Abuse | implemented | validateResourceURI() on URL-typed tool arguments (ISC-12) |
| AML.T0054.001 | Jailbreak DAN | implemented | IOC pattern + anomaly scoring (ISC-49) |
| AML.T0054.003 | System Prompt Override | implemented | IOC pattern post-M006 (ISC-8, ISC-50) |
| AML.T0054.004 | Roleplay Jailbreak | implemented | IOC pattern post-M006 (ISC-51) |
| AML.T0054.007 | Crescendo | implemented | LLM judge layer (M009) evaluates SUSPICIOUS-flagged traffic; single-session Crescendo payloads yield SUSPICIOUS/BLOCK (ISC-52). Cross-session distributed escalation remains not covered. |
| AML.T0056 | Meta Prompt Extraction | implemented | Pure extraction patterns shipped (M008, ISC-25) |
| AML.T0057 | LLM Data Leakage | implemented | Response compliance scan active (ISC-11); AWS/Azure SAS/GCP SA/Slack secret patterns shipped M007 (ISC-17–19); per-type severity and block/redact/log-only policy shipped M008 (ISC-27/28) |
| AML.T0070 | RAG Poisoning | implemented | LLM judge layer detects semantic intent inline (M009, ISC-55); TestJudgeATLASTechniques verifies AML.T0070 payloads yield SUSPICIOUS/BLOCK |
| SSRF.001-004 | SSRF via Tool Arguments | implemented | Parse-time validation active (ISC-12); connection-time re-validation via custom DialContext (ISC-1, BUG-2 resolved) |
| POLY.001-002 | Case/Spacing Bypass | implemented | Pre-match normalisation: case folding, spacing collapse, unicode (ISC-58) |
| POLY.003 | Leet Speak Bypass | implemented | Leet normalisation pass shipped (M008, ISC-24) |

**Status key:** `implemented` = active and confirmed in code | `partial` = mechanism exists with documented gaps | `planned` = scheduled in a named milestone | `not_covered` = out of scope by design

---

## OWASP LLM Top 10 (2025) Coverage

This is the second authoritative coverage mapping (after MITRE ATLAS above). Out-of-scope items are declared honestly here rather than falsely claimed as covered.

| OWASP 2025 | Status | Owning ISCs | Mechanism |
|---|---|---|---|
| LLM01 Prompt Injection | covered | ISC-8, ISC-22, ISC-45, ISC-46, ISC-23, ISC-24, ISC-52 | Direct + indirect (tool-result) injection detection via base64/leet normalisation and an Aho-Corasick pattern layer, backed by an LLM judge for semantic/Crescendo-style attacks |
| LLM02 Sensitive Information Disclosure | covered | ISC-11, ISC-27, ISC-28, ISC-60, ISC-61, ISC-62, ISC-63, ISC-64, ISC-65, ISC-17, ISC-18, ISC-19, ISC-109 | PII/PHI/PCI redaction (request + response) plus secret detection |
| LLM03 Supply Chain | partial | ISC-107, ISC-108, ISC-115, ISC-116, ISC-111 | Tool-integrity subset only (drift, collision, full-schema poisoning, typosquatting, upstream mTLS); broad software/dependency supply chain is out of scope |
| LLM04 Data & Model Poisoning | partial | ISC-55, ISC-117 | Runtime RAG-poisoning intent + resource-content poisoning; training-time weights/pipeline poisoning is out of scope |
| LLM05 Improper Output Handling | covered | ISC-114, ISC-110, ISC-123 | ACE patterns (CWE-77/78/94/95) on response bodies, JSON-RPC schema validation, large-response anomaly detection |
| LLM06 Excessive Agency | partial | ISC-119, ISC-112, ISC-48, ISC-121, ISC-122, ISC-113 | Human-approval gate, tool-call sequence anomaly, tool-arg abuse, recon rate-limit, OAuth scope audit; A2A trust delegation documented not-covered |
| LLM07 System Prompt Leakage | covered | ISC-25, ISC-53, ISC-33, ISC-93 | Meta-prompt-extraction patterns (AML.T0056); judge reasoning never leaks to the client |
| LLM08 Vector & Embedding Weaknesses | out-of-scope | — | Requires model-internal/embedding access, explicitly excluded |
| LLM09 Misinformation | out-of-scope | — | Model output-quality/hallucination is not a transport-proxy concern |
| LLM10 Unbounded Consumption | covered | ISC-14, ISC-56, ISC-2, ISC-3, ISC-123 | Identity + IP rate limiting, memory-bounded limiter, content-length anomaly (DoS / Denial-of-Wallet) |

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

The judge addresses semantic attacks above the pattern-matching ceiling. Single-session Crescendo (AML.T0054.007) and RAG poisoning (AML.T0070) are now covered via the judge (ISC-52, ISC-55). Indirect injection via tool result content (AML.T0051.001, ISC-22) is implemented. Remaining gap: cross-session distributed Crescendo requires session-level context across multiple requests.

---

*Aegir is a necessary first layer in a defence-in-depth stack. Deploy it as one component of a broader security posture, not as a sole defence.*
