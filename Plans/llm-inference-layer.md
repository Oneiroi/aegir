# Idea: LLM Inference Layer (Judge Model)

**Added:** 2026-05-23  
**Status:** Idea — not yet scoped

## Concept

Add an LLM inference layer to Aegir that acts as a "judge" on traffic flagged by the rule engine. Detected/suspicious requests are handed off to an LLM model for a final decision. Both signals are collated to arrive at the final verdict. Mirrors the LLM judge pattern used in the llm-redteam project.

## Architecture

```
MCP Request
    │
    ▼
Rule Engine (fast, deterministic)
    │
    ├── ALLOW → pass through (no LLM invoked)
    ├── BLOCK → hard block (no LLM override)
    └── SUSPICIOUS → issue MCP "please wait" (synthetic in-progress notification)
                         │
                         ▼
                     LLM Judge (async, internal)
                         │
                         ├── ALLOW → forward buffered tool response to client LLM
                         └── BLOCK → send opaque MCP error + terminate session
```

**Key isolation principle:** the client LLM never sees the judge's reasoning or output. The firewall is the sole interpreter of the judge's verdict. The client LLM experiences either a slow tool call or a clean termination — it cannot distinguish a judge BLOCK from a backend failure. This eliminates the adaptive attack feedback loop (attacker cannot refine payloads based on judge signals).

**"Please wait" implementation:** MCP over SSE supports in-progress notifications for long-running tool operations — the firewall issues a synthetic progress notification (valid MCP protocol) to hold the connection while the judge runs. No protocol violation; the client LLM sees a slow but legitimate tool execution.

**Termination signal:** clean MCP error response (opaque error code, no reasoning exposed), not a connection drop. Gives better audit logging and a deterministic failure state for the client rather than a timeout.

Rule engine verdict is the first gate. LLM judge is only invoked on SUSPICIOUS — never on all traffic. Hard BLOCK from rules is final; LLM cannot override a rule-based hard block.

## Why

- Rule-based detection is brittle against semantic attacks (prompt injection, context poisoning, novel MCP abuse patterns)
- LLM judges understand intent, not just pattern — suited to stochastic/semantic attack classes
- Ensemble approach (rules + LLM) reduces false positives without sacrificing rule-based certainty
- Consistent with llm-redteam's LLM judge model — reuse of pattern across both projects

## Design Constraints

- **LLM must not be in the hot path** — inference only on flagged traffic, not all MCP calls
- **Judge prompt must be hardened** — the judge itself is an attack surface; its system prompt must not be injectable
- **Collation logic must be explicit** — define weighting before implementation, not after; ambiguity here is a security gap
- **Cost scoping** — inference per flagged request is acceptable; per-request inference on all MCP traffic is not viable

## CFP Relevance

"We use an LLM to defend against LLM-generated attacks on AI systems" — tight, quotable thesis for the 44con submission. Strengthens the talk narrative significantly.

## Judge Refusal = Implicit BLOCK

If the judge model refuses to respond due to its own safety guardrails being triggered, that refusal is itself a strong signal that the content is malicious. Aegir treats judge refusal as an implicit BLOCK — stronger than a standard verdict BLOCK — and terminates the session immediately.

Rationale: if even a safety-trained LLM won't analyse the content, the content was obviously malicious enough to trip the model's own filters. This is a harder signal than a BLOCK verdict derived from analysis.

- Judge refusal logged as `judge_refused` with severity CRITICAL (higher than standard BLOCK)
- Aegir never falls back to ALLOW on refusal — fail-closed, not fail-open
- Same applies to judge timeout — timeout → BLOCK, not ALLOW

## Open Questions

- Which inference model? Local (Ollama) vs API (Claude Haiku, GPT-4o-mini) — latency and cost tradeoffs differ; local strongly preferred to avoid shipping MCP traffic (which may contain sensitive payloads) to a third-party API
- What is the maximum acceptable "please wait" duration before the client LLM times out? Sets the SLA for judge response time.
- What does the opaque termination error code look like — generic MCP error, or a specific code that operators can grep for in logs?
- How is the judge's decision logged and auditable (full reasoning stored internally, opaque externally)?
- How does the judge prompt get tested against adversarial inputs — can an attacker craft an MCP payload that fools the judge into ALLOW?
