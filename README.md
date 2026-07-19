# Aegir — MCP Security Gateway

The Model Context Protocol has no security model. Authentication, content inspection, and threat detection are entirely absent from the specification. MCP is being deployed at scale — in production AI copilots, internal agentic workflows, and enterprise integrations — and the assumption is that security is someone else's problem.

Aegir is that problem's solution. It's a drop-in transport-layer proxy that sits between any MCP client and your MCP server, enforcing enterprise-grade authentication, applying MITRE ATLAS-mapped threat detection, performing compliance redaction, and routing suspicious traffic through an inline LLM judge — all without trusting the model to protect itself.

**The ceiling is honest:** pattern-based detection at the transport layer covers approximately 62% of the MITRE ATLAS technique surface for MCP deployments. The remaining 38% requires semantic analysis above the regex layer. We document exactly what's covered, what's partial, and what isn't covered. See [`SCOPE.md`](SCOPE.md) and [`aegir-scope.json`](aegir-scope.json).

---

## The threat model

MCP tool calls are an unvalidated attack surface. Three confirmed attack paths against unprotected MCP deployments:

**SSRF via Tool Argument URLs** — MCP proxies validate resource URIs at the protocol layer but not the values inside tool call arguments. Pass an AWS IMDS URL (`http://169.254.169.254/latest/meta-data/`) as a tool parameter and an unprotected proxy forwards it without inspection.

**DNS Rebinding Bypass** — URI validation at parse time can be bypassed. An attacker-controlled hostname passes the blocklist check, then resolves to `192.168.1.1` at TCP connection time. Standard blocklist enforcement fails.

**Indirect Prompt Injection via Tool Results** — Content returned by upstream tool calls flows back into model context. Malicious instructions embedded in a database response, fetched document, or API reply execute with full system prompt authority. Pattern matching at the proxy layer does not catch this without inspecting tool result content.

Aegir mitigates path 1 (SSRF) via parse-time tool-argument URL validation — note that DNS rebinding is not covered at parse time; see [`SECURITY.md`](SECURITY.md). Path 2 (DNS rebinding) is an open gap requiring network-level egress controls. Path 3 (indirect injection via tool results) is implemented — `scanToolResultForInjection()` applies the full detection suite to tools/call result content before forwarding (M008, ISC-22). Anomaly detection is active for encoding-based evasion and high-entropy payloads.

---

## MITRE ATLAS coverage

Aegir's detection is mapped against the MITRE ATLAS framework for ML attacks. Full gap analysis in [`MITRE-ATLAS-GAP-ANALYSIS.md`](MITRE-ATLAS-GAP-ANALYSIS.md).

| Technique | Status | Mechanism |
|---|---|---|
| AML.T0051.000 — Direct Prompt Injection | implemented | 61 IOC patterns, Aho-Corasick trie, case/spacing/unicode normalisation |
| AML.T0051.001 — Indirect Prompt Injection | implemented | `scanToolResultForInjection()` applies full detection suite to tools/call result content before forwarding (M008, ISC-22) |
| AML.T0053 — Agent Tool Invocation Abuse | implemented | `validateResourceURI()` on URL-typed tool arguments |
| AML.T0054.001–.006 — Jailbreak variants | implemented | IOC patterns + anomaly scoring |
| AML.T0054.007 — Crescendo | implemented | LLM judge layer (M009) — semantic detection above the pattern-matching ceiling |
| AML.T0057 — LLM Data Leakage | partial | Response compliance scan active; extended secret patterns pending |
| AML.T0012 — Valid Accounts | implemented | JWT + OAuth2 + API key (MCP data path); WebAuthn/FIDO2 MFA (admin management interface) |
| AML.T0022 — Denial of ML Service | implemented | Per-identity rate limiting, bounded tracking map |

The 62% ceiling is not a failure — it's an honest accounting of what a transport-layer proxy can and cannot do. Crescendo attacks, distributed model extraction, and RAG poisoning require semantic understanding above the pattern-matching layer. The inline LLM judge (M009) provides that capability for single-request semantic attacks. Indirect prompt injection via tool results (ISC-22) and single-session Crescendo detection (ISC-52) are both implemented; cross-session distributed Crescendo (context spread across multiple requests) remains an open gap.

---

## Architecture

```
MCP Client → Aegir proxy → upstream MCP server
                │
                ├─ Auth gate (JWT / OAuth2 / API key / WebAuthn)
                ├─ TLS 1.3 enforcement
                ├─ Pattern detection (Aho-Corasick trie, 61 IOC patterns)
                ├─ Anomaly scoring (Shannon entropy, non-ASCII ratio)
                ├─ Compliance redaction (GDPR/HIPAA/PCI)
                ├─ HMAC-protected audit log
                └─ LLM judge (M009, synchronous inline — SUSPICIOUS traffic only)
```

Fail-closed by design: judge timeout → BLOCK, never ALLOW. Clean traffic takes the non-judge path (no judge invocation, <10ms p99). Suspicious traffic incurs synchronous judge latency on the request path — the client blocks until the verdict returns.

Local-first: the default judge backend is Ollama. MCP payloads may contain sensitive data. They do not leave your perimeter by default. API-hosted models (Anthropic, OpenAI-compatible) are explicit opt-in.

---

## Quick start

### Prerequisites

- Go 1.21+
- `just` (task runner) or `make`
- OpenSSL (for certificate generation in development)

### Build and run

```bash
git clone https://github.com/Oneiroi/aegir.git
cd aegir

# Generate development certificates
make certs

# Build
just build
# or: make build

# Run (TLS disabled for local dev)
MCP_SERVER_TLS_ENABLED=false ./bin/aegir

# Run tests
just test
# or: go test ./...
```

### Configuration

Aegir is configured via `aegir.yaml`. Key settings:

```yaml
server:
  port: 8443
  tls:
    enabled: true
    cert_file: certs/cert.pem
    key_file: certs/key.pem

upstream:
  url: "http://your-mcp-server:8080"

security:
  detection:
    enabled: true
  anomaly_detection:
    enabled: false          # opt-in; logs anomaly scores when false
    block_threshold: 0.85
```

Full configuration reference: `aegir.yaml` in the repository root.

### Default credentials (development only)

A default admin user is created in development:
- **Username:** `admin`
- **Password:** `admin123`

> **Do not use these in production.** Set `AEGIR_ADMIN_PASSWORD` on first boot or configure your IdP via OAuth2/OIDC. Production deployments with default credentials are a hardcoded P1 gap in the ATLAS analysis ([P1-4](MITRE-ATLAS-GAP-ANALYSIS.md)).

---

## Compliance

Aegir performs automatic redaction in transit:

| Framework | What gets detected | Redaction marker |
|---|---|---|
| GDPR / CCPA | PII (SSN, email, address, name patterns) | `PII_REDACTED` |
| HIPAA | PHI (medical records, diagnoses, NPI) | `PHI_REDACTED` |
| PCI DSS | Card numbers, CVV, track data | `CARD_DATA_REDACTED` |

Audit logs are HMAC-protected (tamper-evident). Format suitable for SIEM ingestion. Aegir is not a SIEM.

---

## Honest scope

Not all MCP attacks are catchable at the transport layer. The following are explicitly out of scope by design:

- ML model weights, training pipelines, fine-tuning infrastructure
- Crescendo and slow-escalation attacks without explicit keywords (above the 62% ceiling — LLM judge M009 addresses this)
- Distributed model extraction via cross-session behavioural clustering
- Agent-to-agent trust verification and delegation chain validation
- Supply chain and physical environment security

Full scope boundary with machine-readable coverage map: [`SCOPE.md`](SCOPE.md) and [`aegir-scope.json`](aegir-scope.json).

---

## Roadmap

| Milestone | Focus | Status |
|---|---|---|
| M006 | Activate dead IOC patterns; anomaly block threshold; response compliance scan | Shipped |
| M007 | WebAuthn/FIDO2 MFA; per-identity rate limiting; model extraction detection | Shipped |
| M008 | Leet-speak normalisation; base64 decode-then-scan; indirect injection (tool-result scan in progress) | Mostly shipped |
| M009 | LLM judge layer — async hold-and-decide, Ollama local default | Shipped (sync judge + hold wired; MCP-native progress pending SSE transport) |
| M012 | Aho-Corasick detection trie (stdlib, no new deps) | Shipped |
| M013 | Judge backend portability — Ollama / OpenAI-compatible / Anthropic adapters + transport-error failover | Shipped |
| M014 | Pre-OSS security audit remediation (1 CRITICAL + 4 HIGH + 5 MED + 5 LOW) | Shipped |
| M015 | MCP 2026-07-28 spec hardening (13 ISCs: header validation, meta inspection, async quota, XSS hardening, signed state, PKCE) | Shipped |
| M016 | LLMVault reference integration; defensive-architecture positioning (documentation + mapping guide) | **In progress** |

---

## Landscape

This is an emerging space. If you're evaluating MCP security tooling:

- **Solo.io Agentgateway** — purpose-built MCP/A2A gateway (Rust, Linux Foundation). Strong on A2A agent trust, tool-level RBAC, and performance (165k QPS). Does not publish MITRE ATLAS coverage mapping or technique-level ceiling disclosure. If agent delegation chain verification is your primary concern, evaluate both.
- **Costa.security AI Gateway** — auth/authz proxy with model-tool optimization focus.
- **MCPSafetyScanner** (Radosevich & Halloran, 2025, arxiv.org/abs/2504.03767) — pre-deployment auditing tool that generates adversarial samples and reports. Complementary to a runtime proxy.

Aegir's differentiation: MITRE ATLAS mapping with published technique-level coverage, SCOPE.md honest ceiling disclosure, GDPR/HIPAA/PCI compliance redaction, and an LLM judge layer (Ollama-local by default, OpenAI/Anthropic opt-in) for the semantic attacks that pattern matching cannot catch.

---

## Learning & validation

Practitioners learning MCP attack patterns should start here, then deploy Aegir to practice defense:

- **[LLMVault](https://github.com/CyberSunil/LLMVault)** — Deliberately-vulnerable CTF-style training platform. 25 labs across three tiers (core, advanced, expert) teaching the OWASP Top 10 for LLM Applications (2025): prompt injection, data exfiltration, supply chain poisoning, model poisoning, output handling, excessive agency, system prompt leakage, and more. Each lab includes a private solutions guide showing the defense. **Aegir is the reference implementation for defending these attack classes** — see [`docs/LLMVAULT-DEFENSIVE-MAPPING.md`](docs/LLMVAULT-DEFENSIVE-MAPPING.md) for a category-by-category walkthrough.

## Research

The threat model preceded the implementation. The ATLAS gap analysis was written before the first line of proxy code.

- [`MITRE-ATLAS-GAP-ANALYSIS.md`](MITRE-ATLAS-GAP-ANALYSIS.md) — Full technique-by-technique analysis with P1/P2/P3 gap prioritisation
- [`SCOPE.md`](SCOPE.md) — Honest scope boundary with machine-readable companion
- [`REDTEAM-REPORT-20260520.md`](REDTEAM-REPORT-20260520.md) — Red team findings against the current implementation
- [`docs/LLMVAULT-DEFENSIVE-MAPPING.md`](docs/LLMVAULT-DEFENSIVE-MAPPING.md) — How Aegir defends against each LLMVault lab category (reference-architecture guide)

---

## License

Apache 2.0.

## Contributing

Issues and PRs welcome. For security issues: security@oneiroi.co.uk

The ATLAS gap analysis and IOC pattern library are the most useful contribution surfaces for the community. If you have a detection technique for an uncovered ATLAS technique, open an issue with the technique ID and a proposed pattern.
