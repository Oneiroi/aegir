# LLMVault Defense Mapping — Aegir as Reference Architecture

> **Purpose:** Practitioners learning MCP attacks via [LLMVault](https://github.com/CyberSunil/LLMVault) can use this mapping to understand how Aegir implements defenses for each attack category. Aegir is the reference defensive architecture for OWASP Top 10 for LLM Applications (2025) at the MCP transport layer.

---

## How to use this document

1. **Learn the attack** in a LLMVault lab (e.g., "Prompt Injection — Core Tier, Lab 1")
2. **Locate the attack category** in the table below (e.g., **LLM01: Prompt Injection**)
3. **Review Aegir's defense** — which ISCs implement the defense, which config enables it, which probe verifies it
4. **Deploy Aegir** in your MCP stack using the linked config example
5. **Verify the defense** by running the probe test or building against the documented code

---

## OWASP Top 10 for LLM Applications (2025) — Aegir Defense Map

### LLM01: Prompt Injection

**Attack types trained in LLMVault:**
- Direct prompt injection (immediate malicious instructions in a message)
- Indirect prompt injection (malicious instructions embedded in tool results or fetched data)
- Encoding-based evasion (base64, leet-speak variants)
- Semantic escalation (Crescendo attacks requiring multi-turn reasoning)

**Aegir defenses:**

| Defense | ISC(s) | Mechanism | Config | Probe |
|---------|--------|-----------|--------|-------|
| **Pattern-based direct injection** | ISC-8, ISC-45 | 61 IOC patterns post-normalisation (case, spacing, unicode, leet-speak); Aho-Corasick trie for O(n) matching | `security.detection.enabled: true` | `TestPromptInjectionDetection` (subtest `system_prompt_override`) |
| **Indirect injection via tool results** | ISC-22, ISC-46 | `scanToolResultForInjection()` applies full detection suite to tool call results before forwarding | `security.detection.enabled: true` | `TestToolResultInjectionBlocked`, `TestToolResultCleanAllowed` |
| **Base64 decode-then-scan** | ISC-23 | Base64-encoded payloads decoded and re-scanned before forwarding | `security.detection.enabled: true` | `TestPromptInjectionDetection` (subtest `base64_injection`) |
| **Leet-speak normalisation** | ISC-24 | Payload normalised to `i→i`, `3→e`, `0→o`, `1→l`, etc., scanned post-norm | `security.detection.enabled: true` | `TestAdvancedPromptInjectionDetection` (subtest `leet_speak`) |
| **Meta-prompt extraction patterns** | ISC-25, ISC-53 | Pure extraction patterns (e.g., "what are your instructions") detected independent of override verb | `security.detection.enabled: true` | `(no dedicated probe yet)` |
| **Semantic analysis (Crescendo)** | ISC-52, M009 | LLM judge layer invoked on SUSPICIOUS traffic; catches multi-step escalation patterns regex cannot | `judge.enabled: true; judge.provider: ollama` (or `openai`/`anthropic`) | `TestJudgeATLASTechniques` (subtest `AML.T0054.007`) |

**Getting started:** Deploy with this config snippet:
```yaml
security:
  detection:
    enabled: true       # Activates pattern + anomaly baseline
  
judge:
  enabled: true
  provider: ollama      # Local-first; no outbound data transmission
  base_url: "http://localhost:11434"
  model: "mistral"      # Or any local GGUF model
```

---

### LLM02: Sensitive Information Disclosure

**Attack types trained in LLMVault:**
- Leaking PII (names, emails, phone numbers, SSNs) in model outputs
- Leaking PHI (medical records, diagnoses) in responses
- Leaking credentials (API keys, database connection strings) in tool results
- Leaking secrets in HTTP headers (via the `x-mcp-header` directive)

**Aegir defenses:**

| Defense | ISC(s) | Mechanism | Config | Probe |
|---------|--------|-----------|--------|-------|
| **PII detection & redaction (request + response)** | ISC-60, ISC-61 | Regex patterns for SSN, email, phone, address; redaction marker `PII_REDACTED` | `compliance.response_policy.pii: redact` (or `block`) | `TestGDPRCompliancePayloads` |
| **PHI detection (HIPAA)** | ISC-62 | ICD-10 codes, medical terms, diagnoses; redaction marker `PHI_REDACTED` | `compliance.response_policy.phi: redact` | `TestHIPAACompliancePayloads` |
| **PCI detection** | ISC-63 | Card numbers (Luhn-validated), CVV, track data; redaction marker `CARD_DATA_REDACTED` | `compliance.response_policy.pci: redact` | `TestPCIDSSCompliancePayloads` |
| **Secret detection (extended)** | ISC-17, ISC-18, ISC-19, ISC-109 | AWS keys (AKIA pattern), GCP SA JSON, Azure SAS tokens, Slack tokens; blocks or redacts per policy | `security.secret_detection.enabled: true` | `TestSecretDetection`; `(no dedicated probe yet)` for Slack tokens |
| **HTTP header egress scan** | ISC-169, ISC-170 | Request & response HTTP headers scanned for secrets; `x-mcp-header` directive-driven leakage flagged explicitly | `security.detection.enabled: true` | `TestScanHeadersDetectsXMcpHeaderCredential` |
| **Partial/split PII detection** | ISC-160 | SSN patterns across chunk boundaries (e.g., one chunk ends with `123-45-`, next starts with `6789`) detected | `security.detection.enabled: true` | `TestPartialRedactionCoverage` |

**Getting started:**
```yaml
compliance:
  response_policy:
    pii: block          # Block responses containing PII; log the finding
    phi: redact         # Redact PHI in-transit
    pci: block          # Block PCI-DSS violations
    # Note: there is no "secret" key here — secret-detection violations are
    # typed "secret_<pattern>" (e.g. "secret_aws_key"), not bare "secret",
    # so response_policy has no matching default. Gate secret detection via:
security:
  secret_detection:
    enabled: true        # Block/redact responses leaking credentials
```

---

### LLM03: Supply Chain

**Attack types trained in LLMVault:**
- Tool description poisoning (malicious descriptions in upstream tool metadata)
- Tool shadowing (BCC-injection-style strings in tool descriptions cross-referencing other tools)
- Tool name collision (duplicate tool names across multiple upstreams)
- Tool schema poisoning (hidden parameters injected into tool definitions)
- Typosquatting (tool names deliberately close to legitimate ones)

**Aegir defenses (tool metadata integrity):**

| Defense | ISC(s) | Mechanism | Config | Probe |
|---------|--------|-----------|--------|-------|
| **Tool description drift detection** | ISC-107 | SHA-256 hash of each tool description stored on first receipt; changes logged as `tool_description_changed` | `(no dedicated config key)` — implemented in `internal/toolmeta`, not yet wired to production config | `TestISC107_DescriptionDriftDetected` |
| **Tool shadowing detection** | ISC-106 | Heuristic cross-tool behavioural directives (e.g., "when calling X tool, always...") flagged in `tools/list` responses | `(no dedicated config key)` — implemented in `internal/toolmeta`, not yet wired to production config | `TestISC106_ShadowingDetected` |
| **Tool name collision detection** | ISC-108 | Duplicate tool names across multiple MCP server upstreams logged as `tool_name_collision` | `(no dedicated config key)` — implemented in `internal/toolidentity`, not yet wired to production config | `TestISC108_CollisionDetected` |
| **Full schema poisoning detection** | ISC-115 | Complete tool schema (parameters, types, required flags) fingerprinted; structural changes without version bump logged | `(no dedicated config key)` — implemented in `internal/toolidentity`, not yet wired to production config | `TestISC115_SchemaPoisoningDetected` |
| **Typosquatting detection** | ISC-116 | Levenshtein distance ≤2 against trusted-tool allowlist triggers `tool_name_confusion_suspected` event | `(no dedicated config key)` — implemented in `internal/toolidentity`, not yet wired to production config | `TestISC116_ConfusionDetected_SendEmail` |
| **Upstream mTLS + cert pinning** | ISC-111 | TLS certificate pinning (SHA-256 fingerprint); upstream cert mismatch blocks connection | `(no dedicated config key)` — cert-pinning logic exists in `internal/upstream.Manager.ConfigureTLS` (test-only `UpstreamTLSConfig.CertPin`), but the production `config.UpstreamTLS` struct has no `cert_pin` field | `TestUpstreamCertPinMismatch` |

**Note:** Broad software supply-chain attacks (compromised dependencies, build pipeline injection) are **out of scope** for a transport-layer proxy. Aegir covers tool-metadata integrity only.

**Status:** the tool-metadata-integrity and identity packages (`internal/toolmeta`, `internal/toolidentity`) and upstream cert-pinning are implemented and unit-tested but **not yet wired into the live proxy path or exposed via `aegir.yaml`**. There is currently no config snippet that activates these defenses in a running deployment — treat this section as a roadmap of tested-but-unreleased capability, not a deployable control.

**Getting started:** No deployable config exists yet for this section (see Status above). Track wiring progress via the ISC entries above in `ISA.md`.

---

### LLM04: Data & Model Poisoning

**Attack types trained in LLMVault:**
- RAG poisoning (malicious documents injected into retrieval-augmented generation systems)
- Runtime resource poisoning (tool results deliberately crafted to alter model behaviour)

**Aegir defenses:**

| Defense | ISC(s) | Mechanism | Config | Probe |
|---------|--------|-----------|--------|-------|
| **RAG poisoning intent detection** | ISC-55 | LLM judge layer detects RAG-poisoning intent in suspicious traffic | `judge.enabled: true` | `TestJudgeATLASTechniques` (subtest `AML.T0070`) |
| **Resource content poisoning** | ISC-117 | Prompt injection patterns applied to `tools/call` response bodies (data returned from tool invocations) | `(no dedicated config key)` — implemented in `internal/compliance`, not yet wired to production config | `TestISC117_PromptInjectionTriggersEvent` |

**Note:** Training-time model-weight poisoning is **out of scope** — Aegir operates at runtime only.

**Getting started:** See LLM01 (Prompt Injection) config — the same detection layer catches poisoning attempts.

---

### LLM05: Improper Output Handling

**Attack types trained in LLMVault:**
- Arbitrary code execution (ACE) patterns in tool results (shell commands, eval-class injections)
- Command substitution (`$(...)`, backtick wrapping)
- JSON-RPC schema confusion (malformed or unexpected message structure)
- Large response anomalies (Denial-of-Wallet / response bombing)

**Aegir defenses:**

| Defense | ISC(s) | Mechanism | Config | Probe |
|---------|--------|-----------|--------|-------|
| **ACE pattern detection** | ISC-114 | Shell metacharacter sequences (CWE-77/78), eval-class injections (CWE-94/95), command substitution patterns detected in tool results | `(no dedicated config key)` — implemented in `internal/compliance`, not yet wired to production config | `TestISC114_BacktickCommandTriggersEvent` |
| **JSON-RPC schema validation** | ISC-110 | Message structure validation; unknown fields or unexpected types rejected with MCP error | Default (always enforced) | `TestISC110_MissingJsonrpc` |
| **XSS/active-content hardening** | ISC-173, ISC-174 | Event-handler attributes, `<svg>` embedded script, `data:` URIs stripped from tool results; MCP App payloads scanned stricter | `security.detection.enabled: true; security.sanitization.xss_prevention: true` | `TestToolResultStripsEventHandlers`, `TestMcpAppContentScannedStrict` |
| **Large response anomaly detection** | ISC-123 | Responses above configurable size threshold (default 1 MB) trigger `large_response_anomaly` event | `(no dedicated config key)` — implemented in `internal/compliance`, not yet wired to production config | `TestISC123_LargeResponseTriggersEvent` |

**Getting started:**
```yaml
security:
  detection:
    enabled: true
  sanitization:
    xss_prevention: true
# Note: ACE pattern detection and large-response anomaly detection
# (internal/compliance) are implemented and unit-tested but not yet
# wired into the live proxy path — no config key activates them today.
```

---

### LLM06: Excessive Agency

**Attack types trained in LLMVault:**
- Unrestricted tool invocation (model calling destructive tools without approval)
- Tool reconnaissance (enumeration of available tools to identify attack surface)
- Anomalous tool-call sequences (high-risk sequences like `list_credentials` → `send_email`)
- OAuth scope escalation (agent requesting excessive permission scopes)

**Aegir defenses:**

| Defense | ISC(s) | Mechanism | Config | Probe |
|---------|--------|-----------|--------|-------|
| **Human approval gate** | ISC-119 | Destructive tools (prefix-matched, case-insensitive) require human approval via webhook before execution | `security.human_approval.enabled: true; security.human_approval.webhook_url: "https://..."` | `TestHumanApprovalGate` |
| **Tool-call sequence anomaly detection** | ISC-112 | Ordered tool-call sequences per session; high-risk patterns (e.g., `list_credentials` → `send_*` within a window) trigger detection | `session_analysis.enabled: true` | `TestToolCallSequenceAnomaly` |
| **Tools/list reconnaissance rate limiting** | ISC-121 | `tools/list` recon calls rate-limited per session; threshold configurable | `security.recon_rate_limit.enabled: true; security.recon_rate_limit.tools_list_max_per_min: 10` | `TestToolsListReconRateLimit` |
| **OAuth scope audit logging** | ISC-122 | JWT scope/scp claims parsed and logged; prohibited scopes logged or enforced | `security.oauth_scope_audit.enabled: true; security.oauth_scope_audit.prohibited_scopes: ["*", "admin", "write:all"]` | `TestOAuthScopeAuditMiddleware` |
| **OAuth scope enforcement** | ISC-148 | Prohibited scopes rejected before request forwarding (gated by config) | `security.oauth_scope_audit.enforcement: true` | `TestOAuthScopeEnforcement` |

**Note:** Agent-to-agent trust delegation and cross-agent authorization verification are **out of scope** (documented in [`SCOPE.md`](SCOPE.md)).

**Getting started:**
```yaml
security:
  human_approval:
    enabled: true
    webhook_url: "https://approval-service.internal/approve"
    timeout: 30s
    patterns:
      - "delete_*"
      - "drop_*"
      - "execute_*"

  recon_rate_limit:
    enabled: true
    tools_list_max_per_min: 10

  oauth_scope_audit:
    enabled: true
    enforcement: true
    prohibited_scopes:
      - "*"
      - "admin"
      - "write:all"

session_analysis:
  enabled: true   # Backs tool-call sequence anomaly detection (ISC-112)
```

---

### LLM07: System Prompt Leakage

**Attack types trained in LLMVault:**
- Meta-prompt extraction (questions like "what are your instructions")
- System prompt inference (behavioral analysis to reverse-engineer prompts)
- Judge reasoning leakage (Aegir's internal reasoning exposed to the client)

**Aegir defenses:**

| Defense | ISC(s) | Mechanism | Config | Probe |
|---------|--------|-----------|--------|-------|
| **Meta-prompt extraction patterns** | ISC-25, ISC-53 | Pure extraction patterns (no override verb required) detected and blocked | `security.detection.enabled: true` | `(no dedicated probe yet)` |
| **Judge reasoning never leaks to client** | ISC-33, ISC-93 | Judge output consumed internally; client sees slow tool call or clean termination, never reasoning | Default (always enforced) | `TestJudgeReasonNeverLeaksToClient` |
| **Judge refusal treated as implicit BLOCK** | ISC-37.1 | Judge's own safety guardrails (refusal) result in session termination, not pass-through | Default (always enforced) | `TestJudgeRefusal_ImplicitBlock` |

**Note:** Behavioral reverse-engineering via inference is **out of scope** — Aegir focuses on preventing explicit extraction and information leakage.

**Getting started:** See LLM01 (Prompt Injection) config. Judge reasoning is never exposed by default.

---

### LLM08: Vector & Embedding Weaknesses

**Status:** ✗ **Out of scope for Aegir**

Embedding attacks require access to model internals (embeddings, weights, or fine-tuning infrastructure). Aegir is a transport-layer proxy and has no visibility into embedding space or model training.

**Recommended alternative:** Defend embeddings at the model-infrastructure layer (e.g., embedding model validation, input sanitization at the RAG ingestion point).

---

### LLM09: Misinformation

**Status:** ✗ **Out of scope for Aegir**

Model output quality, hallucination detection, and misinformation screening are not transport-proxy concerns. These are model-architecture and application-level responsibilities.

**Recommended alternative:** Implement output-validation logic in the client application (fact-checking, confidence scoring, user feedback loops).

---

### LLM10: Unbounded Consumption

**Attack types trained in LLMVault:**
- Denial-of-Service via high-frequency requests
- Denial-of-Wallet via large response payloads or resource exhaustion
- Rate-based extraction (model extraction via high-volume queries)

**Aegir defenses:**

| Defense | ISC(s) | Mechanism | Config | Probe |
|---------|--------|-----------|--------|-------|
| **Per-identity rate limiting** | ISC-14, ISC-56 | Authenticated user identity tracked; per-user request rate limited | `security.rate_limit.enabled: true; security.rate_limit.requests_per_min: 60` | `(no dedicated probe yet)` |
| **IP-based rate limiting** | ISC-56 | Source IP tracked as fallback for unauthenticated requests; rate limited | Default when auth not present | `(no dedicated probe yet)` |
| **Memory-bounded rate limiter** | ISC-2, ISC-3 | Limiter map capped at configurable max; LRU eviction prevents memory growth | `security.rate_limit.max_tracked_ips: 10000` | `TestRateLimiterMemoryCap`, `TestRateLimiterRotation` |
| **Cross-session repetition counter** | ISC-15 | Uniform query patterns from same user over sliding window trigger model-extraction flag | `session_analysis.enabled: true` | `TestModelExtractionDetection` |
| **Large response anomaly detection** | ISC-123 | Responses above size threshold (default 1 MB) flagged for denial-of-wallet attacks | `(no dedicated config key)` — implemented in `internal/compliance`, not yet wired to production config | `TestISC123_LargeResponseTriggersEvent` |
| **Content-length anomaly** | ISC-123 | HTTP response content-length monitored; anomalies contribute to session suspicion score | `(no dedicated config key)` — same underlying probe as large-response anomaly above; no distinct implementation exists | `TestISC123_LargeResponseTriggersEvent` |

**Getting started:**
```yaml
security:
  rate_limit:
    enabled: true
    requests_per_min: 60           # Per tracked identity/IP
    max_tracked_ips: 10000         # Memory cap for IP tracking
    burst_size: 5                  # Allow short bursts

session_analysis:
  enabled: true   # Backs cross-session repetition / model-extraction detection (ISC-15)

# Note: large-response and content-length anomaly detection (internal/compliance,
# ISC-123) are implemented and unit-tested but not yet wired into the live proxy
# path — no config key activates them today.
```

---

## Deployment checklist

When deploying Aegir as your MCP defense reference:

- [ ] **Generate TLS certificates** (production) or use development mode
- [ ] **Configure upstream MCP server URL** in `aegir.yaml`
- [ ] **Enable detection layer** (`security.detection.enabled: true`)
- [ ] **Deploy judge** (local Ollama or API-hosted; Ollama is local-first default)
- [ ] **Configure compliance policies** (PII/PHI/PCI/secret blocking or redaction)
- [ ] **Set up rate limiting** per identity and IP
- [ ] **Enable audit logging** (HMAC-protected, suitable for SIEM ingestion)
- [ ] **Test with LLMVault labs** (run attacks; verify Aegir blocks them)
- [ ] **Review probe tests** (`go test ./...`) to validate all defenses active

---

## Feedback & contributions

Found a gap? Think a defense is incomplete?

- Open an issue: [github.com/Oneiroi/aegir/issues](https://github.com/Oneiroi/aegir/issues)
- Security issues: security@oneiroi.co.uk
- Contribute IOC patterns or detection logic for uncovered OWASP categories to help Aegir evolve
