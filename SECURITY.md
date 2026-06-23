# Security Policy

## Reporting a Vulnerability

Security issues should be reported to **d.busby@saiweb.co.uk** with the subject line
`[Aegir Security]`. Please include:

- A description of the issue and its potential impact
- Steps to reproduce or proof-of-concept
- Affected versions / configuration

I aim to respond within 48 hours and will work with you on disclosure timing. There is no
formal bug bounty at this time — but credited disclosure in the changelog is standard practice
here.

---

## Known Limitations

Aegir is a defence-in-depth proxy, not a complete MCP security solution. The following
limitations are documented openly so operators can apply compensating controls.

### LLM Judge Semantic Jailbreak

The LLM judge (second-pass analysis for SUSPICIOUS payloads) is protected against
response-injection attacks — `parseVerdict` requires the model's entire response to be exactly
the string `ALLOW` (no surrounding text, no markdown); anything else is treated as `BLOCK`.
This makes structural prompt injection to force an `ALLOW` verdict extremely difficult.

However, a sufficiently capable adversary may still use semantic jailbreaking techniques to
convince the judge model to emit a bare `ALLOW` response. This is a fundamental limitation of
LLM-based detection and not specific to Aegir. The pattern-based first pass (sanitizer) provides
a separate, non-LLM defence line; both must be bypassed for an attack to succeed.

**Mitigation:** Use a capable, instruction-following judge model (`llama3.1`, `mistral-nemo` or
similar). Consider running Aegir with `response_policy: block` for high-security deployments,
which blocks any request the pattern layer flags regardless of the judge verdict.

### Detection Coverage Ceiling

Pattern-based detection has a **hard ceiling of approximately 62% MITRE ATLAS coverage** at the
transport layer. The judge (LLM second-pass) exists to surpass this ceiling for SUSPICIOUS
payloads, but is not a guarantee. Novel and highly obfuscated attacks may pass undetected.
The current ATLAS technique coverage is documented in `ISA.md` (Features → detection-coverage).

### Anonymous Session Rate-Limiter (IP Spoofing)

Unauthenticated requests fall back to a rate-limit session key of `anonymous_<client_IP>`. In
deployments behind a reverse proxy or load balancer, `c.ClientIP()` follows `X-Forwarded-For`,
which can be spoofed by a client to obtain different rate-limit buckets and bypass per-IP limits.

**Mitigation:** Configure your reverse proxy to strip client-supplied `X-Forwarded-For` headers
and inject the real IP only. Alternatively, require authentication (JWT/API key) for all MCP
sessions so the rate limiter operates on an authenticated identity, not an IP.

**Fix planned:** v0.x — rate-limit key hashing + `trusted_proxies` configuration.

### DNS Rebinding Bypass (Open — BUG-2)

Aegir validates resource URIs and tool-argument URLs at URL parse time. DNS resolves at TCP
connection time. An attacker-controlled hostname (`attacker.example.com`) may pass parse-time
validation, then resolve to an internal IP address (`192.168.1.1`) at connection time, bypassing
all blocklist enforcement.

This is a known open gap. Parse-time SSRF detection (SSRF.001–004, AWS IMDS URL blocking,
`validateResourceURI`) is **not protection against DNS rebinding**.

**Mitigation:** Deploy a network-level egress filter (firewall, no-route to RFC1918 from the
proxy host) that blocks internal IP connections independently of the application layer. DNS
rebinding cannot be fully mitigated at the application level without connection-time IP
re-validation, which is planned.

**Fix planned:** Custom `DialContext` on the upstream HTTP transport to re-validate the
resolved IP at connection time (ISC-1).

### SSRF Dual-Implementation

Server-Side Request Forgery detection has two independent implementations:
- IOC regex patterns in `internal/sanitizer/ioc_patterns.go` (SSRF.001–004, SSRF.AWS.IMDS)
- Structural URI validation in `internal/server/mcp_proxy.go` (`validateResourceURI`, `isSSRFTarget`)

These are not identical in coverage. Future changes that update one but not the other risk
introducing coverage gaps.

**Mitigation:** Run Aegir behind a network-level egress filter that enforces the same URI
restrictions independently of the application layer.

**Fix planned:** Consolidate to a single structural validation path in v0.x.

### Indirect Prompt Injection via Tool Results (Open — ISC-22)

Content returned by upstream tool calls — fetched documents, database responses, API replies —
flows back to the MCP client as tool result data. If that content contains injected directives
(e.g. "Ignore previous instructions and..."), those directives reach the model's context
without inspection.

Aegir currently inspects inbound requests. Tool result content (the response path from upstream
back to the model) is sanitized for PII/PHI/PCI and secrets, but is not yet scanned by the
full prompt-injection detection suite before forwarding.

**Mitigation:** Treat all upstream tool sources as untrusted data sources. Restrict tool scope
to read-only where possible. Monitor the audit log for high-frequency SUSPICIOUS flags on
the same session as a potential indicator of indirect injection attempts.

**Fix in progress:** Tool-result scanning will apply the full detection suite to upstream
content before it reaches the model context (ISC-22, M008/M009 scope).

### SSE Transport (Server-Sent Events)

The HTTP SSE transport endpoint is implemented for MCP protocol compliance but does not add
TLS-level origin validation on the SSE stream beyond the standard HTTP CORS/Origin middleware.
Prefer WebSocket (which enforces `AllowedOrigins`) or authenticated REST for sensitive
deployments until ISC-32 (SSE TLS protection) is addressed.

### WebSocket Origin Validation Default

When `security.allowed_origins` is not configured (empty list), the WebSocket `CheckOrigin`
handler permits all cross-origin connections, including from browser pages. This is
backward-compatible but is fail-open from a security perspective.

**Mitigation:** Set `security.allowed_origins` in `aegir.yaml` to the list of origins that
should be permitted to open WebSocket connections:

```yaml
security:
  allowed_origins:
    - "https://your-mcp-client.example.com"
```

Note: non-browser clients (no `Origin` header) always bypass this check by design, as they
cannot perform cross-site WebSocket hijacking. The allowlist only constrains browser clients.

### JWT Secret and Audit-Log HMAC Key — Development and Pod Restarts

The auto-generated dev secrets (`CHANGE_ME_IN_PRODUCTION_*`) are stable within a single
process run but rotate on every process restart (pod restart, crash-loop, rolling deploy).

This means:
- Previously issued JWTs are invalid after a restart (no persistent session state in dev anyway)
- Audit log HMAC chain breaks across restarts — log entries before and after a restart cannot
  be verified with a common key

The startup guard (`secret_guard.go`) refuses to start with the default JWT secret **and**
the default HMAC key unless `AEGIR_ALLOW_INSECURE_JWT_SECRET=true` is set.

**Production deployments must set both:**

```bash
export JWT_SECRET="<strong-random-secret>"
export LOG_HMAC_KEY="<strong-random-key>"
```

Or via `aegir.yaml`:
```yaml
auth:
  jwt:
    secret: "${JWT_SECRET}"
logging:
  hmac_key: "${LOG_HMAC_KEY}"
```

---

## Security Architecture Summary

- **Fail-closed by default**: all error paths block; ALLOW is the explicitly computed outcome
- **Zero client trust on judge output**: judge verdict reason never reaches the client by default
  (`judge.expose_reasoning: false`); enabling it logs a startup warning that it violates GDPR/HIPAA/PCI
- **Audit trail**: all blocked requests are logged with HMAC-integrity signatures
- **TLS 1.3 enforced**: minimum TLS version in `createTLSConfig`; `just demo` disables TLS
  deliberately for local testing only
- **MITRE ATLAS mapping**: all detections carry ATLAS technique IDs in audit log events
- **WebAuthn/FIDO2 MFA**: available as a second factor for the admin dashboard

---

*Aegir is open-source research software. Use it in production with appropriate compensating
controls and a security review of your deployment topology.*
