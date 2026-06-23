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

### SSRF Dual-Implementation

Server-Side Request Forgery detection has two independent implementations:
- IOC regex patterns in `internal/sanitizer/ioc_patterns.go` (SSRF.001–004, SSRF.AWS.IMDS)
- Structural URI validation in `internal/server/mcp_proxy.go` (`validateResourceURI`, `isSSRFTarget`)

These are not identical in coverage. Future changes that update one but not the other risk
introducing coverage gaps. DNS rebinding is explicitly not covered.

**Mitigation:** Run Aegir behind a network-level egress filter that enforces the same URI
restrictions independently of the application layer.

**Fix planned:** Consolidate to a single structural validation path in v0.x.

### SSE Transport (Server-Sent Events)

The HTTP SSE transport endpoint is implemented for MCP protocol compliance but does not add
TLS-level origin validation on the SSE stream beyond the standard HTTP CORS/Origin middleware.
Prefer WebSocket (which enforces `AllowedOrigins`) or authenticated REST for sensitive
deployments until ISC-32 (SSE TLS protection) is addressed.

### JWT Secret — Development Deployments

The auto-generated dev secret (`CHANGE_ME_IN_PRODUCTION_*`) changes between processes but is
stable within a single process run. Restarting Aegir without setting `JWT_SECRET` invalidates
all previously issued JWTs and breaks audit chain continuity. This is by design for development;
**production deployments must set `JWT_SECRET` to a persistent, operator-managed value.**

The startup guard (`secret_guard.go`) refuses to start with the default secret unless
`AEGIR_ALLOW_INSECURE_JWT_SECRET=true` is set.

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
