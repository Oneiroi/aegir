# MCP 2026-07-28 Specification — Security Gap Analysis (Aegir)

> **What this is.** A forward-looking gap analysis of Aegir against the threat vectors
> introduced by the **MCP 2026-07-28** specification (release candidate 21 May 2026; final
> release scheduled 28 July 2026). It is *not* a historical code-rot audit like
> `MITRE-ATLAS-GAP-ANALYSIS.md` — it measures Aegir against protocol surfaces that did not
> exist when the gateway was built.

> Generated: 2026-07-13
> Version: 1.0
> HEAD at audit: `4193fc7` (branch `public`, ISA 165/167)
> Source: Akamai Security Research, *"The New MCP Specification: What Security Teams Must
> Prepare For"* + first-hand Aegir code audit (this session)
> Codebase: `public` branch

---

## 1. Scope and headline

The 2026-07-28 spec is an architectural shift, not a point release. It moves MCP from
stateful to stateless multi-round-trip, removes protocol-managed sessions
(`Mcp-Session-Id`), introduces standardized HTTP headers (`Mcp-Method`, `Mcp-Name`), a
universal `_meta` object, first-class MCP Apps (HTML/JS panels), asynchronous long-running
tasks, and mandatory OAuth 2.1 + PKCE.

**Aegir has zero code awareness of these surfaces.** A grep of the Go tree for `_meta`,
`Mcp-Method`, `Mcp-Name`, `x-mcp-header`, `Mcp-Session-Id`, elicitation, and async/task
returns nothing outside unrelated identifiers. Of the six attack vectors the article
raises, **three are entirely unhandled and three are partially covered** by existing
infrastructure that would need extending. None are fully covered.

| # | Vector | Spec surface | Coverage | Severity | Required change |
|---|--------|--------------|----------|----------|-----------------|
| 1 | Cross-agent workflow hijacking | Stateless resumable state / async task IDs | **NOT COVERED** | Critical | Cryptographically verify client-supplied state + task IDs |
| 2 | `_meta` metadata manipulation | Universal `_meta` object | **NOT COVERED** | High | Inspect/allowlist `params._meta`; never route/authz on it |
| 3 | Protocol confusion (desync) | `Mcp-Method` / `Mcp-Name` headers | **NOT COVERED** | High | Assert header/body method+name consistency |
| 4 | Data leakage via `x-mcp-header` | `x-mcp-header` directive | **PARTIAL** | Medium | Extend secret/PII scanning to headers |
| 5 | Stored XSS in MCP Apps | MCP Apps (HTML/JS panels) | **PARTIAL** | High | Broaden active-content stripping on tool output |
| 6 | DoS via long-running tasks | Asynchronous tasks | **PARTIAL** | Medium | Async task quotas, concurrency caps, disconnect-cancel |

---

## 2. Detailed findings

### V1 — Cross-Agent Workflow Hijacking — **NOT COVERED (Critical)**

**Attack.** With protocol-managed sessions gone, the stateless model requires clients to
hand back state objects and tracking IDs that the server trusts to resume a workflow.
Predictable IDs or tamperable, unsigned state let an attacker hijack another user's
workflow or trigger cross-tenant actions.

**Aegir today.** The only adjacent control is `protocolguard.ReplayCache`, which is keyed on
`sessionID` (`internal/protocolguard/protocolguard.go:97,113`) — the exact identifier the
new spec removes. There is no cryptographic binding of resumable state to an identity, and
no async task model at all.

**Gap.** No verification of client-asserted state; the primary anti-hijacking anchor
(session ID) disappears under the new spec.

**Required change.** Sign or HMAC any state/task ID the gateway issues; reject client-supplied
state that fails verification; enforce per-tenant isolation on resume. This is net-new work
gated on modelling the async task lifecycle (see V6).

---

### V2 — Client-Controlled Metadata Manipulation — **NOT COVERED (High)**

**Attack.** Inject malicious key-value pairs into the `_meta` object (e.g.
`{"tenant": "admin"}`) to escalate privilege or reach cross-tenant data.

**Aegir today.** `protocolguard.Validate` rejects unknown *top-level* JSON-RPC fields
(`validTopLevelFields`, `internal/protocolguard/protocolguard.go:12`) and enforces
`jsonrpc:"2.0"`. But `_meta` lives inside `params`, which the gateway forwards unmodified.
An injected `params._meta` passes straight through to the upstream.

**Gap.** No inspection of `params._meta`; client metadata is trusted by omission.

**Required change.** A params-level `_meta` inspector: strip or key-allowlist `_meta`, and
guarantee no `_meta` value can influence Aegir's routing or authorization decisions. Small,
self-contained, lands next to `protocolguard`.

---

### V3 — Protocol Confusion (Desync) Attacks — **NOT COVERED (High)**

**Attack.** Send conflicting values between the new HTTP headers (`Mcp-Method`, `Mcp-Name`)
and the JSON-RPC body, exploiting the disagreement to bypass a control that inspects one
but enforces on the other.

**Aegir today.** `protocolguard.Validate` operates purely on the JSON-RPC body
(`internal/protocolguard/protocolguard.go:52`) and never reads the new headers.

**Gap.** No cross-layer consistency check; a header/body method mismatch is invisible.

**Required change.** In the same validation pass, parse `Mcp-Method`/`Mcp-Name` and assert
equality with the body's `method` and tool name; reject on mismatch (`-32600`). Smallest,
highest-confidence fix in this set.

---

### V4 — Data Leakage via `x-mcp-header` — **PARTIAL (Medium)**

**Attack.** Developers map sensitive inputs (API keys, tokens, PII) into HTTP headers via
`x-mcp-header`, exposing them to every proxy, load balancer, and log along the path.

**Aegir today.** Response **body** scanning for secrets/PII and SSRF egress exists
(ISC-114/117/156), but there is **no header inspection** in the proxy or upstream path —
confirmed: no `resp.Header`/`.Header().Get` reads in `internal/server` or `internal/upstream`.

**Gap.** Header channel is unmonitored; existing detectors only see bodies.

**Required change.** Point the existing secret/PII/egress detectors at request and response
**headers**, with a specific rule flagging `x-mcp-header` credential mappings. Detection
logic is reusable; the work is wiring it to a new input surface.

---

### V5 — Stored XSS in MCP Apps — **PARTIAL (High)**

**Attack.** Store malicious HTML/JS via a tool; when rendered in an MCP App panel (even a
sandboxed iframe) it runs — phishing, deceptive content, theft of visible user data.

**Aegir today.** `scanToolResultForInjection` runs `SanitizeContent` over tool-result text,
which includes `sanitizeXSS` stripping `<script>...</script>` and `javascript:`
(`internal/sanitizer/manager.go:364-370`). So basic active content in tool output is caught.

**Gap.** The XSS pattern set is thin (no `onerror`/`onload`/`svg`/`data:` URI/encoded
variants), regex stripping is bypassable, and MCP Apps are a new first-class content type
Aegir does not model distinctly. True mitigation (context-aware output encoding) belongs at
the App renderer, downstream of the proxy.

**Required change.** Broaden the active-content filter (event handlers, `svg`, `data:`,
encoded payloads), and treat MCP App payloads as their own scanned content class. Accept
that a proxy can harden but not fully own renderer-side encoding.

---

### V6 — Denial-of-Service via Long-Running Background Tasks — **PARTIAL (Medium)**

**Attack.** A cheap request spawns an expensive async task; the client disconnects
immediately, leaving the server to grind through CPU/memory/DB-heavy work with no consumer.

**Aegir today.** `internal/server/ratelimit.go` is a per-client token bucket
(`golang.org/x/time/rate`) counting request *arrivals*. It has no concept of task cost, no
quota on concurrent async work, and no cancellation on client disconnect. The async task
type is unhandled entirely.

**Gap.** Rate limiting models request frequency, not asynchronous work-in-flight; nothing
reclaims resources after a client vanishes.

**Required change.** Per-identity async task quotas + concurrency caps, cost accounting
(not just request count), and disconnect-triggered server-side cancellation.

---

## 3. Spec-transition notes (maintenance, not new defenses)

- **Session hijacking is "mitigated" by the spec removing `Mcp-Session-Id`.** The
  side effect: Aegir's `ReplayCache` is session-keyed and loses its anchor. It must be
  reworked around per-connection identity or a cryptographic nonce, or it silently stops
  providing replay protection. Tracked jointly with V1.
- **OAuth 2.1 + PKCE is now mandatory.** Aegir already ships OAuth2/OIDC
  (`auth/manager.go`, per `SCOPE.md`). Action: verify PKCE is *enforced*, not optional, and
  confirm OAuth 2.1 conformance.

---

## 4. Recommended milestone — M015: MCP 2026-07-28 spec hardening

A single coherent milestone. Suggested sequencing, cheapest-and-highest-confidence first:

| Order | Vector | Rationale | Rough LoW |
|-------|--------|-----------|-----------|
| 1 | V3 desync check | Smallest, lands beside `protocolguard`, high confidence | S |
| 2 | V2 `_meta` inspector | Contained, high-value privilege-escalation block | S–M |
| 3 | V4 header secret scan | Reuses existing detectors on a new surface | S–M |
| 4 | V6 async task quotas | Net-new but bounded; needs task lifecycle model | M |
| 5 | V5 active-content hardening | Broaden filters; partial by architecture | M |
| 6 | V1 state verification | Largest; depends on V6's task model + crypto binding | L |

---

## 5. How this was verified

Every "Aegir today" claim above traces to code read on 2026-07-13 at HEAD `4193fc7`:
`internal/protocolguard/protocolguard.go`, `internal/server/ratelimit.go`,
`internal/server/mcp_proxy.go` (`scanToolResultForInjection`), `internal/sanitizer/manager.go`
(`sanitizeXSS`). Absence claims (`_meta`, MCP headers, response-header scanning, async tasks)
were confirmed by full-tree grep returning no matches outside unrelated identifiers.
