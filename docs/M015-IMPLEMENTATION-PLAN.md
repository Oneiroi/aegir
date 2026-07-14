# M015 — MCP 2026-07-28 Spec Hardening — Implementation Plan

> Planning artifact produced under the ISA workflow (FablePlan, Fable tier, 2026-07-13).
> Source gap analysis: `docs/MCP-2026-07-28-SPEC-GAP-ANALYSIS.md`.
> **Status: proposed — not yet reconciled into `ISA.md`, not yet built.** All ISCs are open.
> Proposed ISC IDs start at ISC-166 (current master max is ISC-165); IDs are final only
> after a Reconcile pass into `ISA.md`.

## Literal request (Fable-tier anti-reframe check)

The six vectors below are restated verbatim from the gap analysis, in the article's terms,
so the plan is measured against the actual ask and not a substituted one:

1. **V1** Cross-agent workflow hijacking — unverified client state / predictable task IDs.
2. **V2** Client-controlled `_meta` metadata manipulation.
3. **V3** Protocol confusion (desync) between `Mcp-Method`/`Mcp-Name` headers and JSON-RPC body.
4. **V4** Data leakage via the `x-mcp-header` directive.
5. **V5** Stored XSS in MCP Apps.
6. **V6** Denial-of-service via long-running background tasks.

Plus two spec-transition items that are not attacks but break existing controls: session-ID
removal (invalidates the replay cache anchor) and mandatory OAuth 2.1 + PKCE.

## Decisions

- **refined:** "Implementation plan" was interpreted as ISA/ISC milestone work (the project's
  native planning primitive), **not** frontier-systems-planning's kill-memo pipeline. These
  gaps are already decided as in-scope; the open question is *how*, not *whether*. Recorded
  here so the substitution is visible and reversible.
- **decision:** M015 is scoped strictly to the six article vectors + two transition items. No
  additional "while we're here" hardening is included; anything discovered mid-build is a new
  Decisions candidate, not silent scope growth.
- **decision:** Sequencing is cheapest-and-highest-confidence first (V3 → V2 → V4 → V6 → V5 →
  V1), so the two contained wins land before the async-task model work that V1 and V6 depend on.
- **open question (for David):** does Aegir commit to targeting the 2026-07-28 spec as a
  supported protocol version, or treat this as defensive future-proofing while still fronting
  older servers? This changes whether V1/V6 are must-ship or staged. Not assumed here.

---

## Features and ISCs

Owner-tier suggestions follow the project model-tiering table (Security/threat = Opus,
feature impl = Sonnet, boilerplate = Haiku). Every ISC names a concrete Go probe.

### V3 — Header/body desync guard — `m015-desync-guard`
Smallest, highest-confidence; lands beside `protocolguard.Validate`.

- [ ] **ISC-166:** When `Mcp-Method` and/or `Mcp-Name` HTTP headers are present, the gateway
  asserts they equal the JSON-RPC body `method` and tool name; any mismatch is rejected with
  a JSON-RPC `-32600` before forwarding. — probe: `TestHeaderBodyMethodMismatchRejected` /
  `TestHeaderBodyMatchAllowed` (`internal/protocolguard`). Touch-point:
  `internal/protocolguard/protocolguard.go:52` (extend `Validate` signature to take headers,
  or add `ValidateWithHeaders`).
- Owner: Sonnet. Depends: none. Parallelizable: yes.

### V2 — `_meta` inspector — `m015-meta-inspector`
Contained privilege-escalation block; `_meta` sits in `params`, below the current top-level guard.

- [ ] **ISC-167:** Inbound `params._meta` is key-allowlisted (unknown keys stripped or the
  request rejected, config-selectable); the raw client `_meta` is never forwarded unmodified.
  — probe: `TestMetaUnknownKeysStripped`. Touch-point: new inspector called from the request
  path in `internal/server/mcp_proxy.go`.
- [ ] **ISC-168:** No value inside client-supplied `_meta` can influence Aegir's routing or
  authorization decision (e.g. `_meta.tenant` is ignored for authz). — probe:
  `TestMetaTenantCannotEscalate` (inject `{"tenant":"admin"}`, assert no privilege change).
- Owner: Opus (authz-adjacent). Depends: none. Parallelizable: yes.

### V4 — Header secret/PII scan — `m015-header-egress-scan`
Reuses existing body detectors on the header surface.

- [ ] **ISC-169:** The secret/PII/egress detectors run over request **and** response HTTP
  headers, not only bodies; a credential-shaped value in a header is flagged/blocked per the
  configured action. — probe: `TestSecretInResponseHeaderFlagged`. Touch-point: response path
  in `internal/server/mcp_proxy.go` + `internal/compliance/scanner.go` (currently body-only).
- [ ] **ISC-170:** A sensitive value mapped via an `x-mcp-header` directive is specifically
  detected and reported as credential-in-header leakage. — probe:
  `TestXMcpHeaderCredentialBlocked`.
- Owner: Sonnet. Depends: none. Parallelizable: yes.

### V6 — Async task quotas — `m015-async-task-quota`
Net-new; establishes the async task lifecycle model V1 also needs.

- [ ] **ISC-171:** Async/long-running tasks are tracked per authenticated identity with a
  configurable concurrency cap and quota; exceeding it is rejected before the task is spawned.
  — probe: `TestAsyncTaskQuotaEnforced`. Touch-point: new task registry; integrates with
  `internal/server/ratelimit.go` (extend from arrival-count to work-in-flight accounting).
- [ ] **ISC-172:** A long-running task is cancelled server-side when the initiating client
  disconnects, rather than running to completion unconsumed. — probe:
  `TestTaskCancelledOnClientDisconnect` (open task, drop connection, assert `context` cancelled).
- Owner: Opus (resource-exhaustion threat model) + Sonnet (impl). Depends: none, but shares
  the task registry with V1. Parallelizable: partially.

### V5 — Active-content hardening — `m015-app-content-hardening`
Broadens the existing `sanitizeXSS`; renderer-side encoding stays downstream.

- [ ] **ISC-173:** The tool-result active-content filter strips/flags event-handler
  attributes (`onerror`, `onload`, …), `svg`-embedded script, and `data:`/encoded script
  URIs, not only `<script>` and `javascript:`. — probe: `TestToolResultStripsEventHandlers`,
  `TestToolResultStripsDataURI`, `TestToolResultStripsSvgScript`. Touch-point:
  `internal/sanitizer/manager.go:364-370` (`sanitizeXSS` pattern set).
- [ ] **ISC-174:** MCP App payloads are handled as a distinct scanned content class (not
  conflated with plain tool-result text), so App-destined HTML gets the stricter filter. —
  probe: `TestMcpAppContentScannedStrict`.
- Owner: Sonnet. Depends: none. Parallelizable: yes.

### V1 — Client-state verification — `m015-state-verification`
Largest; depends on V6's task registry and adds cryptographic binding.

- [ ] **ISC-175:** Any resumable state or task ID the gateway issues is cryptographically
  signed (HMAC/keyed); client-supplied state that fails verification is rejected, not resumed.
  — probe: `TestUnsignedResumeStateRejected`, `TestTamperedTaskIdRejected`. Touch-point: new
  state-signing helper; consumed by the V6 task registry.
- [ ] **ISC-176:** Resuming a workflow enforces tenant/identity isolation — a state object
  issued to identity A cannot be resumed by identity B. — probe: `TestCrossTenantResumeDenied`.
- Owner: Opus. Depends: ISC-171 (task registry). Parallelizable: no (last).

### Spec-transition items — `m015-spec-transition`

- [ ] **ISC-177:** Replay protection functions without `Mcp-Session-Id` — the replay cache is
  re-anchored on per-connection identity or a cryptographic nonce, since the session header is
  removed by the spec. — probe: `TestReplayCacheWorksWithoutSessionId`. Touch-point:
  `internal/protocolguard/protocolguard.go:97,113` (`ReplayCache` keying).
- [ ] **ISC-178:** OAuth 2.1 + PKCE is enforced (not optional) on the auth path. — probe:
  `TestPKCEEnforced` (auth without PKCE is rejected). Touch-point: `auth/manager.go`.
- Owner: Opus. Depends: ISC-177 shares the replay-cache change with V1's anchor rework.

---

## Sequencing and effort

| Order | Feature | ISCs | Effort | Owner | Blocks |
|-------|---------|------|--------|-------|--------|
| 1 | m015-desync-guard | 166 | S | Sonnet | — |
| 2 | m015-meta-inspector | 167, 168 | S–M | Opus | — |
| 3 | m015-header-egress-scan | 169, 170 | S–M | Sonnet | — |
| 4 | m015-async-task-quota | 171, 172 | M | Opus+Sonnet | enables V1 |
| 5 | m015-app-content-hardening | 173, 174 | M | Sonnet | — |
| 6 | m015-state-verification | 175, 176 | L | Opus | needs 171 |
| — | m015-spec-transition | 177, 178 | M | Opus | 177 pairs with V1 anchor |

Orders 1–3 and 5 are mutually independent and parallelizable (disjoint files: `protocolguard`,
request-path `_meta`, compliance/header scan, `sanitizer/manager.go`). Order 4 must precede
Order 6. ISC-177's replay-cache rework should be coordinated with V1 so the session-ID anchor
is replaced once, not twice.

## Verification gate for M015 (per QB1)

Each ISC ships only when: its named probe fails without the change and passes with it;
`go build ./...` and `go test ./...` are green at committed HEAD; the diff carries no
hardcoded paths/credentials; and the fingerprint scan is clean for any model-generated code.
No ISC is "done" on a working-tree claim — done means committed with the probe re-run at the commit.
