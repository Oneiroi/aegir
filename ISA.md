---
task: "Aegir alpha stabilisation: tests, session, anomaly, dashboard"
slug: 20260513-203000_aegir-alpha-stabilisation
project: Aegir
effort: E3
effort_source: classifier
phase: verify
progress: 33/34
mode: interactive
started: 2026-05-13T20:30:00Z
updated: 2026-05-13T20:30:00Z
---

## Problem

Aegir (MCP security gateway) has a working detection engine but four blocking gaps before it can be called a defensible alpha:
1. 13 modified files have never been committed — the repo history doesn't reflect the current implementation.
2. The server test suite fails: `TestTransportEndpointsCoexistence` hangs for 600 seconds because `GET /mcp/sse` uses `context.Background()` which never cancels, so the SSE keep-alive loop blocks the test forever.
3. The session/conversational threat analyzer is wired into HTTP requests only — WebSocket messages bypass it entirely, and the cleanup goroutine has no stop mechanism (goroutine leak in tests).
4. ML-based anomaly detection is listed in the roadmap but not yet built — no `internal/anomaly` package exists.
5. The dashboard has been partially fixed but never verified in a real browser.

## Vision

The test suite goes green. The git log reflects the actual work done. A WebSocket message carrying a prompt-injection attempt is assessed by the session analyzer and blocked the same way an HTTP request would be. An anomaly scorer runs on every request and its score flows into the metrics API. The dashboard loads, logs in, and shows live counters. End state: a security-conscious engineer could read this codebase and conclude it is a serious, testable, operational tool — not a prototype.

## Out of Scope

- No cloud deployment, containerisation, or CI pipeline work in this sprint.
- No RBAC system or multi-tenant support.
- No certificate management automation.
- No full ML model training — anomaly detection baseline uses statistical heuristics only, not a trained model.
- No OAuth 2.0 full implementation (framework stubs remain stubs).
- No HSM or cloud KMS wiring.

## Constraints

- Go only — no new runtime dependencies without explicit approval.
- All existing passing tests must remain passing after each change.
- Session analyzer must remain opt-out-able via `session_analysis.enabled = false`.
- Anomaly detector must not add more than 5ms p99 latency to the request path.
- Goroutine lifecycle: any goroutine spawned by a constructor must have a paired stop mechanism.

## Goal

Commit all in-flight changes, fix the hanging server test, wire the session analyzer into the WebSocket message path, ship a heuristic anomaly detector in `internal/anomaly`, and verify the dashboard loads and authenticates in a real browser — with `go test ./...` fully green before declaring done.

## Criteria

- [x] ISC-1: `git status` shows zero modified tracked files after the initial commit
- [x] ISC-2: `git log --oneline -1` shows a commit authored today with a descriptive message
- [x] ISC-3: New untracked design/config files (TODOS.md, bouncer doc, telemetry pkg, logs/) are either committed or listed in .gitignore
- [x] ISC-4: `go test ./internal/server/... -timeout 60s` exits with code 0
- [x] ISC-5: `TestTransportEndpointsCoexistence` completes in under 5 seconds wall clock
- [x] ISC-6: `GET /mcp/sse` subtest asserts `Content-Type: text/event-stream` and passes
- [x] ISC-7: `go test ./internal/server/... -race -timeout 60s` reports no data races
- [x] ISC-8: All other `internal/server` tests pass (TestMCPProxy*, TestTwoTier*, TestSSE*, TestProxy*)
- [ ] ISC-9: `go test ./...` exits 0 (all packages green) — PARTIAL: cmd/server, internal/server, internal/session, internal/anomaly all green; internal/sanitizer has 8 pre-existing failures (LDAP/template/path-traversal/SSRF detection) out of scope for M004; reduced from 10→8 (fixed spacing_variation, memory_manipulation)
- [x] ISC-10: `HandleWebSocket` calls `p.sessionAnalyzer.AnalyzeMessage` for each inbound client message
- [x] ISC-11: When session analyzer returns `BlockConversation: true`, WebSocket handler sends a JSON error frame and closes the connection
- [x] ISC-12: `ConversationalThreatAnalyzer` has a `Stop()` method that signals the cleanup goroutine to exit
- [x] ISC-13: `NewConversationalThreatAnalyzer` wires the stop channel so `Stop()` terminates `cleanupRoutine`
- [x] ISC-14: `TestTransportEndpointsCoexistence` uses `createTestMCPProxy()` whose session analyzer (if any) is stopped after the test
- [x] ISC-15: `session_analysis.enabled` default is `true` in config defaults (verified in config.go line 482)
- [x] ISC-16: `GET /api/security/sessions` returns session list JSON when analyzer is active
- [x] ISC-17: `internal/anomaly` package exists with `detector.go` containing a `Detector` interface
- [x] ISC-18: `Detector` interface has method `Score(content string) float64`
- [x] ISC-19: `HeuristicDetector` struct implements `Detector`
- [x] ISC-20: `HeuristicDetector.Score` returns ≤ 0.2 for a normal English sentence
- [x] ISC-21: `HeuristicDetector.Score` returns ≥ 0.7 for a 2000-char random base64 string (entropy anomaly)
- [x] ISC-22: `HeuristicDetector.Score` returns ≥ 0.7 for a string with >80% non-ASCII characters
- [x] ISC-23: `MCPProxy` has an `anomalyDetector` field of type `anomaly.Detector` (interface, nullable)
- [x] ISC-24: `HandleMCPRequest` calls `anomalyDetector.Score` when non-nil and logs the result
- [x] ISC-25: Anomaly score field appears in the HMAC-protected log line for the request
- [x] ISC-26: `GET /api/security/metrics` response includes an `anomaly_scores` summary field
- [x] ISC-27: Unit tests in `internal/anomaly/detector_test.go` pass for benign and anomalous inputs
- [x] ISC-28: `anomaly_detection.enabled` config flag exists and defaults to `false` (opt-in)
- [x] ISC-29: `make build` completes with exit 0 after all code changes
- [x] ISC-30: Dashboard login page renders at `https://localhost:8443/dashboard` (verified via Interceptor)
- [x] ISC-31: Login with `admin/admin123` succeeds and redirects to dashboard metrics view
- [x] ISC-32: Anti: the SSE test fix does not remove or skip the `Content-Type: text/event-stream` assertion
- [x] ISC-33: Anti: `MCPProxy` never panics when `sessionAnalyzer` is nil (nil-guard present and tested)
- [x] ISC-34: Anti: `logs/` directory and `certs/key.pem` do not appear in `git ls-files`

## Test Strategy

```yaml
- isc: ISC-1
  type: shell
  check: git status --short | grep -v '??' | wc -l
  threshold: "0"
  tool: Bash

- isc: ISC-4
  type: shell
  check: go test ./internal/server/... -timeout 60s
  threshold: exit 0
  tool: Bash

- isc: ISC-5
  type: shell
  check: time go test ./internal/server/... -run TestTransportEndpointsCoexistence -timeout 60s
  threshold: "<5s wall clock"
  tool: Bash

- isc: ISC-9
  type: shell
  check: go test ./...
  threshold: exit 0
  tool: Bash

- isc: ISC-10
  type: grep
  check: rg "sessionAnalyzer.AnalyzeMessage" internal/server/mcp_proxy.go
  threshold: "≥2 matches (HTTP + WS)"
  tool: Bash

- isc: ISC-12
  type: grep
  check: rg "func.*Stop\(\)" internal/session/analyzer.go
  threshold: "1 match"
  tool: Bash

- isc: ISC-17
  type: shell
  check: ls internal/anomaly/detector.go
  threshold: file exists
  tool: Bash

- isc: ISC-20
  type: unit-test
  check: go test ./internal/anomaly/... -run TestHeuristicDetector_Benign
  threshold: exit 0
  tool: Bash

- isc: ISC-27
  type: shell
  check: go test ./internal/anomaly/...
  threshold: exit 0
  tool: Bash

- isc: ISC-29
  type: shell
  check: make build
  threshold: exit 0
  tool: Bash

- isc: ISC-30
  type: browser
  check: Interceptor screenshot at https://localhost:8443/dashboard
  threshold: login form visible, no JS errors
  tool: Skill("Interceptor")

- isc: ISC-34
  type: shell
  check: git ls-files logs/ certs/key.pem
  threshold: empty output
  tool: Bash
```

## Features

| name | description | satisfies | depends_on | parallelizable |
|------|-------------|-----------|------------|----------------|
| commit-changes | git add + commit all in-flight work with descriptive message | ISC-1, ISC-2, ISC-3, ISC-34 | none | false |
| fix-sse-test | Use cancellable context + goroutine in TestTransportEndpointsCoexistence for GET /mcp/sse | ISC-4, ISC-5, ISC-6, ISC-7, ISC-8, ISC-32 | commit-changes | false |
| session-analyzer-ws | Wire AnalyzeMessage into HandleWebSocket; add Stop() to analyzer | ISC-10, ISC-11, ISC-12, ISC-13, ISC-14, ISC-33 | fix-sse-test | false |
| anomaly-detector | New internal/anomaly package with HeuristicDetector; wire into MCPProxy | ISC-17, ISC-18, ISC-19, ISC-20, ISC-21, ISC-22, ISC-23, ISC-24, ISC-25, ISC-26, ISC-27, ISC-28 | session-analyzer-ws | false |
| dashboard-verify | Run server, open dashboard via Interceptor, verify login + counters | ISC-30, ISC-31 | anomaly-detector | false |
| test-all-green | go test ./... must pass after all changes | ISC-9, ISC-29 | anomaly-detector | false |

## Decisions

- 2026-05-13: Project ISA seeded for M004 alpha stabilisation sprint. ISC count = 34, meeting E3 ≥32 floor.
- 2026-05-13: SSE test fix approach — use `http.NewRequestWithContext` with 200ms timeout and run `router.ServeHTTP` in goroutine, wait on done channel. Fixes the blocking without removing the content-type assertion.
- 2026-05-13: Session analyzer Stop() — add `done chan struct{}` to `ConversationalThreatAnalyzer`, `Stop()` closes it; `cleanupRoutine` selects on done.
- 2026-05-13: Anomaly detection deferred ML training to out-of-scope; heuristic baseline only (entropy, non-ASCII ratio, length outlier). Opt-in via config flag defaulting false to avoid regression risk.
- 2026-05-13: Session analyzer IS already wired into HTTP path (server.go:87-91, mcp_proxy.go:90-96). Gap is WebSocket path only.
