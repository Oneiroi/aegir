# Aegir M004 Handoff — 2026-05-13

## State: COMPLETE (33/34 ISCs)

Working tree is clean. All changes committed. Branch: `main`, HEAD: `2c2f056`.

---

## What was done this session

### Commits (newest first)

| SHA | Summary |
|-----|---------|
| `2c2f056` | ISA verification pass — 33/34 ISCs |
| `8e859a7` | ISC-14/ISC-26/ISC-34 — test cleanup, metrics anomaly_scores, untrack certs |
| `d648215` | M004 stabilisation — anomaly detection, session WebSocket, test fixes |
| `40f8903` | M004 alpha stabilisation baseline (prior session) |

### Changes delivered

1. **`internal/anomaly/`** (new package)
   - `detector.go`: `Detector` interface + `HeuristicDetector` (Shannon entropy baseline 4.5 bits + non-ASCII ratio, combined score [0,1])
   - `detector_test.go`: 5 tests, all green

2. **`internal/server/mcp_proxy.go`**
   - `anomalyDetector anomaly.Detector` field wired into `HandleMCPRequest` — logs score per request via HMAC-protected logger
   - Atomic `anomalyCount` / `anomalyScoreSum` counters + `GetAnomalyStats()` method
   - Session analyzer wired into `HandleWebSocket` — blocks hostile sessions mid-stream
   - Upstream fallback fixed: `processMCPMethod` called for ALL methods (was only `initialize`)

3. **`internal/server/mcp_proxy_test.go`**
   - `createTestMCPProxy` now accepts `testing.TB`, registers `t.Cleanup(analyzer.Stop)`
   - `TestTransportEndpointsCoexistence` GET /mcp/sse hang fixed (300ms context timeout)
   - All `NewMCPProxy` call sites updated with nil 6th arg (anomaly detector)

4. **`internal/server/server.go`**
   - Anomaly detector conditionally created (`cfg.Security.AnomalyDetection.Enabled`)
   - `GET /api/security/metrics` includes `anomaly_scores: {total_scored, average_score}`

5. **`internal/session/analyzer.go`**
   - `done chan struct{}` + `Stop()` method for clean goroutine shutdown
   - Defensive defaults in constructor for zero-value config fields

6. **`internal/config/config.go`**
   - `AnomalyDetection` struct added to `Security`
   - Default: `security.anomaly_detection.enabled = false` (opt-in)

7. **`internal/sanitizer/manager.go`**
   - `collapseSpacingVariant()` — normalises "i g n o r e" letter-spacing attacks
   - `memory_manipulation` regex expanded to cover "you can", "anything", etc.

8. **`cmd/server/main_test.go`**
   - `TestGracefulShutdown` passes `MCP_SERVER_TLS_ENABLED=false` to subprocess (TLS default is on, certs don't exist in dev)

9. **`.gitignore`** — added `certs/cert.pem`, `certs/key.pem`; removed both from git tracking

---

## ISC-9 partial (the one open item)

`internal/sanitizer` has **8 pre-existing test failures** (was 10 at session start; fixed 2):

- `TestGDPRCompliancePayloads`, `TestHIPAACompliancePayloads`, `TestPCIDSSCompliancePayloads`
- `TestKnownAttackPayloads`, `TestRealWorldCVEPayloads`, `TestSecretDetection`
- `TestSQLInjectionDetection`, `TestPromptInjectionDetection` (base64, unicode, function subtests)

These test LDAP injection, Apache Velocity template injection, path traversal, SSRF, null-byte injection — none are regressions from this session. Out of scope for M004 but candidates for M005.

---

## Test status

```
ok   cmd/server             (all 5 tests pass incl. TestGracefulShutdown)
ok   internal/anomaly       (5 tests)
FAIL internal/sanitizer     (8 pre-existing failures, see above)
ok   internal/server        (all tests, -race clean)
ok   internal/session       (all tests)
make build                  ✓  bin/aegir
```

---

## Key config knobs

| Env var | Default | Purpose |
|---------|---------|---------|
| `MCP_SERVER_TLS_ENABLED` | `true` | Set to `false` for local dev (no certs) |
| `MCP_SESSION_ANALYSIS_ENABLED` | `true` | Multi-turn threat detection |
| `MCP_SECURITY_ANOMALY_DETECTION_ENABLED` | `false` | Shannon entropy scorer (opt-in) |

Default credentials: `admin / admin123` (JWT via `POST /auth/login`)

---

## What's next (M005 candidates)

- Fix remaining 8 sanitizer test failures (LDAP, template, path-traversal, SSRF detection)
- Add anomaly score threshold for auto-blocking (currently only logged)
- WebSocket session analyzer: extend to SSE transport
- Dashboard: real-browser E2E test (Interceptor not installed in this env)
- Rate limiter + anomaly detector integration (block on combined signal)
