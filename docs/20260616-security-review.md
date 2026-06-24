## Aegir MCP‑firewall – Security review (20260616-security-review.md)

| # | File:line | Category | PoC exploit (benign) | Severity | Fix |
|---

## Defensive responses

|---

## Defensive responses

---

## Defensive responses

---

## Defensive responses

--|---

## Defensive responses

---

## Defensive responses

---

## Defensive responses

-|---

## Defensive responses

---

## Defensive responses

---

## Defensive responses

---

## Defensive responses

---

## Defensive responses

---

## Defensive responses

---

## Defensive responses

-|---

## Defensive responses

---

## Defensive responses

---

## Defensive responses

-|---

## Defensive responses

--|
| **CRITICAL‑1** | `cmd/server/main.go:70` (TLS disabled flag) | Configuration‑validation bypass | ```bash
curl -sk -X POST http://localhost:8080/mcp -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"run_sql","params":{"query":"SELECT * FROM users WHERE name='' OR 1=1--"},"id":1}'
``` (server runs without TLS) | **Critical** – clear‑text traffic is sniffable and manipulable. | Enforce TLS in production (`cfg.Server.TLS.Enabled = true`); refuse start if disabled. |
| **HIGH‑2** | `internal/server/mcp_proxy.go:889` (POST handling) | Input‑validation / SQL‑injection | Same PoC as above. The proxy forwards the raw `query` field to downstream services without sanitization. | **High** – raw query could cause data leakage or destructive DDL. | Use parameterized queries; reject any DDL (`DROP`, `ALTER`, etc.) in downstream handlers. |
| **HIGH‑3** | `internal/auth/webauthn/handler.go:129` (LoginBegin) | Authentication‑spoofing | ```bash
curl -sk -X POST http://localhost:8080/auth/webauthn/login/begin -d '{}'
``` (missing `X-User-ID` header) – handler may continue if both header and `user_id` query param are absent. | **High** – unauthenticated access to WebAuthn flow. | Require both header and query param; verify against session store; reject if missing. |
| **MEDIUM‑4** | `internal/server/server.go:171` (Health endpoint) | Information‑disclosure | ```bash
curl -sk http://localhost:8080/health
``` returns `version` and `timestamp`. | **Medium** – helps fingerprinting attacks. | Strip version and timestamp; return only `"status":"healthy"`. |
| **MEDIUM‑5** | `internal/sanitizer/manager.go:424` (SQL‑injection pattern detection) | Incomplete sanitization – false negatives | ```bash
curl -sk -X POST http://localhost:8080/mcp -d '{"jsonrpc":"2.0","method":"run_sql","params":{"query":"DROP DATABASE; SELECT * FROM users;"},"id":1}'
``` may bypass regex detection. | **Medium** – destructive command execution. | Extend regex detection; whitelist allowed query commands; reject any DDL statements. |
| **LOW‑6** | `internal/sanitizer/ioc_patterns.go:43` (MongoDB operator smuggling) | NoSQL‑injection | ```bash
curl -sk -X POST http://localhost:8080/mcp -d '{"jsonrpc":"2.0","method":"run_mongo","params":{"query":{"$where":"this.password='test' || true"}},"id":1}'
``` smuggles `$where` operator. | **Low** – limited effect if downstream DB validates. | Reject `$where`, `$regex` operators; enforce strict schema validation. |
| **INFO‑7** | `internal/dashboard/web.go:272` (POST endpoint) | CSRF exposure (no token) | ```bash
curl -sk -X POST http://localhost:8080/dashboard/reset
``` processes request from any origin. | **Informational** – can be mitigated with token. | Require CSRF token header for POST actions. |

**Benign PoC payload (SQL‑injection demonstration):**
```json
{
  "jsonrpc":"2.0",
  "method":"run_sql",
  "params":{"query":"SELECT * FROM users WHERE name='' OR 1=1--"},
  "id":1
}
```
Send via curl to the MCP Proxy POST endpoint (`/mcp`):
```bash
curl -sk -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"run_sql","params":{"query":"SELECT * FROM users WHERE name='' OR 1=1--"},"id":1}'
```
The request reaches downstream services unchanged, demonstrating the injection path. This is a harmless read‑only query (no DB writes).

**Recommended mitigations** are listed per finding in the table above. Prioritize fixing **CRITICAL‑1** (TLS enforcement) and **HIGH‑2** (SQL‑injection sanitization), then address authentication, information leakage, and CSRF.

---

## Defensive responses



## Reviewer response — verification pass (2026-06-16, Mimir/Claude)

Each finding was tested against the actual code at committed HEAD `362837e` plus the
uncommitted working tree. The cited line numbers do not match the code (e.g. `main.go:70` is a
`var cfg` declaration; `ioc_patterns.go:43` is a comment). Verdicts below cite real `file:line`.
Two findings hold up and are fixed; five do not. **Counter-arguments welcome — push back with
evidence and we'll reconcile.**

| # | Original severity | Verdict | Evidence |
|---

## Defensive responses

|---

## Defensive responses

|---

## Defensive responses

|---

## Defensive responses

|
| CRITICAL‑1 | Critical | **Accepted risk (not a defect)** | TLS is conditional at `cmd/server/main.go:194-201`; when disabled it logs `WARNING: Running without TLS`. `createTLSConfig` (`main.go:231-246`) already enforces `MinVersion: tls.VersionTLS13` + AEAD-only cipher suites — the AGENTS.md "TLS 1.3 minimum" constraint is met. The toggle is *intentional* for `just demo` and STDIO/SSE transports. The unrelated `run_sql` SQLi PoC does not demonstrate this finding. |
| HIGH‑2 | High | **Rejected — not reproducible** | No `run_sql` method and no SQL backend exist. Aegir is a sanitizing MCP *proxy*; "use parameterized queries" is not applicable to a forwarding gateway. The PoC describes a system that isn't here. |
| HIGH‑3 | High | **Rejected — no bypass** | `LoginBegin` (`internal/auth/webauthn/handler.go:131-144`) binds `user_id` with `binding:"required"` and returns `401 unknown user` for unregistered IDs. The PoC `-d '{}'` fails JSON binding → `400`. The "header or query param" code the finding describes is `RegisterFinish` (`handler.go:87-96`), which *also* rejects empty `userID` with `400`. No unauthenticated path through the ceremony. |
| MEDIUM‑4 | Medium | **CONFIRMED — fixed** | `/health` (`internal/server/server.go:293-299`) returned `version` + `timestamp`. Legitimate fingerprinting surface on an unauthenticated endpoint. **Fix applied:** now returns `{"status":"healthy"}` only. No internal/test consumer depends on the removed fields (verified). |
| MEDIUM‑5 | Medium | **PARTIALLY CONFIRMED — fixed** | SQL detection (`internal/sanitizer/manager.go:399-415`) *did* catch `DROP TABLE`, `UNION SELECT`, `DELETE FROM`, etc., but `DROP DATABASE`/`SCHEMA`, `TRUNCATE`, and `ALTER` slipped through. **Fix applied:** generalised the DROP pattern to `drop\s+(database\|schema\|table\|index\|view)` and added `TRUNCATE`/`ALTER` patterns; regression cases added to `TestSQLInjectionDetection`. Note: SQLi neutralisation here is defense-in-depth on proxied content, not Aegir's primary mission (prompt-injection/IOC). |
| LOW‑6 | Low | **Rejected — already mitigated** | `NOSQL.MONGO.001` (`internal/sanitizer/ioc_patterns.go:571-576`) already matches `$where`, `$regex`, `$ne`, `$gt`, `$eval`, `$function`, etc. via `(?i)\{\s*"\$(?:…\|where\|regex\|…)"\s*:`. The PoC `{"$where":"…"}` is detected today. |
| INFO‑7 | Informational | **Rejected — wrong endpoint + wrong threat model** | There is no unauthenticated `/dashboard/reset`. The real route is `POST /api/dashboard/reset` (`internal/dashboard/handlers.go:232`), registered under `protectedDashboard` which applies `AuthMiddleware()` (`internal/server/server.go:197-200`). Auth is **Bearer JWT in the `Authorization` header**, not cookies — so CSRF is structurally inapplicable (no ambient credentials to forge). The PoC `curl -X POST /dashboard/reset` with no token hits a non-route / 401. |

### Changes made this pass
- `internal/server/server.go` — `/health` stripped to `{"status":"healthy"}` (MEDIUM‑4).
- `internal/sanitizer/manager.go` — DDL coverage extended: generalised DROP + TRUNCATE/ALTER (MEDIUM‑5).
- `internal/sanitizer/sanitizer_test.go` — regression cases for `DROP DATABASE` / `TRUNCATE` / `ALTER`.
- Verified: `go build ./...` exit 0; `go test ./internal/sanitizer/ ./internal/server/` exit 0.

### Process note for the next round
The PoC payloads were generic templates (`run_sql`, `/dashboard/reset`, `-d '{}'`) that did not
match this codebase's actual surface (MCP JSON-RPC over `/mcp`, Bearer-auth dashboard API,
WebAuthn ceremonies). For the counter, please supply PoCs that hit real routes with real methods,
and pin findings to current `file:line` at HEAD — that's the fastest path to separating real
issues from template noise.
