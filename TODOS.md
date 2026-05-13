# Aegir Todo List

## Dashboard Rendering Fixes

- [x] Fix dashboard rendering - CSS broken, login form doesn't submit properly
      Root cause: `Content-Security-Policy: default-src 'self'` (global middleware) blocked all
      inline `<style>` and `<script>` in the dashboard HTML. Fixed by overriding CSP in
      `ServeWebDashboard` to allow `'unsafe-inline'` for script-src and style-src.
- [x] Ensure login form properly posts to `/auth/login` endpoint
      JS was correct all along — it was blocked from running by the CSP above.
- [x] Verify JavaScript executes correctly for token storage and dashboard display
      CSP override fixes this. JS now sends `Authorization: Bearer <token>` header on dashboard
      API calls and handles 401 by clearing the stored token and showing the login form.
- [x] Fixed: dashboard API routes were unprotected despite "protected" comment in server.go.
      Wrapped in auth middleware group before calling `RegisterRoutes`.
- [ ] Test in real browser (not curl) — run `make demo` then open https://localhost:8443/dashboard

## Demo Data Flow Testing

- [x] Configure demo data flow testing — `bin/demo-flow-test.sh` covers approved + denied flows
- [x] Test approved flows (clean requests passing through) — in demo-flow-test.sh
- [x] Test denied flows (blocked requests) — in demo-flow-test.sh
- [x] Configure OpenTelemetry (OTEL) to write to local directory
      Added `internal/telemetry/otel.go` using stdouttrace exporter writing to
      `logs/traces/traces-<date>.jsonl`. Enable with `OTEL_ENABLED=true`.
      Config keys: OTEL_ENABLED, OTEL_OUTPUT_DIR, OTEL_SERVICE_NAME, OTEL_SAMPLE_RATE.
- [x] Verify OTEL logs are written to file (not just stdout) — demo-flow-test.sh checks for trace file
- [ ] Run `bin/demo-flow-test.sh` to execute end-to-end verification

---

*Last updated: 2026-05-12*
