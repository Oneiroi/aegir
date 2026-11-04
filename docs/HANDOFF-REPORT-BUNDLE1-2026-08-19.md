# Handoff Report — Red-team remediation, phase 1 (2026-08-19)

**Quorum:** supervisor (Kimi Code CLI) + implementer (pi session, Qwen3.8-27B via mtplx) agree: every task handed off from the 2026-08-17 red-team session is complete at the agreed done bar. Full verbatim discourse: `docs/HANDOFF-DISCOURSE-2026-08-18.md`.

## What was done

1. **Handoff received** from pi session `01a00ac6-…` (red-team campaign vs `d479710`, findings F1–F9, three-doc review chain in `redteam/aegir/results/rt-20260816/`).
2. **Bundle 1 (F1+F2+N1+F8) — COMPLETE.**
   - Found already implemented (uncommitted) by a third agent; jointly reviewed instead of trusted: implementer produced gap list G1–G6, supervisor independently line-verified and closed G3–G6 (fail-closed 502, content-asserting round-trip test, shared gates, dial-guard test coverage).
   - G1 implemented: per-connect `upstream_trusted_dial` audit log (resolved IP:port) on the trusted-authority dial branch — DNS-rebinding forensics (`internal/upstream/manager.go`, + test).
   - G2 implemented: operator-trust scope statement in `README.md` (identity trust, no IP re-verification, rebinding = operator-DNS compromise, startup warning, pinned-IP follow-up).
   - **Evidence:** `go build ./... && go test ./... -count=1` GREEN, all 19 packages, uncached, 2026-08-19. `TestTransportModeSelection -count=2` passed earlier (flake check).
3. **Fold-in (step b) — COMPLETE.** §F appended to `REDTEAM-FINDINGS-20260816-ADJUDICATION.md`: all four of Kimi's second-pass corrections (each supervisor-verified against code, incl. path fix to `internal/session/analyzer.go`), three new items (`maxSanitized.Blocked` discarded in high band, dead regex score, JWT `expires_in: 3600`), and the bundle-1 status record. Sections A–E untouched.
4. **Kimi's citations verified:** band `>= 0.5` (`internal/session/analyzer.go:710`), log-string "0.6-0.79" bug (`mcp_proxy.go:393`), headers leak every in-band request (`:406-407`), `Blocked` unchecked (`:397-402`).

## Decisions locked (do not re-litigate)

- F1 exemption v1 = host:port string match, **no** resolved-IP re-check (re-checking would re-block the private topologies F1 exists to fix); per-connect audit log + README scope statement ship with bundle 1; **pinned-IP mode is a follow-up**, to be recorded in ISA.md.
- Done bar: root gate green (uncached) + joint review sign-off; **commits are David's** — commit message drafted at `/tmp/aegir-bundle1-commit.txt` with staging notes.
- `redteam/` stays untracked; bypass details not published without David's decision.
- Old pi session `01a00ac6-…` retired at ~172K tokens (performance); working session is now `7ec48760-6103-4e87-94d2-50b251103161` (`aegir-bundle1-g1g2`).

## Infra incidents (resolved)

- 3 external cancels of pi generations on mtplx :8001 (`stream_cancelled_by_client: false` — never the pi client); :8002 lacks MTP runtime (unusable); service restarted clean on **:8000**, stable since.
- macOS update reboot killed one exchange mid-flight; no edits were lost (verified via `git diff`).

## Current tree state

Uncommitted bundle-1 changes (awaiting David's commit): `internal/upstream/manager.go`, `internal/upstream/secure_dial_test.go`, `internal/server/mcp_proxy.go`, `internal/server/proxy_roundtrip_test.go` (new), `README.md`. Pre-existing unrelated modifications also present (`.gitignore`, `AGENTS.md`, `CLAUDE.md`, `justfile`, parts of `README.md`).

## Next work (ordered, per ADJUDICATION §D)

2. **Bundle 2 — F3 SSRF hardening** (starting now): URL-candidate extraction from prose, empty-authority rejection, DNS-fail-closed internal-suffix denylist, dead bracket-branch removal, raw-fallback hardening, encoded-zone IPv6 variant.
3. Bundle 3 — F4(b/d/e) + N5/B1/B2 (session rate-limit, fragment accumulation, honor `maxSanitized.Blocked` in high band, strip score egress headers).
4. Bundle 4 — F5 confusables + ATLAS doc fix.
5. Bundle 5 — F6 + N2/N3 compliance alignment.
6. Bundle 6 — F7/F9/N4 + flaky test + JWT-shaped session IDs.
7. Wrap: ISA.md update (incl. pinned-IP follow-up), gate on committed code, handoff per repo protocol.
