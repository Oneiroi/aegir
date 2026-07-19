# LLMVault / SPIKEE Testing — Handoff

**Written:** 2026-07-18 · **For:** the next session (any model tier) picking up LLMVault testing support.
**Do not commit on the maintainer's behalf.** David commits everything himself (GPG signing gate). This handoff, the report, and all code changes are left in the working tree for his review.

---

## 1. What this work is

Make Aegir's LLMVault / OWASP-LLM-Top-10 testing support **functional front-to-back** and produce an **initial testing report** for the repo. LLMVault (https://github.com/CyberSunil/LLMVault) is an external CTF training range; Aegir is positioned as the reference *defensive* architecture for the attack classes it teaches (see `docs/LLMVAULT-DEFENSIVE-MAPPING.md`). The runnable test path is the SPIKEE replay harness in `redteam/aegir/`.

## 2. Current status — what is DONE

- **Harness confirmed functional front-to-back.** Built `bin/aegir` + `bin/echo-server` fresh, brought up Aegir (HTTP, TLS off, rate-limit off, judge off) + a mock upstream, authenticated, and ran `redteam/aegir/replay.py` against the frozen `corpus/adversarial.jsonl` (2,720 payloads) and `benign_corpus.jsonl` (15). Reports emit; latency healthy (p99 13–28 ms on the non-wedged path).
- **Initial testing report written:** `redteam/aegir/results/INITIAL-TESTING-REPORT-20260718.md`. Read it — it is the primary artifact and contains the finding below in full.

## 3. THE finding that stopped a clean efficacy number — latching global block-all (CRITICAL) — FIXED

A fresh Aegir instance that passed benign traffic **degraded, after ~30–40 detection-positive (adversarial) requests, into a latched global state that blocked ALL traffic** — benign requests, `tools/list`, even empty-argument calls — with `HTTP 403 … "Risk level: critical (critical)"`. It did not clear; new session IDs were still blocked; only a process restart recovered.

Verified deterministically on 5 fresh instances:
- Benign `"hello"` probe: **200** before adversarial traffic; **200** at 10/20/30 adversarial payloads; **403** from ~40 onward, permanently.
- 300 benign (fixed session) and 400 benign (unique sessions) NEVER wedged → trigger was **detection-positive volume**, not request/session count or benign load.

**Root cause:** `internal/server/mcp_proxy.go:getSessionID` ignored the `X-Session-ID` header sent by the SPIKEE target and fell back to `userID_clientIP`. All replay traffic used the same JWT and source IP, so every payload collapsed into a single `SessionContext`. The per-session anomaly EWMA (`SessionContext.AnomalyEWMA`) ratcheted upward with each adversarial detection and never decayed; once it crossed `AnomalyBlockThreshold` (default 0.70), every subsequent request was blocked.

**Fix landed (working tree, not committed by maintainer):**
1. `getSessionID` now honours `X-Session-ID` (length-bounded and sanitized) before falling back to `userID_clientIP`.
2. `ConversationalThreatAnalyzer` applies time-based EWMA decay with a configurable half-life (`SessionAnalysis.AnomalyEWMADecayHalfLife`, default 5 minutes).
3. Added auth-gated `DELETE /api/security/sessions` to clear all session state.
4. `redteam/aegir/replay.py` gained `--recycle-after-detections N` and `--state-reset-url` to use that endpoint.
5. Regression probes: `TestSessionIsolationAfterAdversarialBurst` (server) and `TestAnomalyEWMADecay` (session).

**Consequences:**
1. **Availability defect (release-blocking) — resolved.** A latched attacker session can no longer block benign traffic in a different session. EWMA decay also lets a quiet session recover.
2. **Efficacy now measurable.** The full-corpus "94.78% block / 100% benign FP" numbers were **CONTAMINATED** (tail was wedge, not detection) — do NOT quote them. Clean numbers with state recycled every 25 detections: adversarial block rate **62.13%** (1690/2720), benign FP **13.33%** (2/15), latency p99 **~13 ms**.

## 4. Intended work for pickup — COMPLETED

1. ✅ **Root-cause + fix the latch.** Fixed in `internal/server/mcp_proxy.go` and `internal/session/analyzer.go`.
2. ✅ **Add process/state recycling to `replay.py`.** Added `--recycle-after-detections` / `--state-reset-url` plus `DELETE /api/security/sessions`.
3. ✅ **Re-measure efficacy.** Clean numbers recorded above.
4. ✅ **Add a regression probe.** `TestSessionIsolationAfterAdversarialBurst` and `TestAnomalyEWMADecay`.

## 5. Gotchas that will bite the next session

- **`redteam/` is entirely git-ignored** (`.git/info/exclude:20: redteam/`). The harness AND the testing report are invisible to `git add` / `git status`. To land the report in the repo, either `git add -f redteam/aegir/results/INITIAL-TESTING-REPORT-20260718.md`, or move/copy it somewhere tracked (e.g. `docs/`). **Decision for David** — flagged, not actioned.
- **Sandbox blocks the Go build cache and `nice()`** — `go build`/`go test` and launching background servers fail with "operation not permitted" under the sandbox. Re-run those with the sandbox disabled. `/tmp` is also blocked; use repo-local scratch.
- **`llm-redteam` must be a sibling** at `../llm-redteam` (i.e. `…/Keybase/llm-redteam`). Present now; `replay.py` imports `targets/aegir_mcp_target.py` from it for the BLOCKED/PASSED contract. A second empty `../../llm-redteam` exists — ignore it.
- **Contaminated result files retained as wedge evidence:** `redteam/aegir/results/replay-{adversarial,benign}-20260718.{json,md}` hold the wedge-contaminated numbers. They are evidence, NOT efficacy. Any prior `EFFICACY-REPORT.md` measured on one long-lived instance is suspect for the same reason.

## 6. Reproduction

```bash
go build -o bin/aegir ./cmd/server          # sandbox-disabled
# mock upstream on :8080 (see bin/demo-flow-test.sh inline python), then:
MCP_SERVER_PORT=18443 MCP_SERVER_TLS_ENABLED=false MCP_SECURITY_RATE_LIMIT_ENABLED=false \
  MCP_UPSTREAM_URL=http://127.0.0.1:8080 AEGIR_ALLOW_INSECURE_JWT_SECRET=true ./bin/aegir &
# login: POST /auth/login  admin + password from startup log line "Admin password (save this):"
# benign "hello" tools/call -> 200; fire ~40 corpus adversarial payloads; benign "hello" -> 403 (wedged)
```

## 7. Working-tree state at handoff (nothing committed)

- **Tracked modified (from earlier tasks this session, not the testing work):** `ISA.md`, `README.md` (M016 LLMVault docs); `internal/config/config.go`, `internal/server/mcp_proxy.go` (dormant-by-default `Security.ToolMetadataInspection` wiring of the ISC-106/107/108/115/116 detectors).
- **Untracked (tracked location):** `internal/server/toolmeta_wiring_test.go` (the wiring probes; `TestISC*_Wired` + dormant-default, all green — run sandbox-disabled), `docs/LLMVAULT-DEFENSIVE-MAPPING.md`.
- **Untracked (git-ignored `redteam/`):** this session's report + result files (see §5).
- **Pre-existing untracked, unrelated:** `ISA-update-plan.md`, `RECOMMENDATIONS.md`, `observations.md`, `package.json`, `bun.lock`, `aegir.omlx-judge.example.yaml`.
- Background test servers were torn down; scratch (`__pycache__`, transient logs) removed.

## 8. Related SeniorEngineer artifacts (context, already landed in ~/.claude)

The wider session hardened the SeniorEngineer skill (gates for confabulated handles, untracked-junk, present-but-not-wired, red-reachability) and wrote 4 learning notes under `~/.claude/skills/extract-approach/learnings/2026-07-17-*`. The dormant toolmeta wiring in §7 was the "present-but-not-wired" fix. None of that blocks this testing work; it's the backdrop.
