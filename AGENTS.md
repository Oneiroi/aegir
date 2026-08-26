# Aegir — Agent Instructions

Aegir is MCP (Model Context Protocol) security gateway written in Go. Shared source of truth for ALL coding agents — Claude Code, local models via OMLX, any other harness. `CLAUDE.md` adds Claude-specific skill routing; load-bearing content lives here.

Living spec is `ISA.md` (Ideal State Articulation). Read frontmatter + Status Summary before starting; update checkbox state, append Decisions/Verification entries as you go.

## Build verification gate — MANDATORY at session start

Trust build, not docs. Before believing ANY "done"/"complete"/"committed" claim:

```bash
git log --oneline -1          # note committed HEAD
go build ./... && go test ./...
```

- ISC/task "done" only when **whole-repo** gate — `go build ./... && go test ./...` run from repo root — exits 0 against **committed** code with real probe test. "Files created" ≠ done. Per-package `go build ./<pkg>/` / `go test ./<pkg>/` is floor while iterating, NOT substitute for root gate: code that compiles in isolation most likely breaks package that wires it in, so whole-repo run counts.
- `go vet`, `gofmt`, `golangci-lint`, or single-package pass is NOT build passing. `vet` routinely passes on code that doesn't compile as whole program. Moment you're about to report proxy check in place of root gate = signal you haven't run it.
- Environmental blocker = escalation, not waiver. Gate can't run — sandbox blocking Go build cache is known case; re-run outside sandbox — STOP + report "UNVERIFIED, blocked by X". Never downgrade to weaker check + present result as though gate passed. Self-certifying around blocker = broken code gets called done.
- Uncommitted code that doesn't compile = worth zero. Don't build on top. Find broken uncommitted work? Back it up + reset to last green commit first.
- Present ≠ wired, wired ≠ done: symbol that exists but nothing calls is dead code, not shipped feature. Grep call site + exercise real entry point (request handler, route, CLI command), not just unit in isolation, before claiming criterion done.

## Local-model code-gen failure fingerprints

Grep generated Go for these before trusting or committing — all occurred in this repo:

- literal `\!=` instead of `!=`
- backslash-escaped quotes or backticks inside source (`\"`, malformed backtick regex literals)
- split identifiers (`Tech nique` for `Technique`)
- duplicate type declarations across files in one package
- invalid recursive value types (`children [256]TrieNode` — use `map[byte]*TrieNode`)
- references to config types/fields never defined

## Parallel work rule

One agent per disjoint package, isolated in git worktree off green HEAD. Never edit shared files (`internal/config/config.go`, `internal/server/*`, `internal/sanitizer/manager.go`) from parallel agents — central proxy/config wiring is SERIAL step after packages land. Overlapping file targets cause transient build races.

## Hard constraints

- No new external dependencies without explicit approval; Go stdlib preferred for all detection logic.
- LLM judge invoked only on SUSPICIOUS-flagged traffic; judge default is local (Ollama/OMLX-class endpoint) — API-hosted judge models explicit opt-in only.
- No regex with catastrophic backtracking potential; all patterns pre-compiled at startup.
- Sanitiser must not add >10ms p99 latency to non-judge request path.
- TLS 1.3 minimum; all log entries HMAC-protected.
- Fail closed: judge timeout, refusal, or backend error → BLOCK, never ALLOW.

## Developer commands (`just`)

```
just build        # compile → bin/aegir
just run          # build + certs + run (HTTP)
just run-stdio    # build + run STDIO transport
just run-sse      # build + run SSE transport
just dev          # go run (no compile step, HTTP)
just dev-stdio    # go run with STDIO transport
just demo         # TLS + rate-limit disabled, quick test
just test         # go test -v ./...
just lint         # golangci-lint run
just deps         # go mod download && tidy
just certs        # generate dev TLS certs (skips if present)
just certs-force  # force-regenerate certs
just token        # fetch admin JWT from running server
just demo-flow    # full scenario loop (builds, starts server + mock)
just clean        # remove build artifacts
```

## Handoff protocol

When handing off (especially Claude ↔ local model via OMLX, e.g. connectivity loss or session limits):

1. Commit green work; never hand off broken working-tree state without flagging in `ISA.md`.
2. Update `ISA.md`: checkbox state, `progress:` frontmatter, Decisions entry naming HEAD.
3. Next agent re-runs build verification gate before reading any "done" claims.
