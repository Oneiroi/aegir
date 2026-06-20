# Aegir — Agent Instructions

Aegir is an MCP (Model Context Protocol) security gateway written in Go. This file is the
shared source of truth for ALL coding agents working on this repo — Claude Code, local models
served via OMLX, or any other harness. `CLAUDE.md` adds Claude-specific skill routing on top;
everything load-bearing lives here.

The living spec is `ISA.md` (Ideal State Articulation). Read its frontmatter and Status
Summary before starting work; update checkbox state and append Decisions/Verification
entries as you go.

## Build verification gate — MANDATORY at session start

Trust the build, not the docs. Before believing ANY "done"/"complete"/"committed" claim:

```bash
git log --oneline -1          # note committed HEAD
go build ./... && go test ./...
```

- An ISC/task is "done" only when `go build ./<pkg>/` and `go test ./<pkg>/` exit 0 against
  **committed** code with a real probe test. "Files created" is NOT done.
- Uncommitted code that does not compile is worth zero. Do not build on top of it. If you
  find broken uncommitted work, back it up and reset to the last green commit first.
- Per-package green gate: every package must pass its own build + test before its work is
  claimed complete.

## Local-model code-gen failure fingerprints

Grep generated Go for these before trusting or committing it — every one has occurred in
this repo:

- literal `\!=` instead of `!=`
- backslash-escaped quotes or backticks inside source (`\"`, malformed backtick regex literals)
- split identifiers (`Tech nique` for `Technique`)
- duplicate type declarations across files in one package
- invalid recursive value types (`children [256]TrieNode` — use `map[byte]*TrieNode`)
- references to config types/fields that were never defined

## Parallel work rule

One agent per disjoint package, isolated in a git worktree off green HEAD. Never edit shared
files (`internal/config/config.go`, `internal/server/*`, `internal/sanitizer/manager.go`)
from parallel agents — central proxy/config wiring is a SERIAL step done after packages land.
Overlapping file targets cause transient build races.

## Hard constraints

- No new external dependencies without explicit approval; Go stdlib preferred for all
  detection logic.
- LLM judge invoked only on SUSPICIOUS-flagged traffic; judge default is local
  (Ollama/OMLX-class endpoint) — API-hosted judge models are explicit opt-in only.
- No regex with catastrophic backtracking potential; all patterns pre-compiled at startup.
- Sanitiser must not add >10ms p99 latency to the non-judge request path.
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

When handing off (especially Claude ↔ local model via OMLX, e.g. at connectivity loss or
session limits):

1. Commit green work; never hand off broken working-tree state without flagging it in ISA.md.
2. Update `ISA.md`: checkbox state, `progress:` frontmatter, a Decisions entry naming HEAD.
3. The next agent re-runs the build verification gate before reading any "done" claims.
