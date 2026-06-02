
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

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill.

Key routing rules:
- Product ideas/brainstorming → invoke /office-hours
- Strategy/scope → invoke /plan-ceo-review
- Architecture → invoke /plan-eng-review
- Design system/plan review → invoke /design-consultation or /plan-design-review
- Full review pipeline → invoke /autoplan
- Bugs/errors → invoke /investigate
- QA/testing site behavior → invoke /qa or /qa-only
- Code review/diff check → invoke /review
- Visual polish → invoke /design-review
- Ship/deploy/PR → invoke /ship or /land-and-deploy
- Save progress → invoke /context-save
- Resume context → invoke /context-restore
