
## Shared agent instructions

Read `AGENTS.md` first — it is the model-agnostic source of truth shared by Claude and
non-Claude agents (local models via OMLX). It carries the build verification gate, the
handoff protocol, the local-model code-gen failure fingerprints, the parallel-work rule,
the hard constraints, and the full `just` command table. The living spec is `ISA.md`.

This file adds only Claude-specific behaviour (skill routing below).

## Developer commands (`just`)

Full table in `AGENTS.md`. Most used: `just build`, `just test`, `just demo-flow`.

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

## Model Tiering (via OMLX)

To optimize for cognitive complexity and memory profile, steer based on the following mapping:

| Task Type | Recommended Tier | Local Model | Memory Profile |
| :--- | :--- | :--- | :--- |
| Security Audit / Threat Model | **Opus** | `Qwen3-Coder-Next-MLX-8bit` | $\approx 45\text{GB}$ |
| Feature Implementation | **Sonnet** | `Qwen3.6-35B-A3B-MLX-8bit` | $\approx 30\text{GB}$ |
| Boilerplate / Docs / Logs | **Haiku** | `Ornith-1.0-9B-8bit` | $\approx 15\text{GB}$ |

**Mimir's Take:** Don't let the ISA.md dictate the model choice if the task feels trivial. If you're just moving a function from one file to another, don't wake up the 31B—it's like using a sledgehammer to crack a nut. Use the 12B for the grunt work and save the 31B for when we're actually trying to break something.

## learning law
after every non-trivial solved problem, run the extract-approach skill before moving on
a solution without its learnings note is unfinished work