
## Shared agent instructions

Read `AGENTS.md` first — model-agnostic source of truth shared by Claude + non-Claude agents (local models via OMLX). Contains build verification gate, handoff protocol, local-model code-gen failure fingerprints, parallel-work rule, hard constraints, full `just` command table. Living spec is `ISA.md`.

This file adds only Claude-specific behaviour (skill routing below).

## Developer commands (`just`)

Full table in `AGENTS.md`. Most used: `just build`, `just test`, `just demo-flow`.

## Skill routing

When user request matches available skill, invoke via Skill tool. When in doubt, invoke skill.

Key routing rules:
- Product ideas/brainstorming → `/office-hours`
- Strategy/scope → `/plan-ceo-review`
- Architecture → `/plan-eng-review`
- Design system/plan review → `/design-consultation` or `/plan-design-review`
- Full review pipeline → `/autoplan`
- Bugs/errors → `/investigate`
- QA/testing site behavior → `/qa` or `/qa-only`
- Code review/diff check → `/review`
- Visual polish → `/design-review`
- Ship/deploy/PR → `/ship` or `/land-and-deploy`
- Save progress → `/context-save`
- Resume context → `/context-restore`

## Model Tiering (via OMLX)

Optimize by cognitive complexity + memory profile:

| Task Type | Recommended Tier | Local Model | Memory Profile |
| :--- | :--- | :--- | :--- |
| Security Audit / Threat Model | **Opus** | `Qwen3-Coder-Next-MLX-8bit` | $\approx 45\text{GB}$ |
| Feature Implementation | **Sonnet** | `Qwen3.6-35B-A3B-MLX-8bit` | $\approx 30\text{GB}$ |
| Boilerplate / Docs / Logs | **Haiku** | `Ornith-1.0-9B-8bit` | $\approx 15\text{GB}$ |

**Mimir's Take:** Don't let `ISA.md` dictate model choice for trivial tasks. Moving a function? Don't wake 31B. Use 12B for grunt work, save 31B for breaking things.

## Learning law

After every non-trivial solved problem, run `extract-approach` skill before moving on. Solution without learnings note = unfinished work.
