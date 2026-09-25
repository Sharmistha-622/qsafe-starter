# QSafe Scanner — find and fix quantum-vulnerable crypto with IBM Bob

Starter kit for the IBM Bob 2.0 Hackathon (lablab.ai, 25–27 Sep 2026).

## What's inside
| Path | Purpose |
|---|---|
| `AGENTS.md` | Project context Bob loads automatically |
| `.bob/custom_modes.yaml` | Two custom modes: 🔐 Quantum-Safe Auditor, 🛠️ PQC Migrator |
| `.bob/rules/` | Coding rules for every Bob mode |
| `.bob/skills/pqc-scan/` | Bob skill that runs the full audit |
| `.bob/commands/qscan.md` | `/qscan` slash command |
| `scanner/rules.yaml` | 10 seed detection rules (tested: all match the demo app) |
| `demo_vulnerable_app/` | Intentionally vulnerable Python / JS / Java / nginx samples |
| `bob_sessions/` | Where exported Bob session reports go (likely mandatory) |
| `docs/PLAN.md` | 48-hour plan, roles, Bob prompts, demo script |

## Start
1. Push this folder to a new GitHub repo.
2. Open it in IBM Bob IDE. Check the mode picker shows the two custom modes.
3. Follow `docs/PLAN.md`, starting with prompt P1 in Plan mode.

Note: Bob config paths for skills/commands come from community docs — if Bob doesn't pick them up,
check bob.ibm.com/docs and move the files.
