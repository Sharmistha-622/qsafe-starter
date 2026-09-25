# QSafe Scanner — 48-hour build plan (IBM Bob 2.0 Hackathon)

**Deadline:** Sun 27 Sep, 8:30 PM IST (15:00 UTC). **Our internal deadline:** Sun 4:00 PM IST.

## The one-line pitch
"Quantum computers will break RSA and ECC. QSafe Scanner uses IBM Bob to find every quantum-vulnerable
line of crypto in your codebase, scores your risk, generates a standard CBOM, and fixes it with hybrid
post-quantum code — in minutes instead of a months-long audit."

## How Bob is used (this is what judges score as "Application of Tech")
| # | Bob feature | What we do with it |
|---|---|---|
| 1 | **Plan mode** | Design the architecture and task list (export the session!) |
| 2 | **Agent mode + AGENTS.md + rules** | Build the scanner engine, CBOM/SARIF exporters, dashboard |
| 3 | **Custom mode 🔐 Quantum-Safe Auditor** | Bob verifies findings, removes false positives, explains risk in plain English |
| 4 | **Skill `pqc-scan` + slash command `/qscan`** | One command runs the full audit inside Bob |
| 5 | **Custom mode 🛠️ PQC Migrator** | Bob rewrites RSA/ECDH code into hybrid ML-KEM / ML-DSA code with tests |
| 6 | **`/review` + Bob Findings panel** | A PR that adds new RSA code gets caught; click "Fix with Bob" live in the demo |
| 7 | **Literate coding (Cmd+M)** | Write the risk-score formula in plain English, let Bob turn it into code |
| 8 | **bob_sessions/** | Exported reports prove Bob was core to the build |

## Architecture
```
repo path ──► Scanner engine (regex rules.yaml + Python ast)
                 │
                 ▼
          findings.json ──► Risk scorer (Mosca: data lifetime + migration time > years to quantum?)
                 │
      ┌──────────┼──────────────┬────────────────┐
      ▼          ▼              ▼                ▼
  cbom.json   results.sarif   summary.md   Streamlit dashboard
 (CycloneDX)  (GitHub/IDE)    (Bob writes)  (score, heatmap, timeline)
                 │
                 ▼
        Bob PQC Migrator ──► hybrid ML-KEM / ML-DSA patch + pytest
```

## Quantum Readiness Score (what you learn + what makes it original)
Mosca's theorem: if **X + Y > Z** you are already in trouble.
- X = how many years the data must stay secret (card data ≈ 7, health ≈ 25, passwords ≈ 1)
- Y = years your organisation needs to migrate (default 5)
- Z = years until a cryptographically relevant quantum computer (make it a slider: 5–15)

Per finding: `risk = usage_weight × (1 if X+Y>Z else 0.4)`; usage_weight: key_exchange/encryption 10,
signature 7, symmetric 3, hash 2. Score = `100 − normalised total risk`.

## Who does what
**You — engine & Bob power-user:** scanner, scorer, CBOM/SARIF, custom modes, migrator demo, bob_sessions.
**Kartik — product & story:** Streamlit dashboard, sample data, README, pitch deck, demo video, submission form.

## Timeline (IST)
| When | You | Kartik |
|---|---|---|
| **Fri before 8:30 PM** | REGISTER both of you. Install Bob IDE, sign in with IBMid | Register. Install Bob. Create GitHub repo, push this starter kit |
| Fri 8:30–10 PM | Watch kickoff — note tracks, judging, bob_sessions rule, Bobcoin budget | Same; write down rules in docs/RULES.md |
| Fri 10 PM–1 AM | Prompt P1 (Plan mode) → P2 (scanner engine) | Prompt P5 (dashboard skeleton with fake findings.json) |
| **Sat 9 AM–2 PM** | P3 (CBOM + SARIF), P4 (score), tests | Dashboard on real output: score gauge, findings table, per-file chart, Mosca slider |
| Sat 2–7 PM | Try /qscan skill in Auditor mode; P6 migrator demo on payments_service.py | Pitch deck (6 slides) + README with screenshots |
| Sat 7–11 PM | P7: create a PR adding new RSA code → /review → Fix with Bob | Integrate, fix UI bugs, record rough demo |
| **Sun 9 AM–1 PM** | Bug fixes, export all bob_sessions + screenshots, remove secrets | Final demo video (≤ 3 min), cover image |
| Sun 1–4 PM | Full dry run together, then SUBMIT | Fill lablab form: repo, video, slides, demo link |
| Sun 4–8:30 PM | Buffer only. Do not start new features. | |

## Ready-to-paste Bob prompts
**P1 — Plan mode**
> Read AGENTS.md and scanner/rules.yaml. Plan a Python CLI `scanner/cli.py` with commands `scan <path> --out <dir>`
> and `score <findings.json>`. List the modules, data flow and a 10-step task list. Keep it simple enough to build in 6 hours.

**P2 — Agent mode: engine**
> Implement the plan. `scan` walks the path (skip .git, node_modules, venv), picks rules by file extension, matches
> patterns line by line, and for Python files also uses `ast` to find `key_size=` values. Write reports/findings.json
> using the schema in AGENTS.md. Add pytest tests that run against demo_vulnerable_app and expect 10 findings.

**P3 — CBOM & SARIF**
> Add exporters: reports/cbom.json in CycloneDX 1.6 format (components of type "cryptographic-asset" with
> cryptoProperties) and reports/results.sarif in SARIF 2.1.0. Validate the CBOM against the official CycloneDX 1.6
> JSON schema in a test.

**P4 — Literate coding (Cmd+M in scanner/score.py)**
> For each finding compute risk from usage weight and Mosca's inequality X+Y>Z (defaults in a dict, overridable by
> CLI flags). Return a 0–100 Quantum Readiness Score and a verdict string.

**P5 — Dashboard (Kartik)**
> Build app/dashboard.py in Streamlit: upload or choose a folder, run the scanner, show a score gauge, findings table
> with severity colours, bar chart of findings per file, and sliders for X, Y, Z that recompute the score live.
> Add a "Download CBOM" button.

**P6 — 🛠️ PQC Migrator mode**
> Migrate `encrypt_card_number` in demo_vulnerable_app/payments_service.py to a crypto-agile hybrid scheme:
> X25519 + ML-KEM-768 (liboqs-python) to derive a key, AES-256-GCM to encrypt. Keep RSA behind a config flag.
> Put the new code in `migrated/payments_service_pqc.py` and add a round-trip test.

**P7 — /review demo**
> Create branch `feature/new-login`, add a file using RSA-1024 and SHA-1, then run /review. Show the Findings panel.

## Bobcoin budget tips (last hackathon: 40 coins, no top-ups)
- Use Ask mode for questions, not Agent mode. Give Bob exact file names so it doesn't read the whole repo.
- One focused task per session → also gives you clean bob_sessions exports.
- If Bob loops on an error, stop it and fix the small thing yourself.

## Demo video script (≤ 3 min)
1. (0:00) Problem: "Harvest now, decrypt later" — encrypted data stolen today is readable once quantum arrives. NIST says RSA/ECC disallowed by 2035.
2. (0:30) Type `/qscan` in Bob → findings appear, Auditor explains them.
3. (1:10) Dashboard: score 23/100, move the Mosca slider, show CBOM download.
4. (1:50) Switch to PQC Migrator → hybrid ML-KEM patch + passing test.
5. (2:20) New PR with RSA-1024 → /review catches it → "Fix with Bob".
6. (2:45) Impact + what's next (CI GitHub Action, more languages, certificate scanning).

## Pitch deck (6 slides)
Problem · Solution · How Bob powers it · Live results (score + CBOM) · Business value (banks, govt, health must migrate by 2030–35) · Roadmap & team

## Stretch goals (only if ahead of schedule)
- GitHub Action that fails a PR when the score drops
- Scan X.509 certificates / .pem files with the `cryptography` library
- A small Qiskit notebook showing *why* Shor's algorithm breaks RSA (education slide)
