# Project rules (all modes)

- Before writing code, state the plan in max 5 bullets. We have a limited Bobcoin budget — be efficient,
  do not re-read the whole repo if you already know where things are.
- Write Python 3.11, type hints, docstrings of one line. Format with black defaults.
- Every new detection rule goes in `scanner/rules.yaml` AND gets a test in `tests/test_rules.py`.
- Output formats must stay stable:
  - `reports/findings.json` — list of findings (schema in AGENTS.md)
  - `reports/cbom.json` — CycloneDX 1.6, components of type `cryptographic-asset`
  - `reports/results.sarif` — SARIF 2.1.0
- Never commit secrets. Never call external APIs from the scanner.
- When unsure about a cryptography fact, say so instead of guessing.
