# QSafe CLI — Implementation Plan

## Overview

Build `scanner/cli.py` with two sub-commands:

- **`scan <path> --out <dir>`** — walks a source tree, matches rules from `scanner/rules.yaml` against
  each file (regex line scan + Python AST for key sizes), and writes `<dir>/findings.json`.
- **`score <findings.json>`** — reads `findings.json`, applies the Mosca-based risk formula, and prints
  a 0–100 Quantum Readiness Score plus a verdict string to stdout.

Scope is limited to these two commands. CBOM, SARIF, and the Streamlit dashboard are out of scope for
this plan.

---

## Modules

| Module | Responsibility |
|---|---|
| `scanner/cli.py` | Argparse entry point; wires `scan` and `score` sub-commands |
| `scanner/loader.py` | Loads and validates `scanner/rules.yaml` into typed dataclasses |
| `scanner/engine.py` | File walker + regex matcher; calls AST extractor for `.py` files |
| `scanner/ast_extractor.py` | Python AST visitor that extracts `key_size=` keyword arguments |
| `scanner/scorer.py` | Mosca risk formula → 0–100 score + verdict |
| `scanner/models.py` | Shared `Finding` dataclass (matches schema in AGENTS.md) |

---

## Data Flow

```
scan <path>
    │
    ▼
loader.py          rules.yaml
  load_rules() ◄──────────────
    │
    ▼
engine.py
  walk_path()
    │ for each file
    ▼
  match_rules()     ← regex per line, filtered by file extension / lang
    │
    │ .py files only
    ▼
ast_extractor.py
  extract_key_sizes()  ← enriches finding.key_size from AST
    │
    ▼
  List[Finding]
    │
    ▼
  write findings.json  →  <out>/findings.json


score <findings.json>
    │
    ▼
scorer.py
  load_findings()
  compute_score()  ← usage_weight × Mosca multiplier per finding
    │
    ▼
  print score + verdict to stdout
```

---

## Finding Schema (from AGENTS.md)

Every entry in `findings.json`:

```
id, rule_id, file, line, algorithm, primitive, key_size,
quantum_vulnerable (bool), severity, recommendation, nist_replacement
```

`primitive` is derived from the rule's `usage` field:  
`key_exchange` → `asymmetric-key-exchange`, `signature` → `digital-signature`,  
`encryption` → `asymmetric-encryption`, `hash` → `hash`, `symmetric` → `symmetric-encryption`.

`severity` is derived from `usage` + `quantum_vulnerable`:  
CRITICAL: key_exchange or encryption + quantum_vulnerable  
HIGH: signature + quantum_vulnerable  
MEDIUM: hash/symmetric, not quantum_vulnerable  
LOW: anything else

---

## Mosca Score Formula (from docs/PLAN.md)

Parameters (with defaults, overridable via CLI flags):
- `X` = data lifetime in years (default 7)
- `Y` = migration time in years (default 5)
- `Z` = years to cryptographically relevant quantum computer (default 10)

Usage weights: `key_exchange/encryption → 10`, `signature → 7`, `symmetric → 3`, `hash → 2`

Per finding:
```
risk = usage_weight × (1.0 if X + Y > Z else 0.4)
```

Aggregate:
```
max_possible = sum of usage_weights for all findings (at full multiplier)
total_risk   = sum of per-finding risk values
score        = round(100 − (total_risk / max_possible) × 100)   # clamped 0–100
```

Verdict strings: `"CRITICAL"` (0–25), `"AT RISK"` (26–50), `"IMPROVING"` (51–75), `"QUANTUM READY"` (76–100)

---

## Numbered Task List

1. **Create `scanner/models.py`**  
   Define the `Finding` dataclass with all fields from AGENTS.md. Add a `to_dict()` method for JSON
   serialisation. Add a `from_dict()` classmethod for deserialisation (needed by `score`).
   *Status: [ ] pending*

2. **Create `scanner/loader.py`**  
   Load `scanner/rules.yaml` with PyYAML. Map each rule entry to a typed `Rule` dataclass. Build a
   `{lang: [Rule]}` index so the engine can look up rules by language without iterating all rules.
   *Status: [ ] pending*

3. **Create `scanner/ast_extractor.py`**  
   Write a single `ast.NodeVisitor` that finds `keyword` arguments named `key_size` in function calls
   and returns `{line: int_value}`. No other AST logic needed at this stage.
   *Status: [ ] pending*

4. **Create `scanner/engine.py` — file walker**  
   Implement `walk_path(root)` that `os.walk`s the tree, skips `.git`, `node_modules`, `venv`, and
   binary extensions, and yields `(filepath, lang)` pairs. Language is resolved from file extension
   (`.py → python`, `.js/.ts → javascript`, `.java → java`, `.conf/.yaml → config`).
   *Status: [ ] pending*

5. **Create `scanner/engine.py` — rule matcher**  
   Implement `match_rules(filepath, lang, rules)` that opens the file, iterates lines, and runs each
   compiled regex. On a match, construct a `Finding` (populate `severity` and `primitive` from `usage`).
   Call `ast_extractor` for `.py` files to enrich `key_size`. Return `List[Finding]`.
   *Status: [ ] pending*

6. **Create `scanner/scorer.py`**  
   Implement `compute_score(findings, X, Y, Z)` that applies the Mosca formula. Return a `dict` with
   keys `score` (int), `verdict` (str), and a `per_finding` breakdown list for future dashboard use.
   *Status: [ ] pending*

7. **Create `scanner/cli.py` — `scan` sub-command**  
   Use `argparse` with sub-parsers. `scan` accepts `path` (positional) and `--out` (default `reports/`).
   Call `loader`, `engine`, serialise findings to `<out>/findings.json`. Print a summary line:
   `Scanned N files — M findings (K critical)`.
   *Status: [ ] pending*

8. **Create `scanner/cli.py` — `score` sub-command**  
   `score` accepts `findings_file` (positional) and `--data-lifetime X`, `--migration-years Y`,
   `--quantum-years Z` (all with defaults from the formula). Load findings, call scorer, print:
   `Quantum Readiness Score: 42/100 — AT RISK`.
   *Status: [ ] pending*

9. **Add pytest tests in `tests/test_cli.py`**  
   - `test_scan_demo_app`: run `scan` against `demo_vulnerable_app/`, assert findings.json exists and
     contains ≥ 1 finding per language present in that directory.
   - `test_score_formula`: call `compute_score` directly with a known fixture; assert exact score.
   - `test_score_command`: invoke via `subprocess` or `click` test client, assert exit code 0 and score
     in output.
   *Status: [ ] pending*

10. **Wire `__main__` and smoke-test end-to-end**  
    Add `if __name__ == "__main__": main()` to `cli.py` and ensure the package is runnable as
    `python -m scanner <args>` via a `scanner/__main__.py` shim. Run against `demo_vulnerable_app/`
    manually; confirm JSON is valid and score prints.
    *Status: [ ] pending*

---

## Non-Goals for This Plan

- CBOM (`cbom.json`) and SARIF (`results.sarif`) exporters — separate plan (P3)
- Streamlit dashboard — Kartik's responsibility (P5)
- PQC Migrator — separate plan (P6)
- Network calls of any kind
