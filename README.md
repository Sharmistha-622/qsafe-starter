# QSafe Scanner

**Find every quantum-vulnerable cryptographic primitive in your codebase, score your risk, and migrate to post-quantum standards — powered by IBM Bob.**

---

## The Problem

Quantum computers running Shor's algorithm will break RSA, ECDH, ECDSA, and finite-field Diffie-Hellman in polynomial time. That threat is not theoretical — it is operational *today* through **harvest-now, decrypt-later (HNDL)**: adversaries are already recording encrypted traffic and ciphertext, waiting for the day a cryptographically relevant quantum computer exists to decrypt it retroactively.

**NIST IR 8547 (draft) sets hard deadlines:**

| Deadline | Status |
|---|---|
| 2030 | 112-bit RSA/ECC deprecated |
| 2035 | All RSA, ECDSA, EdDSA, DH, ECDH disallowed |

NIST published its first post-quantum standards in August 2024 (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA). The migration window is short, and most codebases have never been audited for cryptographic hygiene.

---

## What QSafe Scanner Does

QSafe Scanner is a static-analysis tool that finds quantum-vulnerable cryptography across polyglot codebases (Python, JavaScript, Java, nginx config), scores your risk using Mosca's inequality, and generates standards-compliant reports — all offline, with no external API calls.

```
repo path ──► Scanner engine (regex rules.yaml + Python ast)
                 │
                 ▼
          findings.json ──► Risk scorer  (Mosca: X + Y > Z ?)
                 │
     ┌───────────┼───────────────┬────────────────┐
     ▼           ▼               ▼                ▼
 cbom.json   results.sarif   summary.md   Streamlit dashboard
(CycloneDX)  (SARIF 2.1.0)   (Bob writes)  (score, heatmap, Mosca slider)
                 │
                 ▼
       Bob PQC Migrator ──► hybrid ML-KEM / ML-DSA patch + pytest
```

### Quantum Readiness Score

Mosca's theorem: if **X + Y > Z** you are already at risk.

- **X** — years the data must stay secret (card data ≈ 7, health records ≈ 25)
- **Y** — years your organisation needs to migrate (default 5)
- **Z** — years until a cryptographically relevant quantum computer (slider: 5–15)

Per finding: `risk = usage_weight × (1 if X+Y>Z else 0.4)` where usage weights are key exchange / encryption → 10, signatures → 7, symmetric → 3, hashes → 2.
Final score: `100 − normalised total risk` (0 = all CRITICAL, 100 = fully quantum-safe).

### Output Formats

| File | Format | Description |
|---|---|---|
| `reports/findings.json` | Custom schema | Every finding with `id, rule_id, file, line, algorithm, key_size, severity, quantum_vulnerable, recommendation, nist_replacement` |
| `reports/cbom.json` | CycloneDX 1.6 | Cryptographic Bill of Materials (`cryptographic-asset` components with `cryptoProperties`) |
| `reports/results.sarif` | SARIF 2.1.0 | Machine-readable for GitHub Advanced Security, VS Code, and IDEs |

---

## How IBM Bob Powers the Workflow

IBM Bob is not a peripheral tool here — it is the development environment and the auditor.

| Bob Feature | How We Used It |
|---|---|
| **`AGENTS.md`** | Project context Bob loads automatically; defines the finding schema, severity scale, and NIST facts so every Bob session stays consistent |
| **🔐 Quantum-Safe Auditor** (custom mode) | Switches Bob into a specialised auditor persona; verifies scanner findings, removes false positives, and explains cryptographic risk in plain English |
| **🛠️ PQC Migrator** (custom mode) | Switches Bob into a migration engineer; rewrites RSA / ECDH code into hybrid ML-KEM / ML-DSA code with round-trip tests |
| **`pqc-scan` skill** | Encapsulates the full audit workflow; Bob loads it via `.bob/skills/pqc-scan/` and runs the scanner, scores the result, and generates the CBOM in one step |
| **`/qscan` slash command** | One-line trigger inside Bob that invokes the `pqc-scan` skill end-to-end; type `/qscan` to audit the open workspace |
| **`bob_sessions/`** | Exported Bob session reports proving Bob was core to the build — architecture decisions, scanner implementation, migrator patches, and the CBOM all trace back to sessions here |
| **Plan mode** | Used to design the architecture, data flow, and 48-hour task breakdown before a single line of code was written |
| **Agent mode + coding rules** | Built the scanner engine, CBOM/SARIF exporters, risk scorer, and Streamlit dashboard under `.bob/rules/` constraints |

Custom modes live in [`.bob/custom_modes.yaml`](.bob/custom_modes.yaml). The slash command definition is in [`.bob/commands/qscan.md`](.bob/commands/qscan.md).

---

## Results

### Demo App: `demo_vulnerable_app/`

The demo app intentionally uses quantum-vulnerable cryptography across Python, JavaScript, Java, and nginx.

**Before migration — Score: 0 / 100 (CRITICAL)**

| Severity | Finding | File |
|---|---|---|
| CRITICAL | RSA-2048 encrypts card numbers | `payments_service.py:9` |
| CRITICAL | ECDHE/RSA TLS key exchange | `nginx.conf:5` |
| CRITICAL | DH key agreement | `TokenService.java:17` |
| CRITICAL | ECDH key exchange | `auth.js:8` |
| HIGH | ECDSA signature (SECP256R1) | `payments_service.py:20` |
| HIGH | SHA256withECDSA signature | `TokenService.java:14` |
| HIGH | RSA key-pair (signatures) | `auth.js:5` |
| MEDIUM | MD5 checksum | `payments_service.py:25` |
| MEDIUM | SHA-1 hash | `auth.js:12` |

**After migration — Score: 100 / 100**

The PQC Migrator rewrote `encrypt_card_number` in `payments_service.py` to a crypto-agile hybrid scheme: **X25519 + ML-KEM-768** (FIPS 203) for key encapsulation, **AES-256-GCM** for symmetric encryption. The ML-KEM backend is plugged in via **liboqs-python** (`oqs.KeyEncapsulation("ML-KEM-768")`), providing both classical and post-quantum security during the transition period. The migrated file lives in `migrated/payments_service_pqc.py` with a passing round-trip pytest.

---

## How to Run

### Prerequisites

```bash
pip install -r requirements.txt   # includes liboqs-python, streamlit, pytest
```

### Scan a codebase

```bash
python -m scanner.cli scan <path/to/scan> --out reports/
```

### Score findings

```bash
python -m scanner.cli score reports/findings.json
```

Override Mosca parameters:

```bash
python -m scanner.cli score reports/findings.json --data-lifetime 10 --migration-years 5 --quantum-years 8
```

### Run tests

```bash
pytest
```

### Streamlit dashboard

```bash
streamlit run app/dashboard.py
```

The dashboard shows the Quantum Readiness Score gauge, a findings table with severity colours, a per-file findings bar chart, Mosca sliders that recompute the score live, and a **Download CBOM** button.

---

## Project Structure

| Path | Purpose |
|---|---|
| `AGENTS.md` | Project context Bob loads automatically |
| `.bob/custom_modes.yaml` | Custom modes: 🔐 Quantum-Safe Auditor, 🛠️ PQC Migrator |
| `.bob/rules/` | Coding rules applied in every Bob mode |
| `.bob/skills/pqc-scan/` | `pqc-scan` skill definition |
| `.bob/commands/qscan.md` | `/qscan` slash command |
| `scanner/` | Scan engine (`cli.py`, `rules.yaml`, `score.py`, exporters) |
| `app/dashboard.py` | Streamlit dashboard |
| `demo_vulnerable_app/` | Intentionally vulnerable sample code — do not "fix" these files |
| `migrated/` | PQC-migrated versions produced by the Migrator mode |
| `reports/` | Scanner output: `findings.json`, `cbom.json`, `results.sarif` |
| `bob_sessions/` | Exported Bob session reports |
| `docs/PLAN.md` | 48-hour build plan, roles, Bob prompts, demo script |

---

## Team

| Name | Role |
|---|---|
| **Sharmishtha Mazumdar** | Scanner engine, risk scorer, CBOM/SARIF exporters, custom Bob modes, PQC Migrator demo, `bob_sessions` |
| **Kartik Tripathi** | Streamlit dashboard, sample data, README, pitch deck, demo video, submission |

---

*Built for the IBM Bob 2.0 Hackathon (lablab.ai). NIST PQC references: FIPS 203, FIPS 204, FIPS 205 (Aug 2024); NIST IR 8547 (draft).*
