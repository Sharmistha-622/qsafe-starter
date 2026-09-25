# AGENTS.md — QSafe Scanner

Bob loads this file automatically. It tells Bob what this project is and how to work in it.

## Project
QSafe Scanner finds quantum-vulnerable cryptography (RSA, ECC, DH, weak hashes) in a codebase,
scores the risk, exports a CycloneDX 1.6 CBOM + SARIF report, and proposes post-quantum (PQC) fixes.

## Stack
- Python 3.11+
- `scanner/` — the scan engine (regex rules + Python `ast`), CLI entry `scanner/cli.py`
- `scanner/rules.yaml` — detection rules (one rule per algorithm/API pattern)
- `app/` — Streamlit dashboard (`streamlit run app/dashboard.py`)
- `demo_vulnerable_app/` — intentionally vulnerable sample code used for the demo. NEVER "fix" files here unless the user explicitly asks for a migration demo.

## Conventions
- Every finding has: `id, rule_id, file, line, algorithm, primitive, key_size, quantum_vulnerable (bool), severity, recommendation, nist_replacement`.
- Severity scale: CRITICAL (key exchange / encryption with RSA/ECDH/DH — "harvest now, decrypt later"),
  HIGH (signatures with RSA/ECDSA/EdDSA), MEDIUM (AES-128, SHA-1 in non-signature use), LOW (informational).
- Keep functions small and typed. Add a pytest test for every new rule in `tests/`.
- Do not add network calls to the scanner. It must run fully offline.

## Facts to use (do not invent others)
- NIST PQC standards (Aug 2024): FIPS 203 ML-KEM (key encapsulation), FIPS 204 ML-DSA (signatures), FIPS 205 SLH-DSA (hash-based signatures).
- FIPS 206 FN-DSA (Falcon) is not yet final.
- NIST IR 8547 (draft): 112-bit RSA/ECC deprecated after 2030; all RSA/ECDSA/EdDSA/DH/ECDH disallowed after 2035.
- Recommended migration pattern: hybrid (classical + PQC), e.g. X25519 + ML-KEM-768, behind a crypto-agility wrapper.

## Security
- Never write secrets, API keys or real private keys into the repo. Demo keys must be generated at runtime.
