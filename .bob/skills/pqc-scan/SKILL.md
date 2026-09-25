---
name: pqc-scan
description: Scan a folder for quantum-vulnerable cryptography and produce findings.json, cbom.json, results.sarif and a plain-English summary.
---

# PQC Scan skill

## When to use
The user asks to "scan", "audit crypto", "check quantum readiness" or "make a CBOM" for a path.

## Steps
1. Run: `python -m scanner.cli scan <path> --out reports/`
2. Open `reports/findings.json`. For the top 10 findings by severity, open the source line and confirm it is real.
3. For each confirmed finding, add a one-sentence explanation and the NIST replacement:
   - RSA / ECDH / DH / X25519 used for key exchange or encryption → ML-KEM-768 (FIPS 203), hybrid with X25519
   - RSA / ECDSA / EdDSA signatures → ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) for long-lived roots of trust
   - MD5 / SHA-1 → SHA-256 or SHA3-256 (not a quantum issue, but a blocker for any migration)
   - AES-128 → AES-256 (Grover's algorithm halves effective key strength)
4. Compute the Quantum Readiness Score with `python -m scanner.cli score reports/findings.json`.
5. Write `reports/summary.md`:
   - Score (0–100) and one-line verdict
   - Top 3 risks, each with file:line
   - Migration order (key exchange first, then signatures, then hashes)
6. Tell the user they can click "Fix with Bob" on a finding, or switch to the 🛠️ PQC Migrator mode.

## Do not
- Do not modify source files in this skill. It is read-only apart from `reports/`.
