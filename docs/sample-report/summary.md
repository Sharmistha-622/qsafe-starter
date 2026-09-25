# QSafe Scan Summary — `demo_vulnerable_app`

## Score

**0 / 100 — CRITICAL**

Every key-exchange and encryption primitive in the app is quantum-vulnerable.
A cryptographically relevant quantum computer running Shor's algorithm would
break all of them retroactively (harvest-now, decrypt-later threat is active today).

---

## Top 3 Risks

| # | Severity | Algorithm | File : Line | Why it matters |
|---|----------|-----------|-------------|----------------|
| 1 | **CRITICAL** | RSA-2048 (encryption) | `demo_vulnerable_app/payments_service.py:9` | Encrypts card numbers with RSA-2048. Adversaries can record ciphertext now and decrypt it once a quantum computer exists. Long data-lifetime makes this the most urgent finding. |
| 2 | **CRITICAL** | ECDHE/RSA TLS (key exchange) | `demo_vulnerable_app/nginx.conf:5` | TLS session keys are negotiated with ECDHE — every HTTPS connection's forward secrecy is broken by a quantum attacker. Affects all traffic at the network boundary. |
| 3 | **CRITICAL** | DH (key exchange) | `demo_vulnerable_app/TokenService.java:17` | Finite-field Diffie-Hellman is broken by Shor's algorithm in polynomial time for any practical group size. |

---

## Migration Order

### 1 — Key exchange / encryption (fix first — harvest-now-decrypt-later)
| Finding | Replace with |
|---------|-------------|
| `payments_service.py:9` RSA-2048 encryption | **ML-KEM-768** (FIPS 203), hybrid with X25519 |
| `nginx.conf:5` ECDHE/RSA TLS ciphers | **X25519MLKEM768** hybrid TLS group (RFC draft) |
| `TokenService.java:17` DH key agreement | **ML-KEM-768** (FIPS 203) |
| `auth.js:8` ECDH key exchange | **ML-KEM-768** (FIPS 203), hybrid with X25519 |

### 2 — Signatures (fix after key exchange)
| Finding | Replace with |
|---------|-------------|
| `payments_service.py:20` ECDSA (SECP256R1) | **ML-DSA-65** (FIPS 204) |
| `TokenService.java:14` SHA256withECDSA | **ML-DSA-65** (FIPS 204) |
| `auth.js:5` RSA key-pair (signature) | **ML-DSA-65** (FIPS 204) |

### 3 — Weak hashes (not quantum, but block migration)
| Finding | Replace with |
|---------|-------------|
| `payments_service.py:25` MD5 checksum | **SHA-256** or SHA3-256 |
| `auth.js:12` SHA-1 hash | **SHA-256** (Argon2 if password hashing) |

---

## Fix First: `payments_service.py:9` — RSA-2048 Encrypting Card Numbers

**Why this one before any other:**

1. **Data sensitivity** — card numbers are PCI-DSS regulated; breach carries legal and financial liability.
2. **Harvest-now-decrypt-later** — encrypted card data stored or transmitted today can be archived by
   adversaries and decrypted once a quantum computer is available, well before the 2030–2035 NIST
   deprecation deadline (NIST IR 8547 draft).
3. **Long data lifetime** — payment records are retained for years, maximising the exposure window.
4. **Key size is explicit** (`key_size=2048`) — the scanner confirmed this; 2048-bit RSA offers only
   ~112 bits of classical security and zero quantum security.

**Recommended replacement:** wrap the key-encapsulation step in a crypto-agility layer and replace
`rsa.generate_private_key(…)` + OAEP encrypt with **X25519 + ML-KEM-768** (hybrid, FIPS 203).
This provides both classical and post-quantum security during the transition period.

---

> 💡 **Next step:** Click "Fix with Bob" on a finding above, or switch to the 🛠️ **PQC Migrator** mode
> to get a guided, file-by-file migration plan.
