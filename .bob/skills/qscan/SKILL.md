---
name: qscan
description: Run the quantum-safe scan on a path and summarise the results
metadata:
  user-invocable: true
  disable-model-invocation: true
  argument-hint: '<path to scan, default demo_vulnerable_app>'
---

Use the `pqc-scan` skill on `$ARGUMENTS` (default: `demo_vulnerable_app`).
Then show me: the Quantum Readiness Score, the top 3 findings with file:line, and which one to fix first and why.
