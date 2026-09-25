"""Export findings as a CycloneDX 1.6 CBOM (reports/cbom.json)."""
from __future__ import annotations

import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from scanner.models import Finding

# CycloneDX 1.6 schema URL
_SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"
_BOM_FORMAT = "CycloneDX"
_SPEC_VERSION = "1.6"


def _nist_quantum_security_level(finding: Finding) -> int:
    """Return 0 for quantum-vulnerable algorithms, else None (omit)."""
    return 0 if finding.quantum_vulnerable else None


def export_cbom(findings: List[Finding], out_dir: Path) -> Path:
    """Write a CycloneDX 1.6 CBOM to *out_dir*/cbom.json and return the path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "cbom.json"

    # Group findings by algorithm (case-insensitive key)
    by_algorithm: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_algorithm[f.algorithm.upper()].append(f)

    components = []
    for algo_key, algo_findings in sorted(by_algorithm.items()):
        # Representative finding for metadata (all share the same algorithm)
        rep = algo_findings[0]

        crypto_props: dict = {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": rep.primitive,
            },
        }
        nqsl = _nist_quantum_security_level(rep)
        if nqsl is not None:
            crypto_props["algorithmProperties"]["nistQuantumSecurityLevel"] = nqsl

        occurrences = [
            {"location": f"{f.file}:{f.line}"}
            for f in algo_findings
        ]

        component = {
            "type": "cryptographic-asset",
            "bom-ref": str(uuid.uuid4()),
            "name": rep.algorithm,
            "cryptoProperties": crypto_props,
            "occurrences": occurrences,
        }
        components.append(component)

    bom = {
        "$schema": _SCHEMA,
        "bomFormat": _BOM_FORMAT,
        "specVersion": _SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"name": "qsafe-scanner"}],
        },
        "components": components,
    }

    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)

    return out_file
