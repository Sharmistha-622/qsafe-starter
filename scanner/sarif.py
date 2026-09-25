"""Export findings as a SARIF 2.1.0 report (reports/results.sarif)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from scanner.models import Finding

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_TOOL_NAME = "qsafe-scanner"
_TOOL_VERSION = "1.0.0"


def _level(severity: str) -> str:
    """Map finding severity to SARIF level."""
    if severity in ("CRITICAL", "HIGH"):
        return "error"
    return "warning"


def export_sarif(findings: List[Finding], out_dir: Path) -> Path:
    """Write a SARIF 2.1.0 report to *out_dir*/results.sarif and return the path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "results.sarif"

    # Collect unique rules
    seen_rules: dict[str, dict] = {}
    for f in findings:
        if f.rule_id not in seen_rules:
            seen_rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.algorithm,
                "shortDescription": {"text": f.recommendation},
                "help": {"text": f"Replace with: {f.nist_replacement}"},
            }

    results = []
    for f in findings:
        result = {
            "ruleId": f.rule_id,
            "level": _level(f.severity),
            "message": {
                "text": (
                    f"{f.algorithm} is quantum-vulnerable. "
                    f"Severity: {f.severity}. "
                    f"Recommended replacement: {f.nist_replacement}."
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line},
                    }
                }
            ],
        }
        results.append(result)

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "rules": list(seen_rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)

    return out_file
