"""Mosca-based Quantum Readiness Score calculator."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Union

from scanner.models import Finding

# Usage → weight mapping
_USAGE_WEIGHT: Dict[str, int] = {
    "asymmetric-key-exchange": 10,
    "asymmetric-encryption": 10,
    "digital-signature": 7,
    "symmetric-encryption": 3,
    "hash": 2,
}

# primitive fallback for any unmapped value
_DEFAULT_WEIGHT = 2


def _verdict(score: int) -> str:
    """Map 0–100 score to a verdict string."""
    if score <= 25:
        return "CRITICAL"
    if score <= 50:
        return "AT RISK"
    if score <= 75:
        return "IMPROVING"
    return "QUANTUM READY"


def compute_score(
    findings: List[Finding],
    X: int = 7,
    Y: int = 5,
    Z: int = 10,
) -> Dict:
    """Apply the Mosca formula and return score dict.

    Parameters
    ----------
    findings : list of Finding
    X : data lifetime in years (default 7)
    Y : migration time in years (default 5)
    Z : years to cryptographically relevant quantum computer (default 10)

    Returns
    -------
    dict with keys: score (int), verdict (str), per_finding (list)
    """
    if not findings:
        return {"score": 100, "verdict": "QUANTUM READY", "per_finding": []}

    mosca_multiplier = 1.0 if (X + Y) > Z else 0.4

    per_finding = []
    total_risk = 0.0
    max_possible = 0.0

    for f in findings:
        weight = _USAGE_WEIGHT.get(f.primitive, _DEFAULT_WEIGHT)
        risk = weight * mosca_multiplier
        max_risk = weight * 1.0  # full multiplier
        total_risk += risk
        max_possible += max_risk
        per_finding.append(
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "algorithm": f.algorithm,
                "severity": f.severity,
                "weight": weight,
                "risk": risk,
            }
        )

    raw = (total_risk / max_possible) * 100 if max_possible else 0.0
    score = int(round(max(0, min(100, 100 - raw))))
    return {
        "score": score,
        "verdict": _verdict(score),
        "per_finding": per_finding,
    }


def load_findings(path: Union[str, Path]) -> List[Finding]:
    """Load a findings.json file and return a list of Finding objects."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return [Finding.from_dict(d) for d in data]
