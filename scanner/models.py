"""Shared data model for QSafe scanner findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """A single cryptographic finding produced by the scanner."""

    id: str
    rule_id: str
    file: str
    line: int
    algorithm: str
    primitive: str
    key_size: Optional[int]
    quantum_vulnerable: bool
    severity: str
    recommendation: str
    nist_replacement: str

    def to_dict(self) -> dict:
        """Serialise to a plain dict (JSON-safe)."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "algorithm": self.algorithm,
            "primitive": self.primitive,
            "key_size": self.key_size,
            "quantum_vulnerable": self.quantum_vulnerable,
            "severity": self.severity,
            "recommendation": self.recommendation,
            "nist_replacement": self.nist_replacement,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        """Deserialise from a plain dict."""
        return cls(
            id=d["id"],
            rule_id=d["rule_id"],
            file=d["file"],
            line=d["line"],
            algorithm=d["algorithm"],
            primitive=d["primitive"],
            key_size=d.get("key_size"),
            quantum_vulnerable=d["quantum_vulnerable"],
            severity=d["severity"],
            recommendation=d["recommendation"],
            nist_replacement=d["nist_replacement"],
        )
