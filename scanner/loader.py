"""Load and validate scanner/rules.yaml into typed Rule dataclasses."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import yaml

RULES_PATH = Path(__file__).parent / "rules.yaml"


@dataclass
class Rule:
    """A single detection rule loaded from rules.yaml."""

    id: str
    lang: str
    pattern: str
    algorithm: str
    usage: str
    quantum_vulnerable: bool
    replacement: str
    _compiled: re.Pattern = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.pattern)

    @property
    def regex(self) -> re.Pattern:
        """Return compiled regex for this rule."""
        return self._compiled


def load_rules(path: Path = RULES_PATH) -> Dict[str, List[Rule]]:
    """Load rules.yaml and return a {lang: [Rule]} index.

    Unknown or missing fields are ignored gracefully.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    index: Dict[str, List[Rule]] = {}
    for entry in data.get("rules", []):
        rule = Rule(
            id=entry["id"],
            lang=entry["lang"],
            pattern=entry["pattern"],
            algorithm=entry["algorithm"],
            usage=entry["usage"],
            quantum_vulnerable=bool(entry.get("quantum_vulnerable", False)),
            replacement=entry.get("replacement", ""),
        )
        index.setdefault(rule.lang, []).append(rule)
    return index
