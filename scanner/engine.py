"""File walker and regex rule matcher for the QSafe scanner."""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Dict, Generator, List, Tuple

from scanner.ast_extractor import extract_key_sizes
from scanner.loader import Rule
from scanner.models import Finding

# Extension → language mapping
_EXT_LANG: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".java": "java",
    ".conf": "config",
    ".yaml": "config",
    ".yml": "config",
}

# Directories to skip wholesale
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", ".tox"}

# Extensions treated as binary (skip)
_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".zip", ".tar", ".gz", ".bz2", ".whl", ".egg",
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".pdf",
    ".class", ".jar",
}

# usage → primitive label
_USAGE_PRIMITIVE: Dict[str, str] = {
    "key_exchange": "asymmetric-key-exchange",
    "signature": "digital-signature",
    "encryption": "asymmetric-encryption",
    "hash": "hash",
    "symmetric": "symmetric-encryption",
}


def _severity(usage: str, quantum_vulnerable: bool) -> str:
    """Derive severity from usage and quantum_vulnerable flag."""
    if quantum_vulnerable:
        if usage in ("key_exchange", "encryption"):
            return "CRITICAL"
        if usage == "signature":
            return "HIGH"
    if usage in ("hash", "symmetric"):
        return "MEDIUM"
    return "LOW"


def walk_path(root: str | Path) -> Generator[Tuple[str, str], None, None]:
    """Yield (filepath, lang) for every scannable file under *root*."""
    root = str(root)
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place so os.walk won't descend into them
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in _BINARY_EXTS:
                continue
            lang = _EXT_LANG.get(ext)
            if lang is None:
                continue
            yield os.path.join(dirpath, fname), lang


def match_rules(
    filepath: str,
    lang: str,
    rules_index: Dict[str, List[Rule]],
) -> List[Finding]:
    """Scan *filepath* against rules for *lang* and return findings."""
    rules = rules_index.get(lang, [])
    if not rules:
        return []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError:
        return []

    lines = source.splitlines()

    # Pre-compute key_size map for Python files
    key_sizes: Dict[int, int] = {}
    if lang == "python":
        key_sizes = extract_key_sizes(source)

    findings: List[Finding] = []
    for rule in rules:
        for lineno, line in enumerate(lines, start=1):
            if rule.regex.search(line):
                # Try to find key_size on this or the next few lines
                key_size = key_sizes.get(lineno)
                if key_size is None:
                    # also check ±1 line (multiline calls)
                    key_size = key_sizes.get(lineno - 1) or key_sizes.get(lineno + 1)

                finding = Finding(
                    id=str(uuid.uuid4()),
                    rule_id=rule.id,
                    file=filepath,
                    line=lineno,
                    algorithm=rule.algorithm,
                    primitive=_USAGE_PRIMITIVE.get(rule.usage, rule.usage),
                    key_size=key_size,
                    quantum_vulnerable=rule.quantum_vulnerable,
                    severity=_severity(rule.usage, rule.quantum_vulnerable),
                    recommendation=f"Replace {rule.algorithm} with {rule.replacement}",
                    nist_replacement=rule.replacement,
                )
                findings.append(finding)
    return findings


def scan_path(
    root: str | Path,
    rules_index: Dict[str, List[Rule]],
) -> List[Finding]:
    """Walk *root* and return all findings."""
    all_findings: List[Finding] = []
    for filepath, lang in walk_path(root):
        all_findings.extend(match_rules(filepath, lang, rules_index))
    return all_findings
