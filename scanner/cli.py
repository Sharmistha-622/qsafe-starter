"""QSafe CLI — scan and score sub-commands."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan sub-command."""
    from scanner.engine import scan_path
    from scanner.loader import load_rules

    rules_index = load_rules()
    findings = scan_path(args.path, rules_index)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "findings.json"

    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in findings], fh, indent=2)

    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    scanned = _count_files(args.path)
    print(
        f"Scanned {scanned} files — {len(findings)} findings ({critical_count} critical)"
    )
    print(f"Findings written to {out_file}")
    return 0


def _count_files(root: str) -> int:
    """Count scannable files under root (mirrors engine.walk_path logic)."""
    from scanner.engine import walk_path

    return sum(1 for _ in walk_path(root))


def _cmd_score(args: argparse.Namespace) -> int:
    """Execute the score sub-command."""
    from scanner.scorer import compute_score, load_findings

    findings = load_findings(args.findings_file)
    result = compute_score(
        findings,
        X=args.data_lifetime,
        Y=args.migration_years,
        Z=args.quantum_years,
    )
    score = result["score"]
    verdict = result["verdict"]
    print(f"Quantum Readiness Score: {score}/100 — {verdict}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="QSafe Scanner — quantum-vulnerability detector",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan sub-command
    scan_p = sub.add_parser("scan", help="Scan a source tree for quantum-vulnerable crypto")
    scan_p.add_argument("path", help="Root directory to scan")
    scan_p.add_argument(
        "--out",
        default="reports/",
        help="Output directory for findings.json (default: reports/)",
    )

    # score sub-command
    score_p = sub.add_parser("score", help="Compute Quantum Readiness Score from findings.json")
    score_p.add_argument("findings_file", help="Path to findings.json")
    score_p.add_argument(
        "--data-lifetime",
        dest="data_lifetime",
        type=int,
        default=7,
        metavar="X",
        help="Data lifetime in years (default: 7)",
    )
    score_p.add_argument(
        "--migration-years",
        dest="migration_years",
        type=int,
        default=5,
        metavar="Y",
        help="Migration time in years (default: 5)",
    )
    score_p.add_argument(
        "--quantum-years",
        dest="quantum_years",
        type=int,
        default=10,
        metavar="Z",
        help="Years to cryptographically relevant quantum computer (default: 10)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "score":
        return _cmd_score(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
