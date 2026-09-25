"""Tests for QSafe CLI: scan, score formula, and score command."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from scanner.models import Finding
from scanner.scorer import compute_score

DEMO_APP = Path(__file__).parent.parent / "demo_vulnerable_app"
SCANNER_PKG = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_finding(primitive: str, quantum_vulnerable: bool = True) -> Finding:
    """Return a minimal Finding with the given primitive."""
    return Finding(
        id="test-id",
        rule_id="TEST",
        file="test.py",
        line=1,
        algorithm="RSA",
        primitive=primitive,
        key_size=None,
        quantum_vulnerable=quantum_vulnerable,
        severity="CRITICAL" if quantum_vulnerable else "MEDIUM",
        recommendation="replace",
        nist_replacement="ML-KEM-768",
    )


# ---------------------------------------------------------------------------
# test_score_formula — deterministic unit test
# ---------------------------------------------------------------------------

class TestScoreFormula:
    def test_no_findings_gives_100(self):
        result = compute_score([])
        assert result["score"] == 100
        assert result["verdict"] == "QUANTUM READY"

    def test_single_key_exchange_urgent(self):
        # X+Y=12 > Z=10 → multiplier 1.0 → full risk → score = 0
        findings = [_make_finding("asymmetric-key-exchange")]
        result = compute_score(findings, X=7, Y=5, Z=10)
        # risk=10, max=10 → raw=100 → score=0
        assert result["score"] == 0
        assert result["verdict"] == "CRITICAL"

    def test_not_urgent_reduces_risk(self):
        # X+Y=8 <= Z=10 → multiplier 0.4
        # risk=10*0.4=4, max=10 → raw=40 → score=60
        findings = [_make_finding("asymmetric-key-exchange")]
        result = compute_score(findings, X=3, Y=5, Z=10)
        assert result["score"] == 60
        assert result["verdict"] == "IMPROVING"

    def test_mixed_findings_score(self):
        # Two findings: key_exchange (weight 10) + hash (weight 2)
        # X+Y=12 > Z=10 → multiplier 1.0
        # total_risk=12, max_possible=12 → raw=100 → score=0
        findings = [
            _make_finding("asymmetric-key-exchange"),
            _make_finding("hash", quantum_vulnerable=False),
        ]
        result = compute_score(findings, X=7, Y=5, Z=10)
        assert result["score"] == 0
        assert result["verdict"] == "CRITICAL"

    def test_verdicts(self):
        verdicts = {
            0: "CRITICAL",
            25: "CRITICAL",
            26: "AT RISK",
            50: "AT RISK",
            51: "IMPROVING",
            75: "IMPROVING",
            76: "QUANTUM READY",
            100: "QUANTUM READY",
        }
        from scanner.scorer import _verdict
        for score, expected in verdicts.items():
            assert _verdict(score) == expected, f"score={score}"

    def test_per_finding_breakdown(self):
        findings = [_make_finding("digital-signature")]
        result = compute_score(findings, X=7, Y=5, Z=10)
        assert len(result["per_finding"]) == 1
        pf = result["per_finding"][0]
        assert pf["weight"] == 7
        assert pf["risk"] == 7.0


# ---------------------------------------------------------------------------
# test_scan_demo_app — integration test
# ---------------------------------------------------------------------------

class TestScanDemoApp:
    def test_scan_produces_findings(self, tmp_path):
        """scan against demo_vulnerable_app/ must write findings.json with ≥1 finding."""
        from scanner.cli import main

        out_dir = tmp_path / "reports"
        exit_code = main(["scan", str(DEMO_APP), "--out", str(out_dir)])
        assert exit_code == 0

        findings_file = out_dir / "findings.json"
        assert findings_file.exists(), "findings.json was not created"

        findings = json.loads(findings_file.read_text())
        assert len(findings) >= 1, "Expected at least one finding"

    def test_scan_finds_python_findings(self, tmp_path):
        out_dir = tmp_path / "reports"
        from scanner.cli import main
        main(["scan", str(DEMO_APP), "--out", str(out_dir)])
        findings = json.loads((out_dir / "findings.json").read_text())
        python_findings = [f for f in findings if f["file"].endswith(".py")]
        assert len(python_findings) >= 1, "Expected ≥1 Python finding"

    def test_scan_finds_js_findings(self, tmp_path):
        out_dir = tmp_path / "reports"
        from scanner.cli import main
        main(["scan", str(DEMO_APP), "--out", str(out_dir)])
        findings = json.loads((out_dir / "findings.json").read_text())
        js_findings = [f for f in findings if f["file"].endswith(".js")]
        assert len(js_findings) >= 1, "Expected ≥1 JavaScript finding"

    def test_scan_finds_java_findings(self, tmp_path):
        out_dir = tmp_path / "reports"
        from scanner.cli import main
        main(["scan", str(DEMO_APP), "--out", str(out_dir)])
        findings = json.loads((out_dir / "findings.json").read_text())
        java_findings = [f for f in findings if f["file"].endswith(".java")]
        assert len(java_findings) >= 1, "Expected ≥1 Java finding"

    def test_finding_schema_complete(self, tmp_path):
        """Every finding must have all required schema fields."""
        from scanner.cli import main
        out_dir = tmp_path / "reports"
        main(["scan", str(DEMO_APP), "--out", str(out_dir)])
        findings = json.loads((out_dir / "findings.json").read_text())
        required_fields = {
            "id", "rule_id", "file", "line", "algorithm", "primitive",
            "key_size", "quantum_vulnerable", "severity", "recommendation",
            "nist_replacement",
        }
        for f in findings:
            missing = required_fields - set(f.keys())
            assert not missing, f"Finding missing fields: {missing}"

    def test_key_size_extracted_for_rsa(self, tmp_path):
        """RSA finding from payments_service.py should have key_size=2048."""
        from scanner.cli import main
        out_dir = tmp_path / "reports"
        main(["scan", str(DEMO_APP), "--out", str(out_dir)])
        findings = json.loads((out_dir / "findings.json").read_text())
        rsa_py = [
            f for f in findings
            if f["rule_id"] == "PY-RSA-GEN"
        ]
        assert rsa_py, "PY-RSA-GEN finding not found"
        assert rsa_py[0]["key_size"] == 2048


# ---------------------------------------------------------------------------
# test_score_command — subprocess smoke-test
# ---------------------------------------------------------------------------

class TestScoreCommand:
    def test_score_command_exit_zero(self, tmp_path):
        """score sub-command must exit 0 and print a score line."""
        from scanner.cli import main

        # First produce findings
        out_dir = tmp_path / "reports"
        main(["scan", str(DEMO_APP), "--out", str(out_dir)])

        findings_file = out_dir / "findings.json"
        result = subprocess.run(
            [sys.executable, "-m", "scanner.cli", "score", str(findings_file)],
            capture_output=True,
            text=True,
            cwd=str(SCANNER_PKG),
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "Quantum Readiness Score:" in result.stdout
        assert "/100" in result.stdout

    def test_score_output_contains_verdict(self, tmp_path):
        """Score output must end with a known verdict string."""
        from scanner.cli import main

        out_dir = tmp_path / "reports"
        main(["scan", str(DEMO_APP), "--out", str(out_dir)])
        findings_file = out_dir / "findings.json"

        result = subprocess.run(
            [sys.executable, "-m", "scanner.cli", "score", str(findings_file)],
            capture_output=True,
            text=True,
            cwd=str(SCANNER_PKG),
        )
        verdicts = {"CRITICAL", "AT RISK", "IMPROVING", "QUANTUM READY"}
        found = any(v in result.stdout for v in verdicts)
        assert found, f"No verdict in output: {result.stdout!r}"
