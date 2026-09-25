"""Tests for scanner/cbom.py and scanner/sarif.py exporters."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.cbom import export_cbom
from scanner.models import Finding
from scanner.sarif import export_sarif

DEMO_APP = Path(__file__).parent.parent / "demo_vulnerable_app"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    fid: str = "test-1",
    rule_id: str = "PY-RSA-GEN",
    file: str = "app/crypto.py",
    line: int = 42,
    algorithm: str = "RSA",
    primitive: str = "asymmetric-key-exchange",
    key_size: int | None = 2048,
    quantum_vulnerable: bool = True,
    severity: str = "CRITICAL",
    recommendation: str = "Migrate to ML-KEM-768",
    nist_replacement: str = "ML-KEM-768",
) -> Finding:
    return Finding(
        id=fid,
        rule_id=rule_id,
        file=file,
        line=line,
        algorithm=algorithm,
        primitive=primitive,
        key_size=key_size,
        quantum_vulnerable=quantum_vulnerable,
        severity=severity,
        recommendation=recommendation,
        nist_replacement=nist_replacement,
    )


# ---------------------------------------------------------------------------
# CBOM exporter tests
# ---------------------------------------------------------------------------


class TestExportCbom:
    def test_creates_cbom_file(self, tmp_path: Path) -> None:
        """export_cbom must create cbom.json in the given directory."""
        findings = [_make_finding()]
        out = export_cbom(findings, tmp_path)
        assert out == tmp_path / "cbom.json"
        assert out.exists()

    def test_cbom_top_level_fields(self, tmp_path: Path) -> None:
        """Top-level BOM fields must match CycloneDX 1.6."""
        export_cbom([_make_finding()], tmp_path)
        bom = json.loads((tmp_path / "cbom.json").read_text())
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.6"
        assert bom["version"] == 1
        assert bom["serialNumber"].startswith("urn:uuid:")

    def test_cbom_one_component_per_algorithm(self, tmp_path: Path) -> None:
        """Two findings for RSA + one for ECDH → 2 components."""
        findings = [
            _make_finding(fid="1", algorithm="RSA", line=10),
            _make_finding(fid="2", algorithm="RSA", line=20),
            _make_finding(
                fid="3",
                algorithm="ECDH",
                primitive="asymmetric-key-exchange",
                nist_replacement="ML-KEM-768",
                severity="CRITICAL",
                line=30,
            ),
        ]
        export_cbom(findings, tmp_path)
        bom = json.loads((tmp_path / "cbom.json").read_text())
        assert len(bom["components"]) == 2

    def test_cbom_component_type_is_cryptographic_asset(self, tmp_path: Path) -> None:
        """Every component must have type 'cryptographic-asset'."""
        export_cbom([_make_finding()], tmp_path)
        bom = json.loads((tmp_path / "cbom.json").read_text())
        for comp in bom["components"]:
            assert comp["type"] == "cryptographic-asset"

    def test_cbom_crypto_properties_structure(self, tmp_path: Path) -> None:
        """cryptoProperties must include assetType and primitive."""
        export_cbom([_make_finding()], tmp_path)
        bom = json.loads((tmp_path / "cbom.json").read_text())
        cp = bom["components"][0]["cryptoProperties"]
        assert cp["assetType"] == "algorithm"
        assert "primitive" in cp["algorithmProperties"]

    def test_cbom_quantum_vulnerable_has_level_zero(self, tmp_path: Path) -> None:
        """Quantum-vulnerable algorithms must have nistQuantumSecurityLevel == 0."""
        export_cbom([_make_finding(quantum_vulnerable=True)], tmp_path)
        bom = json.loads((tmp_path / "cbom.json").read_text())
        cp = bom["components"][0]["cryptoProperties"]
        assert cp["algorithmProperties"]["nistQuantumSecurityLevel"] == 0

    def test_cbom_non_vulnerable_omits_level(self, tmp_path: Path) -> None:
        """Non-quantum-vulnerable algorithms must NOT include nistQuantumSecurityLevel."""
        export_cbom(
            [_make_finding(quantum_vulnerable=False, severity="MEDIUM")], tmp_path
        )
        bom = json.loads((tmp_path / "cbom.json").read_text())
        cp = bom["components"][0]["cryptoProperties"]
        assert "nistQuantumSecurityLevel" not in cp["algorithmProperties"]

    def test_cbom_occurrences_contain_file_and_line(self, tmp_path: Path) -> None:
        """Each occurrence must be 'file:line' formatted."""
        f = _make_finding(file="services/auth.py", line=99)
        export_cbom([f], tmp_path)
        bom = json.loads((tmp_path / "cbom.json").read_text())
        occurrences = bom["components"][0]["occurrences"]
        assert len(occurrences) == 1
        assert occurrences[0]["location"] == "services/auth.py:99"

    def test_cbom_multiple_occurrences_same_algorithm(self, tmp_path: Path) -> None:
        """Multiple findings for the same algorithm → multiple occurrences."""
        findings = [
            _make_finding(fid="a", file="a.py", line=1),
            _make_finding(fid="b", file="b.py", line=2),
        ]
        export_cbom(findings, tmp_path)
        bom = json.loads((tmp_path / "cbom.json").read_text())
        assert len(bom["components"][0]["occurrences"]) == 2

    def test_cbom_empty_findings_produces_no_components(self, tmp_path: Path) -> None:
        """Empty findings list → components array is empty."""
        export_cbom([], tmp_path)
        bom = json.loads((tmp_path / "cbom.json").read_text())
        assert bom["components"] == []


# ---------------------------------------------------------------------------
# SARIF exporter tests
# ---------------------------------------------------------------------------


class TestExportSarif:
    def test_creates_sarif_file(self, tmp_path: Path) -> None:
        """export_sarif must create results.sarif in the given directory."""
        out = export_sarif([_make_finding()], tmp_path)
        assert out == tmp_path / "results.sarif"
        assert out.exists()

    def test_sarif_top_level_fields(self, tmp_path: Path) -> None:
        """version must be '2.1.0'."""
        export_sarif([_make_finding()], tmp_path)
        sarif = json.loads((tmp_path / "results.sarif").read_text())
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1

    def test_sarif_one_result_per_finding(self, tmp_path: Path) -> None:
        """Each finding produces exactly one SARIF result."""
        findings = [_make_finding(fid="1"), _make_finding(fid="2", line=100)]
        export_sarif(findings, tmp_path)
        sarif = json.loads((tmp_path / "results.sarif").read_text())
        assert len(sarif["runs"][0]["results"]) == 2

    def test_sarif_critical_maps_to_error(self, tmp_path: Path) -> None:
        """CRITICAL severity → SARIF level 'error'."""
        export_sarif([_make_finding(severity="CRITICAL")], tmp_path)
        sarif = json.loads((tmp_path / "results.sarif").read_text())
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_high_maps_to_error(self, tmp_path: Path) -> None:
        """HIGH severity → SARIF level 'error'."""
        export_sarif([_make_finding(severity="HIGH")], tmp_path)
        sarif = json.loads((tmp_path / "results.sarif").read_text())
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_medium_maps_to_warning(self, tmp_path: Path) -> None:
        """MEDIUM severity → SARIF level 'warning'."""
        export_sarif([_make_finding(severity="MEDIUM", quantum_vulnerable=False)], tmp_path)
        sarif = json.loads((tmp_path / "results.sarif").read_text())
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_sarif_low_maps_to_warning(self, tmp_path: Path) -> None:
        """LOW severity → SARIF level 'warning'."""
        export_sarif([_make_finding(severity="LOW", quantum_vulnerable=False)], tmp_path)
        sarif = json.loads((tmp_path / "results.sarif").read_text())
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_sarif_result_has_rule_id(self, tmp_path: Path) -> None:
        """Each result must include ruleId."""
        export_sarif([_make_finding(rule_id="PY-RSA-GEN")], tmp_path)
        sarif = json.loads((tmp_path / "results.sarif").read_text())
        assert sarif["runs"][0]["results"][0]["ruleId"] == "PY-RSA-GEN"

    def test_sarif_result_has_message(self, tmp_path: Path) -> None:
        """Each result must include a non-empty message text."""
        export_sarif([_make_finding()], tmp_path)
        sarif = json.loads((tmp_path / "results.sarif").read_text())
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert len(msg) > 0

    def test_sarif_location_file_and_line(self, tmp_path: Path) -> None:
        """Location must include the source file URI and start line."""
        export_sarif([_make_finding(file="auth/login.py", line=77)], tmp_path)
        sarif = json.loads((tmp_path / "results.sarif").read_text())
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "auth/login.py"
        assert loc["region"]["startLine"] == 77

    def test_sarif_rules_deduplicated(self, tmp_path: Path) -> None:
        """Multiple findings with the same rule_id → one rule entry."""
        findings = [
            _make_finding(fid="1", rule_id="PY-RSA-GEN", line=1),
            _make_finding(fid="2", rule_id="PY-RSA-GEN", line=2),
        ]
        export_sarif(findings, tmp_path)
        sarif = json.loads((tmp_path / "results.sarif").read_text())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "PY-RSA-GEN"

    def test_sarif_empty_findings(self, tmp_path: Path) -> None:
        """Empty findings list → empty results array."""
        export_sarif([], tmp_path)
        sarif = json.loads((tmp_path / "results.sarif").read_text())
        assert sarif["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# Integration: scan command writes both outputs
# ---------------------------------------------------------------------------


class TestScanCommandExportsAll:
    def test_scan_produces_cbom(self, tmp_path: Path) -> None:
        """scan command must write cbom.json alongside findings.json."""
        from scanner.cli import main

        exit_code = main(["scan", str(DEMO_APP), "--out", str(tmp_path)])
        assert exit_code == 0
        assert (tmp_path / "cbom.json").exists()

    def test_scan_produces_sarif(self, tmp_path: Path) -> None:
        """scan command must write results.sarif alongside findings.json."""
        from scanner.cli import main

        exit_code = main(["scan", str(DEMO_APP), "--out", str(tmp_path)])
        assert exit_code == 0
        assert (tmp_path / "results.sarif").exists()

    def test_scan_cbom_valid_cyclonedx(self, tmp_path: Path) -> None:
        """cbom.json from demo scan must be valid CycloneDX 1.6 structure."""
        from scanner.cli import main

        main(["scan", str(DEMO_APP), "--out", str(tmp_path)])
        bom = json.loads((tmp_path / "cbom.json").read_text())
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.6"
        assert len(bom["components"]) >= 1

    def test_scan_sarif_valid_structure(self, tmp_path: Path) -> None:
        """results.sarif from demo scan must have SARIF 2.1.0 structure."""
        from scanner.cli import main

        main(["scan", str(DEMO_APP), "--out", str(tmp_path)])
        sarif = json.loads((tmp_path / "results.sarif").read_text())
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) >= 1
