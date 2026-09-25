"""QSafe Dashboard — Streamlit front-end for the quantum-vulnerability scanner."""
from __future__ import annotations
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import json
import subprocess
import sys
from pathlib import Path

import streamlit as st

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="QSafe Scanner",
    page_icon="🔐",
    layout="wide",
)

REPO_ROOT = Path(__file__).parent.parent
REPORTS_DIR = REPO_ROOT / "reports"
MIGRATED_REPORTS_DIR = REPORTS_DIR / "migrated"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_scan(folder: str, out_dir: Path) -> tuple[bool, str]:
    """Run the scanner CLI and return (success, output_text)."""
    result = subprocess.run(
        [sys.executable, "-m", "scanner.cli", "scan", folder, "--out", str(out_dir)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    output = result.stdout + result.stderr
    return result.returncode == 0, output


def _load_findings(findings_path: Path) -> list[dict]:
    """Load findings.json and return a list of dicts (empty list on missing file)."""
    if not findings_path.exists():
        return []
    return json.loads(findings_path.read_text(encoding="utf-8"))


def _compute_score(findings_dicts: list[dict], X: int, Y: int, Z: int) -> dict:
    """Convert raw finding dicts → Finding objects and call scorer."""
    from scanner.models import Finding
    from scanner.scorer import compute_score

    findings = [Finding.from_dict(d) for d in findings_dicts]
    return compute_score(findings, X=X, Y=Y, Z=Z)


_SEVERITY_COLOUR = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#27ae60",
}

_VERDICT_COLOUR = {
    "CRITICAL": "#c0392b",
    "AT RISK": "#e67e22",
    "IMPROVING": "#2980b9",
    "QUANTUM READY": "#27ae60",
}


def _colour_row(row: dict) -> list[str]:
    colour = _SEVERITY_COLOUR.get(row.get("severity", ""), "#888888")
    return [f"background-color: {colour}22; color: {colour}; font-weight:600"] * len(row)


def _score_gauge(score: int, verdict: str, label: str = "") -> None:
    """Render a big score number with verdict badge."""
    colour = _VERDICT_COLOUR.get(verdict, "#888")
    label_html = (
        f"<p style='color:#888;font-size:0.85rem;margin-bottom:0'>{label}</p>"
        if label else ""
    )
    badge_style = (
        "display:inline-block;"
        "margin-top:0.5rem;"
        "padding:0.3rem 1.1rem;"
        "border-radius:999px;"
        f"background:{colour}22;"
        f"color:{colour};"
        "font-weight:700;"
        "font-size:1.05rem;"
        "letter-spacing:0.05em;"
    )
    html = (
        "<div style='text-align:center;padding:1rem 0;'>"
        + label_html
        + f"<span style='font-size:4.5rem;font-weight:800;color:{colour};line-height:1'>{score}</span>"
        + "<span style='font-size:1.5rem;color:#888'>/100</span><br>"
        + f"<span style='{badge_style}'>{verdict}</span>"
        + "</div>"
    )
    st.markdown(html, unsafe_allow_html=True)


def _findings_table(findings: list[dict]) -> None:
    """Render a colour-coded severity table."""
    import pandas as pd

    if not findings:
        st.info("No findings — this folder looks quantum-safe! 🎉")
        return

    display_cols = ["severity", "algorithm", "primitive", "file", "line", "rule_id", "recommendation"]
    rows = [{k: f.get(k, "") for k in display_cols} for f in findings]
    df = pd.DataFrame(rows)

    # severity ordering for sort
    _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    df["_sort"] = df["severity"].map(_order).fillna(9)
    df = df.sort_values("_sort").drop(columns=["_sort"])

    styled = df.style.apply(_colour_row, axis=1)
    st.dataframe(styled, use_container_width=True, hide_index=True)


def _bar_chart(findings: list[dict]) -> None:
    """Render a bar chart of findings per file using st.bar_chart."""
    import pandas as pd

    if not findings:
        return

    counts: dict[str, int] = {}
    for f in findings:
        short = Path(f.get("file", "unknown")).name
        counts[short] = counts.get(short, 0) + 1

    df = pd.DataFrame(
        {"file": list(counts.keys()), "findings": list(counts.values())}
    ).set_index("file")
    st.bar_chart(df, height=260)


def _download_cbom(cbom_path: Path) -> None:
    if cbom_path.exists():
        st.download_button(
            label="⬇️  Download CBOM (CycloneDX 1.6)",
            data=cbom_path.read_bytes(),
            file_name="cbom.json",
            mime="application/json",
        )
    else:
        st.caption("CBOM not yet generated — run a scan first.")


# ---------------------------------------------------------------------------
# Tab: Scan
# ---------------------------------------------------------------------------


def tab_scan() -> None:
    st.header("🔍 Quantum-Vulnerability Scan")

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        folder = st.text_input(
            "Folder to scan",
            value="demo_vulnerable_app",
            placeholder="e.g. demo_vulnerable_app  or  /absolute/path",
        )
    with col_btn:
        st.markdown("<div style='padding-top:1.75rem'>", unsafe_allow_html=True)
        run_scan = st.button("▶  Run Scan", type="primary", use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    # ---- run scan ----
    if run_scan:
        with st.spinner(f"Scanning {folder} …"):
            ok, output = _run_scan(folder, REPORTS_DIR)
        if ok:
            st.success(output.strip())
            st.session_state["findings"] = _load_findings(REPORTS_DIR / "findings.json")
        else:
            st.error(f"Scan failed:\n```\n{output}\n```")
            return

    # ---- load findings (from session or from disk) ----
    if "findings" not in st.session_state:
        st.session_state["findings"] = _load_findings(REPORTS_DIR / "findings.json")

    findings = st.session_state["findings"]

    if not findings and not (REPORTS_DIR / "findings.json").exists():
        st.info("Press **Run Scan** to analyse a folder.")
        return

    # ---- Mosca sliders ----
    st.subheader("⚙️  Mosca Parameters")
    c1, c2, c3 = st.columns(3)
    with c1:
        X = st.slider("X — Data lifetime (years)", 1, 20, 7,
                      help="How long does your sensitive data need protection?")
    with c2:
        Y = st.slider("Y — Migration time (years)", 1, 15, 5,
                      help="How long will it take you to migrate?")
    with c3:
        Z = st.slider("Z — Years to quantum computer", 1, 30, 10,
                      help="When do you expect a cryptographically relevant quantum computer?")

    mosca_alert = (X + Y) > Z
    if mosca_alert:
        st.warning(
            f"⚠️  **Mosca inequality triggered** (X+Y={X+Y} > Z={Z}): "
            "you will not finish migrating before a quantum computer can break your crypto."
        )

    # ---- Score ----
    result = _compute_score(findings, X, Y, Z)
    score, verdict = result["score"], result["verdict"]

    st.subheader("📊 Quantum Readiness Score")
    _score_gauge(score, verdict)

    # ---- Findings table ----
    st.subheader(f"🗂  Findings ({len(findings)} total)")
    _findings_table(findings)

    # ---- Bar chart ----
    if findings:
        st.subheader("📁 Findings per file")
        _bar_chart(findings)

    # ---- CBOM download ----
    st.subheader("📦 CycloneDX CBOM")
    _download_cbom(REPORTS_DIR / "cbom.json")


# ---------------------------------------------------------------------------
# Tab: Before vs After
# ---------------------------------------------------------------------------


def tab_before_after() -> None:
    st.header("↔️  Before vs After Migration")
    st.markdown(
        "Comparing **`demo_vulnerable_app/`** (original, quantum-vulnerable) "
        "with **`migrated/`** (post-quantum hybrid)."
    )

    # Ensure both reports exist; generate on demand
    before_path = REPORTS_DIR / "findings.json"
    after_path = MIGRATED_REPORTS_DIR / "findings.json"

    needs_scan = []
    if not before_path.exists():
        needs_scan.append(("demo_vulnerable_app", REPORTS_DIR))
    if not after_path.exists():
        needs_scan.append(("migrated", MIGRATED_REPORTS_DIR))

    if needs_scan:
        with st.spinner("Generating missing reports …"):
            for folder, out_dir in needs_scan:
                _run_scan(folder, out_dir)

    before_findings = _load_findings(before_path)
    after_findings = _load_findings(after_path)

    # ---- Score cards ----
    col_b, col_sep, col_a = st.columns([5, 1, 5])

    with col_b:
        st.markdown("### 🔴 Before")
        br = _compute_score(before_findings, X=7, Y=5, Z=10)
        _score_gauge(br["score"], br["verdict"], "demo_vulnerable_app/")
        st.metric("Findings", len(before_findings), delta=None)
        crit_b = sum(1 for f in before_findings if f.get("severity") == "CRITICAL")
        st.metric("CRITICAL", crit_b)

    with col_sep:
        st.markdown(
            "<div style='text-align:center;font-size:2.5rem;padding-top:3rem;color:#888'>→</div>",
            unsafe_allow_html=True,
        )

    with col_a:
        st.markdown("### 🟢 After")
        ar = _compute_score(after_findings, X=7, Y=5, Z=10)
        _score_gauge(ar["score"], ar["verdict"], "migrated/")
        delta_findings = len(after_findings) - len(before_findings)
        st.metric("Findings", len(after_findings), delta=delta_findings,
                  delta_color="inverse")
        crit_a = sum(1 for f in after_findings if f.get("severity") == "CRITICAL")
        st.metric("CRITICAL", crit_a, delta=crit_a - crit_b, delta_color="inverse")

    st.divider()

    # ---- Side-by-side findings tables ----
    col_tb, col_ta = st.columns(2)
    with col_tb:
        st.markdown("**Before — findings**")
        _findings_table(before_findings)
    with col_ta:
        st.markdown("**After — findings**")
        _findings_table(after_findings)

    st.divider()

    # ---- Bar charts ----
    col_cb, col_ca = st.columns(2)
    with col_cb:
        st.markdown("**Before — findings per file**")
        _bar_chart(before_findings)
    with col_ca:
        st.markdown("**After — findings per file**")
        if not after_findings:
            st.success("Zero findings — QUANTUM READY 🎉")

    # ---- What changed callout ----
    st.subheader("🔧 What changed")
    st.markdown(
        """
| | Before (`payments_service.py`) | After (`payments_service_pqc.py`) |
|---|---|---|
| **Key encapsulation** | RSA-2048 OAEP | X25519 + ML-KEM-768 (FIPS 203) |
| **Symmetric cipher** | embedded in RSA | AES-256-GCM |
| **Key derivation** | none | HKDF-SHA-256 |
| **Crypto agility** | ❌ hard-coded | ✅ `backend=` kwarg + env var |
| **Quantum-safe** | ❌ | ✅ (ML-KEM stub ready for liboqs) |
        """
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    st.title("🔐 QSafe — Quantum-Safety Scanner")
    st.caption(
        "Detect quantum-vulnerable cryptography · Score your risk · Plan your PQC migration"
    )

    tab1, tab2 = st.tabs(["🔍 Scan", "↔️ Before vs After"])
    with tab1:
        tab_scan()
    with tab2:
        tab_before_after()


main()
