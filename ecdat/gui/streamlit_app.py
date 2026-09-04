from __future__ import annotations

import io
import sys
import tempfile
import zipfile
from pathlib import Path

import pandas as pd
import streamlit as st

from ecdat.core.orchestrator import run_scan
from ecdat.domain.models import MoscaInputs, ScanResult
from ecdat.domain.posture import build_posture
from ecdat.domain.risk import assess
from ecdat.reporters.cbom import to_cbom
from ecdat.reporters.json_out import to_json
from ecdat.reporters.report import render_html
from ecdat.reporters.sarif import to_sarif

st.set_page_config(page_title="ECDAT Console", layout="wide", page_icon="🔐")

_SEV = {"safe": "#2f7c50", "weakened": "#9a6700", "vulnerable": "#bc4c00",
        "broken": "#cf222e", "unknown": "#6a747d"}


def _default_result_path() -> str | None:
    for a in reversed(sys.argv):
        if a.endswith(".json") and Path(a).exists():
            return a
    p = Path("ecdat-out/result.json")
    return str(p) if p.exists() else None


def _get_result() -> ScanResult | None:
    if "result_json" in st.session_state:
        return ScanResult.model_validate_json(st.session_state["result_json"])
    dp = _default_result_path()
    if dp:
        return ScanResult.model_validate_json(Path(dp).read_text())
    return None


def _store(result: ScanResult) -> None:
    st.session_state["result_json"] = result.model_dump_json()


# ---------------- sidebar ----------------
st.sidebar.title("🔐 ECDAT")
result = _get_result()
if result:
    st.sidebar.caption(f"scan of `{Path(result.target).name}`  ·  {result.posture.total_assets} assets")
    views = ["Scan", "Overview", "Inventory", "Weaknesses", "PQC Readiness", "Mosca Lab", "Coverage"]
    default_ix = 1
else:
    st.sidebar.caption("no scan loaded")
    views = ["Scan"]
    default_ix = 0
view = st.sidebar.radio("View", views, index=default_ix, label_visibility="collapsed")
st.sidebar.divider()
st.sidebar.caption("engine 0.9.0 · offline\nnothing is uploaded — scans run locally")


# ---------------- helpers ----------------
def status_badge(s: str) -> str:
    return f"<span style='color:{_SEV.get(s,'#888')};font-weight:600'>{s}</span>"


def assets_df(items) -> pd.DataFrame:
    return pd.DataFrame([{
        "risk": a.risk_score, "asset": a.name, "type": a.asset_type.value,
        "family": a.algorithm_family, "primitive": a.primitive.value,
        "status": a.quantum_status.value, "criticality": a.criticality.value,
        "data": a.data_classification, "hndl": "yes" if a.hndl_exposed else "",
        "recommended": a.recommendation.target_algorithm if a.recommendation else "—",
        "location": a.locations[0].component if a.locations else "",
    } for a in items])


def _risk_col():
    return {"risk": st.column_config.ProgressColumn("risk", min_value=0, max_value=100, format="%d")}


# ================= SCAN =================
if view == "Scan":
    st.subheader("Scan a codebase")
    st.caption("ECDAT reads a folder of source. Nothing leaves this machine — the scan runs here.")

    tab_path, tab_zip = st.tabs(["📁  Local folder", "🗜️  Upload a .zip"])

    with tab_path:
        p = st.text_input("Path to the codebase", value="tests/fixtures/vulnerable-repo",
                          help="Absolute or relative to where `ecdat serve` was started")
        c1, c2, c3 = st.columns(3)
        crqc = c1.number_input("Z · quantum threat year", 2028, 2045, 2032)
        xo = c2.number_input("X override (yr, 0 = auto)", 0, 30, 0)
        yo = c3.number_input("Y override (yr, 0 = auto)", 0, 10, 0)
        if st.button("Run scan", type="primary", key="run_path"):
            if not Path(p).exists():
                st.error(f"No such path: `{p}`")
            else:
                with st.spinner(f"scanning {p} …"):
                    r = run_scan(p, crqc_year=int(crqc),
                                 x=float(xo) or None, y=float(yo) or None)
                _store(r)
                st.success(f"Found {r.posture.total_assets} cryptographic assets · "
                           f"posture {r.posture.grade} ({r.posture.posture_score:.0f}/100)")
                st.rerun()

    with tab_zip:
        up = st.file_uploader("Zip of your repository", type=["zip"])
        crqc2 = st.number_input("Z · quantum threat year", 2028, 2045, 2032, key="z2")
        if up is not None and st.button("Run scan", type="primary", key="run_zip"):
            with st.spinner("extracting and scanning …"):
                tmp = Path(tempfile.mkdtemp(prefix="ecdat-"))
                with zipfile.ZipFile(io.BytesIO(up.getvalue())) as zf:
                    for m in zf.namelist():
                        if ".." in m or m.startswith("/"):
                            continue
                        zf.extract(m, tmp)
                roots = [d for d in tmp.iterdir() if d.is_dir()]
                target = roots[0] if len(roots) == 1 and not any(tmp.glob("*.*")) else tmp
                r = run_scan(str(target), crqc_year=int(crqc2))
            _store(r)
            st.success(f"Found {r.posture.total_assets} cryptographic assets · "
                       f"posture {r.posture.grade}")
            st.rerun()

    if result:
        st.divider()
        st.markdown("**Downloads for the loaded scan**")
        d1, d2, d3, d4 = st.columns(4)
        d1.download_button("cbom.json", to_cbom(result), "cbom.json", "application/json")
        d2.download_button("result.json", to_json(result), "result.json", "application/json")
        d3.download_button("report.html", render_html(result), "report.html", "text/html")
        d4.download_button("results.sarif", to_sarif(result), "results.sarif", "application/json")

    st.stop()


# from here on `result` is guaranteed
assert result is not None
assets = result.assets

# ================= OVERVIEW =================
if view == "Overview":
    p = result.posture
    st.subheader("Estate posture")
    c = st.columns(5)
    c[0].metric("Posture", p.grade, f"{p.posture_score:.0f}/100")
    c[1].metric("Assets", p.total_assets)
    c[2].metric("Quantum-vulnerable", p.by_status.get("vulnerable", 0))
    c[3].metric("HNDL exposed", p.hndl_count)
    c[4].metric("At risk · Mosca", p.at_risk_count)
    crit_hi = sum(1 for f in result.findings if f.severity.value in ("critical", "high"))
    c2 = st.columns(5)
    c2[0].metric("Weaknesses", len(result.findings), f"{crit_hi} critical/high", delta_color="inverse")
    c2[1].metric("Crypto-agility", f"{result.pqc_readiness.crypto_agility_index:.0f}",
                 result.pqc_readiness.agility_grade)
    c2[2].metric("NQM 2028 wave", result.pqc_readiness.nqm_phase_counts.get("high-priority-2028", 0))
    c2[3].metric("HNDL at rest", result.pqc_readiness.hndl_at_rest_count)
    c2[4].metric("Already safe", p.by_status.get("safe", 0))
    st.divider()
    left, right = st.columns([3, 2])
    with left:
        st.markdown("**Highest risk — remediate first**")
        top = sorted(assets, key=lambda a: -a.risk_score)[:12]
        df = assets_df(top)[["risk", "asset", "family", "status", "criticality", "recommended", "location"]]
        st.dataframe(df, hide_index=True, width="stretch", column_config=_risk_col())
    with right:
        st.markdown("**Quantum status**")
        st.bar_chart(pd.Series(p.by_status).reindex(["broken", "vulnerable", "weakened", "safe"]).fillna(0),
                     horizontal=True, color="#bc4c00")
        st.markdown("**By criticality**")
        st.bar_chart(pd.Series(p.by_criticality).reindex(["critical", "high", "medium", "low"]).fillna(0),
                     horizontal=True, color="#9a6700")

# ================= INVENTORY =================
elif view == "Inventory":
    st.subheader("Cryptographic inventory")
    f1, f2, f3 = st.columns(3)
    sts = f1.multiselect("Status", ["vulnerable", "broken", "weakened", "safe"])
    crits = f2.multiselect("Criticality", ["critical", "high", "medium", "low"])
    q = f3.text_input("Search", "")
    items = assets
    if sts:
        items = [a for a in items if a.quantum_status.value in sts]
    if crits:
        items = [a for a in items if a.criticality.value in crits]
    if q:
        ql = q.lower()
        items = [a for a in items if ql in (a.name + a.algorithm_family +
                 (a.locations[0].component if a.locations else "")).lower()]
    st.caption(f"{len(items)} of {len(assets)} assets")
    st.dataframe(assets_df(sorted(items, key=lambda a: -a.risk_score)), hide_index=True,
                 width="stretch", height=440, column_config=_risk_col())
    names = [f"{a.name}  ·  {a.locations[0].component if a.locations else ''}" for a in items]
    if names:
        a = items[names.index(st.selectbox("Inspect asset", names))]
        d1, d2 = st.columns(2)
        with d1:
            st.markdown(f"### {a.name}")
            st.markdown(status_badge(a.quantum_status.value), unsafe_allow_html=True)
            st.write(a.quantum_status_reason)
            st.code("\n".join(e.snippet or "" for e in a.detection.evidence) or "—")
            if a.mosca_result and a.quantum_status.value != "safe":
                st.caption("Mosca: " + a.mosca_result.formula)
        with d2:
            if a.recommendation:
                r = a.recommendation
                st.markdown(f"**Recommended → `{r.target_algorithm}`**")
                if r.hybrid_option:
                    st.caption(f"transition: {r.hybrid_option}")
                st.write(r.rationale)
                st.caption(f"effort: {r.migration_effort.value} · latency: {r.latency_class or 'n/a'}")
                if r.library_support:
                    st.caption("libraries: " + ", ".join(r.library_support))
            else:
                st.success("No action — quantum-safe at current parameters.")

# ================= WEAKNESSES =================
elif view == "Weaknesses":
    st.subheader("Cryptographic weaknesses & misuse")
    st.caption("Threat findings — insecure use of cryptography, distinct from the quantum inventory.")
    if not result.findings:
        st.success("No crypto-misuse findings.")
    else:
        cats = sorted({f.category for f in result.findings})
        pick = st.multiselect("Category", cats)
        items = [f for f in result.findings if not pick or f.category in pick]
        sev_color = {"critical": "🔴", "medium": "🟡", "high": "🟠", "low": "⚪", "info": "⚫"}
        df = pd.DataFrame([{
            "severity": sev_color.get(f.severity.value, "") + " " + f.severity.value,
            "finding": f.title, "category": f.category, "cwe": f.cwe or "",
            "location": f.location,
        } for f in items])
        st.dataframe(df, hide_index=True, width="stretch", height=360)
        labels = [f"{f.severity.value.upper()} · {f.title}  ·  {f.location}" for f in items]
        if labels:
            f = items[labels.index(st.selectbox("Detail", labels))]
            st.markdown(f"### {f.title}")
            st.caption(f"{f.location} · {f.category}" + (f" · {f.cwe}" if f.cwe else "")
                       + (" · quantum-relevant" if f.quantum_relevant else ""))
            if f.snippet:
                st.code(f.snippet)
            st.write(f.description)
            st.markdown(f"**Fix:** {f.remediation}")

# ================= PQC READINESS =================
elif view == "PQC Readiness":
    rd = result.pqc_readiness
    st.subheader("Post-quantum readiness")
    m = st.columns(4)
    m[0].metric("Crypto-agility index", f"{rd.crypto_agility_index:.0f}/100", rd.agility_grade)
    m[1].metric("High-priority (NQM 2028)", rd.nqm_phase_counts.get("high-priority-2028", 0))
    m[2].metric("Full adoption (NQM 2029)", rd.nqm_phase_counts.get("full-adoption-2029", 0))
    m[3].metric("Already quantum-safe", rd.nqm_phase_counts.get("no-action", 0))
    st.divider()
    st.markdown("**Quantum-risk timeline** — assets that fail Mosca's inequality if a "
                "cryptographically-relevant quantum computer arrives in year …")
    tl = pd.DataFrame(rd.quantum_risk_timeline).set_index("year")
    st.bar_chart(tl, color="#bc4c00", height=220)
    st.markdown("**Migration waves** — vulnerable assets sequenced by effort")
    if rd.migration_waves:
        wdf = pd.DataFrame([{
            "wave": w.order, "scope": w.name, "effort": w.effort,
            "assets": w.asset_count, "risk removed": w.risk_reduction,
            "examples": ", ".join(w.example_assets[:3]),
        } for w in rd.migration_waves])
        st.dataframe(wdf, hide_index=True, width="stretch")

# ================= MOSCA LAB =================
elif view == "Mosca Lab":
    st.subheader("Mosca Lab")
    st.caption("If X + Y > Z − now, the data is already exposed to harvest-now-decrypt-later. "
               "These sliders apply a **uniform** X and Y to every asset — a stress test. "
               "The Overview uses each asset's own data classification instead.")
    preset = st.radio("Preset", ["NIST baseline", "Optimistic", "Regulator (EU 2030)"], horizontal=True)
    dfl = {"NIST baseline": (10, 3, 2032), "Optimistic": (7, 2, 2035),
           "Regulator (EU 2030)": (15, 4, 2030)}[preset]
    cx, cy, cz = st.columns(3)
    X = cx.slider("X · data secrecy lifetime (yr)", 1, 30, dfl[0])
    Y = cy.slider("Y · migration time (yr)", 1, 10, dfl[1])
    Z = cz.slider("Z · quantum threat year", 2028, 2045, dfl[2])
    now = result.started_at.year
    recomputed = []
    for a in assets:
        b = a.model_copy(deep=True)
        assess(b, MoscaInputs(data_lifetime_years=X, migration_years=Y, crqc_year=Z, now_year=now))
        recomputed.append(b)
    pp = build_posture(recomputed)
    at_risk = [a for a in recomputed if a.mosca_result and a.mosca_result.at_risk and a.risk_score > 0]
    m = st.columns(4)
    m[0].metric("Estate posture", pp.grade, f"{pp.posture_score:.0f}/100")
    m[1].metric("At risk", f"{len(at_risk)} / {len(assets)}")
    m[2].metric("HNDL exposed", sum(1 for a in recomputed if a.hndl_exposed))
    m[3].metric("X + Y  vs  Z − now", f"{X + Y}  vs  {Z - now}")
    st.markdown("**Assets at risk under these assumptions**")
    df = assets_df(sorted(at_risk, key=lambda a: -a.risk_score))
    if not df.empty:
        st.dataframe(df[["risk", "asset", "family", "status", "criticality", "recommended", "location"]],
                     hide_index=True, width="stretch", column_config=_risk_col())

# ================= COVERAGE =================
else:
    st.subheader("Methodology & coverage")
    cov = result.coverage
    st.write(f"**Collectors run:** {', '.join(cov.scanners_run)}")
    st.write(f"**Files parsed:** {cov.files_parsed}")
    st.write(f"**Skipped:** {cov.files_skipped or 'none'}")
    st.write("**Known limitations:**")
    for x in cov.known_limitations:
        st.write(f"- {x}")
    st.divider()
    st.caption(f"tool {result.tool_version} · kb {result.kb_version} · config {result.config_hash}")
