from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

from ecdat.domain.models import MoscaInputs, ScanResult
from ecdat.domain.posture import build_posture
from ecdat.domain.risk import assess

st.set_page_config(page_title="ECDAT Console", layout="wide", page_icon="🔐")

_SEV = {"safe": "#2f7c50", "weakened": "#9a6700", "vulnerable": "#bc4c00",
        "broken": "#cf222e", "unknown": "#6a747d"}


@st.cache_data
def load(path: str) -> dict:
    return ScanResult.model_validate_json(Path(path).read_text()).model_dump()


def _result_path() -> str:
    for a in reversed(sys.argv):
        if a.endswith(".json") and Path(a).exists():
            return a
    return "ecdat-out/result.json"


path = _result_path()
if not Path(path).exists():
    st.error(f"No scan result found at `{path}`. Run `ecdat scan <target>` first.")
    st.stop()

raw = load(path)
result = ScanResult.model_validate(raw)
assets = result.assets

st.sidebar.title("🔐 ECDAT")
st.sidebar.caption(f"scan of `{Path(result.target).name}`")
view = st.sidebar.radio("View", ["Overview", "Inventory", "Mosca Lab", "Coverage"], label_visibility="collapsed")
st.sidebar.divider()
st.sidebar.caption(f"engine {result.tool_version} · kb {result.kb_version}\nmode offline")


def status_badge(s: str) -> str:
    return f"<span style='color:{_SEV.get(s,'#888')};font-weight:600'>{s}</span>"


def assets_df(items) -> pd.DataFrame:
    return pd.DataFrame([{
        "risk": a.risk_score,
        "asset": a.name,
        "type": a.asset_type.value,
        "family": a.algorithm_family,
        "primitive": a.primitive.value,
        "status": a.quantum_status.value,
        "criticality": a.criticality.value,
        "data": a.data_classification,
        "hndl": "yes" if a.hndl_exposed else "",
        "recommended": a.recommendation.target_algorithm if a.recommendation else "—",
        "location": a.locations[0].component if a.locations else "",
    } for a in items])


# ---------------- Overview ----------------
if view == "Overview":
    p = result.posture
    st.subheader("Estate posture")
    c = st.columns([1, 1, 1, 1, 1])
    c[0].metric("Posture", f"{p.grade}", f"{p.posture_score:.0f}/100")
    c[1].metric("Assets", p.total_assets)
    c[2].metric("Quantum-vulnerable", p.by_status.get("vulnerable", 0))
    c[3].metric("HNDL exposed", p.hndl_count)
    c[4].metric("At risk · Mosca", p.at_risk_count)

    st.divider()
    left, right = st.columns([3, 2])
    with left:
        st.markdown("**Highest risk — remediate first**")
        top = sorted(assets, key=lambda a: -a.risk_score)[:12]
        df = assets_df(top)[["risk", "asset", "family", "status", "criticality", "recommended", "location"]]
        st.dataframe(df, hide_index=True, width="stretch",
                     column_config={"risk": st.column_config.ProgressColumn(
                         "risk", min_value=0, max_value=100, format="%d")})
    with right:
        st.markdown("**Quantum status**")
        counts = pd.Series(p.by_status).reindex(["broken", "vulnerable", "weakened", "safe"]).fillna(0)
        st.bar_chart(counts, horizontal=True, color="#bc4c00")
        st.markdown("**By criticality**")
        cc = pd.Series(p.by_criticality).reindex(["critical", "high", "medium", "low"]).fillna(0)
        st.bar_chart(cc, horizontal=True, color="#9a6700")

# ---------------- Inventory ----------------
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
    df = assets_df(sorted(items, key=lambda a: -a.risk_score))
    st.dataframe(df, hide_index=True, width="stretch", height=460,
                 column_config={"risk": st.column_config.ProgressColumn(
                     "risk", min_value=0, max_value=100, format="%d")})

    names = [a.name + "  ·  " + (a.locations[0].component if a.locations else "") for a in items]
    if names:
        pick = st.selectbox("Inspect asset", names)
        a = items[names.index(pick)]
        d1, d2 = st.columns(2)
        with d1:
            st.markdown(f"### {a.name}")
            st.markdown(status_badge(a.quantum_status.value), unsafe_allow_html=True)
            st.write(a.quantum_status_reason)
            st.code("\n".join(e.snippet or "" for e in a.detection.evidence) or "—")
            if a.mosca_result:
                st.caption("Mosca: " + a.mosca_result.formula)
        with d2:
            if a.recommendation:
                r = a.recommendation
                st.markdown(f"**Recommended → `{r.target_algorithm}`**")
                if r.hybrid_option:
                    st.caption(f"transition: {r.hybrid_option}")
                st.write(r.rationale)
                st.caption(f"effort: {r.migration_effort.value}  ·  "
                           f"latency: {r.latency_class or 'n/a'}")
                if r.library_support:
                    st.caption("libraries: " + ", ".join(r.library_support))
            else:
                st.success("No action — quantum-safe at current parameters.")

# ---------------- Mosca Lab ----------------
elif view == "Mosca Lab":
    st.subheader("Mosca Lab")
    st.caption("Model your organisation's assumptions. If X + Y > Z − now, the data is already "
               "exposed to harvest-now-decrypt-later.")
    preset = st.radio("Preset", ["NIST baseline", "Optimistic", "Regulator (EU 2030)"], horizontal=True)
    defaults = {"NIST baseline": (10, 3, 2032), "Optimistic": (7, 2, 2035),
                "Regulator (EU 2030)": (15, 4, 2030)}[preset]
    cx, cy, cz = st.columns(3)
    X = cx.slider("X · data secrecy lifetime (yr)", 1, 30, defaults[0])
    Y = cy.slider("Y · migration time (yr)", 1, 10, defaults[1])
    Z = cz.slider("Z · quantum threat year", 2028, 2045, defaults[2])

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
    m[3].metric("X + Y  vs  Z − now", f"{X+Y}  vs  {Z-now}")

    st.markdown("**Assets at risk under these assumptions**")
    df = assets_df(sorted(at_risk, key=lambda a: -a.risk_score))
    st.dataframe(df[["risk", "asset", "family", "status", "criticality", "recommended", "location"]],
                 hide_index=True, width="stretch",
                 column_config={"risk": st.column_config.ProgressColumn(
                     "risk", min_value=0, max_value=100, format="%d")})

# ---------------- Coverage ----------------
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
    st.caption(f"tool {result.tool_version} · kb {result.kb_version} · config {result.config_hash} · "
               f"target {result.target}")
