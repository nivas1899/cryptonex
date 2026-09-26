from __future__ import annotations

import io
import sys
import tempfile
import time
import zipfile
from collections import Counter
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from cryptonex.core.orchestrator import run_scan
from cryptonex.domain.models import MoscaInputs, ScanResult
from cryptonex.domain.posture import build_posture
from cryptonex.domain.risk import assess
from cryptonex.reporters.cbom import to_cbom
from cryptonex.reporters.json_out import to_json
from cryptonex.reporters.report import render_html
from cryptonex.reporters.sarif import to_sarif

st.set_page_config(page_title="CRYPTONEX Console", layout="wide", page_icon="🔐",
                    initial_sidebar_state="expanded")

# ---------------- design tokens ----------------
# One color per rating everywhere in the app (console, exported report, CLI) —
# keep this in sync with cryptonex/reporters/report.py's _SEV.
_SEV = {"safe": "#2f7c50", "weakened": "#9a6700", "vulnerable": "#bc4c00",
        "broken": "#cf222e", "unknown": "#6a747d"}
_SEV_LABEL = {"safe": "Safe", "weakened": "Weakened", "vulnerable": "Vulnerable",
              "broken": "Broken", "unknown": "Unknown"}
_CRIT = {"critical": "#cf222e", "high": "#bc4c00", "medium": "#9a6700", "low": "#57606a"}
_FIND_SEV = {"critical": "#cf222e", "high": "#bc4c00", "medium": "#9a6700",
             "low": "#57606a", "info": "#8c959f"}
_GRADE = {"A": "#2f7c50", "B": "#2f7c50", "C": "#9a6700", "D": "#bc4c00", "F": "#cf222e"}
_RISK_BANDS = [(0, 24, "Low", "#2f7c50"), (25, 49, "Moderate", "#9a6700"),
               (50, 74, "High", "#bc4c00"), (75, 100, "Critical", "#cf222e")]
_STATUS_EMOJI = {"safe": "🟢", "weakened": "🟡", "vulnerable": "🟠", "broken": "🔴", "unknown": "⚪"}
_CRIT_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}
_FIND_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪", "info": "⚪"}

_VIEW_ICON = {"Scan": "🔎", "Overview": "📊", "Inventory": "📦", "Weaknesses": "⚠️",
              "PQC Readiness": "🛡️", "Mosca Lab": "🧪", "Coverage": "📚"}

st.markdown("""
<style>
  .block-container { max-width: 100%; padding-top: 1.6rem; padding-bottom: 3rem;
                      padding-left: 3rem; padding-right: 3rem; }
  html { font-size: 15.5px; }

  section[data-testid="stSidebar"] { width: 272px !important; }
  section[data-testid="stSidebar"] > div { padding-top: 0; }
  [data-testid="stSidebarHeader"] { padding-bottom: 0; }
  [data-testid="stLogoSpacer"] { display: none; }

  /* Dark enterprise-console sidebar (Nessus-style navy chrome + light content pane). */
  section[data-testid="stSidebar"] {
    background: #141c2b; border-right: 1px solid #0b1119;
  }
  section[data-testid="stSidebar"] * { color: #cfd7e3; }
  section[data-testid="stSidebar"] h1 {
    color: #ffffff; letter-spacing: .04em; font-size: 1.3rem; padding: 18px 14px 0;
  }
  section[data-testid="stSidebar"] [data-testid="stCaptionContainer"],
  section[data-testid="stSidebar"] small, section[data-testid="stSidebar"] p { color: #7c8aa0; }
  section[data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] button svg { color: #7c8aa0; }
  section[data-testid="stSidebar"] hr { border-color: #232f45; }
  section[data-testid="stSidebar"] code {
    background: #1f2b40; color: #8fd0ff; border: none;
  }

  /* Force a real, always-visible scrollbar on the main pane — some browsers/
     OSes render an invisible "overlay" scrollbar by default, which looks like
     scrolling is broken on a full-width layout. */
  [data-testid="stMain"] { overflow-y: scroll !important; scrollbar-gutter: stable; }
  [data-testid="stMain"]::-webkit-scrollbar { width: 12px; }
  [data-testid="stMain"]::-webkit-scrollbar-track { background: transparent; }
  [data-testid="stMain"]::-webkit-scrollbar-thumb {
    background: #c6cbd1; border-radius: 7px; border: 3px solid transparent;
    background-clip: padding-box;
  }
  [data-testid="stMain"]::-webkit-scrollbar-thumb:hover { background: #9aa2ac; }

  [data-testid="stMetricValue"] { font-size: 1.85rem; line-height: 1.15; }
  [data-testid="stMetricLabel"] p { font-size: .85rem; color: #57606a; }
  [data-testid="stMetricDelta"] { font-size: .8rem; }
  h2, [data-testid="stHeadingWithActionElements"] h2 { font-size: 1.45rem; }
  h3 { font-size: 1.1rem; }
  [data-testid="stDataFrame"] { font-size: .92rem; }

  /* metric / chart cards */
  div[data-testid="stVerticalBlockBorderWrapper"] {
    border-radius: 10px !important;
  }

  /* Sidebar navigation — full-width nav rows, Nessus-style: flat on dark chrome,
     a bright left accent bar marks the active view instead of a filled pill. */
  section[data-testid="stSidebar"] div[data-testid="stRadioGroup"] {
    gap: 2px; display: flex; flex-direction: column;
  }
  section[data-testid="stSidebar"] label[data-testid="stRadioOption"] {
    width: 100%; padding: 10px 14px 10px 17px; border-radius: 6px; margin: 0;
    border: 1px solid transparent; border-left: 3px solid transparent;
    transition: background .12s, border-color .12s; box-sizing: border-box;
  }
  section[data-testid="stSidebar"] label[data-testid="stRadioOption"] > div > div > div:first-child {
    display: none;
  }
  section[data-testid="stSidebar"] label[data-testid="stRadioOption"] p {
    font-size: .96rem; color: #a7b2c4 !important; font-weight: 500;
  }
  section[data-testid="stSidebar"] label[data-testid="stRadioOption"]:hover {
    background: #1a2436;
  }
  section[data-testid="stSidebar"] label[data-testid="stRadioOption"]:hover p { color: #e6e9ef !important; }
  section[data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"] {
    background: #1c2942; border-left-color: #4c8dff;
  }
  section[data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"] p {
    color: #ffffff !important; font-weight: 700;
  }

  .cx-pill {
    display: inline-block; padding: 2px 10px; border-radius: 11px; font-size: .74rem;
    font-weight: 700; letter-spacing: .02em; text-transform: uppercase; color: #fff;
  }
  .cx-dot {
    width: 9px; height: 9px; border-radius: 50%; display: inline-block; margin-right: 6px;
  }
  .cx-legend-chip {
    display: inline-flex; align-items: center; margin: 2px 12px 2px 0; font-size: .82rem; color: #444;
  }
  .cx-hint {
    background: #f6f8fa; border: 1px solid #eaecef; border-radius: 8px;
    padding: 8px 12px; font-size: .84rem; color: #57606a; margin: 6px 0 4px;
  }

  /* Scan-detail-style page header (icon + title + right-aligned meta chips). */
  .cx-pagehead {
    display: flex; align-items: flex-end; justify-content: space-between;
    flex-wrap: wrap; gap: 14px 28px; margin: 0 0 16px; padding-bottom: 14px;
    border-bottom: 1px solid #e3e6e9;
  }
  .cx-pagehead-title { font-size: 1.55rem; font-weight: 700; color: #1a1f24; line-height: 1.2; }
  .cx-pagehead-sub { font-size: .86rem; color: #6a747d; margin-top: 3px; }
  .cx-pagehead-meta { display: flex; gap: 22px; flex-wrap: wrap; }
  .cx-meta-chip { display: flex; flex-direction: column; align-items: flex-start; }
  .cx-meta-k {
    font-size: .66rem; text-transform: uppercase; letter-spacing: .06em; color: #8c959f;
  }
  .cx-meta-v {
    font-size: .92rem; font-weight: 600; color: #1a1f24;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  }

  /* Estate severity strip — one proportional bar, Nessus-style "at a glance". */
  .cx-sevstrip {
    display: flex; width: 100%; height: 26px; border-radius: 6px; overflow: hidden;
    border: 1px solid #e3e6e9; margin-top: 2px;
  }
  .cx-sevstrip > div {
    display: flex; align-items: center; justify-content: center;
    color: #fff; font-size: .72rem; font-weight: 700; min-width: 2px;
  }
</style>
""", unsafe_allow_html=True)


def _default_result_path() -> str | None:
    for a in reversed(sys.argv):
        if a.endswith(".json") and Path(a).exists():
            return a
    p = Path("cryptonex-out/result.json")
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
st.sidebar.title("CRYPTONEX")
st.sidebar.caption("cryptographic posture console")
result = _get_result()
if result:
    st.sidebar.caption(f"scan of `{Path(result.target).name}`  ·  {result.posture.total_assets} assets")
    views = ["Scan", "Overview", "Inventory", "Weaknesses", "PQC Readiness", "Mosca Lab", "Coverage"]
    default_ix = 1
else:
    st.sidebar.caption("no scan loaded")
    views = ["Scan"]
    default_ix = 0

# A widget's session_state key can't be reassigned after the widget has been
# instantiated this run — so a click elsewhere in the app that wants to change
# the view stashes it under `_pending_nav` and calls st.rerun(); we apply it
# here, before the radio below is created, on the following run.
pending = st.session_state.pop("_pending_nav", None)
if pending in views:
    st.session_state["nav_view"] = pending
elif "nav_view" not in st.session_state or st.session_state["nav_view"] not in views:
    st.session_state["nav_view"] = views[default_ix]
view = st.sidebar.radio("View", views, key="nav_view", label_visibility="collapsed",
                         format_func=lambda v: f"{_VIEW_ICON.get(v, '')}  {v}")
st.sidebar.divider()

if result:
    st.sidebar.caption("**Quantum status colors**")
    dots = "".join(
        f"<div class='cx-legend-chip'><span class='cx-dot' style='background:{_SEV[s]}'></span>"
        f"{_SEV_LABEL[s]}</div>"
        for s in ["safe", "weakened", "vulnerable", "broken"]
    )
    st.sidebar.markdown(f"<div style='line-height:2'>{dots}</div>", unsafe_allow_html=True)
    st.sidebar.caption("Full glossary → Overview or Coverage tab.")
    st.sidebar.divider()

st.sidebar.caption("engine 0.9.0 · offline\nnothing is uploaded — scans run locally")


# ---------------- shared viz helpers ----------------
def loc_str(loc) -> str:
    """Render a Location as `path/to/file.py:123` — exact line when we have one,
    just the path when we don't (certs/keys/libraries have no line number)."""
    if loc is None:
        return ""
    return f"{loc.component}:{loc.line}" if loc.line is not None else loc.component


def asset_loc(a) -> str:
    return loc_str(a.locations[0]) if a.locations else ""


def assets_df(items) -> pd.DataFrame:
    return pd.DataFrame([{
        "risk": a.risk_score, "asset": a.name, "type": a.asset_type.value,
        "family": a.algorithm_family, "primitive": a.primitive.value,
        "status": f"{_STATUS_EMOJI.get(a.quantum_status.value, '⚪')} {a.quantum_status.value}",
        "conf.": a.detection.confidence.value,
        "criticality": f"{_CRIT_EMOJI.get(a.criticality.value, '⚪')} {a.criticality.value}",
        "data": a.data_classification, "hndl": "yes" if a.hndl_exposed else "",
        "recommended": a.recommendation.target_algorithm if a.recommendation else "—",
        "location": asset_loc(a),
        "occurrences": a.occurrences,
    } for a in items])


def _risk_col():
    return {"risk": st.column_config.ProgressColumn(
        "risk", min_value=0, max_value=100, format="%d",
        help="0-100 · combines quantum status, business criticality, HNDL exposure window "
             "and detection confidence. See the color legend above for the risk bands.",
    )}


def pill(text: str, color: str) -> str:
    return f"<span class='cx-pill' style='background:{color}'>{text}</span>"


def donut(labels: list[str], values: list[float], colors: list[str],
          center_top: str | None = None, center_sub: str | None = None, height: int = 230) -> None:
    """Plain donut chart — the visual. Pair it with `chip_buttons()` right below
    for the actual click-to-drill interaction (Plotly pie slices don't reliably
    forward click events back to Streamlit, real buttons always do)."""
    fig = go.Figure(data=[go.Pie(
        labels=labels, values=values, hole=0.62, sort=False, direction="clockwise",
        marker=dict(colors=colors, line=dict(color="#ffffff", width=1)),
        textinfo="percent", textfont=dict(size=12, color="#1a1f24"),
        hovertemplate="<b>%{label}</b><br>%{value} (%{percent})<extra></extra>",
    )])
    fig.update_layout(
        showlegend=False, height=height, margin=dict(t=8, b=8, l=8, r=8),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#1a1f24"),
    )
    if center_top is not None:
        fig.add_annotation(text=f"<b>{center_top}</b>", x=0.5, y=0.56, showarrow=False,
                            font=dict(size=24, color="#1a1f24"))
        if center_sub:
            fig.add_annotation(text=center_sub, x=0.5, y=0.38, showarrow=False,
                                font=dict(size=11, color="#6a747d"))
    st.plotly_chart(fig, config={"displayModeBar": False})


def chip_buttons(items: list[tuple[str, str, int]], emoji_map: dict[str, str], key_prefix: str,
                  per_row: int = 3) -> str | None:
    """One button per (raw_value, display_label, count) — click drills into that
    slice. Renders as rows of colored chips right under a donut chart, doubling
    as both its legend and its click target."""
    clicked = None
    for start in range(0, len(items), per_row):
        cols = st.columns(per_row)
        for col, (raw, disp, count) in zip(cols, items[start:start + per_row]):
            if col.button(f"{emoji_map.get(raw, '⚪')} {disp} · {count}",
                          key=f"{key_prefix}_{raw}", width="stretch"):
                clicked = raw
    return clicked


def rating_glossary() -> None:
    st.markdown("##### Quantum status — will this survive a quantum computer?")
    rows = [
        ("safe", "Already resistant to a large-scale quantum computer (PQC, AES-256, SHA-384+). "
                  "No migration needed."),
        ("weakened", "Quantum computing halves its effective security margin (e.g. AES-128, SHA-256 "
                      "under Grover's algorithm). Usable short-term — plan an upgrade."),
        ("vulnerable", "Breakable by a cryptographically-relevant quantum computer (RSA, ECDSA, ECDH, "
                        "Diffie-Hellman). Must migrate before the threat year Z."),
        ("broken", "Already broken today with ordinary computers (MD5, SHA-1, DES, RC4). Fix "
                    "immediately — this has nothing to do with quantum risk."),
        ("unknown", "Not enough evidence to classify automatically — needs a manual look."),
    ]
    for s, desc in rows:
        st.markdown(f"<div style='margin:5px 0 5px 0'>{pill(s, _SEV[s])}"
                    f"&nbsp;&nbsp;{desc}</div>", unsafe_allow_html=True)

    st.markdown("##### Risk score (0–100)")
    st.caption("One number per asset — blends quantum status, business criticality, the "
               "harvest-now-decrypt-later exposure window (Mosca), and how confident the "
               "detection is. Higher = fix sooner.")
    chips = "".join(pill(f"{lo}–{hi} · {name}", c) + "&nbsp; "
                     for lo, hi, name, c in _RISK_BANDS)
    st.markdown(chips, unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("##### Business criticality")
        st.caption("How damaging it would be if *this specific asset* were compromised — inferred "
                   "from path/config keywords (e.g. `pki/`, `payments/`). Independent of quantum "
                   "status: a critical asset can still be quantum-safe.")
    with c2:
        st.markdown("##### Finding severity")
        st.caption("Critical / High / Medium / Low / Info — how urgently a specific cryptographic "
                   "*misuse* (hardcoded key, weak mode, missing IV…) needs fixing. Separate from "
                   "the quantum inventory above.")


def page_header(icon: str, title: str, subtitle: str | None = None,
                 meta: list[tuple[str, str]] | None = None) -> None:
    """Scan-detail-style page header — icon + title on the left, a row of small
    label/value meta chips (target, engine, scan time…) on the right, in place
    of a bare subheader."""
    meta_html = "".join(
        f"<div class='cx-meta-chip'><span class='cx-meta-k'>{k}</span>"
        f"<span class='cx-meta-v'>{v}</span></div>" for k, v in (meta or [])
    )
    sub_html = f"<div class='cx-pagehead-sub'>{subtitle}</div>" if subtitle else ""
    st.markdown(f"""
    <div class='cx-pagehead'>
      <div><div class='cx-pagehead-title'>{icon} {title}</div>{sub_html}</div>
      <div class='cx-pagehead-meta'>{meta_html}</div>
    </div>
    """, unsafe_allow_html=True)


def severity_strip(items: list[tuple[str, int, str]]) -> None:
    """A single proportional horizontal distribution bar — the 'at a glance'
    estate-severity strip, with a color-dot legend underneath."""
    items = [(l, c, col) for l, c, col in items if c > 0]
    total = sum(c for _, c, _ in items) or 1
    segs = "".join(
        f"<div style='flex:{c} 0 0;background:{color}' title='{label}: {c}'>"
        + (f"<span>{c}</span>" if c / total > 0.06 else "") + "</div>"
        for label, c, color in items
    )
    legend = "".join(
        f"<span class='cx-legend-chip'><span class='cx-dot' style='background:{color}'></span>"
        f"{label} <b style='margin-left:3px'>{c}</b></span>"
        for label, c, color in items
    )
    st.markdown(f"<div class='cx-sevstrip'>{segs}</div>"
                f"<div style='margin-top:7px'>{legend}</div>", unsafe_allow_html=True)


# ================= SCAN =================
if view == "Scan":
    page_header(_VIEW_ICON["Scan"], "Scan a codebase",
                subtitle="CRYPTONEX reads a folder of source — nothing leaves this machine")
    st.caption("Validated on 8 real open-source repos — pyjwt, itsdangerous, python-jose, paramiko, "
               "golang-jwt, node-jsonwebtoken, pyca/cryptography, certbot — see "
               "`docs/benchmark/results.md`.")

    tab_path, tab_zip = st.tabs(["Local folder", "Upload .zip"])

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
                t0 = time.time()
                with st.status(f"Scanning `{p}` …", expanded=True) as status:
                    bar = st.progress(0, text="counting files …")

                    def _cb(pct: float, msg: str) -> None:
                        bar.progress(pct, text=msg)

                    r = run_scan(p, crqc_year=int(crqc),
                                 x=float(xo) or None, y=float(yo) or None, progress_cb=_cb)
                    elapsed = time.time() - t0
                    status.update(
                        label=f"Scan complete in {elapsed:.1f}s — {r.posture.total_assets} assets, "
                              f"posture {r.posture.grade}",
                        state="complete", expanded=False,
                    )
                _store(r)
                st.success(f"Found {r.posture.total_assets} cryptographic assets · "
                           f"posture {r.posture.grade} ({r.posture.posture_score:.0f}/100) · "
                           f"{elapsed:.1f}s")
                st.session_state["_pending_nav"] = "Overview"
                st.rerun()

    with tab_zip:
        up = st.file_uploader("Zip of your repository", type=["zip"])
        crqc2 = st.number_input("Z · quantum threat year", 2028, 2045, 2032, key="z2")
        run_clicked = st.button("Run scan", type="primary", key="run_zip")
        if run_clicked and up is None:
            st.error("Choose a .zip file first.")
        elif run_clicked and up is not None:
            t0 = time.time()
            with st.status(f"Extracting and scanning `{up.name}` …", expanded=True) as status:
                bar = st.progress(0, text="extracting archive …")
                tmp = Path(tempfile.mkdtemp(prefix="cryptonex-"))
                with zipfile.ZipFile(io.BytesIO(up.getvalue())) as zf:
                    for m in zf.namelist():
                        if ".." in m or m.startswith("/"):
                            continue
                        zf.extract(m, tmp)
                roots = [d for d in tmp.iterdir() if d.is_dir()]
                target = roots[0] if len(roots) == 1 and not any(tmp.glob("*.*")) else tmp

                def _cb(pct: float, msg: str) -> None:
                    bar.progress(pct, text=msg)

                r = run_scan(str(target), crqc_year=int(crqc2), progress_cb=_cb)
                elapsed = time.time() - t0
                status.update(
                    label=f"Scan complete in {elapsed:.1f}s — {r.posture.total_assets} assets, "
                          f"posture {r.posture.grade}",
                    state="complete", expanded=False,
                )
            _store(r)
            st.success(f"Found {r.posture.total_assets} cryptographic assets · "
                       f"posture {r.posture.grade} · {elapsed:.1f}s")
            st.session_state["_pending_nav"] = "Overview"
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
    page_header(_VIEW_ICON["Overview"], "Estate posture",
                subtitle="Cryptographic risk across the whole scanned estate",
                meta=[
                    ("Target", Path(result.target).name),
                    ("Engine", result.tool_version),
                    ("KB", result.kb_version),
                    ("Scanned", result.started_at.strftime("%Y-%m-%d %H:%M")),
                ])

    grade_color = _GRADE.get(p.grade, "#6a747d")
    st.markdown(f"""
    <div style='display:flex;align-items:center;gap:18px;margin:2px 0 16px'>
      <div style='background:{grade_color};color:#fff;font-size:2rem;font-weight:800;
                  width:60px;height:60px;border-radius:14px;display:flex;align-items:center;
                  justify-content:center;flex-shrink:0'>{p.grade}</div>
      <div>
        <div style='font-size:1.4rem;font-weight:700'>{p.posture_score:.0f}<span
             style='font-size:.85rem;color:#8c959f;font-weight:400'> / 100 posture score</span></div>
        <div style='color:#6a747d;font-size:.85rem'>Grade {p.grade} across {p.total_assets} cryptographic
             assets — see "What do the ratings mean?" below for how this is computed.</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    severity_strip([(_SEV_LABEL[s], p.by_status.get(s, 0), _SEV[s])
                     for s in ["broken", "vulnerable", "weakened", "safe", "unknown"]])

    with st.expander("🎨 What do the colors and ratings mean?", expanded=False):
        rating_glossary()

    with st.container(border=True):
        c = st.columns(5)
        c[0].metric("Posture", p.grade, f"{p.posture_score:.0f}/100", delta_color="off")
        c[1].metric("Assets", p.total_assets)
        c[2].metric("Quantum-vulnerable", p.by_status.get("vulnerable", 0))
        c[3].metric("HNDL exposed", p.hndl_count)
        c[4].metric("At risk · Mosca", p.at_risk_count)
    with st.container(border=True):
        crit_hi = sum(1 for f in result.findings if f.severity.value in ("critical", "high"))
        c2 = st.columns(5)
        c2[0].metric("Weaknesses", len(result.findings), f"{crit_hi} critical/high", delta_color="inverse")
        c2[1].metric("Crypto-agility", f"{result.pqc_readiness.crypto_agility_index:.0f}",
                     result.pqc_readiness.agility_grade, delta_color="off")
        c2[2].metric("NQM 2028 wave", result.pqc_readiness.nqm_phase_counts.get("high-priority-2028", 0))
        c2[3].metric("HNDL at rest", result.pqc_readiness.hndl_at_rest_count)
        c2[4].metric("Already safe", p.by_status.get("safe", 0))

    st.divider()

    if st.session_state.get("inv_status_filter") or st.session_state.get("inv_crit_filter"):
        cc1, cc2 = st.columns([5, 1])
        cc1.info("A filter from a chart click is active on the **Inventory** tab.")
        if cc2.button("Clear filter"):
            st.session_state.pop("inv_status_filter", None)
            st.session_state.pop("inv_crit_filter", None)
            st.rerun()

    left, right = st.columns([3, 2])
    with left:
        st.markdown("**Highest risk — remediate first**")
        top = sorted(assets, key=lambda a: -a.risk_score)[:12]
        df = assets_df(top)[["risk", "asset", "family", "status", "criticality", "recommended", "location"]]
        st.dataframe(df, hide_index=True, width="stretch", column_config=_risk_col())
        st.markdown("**Quantum-risk timeline** — assets exposed if a quantum computer "
                    "arrives in a given year")
        rd = result.pqc_readiness
        tl = pd.DataFrame(rd.quantum_risk_timeline)
        if not tl.empty:
            fig_tl = go.Figure(go.Bar(
                x=tl["year"], y=tl["exposed_assets"], marker=dict(color="#bc4c00"),
                hovertemplate="year %{x}<br>%{y} assets exposed<extra></extra>",
            ))
            fig_tl.update_layout(height=200, margin=dict(t=6, b=6, l=6, r=6),
                                  paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                  xaxis=dict(title=None, dtick=1), yaxis=dict(title=None))
            st.plotly_chart(fig_tl)

    with right:
        st.markdown("**Quantum status** — click a status below to inspect those assets")
        status_labels = ["broken", "vulnerable", "weakened", "safe", "unknown"]
        status_vals = [p.by_status.get(s, 0) for s in status_labels]
        keep = [(l, v) for l, v in zip(status_labels, status_vals) if v > 0]
        if keep:
            labels_k, vals_k = zip(*keep)
            donut(list(labels_k), list(vals_k), [_SEV[s] for s in labels_k],
                  center_top=str(p.total_assets), center_sub="assets")
            clicked = chip_buttons(
                [(s, _SEV_LABEL[s], v) for s, v in zip(labels_k, vals_k)],
                _STATUS_EMOJI, "status_chip")
            if clicked:
                st.session_state["inv_status_filter"] = [clicked]
                st.session_state["_pending_nav"] = "Inventory"
                st.rerun()
        else:
            st.caption("No assets found.")

        st.markdown("**By criticality** — click a level below to inspect those assets")
        crit_labels = ["critical", "high", "medium", "low"]
        crit_vals = [p.by_criticality.get(c, 0) for c in crit_labels]
        keepc = [(l, v) for l, v in zip(crit_labels, crit_vals) if v > 0]
        if keepc:
            labels_c, vals_c = zip(*keepc)
            donut(list(labels_c), list(vals_c), [_CRIT[c] for c in labels_c], height=210)
            clicked_c = chip_buttons(
                [(c, c.capitalize(), v) for c, v in zip(labels_c, vals_c)],
                _CRIT_EMOJI, "crit_chip")
            if clicked_c:
                st.session_state["inv_crit_filter"] = [clicked_c]
                st.session_state["_pending_nav"] = "Inventory"
                st.rerun()
        else:
            st.caption("No assets found.")

# ================= INVENTORY =================
elif view == "Inventory":
    page_header(_VIEW_ICON["Inventory"], "Cryptographic inventory",
                subtitle="Every discovered asset — filterable, evidence-backed",
                meta=[("Assets", str(result.posture.total_assets)),
                      ("Target", Path(result.target).name)])
    n_test = sum(1 for a in assets if a.test_only)
    f1, f2, f3, f4 = st.columns([2, 2, 2, 1.4])
    sts = f1.multiselect("Status", ["vulnerable", "broken", "weakened", "safe"], key="inv_status_filter")
    crits = f2.multiselect("Criticality", ["critical", "high", "medium", "low"], key="inv_crit_filter")
    q = f3.text_input("Search", "")
    show_test = f4.checkbox(f"Include test-path ({n_test})", value=False,
                             help="Assets found only in test/example/fixture paths. Excluded from "
                                  "the posture grade by default — the same rule the CLI and "
                                  "Overview grade use.")
    if sts or crits:
        chip = " · ".join(
            [pill(f"status: {s}", _SEV.get(s, "#6a747d")) for s in sts]
            + [pill(f"crit: {c}", _CRIT.get(c, "#6a747d")) for c in crits]
        )
        cf1, cf2 = st.columns([5, 1])
        cf1.markdown(f"Filter active — {chip}", unsafe_allow_html=True)
        if cf2.button("Clear"):
            st.session_state["inv_status_filter"] = []
            st.session_state["inv_crit_filter"] = []
            st.rerun()

    items = assets if show_test else [a for a in assets if not a.test_only]
    if sts:
        items = [a for a in items if a.quantum_status.value in sts]
    if crits:
        items = [a for a in items if a.criticality.value in crits]
    if q:
        ql = q.lower()
        items = [a for a in items if ql in (a.name + a.algorithm_family + asset_loc(a)).lower()]
    st.caption(f"{len(items)} of {len(assets)} assets"
               + ("" if show_test else f"  ·  {n_test} test-path assets hidden"))
    st.dataframe(assets_df(sorted(items, key=lambda a: -a.risk_score)), hide_index=True,
                 width="stretch", height=440, column_config=_risk_col())
    with st.expander("What does the risk score / status color mean?", expanded=False):
        rating_glossary()
    names = [f"{a.name}  ·  {asset_loc(a)}"
             + (f"  (+{a.occurrences - 1} more)" if a.occurrences > 1 else "")
             for a in items]
    if names:
        a = items[names.index(st.selectbox("Inspect asset", names))]
        status_color = _SEV.get(a.quantum_status.value, "#6a747d")
        st.markdown(f"""
        <div style='border-left:4px solid {status_color};padding:4px 0 4px 14px;margin:8px 0 14px'>
          <div style='display:flex;align-items:center;gap:10px'>
            <span style='font-size:1.25rem;font-weight:700'>{a.name}</span>
            {pill(a.quantum_status.value, status_color)}
          </div>
          <div style='color:#6a747d;font-size:.82rem;margin-top:2px'>risk {a.risk_score:.0f}/100 ·
            {a.criticality.value} criticality · {asset_loc(a)}</div>
        </div>
        """, unsafe_allow_html=True)
        d1, d2 = st.columns(2)
        with d1:
            st.markdown("**Observed** — evidence-backed")
            for e in a.assessment.observed:
                st.caption("· " + e)
            if a.occurrences > 1:
                st.caption(f"Found at **{a.occurrences}** locations — every exact line below.")
            for e in a.detection.evidence:
                st.caption(f"📍 `{e.locator}`")
                st.code(e.snippet or "—")
            st.markdown("**Knowledge base** — deterministic, cited")
            for e in a.assessment.kb_derived:
                st.caption("· " + e)
        with d2:
            st.markdown("**Inferred** — heuristic, review before acting")
            for e in a.assessment.inferred:
                st.caption("· " + e)
            st.markdown("**Assumed** — operator-set")
            for e in a.assessment.assumed:
                st.caption("· " + e)
            if a.mosca_result and a.quantum_status.value != "safe":
                st.info("Mosca: " + a.mosca_result.formula)
            if a.recommendation:
                r = a.recommendation
                st.markdown(f"**Recommended → `{r.target_algorithm}`**"
                            + (f"  ·  transition via `{r.hybrid_option}`" if r.hybrid_option else ""))
                st.caption(r.rationale)
                st.caption(f"effort: {r.migration_effort.value} · latency: {r.latency_class or 'n/a'}"
                           + (f" · libs: {', '.join(r.library_support)}" if r.library_support else ""))
            else:
                st.success("No action — quantum-safe at current parameters.")

# ================= WEAKNESSES =================
elif view == "Weaknesses":
    page_header(_VIEW_ICON["Weaknesses"], "Cryptographic weaknesses & misuse",
                subtitle="Threat findings — insecure use of cryptography, distinct from the quantum inventory",
                meta=[("Findings", str(len(result.findings)))])
    if not result.findings:
        st.success("No crypto-misuse findings.")
    else:
        n_test_f = sum(1 for f in result.findings if f.test_path)
        top = st.columns([3, 1.4])
        with top[0]:
            cats = sorted({f.category for f in result.findings})
            pick = st.multiselect("Category", cats)
        with top[1]:
            show_test_f = st.checkbox(f"Include test-path ({n_test_f})", value=False,
                                       help="Findings in test/example/fixture paths — excluded "
                                            "from the CLI's headline count by default.")
        pool = result.findings if show_test_f else [f for f in result.findings if not f.test_path]
        sev_filter = st.session_state.get("wk_severity_filter")
        items = [f for f in pool if not pick or f.category in pick]
        if sev_filter:
            items = [f for f in items if f.severity.value in sev_filter]
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        items = sorted(items, key=lambda f: (sev_rank.get(f.severity.value, 9), f.location))
        sc = Counter(f.severity.value for f in pool)

        left, right = st.columns([3, 2])
        with right:
            st.markdown("**By severity** — click a level below to filter the table")
            sev_order = ["critical", "high", "medium", "low", "info"]
            sev_vals = [sc.get(s, 0) for s in sev_order]
            keep = [(s, v) for s, v in zip(sev_order, sev_vals) if v > 0]
            if keep:
                labels_s, vals_s = zip(*keep)
                donut(list(labels_s), list(vals_s), [_FIND_SEV[s] for s in labels_s],
                      center_top=str(sum(vals_s)), center_sub="findings", height=210)
                clicked_s = chip_buttons(
                    [(s, s.capitalize(), v) for s, v in zip(labels_s, vals_s)],
                    _FIND_EMOJI, "sev_chip")
                if clicked_s:
                    cur = set(st.session_state.get("wk_severity_filter") or [])
                    cur = [] if cur == {clicked_s} else [clicked_s]
                    st.session_state["wk_severity_filter"] = cur
                    st.rerun()
            with st.expander("What does severity mean?", expanded=False):
                st.caption("Critical / High / Medium / Low / Info — how urgently this specific "
                           "misuse needs fixing (independent of the quantum-status colors used "
                           "elsewhere in the app).")

        with left:
            if sev_filter:
                cf1, cf2 = st.columns([4, 1])
                cf1.markdown("Filter active — " + " ".join(
                    pill(s, _FIND_SEV.get(s, "#6a747d")) for s in sev_filter), unsafe_allow_html=True)
                if cf2.button("Clear", key="clear_sev"):
                    st.session_state["wk_severity_filter"] = []
                    st.rerun()
            st.caption(f"{len(items)} of {len(pool)} shown"
                       + ("" if show_test_f else f"  ·  {n_test_f} test-path findings hidden"))
            _emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪", "info": "⚪"}
            df = pd.DataFrame([{
                "severity": f"{_emoji.get(f.severity.value,'')} {f.severity.value.upper()}",
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
    page_header(_VIEW_ICON["PQC Readiness"], "Post-quantum readiness",
                subtitle="Crypto-agility, quantum-risk timeline, and migration sequencing",
                meta=[("Agility", f"{rd.crypto_agility_index:.0f}/100 · {rd.agility_grade}")])
    m = st.columns(4)
    m[0].metric("Crypto-agility index", f"{rd.crypto_agility_index:.0f}/100", rd.agility_grade, delta_color="off")
    m[1].metric("High-priority (NQM 2028)", rd.nqm_phase_counts.get("high-priority-2028", 0))
    m[2].metric("Full adoption (NQM 2029)", rd.nqm_phase_counts.get("full-adoption-2029", 0))
    m[3].metric("Already quantum-safe", rd.nqm_phase_counts.get("no-action", 0))
    st.divider()
    st.markdown("**Quantum-risk timeline** — assets that fail Mosca's inequality if a "
                "cryptographically-relevant quantum computer arrives in year …")
    tl = pd.DataFrame(rd.quantum_risk_timeline)
    if not tl.empty:
        fig = go.Figure(go.Bar(
            x=tl["year"], y=tl["exposed_assets"],
            marker=dict(color=tl["exposed_assets"], colorscale=[[0, "#f6c199"], [1, "#bc4c00"]]),
            hovertemplate="year %{x}<br>%{y} assets exposed<extra></extra>",
        ))
        fig.update_layout(height=240, margin=dict(t=10, b=10, l=10, r=10),
                           paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                           xaxis=dict(title=None, dtick=1), yaxis=dict(title="exposed assets"))
        st.plotly_chart(fig)
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
    page_header(_VIEW_ICON["Mosca Lab"], "Mosca Lab",
                subtitle="Stress-test your own harvest-now-decrypt-later assumptions")
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

    left, right = st.columns([3, 2])
    with left:
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
    with right:
        n_ok = len(assets) - len(at_risk)
        st.markdown("**At risk under this scenario**")
        donut(["At risk", "Within margin"], [len(at_risk), n_ok], ["#cf222e", "#2f7c50"])
        st.markdown(f"<div style='line-height:1.9'>{pill(f'At risk · {len(at_risk)}', '#cf222e')}"
                    f"&nbsp; {pill(f'Within margin · {n_ok}', '#2f7c50')}</div>", unsafe_allow_html=True)
        st.caption("At risk = X + Y (secrecy + migration time) exceeds the years left "
                   "before the assumed quantum-threat year Z.")

# ================= COVERAGE =================
else:
    page_header(_VIEW_ICON["Coverage"], "Methodology & coverage",
                subtitle="How CRYPTONEX scores, and what every color means")
    cov = result.coverage
    c = st.columns(4)
    c[0].metric("Collectors run", len(cov.scanners_run))
    c[1].metric("Files parsed", cov.files_parsed)
    c[2].metric("Files skipped", sum(cov.files_skipped.values()) if cov.files_skipped else 0)
    c[3].metric("Known limitations", len(cov.known_limitations))
    st.caption("Collectors: " + ", ".join(f"`{s}`" for s in cov.scanners_run))
    if cov.files_skipped:
        st.caption("Skipped: " + ", ".join(f"{k} ({v})" for k, v in cov.files_skipped.items()))

    st.divider()
    st.markdown("### 🎨 What every color and rating in this console means")
    rating_glossary()

    st.divider()
    st.markdown("### How every asset is scored — evidence, not a black box")
    st.caption("Every asset in the Inventory carries this exact four-way breakdown so a reviewer "
               "can always tell fact from inference.")
    e1, e2 = st.columns(2)
    with e1:
        st.markdown("🔍 **Observed** — evidence-backed")
        st.caption("The literal algorithm, key size, curve or hash pulled straight out of the "
                   "source line, certificate, or binary symbol that triggered the match. Not a guess.")
        st.markdown("📚 **Knowledge base** — deterministic, cited")
        st.caption("Quantum status and the PQC target come from a versioned YAML rule table "
                   "(`knowledge/algorithms.yaml`, `pqc_mapping.yaml`) — the same input always "
                   "produces the same, explainable output. No model, no randomness.")
    with e2:
        st.markdown("🧭 **Inferred** — heuristic, review before acting")
        st.caption("Business criticality, data classification and external-facing status are "
                   "guessed from path/config keywords (e.g. `pki/`, `payments/`). Flagged as "
                   "inferred so a human double-checks before acting on it.")
        st.markdown("⚙️ **Assumed** — operator-set")
        st.caption("Mosca's X (data secrecy years), Y (migration years) and Z (quantum-threat year) "
                   "are scenario assumptions you control in the Mosca Lab — CRYPTONEX never "
                   "claims to predict when a quantum computer arrives.")

    st.divider()
    with st.expander("Known limitations of this build", expanded=False):
        for x in cov.known_limitations:
            st.write(f"- {x}")
    st.caption(f"tool {result.tool_version} · kb {result.kb_version} · config {result.config_hash}")
