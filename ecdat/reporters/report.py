"""Executive / audit report. Renders HTML; converts to PDF if weasyprint is present."""
from __future__ import annotations

import html
from datetime import datetime

from ecdat.domain.enums import Effort
from ecdat.domain.models import ScanResult

_SEV = {"safe": "#2f7c50", "weakened": "#9a6700", "vulnerable": "#bc4c00",
        "broken": "#cf222e", "unknown": "#6a747d"}


def _esc(s) -> str:
    return html.escape(str(s))


def render_html(result: ScanResult) -> str:
    p = result.posture
    rows = sorted(result.assets, key=lambda a: -a.risk_score)
    top = rows[:12]
    hndl = [a for a in result.assets if a.hndl_exposed]

    by_effort: dict[str, list] = {}
    for a in result.assets:
        if a.recommendation:
            by_effort.setdefault(a.recommendation.migration_effort.value, []).append(a)
    effort_order = [e.value for e in Effort]

    def asset_row(a):
        return (
            f"<tr><td>{_esc(a.name)}<br><span class='loc'>{_esc(a.locations[0].component) if a.locations else ''}</span></td>"
            f"<td>{_esc(a.algorithm_family)}</td>"
            f"<td style='color:{_SEV.get(a.quantum_status.value)}'>{a.quantum_status.value}</td>"
            f"<td>{a.criticality.value}</td>"
            f"<td>{_esc(a.recommendation.target_algorithm) if a.recommendation else '—'}</td>"
            f"<td class='n'>{a.risk_score:.0f}</td></tr>"
        )

    top_rows = "".join(asset_row(a) for a in top)
    hndl_rows = "".join(f"<li>{_esc(a.name)} — {_esc(a.locations[0].component) if a.locations else ''}</li>" for a in hndl) or "<li>none</li>"

    waves = ""
    for e in effort_order:
        items = by_effort.get(e, [])
        if not items:
            continue
        li = "".join(
            f"<li>{_esc(a.name)} → <b>{_esc(a.recommendation.target_algorithm)}</b> "
            f"<span class='loc'>({_esc(a.locations[0].component) if a.locations else ''})</span></li>"
            for a in sorted(items, key=lambda x: -x.risk_score)
        )
        waves += f"<h3>Effort: {e} <span class='loc'>({len(items)})</span></h3><ul>{li}</ul>"

    crit_details = ""
    for a in [x for x in rows if x.criticality.value in ("critical", "high") and x.risk_score > 0][:10]:
        rec = a.recommendation
        crit_details += (
            f"<div class='card'><h3>{_esc(a.name)} "
            f"<span style='color:{_SEV.get(a.quantum_status.value)}'>[{a.quantum_status.value}]</span></h3>"
            f"<p class='loc'>{_esc(a.locations[0].component) if a.locations else ''} · {a.criticality.value} · risk {a.risk_score:.0f}</p>"
            f"<pre>{_esc(a.detection.evidence[0].snippet or '')}</pre>"
            f"<p><b>Mosca:</b> {_esc(a.mosca_result.formula) if a.mosca_result else ''}</p>"
            + (f"<p><b>Recommend:</b> {_esc(rec.target_algorithm)}"
               + (f" (hybrid: {_esc(rec.hybrid_option)})" if rec.hybrid_option else "")
               + f" — {_esc(rec.rationale)}</p>" if rec else "")
            + "</div>"
        )

    skipped = ", ".join(f"{k}: {v}" for k, v in result.coverage.files_skipped.items()) or "none"

    # weaknesses
    sev_c = {"critical": "#cf222e", "high": "#bc4c00", "medium": "#9a6700",
             "low": "#57606a", "info": "#8c959f"}
    findings_html = ""
    for f in result.findings[:40]:
        findings_html += (
            f"<div class='card'><h3 style='color:{sev_c.get(f.severity.value)}'>"
            f"[{f.severity.value.upper()}] {_esc(f.title)}</h3>"
            f"<p class='loc'>{_esc(f.location)}  ·  {f.category}"
            + (f"  ·  {f.cwe}" if f.cwe else "") + "</p>"
            f"<pre>{_esc(f.snippet or '')}</pre>"
            f"<p>{_esc(f.description)}</p>"
            f"<p><b>Fix:</b> {_esc(f.remediation)}</p></div>"
        )
    from collections import Counter
    fcount = Counter(f.severity.value for f in result.findings)

    # pqc readiness
    rd = result.pqc_readiness
    tl = rd.quantum_risk_timeline
    tl_bars = ""
    if tl:
        mx = max((t["exposed_assets"] for t in tl), default=1) or 1
        for t in tl:
            h = int(60 * t["exposed_assets"] / mx)
            tl_bars += (f"<span style='display:inline-block;width:22px;text-align:center;"
                        f"vertical-align:bottom'><span style='display:block;height:{h}px;"
                        f"background:#bc4c00;margin:0 2px'></span>"
                        f"<span class='loc'>{str(t['year'])[2:]}</span></span>")
    waves_html = "".join(
        f"<tr><td>Wave {w.order}</td><td>{_esc(w.name)}</td><td>{w.effort}</td>"
        f"<td class='n'>{w.asset_count}</td><td class='n'>{w.risk_reduction:.0f}</td></tr>"
        for w in rd.migration_waves
    )

    return f"""<!doctype html><html><head><meta charset="utf-8"><title>ECDAT report — {_esc(result.target)}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1a1f24;max-width:820px;margin:32px auto;padding:0 20px;line-height:1.5}}
 h1{{font-size:22px;margin-bottom:2px}} h2{{font-size:16px;margin-top:28px;border-bottom:1px solid #ddd;padding-bottom:4px}}
 h3{{font-size:13px;margin:14px 0 4px}}
 .grade{{display:inline-block;font-size:26px;font-weight:700;padding:6px 14px;border-radius:6px;color:#fff}}
 table{{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px}}
 th,td{{text-align:left;padding:5px 8px;border-bottom:1px solid #eee}} td.n{{text-align:right;font-variant-numeric:tabular-nums}}
 .loc{{color:#888;font-size:11px;font-family:ui-monospace,monospace}}
 pre{{background:#f6f8fa;padding:8px;border-radius:5px;font-size:11px;overflow-x:auto}}
 .card{{border:1px solid #e3e6e9;border-radius:7px;padding:10px 14px;margin:10px 0}}
 .meta{{color:#888;font-size:11px;font-family:ui-monospace,monospace}}
</style></head><body>
<h1>Cryptographic Discovery &amp; Post-Quantum Risk Report</h1>
<p class="meta">target {_esc(result.target)} · generated {datetime.now().isoformat(timespec='seconds')} · tool {result.tool_version} · kb {result.kb_version}</p>

<h2>Executive summary</h2>
<p><span class="grade" style="background:{_grade_color(p.grade)}">{p.grade}</span>
&nbsp; Posture score <b>{p.posture_score:.0f}/100</b> across <b>{p.total_assets}</b> cryptographic assets.</p>
<ul>
 <li><b>{p.by_status.get('vulnerable',0)}</b> quantum-vulnerable, <b>{p.by_status.get('broken',0)}</b> already broken, <b>{p.by_status.get('weakened',0)}</b> weakened.</li>
 <li><b>{p.hndl_count}</b> assets exposed to harvest-now-decrypt-later.</li>
 <li><b>{p.at_risk_count}</b> assets fail Mosca's inequality under the current assumptions.</li>
 <li><b>{len(result.findings)}</b> cryptographic weaknesses / misuse findings
   ({fcount.get('critical',0)} critical, {fcount.get('high',0)} high).</li>
 <li>Crypto-agility index <b>{rd.crypto_agility_index:.0f}/100</b> (grade {rd.agility_grade}).</li>
</ul>

<h2>Highest risk</h2>
<table><thead><tr><th>Asset</th><th>Family</th><th>Status</th><th>Crit.</th><th>Recommended</th><th class="n">Risk</th></tr></thead>
<tbody>{top_rows}</tbody></table>

<h2>Harvest-now-decrypt-later exposure</h2>
<ul>{hndl_rows}</ul>
<p class="meta">{rd.hndl_at_rest_count} of these protect long-lived (SECRET/PCI/PII) data — the highest HNDL priority.</p>

<h2>Cryptographic weaknesses &amp; misuse</h2>
<p><b>{len(result.findings)}</b> findings —
 {fcount.get('critical',0)} critical, {fcount.get('high',0)} high, {fcount.get('medium',0)} medium, {fcount.get('low',0)} low.</p>
{findings_html or '<p>none</p>'}

<h2>Post-quantum readiness</h2>
<p><span class="grade" style="background:{_grade_color(rd.agility_grade)}">{rd.agility_grade}</span>
&nbsp; Crypto-agility index <b>{rd.crypto_agility_index:.0f}/100</b> — how readily the estate can be made quantum-safe.</p>
<p><b>India NQM roadmap:</b>
 {rd.nqm_phase_counts.get('high-priority-2028',0)} systems for the Dec-2028 high-priority wave,
 {rd.nqm_phase_counts.get('full-adoption-2029',0)} for full adoption by Dec-2029,
 {rd.nqm_phase_counts.get('no-action',0)} already quantum-safe.</p>
<h3>Quantum-risk timeline — assets exposed if a quantum computer arrives in year&hellip;</h3>
<div style="border-bottom:1px solid #ddd;padding-bottom:4px">{tl_bars}</div>
<h3>Migration waves</h3>
<table><thead><tr><th>Wave</th><th>Scope</th><th>Effort</th><th class="n">Assets</th><th class="n">Risk removed</th></tr></thead>
<tbody>{waves_html}</tbody></table>

<h2>Critical &amp; high assets</h2>
{crit_details or '<p>none</p>'}

<h2>Migration plan</h2>
{waves or '<p>No migrations required.</p>'}

<h2>Methodology &amp; coverage</h2>
<p class="meta">collectors: {', '.join(result.coverage.scanners_run)} · files parsed: {result.coverage.files_parsed} · skipped: {skipped}</p>
<ul>{''.join(f'<li>{_esc(x)}</li>' for x in result.coverage.known_limitations)}</ul>
</body></html>"""


def _grade_color(g: str) -> str:
    return {"A": "#2f7c50", "B": "#2f7c50", "C": "#9a6700", "D": "#bc4c00", "F": "#cf222e"}.get(g, "#6a747d")


def write_report(result: ScanResult, out_path) -> str:
    """Write PDF if weasyprint is available, otherwise HTML. Returns the path written."""
    html_str = render_html(result)
    out_path = str(out_path)
    try:
        from weasyprint import HTML  # type: ignore

        pdf_path = out_path if out_path.endswith(".pdf") else out_path + ".pdf"
        HTML(string=html_str).write_pdf(pdf_path)
        return pdf_path
    except Exception:
        html_path = out_path[:-4] + ".html" if out_path.endswith(".pdf") else out_path + ".html"
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_str)
        return html_path
