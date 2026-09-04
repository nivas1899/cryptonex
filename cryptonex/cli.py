from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from cryptonex import __version__
from cryptonex.core.orchestrator import run_scan
from cryptonex.knowledge import get_kb
from cryptonex.reporters.cbom import to_cbom
from cryptonex.reporters.json_out import to_json
from cryptonex.reporters.report import write_report
from cryptonex.reporters.sarif import to_sarif

app = typer.Typer(add_completion=False, help="Enterprise Cryptographic Discovery & Analysis Tool")
console = Console()

_SEV_STYLE = {"safe": "green", "weakened": "yellow", "vulnerable": "dark_orange3",
              "broken": "red", "unknown": "dim"}


@app.command()
def scan(
    target: str = typer.Argument(..., help="Directory or file to scan"),
    out: Path = typer.Option("cryptonex-out", "--out", "-o", help="Output directory"),
    fmt: str = typer.Option("cbom,json,report", "--format", "-f",
                            help="Comma-separated: cbom,json,report,sarif"),
    crqc_year: int = typer.Option(2032, "--crqc-year", help="Z — assumed CRQC arrival year"),
    x: float = typer.Option(None, "--x", help="Override X (data secrecy lifetime, years)"),
    y: float = typer.Option(None, "--y", help="Override Y (migration time, years)"),
    scanners: str = typer.Option(None, "--scanners", help="Comma-separated subset"),
    fail_on: str = typer.Option(None, "--fail-on",
                                help="Exit non-zero if any asset status is at/above this (weakened|vulnerable|broken)"),
    no_timestamp: bool = typer.Option(False, "--no-timestamp", help="Deterministic CBOM"),
):
    """Scan a codebase for cryptographic assets and assess post-quantum risk."""
    sc_list = scanners.split(",") if scanners else None
    console.print(f"[bold]CRYPTONEX[/] {__version__}  ·  scanning [cyan]{target}[/] …")
    result = run_scan(target, scanners=sc_list, crqc_year=crqc_year, x=x, y=y)

    out.mkdir(parents=True, exist_ok=True)
    formats = {f.strip() for f in fmt.split(",")}
    written = []
    if "json" in formats:
        (out / "result.json").write_text(to_json(result), encoding="utf-8")
        written.append(out / "result.json")
    if "cbom" in formats:
        (out / "cbom.json").write_text(to_cbom(result, no_timestamp=no_timestamp), encoding="utf-8")
        written.append(out / "cbom.json")
    if "report" in formats:
        written.append(Path(write_report(result, out / "report.pdf")))
    if "sarif" in formats:
        (out / "results.sarif").write_text(to_sarif(result), encoding="utf-8")
        written.append(out / "results.sarif")

    _print_summary(result)
    console.print("\n[dim]written:[/] " + ", ".join(str(w) for w in written))

    if fail_on:
        order = ["weakened", "vulnerable", "broken"]
        sev_map = {"low": "weakened", "medium": "weakened",
                   "high": "vulnerable", "critical": "broken"}
        threshold = order.index(fail_on) if fail_on in order else len(order)
        worst = max(
            (order.index(a.quantum_status.value) for a in result.assets
             if a.quantum_status.value in order),
            default=-1,
        )
        worst = max(
            worst,
            max((order.index(sev_map[f.severity.value]) for f in result.findings
                 if f.severity.value in sev_map), default=-1),
        )
        if worst >= threshold:
            console.print(f"[red]fail-on {fail_on}: threshold met[/]")
            raise typer.Exit(code=1)


def _print_summary(result) -> None:
    p = result.posture
    rd = result.pqc_readiness
    from collections import Counter
    prod_findings = [f for f in result.findings if not f.test_path]
    fc = Counter(f.severity.value for f in prod_findings)
    test_f = len(result.findings) - len(prod_findings)
    test_note = f"  ·  [dim]{p.test_only_assets} test-only (excluded from grade)[/]" if p.test_only_assets else ""
    console.print(
        f"\n[bold]Posture {p.grade}[/] ({p.posture_score:.0f}/100)  ·  "
        f"{p.total_assets} assets{test_note}  ·  "
        f"[dark_orange3]{p.by_status.get('vulnerable',0)} vulnerable[/]  "
        f"[red]{p.by_status.get('broken',0)} broken[/]  "
        f"[yellow]{p.by_status.get('weakened',0)} weakened[/]  ·  "
        f"HNDL {p.hndl_count}  ·  Mosca at-risk {p.at_risk_count}"
    )
    console.print(
        f"[bold]Weaknesses[/] {len(prod_findings)}  "
        f"([red]{fc.get('critical',0)} critical[/] [dark_orange3]{fc.get('high',0)} high[/] "
        f"[yellow]{fc.get('medium',0)} medium[/] {fc.get('low',0)} low)"
        + (f" [dim]+{test_f} in test paths[/]" if test_f else "")
        + f"  ·  crypto-agility {rd.crypto_agility_index:.0f}/100 ({rd.agility_grade})  ·  "
        f"NQM 2028 wave: {rd.nqm_phase_counts.get('high-priority-2028',0)}"
    )
    if prod_findings:
        ft = Table(show_header=True, header_style="dim", box=None, pad_edge=False)
        ft.add_column("sev"); ft.add_column("finding"); ft.add_column("where")
        _fs = {"critical": "red", "high": "dark_orange3", "medium": "yellow", "low": "dim", "info": "dim"}
        for f in prod_findings[:8]:
            ft.add_row(f"[{_fs[f.severity.value]}]{f.severity.value}[/]", f.title[:52], f.location)
        console.print(ft)
    t = Table(show_header=True, header_style="dim", box=None, pad_edge=False)
    t.add_column("asset"); t.add_column("family"); t.add_column("status")
    t.add_column("crit"); t.add_column("recommended"); t.add_column("risk", justify="right")
    for a in result.assets[:15]:
        st = a.quantum_status.value
        t.add_row(
            a.name,
            a.algorithm_family,
            f"[{_SEV_STYLE.get(st,'')}]{st}[/]",
            a.criticality.value,
            a.recommendation.target_algorithm if a.recommendation else "—",
            f"{a.risk_score:.0f}",
        )
    console.print(t)


@app.command()
def serve(
    result: Path = typer.Option("cryptonex-out/result.json", "--result",
                                help="Scan result JSON to load (optional — the console can scan directly)"),
    port: int = typer.Option(8713, "--port"),
):
    """Open the local web console. Scan a codebase from the browser, or load an existing result."""
    gui = Path(__file__).parent / "gui" / "streamlit_app.py"
    # Theme is passed explicitly so the console looks the same from any working
    # directory (a bare `.streamlit/config.toml` is only picked up from the CWD).
    theme = [
        "--theme.base", "light",
        "--theme.primaryColor", "#1f5fbf",
        "--theme.backgroundColor", "#f5f6f7",
        "--theme.secondaryBackgroundColor", "#eceef0",
        "--theme.textColor", "#191d21",
        "--theme.linkColor", "#1f5fbf",
        "--theme.borderColor", "#e2e5e8",
        "--theme.baseRadius", "small",
        "--theme.showWidgetBorder", "true",
        "--client.toolbarMode", "minimal",
        "--browser.gatherUsageStats", "false",
    ]
    args = [sys.executable, "-m", "streamlit", "run", str(gui),
            "--server.port", str(port), "--server.headless", "true", *theme]
    if result.exists():
        args += ["--", str(result.resolve())]
    else:
        console.print("[dim]no scan result loaded — the console will open on the Scan page[/]")
    console.print(f"[bold]CRYPTONEX console[/] → http://localhost:{port}")
    subprocess.run(args, check=False)


@app.command("kb")
def kb_info():
    """Show Knowledge Base version and contents."""
    from cryptonex.scanners.registry import available_scanners

    kb = get_kb()
    uniq_rules = len({r.id for rs in kb.rules_by_ext.values() for r in rs})
    console.print(f"kb version:          [cyan]{kb.version}[/]")
    console.print(f"algorithm families:  {len(kb.algorithms['families'])}")
    console.print(f"aliases:             {len(kb.aliases.get('aliases', {}))}")
    console.print(f"libraries:           {len(kb.libraries.get('libraries', []))}")
    console.print(f"pqc recommendation:  {len(kb.pqc_rules())} rules")
    langs = sorted({r.language for rs in kb.rules_by_ext.values() for r in rs})
    console.print(f"crypto detection:    {uniq_rules} rules across {len(langs)} languages")
    console.print(f"threat / misuse:     {len(kb.misuse_rules)} rules")
    console.print(f"crypto constants:    {len(kb.constants)} fingerprints")
    console.print(f"library advisories:  {len(kb.advisories)} (CVE / RUSTSEC / GHSA)")
    console.print(f"scanners:            {', '.join(available_scanners())}")


@app.command()
def version():
    console.print(f"CRYPTONEX {__version__}")


if __name__ == "__main__":
    app()
