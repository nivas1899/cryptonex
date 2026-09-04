from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from ecdat import __version__
from ecdat.core.enrich import enrich_and_assess
from ecdat.core.normalize import normalize
from ecdat.domain.models import CoverageStatement, ScanResult
from ecdat.domain.posture import build_posture
from ecdat.knowledge import get_kb
from ecdat.scanners import all_scanners
from ecdat.scanners.base import ScanContext


def run_scan(
    target: str,
    scanners: list[str] | None = None,
    crqc_year: int = 2032,
    now_year: int | None = None,
    x: float | None = None,
    y: float | None = None,
) -> ScanResult:
    kb = get_kb()
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"scan target does not exist: {target}")
    now_year = now_year or datetime.now().year
    started = datetime.now(timezone.utc)

    ctx = ScanContext(root=root)
    findings = []
    run_names: list[str] = []
    for sc in all_scanners(scanners):
        run_names.append(sc.name)
        findings.extend(list(sc.scan(ctx)))

    assets, graph = normalize(findings)
    assets = enrich_and_assess(assets, crqc_year=crqc_year, now_year=now_year,
                               x_override=x, y_override=y)
    assets.sort(key=lambda a: (-a.risk_score, a.id))
    posture = build_posture(assets)

    finished = datetime.now(timezone.utc)
    cfg = {"scanners": run_names, "crqc_year": crqc_year, "x": x, "y": y}
    config_hash = hashlib.blake2b(
        json.dumps(cfg, sort_keys=True).encode(), digest_size=6
    ).hexdigest()

    coverage = CoverageStatement(
        scanners_run=run_names,
        files_parsed=ctx.files_parsed,
        files_skipped=ctx.files_skipped,
        known_limitations=[
            "binary and container collectors not run (M0 scope)",
            "detection uses regex rules, not full AST parsing",
        ],
    )

    return ScanResult(
        tool_version=__version__,
        kb_version=kb.version,
        config_hash=config_hash,
        target=str(root),
        started_at=started,
        finished_at=finished,
        assets=assets,
        graph=graph,
        posture=posture,
        coverage=coverage,
    )
