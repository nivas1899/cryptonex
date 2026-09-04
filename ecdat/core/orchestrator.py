from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from ecdat import __version__
from ecdat.core.enrich import enrich_and_assess
from ecdat.core.normalize import normalize
from ecdat.domain.enums import QuantumStatus, Severity
from ecdat.domain.models import (
    AlgorithmParameters,
    CoverageStatement,
    Evidence,
    RawFinding,
    ScanResult,
    SecurityFinding,
)
from ecdat.domain.enums import AssetType, Confidence, Primitive
from ecdat.domain.pqc_readiness import build_readiness
from ecdat.domain.posture import build_posture
from ecdat.knowledge import get_kb
from ecdat.scanners import all_scanners
from ecdat.scanners.base import ScanContext
from ecdat.scanners.misuse import scan_constants


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
    raw_findings: list[RawFinding] = []
    findings: list[SecurityFinding] = []
    run_names: list[str] = []

    for sc in all_scanners(scanners):
        run_names.append(sc.name)
        for item in sc.scan(ctx):
            if isinstance(item, SecurityFinding):
                findings.append(item)
            else:
                raw_findings.append(item)

    # constant / hand-rolled-crypto pass
    for _kind, finding, hint in scan_constants(ctx):
        findings.append(finding)
        if hint:
            try:
                prim = Primitive(hint["primitive"]) if hint.get("primitive") else None
            except ValueError:
                prim = None
            raw_findings.append(RawFinding(
                scanner="source.constant",
                asset_type=AssetType.ALGORITHM,
                raw_name=hint["raw_name"],
                family_hint=hint.get("family"),
                primitive_hint=prim,
                parameters=AlgorithmParameters(extra={"detection": "constant"}),
                evidence=Evidence(kind="constant", locator=hint["locator"],
                                  snippet=hint["name"], rule_id=hint["rule_id"]),
                confidence=Confidence.MEDIUM,
            ))

    # dedupe findings by id
    findings = list({f.id: f for f in findings}.values())
    findings.sort(key=lambda f: (-_SEV_RANK[f.severity], f.location))

    assets, graph = normalize(raw_findings)
    assets = enrich_and_assess(assets, crqc_year=crqc_year, now_year=now_year,
                               x_override=x, y_override=y)
    assets.sort(key=lambda a: (-a.risk_score, a.id))
    posture = build_posture(assets)
    readiness = build_readiness(assets, now_year=now_year)

    finished = datetime.now(timezone.utc)
    cfg = {"scanners": run_names, "crqc_year": crqc_year, "x": x, "y": y}
    config_hash = hashlib.blake2b(
        json.dumps(cfg, sort_keys=True).encode(), digest_size=6
    ).hexdigest()

    limitations = ["detection uses regex + constant fingerprints, not full AST parsing"]
    if "binary" not in run_names:
        limitations.append("binary collector not run (install `lief`, or --scanners includes binary)")
    limitations.append("container-image and live-TLS collectors: roadmap")

    coverage = CoverageStatement(
        scanners_run=run_names,
        files_parsed=ctx.files_parsed,
        files_skipped=ctx.files_skipped,
        known_limitations=limitations,
    )

    return ScanResult(
        tool_version=__version__,
        kb_version=kb.version,
        config_hash=config_hash,
        target=str(root),
        started_at=started,
        finished_at=finished,
        assets=assets,
        findings=findings,
        graph=graph,
        posture=posture,
        pqc_readiness=readiness,
        coverage=coverage,
    )


_SEV_RANK = {
    Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
    Severity.LOW: 1, Severity.INFO: 0,
}
