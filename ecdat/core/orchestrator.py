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
    scanner_errors: list[str] = []

    for sc in all_scanners(scanners):
        run_names.append(sc.name)
        try:
            for item in sc.scan(ctx):
                if isinstance(item, SecurityFinding):
                    findings.append(item)
                else:
                    raw_findings.append(item)
        except Exception as exc:  # one scanner failing must not kill the scan
            scanner_errors.append(f"collector '{sc.name}' stopped early: {type(exc).__name__}")

    # constant / hand-rolled-crypto pass
    try:
        _const = list(scan_constants(ctx))
    except Exception as exc:
        _const = []
        scanner_errors.append(f"constant pass stopped early: {type(exc).__name__}")
    for _kind, finding, hint in _const:
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

    # dedupe findings by id, tag test-path findings
    from ecdat.domain.paths import is_test_path
    findings = list({f.id: f for f in findings}.values())
    for f in findings:
        f.test_path = is_test_path(f.location.split("!")[-1])
    findings.sort(key=lambda f: (f.test_path, -_SEV_RANK[f.severity], f.location))

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

    limitations = ["detection uses regex + constant fingerprints, not full AST parsing "
                   "(no variable indirection, wrapper functions, or generated code)",
                   "business criticality / data classification / external-exposure are heuristic "
                   "inferences from path & config signals — review before acting",
                   "CVE/RUSTSEC/GHSA advisories are a versioned offline snapshot, not a live feed"]
    if "binary" not in run_names:
        limitations.append("binary collector not run (install `lief`, or --scanners includes binary)")
    if "container" not in run_names:
        limitations.append("container collector not run")
    limitations.extend(scanner_errors)
    limitations.append("live-network/TLS, cloud-KMS and HSM/PKCS#11 collectors: roadmap (M2)")

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
