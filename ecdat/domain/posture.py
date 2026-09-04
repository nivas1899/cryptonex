from __future__ import annotations

from collections import Counter

from ecdat.domain.models import CryptoAsset, Posture
from ecdat.domain.risk import posture_score


def build_posture(assets: list[CryptoAsset]) -> Posture:
    """Grade is computed on production assets only; test/example assets are
    inventoried but excluded so a repo's own test fixtures don't skew the score."""
    prod = [a for a in assets if not a.test_only]
    graded = prod or assets  # if everything is test code, grade on everything
    score, grade = posture_score(graded)
    by_status = Counter(a.quantum_status.value for a in assets)
    by_crit = Counter(a.criticality.value for a in assets)
    return Posture(
        total_assets=len(assets),
        test_only_assets=sum(1 for a in assets if a.test_only),
        by_status=dict(by_status),
        by_criticality=dict(by_crit),
        hndl_count=sum(1 for a in prod if a.hndl_exposed),
        at_risk_count=sum(
            1 for a in prod if a.mosca_result and a.mosca_result.at_risk and a.risk_score > 0
        ),
        posture_score=score,
        grade=grade,
    )
