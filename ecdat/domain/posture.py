from __future__ import annotations

from collections import Counter

from ecdat.domain.models import CryptoAsset, Posture
from ecdat.domain.risk import posture_score


def build_posture(assets: list[CryptoAsset]) -> Posture:
    score, grade = posture_score(assets)
    by_status = Counter(a.quantum_status.value for a in assets)
    by_crit = Counter(a.criticality.value for a in assets)
    return Posture(
        total_assets=len(assets),
        by_status=dict(by_status),
        by_criticality=dict(by_crit),
        hndl_count=sum(1 for a in assets if a.hndl_exposed),
        at_risk_count=sum(
            1 for a in assets if a.mosca_result and a.mosca_result.at_risk and a.risk_score > 0
        ),
        posture_score=score,
        grade=grade,
    )
