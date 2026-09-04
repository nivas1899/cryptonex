"""Estate-level post-quantum readiness analytics — crypto-agility index,
migration waves, India NQM phase mapping, and a quantum-risk timeline.
Pure functions.
"""
from __future__ import annotations

from ecdat.domain.enums import (
    Criticality,
    Effort,
    HNDL_PRIMITIVES,
    Primitive,
    QuantumStatus,
)
from ecdat.domain.models import CryptoAsset, MigrationWave, MoscaInputs, PQCReadiness
from ecdat.domain.risk import mosca

_UNSAFE = {QuantumStatus.VULNERABLE, QuantumStatus.BROKEN, QuantumStatus.WEAKENED}
_EFFORT_ORDER = [Effort.TRIVIAL, Effort.LOW, Effort.MEDIUM, Effort.HIGH, Effort.ARCHITECTURAL]
_EFFORT_COST = {Effort.TRIVIAL: 0.05, Effort.LOW: 0.2, Effort.MEDIUM: 0.5,
                Effort.HIGH: 0.8, Effort.ARCHITECTURAL: 1.0}
_WAVE_NAME = {
    Effort.TRIVIAL: "Configuration & key-size changes",
    Effort.LOW: "Dependency & library upgrades",
    Effort.MEDIUM: "Localised code & protocol changes",
    Effort.HIGH: "Standards / counterparty coordination",
    Effort.ARCHITECTURAL: "Architectural — roots of trust & hardware",
}


def crypto_agility_index(assets: list[CryptoAsset]) -> tuple[float, str]:
    """0..100, higher = the estate is easier to make quantum-safe.

    Penalises unsafe assets weighted by how hard they are to change and how
    business-critical they are.
    """
    unsafe = [a for a in assets if a.quantum_status in _UNSAFE]
    if not assets:
        return 100.0, "A"
    if not unsafe:
        return 100.0, "A"
    crit_w = {Criticality.LOW: 0.4, Criticality.MEDIUM: 0.7,
              Criticality.HIGH: 1.0, Criticality.CRITICAL: 1.3}
    penalty = 0.0
    for a in unsafe:
        eff = a.recommendation.migration_effort if a.recommendation else Effort.MEDIUM
        penalty += _EFFORT_COST[eff] * crit_w[a.criticality]
    # normalise: full penalty if every asset were architectural+critical
    max_penalty = len(assets) * _EFFORT_COST[Effort.ARCHITECTURAL] * crit_w[Criticality.CRITICAL]
    idx = round(max(0.0, 100.0 * (1.0 - penalty / max_penalty)), 1)
    grade = ("A" if idx >= 85 else "B" if idx >= 70 else "C" if idx >= 55
             else "D" if idx >= 40 else "F")
    return idx, grade


def migration_waves(assets: list[CryptoAsset]) -> list[MigrationWave]:
    buckets: dict[Effort, list[CryptoAsset]] = {e: [] for e in _EFFORT_ORDER}
    for a in assets:
        if a.quantum_status in _UNSAFE and a.recommendation:
            buckets[a.recommendation.migration_effort].append(a)
    waves: list[MigrationWave] = []
    order = 1
    for eff in _EFFORT_ORDER:
        items = buckets[eff]
        if not items:
            continue
        items.sort(key=lambda a: -a.risk_score)
        waves.append(MigrationWave(
            order=order,
            name=_WAVE_NAME[eff],
            effort=eff.value,
            asset_count=len(items),
            risk_reduction=round(sum(a.risk_score for a in items), 1),
            example_assets=[f"{a.name} ({a.locations[0].component})" if a.locations else a.name
                            for a in items[:4]],
        ))
        order += 1
    return waves


def nqm_phase(asset: CryptoAsset) -> str:
    """India National Quantum Mission migration phase for an asset."""
    if asset.quantum_status not in _UNSAFE:
        return "no-action"
    if asset.criticality in (Criticality.CRITICAL, Criticality.HIGH) or asset.external_facing:
        return "high-priority-2028"
    if asset.hndl_exposed:
        return "high-priority-2028"
    return "full-adoption-2029"


def quantum_risk_timeline(assets: list[CryptoAsset], now_year: int) -> list[dict]:
    """For each year, how many assets fail Mosca's inequality if the CRQC arrives then."""
    unsafe = [a for a in assets if a.quantum_status in _UNSAFE and a.mosca_inputs]
    out = []
    for yr in range(now_year, now_year + 15):
        exposed = 0
        for a in unsafe:
            mi = MoscaInputs(
                data_lifetime_years=a.mosca_inputs.data_lifetime_years,
                migration_years=a.mosca_inputs.migration_years,
                crqc_year=yr, now_year=now_year,
            )
            if mosca(mi).at_risk:
                exposed += 1
        out.append({"year": yr, "exposed_assets": exposed})
    return out


def hndl_at_rest(assets: list[CryptoAsset]) -> int:
    """Assets whose HNDL exposure is worst — long-lived confidentiality primitives."""
    n = 0
    for a in assets:
        if (a.hndl_exposed and a.primitive in HNDL_PRIMITIVES
                and a.data_classification in ("SECRET", "PCI", "PII")):
            n += 1
    return n


def build_readiness(assets: list[CryptoAsset], now_year: int) -> PQCReadiness:
    idx, grade = crypto_agility_index(assets)
    phases: dict[str, int] = {}
    for a in assets:
        p = nqm_phase(a)
        phases[p] = phases.get(p, 0) + 1
    return PQCReadiness(
        crypto_agility_index=idx,
        agility_grade=grade,
        migration_waves=migration_waves(assets),
        nqm_phase_counts=phases,
        quantum_risk_timeline=quantum_risk_timeline(assets, now_year),
        hndl_at_rest_count=hndl_at_rest(assets),
    )
