"""Mosca inequality + risk scoring. Pure functions, no I/O.

Risk score formula (0-100):

    risk = 100
         * w_status
         * (0.5*w_crit + 0.3*w_expose + 0.2*w_surface)
         * w_conf
         * w_hndl

where w_expose = sigmoid(exposure_years / 4) and
exposure_years = (X + Y) - (Z - now).
"""
from __future__ import annotations

import math

from ecdat.domain.enums import (
    CONFIDENCE_WEIGHT,
    CRITICALITY_MULTIPLIER,
    CRITICALITY_WEIGHT,
    HNDL_PRIMITIVES,
    STATUS_WEIGHT,
    QuantumStatus,
)
from ecdat.domain.models import CryptoAsset, MoscaInputs, MoscaResult


def _sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-z))


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def mosca(inputs: MoscaInputs) -> MoscaResult:
    lhs = inputs.data_lifetime_years + inputs.migration_years
    rhs = inputs.crqc_year - inputs.now_year
    exposure = lhs - rhs
    at_risk = lhs > rhs
    formula = (
        f"X({inputs.data_lifetime_years:g}) + Y({inputs.migration_years:g}) = {lhs:g}  "
        f"vs  Z({inputs.crqc_year}) - now({inputs.now_year}) = {rhs:g}  ->  "
        + (f"AT RISK, exposed ~{exposure:.1f}y" if at_risk else "within margin")
    )
    return MoscaResult(at_risk=at_risk, exposure_years=exposure, formula=formula)


def hndl_exposed(asset: CryptoAsset, mosca_result: MoscaResult) -> bool:
    return (
        asset.quantum_status == QuantumStatus.VULNERABLE
        and asset.primitive in HNDL_PRIMITIVES
        and mosca_result.exposure_years > 0
    )


def risk_score(asset: CryptoAsset, mosca_result: MoscaResult) -> float:
    w_status = STATUS_WEIGHT[asset.quantum_status]
    if w_status == 0.0:
        return 0.0
    w_crit = CRITICALITY_WEIGHT[asset.criticality]
    w_expose = _sigmoid(mosca_result.exposure_years / 4.0)
    w_surface = 1.0 if asset.external_facing else 0.7
    w_conf = CONFIDENCE_WEIGHT[asset.detection.confidence]
    w_hndl = 1.15 if hndl_exposed(asset, mosca_result) else 1.0

    raw = 100.0 * w_status * (0.5 * w_crit + 0.3 * w_expose + 0.2 * w_surface) * w_conf * w_hndl
    return round(_clamp(raw, 0.0, 100.0), 1)


def assess(asset: CryptoAsset, inputs: MoscaInputs) -> CryptoAsset:
    """Return a copy of *asset* with mosca_inputs/result, risk_score, hndl filled."""
    mr = mosca(inputs)
    asset.mosca_inputs = inputs
    asset.mosca_result = mr
    asset.hndl_exposed = hndl_exposed(asset, mr)
    asset.risk_score = risk_score(asset, mr)
    return asset


def posture_score(assets: list[CryptoAsset]) -> tuple[float, str]:
    if not assets:
        return 100.0, "A"
    penalty = sum(
        a.risk_score * CRITICALITY_MULTIPLIER[a.criticality] for a in assets
    ) / len(assets) / 3.0
    score = round(_clamp(100.0 - penalty, 0.0, 100.0), 1)
    grade = (
        "A" if score >= 85 else
        "B" if score >= 70 else
        "C" if score >= 55 else
        "D" if score >= 40 else
        "F"
    )
    return score, grade
