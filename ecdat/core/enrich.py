from __future__ import annotations

from ecdat.domain.enums import AssetType, Criticality, QuantumStatus
from ecdat.domain.models import CryptoAsset, MoscaInputs
from ecdat.domain.recommend import recommend
from ecdat.domain.risk import assess
from ecdat.knowledge import get_kb


def enrich_and_assess(
    assets: list[CryptoAsset], crqc_year: int, now_year: int,
    x_override: float | None = None, y_override: float | None = None,
) -> list[CryptoAsset]:
    kb = get_kb()
    rules = kb.pqc_rules()

    for a in assets:
        paths = [loc.component for loc in a.locations] or [a.name]

        # data classification
        dc = None
        for p in paths:
            dc = kb.data_class_for_path(p)
            if dc:
                break
        a.data_classification = dc or "INTERNAL"

        # external facing
        if not a.external_facing:
            a.external_facing = any(kb.is_external(p) for p in paths)

        # quantum status
        if a.asset_type == AssetType.LIBRARY:
            entry = kb.library_lookup(
                a.parameters.extra.get("ecosystem", ""), a.algorithm_family,
                a.parameters.extra.get("version"),
            )
            if entry and entry.get("flagged"):
                a.quantum_status = QuantumStatus.VULNERABLE
                a.quantum_status_reason = entry.get("reason", "Library predates post-quantum support.")
            else:
                a.quantum_status = QuantumStatus.SAFE
                a.quantum_status_reason = "Library catalogued; no migration concern at this version."
        else:
            status, reason = kb.classify(
                a.algorithm_family, a.primitive.value, a.parameters.model_dump()
            )
            # expired certs are always a concern regardless of family
            if a.parameters.extra.get("expired") == "true" and status == QuantumStatus.SAFE.value:
                status, reason = "vulnerable", "Certificate is expired."
            a.quantum_status = QuantumStatus(status)
            a.quantum_status_reason = reason

        # criticality
        is_ca_key = a.parameters.extra.get("ca") == "true"
        bucket, why = kb.criticality(paths, a.external_facing, a.data_classification, is_ca_key)
        a.criticality = Criticality(bucket)
        a.criticality_reason = why

        # recommendation
        contexts = []
        for p in paths:
            contexts.extend(kb.context_tags(p))
        a.recommendation = recommend(a, rules, contexts)

        # Mosca inputs — X from data class, Y from recommendation effort
        x = x_override if x_override is not None else kb.data_lifetime(a.data_classification)
        if y_override is not None:
            y = y_override
        elif a.recommendation is not None:
            y = kb.migration_years(a.recommendation.migration_effort.value)
        else:
            y = kb.migration_years("low")
        assess(a, MoscaInputs(
            data_lifetime_years=x, migration_years=y,
            crqc_year=crqc_year, now_year=now_year,
        ))

    return assets
