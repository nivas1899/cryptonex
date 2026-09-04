from __future__ import annotations

from ecdat.domain.enums import AssetType, Criticality, QuantumStatus
from ecdat.domain.models import AssessmentBasis, CryptoAsset, MoscaInputs
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

        # ---- data classification (INFERRED from path keywords) ----
        hit = None
        for p in paths:
            hit = kb.data_class_for_path(p)
            if hit:
                break
        if hit:
            a.data_classification, kw = hit
            a.data_classification_reason = f"path contains '{kw}'"
        else:
            a.data_classification = "INTERNAL"
            a.data_classification_reason = "no classification keyword in path — defaulted to INTERNAL"

        # ---- external-facing (INFERRED) ----
        if a.external_facing and not a.external_facing_reason:
            a.external_facing_reason = "collector marked it external (TLS server cert / edge config)"
        elif not a.external_facing:
            eh = next((kb.external_hint(p) for p in paths if kb.external_hint(p)), None)
            if eh:
                a.external_facing = True
                a.external_facing_reason = f"path contains '{eh}'"
            else:
                a.external_facing_reason = "no external-facing signal — assumed internal"

        # ---- quantum status (KB-DERIVED, deterministic + cited) ----
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
            if a.parameters.extra.get("expired") == "true" and status == QuantumStatus.SAFE.value:
                status, reason = "vulnerable", "Certificate is expired."
            a.quantum_status = QuantumStatus(status)
            a.quantum_status_reason = reason

        # ---- criticality (INFERRED, scored) ----
        is_ca_key = a.parameters.extra.get("ca") == "true"
        bucket, why = kb.criticality(paths, a.external_facing, a.data_classification, is_ca_key)
        a.criticality = Criticality(bucket)
        a.criticality_reason = why

        # ---- recommendation (KB-DERIVED rule) ----
        contexts = []
        for p in paths:
            contexts.extend(kb.context_tags(p))
        a.recommendation = recommend(a, rules, contexts)

        # ---- Mosca inputs — X inferred from data class, Y from effort, Z assumed ----
        x = x_override if x_override is not None else kb.data_lifetime(a.data_classification)
        x_basis = ("operator override" if x_override is not None
                   else f"{a.data_classification} data → {x:g}y default")
        if y_override is not None:
            y, y_basis = y_override, "operator override"
        elif a.recommendation is not None:
            y = kb.migration_years(a.recommendation.migration_effort.value)
            y_basis = f"{a.recommendation.migration_effort.value} effort → {y:g}y"
        else:
            y = kb.migration_years("low")
            y_basis = "no migration needed → low effort default"
        assess(a, MoscaInputs(
            data_lifetime_years=x, migration_years=y,
            crqc_year=crqc_year, now_year=now_year,
        ))

        # ---- assessment provenance ----
        a.assessment = AssessmentBasis(
            observed=[
                f"algorithm: {a.name} ({a.algorithm_family}/{a.primitive.value})",
                f"parameters: {a.parameters.model_dump(exclude_none=True, exclude={'extra'}) or 'not resolved'}",
                f"located at {len(a.locations)} site(s), detected by {a.detection.scanner} "
                f"(confidence: {a.detection.confidence.value})",
            ],
            kb_derived=[
                f"quantum status: {a.quantum_status.value} — {a.quantum_status_reason}",
            ] + ([f"recommendation: {a.recommendation.target_algorithm} (rule {a.recommendation.rule_id})"]
                 if a.recommendation else []),
            inferred=[
                f"data classification: {a.data_classification} — {a.data_classification_reason}",
                f"external-facing: {a.external_facing} — {a.external_facing_reason}",
                f"business criticality: {a.criticality.value} — {a.criticality_reason}",
            ],
            assumed=[
                f"X (data secrecy lifetime): {x:g}y — {x_basis}",
                f"Y (migration time): {y:g}y — {y_basis}",
                f"Z (quantum threat year): {crqc_year} — configurable assumption, not a prediction",
            ],
        )

    return assets
