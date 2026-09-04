from __future__ import annotations

import re

from cryptonex.domain.enums import AssetType, Effort, QuantumStatus
from cryptonex.domain.models import CryptoAsset, Recommendation

_WS = re.compile(r"\s+")


def _match(rule_match: dict, asset: CryptoAsset, contexts: list[str]) -> bool:
    m = rule_match
    if "asset_type" in m and asset.asset_type.value not in m["asset_type"]:
        return False
    if "primitive" in m and asset.primitive.value not in m["primitive"]:
        return False
    if "family" in m and asset.algorithm_family not in m["family"]:
        return False
    if "context" in m and not any(c in m["context"] for c in contexts):
        return False
    if "key_size" in m and asset.parameters.key_size != m["key_size"]:
        return False
    if "hash" in m:
        h = (asset.parameters.hash or "").upper()
        if h not in {x.upper() for x in m["hash"]}:
            return False
    return True


def recommend(asset: CryptoAsset, rules: list[dict], contexts: list[str]) -> Recommendation | None:
    if asset.quantum_status in (QuantumStatus.SAFE, QuantumStatus.UNKNOWN):
        return None
    for rule in rules:
        if not _match(rule.get("match", {}), asset, contexts):
            continue
        effort = Effort(rule.get("default_effort", "medium"))
        if asset.asset_type == AssetType.LIBRARY:
            effort = Effort.LOW
        elif all(ev.kind == "dependency" for ev in asset.detection.evidence) and asset.detection.evidence:
            effort = Effort.LOW
        rationale = _WS.sub(" ", str(rule.get("rationale", ""))).strip()
        rationale = rationale.replace("{name}", asset.name)
        return Recommendation(
            rule_id=rule["id"],
            target_algorithm=rule["target"],
            hybrid_option=rule.get("hybrid_option"),
            nist_category=rule.get("nist_category"),
            library_support=list(rule.get("library_support", [])),
            protocol_support=rule.get("protocol_support"),
            latency_class=rule.get("latency_class"),
            migration_effort=effort,
            rationale=rationale,
        )
    return None
