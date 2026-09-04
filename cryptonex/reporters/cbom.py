"""CycloneDX 1.6 CBOM emitter.

Emits one `cryptographic-asset` component per CryptoAsset with cryptoProperties,
a dependencies graph, and ecdat: namespaced risk properties.
"""
from __future__ import annotations

import json
import uuid

from cryptonex.domain.enums import AssetType, Primitive
from cryptonex.domain.models import CryptoAsset, ScanResult

_NS = uuid.UUID("6f9619ff-8b86-d011-b42d-00cf4fc964ff")

_PRIMITIVE_MAP = {
    Primitive.PKE: "pke",
    Primitive.SIGNATURE: "signature",
    Primitive.KEY_AGREEMENT: "key-agree",
    Primitive.KEM: "kem",
    Primitive.HASH: "hash",
    Primitive.MAC: "mac",
    Primitive.BLOCK_CIPHER: "block-cipher",
    Primitive.STREAM_CIPHER: "stream-cipher",
    Primitive.AEAD: "ae",
    Primitive.KDF: "kdf",
    Primitive.DRBG: "drbg",
    Primitive.OTHER: "other",
}

_ASSET_TYPE_MAP = {
    AssetType.ALGORITHM: "algorithm",
    AssetType.CERTIFICATE: "certificate",
    AssetType.KEY: "related-crypto-material",
    AssetType.PROTOCOL: "protocol",
    AssetType.RELATED_MATERIAL: "related-crypto-material",
    AssetType.LIBRARY: "algorithm",
}


def _component(a: CryptoAsset) -> dict:
    at = _ASSET_TYPE_MAP.get(a.asset_type, "algorithm")
    crypto: dict = {"assetType": at}

    if at == "algorithm":
        ap: dict = {"primitive": _PRIMITIVE_MAP.get(a.primitive, "other")}
        if a.parameters.parameter_set:
            ap["parameterSetIdentifier"] = a.parameters.parameter_set
        if a.parameters.curve:
            ap["curve"] = a.parameters.curve
        if a.parameters.mode:
            ap["mode"] = a.parameters.mode.lower()
        if a.parameters.padding:
            ap["padding"] = a.parameters.padding.lower()
        if a.recommendation and a.recommendation.nist_category:
            ap["nistQuantumSecurityLevel"] = a.recommendation.nist_category
        crypto["algorithmProperties"] = ap
    elif at == "certificate":
        cp: dict = {"certificateFormat": "X.509"}
        if a.parameters.extra.get("subject"):
            cp["subjectName"] = a.parameters.extra["subject"]
        crypto["certificateProperties"] = cp
    elif at == "related-crypto-material":
        rp: dict = {"type": "private-key" if a.parameters.extra.get("private") == "true" else "public-key"}
        if a.parameters.key_size:
            rp["size"] = a.parameters.key_size
        if a.parameters.extra.get("fingerprint"):
            rp["value"] = a.parameters.extra["fingerprint"]
        crypto["relatedCryptoMaterialProperties"] = rp

    props = [
        {"name": "cryptonex:quantumStatus", "value": a.quantum_status.value},
        {"name": "cryptonex:quantumStatusReason", "value": a.quantum_status_reason},
        {"name": "cryptonex:detectionConfidence", "value": a.detection.confidence.value},
        {"name": "cryptonex:criticality", "value": a.criticality.value},
        {"name": "cryptonex:criticalityBasis", "value": "inferred: " + a.criticality_reason},
        {"name": "cryptonex:riskScore", "value": str(a.risk_score)},
        {"name": "cryptonex:hndlExposed", "value": str(a.hndl_exposed).lower()},
        {"name": "cryptonex:occurrences", "value": str(a.occurrences)},
        {"name": "cryptonex:dataClassification", "value": a.data_classification},
        {"name": "cryptonex:dataClassificationBasis", "value": "inferred: " + a.data_classification_reason},
        {"name": "cryptonex:externalFacing", "value": str(a.external_facing).lower()},
        {"name": "cryptonex:externalFacingBasis", "value": "inferred: " + a.external_facing_reason},
    ]
    if a.mosca_result and a.quantum_status.value != "safe":
        props.append({"name": "cryptonex:moscaFormula", "value": a.mosca_result.formula})
    if a.recommendation:
        props.append({"name": "cryptonex:recommendedTarget", "value": a.recommendation.target_algorithm})
        props.append({"name": "cryptonex:migrationEffort", "value": a.recommendation.migration_effort.value})
        if a.recommendation.hybrid_option:
            props.append({"name": "cryptonex:hybridOption", "value": a.recommendation.hybrid_option})

    occurrences = [{"location": loc.component + (f":{loc.line}" if loc.line else "")}
                   for loc in a.locations]

    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/{a.id}",
        "name": a.name,
        "cryptoProperties": crypto,
        "properties": props,
        "evidence": {"occurrences": occurrences} if occurrences else {},
    }


def to_cbom(result: ScanResult, no_timestamp: bool = False) -> str:
    content_seed = "|".join(a.id for a in result.assets) + result.kb_version + result.config_hash
    serial = uuid.uuid5(_NS, result.target + content_seed)

    components = [_component(a) for a in sorted(result.assets, key=lambda x: x.id)]

    # dependency edges: component -> the crypto it invokes/depends-on
    deps: dict[str, set[str]] = {}
    ref_ids = {f"crypto/{a.id}" for a in result.assets}
    for e in result.graph:
        deps.setdefault(f"component/{e.src}", set()).add(f"crypto/{e.dst}")
    dependencies = [
        {"ref": k, "dependsOn": sorted(v & ref_ids | (v - ref_ids))}
        for k, v in sorted(deps.items())
    ]

    rd = result.pqc_readiness
    metadata: dict = {
        "tools": {"components": [{"type": "application", "name": "CRYPTONEX", "version": result.tool_version}]},
        "properties": [
            {"name": "cryptonex:kbVersion", "value": result.kb_version},
            {"name": "cryptonex:configHash", "value": result.config_hash},
            {"name": "cryptonex:postureScore", "value": str(result.posture.posture_score)},
            {"name": "cryptonex:postureGrade", "value": result.posture.grade},
            {"name": "cryptonex:cryptoAgilityIndex", "value": str(rd.crypto_agility_index)},
            {"name": "cryptonex:findingsCount", "value": str(len(result.findings))},
            {"name": "cryptonex:nqmHighPriority2028", "value": str(rd.nqm_phase_counts.get("high-priority-2028", 0))},
            {"name": "cryptonex:target", "value": result.target},
        ],
    }
    if not no_timestamp:
        metadata["timestamp"] = result.finished_at.isoformat()

    _RATING = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 1.0}
    vulnerabilities = [
        {
            "bom-ref": f"weakness/{f.id}",
            "id": f.rule_id,
            "ratings": [{"severity": f.severity.value, "score": _RATING[f.severity.value],
                        "method": "other"}],
            "cwes": [int(f.cwe.split("-")[1])] if f.cwe and f.cwe.startswith("CWE-") else [],
            "description": f.title + " — " + f.description,
            "recommendation": f.remediation,
            "affects": [{"ref": f.location}],
            "properties": [{"name": "cryptonex:category", "value": f.category},
                           {"name": "cryptonex:quantumRelevant", "value": str(f.quantum_relevant).lower()}],
        }
        for f in result.findings
    ]

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
        "vulnerabilities": vulnerabilities,
    }
    return json.dumps(doc, indent=2, sort_keys=False)
