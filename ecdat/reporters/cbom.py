"""CycloneDX 1.6 CBOM emitter.

Emits one `cryptographic-asset` component per CryptoAsset with cryptoProperties,
a dependencies graph, and ecdat: namespaced risk properties.
"""
from __future__ import annotations

import json
import uuid

from ecdat.domain.enums import AssetType, Primitive
from ecdat.domain.models import CryptoAsset, ScanResult

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
        {"name": "ecdat:quantumStatus", "value": a.quantum_status.value},
        {"name": "ecdat:quantumStatusReason", "value": a.quantum_status_reason},
        {"name": "ecdat:criticality", "value": a.criticality.value},
        {"name": "ecdat:riskScore", "value": str(a.risk_score)},
        {"name": "ecdat:hndlExposed", "value": str(a.hndl_exposed).lower()},
        {"name": "ecdat:occurrences", "value": str(a.occurrences)},
        {"name": "ecdat:dataClassification", "value": a.data_classification},
    ]
    if a.mosca_result and a.quantum_status.value != "safe":
        props.append({"name": "ecdat:moscaFormula", "value": a.mosca_result.formula})
    if a.recommendation:
        props.append({"name": "ecdat:recommendedTarget", "value": a.recommendation.target_algorithm})
        props.append({"name": "ecdat:migrationEffort", "value": a.recommendation.migration_effort.value})
        if a.recommendation.hybrid_option:
            props.append({"name": "ecdat:hybridOption", "value": a.recommendation.hybrid_option})

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

    metadata: dict = {
        "tools": {"components": [{"type": "application", "name": "ECDAT", "version": result.tool_version}]},
        "properties": [
            {"name": "ecdat:kbVersion", "value": result.kb_version},
            {"name": "ecdat:configHash", "value": result.config_hash},
            {"name": "ecdat:postureScore", "value": str(result.posture.posture_score)},
            {"name": "ecdat:postureGrade", "value": result.posture.grade},
            {"name": "ecdat:target", "value": result.target},
        ],
    }
    if not no_timestamp:
        metadata["timestamp"] = result.finished_at.isoformat()

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
    }
    return json.dumps(doc, indent=2, sort_keys=False)
