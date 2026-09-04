from __future__ import annotations

from enum import Enum


class AssetType(str, Enum):
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    KEY = "key"
    PROTOCOL = "protocol"
    RELATED_MATERIAL = "related-crypto-material"
    LIBRARY = "library"
    HARDWARE_MODULE = "hardware-module"
    CLOUD_SERVICE = "cloud-service"


class Primitive(str, Enum):
    PKE = "pke"
    SIGNATURE = "signature"
    KEY_AGREEMENT = "key-agreement"
    KEM = "kem"
    HASH = "hash"
    MAC = "mac"
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    AEAD = "aead"
    KDF = "kdf"
    DRBG = "drbg"
    OTHER = "other"


class QuantumStatus(str, Enum):
    SAFE = "safe"
    WEAKENED = "weakened"
    VULNERABLE = "vulnerable"
    BROKEN = "broken"
    UNKNOWN = "unknown"


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Effort(str, Enum):
    TRIVIAL = "trivial"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    ARCHITECTURAL = "architectural"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    AI_ASSISTED = "ai-assisted"


# ---- ordered weightings used by the risk engine (domain/risk.py) ----

STATUS_WEIGHT = {
    QuantumStatus.SAFE: 0.0,
    QuantumStatus.WEAKENED: 0.35,
    QuantumStatus.VULNERABLE: 0.9,
    QuantumStatus.BROKEN: 1.0,
    QuantumStatus.UNKNOWN: 0.5,
}

CRITICALITY_WEIGHT = {
    Criticality.LOW: 0.25,
    Criticality.MEDIUM: 0.5,
    Criticality.HIGH: 0.8,
    Criticality.CRITICAL: 1.0,
}

CRITICALITY_MULTIPLIER = {
    Criticality.LOW: 0.5,
    Criticality.MEDIUM: 1.0,
    Criticality.HIGH: 2.0,
    Criticality.CRITICAL: 3.0,
}

CONFIDENCE_WEIGHT = {
    Confidence.CONFIRMED: 1.0,
    Confidence.HIGH: 0.95,
    Confidence.MEDIUM: 0.8,
    Confidence.LOW: 0.6,
    Confidence.AI_ASSISTED: 0.5,
}

CONFIDENCE_ORDER = [
    Confidence.LOW,
    Confidence.AI_ASSISTED,
    Confidence.MEDIUM,
    Confidence.HIGH,
    Confidence.CONFIRMED,
]

SEVERITY_ORDER = {
    QuantumStatus.SAFE: 0,
    QuantumStatus.UNKNOWN: 1,
    QuantumStatus.WEAKENED: 2,
    QuantumStatus.VULNERABLE: 3,
    QuantumStatus.BROKEN: 4,
}

# confidentiality primitives — HNDL only applies to these
HNDL_PRIMITIVES = {Primitive.PKE, Primitive.KEY_AGREEMENT, Primitive.KEM}
