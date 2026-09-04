import json
from pathlib import Path

import pytest

from cryptonex.core.orchestrator import run_scan
from cryptonex.domain.enums import QuantumStatus
from cryptonex.reporters.cbom import to_cbom

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-repo"

# planted crypto that MUST be found (family, a substring of a location)
EXPECTED = [
    ("RSA", "jwt_signer.py"),        # RS256 signing
    ("RSA", "root-ca.crt"),          # RSA-4096 root
    ("RSA", "wildcard.pem"),         # expired staging cert
    ("PBKDF2", "password.py"),       # PBKDF2-HMAC-SHA-1
    ("bcrypt", "password.py"),       # current password hash
    ("AES", "crypto.go"),            # AES-256-GCM
    ("AES", "legacy_tokens.js"),     # AES-128-CBC
    ("3DES", "des3_wrap.c"),         # mainframe 3DES
    ("MD5", "verify.sh"),            # md5sum in CI
    ("HMAC", "sign.js"),             # HMAC-SHA1 / HMAC-SHA256
    ("ECC", "mesh_svc_cert.pem"),    # ECDSA mesh identity
    ("ECC", "ssl.conf"),             # ECDH P-256
    ("DH", "ipsec.conf"),            # DH modp2048
    ("SHA-2", "LegacyCipher.java"),  # SHA-256
]


@pytest.fixture(scope="module")
def result():
    return run_scan(str(FIXTURE), crqc_year=2032, now_year=2026)


def test_recall_of_planted_crypto(result):
    misses = []
    for family, loc_sub in EXPECTED:
        hit = any(
            a.algorithm_family == family
            and any(loc_sub in l.component for l in a.locations)
            for a in result.assets
        )
        if not hit:
            misses.append(f"{family} @ {loc_sub}")
    assert not misses, f"missed planted crypto: {misses}"


def test_every_unsafe_asset_has_a_recommendation(result):
    for a in result.assets:
        if a.quantum_status in (QuantumStatus.VULNERABLE, QuantumStatus.BROKEN,
                                QuantumStatus.WEAKENED):
            assert a.recommendation is not None, f"{a.name} @ {a.locations} has no recommendation"


def test_safe_assets_have_no_recommendation(result):
    for a in result.assets:
        if a.quantum_status == QuantumStatus.SAFE:
            assert a.recommendation is None


def test_rsa_signing_is_shor_vulnerable(result):
    rsa = [a for a in result.assets if a.algorithm_family == "RSA"]
    assert rsa and all(a.quantum_status == QuantumStatus.VULNERABLE for a in rsa)


def test_aes256_gcm_is_safe(result):
    gcm = [a for a in result.assets
           if a.algorithm_family == "AES" and a.primitive.value == "aead"]
    assert gcm and all(a.quantum_status == QuantumStatus.SAFE for a in gcm)


def test_cbom_structure(result):
    doc = json.loads(to_cbom(result))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert len(doc["components"]) == len(result.assets)
    for comp in doc["components"]:
        assert comp["type"] == "cryptographic-asset"
        assert comp["bom-ref"].startswith("crypto/")
        assert "cryptoProperties" in comp
        assert "assetType" in comp["cryptoProperties"]


def test_cbom_deterministic(result):
    a = to_cbom(result, no_timestamp=True)
    b = to_cbom(result, no_timestamp=True)
    assert a == b


def test_posture_and_counts_consistent(result):
    p = result.posture
    assert p.total_assets == len(result.assets)
    assert sum(p.by_status.values()) == p.total_assets
