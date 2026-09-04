from cryptonex.domain.enums import Confidence, Primitive, QuantumStatus
from cryptonex.domain.models import CryptoAsset, Detection
from cryptonex.domain.recommend import recommend
from cryptonex.knowledge import get_kb

RULES = get_kb().pqc_rules()


def _a(family, primitive, status=QuantumStatus.VULNERABLE, **kw):
    return CryptoAsset(
        id="CR-x", asset_type=kw.pop("asset_type", "algorithm"), name=family,
        primitive=primitive, algorithm_family=family, quantum_status=status,
        detection=Detection(scanner="t", confidence=Confidence.HIGH), **kw,
    )


def test_rsa_signature_maps_to_ml_dsa():
    r = recommend(_a("RSA", Primitive.SIGNATURE), RULES, [])
    assert r and r.target_algorithm == "ML-DSA-65"


def test_rsa_keyagreement_maps_to_ml_kem_hybrid():
    r = recommend(_a("RSA", Primitive.PKE), RULES, [])
    assert r and r.target_algorithm == "ML-KEM-768"
    assert r.hybrid_option == "X25519+ML-KEM-768"


def test_root_ca_context_prefers_slh_dsa():
    r = recommend(_a("RSA", Primitive.SIGNATURE), RULES, ["root-ca"])
    assert r and r.target_algorithm.startswith("SLH-DSA")


def test_legacy_cipher_maps_to_aes256():
    r = recommend(_a("3DES", Primitive.BLOCK_CIPHER, status=QuantumStatus.BROKEN), RULES, [])
    assert r and r.target_algorithm == "AES-256-GCM"


def test_safe_asset_gets_nothing():
    assert recommend(_a("AES", Primitive.AEAD, status=QuantumStatus.SAFE), RULES, []) is None


def test_every_vulnerable_family_is_covered():
    for fam, prim in [("RSA", Primitive.SIGNATURE), ("ECC", Primitive.SIGNATURE),
                      ("ECC", Primitive.KEY_AGREEMENT), ("DH", Primitive.KEY_AGREEMENT),
                      ("DSA", Primitive.SIGNATURE)]:
        assert recommend(_a(fam, prim), RULES, []) is not None
