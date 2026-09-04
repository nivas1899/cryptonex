from ecdat.domain.enums import Confidence, Criticality, Primitive, QuantumStatus
from ecdat.domain.models import CryptoAsset, Detection, MoscaInputs
from ecdat.domain.risk import assess, mosca, posture_score


def _asset(**kw):
    base = dict(
        id="CR-x", asset_type="algorithm", name="RSA",
        primitive=Primitive.SIGNATURE, algorithm_family="RSA",
        detection=Detection(scanner="test", confidence=Confidence.HIGH),
        quantum_status=QuantumStatus.VULNERABLE, criticality=Criticality.HIGH,
    )
    base.update(kw)
    return CryptoAsset(**base)


def _mi(x=10, y=3, z=2032, now=2026):
    return MoscaInputs(data_lifetime_years=x, migration_years=y, crqc_year=z, now_year=now)


def test_mosca_at_risk_formula():
    r = mosca(_mi(x=10, y=3, z=2032, now=2026))  # 13 > 6
    assert r.at_risk is True
    assert abs(r.exposure_years - 7) < 1e-9

    r2 = mosca(_mi(x=2, y=1, z=2045, now=2026))  # 3 > 19 -> False
    assert r2.at_risk is False


def test_safe_asset_scores_zero():
    a = assess(_asset(quantum_status=QuantumStatus.SAFE), _mi())
    assert a.risk_score == 0.0


def test_risk_monotonic_in_criticality():
    low = assess(_asset(criticality=Criticality.LOW), _mi())
    crit = assess(_asset(criticality=Criticality.CRITICAL), _mi())
    assert crit.risk_score >= low.risk_score


def test_risk_monotonic_in_exposure():
    near = assess(_asset(), _mi(z=2045))   # small / negative exposure
    far = assess(_asset(), _mi(z=2028))    # large exposure
    assert far.risk_score >= near.risk_score


def test_broken_critical_external_is_high():
    a = _asset(quantum_status=QuantumStatus.BROKEN, criticality=Criticality.CRITICAL,
               external_facing=True,
               detection=Detection(scanner="t", confidence=Confidence.CONFIRMED))
    assess(a, _mi())
    assert a.risk_score >= 85


def test_hndl_only_for_confidentiality_primitives():
    sig = assess(_asset(primitive=Primitive.SIGNATURE), _mi())
    kex = assess(_asset(primitive=Primitive.KEY_AGREEMENT), _mi())
    assert sig.hndl_exposed is False
    assert kex.hndl_exposed is True


def test_posture_bounds():
    score, grade = posture_score([])
    assert score == 100.0 and grade == "A"
    score, grade = posture_score([assess(_asset(criticality=Criticality.CRITICAL,
                                  quantum_status=QuantumStatus.BROKEN), _mi())])
    assert 0 <= score <= 100
