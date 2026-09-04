import json
from pathlib import Path

import pytest

from ecdat.core.orchestrator import run_scan
from ecdat.domain.enums import Severity
from ecdat.reporters.sarif import to_sarif

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-repo"


@pytest.fixture(scope="module")
def result():
    return run_scan(str(FIXTURE), crqc_year=2032, now_year=2026)


EXPECTED_FINDINGS = [
    ("misuse.tls.verify_off.py", "http_client.py"),
    ("misuse.tls.verify_off.go", "settle.go"),
    ("misuse.tls.verify_off.node", "token.js"),
    ("misuse.ecb", "http_client.py"),
    ("misuse.hardcoded.key", "http_client.py"),
    ("misuse.static.iv", "http_client.py"),
    ("misuse.rsa.small", "settle.go"),
    ("const.aes.sbox", "aes_inline.c"),
    ("misuse.rng.jsmath", "token.js"),
    ("misuse.rng.python", "http_client.py"),
]


def test_threat_finders_hit_planted_misuse(result):
    got = {(f.rule_id, f.location) for f in result.findings}
    misses = [
        f"{rid} @ {loc}" for rid, loc in EXPECTED_FINDINGS
        if not any(rid == g[0] and loc in g[1] for g in got)
    ]
    assert not misses, f"missed threat findings: {misses}"


def test_disabled_tls_is_critical(result):
    tls = [f for f in result.findings if f.category == "cert-validation"]
    assert tls and all(f.severity == Severity.CRITICAL for f in tls)


def test_hand_rolled_crypto_detected(result):
    hr = [f for f in result.findings if f.category == "hand-rolled-crypto"]
    assert any("S-box" in f.title for f in hr)


def test_no_c_rng_false_positive_on_js(result):
    # misuse.rng.c must not fire on token.js (Math.random -> random())
    for f in result.findings:
        if f.rule_id == "misuse.rng.c":
            assert f.location.endswith(".c") or f.location.endswith(".h")


def test_findings_carry_remediation_and_cwe(result):
    for f in result.findings:
        assert f.remediation, f"{f.rule_id} has no remediation"
        if f.category not in ("hand-rolled-crypto",):
            assert f.cwe and f.cwe.startswith("CWE-"), f"{f.rule_id} missing CWE"


def test_pqc_readiness_populated(result):
    rd = result.pqc_readiness
    assert 0 <= rd.crypto_agility_index <= 100
    assert rd.agility_grade in {"A", "B", "C", "D", "F"}
    assert rd.migration_waves
    assert sum(rd.nqm_phase_counts.values()) == result.posture.total_assets
    assert len(rd.quantum_risk_timeline) == 15
    # timeline monotonic non-increasing as CRQC year recedes
    exposed = [t["exposed_assets"] for t in rd.quantum_risk_timeline]
    assert exposed == sorted(exposed, reverse=True)


def test_cbom_has_vulnerabilities(result):
    from ecdat.reporters.cbom import to_cbom
    doc = json.loads(to_cbom(result))
    assert len(doc["vulnerabilities"]) == len(result.findings)
    for v in doc["vulnerabilities"]:
        assert v["ratings"] and v["affects"]


def test_sarif_valid(result):
    doc = json.loads(to_sarif(result))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "ECDAT"
    assert run["results"]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in {"error", "warning", "note"}
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_expanded_kb_families():
    from ecdat.knowledge import get_kb
    fams = get_kb().algorithms["families"]
    for f in ("ML-KEM", "SLH-DSA", "Camellia", "SM4", "XMSS", "Ed448"):
        assert f in fams
    assert len(fams) >= 40
