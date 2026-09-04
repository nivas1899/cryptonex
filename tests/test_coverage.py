from pathlib import Path

import pytest

from ecdat.core.orchestrator import run_scan
from ecdat.knowledge import get_kb

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-repo"


@pytest.fixture(scope="module")
def result():
    return run_scan(str(FIXTURE), crqc_year=2032, now_year=2026)


def test_multi_language_source_coverage(result):
    scanners = {a.detection.scanner for a in result.assets}
    for lang in ("source.python", "source.java", "source.go", "source.javascript",
                 "source.c", "source.csharp", "source.rust", "source.php",
                 "source.ruby", "source.swift", "source.config"):
        assert lang in scanners, f"no assets from {lang}"


def test_multi_ecosystem_dependency_coverage(result):
    scanners = {a.detection.scanner for a in result.assets}
    for eco in ("dependency.pip", "dependency.npm", "dependency.maven",
                "dependency.cargo", "dependency.gem", "dependency.nuget"):
        assert eco in scanners, f"no assets from {eco}"


def test_advisory_findings(result):
    adv = {f.rule_id for f in result.findings if f.category == "vulnerable-dependency"}
    assert "CVE-2022-29217" in adv   # pyjwt 1.7.1
    assert "RUSTSEC-2023-0071" in adv  # rsa crate 0.9.6


def test_new_language_crypto_found(result):
    # C# RSA, Rust Ed25519, PHP HMAC-SHA1, Ruby AES-CBC, Swift AES-GCM
    by_loc = {}
    for a in result.assets:
        for loc in a.locations:
            by_loc.setdefault(loc.component, set()).add(a.algorithm_family)
    assert "RSA" in by_loc.get("services/reporting/Signer.cs", set())
    assert "ECC" in by_loc.get("services/ledger/sign.rs", set())      # Ed25519
    assert "AES" in by_loc.get("services/mobile/Crypto.swift", set())


def test_kb_scale():
    kb = get_kb()
    assert len(kb.algorithms["families"]) >= 40
    assert len(kb.libraries["libraries"]) >= 75
    assert len(kb.misuse_rules) >= 25
    assert len(kb.constants) >= 25
    assert len(kb.advisories) >= 10
    total_rules = len({r.id for rs in kb.rules_by_ext.values() for r in rs})
    assert total_rules >= 120


def test_ssh_config_weaknesses(result):
    ssh = [f for f in result.findings if "sshd_config" in f.location]
    rule_ids = {f.rule_id for f in ssh}
    assert "misuse.ssh.weak" in rule_ids or "misuse.dh.small" in rule_ids


def test_no_finding_on_safe_go_aes(result):
    # services/vault/crypto.go uses AES-256-GCM — no misuse finding there
    assert not any("vault/crypto.go" in f.location for f in result.findings)
