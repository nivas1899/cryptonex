"""SARIF 2.1.0 output — for CI annotations and merge gates."""
from __future__ import annotations

import json

from ecdat import __version__
from ecdat.domain.enums import QuantumStatus
from ecdat.domain.models import ScanResult

_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "info": "note"}


def _loc(locator: str) -> dict:
    if ":" in locator and locator.rsplit(":", 1)[-1].isdigit():
        uri, line = locator.rsplit(":", 1)
        region = {"startLine": int(line)}
    else:
        uri, region = locator, {"startLine": 1}
    return {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}


def to_sarif(result: ScanResult) -> str:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in result.findings:
        rid = f.rule_id
        rules.setdefault(rid, {
            "id": rid,
            "name": f.category,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description or f.title},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[1]}.html"
                       if f.cwe and f.cwe.startswith("CWE-") else "",
            "properties": {"security-severity": {"critical": "9.5", "high": "7.5",
                           "medium": "5.0", "low": "3.0", "info": "1.0"}[f.severity.value],
                           "tags": ["cryptography", f.category]},
        })
        results.append({
            "ruleId": rid,
            "level": _LEVEL[f.severity.value],
            "message": {"text": f"{f.title}. {f.remediation}"},
            "locations": [_loc(f.location)],
        })

    for a in result.assets:
        if a.quantum_status not in (QuantumStatus.VULNERABLE, QuantumStatus.BROKEN,
                                    QuantumStatus.WEAKENED):
            continue
        rid = f"ecdat/quantum/{a.quantum_status.value}/{a.algorithm_family}"
        rules.setdefault(rid, {
            "id": rid,
            "shortDescription": {"text": f"{a.quantum_status.value} cryptography: {a.algorithm_family}"},
            "properties": {"security-severity": "8.5" if a.quantum_status == QuantumStatus.VULNERABLE
                           else "7.0", "tags": ["cryptography", "post-quantum"]},
        })
        lvl = "error" if a.risk_score >= 70 else "warning" if a.risk_score >= 40 else "note"
        tgt = a.recommendation.target_algorithm if a.recommendation else "a PQC alternative"
        for loc in a.locations or []:
            results.append({
                "ruleId": rid,
                "level": lvl,
                "message": {"text": f"{a.name} is {a.quantum_status.value} "
                            f"(risk {a.risk_score:.0f}). {a.quantum_status_reason} "
                            f"Migrate to {tgt}."},
                "locations": [_loc(loc.component + (f":{loc.line}" if loc.line else ""))],
            })

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ECDAT",
                "version": __version__,
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
