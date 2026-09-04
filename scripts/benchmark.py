#!/usr/bin/env python3
"""Benchmark ECDAT against real open-source repositories.

Clones a curated set of small, well-known crypto-adjacent projects, scans each,
and writes a summary table plus a precision spot-check sheet (a random sample of
findings for a human to mark true/false positive).

Usage:  python scripts/benchmark.py [--out benchmark] [--keep]
Offline: repos that can't be cloned are skipped and noted.
"""
from __future__ import annotations

import argparse
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from ecdat.core.orchestrator import run_scan

REPOS = [
    ("pyjwt",              "https://github.com/jpadilla/pyjwt",            "JWT — signing / alg handling"),
    ("itsdangerous",       "https://github.com/pallets/itsdangerous",      "Flask signing helpers"),
    ("python-jose",        "https://github.com/mpdavis/python-jose",       "JOSE / JWT — had alg-confusion CVEs"),
    ("paramiko",           "https://github.com/paramiko/paramiko",         "SSH — keys, KEX, ciphers"),
    ("golang-jwt",         "https://github.com/golang-jwt/jwt",            "Go JWT (successor to dgrijalva)"),
    ("node-jsonwebtoken",  "https://github.com/auth0/node-jsonwebtoken",   "Node JWT"),
    ("cryptography",       "https://github.com/pyca/cryptography",         "the reference Python crypto library"),
]

SPOT_CHECK_N = 25


def clone(url: str, dest: Path) -> bool:
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "-q", url, str(dest)],
            check=True, timeout=90,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="benchmark")
    ap.add_argument("--keep", action="store_true", help="keep the cloned repos")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="ecdat-bench-"))
    rows = []
    spot: list[tuple] = []
    skipped = []

    for name, url, desc in REPOS:
        dest = work / name
        print(f"→ {name} … ", end="", flush=True)
        if not clone(url, dest):
            print("clone failed (offline?) — skipped")
            skipped.append(name)
            continue
        t0 = time.time()
        r = run_scan(str(dest), crqc_year=2032, now_year=2026)
        dt = time.time() - t0
        loc = sum(1 for _ in dest.rglob("*") if _.is_file())
        prod_findings = [f for f in r.findings if not f.test_path]
        prod_assets = [a for a in r.assets if not a.test_only]
        rows.append({
            "repo": name, "desc": desc, "files": loc,
            "assets": len(r.assets), "test_assets": r.posture.test_only_assets,
            "findings": len(prod_findings), "test_findings": len(r.findings) - len(prod_findings),
            "vuln": sum(1 for a in prod_assets if a.quantum_status.value == "vulnerable"),
            "broken": sum(1 for a in prod_assets if a.quantum_status.value == "broken"),
            "grade": r.posture.grade, "seconds": round(dt, 1),
            "top_families": ", ".join(sorted({a.algorithm_family for a in r.assets
                                              if a.algorithm_family != "UNKNOWN"})[:8]),
        })
        for a in r.assets:
            for l in a.locations:
                spot.append(("asset", name, a.name, a.algorithm_family,
                             a.detection.confidence.value, l.component + (f":{l.line}" if l.line else "")))
        for f in prod_findings:
            spot.append(("finding", name, f.rule_id, f.severity.value, "", f.location))
        print(f"{len(r.assets)} assets ({r.posture.test_only_assets} test), "
              f"{len(prod_findings)} findings (+{len(r.findings)-len(prod_findings)} test), {dt:.1f}s")

    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)

    # summary table
    md = ["# ECDAT benchmark — real open-source repositories\n",
          f"_{len(rows)} repositories scanned"
          + (f", {len(skipped)} skipped (offline): {', '.join(skipped)}" if skipped else "")
          + "._\n",
          "Assets / findings columns show **production (test-path)**. Grade is on production assets only.\n",
          "| repo | what it is | files | assets | findings | vuln | broken | grade | time |",
          "|---|---|--:|--:|--:|--:|--:|:--:|--:|"]
    for x in rows:
        md.append(f"| `{x['repo']}` | {x['desc']} | {x['files']} | "
                  f"{x['assets']-x['test_assets']} ({x['test_assets']}) | "
                  f"{x['findings']} ({x['test_findings']}) | {x['vuln']} | {x['broken']} | "
                  f"{x['grade']} | {x['seconds']}s |")
    md.append("\n## Algorithm families detected per repo\n")
    for x in rows:
        md.append(f"- **{x['repo']}**: {x['top_families'] or '—'}")
    (out / "results.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    # spot-check sheet
    random.seed(42)
    sample = random.sample(spot, min(SPOT_CHECK_N, len(spot)))
    sc = ["# ECDAT precision spot-check\n",
          "Mark each row **TP** (true positive) or **FP** (false positive) by hand, "
          "then compute precision = TP / (TP + FP).\n",
          "| # | kind | repo | what | detail | conf/sev | location | TP/FP |",
          "|--:|---|---|---|---|---|---|:--:|"]
    for i, (kind, repo, what, fam, cs, locn) in enumerate(sample, 1):
        sc.append(f"| {i} | {kind} | {repo} | {what} | {fam} | {cs} | `{locn}` |  |")
    (out / "spot-check.md").write_text("\n".join(sc) + "\n", encoding="utf-8")

    print(f"\nwrote {out/'results.md'} and {out/'spot-check.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
