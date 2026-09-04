# ECDAT — Build Status

**Working end-to-end.** ~3,500 LOC Python + a versioned YAML Knowledge Base. **37 tests pass.**
Verified on the Docker image (`ecdat:local`).

See `docs/CAPABILITIES.md` for the full capability list and the comparison vs. IBM / SandboxAQ.

## Knowledge base

| | count |
|---|---|
| Algorithm families | **42** (RSA…SM4, XMSS/LMS, ML-KEM/ML-DSA/SLH-DSA) |
| Aliases | 108 |
| Source detection rules | **162** across **13 languages** (Python, Java, JS/TS, C#, Rust, PHP, Ruby, Swift, Go, C/C++, config, shell) |
| Dependency ecosystems | **6** — pip, npm, Maven/Gradle, Go, Cargo, NuGet, RubyGems, Composer, CocoaPods |
| Catalogued crypto libraries | **80** with EOL / advisory flags |
| Library CVE / RUSTSEC / GHSA advisories | **13** matched by version range |
| Misuse / threat rules | **28** CWE-mapped |
| Crypto-constant fingerprints | **28** |
| PQC recommendation rules | 9 |

## Since M0

- **Threat finders** — `misuse` scanner (28 rules): disabled TLS verification, ECB, static IV,
  hardcoded keys, weak RNG, RSA<2048, JWT alg-confusion, legacy TLS/SSH config, non-constant-time
  MAC compare, fixed ECDSA nonce, vulnerable-dependency advisories, …
- **Hand-rolled-crypto detection** — 28 constant fingerprints
- **Binary scanner** — ELF/PE/Mach-O via `lief`
- **Container-image scanner** — unpacks OCI/docker-save layers, scans the merged rootfs
- **PQC-readiness analytics** — crypto-agility index, migration waves, **India NQM phase mapping**,
  quantum-risk timeline
- **SARIF 2.1.0** + CBOM `vulnerabilities` array + `--fail-on` covers findings
- **Console** — **Weaknesses** and **PQC Readiness** views
- **Credibility layer** — every asset carries an `AssessmentBasis`: **Observed** (evidence-backed,
  with detection confidence) vs **Knowledge-base** (deterministic, cited) vs **Inferred** (heuristic —
  criticality / data-class / external-exposure, with the reasoning) vs **Assumed** (X / Y / Z). Shown
  in the console asset detail, the report, and as `ecdat:*Basis` properties in the CBOM.
- **Test-code handling** — test-vector corpora (`vectors/`, `wycheproof/`, …) skipped; assets/findings
  whose every location is a test/example/fixture path are inventoried but **excluded from the grade**.
- **Real-OSS benchmark** — `scripts/benchmark.py` scans 7 real projects (PyJWT, paramiko, python-jose,
  the `cryptography` library, …); results + a precision spot-check sheet in `docs/benchmark/`.
- **Presentation kit** — `docs/HOW_TO_PRESENT.md` (opening line, one-asset demo spine, judge Q&A,
  overclaim rewrites).

## What runs today

```bash
cd /home/nivx/SIH/ecdat
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

ecdat scan tests/fixtures/vulnerable-repo      # → ecdat-out/{cbom.json, report.html, result.json}
ecdat serve                                     # → local Streamlit console on :8713
ecdat kb                                        # knowledge base info
pytest -q                                       # 21 passing
```

On the fixture repo it finds **28 cryptographic assets**, grades the estate **B (80/100)**, flags
**12 vulnerable / 2 broken / 3 weakened**, **2 HNDL-exposed**, **11 at-risk under Mosca**, and
recommends a specific PQC target for every unsafe asset (root CA → SLH-DSA, JWT/RSA sign → ML-DSA-65,
TLS/IPsec key exchange → ML-KEM-768 hybrid, 3DES → AES-256-GCM, PBKDF2-SHA1 → Argon2id, …).

## Components built

| Layer | Modules | Status |
|---|---|---|
| **Domain** (pure) | `enums`, `models` (Pydantic v2), `risk` (Mosca + scoring), `recommend`, `posture` | ✅ |
| **Knowledge Base** | `algorithms.yaml`, `aliases.yaml`, `libraries.yaml`, `pqc_mapping.yaml`, `policy.yaml`, `rules/{python,java,javascript,go,c,config,shell}.yaml` + loader | ✅ |
| **Scanners** | `source` (7 languages, regex rules), `dependency` (pip/npm/maven/go), `certificate` (X.509 PEM/DER, keys → fingerprint only) | ✅ |
| **Core** | `normalize` (identity + merge + graph), `enrich` (status · criticality · lifetime · Mosca), `orchestrator` | ✅ |
| **Reporters** | `cbom` (CycloneDX 1.6, deterministic serial), `report` (HTML → PDF if WeasyPrint present), `json_out` | ✅ |
| **CLI** | `ecdat scan / serve / kb / version` — `--crqc-year`, `--x`, `--y`, `--scanners`, `--fail-on`, `--no-timestamp` | ✅ |
| **GUI** | Streamlit console — Overview / Inventory (filter + inspect) / Mosca Lab (live X·Y·Z + presets) / Coverage | ✅ |
| **Packaging** | `Dockerfile` (multi-stage, non-root), `Makefile`, `compose.yaml`, `.dockerignore` | ✅ |
| **Tests** | `test_risk` (Mosca + scoring + monotonicity), `test_recommend` (rule coverage), `test_pipeline` (recall of 14 planted assets, CBOM structure + determinism) | ✅ 21 pass |

## Deliberately deferred (M1) — say "roadmap" in the demo

- Binary & container-image collectors
- tree-sitter AST parsing (M0 uses regex rules)
- React + FastAPI console (M0 = Streamlit)
- SARIF export, scan history / drift diff in the GUI
- Local-LLM explainer
- Full CycloneDX schema validation in CI (M0 asserts structure)
- Plugin auto-discovery via entry points (M0 = static registry)

## Fixture census (`tests/fixtures/vulnerable-repo/`)

A synthetic payments monorepo with planted crypto across Python, Java, JS, Go, C, config,
shell, `requirements.txt`, `pom.xml`, `package.json`, and real X.509 certs (an **expired**
staging wildcard, an RSA-4096 root CA, an ECDSA mesh cert). `test_pipeline.py` asserts every
planted item is found.
