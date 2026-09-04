# ECDAT — Build Status

**Working end-to-end.** ~3,000 LOC Python + a versioned YAML Knowledge Base. **30 tests pass.**
Verified on the Docker image (`ecdat:local`).

See `docs/CAPABILITIES.md` for the full capability list and the comparison vs. IBM / SandboxAQ.

## New since M0

- **Threat finders** — a `misuse` scanner with **21 CWE-mapped rules**: disabled TLS verification
  (critical), ECB mode, static/zero IV, hardcoded keys, weak RNG, RSA<2048, JWT alg-confusion, …
- **Hand-rolled-crypto detection** — 17 constant fingerprints (AES S-box, SHA/MD5 tables, curve primes).
- **Binary scanner** — ELF/PE/Mach-O via `lief` (linked libs, crypto symbols, version banners).
- **PQC-readiness analytics** — crypto-agility index, migration waves, **India NQM phase mapping**,
  quantum-risk timeline.
- **SARIF 2.1.0 export** + CBOM `vulnerabilities` array + `--fail-on` now covers findings.
- **Knowledge base doubled** — 42 algorithm families (was 26), 39 libraries (was 16), 63 detection rules.
- **Console** — new **Weaknesses** and **PQC Readiness** views.

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
