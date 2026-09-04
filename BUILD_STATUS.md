# ECDAT — Build Status (M0)

**Working end-to-end.** `~2,000 LOC` Python + a versioned YAML Knowledge Base. 21 tests pass.

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
