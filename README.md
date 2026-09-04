# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool

Scans a codebase for cryptographic assets (algorithms, keys, certificates, protocols,
libraries), assesses post-quantum risk with **Mosca's inequality**, recommends
PQC / hybrid replacements, and emits a **CycloneDX 1.6 CBOM**, an executive report,
and an interactive local console.

> SIH 2026 · Problem Statement 26164 · National Technical Research Organisation (NTRO)

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

ecdat scan tests/fixtures/vulnerable-repo
ecdat serve                       # local web console on http://localhost:8713
```

Or with Docker:

```bash
docker build -t ecdat:local .
mkdir -p ecdat-out
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD":/scan:ro -v "$PWD/ecdat-out":/out \
  ecdat:local scan /scan --out /out
```

**Analysing your own codebase:** see [`ANALYZE_YOUR_CODE.md`](ANALYZE_YOUR_CODE.md).

## What it produces

| File | Format |
|------|--------|
| `ecdat-out/cbom.json` | CycloneDX 1.6 Cryptographic Bill of Materials |
| `ecdat-out/report.pdf` (or `.html`) | Executive & audit report |
| `ecdat-out/result.json` | Full `ScanResult` for a SIEM / data lake / the console |

## Commands

```
ecdat scan <path> [--out DIR] [--format cbom,json,report]
                  [--crqc-year 2032] [--x 10] [--y 3]
                  [--scanners source,dependency,certificate]
                  [--fail-on vulnerable] [--no-timestamp]
ecdat serve [--result ecdat-out/result.json] [--port 8713]
ecdat kb
ecdat version
```

## Architecture

`scanners/` (source · dependency · certificate) → `core/normalize` → `core/enrich`
(quantum status · criticality · Mosca) → `domain/recommend` → `domain/posture` →
`reporters/` (cbom · report · json). The `domain/` package is pure — no I/O — and
holds the risk math. All cryptographic knowledge lives in versioned YAML under
`ecdat/knowledge/`.

Offline by construction — no network calls during scan or analysis.
