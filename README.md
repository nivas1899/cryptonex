# CRYPTONEX

**Cryptographic discovery · post-quantum risk assessment · migration planning.**

Scans a codebase — source, dependencies, certificates, binaries, container images — for
cryptographic assets (algorithms, keys, certificates, protocols, libraries), assesses
post-quantum risk with **Mosca's inequality**, flags cryptographic misuse, recommends
PQC / hybrid replacements, and emits a **CycloneDX 1.6 CBOM**, an executive report,
SARIF, and an interactive local console.

> SIH 2026 · Problem Statement 26164 (Enterprise Cryptographic Discovery & Analysis Tool)
> · National Technical Research Organisation (NTRO)

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

cryptonex scan tests/fixtures/vulnerable-repo
cryptonex serve                       # local web console on http://localhost:8713
```

Or with Docker:

```bash
docker build -t cryptonex:local .
mkdir -p cryptonex-out
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD":/scan:ro -v "$PWD/cryptonex-out":/out \
  cryptonex:local scan /scan --out /out
```

**Analysing your own codebase:** see [`ANALYZE_YOUR_CODE.md`](ANALYZE_YOUR_CODE.md).

## What it produces

| File | Format |
|------|--------|
| `cryptonex-out/cbom.json` | CycloneDX 1.6 Cryptographic Bill of Materials |
| `cryptonex-out/report.pdf` (or `.html`) | Executive & audit report |
| `cryptonex-out/result.json` | Full `ScanResult` for a SIEM / data lake / the console |

## Commands

```
cryptonex scan <path> [--out DIR] [--format cbom,json,report]
                  [--crqc-year 2032] [--x 10] [--y 3]
                  [--scanners source,dependency,certificate]
                  [--fail-on vulnerable] [--no-timestamp]
cryptonex serve [--result cryptonex-out/result.json] [--port 8713]
cryptonex kb
cryptonex version
```

## Architecture

`scanners/` (source · dependency · certificate) → `core/normalize` → `core/enrich`
(quantum status · criticality · Mosca) → `domain/recommend` → `domain/posture` →
`reporters/` (cbom · report · json). The `domain/` package is pure — no I/O — and
holds the risk math. All cryptographic knowledge lives in versioned YAML under
`cryptonex/knowledge/`.

Offline by construction — no network calls during scan or analysis.
