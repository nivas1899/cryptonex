# CRYPTONEX — Demo walkthrough

A verified 5-minute demo. Everything below was run against the Docker image
(`cryptonex:local`) with a real `.zip` upload, driven end-to-end and screenshotted.

## Setup (once)

```bash
docker build -t cryptonex:local .
docker run -d --name cryptonex -p 8713:8713 cryptonex:local serve --port 8713
# → http://localhost:8713
```

The demo repo: `demo-repo.zip` = a zip of `tests/fixtures/vulnerable-repo/` (a synthetic
payments monorepo — Python/Java/JS/Go/C, `requirements.txt`, `pom.xml`, `package.json`,
nginx + strongSwan config, and three real X.509 certs including an expired one).

---

## The script

### 1 · "You have a codebase. Nothing gets uploaded anywhere."

Open `http://localhost:8713` → lands on the **Scan** page.
`![](demo/demo-01-scan-page.png)`

> "CRYPTONEX runs locally. Point it at a folder, or — for this demo — drop a zip of the repo."

Go to the **Upload a .zip** tab → drop `demo-repo.zip`.
_(drop the zip → Run scan)_

Click **Run scan**.

### 2 · Estate posture (auto-navigates here)

`![](demo/demo-03-overview.png)`

> "28 cryptographic assets found across 18 files. Grade **B**. **12 quantum-vulnerable**,
> 2 already broken, **2 exposed to harvest-now-decrypt-later**, **11 fail Mosca's inequality**."

Point at the status and criticality bars, and the highest-risk table — root CA and staging
cert at the top.

### 3 · Inventory — drill into one asset

Sidebar → **Inventory**. 28 assets, filterable by status / criticality.
`![](demo/demo-04-inventory.png)`

Pick **`RSA · pki/root-ca/root-ca.crt`** in *Inspect asset*:

- **Evidence:** `subject=CN=BharatPay Root CA | key=rsa 4096 | notAfter=2043-01-01 | CA`
- **Mosca:** `X(20) + Y(5) = 25  vs  Z(2032) − now(2026) = 6  →  AT RISK, exposed ~19.0y`
- **Recommended → `SLH-DSA-SHA2-192s`** — "a root of trust is the most conservative case;
  prefer hash-based SLH-DSA despite larger signatures. Stand up a parallel PQC root and
  cross-sign." · effort *architectural* · libraries: liboqs / oqs-provider, BouncyCastle ≥ 1.78

> "Every unsafe asset gets a specific target — RSA signing → ML-DSA-65, TLS/IPsec key
> exchange → ML-KEM-768 with an X25519 hybrid for transition, 3DES → AES-256-GCM."

### 4 · Mosca Lab — stress-test the assumptions

Sidebar → **Mosca Lab**.
_(Mosca Lab: three sliders + presets)_

> "This is the analyst tool. Three assumptions: how long your data must stay secret,
> how long migration takes, when a quantum computer arrives."

Click the **Regulator (EU 2030)** preset (X=15, Y=4, Z=2030):
_(pick the "Regulator (EU 2030)" preset — the at-risk table and posture recompute live)_

> "`X + Y = 19` vs `Z − now = 4`. Under a regulator's assumptions the posture drops and
> **17 of 28** assets are at risk — the root CA's exposure jumps to ~89. Everything
> recomputes live."

### 5 · Deliverables

Sidebar → **Scan** → download buttons.
_(Scan page → download cbom.json / result.json / report.html / results.sarif)_

- **`cbom.json`** — CycloneDX 1.6 Cryptographic Bill of Materials (28 components, evidence,
  dependency graph, `cryptonex:` risk properties). "This is the interchange format — feeds a
  GRC platform or an auditor."
- **`report.html`** — executive summary + migration plan grouped by effort.
- **`result.json`** — the full scan for a SIEM.

Close with:

> "Same engine in CI: `cryptonex scan . --fail-on vulnerable` exits non-zero and blocks the
> merge on any new quantum-vulnerable crypto in a critical path. Offline, free, and aligned
> to India's National Quantum Mission roadmap — cryptographic inventories are mandated for
> critical sectors by December 2027."

---

## Verified on Docker (`cryptonex:local`)

| Path | Result |
|---|---|
| `serve` with no prior scan | lands on Scan page ✅ |
| Scan from **folder path** | 28 assets, posture B ✅ |
| Scan from **.zip upload** | identical 28 assets ✅ (driven via Playwright) |
| Overview / Inventory / Mosca Lab / Coverage | all render, 0 console errors ✅ |
| Mosca Lab preset switch → live recompute | 11→17 at-risk, posture 80→79 ✅ |
| Inspect asset → evidence + Mosca + recommendation | full detail ✅ |
| Download cbom.json / result.json / report.html | all work ✅ |
| `docker run … scan … --format cbom,json,report` | 3 files, CBOM specVersion 1.6, 28 components ✅ |
| `--fail-on vulnerable` | exit 1 ✅ · clean subdir → exit 0 ✅ |
| `--scanners certificate` subset | 3 cert assets only ✅ |
| `docker run … version` / `kb` | ✅ |
| CBOM byte-identical host vs container (`--no-timestamp`) | ✅ (modulo target path in serial) |
