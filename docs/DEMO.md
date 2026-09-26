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

Recorded a second time against the redesigned console — interactive donut charts you
click to drill into a stat, a color/rating glossary on every view, and a full-width
professional layout. See `docs/cryptonex-demo.mp4` (+ `.gif` / `.srt`) for the recorded
version of this exact walkthrough, and `docs/VOICEOVER_SCRIPT.md` for its timed narration.

### 1 · "You have a codebase. Nothing gets uploaded anywhere."

Open `http://localhost:8713` → lands on the **Scan** page.
`![](demo/demo-01-scan-page.png)`

> "CRYPTONEX runs locally. Point it at a folder, or — for this demo — drop a zip of the repo."

Go to the **Upload a .zip** tab → drop `demo-repo.zip`.
_(drop the zip → Run scan)_

Click **Run scan**.

### 2 · Estate posture (auto-navigates here)

`![](demo/demo-03-overview.png)`

> "46 cryptographic assets found. Estate posture: grade **B** — 79 out of 100.
> **15 quantum-vulnerable**, 2 already broken, **2 exposed to harvest-now-decrypt-later**,
> **16 fail Mosca's inequality**."

Point at the two donut charts — quantum status and criticality, each with a plain-language
color legend right underneath — and the highest-risk table (root CA at the top). Click the
**Vulnerable** chip under the first donut:

> "One click — and we're already in the Inventory, filtered to exactly those fifteen
> assets. No re-typing a filter."

Open **"What do the colors and ratings mean?"** for a beat:

> "Every rating in this console is explained in plain language, right where you see it —
> what 'vulnerable' means, what the risk score is made of, what counts as critical."

### 3 · Inventory — drill into one asset

Sidebar → **Inventory** (already filtered to *vulnerable* from the click above). 46 assets
total, filterable by status / criticality / free-text search.
`![](demo/demo-04-inventory.png)`

Pick **`RSA · pki/root-ca/root-ca.crt`** in *Inspect asset*:

- **Evidence:** `subject=CN=BharatPay Root CA | key=rsa 4096 | notAfter=2043-01-01 | CA`
- **Mosca:** `X(20) + Y(5) = 25  vs  Z(2032) − now(2026) = 6  →  AT RISK, exposed ~19.0y`
- **Recommended → `SLH-DSA-SHA2-192s`** — "a root of trust is the most conservative case;
  prefer hash-based SLH-DSA despite larger signatures. Stand up a parallel PQC root and
  cross-sign." · effort *architectural* · libraries: liboqs / oqs-provider, BouncyCastle ≥ 1.78

> "Every unsafe asset gets a specific target — RSA signing → ML-DSA-65, TLS/IPsec key
> exchange → ML-KEM-768 with an X25519 hybrid for transition, 3DES → AES-256-GCM."

### 4 · Weaknesses — misuse findings, click a severity to filter

Sidebar → **Weaknesses**. A severity donut (critical/high/medium/low/info) sits beside the
findings table — same click-to-filter pattern as Overview.
`![](demo/demo-09-weaknesses.png)`

Click **Critical**:

> "Twenty-five real-world misuse findings — hardcoded keys, disabled TLS verification,
> weak cipher modes. Click Critical, and we're down to the five that need fixing today —
> each with the exact line, the CWE, and the fix."

### 5 · Mosca Lab — stress-test the assumptions

Sidebar → **Mosca Lab**.
_(Mosca Lab: three sliders + presets)_

> "This is the analyst tool. Three assumptions: how long your data must stay secret,
> how long migration takes, when a quantum computer arrives."

Click the **Regulator (EU 2030)** preset (X=15, Y=4, Z=2030):
_(pick the "Regulator (EU 2030)" preset — the at-risk table and posture recompute live)_

> "`X + Y = 19` vs `Z − now = 4`. Under a regulator's assumptions the posture drops to 77
> and **24 of 46** assets are at risk. Everything recomputes live."

### 6 · Deliverables

Sidebar → **Scan** → download buttons.
_(Scan page → download cbom.json / result.json / report.html / results.sarif)_

- **`cbom.json`** — CycloneDX 1.6 Cryptographic Bill of Materials (46 components, evidence,
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

Historical record from the original recording — `tests/fixtures/vulnerable-repo` has
grown since (46 assets today, not 28); the counts below are as they were at the time.

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

## Verified against the redesigned console (this recording)

Driven via `streamlit run` + Playwright against the current
`tests/fixtures/vulnerable-repo` scan (46 assets, posture B / 79 · agility A / 86).

| Path | Result |
|---|---|
| Overview → click "Vulnerable" donut chip | navigates to Inventory pre-filtered to the 15 vulnerable assets ✅ |
| Overview → click a criticality chip | navigates to Inventory pre-filtered by that level ✅ |
| Weaknesses → click "Critical" severity chip | table filters in place to the 5 critical findings, clearable ✅ |
| "What do the colors and ratings mean?" glossary | renders on Overview, Inventory, Weaknesses, Coverage ✅ |
| Mosca Lab → Regulator (EU 2030) preset | posture 79→77, at-risk 16→24, recomputes live ✅ |
| Full-width layout at 1920px / scroll on the main pane | no dead margin, scrollbar visible and functional ✅ |
| Sidebar nav as full-width tab buttons | icons + labels render, active tab highlighted ✅ |
