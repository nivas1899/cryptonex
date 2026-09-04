# Analyzing your own codebase with CRYPTONEX

CRYPTONEX reads a **directory of source code** (plus its dependency manifests and certificate
files) and produces a cryptographic inventory + post-quantum risk assessment.
**Nothing is uploaded anywhere** — the scan runs on your machine. "Upload a zip" in the
console just means CRYPTONEX unpacks it into a local temp folder and scans it there.

---

## 0. Fastest path — scan from the console

```bash
cryptonex serve                     # opens http://localhost:8713 on the "Scan" page
```

On the **Scan** page:
- **Local folder** tab → type the path to your codebase → *Run scan*
- **Upload a .zip** tab → drop a zip of your repo → *Run scan*

Results appear immediately (Overview / Inventory / Mosca Lab) and you can download
`cbom.json`, `result.json` and `report.html` from the Scan page.

With Docker, mount your code and point the path box at the mount:

```bash
docker run --rm -p 8713:8713 -v "/path/to/your/repo":/code:ro cryptonex:local serve
# then in the browser, Local folder → /code → Run scan
```

---

## 1. Point it at your code

| Your code is… | Do this |
|---|---|
| A local folder | scan the folder directly |
| A Git repository | `git clone <url>` first, then scan the folder |
| A monorepo | scan the repo root, or a sub-path (`cryptonex scan services/payments`) |
| A built container image | `docker save img:tag -o img.tar` then `cryptonex scan img.tar` — layers are unpacked and scanned in place |

CRYPTONEX recognises: `.py .java .kt .js .ts .go .c .cpp .h`, config files
(`.conf .cnf .yaml .yml .ini .properties .toml`), shell scripts, dependency manifests
(`requirements.txt`, `Pipfile`, `pyproject.toml`, `package.json`, `pom.xml`, `build.gradle`,
`go.mod`), and certificate/key files (`.pem .crt .cer .der .key .pub`).

---

## 2. Run it — pick one

### A. Docker (recommended — nothing to install but Docker)

```bash
docker build -t cryptonex:local .            # once

mkdir -p cryptonex-out
docker run --rm --user "$(id -u):$(id -g)" \
  -v "/path/to/your/repo":/scan:ro \
  -v "$PWD/cryptonex-out":/out \
  cryptonex:local scan /scan --out /out
```

> `--user "$(id -u):$(id -g)"` makes the container write the output as *you*, not root.
> Pre-create `cryptonex-out` so the mount exists.

Then open the console:

```bash
docker run --rm -p 8713:8713 -v "$PWD/cryptonex-out":/out \
  cryptonex:local serve --result /out/result.json --port 8713
# → http://localhost:8713
```

Or with the Makefile: `make docker && make docker-scan DIR=/path/to/your/repo && make ui`

### B. Installed CLI

```bash
pipx install cryptonex            # or: pip install -e ".[gui]"
cryptonex scan /path/to/your/repo --out cryptonex-out
cryptonex serve                   # console on :8713
```

### C. From the clone

```bash
make dev                              # venv + install
make scan DIR=/path/to/your/repo      # → cryptonex-out/
make ui
```

---

## 3. Tune the analysis to your organisation

The risk numbers depend on **Mosca's inequality** — `X + Y > Z − now`. Defaults are
`X` = per data-classification, `Y` = per remediation effort, `Z` = 2032. Override:

```bash
cryptonex scan <repo> \
  --crqc-year 2030 \       # Z — when you assume a quantum computer arrives
  --x 15 \                 # X — years your most sensitive data must stay secret
  --y 4                    # Y — years your org needs to migrate
```

Or model interactively in the console's **Mosca Lab** — three sliders + presets
(NIST baseline / Optimistic / Regulator EU-2030) that recompute the whole estate live.

Data classification is inferred from paths (`auth/`, `payment/`, `vault/`, `kms/` → higher
sensitivity; `test/`, `fixture/` → lower). Edit `cryptonex/knowledge/policy.yaml` to tune it.

---

## 4. What you get and how to read it

| File | What it is | Use it for |
|---|---|---|
| `cryptonex-out/cbom.json` | **CycloneDX 1.6 Cryptographic Bill of Materials** — every asset, its evidence, the dependency graph, `cryptonex:` risk properties | Feed to a GRC platform, an auditor, or a later migration tool. The interchange format. |
| `cryptonex-out/report.html` (`.pdf` with WeasyPrint) | Executive & audit report — posture grade, top risks, HNDL exposure, per-critical-asset detail, **migration plan grouped by effort** | Hand to leadership / an auditor / put in a submission |
| `cryptonex-out/result.json` | The full `ScanResult` — assets, graph, posture, coverage | SIEM / data lake ingestion; the console reads this |
| `cryptonex serve` console | Interactive — Overview, Inventory (filter + inspect evidence + recommendation), Mosca Lab, Coverage | Exploring the findings, demoing, tuning assumptions |

**Reading the CLI summary:**

```
Posture B (80/100)  ·  28 assets  ·  12 vulnerable  2 broken  3 weakened
HNDL 2  ·  Mosca at-risk 11
```

- **vulnerable** = broken by a quantum computer (Shor) — RSA, ECC, DH, DSA
- **broken** = already broken classically — MD5, SHA-1, DES, 3DES, RC4
- **weakened** = parameter fix needed — AES-128, PBKDF2-SHA1
- **HNDL** = *harvest-now-decrypt-later* — recorded today, decryptable later (key-exchange only)
- **Mosca at-risk** = `X + Y` exceeds `Z − now` for that asset

Each unsafe asset gets a **specific target**: RSA-sign → `ML-DSA-65`, key exchange →
`ML-KEM-768` (+ `X25519+ML-KEM-768` hybrid for transition), root CA → `SLH-DSA`,
3DES → `AES-256-GCM`, PBKDF2-SHA1 → `Argon2id`, with library and protocol support notes.

---

## 5. Put it in CI

```bash
cryptonex scan . --format sarif,cbom --fail-on vulnerable
# exit 1 if any asset is vulnerable/broken → blocks the merge
# exit 0 otherwise
```

`--fail-on` accepts `weakened`, `vulnerable`, or `broken`. Publish `cbom.json` as a build
artefact so you track crypto drift over time. (SARIF output + GitHub PR annotations are M1.)

---

## 6. Privacy

- **No network** during scan or analysis — verify with `--strict-offline` (M1) or just run it air-gapped.
- **Private keys are never read** — the certificate scanner records a `SHA-256(SubjectPublicKeyInfo)` fingerprint and metadata only, never the key material.
- Outputs stay in your `--out` directory. Nothing is sent anywhere.

---

## 7. Worked example — scanning a real library

```bash
$ cryptonex scan $(python -c "import cryptography,os;print(os.path.dirname(cryptography.__file__))")

Posture A (96/100)  ·  6 assets  ·  1 vulnerable  3 broken
  37  SHA-1     broken      x509/extensions.py
  33  RSA       vulnerable  hazmat/primitives/asymmetric/rsa.py   → ML-KEM-768
  32  RC4       broken      hazmat/decrepit/ciphers/algorithms.py → AES-256-GCM
  32  3DES      broken      hazmat/decrepit/ciphers/algorithms.py → AES-256-GCM
   0  AES       safe        fernet.py
   0  Argon2id  safe        hazmat/backends/openssl/backend.py
```

Grade A because it's a crypto library that *names* these algorithms rather than
depending on them in a high-criticality service — exactly the nuance the criticality
and Mosca weighting is there to capture.
