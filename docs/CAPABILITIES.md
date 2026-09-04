# ECDAT capabilities

What the tool does today, and how it lines up against the commercial post-quantum
discovery tools.

## Discovery — what it finds

| Collector | Sources | High-class OSS used |
|---|---|---|
| **source** | Python, Java/Kotlin/Scala, JavaScript/TypeScript, **C#**, **Rust**, **PHP**, **Ruby**, **Swift**, Go, C/C++, config files (nginx, Apache, HAProxy, Postfix, IPsec, **sshd_config**), shell — **160+ detection rules across 13 languages** | regex ruleset + KB (tree-sitter on the roadmap) |
| **dependency** | pip, npm, Maven/Gradle, Go modules, **Cargo**, **NuGet / .csproj**, **RubyGems**, **Composer**, **CocoaPods** — **80 catalogued crypto libraries** with EOL / advisory flags, + **14 CVE / RUSTSEC / GHSA advisories** matched by version range | `packaging` + offline advisory snapshot |
| **certificate** | X.509 (PEM/DER/PKCS7), public & private keys — key material never read, only a SHA-256(SPKI) fingerprint | `cryptography` |
| **binary** | ELF / PE / Mach-O — linked libcrypto/libssl/mbedTLS/wolfSSL/liboqs, crypto symbols, version banners, embedded PEM/OIDs | **`lief`** |
| **hand-rolled crypto** | **28 constant fingerprints** — AES S-box/Rcon, SHA-256/512/1/3 constants, MD5 T-table, Blowfish P-array, DES/GOST/SM4 S-boxes, Twofish/Serpent constants, NIST P-256 / secp256k1 / Curve25519 primes, ChaCha20 sigma, Poly1305 clamp, bcrypt magic, BLAKE2b IV | own detector |

## Threat finders — cryptographic misuse (28 rules → SARIF + CBOM vulnerabilities)

| Category | Detects |
|---|---|
| **cert-validation** (critical) | `verify=False`, `CERT_NONE`, Go `InsecureSkipVerify`, Node `rejectUnauthorized:false` / `NODE_TLS_REJECT_UNAUTHORIZED=0`, libcurl `VERIFYPEER 0`, Java all-trusting `TrustManager` / `NoopHostnameVerifier`, relaxed X509 flags |
| **crypto-misuse** | ECB mode, static / zero IV & nonce, hardcoded / empty KDF salt, unauthenticated CBC, fast-hash password storage, deprecated cipher references (RC2/RC4/DES/3DES/Blowfish), **legacy TLS (SSLv3, TLS 1.0, RSA-kx, NULL/EXPORT/anon)**, **weak SSH config** (group1, arcfour, HMAC-MD5, 3des-cbc), **non-constant-time MAC comparison**, **fixed ECDSA nonce**, insecure deserialization near a trust boundary |
| **weak-rng** | `random.*` (Python), `Math.random()` (JS), `java.util.Random`, C `rand()`/`srand()` — scoped per language, one finding per file |
| **hardcoded-secret** | literal API keys / passphrases / `SecretKeySpec("…")`, PEM private-key blocks in source |
| **weak-parameters** | RSA < 2048, DH group < 2048 / IKE Group 1-2, low PBKDF2 iteration counts |
| **algorithm-confusion** | JWT `alg:none`, empty algorithm allow-list, `jwt.decode(verify=False)` |
| **vulnerable-dependency** | crypto library at a version in a known-vulnerable range — CVE-2022-29217 (PyJWT), CVE-2020-26160 (`dgrijalva/jwt-go`), RUSTSEC-2023-0071 (`rsa` crate), CVE-2024-48948 (`elliptic`), BouncyCastle / node-forge / crypto-js advisories, … |

Every finding carries a CWE, a plain-language description, and a concrete fix.

## Analysis

- **Quantum status** — 42 algorithm families classified `safe / weakened / vulnerable / broken` with a cited reason; parameter overrides (AES-128 → weakened, RSA-1024 → broken, HMAC-SHA-1 → weakened, expired cert → vulnerable).
- **Mosca's inequality** per asset — X from data classification, Y from migration effort, Z configurable; exposure years + at-risk flag + a human-readable formula.
- **Risk score** (0–100) — published formula weighting quantum status, business criticality, Mosca exposure, external-facing surface, detection confidence, and an HNDL multiplier.
- **HNDL analysis** — confidentiality primitives only; `hndl_at_rest` highlights the worst case (long-lived SECRET/PCI/PII data).
- **Recommendation engine** — 9 rules: RSA/ECDSA sign → ML-DSA-65, roots of trust → SLH-DSA, key exchange → ML-KEM-768 + X25519 hybrid (TLS 1.3 / RFC 9370), 3DES/RC4 → AES-256-GCM, PBKDF2-SHA1 → Argon2id, EOL libraries → current release. Each carries NIST category, library + protocol support, latency class, and effort.

## PQC-readiness analytics (estate level)

- **Crypto-agility index** (0–100 + grade) — how readily the whole estate can be made quantum-safe, weighted by per-asset migration effort × business criticality.
- **Migration waves** — vulnerable assets sequenced by effort (config → library → code/protocol → coordination → architectural) with per-wave asset count and risk removed.
- **India NQM roadmap mapping** — every asset bucketed to *high-priority (Dec 2028)*, *full adoption (Dec 2029)*, or *no action*.
- **Quantum-risk timeline** — assets that fail Mosca's inequality for each possible CRQC arrival year, 2026–2040.

## Outputs

| Format | Purpose |
|---|---|
| **CycloneDX 1.6 CBOM** | crypto components + `cryptoProperties` + dependency graph + `vulnerabilities` array (the misuse findings) + `ecdat:` risk/agility properties. Deterministic serial. |
| **SARIF 2.1.0** | CI annotations + merge gate — one rule per misuse type and per quantum class, `security-severity` set for code-scanning UIs |
| **Executive / audit HTML (PDF with WeasyPrint)** | posture, weaknesses, HNDL, PQC readiness, quantum-risk timeline, migration waves |
| **ScanResult JSON** | complete, for a SIEM / data lake / the console |

## Positioning vs. the market

| Capability | ECDAT | IBM Guardium Quantum Safe | SandboxAQ | cbomkit (OSS) |
|---|---|---|---|---|
| Source-code discovery | ✅ 6 languages, 63 rules | ✅ | partial | ✅ 3 langs |
| Dependency discovery | ✅ 5 ecosystems | ✅ | – | – |
| Certificate / key discovery | ✅ | ✅ | ✅ | – |
| Binary discovery | ✅ (lief) | ✅ | – | – |
| Hand-rolled-crypto detection | ✅ constant fingerprints | ✅ | – | – |
| **Crypto-misuse / threat finders** | ✅ 21 rules, CWE-mapped | partial | – | – |
| Quantum risk + Mosca | ✅ | ✅ | ✅ | flag only |
| PQC / hybrid recommendation | ✅ 9 rules | partial | partial | – |
| **Crypto-agility index + migration waves** | ✅ | partial | – | – |
| **India NQM roadmap mapping** | ✅ | – | – | – |
| CycloneDX CBOM | ✅ + vulnerabilities | ✅ | ✅ | ✅ |
| SARIF / CI gate | ✅ | – | – | – |
| Fully offline / air-gapped | ✅ | – (SaaS) | – (SaaS) | self-host |
| Cost | free | $$$ | $$$ | free |

The differentiated columns: **threat finders + crypto-agility analytics + NQM mapping + SARIF, offline and free.**
