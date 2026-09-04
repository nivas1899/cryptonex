# The two remaining collectors — HSM and Cloud

PS 26164 requirement (i) names "hardware modules" and "cloud services" as artefact
types to catalogue. Both fit the **existing plugin architecture** unchanged — the
`AssetType` enum already has `HARDWARE_MODULE` and `CLOUD_SERVICE`, so each is just a
new `Scanner` subclass that emits `RawFinding`s. Neither can live in the **offline
default** because both need live access + operator credentials, so both are opt-in
scanners (`--scanners hsm` / `--scanners cloud.aws`).

---

## 1. Hardware modules (HSM / TPM / smartcard)

### What it is
Devices that hold private keys in tamper-resistant hardware — network HSMs (Thales
Luna, Entrust nShield, AWS/Azure Cloud HSM), TPMs, PKCS#11 tokens, smartcards. You
cannot extract the key material; you enumerate the *objects* and their attributes.

### What CRYPTONEX would report
Per token/slot: each key object's **type** (RSA / EC / AES), **size / curve**,
**label & ID**, and **allowed operations** (`CKA_SIGN`, `CKA_DECRYPT`, `CKA_WRAP`) →
one `CryptoAsset` with `asset_type = hardware-module`, then the normal quantum-status +
Mosca + recommendation pipeline runs on it (an RSA-2048 signing key in an HSM is still
Shor-vulnerable — the HSM protects it from extraction, not from a quantum computer).

### What's needed
| Item | Detail |
|---|---|
| Binding | `python-pkcs11` **or** `PyKCS11` (both maintained OSS) |
| Also | `PyKMIP` for network HSMs that speak KMIP; `python-tss` for TPM 2.0 |
| Runtime input | the vendor's PKCS#11 module path (`/usr/lib/softhsm/libsofthsm2.so`, `libCryptoki2_64.so`, …) + the slot **PIN** from the operator — used, never stored |
| CLI | `cryptonex scan --scanners hsm --pkcs11-module <path> --slot 0` |
| Test double | **SoftHSM2** (`apt install softhsm2`) — a free software HSM; a fixture script creates a token with a few keys so the scanner is fully testable offline in CI |
| New code | `cryptonex/scanners/hsm.py` (~120 lines): open module → `get_slots()` → per token `get_objects({ObjectClass: PRIVATE_KEY / CERTIFICATE / SECRET_KEY})` → read attributes → `RawFinding` |
| Effort | ~1–1.5 days incl. SoftHSM fixture + tests |

### Why it's deferred
No generic demo — you need an actual HSM or a SoftHSM install, and it breaks the
"nothing but a folder" story. The design is done; it's adapter code.

---

## 2. Cloud services (KMS / certificate managers / TLS policies)

### What it is
Managed cryptography in the cloud:
- **AWS** — KMS keys, ACM certificates, Secrets Manager, CloudHSM, TLS policies on ALB/NLB/CloudFront/API-Gateway
- **Azure** — Key Vault (keys/certs/secrets), Managed HSM, Application Gateway TLS
- **GCP** — Cloud KMS, Certificate Manager, Cloud HSM

### What CRYPTONEX would report
Read-only `List*` + `Describe*` calls → per key: **key spec** (`RSA_2048`,
`ECC_NIST_P256`, `SYMMETRIC_DEFAULT`), **origin** (AWS_KMS vs external vs CloudHSM),
**usage** (ENCRYPT_DECRYPT / SIGN_VERIFY), rotation status; per cert: signature &
public-key algorithm, expiry; per load-balancer: the negotiated TLS policy →
`CryptoAsset` with `asset_type = cloud-service`. Then quantum-status + Mosca +
recommendation run as normal (most cloud KMS crypto is already modern — the value is
**inventory completeness** and a **PQC-readiness view of the cloud estate**, plus
catching the RSA-2048 signing keys and old TLS policies).

### What's needed
| Item | Detail |
|---|---|
| SDKs | `boto3` (AWS) · `azure-identity` + `azure-keyvault-keys` + `azure-keyvault-certificates` + `azure-mgmt-network` (Azure) · `google-cloud-kms` + `google-cloud-certificate-manager` (GCP) |
| Runtime input | a **read-only** role/profile from the operator: `kms:List*/Describe*`, `acm:List*/Describe*`, `elasticloadbalancing:Describe*` (AWS) — supplied via the normal SDK credential chain, never stored |
| CLI | `cryptonex scan --scanners cloud.aws --profile prod --region ap-south-1` |
| Test double | **`moto`** (AWS mock, pure-Python, free) or **LocalStack** — CI seeds fake KMS keys / ACM certs and asserts the scanner catalogues them; Azure has `azure-mock`-style fixtures |
| New code | `cryptonex/scanners/cloud/aws.py`, `.../azure.py`, `.../gcp.py` — ~100–150 lines each; paginate, describe, map key-spec → family/params |
| Effort | ~1 day for AWS (do first — largest footprint), ~1 day each for Azure & GCP |

### Why it's deferred
Needs real cloud credentials, breaks offline, and is three separate provider
integrations. Not demoable generically.

---

## Cheapest way to show "cloud coverage" in the 3-day window (optional)

A **bring-your-own-export** scanner — offline, no credentials:

```bash
aws kms list-keys | aws kms describe-key ...   # operator runs this themselves
cryptonex scan --scanners cloud.import --import kms-export.json
```

`cryptonex/scanners/cloud_import.py` (~60 lines) reads a JSON/CSV the operator exports from
their cloud CLI (or a KMIP inventory dump) and turns each row into a `cloud-service`
`CryptoAsset`. This is a legitimate M1.5 capability, fully offline, and lets the demo
show a cloud KMS inventory from a sample file. If you have half a day spare after
everything else, build this one.

---

## The one-paragraph pitch line for the gap

> "Discovery covers source, dependencies, certificates, binaries and container images
> today, fully offline. Hardware security modules and cloud key stores plug into the
> same collector interface — `AssetType.HARDWARE_MODULE` and `CLOUD_SERVICE` are already
> in the model. They're the M2 milestone because they require live PKCS#11 or cloud-API
> access with operator credentials, which an air-gapped tool has to expose as an
> explicit opt-in connector rather than a default. SoftHSM2 and `moto` give us offline
> CI coverage for both when we build them."
