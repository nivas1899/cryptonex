# How to present CRYPTONEX — framing, demo spine, and judge Q&A

Distilled from an external review. The goal: the judge remembers *"they showed me
exactly where quantum risk is, why it matters, and what to do about it"* — not
*"they had a lot of scanners."*

---

## 1. The opening line

> **"You cannot migrate what you cannot see."**

Then, in three sentences:

> Enterprises have no single inventory of where cryptography is used — it is scattered
> across source code, dependencies, certificates, binaries and container images.
> CRYPTONEX discovers that cryptographic footprint, assesses its exposure to a future
> quantum computer, and turns it into an actionable migration plan.
> India's National Quantum Mission mandates exactly this inventory for critical sectors
> by December 2027.

**Do not open with:** line counts, "42 algorithm families", "162 rules", "39 tests".
Those are evidence you bring out *when asked*, not the story.

---

## 2. The demo — follow ONE asset end to end

Scan the fictional payments monorepo → **46 assets, 25 weaknesses, posture B**.
Then pick **one** asset and walk the full pipeline. Use the RSA-4096 **root CA**
(`pki/root-ca/root-ca.crt`).

| Step | What you show | What you say |
|---|---|---|
| **1 · Discover** | It appears in the inventory | "We found an RSA-4096 signing key — the offline root of trust for the whole PKI." |
| **2 · Evidence** | The Asset Detail → *Observed* block: `certificate` collector, confidence **confirmed**, the actual subject/key-size/CA-flag | "This is an observed fact, not a guess — here's the certificate it came from." |
| **3 · Quantum status** | *Knowledge base* block: `vulnerable — Shor's algorithm recovers the private key by factoring the modulus` | "Deterministic lookup with a citation. RSA of any size falls to Shor." |
| **4 · Assessment** | *Inferred* block: criticality `critical` — `pki(+22), root-ca(+15), external(+30), ca-key(+15), data:SECRET` | "Criticality is a **heuristic** from path and config signals — a starting point a human confirms. We never hide that it's inferred." |
| **5 · Mosca** | *Assumed* block: `X 20y + Y 5y = 25 vs Z(2032) − 2026 = 6 → exposed ~19y` | "X, Y and Z are configurable assumptions. We don't predict when a quantum computer arrives — we run a transparent scenario." |
| **6 · Recommend** | Recommendation card: `SLH-DSA-SHA2-192s` (rule `rec.sig.longlived`), effort *architectural*, "parallel PQC root, cross-sign" | "A root of trust is the most conservative case — hash-based SLH-DSA, and the migration pattern is a cross-signed parallel root." |
| **7 · Plan** | PQC Readiness → Migration waves: this asset is in **Wave 4 (architectural)**, NQM phase **high-priority 2028** | "Now it's an executive decision, sequenced against the national roadmap." |

That thread — **Code → Evidence → Status → Assessment → Mosca → Recommendation →
Wave → Decision** — is the whole product in ninety seconds.

Then (only then) show the estate views: Overview, Weaknesses, the Mosca Lab
recompute, the CBOM/SARIF export.

---

## 3. Judge Q&A — the hard questions and the honest answers

**"How do I know your scanner isn't full of false positives?"**
> "Two answers. One — every finding carries a stated **detection confidence**
> (confirmed / high / medium / low) and its evidence, so a reviewer can verify it in
> seconds. Two — we benchmarked it against seven real open-source projects (PyJWT,
> paramiko, python-jose, the `cryptography` library, …). `docs/benchmark` has the
> results and a precision spot-check sheet. Scans run in under six seconds and we
> separate production findings from test-fixture findings."

**"How do you know this cryptographic usage actually protects sensitive data?"**
> "We don't claim to. CRYPTONEX separates **observed evidence** from **inferred risk**.
> The algorithm, parameters and location are observed. Business criticality, data
> classification and external exposure are heuristic inferences from path and config
> signals — the report labels them as such and shows the reasoning. They're a
> prioritisation starting point for a human, not organisational truth."

**"How do you determine business criticality?"**
> "A transparent scoring model — path keywords (`auth`, `payment`, `vault`, `kms`,
> `pki`), external-facing signals, CA-key detection, and the inferred data
> classification, each with a published weight. Every asset shows its exact score
> breakdown. It's a heuristic and we say so."

**"Why 2032 for the quantum computer? Who decides X, Y, Z?"**
> "Nobody in the tool decides it. X, Y and Z are **configurable assumptions**. The
> Mosca Lab lets an organisation model their own — we ship NIST-baseline, optimistic,
> and EU-2030-regulator presets. CRYPTONEX doesn't predict a date; it performs a
> transparent scenario analysis and re-scores the estate live."

**"What about variable indirection, wrapper functions, dynamic imports, generated code?"**
> "Regex + constant-fingerprint detection is the M0 layer. We deliberately made
> detection a replaceable scanner plugin — AST / tree-sitter analysis is the next
> precision layer and it slots in behind the same interface without touching the core."

**"Your CVE data — what happens when a vulnerability drops tomorrow?"**
> "The detection knowledge base — rules, algorithms, libraries, advisories — is
> **versioned independently** from the scanner engine, so it updates without an
> engine release. The current build ships an offline snapshot on purpose: CRYPTONEX is
> designed to run air-gapped."

**"Can you scan AWS KMS / an HSM right now?"**
> "The demonstrable build covers source, dependencies, certificates, binaries and
> container images. HSM (PKCS#11) and cloud KMS collectors plug into the same scanner
> interface — `HARDWARE_MODULE` and `CLOUD_SERVICE` are already in the model — and are
> the next integration. We kept credentialed infrastructure access out of the offline
> demo on purpose. `docs/ROADMAP_HSM_CLOUD.md` has the exact plan and the offline test
> doubles (SoftHSM2, `moto`)."

**"Isn't this just cbomkit / IBM Guardium?"**
> "cbomkit scans three languages of source and stops at a flat list. IBM and SandboxAQ
> are $100k+/year foreign SaaS covering only part of the surface. CRYPTONEX is free,
> offline, unified across all five scan targets, and adds the parts nobody else does:
> **threat finding** (28 CWE-mapped misuse rules), a **crypto-agility index**,
> **migration waves**, and **India NQM roadmap mapping**."

---

## 4. Words to avoid

| Don't say | Say instead |
|---|---|
| "We identify **all** cryptographic assets." | "We provide **evidence-based discovery** across the supported artefact types, and report coverage and limitations." |
| "The system decides the criticality." | "The system **infers** a criticality score from transparent signals, for a human to confirm." |
| "We predict the quantum threat in 2032." | "2032 is one **configurable assumption**; the Mosca Lab models any scenario." |
| "It finds every misuse." | "It flags the misuse patterns in our rule set, each with confidence and evidence." |

---

## 5. What to have open in tabs during judging

1. The console on the payments-monorepo scan (Overview)
2. An Asset Detail showing the Observed / KB / Inferred / Assumed split
3. `docs/benchmark/results.md` (the real-OSS numbers)
4. The generated `report.html` (scroll to *Methodology, coverage & limitations*)
5. `docs/ROADMAP_HSM_CLOUD.md` (for the "can you do cloud?" question)
