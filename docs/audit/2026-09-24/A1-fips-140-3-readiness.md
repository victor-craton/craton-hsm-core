# A1 — FIPS 140-3 certification readiness assessment

| Field | Value |
|---|---|
| Target | craton-hsm `0.9.1` (`Cargo.toml:4`), branch `claude/modest-hamilton-y6ok79`, PKCS#11 v3.0 software module (`cdylib` + `rlib`) |
| Claimed level | FIPS 140-3 Overall Level 1, software module, modifiable OE (`docs/fips-140-3-certification.md` §1.2) |
| Assessment date | 2026-09-24 |
| Assessor stance | CMVP / accredited-lab evaluator (ISO/IEC 19790:2012 + ISO/IEC 24759, SP 800-140A..F, FIPS 140-3 IG) |
| Method | Static review of documentation and source only. Nothing was built or executed. |

---

## Scope, standards & method

**Standards and guidance applied**

- FIPS 140-3 / ISO/IEC 19790:2012 §7.2–7.12, with the derived test requirements in ISO/IEC 24759:2017.
- SP 800-140 (A: documentation, B: Security Policy, C/D: approved security functions and SSP establishment, E: authentication, F: non-invasive).
- FIPS 140-3 Implementation Guidance. The IGs cited are 2.4.A/2.4.C (approved modes, service indicator), 9.x (SSP entry/output), 10.3.A/10.3.B (CASTs, integrity-test algorithm), C.H (GCM IV), D.F (key agreement), D.N (key transport/wrapping) and the ESV requirement for entropy sources.
- Algorithm standards: FIPS 180-4, 186-5, 197, 198-1, 202, 203, 204 and 205; SP 800-38A/D/F, 800-56A r3, 800-56B r2, 800-56C r2, 800-57, 800-90A r1/B/C, 800-131A r2 (plus the r3 draft and NIST IR 8547 ipd for transition dates), 800-132 and 800-133 r2.

**Inputs reviewed**

- Docs: `docs/fips-140-3-certification.md`, `fips-gap-analysis.md`, `fips-mode-guide.md`, `security-policy.md`, `security-model.md`, `audit-scope.md`, `security-review-checklist.md`, `architecture.md`, `operator-runbook.md`, `tested-platforms.md`, `README.md`, `SECURITY.md`, `ROADMAP.md`, `CHANGELOG.md`.
- Code: `src/crypto/{self_test,integrity,drbg,pairwise_test,mechanisms,awslc_backend,rustcrypto_backend,sign,encrypt,wrap,derive,keygen,pqc,mlock}.rs`, `src/store/{key_material,attributes,encrypted_store,backup,lockout_store}.rs`, `src/token/{token,slot}.rs`, `src/session/{session,handle}.rs`, `src/core.rs`, `src/config/config.rs`, `src/pkcs11_abi/functions.rs`.
- Build and CI: `Cargo.toml`, `Cargo.lock`, `deny.toml`, `rust-toolchain.toml`, `.github/workflows/{ci,release}.yml`, `tools/*integrity*`, `craton-hsm-daemon/src/main.rs`, `tools/craton-hsm-admin/src/commands/*`.

**Confidence notation:** **[H]** high, meaning the evidence was read directly in code. **[M]** medium, meaning it depends on interpreting CMVP/IG practice or third-party crate behaviour. **[L]** low.

Line numbers refer to the reviewed commit. Where only a function is cited, the line given is the one where the function starts.

---

## Overall readiness verdict

### **NOT READY**

This codebase is a well-hardened PKCS#11 engineering effort, but a lab could not accept it for FIPS 140-3 testing in its current state. The reasons:

1. **The approved services are not provided by validated algorithm implementations, and the approved mode does not force them to be.** The default and release builds use RustCrypto, which has no CAVP certificates. The `fips` feature leaves `crypto_backend = "rustcrypto"` (`config.rs:282-290`, `core.rs:54-107`), and validation accepts `fips_approved_only = true` together with the RustCrypto backend (`config.rs:685-700`). Even with the AWS-LC backend, multi-part sign/verify, PBKDF2, HKDF, PQC, the integrity test and every self-test still run RustCrypto code (`awslc_backend.rs:202-340`, `self_test.rs`).
2. **The RBG requirement fails.** `C_GenerateRandom` returns raw `OsRng` output and bypasses the SP 800-90A DRBG entirely (`functions.rs:3280-3284`). The `HsmCore.drbg` instance is never used. There is no ESV-certified entropy source, no min-entropy claim, and no SP 800-90A §11.3 health testing.
3. **Self-tests do not meet IG 10.3.A.** The GCM test compares no known answer. The RSA, ECDSA, ML-DSA and ML-KEM tests are round-trips with freshly generated keys. ECDH, AES-KW, KTS-OAEP, PBKDF2, KDA/HKDF, DRBG and SLH-DSA have no CASTs. The tests exercise RustCrypto even when AWS-LC provides the service.
4. **The software integrity test is optional and bypassable, and is documented incorrectly.** It passes without a `.sig` file in the documented FIPS build, which omits the `fips` feature. It passes when the module path can't be resolved, even with `fips` enabled (`integrity.rs:85-93`). It uses an unvalidated Ed25519 with no prior CAST. All FIPS documents describe an HMAC-SHA256/`.hmac` scheme that the code no longer implements.
5. **The cryptographic boundary and module identity are not defined consistently.** `security-policy.md` puts the gRPC daemon and admin CLI inside the boundary, and the certification document puts them outside. The public `rlib` API lets those tools run crypto without POST or the error state. The version reported by `C_GetInfo` is 0.1.
6. **There are serious PKCS#11/SSP-management security defects:**
   - A **wrong SO PIN in `C_InitToken` still wipes every key in every slot** (A1-07, High).
   - **Keys that are both sensitive and extractable are returned in plaintext** by `C_GetAttributeValue` (A1-08, High).
   - Keys are not zeroized at `C_Finalize` or `C_DestroyObject`.
   - Several services have no authorization check.

**Counts:** 6 Blocker, 15 Major, 8 Minor, 3 Observation (32 findings). Ten findings are also security vulnerabilities: 2 High (A1-07, A1-08), 3 Medium (A1-10, A1-12, A1-26) and 5 Low (A1-01, A1-13, A1-14, A1-15, A1-23).

Much of the documentation in `fips-gap-analysis.md` and `fips-140-3-certification.md` is aspirational or out of date. A lab would treat the Security Policy draft as non-conformant to SP 800-140B until it has been rewritten against the code (see the discrepancy table).

---

## Readiness matrix

| # | FIPS 140-3 area (ISO 19790 §) | Status | Evidence | Principal gap(s) |
|---|---|---|---|---|
| 1 | Cryptographic module specification (7.2) | **Not met** | `fips-140-3-certification.md` §1.5 vs `security-policy.md` §1.1; `Cargo.toml:14-21`; `core.rs:54-107`; `functions.rs:324` | Boundary and module identity are inconsistent. Approved mode can run on the unvalidated backend. There is no version/status output. The service indicator is inadequate (A1-03, A1-06, A1-11, A1-24). |
| 2 | Module interfaces (7.3) | Partial | `functions.rs` (C ABI), `fips-140-3-certification.md` §2 | The four logical interfaces are mapped. The error state is reported as `CKR_CRYPTOKI_NOT_INITIALIZED` by `C_GetInfo` (A1-09). Operation-state export is undocumented (A1-22). Control and data are separated adequately. |
| 3 | Roles, services, authentication (7.4) | **Not met** | `session.rs:38-43`; `functions.rs:2508-2530, 2688-2712, 1066-1080, 5263-5310, 4983-5060` | Services table contradicts code: SO can run User crypto, and several services need no login (A1-12). Documented PIN policy is wrong (A1-23). A version/status-show service is missing. |
| 4 | Software/firmware security (7.5) | **Not met** | `integrity.rs:84-232`; `tools/sign-integrity.sh`; `release.yml` | Integrity test is optional, has a bypass, uses an unvalidated algorithm with no prior CAST, is documented as HMAC, and releases carry no signature (A1-05). |
| 5 | Operational environment (7.6) | Partial | `security-policy.md` §8; `tested-platforms.md`; `rust-toolchain.toml` | No specific tested OE list ("Expected" status). Toolchain is not pinned. `AWS_LC_SYS_NO_ASM` differs from the validated build (A1-19). The single-operator and process-isolation claims are adequate. |
| 6 | Physical security (7.7) | N/A | `fips-140-3-certification.md` §6 | Justified for a Level 1 software module. |
| 7 | Non-invasive security (7.8) | N/A | §7 | Acceptable at Level 1 (SP 800-140F currently defines no mandatory approved non-invasive mitigations). |
| 8 | SSP management (7.9) | **Not met** | `functions.rs:3259-3297`; `drbg.rs`; `attributes.rs:566-579`; `sign.rs:34-100`; `functions.rs:78-82,143-188`; `derive.rs`; `awslc_backend.rs:694-740` | RBG and entropy are not compliant (A1-01, A1-02). Plaintext output of sensitive keys (A1-08). Zeroization gaps (A1-10). Key agreement does not follow SP 800-56A/C (A1-14). GCM IV scheme does not match IG C.H (A1-15). SSP table is incomplete (A1-18). |
| 9 | Self-tests (7.10) | **Not met** | `self_test.rs:21-66`; `pairwise_test.rs`; `functions.rs:226-277` | CASTs do not meet IG 10.3.A and do not test the implementations in use (A1-04). Error-state semantics differ from the docs (A1-09). PCTs exist for all key-pair types (partial credit). |
| 10 | Life-cycle assurance (7.11) | **Not met** | `.github/workflows/release.yml`, `ci.yml`; `rust-toolchain.toml`; doc versions | No FIPS build or release. CI never tests `awslc-backend` or `fips`. Guidance documents contradict the code. Versioning is inconsistent (A1-20). |
| 11 | Mitigation of other attacks (7.12) | Partial / claims inaccurate | `deny.toml:5-7`; `fips-140-3-certification.md` §11 | "RSA blinding" is claimed while RUSTSEC-2023-0071 (Marvin) is suppressed and the `rsa` crate is used on the default path (A1-26). Other claims are voluntary. |
| — | Algorithm validation (CAVP/ACVP) | **Not met** | `Cargo.toml:25-54`; `Cargo.lock:175-190` | The only implementation that could be validated (AWS-LC FIPS, `aws-lc-fips-sys 0.13.13`) is optional, is not the default, and is not used for several services. ECDSA hash binding is wrong (A1-13). Mechanism semantics are wrong (A1-16). |
| — | Approved/non-approved algorithm policy & transitions | Partial | `mechanisms.rs:164-273` | SHA-1 and weak RSA are blocked. The status text for Ed25519 and PQC is out of date (A1-21). |

---

## Findings

Severity is given twice: **Cert** is the effect on certification (Blocker / Major / Minor / Observation), and **Sec** is the security severity where the finding is also a vulnerability.

### A1-01 [Blocker] `C_GenerateRandom` bypasses the SP 800-90A DRBG and returns raw OS RNG output
- **Area:** 8 SSP management (RBG), 2 interfaces. **Sec:** Low. **Confidence:** [H]
- **Location:**
  - `src/pkcs11_abi/functions.rs:3259-3297`: `use rand::rngs::OsRng; … OsRng.fill_bytes(data);` at 3280-3284.
  - `src/core.rs:26,142,231`: `HsmCore.drbg` is created and exposed but never used anywhere.
  - Docs: `fips-140-3-certification.md` §2.2 ("Generate random bytes via HMAC_DRBG"), §9.2.2 ("Continuous RNG … every `C_GenerateRandom` call … compare consecutive 256-byte OS RNG outputs"); `fips-gap-analysis.md:69` ("`Mutex<[u8;32]>` … identical output fails with `CKR_FUNCTION_FAILED`"); `security-policy.md` §5.4, §7.3; `fips-mode-guide.md:151,179`.
- **Description:** The module's only random-output service writes `OsRng` bytes (getrandom/BCryptGenRandom) directly to the caller's buffer. There is no DRBG, no health test, and no continuous test anywhere on this path, and the documented "continuous RNG test" for `C_GenerateRandom` does not exist in code. Elsewhere, key generation, PSS/OAEP/ECDSA randomness and GCM prefixes each instantiate a fresh `HmacDrbg` per call (`drbg.rs:250-260`, `keygen.rs:64,88,104,119`, `sign.rs:306,397,473,511,752`, `pqc.rs:17-78`). That design adds nothing over the OS RNG, and every one of those instances also needs to be accounted for in the SSP table. The `rsa_pss_sign_prehashed` path in the AWS-LC backend uses `OsRng` directly (`awslc_backend.rs:269-296`).
- **Certification impact:** The Security Policy lists the RBG as an approved service, but the output does not come from an approved DRBG. Per SP 800-90C/IG, an approved RBG must be an SP 800-90A DRBG seeded from an ESV-validated source; the OS kernel CSPRNG is not an approved RBG unless it is claimed and validated as such. This is a Blocker for area 8 and for the services table.
- **Recommendation:**
  - Route `C_GenerateRandom` and all internal randomness through one module-level approved DRBG. With AWS-LC, use AWS-LC's DRBG (`aws_lc_rs::rand`), which is covered by the AWS-LC certificate. Otherwise use `HsmCore.drbg`.
  - Enforce SP 800-90A limits: at most 2^19 bits per request, with reseed counter handling.
  - Remove the per-call DRBG instances, or document them as separate DRBG instances in the SSP table.
  - Delete the false "continuous RNG test" claims.

### A1-02 [Blocker] No compliant entropy source (ESV) and no SP 800-90A health testing/CAST for the HMAC_DRBG
- **Area:** 8 (RBG), 9. **Confidence:** [H] on code, [M] on CMVP policy.
- **Location:**
  - `src/crypto/drbg.rs:67-84` (instantiate from `OsRng`, 48 bytes, no personalization string).
  - `drbg.rs:185-239`: "prediction resistance" is simply an `OsRng` reseed. The "continuous health test (SP 800-90B §4.9)" is a comparison of consecutive output blocks.
  - `self_test.rs:442-462` (`post_drbg_health` checks only non-zero and "outputs differ").
  - `drbg.rs:86-105` (`new_deterministic` is `#[cfg(test)]` only).
  - Docs: `fips-gap-analysis.md:65,73,129` and `security-policy.md` §5.4/§7.1 row 16 claim a "NIST CAVP known-answer test".
- **Description:**
  - The entropy input comes from the OS CSPRNG with no ESV certificate reference, no min-entropy estimate and no noise-source health tests (RCT/APT, SP 800-90B §4.4).
  - SP 800-90B §4.9 applies to noise sources, not to DRBG outputs. The output-comparison test is the old FIPS 140-2 CRNGT, which is neither required nor sufficient under 140-3.
  - SP 800-90A §11.3 health testing (instantiate/generate/reseed known-answer testing) is absent. The documented "NIST CAVP KAT" in POST does not exist; `post_drbg_health` cannot detect an incorrect DRBG.
  - DRBG failure handling is inconsistent across callers: `process::abort()` in `DrbgRng::fill_bytes` (`drbg.rs:275-299`) and `PqcDrbgRng` (`pqc.rs:38-68`), an ignored error in PIN-salt generation (`encrypted_store.rs:443-448`, `let _ = drbg.generate(&mut s)` leaves an all-zero salt on failure), and error propagation elsewhere.
  - The HMAC internal state (`hmac::Hmac` ipad/opad) and the `finalize()` temporaries that hold the new K and V are not zeroized (`drbg.rs:116-148`).
- **Certification impact:** CMVP requires an ESV public-use document or certificate for the entropy source, a min-entropy claim in the SP, and a DRBG CAST. With none of these the RBG cannot be approved.
- **Recommendation:**
  - Use AWS-LC's DRBG plus its ESV-validated CPU Jitter entropy source, and reference the ESV certificate. Alternatively, obtain an ESV for the claimed OE's kernel source.
  - Add an SP 800-90A instantiate/generate/reseed KAT using CAVP HMAC_DRBG vectors to POST.
  - Unify the failure behaviour into a latched error state. Never ignore a DRBG failure.
  - Drop the "SP 800-90B §4.9" labelling.

### A1-03 [Blocker] Approved services run on non-validated implementations, even when the "FIPS" configuration is used
- **Area:** 1, CAVP. **Confidence:** [H]
- **Location:**
  - `Cargo.toml:14-18`: `default = ["rustcrypto-backend"]`; the `fips = []` feature changes only the integrity check and config loading.
  - `src/config/config.rs:282-290`: `fips_defaults()` keeps `crypto_backend = "rustcrypto"` (from `default_crypto_backend()`, `config.rs:217-219`).
  - `src/core.rs:57-72`: `"rustcrypto"` selects `RustCryptoBackend` whenever `rustcrypto-backend` is compiled, which is the default.
  - `config.rs:669-700`: `validate()` accepts `fips_approved_only = true` together with `crypto_backend = "rustcrypto"` and only logs a warning when `awslc` is missing (`core.rs:61-68`).
  - `src/crypto/awslc_backend.rs:202-340`: every `*_prehashed` sign/verify (the multi-part `C_SignUpdate`/`C_SignFinal` path) delegates to RustCrypto `rsa`/`p256`/`p384`, as the file's own comment admits.
  - Always RustCrypto regardless of backend: PBKDF2 PIN hashing (`encrypted_store.rs:430-457`), HKDF (`derive.rs:142-156`, RustCrypto backend only), the integrity test (`integrity.rs:17-18`), all PQC (`pqc.rs`), and all POST tests (`self_test.rs`).
  - `.github/workflows/release.yml:41-42` builds with default features; `ci.yml` never enables `awslc-backend` or `fips`.
- **Description:** A deployment built as documented has `fips_approved_only = true` and reports approved mechanisms, but every classical operation still runs RustCrypto code with no CAVP certificate. That includes `cargo build --features fips` and even `--features fips,awslc-backend` without `--no-default-features`. With AWS-LC selected, a documented approved service (multi-part signing) still silently uses RustCrypto, and the audit log still records `fips_approved: true` (`functions.rs:4717`).
- **Certification impact:** Every approved security function in the module must have a CAVP certificate for the exact implementation and OE. As built, the module cannot be tested by ACVP for its claimed approved services. Blocker.
- **Recommendation:**
  - Define a single FIPS build: `--no-default-features --features fips,awslc-backend`. Make the `fips` feature imply `awslc-backend` and exclude `rustcrypto-backend`.
  - Hard-fail `C_Initialize` if `fips_approved_only` is set and the backend is not AWS-LC.
  - Implement prehashed operations through AWS-LC low-level APIs, or refuse multi-part sign/verify in approved mode.
  - Move PBKDF2, HKDF, HMAC and the integrity signature to AWS-LC.
  - Obtain ACVP certificates for the exact AWS-LC build and OE, and document how the embedded AWS-LC module relates to this module's boundary.

### A1-04 [Blocker] Pre-operational and conditional self-tests don't meet IG 10.3.A/10.3.B and don't test the implementations in use
- **Area:** 9. **Confidence:** [H] on code, [M] on IG interpretation.
- **Location:** `src/crypto/self_test.rs:21-66` (sequence), with per-test issues below. Docs: `fips-140-3-certification.md` §9.1.2, `fips-gap-analysis.md:45-77` ("Remaining POST Gaps: None").
- **Description:**
  - **Wrong implementation under test.** Every KAT calls `sha2`, `hmac`, `aes_gcm`, `crate::crypto::encrypt::*`, `keygen::*` or `sign::*` directly (RustCrypto). None goes through `hsm.crypto_backend`. POST runs before the config and backend are even chosen (`functions.rs:251` vs `256-263`). With AWS-LC selected, the module's CASTs therefore do not cover the code that provides the service. AWS-LC's internal self-tests may cover AWS-LC, but only if the boundary/bound-module relationship is documented (A1-06).
  - **AES-GCM is not a KAT** (`self_test.rs:225-269`). Part 1 is a round-trip. Part 2 only checks that the tag is 16 bytes and "not all zeros". The known tag for key=0, IV=0, P="" (`530f8afbc74536b9a963b4f1c4cb738b`) is never compared.
  - **Signature CASTs use freshly generated keys.** RSA (`:341-358`), ECDSA P-256 (`:361-371`), ML-DSA-44 (`:378-388`) and ML-KEM-768 (`:391-405`) are generate-sign-verify or generate-encaps-decaps round-trips. IG 10.3.A requires a CAST with a known key and known answer, or at least a fixed key with a deterministic signature or verification of a known signature. ML-KEM requires encapsulation and decapsulation CASTs, including implicit rejection; ML-DSA requires keygen, sign and verify CASTs. A round-trip using a new random key also depends on the untested RBG.
  - **Missing CASTs:**
    - ECDH/KAS-ECC-SSC (primitive Z computation)
    - AES-KW/KWP (SP 800-38F)
    - RSA-OAEP KTS
    - RSA-PSS
    - PBKDF2 (SP 800-132, which IG 10.3.A requires)
    - HKDF/KDA
    - HMAC_DRBG (A1-02)
    - SLH-DSA
    - Ed25519, which is the integrity-test algorithm (A1-05)
  - **Ordering (IG 10.3.B).** The integrity test (Ed25519 over SHA-256) runs first, at `self_test.rs:30`, before any CAST of SHA-256 or Ed25519. IG 10.3.B requires the integrity-technique algorithm to pass its CAST before it is used.
  - **POST side effects.** `run_post()` clears the CBC/CTR IV-reuse trackers (`self_test.rs:25-26`; `encrypt.rs:60-68,209-211`). The KATs also touch the global GCM counter and prefix maps (`encrypt.rs:34-45`).
  - **PCTs** (`pairwise_test.rs`) exist for RSA, EC, Ed25519, ML-DSA, SLH-DSA and ML-KEM, and a failure latches `POST_FAILED` (`functions.rs:2794-2801, 2875-2890, 2945-2948, 3025-3050`). This part is broadly acceptable.
- **Certification impact:** Blocker. A lab will reject round-trip "KATs" and missing CASTs for approved algorithms.
- **Recommendation:**
  - Rewrite POST as backend-dispatched CASTs with fixed CAVP vectors for every approved algorithm the backend provides. That means encrypt and decrypt for AES-GCM; RSA SigGen/SigVer with a fixed key and fixed PKCS#1 v1.5 answer; ECDSA with a fixed key, verifying a known signature; KAS-ECC-SSC with known Z; AES-KW; OAEP decrypt with a known answer; PBKDF2; HKDF; and DRBG.
  - Run the Ed25519 (or ECDSA) and SHA-256 CASTs before the integrity test.
  - Before offering ML-KEM/ML-DSA/SLH-DSA as approved, add FIPS 203/204/205-conformant CASTs.
  - Don't reset IV trackers in `run_post`.

### A1-05 [Blocker] Software integrity test is optional, bypassable, uses an unvalidated algorithm, and is documented as a different mechanism
- **Area:** 4, 9, 10. **Confidence:** [H]
- **Location:**
  - `src/crypto/integrity.rs:84-94`: "could not determine module path — skipping" returns `Ok(())` before any `#[cfg(feature = "fips")]` guard, so it applies in FIPS builds too.
  - `integrity.rs:127-143`: without the `fips` feature, a missing `.sig` means the test passes.
  - `integrity.rs:36-68`: the public key comes from the build environment variable; the default is all zeros.
  - `integrity.rs:196-214`: Ed25519 via `ed25519-dalek` over SHA-256 via `sha2`.
  - `tools/sign-integrity.sh`; `tools/compute-integrity-hmac.sh` (obsolete HMAC tool still shipped).
  - `release.yml:41-42` (no `CRATON_HSM_INTEGRITY_PUBLIC_KEY`, no `.sig` artifact).
  - Docs: `fips-140-3-certification.md` §4.1 (HMAC-SHA256, key `b"Craton HSM-FIPS-Integrity-Key-v1.0!"` at `integrity.rs:23`, `.hmac` sidecar, `compute-integrity-hmac.sh`); `fips-mode-guide.md` §3 and checklist line 196; `fips-gap-analysis.md:49,81`; `security-policy.md` §7.1 row 0 and §11 ("Integrity HMAC key"); `CHANGELOG.md:23`.
- **Description:**
  - The documented FIPS build (`fips-mode-guide.md:16`: `--features awslc-backend`) does not enable the `fips` feature, so the integrity test is opt-in and passes when `.sig` is absent.
  - Even with `fips`, a `dladdr`/`GetModuleHandleExW` failure skips the test.
  - The test verifies the file on disk rather than the loaded image. That is acceptable only if the SP documents it.
  - Ed25519 is approved under FIPS 186-5, but here it runs on an unvalidated library, has no CAST, and the module itself classifies `CKM_EDDSA` as non-approved (`mechanisms.rs:160-163`).
  - Every FIPS document describes a different mechanism (HMAC, embedded HMAC key, `.hmac`), including source line citations that no longer exist.
  - The release pipeline produces neither a signed module nor an embedded key.
- **Certification impact:** Blocker. ISO 19790 §7.5 requires an approved integrity technique that runs every time. The procedure has to be accurately described in the SP and the Admin guidance.
- **Recommendation:**
  - Make the integrity test unconditional in the FIPS build: fail closed on a missing `.sig`, an unresolved path or a placeholder key.
  - Implement it with an AWS-LC-validated algorithm (HMAC-SHA-256 or ECDSA P-256/P-384, or Ed25519 if it is on the AWS-LC certificate), with a preceding CAST.
  - Sign and ship `.sig` in the release pipeline.
  - Remove `compute-integrity-hmac.*` and rewrite §4.1 and the guide.

### A1-06 [Blocker] Cryptographic boundary, module identity and versioning are inconsistent; the in-boundary crypto is reachable without POST or the error state
- **Area:** 1, 2, 10. **Confidence:** [H]
- **Location:**
  - `docs/security-policy.md` §1.1 (lines 24-52) draws the gRPC daemon and Admin CLI **inside** the boundary. `docs/fips-140-3-certification.md` §1.5 (lines 185-193) lists them **outside**.
  - `README.md:30,98-101,116,150`: the FIPS backend lives in a separate enterprise crate `craton-hsm-awslc`, while this repo ships an inline `awslc_backend.rs` ("inline variant … for benchmarking", `awslc_backend.rs:1-7`).
  - `src/lib.rs`: all modules are `pub`. `Cargo.toml:14` builds `crate-type = ["cdylib","rlib"]`.
  - Admin CLI: `tools/craton-hsm-admin/src/commands/*.rs` construct `HsmCore::new` with no `run_post()` (for example `key.rs:80`, `backup.rs:108`, `token.rs:13`).
  - Daemon: `craton-hsm-daemon/src/main.rs:68-86` uses `HsmConfig::load_from_path`, which bypasses the `fips` hard-coded defaults and `CRATON_HSM_FIPS`. It calls `HsmCore` directly, so `POST_FAILED` from PCTs (which lives in `pkcs11_abi/functions.rs:72`) never applies.
  - `functions.rs:324`: `CK_INFO.library_version = 0.1`. `fips-140-3-certification.md:101` says Version 0.9.0 while the header says 0.9.1. `fips-140-3-certification.md:105` says `name = "craton_hsm"`; the crate name is `craton-hsm`.
- **Description:** The module's identity is undefined. It could be the `.so`/`.dll` alone, the `.so` plus the daemon, or the enterprise build. The lab needs one binary set with one name and version, plus a documented relationship to the embedded AWS-LC FIPS module. The Rust library API exposes every security function without POST gating, error state or role checks, so any "outside-the-boundary" tool that links the `rlib` is in practice running module code outside the module's control.
- **Certification impact:** Blocker for area 1: SP 800-140B §1 (boundary diagram and components, excluded components, versions).
- **Recommendation:**
  - Decide the boundary: the `cdylib` only, with a clearly defined OE.
  - Make the internal crypto APIs `pub(crate)`, or put POST and the error state in `HsmCore` construction so every entry point shares them.
  - Report a version that matches the certificate via `C_GetInfo`/`C_GetTokenInfo` (`CK_VERSION` 0.9.1) and provide a "show status" service.
  - Name the embedded AWS-LC version and certificate.

### A1-07 [Major] `C_InitToken` destroys all objects (all slots) and closes sessions *before* verifying the SO PIN
- **Area:** 3, 8. **Sec:** **High** (unauthenticated destruction of all keys; availability and integrity). **Confidence:** [H]
- **Location:** `src/pkcs11_abi/functions.rs:515` (`close_all_sessions`), `:518` (`hsm.object_store.clear()`), `:520` (`force_reset_all_counters()`), `:522` (`token.init_token(pin,&label)`, where the PIN is verified, `token.rs:403-431`). `ObjectStore::clear` is global and also clears any persistent store (`attributes.rs:333-343`).
- **Description:** Any caller able to invoke `C_InitToken` on an initialized token can pass an arbitrary PIN. The object store is cleared first, across **all slots**, because there is a single `ObjectStore` in `HsmCore`. Every session is closed, and only then does PIN verification fail with `CKR_PIN_INCORRECT`. The SO-PIN check in `init_token` also bypasses the SO lockout (only a backoff capped at 5 s, `token.rs:27,403-431`), so it can be used indefinitely for SO PIN guessing (see A1-23).
- **Certification impact:** The services table says token initialization requires CO authentication, and a zeroization service reachable without authentication conflicts with the documented roles. Major.
- **Recommendation:** Verify the SO PIN first, while holding the auth lock. Only then clear objects, and only for the target slot's token. Apply SO lockout to `C_InitToken` verification, and require that no sessions are open (`CKR_SESSION_EXISTS`) as PKCS#11 specifies.

### A1-08 [Major] Plaintext export of keys that are both sensitive and extractable; the documented export rule differs
- **Area:** 8 (SSP output). **Sec:** **High**. **Confidence:** [H]
- **Location:** `src/store/attributes.rs:566-579`: `if obj.sensitive && !obj.extractable { return Err(AttributeSensitive) }`, so sensitive+extractable is allowed, and non-sensitive keys are always allowed. Docs: `fips-140-3-certification.md` §8.4 ("`CKA_EXTRACTABLE = true` AND `CKA_SENSITIVE = false`"); `security-policy.md` §6.5.
- **Description:** In PKCS#11, `CKA_SENSITIVE=TRUE` means the value can never be revealed in plaintext; `CKA_EXTRACTABLE` only governs wrapping. Here a key generated with `CKA_SENSITIVE=TRUE, CKA_EXTRACTABLE=TRUE` (a common template for wrap-exportable keys) is returned in plaintext by `C_GetAttributeValue(CKA_VALUE)`. The returned `Vec` copy is not zeroized (`attributes.rs:578`). The Security Policy states a different, stricter rule.
- **Certification impact:** SSP output behaviour must be specified exactly (ISO 19790 §7.9.5; IG 9.5.A). The SP is false, and the actual behaviour exports CSPs in plaintext against the object policy. Major.
- **Recommendation:** Block `CKA_VALUE` whenever `sensitive` is set, regardless of `extractable`. In approved mode, also consider blocking plaintext output of private and secret keys altogether, allowing only approved wrapping. Zeroize the copies.

### A1-09 [Major] Error-state semantics differ from the documentation; failure handling is inconsistent
- **Area:** 9, 2. **Confidence:** [H]
- **Location:**
  - `functions.rs:248`: `POST_FAILED.store(false)` on every `C_Initialize`.
  - `functions.rs:280-307`: `C_Finalize` does not consult `POST_FAILED`, so a module in the error state can be finalized and re-initialized, which re-runs POST.
  - `functions.rs:310-314`: `C_GetInfo` maps the error state to `CKR_CRYPTOKI_NOT_INITIALIZED`.
  - `drbg.rs:298`, `pqc.rs:47,58,65`: `abort()` of the host process.
  - `encrypted_store.rs:443-448`: DRBG error ignored.
  - Docs: `fips-140-3-certification.md` §9.3 item 4 ("cannot recover without process restart"); `fips-mode-guide.md:187`; `operator-runbook.md:297-307`.
- **Description:** A PCT failure can be cleared by `C_Finalize` followed by `C_Initialize`. That is permissible as a "reset/re-run of pre-operational self-tests" (ISO 19790 §7.10), but it contradicts the SP. In the error state, status output reports "not initialized" instead of an error indication. Some RBG failures kill the host application, one is silently ignored, and others propagate normally. There is no documented list of error states (hard vs soft) or of the exit conditions for each.
- **Certification impact:** SP 800-140B requires the error states, their status indicators and recovery to be documented accurately. Major.
- **Recommendation:**
  - Define the error states in the FSM and document the recovery path (re-initialization re-runs POST).
  - Return a distinguishable status such as `CKR_GENERAL_ERROR`/`CKR_DEVICE_ERROR` from every function, including `C_GetInfo`.
  - Replace `abort()` and the ignored errors with a transition to the latched error state.

### A1-10 [Major] SSP zeroization gaps: module shutdown, key destroy, cached RSA keys and transient copies
- **Area:** 8 (zeroization). **Sec:** Medium. **Confidence:** [H], [M] for the `hmac` crate internals.
- **Location and description:**
  - **Shutdown.** `C_Finalize` (`functions.rs:280-307`) sets the global to `None` but never zeroizes the object store or PIN hashes. Every other thread's thread-local `CACHED_HSM` (`functions.rs:78-82`) keeps an `Arc<HsmCore>` alive. `get_hsm()`'s slow path returns `NOT_INITIALIZED` before replacing the stale cache (`functions.rs:178-183`). All keys, PIN hashes and DRBG state therefore survive `C_Finalize` until those threads exit.
  - **RSA key cache.** `sign.rs:69-95` caches up to 64 parsed `RsaPrivateKey` values in a static `DashMap` that is not mlocked. `clear_rsa_key_cache()` (`sign.rs:98`) has **no callers**, contradicting its comment "Called on C_Finalize / C_InitToken". Destroyed keys therefore remain cached. `ZeroizingRsaKey::drop` (`sign.rs:44-63`) zeroizes only a new DER *copy* and then replaces the key; its comment's premise is inaccurate [M].
  - **Destroy path.** `C_DestroyObject` copies the key into a plain `Vec` (`functions.rs:1091-1094`) and never zeroizes it.
  - **Other plain `Vec` copies of keys:**
    - `C_WrapKey`: wrapping key and target key (`functions.rs:5036-5039, 5060-5063`)
    - `C_DeriveKey`: base private key (`functions.rs:5308-5311`)
    - `C_GetAttributeValue` (`attributes.rs:578`)
    - AWS-LC OAEP decrypt output and the raw ECDH `shared.to_vec()` (`awslc_backend.rs:539-554, 707-716`)
    - the ML-KEM shared secret returned as `Vec<u8>` (`pqc.rs` encapsulate/decapsulate)
    - the ML-KEM seed copied into a non-zeroizing `ml_kem::Seed` (`pqc.rs` keygen)
  - **Active operations.** They hold `Arc<RwLock<StoredObject>>` (`session.rs` `cached_object`), which keeps destroyed keys alive until the operation ends.
  - **mlock.** `munlock` is page-granular and not reference-counted (`key_material.rs:92`, `mlock.rs:33-48`), so freeing one key can unlock pages that still hold other keys. `mlock` failures are only warnings (`key_material.rs:39-41`), and `new_strict` is unused.
  - **DRBG.** HMAC keyed state and `finalize()` temporaries are not zeroized (`drbg.rs:116-148`).
- **Certification impact:** ISO 19790 §7.9.7 requires all unprotected SSPs to be zeroizable, with zeroization documented per SSP and effective. The SP's "all CSPs zeroized" claims (§8.6; `security-model.md:217`) are false. Major.
- **Recommendation:**
  - Explicitly `clear()` the object store, token PIN hashes and caches in `C_Finalize`, and bump the generation so that every `get_hsm` call drops a stale cache entry.
  - Call `clear_rsa_key_cache` on destroy, finalize and init-token, or remove the cache.
  - Use `Zeroizing<Vec<u8>>` or borrowed slices instead of `to_vec()`.
  - Zeroize `hmac` state (enable the crate's `zeroize` features where available, or use AWS-LC).
  - Document mlock as best-effort.

### A1-11 [Major] Approved service indicator (IG 2.4.C) is inadequate and inaccurate
- **Area:** 1, 2. **Confidence:** [H]
- **Location:**
  - `mechanisms.rs:164-206`: static per-mechanism classification.
  - The only indicator is `fips_approved: mechanisms::is_fips_approved(mechanism)` written to the audit log (for example `functions.rs:1684, 2117, 4717`).
  - `session.rs:371,399`: `last_operation_fips_approved` is never set anywhere.
  - `constants.rs:223`: `CKA_VENDOR_FIPS_APPROVED` is defined but never used.
  - Docs: `fips-mode-guide.md` §4.2-4.3; `fips-gap-analysis.md:89`; `CHANGELOG.md:115-117`.
- **Description:**
  - The indicator is not available to the calling operator through the API; the audit log is a file, possibly in memory, and not a per-service status output.
  - It ignores the backend actually used (RustCrypto vs AWS-LC), the prehashed RustCrypto fallback, key sizes and curves (A1-25), whether a KDF was applied (A1-14) and the IV provenance (A1-15).
  - It marks as approved mechanisms that are non-functional or mis-implemented: `CKM_RSA_PKCS` always fails (`sign.rs:229-233`); `CKM_AES_KEY_WRAP_KWP` is actually KW (A1-16).
  - Services such as `C_GenerateRandom`, PIN services and `C_DeriveKey` via ML-KEM have no indicator.
- **Certification impact:** IG 2.4.C requires an unambiguous per-service indicator, or a documented approved-only mode where every available service is approved. Neither holds. Major.
- **Recommendation:** Either (a) a strict approved-only build where non-approved services are unreachable, plus a global approved-mode status query, or (b) a per-operation indicator via a vendor function or attribute that reflects backend and parameters. Remove the unused claims.

### A1-12 [Major] Roles/services mapping in the SP does not match code; several services lack authorization checks
- **Area:** 3. **Sec:** Medium. **Confidence:** [H]
- **Location:**
  - `session.rs:38-43`: `is_logged_in()` includes `RwSO`, so SO sessions pass every "logged in" check for signing, decryption and private-object access (`functions.rs:1458,1755,1964,2380`).
  - No login check in `C_GenerateKey` (`functions.rs:2508-2540`), `C_GenerateKeyPair` (`:2688-2724`), `C_DeriveKey` (`:5263-5311`, including use of a private base key and ML-KEM decapsulation) or `C_DestroyObject` (`:1066-1096`, no `private` check).
  - `C_WrapKey` checks only the *wrapping* key's `private` flag (`:5024`) and not the target key's (`:5043-5063`).
  - Docs: `fips-140-3-certification.md` §3.2 (lines 362-467: key generation "User only", CO "No" for crypto); `security-policy.md` §3.2 (lines 88-101).
- **Description:** An unauthenticated RW session can generate keys, destroy private objects, run key agreement or decapsulation with private keys, and wrap private extractable keys under a key it generated itself as non-private and non-sensitive. It can then read that key's `CKA_VALUE` (`functions.rs:2590-2616` honours template `CKA_PRIVATE`/`CKA_SENSITIVE`/`CKA_EXTRACTABLE`) and unwrap the victim key offline. Handles are Feistel-scrambled (`handle.rs:30-80`), which raises the bar but is not an access control; on Windows `CK_ULONG` is 32-bit. The SO can use User keys.
- **Certification impact:** At Level 1, authentication is not mandatory. But the SP services table (SP 800-140B, ISO 24759 TE04.x) must match what each role can actually do, and CO/User separation must be as documented. Major.
- **Recommendation:**
  - Split `is_logged_in()` into `is_user()` and `is_so()`, and require `is_user()` for key usage.
  - Add `private`/login checks to `C_DestroyObject`, `C_DeriveKey`, `C_WrapKey` (target key), `C_GenerateKey*` (or document them as unauthenticated services) and `C_CopyObject`.
  - Regenerate the services table from the code.

### A1-13 [Major] ECDSA hash/mechanism binding is wrong in single-part operations; signature format is not PKCS#11
- **Area:** CAVP, 1. **Sec:** Low (wrong-algorithm signatures, interoperability). **Confidence:** [H]
- **Location:**
  - `functions.rs:2153-2175` (`sign_single_shot`) calls `backend.ecdsa_p256_sign(key, data)` for all four of `CKM_ECDSA`, `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384` and `CKM_ECDSA_SHA512`.
  - RustCrypto `sign.rs:465-476, 503-514`: `SigningKey::sign_with_rng` hashes with the curve's default hash (SHA-256 for P-256, SHA-384 for P-384).
  - AWS-LC `awslc_backend.rs:120-163`: `ECDSA_P256_SHA256_ASN1_SIGNING` / `ECDSA_P384_SHA384_ASN1_SIGNING`.
  - Multi-part path `sign_prehashed` (`functions.rs:2201-2222`) uses the mechanism's hash.
  - Output is DER (`signature.to_der()`, `sign.rs:475,513`).
- **Description:**
  - `CKM_ECDSA_SHA512` on a P-256 key produces an ECDSA-SHA-256 signature when single-part, and a correct SHA-512 signature when multi-part. The same mechanism and data give signatures that don't cross-verify.
  - `CKM_ECDSA`, which is defined over caller-supplied hash input, double-hashes.
  - PKCS#11 §2.3 mandates a raw `r||s` signature, not DER.
- **Certification impact:** ACVP ECDSA SigGen/SigVer run through the module API would fail for SHA-384/512 on P-256 and for component (raw) signing. The algorithm/hash combinations in the SP are not what is implemented. Major.
- **Recommendation:** Dispatch on the mechanism's hash for single-part operations (hash, then call `sign_prehash`). Implement `CKM_ECDSA` as prehash input. Emit and accept raw `r||s`.

### A1-14 [Major] ECDH key derivation does not follow SP 800-56A r3/56C r2; the two backends derive different keys; RustCrypto derivation is party-order dependent
- **Area:** 8 (key establishment), CAVP. **Sec:** Low. **Confidence:** [H]
- **Location:**
  - `src/crypto/derive.rs:56-68, 102-114`: HKDF info = OID ‖ len ‖ **our_pk ‖ peer_pk**, with a fixed salt `b"CratonHSM-ECDH-HKDF-Salt-v1"` (`derive.rs:135`).
  - `awslc_backend.rs:694-740`: raw Z is truncated to the requested length, with no KDF.
  - `functions.rs:5316-5360`: the mechanism parameter is treated as a raw peer point. `CK_ECDH1_DERIVE_PARAMS` (kdf, shared data) is ignored.
  - `CKM_ECDH1_COFACTOR_DERIVE` is treated identically.
- **Description:**
  - With the RustCrypto backend, party A computes HKDF(info = A_pk‖B_pk) and party B computes HKDF(info = B_pk‖A_pk). Two instances of this module therefore never agree on a key, and no standard peer can reproduce the proprietary info or salt.
  - With AWS-LC, the output is the leftmost bytes of Z used directly as an AES key. SP 800-56A r3 §5.8 requires a key-derivation method, so using Z directly as a key is not approved (IG D.F).
  - Switching backends silently changes derived keys.
  - No full public-key validation is documented (SP 800-56A §5.6.2.3), and there is no Z CAST (A1-04).
- **Certification impact:** KAS claims cannot be validated as implemented. Major.
- **Recommendation:** Implement `CK_ECDH1_DERIVE_PARAMS` with an approved KDF: `CKD_SHA*_KDF` (SP 800-56C one-step) or the SP 800-56C two-step HKDF with a canonical, party-independent `FixedInfo`. Do this identically in both backends. Document public-key validation. Add a KAS-ECC-SSC CAST.

### A1-15 [Major] AES-GCM IV generation doesn't clearly satisfy IG C.H; GCM parameters ignored; documented key sizes unsupported
- **Area:** 8, CAVP. **Sec:** Low. **Confidence:** [H] on code, [M] on AWS-LC indicator behaviour.
- **Location:**
  - RustCrypto: `encrypt.rs:34-45, 113-126, 226-...`. The IV is a 4-byte random per-key prefix (per process) plus a 64-bit counter that restarts at 0 in every process.
  - AWS-LC: `awslc_backend.rs:342-364` uses `LessSafeKey` with an externally generated nonce (`Nonce::try_assume_unique_for_key`).
  - `functions.rs:1616, 1861`: `CK_GCM_PARAMS` (IV, AAD, tag bits) ignored.
  - AES-GCM restricted to 32-byte keys (`encrypt.rs:226-229`, `awslc_backend.rs:343-345`), while docs claim 128/192/256 (`fips-140-3-certification.md` A-table line 1076; `fips-mode-guide.md:61`).
- **Description:**
  - The RustCrypto scheme is neither SP 800-38D §8.2.1 (the 32-bit fixed field is random rather than a guaranteed-unique context identifier, so an imported key reused across processes collides with probability about 2^-32 per pair, with counters restarting) nor §8.2.2 (a fully random 96-bit IV).
  - On AWS-LC, sealing through `LessSafeKey` with a caller-supplied nonce is, as far as I understand the AWS-LC service indicator, reported as *not approved*; the approved path is `RandomizedNonceKey` [M].
- **Certification impact:** IG C.H compliance must be demonstrated and stated in the SP. Major.
- **Recommendation:** On AWS-LC use `aead::RandomizedNonceKey` (internal 96-bit IV from the approved DRBG). Document the IG C.H scenario. Parse `CK_GCM_PARAMS` (AAD, tag length) and return the generated IV via the parameter structure. Support or stop documenting AES-128/192-GCM.

### A1-16 [Minor] Mechanism semantics diverge from PKCS#11 and from the approved-algorithm table
- **Area:** 1, CAVP. **Confidence:** [H]
- **Location and description:**
  - `CKM_AES_CBC` and `CKM_AES_CBC_PAD` both apply PKCS#7 padding (`encrypt.rs:516-535`; `awslc_backend.rs:405-432` `cbc_pkcs7`).
  - `CKM_AES_KEY_WRAP_KWP` is routed to RFC 3394 KW (`functions.rs:5066-5070` does not branch on mechanism; `wrap.rs:11-52` requires multiples of 8), so KWP (SP 800-38F §6.3) is not implemented.
  - `CKM_RSA_PKCS` sign/verify always fails (`sign.rs:229-233, 283-287`; `awslc_backend.rs:47,69`) but is listed as supported and approved.
  - `CKM_RSA_PKCS_PSS` always fails because `CK_RSA_PKCS_PSS_PARAMS` is never parsed (`sign.rs:617-625`).
  - RustCrypto approved mode rejects AES-128 key generation and wrapping (`keygen.rs:33-35`, `wrap.rs:20-23,67-70`, "minimum 192-bit required") and RSA-2048 key generation (`keygen.rs:60-62`, "below 3072"). Both are approved under SP 800-131A r2, and the AWS-LC backend ignores `fips_mode` (`awslc_backend.rs:563, 578`). Behaviour therefore differs between backends and from the docs, which claim AES-128 and RSA-2048.
- **Certification impact:** Algorithm and mechanism tables in the SP would be wrong, and ACVP/functional testing through the API would fail.
- **Recommendation:** Implement the mechanisms as specified or remove them from the list. Align the approved-mode key-size policy across backends and state the rationale correctly.

### A1-17 [Major] Persistent storage and storage-key claims are not implemented; backup design conflicts with SSP policy
- **Area:** 8 (storage), documentation. **Confidence:** [H]
- **Location:**
  - `ObjectStore::with_persistence` (`attributes.rs:61`), `set_persist_key` (`:96`) and `clear_persist_key` (`:103`) have no callers.
  - `HsmCore::try_new` always uses `ObjectStore::new()` (`core.rs:135`).
  - `TokenConfig.persist_objects` (`config.rs:62`) is never read.
  - Docs: `fips-140-3-certification.md` §8.1 CSP #14 ("Storage encryption key … PBKDF2 from SO PIN … cleared on logout/reinit") and §8.5; `security-policy.md` §6.2 ("derived from the SO PIN"), while the code comment in `attributes.rs:39` says "derived from user PIN"; `fips-gap-analysis.md:109`; `tested-platforms.md` ("Persistent storage (redb) ✅").
  - Admin backup: `tools/craton-hsm-admin/src/commands/backup.rs:106-116` builds a fresh `HsmCore` and exports `export_all_objects()`. That is always empty, and by design it would export every object regardless of `CKA_EXTRACTABLE`/`CKA_SENSITIVE`, under a PBKDF2 passphrase key (`store/backup.rs:67-110`), with no authentication.
  - `LockoutStore::new(&c.token.storage_path)` is shared by all slots (`token.rs:155`, `slot.rs:34-37`).
- **Description:** The documented CSP #14 and its lifecycle do not exist. All token objects are volatile. The backup path, if it were connected, would be an SSP output that bypasses the object export policy and uses password-based key protection (SP 800-132 allows PBKDF-derived keys for storage only; any SSP output must follow IG D.N).
- **Certification impact:** SSP storage and lifecycle documentation is incorrect. Major.
- **Recommendation:** Either wire persistence and document the real key hierarchy, or remove the claims. Restrict backup to extractable objects wrapped with approved key wrapping, behind CO authentication. Use a per-slot lockout file.

### A1-18 [Major] SSP/CSP table is incomplete and partly wrong
- **Area:** 8. **Confidence:** [H]
- **Location:** `fips-140-3-certification.md` §8.1 (lines 597-627); `security-policy.md` §11 (lines 406-430).
- **Description:**
  - **Missing SSPs:**
    - `HsmCore.state_hmac_key` (`core.rs:32-36,120-126`), which authenticates operation-state blobs
    - the per-call DRBG instances, their entropy inputs and seeds
    - the RSA parsed-key cache (A1-10)
    - HKDF inputs and outputs (Z and OKM)
    - ML-KEM shared secrets and seeds
    - GCM nonce prefixes and counters (security-relevant for IV uniqueness)
    - the integrity-verification public key (a PSP)
    - the backup passphrase and derived key
    - the plaintext PIN during entry
    - AWS-LC internal SSPs (its DRBG state)
  - **Wrong entries:**
    - "Integrity HMAC key" (the key is actually an Ed25519 public key)
    - "Storage encryption key" (not implemented; A1-17)
    - "HMAC key" (no HMAC mechanism exists; see A1-21 and the discrepancy table)
    - "AES-GCM nonces … `OsRng`"
    - "PIN hash … 64 bytes"; the "salt via `OsRng`" claim is also wrong, since salts come from the DRBG (`encrypted_store.rs:442-448`)
  - Several SSPs lack generation method, establishment, entry/output, storage and zeroization columns in the form SP 800-140B requires.
- **Certification impact:** Major. The SSP table is a core SP 800-140B artifact.
- **Recommendation:** Rebuild the table from a code inventory, with columns for SSP, type, strength, generation (SP 800-133 reference), establishment, entry/output, storage, zeroization and use/role.

### A1-19 [Major] Operational environment not specified for validation
- **Area:** 5. **Confidence:** [H]
- **Location:** `security-policy.md` §8.1 ("Any OS supporting Rust compilation"); `fips-140-3-certification.md` §5.2 (Linux, musl and macOS rows say "Expected compatible"); `tested-platforms.md` (tests "✅ Expected"); `fips-mode-guide.md:27-31` (`AWS_LC_SYS_NO_ASM=1` on Windows); `rust-toolchain.toml` (`channel = "stable"`).
- **Description:**
  - A modifiable-OE validation needs a finite list of tested OEs (OS version plus processor, with and without PAA) on which ACVP and self-tests were actually run.
  - The only platform actually exercised is a Windows development box.
  - Building AWS-LC with `NO_ASM` may not match the validated AWS-LC configuration.
  - The single-operator and process-isolation assumptions are stated (§5.1, `security-model.md:5`), which is adequate.
- **Certification impact:** Major.
- **Recommendation:** Pick two or three target OEs, pin the toolchain version, run ACVP and the module's tests on each, and document PAA use and the vendor-affirmed porting rules (IG 2.3.B/2.3.C).

### A1-20 [Major] Life-cycle assurance: no FIPS build/delivery pipeline, CI gaps, guidance inconsistent with code
- **Area:** 10. **Confidence:** [H]
- **Location:**
  - `.github/workflows/release.yml:41-42`: `cargo build --release` with default features. There is no `fips`/`awslc-backend` build, no integrity signing, and the artifacts include the daemon and admin tools. Cosign signing of the tarballs (`release.yml:92-99`) is a good delivery control.
  - `ci.yml`: no job enables `awslc-backend` or `fips`, and the FIPS tests are excluded from coverage (`ci.yml:297`).
  - `tests/zeroization.rs`: ignored by default (`fips-140-3-certification.md:726`).
  - `rust-toolchain.toml`: not pinned.
  - Versions: `fips-140-3-certification.md` says 0.9.0 and 0.9.1; `C_GetInfo` says 0.1.
  - Admin/User guidance (`fips-mode-guide.md`, `operator-runbook.md`) prescribes the obsolete `.hmac` procedure, a build that omits `fips`, and "Rebuild from source" as the recovery for a POST failure.
- **Certification impact:** ISO 19790 §7.11 (configuration management, delivery, guidance, vendor testing) evidence is insufficient. Major.
- **Recommendation:** Add a FIPS release job that pins the toolchain, uses `--no-default-features --features fips,awslc-backend`, embeds the public key, produces `.sig`, runs POST on each tested OE, and publishes an SBOM. Run the FIPS tests and zeroization tests in CI. Rewrite the Admin and User guidance.

### A1-21 [Minor] Approved-algorithm status statements are out of date; transition dates not addressed
- **Area:** 1, SP. **Confidence:** [H] for FIPS 186-5/203/204/205, [M] for draft transition dates.
- **Location:** `mechanisms.rs:160-163` ("EdDSA … not in FIPS 186-5"; PQC "not yet FIPS-standardized"); `fips-gap-analysis.md:37,95`; `fips-mode-guide.md:47,67-68`; `security-policy.md` §5.2 (lines 193-199). `Cargo.toml:47-49` pulls PQC crates as release candidates (`ml-kem 0.3.0-rc.0`, `ml-dsa 0.1.0-rc.7`, `slh-dsa 0.2.0-rc.4`).
- **Description:**
  - Ed25519 (pure EdDSA) is approved in FIPS 186-5 (February 2023).
  - ML-KEM, ML-DSA and SLH-DSA were approved in FIPS 203/204/205 (August 2024), and CAVP testing exists.
  - Blocking them in approved mode is a legitimate vendor choice, but the SP must not call them "not approved". It should say "not offered in approved mode", or "non-approved implementation (not CAVP-tested)".
  - The PQC implementations are pre-release crates and cannot be validated as-is.
  - The docs don't address SP 800-131A r3 (draft) and NIST IR 8547 (ipd) timelines: 112-bit security (RSA-2048) deprecated after 2030, and quantum-vulnerable RSA/ECC disallowed after 2035 [M].
  - Treating SHA-1 digest as non-approved is conservative and acceptable; the SP should state it as a vendor policy.
- **Recommendation:** Correct the wording and add a transitions section. To claim PQC, take PQC from AWS-LC (ML-KEM/ML-DSA are in recent AWS-LC FIPS branches [M]) and CAVP-test it.

### A1-22 [Minor] `C_GetOperationState`/`C_SetOperationState` are implemented but documented as unsupported; they are an undocumented service
- **Area:** 2, 3. **Confidence:** [H]
- **Location:** `functions.rs:3311-3505`; `session.rs:105-200` (serializer); docs `fips-140-3-certification.md:336` (listed as "Not Implemented").
- **Description:** These functions export and import intermediate operation state, including accumulated multi-part input, IV/mechanism parameters and key handles. The state is HMAC-authenticated with `state_hmac_key` but not encrypted. This is a service (with data output) missing from the services table and the SSP analysis.
- **Recommendation:** Document the service and its SSP handling, or disable it in approved mode.

### A1-23 [Minor] PIN policy, default-PIN and lockout documentation don't match code; `C_InitToken` offers unlimited SO PIN guessing
- **Area:** 3 (authentication). **Sec:** Low. **Confidence:** [H]
- **Location:**
  - `security-policy.md:107-110` ("Default SO PIN `12345678`"); no such default exists in code (`grep` finds none).
  - `fips-140-3-certification.md` §3.3-3.4 (minimum PIN 4, 10 attempts, "62^4") vs code: config default minimum 8 (`config.rs:196-198`), token default 8 (`token.rs:16`), token default max failures 5 (`token.rs:18`) vs config 10 (`config.rs:202-204`), at least 3 distinct bytes and 2 character classes (`token.rs:208-251`), exponential backoff capped at 5 s (`token.rs:25-27`).
  - `C_InitToken` SO-PIN verification increments `failed_init_token_logins` but never locks (`token.rs:409-429`).
- **Description:** Level 1 does not require authentication strength. But if authentication is claimed, the SP's false-acceptance and per-minute rates (ISO 19790 §7.4.3) must be computed from the real policy, and the `C_InitToken` path allows about 17k SO-PIN guesses per day. Combined with A1-07, each guess also wipes all keys.
- **Recommendation:** Correct the docs, enforce lockout on the `C_InitToken` path, and compute the authentication strength from the actual policy.

### A1-24 [Major] Approved-mode activation is advisory and has no status output
- **Area:** 1 (modes of operation). **Confidence:** [H]
- **Location:**
  - `config.rs:231-279`: approved mode comes from a config file or the `CRATON_HSM_FIPS=1` env var. The code itself warns that the env var is "ADVISORY ONLY" (`config.rs:244-263`).
  - The `fips` compile-time feature (`config.rs:234-240`) is absent from the documented build (`fips-mode-guide.md:16`, `fips-140-3-certification.md` §10.6).
  - There is no API to query the mode: `C_GetInfo` flags are 0 (`functions.rs:319-325`) and `C_GetTokenInfo` carries no mode indication.
  - Validation does not tie approved mode to the AWS-LC backend (A1-03).
- **Description:** An operator cannot verify through the module interface that it is in approved mode, and the configuration that enables approved mode doesn't guarantee approved implementations.
- **Certification impact:** IG 2.4.A/2.4.C require a documented, verifiable way to enter approved mode and an indication of the mode. Major.
- **Recommendation:** Make approved mode a build property: a FIPS-only binary with a non-overridable configuration. Expose the mode and module version via `C_GetInfo.libraryDescription`/`flags` or a vendor function.

### A1-25 [Minor] EC domain parameters not validated; unknown curves are processed as P-256
- **Area:** 1, CAVP. **Confidence:** [H]
- **Location:** `functions.rs:2146-2151` (`is_p384_params` only checks for the P-384 OID), `2165-2170`, `2250-2256`, `5347-5360`.
- **Description:** Any EC key whose `CKA_EC_PARAMS` is not P-384 (for example secp256k1, P-521, brainpool, or garbage) is handled as P-256 in sign, verify and derive, and still reported as approved. `C_CreateObject`/`C_UnwrapKey` don't validate curve and key consistency.
- **Recommendation:** Parse `CKA_EC_PARAMS` strictly, accept only P-256 and P-384 (plus P-521 if implemented), and reject anything else with `CKR_CURVE_NOT_SUPPORTED`/`CKR_DOMAIN_PARAMS_INVALID`.

### A1-26 [Major] "Mitigation of other attacks" claims are inaccurate: known RSA timing advisory suppressed
- **Area:** 11. **Sec:** Medium (RustCrypto backend). **Confidence:** [H] for the advisory and its suppression, [M] for exploitability.
- **Location:** `deny.toml:5-7` (`ignore = ["RUSTSEC-2023-0071"]`, "we mitigate by not exposing raw RSA decryption"); `Cargo.lock:2158-2159` (`rsa 0.9.10`); `sign.rs:422` (`rsa_oaep_decrypt`, reachable via `C_Decrypt`/`CKM_RSA_PKCS_OAEP`) and all RSA signing; claims in `fips-140-3-certification.md` §11 ("RSA blinding … Library default") and `security-model.md:59`.
- **Description:** The Marvin timing side channel in the `rsa` crate affects private-key operations generally, not only raw decryption. OAEP decryption and PKCS#1 v1.5/PSS signing on the default backend use the affected code. The suppression rationale doesn't hold, and the SP lists RSA blinding as a mitigation.
- **Recommendation:** Use AWS-LC for all RSA private-key operations (required anyway; A1-03). Until then, remove the claim and document the limitation.

### A1-27 [Observation] Physical and non-invasive security "N/A" claims
- **Area:** 6, 7. **Confidence:** [H]
- **Location:** `fips-140-3-certification.md` §6-§7; `security-policy.md` §1.2.
- **Description:** Justified for a Level 1 software module. The SP should say so in the SP 800-140B format ("the module does not claim physical/non-invasive mitigations") and state explicitly that the physical perimeter is the GPC hosting the tested OE.

### A1-28 [Observation] Integrity check reads the file on disk (TOCTOU) and depends on `dli_fname`
- **Area:** 4. **Confidence:** [H]
- **Location:** `integrity.rs:172-196, 266-282`.
- **Description:** The binary is re-read by path after load. A replaced file, or a relative `dlopen` path followed by a change of working directory, produces a false pass or a false failure. This is common and acceptable for Level 1 if documented, but path resolution failures must fail closed (A1-05).

### A1-29 [Observation] Level 1 PCT/POST performance and DoS considerations
- **Area:** 9. **Confidence:** [M]
- **Location:** `self_test.rs:343` (RSA-2048 keygen in every `C_Initialize`); `token.rs:576-640` (PBKDF2 at 600k iterations run while holding the auth mutex).
- **Description:** Not a conformance failure. Slow POST and PIN verification under a lock can stall applications. Once fixed-key CASTs replace keygen-based POST (A1-04), POST will be faster.

### A1-30 [Minor] Services use keys without key-type/mechanism consistency checks
- **Area:** 1, 8. **Confidence:** [M]
- **Location:** `functions.rs:1450-1470` (`C_EncryptInit`), `1990-2005` (`C_SignInit`). Only `can_encrypt`/`can_sign` and the lifecycle are checked; `key_type` vs mechanism is not.
- **Description:** A key of the wrong type is rejected only by length or parsing failures deeper in the stack, which yields misleading return codes. Approved-mode enforcement should reject wrong key types and non-approved key sizes at `*Init`, returning `CKR_KEY_TYPE_INCONSISTENT`.

### A1-31 [Minor] Audit log "algorithm indicator" and tamper-evidence are not security functions in the FIPS sense
- **Area:** 1, 11. **Confidence:** [M]
- **Location:** `src/audit/log.rs` (unkeyed SHA-256 chain); `fips-140-3-certification.md` §11.
- **Description:** An unkeyed hash chain can be recomputed by anyone who can modify the file, so it is tamper-evident only against accidental corruption. That's fine as a voluntary feature, but it must not be the IG 2.4.C indicator (A1-11) or be described as protection against a capable attacker.

### A1-32 [Minor] Documentation references stale file/line citations throughout
- **Area:** 10 (guidance). **Confidence:** [H]
- **Location:** For example `fips-140-3-certification.md` §4.1 (`integrity.rs:23,141-156,159-197`), §9.1.2 line numbers, §8.2 (`drbg.rs:22,25,29-31,74-78`), §9.3 (`functions.rs:62,83`), Appendix A (`constants.rs:92-138`).
- **Description:** Line references don't match the current code, and many point to removed constructs. A lab uses the SP's source references for TE mapping.
- **Recommendation:** Generate the references automatically or drop line numbers from the SP.

---

## Documentation vs code discrepancies

| # | Document claim (location) | Actual code behaviour (location) | Finding |
|---|---|---|---|
| 1 | Integrity test = HMAC-SHA256 with embedded key and `.hmac` sidecar (`fips-140-3-certification.md` §4.1; `fips-mode-guide.md` §3; `fips-gap-analysis.md:49,81`; `security-policy.md` §7.1/§11; `CHANGELOG.md:23`) | Ed25519 signature over SHA-256 with a `.sig` sidecar; a legacy `.hmac` is ignored with only a warning (`integrity.rs:5-15,96-107,196-214`) | A1-05 |
| 2 | FIPS build: `--features awslc-backend` + config gives "all operations through FIPS-validated aws-lc-rs" (`fips-140-3-certification.md` §1.6, §10.6, App. C note; `fips-mode-guide.md` §1) | The `fips` feature is not enabled. Prehashed sign/verify, PBKDF2, HKDF, PQC, integrity and POST all run RustCrypto (`awslc_backend.rs:202-340`). With the `fips` feature, the backend defaults to RustCrypto (`config.rs:282-290`) | A1-03, A1-24 |
| 3 | `C_GenerateRandom` uses HMAC_DRBG and a continuous RNG test (`fips-140-3-certification.md` §2.2, §9.2.2; `security-policy.md` §5.4, §7.3; `fips-gap-analysis.md:69`) | Raw `OsRng`, no test (`functions.rs:3280-3284`) | A1-01 |
| 4 | POST contains a DRBG "NIST CAVP KAT" (`fips-gap-analysis.md:65,73,129`; `security-policy.md` §5.4, §7.1 row 16) | Only "non-zero" and "differs" checks (`self_test.rs:442-462`) | A1-02, A1-04 |
| 5 | AES-GCM "known-answer decrypt" (`fips-gap-analysis.md:57`) | Only "tag is not all zeros" (`self_test.rs:244-266`) | A1-04 |
| 6 | Error state: "cannot recover without process restart" (`fips-140-3-certification.md` §9.3; `fips-mode-guide.md:187`) | `C_Finalize` + `C_Initialize` clears it (`functions.rs:248`) | A1-09 |
| 7 | CKA_VALUE exported only if EXTRACTABLE **and** not SENSITIVE (`fips-140-3-certification.md` §8.4) | Exported if not sensitive, **or** if sensitive and extractable (`attributes.rs:566-579`) | A1-08 |
| 8 | Persistent storage with a PBKDF2 storage key from the SO PIN, cleared on logout (`fips-140-3-certification.md` §8.1 #14, §8.5; `security-policy.md` §6.2; `tested-platforms.md`) | Persistence never enabled. `persist_objects` is unused; `set_persist_key`/`clear_persist_key` have no callers. The code comment says "user PIN" (`attributes.rs:39`) | A1-17 |
| 9 | CO has no crypto services; key generation and derive are User-only; object destruction requires authentication (`fips-140-3-certification.md` §3.2; `security-policy.md` §3.2) | SO passes `is_logged_in()`. `C_GenerateKey*`, `C_DeriveKey` and `C_DestroyObject` have no login check (`session.rs:38-43`; `functions.rs:2508,2688,5263,1066`) | A1-12 |
| 10 | Default SO PIN `"12345678"` (`security-policy.md:107-110`) | No default PIN exists; the token starts uninitialized | A1-23 |
| 11 | Minimum PIN 4, 10 failed attempts (`fips-140-3-certification.md` §3.3, App. E) | Default minimum 8; token default 5 and config default 10; character-class rules; `C_InitToken` never locks | A1-23 |
| 12 | Algorithm indicator: `last_operation_fips_approved` "can be queried"; `CKA_VENDOR_FIPS_APPROVED` (`fips-mode-guide.md` §4.2-4.3; `CHANGELOG.md:116-117`) | Field never written; attribute never used | A1-11 |
| 13 | Services: "MAC: HMAC-SHA256/384/512" (`fips-mode-guide.md:66,149`; `security-policy.md` §5.1); CSP "HMAC key" | No HMAC mechanism in `supported_mechanisms()` (`mechanisms.rs:94-144`); `CKM_*_HMAC` not even defined in `constants.rs` | A1-18 |
| 14 | `CKM_AES_KEY_WRAP_KWP` approved and implemented (App. A; `mechanisms.rs:194`) | Routed to RFC 3394 KW; no padding variant (`functions.rs:5066`; `wrap.rs`) | A1-16 |
| 15 | AES-GCM with 128/192/256-bit keys (App. A; `fips-mode-guide.md:61`) | 256-bit only (`encrypt.rs:226-229`; `awslc_backend.rs:343`) | A1-15 |
| 16 | `CKM_RSA_PKCS` and `CKM_RSA_PKCS_PSS` sign/verify supported and approved (App. A) | Always rejected (`sign.rs:229-233`, `617-625`) | A1-16 |
| 17 | RSA 2048/3072/4096 and AES-128 available in approved mode (`fips-mode-guide.md:61-62`, §5) | RustCrypto approved mode rejects RSA-2048 keygen and AES-128 keygen/wrap (`keygen.rs:33-35,60-62`; `wrap.rs:20-23`); AWS-LC doesn't | A1-16 |
| 18 | `C_GetOperationState`/`C_SetOperationState` "Not Implemented" (`fips-140-3-certification.md:336`) | Implemented (`functions.rs:3311-3505`) | A1-22 |
| 19 | Boundary includes the daemon and Admin CLI (`security-policy.md` §1.1) vs excludes them (`fips-140-3-certification.md` §1.5) | Both tools link the `rlib` and bypass `C_Initialize`, POST and the error state (`admin/commands/*.rs`, `daemon/main.rs:79-86`) | A1-06 |
| 20 | Module version 0.9.0 (§1.1) / 0.9.1 (header) | `C_GetInfo` reports 0.1 (`functions.rs:324`) | A1-06 |
| 21 | Ed25519 and PQC are "not FIPS-approved" (`mechanisms.rs:160-163`; gap analysis; SP §5.2) | FIPS 186-5 (Ed25519) and FIPS 203/204/205 (PQC) approve them; what is missing is validation of these implementations | A1-21 |
| 22 | "All CSPs zeroized", "`ZeroizeOnDrop` on all key material" (`fips-140-3-certification.md` §8.6; `security-model.md:217`) | RSA cache never cleared; `C_Finalize` leaves the core alive in thread-local caches; many plain `Vec` copies | A1-10 |
| 23 | `clear_rsa_key_cache` is "Called on C_Finalize / C_InitToken" (`sign.rs:96-97`) | No callers | A1-10 |
| 24 | ECDH output via HKDF "per SP 800-56C" (`derive.rs`) and "SP 800-56A" derive (App. A) | AWS-LC path uses truncated raw Z; the RustCrypto HKDF info depends on party order | A1-14 |
| 25 | "RSA blinding" mitigation (§11); Marvin mitigated by "not exposing raw RSA decryption" (`deny.toml:6`) | OAEP decryption and RSA signing on the RustCrypto path use the affected code | A1-26 |
| 26 | "Tested with 547 tests / 617+ tests", "CI tested" platforms (App. D; `tested-platforms.md`) | CI builds default features only; platforms other than Windows are marked "Expected" | A1-19, A1-20 |
| 27 | PIN salt "Generated via `OsRng`" (§3.3) | `HmacDrbg`, with the error ignored (`encrypted_store.rs:442-448`) | A1-02 |
| 28 | Integrity "Module path cannot be determined → warning, test passes" (§4.1) is presented as acceptable | Same behaviour in `fips` builds; must fail closed | A1-05 |

---

## Stubs, TODOs and unimplemented items relevant to certification

| # | Item | Location | Relevance |
|---|---|---|---|
| 1 | All-zero integrity public key placeholder; only rejected when `fips` is enabled | `integrity.rs:21-73, 118-125` | A1-05 |
| 2 | `HsmCore.drbg` created but never used for any service | `core.rs:26,131,142,231` | A1-01 |
| 3 | `last_operation_fips_approved` never set | `session.rs:371,399` | A1-11 |
| 4 | `CKA_VENDOR_FIPS_APPROVED` defined, never used ("for future use") | `constants.rs:223`; `fips-mode-guide.md:132` | A1-11 |
| 5 | Persistence API never wired (`with_persistence`, `set_persist_key`, `clear_persist_key`, `persist_objects`) | `attributes.rs:61,96,103`; `config.rs:62` | A1-17 |
| 6 | `clear_rsa_key_cache()` has no callers | `sign.rs:98` | A1-10 |
| 7 | `RawKeyMaterial::new_strict` (mandatory mlock) unused | `key_material.rs:50-62` | A1-10 |
| 8 | `C_SignRecover*`, `C_VerifyRecover*`, dual-function updates, `C_CancelFunction`, `C_WaitForSlotEvent` are stubs; `C_GetFunctionStatus` returns `CKR_FUNCTION_NOT_PARALLEL` | `functions.rs:4736-4980, 5437-5460` | Services table must list them as unavailable |
| 9 | `CKM_AES_KEY_WRAP_KWP` has no KWP implementation | `wrap.rs`; `functions.rs:5066` | A1-16 |
| 10 | `CK_GCM_PARAMS`, `CK_RSA_PKCS_PSS_PARAMS` and `CK_ECDH1_DERIVE_PARAMS` not parsed | `functions.rs:1616,1861,5316`; `sign.rs:617-625` | A1-13..A1-16 |
| 11 | `rand_core` version aliases for PQC ("TODO: Remove aliases once RustCrypto migrates") | `Cargo.toml:51-56` | Two RNG trait ecosystems; PQC randomness path (`pqc.rs:17-78`) |
| 12 | PQC crates are release candidates | `Cargo.toml:47-49` | A1-21; cannot be validated |
| 13 | Enterprise `craton_hsm-awslc` crate referenced but absent ("only available with the enterprise repo") | `Cargo.toml:108-110`; `README.md:30,101` | A1-06: the module under evaluation is undefined |
| 14 | Obsolete HMAC integrity tools still shipped | `tools/compute-integrity-hmac.{sh,ps1}` | A1-05 |
| 15 | No FIPS release or CI job; no `.sig` generation in the pipeline | `.github/workflows/{ci,release}.yml` | A1-20 |
| 16 | Zeroization tests `#[ignore]`d by default | `tests/zeroization.rs` (per `fips-140-3-certification.md:726`) | A1-20 |
| 17 | RUSTSEC-2023-0071 suppressed "until rsa crate ships a fix" | `deny.toml:5-7` | A1-26 |
| 18 | "Entropy source qualification" listed as P2 / Level 2+ | `fips-gap-analysis.md:246` | Wrong: ESV is needed at Level 1 (A1-02) |

---

## Roadmap to certification

The steps are in dependency order. Items 1–6 are prerequisites for engaging a CST lab. Items 7–12 can run alongside SP rewriting.

1. **Freeze the module definition (A1-06, A1-24).**
   - The module is the `cdylib` only, with a single name and version (use the same version everywhere: `Cargo.toml`, `C_GetInfo`, SP).
   - Make the internal crypto APIs `pub(crate)`, or move POST, the error state and the approved-mode gate into `HsmCore` construction.
   - Declare the daemon and Admin CLI as external applications that use the C ABI, or exclude them.
   - Decide between the inline AWS-LC backend and the enterprise crate, and document how the embedded AWS-LC FIPS module (exact version and certificate) relates to the boundary.
2. **Make approved mode a build (A1-03, A1-24).** Build with `--no-default-features --features fips,awslc-backend`. Make `fips` imply AWS-LC, forbid RustCrypto, and hard-fail if the backend isn't AWS-LC. Report the mode through a status output.
3. **Move every approved security function to AWS-LC (A1-03, A1-13, A1-14, A1-15, A1-26):**
   - prehashed RSA/ECDSA
   - PBKDF2 and HMAC
   - HKDF or an SP 800-56C KDF
   - GCM through `RandomizedNonceKey`
   - ECDH through `CK_ECDH1_DERIVE_PARAMS` with an approved KDF
   - the integrity signature
   - correct ECDSA hash dispatch and raw `r||s` output

   Remove, or mark non-approved and unreachable in FIPS mode, anything AWS-LC can't provide.
4. **RBG (A1-01, A1-02).** Use AWS-LC's DRBG for `C_GenerateRandom` and all internal randomness. Reference AWS-LC's ESV-certified entropy source, or obtain an ESV. Latch DRBG failures into the error state; don't `abort()` or ignore them.
5. **Self-tests (A1-04, A1-05, A1-09).**
   - Backend-dispatched CASTs with CAVP vectors for every approved algorithm (AES encrypt and decrypt, GCM, KW, SHA-2/3, HMAC, PBKDF2, KDF, DRBG, RSA SigGen/SigVer and OAEP, ECDSA, KAS-ECC-SSC), run before the integrity test for the algorithms the integrity test uses.
   - A mandatory, fail-closed integrity test.
   - Documented error states with distinct status codes.
6. **Security defects (A1-07, A1-08, A1-10, A1-12).**
   - Verify the SO PIN before any destruction in `C_InitToken` and scope it per slot.
   - Never return CKA_VALUE for sensitive keys.
   - Zeroize on `C_Finalize` (explicit clear plus stale thread-local invalidation), `C_DestroyObject` and in the RSA cache.
   - Remove the unzeroized `Vec` copies.
   - Separate User and SO roles and add the missing authorization checks.
7. **Mechanism correctness (A1-15, A1-16, A1-25, A1-30).** Separate CBC from CBC_PAD. Implement KWP or drop it. Parse the PKCS#11 parameter structures. Validate curves and key types, and apply the same approved-mode key-size policy on both backends.
8. **CAVP/ACVP.** Run ACVP for the AWS-LC build on each target OE through the module's own boundary (or document reuse of AWS-LC certificates if the lab and CMVP policy allow). Include ECDSA with SHA-2 combinations, RSA 2048/3072/4096, AES-GCM/CBC/CTR/KW, HMAC, PBKDF2, KDA and DRBG.
9. **Service indicator (A1-11).** Implement an IG 2.4.C indicator accessible through the API, or a strictly approved-only build with a global mode indicator. Remove the unused fields.
10. **Operational environment (A1-19).** Choose and test two or three OEs. Pin the Rust toolchain and the AWS-LC version, avoid `NO_ASM` unless it is covered by the certificate, and document PAA.
11. **Life cycle (A1-20).** Add a FIPS release pipeline (reproducible build, embedded public key, `.sig`, cosign, SBOM, POST on each OE). Run the FIPS and zeroization tests in CI. Add configuration management of documents with version-matched references.
12. **Documentation (A1-17, A1-18, A1-21, A1-22, A1-23, A1-32 and the discrepancy table).** Rewrite the Security Policy in SP 800-140B format from the code:
    - boundary diagram
    - approved and non-approved algorithm tables with certificate numbers
    - services table per role with indicators
    - complete SSP table
    - self-test table matching IG 10.3.A
    - error states
    - Admin/User guidance for installing, configuring and verifying the integrity signature and approved mode
    - SP 800-131A/IR 8547 transition notes

    Remove the stale gap-analysis "✅" claims.
13. **Pre-validation dry run.** Before submission, commission a lab gap assessment against ISO 24759 TEs, then enter the CMVP queue. Plan for PQC (FIPS 203/204/205) only through a validated provider (for example an AWS-LC FIPS branch that includes ML-KEM/ML-DSA [M]), with the required CASTs and PCTs.
