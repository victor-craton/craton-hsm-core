# FIPS 140-3 Gap Analysis

> **DISCLAIMER: Craton HSM is NOT FIPS 140-3 validated.** This document is
> the tracking list of what stands between the code and a CMVP submission.
> It replaces the earlier "Level 1 ready" narrative, which the 2026-09-24
> readiness audit (report A1, with A2/A3 for conformance and supply chain)
> found to be inaccurate.

## Current status: NOT READY

A CMVP laboratory could not accept the module today. The blocking reasons
are:

1. **No validated algorithm implementations in use.** RustCrypto (default)
   has no CAVP certificates. The AWS-LC backend links the AWS-LC FIPS module,
   but several services (multi-part sign/verify, PBKDF2, HKDF, PQC, the
   integrity test and parts of the self-tests) still use RustCrypto code.
2. **No validated entropy source** (no ESV certificate, no min-entropy claim).
3. **No approved-service indicator** available through the API.
4. **Operational environments** are defined and tested in CI, but no ACVP
   testing has been performed on them.

Status legend used below:

- **Remediated** — fixed in the 2026-09 remediation batch (verify on the
  merged code before relying on it).
- **Partially remediated** — part of the finding is fixed; the rest is open.
- **Open** — not addressed yet.
- **Documented** — the behaviour is unchanged but now described accurately.
- **Organisational** — cannot be fixed in code (process, paperwork, external
  certificates).

## Tracking table (audit A1 findings)

| ID | Topic | Status | Notes |
|---|---|---|---|
| A1-01 | `C_GenerateRandom` bypassed the DRBG | Remediated | `C_GenerateRandom` is served by the process-wide HMAC_DRBG (AWS-LC's DRBG with the AWS-LC backend). |
| A1-02 | Entropy source / DRBG health testing | Partially remediated | Repetition-count and adaptive-proportion tests on entropy input, start-up test, SP 800-90A §11.3 KAT, continuous test on a long-lived instance. **Open / organisational:** ESV certificate and min-entropy justification for the OS entropy source. |
| A1-03 | Approved services on non-validated implementations | Open | `fips` builds refuse a non-validated backend at POST, so they must use AWS-LC; remaining services still implemented in RustCrypto must be moved to AWS-LC or made unavailable in approved mode. The `fips` defaults must select `crypto_backend = "awslc"`. |
| A1-04 | Self-tests not IG 10.3.A/B compliant | Remediated | Fixed-vector CASTs for every algorithm family, run through the selected backend; integrity-test algorithms tested first. |
| A1-05 | Integrity test optional/bypassable, documented as HMAC | Partially remediated | Fails closed in `fips` builds (missing `.sig`, placeholder key, unresolvable path); releases embed the key and ship `.sig`; docs describe the Ed25519 scheme; HMAC tooling removed. **Open:** Ed25519 runs on the unvalidated `ed25519-dalek`; move to an AWS-LC-validated algorithm. |
| A1-06 | Boundary, identity and version inconsistent | Partially remediated | One boundary definition ([fips-140-3-certification.md §1.5](fips-140-3-certification.md#15-module-boundary-canonical-definition)); daemon and admin CLI declared outside. **Open:** the `rlib` API still exposes internals without POST gating; verify that `C_GetInfo.libraryVersion` reports the package version. |
| A1-07 | `C_InitToken` destroyed objects before checking the SO PIN | Remediated | PIN verified first, per slot, SO lockout applies, `CKR_SESSION_EXISTS` with open sessions. |
| A1-08 | Sensitive + extractable keys exported in plaintext | Remediated | `CKA_VALUE` of sensitive or non-extractable keys is never returned. |
| A1-09 | Error-state semantics | Remediated | Latched error state; services refused; recovery only via `C_Finalize` + successful `C_Initialize`. Residual: a DRBG failure inside an infallible third-party callback aborts the process (A3-19). |
| A1-10 | Zeroization gaps | Partially remediated | RSA parsed-key cache cleared on `C_Finalize` / `C_InitToken`; verify zeroization of all volatile SSPs at `C_Finalize`. |
| A1-11 | Approved-service indicator | Open | See [fips-140-3-certification.md §1.7](fips-140-3-certification.md#17-approved-service-indicator-ig-24c). Unused `last_operation_fips_approved` / `CKA_VENDOR_FIPS_APPROVED` should be removed or implemented. |
| A1-12 | Roles/services mismatch; missing authorization checks | Remediated | Key use requires the User role; SO sessions are not "logged in" for key use. Services table regenerated. |
| A1-13 | ECDSA hash binding and signature format | Remediated | Per-mechanism hashing; PKCS#11 raw `r ‖ s` signatures. |
| A1-14 | ECDH KDF | Remediated | Approved KDFs per SP 800-56C; `CKD_NULL` refused in approved mode. |
| A1-15 | AES-GCM IV generation (IG C.H) | Remediated | `CK_GCM_PARAMS` honoured; in approved mode IVs are generated inside the module from the DRBG; per-key invocation limit. |
| A1-16 | Mechanism semantics | Remediated | `CKM_AES_CBC` unpadded vs `CKM_AES_CBC_PAD`; real KWP; `CKM_RSA_PKCS` sign/verify; generic `CKM_RSA_PKCS_PSS` and the composite ML-DSA/ECDSA mechanism are no longer advertised; approved-mode key-size policy (AES-128, RSA-2048) to be identical on both backends — verify. |
| A1-17 | Persistent storage claims not implemented | Remediated | Encrypted persistence with a per-slot DEK wrapped under PIN-derived KEKs, authenticated manifest. **Open:** whole-file rollback detection needs an external monotonic counter. |
| A1-18 | SSP table incomplete | Documented | [fips-140-3-certification.md §8.1](fips-140-3-certification.md#81-ssp-inventory). |
| A1-19 | Operational environment not specified | Partially remediated | Tested OEs pinned in CI (Ubuntu 24.04 x86_64, Windows Server 2025 x86_64, macOS 15 arm64). **Open:** ACVP on each claimed OE; PAA documentation per OE. |
| A1-20 | Life-cycle: no FIPS build/delivery pipeline | Remediated | Gated release workflow with a `fips` flavour, embedded key, `.sig`, SBOM, provenance. CI builds **and tests** `awslc-backend`, `fips` and `--no-default-features --features fips` (test executables signed with an ephemeral key so the fail-closed integrity test runs). |
| A1-21 | Out-of-date approval statements | Documented | Ed25519 is approved (FIPS 186-5); ML-KEM/ML-DSA/SLH-DSA are approved algorithms (FIPS 203/204/205) whose implementations here are not validated and are not offered in approved mode. |
| A1-22 | Operation-state functions undocumented | Documented | [fips-140-3-certification.md §2.4](fips-140-3-certification.md#24-operation-state-service). |
| A1-23 | PIN policy / default PIN docs wrong; unlimited SO guessing via `C_InitToken` | Remediated | Docs describe the real policy (no default PIN); `C_InitToken` verification subject to SO lockout. |
| A1-24 | Approved-mode activation advisory, no status output | Partially remediated | The `fips` build is the approved-only mode and cannot be overridden at run time. **Open:** mode/status output through `C_GetInfo`. |
| A1-25 | EC domain parameters not validated | Partially remediated | Key generation accepts only P-256/P-384 (named-curve OIDs) and rejects others with `CKR_CURVE_NOT_SUPPORTED`. **Open (wave-2 ABI):** an absent `CKA_EC_PARAMS` still defaults to P-256 instead of `CKR_TEMPLATE_INCOMPLETE`; `C_CreateObject` / `C_UnwrapKey` must validate `CKA_EC_PARAMS` too. |
| A1-26 | "RSA blinding" claim vs RUSTSEC-2023-0071 | Documented | Blinding is now applied to every RustCrypto RSA private-key operation and there is no PKCS#1 v1.5 decryption service, but the bignum code is not constant time: the Marvin side channel on the RustCrypto backend is **not** claimed as mitigated (see `deny.toml`, time-boxed exception). `fips` builds use AWS-LC. |
| A1-27 | Physical / non-invasive N/A wording | Documented | SP 800-140B wording used. |
| A1-28 | Integrity check reads the file on disk | Documented | Accepted at Level 1; operator guidance added. |
| A1-29 | POST/PBKDF2 performance | Open (observation) | Fixed-key CASTs removed key generation from POST. |
| A1-30 | Key-type / mechanism consistency | Open (wave-2 ABI) | `*Init` should return `CKR_KEY_TYPE_INCONSISTENT` for wrong key types. |
| A1-31 | Audit log is not a security function | Documented | Keyed HMAC chain + anchor since the H3-10 fix; still not a security function and not the IG 2.4.C indicator. |
| A1-32 | Stale line citations | Documented | FIPS documents cite files/functions only. |

## Pre-release post-quantum dependencies (A3-07)

The PQC mechanisms use **release-candidate** crates: `ml-kem 0.3.0-rc.0`,
`ml-dsa 0.1.0-rc.7`, `slh-dsa 0.2.0-rc.4`. They pull further pre-release
crates into the build (`sha2 0.11.0-rc`, `sha3 0.11.0-rc`,
`hmac 0.13.0-rc`, `signature 3.0.0-rc`, `pkcs8 0.11.0-rc`, `spki 0.8.0-rc`,
`kem 0.3.0-rc`).

Risks:

- no API or security stability guarantee; breaking changes between release
  candidates;
- no CAVP validation of any version;
- the PQC code hashes with a **second** SHA-2/SHA-3/HMAC implementation
  (the pre-release generation) that the SHA-2/SHA-3/HMAC self-tests do not
  exercise — only the PQC KATs cover it indirectly.

Controls:

- PQC is refused in approved mode and in `fips` builds (`enable_pqc = false`).
- `deny.toml` lists every duplicate crate version explicitly (`[bans] skip`),
  so new duplicates fail CI.
- Dependabot still proposes release-candidate and security updates for the
  PQC crates; only semver-major bumps (which need an API migration) are
  ignored.
- To offer PQC as an approved service, take it from a validated provider
  (e.g. an AWS-LC FIPS release that includes ML-KEM/ML-DSA) with the required
  CASTs and PCTs.

## Operational environment

See [fips-140-3-certification.md §5](fips-140-3-certification.md#5-operational-environment)
and [tested-platforms.md](tested-platforms.md). For a submission the vendor
must choose the OEs to claim, run ACVP on each, and document PAA use and the
vendor-affirmed porting rules (IG 2.3.B/2.3.C).

## Documentation status

| Document | Status |
|---|---|
| Draft Security Policy | [fips-140-3-certification.md](fips-140-3-certification.md) — rewritten against the code; still a draft, not in final SP 800-140B template form |
| Operator summary | [security-policy.md](security-policy.md) |
| Approved-only build guide | [fips-mode-guide.md](fips-mode-guide.md) |
| Delivery / verification | [release-signing.md](release-signing.md) |
| Finite state model | [fips-140-3-certification.md §10.3](fips-140-3-certification.md#103-finite-state-model) |

## Organisational items (not fixable in code)

- Engage a CST laboratory for a gap assessment against ISO/IEC 24759.
- ESV submission (or reliance on a validated entropy source).
- ACVP testing on the claimed OEs; reference the AWS-LC module certificate if
  its validated implementation is used.
- Publish full version history, or at least signed annotated tags per
  release; require signed commits (GOVERNANCE.md).
- Configure the repository settings required by the release workflow
  (protected environments, trusted publishing, tag protection — see
  [release-signing.md](release-signing.md#repository-configuration-required-for-releases-maintainers)).
