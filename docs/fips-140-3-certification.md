# Craton HSM FIPS 140-3 Security Policy (Draft) and Certification Document

> **DISCLAIMER: Craton HSM is NOT FIPS 140-3 validated and is not ready to be
> submitted to a CMVP laboratory.** This document is a draft Security Policy
> written against the code as it is (not as it is hoped to be). Where a
> requirement is not met, the text says so and points to the tracking item in
> [fips-gap-analysis.md](fips-gap-analysis.md). It has not been reviewed by an
> accredited laboratory.
>
> Source references are given as file paths (and function names), never as
> line numbers, so that they do not go stale (A1-32).

---

## Document Information

| Field | Value |
|-------|-------|
| Module Name | Craton HSM |
| Module Version | 0.9.1 (Cargo package `craton-hsm`) |
| Module Type | Software (multi-chip standalone, modifiable operational environment) |
| FIPS 140-3 Overall Security Level | 1 (target; not validated) |
| PKCS#11 interface | v2.40 function set + v3.0 interface discovery (see §2.2) |
| Document Version | 2.0 (draft) |
| Date | 2026-09-25 |
| Purpose | Draft SP 800-140B Security Policy and certification-readiness reference |
| Author | Craton HSM Project |

### Revision History

| Version | Date | Description |
|---------|------|-------------|
| 2.0 | 2026-09-25 | Rewritten against the code after the 2026-09-24 readiness audit (A1/A2/A3): single module-boundary definition, Ed25519 integrity scheme (replaces the removed HMAC description), complete SSP table, tested operational environments, approved-mode and service-indicator status, corrected services, mechanisms, self-tests and error states, no line-number citations. |
| 1.1 | 2026-03-17 | Security audit hardening |
| 1.0 | 2026-03-08 | Initial certification document |

### Readiness status (summary)

The following items prevent submission today. Each is tracked in
[fips-gap-analysis.md](fips-gap-analysis.md).

| Area | Status | Item |
|---|---|---|
| Algorithm validation | **Not met** | No algorithm implementation used by the module has a CAVP certificate in this configuration. The only validatable implementation is the AWS-LC FIPS module (`aws-lc-fips-sys`, `awslc-backend` feature), and several services still run RustCrypto code (A1-03). |
| Entropy source | **Not met** | The OS RNG feeding the DRBG has no ESV certificate and no documented min-entropy claim (A1-02). |
| Approved-service indicator | **Not met** | No indicator is available through the PKCS#11 API (§1.7, A1-11/A1-24). |
| Operational environment | **Partial** | CI tests fixed runner images (§5.2); no ACVP run on them yet (A1-19). |
| Life-cycle / configuration management | **Partial** | Pinned toolchain, gated signed releases; public history starts at a single squashed commit (A3-17). |

---

## Acronyms and Abbreviations

| Acronym | Definition |
|---------|-----------|
| AES | Advanced Encryption Standard (FIPS 197) |
| CAST | Cryptographic Algorithm Self-Test |
| CAVP / ACVP | Cryptographic Algorithm Validation Program / Automated Cryptographic Validation Protocol |
| CMVP | Cryptographic Module Validation Program |
| CO | Crypto Officer (PKCS#11 Security Officer, `CKU_SO`) |
| CSP / PSP / SSP | Critical / Public / Sensitive Security Parameter |
| DEK / KEK | Data-Encryption Key / Key-Encryption Key |
| DRBG | Deterministic Random Bit Generator (SP 800-90A) |
| ESV | Entropy Source Validation (SP 800-90B) |
| KAT | Known-Answer Test |
| OE | Operational Environment |
| PAA | Processor Algorithm Accelerator |
| PCT | Pair-wise Consistency Test |
| POST | Pre-operational (power-on) self-tests |
| SO | Security Officer (= CO) |

---

## Normative References

| Reference | Title |
|-----------|-------|
| FIPS 140-3 / ISO/IEC 19790:2012 | Security Requirements for Cryptographic Modules |
| ISO/IEC 24759 | Test requirements for cryptographic modules |
| SP 800-140B | CMVP Security Policy Requirements |
| FIPS 140-3 IG | Implementation Guidance (IG 2.4.A/C, 9.x, 10.3.A/B, C.H, D.N) |
| FIPS 180-4, FIPS 202 | SHA-2, SHA-3 |
| FIPS 186-5 | Digital Signature Standard (RSA, ECDSA, EdDSA) |
| FIPS 197, SP 800-38A/D/F | AES and modes (CBC, CTR, GCM, KW/KWP) |
| FIPS 198-1 | HMAC |
| FIPS 203 / 204 / 205 | ML-KEM / ML-DSA / SLH-DSA |
| SP 800-56A Rev. 3, SP 800-56C Rev. 2 | Key agreement and key derivation |
| SP 800-57 Part 1 | Key management |
| SP 800-90A Rev. 1, SP 800-90B | DRBG, entropy sources |
| SP 800-131A Rev. 2 | Algorithm transitions |
| SP 800-132, SP 800-133 | PBKDF, key generation |
| PKCS#11 v2.40 / v3.0 | OASIS Cryptographic Token Interface |

---

## 1. Cryptographic Module Specification

### 1.1 Module Identification

| Property | Value |
|----------|-------|
| Module name | Craton HSM |
| Version | 0.9.1 (= `version` of the `craton-hsm` package in `Cargo.toml`) |
| Version reported by the module | `C_GetInfo.libraryVersion` = major.minor of the package version (0.9). The 2026-09-24 audit found a hard-coded `0.1` (A3-16/A1-06); this value must be checked against the binary under test before any submission. |
| Type | Software module |
| Language | Rust (edition 2021), toolchain pinned in `rust-toolchain.toml` |
| Artefact | Shared library `libcraton_hsm.so` (Linux), `craton_hsm.dll` (Windows), `libcraton_hsm.dylib` (macOS), with integrity sidecar `libcraton_hsm.sig` / `craton_hsm.sig` |
| Package / library names | Cargo package `craton-hsm`; Rust library crate `craton_hsm` |

### 1.2 Security Level Claim

| FIPS 140-3 Area | Target Level |
|----------------|----------------|
| 1. Cryptographic module specification | 1 |
| 2. Cryptographic module interfaces | 1 |
| 3. Roles, services, and authentication | 1 (role-based, PIN authentication) |
| 4. Software/firmware security | 1 |
| 5. Operational environment | 1 (modifiable) |
| 6. Physical security | N/A — the module claims no physical security mechanisms |
| 7. Non-invasive security | N/A — the module claims no non-invasive mitigations |
| 8. Sensitive security parameter management | 1 |
| 9. Self-tests | 1 |
| 10. Life-cycle assurance | 1 |
| 11. Mitigation of other attacks | None claimed (§11 lists voluntary measures) |
| **Overall** | **1** |

### 1.3 Module Description

Craton HSM is a software cryptographic module implemented in Rust that
provides key generation, key storage, digital signature, encryption, hashing,
key agreement/derivation and key wrapping services through the PKCS#11 C API.
It is compiled as a dynamically loadable shared library that applications load
at run time (`dlopen` / `LoadLibrary`).

### 1.4 Module Architecture

```
┌──────────────────────────── CRYPTOGRAPHIC BOUNDARY ────────────────────────────┐
│  (the shared library file libcraton_hsm.{so,dylib} / craton_hsm.dll + .sig)     │
│                                                                                 │
│  PKCS#11 C ABI (src/pkcs11_abi/) — the ONLY module interface                    │
│     │ argument validation, catch_unwind, POST/error-state gate, CK_RV mapping   │
│     ▼                                                                           │
│  HsmCore (src/core.rs)                                                          │
│   ├── SlotManager / Token (src/token/)      roles, PIN verification, lockout    │
│   ├── SessionManager (src/session/)         PKCS#11 session state machine       │
│   ├── ObjectStore (src/store/)              objects; encrypted persistence       │
│   ├── AuditLog (src/audit/)                 hash-chained event log               │
│   ├── CryptoBackend (src/crypto/backend.rs) RustCrypto | AWS-LC (awslc-backend) │
│   ├── HMAC_DRBG + entropy health tests (src/crypto/drbg.rs)                     │
│   └── Self-tests (src/crypto/self_test.rs, pairwise_test.rs, integrity.rs)      │
└─────────────────────────────────────────────────────────────────────────────────┘
          ▲ C calls only
   Calling application (outside the boundary)
```

### 1.5 Module Boundary (canonical definition)

This section is the single, normative definition of the cryptographic
boundary. [security-policy.md](security-policy.md) and every other document
refer to it and must not redefine it (A1-06).

**The cryptographic module is the shared-library file built from the
`craton-hsm` package (`crate-type = "cdylib"`), together with its Ed25519
integrity sidecar (`.sig`). Its only interface is the set of exported PKCS#11
C functions listed in §2.2.** The physical perimeter is that of the
general-purpose computer running the tested operational environment (§5); the
logical boundary is the library's code and data inside the calling process.

Inside the boundary (all compiled into the one library file):

| Component | Source |
|-----------|--------|
| PKCS#11 C ABI | `src/pkcs11_abi/` |
| Cryptographic algorithms, DRBG, self-tests, integrity test | `src/crypto/` |
| Object store, key-material protection, encrypted persistence | `src/store/` |
| Session and token/PIN management | `src/session/`, `src/token/` |
| Audit log | `src/audit/` |
| Configuration parsing | `src/config/` |
| Statically linked third-party crates | `Cargo.lock` (RustCrypto crates; with `awslc-backend`, the AWS-LC FIPS module via `aws-lc-rs`/`aws-lc-fips-sys`) |

Outside the boundary (**not** part of the module):

| Component | Path | Relationship |
|-----------|------|--------------|
| Calling application | — | Uses the module through the PKCS#11 C API |
| gRPC daemon | `craton-hsm-daemon/` | Separate executable. It links the Rust library (`rlib`) and calls `HsmCore` directly instead of the C API, so it does **not** operate the module: its requests are not covered by this Security Policy. It must not be deployed where a validated module is required. |
| Admin CLI | `tools/craton-hsm-admin/` | Same situation as the daemon (links the `rlib`). |
| pkcs11-spy | `tools/pkcs11-spy/` | Debug interposer library; must not be used in production. |
| Deployment artefacts, docs, tests, fuzz targets | `deploy/`, `docs/`, `tests/`, `fuzz/` | Not delivered as part of the module |
| The Rust `rlib` API (`pub` items of `craton_hsm`) | `src/lib.rs` | **Not a module interface.** It exposes internal functions without the POST gate, error state or role checks of the C API. |

### 1.6 Modes of Operation

| Mode | How it is entered | Properties |
|---|---|---|
| **Approved-only build** (target approved mode) | Compile with `--features fips` (release flavour `…-fips`, built with `fips,awslc-backend`). | Configuration files and `CRATON_HSM_*` environment overrides are ignored; hard-coded policy: `fips_approved_only = true`, `enable_pqc = false`, `allow_weak_rsa = false`, `allow_sha1_signing = false`, audit enabled. The integrity test is mandatory and fails closed (§4). The self-tests refuse a crypto backend that is not a validated module, so the build must select the AWS-LC backend; with RustCrypto it stays in the error state. |
| Approved-mode *policy* on a default build | `fips_approved_only = true` in `craton_hsm.toml` or `CRATON_HSM_FIPS=1` | Blocks non-approved mechanisms, but it is **advisory only**: it can be undone by changing the environment or configuration, the integrity test remains optional, and a non-validated backend is only warned about. **It is not an approved mode.** |
| Non-approved (default) | Default build and configuration | All mechanisms available, including PQC; RustCrypto backend. |

Approved-only builds report `CKR_MECHANISM_INVALID` for every non-approved
mechanism, and `C_GetMechanismList` lists only permitted mechanisms.

### 1.7 Approved-service indicator (IG 2.4.C)

**Status: not yet implemented.** IG 2.4.C requires an indicator that tells
the operator, through the module interface, whether a service invocation was
approved. The module currently offers:

- a static per-mechanism classification (`is_fips_approved()` in
  `src/crypto/mechanisms.rs`), recorded as the `fips_approved` field of each
  audit-log record. The audit log is a file, not an API output, and the
  classification does not reflect the backend, parameters or key sizes
  actually used, so it is **not** a conforming indicator;
- no global approved-mode status output (`C_GetInfo.flags` is 0 and
  `libraryDescription` carries no mode string).

The session field `last_operation_fips_approved` and the vendor attribute
`CKA_VENDOR_FIPS_APPROVED` exist in the source but are never set or returned;
they must not be relied on.

Planned approach (not yet implemented): in an approved-only build every
available service is approved (IG 2.4.C "approved-only mode"), and the module
reports that mode through `CK_INFO.libraryDescription` and a vendor flag in
`CK_INFO.flags`, so that the operator can verify it via `C_GetInfo`.

---

## 2. Cryptographic Module Interfaces

### 2.1 Logical Interface Mapping

| FIPS 140-3 interface | PKCS#11 mapping |
|---------------------|-----------------|
| Data input | Plaintext/ciphertext/signature input of `C_Encrypt*`, `C_Decrypt*`, `C_Sign*`, `C_Verify*`, `C_Digest*`; key values in `C_CreateObject`/`C_UnwrapKey` templates; PINs in `C_Login`, `C_InitToken`, `C_InitPIN`, `C_SetPIN`; operation-state blobs in `C_SetOperationState` |
| Data output | Ciphertext, plaintext, signatures, digests, wrapped keys (`C_WrapKey`), random data (`C_GenerateRandom`), attribute values (`C_GetAttributeValue`), operation-state blobs (`C_GetOperationState`) |
| Control input | `C_Initialize`, `C_Finalize`, session/login functions, `*Init` functions (mechanism + parameters), templates of generate/derive/unwrap/create/copy/set-attribute |
| Status output | `CK_RV` return codes; `C_GetInfo`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetSessionInfo`, `C_GetMechanismList`, `C_GetMechanismInfo`, `C_GetInterfaceList`/`C_GetInterface` |
| Control output | None |

### 2.2 Exported API Functions

`C_GetFunctionList` returns a `CK_FUNCTION_LIST` (v2.40 layout) containing
the 68 PKCS#11 v2.40 functions. The v3.0 interface-discovery functions
`C_GetInterfaceList` and `C_GetInterface` are also exported and describe the
`"PKCS 11"` interface. No other v3.0 function is implemented (`C_LoginUser`,
`C_SessionCancel`, and the message-based API `C_MessageEncryptInit`,
`C_EncryptMessage*`, `C_DecryptMessage*`, `C_MessageSign*`,
`C_MessageVerify*` are absent).

Every function that dereferences caller pointers or reaches module state is
wrapped in `catch_unwind` so that a Rust panic cannot unwind into the caller;
functions that only return a constant (the stubs below) need no wrapper.

| Group | Functions | Notes |
|---|---|---|
| General | `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`, `C_GetInterfaceList`, `C_GetInterface` | `C_Initialize` runs the pre-operational self-tests |
| Slot & token | `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo`, `C_InitToken`, `C_InitPIN`, `C_SetPIN` | |
| Session | `C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo`, `C_Login`, `C_Logout`, `C_GetOperationState`, `C_SetOperationState` | See §2.4 for the operation-state service |
| Object | `C_CreateObject`, `C_CopyObject`, `C_DestroyObject`, `C_GetObjectSize`, `C_GetAttributeValue`, `C_SetAttributeValue`, `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal` | |
| Encryption | `C_EncryptInit`, `C_Encrypt`, `C_EncryptUpdate`, `C_EncryptFinal`, `C_DecryptInit`, `C_Decrypt`, `C_DecryptUpdate`, `C_DecryptFinal` | |
| Digest | `C_DigestInit`, `C_Digest`, `C_DigestUpdate`, `C_DigestKey`, `C_DigestFinal` | |
| Signature | `C_SignInit`, `C_Sign`, `C_SignUpdate`, `C_SignFinal`, `C_VerifyInit`, `C_Verify`, `C_VerifyUpdate`, `C_VerifyFinal` | |
| Key management | `C_GenerateKey`, `C_GenerateKeyPair`, `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey` | |
| Random | `C_GenerateRandom`, `C_SeedRandom` | `C_SeedRandom` returns `CKR_RANDOM_SEED_NOT_SUPPORTED` |

Exported but **not supported** (no service):

| Function | Return value |
|---|---|
| `C_SignRecoverInit`, `C_SignRecover`, `C_VerifyRecoverInit`, `C_VerifyRecover` | `CKR_FUNCTION_NOT_SUPPORTED` |
| `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate` | `CKR_FUNCTION_NOT_SUPPORTED` |
| `C_WaitForSlotEvent` | `CKR_FUNCTION_NOT_SUPPORTED` |
| `C_GetFunctionStatus`, `C_CancelFunction` | `CKR_FUNCTION_NOT_PARALLEL` (legacy functions) |

### 2.3 Interface Separation

- PINs and key values enter only through the documented data-input
  parameters and are never echoed in status output.
- `CK_RV` codes are the generic PKCS#11 codes produced by the mapping in
  `src/error.rs`; internal error details are logged, not returned.
- While the module is in the error state (§9.4) no data output is produced.

### 2.4 Operation-state service

`C_GetOperationState` serialises the state of the active operation in a
session (mechanism, mechanism parameters, key *handles* and data accumulated
by multi-part operations — never key values) and appends an HMAC-SHA-256 tag
computed with the per-process operation-state key (SSP #21 in §8.1).
`C_SetOperationState` accepts a blob only if the tag verifies and the
referenced keys exist. The blob is authenticated but **not encrypted**: it
reveals accumulated plaintext input of multi-part operations to the caller
that requested it. It is only meaningful within the same process instance.

---

## 3. Roles, Services, and Authentication

### 3.1 Roles

| Role | PKCS#11 user type | Authentication |
|------|-------------------|----------------|
| Crypto Officer (CO) | `CKU_SO` | SO PIN, verified with PBKDF2-HMAC-SHA-256 |
| User | `CKU_USER` | User PIN, verified with PBKDF2-HMAC-SHA-256 |
| Unauthenticated | — | none |

Only one role can be logged in to a token at a time (PKCS#11 semantics); the
SO can only log in on read-write sessions.

### 3.2 Services

Legend: **Y** = allowed, **N** = refused. "Approved" refers to the
algorithm (Appendix A); a service is only an *approved service* in an
approved-only build on a validated backend (§1.6).

| Service | Functions | CO | User | Unauth. | SSPs (access) |
|---|---|---|---|---|---|
| Show status / module info | `C_GetInfo`, `C_GetSlot*`, `C_GetTokenInfo`, `C_GetMechanism*`, `C_GetSessionInfo`, `C_GetInterface*` | Y | Y | Y | — |
| Self-test on demand | `C_Finalize` + `C_Initialize` (re-runs POST) | Y | Y | Y | all volatile SSPs zeroized, DRBG re-instantiated |
| Initialize token | `C_InitToken` | Y (SO PIN) | N | N | SO PIN (E), PIN verifier (G/W), persistence DEK (G), all token objects (Z) |
| Initialize User PIN | `C_InitPIN` | Y | N | N | User PIN (E), PIN verifier (G/W), KEK (G) |
| Change own PIN | `C_SetPIN` | Y | Y | N | old/new PIN (E), PIN verifier (W), KEK (G) |
| Log in / out | `C_Login`, `C_Logout` | Y | Y | — | PIN (E), PIN verifier (R), DEK (unwrapped into RAM at login) |
| Session management | `C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions` | Y | Y | Y | session objects (Z on close) |
| Generate symmetric key | `C_GenerateKey` | N | Y | N | DRBG (X), secret key (G) |
| Generate key pair (with PCT) | `C_GenerateKeyPair` | N | Y | N | DRBG (X), private key (G) |
| Encrypt / decrypt | `C_Encrypt*`, `C_Decrypt*` | N | Y | public keys only | secret/private key (X) |
| Sign / verify | `C_Sign*`, `C_Verify*` | N | Y | verify with public keys only | private key (X) |
| Digest | `C_Digest*` | Y | Y | Y | — (`C_DigestKey`: secret key (X), User only) |
| Wrap / unwrap key | `C_WrapKey`, `C_UnwrapKey` | N | Y | N | wrapping key (X), target key (R/W) |
| Derive key (ECDH, ML-KEM) | `C_DeriveKey` | N | Y | N | private key (X), shared secret (G, transient), derived key (G) |
| Random number generation | `C_GenerateRandom` | Y | Y | Y | DRBG (X) |
| Object management (public objects) | `C_CreateObject`, `C_CopyObject`, `C_DestroyObject`, `C_GetAttributeValue`, `C_SetAttributeValue`, `C_Find*`, `C_GetObjectSize` | Y | Y | Y (RW session for writes) | — |
| Object management (private objects, key values) | same | N | Y | N | keys (R/W/Z) |
| Save / restore operation state | `C_GetOperationState`, `C_SetOperationState` | N | Y | N | operation-state key (X) |

(E = entered, G = generated, R = read, W = written, X = executed/used,
Z = zeroized.)

Rules enforced by the implementation:

- Key-usage services (sign, decrypt, unwrap, derive, wrap, `C_DigestKey`,
  private-object access) require the **User** role; an SO session is not
  "logged in" for these purposes.
- Every write service requires a read-write session.
- `C_InitToken` verifies the SO PIN **before** destroying anything, applies
  the SO lockout to that verification, affects only the target slot, and
  returns `CKR_SESSION_EXISTS` while sessions are open on the slot.

> **Verification note.** The 2026-09-24 audit found these rules violated
> (A1-07: `C_InitToken` wiped all slots before checking the PIN; A1-12: SO
> sessions could use keys and key generation/derivation/destruction required
> no login). The fixes change `src/session/session.rs`, `src/token/`,
> `src/store/attributes.rs` and `src/pkcs11_abi/functions.rs`; this table
> must be re-verified against the merged code and the integration tests
> before it is used as evidence.

### 3.3 Authentication Mechanism

| Parameter | Value | Source |
|-----------|-------|--------|
| Verifier | salt (32 bytes, from the module DRBG) ‖ PBKDF2-HMAC-SHA-256(PIN, salt) (32 bytes) | `src/store/encrypted_store.rs`, `src/token/` |
| Iterations | 600 000 (`security.pbkdf2_iterations`) | `src/config/config.rs` |
| Comparison | constant time (`subtle::ConstantTimeEq`) | |
| PIN length | 8–64 bytes by default (`security.pin_min_length` / `pin_max_length`) | |
| PIN composition | at least 3 distinct byte values; ASCII PINs need at least 2 character classes (lower, upper, digit, other) | `src/token/` |
| Lockout | after `security.max_failed_logins` consecutive failures (default **10**), `CKR_PIN_LOCKED`; lockout counters are persisted per slot | |
| Throttling | exponential back-off after each failure, from 100 ms, capped at 5 s | |
| Recovery | a locked User PIN is reset by the SO with `C_InitPIN`; a locked SO PIN cannot be recovered through the PKCS#11 API (the token's persistent storage must be removed by the system administrator, destroying its objects, and the token re-initialised) | |

There is no default PIN: a token starts uninitialised and receives its SO PIN
in `C_InitToken`; the User PIN is set by the SO with `C_InitPIN`.

### 3.4 Authentication Strength

Computed from the enforced policy (minimum 8 characters, at least two
character classes). The smallest compliant alphabet is 36 symbols
(lower-case letters + digits):

- Probability of a random single attempt succeeding:
  1 / 36⁸ ≈ 3.6 × 10⁻¹³ (requirement: < 10⁻⁶).
- Attempts possible in one minute: at most 10 before lockout (default
  `max_failed_logins`), and fewer because of the back-off; probability of
  success within one minute ≤ 10 / 36⁸ ≈ 3.6 × 10⁻¹² (requirement: < 10⁻⁵).

If an operator lowers `pin_min_length`, these figures must be recomputed;
`pin_min_length` below 6 cannot meet the 10⁻⁶ single-attempt requirement for
numeric PINs.

---

## 4. Software/Firmware Security

### 4.1 Software integrity test

| Property | Value |
|---|---|
| Technique | Ed25519 digital signature (FIPS 186-5 EdDSA) over the SHA-256 digest of the module file |
| Implementation | `src/crypto/integrity.rs` (`check_integrity()`), using `ed25519-dalek` and `sha2` (RustCrypto; **not CAVP-validated** — A1-05) |
| Public key | 32-byte Ed25519 public key embedded at compile time from `CRATON_HSM_INTEGRITY_PUBLIC_KEY` (PSP #25) |
| Signature | `<library stem>.sig` next to the library: hex-encoded 64-byte signature, produced at release time by `tools/sign-integrity.sh` with the private key held in the protected `release` environment (never distributed) |
| Module path discovery | `dladdr()` (Unix) / `GetModuleHandleExW` + `GetModuleFileNameW` (Windows) |
| Ordering | runs during `C_Initialize` after the SHA-256, SHA-512 and Ed25519 CASTs it depends on, and before any other service is available (IG 10.3.B) |

Behaviour:

| Condition | `fips` build | default build |
|---|---|---|
| Signature valid | pass | pass |
| Signature invalid (file modified) | **fail** → error state | **fail** → error state |
| `.sig` missing | **fail** | skipped (logged) |
| Public key not embedded (all-zero placeholder) | **fail** | skipped (logged) |
| Module path cannot be determined | **fail** | skipped (logged) |

The check reads the library file from disk after it has been loaded; it
verifies the file that was mapped only if the file is not replaced between
loading and `C_Initialize` (A1-28). Operators must install the library in a
directory writable only by administrators.

There is no HMAC-based integrity test: the former HMAC-SHA-256 `.hmac`
scheme and its tooling have been removed. A leftover `.hmac` file is ignored
(a warning is logged).

### 4.2 Executable code

- The module loads no code at run time and contains no self-modifying code.
- All cryptographic code is statically linked into the library.

---

## 5. Operational Environment

### 5.1 Type

Modifiable operational environment (general-purpose operating system). The
module runs in the address space of a single calling process; the OS process
isolation provides separation between operators (single-operator model).

### 5.2 Tested operational environments

These are the environments on which the module's own test suite runs in CI
(`.github/workflows/ci.yml`, pinned runner images). **No ACVP testing has
been performed on any of them yet** (A1-19).

| # | Operating system | Processor | Runner image | PAA | Notes |
|---|---|---|---|---|---|
| 1 | Ubuntu 24.04 LTS | x86_64 | `ubuntu-24.04` | AES-NI / PCLMULQDQ / SHA-NI where available (runtime-detected by the RustCrypto crates; AWS-LC assembly) | Full test suite, Miri, fuzz smoke, feature builds |
| 2 | Windows Server 2025 | x86_64 | `windows-2025` | as above | Full test suite (main branch and releases) |
| 3 | macOS 15 | Apple Silicon (arm64) | `macos-15` | ARMv8 AES/SHA extensions | Full test suite (main branch and releases) |

Release artefacts are also built for `x86_64-apple-darwin` (cross-compiled on
the macOS 15 arm64 runner). That target is **not tested** and is not a tested
OE.

For a validation the vendor must: pick the OEs to claim, run ACVP for the
algorithm implementations actually used on each (with and without PAA where
applicable), and record the exact OS build numbers. Building AWS-LC with
`AWS_LC_SYS_NO_ASM=1` produces a different implementation from the validated
AWS-LC configuration and must not be used for a claimed OE.

### 5.3 Platform-specific security features

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| Memory locking (best effort) | `mlock(2)` | `VirtualLock` | `mlock(2)` |
| Fork detection | PID check on every call | N/A | PID check |
| File locking (persistence) | `flock` via `fs2` | `LockFileEx` via `fs2` | `flock` via `fs2` |
| Entropy input | `getrandom(2)` | `BCryptGenRandom` | `getentropy` / `SecRandomCopyBytes` (via `getrandom`) |

### 5.4 Build requirements

| Item | Requirement |
|---|---|
| Rust toolchain | as pinned in `rust-toolchain.toml` (1.94.1); MSRV 1.89 |
| AWS-LC backend | CMake, Clang, Go (for `aws-lc-fips-sys`) |
| Approved-only build | `cargo build --release --locked -p craton-hsm --no-default-features --features fips` (the release workflow's `-fips` flavour builds with `craton-hsm/fips,craton-hsm/awslc-backend`), with `CRATON_HSM_INTEGRITY_PUBLIC_KEY` set, followed by signing (§4.1) |

---

## 6. Physical Security

The module does not claim any physical security mechanisms. It is a software
module; its physical perimeter is the enclosure of the general-purpose
computer on which the tested operational environment runs.

## 7. Non-Invasive Security

The module does not claim any non-invasive attack mitigations.

---

## 8. Sensitive Security Parameter Management

### 8.1 SSP inventory

Columns follow SP 800-140B: generation, establishment/entry, output, storage
and zeroization. "RKM" = `RawKeyMaterial` (`src/store/key_material.rs`):
heap buffer, best-effort `mlock`/`VirtualLock`, zeroized then unlocked on drop.

| # | SSP | Type / strength | Generation / establishment | Entry | Output | Storage | Zeroization |
|---|---|---|---|---|---|---|---|
| 1 | AES secret keys | CSP; 128/192/256-bit | `C_GenerateKey` from DRBG output (SP 800-133 §6.1); `C_DeriveKey`; `C_UnwrapKey` | `C_CreateObject` (plaintext), `C_UnwrapKey` (wrapped) | `C_WrapKey` if `CKA_EXTRACTABLE`; plaintext `C_GetAttributeValue(CKA_VALUE)` only if `CKA_SENSITIVE = false` | RKM; persisted token objects encrypted under #13 | `C_DestroyObject`, session close (session objects), `C_Finalize`, `C_InitToken` |
| 2 | RSA private keys | CSP; 2048/3072/4096-bit (112–≥128-bit strength) | `C_GenerateKeyPair` (FIPS 186-5 key generation via backend, DRBG) + PCT | `C_CreateObject`, `C_UnwrapKey` | as #1 | RKM (PKCS#8 DER); parsed keys cached in a bounded in-memory cache | as #1; the parsed-key cache is cleared on `C_Finalize` and `C_InitToken` |
| 3 | EC private keys | CSP; P-256 (128-bit), P-384 (192-bit) | `C_GenerateKeyPair` + PCT | `C_CreateObject`, `C_UnwrapKey` | as #1 | RKM | as #1 |
| 4 | Ed25519 private keys | CSP; 128-bit | `C_GenerateKeyPair` + PCT | `C_CreateObject`, `C_UnwrapKey` | as #1 | RKM | as #1 |
| 5 | ML-DSA / SLH-DSA private keys (and seeds) | CSP; categories 1–5 | `C_GenerateKeyPair` + PCT | `C_CreateObject`, `C_UnwrapKey` | as #1 | RKM | as #1 |
| 6 | ML-KEM decapsulation keys (and seeds) | CSP | `C_GenerateKeyPair` + PCT | `C_CreateObject`, `C_UnwrapKey` | as #1 | RKM | as #1 |
| 7 | ECDH shared secret Z | CSP; transient | `C_DeriveKey` (`CKM_ECDH1_DERIVE` / `COFACTOR`) | — | never | stack/heap, transient | immediately after the KDF step |
| 8 | ML-KEM shared secret | CSP; 256-bit | `C_DeriveKey` with an ML-KEM mechanism (encapsulation/decapsulation) | — | only as the value of the derived secret-key object (#1 rules apply) | RKM | as #1 |
| 9 | KDF intermediate values (HKDF / X9.63 one-step KDF, SP 800-56C) | CSP; transient | ECDH derive | — | never | transient | after use |
| 10 | SO PIN, User PIN (plaintext) | CSP; ≥ 8 characters | chosen by operator | `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_Login` | never | only for the duration of the call | zeroized after hashing / verification |
| 11 | PIN verifiers | CSP; PBKDF2 output | PBKDF2-HMAC-SHA-256 (SP 800-132), 32-byte salt from DRBG | — | never | token state (persisted when persistence is enabled) | `C_InitToken`, PIN change, `Drop` |
| 12 | PIN-derived key-encryption keys (KEK) | CSP; 256-bit | PBKDF2-HMAC-SHA-256 of the SO / User PIN with a per-PIN salt | — | never | transient | after wrapping/unwrapping #13 |
| 13 | Persistent-store data-encryption key (DEK), one per slot | CSP; AES-256 | random, from DRBG, at `C_InitToken` | — | never (stored only wrapped under #12 with AES-256-GCM) | RAM keyring after a successful login | `C_Finalize`, re-initialisation (crypto-shredding all records), `Drop` |
| 14 | Persistent-store manifest MAC key | CSP; 256-bit | derived from #13 | — | never | RAM | with #13 |
| 15 | DRBG entropy input and seed material | CSP | OS RNG via SP 800-90B-style health tests (RCT/APT) | — | never | transient | after instantiate/reseed |
| 16 | HMAC_DRBG internal state (K, V) | CSP; 256-bit security strength | SP 800-90A instantiate / reseed | — | never | process-wide DRBG instance | on drop, on fork detection, and at `C_Finalize` |
| 17 | AWS-LC internal DRBG state | CSP | inside AWS-LC (awslc-backend) | — | never | AWS-LC | per AWS-LC's own Security Policy |
| 18 | AES-GCM IVs and per-key invocation counters | PSP (IV) / state | IVs generated inside the module from the DRBG (SP 800-38D §8.2.2, IG C.H); in approved mode caller-supplied IVs are refused | — | IV returned to caller | per-key tracking table keyed by SHA-256(key) | tracking entries dropped at `C_InitToken` |
| 19 | Multi-part operation buffers and mechanism parameters | CSP (may contain plaintext) | during multi-part operations | data input | — | session (`Zeroizing`) | on operation end / session close |
| 20 | Operation-state blobs | contains #19 data (authenticated, not encrypted) | `C_GetOperationState` | `C_SetOperationState` | `C_GetOperationState` | caller | caller's responsibility |
| 21 | Operation-state HMAC key | CSP; 256-bit | DRBG at `HsmCore` creation | — | never | `HsmCore` (`Zeroizing`) | `C_Finalize` |
| 22 | Public keys (RSA, EC, Ed25519, ML-DSA, SLH-DSA, ML-KEM encapsulation keys) | PSP | with the private key | `C_CreateObject`, `C_UnwrapKey` | `C_GetAttributeValue` | object store | with the object |
| 23 | Integrity-verification public key | PSP; Ed25519 | release build | compiled in | never | library image | N/A |
| 24 | Self-test key material (KAT vectors, including a test RSA key) | not an SSP (fixed public test data) | compiled in | — | never | library image | N/A |

Items that are **not** module SSPs: the admin CLI's backup passphrase and
backup key (`tools/craton-hsm-admin`, `src/store/backup.rs`) and the daemon's
TLS keys belong to applications outside the boundary (§1.5).

### 8.2 Random bit generation

| Property | Value |
|---|---|
| RBG | HMAC_DRBG with HMAC-SHA-256 (SP 800-90A Rev. 1), one process-wide, fork-aware instance (`src/crypto/drbg.rs`) serving all module randomness **including `C_GenerateRandom`**. With the AWS-LC backend, `C_GenerateRandom` is served by AWS-LC's own DRBG. |
| Security strength | 256 bits |
| Prediction resistance | enabled (fresh entropy input on every generate request) |
| Reseed interval | 2¹⁶ requests (well below the SP 800-90A limit of 2⁴⁸) |
| Max request | 2¹⁹ bits per generate call; larger `C_GenerateRandom` requests are split |
| Entropy input | OS RNG, passed through Repetition Count and Adaptive Proportion tests with a start-up test over 1024 samples; a failure latches the error state |
| Health tests | SP 800-90A §11.3 known-answer test (NIST CAVP HMAC_DRBG SHA-256 vector) in POST; continuous test on consecutive output blocks |
| `C_SeedRandom` | not supported (`CKR_RANDOM_SEED_NOT_SUPPORTED`) |
| **Gap** | The entropy source has **no ESV certificate** and no documented min-entropy estimate (A1-02). |

### 8.3 Key generation

Symmetric keys are DRBG output of the requested length. Asymmetric key pairs
are generated by the backend using DRBG output as the random source, followed
by a pair-wise consistency test (§9.3). Approved-mode minimums: RSA ≥ 2048
bits (SP 800-131A); AES 128/192/256 bits; EC P-256/P-384.

### 8.4 Key entry and output

| Rule | Enforcement |
|---|---|
| `CKA_VALUE` of a key with `CKA_SENSITIVE = true` is never returned in plaintext | `C_GetAttributeValue` returns `CKR_ATTRIBUTE_SENSITIVE` |
| `CKA_VALUE` of a key with `CKA_EXTRACTABLE = false` is never returned in plaintext | `CKR_ATTRIBUTE_SENSITIVE` |
| A key can be wrapped only if `CKA_EXTRACTABLE = true` | `C_WrapKey` refuses (currently with `CKR_KEY_FUNCTION_NOT_PERMITTED`; PKCS#11 specifies `CKR_KEY_UNEXTRACTABLE`) |
| `CKA_SENSITIVE` can only change false → true; `CKA_EXTRACTABLE` only true → false | `C_SetAttributeValue` / `C_CopyObject` |
| Keys enter in plaintext through `C_CreateObject` or wrapped through `C_UnwrapKey` | in approved mode, plaintext key entry is an IG D.N concern for the operator: keys must be entered only within the OE (the API is local) |

> **Verification note.** A1-08 found that keys with `CKA_SENSITIVE = true`
> and `CKA_EXTRACTABLE = true` were returned in plaintext. The fix is in
> `src/store/attributes.rs`; re-verify with the `attribute_validation` and
> `security_properties` integration tests.

### 8.5 Storage

- **In memory:** key values live in `RawKeyMaterial` buffers (zeroize on drop,
  best-effort memory locking; `mlock` failures are logged, not fatal).
- **Persistent (optional, `persist_objects = true`):** token objects
  (`CKA_TOKEN = true`) are stored in a redb database at `storage_path`. Each
  record is encrypted with AES-256-GCM under the slot DEK (#13), with
  associated data binding it to the slot, handle and generation, and each
  slot has an HMAC-authenticated manifest (#14) so that records cannot be
  moved, replayed or resurrected. The DEK exists on disk only wrapped under
  PIN-derived KEKs (#12); it is unwrapped into memory at login. Session
  objects are never persisted. Whole-file rollback of the database is not
  detectable without an external monotonic counter.
- The database file is locked exclusively (`fs2`) so that only one process
  uses it.

### 8.6 Zeroization

| Event | SSPs zeroized |
|---|---|
| `C_DestroyObject` | the object's key value (#1–#6, #8) |
| `C_CloseSession` / `C_CloseAllSessions` | session objects; operation buffers (#19) |
| `C_Logout` | per-login state (the slot's unwrapped DEK deliberately stays in the keyring until `C_Finalize` so that token objects remain loaded) |
| `C_InitToken` | all objects of the slot, PIN verifiers (#11), DEK (#13, crypto-shredding the persisted records), GCM tracking (#18), RSA parsed-key cache |
| `C_Finalize` | all volatile SSPs: objects in memory, DRBG state (#16), operation-state key (#21), DEK keyring (#13/#14), RSA parsed-key cache |
| Error state | services are refused; SSPs are zeroized at `C_Finalize` |

Zeroization overwrites memory with zeros through the `zeroize` crate (which
prevents the compiler from eliding the writes). Copies made by the OS (swap,
core dumps) are outside the module's control; operators should disable core
dumps for processes that load the module.

### 8.7 Key lifecycle (SP 800-57)

Objects carry `CKA_START_DATE` / `CKA_END_DATE`; the effective state is
evaluated at every use (`src/store/object.rs`):

| State | Condition | Permitted operations |
|---|---|---|
| Pre-activation | now < `CKA_START_DATE` | none |
| Active | within the dates (or no dates) | all permitted by the key's usage attributes |
| Deactivated | now > `CKA_END_DATE` | verify, decrypt, unwrap only |
| Compromised | marked compromised (vendor lifecycle state) | none |
| Destroyed | after `C_DestroyObject` | handle invalid |

---

## 9. Self-Tests

### 9.1 Pre-operational self-tests

Run inside `C_Initialize` before any other service is available
(`src/crypto/self_test.rs`, `run_post()` then `run_backend_post()`):

1. **CASTs of the algorithms used by the integrity test** — SHA-256,
   SHA-512 and Ed25519 (sign and verify with a fixed key, RFC 8032 vector).
2. **Software integrity test** (§4.1).

### 9.2 Cryptographic algorithm self-tests (CASTs)

Every CAST compares the complete output with a fixed expected value
(no round-trip tests; signature CASTs use fixed keys). CASTs run at
`C_Initialize`, after the integrity test.

| Algorithm | Test | Implementation tested |
|---|---|---|
| SHA-256, SHA-384, SHA-512 | KAT (FIPS 180-4 "abc") | RustCrypto and the selected backend |
| SHA3-256, SHA3-384, SHA3-512 | KAT (FIPS 202 "abc") | RustCrypto |
| HMAC-SHA-256/384/512 | KAT (RFC 4231) | RustCrypto |
| HMAC_DRBG | SP 800-90A §11.3 KAT (instantiate, generate, reseed) | module DRBG |
| HKDF-SHA-256, X9.63/SP 800-56C one-step KDF | KAT (RFC 5869 A.1 and fixed vector) | RustCrypto |
| PBKDF2-HMAC-SHA-256 | KAT (RFC 7914 §11) | RustCrypto |
| AES-GCM | encrypt and decrypt KAT (fixed key/IV/AAD, expected ciphertext and tag) | selected backend |
| AES-CBC, AES-CTR | encrypt and decrypt KAT (SP 800-38A F.2.5 / F.5.5) | selected backend |
| AES-KW, AES-KWP | wrap/unwrap KAT (RFC 3394 §4.6 / RFC 5649 §6) | selected backend |
| RSA | PKCS#1 v1.5 SigGen KAT with a fixed test key (deterministic), PKCS#1 v1.5 and PSS SigVer KATs, OAEP decryption KAT | selected backend |
| ECDSA P-256 / P-384 | SigVer KATs (P-256/SHA-256, P-384/SHA-384) including a negative test; SigGen with a fixed key checked by verification (ECDSA signing is randomised) | selected backend |
| ECDH P-256 | shared-secret KAT (KAS-ECC-SSC) | selected backend |
| Ed25519 | sign and verify KAT | RustCrypto and the selected backend |
| ML-KEM-768 | KeyGen, Encaps, Decaps and implicit-rejection KAT | RustCrypto (pre-release crate) |
| ML-DSA-44 | KeyGen, Sign, Verify KAT | RustCrypto (pre-release crate) |
| SLH-DSA-SHA2-128s | Verify KAT | RustCrypto (pre-release crate) |

In a `fips` build `run_backend_post()` also refuses a crypto backend that is
not a validated module, which leaves the module in the error state.

### 9.3 Conditional self-tests

| Test | Trigger | Action on failure |
|---|---|---|
| Pair-wise consistency test (sign/verify, or encapsulate/decapsulate) | every `C_GenerateKeyPair` for RSA, EC, Ed25519, ML-DSA, SLH-DSA, ML-KEM (`src/crypto/pairwise_test.rs`) | key pair discarded, error state |
| Entropy health tests (RCT, APT) | every entropy input | error state |
| DRBG continuous output test | every generate call on the process-wide instance | error state |

### 9.4 Error state

- Any self-test failure latches the module error state
  (`self_test::enter_error_state`). While it is set, every function that
  reaches module state returns `CKR_GENERAL_ERROR` and no data is output;
  only `C_Finalize` and the function-list/interface functions remain
  usable.
- The only way to leave the error state is `C_Finalize` followed by a
  successful `C_Initialize` (self-tests on demand); if any test fails again the
  module stays in the error state.
- A DRBG failure deep inside a third-party trait callback that cannot report
  an error aborts the process instead (documented limitation, A3-19).

---

## 10. Life-Cycle Assurance

### 10.1 Configuration management

| Aspect | Control |
|---|---|
| Source control | Git (GitHub); CODEOWNERS review; signed release tags required by GOVERNANCE.md |
| History | The public history starts at a single squashed commit (`2f76874`); earlier releases in CHANGELOG.md have no tags here (A3-17) |
| Dependencies | `Cargo.lock` committed and enforced with `--locked`; `cargo deny` (advisories, bans, licences, sources) and `cargo audit` on every PR and release; suppressions only in `deny.toml` with reason and expiry |
| Toolchain | pinned in `rust-toolchain.toml`; MSRV checked in CI |
| Module version | `version` in `Cargo.toml`; release tag must match (release workflow `verify-tag` job) |

### 10.2 Design

`HsmCore` (`src/core.rs`) owns the slot/session managers, object store, audit
log, crypto backend, DRBG and the operation-state key. Two `CryptoBackend`
implementations exist: `RustCryptoBackend` (default) and `AwsLcBackend`
(`awslc-backend` feature). Backend selection comes from `crypto_backend` in
the configuration (hard-coded in `fips` builds).

### 10.3 Finite state model

| State | Entered by | Services |
|---|---|---|
| Power off / not initialised | process start, `C_Finalize` | only `C_Initialize`, `C_GetFunctionList`, `C_GetInterface*` |
| Self-test | `C_Initialize` | none |
| Operational (no user) | self-tests passed | status, digest, random, public-object services, `C_Login` |
| CO logged in | `C_Login(CKU_SO)` | token and PIN administration, public objects |
| User logged in | `C_Login(CKU_USER)` | all cryptographic services |
| Error | any self-test failure | none except `C_Finalize` and status (§9.4) |

Session states follow PKCS#11: R/O Public, R/W Public, R/O User, R/W User,
R/W SO (`src/session/session.rs`).

### 10.4 Development

| Aspect | Value |
|---|---|
| Language | Rust 2021 |
| `unsafe` code | confined to the FFI boundary (`src/pkcs11_abi/functions.rs`), memory locking (`src/crypto/mlock.rs`), module-path discovery (`src/crypto/integrity.rs`), digest-state zeroization (`src/crypto/digest.rs`) and Windows ACL calls (`src/store/`, `src/platform_acl.rs`) |
| Verification in CI | unit/integration tests on three OEs, clippy (correctness/suspicious denied), Miri on library unit tests, 60-second fuzz smoke run of all 12 fuzz targets, feature builds (`fips`, `awslc-backend`) |

### 10.5 Delivery

Releases are built, signed and published only by the gated release workflow;
see [release-signing.md](release-signing.md) for the artefacts (SHA256SUMS,
cosign bundles, SLSA provenance, SBOM, licence notices) and the user
verification procedure.

### 10.6 Approved-only build procedure

```bash
export CRATON_HSM_INTEGRITY_PUBLIC_KEY=<64 hex chars>
cargo build --release --locked -p craton-hsm --no-default-features --features fips --lib
./tools/sign-integrity.sh target/release/libcraton_hsm.so

# Tests: in a fips build every test executable is "the module" for the
# integrity test, so it must be signed too (CI uses a throw-away key; see the
# `features` job in .github/workflows/ci.yml).
cargo test --locked -p craton-hsm --no-default-features --features fips \
  --lib --test fips_approved_mode --no-run --message-format=json \
  | jq -r 'select(.reason=="compiler-artifact" and .profile.test and .executable!=null) | .executable' \
  | while read -r exe; do ./tools/sign-integrity.sh "$exe" /path/to/test-key.pem; done
cargo test --locked -p craton-hsm --no-default-features --features fips \
  --lib --test fips_approved_mode -- --test-threads=1
```

The configuration file is ignored in `fips` builds, so there is no FIPS
configuration to write; see [fips-mode-guide.md](fips-mode-guide.md).

### 10.7 Guidance documents

| Document | Contents |
|---|---|
| [install.md](install.md) | installation and configuration |
| [fips-mode-guide.md](fips-mode-guide.md) | approved-only build, verification, limitations |
| [operator-runbook.md](operator-runbook.md) | operations and incident handling |
| [release-signing.md](release-signing.md) | verifying delivered artefacts |
| [security-policy.md](security-policy.md) | operator summary of this document |

---

## 11. Mitigation of Other Attacks

No mitigation of other attacks is claimed. The following voluntary measures
exist; they are not security functions in the FIPS sense:

| Measure | Notes |
|---|---|
| Constant-time PIN comparison | `subtle::ConstantTimeEq` |
| Best-effort memory locking and zeroization | see §8.5–8.6 |
| Hash-chained audit log | keyed HMAC-SHA256 chain with a MAC-protected anchor (H3-10): detects modification, truncation and deletion by a party without the audit key; not a security function in the FIPS sense (A1-31) |
| Fork detection | the child must call `C_Initialize` again |
| AES-NI / hardware AES | used when available by the RustCrypto `aes` crate and AWS-LC |

**Known weakness:** RSA private-key operations on the RustCrypto backend
(`C_Decrypt` with `CKM_RSA_PKCS_OAEP`, all RSA signing) use the `rsa` crate,
which is affected by the Marvin timing side channel (RUSTSEC-2023-0071) and
has no fixed release. Base blinding is applied to every private-key
operation and there is no PKCS#1 v1.5 decryption service, but the bignum
arithmetic is not constant time, so no mitigation of the timing side channel
is claimed. `fips` builds use the AWS-LC backend; use it for RSA private-key
operations wherever timing attacks are in scope (A1-26, H2-03).

---

## Appendix A: Mechanism Table

`C_GetMechanismList` reports the mechanisms permitted by the active policy.
"Approved algorithm" means the algorithm is approved by NIST; the module
provides it as an approved *service* only in an approved-only build on a
validated backend (§1.6).

| Mechanism | Functions | Approved algorithm | Key sizes / notes |
|---|---|---|---|
| `CKM_RSA_PKCS_KEY_PAIR_GEN` | GenerateKeyPair | Yes (FIPS 186-5) | 2048 / 3072 / 4096 |
| `CKM_RSA_PKCS` | Sign, Verify (input: DER `DigestInfo`) | Yes | encryption with PKCS#1 v1.5 padding is not offered |
| `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`, `CKM_SHA512_RSA_PKCS` | Sign, Verify (single- and multi-part) | Yes | |
| `CKM_SHA256_RSA_PKCS_PSS`, `CKM_SHA384_RSA_PKCS_PSS`, `CKM_SHA512_RSA_PKCS_PSS` | Sign, Verify | Yes | generic `CKM_RSA_PKCS_PSS` is not offered (its `CK_RSA_PKCS_PSS_PARAMS` handling is not implemented) |
| `CKM_RSA_PKCS_OAEP` | Encrypt, Decrypt, Wrap, Unwrap | Yes (KTS-OAEP) | see §11 on RUSTSEC-2023-0071 |
| `CKM_EC_KEY_PAIR_GEN` | GenerateKeyPair | Yes | P-256, P-384; other curves are rejected |
| `CKM_ECDSA`, `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384`, `CKM_ECDSA_SHA512` | Sign, Verify | Yes | PKCS#11 raw `r ‖ s` signature format |
| `CKM_ECDH1_DERIVE`, `CKM_ECDH1_COFACTOR_DERIVE` | Derive | Yes (SP 800-56A r3) with an approved KDF (SP 800-56C); `CKD_NULL` is refused in approved mode | P-256, P-384 |
| `CKM_EDDSA` | GenerateKeyPair, Sign, Verify | Yes (FIPS 186-5, pure Ed25519) | Ed25519 |
| `CKM_AES_KEY_GEN` | GenerateKey | Yes | 128 / 192 / 256 |
| `CKM_AES_CBC` | Encrypt, Decrypt | Yes (SP 800-38A) | no padding: input must be a multiple of 16 bytes |
| `CKM_AES_CBC_PAD` | Encrypt, Decrypt | Yes (SP 800-38A + PKCS#7 padding) | |
| `CKM_AES_CTR` | Encrypt, Decrypt | Yes (SP 800-38A) | `CK_AES_CTR_PARAMS` honoured; counter ranges tracked per key |
| `CKM_AES_GCM` | Encrypt, Decrypt | Yes (SP 800-38D) | `CK_GCM_PARAMS` (IV, AAD, tag length) honoured; module-generated IVs in approved mode |
| `CKM_AES_KEY_WRAP` | Wrap, Unwrap | Yes (SP 800-38F KW) | |
| `CKM_AES_KEY_WRAP_KWP` | Wrap, Unwrap | Yes (SP 800-38F KWP) | |
| `CKM_SHA_1` | Digest | Digest only; refused in approved mode (vendor policy) | |
| `CKM_SHA256`, `CKM_SHA384`, `CKM_SHA512` | Digest | Yes (FIPS 180-4) | |
| `CKM_SHA3_256`, `CKM_SHA3_384`, `CKM_SHA3_512` | Digest | Yes (FIPS 202) | |
| `CKM_ML_KEM_512/768/1024` (vendor-defined codes) | GenerateKeyPair, Derive (encapsulate/decapsulate) | Algorithm approved (FIPS 203); **implementation not validated, pre-release crate** — not offered in approved mode | |
| `CKM_ML_DSA_44/65/87` (vendor-defined) | GenerateKeyPair, Sign, Verify | Algorithm approved (FIPS 204); implementation not validated — not offered in approved mode | |
| `CKM_SLH_DSA_SHA2_128S/256S` (vendor-defined) | GenerateKeyPair, Sign, Verify | Algorithm approved (FIPS 205); implementation not validated — not offered in approved mode | |

No HMAC (`CKM_SHA*_HMAC`) mechanism is offered; HMAC is used only internally
(DRBG, PBKDF2, HKDF, operation-state and manifest authentication).

The authoritative lists are `supported_mechanisms()` and `is_fips_approved()`
in `src/crypto/mechanisms.rs`.

### Algorithm transitions

- SP 800-131A: SHA-1 is not used for signatures; RSA < 2048 bits is refused.
- 112-bit security (RSA-2048) is expected to be deprecated after 2030 and
  quantum-vulnerable RSA/ECC disallowed after 2035 (NIST IR 8547, draft).
  Deployments with long-lived keys should use RSA-3072+/P-384 today and plan
  migration to ML-KEM/ML-DSA from a validated provider.

---

## Appendix B: Error Codes

Internal errors (`HsmError`, `src/error.rs`) map to the standard PKCS#11
`CK_RV` codes of the same name (for example `PinIncorrect` →
`CKR_PIN_INCORRECT`, `AttributeSensitive` → `CKR_ATTRIBUTE_SENSITIVE`,
`MechanismInvalid` → `CKR_MECHANISM_INVALID`). The complete mapping is the
`From<HsmError> for CK_RV` implementation in `src/error.rs`; it is not
duplicated here to avoid drift.

---

## Appendix C: Cryptographic dependency inventory

Versions are those locked in `Cargo.lock` at the time of writing; the SBOM
shipped with each release is authoritative.

| Crate | Version | Purpose | Validation status |
|---|---|---|---|
| `rsa` | 0.9.10 | RSA | Not validated; affected by RUSTSEC-2023-0071 |
| `p256`, `p384`, `ecdsa`, `elliptic-curve` | 0.13 / 0.16 | ECDSA, ECDH | Not validated |
| `ed25519-dalek` (`curve25519-dalek`) | 2.2 (4.1) | Ed25519, integrity test | Not validated |
| `aes`, `aes-gcm`, `cbc`, `ctr`, `aes-kw` | 0.8 / 0.10 / 0.1 / 0.9 / 0.2 | AES modes | Not validated |
| `sha1`, `sha2`, `sha3` | 0.10 | digests | Not validated |
| `hmac`, `pbkdf2`, `hkdf` | 0.12 | HMAC, PBKDF2, HKDF | Not validated |
| `ml-kem`, `ml-dsa`, `slh-dsa` | 0.3.0-rc.0 / 0.1.0-rc.7 / 0.2.0-rc.4 | PQC | **Pre-release**, not validated; they pull their own pre-release `sha2 0.11`, `sha3 0.11` and `hmac 0.13`, which the SHA-2/SHA-3/HMAC CASTs above do not exercise |
| `aws-lc-rs` / `aws-lc-fips-sys` (optional) | 1.16 / 0.13.13 | AWS-LC backend | `aws-lc-fips-sys` builds the AWS-LC FIPS module. Its own CMVP certificate (if any applies to this exact version and OE) must be referenced in a submission; this document does not claim it. |
| `zeroize`, `subtle` | 1.8 / 2.6 | zeroization, constant-time comparison | utilities |
| `redb`, `fs2` | 3.1 / 0.4 | persistence, file locking | storage |

---

## Appendix D: Vendor test evidence

| Evidence | Where |
|---|---|
| Integration tests (35 files under `tests/`, all run by CI; the CI job fails if a test file is not scheduled) | `.github/workflows/ci.yml` |
| Library unit tests | `cargo test --lib` |
| FIPS policy tests | `tests/fips_approved_mode.rs` |
| Zeroization tests | `tests/zeroization.rs` (run serially in CI; they inspect memory after drop and are best-effort evidence) |
| Pair-wise consistency tests | `tests/pairwise_consistency.rs` |
| Fuzzing | 12 cargo-fuzz targets in `fuzz/fuzz_targets/` (`fuzz_c_abi`, `fuzz_crypto_ops`, `fuzz_attributes`, `fuzz_session_lifecycle`, `fuzz_buffer_overflow`, `fuzz_rsa_ops`, `fuzz_keygen`, `fuzz_wrap_unwrap`, `fuzz_multipart_crypto`, `fuzz_derive_key`, `fuzz_set_attribute`, `fuzz_init_token`); each runs for 60 s in CI. The token is provisioned with policy-compliant PINs so authenticated paths are reached. |
| Undefined-behaviour checks | Miri on library unit tests (`crypto::digest`, `crypto::integrity`, `crypto::drbg`, `crypto::mlock`, `session::`, `pkcs11_abi::`) |

Test counts change frequently; use `cargo test -- --list` for the current
inventory instead of a number in this document.

---

## Appendix E: Configuration reference (security-relevant subset)

Default builds read the file named by `CRATON_HSM_CONFIG` or, if unset, the
system-wide `/etc/craton-hsm/craton_hsm.toml`; they never read the working
directory (H3-13). The file must be owned by the user or root and not be
group/world-writable. Storage and audit paths should be absolute,
service-owned directories (system directories and `..` are rejected).
`fips` builds ignore configuration files entirely.

```toml
[token]
label = "Craton HSM Token 0"
storage_path = "/var/lib/craton-hsm/store"
persist_objects = true              # false = ephemeral token (development only)
max_sessions = 100
max_rw_sessions = 10
slot_count = 1

[security]
pin_min_length = 8
pin_max_length = 64
max_failed_logins = 5
pbkdf2_iterations = 600000

[algorithms]
crypto_backend = "rustcrypto"       # or "awslc"; `fips` builds always use AWS-LC
fips_approved_only = false          # advisory policy switch in default builds
enable_pqc = true
allow_weak_rsa = false
allow_sha1_signing = false

[audit]
enabled = true
log_path = "/var/log/craton-hsm/audit.jsonl"
log_level = "all"                   # all | crypto | auth | admin
key_path = "/var/lib/craton-hsm/audit.key"   # HMAC key of the keyed chain
fail_closed = true                  # default in fips builds
```

The gRPC daemon has its own configuration file (see
[configuration-reference.md](configuration-reference.md)); it is outside the
module boundary.

---

*End of draft Security Policy — Craton HSM 0.9.1 — 2026-09-25*
