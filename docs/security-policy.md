# Craton HSM Security Policy (Operator Summary)

> **DISCLAIMER: Craton HSM is NOT FIPS 140-3 validated.** This document
> summarises the security design for operators. The normative definitions —
> cryptographic boundary, services, SSPs, self-tests, error states — are in
> the draft Security Policy [fips-140-3-certification.md](fips-140-3-certification.md).
> This summary must not contradict it; if it does, the certification
> document wins and this file is wrong.

## Document Information

| Property | Value |
|----------|-------|
| Module Name | Craton HSM |
| Module Version | 0.9.1 |
| Module Type | Software |
| FIPS 140-3 Target Level | 1 (not validated) |
| Document Version | 5.0 |
| Date | 2026-09-25 |

---

## 1. Module and boundary

Craton HSM is a PKCS#11 software token implemented in Rust. It exports the
PKCS#11 v2.40 function set plus the v3.0 interface-discovery functions
(`C_GetInterfaceList`, `C_GetInterface`); other v3.0 functions are not
implemented.

**Cryptographic boundary** (identical to
[fips-140-3-certification.md §1.5](fips-140-3-certification.md#15-module-boundary-canonical-definition)):
the module is the shared-library file built from the `craton-hsm` package
(`libcraton_hsm.so` / `craton_hsm.dll` / `libcraton_hsm.dylib`) together with
its Ed25519 integrity sidecar (`.sig`). Its only interface is the set of
exported PKCS#11 C functions.

The following are **outside** the boundary and are not part of the module:
the gRPC daemon (`craton-hsm-daemon`), the admin CLI (`craton-hsm-admin`),
`pkcs11-spy`, the deployment artefacts, and the Rust `rlib` API. The daemon
and the admin CLI link the Rust library directly instead of using the C API,
so the module's self-tests, error state and role checks do not govern them;
they must not be used where a validated module is required.

As a software module, the physical perimeter is that of the computer running
the operational environment. No physical or non-invasive security mechanisms
are claimed.

---

## 2. Interfaces

| Interface | Mapping |
|-----------|---------|
| Data input | PKCS#11 input buffers, key values in templates, PINs, operation-state blobs |
| Data output | ciphertext/plaintext, signatures, digests, wrapped keys, random data, attribute values, operation-state blobs |
| Control input | `C_Initialize`, login/session functions, `*Init` functions, templates |
| Status output | `CK_RV` codes, `C_GetInfo`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetSessionInfo`, `C_GetMechanism*` |

Every exported function that touches module state is protected by
`catch_unwind`, so a Rust panic is converted into an error code instead of
unwinding into the caller. The full function list, including the functions
that return `CKR_FUNCTION_NOT_SUPPORTED`, is in
[fips-140-3-certification.md §2.2](fips-140-3-certification.md#22-exported-api-functions).

---

## 3. Roles, services and authentication

| Role | PKCS#11 identity | Authentication |
|------|-----------------|----------------|
| Crypto Officer (SO) | `CKU_SO` | PIN, PBKDF2-HMAC-SHA-256 (600 000 iterations) |
| User | `CKU_USER` | PIN, PBKDF2-HMAC-SHA-256 (600 000 iterations) |
| Unauthenticated | — | none |

| Service | SO | User | Unauthenticated |
|---------|----|------|-----------------|
| Status / information | Yes | Yes | Yes |
| Token initialisation (`C_InitToken`) | Yes (SO PIN) | No | No |
| Set User PIN (`C_InitPIN`) | Yes | No | No |
| Change own PIN (`C_SetPIN`) | Yes | Yes | No |
| Key generation, sign, decrypt, unwrap, derive, wrap | No | Yes | No |
| Encrypt / verify with public keys | No | Yes | Yes (public objects only) |
| Digest | Yes | Yes | Yes |
| Random number generation | Yes | Yes | Yes |
| Private-object and key-value access | No | Yes | No |
| Public-object management | Yes | Yes | Yes (writes need an R/W session) |

The complete services table with SSP access is in
[fips-140-3-certification.md §3.2](fips-140-3-certification.md#32-services).

**PIN policy (defaults):** 8–64 bytes; at least 3 distinct byte values; ASCII
PINs need at least 2 character classes; lockout after 10 consecutive failures
(`security.max_failed_logins`) with exponential back-off (100 ms doubling to
5 s). **There is no default PIN**: a new token is uninitialised; the SO PIN
is set by `C_InitToken` and the User PIN by the SO with `C_InitPIN`.

---

## 4. States

| State | Description |
|---|---|
| Not initialised | before `C_Initialize` / after `C_Finalize` |
| Self-test | during `C_Initialize` |
| Operational | self-tests passed; login possible |
| Error | a self-test failed; services refused with `CKR_GENERAL_ERROR` until `C_Finalize` + a successful `C_Initialize` |

Sessions follow the PKCS#11 states R/O Public, R/W Public, R/O User,
R/W User and R/W SO. After a Unix `fork()`, the child must call
`C_Initialize` again; until then it receives
`CKR_CRYPTOKI_NOT_INITIALIZED`.

---

## 5. Cryptographic algorithms

The mechanism list, with the approval status of each *algorithm*, is
[fips-140-3-certification.md Appendix A](fips-140-3-certification.md#appendix-a-mechanism-table).
Summary:

- **Approved algorithms offered:** AES (128/192/256) GCM, CBC, CBC-PAD, CTR,
  KW, KWP; RSA 2048–4096 key generation, PKCS#1 v1.5 and PSS signatures,
  OAEP; ECDSA and ECDH on P-256/P-384; Ed25519 (FIPS 186-5); SHA-2 and SHA-3
  digests.
- **Algorithms approved by NIST but whose implementations here are not
  validated, and which are not offered in approved mode:** ML-KEM (FIPS 203),
  ML-DSA (FIPS 204), SLH-DSA (FIPS 205) — implemented with pre-release
  crates.
- **Not approved / restricted:** SHA-1 (digest only, refused in approved
  mode), RSA < 2048 bits (refused).
- **No HMAC mechanism** is offered to callers.

**Implementation status:** no algorithm implementation used by the module
is CAVP-validated in its current configuration. The AWS-LC backend
(`awslc-backend` feature) links the AWS-LC FIPS module, but several services
still use RustCrypto code. See
[fips-gap-analysis.md](fips-gap-analysis.md).

**Random numbers:** one process-wide SP 800-90A HMAC_DRBG (SHA-256,
prediction resistance) serves key generation and `C_GenerateRandom`. It is
seeded from the operating-system RNG through repetition-count and
adaptive-proportion health tests. The entropy source is not ESV-validated.

---

## 6. Key management

- **Generation:** from the DRBG; every key pair passes a pair-wise
  consistency test.
- **Storage:** in memory by default (lost on process exit). With
  `persist_objects = true`, token objects are stored in a redb database, each
  record AES-256-GCM-encrypted under a random per-slot data-encryption key
  that is kept on disk only wrapped under PIN-derived keys (PBKDF2).
- **Export:** `CKA_VALUE` is never returned in plaintext for keys that are
  sensitive or non-extractable; wrapping requires `CKA_EXTRACTABLE = true`.
  Keys are non-extractable unless the template says otherwise.
- **Destruction:** `C_DestroyObject`, session close (session objects),
  `C_InitToken` (all objects of the slot; persisted records become
  unreadable because the slot key is replaced) and `C_Finalize` (all volatile
  state) zeroize the key material.
- **Lifecycle:** SP 800-57 states from `CKA_START_DATE` / `CKA_END_DATE`.

The complete SSP table (generation, entry, output, storage, zeroization) is
[fips-140-3-certification.md §8.1](fips-140-3-certification.md#81-ssp-inventory).

---

## 7. Self-tests

- **Pre-operational:** the SHA-256, SHA-512 and Ed25519 self-tests, then the
  Ed25519 software-integrity test over the library file (signature in the
  `.sig` sidecar; mandatory in `fips` builds, skipped with a log message in
  default builds when no `.sig` or no embedded key is present).
- **Cryptographic algorithm self-tests:** known-answer tests for every
  algorithm family, executed through the selected backend where applicable
  (list: [fips-140-3-certification.md §9.2](fips-140-3-certification.md#92-cryptographic-algorithm-self-tests-casts)).
- **Conditional:** pair-wise consistency tests on key-pair generation,
  entropy health tests, DRBG continuous test.
- **Failure:** the module enters the error state (§4).

There is no HMAC-based integrity test: it was replaced by the Ed25519
signature scheme and the `.hmac` tooling has been removed.

---

## 8. Operational environment

Modifiable OE; single operator per process. Tested environments (CI):
Ubuntu 24.04 x86_64, Windows Server 2025 x86_64, macOS 15 arm64 — see
[fips-140-3-certification.md §5.2](fips-140-3-certification.md#52-tested-operational-environments)
and [tested-platforms.md](tested-platforms.md). No ACVP testing has been
performed on them.

- Persistent storage: one process per database (exclusive file lock).
- Multi-process access through the gRPC daemon is possible but the daemon is
  outside the module boundary.

---

## 9. Mitigation of other attacks

None claimed. Voluntary measures: constant-time PIN comparison, best-effort
memory locking and zeroization, fork detection, and a hash-chained audit log
(unkeyed; detects accidental corruption only). The RustCrypto `rsa` crate is
affected by the Marvin timing side channel (RUSTSEC-2023-0071); this is **not**
mitigated — use the AWS-LC backend for RSA private-key operations where timing
attacks are in scope.
