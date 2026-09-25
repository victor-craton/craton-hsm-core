# FIPS 140-3 Mode Operator Guide

> **Craton HSM is not FIPS 140-3 validated.** Following this guide gives you
> the most restrictive, approved-algorithm-only configuration the code
> supports. It does **not** give you a validated module; see
> [fips-gap-analysis.md](fips-gap-analysis.md) for what is missing.

## Overview

There are two very different things that are both loosely called "FIPS mode":

| | Approved-only **build** (`fips` feature) | Approved-only **policy** (`fips_approved_only = true` or `CRATON_HSM_FIPS=1`) |
|---|---|---|
| How | compile-time feature | configuration file / environment variable |
| Can be undone at run time | No — configuration files and environment overrides are ignored | Yes — by anyone who controls the configuration or environment |
| Integrity self-test | mandatory, fails closed | optional (skipped without `.sig` or embedded key) |
| Backend | must be the validated AWS-LC module; POST refuses anything else | whatever `crypto_backend` says (RustCrypto by default); only a warning |
| Use it for | anything that claims FIPS alignment | development and testing only |

The rest of this guide is about the approved-only **build**.

---

## 1. Obtain or build the approved-only library

### Option A — release artefact (recommended)

Every release ships `craton-hsm-<version>-x86_64-unknown-linux-gnu-fips.tar.gz`,
built with `--features fips,awslc-backend`, with the integrity public key
embedded and the `.sig` sidecar included. Verify it as described in
[release-signing.md](release-signing.md#verifying-a-release-users).

### Option B — build it yourself

```bash
# Build dependencies for aws-lc-fips-sys: CMake, Clang/LLVM, Go
export CRATON_HSM_INTEGRITY_PUBLIC_KEY=<64 hex chars>   # your Ed25519 public key
cargo build --release --locked -p craton-hsm --no-default-features --features fips --lib
./tools/sign-integrity.sh target/release/libcraton_hsm.so   # writes libcraton_hsm.sig
```

- `fips` implies `awslc-backend`; `--no-default-features` additionally keeps
  the RustCrypto backend out of the build. The self-tests refuse to leave the
  error state on a backend that is not a validated module.
- Do **not** set `AWS_LC_SYS_NO_ASM=1` for a build you intend to use in
  approved mode: it builds a different AWS-LC implementation from the
  validated configuration. (It is only a workaround for Windows development
  machines without an assembler toolchain.)
- Key generation and signing tooling: [release-signing.md](release-signing.md#module-self-integrity-signature).

## 2. Configuration

A `fips` build **ignores `craton_hsm.toml` and `CRATON_HSM_CONFIG` /
`CRATON_HSM_FIPS`** and uses hard-coded settings:

| Setting | Value |
|---|---|
| `fips_approved_only` | `true` |
| `enable_pqc` | `false` |
| `allow_weak_rsa` | `false` |
| `allow_sha1_signing` | `false` |
| `audit.enabled` | `true` |
| everything else | the documented defaults ([configuration-reference.md](configuration-reference.md)) |

Consequently token storage, audit log path, PIN policy and session limits
cannot be changed in a `fips` build; they use the defaults: the token is
**ephemeral** (`persist_objects = false`), and the storage directory
`craton_hsm_store` and audit log `craton_hsm_audit.jsonl` are relative to the
process working directory. Run the process from a dedicated, service-owned
working directory. Audit logging is fail-closed (`audit.fail_closed = true`).

### Effect of the approved-only policy

| Category | Allowed | Refused (`CKR_MECHANISM_INVALID`) |
|----------|---------|---------|
| Symmetric | AES-128/192/256: GCM (module-generated IVs), CBC, CBC-PAD, CTR, KW, KWP | — |
| RSA | 2048/3072/4096: key generation, PKCS#1 v1.5 and PSS signatures (hash-specific mechanisms), OAEP | RSA < 2048 |
| EC | ECDSA and ECDH on P-256/P-384 (ECDH only with an approved KDF; `CKD_NULL` refused) | other curves |
| EdDSA | Ed25519 (FIPS 186-5) | — |
| Digest | SHA-256/384/512, SHA3-256/384/512 | SHA-1 (also as a plain digest) |
| PQC | — | ML-KEM, ML-DSA, SLH-DSA (algorithms approved by FIPS 203/204/205, but these implementations are pre-release and not validated) |

No HMAC mechanism is offered to callers in any mode.

---

## 3. Software integrity verification

The module verifies an **Ed25519 signature** over the SHA-256 digest of its
own library file at every `C_Initialize`. The signature is read from the
`.sig` sidecar next to the library (`libcraton_hsm.so` → `libcraton_hsm.sig`,
`craton_hsm.dll` → `craton_hsm.sig`); the public key is compiled in.

| Scenario | `fips` build |
|----------|--------------|
| `.sig` valid | pass |
| library or `.sig` modified | self-test fails, error state |
| `.sig` missing | self-test fails, error state |
| public key not embedded at build time | self-test fails, error state |
| module path cannot be determined | self-test fails, error state |

Install the library and its `.sig` together, in a directory writable only by
administrators, and re-sign after every rebuild. There is no HMAC/`.hmac`
integrity mechanism any more; the old `compute-integrity-hmac` scripts have
been removed.

---

## 4. Approved-service indicator (IG 2.4.C)

**Not yet implemented as an API output.** What exists today:

- Each audit-log record for a cryptographic operation contains
  `"fips_approved": true|false`, a static classification of the mechanism.
  It does not reflect the backend or parameters actually used and is written
  to a log file, so it does not satisfy IG 2.4.C on its own.
- In a `fips` build every mechanism that `C_GetMechanismList` reports is an
  approved algorithm (non-approved ones are refused), which is the basis for
  the planned "approved-only mode" indicator.

Not implemented (do not rely on them): the session field
`last_operation_fips_approved` is never set, and the vendor attribute
`CKA_VENDOR_FIPS_APPROVED` is never returned. There is currently no way to
query through `C_GetInfo` whether the library is an approved-only build;
identify it by the release asset name (`…-fips`) and verify the artefact
signature.

---

## 5. Self-tests

- **Pre-operational:** SHA-256, SHA-512 and Ed25519 self-tests, then the
  integrity test (§3).
- **Algorithm self-tests (CASTs):** fixed-vector known-answer tests for SHA-2,
  SHA-3, HMAC, HMAC_DRBG, HKDF/one-step KDF, PBKDF2, AES-GCM/CBC/CTR/KW/KWP,
  RSA, ECDSA, ECDH, Ed25519, ML-KEM, ML-DSA and SLH-DSA; backend algorithms are
  tested through the AWS-LC backend itself. Full list:
  [fips-140-3-certification.md §9](fips-140-3-certification.md#9-self-tests).
- **Conditional:** pair-wise consistency test after every key-pair
  generation; entropy health tests; DRBG continuous test.

### Error state

If any self-test fails, the module enters the error state: every function
that reaches module state returns `CKR_GENERAL_ERROR`. To recover, call
`C_Finalize` and then `C_Initialize` (or restart the process); the self-tests
run again and the module leaves the error state only if all of them pass. If
the failure persists, **do not rebuild from source on the production host** —
reinstall the signed release artefact and investigate the cause (see
[operator-runbook.md](operator-runbook.md)).

---

## 6. Deployment checklist

- [ ] Use the signed `…-fips` release artefact, or build with
      `-p craton-hsm --no-default-features --features fips` and an embedded
      integrity key, then sign the library.
- [ ] Verify the release (cosign bundle + `SHA256SUMS`) before installation.
- [ ] Install the library **and** its `.sig` in an administrator-only directory.
- [ ] `C_Initialize` returns `CKR_OK` (the integrity test and all CASTs passed).
- [ ] `pkcs11-tool --module ./libcraton_hsm.so --list-mechanisms` lists no
      PQC, SHA-1 or other non-approved mechanism.
- [ ] Initialise the token and set the User PIN **interactively** (do not put
      PINs on the command line or in shell history):
      `pkcs11-tool --module ./libcraton_hsm.so --init-token --label "Production"`
      then `pkcs11-tool --module ./libcraton_hsm.so --login --login-type so --init-pin`
      (both prompt for the PINs). PINs must be 8–64 characters with at least
      two character classes.
- [ ] Do not use the gRPC daemon or admin CLI in a deployment that must stay
      within the module boundary (they are outside it).
- [ ] Disable core dumps for processes that load the module.
- [ ] Review the audit log periodically.
