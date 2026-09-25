# Craton HSM

[![CI](https://github.com/craton-co/craton-hsm-core/actions/workflows/ci.yml/badge.svg)](https://github.com/craton-co/craton-hsm-core/actions/workflows/ci.yml)
[![Security Audit](https://github.com/craton-co/craton-hsm-core/actions/workflows/security-audit.yml/badge.svg)](https://github.com/craton-co/craton-hsm-core/actions/workflows/security-audit.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
<!-- Badges below will activate after crates.io publish and Codecov setup -->
[![Crates.io](https://img.shields.io/crates/v/craton-hsm.svg)](https://crates.io/crates/craton-hsm)
[![docs.rs](https://docs.rs/craton-hsm/badge.svg)](https://docs.rs/craton-hsm)
[![codecov](https://codecov.io/gh/craton-co/craton-hsm-core/branch/main/graph/badge.svg)](https://codecov.io/gh/craton-co/craton-hsm-core)

> **Not FIPS 140-3 validated.** This software has not undergone CMVP
> validation and, as of the 2026-09 readiness assessment, is not ready to be
> submitted (see [FIPS Gap Analysis](docs/fips-gap-analysis.md)). Do not use it
> where a FIPS 140-3 validated module is required.

A PKCS#11 (Cryptoki) software token ("software HSM") written in Rust.

## Overview

Craton HSM implements the PKCS#11 Cryptographic Token Interface as a shared
library with the standard C ABI, so PKCS#11-aware applications (OpenSC
`pkcs11-tool`, OpenSSL providers/engines, Java SunPKCS11, NSS, …) can load it
as a cryptographic token.

**PKCS#11 version.** The library exports the complete PKCS#11 **v2.40**
function set through `C_GetFunctionList` and the v3.0 interface-discovery
functions `C_GetInterfaceList` / `C_GetInterface`. The other functions
introduced in v3.0 (`C_LoginUser`, `C_SessionCancel`, the message-based
`C_Message*` / `C_*Message*` API) are **not implemented**. See
[API Reference](docs/api-reference.md) for the exact list, including the
v2.40 functions that return `CKR_FUNCTION_NOT_SUPPORTED`.

### Key Features

- **PKCS#11 C ABI**: the 68 PKCS#11 v2.40 entry points plus v3.0 interface discovery
- **Classical cryptography**: RSA (2048/3072/4096), ECDSA and ECDH (P-256/P-384), EdDSA (Ed25519), AES (GCM/CBC/CTR, key wrap), SHA-1/SHA-2/SHA-3 digests
- **Post-quantum cryptography** (vendor-defined mechanisms): ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA-SHA2-128s/256s. *The PQC crates are pre-release (release-candidate) versions, pinned exactly, with no independent audit history, no stability guarantee (encodings may change between candidates) and no CAVP validation; PQC is disabled in approved-only mode and `fips` builds. See [Security Model](docs/security-model.md#pre-release-post-quantum-crates) and [FIPS Gap Analysis](docs/fips-gap-analysis.md).*
- **Multi-part operations**: streaming sign/verify and encrypt/decrypt
- **SP 800-90A HMAC_DRBG** (HMAC-SHA-256, prediction resistance) used for key generation and `C_GenerateRandom`; seeded from the operating-system RNG (the entropy source is not SP 800-90B/ESV validated)
- **Power-on self-tests**: Ed25519 software-integrity test plus known-answer self-tests (see [FIPS 140-3 document §9](docs/fips-140-3-certification.md#9-self-tests) for the exact list); pairwise-consistency tests on every key-pair generation
- **SP 800-57 key lifecycle**: date-based activation/deactivation
- **Memory hardening**: mlock/VirtualLock for key material (best effort), zeroize-on-drop, constant-time PIN comparison
- **Audit log** with a keyed HMAC-SHA256 hash chain and a MAC-protected anchor (tamper-evident against anyone without the audit key; forward it off-host for stronger guarantees)
- **Crypto backends**: RustCrypto (default) and an in-tree AWS-LC backend (`awslc-backend` feature, Apache-2.0, in this repository); not every service is routed through AWS-LC yet
- **Encrypted persistent storage** of token objects (`persist_objects = true`): redb + per-object AES-256-GCM
- **gRPC daemon** (`craton-hsm-daemon`) with mutual TLS and per-client authorization — *outside* the module's cryptographic boundary
- **Admin CLI** (`craton-hsm-admin`) for token management, PIN operations and diagnostics — *outside* the module's cryptographic boundary

## Quick Start

### Prerequisites

- Rust: the repository pins the toolchain in `rust-toolchain.toml` (currently
  1.94.1, installed automatically by `rustup`). The minimum supported Rust
  version (MSRV) is **1.89**, dictated by the locked dependencies.
- `protoc` (only for the gRPC daemon).
- CMake, Clang and Go (only for the optional `awslc-backend` feature).

### Build

```bash
# Default build (RustCrypto backend)
cargo build --release --locked
```

### Test

```bash
# ABI tests share a process-wide PKCS#11 singleton and must run single-threaded
cargo test --locked -- --test-threads=1
```

### Use as a PKCS#11 Library

```bash
cargo build --release --locked --lib
# Output: target/release/libcraton_hsm.so (Linux) / craton_hsm.dll (Windows) / libcraton_hsm.dylib (macOS)
```

Point your PKCS#11 consumer at the library:

```bash
pkcs11-tool --module /path/to/libcraton_hsm.so --list-slots
```

Prefer the signed release artefacts for production: they embed the
integrity-verification key and ship the `.sig` sidecar, so the software
integrity self-test is enforced (see [Release Signing](docs/release-signing.md)).

## Architecture

```
craton-hsm/
  src/
    core.rs            - HsmCore: central state shared by all interfaces
    pkcs11_abi/        - C ABI layer (types, constants, exported functions)
    session/           - Session management
    token/             - Token/slot management, PIN lifecycle
    store/             - Object storage, encrypted persistence, key material
    crypto/            - Cryptographic operations, backends, DRBG, self-tests
    audit/             - Append-only audit log with hash chain
    error.rs           - HsmError -> CK_RV mapping
  craton-hsm-daemon/   - gRPC server with mutual TLS
  tools/
    craton-hsm-admin/  - Admin CLI (clap)
    pkcs11-spy/        - PKCS#11 spy/logging wrapper
  fuzz/                - cargo-fuzz targets (12)
  deploy/              - Dockerfile + Helm chart
  docs/                - Architecture, security model, FIPS documents, runbooks
  tests/               - Integration test suites
  benches/             - Criterion benchmarks
```

## Crypto Backend Selection

| Backend | Feature flag | Location | Validation status |
|---------|--------------|----------|-------------------|
| **RustCrypto** (default) | `rustcrypto-backend` | This repo | Not validated (no CAVP certificates) |
| **AWS-LC** | `awslc-backend` | This repo (`src/crypto/awslc_backend.rs`, Apache-2.0) | Links the AWS-LC FIPS module (`aws-lc-fips-sys`); Craton HSM itself is **not** validated, and several services (multi-part sign/verify, PBKDF2, HKDF, PQC, self-tests) still use RustCrypto code |

The backend is chosen with `crypto_backend` in `craton_hsm.toml`, or
injected programmatically with `HsmCore::new_with_backend()`.

## Security Model

- **Memory protection**: key material is mlock'd where the OS allows it and zeroized on drop
- **PIN security**: PBKDF2-HMAC-SHA-256 (600 000 iterations), constant-time comparison, configurable lockout
- **Self-tests**: power-on self-tests run inside `C_Initialize` before any service is available; a failure puts the module in an error state
- **Integrity**: released libraries verify an Ed25519 signature over their own file at every `C_Initialize`
- **Audit trail**: security-relevant operations are logged with a keyed HMAC-SHA256 hash chain
- **Key lifecycle**: SP 800-57 states (pre-activation, active, deactivated, compromised)

Known limitations are tracked in [FIPS Gap Analysis](docs/fips-gap-analysis.md)
and [Security Model](docs/security-model.md) (for example the unmitigated
RSA timing side channel in the RustCrypto `rsa` crate, RUSTSEC-2023-0071).

## FIPS 140-3 Status

Craton HSM is **not** FIPS 140-3 validated and has not been submitted to a
CMVP laboratory. [docs/fips-gap-analysis.md](docs/fips-gap-analysis.md) lists
the remaining blockers, and
[docs/fips-140-3-certification.md](docs/fips-140-3-certification.md) is the
draft security policy describing what the code does today.

## Documentation

- [Documentation Index](docs/README.md) — full documentation table of contents
- [Installation Guide](docs/install.md) — build, test, deploy, configure
- [API Reference](docs/api-reference.md) — PKCS#11 C ABI functions and Rust library API
- [Examples](docs/examples.md) — usage with pkcs11-tool, OpenSSL, Python, Java
- [Configuration Reference](docs/configuration-reference.md) — all `craton_hsm.toml` fields, defaults, and examples
- [Architecture Overview](docs/architecture.md) — module diagram, source layout, data flow
- [Security Model](docs/security-model.md) — threat model, key protection, access control
- [Release Signing](docs/release-signing.md) — release artefacts and how to verify them
- [Troubleshooting](docs/troubleshooting.md) — common errors, build issues, runtime problems
- [FAQ](docs/faq.md) — frequently asked questions
- [Migration Guide](docs/migration-guide.md) — version upgrade instructions
- [FIPS Gap Analysis](docs/fips-gap-analysis.md) — certification readiness assessment
- [Operator Runbook](docs/operator-runbook.md) — day-to-day operations
- [Tested Platforms](docs/tested-platforms.md) — platform support matrix, CI pipeline
- [Changelog](CHANGELOG.md) — version history
- [Roadmap](ROADMAP.md) — completed phases and future directions
- [Governance](GOVERNANCE.md) — decision-making, roles, contribution process
- [Security Policy (vulnerability reporting)](SECURITY.md)

## Disclaimer

**Craton HSM is NOT FIPS 140-3 validated.** It implements several FIPS 140-3
Level 1 technical mechanisms (self-tests, pairwise-consistency tests, an
approved-only policy switch), but the readiness assessment found blocking gaps
(unvalidated algorithm implementations, no validated entropy source,
incomplete self-tests, no API-visible approved-service indicator). Use at your
own risk.

## License

Copyright 2026 Craton Software Company. Licensed under the
[Apache License, Version 2.0](LICENSE). Third-party components are listed in
[NOTICE](NOTICE) and, for release artefacts, in `THIRD-PARTY-LICENSES.txt`.

### Related Repositories

| Repository | License | Contents |
|-----------|---------|----------|
| [craton-hsm-core](https://github.com/craton-co/craton-hsm-core) | Apache-2.0 | Core PKCS#11 library (including the in-tree AWS-LC backend), daemon, CLI, tooling |
| [craton-hsm-core-enterprise](https://github.com/craton-co/craton-hsm-core-enterprise) | BSL 1.1 | Commercial add-ons (see that repository). |
