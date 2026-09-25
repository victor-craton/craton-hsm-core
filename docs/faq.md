# Frequently Asked Questions

## General

### Is Craton HSM FIPS 140-3 certified?

**No.** Craton HSM implements several FIPS 140-3 Level 1 mechanisms (self-tests, an approved-only build, an SP 800-90A DRBG, pair-wise consistency tests, an Ed25519 module-integrity check), but it has **not** undergone CMVP validation, and the 2026-09 readiness audit found blocking gaps (no validated algorithm implementations in use, no validated entropy source, no API-visible approved-service indicator). Do not rely on it where a validated module is required. See [FIPS Gap Analysis](fips-gap-analysis.md).

### Can I use Craton HSM in production?

Craton HSM is designed for production use as a software PKCS#11 provider. It includes memory hardening, tamper-evident audit logging, encrypted persistence, and comprehensive self-tests. However:

- It is a **software** HSM (FIPS Level 1) — it does not provide physical tamper resistance
- The PQC dependencies are at release candidate versions
- A third-party-style security audit (2026-09) found issues that are being remediated; check [FIPS Gap Analysis](fips-gap-analysis.md) and the CHANGELOG
- RSA private-key operations on the default RustCrypto backend are exposed to the Marvin timing side channel (RUSTSEC-2023-0071); use the AWS-LC backend if that matters for you

Evaluate your threat model and compliance requirements before deploying.

### How does Craton HSM compare to SoftHSMv2?

| Feature | Craton HSM | SoftHSMv2 |
|---------|---------|-----------|
| Language | Rust (memory-safe) | C++ |
| Post-quantum crypto | ML-KEM, ML-DSA, SLH-DSA | No |
| FIPS-style self-tests | Integrity test + known-answer self-tests at `C_Initialize` | No |
| Audit logging | Keyed HMAC-SHA256 chain with a MAC-protected anchor (detects modification, truncation and deletion; forward off-host against an attacker holding the key) | No |
| Key lifecycle (SP 800-57) | Yes | No |
| HMAC_DRBG (SP 800-90A) | Yes (prediction resistance) | No |
| Memory hardening | mlock + ZeroizeOnDrop | Partial |
| Multi-slot | Yes (up to 256) | Yes |
| Encrypted persistence | per-object AES-256-GCM, key wrapped under PBKDF2-derived keys | SQLite + AES |

See [Benchmarks](benchmarks.md) for performance comparisons.

### What PKCS#11 version does Craton HSM implement?

The PKCS#11 **v2.40** function set (68 functions via `C_GetFunctionList`) plus the v3.0 interface-discovery functions `C_GetInterfaceList` and `C_GetInterface`. The other v3.0 additions (`C_LoginUser`, `C_SessionCancel`, the message-based API) are not implemented, and a few v2.40 functions return `CKR_FUNCTION_NOT_SUPPORTED` (sign/verify-recover, dual-function updates, `C_WaitForSlotEvent`). See [API Reference](api-reference.md).

## Cryptography

### What algorithms are supported?

**Classical**:
- RSA: 2048/3072/4096-bit (PKCS#1 v1.5, PSS, OAEP)
- ECDSA: P-256, P-384
- EdDSA: Ed25519
- AES: 128/192/256-bit (GCM, CBC, CBC-PAD, CTR, Key Wrap KW/KWP)
- Digest: SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512
- Key agreement: ECDH (P-256/P-384) with a KDF per SP 800-56C
- No HMAC mechanism is offered to applications (HMAC is used internally)

**Post-Quantum** (NIST standards, RC crate versions):
- ML-KEM: 512, 768, 1024 (FIPS 203)
- ML-DSA: 44, 65, 87 (FIPS 204)
- SLH-DSA: SHA2-128s, SHA2-256s (FIPS 205)

### Are the PQC implementations stable?

The PQC crates (`ml-kem 0.3.0-rc.0`, `ml-dsa 0.1.0-rc.7`, `slh-dsa 0.2.0-rc.4`) are release candidates. Their APIs and key serialization formats may change before reaching 1.0. Keys generated with RC versions should be considered non-portable across major version bumps. See [Future Work Guide](future-work-guide.md) for the upgrade timeline.

### Why is SHA-1 available but restricted?

SHA-1 is available for digest operations (`C_Digest`) and signature verification (`C_Verify`) for backward compatibility, but is blocked for new signatures by default. This is controlled by `allow_sha1_signing` in the `[algorithms]` config section. In FIPS approved mode, SHA-1 is fully blocked.

### How is randomness generated?

All randomness goes through an SP 800-90A HMAC_DRBG (HMAC-SHA256) with:
- **One process-wide instance** serving key generation and `C_GenerateRandom` (AWS-LC's own DRBG when the AWS-LC backend is selected)
- **Prediction resistance**: fresh entropy input on every generate request
- **Entropy health tests**: repetition-count and adaptive-proportion tests on the OS entropy input
- **Continuous test** on DRBG output and a known-answer test at start-up
- The OS entropy source itself is not SP 800-90B / ESV validated

## Security

### How is key material protected?

1. **In memory**: Wrapped in `RawKeyMaterial` (`Vec<u8>` with mlock), locked to physical RAM via `mlock`/`VirtualLock`, zeroed on drop via `ZeroizeOnDrop`
2. **At rest** (only with `persist_objects = true`): each object encrypted with AES-256-GCM under a random per-slot key, which is stored only wrapped under keys derived from the SO/User PINs with PBKDF2 (600,000 iterations)
3. **In logs**: Never appears — `Debug` impl returns `[REDACTED]`
4. **In backups**: Encrypted with PIN-derived key (PBKDF2 + AES-256-GCM)

### What happens after too many failed PINs?

Failed login attempts trigger exponential backoff:
- Base delay: 100 ms, doubles per failure, capped at 5 seconds
- After `max_failed_logins` failures (default: 10), the account is locked
- A locked User PIN is reset by the SO (`C_InitPIN`); a locked SO PIN cannot be recovered through the API (the token must be re-created, destroying its keys)

### Does Craton HSM protect against side-channel attacks?

At the software level:
- **Constant-time PIN comparison** via `subtle::ConstantTimeEq`
- **Constant-time template matching** using bitwise accumulators (no early returns)
- **No secret-dependent branching** in the HSM logic layer

The underlying crypto libraries (RustCrypto, aws-lc-rs) have their own side-channel properties. Known gap: the RustCrypto `rsa` crate is affected by the Marvin timing attack (RUSTSEC-2023-0071) and has no fix; RSA decryption and signing on the default backend are exposed. See [Security Model](security-model.md).

## Operations

### Can multiple processes use Craton HSM simultaneously?

Not directly — the persistent store uses exclusive file locking. For multi-process access, use the **gRPC daemon** (`craton-hsm-daemon`) which serializes all access through a single HSM instance with mutual TLS authentication. See [Fork Safety](fork-safety.md) for deployment patterns.

### How do I back up token data?

```bash
# Export an encrypted backup (prompts for the SO PIN and a backup passphrase)
craton-hsm-admin backup --output backup.enc

# Restore from backup (prompts; --verify-only checks a backup without restoring)
craton-hsm-admin restore --input backup.enc
```

Backups are protected with a passphrase-derived key (PBKDF2 + AES-256-GCM).
The admin CLI is outside the module boundary. See `craton-hsm-admin --help`
and [Operator Runbook](operator-runbook.md).

### How do I run in a container?

A production Dockerfile is provided at `deploy/Dockerfile` using a distroless runtime image (no shell, non-root). A Helm chart is available at `deploy/helm/craton-hsm/`. See [Installation Guide](install.md) for details.

## Development

### Why must tests run single-threaded?

PKCS#11 defines a single global state per process (`C_Initialize` / `C_Finalize`). Running tests in parallel causes race conditions on this global state. Always use `cargo test -- --test-threads=1`.

### How do I add a new crypto mechanism?

1. Add the mechanism constant to `src/pkcs11_abi/constants.rs`
2. Register it in `src/crypto/mechanisms.rs` (validation + FIPS policy)
3. Implement the operation in the appropriate `src/crypto/` module
4. Add the `CryptoBackend` trait method in `src/crypto/backend.rs`
5. Implement for both backends (`rustcrypto_backend.rs`, `awslc_backend.rs`)
6. Wire it into the C ABI in `src/pkcs11_abi/functions.rs`
7. Add integration tests and update `C_GetMechanismList`/`C_GetMechanismInfo`

### How do I run the fuzz targets?

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run a specific target
cargo +nightly fuzz run fuzz_buffer_overflow

# Run with a time limit
cargo +nightly fuzz run fuzz_c_abi -- -max_total_time=300
```

See [Security Review Checklist](security-review-checklist.md) for fuzz target priorities.
