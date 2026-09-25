# FIPS 140-3 Audit Scope

This page is a short orientation for auditors. The normative definitions are
in the draft Security Policy [fips-140-3-certification.md](fips-140-3-certification.md);
readiness status is in [fips-gap-analysis.md](fips-gap-analysis.md).

## Cryptographic module boundary

The module is the shared-library file built from the `craton-hsm` package,
plus its `.sig` integrity sidecar; its only interface is the PKCS#11 C API.
The full definition (inside/outside tables) is
[fips-140-3-certification.md §1.5](fips-140-3-certification.md#15-module-boundary-canonical-definition).

- **Inside:** everything compiled into the library — `src/pkcs11_abi/`,
  `src/crypto/`, `src/store/`, `src/session/`, `src/token/`, `src/audit/`,
  `src/config/`, `src/core.rs`, and the statically linked crates.
- **Outside:** `craton-hsm-daemon/` and `tools/craton-hsm-admin/` (separate
  executables that link the Rust library directly and therefore bypass the
  module's C-API controls), `tools/pkcs11-spy/`, `deploy/`, `benches/`,
  `tests/`, `fuzz/`.
- **Ports and interfaces:** the PKCS#11 C API only. The daemon's gRPC API is
  **not** a module interface.

## Algorithm inventory

"Approved" below refers to the NIST status of the *algorithm*. None of the
implementations listed has a CAVP certificate in this configuration; see
[fips-gap-analysis.md](fips-gap-analysis.md) (A1-03).

| Algorithm | Standard | Sizes | RustCrypto implementation | Approved algorithm? |
|-----------|----------|-------|---------------------------|---------------------|
| AES-GCM | SP 800-38D | 128/192/256 | `aes-gcm` 0.10 | Yes |
| AES-CBC, AES-CBC-PAD | SP 800-38A | 128/192/256 | `aes` 0.8 + `cbc` 0.1 | Yes |
| AES-CTR | SP 800-38A | 128/192/256 | `aes` 0.8 + `ctr` 0.9 | Yes |
| AES-KW / KWP | SP 800-38F | 128/192/256 | `aes-kw` 0.2 | Yes |
| RSA PKCS#1 v1.5 / PSS signatures, OAEP | FIPS 186-5, SP 800-56B | 2048/3072/4096 | `rsa` 0.9 | Yes (Marvin side channel: RUSTSEC-2023-0071, not mitigated) |
| ECDSA P-256/P-384 | FIPS 186-5 | — | `p256`/`p384` 0.13 | Yes |
| ECDH P-256/P-384 + KDF | SP 800-56A r3 / 56C r2 | — | `p256`/`p384`, `hkdf` | Yes |
| Ed25519 | FIPS 186-5 | — | `ed25519-dalek` 2 | Yes |
| SHA-256/384/512 | FIPS 180-4 | — | `sha2` 0.10 | Yes |
| SHA3-256/384/512 | FIPS 202 | — | `sha3` 0.10 | Yes |
| HMAC-SHA-256/384/512 (internal only; no HMAC mechanism is offered) | FIPS 198-1 | — | `hmac` 0.12 | Yes |
| PBKDF2-HMAC-SHA-256 (PIN verification and PIN-derived KEKs) | SP 800-132 | — | `pbkdf2` 0.12 | Yes |
| HMAC_DRBG (SHA-256) | SP 800-90A | — | in-tree (`src/crypto/drbg.rs`) | Yes |
| ML-KEM-512/768/1024 | FIPS 203 | — | `ml-kem` 0.3.0-rc.0 (pre-release) | Algorithm yes; not offered in approved mode |
| ML-DSA-44/65/87 | FIPS 204 | — | `ml-dsa` 0.1.0-rc.7 (pre-release) | Algorithm yes; not offered in approved mode |
| SLH-DSA-SHA2-128s/256s | FIPS 205 | — | `slh-dsa` 0.2.0-rc.4 (pre-release) | Algorithm yes; not offered in approved mode |
| SHA-1 | FIPS 180-4 | — | `sha1` 0.10 | Digest only; refused in approved mode |

With the `awslc-backend` feature, the classical primitives listed in
[fips-140-3-certification.md Appendix A](fips-140-3-certification.md#appendix-a-mechanism-table)
are executed by AWS-LC instead.

The authoritative mechanism list is `supported_mechanisms()` in
`src/crypto/mechanisms.rs`; do not rely on counts in documents.

## Self-tests

See [fips-140-3-certification.md §9](fips-140-3-certification.md#9-self-tests):
SHA-256/SHA-512/Ed25519 self-tests, then the Ed25519 software-integrity
test, then fixed-vector CASTs for every algorithm family (through the
selected backend), pair-wise consistency tests on key-pair generation, and
entropy/DRBG health tests. There is no HMAC-based integrity test.

## Test evidence

- All 35 integration test files in `tests/` are executed by CI; the CI job
  fails if a new test file is not scheduled. Obtain the current test inventory
  with `cargo test -- --list` rather than from counts in documents.
- `tests/zeroization.rs` runs in CI (serially). It inspects memory after
  drop, which is best-effort evidence rather than proof.
- `tests/multipart_sign_verify.rs` and `tests/multipart_encrypt_decrypt.rs`
  each contain one broad scenario test.

## Fuzzing

Twelve cargo-fuzz targets live in `fuzz/fuzz_targets/`:

| Target | Focus |
|---|---|
| `fuzz_c_abi` | random PKCS#11 call sequences with fuzzed arguments |
| `fuzz_crypto_ops` | encrypt/decrypt/digest with fuzzed data and parameters |
| `fuzz_attributes` | template construction and attribute values |
| `fuzz_session_lifecycle` | session/login state machine |
| `fuzz_buffer_overflow` | two-call pattern, null pointers, extreme lengths |
| `fuzz_rsa_ops` | RSA sign/verify/encrypt/decrypt with fuzzed inputs |
| `fuzz_keygen` | key generation with malformed templates/parameters |
| `fuzz_wrap_unwrap` | key wrapping/unwrapping |
| `fuzz_multipart_crypto` | multi-part operations |
| `fuzz_derive_key` | key derivation parameters |
| `fuzz_set_attribute` | `C_SetAttributeValue` on existing objects |
| `fuzz_init_token` | `C_InitToken` / PIN handling |

The authenticated targets provision the token with policy-compliant PINs
(`fuzz/fuzz_targets/common.rs`) so that logged-in code paths are reached.
CI builds all targets and runs each for 60 seconds on every pull request:

```bash
cargo +nightly fuzz run --fuzz-dir fuzz <target> -- -max_total_time=60
```

Longer campaigns (hours per target) are a manual activity and are not
currently scheduled.

## Size

| Property | Value |
|----------|-------|
| Module type | Software, Level 1 target |
| Ports and interfaces | PKCS#11 C API |
| Rust source in `src/` | about 19 000 lines (about 15 000 non-blank, non-comment) as of 2026-09 |
| Key storage | in memory (zeroized on free); optional encrypted persistence |
