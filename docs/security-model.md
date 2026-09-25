# Security Model

## Threat Model

Craton HSM is a software HSM. Unlike hardware HSMs, it does not protect against physical attacks or OS-level compromise. Its security boundary is the process.

### In scope (threats Craton HSM defends against)

| Threat | Defense |
|--------|---------|
| Memory corruption (buffer overflow, use-after-free) | Rust's ownership system prevents these at compile time |
| PIN brute-force | PBKDF2 (600K iterations) + configurable lockout after N failures |
| Timing side-channels on PIN comparison | `subtle::ConstantTimeEq` for all sensitive comparisons |
| Key material leakage via logging | Custom `Debug` impls print `[REDACTED]` for all key types |
| Key material leakage in memory after use | `ZeroizeOnDrop` on `RawKeyMaterial`; `mlock`/`VirtualLock` on key pages |
| Fork-induced state corruption | PID recorded at init; child gets `CKR_CRYPTOKI_NOT_INITIALIZED` |
| Database corruption from concurrent processes | Exclusive file lock on persistent store |
| Unauthorized key extraction | `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false` enforced |
| Unauthorized operations | Session state machine enforces login before private object access |
| Audit-log tampering | Keyed chain (HMAC-SHA256 under a separate 0600 key file) with a MAC-protected anchor: modification, reordering, truncation or deletion is detected at the next start; the module refuses to start on a broken chain unless explicitly allowed. Whoever can read the key file *and* write the log can still rewrite it, so forward events off-host |
| Panic-induced undefined behavior at FFI boundary | `catch_unwind` wraps every `extern "C"` export that touches module state |
| Use of weak algorithms | `allow_weak_rsa=false`, `allow_sha1_signing=false` by default |
| Corrupted or tampered library | Ed25519 software-integrity self-test at `C_Initialize` (in force for signed release builds; mandatory in `fips` builds) plus distribution signatures (cosign, SHA256SUMS, provenance). The known-answer self-tests detect broken algorithms, not tampering |
| AES-GCM nonce reuse (per key) | Module-generated random IVs in approved mode, per-key invocation limit (2^32, SP 800-38D §8.3) and rejection of recently seen (key, IV) pairs; CTR counter-range overlap detection |
| Configuration planting / path traversal | Configuration is never read from the working directory; config files must be owned by the user or root and not group/world-writable; `..`, UNC, symlink, sensitive-directory and system-directory paths are rejected |
| Key misuse after expiry | SP 800-57 key lifecycle: date-based deactivation blocks signing/encryption |

### Out of scope (threats requiring hardware HSM or OS hardening)

| Threat | Why out of scope |
|--------|-----------------|
| Cold boot attacks | Keys live in process memory; physical access can dump RAM |
| DMA attacks | No IOMMU enforcement at software level |
| OS kernel compromise | If the kernel is compromised, all process memory is accessible |
| Power analysis / EM side-channels | Software cannot prevent hardware-level leakage |
| Speculative execution attacks (Spectre) | Mitigations depend on CPU microcode and OS patches |

### Side-Channel Resistance

Craton HSM implements software-level side-channel countermeasures for timing attacks. Physical side-channels (power, electromagnetic) are out of scope for a software HSM.

**Constant-time operations:**

| Operation | Implementation | Side-Channel Defense |
|-----------|---------------|---------------------|
| PIN comparison | PBKDF2-HMAC-SHA256 + `subtle::ConstantTimeEq` | Timing-safe: compare time independent of correct/incorrect PIN bytes |
| HMAC verification | `subtle::ConstantTimeEq` on HMAC tags | Prevents byte-by-byte timing leakage of MAC values |
| RSA private-key operations (RustCrypto) | `rsa` crate | **Not constant time.** Affected by the Marvin attack (RUSTSEC-2023-0071, no fixed release; expected in `rsa` 0.10). Every private-key operation is base-blinded (`sign_with_rng`, `Pss::new_blinded`, `decrypt_blinded`) and there is no PKCS#1 v1.5 decryption service, which reduces but does **not** remove the exposure: the bignum arithmetic still leaks timing. `CKM_RSA_PKCS_OAEP` decryption and RSA signing on this backend remain exposed. `fips` builds use AWS-LC instead. |
| RSA signing (aws-lc-rs) | AWS-LC (BoringSSL fork) | Constant-time bignum arithmetic, same as Google/AWS production |
| ECDSA signing (RustCrypto) | `p256`/`p384` crates | Field arithmetic in constant time (no branching on secret scalars) |
| ECDSA signing (aws-lc-rs) | AWS-LC P-256/P-384 | Assembly-optimized constant-time point multiplication |
| AES operations | RustCrypto `aes` crate with AES-NI | Hardware AES-NI intrinsics are inherently constant-time (no table lookups) |
| SHA-256/384/512 | RustCrypto `sha2` crate | No secret-dependent branching; hardware SHA extensions when available |

**Backend-specific notes:**

- **RustCrypto backend** (default): Pure Rust implementations. RSA private-key operations are **not** timing-safe (see above); use the AWS-LC backend where timing attacks are in scope. ECC uses projective coordinates with complete addition formulas. AES uses AES-NI when available, falling back to a bitsliced implementation that avoids timing-leaky S-box table lookups.

- **aws-lc-rs backend** (`awslc-backend`): Assembly-optimized constant-time implementations from AWS-LC/BoringSSL. Battle-tested in AWS production. RSA uses constant-time modular exponentiation. ECC uses optimized P-256 and P-384 assembly with constant-time scalar multiplication. This is the same cryptographic core used by AWS KMS.

**What we do NOT claim:**
- Protection against cache-timing attacks on systems without AES-NI (extremely rare on modern hardware)
- Protection against speculative execution attacks (Spectre/Meltdown variants)
- Protection against physical side-channels (power analysis, EM emanations)
- Formally verified constant-time guarantees (would require tools like ct-verif or Jasmin)

## Key Protection

### Memory safety (Rust guarantees)

Rust eliminates at compile time the vulnerability classes responsible for the majority of memory-safety CVEs in C/C++ HSM implementations:

- **No buffer overflows**: array bounds are checked at runtime
- **No use-after-free**: the ownership system prevents accessing freed memory
- **No double-free**: memory is freed exactly once when the owner is dropped
- **No null pointer dereference**: `Option<T>` forces explicit handling
- **No data races**: the borrow checker prevents concurrent mutable access

The only `unsafe` code is in the PKCS#11 C ABI layer (`src/pkcs11_abi/functions.rs`) and the memory locking module (`src/crypto/mlock.rs`). All blocks are annotated with `// SAFETY:` comments explaining their correctness.

**Fork safety**: On Unix, Craton HSM detects `fork(2)` by comparing the current PID against the PID stored at `C_Initialize` time. A forked child process receives `CKR_CRYPTOKI_NOT_INITIALIZED` on any PKCS#11 call and must call `C_Initialize` to create fresh state. See `docs/fork-safety.md` for full details.

**Multi-process access**: Concurrent multi-process access to the same persistent database is prevented by an exclusive file lock acquired at initialization. For multi-process access to the same token, use the gRPC daemon (`craton-hsm-daemon`), which serializes all operations.

### Key material lifecycle

```
Generate / Import
       |
       v
  RawKeyMaterial::new(bytes)
  |  └── mlock(ptr, len)    <-- locks pages into physical RAM
  |  └── Debug: [REDACTED]  <-- never logs key bytes
  |
  |  Used via &[u8] borrow (never cloned unnecessarily)
  |
  v
  Crypto operation (sign, encrypt, etc.)
  |
  v
  Drop (manual impl):
  |  1. self.0.zeroize()     <-- clears all bytes to 0x00
  |  2. munlock(ptr, len)    <-- unlocks (now-zeroed) pages
```

**Platform support**:
- Unix: `libc::mlock` / `libc::munlock`
- Windows: `VirtualLock` / `VirtualUnlock` via `windows-sys`
- Failure is non-fatal (logged, continues) — may lack privileges for large buffers

### Access control model

PKCS#11 objects have three levels of protection:

1. **CKA_PRIVATE**: If `true`, object is invisible to `C_FindObjects` unless the session is logged in
2. **CKA_SENSITIVE**: If `true`, `CKA_VALUE` (key bytes) cannot be read via `C_GetAttributeValue`
3. **CKA_EXTRACTABLE**: If `false`, key material cannot be exported

Rules: `CKA_VALUE` is never returned in plaintext when `CKA_SENSITIVE=true` **or** `CKA_EXTRACTABLE=false`; only extractable keys can be wrapped. Default for generated keys: `PRIVATE=true, SENSITIVE=true, EXTRACTABLE=false` (maximum protection). Key-usage operations require the User role; an SO session cannot use keys.

### PIN security

| Property | Implementation |
|----------|---------------|
| Hash algorithm | PBKDF2-HMAC-SHA256 |
| Iterations | 600,000 (configurable) |
| Salt | 32 bytes from the module DRBG (per PIN, stored with the hash) |
| Comparison | `subtle::ConstantTimeEq` |
| Lockout | Configurable threshold (default: 5 failures), exponential back-off, lockout counters persisted per slot; `C_InitToken` SO-PIN checks count as well |
| PIN storage | Hash stored in `Zeroizing<Vec<u8>>` (zeroed on drop) |
| PIN in transit | Never logged; CLI uses `rpassword` (no terminal echo) |

## Audit Integrity

The audit log (`audit.log_path`, NDJSON) is a **keyed** hash chain
(src/audit/log.rs, H3-10/H3-11):

```
H_n = HMAC-SHA256(K, H_{n-1} || serialize(payload_n))    payload_n includes seq = n
```

- `K` is a random 256-bit key in a separate file (`audit.key_path`, default
  `<log_path>.key`, mode 0600) that is never written to the log.
- After every durable write a MAC-protected **anchor** (`<log_path>.anchor`:
  last sequence number and chain value) is replaced atomically, so tail
  truncation and deletion are detected on the next start.
- Rotation starts each generation with a `LogRotated` event chained to the
  previous generation.
- At start-up the chain is verified; on failure the module refuses to start
  unless `audit.allow_start_with_broken_chain = true`.
- Events go through a bounded queue with group-commit `fsync`;
  authentication and key-management events are recorded synchronously
  (`record_sync`). With `audit.fail_closed = true` (default in `fips`
  builds) a write failure makes further audited operations fail with
  `CKR_DEVICE_ERROR`.
- A single process may write a given log (`<log_path>.lock`).

Limits: whoever can read the key file **and** write the log can recompute the
chain, and restoring an older copy of log + anchor + key is a rollback that
needs an external monotonic counter to detect. Forward events off-host
(syslog/SIEM) for stronger guarantees.

## Algorithm Selection

### Supported algorithms

"Standard" names the specification; it does not mean the implementation is validated (see [fips-gap-analysis.md](fips-gap-analysis.md)). The PQC implementations are pre-release crates.

| Category | Algorithms | Standard |
|----------|-----------|----------|
| Symmetric encryption | AES-128/192/256 GCM, CBC, CBC-PAD, CTR | SP 800-38A/D |
| Key wrapping | AES Key Wrap (KW) and Key Wrap with Padding (KWP) | SP 800-38F (RFC 3394 / RFC 5649) |
| RSA signing | PKCS#1 v1.5, PSS (SHA-256/384/512) | FIPS 186-5 |
| RSA encryption | OAEP | PKCS#1 v2.2 / SP 800-56B |
| Elliptic curve | ECDSA P-256, P-384 | FIPS 186-5 |
| Edwards curve | Ed25519 | FIPS 186-5 / RFC 8032 |
| Key agreement | ECDH P-256, P-384 with SP 800-56C KDF | SP 800-56A / 56C |
| Hash | SHA-256, SHA-384, SHA-512 | FIPS 180-4 |
| Hash (SHA-3) | SHA3-256, SHA3-384, SHA3-512 | FIPS 202 |
| KDF | PBKDF2-HMAC-SHA256 (PIN verification, PIN-derived storage keys only) | SP 800-132 |
| PQC signing | ML-DSA-44/65/87 | FIPS 204 |
| PQC KEM | ML-KEM-512/768/1024 | FIPS 203 |
| PQC signing | SLH-DSA (SHA2-128s, SHA2-256s) | FIPS 205 |

### Pre-release post-quantum crates

ML-KEM, ML-DSA and SLH-DSA are implemented by the RustCrypto `ml-kem`
(`=0.3.0-rc.0`), `ml-dsa` (`=0.1.0-rc.7`) and `slh-dsa` (`=0.2.0-rc.4`)
crates. These are **release candidates without an independent audit
history**; they pull pre-release versions of `sha2`, `sha3`, `hmac` and the
RustCrypto trait crates that are not covered by the module's own SHA/HMAC
known-answer tests. Risks: undiscovered correctness or side-channel defects,
and API/encoding changes between release candidates (keys and signatures
created with one version might not be accepted by the next). Mitigations:
exact version pins (`=`) in `Cargo.toml`, Dependabot/cargo-deny review of
every bump, PQC CASTs in the POST (ML-KEM, ML-DSA; SLH-DSA verification only) and
pairwise consistency tests at key generation, vendor-defined mechanism
codes, and PQC is **blocked** in approved-only mode and in `fips` builds.
Set `algorithms.enable_pqc = false` if these risks are not acceptable.

### Restricted by default

| Setting | Default | Effect |
|---------|---------|--------|
| `allow_weak_rsa` | `false` | Blocks RSA key generation < 2048 bits |
| `allow_sha1_signing` | `false` | Blocks SHA-1 as a hash in signatures |

## FIPS 140-3 Readiness

### Power-On Self-Tests (POST)

Run during `C_Initialize`: SHA-2 and Ed25519 self-tests, the Ed25519 software-integrity test, then fixed-vector known-answer tests for every algorithm family (through the selected backend). If any test fails, the module enters the error state and every call that reaches module state returns `CKR_GENERAL_ERROR`; `C_Finalize` + `C_Initialize` re-runs the tests. Full list: [fips-140-3-certification.md §9](fips-140-3-certification.md#9-self-tests).

### SP 800-90A DRBG

All module randomness — key generation and `C_GenerateRandom` — comes from one process-wide HMAC_DRBG (HMAC-SHA256, SP 800-90A) with prediction resistance (AWS-LC's DRBG serves `C_GenerateRandom` with the AWS-LC backend). Entropy input from the OS passes repetition-count and adaptive-proportion health tests; a continuous test runs on DRBG output. The OS entropy source is not ESV-validated.

### SP 800-57 Key Lifecycle

Keys support date-based lifecycle states per SP 800-57: pre-activation (before `CKA_START_DATE`), active, deactivated (after `CKA_END_DATE`), compromised, and destroyed. Deactivated keys can still verify/decrypt but cannot sign/encrypt.

### FIPS crypto backend

Craton HSM supports two crypto backends, selectable via `algorithms.crypto_backend` in config:

| Backend | Feature Flag | FIPS Status |
|---------|-------------|-------------|
| RustCrypto (default) | `rustcrypto-backend` | Not FIPS-certified |
| AWS-LC (aws-lc-rs) | `awslc-backend` | Links the AWS-LC FIPS module; Craton HSM itself is not validated |

With `--features awslc-backend` and `crypto_backend = "awslc"`, the classical primitives of the `CryptoBackend` trait run on AWS-LC. Multi-part sign/verify, PBKDF2, HKDF, PQC and the integrity test still use RustCrypto code.

### Remaining gaps for formal FIPS certification

The module is **not ready** for submission. See `docs/fips-gap-analysis.md`: blocking items include validated implementations for every approved service, an ESV-validated entropy source, an API-visible approved-service indicator and ACVP testing on the claimed operational environments.

## Security Invariants

These 10 properties are verified at every development phase and must never be violated:

1. **No panic crosses FFI boundary** — `catch_unwind` on every `extern "C"` function that touches module state
2. **No key bytes in logs** — custom `Debug` impls with `[REDACTED]`
3. **No key bytes returned** in plaintext for objects with `CKA_SENSITIVE=true` or `CKA_EXTRACTABLE=false`
4. **Constant-time PIN/HMAC comparison** — `subtle::ConstantTimeEq` everywhere
5. **Key material zeroized on drop** — `RawKeyMaterial` and other key containers zeroize on drop; all volatile SSPs are released at `C_Finalize`
6. **Session state machine is authoritative** — check state, not just login flag
7. **Audit log written before operation returns** — not fire-and-forget async
8. **DRBG for all key material and random output** — SP 800-90A HMAC_DRBG for key generation and `C_GenerateRandom`; never `OsRng` directly or `rand::random()`
9. **Minimal, documented `unsafe`** — confined to the ABI layer, `mlock.rs`, module-path discovery in `integrity.rs`, digest zeroization in `digest.rs` and Windows ACL calls; every block carries a `// SAFETY:` comment
10. **Generic errors to callers** — never leak internal state via error messages
