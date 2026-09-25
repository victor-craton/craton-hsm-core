# API Reference

Craton HSM exposes two primary interfaces: a **PKCS#11 C ABI** (the standard way to consume it) and a **Rust library API** (for embedding directly in Rust programs).

## PKCS#11 C ABI

The shared library (`libcraton_hsm.so` / `craton_hsm.dll` / `libcraton_hsm.dylib`) exports the 68 functions of the PKCS#11 **v2.40** `CK_FUNCTION_LIST` (returned by `C_GetFunctionList`) plus the PKCS#11 v3.0 interface-discovery functions `C_GetInterfaceList` and `C_GetInterface`, which describe the `"PKCS 11"` interface.

**Not implemented:** the other functions added in PKCS#11 v3.0 — `C_LoginUser`, `C_SessionCancel` and the message-based API (`C_MessageEncryptInit`, `C_EncryptMessage*`, `C_DecryptMessage*`, `C_MessageSign*`, `C_MessageVerify*`). Several v2.40 functions are exported but not supported (see [Unsupported functions](#unsupported-functions)).

Any PKCS#11-aware consumer (OpenSSL engines, Java SunPKCS11, Firefox NSS, `pkcs11-tool`, etc.) can load the library directly.

### Loading the Library

```bash
# pkcs11-tool (OpenSC)
pkcs11-tool --module /path/to/libcraton_hsm.so --list-slots

# OpenSSL (via engine or provider)
export PKCS11_MODULE_PATH=/path/to/libcraton_hsm.so

# Python (PyKCS11)
import PyKCS11
lib = PyKCS11.PyKCS11Lib()
lib.load("/path/to/libcraton_hsm.so")
```

### Exported Functions

#### Initialization

| Function | Description |
|----------|-------------|
| `C_Initialize` | Initialize the Cryptoki library (runs POST self-tests) |
| `C_Finalize` | Clean up and release resources |
| `C_GetInfo` | Return library version and manufacturer info |
| `C_GetFunctionList` | Return the v2.40 function pointer table |
| `C_GetInterfaceList` | (v3.0) List the available interfaces |
| `C_GetInterface` | (v3.0) Return a named interface (`"PKCS 11"`) |

#### Slot and Token Management

| Function | Description |
|----------|-------------|
| `C_GetSlotList` | Enumerate available slots |
| `C_GetSlotInfo` | Query slot properties |
| `C_GetTokenInfo` | Query token label, serial, flags, capabilities |
| `C_GetMechanismList` | List the mechanisms permitted by the active policy |
| `C_GetMechanismInfo` | Query min/max key size, supported operations |
| `C_InitToken` | Initialize token with SO PIN and label |

#### Session Management

| Function | Description |
|----------|-------------|
| `C_OpenSession` | Open a new session (R/O or R/W) |
| `C_CloseSession` | Close a session |
| `C_CloseAllSessions` | Close all sessions on a slot |
| `C_GetSessionInfo` | Query session state and flags |
| `C_Login` | Authenticate as User or SO |
| `C_Logout` | End authenticated session |

#### PIN Management

| Function | Description |
|----------|-------------|
| `C_InitPIN` | SO initializes user PIN |
| `C_SetPIN` | Change user or SO PIN |

#### Object Management

| Function | Description |
|----------|-------------|
| `C_CreateObject` | Create an object from a template |
| `C_DestroyObject` | Delete an object |
| `C_CopyObject` | Duplicate an object with template overrides |
| `C_GetObjectSize` | Query object storage size |
| `C_GetAttributeValue` | Read object attributes |
| `C_SetAttributeValue` | Modify object attributes (if CKA_MODIFIABLE) |
| `C_FindObjectsInit` | Begin object search by template |
| `C_FindObjects` | Iterate search results |
| `C_FindObjectsFinal` | End object search |

#### Key Generation

| Function | Description |
|----------|-------------|
| `C_GenerateKey` | Generate an AES key (`CKM_AES_KEY_GEN`) |
| `C_GenerateKeyPair` | Generate an asymmetric key pair (RSA, EC, Ed25519, ML-DSA, SLH-DSA, ML-KEM); a pair-wise consistency test runs on every new pair |

#### Signing and Verification

| Function | Description |
|----------|-------------|
| `C_SignInit` | Initialize a signing operation |
| `C_Sign` | Single-part sign |
| `C_SignUpdate` | Multi-part sign (streaming) |
| `C_SignFinal` | Finalize multi-part sign |
| `C_VerifyInit` | Initialize a verification operation |
| `C_Verify` | Single-part verify |
| `C_VerifyUpdate` | Multi-part verify (streaming) |
| `C_VerifyFinal` | Finalize multi-part verify |

#### Encryption and Decryption

| Function | Description |
|----------|-------------|
| `C_EncryptInit` | Initialize encryption |
| `C_Encrypt` | Single-part encrypt |
| `C_EncryptUpdate` | Multi-part encrypt (streaming) |
| `C_EncryptFinal` | Finalize multi-part encrypt |
| `C_DecryptInit` | Initialize decryption |
| `C_Decrypt` | Single-part decrypt |
| `C_DecryptUpdate` | Multi-part decrypt (streaming) |
| `C_DecryptFinal` | Finalize multi-part decrypt |

#### Digesting

| Function | Description |
|----------|-------------|
| `C_DigestInit` | Initialize a digest operation |
| `C_Digest` | Single-part digest |
| `C_DigestUpdate` | Multi-part digest (streaming) |
| `C_DigestFinal` | Finalize multi-part digest |
| `C_DigestKey` | Include a key's value in the digest |

#### Key Wrapping

| Function | Description |
|----------|-------------|
| `C_WrapKey` | Export an extractable key encrypted under another key (AES KW/KWP, RSA-OAEP) |
| `C_UnwrapKey` | Import a wrapped key |

#### Key Derivation

| Function | Description |
|----------|-------------|
| `C_DeriveKey` | Derive a new key: ECDH (`CK_ECDH1_DERIVE_PARAMS`, KDF per SP 800-56C; `CKD_NULL` refused in approved mode) and ML-KEM encapsulation/decapsulation |

#### Random Number Generation

| Function | Description |
|----------|-------------|
| `C_GenerateRandom` | Random bytes from the module's SP 800-90A HMAC_DRBG (AWS-LC's DRBG with the AWS-LC backend) |
| `C_SeedRandom` | Not supported: returns `CKR_RANDOM_SEED_NOT_SUPPORTED` (the DRBG reseeds itself from the OS entropy source) |

#### Operation State

| Function | Description |
|----------|-------------|
| `C_GetOperationState` | Serialize the active operation (HMAC-authenticated, **not encrypted**; contains accumulated input of multi-part operations and key handles, never key values; valid only within the same process) |
| `C_SetOperationState` | Restore a serialized operation |

#### Unsupported functions

| Function | Return value |
|----------|--------------|
| `C_SignRecoverInit`, `C_SignRecover`, `C_VerifyRecoverInit`, `C_VerifyRecover` | `CKR_FUNCTION_NOT_SUPPORTED` |
| `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate` | `CKR_FUNCTION_NOT_SUPPORTED` |
| `C_WaitForSlotEvent` | `CKR_FUNCTION_NOT_SUPPORTED` |
| `C_GetFunctionStatus`, `C_CancelFunction` | `CKR_FUNCTION_NOT_PARALLEL` (legacy) |

### Supported Mechanisms

The authoritative list is `supported_mechanisms()` in
`src/crypto/mechanisms.rs`; `C_GetMechanismList` returns the subset
permitted by the active policy (e.g. no PQC or SHA-1 in approved mode).

| Category | Mechanisms | Notes |
|----------|-----------|-------|
| RSA | `CKM_RSA_PKCS_KEY_PAIR_GEN`, `CKM_RSA_PKCS` (sign/verify of a DER `DigestInfo`), `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`, `CKM_SHA512_RSA_PKCS`, `CKM_SHA256_RSA_PKCS_PSS`, `CKM_SHA384_RSA_PKCS_PSS`, `CKM_SHA512_RSA_PKCS_PSS`, `CKM_RSA_PKCS_OAEP` | Generic `CKM_RSA_PKCS_PSS` is not offered |
| EC | `CKM_EC_KEY_PAIR_GEN`, `CKM_ECDSA`, `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384`, `CKM_ECDSA_SHA512`, `CKM_ECDH1_DERIVE`, `CKM_ECDH1_COFACTOR_DERIVE` | P-256 and P-384; ECDSA signatures in the PKCS#11 raw `r ‖ s` format |
| EdDSA | `CKM_EDDSA` | Ed25519 |
| AES | `CKM_AES_KEY_GEN`, `CKM_AES_GCM`, `CKM_AES_CBC` (no padding), `CKM_AES_CBC_PAD` (PKCS#7), `CKM_AES_CTR`, `CKM_AES_KEY_WRAP` (RFC 3394), `CKM_AES_KEY_WRAP_KWP` (RFC 5649) | `CK_GCM_PARAMS` and `CK_AES_CTR_PARAMS` are honoured |
| Digest | `CKM_SHA_1`, `CKM_SHA256`, `CKM_SHA384`, `CKM_SHA512`, `CKM_SHA3_256`, `CKM_SHA3_384`, `CKM_SHA3_512` | |
| PQC (vendor-defined codes) | `CKM_ML_KEM_512`, `CKM_ML_KEM_768`, `CKM_ML_KEM_1024`, `CKM_ML_DSA_44`, `CKM_ML_DSA_65`, `CKM_ML_DSA_87`, `CKM_SLH_DSA_SHA2_128S`, `CKM_SLH_DSA_SHA2_256S` | Pre-release crates; not offered in approved mode |

No HMAC or hybrid KEM (e.g. X25519 + ML-KEM) mechanism exists.

## Rust Library API

When used as an `rlib` (Rust library), the public API is organized into the modules below.

> **Not a module interface.** The Rust API gives direct access to internal
> components. It bypasses the PKCS#11 layer's controls (the self-test gate,
> error state, role checks), is outside the cryptographic boundary defined in
> [fips-140-3-certification.md §1.5](fips-140-3-certification.md#15-module-boundary-canonical-definition),
> and is not covered by any FIPS claim. Embedders that construct `HsmCore`
> directly must run the self-tests themselves
> (`craton_hsm::crypto::self_test::run_post_with_backend`) and treat a failure
> as fatal. The API is not yet stable (pre-1.0).

### `craton_hsm::core` — Central State

```rust
use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;

// Configuration from CRATON_HSM_CONFIG / ./craton_hsm.toml (defaults if absent)
let config = HsmConfig::load()?;
let hsm = HsmCore::try_new(&config)?;

// Or from an explicit (relative) path, validated
let config = HsmConfig::load_from_path("craton_hsm.toml")?;
config.validate()?;
let hsm = HsmCore::try_new(&config)?;

// Custom crypto backend
let hsm = HsmCore::try_new_with_backend(&config, my_backend)?;
```

### `craton_hsm::config` — Configuration

```rust
use craton_hsm::config::config::{AlgorithmConfig, AuditConfig, HsmConfig, SecurityConfig, TokenConfig};

let config = HsmConfig::default();
let config = HsmConfig::load()?;                        // env var / default path
let config = HsmConfig::load_from_path("craton_hsm.toml")?;
config.validate()?;
```

See [Configuration Reference](configuration-reference.md) for all fields.

### `craton_hsm::error` — Error Types

```rust
use craton_hsm::error::{HsmError, HsmResult};
```

`HsmError` maps 1:1 to PKCS#11 `CK_RV` return codes. See [Troubleshooting](troubleshooting.md) for common errors.

### `craton_hsm::crypto` — Cryptographic Operations

The `CryptoBackend` trait defines all cryptographic operations:

```rust
use craton_hsm::crypto::backend::CryptoBackend;

// Backend is selected at HsmCore creation time:
// - Default: RustCrypto (pure Rust, not validated)
// - Optional: AWS-LC via the in-tree `awslc-backend` feature
//   (links the AWS-LC FIPS module; Craton HSM itself is not validated)
```

Sub-modules:
- `crypto::keygen` — key generation (RSA, EC, Ed25519, AES)
- `crypto::sign` — signing (RSA PKCS#1/PSS, ECDSA, EdDSA)
- `crypto::encrypt` — encryption (AES-GCM/CBC/CTR, RSA-OAEP)
- `crypto::digest` — hashing (SHA-1/2/3)
- `crypto::derive` — key derivation (ECDH + SP 800-56C KDFs)
- `crypto::wrap` — key wrapping (AES-KW RFC 3394, AES-KWP RFC 5649)
- `crypto::pqc` — post-quantum (ML-KEM, ML-DSA, SLH-DSA)
- `crypto::drbg` — SP 800-90A HMAC_DRBG
- `crypto::self_test` — pre-operational self-tests and the module error state
- `crypto::integrity` — Ed25519 software-integrity test
- `crypto::pairwise_test` — pairwise consistency tests

### `craton_hsm::store` — Object Storage

```rust
use craton_hsm::store::object::StoredObject;
use craton_hsm::store::attributes::ObjectStore;
use craton_hsm::store::key_material::RawKeyMaterial;
use craton_hsm::store::encrypted_store::EncryptedStore;
```

### `craton_hsm::session` — Session Management

```rust
use craton_hsm::session::manager::SessionManager;
use craton_hsm::session::session::{Session, SessionState};
```

### `craton_hsm::token` — Token Management

```rust
use craton_hsm::token::token::Token;
use craton_hsm::token::slot::SlotManager;
```

### `craton_hsm::audit` — Audit Logging

```rust
use craton_hsm::audit::log::{AuditLog, AuditOperation, AuditResult};
```

## Generated Rustdoc

Full Rust API documentation with type signatures is available via:

```bash
cargo doc --open --no-deps
```

Or online at [docs.rs/craton-hsm](https://docs.rs/craton-hsm) (after crates.io publication).
