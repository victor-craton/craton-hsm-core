# Configuration Reference

Craton HSM is configured via a TOML file. By default, the library looks for `craton_hsm.toml` in the current working directory. Override the path with the `CRATON_HSM_CONFIG` environment variable (it must be a relative path).

If the config file is not found, the library uses the defaults below. If the file exists but cannot be parsed or fails validation, `C_Initialize` fails (the module refuses to start with potentially misconfigured security parameters).

Approved-only settings:

- **`fips` build** (`--features fips`): configuration files and environment
  variables are ignored; hard-coded settings are used (see
  [FIPS Mode Guide](fips-mode-guide.md)). This is the only mode that cannot be
  changed at run time.
- **`CRATON_HSM_FIPS=1`** on a default build: loads the same hard-coded
  approved-only settings instead of the file, but it is **advisory only** —
  anyone who controls the process environment can unset it.

The gRPC daemon reads the same file format from the path given as its first
argument, plus a mandatory `[daemon]` section (see below).

### Configuration Validation (v0.9.1)

The following validation rules are enforced on load:
- `storage_path` and `log_path`: must be relative, no `..` traversal, no UNC paths (`\\server\share`), no null bytes
- `pin_min_length` ≥ 4; `pin_max_length` ≥ `pin_min_length`
- `pbkdf2_iterations` ≥ 100,000
- `max_failed_logins`: 3–100 (prevents accidental lockout or brute-force)
- `serial_number`: 1–16 ASCII printable characters
- `slot_count` ≥ 1
- `crypto_backend`: must be `"rustcrypto"` or `"awslc"`
- `log_level`: must be `"all"`, `"crypto"`, `"auth"`, `"admin"`, or `"none"`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CRATON_HSM_CONFIG` | `craton_hsm.toml` | Path to the library configuration file (relative) |
| `CRATON_HSM_FIPS` | unset | `1` = use the hard-coded approved-only settings (advisory; see above) |

## `[token]` — Token & Slot Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `label` | string | `"Craton HSM Token 0"` | Token display name (returned by `C_GetTokenInfo`) |
| `storage_path` | string | `"craton_hsm_store"` | Path to the redb persistent storage database. Must be relative (no absolute paths, no `..` traversal, no UNC paths). |
| `max_sessions` | integer | `100` | Maximum concurrent PKCS#11 sessions |
| `max_rw_sessions` | integer | `10` | Maximum read-write sessions |
| `persist_objects` | bool | `false` | Persist token objects (`CKA_TOKEN = true`) in the redb database at `storage_path`. Each record is AES-256-GCM-encrypted under a random per-slot key, which is stored only wrapped under PIN-derived keys; objects become readable after login. Session objects are never persisted. |
| `slot_count` | integer | `1` | Number of virtual slots to expose (must be ≥ 1) |
| `serial_number` | string | `"0000000000000001"` | Token serial number (max 16 chars, ASCII printable) |

## `[security]` — PIN & Authentication

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pin_min_length` | integer | `8` | Minimum PIN length in bytes (must be ≥ 4) |
| `pin_max_length` | integer | `64` | Maximum PIN length in bytes (must be ≥ pin_min_length) |
| `max_failed_logins` | integer | `10` | Failed login attempts before PIN lockout (range: 3–100) |
| `pbkdf2_iterations` | integer | `600000` | PBKDF2-HMAC-SHA256 iterations for PIN hashing (must be ≥ 100,000; SP 800-132) |

## `[algorithms]` — Cryptographic Policy

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `crypto_backend` | string | `"rustcrypto"` | Crypto backend: `"rustcrypto"` (default) or `"awslc"` (requires building with the in-tree `awslc-backend` feature) |
| `fips_approved_only` | bool | `false` | Refuse mechanisms that are not approved algorithms (policy switch; not a validated approved mode — see [FIPS Mode Guide](fips-mode-guide.md)) |
| `enable_pqc` | bool | `true` | Enable post-quantum mechanisms (ML-KEM, ML-DSA, SLH-DSA) |
| `allow_weak_rsa` | bool | `false` | Allow RSA key sizes below 2048 bits |
| `allow_sha1_signing` | bool | `false` | Allow SHA-1 in signing contexts (deprecated per SP 800-131A) |

### FIPS Approved Mode

When `fips_approved_only = true`:

**Allowed**: RSA (>= 2048), ECDSA and ECDH (P-256, P-384; ECDH only with an approved KDF), Ed25519, AES (GCM/CBC/CBC-PAD/CTR/KW/KWP), SHA-256/384/512, SHA3-256/384/512

**Blocked**: SHA-1 (also as a plain digest), all PQC mechanisms, RSA < 2048

See [FIPS Mode Guide](fips-mode-guide.md) for deployment details.

## `[audit]` — Audit Logging

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable audit logging (hash-chained; the chain is unkeyed) |
| `log_path` | string | `"craton_hsm_audit.jsonl"` | Path to the append-only audit log file |
| `log_level` | string | `"all"` | Log verbosity: `"all"`, `"crypto"`, `"auth"`, `"admin"`, or `"none"` |

## `[daemon]` — gRPC Server (craton-hsm-daemon only)

The daemon is outside the module's cryptographic boundary. Its configuration
file is mandatory (a missing or invalid file is fatal), unknown keys in
`[daemon]` are rejected, and the daemon refuses to listen in plaintext on a
non-loopback address. The main fields are listed below; the doc comments on
`DaemonConfig` in `craton-hsm-daemon/src/config.rs` are the authoritative and
complete list (limits, timeouts, connection caps).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind` | string | `"127.0.0.1:5696"` | gRPC listen address and port |
| `tls_cert` | string | *(none)* | PEM server certificate |
| `tls_key` | string | *(none)* | PEM server private key |
| `tls_client_ca` | string | *(none)* | PEM CA certificate(s) for verifying client certificates (mutual TLS). Required unless `allow_no_client_auth = true` |
| `tls_client_crl` | string or list | `[]` | CRL file(s) for client certificates |
| `allow_no_client_auth` | bool | `false` | Explicitly run TLS without client authentication (not recommended) |
| `admin_client_cert_sha256` | list of strings | `[]` | SHA-256 fingerprints of client certificates allowed to perform administrator operations (InitToken, SO login, InitPin) |
| `allow_insecure` | bool | `false` | Plaintext on a loopback address — development only |
| `max_login_attempts`, `login_cooldown_secs` | integer | see source | Daemon-level throttling of failed logins per client, slot and role |

## Example: Default Configuration

```toml
[token]
label = "Craton HSM Token 0"
storage_path = "craton_hsm_store"
max_sessions = 100
max_rw_sessions = 10
persist_objects = false
slot_count = 1

[security]
pin_min_length = 8
pin_max_length = 64
max_failed_logins = 10
pbkdf2_iterations = 600000

[algorithms]
crypto_backend = "rustcrypto"
fips_approved_only = false
enable_pqc = true
allow_weak_rsa = false
allow_sha1_signing = false

[audit]
enabled = true
log_path = "craton_hsm_audit.jsonl"
log_level = "all"
```

## Example: approved-only policy on a default build (development / testing)

For production use of the approved-only settings build with `--features fips`
(the file below is then ignored). On a default build this policy is
advisory and does not make the module FIPS-validated.

```toml
[algorithms]
crypto_backend = "awslc"        # requires the awslc-backend feature
fips_approved_only = true
enable_pqc = false
allow_weak_rsa = false
allow_sha1_signing = false

[security]
pbkdf2_iterations = 600000
max_failed_logins = 5

[audit]
enabled = true
log_level = "all"
```

## Example: High-Session Server

```toml
[token]
max_sessions = 1000
max_rw_sessions = 100
persist_objects = true
slot_count = 4
```
