# Configuration Reference

Craton HSM is configured with a TOML file. The PKCS#11 library, the gRPC
daemon and the admin CLI all read the same four core sections (`[token]`,
`[security]`, `[algorithms]`, `[audit]`). The daemon also needs a `[daemon]`
section.

## Where the configuration comes from

### PKCS#11 library (`libcraton_hsm`)

On a **default build**, `C_Initialize` looks for configuration in this order:

1. The file named by `$CRATON_HSM_CONFIG`.
2. The system-wide file `/etc/craton-hsm/craton_hsm.toml`
   (`C:\ProgramData\craton-hsm\craton_hsm.toml` on Windows).
3. If neither exists, the built-in secure defaults listed below.

The library **never** reads `./craton_hsm.toml` from the working directory
(H3-13). A file left there is ignored and a warning is logged. If a file is
named explicitly but is missing, unreadable, fails to parse or fails
validation, `C_Initialize` fails. The module will not start with security
parameters that may be wrong.

The configuration file is opened without following symlinks. It must be
owned by the effective user or by root. It must not be group- or
world-writable. Its directory must not be writable by other users, and no
ancestor directory may be world-writable unless the sticky bit is set.

Settings for approved-only operation:

- **`fips` build** (`--no-default-features --features fips`): the library
  ignores configuration files and environment variables and uses hard-coded
  settings: approved algorithms only, no PQC, audit enabled and fail-closed,
  and the AWS-LC backend (see the [FIPS Mode Guide](fips-mode-guide.md)).
  This is the only mode that cannot be changed at run time.
- **`CRATON_HSM_FIPS=1`** on a default build: the library loads the same
  hard-coded approved-only settings instead of the file. This is **advisory
  only**: anyone who controls the process environment can unset it.

### gRPC daemon (`craton-hsm-daemon`)

The daemon takes the path of its configuration file as its first argument.
If no argument is given, it uses `craton_hsm.toml` in its working
directory. In the container image the path is
`/etc/craton-hsm/craton_hsm.toml`. The file must exist. The daemon parses it
strictly: an unknown top-level section or an unknown key in `[daemon]` stops
start-up. The ownership and permission checks above also apply.

### Admin CLI (`craton-hsm-admin`)

The admin CLI reads the file given by `--config`. On Unix the default is
`/etc/craton_hsm/craton_hsm.toml`, and on Windows it is
`C:\ProgramData\craton_hsm\craton_hsm.toml`. Relative paths inside the file
are resolved against the file's directory. See the [Operator
Runbook](operator-runbook.md).

## Validation rules

The following rules are checked when the configuration is loaded:

- **Paths** (`token.storage_path`, `audit.log_path`, `audit.key_path`):
  - **Absolute paths are allowed and recommended.** Use a directory owned by
    the service account, for example `/var/lib/craton-hsm`.
  - Relative paths are resolved against the process's working directory, and
    a warning is logged.
  - These paths are rejected:
    - system directories (`/etc`, `/bin`, `/sbin`, `/usr`, `/lib`, `/lib64`,
      `/boot`, `/dev`, `/proc`, `/sys`, and `C:\Windows`);
    - paths containing a `..` component;
    - UNC paths;
    - paths containing NUL bytes;
    - symlinks;
    - relative paths that start with `.git`, `.ssh`, `.gnupg`, `.aws`,
      `.config` or `.env`.
- `label`: 1–32 bytes of printable ASCII.
- `serial_number`: 1–16 printable ASCII characters.
- `pin_min_length` ≥ 4, `pin_max_length` ≥ `pin_min_length`, and
  `pin_max_length` ≤ 256.
- `pbkdf2_iterations`: 100,000–10,000,000.
- `max_failed_logins`: 3–100.
- `max_sessions`: 1–10,000. `max_rw_sessions`: 1 to `max_sessions`.
  `max_sessions_per_application` ≥ 1.
- `slot_count`: 1–256.
- `crypto_backend`: `"rustcrypto"` or `"awslc"`.
- `log_level`: `"all"`, `"crypto"`, `"auth"` or `"admin"`. There is no
  `"none"` level.
- `audit.enabled = false` is refused unless
  `audit.allow_disabled_insecure = true`.
- `fips_approved_only = true` cannot be combined with `allow_weak_rsa` or
  `allow_sha1_signing`, and it requires `audit.enabled = true`.

## Environment variables

| Variable | Read by | Description |
|----------|---------|-------------|
| `CRATON_HSM_CONFIG` | library | Path to the configuration file. Takes precedence over the system-wide file. The path rules above apply. |
| `CRATON_HSM_FIPS` | library (default builds) | `1` loads the hard-coded approved-only settings. Advisory only; see above. |
| `RUST_LOG` | daemon, admin CLI | Log level (`error`, `warn`, `info`, `debug`). The shipped binaries are compiled with `info` as the maximum level. |
| `CRATON_HSM_LOG_FORMAT` | daemon | Set to `json` for structured JSON logs (SIEM ingestion). |
| `CRATON_HSM_INTEGRITY_PUBLIC_KEY` | **build time** | 64 hex characters: the Ed25519 public key embedded for the software-integrity test. See [release-signing.md](release-signing.md). |

## `[token]`: token and slot settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `label` | string | `"Craton HSM Token 0"` | Token label returned by `C_GetTokenInfo`. |
| `storage_path` | path | `"craton_hsm_store"` | Directory of the persistent store (see *Persistent storage* below). Use an absolute, service-owned path. |
| `persist_objects` | bool | `false` | `true` makes the token **persistent**. Token state and token objects are stored encrypted under `storage_path` and reloaded at start-up. `false` makes the token **ephemeral**: everything is lost when the process exits and the token has to be initialised again. Use `false` for development only. |
| `max_sessions` | integer | `100` | Maximum concurrent sessions per token. |
| `max_rw_sessions` | integer | `10` | Maximum read/write sessions per token. |
| `max_sessions_per_application` | integer | `max_sessions` | Maximum sessions for one application. The C ABI counts per process; the daemon counts per client. |
| `slot_count` | integer | `1` | Number of slots. Each slot has its own token, PINs, lockout counters, storage key and objects. |
| `serial_number` | string | `"0000000000000001"` | Token serial number. Set a unique value for each deployment. |

### Persistent storage

With `persist_objects = true`:

- The store directory is created with mode `0700`. The redb database file is
  `craton_hsm.redb` (mode `0600`, opened with `O_NOFOLLOW`). The directory
  must be owned by the service account and must not be group- or
  world-writable.
- The store is protected by an **exclusive process lock**. Only one process
  can open a given store at a time: the daemon, the admin CLI or an
  application that loads the library. Stop the daemon before you run
  mutating admin CLI commands against its store.
- **Key hierarchy:**
  - Each slot has a random 256-bit data-encryption key (DEK), generated by
    `C_InitToken`.
  - Every token object is stored as an AES-256-GCM record under that DEK.
    The additional authenticated data (AAD) binds the record to its store
    key, slot, handle and generation.
  - A manifest, authenticated with HMAC-SHA256 under a DEK-derived key,
    lists every record and its generation. Records that are not in the
    manifest are quarantined and not loaded.
  - The DEK is stored only wrapped. It is wrapped under keys derived from
    **both** the SO PIN and the User PIN (PBKDF2-HMAC-SHA256 with
    `pbkdf2_iterations` and a random salt for each PIN). A PIN change wraps
    the DEK again.
  - `C_InitToken` generates a fresh DEK, which crypto-shreds all previous
    records of that slot.
- The first successful login on a slot after start-up unwraps the DEK and
  loads that slot's token objects. Until then, no token objects are visible
  on that slot, not even public ones. The unwrapped DEK stays in memory
  until `C_Finalize`, where it is zeroized. It is not cleared at logout.
- The token record is persisted: the initialised flag, label, PIN verifiers
  (with their KDF parameters), wrapped DEKs and a random token ID. The
  lockout counters for each slot are persisted too. A restart therefore does
  not make an initialised token uninitialised.
- **Limits:**
  - Restoring the whole database file together with the audit anchor from an
    older copy (rollback) cannot be detected without an external monotonic
    counter.
  - The lockout counters are not authenticated before login.
  - Treat the storage volume as sensitive, and back it up and restore it as
    a unit.

**Setup checklist:**

```bash
sudo install -d -m 0700 -o craton-hsm -g craton-hsm /var/lib/craton-hsm
sudo install -d -m 0750 -o craton-hsm -g craton-hsm /var/log/craton-hsm
```

```toml
[token]
persist_objects = true
storage_path = "/var/lib/craton-hsm/store"

[audit]
log_path = "/var/log/craton-hsm/audit.jsonl"
key_path = "/var/lib/craton-hsm/audit.key"   # not readable by log readers
```

Then initialise the token once, with the admin CLI or `C_InitToken`, and set
the User PIN (see the [Operator Runbook](operator-runbook.md)).

## `[security]`: PIN and authentication

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pin_min_length` | integer | `8` | Minimum PIN length in bytes (≥ 4). |
| `pin_max_length` | integer | `64` | Maximum PIN length in bytes (≤ 256). |
| `max_failed_logins` | integer | `5` | Consecutive failed logins before the User or SO PIN is locked (3–100). Failed SO-PIN checks in `C_InitToken` also count. |
| `pbkdf2_iterations` | integer | `600000` | PBKDF2-HMAC-SHA256 iterations for PIN verifiers and storage KEKs (100,000–10,000,000; SP 800-132). |

The PIN composition policy is fixed: at least 3 distinct characters, and
ASCII PINs need at least 2 character classes. There is no default PIN.

## `[algorithms]`: cryptographic policy

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `crypto_backend` | string | `"rustcrypto"` | `"rustcrypto"` or `"awslc"`. `"awslc"` needs a build with the in-tree `awslc-backend` feature. `fips` builds always use AWS-LC. |
| `fips_approved_only` | bool | `false` | Refuse mechanisms that are not approved. On a default build this is a policy switch, not a validated approved mode; see the [FIPS Mode Guide](fips-mode-guide.md). |
| `enable_pqc` | bool | `true` | Enable ML-KEM, ML-DSA and SLH-DSA. These use **pre-release crates**; see the [Security Model](security-model.md#pre-release-post-quantum-crates). |
| `allow_weak_rsa` | bool | `false` | Allow RSA keys shorter than 2048 bits. |
| `allow_sha1_signing` | bool | `false` | Allow SHA-1 in signatures (deprecated by SP 800-131A). |

### Approved-only policy

When `fips_approved_only = true`, the following are allowed:

- RSA with keys of at least 2048 bits;
- ECDSA and ECDH on P-256 and P-384 (ECDH only with an approved KDF;
  `CKD_NULL` is refused);
- Ed25519 (FIPS 186-5);
- AES: GCM with a module-generated IV, CBC, CBC-PAD, CTR, KW and KWP;
- SHA-256/384/512 and SHA3-256/384/512.

The following are blocked: SHA-1 (also as a plain digest), all PQC
mechanisms and RSA keys shorter than 2048 bits.

## `[audit]`: audit logging

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable the audit log. Disabling it requires `allow_disabled_insecure = true`. |
| `log_path` | path | `"craton_hsm_audit.jsonl"` | Append-only NDJSON audit log. Only one process may write a given log; `<log_path>.lock` enforces this. |
| `log_level` | string | `"all"` | `"all"` and `"crypto"` record every event. `"auth"` and `"admin"` record only the mandatory authentication, token-management and key-management events. |
| `key_path` | path | `<log_path>.key` | 256-bit HMAC key for the keyed hash chain (mode `0600`). Keep it where people who read the audit log or run backups cannot read it. |
| `fail_closed` | bool | `false` (`true` in `fips` builds) | After an event fails to be written durably, every further audited operation fails with `CKR_DEVICE_ERROR`. |
| `allow_start_with_broken_chain` | bool | `false` | Start even though the existing log fails verification. The default refuses to start. |
| `allow_disabled_insecure` | bool | `false` | Explicit acknowledgement required for `enabled = false`. |

The log is a **keyed** chain:
`H_n = HMAC-SHA256(K, H_{n-1} || event_n)`, where each event has a
monotonic sequence number. After every durable write, the module updates a
MAC-protected anchor file, `<log_path>.anchor`, so truncation or deletion of
the log is detected at the next start. Rotated generations (`<log_path>.1`,
and so on) are chained to each other. Anyone who holds both the key file and
the log can still rewrite history, so forward the events off-host (syslog or
SIEM).

## `[daemon]`: gRPC server (craton-hsm-daemon only)

The daemon is outside the module's cryptographic boundary. Its
configuration is mandatory, and the daemon rejects unknown keys. TLS 1.3
with **mutual TLS** is the default and expected setup. The authoritative
list is `DaemonConfig` in `craton-hsm-daemon/src/config.rs`. An annotated
example ships as `craton-hsm-daemon/craton_hsm.example.toml`.

### Listener and TLS

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind` | `IP:port` | `"127.0.0.1:5696"` | gRPC listen address. Must be a socket address, not a host name. |
| `tls_cert`, `tls_key` | path | *(none)* | PEM server certificate and private key. Set both or neither. |
| `tls_client_ca` | path | *(none)* | PEM CA bundle used to verify client certificates (mTLS). **Required** when TLS is on, unless `allow_no_client_auth = true`. |
| `tls_client_crl` | path or list of paths | `[]` | CRLs for client certificates, in PEM or DER. Requires `tls_client_ca`. |
| `tls_client_crl_reload_secs` | integer | `300` | How often the CRL files are read again (0–86,400; 0 disables reloading). |
| `allow_no_client_auth` | bool | `false` | Explicitly accept TLS clients that have no certificate. Not recommended. |
| `admin_client_cert_sha256` | list of strings | `[]` | SHA-256 fingerprints (hex, colons allowed) of client certificates that have the **administrator** role. Only administrators can call InitToken, InitPin or log in as SO. Requires `tls_client_ca`. Compute with `openssl x509 -in admin.crt -outform DER \| sha256sum`. |
| `allow_insecure` | bool | `false` | Plaintext gRPC. Allowed only when `bind` is a loopback address. Development only. |
| `insecure_loopback_admin` | bool | `false` | Development only: in plaintext loopback mode, treat every local client as an administrator. Invalid when TLS is on. |
| `health_bind` | `IP:port` | *(disabled)* | Optional plaintext listener that serves **only** `grpc.health.v1.Health`, for kubelet and Docker probes. |

### Request, connection and session limits

| Field | Default | Range | Description |
|-------|---------|-------|-------------|
| `max_request_bytes` | `1048576` | 4096–16 MiB | Maximum decoded size of one inbound message. |
| `max_response_bytes` | `4194304` | 4096–16 MiB | Maximum encoded size of one outbound message. |
| `max_random_length` | `65536` | 1 to `max_response_bytes` − 1024 | Maximum bytes per `GenerateRandom` request. |
| `max_digest_length` | `1047552` | 1 to `max_request_bytes` − 512 | Maximum input size of `Digest`. |
| `max_connections` | `128` | 1–65,536 | Open client connections, including TLS handshakes in progress. |
| `max_connections_per_ip` | `32` | 1 to `max_connections` | Connections from one source IP address. |
| `max_inflight_requests` | `32` | 1–4096 | Requests in flight across all connections. Excess requests are rejected with UNAVAILABLE. |
| `max_concurrent_streams` | `16` | 1–1024 | HTTP/2 streams per connection. |
| `request_timeout_secs` | `30` | 1–600 | Timeout for each request. |
| `handshake_timeout_secs` | `10` | 1–120 | Deadline for completing the TLS handshake. |
| `connection_idle_timeout_secs` | `300` | 0–86,400 | Close connections with no RPC for this long (0 disables). Sessions on a closed connection are closed too. |
| `max_connection_age_secs` | `0` | 0–30 days | Maximum connection lifetime (0 = unlimited). |
| `http2_keepalive_interval_secs` | `30` | 0–3600 | HTTP/2 PING interval (0 disables). |
| `http2_keepalive_timeout_secs` | `10` | 1–600 | Time to wait for the PING acknowledgement. |
| `max_sessions_per_client` | `16` | 1–10,000 | Open sessions per client identity. |
| `session_idle_timeout_secs` | `900` | 0–7 days | Close sessions that have not been used for this long (0 disables). |
| `max_objects_per_client` | `1024` | 1–10,000 | Live objects created through the daemon, per client identity. |
| `max_login_attempts` | `5` | 0–1000 | Failed PIN attempts per client, slot and role before a cooldown starts (0 disables the daemon throttle; the token lockout still applies). |
| `login_cooldown_secs` | `60` | 1–86,400 | Length of that cooldown. |
| `max_blocking_tasks` | `0` | 0–1024 | Concurrent CPU-bound operations such as PIN hashing, key generation and signing. 0 = number of CPUs. |

### Client-visible model

- Sessions belong to the client identity that opened them. Login state is
  kept per client and per slot.
- Closing a client's last session on a slot logs that client out on the
  slot. Sessions are closed when the client disconnects and after
  `session_idle_timeout_secs`.
- SO login, InitToken and InitPin require an administrator certificate.
  Key operations require `CKU_USER`.
- While the token state is ephemeral (`persist_objects = false`),
  `CKA_TOKEN = true` objects are refused.

## Example: minimal default configuration

This file is equivalent to the built-in defaults, except that it turns
persistence on:

```toml
[token]
label = "Craton HSM Token 0"
storage_path = "/var/lib/craton-hsm/store"
persist_objects = true
max_sessions = 100
max_rw_sessions = 10
slot_count = 1

[security]
pin_min_length = 8
pin_max_length = 64
max_failed_logins = 5
pbkdf2_iterations = 600000

[algorithms]
crypto_backend = "rustcrypto"
fips_approved_only = false
enable_pqc = true
allow_weak_rsa = false
allow_sha1_signing = false

[audit]
enabled = true
log_path = "/var/log/craton-hsm/audit.jsonl"
log_level = "all"
```

## Example: approved-only policy on a default build (development and testing)

For production approved-only operation, build with
`--no-default-features --features fips`; the build then ignores the file
below. On a default build, this policy is advisory and does not make the
module FIPS-validated.

```toml
[algorithms]
crypto_backend = "awslc"        # requires the awslc-backend feature
fips_approved_only = true
enable_pqc = false
allow_weak_rsa = false
allow_sha1_signing = false

[audit]
enabled = true
log_level = "all"
fail_closed = true
```

## Example: daemon with mTLS

```toml
[token]
storage_path = "/var/lib/craton-hsm/store"
persist_objects = true

[audit]
log_path = "/var/log/craton-hsm/audit.jsonl"

[daemon]
bind = "0.0.0.0:5696"
tls_cert = "/etc/craton-hsm-tls/tls.crt"
tls_key = "/etc/craton-hsm-tls/tls.key"
tls_client_ca = "/etc/craton-hsm-client-ca/ca.crt"
admin_client_cert_sha256 = ["<64 hex chars>"]
health_bind = "127.0.0.1:5697"
```
