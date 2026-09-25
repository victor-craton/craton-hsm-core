# Operator Runbook

This runbook covers day-to-day operations for Craton HSM administrators: token setup, PIN management, key lifecycle, audit, daemon operations, and troubleshooting.

> The admin CLI prompts for every PIN and passphrase; never pass them as
> arguments. The subcommands below match `craton-hsm-admin --help`; run
> `craton-hsm-admin <command> --help` for all options. The admin CLI links the
> library directly and is outside the module's cryptographic boundary; it
> records its administrative actions in the audit log.

### Before using the admin CLI

- Point it at the **same configuration file** as the service it administers
  (`--config`, default `/etc/craton_hsm/craton_hsm.toml` on Unix). Relative
  paths in that file are resolved against the file's directory.
- The token must be **persistent** (`[token] persist_objects = true`, see
  [configuration-reference.md](configuration-reference.md#persistent-storage)).
  With an ephemeral token the CLI refuses every command that would have no
  lasting effect (exit code 5, "not supported in standalone mode").
- The persistent store and the audit log are **single-writer**: stop the
  daemon (or any application that has the library loaded with that store)
  before running mutating commands (`token init`, `pin`, `key`, `backup`,
  `restore`). The CLI fails instead of waiting if the store is locked.
- Exit codes are listed at the end of `craton-hsm-admin --help`.

## Token Initialization

### First-time setup

```bash
# 1. Initialize the token with a Security Officer (SO) PIN
craton-hsm-admin token init --label "Production HSM"
# Prompts for the new SO PIN (8-64 characters, at least two character classes)

# 2. Set the User PIN (SO authentication required)
craton-hsm-admin pin reset

# 3. Verify
craton-hsm-admin token info
craton-hsm-admin status
```

The same can be done through any PKCS#11 tool, e.g.
`pkcs11-tool --module /path/to/libcraton_hsm.so --init-token --label "Production HSM"`
followed by `pkcs11-tool --module ... --login --login-type so --init-pin`
(both prompt for PINs).

### Re-initialization

Re-initializing a token destroys all objects of that token and its PINs.
It requires the current SO PIN and fails with `CKR_SESSION_EXISTS` while
sessions are open on the slot.

```bash
craton-hsm-admin token init --label "Production HSM"
# Asks for typed confirmation and the current SO PIN
```

## PIN Management

### PIN requirements

| Property | Default | Config key |
|----------|---------|------------|
| Minimum length | 8 | `security.pin_min_length` |
| Maximum length | 64 | `security.pin_max_length` |
| Composition | at least 3 distinct characters; ASCII PINs need at least 2 character classes (lower, upper, digit, other) | not configurable |
| Lockout threshold | 5 consecutive failed attempts (User and SO PIN separately, per slot; persisted) | `security.max_failed_logins` |
| Back-off | exponential after each failure, 100 ms doubling to at most 5 s | not configurable |
| Hash algorithm | PBKDF2-HMAC-SHA256 | not configurable |
| Hash iterations | 600,000 | `security.pbkdf2_iterations` |

There is no default PIN.

### Change SO PIN

```bash
craton-hsm-admin pin change --user-type so
# Prompts: current SO PIN, new SO PIN, confirmation
```

### Change User PIN

```bash
craton-hsm-admin pin change --user-type user
# Prompts: current User PIN, new User PIN, confirmation
```

### Reset a locked User PIN (SO action)

After `max_failed_logins` consecutive failures, the User PIN is locked. Only
the SO can set a new one.

```bash
craton-hsm-admin pin reset
# Prompts: SO PIN, new User PIN, confirmation
```

### PIN lockout recovery

1. Identify the lockout: the application receives `CKR_PIN_LOCKED`
2. The SO sets a new User PIN: `craton-hsm-admin pin reset` (or `C_InitPIN` from any PKCS#11 tool)
3. Communicate the new PIN to the user through a secure channel

A locked **SO** PIN cannot be reset through the PKCS#11 API, and it also
blocks `C_InitToken` (SO-PIN guesses through InitToken count toward the SO
lockout). Recovery is out of band: with the service stopped, an operator with
file-system access removes that slot's persistent store (`storage_path`),
which destroys all of its keys, and initialises the token again. Restore keys
from a backup afterwards.

## Key Management

### List keys

```bash
craton-hsm-admin key list                 # as the User (default)
craton-hsm-admin key list --role so       # objects visible to the SO
```

### Import a key

The admin CLI imports raw AES keys (16, 24 or 32 bytes) as sensitive token
objects. Import other key types through a PKCS#11 application
(`C_CreateObject` / `C_UnwrapKey`), preferably wrapped.

```bash
craton-hsm-admin key import --file aes.key --label "Data Encryption" --type aes
```

### Delete a key

```bash
craton-hsm-admin key delete --handle 42 --role user
# Asks for typed confirmation
```

### Key lifecycle states (SP 800-57)

Craton HSM supports date-based key lifecycle management per SP 800-57:

| State | When | Permitted Operations |
|-------|------|---------------------|
| **Pre-activation** | Before `CKA_START_DATE` | None |
| **Active** | Between start and end dates | All permitted operations |
| **Deactivated** | After `CKA_END_DATE` | Verify, decrypt, unwrap only |
| **Compromised** | Manually set | None |
| **Destroyed** | After `C_DestroyObject` | Handle invalid |

Set lifecycle dates at key creation:
```bash
# Via C_CreateObject or C_GenerateKey template:
# CKA_START_DATE = "20260301" (YYYYMMDD, 8 ASCII bytes)
# CKA_END_DATE   = "20270301"
```

**Important**: Deactivated keys can still verify signatures and decrypt data (for processing existing protected data), but cannot create new signatures or encrypt new data.

### Key lifecycle best practices

1. **Label keys clearly**: include purpose and creation date
2. **Set expiry dates**: use `CKA_END_DATE` to enforce key rotation schedules
3. **Rotate regularly**: create new key, re-encrypt data, destroy old key
4. **Separate duties**: SO manages PINs; users manage their own keys
5. **Audit key operations**: check audit log for unexpected create/destroy events
6. **Back up before deletion**: export public key before destroying key pair

## Backup and Restore

Backups are encrypted with a key derived from a passphrase you are prompted
for (PBKDF2, iteration count from `security.pbkdf2_iterations`, stored in the
authenticated header). They contain the token objects of the slot; by
default **non-extractable keys are not exported**. A backup is bound to the
token's random identity, and every backup ID can be restored only once
(replay guard `.craton_hsm_replay_guard` in the store directory).

```bash
# Create (SO login; refuses to overwrite unless --force)
craton-hsm-admin backup --output /secure/backups/hsm-2026-09-25.rhbk

# Check a backup without restoring it (nothing is consumed)
craton-hsm-admin restore --input /secure/backups/hsm-2026-09-25.rhbk --verify-only

# Restore (SO login; objects get fresh handles)
craton-hsm-admin restore --input /secure/backups/hsm-2026-09-25.rhbk
```

Store backup files and passphrases separately. Older (v1) backup files are
rejected.

## Audit Log

### View audit entries

```bash
# Last 100 entries (SO login required)
craton-hsm-admin audit dump --last 100

# Verify the hash chain of the persisted log (and rotated generations)
craton-hsm-admin audit verify-chain

# Export for processing / SIEM ingestion
craton-hsm-admin audit export-json
craton-hsm-admin audit export-ndjson
craton-hsm-admin audit export-syslog
```

### Audit log structure

The log (`audit.log_path`) is NDJSON; each entry contains:
- **seq**: monotonic sequence number
- **timestamp**: Unix epoch (seconds)
- **session_handle**: which session performed the operation
- **operation**: what was done (Login, GenerateKey, Sign, InitToken, ...)
- **key_id**: the key involved, if any (the daemon and admin CLI prefix the
  client identity / admin action here)
- **result**: Success or Failure with the CK_RV code
- **previous_hash**: chain value of the previous entry

### Integrity verification

The log is a **keyed** chain: `H_n = HMAC-SHA256(K, H_{n-1} || entry_n)` with
the key `K` in `audit.key_path` (default `<log_path>.key`, mode 0600, never
written to the log). A MAC-protected anchor file `<log_path>.anchor` records
the last sequence number and chain value, so truncation or deletion is
detected. The module verifies the chain at start-up and refuses to start on a
broken chain unless `audit.allow_start_with_broken_chain = true`.

- Verify offline with `craton-hsm-admin audit verify-chain` (needs read
  access to the key file; run it where the key is available, not next to a
  running writer).
- Keep the key file readable only by the service account and the auditor who
  verifies; anyone with both the key and write access to the log can
  recompute the chain. Forward the events to an off-host append-only system
  (syslog/SIEM) for stronger guarantees.
- Rotated generations (`<log_path>.1`, ...) are chained to each other and are
  verified oldest to newest.

## Daemon Operations

### Start the daemon

```bash
# The configuration file path is the first argument (default: craton_hsm.toml
# in the working directory; /etc/craton-hsm/craton_hsm.toml in the container).
# The file must exist, be owned by the service user or root, and must not be
# group/world-writable. Unknown keys are fatal.
craton-hsm-daemon /etc/craton-hsm/craton_hsm.toml
```

Start-up order: strict config parse and validation → self-tests (POST) →
open the (persistent) core → TLS set-up → listen. `SIGTERM`/`SIGINT` stop
accepting connections, drain in-flight requests, close sessions and flush the
audit log before exiting.

### Configuration (`[daemon]` section)

Minimal production configuration (TLS 1.3 + mutual TLS; all keys are
documented in [configuration-reference.md](configuration-reference.md#daemon-grpc-server-craton-hsm-daemon-only)):

```toml
[token]
persist_objects = true
storage_path = "/var/lib/craton-hsm/store"

[audit]
log_path = "/var/log/craton-hsm/audit.jsonl"

[daemon]
bind = "0.0.0.0:5696"
tls_cert = "/etc/craton-hsm-tls/tls.crt"
tls_key = "/etc/craton-hsm-tls/tls.key"
tls_client_ca = "/etc/craton-hsm-client-ca/ca.crt"
# Administrator certificates (InitToken, InitPin, SO login):
admin_client_cert_sha256 = ["<sha256 of the admin client certificate DER>"]
health_bind = "127.0.0.1:5697"
```

### Health check

```bash
# Plaintext grpc.health.v1 endpoint on health_bind (serves nothing else)
grpc_health_probe -addr=127.0.0.1:5697
grpcurl -plaintext 127.0.0.1:5697 grpc.health.v1.Health/Check

# The service port itself requires a client certificate
grpcurl -cacert ca.crt -cert client.crt -key client.key \
  hsm.example.com:5696 craton_hsm.HsmService/GetTokenInfo
```

### TLS setup (testing)

```bash
# Server certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout tls.key -out tls.crt -days 365 -nodes -subj "/CN=craton-hsm"
# Client CA + a client certificate signed by it (one per client identity)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout client-ca.key -out client-ca.crt -days 365 -nodes -subj "/CN=craton-hsm-client-ca"
# Fingerprint for admin_client_cert_sha256
openssl x509 -in admin.crt -outform DER | sha256sum
```

Each client certificate is a separate identity: sessions, login state, session
and object quotas are per identity. Revoke client certificates with
`tls_client_crl` (reloaded every `tls_client_crl_reload_secs`).

### Daemon as systemd service

```ini
# /etc/systemd/system/craton-hsm.service
[Unit]
Description=Craton HSM gRPC Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/craton-hsm-daemon /etc/craton-hsm/craton_hsm.toml
User=craton-hsm
Group=craton-hsm
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=45

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/craton-hsm /var/log/craton-hsm
PrivateTmp=true
LimitCORE=0

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now craton-hsm
sudo systemctl status craton-hsm
journalctl -u craton-hsm -f
```

## Kubernetes Operations

### Deploy

```bash
# Chart: deploy/helm/craton-hsm (TLS and mTLS are required by default; see install.md)
helm install my-hsm deploy/helm/craton-hsm/ \
  --set image.repository=registry.example.com/craton-hsm \
  --set image.digest=sha256:<digest> \
  --set tls.secretName=craton-hsm-tls \
  --set tls.clientCaSecretName=craton-hsm-client-ca \
  --set 'tls.adminCertSha256={<admin cert sha256>}'
```

The chart renders a single `craton_hsm.toml` (ConfigMap, mounted at
`/etc/craton-hsm/craton_hsm.toml`); the `[security]` values are part of it
(there is no separate `security.toml`). The working directory is the PVC at
`/data` (relative `storage_path`/`log_path` live there); the pod runs as UID
65532; the plaintext health port is 5697 (`daemon.healthPort`); the
deployment strategy is `Recreate` because the store is single-writer. CI
checks that the rendered configuration is accepted by the daemon.

### Monitor

```bash
# Logs (JSON by default in the chart: daemon.logFormat)
kubectl logs -l app.kubernetes.io/instance=my-hsm -f

# Status
kubectl get pods -l app.kubernetes.io/instance=my-hsm
```

### Upgrade

```bash
helm upgrade my-hsm deploy/helm/craton-hsm/ \
  --reuse-values --set image.digest=sha256:<new digest>
```

## Troubleshooting

### Self-test failure (module error state)

**Symptom**: `C_Initialize` fails, or all PKCS#11 calls return `CKR_GENERAL_ERROR`.

**Cause**: A pre-operational or conditional self-test failed (software
integrity test, an algorithm self-test, a pair-wise consistency test, or an
entropy/DRBG health test). The log names the failing test.

**Actions** (do **not** rebuild from source on the production host — that
produces an unsigned library whose integrity test is skipped):
1. Integrity failure: verify the installed library against the release
   `SHA256SUMS` / cosign bundle (see `docs/release-signing.md`) and make sure
   the matching `.sig` sidecar sits next to it. Reinstall the signed release
   artefact if they differ, and treat an unexplained modification as a
   security incident.
2. Algorithm or health-test failure: reinstall the signed release artefact;
   if it persists on that host, suspect the platform (hardware, OS RNG) and
   report it to the maintainers.
3. Recover by calling `C_Finalize` and then `C_Initialize` (or restarting the
   process); the module leaves the error state only if all self-tests pass.

### PIN locked

**Symptom**: `CKR_PIN_LOCKED` on `C_Login`.

**Action**: Have the SO set a new User PIN (`C_InitPIN`), for example:
```bash
pkcs11-tool --module /path/to/libcraton_hsm.so --login --login-type so --init-pin
# prompts for the SO PIN and the new User PIN
```

### Session exhaustion

**Symptom**: `CKR_SESSION_COUNT` when opening sessions.

**Actions**:
1. Close unused sessions from the application side
2. Check for session leaks (sessions opened but never closed)
3. Increase `max_sessions` in config

### Token not initialized

**Symptom**: `CKR_TOKEN_NOT_RECOGNIZED` or empty slot info.

**Action**:
```bash
craton-hsm-admin token init --label "My Token"
```

### Daemon: connection refused

**Checklist**:
1. Is the daemon running? `ps aux | grep craton-hsm-daemon`
2. Correct bind address? Check `[daemon].bind` in config
3. Firewall rules? Port 5696 must be open
4. TLS mismatch? Client must use TLS if server has it enabled

### Daemon: TLS handshake failure

**Checklist**:
1. Certificate and key match? Compare modulus hashes
2. Certificate expired? `openssl x509 -in tls.crt -enddate -noout`
3. Client trusts the CA? Add the CA cert to client's trust store

### Object store empty after restart

**Causes**:
1. The token is ephemeral (`persist_objects = false`, the default): all
   state is lost when the process exits. Enable persistence:
   ```toml
   [token]
   persist_objects = true
   storage_path = "/var/lib/craton-hsm/store"
   ```
2. Persistent token, but nobody has logged in yet: token objects of a slot
   (also public ones) are loaded only after the first successful login on
   that slot after start-up (the slot's storage key is wrapped under the PINs).
3. Records that are not listed in the authenticated manifest are quarantined
   (logged as "replay/resurrection"); investigate before doing anything else.

### Slow RSA key generation

RSA-3072 and RSA-4096 key generation is CPU-intensive (seconds in debug mode, faster in release).

**Mitigation**: Always use `--release` builds in production. Pre-generate keys during maintenance windows if possible.
