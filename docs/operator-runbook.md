# Operator Runbook

This runbook covers day-to-day operations for Craton HSM administrators: token setup, PIN management, key lifecycle, audit, daemon operations, and troubleshooting.

> The admin CLI prompts for every PIN and passphrase; never pass them as
> arguments. The subcommands below match `craton-hsm-admin --help`; run
> `craton-hsm-admin <command> --help` for all options. The admin CLI links the
> library directly and is outside the module's cryptographic boundary; it
> records its administrative actions in the audit log.

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
| Lockout threshold | 10 consecutive failed attempts | `security.max_failed_logins` |
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

A locked **SO** PIN cannot be reset through the PKCS#11 API. The token's
persistent storage must be removed by the system administrator (destroying
all of its keys) and the token re-initialised.

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

Each entry contains:
- **timestamp**: Unix epoch (seconds)
- **session_handle**: which session performed the operation
- **operation**: what was done (Login, GenerateKey, Sign, etc.)
- **key_id**: which key was involved (if applicable)
- **result**: Success or Failure with CK_RV code
- **previous_hash**: SHA-256 of the prior entry (tamper detection)

### Integrity verification

The audit log uses chained SHA-256 hashes. Each entry's `previous_hash` equals `SHA-256(previous_entry)`. A broken chain means the log was modified or corrupted. The chain is **unkeyed**: someone who can rewrite the whole file can also recompute the chain, so it detects accidental corruption and partial edits, not a capable attacker with write access. Forward the log to a separate, append-only system (SIEM) if you need stronger guarantees.

To verify integrity programmatically:
1. Read all entries in order
2. For each entry after the first, compute `SHA-256(entry[n-1])`
3. Compare with `entry[n].previous_hash`
4. Any mismatch indicates tampering

## Daemon Operations

### Start the daemon

```bash
# The configuration file path is the first argument (default: ./craton_hsm.toml).
# The file must exist and contain a [daemon] section; a missing or invalid
# configuration is fatal.
craton-hsm-daemon /etc/craton_hsm/craton_hsm.toml
```

### Configuration (`[daemon]` section)

```toml
[daemon]
bind = "127.0.0.1:5696"     # Listen address
tls_cert = "tls.crt"        # PEM certificate path
tls_key = "tls.key"          # PEM private key path
```

### Health check

```bash
# gRPC health probe (requires grpcurl)
grpcurl -plaintext localhost:5696 craton_hsm.HsmService/GetTokenInfo

# TCP connectivity check
nc -z localhost 5696
```

### TLS setup

```bash
# Generate self-signed certificate (for testing)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout tls.key -out tls.crt -days 365 -nodes \
  -subj "/CN=craton_hsm"

# Reference in config
# [daemon]
# tls_cert = "tls.crt"
# tls_key = "tls.key"
```

### Daemon as systemd service

```ini
# /etc/systemd/system/craton_hsm.service
[Unit]
Description=Craton HSM gRPC Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/craton-hsm-daemon /etc/craton_hsm/craton_hsm.toml
User=craton_hsm
Group=craton_hsm
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/craton_hsm
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now craton_hsm
sudo systemctl status craton_hsm
journalctl -u craton_hsm -f
```

## Kubernetes Operations

### Deploy

```bash
# Chart: deploy/helm/craton-hsm (TLS and mTLS are required by default; see install.md)
helm install my-hsm deploy/helm/craton-hsm/ \
  --set image.repository=registry.example.com/craton-hsm \
  --set image.tag=0.9.1 \
  --set tls.secretName=craton-hsm-tls \
  --set tls.clientCaSecretName=craton-hsm-client-ca
```

### Monitor

```bash
# Logs
kubectl logs -l app.kubernetes.io/instance=my-hsm -f

# Status
kubectl get pods -l app.kubernetes.io/instance=my-hsm
```

### Upgrade

```bash
helm upgrade my-hsm deploy/helm/craton-hsm/ \
  --reuse-values --set image.tag=0.9.1
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

**Expected behavior** in in-memory mode: state is volatile.

**Solution**: Enable the encrypted persistent store:
```toml
[token]
storage_path = "/var/lib/craton_hsm/store"
```

Or re-import keys after restart.

### Slow RSA key generation

RSA-3072 and RSA-4096 key generation is CPU-intensive (seconds in debug mode, faster in release).

**Mitigation**: Always use `--release` builds in production. Pre-generate keys during maintenance windows if possible.
