# Handoff — daemon area (branch `claude/audit-fixes-daemon`, worktree `/home/user/hsm-fix-daemon`)

Scope: H4-01..H4-28 (H4-daemon-security.md), A3-01, A3-02, A3-09.
Owned paths changed: `craton-hsm-daemon/**`, `deploy/**`, `kreya/**`, `docs/postman-grpc-manual-tests.md`,
plus `.dockerignore` moved from `deploy/` to the repository root (explicitly requested: Docker only reads it
from the build-context root) and `Cargo.lock` (new daemon deps: `tonic-health`, `parking_lot`, `libc`;
rustls/webpki no longer pull `aws-lc-rs` through the daemon).

## 1. H4-03 — switching the daemon to the persistent `HsmCore` constructor

The daemon constructs its core in exactly one place:

- File: `craton-hsm-daemon/src/core_open.rs`, function `open_core(config: &HsmConfig) -> Result<Arc<HsmCore>, String>`.
- Today it calls `HsmCore::try_new(config)`. Replace that single call with the state agent's persistent
  open API (e.g. `HsmCore::open_persistent(config)` / whatever it is named), mapping its error to `String`.
- Nothing else needs to change: the daemon checks `hsm.object_store().has_persistence()` at runtime and
  only then accepts `CKA_TOKEN=true` objects (`server.rs`, `check_token_object`); until then it refuses
  them with FAILED_PRECONDITION and logs an "EPHEMERAL" warning. The Helm chart already renders
  `persist_objects = true` when `persistence.enabled=true`, and relative `storage_path` / `log_path` under
  the working directory `/data` (PVC).
- IMPORTANT interaction with the daemon login model (see §2): the daemon never leaves the core token logged
  in. It calls `token.login(..)` only to verify a PIN and immediately `token.logout()`. If the persistent
  store needs a key derived at User login (currently `ObjectStore::set_persist_key` "called after user
  login"), the persistent API must either (a) not depend on the token staying logged in, or (b) expose a
  call the daemon can make after a successful User PIN verification (e.g.
  `HsmCore::unlock_store_with_user_pin(slot, pin)`), and must not clear the key on `Token::logout`.
  Tell the daemon owner which; the call site would be `server.rs::login_inner`, inside the blocking
  closure right after `token.login(user_type, &pin)` succeeds.
- If the persistent API restores token state (initialised flag, PIN hashes), no daemon change is needed:
  InitToken is already admin-only and refuses while sessions exist.

## 2. Core-library changes requested (behavioural, outside daemon paths)

1. **H4-01 — per-principal PIN verification API** (`src/token/token.rs`).
   The daemon isolates clients itself (session ownership + per-client login table in
   `craton-hsm-daemon/src/registry.rs`) and uses the shared token only as a PIN oracle via
   `login()` + `logout()` under a per-slot lock. Please add:
   - `Token::verify_pin(&self, user_type: CK_ULONG, pin: &[u8]) -> HsmResult<()>` — same rate limiting,
     lockout counters and constant-time behaviour as `login`, but without changing `AuthState.login`.
   - `Token::init_pin_verified_so(&self, so_pin: &[u8], new_pin: &[u8])` (or make `init_pin` usable by a
     caller that has just verified the SO PIN). Today `init_pin` requires `auth.login == SoLoggedIn`, which
     forces the daemon's InitPin RPC to re-present the SO PIN.
   Once available, replace the login/logout pairs in `server.rs` (`login_inner`, `init_pin_inner`).
2. **H4-12 — PBKDF2 under the `auth` mutex** (`token.rs::login`, `init_token`, `set_pin`): compute the
   PBKDF2 hash/verify outside `self.auth.lock()` (snapshot hash + rate-limit state, verify, re-lock and
   commit), keeping the lockout ordering guarantees. The daemon now runs these calls on the blocking pool,
   but every other token getter (`is_initialized`, session counters) still stalls behind a login.
3. **H4-11 — lockout policy** (`token.rs:640-675`): `max_failed_logins` locks the User/SO PIN
   permanently. Any authenticated client that has a session can still lock the *User* PIN (the daemon now
   throttles per client and only admins can touch SO counters). Consider time-based lockout or an SO/admin
   unlock path, and a persistent attempt budget for `init_token` SO-PIN verification (currently back-off
   only, max 5 s).
4. **C_InitToken destroys before verifying (H4-09 related, likely H1/H3 owner)**:
   `src/pkcs11_abi/functions.rs:514-520` closes all sessions, clears the object store and resets all GCM
   counters *before* `token.init_token` verifies the SO PIN — a wrong SO PIN still wipes the token.
   Verify first, destroy after. Also `ObjectStore::clear()` is global across slots — clear per slot. Ideally
   add `HsmCore::init_token(slot, so_pin, label)` implementing: refuse with `SessionExists` if sessions are
   open (PKCS#11), verify SO PIN, destroy only that slot's objects + `remove_gcm_counter` per key. The
   daemon implements exactly that sequence in `server.rs::init_token_inner` / `Shared::wipe_slot_objects`.
5. **H4-16 / H4-26 — audit** (`src/audit/log.rs`): the channel is an unbounded `std::sync::mpsc`; make it
   bounded with back-pressure, and add a durability-acknowledged `record_sync` for security-critical events
   (Login, InitToken, InitPin, key generation, destroy). The daemon calls `flush()` after InitToken/InitPin
   and on shutdown. Please also add `AuditOperation::InitPin` (the daemon records InitPIN as
   `InitToken { slot_id }` with detail `op=InitPIN`) and, optionally, a dedicated client-identity field
   (the daemon currently prefixes `key_id` with `client=<identity>`).
6. **H4-08 — signing primitives** (`src/crypto/sign.rs`): expose (pub) prehashed ECDSA
   (`CKM_ECDSA`) and hash-selectable ECDSA (e.g. `ecdsa_p256_sign_with_hash(key, data, HashAlg)`), so
   `CKM_ECDSA_SHA384/512` can be honoured on any curve. The daemon currently rejects every combination the
   core cannot execute faithfully (only P-256+SHA-256, P-384+SHA-384, EdDSA, SHA*-RSA-PKCS/PSS).
   Parameterised mechanisms (generic PSS params, GCM IV/AAD/tag, OAEP hash/label) are rejected by the
   daemon until the core accepts parameters (stub items S10/S11/S13).
7. **H4-06 defence in depth** (`src/store/attributes.rs::apply_attribute`): cap `CKA_LABEL`/`CKA_ID`
   (e.g. 256 B) and public components, and reject `CKA_LOCAL`/`CKA_ALWAYS_SENSITIVE`/
   `CKA_NEVER_EXTRACTABLE`/`CKA_KEY_GEN_MECHANISM` in caller templates. The daemon no longer calls
   `apply_attribute` with caller data (allow-list in `craton-hsm-daemon/src/template.rs`), but the C ABI
   `C_CreateObject` path still does. Consider sharing `template.rs`'s allow-list logic in the core.
8. **H4-17** (`src/config/config.rs`): add `#[serde(deny_unknown_fields)]` to `HsmConfig`,
   `TokenConfig`, `SecurityConfig`, `AuditConfig`, `AlgorithmConfig`. The daemon already rejects unknown
   `[daemon]` keys and unknown top-level sections, but not typos inside core sections.
9. **H4-10** (`src/session/handle.rs`): handles are not secrets any more (bound to the client identity in
   the daemon), but generating them from a CSPRNG would make handle guessing moot for the C ABI too.
10. **H4-15 / perf** (`src/store/attributes.rs`): `MAX_OBJECTS = 10_000` is global across slots (the
    daemon adds a per-client quota, `max_objects_per_client`); `find_objects_for_slot` scans all objects —
    a per-slot index would help. `GetAttributeValue` cannot distinguish "sensitive" from "absent" because
    `read_attribute` flattens both; a status result would allow CKR_ATTRIBUTE_SENSITIVE semantics.
11. **H4-12 perf**: `HsmCore::drbg()` is one global mutex; the daemon now emits random data in 64 KiB
    chunks, but per-thread DRBG instances would remove the bottleneck. Confirm the RSA key cache
    (`sign.rs::clear_rsa_key_cache`) is used on the `rsa_pkcs1v15_sign`/`rsa_pss_sign`/`rsa_oaep_decrypt`
    paths the daemon calls.

## 3. Other owners (non-core)

- **A3-01 (tests owner)**: `tests/fips_approved_mode.rs:51` and `:80` use the same SO/User PIN values that
  were published in `kreya/`/docs. Replace with different test-only values (do not copy the old ones).
- **A3-01 / A3-23 (root manifest owner)**: add `package.include = ["src/**", "Cargo.toml", "LICENSE",
  "NOTICE", "README.md", "build.rs"]` to the root `Cargo.toml` so `kreya/`, `deploy/`, `.claude/` never
  ship to crates.io; remove `.claude/settings.local.json` and git-ignore `.claude/*.local.json`.
- **H4-23 / A3 (root manifest owner)**: root `Cargo.toml:14` `rust-version = "1.75"` is wrong; the locked
  graph needs >= 1.89 (redb 3.1.1; edition-2024 crates). The Dockerfile now uses `rust:1.94.1-bookworm`
  pinned by digest.
- **CI owner (A3-09, H4-23, H4-28)**: add jobs for `docker build -f deploy/Dockerfile .` (BuildKit),
  `helm lint deploy/helm/craton-hsm --set tls.clientCaSecretName=x --strict`, `helm template` with the
  rendered `craton_hsm.toml` fed to the daemon's config parser, a kind smoke test, and a proto/Kreya
  consistency check. Note: `cargo check --workspace --all-targets` fails on the BASE commit already
  (`benches/crypto_bench.rs` imports `craton_hsm_awslc`, which only exists in the enterprise repo) —
  not introduced by this branch; `--lib --bins --tests --examples` passes.
- **Docs owner**: update `docs/configuration-reference.md` `[daemon]` section with the new keys
  (all documented in `craton-hsm-daemon/src/config.rs` and `craton-hsm-daemon/craton_hsm.example.toml`):
  `tls_client_crl` (string or list, PEM/DER), `tls_client_crl_reload_secs`, `allow_no_client_auth`,
  `admin_client_cert_sha256`, `insecure_loopback_admin`, `max_request_bytes`, `max_response_bytes`,
  `max_connections` (now a real connection cap), `max_connections_per_ip`, `max_inflight_requests`
  (what `max_connections` used to mean), `max_concurrent_streams`, `handshake_timeout_secs`,
  `connection_idle_timeout_secs`, `max_connection_age_secs`, `http2_keepalive_interval_secs`,
  `http2_keepalive_timeout_secs`, `max_sessions_per_client`, `session_idle_timeout_secs`,
  `max_objects_per_client`, `max_blocking_tasks`, `health_bind`; changed defaults
  (`max_random_length` 64 KiB, `max_digest_length` 1 MiB-1 KiB); env vars `RUST_LOG`,
  `CRATON_HSM_LOG_FORMAT=json`. Also `docs/operator-runbook.md` (container config path is now
  `/etc/craton-hsm/craton_hsm.toml`, SIGTERM drains and flushes the audit log, no `security.toml`).
  `docs/api-reference.md` should mention the new `InitPin` RPC and the per-client login model.

## 4. Client-visible behaviour changes (release notes)

- mTLS is required unless `allow_no_client_auth = true`; unknown config keys abort startup.
- Sessions belong to the client identity that opened them; login/logout is per client and slot; closing
  the last session on a slot logs the client out; sessions close on disconnect and after
  `session_idle_timeout_secs`.
- SO login, InitToken and the new InitPin RPC require an administrator certificate
  (`admin_client_cert_sha256`). SO may not use keys; key operations require CKU_USER.
- InitToken fails while any session is open on the slot and destroys that slot's objects.
- Key-generation templates are allow-listed; `CKA_TOKEN=true` refused while state is ephemeral.
- Mechanism selects the algorithm and must match the key; raw `CKM_RSA_PKCS`, generic `CKM_RSA_PKCS_PSS`,
  `CKM_ECDSA`, `CKM_ECDSA_SHA512`, unpadded `CKM_AES_CBC`, and GCM/OAEP parameters are rejected.
- Digest enforces the algorithm policy (SHA-1 blocked in FIPS mode) and is audited.
- GetTokenInfo `login_state` is the caller's own state; counts are token-wide only for admins.
- Container: config path `/etc/craton-hsm/craton_hsm.toml`, working dir `/data`, UID 65532, plaintext
  health on `health_bind` (chart: port 5697). Chart: `secret-security.yaml` removed (settings rendered
  into the main config), `networkPolicy.allowOcsp` removed, `strategy: Recreate`, `image.digest`.

## 5. Not fixable in code

- H4-05 / A3-01: treat the previously committed SO/User PINs and the public test endpoint as compromised —
  re-initialise or decommission that server, firewall it, put it behind TLS+mTLS, rotate PINs everywhere
  they were reused, and consider rewriting Git history (`git filter-repo`) since the values remain in
  history. Enable GitHub secret scanning / push protection.
- H4-23: base-image digests (`rust:1.94.1-bookworm@sha256:6ae102bd…`,
  `gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79…`) and the pinned protoc / grpc_health_probe
  SHA-256 values were resolved on 2026-09-25; refreshing them (e.g. Renovate) and signing the published
  image are process items. The Docker build itself could not be executed in this environment (no Docker
  daemon); `helm lint`/`helm template` were run and the rendered config was validated by the daemon.
- H4-24: the NetworkPolicy label is not an authentication boundary (documented); mTLS is.
