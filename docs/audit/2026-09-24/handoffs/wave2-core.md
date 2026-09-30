# Wave 2 handoff — area `core` (branch `claude/audit-fixes2-core`, worktree `/home/user/hsm-fix2-core`)

Owned paths changed: `src/core.rs`, `src/token/**`, `src/audit/**`, `src/config/**`,
`src/crypto/encrypt.rs`, `src/store/**`, `src/error.rs`, `craton-hsm-daemon/**`,
`tools/craton-hsm-admin/**`, `deploy/helm/**`. No file outside the owned paths was edited.

## 1. PIN policy now enforced by the core (H5-12) — ABI/test owner MUST update test PINs

`src/token/pin_policy.rs::validate_new_pin` is applied by the core whenever a PIN is **set**
(`C_InitToken` SO PIN, `C_InitPIN`, `C_SetPIN` new PIN, daemon InitToken/InitPin, admin CLI).
Login/verification of an existing PIN is unaffected. Rules (in this order):

1. length `security.pin_min_length ..= security.pin_max_length` bytes → `CKR_PIN_LEN_RANGE`
   (config validation now rejects `pin_min_length < 8`; default 8..64);
2. at least **4 distinct** characters (bytes for non-UTF-8 PINs) → `CKR_PIN_INVALID`;
3. ASCII PINs: at least **2 character classes** of lower / upper / digit / other → `CKR_PIN_INVALID`;
4. not a repetition of a shorter unit (`aaaaaaaa`, `12121212`, `abcabcabc`) → `CKR_PIN_INVALID`;
5. not a strictly ascending/descending run of ≥ 4 characters (`12345678`, `hgfedcba`) → `CKR_PIN_INVALID`;
6. not in the denylist (case-insensitive) and not containing `password` → `CKR_PIN_INVALID`.
   Denylist (`pin_policy::DENYLIST`) includes **`sopin123`** and **`userpin1`** (published
   defaults, A3-01/H4-05) and `12345678`, `password`, `changeme`, `testtest`, `test1234`, ...

Impact on `tests/**`: every test that sets `b"sopin123"` (81 uses) or `b"userpin1"` (56 uses)
now gets `CKR_PIN_INVALID` at `C_InitToken`/`C_InitPIN`. Suggested mechanical fix (same length,
policy-compliant, not used anywhere else):
`sed -i 's/sopin123/S0pin-47/g; s/userpin1/Us3rpin9/g' tests/*.rs` (also `tests/interop/*.sh`,
`fuzz/`, benches if they set PINs). Other test PINs I saw that also fail when **set**:
`12345678` (already failing before), `newuserpin` (1 class) → e.g. `newUserpin7`,
`test-pin` is fine, `newpin12` fine, `sopin456` fine, `userpin1234` fine, `userpin0` fine.
Verified locally: with the two substitutions `state_regressions`, `persistence`, `multi_slot`,
`fips_approved_mode`, `backup_restore`, `audit_and_integrity` pass (see §7).

Also: `PinVerifier::create` now refuses `pbkdf2_iterations < 10_000` (`CKR_ARGUMENTS_BAD`) — a
verifier below that floor could never be verified (it made the token unusable silently).

## 2. New / changed core APIs (for ABI, docs and integrators)

| API | Purpose |
|---|---|
| `Token::verify_pin(user_type, pin)` / `HsmCore::verify_pin(slot, user_type, pin)` | H4-01: verify a PIN under lockout/rate limit **without** logging the token in; unlocks the slot DEK and loads the slot's token objects. Not audited (caller audits). |
| `Token::init_pin_with_so_pin` / `HsmCore::init_pin_with_so_pin(slot, so_pin, pin, actor)` | H4-01: SO-verified C_InitPIN without a logged-in token (audited `InitPin`). |
| `HsmCore::init_token_by / init_pin_by / set_pin_by(.., actor)` | same as `init_token/init_pin/set_pin`, actor recorded in the audit event's `key_id`. |
| `HsmCore::export_backup(slot, pass, include_non_extractable, actor)` | backup bound to `token_binding`, audited `BackupExport` (H5-20). |
| `HsmCore::restore_backup(slot, blob, pass, max_age, actor)` / `verify_backup` | atomic restore: objects + consumed backup ID in **one** store transaction; replay guard authenticated inside the encrypted DB (H5-04/H5-06); audited `BackupRestore`. |
| `HsmCore::import_objects` | now all-or-nothing, one transaction (P8). |
| `HsmCore::generate_random(out)` | replaces removed `HsmCore::drbg()` / `drbg` field (crypto #17); module-wide DRBG. |
| `HsmCore::run_self_tests()` | POST + backend CASTs for embedders (daemon/admin call it, A1-06). |
| `ObjectStore::insert_objects_in / insert_objects_recording` | batch insert (P8). |
| `EncryptedStore::put_objects[_recording]`, `put_key_usage/get_key_usage`, `consumed_backup_ids` | batch records, key usage state, replay guard. |
| `crypto::encrypt::{KeyStateSink, PersistedKeyUsage, register_persistent_key, unregister_persistent_key, persisted_key_usage, GCM_PERSIST_LEASE, CTR_MAX_PERSISTED_RANGES}` | H2-02/A1-15 persistence hooks (see §3). |
| `AuditLog::verify_files(log, key, visitor) -> AuditFileSummary / AuditVerifyError` | offline verification of the keyed chain across **all rotated generations**, rotation links, anchor (H5-03). Plus `audit::log::{format_syslog, operation_name, format_rfc3339}`. |
| `AuditOperation::{BackupExport{slot_id,object_count}, BackupRestore{..}, AuditExport}` | H5-20. |
| `HsmError::BackupRejected(BackupRejection)` (→ `CKR_DATA_INVALID`) | H5-04 distinct reasons: Malformed, UnsupportedFormat, KdfParameters, BindingMismatch, Replayed, TooOld, FromFuture, PolicyViolation. **Any exhaustive `match` on `HsmError` outside my paths needs a new arm** (none found in ABI). |
| `PersistentReplayGuard::with_key(path, key)` | H5-06: HMAC-authenticated entries, re-read through the locked fd; replay now returns `BackupRejected(Replayed)` instead of `DataInvalid`. |
| `HsmConfig::fips_defaults()` (now `pub`), `HsmConfig::enforce_build_policy()` | A1-06/A1-24: `fips` builds force approved mode + awslc in every loader. |
| `AlgorithmConfig::{allow_rsa_pkcs1v15_decrypt, rsa_pkcs1v15_decrypt_allowed(), gcm_iv_generation, caller_gcm_iv_allowed()}` | H2-03 gate (default off, rejected in FIPS mode); caller GCM IV policy. |
| `SecurityConfig::user_lockout_duration_secs` | H4-11 lockout hook: time-based **user** unlock (0 = permanent, default; must be 0 in FIPS mode; 60..30d). SO lock is always permanent. |
| `HsmConfig.daemon: Option<toml::Value>` | `[daemon]` section accepted opaquely; all core sections now `deny_unknown_fields` (H4-17). |

## 3. GCM / CTR state persistence (H2-02 / A1-15 / H2-11)

For every token AES key the object store registers a `KeyStateSink`. GCM: before an invocation
beyond the persisted lease, a new lease (`+65 536` invocations) is written (encrypted under the
slot DEK, bound to slot + record) — one durable write per 65 536 encryptions; restored on load, so
the 2^32 limit survives restarts. CTR: each new keystream range is persisted before use (≤ 1024
disjoint ranges per token key, then `CKR_KEY_FUNCTION_NOT_PERMITTED` → rotate). A usage record that
fails authentication keeps the key out of service. Caller CBC IVs and the recent-GCM-IV set remain
per process (documented residual).

## 4. Requests for the ABI owner (`src/pkcs11_abi/**`, `src/session/**`)

1. **H2-03**: any future `CKM_RSA_PKCS` decrypt/unwrap path must check
   `hsm.algorithm_config.rsa_pkcs1v15_decrypt_allowed()` (→ `CKR_MECHANISM_INVALID`).
2. **gcm_iv_generation**: in `C_EncryptInit` for `CKM_AES_GCM` with a caller IV, refuse with
   `CKR_MECHANISM_PARAM_INVALID` when `!algorithm_config.caller_gcm_iv_allowed()` (the daemon does).
3. **C_GenerateRandom / C_SeedRandom**: `HsmCore::drbg()` was removed; use
   `hsm.crypto_backend.generate_random` or `hsm.generate_random` (the ABI did not use it).
4. **C_InitPIN / C_SetPIN**: call `hsm.init_pin(session, pin)` / `hsm.set_pin(session, old, new)`
   so the policy + audit (`InitPin`/`SetPin`) apply; `CKR_PIN_INVALID` / `CKR_PIN_LEN_RANGE` are now
   returned for weak PINs.
5. **H4-10/H3-19** (`src/session/handle.rs`): generate session/object handles from the DRBG
   (64 random bits + collision check) instead of the Feistel permutation.
6. **P9/P10** (`src/session/handle.rs:213`, `src/session/manager.rs:192-217`): lock-free
   `reserved` check; per-slot session index + RO-session counter per token (not in my paths).
7. `ObjectStore::find_objects_for_slot` is now index based (P11); ordering of returned handles
   is unspecified (it always was) — tests must not rely on order.
8. `C_Finalize`: `HsmCore::finalize()` also detaches the persisted key-usage sinks; keep calling it.
9. `tests/**`: see §1 (PIN substitutions). `tests/state_regressions.rs` uses 100 000 PBKDF2
   iterations — fine; anything below 10 000 now fails at C_InitToken with `CKR_ARGUMENTS_BAD`.

## 5. Requests for the release/CI owner (manifests, CI, docs)

1. `tools/craton-hsm-admin/Cargo.toml`: dependencies `fs2` and `sha2` are now unused (the CLI's own
   replay guard and audit verifier were replaced by the core APIs) — remove them; `publish = false`.
2. `craton-hsm-daemon/Cargo.toml`: `publish = false` (ci.md §1.3). I did **not** add `tempfile` to
   the daemon; its persistence test uses a private temp-dir helper.
3. Docs (`docs/configuration-reference.md`, `operator-runbook.md`, `api-reference.md`,
   `fips-mode-guide.md`):
   * new keys `security.user_lockout_duration_secs`, `algorithms.allow_rsa_pkcs1v15_decrypt`,
     `algorithms.gcm_iv_generation`; unknown keys in any core section are now fatal; the
     `[daemon]` section may live in the same file; `pin_min_length` floor is 8;
   * PIN policy of §1; FIPS builds force approved mode/awslc regardless of the file;
   * admin CLI: works on the persistent token (`token.persist_objects = true`) and **requires the
     daemon to be stopped** (single-writer lock → exit 5 "locked by another process");
     new flags `--secrets-from-stdin` (automation) and `backup --include-non-extractable`;
     `restore --verify-only` now needs SO login; `audit verify-chain` needs read access to the
     audit key file (`audit.key_path`, default `<log>.key`) and verifies all rotated generations;
     `status` shows approved-mode, backend, self-test and mlock-failure indicators; the file
     `.craton_hsm_replay_guard` and `lockout_state.json` are no longer used (state is in the DB);
   * backups are bound to the random per-token identity: a backup can only be restored into the
     same token instance (not after `token init`, not onto another machine);
   * daemon: `CKM_ECDSA` (pre-hashed) and every ECDSA hash on P-256/P-384 are accepted; unpadded
     `CKM_AES_CBC` (block-aligned) is distinct from `CKM_AES_CBC_PAD`; `CKM_AES_GCM` parameter may be
     empty (module IV, output `IV||ct||tag`) or a 12-byte caller IV (`ct||tag`, refused in FIPS mode
     or with `gcm_iv_generation = "module"`); all crypto runs through the configured backend;
     the daemon runs POST + backend CASTs at start and zeroizes all SSPs on shutdown;
   * syslog export now carries `seq=` in the structured data.
4. Helm (done here): `values.yaml`/schema gained `config.auditLogLevel`, `auditFailClosed`,
   `auditKeyPath`, `userLockoutDurationSecs`; `pinMinLength`/`pinMaxLength` minimum 8,
   `maxFailedLogins` minimum 3. `helm lint/template` could not be run here (no helm binary) —
   please run the CI helm job.

## 5b. Items reported by the rel agent (wave2-rel.md §4) — done here

* H3-13: `HsmConfig::load()` accepts the system config `/etc/craton-hsm/craton_hsm.toml` (and
  `CRATON_HSM_CONFIG` under /etc); the system-directory rule still applies to `storage_path`,
  `audit.log_path`, `audit.key_path`. Ownership/mode/ancestor checks unchanged.
* H5-03: admin `audit verify-chain/dump/export-*` use `AuditLog::verify_files` (keyed chain).
* Admin default config path is now `craton_hsm::config::config::SYSTEM_CONFIG_PATH`
  (`/etc/craton-hsm/craton_hsm.toml`, Windows `C:\ProgramData\craton-hsm\craton_hsm.toml`)
  → docs (configuration-reference "Admin CLI", runbook, examples `CFG=`) must switch from the
  underscore path.
* FIPS builds: `load()` now reads the config file too (persistence, storage/audit paths
  configurable) and `enforce_build_policy()` then forces approved-only, `awslc`, no PQC/weak
  algorithms/PKCS#1 v1.5 decrypt, audit enabled + fail-closed, no broken-chain override, permanent
  lockout; no file → `fips_defaults()` (awslc). The same policy is applied by `load_from_path`
  (daemon) and the admin CLI loader.
* A3-12: `deploy/Dockerfile` copies `LICENSE` and `NOTICE` to `/usr/share/doc/craton-hsm/`;
  the root `.dockerignore` (outside my paths, edited on the orchestrator's request) now has
  `!LICENSE` / `!NOTICE` exceptions. Image description label → "PKCS#11 v2.40 software HSM"
  (A3-16). Version labels are still static (`IMAGE_VERSION=0.3.0`, chart appVersion) — derive
  them from Cargo.toml in the release pipeline (rel/CI).
* H4-27 doc nit in `craton-hsm-daemon/src/main.rs::init_logging` fixed.

## 6. Not fixable in code / residual

* Whole-database rollback (store + audit anchor + key-usage leases) needs an external monotonic
  counter (TPM NV) — H3-15/H3-17/A1-15 residual.
* Deleting the whole library-level replay-guard file still resets it (use `HsmCore::restore_backup`).
* P13 (pooled mlocked arena) not implemented: needs a new dependency (e.g. `memsec`) or unsafe
  slab allocator — supply-chain decision; mlock stays best effort and failures are reported
  (`mlock_failure_count`, admin `status`).
* H3-29 residual: Windows config ACL check still parses `icacls` output (localisation); needs
  `windows-sys` (`GetSecurityInfo`) — dependency decision.
* `SecurityConfig`-level PIN policy is not configurable (deliberately fixed).

## 7. Verification (this branch)

* `cargo check --workspace --all-targets` OK.
* `cargo test -p craton-hsm --lib`, `-p craton-hsm-daemon`, `-p craton-hsm-admin` all pass.
* Integration suites (`--test-threads=1`): `backup_restore`, `audit_and_integrity` pass unchanged;
  `state_regressions`, `persistence`, `multi_slot`, `fips_approved_mode` fail **only** because
  of the test PINs of §1 — with the two sed substitutions applied locally (not committed) they pass.
