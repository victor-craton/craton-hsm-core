# Handoff — area `state` (store / session / token / audit / config / core)

Branch `claude/audit-fixes-state`, worktree `/home/user/hsm-fix-state`.

## New core API for the daemon and the admin CLI (H4-03, H5-02)

`HsmCore::open(&config) -> Result<HsmCore, HsmError>` (alias of `try_new`) opens the
HSM **including its persistent state** when `token.persist_objects = true`:

* storage dir `token.storage_path` is created/validated (mode 0700, owned by the
  service account, not group/world writable); DB file `craton_hsm.redb` (0600,
  O_NOFOLLOW) under an **exclusive process lock** — only one process (daemon *or*
  admin CLI) can open a given store at a time;
* per-slot token record (initialised flag, label, PIN verifiers incl. KDF params,
  wrapped storage keys, random token id) + per-slot lockout counters are loaded, so
  a restart no longer re-opens `C_InitToken`;
* token objects of a slot are loaded after the first successful login on that slot
  (the slot DEK is wrapped under PIN-derived KEKs — SO and user);
* refuses to start if the audit chain fails verification unless
  `audit.allow_start_with_broken_chain = true`.

`HsmCore::new` now panics on these errors (use `open`). Lifecycle services every
front end should use (they are audited, synchronous for auth/token events):

| Operation | API |
|---|---|
| C_InitToken | `hsm.init_token(slot, so_pin, &label32)` — `SessionExists` if sessions are open, SO PIN verified under lockout **before** wiping only that slot's objects |
| C_InitPIN / C_SetPIN | `hsm.init_pin(session, pin)`, `hsm.set_pin(session, old, new)` |
| C_OpenSession | `hsm.open_session(slot, flags, app_id)` (`app_id`: per-client id → per-application cap `token.max_sessions_per_application`; C ABI uses `PROCESS_APPLICATION`) |
| C_CloseSession / C_CloseAllSessions | `hsm.close_session(h)`, `hsm.close_all_sessions(slot)` (destroy session objects; last close logs the token out) |
| C_Login / C_Logout | `hsm.login(session, user_type, pin)`, `hsm.logout(session)` (atomic: token + sessions + persistent object load, rolled back on failure) |
| object creation | `object_store().create_object_in(&tmpl, &sess.object_ctx())`, `insert_object_in(obj, &ctx, ObjectOrigin::{Generated{mechanism},Unwrapped,Derived{..},Copied,Restored})` |
| object lookup | `object_store().get_object_in_slot(handle, slot)`, `find_objects_for_slot(.., Some(slot))`, `destroy_object_in(handle, slot)`, `set_attributes(handle, slot, &tmpl, is_so)` |
| backup | log in as user on the slot, then `hsm.export_token_objects(slot, include_non_extractable)` (default `false`: non-extractable keys are not exported, A1-17); bind with `hsm.token_binding(slot)` (random per-token id) instead of the public serial |
| restore | `store::backup::restore_backup(..)` (v2 format, objects already policy-checked) → `hsm.import_objects(slot, objs)` (fresh handles; needs the slot unlocked by a login) → only then `PersistentReplayGuard::check_and_record(id)` |
| shutdown | `hsm.finalize()` (also run by `Drop`): zeroizes keys, PIN verifiers, storage keys |
| offline audit verification | `AuditLog::verify_file(log_path, key_path)` (do not construct an `HsmCore` next to a running daemon: the audit log and DB are single-writer locked) |

Notes:
* A locked SO account now also blocks `C_InitToken` (SO-PIN guessing through
  InitToken counts toward the SO lockout, H3-14/A1-23). Recovery is
  out-of-band: an operator with filesystem access removes the slot's store
  (`storage_path`) — an admin-CLI "factory reset" command could wrap this.
* `HsmCore::mark_compromised` is not exposed; use
  `object_store().mark_compromised(handle, slot)` from an SO-authorised path.

## Handoffs to other areas

### ABI (`src/pkcs11_abi/functions.rs`) — behaviour changes not made by me
* H1-03: `C_WrapKey` must apply the private-object/login check to the key being wrapped and `check_usage(KeyUsage::Wrap)` on the wrapping key.
* H1-04: `C_SetOperationState` must re-check authorization/usage of the restored key (I only made the handle lookup slot-scoped).
* H1-07: `C_DestroyObject` must require user login for `CKA_PRIVATE=TRUE` objects (store now returns `CKR_ACTION_PROHIBITED` for non-destroyable objects).
* H1-08: `C_CopyObject` still lets the template change `CKA_PRIVATE`, `CKA_TOKEN`, `CKA_MODIFIABLE/DESTROYABLE` and usage flags freely; restrict to the PKCS#11 copy rules (store already rejects provenance attributes and `CKA_TRUSTED` from non-SO callers via `insert_object_in(.., ObjectOrigin::Copied)`).
* H1-10/H1-14: key-creating functions (`C_GenerateKey*`, `C_UnwrapKey`, `C_DeriveKey`) silently drop unknown template attributes and accept `CKA_PRIVATE=FALSE`/public sessions; validate templates with `store::attributes::apply_attribute_ctx` semantics.
* H1-20/H3-23: call `obj.check_usage(KeyUsage::{Wrap,Unwrap,Derive})` in `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`, `C_CopyObject`; `check_lifecycle(&str)` now returns `KeyFunctionNotPermitted` and fails closed for unknown names.
* H1-21/A1-10: plain `Vec` copies of key bytes remain in `C_WrapKey` (`wk_bytes`, `key_bytes`), `C_DeriveKey` (`bk_bytes`); use `Zeroizing<Vec<u8>>`.
* H1-25/A1-10: `get_hsm()` thread-local cache can return a finalized core; check `hsm.is_finalized()` and drop the cache (the core now refuses token/session operations after `finalize()`).
* H3-11: every `let _ = hsm.audit_log.record(..)` ignores errors; with `audit.fail_closed = true` the ABI should return `CKR_DEVICE_ERROR` when `record` fails for security-relevant operations (use `record_sync` for key management). Not yet audited from the ABI: `C_CopyObject` (variant `AuditOperation::CopyObject` exists), `C_Digest*`, `C_FindObjects`.
* `C_Login` still pre-checks `has_ro_sessions` (harmless; the token now checks atomically).

### daemon (`craton-hsm-daemon/src/server.rs`, `main.rs`, helm chart)
* Construct with `HsmCore::open(&config)` and set `token.persist_objects = true`, absolute `storage_path` (absolute paths are now allowed; system dirs rejected).
* `init_token`: call `hsm.init_token(..)` — `Token::init_token` alone never wipes objects (H3-14/H4-09).
* Use `hsm.open_session(slot, flags, client_id)` / `close_session` / `login` / `logout` and slot-scoped object APIs (see table); `require_session` should bind sessions to the authenticated peer (H3-19).
* `server.rs:550,998`: `!matches!(login_state, Public)` treats SO as user; private objects must only be visible to `LoginState::UserLoggedIn` (H1-05).
* Helm `configmap.yaml`: `enabled = false` now requires `allow_disabled_insecure = true`; valid `log_level`: all/crypto/auth/admin; one audit log path per process (single-writer lock `<log>.lock`); consider `audit.key_path` on a separate volume.
* `HsmConfig::load_from_path` now validates and errors on a missing file.

### admin CLI (`tools/craton-hsm-admin`)
* Replace every `HsmCore::new(&config)` with `HsmCore::open(&config)`; operations need the daemon stopped (exclusive locks) and a login to unlock a slot.
* Backup/restore per the table above (backup format is now v2: header authenticated, KDF params stored; v1 files are rejected). Refuse to back up an uninitialised token (`export_token_objects` returns `TokenNotInitialized`).
* `audit` commands: read/verify the NDJSON file with `AuditLog::verify_file` instead of an in-memory `HsmCore`.

### crypto (`src/crypto`)
* A1-10: `sign::clear_rsa_key_cache()` is now called when an RSA private key is destroyed and on finalize; a per-key `remove_rsa_key_from_cache(der)` would avoid flushing the whole cache.
* `encrypt::force_reset_all_counters()` is no longer called by `C_InitToken` (per-key `remove_gcm_counter` on destroy instead); GCM counters of persistent keys are not persisted across process restarts (nonce-reuse risk if the nonce prefix is not random per process) — needs a persisted counter or a random-per-process prefix.
* `tests/security_properties.rs::test_ecdh_derives_different_from_raw_keygen` fails (ECDH not commutative, A1-14) — pre-existing, crypto area.

### CI / repo
* `cargo check --workspace --all-targets` fails in `benches/crypto_bench.rs:348` (`use craton_hsm_awslc` unconditional) — pre-existing.
* Add `craton_hsm_audit.jsonl.*` to `.gitignore` (tests using the default config create `.key`, `.anchor`, `.lock` next to the audit log in the CWD).
* ABI tests are PBKDF2-bound in debug builds; `cargo test --config 'profile.dev.package."*".opt-level=2'` makes them usable.

### docs
* Security policy / FIPS docs must describe the real key hierarchy (A1-17): per-slot random DEK, AES-256-GCM records with AAD (store key, slot, handle, generation) and HMAC manifest, DEK wrapped under PBKDF2-derived KEKs of **both** SO and user PIN, re-wrapped on PIN change, crypto-shredded by C_InitToken; DEK stays unlocked in memory after first login until C_Finalize (not cleared on logout).
* Config: configuration is no longer read from `./craton_hsm.toml`; sources are `$CRATON_HSM_CONFIG` or `/etc/craton-hsm/craton_hsm.toml`; `audit.log_level` semantics; new keys `token.max_sessions_per_application`, `audit.key_path`, `audit.fail_closed`, `audit.allow_start_with_broken_chain`, `audit.allow_disabled_insecure`; default `max_failed_logins` is now 5 everywhere.
* Deviation: after a restart, token objects (also public ones) become visible only after the first login on that slot.

## Not fixable in code
* Whole-database rollback (replacing the redb file and audit anchor with older copies) can only be detected with an external monotonic counter (TPM NV index / HSM-backed counter) — H3-15/H3-17.
* Lockout counters cannot be authenticated before login without a device secret; a filesystem attacker can reset them (H3-17) — requires a hardware-protected key.
* Audit anchoring off-host (syslog/SIEM forwarding) is an operational control (H3-10).
* Secure deletion inside redb free pages is best-effort (compaction + crypto-shredding on re-init); media-level erasure is operational (H3-15).
* Certification documentation items of A1-17 (SSP table, security policy text).

## Pre-existing test failures (identical on baseline 2f76874, not caused by this branch)
`multipart_encrypt_decrypt`, `multipart_sign_verify`, `pkcs11_compliance`, `pkcs11_compliance_extended`,
`supplementary_functions` (all 15) — SO PIN `12345678` violates the existing 2-character-class PIN policy;
`negative_edge_cases` (aes_ctr roundtrip, encrypt_exact_block_size, encrypt_one_byte, login_max_length_pin),
`pqc_abi_comprehensive` (hybrid ML-DSA/ECDSA, ML-DSA size), `random_and_session::test_set_pin`,
`rsa_abi_comprehensive::test_rsa_2048_oaep_encrypt_decrypt`, `security_properties::test_ecdh_*`,
`zeroization` (2 heuristic memory tests). Owners: ABI/crypto/test areas.
