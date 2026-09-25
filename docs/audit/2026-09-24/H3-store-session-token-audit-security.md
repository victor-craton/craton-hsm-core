# H3 — Store, session, token, audit & config: offensive security review

## Scope & method

**Target:** root crate `craton-hsm` at commit `2f76874` (worktree `/home/user/craton-hsm-audit-wt`).

**In scope (read fully, line by line):**

| Area | Files | LoC |
|---|---|---|
| Store | `src/store/{attributes,backup,encrypted_store,key_material,lockout_store,mod,object}.rs` | 2,449 |
| Session | `src/session/{handle,manager,session,mod}.rs` | 963 |
| Token | `src/token/{slot,token,mod}.rs` | 842 |
| Audit | `src/audit/{log,mod}.rs` | 1,061 |
| Config | `src/config/{config,mod}.rs` | 719 |

**Method:** static review only. Nothing was built or run. I traced call sites into `src/core.rs`, `src/pkcs11_abi/functions.rs`, `src/crypto/drbg.rs`, `craton-hsm-daemon/src/server.rs` and `tools/craton-hsm-admin/src/commands/backup.rs`, but only to confirm whether an in-scope weakness can be reached. Every file:line reference below was checked against the source. Confidence levels:

- **Confirmed:** the code path is unambiguous and I traced the call sites.
- **Likely:** it depends on runtime interleaving or deployment, but the code allows it.
- **Possible:** a theoretical or design-level concern.

"Latent" marks a flaw in code that is not currently reachable from the production entry points. It becomes live as soon as the code is wired in.

## Executive summary

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 4 |
| Medium | 11 |
| Low | 9 |
| Informational | 4 |
| **Total** | **29** |

**Top 5 risks**

1. **H3-01 (Critical): `C_InitToken` wipes every object and session before it checks the SO PIN.** Any caller that can reach `C_InitToken` can destroy every key in every slot by passing a wrong PIN, or even a 1-byte PIN. Locations: `src/pkcs11_abi/functions.rs:515-522` and `src/token/token.rs:403-431`.
2. **H3-02 (High): `C_GetAttributeValue` returns `CKA_VALUE` for keys that are `CKA_SENSITIVE=TRUE` and `CKA_EXTRACTABLE=TRUE`.** Private-key components such as `CKA_PRIVATE_EXPONENT` and `CKA_PRIME_*` are stored in `extra_attributes` and returned with no sensitivity check. Location: `src/store/attributes.rs:566-589`.
3. **H3-03 (High): no slot isolation for objects on the C ABI path.** There is one global `ObjectStore`, `slot_id` is never set, and `find_objects` is called without a slot. A user logged in on slot N can find and use slot M's private keys. `C_InitToken(slotN)` wipes every slot.
4. **H3-04 (High): token state and token objects are never persisted.** `persist_objects` is ignored, and the `EncryptedStore`, backup and replay-guard code is not wired into production. After every restart the token is uninitialized, so whoever calls `C_InitToken` first becomes SO. Lockout persistence has no effect, and admin backup/restore work on an empty, throw-away store.
5. **H3-10 / H3-11 (Medium): the audit trail is neither tamper-evident nor fail-closed.**
   - The SHA-256 hash chain has no key, so an attacker who can write the file can rewrite, truncate or delete it undetectably.
   - The first restart after a log rotation always trips the tamper flag, which then silently disables all auditing.
   - Every ABI caller discards `record()` errors.

## Findings

### H3-01 [Critical] C_InitToken destroys all objects (all slots) and closes all sessions *before* SO-PIN verification

- **Location:**
  - `src/pkcs11_abi/functions.rs:515` (`close_all_sessions`), `:518` (`hsm.object_store.clear()`), `:520` (`force_reset_all_counters()`), `:522` (`token.init_token(...)`)
  - `src/token/token.rs:403-431`: `validate_pin` and SO-PIN verification only happen inside `init_token`
  - `src/store/attributes.rs:333-343`: `clear()` is global and also clears the persistent store
- **CWE:** CWE-696 (Incorrect Behavior Order), CWE-306 (Missing Authentication for Critical Function), CWE-862
- **Confidence:** Confirmed
- **Description:** The ABI wrapper performs all destructive actions first, then delegates to `Token::init_token`, which is the only place the existing SO PIN is checked. `init_token` can fail in several ways after the wipe has already happened:
  - `validate_pin` fails (length or complexity);
  - the SO PIN is wrong (`PinIncorrect`);
  - the call is rate-limited (`PinRateLimited`).

  In every case the wipe is not rolled back. `object_store.clear()` has no slot parameter, so it wipes objects for every slot. It also clears the redb table when persistence is enabled.
- **Trigger condition:** `C_InitToken` is called with an SO PIN that is wrong, fails the PIN-policy check, or arrives inside the rate-limit window. No session or login is needed.
- **Impact:** Unauthenticated, permanent destruction of all key material (integrity and availability). It also forces sessions belonging to other applications closed, instead of returning `CKR_SESSION_EXISTS`.
- **Recommendation:**
  - Move the destructive steps into `Token::init_token`, or add a `Token::verify_so_for_init()` that runs under the `auth` lock.
  - Run them only after `validate_pin` succeeds and the existing SO PIN verifies.
  - Pass the slot to the object-store wipe (`clear_slot(slot_id)`).
  - Return `CKR_SESSION_EXISTS` when other sessions are open, as the spec requires.
  - Add a regression test: wrong PIN, then assert the object count is unchanged.

### H3-02 [High] Sensitive key material readable through C_GetAttributeValue

- **Location:**
  - `src/store/attributes.rs:566-580` (`CKA_VALUE` policy)
  - `src/store/attributes.rs:589` (`_ => extra_attributes.get(..)`, returned with no check)
  - `src/store/attributes.rs:528-537` (unknown attributes stored verbatim)
  - Consumer: `src/pkcs11_abi/functions.rs:1196`
- **CWE:** CWE-200, CWE-863 (Incorrect Authorization)
- **Confidence:** Confirmed
- **Description:**
  1. `read_attribute` blocks `CKA_VALUE` only when `sensitive && !extractable`. The comment explicitly allows reading a sensitive key if it is extractable. That is wrong: PKCS#11 §4.4 says `CKA_SENSITIVE=TRUE` forbids revealing the value in plaintext regardless of `CKA_EXTRACTABLE`. Extractable only permits wrapping. Keys generated through `C_GenerateKey` accept `CKA_SENSITIVE=TRUE, CKA_EXTRACTABLE=TRUE` (`functions.rs:2604-2615`), which is the standard template for a key meant to be exported by wrapping.
  2. `apply_attribute` has no arms for `CKA_PRIVATE_EXPONENT`, `CKA_PRIME_1/2`, `CKA_EXPONENT_1/2`, `CKA_COEFFICIENT` or EC `CKA_VALUE` components. They fall into `extra_attributes`. `read_attribute` then returns anything in `extra_attributes` with no sensitivity check at all.
- **Trigger condition:** A key object has `CKA_SENSITIVE=TRUE` together with `CKA_EXTRACTABLE=TRUE`, or holds private-key components supplied as separate attributes, and `C_GetAttributeValue` requests those attributes.
- **Impact:** Plaintext key extraction. This defeats the core HSM guarantee.
- **Recommendation:**
  - Make `read_attribute(CKA_VALUE)` return `AttributeSensitive` whenever `obj.sensitive` is true, or when the class is a private/secret key and `!extractable`.
  - Keep an explicit deny-list of sensitive component attributes (`CKA_VALUE`, `CKA_PRIVATE_EXPONENT`, `CKA_PRIME_1`, `CKA_PRIME_2`, `CKA_EXPONENT_1`, `CKA_EXPONENT_2`, `CKA_COEFFICIENT`, and the post-quantum private-key attributes). Store them in `RawKeyMaterial`, never in `extra_attributes`, and apply the same sensitivity check to them.

### H3-03 [High] No slot isolation of objects on the C ABI path

- **Location:**
  - `src/core.rs:135` (one `ObjectStore` for all slots)
  - `src/store/object.rs:111` (`slot_id: 0` default, never overwritten on the ABI path: no `.slot_id =` assignment in `functions.rs`)
  - `src/store/attributes.rs:356-362` (`find_objects` passes `slot_id=None`)
  - `src/pkcs11_abi/functions.rs:1330`
  - `src/store/attributes.rs:333-343` (global `clear`)
  - `src/token/slot.rs:28-41` (`slot_count` up to 256 per `config.rs:26`)
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-668
- **Confidence:** Confirmed
- **Description:** Each slot has its own `Token`, with its own PINs and login state, but every object lives in one map with `slot_id=0`. Authorization checks only whether the *session's* login state is logged in; they never check whether the object belongs to the session's slot. The daemon sets `slot_id` (`craton-hsm-daemon/src/server.rs:697`); the C ABI does not.
- **Trigger condition:** `slot_count > 1`, and a session logged in on one slot references or searches for objects created on another slot.
- **Impact:** Complete cross-token confidentiality and integrity break in multi-slot deployments.
- **Recommendation:**
  - Make `slot_id` a mandatory argument of `create_object`, `insert_object` and `find_objects`.
  - Add `get_object_for_slot(handle, slot_id)` and use it in every ABI entry point.
  - Scope `clear()` per slot.
  - Better still, use one `ObjectStore` per `Token`.

### H3-04 [High] Token and objects are never persisted: restart re-opens token ownership; `persist_objects`, lockout persistence and backup are dead

- **Location:**
  - `src/core.rs:135,172`: always `ObjectStore::new()`; `with_persistence`, `set_persist_key` and `load_from_store` are never called outside tests
  - `src/config/config.rs:58-62,144`: `persist_objects` is parsed but never read
  - `src/token/token.rs:167-181`: `so_pin_hash`, `user_pin_hash` and `initialized` are in memory only
  - `src/token/token.rs:154-165` + `:438-445`: lockout state is loaded, then discarded by the next `init_token`
  - `src/store/attributes.rs:178-193`: `persist_object` silently returns when no key is set
  - `tools/craton-hsm-admin/src/commands/backup.rs:108,114,220-235`: backup and restore operate on a fresh `HsmCore`
- **CWE:** CWE-1188 (Insecure Default Initialization), CWE-665, CWE-440 (Expected Behavior Violation)
- **Confidence:** Confirmed
- **Description:**
  - After any restart (crash, upgrade, OOM, or one forced by an attacker) the token reports `CKF_TOKEN_INITIALIZED` unset. `Token::init_token` skips SO verification when `!auth.initialized` (`token.rs:411`).
  - The persisted lockout counters (`lockout_store.rs`) are loaded, but `login` returns `TokenNotInitialized`, and the only way forward (`init_token`) resets them and deletes the file (`token.rs:439-445`). The "brute-force counters survive restart" guarantee in `lockout_store.rs:1-13` therefore never takes effect.
  - Operators who set `persist_objects = true` get no error and no persistence, so `CKA_TOKEN=TRUE` keys vanish on restart.
  - `craton-hsm-admin backup` exports the empty store of a newly built `HsmCore`. `restore` inserts into another temporary `HsmCore` that is dropped straight away, yet it still consumes the backup ID in the replay guard.
- **Trigger condition:** The process restarts, for any reason, while the configuration expects a previously initialized token.
- **Impact:** Token takeover after restart. Silent loss of token keys. False assurance from the lockout and backup features.
- **Recommendation:**
  - Persist a token record (`initialized`, label, SO/user PIN hashes with their KDF parameters, and lockout counters) in an authenticated store, and load it in `Token::new_with_config`.
  - Honor `persist_objects`, or fail closed with a `ConfigError` when it is set but unsupported.
  - Make the admin tool operate on the persistent store and refuse to back up an empty or uninitialized token.
  - Record the replay ID only after a successful commit.

### H3-05 [Medium] Security-relevant attributes are self-assertable; `CKA_COPYABLE=FALSE` is silently ignored

- **Location:**
  - `src/store/attributes.rs:528-537` (catch-all `extra_attributes.insert`)
  - `src/store/attributes.rs:415-540` (no `CKA_COPYABLE`, `CKA_TRUSTED`, `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE` or `CKA_WRAP_WITH_TRUSTED` arms)
  - `src/store/object.rs:59-60,122` (`copyable` defaults to `true` and is never set from a template)
  - Consumers: `functions.rs:3547` (copy check reads `obj.copyable`), `functions.rs:5031-5058` (`CKA_TRUSTED`/`CKA_WRAP_WITH_TRUSTED` read from `extra_attributes`)
- **CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes), CWE-284
- **Confidence:** Confirmed for the code path. Exploitability is Likely. Today, `C_GenerateKey` ignores `CKA_WRAP_WITH_TRUSTED`, and `C_CreateObject` cannot create extractable keys, which narrows the immediate wrap-bypass.
- **Description:**
  - Any logged-in user can create a key with `CKA_TRUSTED=TRUE`. PKCS#11 reserves that attribute for the SO. The wrap-with-trusted enforcement treats it as authoritative.
  - Any user can import a key that claims `CKA_LOCAL=TRUE`, `CKA_NEVER_EXTRACTABLE=TRUE` and `CKA_ALWAYS_SENSITIVE=TRUE`. These are the provenance attributes relying parties use for attestation and key-origin policy. The HSM never computes them itself.
  - A template value `CKA_COPYABLE=FALSE` is stored in `extra_attributes`, and `read_attribute` echoes it back as FALSE. `C_CopyObject` still allows the copy because `obj.copyable` stays `true`.
- **Trigger condition:** A logged-in user passes `CKA_TRUSTED`, `CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE`, `CKA_WRAP_WITH_TRUSTED` or `CKA_COPYABLE` in a `C_CreateObject` or `C_CopyObject` template.
- **Impact:** Policy bypass, key duplication, forged provenance.
- **Recommendation:**
  - Handle every attribute in the PKCS#11 table explicitly in `apply_attribute`.
  - Reject `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE` in templates (`CKR_ATTRIBUTE_READ_ONLY`) and compute them at generation or import.
  - Allow `CKA_TRUSTED` only in SO sessions.
  - Map `CKA_COPYABLE` and `CKA_WRAP_WITH_TRUSTED` to typed fields.
  - Replace the catch-all with an allow-list of non-security vendor or data attributes.

### H3-06 [Medium] SO sessions are treated as "logged in" for user objects (role separation broken)

- **Location:** `src/session/session.rs:38-43` (`is_logged_in` includes `RwSO`). Used for private-object access at `functions.rs:1041,1142,1186,1265,1458,1755,1964,2380,3542,5129`.
- **CWE:** CWE-269 (Improper Privilege Management), CWE-863
- **Confidence:** Confirmed
- **Description:** PKCS#11 and FIPS 140-3 role separation say the SO manages the token and the user PIN but cannot use or read private user objects. Here an SO session passes every `obj.private && !is_logged_in()` gate, so it can find, read, sign and decrypt with user keys, and can create private and secret keys.
- **Trigger condition:** A session is logged in as SO (`CKU_SO`) and uses a handle to a `CKA_PRIVATE=TRUE` user object.
- **Impact:** Privilege escalation from SO to crypto officer or user. This also breaks FIPS role separation.
- **Recommendation:** Split the predicate into `is_user()` (`RoUser | RwUser`) and `is_so()`. Use `is_user()` for private-object and key-use checks. Allow SO only for public objects and token management.

### H3-07 [Medium] Session objects outlive their session; global object cap enables unauthenticated DoS

- **Location:**
  - `src/store/object.rs:42-105` (no owner-session field)
  - `src/session/manager.rs:70-108` (`close_session` and `close_all_sessions` never touch objects)
  - `src/store/attributes.rs:21,237-240,268-272` (`MAX_OBJECTS = 10_000`, global across slots and users)
- **CWE:** CWE-404 (Improper Resource Shutdown or Release), CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-668
- **Confidence:** Confirmed
- **Description:**
  - Objects with `CKA_TOKEN=FALSE` should be destroyed when the session that created them closes (PKCS#11 §4.4). Here they stay in the global map until the process exits, and any later session can see them, including sessions opened by a different application in the daemon.
  - A public R/W session (no login) may create `CKO_DATA` objects, since login is required only for private and secret keys (`functions.rs:1031-1043`).
  - 10,000 such objects fill the single global cap. After that, `C_GenerateKey`, `C_CreateObject`, `C_UnwrapKey`, `C_DeriveKey` and `C_CopyObject` fail with `CKR_DEVICE_MEMORY` for every user and every slot. Closing the attacker's sessions does not release the objects.
  - Each object can also carry 64 × 8 KiB extra attributes (`attributes.rs:529-535`), about 5 GiB in total, which also exhausts memory.
- **Recommendation:**
  - Record `owner_session: Option<CK_SESSION_HANDLE>` on session objects and destroy (and zeroize) them in `close_session`, `close_all_sessions`, and on `C_Finalize`.
  - Apply per-session and per-slot quotas, plus a byte budget in addition to the object count.

### H3-08 [Medium] Race between `open_session` and `C_Logout` leaves a session authenticated after logout

- **Location:**
  - `src/session/manager.rs:40-45` (RO/SO snapshot), `:53-57` (login snapshot), `:66` (late insert)
  - `src/session/manager.rs:192-210` (`logout_all` iterates only sessions already inserted)
  - `src/token/token.rs:292-294` (the snapshot API warns that it must not be used for authorization)
- **CWE:** CWE-367 (Time-of-check Time-of-use Race Condition)
- **Confidence:** Likely. It needs concurrent threads, which are normal for PKCS#11 applications and servers.
- **Description:** `open_session` reads `token.login_state()` (`UserLoggedIn`), sets the new session to `RwUser`, and inserts it only afterwards. If `C_Logout` runs `token.logout()` plus `logout_all` inside that window, the new session is not yet in the map and keeps `RwUser`. Every ABI authorization gate trusts `sess.state`, not the token, so that session keeps full user privileges after logout. The same window lets a read-only session be created after an SO login (`:42-47`). This contradicts the rule that an SO login forbids RO sessions (`CKR_SESSION_READ_WRITE_SO_EXISTS`).
- **Recommendation:**
  - Perform the login-state read, `increment_session_count`, the `Session::new` state derivation and `sessions.insert` while holding the token `auth` lock, for example with `Token::with_auth(|auth| ...)`.
  - Alternatively, have authorization gates re-validate against the token's login state, perhaps using a login epoch counter stored in the session.

### H3-09 [Medium] Token-wide DoS: PBKDF2 runs under the global `auth` mutex; locked accounts are unthrottled

- **Location:**
  - `src/token/token.rs:579` (lock), `:598` (rate check), `:602-605` (PBKDF2 under lock), `:608-610` (locked: return before updating backoff)
  - SO path at `:644-655`; `init_token` at `:407-417`
  - Other users of the same mutex: `flags()` `:366`, `increment_session_count` `:702`, `decrement_session_count` `:731`, `is_initialized` `:279`
- **CWE:** CWE-400 (Uncontrolled Resource Consumption), CWE-833
- **Confidence:** Confirmed
- **Description:** Each `C_Login` holds `auth` for a full PBKDF2 run (600k to 1M iterations, roughly 0.3–1 s). Once `user_pin_locked` (or `so_pin_locked`) is set, `login` still performs the verification and returns `PinLocked` without setting `user_next_allowed`. Back-to-back attempts are therefore never rate-limited, and each one freezes `C_OpenSession`, `C_CloseSession`, `C_GetTokenInfo` and every other login for that token.
- **Trigger condition:** The user or SO account is already locked and further `C_Login` calls for that account keep arriving.
- **Recommendation:**
  - Reject immediately when locked, and equalize timing with a dummy-hash cache or constant-time delay rather than a real PBKDF2 under the lock.
  - Perform PBKDF2 outside `auth`: snapshot the hash, release the lock, verify, then re-acquire and commit with a generation check.
  - Always advance the backoff deadline, including for locked accounts.

### H3-10 [Medium] Audit "tamper-evidence" uses an unkeyed hash chain with no anchor

- **Location:** `src/audit/log.rs:14-18,203-222` (plain SHA-256), `:600-677` (verification only checks internal consistency), `:604-605` (missing file ⇒ fresh chain), `:668-671` (empty file ⇒ fresh chain)
- **CWE:** CWE-354 (Improper Validation of Integrity Check Value), CWE-778 (Insufficient Logging)
- **Confidence:** Confirmed
- **Description:** `H_n = SHA-256(H_{n-1} || payload)` uses no secret. Anyone who can write the log (the HSM service account, a backup operator, a compromised host) can:
  - delete or edit any entry and recompute every later hash;
  - truncate the tail (nothing records the last hash or count anywhere else);
  - delete the file or its rotated generations. Recovery then treats this as `NoFile` and restarts from the zero hash, with no warning.
- **Impact:** Audit records can be removed undetectably. This fails FIPS 140-3 and PCI audit-integrity expectations.
- **Recommendation:**
  - Key the chain with HMAC-SHA-256 or Ed25519-sign periodic checkpoints, using a key held in the HSM and never written to the log.
  - Anchor checkpoints (hash and sequence number) externally: syslog, remote SIEM, or a separate append-only file.
  - Add a monotonic sequence number to every event.
  - Treat a missing or empty log on a previously initialized token as tampering.

### H3-11 [Medium] Audit subsystem fails open; rotation guarantees a false tamper and silent loss of auditing on restart

- **Location:**
  - `src/audit/log.rs:697-718` then `:405-409` (rotation), and `:616` + `:647-654` (recovery starts at zero hash) ⇒ `:553-560` sets `tampered`
  - `src/audit/log.rs:353-355,737-741` (after tampering, events are dropped)
  - `src/audit/log.rs:427-429` (disk I/O errors only logged; the chain still advances in memory)
  - `src/audit/log.rs:746-755` (asynchronous, not durable when `record` returns)
  - `src/core.rs:136-137` (tampered log still yields `Ok`)
  - ABI: every `hsm.audit_log.record` call is `let _ =`
- **CWE:** CWE-636 (Not Failing Securely), CWE-778, CWE-755
- **Confidence:** Confirmed
- **Description:**
  - After a rotation, the first event in the new file carries the previous file's last hash. On the next restart, `recover_chain_from_file` starts from `[0;32]`, reports "TAMPER DETECTED at line 1", and sets the permanent tamper flag. `record()` then refuses every event, but all PKCS#11 operations continue because callers ignore the error. Every rotation therefore turns into "auditing silently off" at the next restart.
  - A transient write failure (disk full, EIO) has the same effect. The event goes into memory and `last_hash` advances, but the line is missing on disk, so the next restart detects a broken chain.
  - Events are queued asynchronously, so a crash loses everything still in the channel, although the operation already returned `CKR_OK`.
- **Coverage gaps (Confirmed; `grep AuditOperation::` in `functions.rs`):** these operations are never audited:
  - `C_InitToken`, `C_InitPIN`, `C_SetPIN`
  - `C_OpenSession`, `C_CloseSession`
  - `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`
  - `C_CopyObject`, `C_SetAttributeValue`, `C_GetAttributeValue` (including `CKA_VALUE` extraction, H3-02)
  - `C_FindObjects`, `C_Digest`

  `AuditOperation` has no variants for PIN changes at all (`log.rs:55-123`).
- **Recommendation:**
  - Make recovery read the rotated generation's last hash, or write a signed "rotation header" line carrying the previous hash and sequence.
  - On a disk write error, set a failure flag and fail closed: return `CKR_DEVICE_ERROR` for security-relevant operations.
  - Have `HsmCore::try_new` refuse to start when the tamper flag is set, unless an explicit SO override applies.
  - Add synchronous (flush-before-return) mode for authentication and key-management events.
  - Add the missing operations to the enum and to the ABI.

### H3-12 [Medium] Unsafe filesystem handling: symlink-following predictable paths, create-then-chmod, CWD-relative storage

- **Location:**
  - Lock file: `src/store/encrypted_store.rs:59-71` (`File::create` truncates and follows symlinks; `set_permissions` also follows symlinks)
  - Database: `src/store/encrypted_store.rs:79-85` (created with umask permissions, then chmod)
  - Lockout: `src/store/lockout_store.rs:118-127` (`fs::write` to predictable `lockout_state.json.tmp` follows symlinks; no `fsync` of file or directory before `rename`); `:107-115` (`create_dir_all` with default 0755)
  - Replay guard: `src/store/backup.rs:355-369` (open-append follows symlinks; chmod after create)
  - Audit: `src/audit/log.rs:229-253` (symlink check at startup only); `:286-300,402,408` (reopened per event with no `O_NOFOLLOW`); `:697-718` (rename rotation)
  - Config: `src/config/config.rs:299-304` forbids absolute paths, so all of the above are relative to the host process's CWD
- **CWE:** CWE-59 (Link Following), CWE-367, CWE-377 (Insecure Temporary File), CWE-276
- **Confidence:** Confirmed for the code behaviour. Exploitation is Likely whenever the CWD or storage directory is writable by another user, for example applications started from `/tmp` or shared working directories.
- **Trigger condition:** The storage directory, the CWD or the audit-log directory is writable by a less-privileged principal, and a predictable file name there is a symlink when the HSM creates or reopens it.
- **Impact:** Arbitrary file clobbering or appending with the HSM's privileges, loss of the audit trail, and lockout-state DoS.
- **Recommendation:**
  - Use `OpenOptions::new().create_new(true).mode(0o600).custom_flags(O_NOFOLLOW | O_CLOEXEC)` for every created file. Open temp files with `O_EXCL` and random names in the same directory.
  - Call `fsync` on the file and on the parent directory before and after `rename`.
  - Keep the audit file descriptor open, and check `fstat` against the startup inode.
  - Allow, or even require, absolute storage and audit paths owned by the service account, and verify the directory's owner and mode (0700) at startup.

### H3-13 [Medium] Config can be planted from CWD or an environment variable; ownership not checked; security fields silently ignored

- **Location:**
  - `src/config/config.rs:270-277` (`CRATON_HSM_CONFIG` or `./craton_hsm.toml`)
  - `src/config/config.rs:373-395`: only mode `0o022` is checked, despite the doc comment "reject insecure ownership"
  - `src/config/config.rs:496-501` (missing file ⇒ silent defaults)
  - `src/config/config.rs:244-268` (FIPS mode advisory via environment variable only)
  - `src/config/config.rs:62` (`persist_objects`) and `:104` (`log_level`): validated but never used anywhere (`grep` shows no readers)
- **CWE:** CWE-15 (External Control of System or Configuration Setting), CWE-427, CWE-1188
- **Confidence:** Confirmed
- **Description:** A PKCS#11 module is loaded into arbitrary host processes, so the CWD is often attacker-influenced, for example a user running a signing tool inside a cloned repository. A file owned by the attacker with mode 0644 passes the checks. The attacker can then:
  - set `pbkdf2_iterations = 100000` and `max_failed_logins = 100`;
  - set `audit.enabled = false` (allowed when `fips_approved_only = false`);
  - set `allow_weak_rsa` and `allow_sha1_signing`;
  - redirect `storage_path` or `log_path` to a directory they control.

  Setting `log_level = "none"` gives a false sense of reduced logging, and `persist_objects` gives a false sense of durability.
- **Recommendation:**
  - Load configuration only from an absolute, root- or service-owned path, defined at build time or in `/etc/craton-hsm/`.
  - Check `st_uid` equals the effective UID (or root) and that no ancestor directory is writable by others.
  - Fail when a security-relevant field is set but unimplemented.
  - Refuse `audit.enabled=false` unless an explicit "insecure" flag is also set.

### H3-14 [Medium] Re-initialization semantics: C_InitToken SO-PIN guessing never locks out; `Token::init_token` does not own object destruction

- **Location:**
  - `src/token/token.rs:411-431`: failures increment `failed_init_token_logins` and set a backoff (maximum 5 s, `:28`), but never lock
  - `src/token/token.rs:403-452`: no object wipe inside `Token`
  - `craton-hsm-daemon/src/server.rs:599`: the daemon calls `token.init_token` and never clears objects
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-459
- **Confidence:** Confirmed
- **Description:**
  - The SO PIN can be brute-forced through `init_token` at one guess per 5 s: about 17k guesses per day, forever. The default PIN policy (8 characters, 2 classes, 3 distinct bytes; `token.rs:208-250`) makes this feasible for weak PINs.
  - Object wiping is left to callers. The C ABI wipes too early (H3-01); the daemon never wipes. A successful re-init through gRPC keeps every previous object, and the new SO can then `InitPIN` and use the old user's private keys.
- **Recommendation:**
  - Apply `max_failed_logins` to `failed_init_token_logins` as well, locking re-init until an out-of-band recovery. Alternatively, lengthen the backoff beyond the 5 s cap for init.
  - Move the wipe into `Token::init_token` through a callback or a shared `ObjectStore` handle, so that every front end gets identical, spec-conformant semantics.

### H3-15 [Medium, latent] Encrypted store design: no AAD, no rollback/deletion detection, PIN-bound key with no re-key or salt storage

- **Location:**
  - `src/store/encrypted_store.rs:113-131`: `encrypt(nonce, plaintext)` with no AAD
  - `src/store/encrypted_store.rs:194-202`: decrypt with no AAD, no version
  - `src/store/encrypted_store.rs:264-280`: `clear` deletes the table, leaving data in redb free pages
  - `src/store/encrypted_store.rs:208-230` (`delete`)
  - `src/store/attributes.rs:96-98,122-126,128-132`: one PIN-derived key; the first undecryptable record aborts the whole load
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity), CWE-924, CWE-226
- **Confidence:** Confirmed (latent, see H3-04)
- **Description:**
  - The AEAD does not bind the ciphertext to its store key, the object handle, or a version or epoch. An attacker with write access to the database file can:
    - replay an older blob (for example a key before it was marked non-extractable, or one later destroyed);
    - resurrect a destroyed or compromised key by copying the file back (whole-file rollback);
    - drop records.
  - Nothing detects any of this, because there is no manifest or MAC over the set of keys.
  - `load_from_store` uses `?` on `load_encrypted`, so a single corrupted record makes the whole token unloadable (DoS).
  - Keys are derived from the user PIN, but no salt is stored anywhere and `C_SetPIN` does not re-encrypt. The design cannot survive a restart or a PIN change. The tests pass only because they hold `enc_key` in memory.
  - Deleted and cleared records remain in free pages of the redb file.
- **Recommendation:**
  - Use a random data-encryption key (DEK) wrapped under a PIN-derived key-encryption key (KEK), stored with salt and KDF parameters.
  - Use AAD = `store_key || handle || generation`.
  - Keep an authenticated manifest (HMAC over sorted `(store_key, generation)`) plus a monotonic counter (TPM NV index or equivalent) against whole-file rollback.
  - Skip and quarantine bad records instead of aborting.
  - Compact or overwrite on delete.

### H3-16 [Medium] Backup/restore: header not authenticated, KDF parameters not recorded, restored objects trusted as-is, replay guard weak

- **Location:**
  - `src/store/backup.rs:127-133,165-178` (magic/version/salt outside AAD; iterations not stored)
  - `src/store/backup.rs:187-196`: when JSON parsing fails, `?` returns before `plaintext.zeroize()`
  - `src/store/backup.rs:192-279`: objects returned without `validate_deserialized_object` or any policy re-check
  - `src/store/backup.rs:299-332` (plaintext replay file, deletion resets it)
  - `src/store/backup.rs:351-389` (lock taken only around the append, not around check+use)
  - Admin tool: `tools/craton-hsm-admin/src/commands/backup.rs:187-219` (ID recorded before the import)
- **CWE:** CWE-502 (Deserialization of Untrusted Data), CWE-345, CWE-294 (Authentication Bypass by Capture-replay), CWE-226
- **Confidence:** Confirmed
- **Description:**
  - A restore trusts every field of each `StoredObject`: `sensitive=false`, `extractable=true`, `copyable`, attacker-chosen `handle` and `slot_id`, and `extra_attributes` such as `CKA_TRUSTED`. The token serial check is weak binding, because serials are public (`C_GetTokenInfo`) and default to `0000000000000001`. Anyone who can persuade an operator to restore a file, with a passphrase the attacker chose, can inject keys with arbitrary policy.
  - The replay guard can be defeated by deleting `.craton_hsm_replay_guard`, or by two concurrent restores. Each loads the ID set before either appends.
  - Because the iteration count is not stored, changing `pbkdf2_iterations` makes old backups unreadable.
- **Recommendation:**
  - Put magic, version, KDF id, iterations and salt in the header and pass the header as AAD.
  - Run every restored object through the same validation as creation. Reject `sensitive=false` for private or secret keys unless the SO opts in, and strip `CKA_TRUSTED`.
  - Reallocate handles.
  - Bind backups to a per-token random identity rather than the public serial.
  - Keep the replay set inside the authenticated token store.
  - Zeroize on every exit path, for example by wrapping `plaintext` in `Zeroizing` immediately.

### H3-17 [Low] Lockout store: unauthenticated, shared by all slots, save errors swallowed

- **Location:**
  - `src/token/token.rs:155`: every slot uses the same `storage_path`
  - `src/store/lockout_store.rs:36-40` (fixed file name)
  - `src/store/lockout_store.rs:75-78`: `NotFound` ⇒ fresh counters, so deleting the file resets lockout
  - `src/store/lockout_store.rs:98-128`: `save` returns `()` and only logs failures
  - `src/token/token.rs:443-445`: `init_token` on any slot deletes the shared file
- **CWE:** CWE-307, CWE-345, CWE-362
- **Confidence:** Confirmed
- **Description:** With several slots, the tokens overwrite each other's counters (last writer wins), and re-initializing slot 1 erases slot 0's lockout state. Deleting or rolling back the JSON file resets all counters. A read-only or full disk means counters are never persisted, and the process continues without them (fail-open). This becomes security-relevant once H3-04 is fixed.
- **Recommendation:**
  - Use a per-slot file (`lockout_slot{N}.json`) or a per-slot key inside the authenticated token store, MAC-ed with a device key.
  - Treat a missing file on an initialized token as "locked".
  - Propagate `save` errors: refuse the login attempt if the failure counter cannot be persisted.

### H3-18 [Low] PBKDF2 salt can silently be all-zero

- **Location:** `src/store/encrypted_store.rs:439-448`. The result of `let _ = drbg.generate(&mut s);` is ignored. `generate` can fail on reseed or the health test (`src/crypto/drbg.rs:185-192,230-236`).
- **CWE:** CWE-252 (Unchecked Return Value), CWE-760 (Use of a One-Way Hash with a Predictable Salt)
- **Confidence:** Confirmed code path. Triggering it requires an entropy or DRBG fault.
- **Description:** If `HmacDrbg::new()` succeeds but `generate` fails, `s` stays `[0;32]`. PIN hashes and backup keys are then derived with a constant salt, which enables precomputation across tokens and deployments. The OS RNG fallback only covers `new()` failing.
- **Recommendation:** Make `derive_key_from_pin` return `HsmResult` and propagate the error, or fall back to `OsRng` on any DRBG error, and assert that the salt is non-zero.

### H3-19 [Low] Handle generation: non-cryptographic permutation; handles act as bearer capabilities in the daemon; wrap-around reuse

- **Location:** `src/session/handle.rs:20-29` (multiply-xorshift round function, `f(0)=0`), `:41-124` (4-round Feistel), `:148-172` and `:198-219` (counter wraps to 0 at `MAX_HANDLE`, no liveness check)
- **CWE:** CWE-330 (Use of Insufficiently Random Values), CWE-340
- **Confidence:** Possible
- **Description:**
  - The Feistel round function is linear-ish (a multiply by an odd constant), there is no security proof, and only the low 32 bits of each round key affect the low output word. The code comments claim the handles are unpredictable, but the construction is not a PRP.
  - In the daemon, `require_session` accepts any valid handle from any client (`craton-hsm-daemon/src/server.rs:281-290`), so the handle's secrecy is the only thing isolating clients.
  - On wrap-around, which is reachable on 32-bit `CK_ULONG` platforms such as Windows, a live handle can be re-issued, and `DashMap::insert` silently replaces the existing session or object.
- **Recommendation:**
  - Use a keyed PRP (for example AES-based format-preserving encryption, or SipHash-based Feistel rounds) or simply 64 random bits with a collision check.
  - Check `contains_key` before insert.
  - In the daemon, bind sessions to the authenticated connection or peer rather than relying on the handle.

### H3-20 [Low] Zeroization gaps for key material and PIN-derived secrets

- **Location:**
  - `src/store/attributes.rs:579` (`km.as_bytes().to_vec()`: plain `Vec` copy of the key)
  - `src/store/attributes.rs:202-206` and `src/store/backup.rs:107,125`: `serde_json::to_vec` grows by reallocating, and freed intermediate buffers are not zeroized; only the final buffer is
  - `src/store/attributes.rs:96-98` (`set_persist_key(key: [u8;32])` by value leaves stack copies)
  - `src/store/backup.rs:98-106,192-205` (payload `extra_attributes` not zeroized on the error paths)
  - `src/session/session.rs:63,71,80,89` (`cached_object` `Arc` keeps a destroyed key alive and usable until the operation ends)
  - Cross-reference: `functions.rs:1091` (plain `Vec` copy of the key in `C_DestroyObject`)
- **CWE:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse), CWE-244
- **Confidence:** Confirmed
- **Recommendation:**
  - Return `Zeroizing<Vec<u8>>` from `read_attribute`.
  - Serialize into a pre-sized `Zeroizing<Vec<u8>>` via `serde_json::to_writer`, or switch to a fixed-layout binary encoding.
  - Take `&Zeroizing<[u8;32]>` in `set_persist_key`.
  - Wrap `BackupPayload` in a zeroizing drop guard.
  - On `destroy_object`, mark the object destroyed (`lifecycle_state = Destroyed`) so that cached operations fail. Then clear `key_material` explicitly.

### H3-21 [Low] Session accounting races and C_InitToken session semantics

- **Location:**
  - `src/token/token.rs:447-448`: `init_token` stores 0 into both session counters while sessions can still exist (opened between `functions.rs:515` and `:522`)
  - `src/session/manager.rs:88-108` (`close_all_sessions` does not clear `active_operation` eagerly, unlike `close_session` at `:78-83`)
  - `src/session/manager.rs:133-183`: `login_all` errors ignored by the caller (`functions.rs:932`), so token and session login state can diverge
- **CWE:** CWE-362, CWE-667
- **Confidence:** Likely
- **Description:** Resetting the counters under live sessions causes counter drift. Later `decrement` calls fail with `GeneralError`, or the per-token `max_sessions`/`max_rw_sessions` limits become too permissive.
- **Recommendation:**
  - Remove the counter reset: `close_all_sessions` already decrements.
  - Refuse `C_InitToken` when sessions exist.
  - Clear active operations in `close_all_sessions`.
  - Handle `login_all` failure by rolling back `token.login`.

### H3-22 [Low] Unbounded audit channel and O(n) in-memory trimming

- **Location:** `src/audit/log.rs:514,571` (`mpsc::channel()`, unbounded), `:402-423` (open, stat and fsync per event), `:440-443` (`Vec::drain(..1)` on 100k entries for every event once the cap is reached)
- **CWE:** CWE-770
- **Confidence:** Confirmed
- **Description:** The worker does one `open` and one `fsync` per event, which is milliseconds each. Producers such as `C_GenerateRandom`, `C_Sign` and `C_FindObjects` enqueue without back-pressure, so a busy or malicious client grows the queue without bound (memory DoS). Once 100k entries exist, every event also memmoves about 100k `AuditEvent`s.
- **Recommendation:**
  - Use `sync_channel(N)` with blocking or fail-closed behaviour.
  - Keep a persistent file handle and batch fsyncs (group commit).
  - Replace `Vec` with `VecDeque`.

### H3-23 [Low] Lifecycle enforcement incomplete and stringly-typed

- **Location:** `src/store/object.rs:283-305` (`&str` operation names; errors mapped to `GeneralError` instead of `CKR_KEY_FUNCTION_NOT_PERMITTED`), `:349-381` (accepts invalid dates like 20250231). Callers exist only for encrypt, decrypt, sign and verify (`functions.rs:1465,1762,2003,2387`). `Compromised` and `Destroyed` are never assigned anywhere.
- **CWE:** CWE-285, CWE-1188
- **Confidence:** Confirmed
- **Description:** Deactivated or expired keys can still wrap, unwrap, derive and copy. There is no API to mark a key compromised. A typo in an operation string silently changes the policy.
- **Recommendation:**
  - Use an `enum KeyUsage { Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive }` and enforce it in every mechanism entry point.
  - Validate `CK_DATE` values strictly.
  - Map errors to the correct `CKR_*` codes.
  - Add an SO-only vendor attribute or function to set `Compromised`.

### H3-24 [Low] `C_CreateObject` template semantics and duplicate attributes

- **Location:**
  - `src/store/attributes.rs:243-255`: the class comes from the *first* `CKA_CLASS`, then every duplicate is re-applied, so the last one wins
  - `src/store/attributes.rs:439-454` + `src/store/object.rs:117-119`: `CKA_SENSITIVE=FALSE` or `CKA_EXTRACTABLE=TRUE` always fail against the `new()` defaults
  - `src/store/attributes.rs:433-481`: boolean attributes of any length accepted (`value[0]`)
  - `src/store/attributes.rs:596-604`: lenient `read_ck_ulong` (`len < size`) vs. strict `src/store/object.rs:417-425`
- **CWE:** CWE-20 (Improper Input Validation), CWE-694
- **Confidence:** Confirmed
- **Description:** Duplicate or contradictory attributes are accepted instead of returning `CKR_TEMPLATE_INCONSISTENT`. The ABI's key-class login gate uses `any()`, which happens to be safe, but future checks that use `find()` would disagree with the stored value. The two parsers disagree: a 16-byte `CKA_CLASS` is accepted at creation but can never be found.
- **Recommendation:**
  - Reject duplicate attribute types in `parse_template` or `create_object`.
  - Use one strict `read_ck_ulong` and one strict `parse_ck_bbool`.
  - Apply per-class defaults before template application, following PKCS#11 default semantics.

### H3-25 [Low] `C_SetAttributeValue` / `destroy_object` persistence errors silently ignored (resurrection)

- **Location:** `src/store/attributes.rs:207-213` (`persist_object` logs and continues), `:224-229` (`unpersist_object` logs and continues after a failed delete), `:258` (persist before insert; failure invisible to caller)
- **CWE:** CWE-755, CWE-460
- **Confidence:** Confirmed (latent until persistence is wired)
- **Description:** A failed delete leaves the encrypted blob on disk, and the "destroyed" key is reloaded on the next start. A failed persist returns `CKR_OK` for a token object that will vanish. `C_SetAttributeValue` (`functions.rs:1232-1296`) never persists changes at all.
- **Recommendation:** Return errors through `create_object`, `insert_object` and `destroy_object`, performing the store write first and the in-memory change on success. Persist after `C_SetAttributeValue`.

### H3-26 [Informational] In-memory `verify_chain` false positives; timestamp floor reset

- **Location:** `src/audit/log.rs:922-935` (expects the first entry's `previous_hash == 0`; wrong after restart with a recovered hash (`:566`) or after trimming (`:440-443`)); `:568,579` (`last_timestamp` restarts at 0, so cross-restart monotonicity is not enforced)
- **Confidence:** Confirmed
- **Recommendation:** Store the chain base hash alongside `entries`. Recover `last_timestamp` from the last on-disk event.

### H3-27 [Informational] Inconsistent security defaults and constants

- **Location:**
  - PBKDF2: `encrypted_store.rs:15` (1,000,000) vs `token.rs:152` and `config.rs:205-207` (600,000); `backup.rs:61-63` doc says 600k but the actual fallback is 1M
  - Failed logins: `token.rs:19` (5) vs `config.rs:202-204` (10)
  - Duplicated `SALT_LEN`/`NONCE_LEN`: `backup.rs:33-34`, `encrypted_store.rs:16-17`
- **Recommendation:** Keep a single `security::defaults` module. Store KDF id and iterations inside PIN hashes (`salt||key` has no parameters, `encrypted_store.rs:459-483`), so parameters can be migrated.

### H3-28 [Informational] Search templates on boolean attributes never match

- **Location:** `src/store/object.rs:157-234`: `CKA_EXTRACTABLE`, `CKA_MODIFIABLE`, `CKA_WRAP`, `CKA_UNWRAP`, `CKA_DERIVE`, `CKA_DESTROYABLE`, `CKA_COPYABLE`, `CKA_VALUE_LEN` and `CKA_MODULUS` fall to the `extra_attributes` branch and return 0. Empty-valued `CKA_TOKEN`/`CKA_PRIVATE` templates match anything (`:173-186`).
- **Confidence:** Confirmed
- **Recommendation:** Route template matching through `read_attribute` (non-sensitive attributes only) so that matching and reading use one source of truth.

### H3-29 [Informational] Windows ACL helper and permission fallbacks fail open

- **Location:**
  - `src/store/encrypted_store.rs:286-302,308-422`: every failure is only logged
  - `src/audit/log.rs:307-317`: explicitly continues when ACL setting fails
  - `src/config/config.rs:418-424`: `canonicalize` failure skips the ACL check
  - `src/config/config.rs:425-455`: parses localized `icacls` text output (breaks on non-English Windows)
- **Confidence:** Confirmed
- **Recommendation:** Return errors and refuse to start if permissions cannot be enforced. Use `GetSecurityInfo` or `GetEffectiveRightsFromAcl` instead of parsing `icacls` output.

## Stubs, TODOs and unimplemented items

`grep` for `todo!`, `unimplemented!`, `TODO`, `FIXME`, `XXX` and `HACK` in scope returned **no hits**. The table lists functional stubs: code that exists but is not wired in, or whose behaviour is a placeholder.

| # | Item | Location | Status / effect |
|---|---|---|---|
| S1 | `TokenConfig::persist_objects` | `src/config/config.rs:58-62` | Parsed, never read; persistence is never enabled |
| S2 | `AuditConfig::log_level` ("all/crypto/auth/admin/none") | `src/config/config.rs:103-104,676-682` | Validated, never used; every event is logged whatever the level |
| S3 | `EncryptedStore`, `ObjectStore::with_persistence`, `set_persist_key`, `load_from_store` | `src/store/encrypted_store.rs`, `src/store/attributes.rs:61-172` | Used only by `tests/persistence.rs`; no salt storage and no re-key on PIN change |
| S4 | Token state persistence (PIN hashes, `initialized`, label) | `src/token/token.rs:167-181` | Missing entirely |
| S5 | Backup/restore end-to-end | `src/store/backup.rs` + `tools/craton-hsm-admin/src/commands/backup.rs:106-249` | Operates on an ephemeral `HsmCore`; the backup is always empty and the restore is discarded |
| S6 | `PersistentReplayGuard::consumed_ids()` "backward compatibility" API | `src/store/backup.rs:392-402` | Diff-based caller contract; error-prone |
| S7 | `KeyLifecycleState::Compromised` / `Destroyed` | `src/store/object.rs:20-26` | Never assigned by any code path |
| S8 | Lifecycle checks for wrap/unwrap/derive | `src/store/object.rs:283-305` | Not called for those operations |
| S9 | `CryptoObject` enum | `src/store/object.rs:388-400` | No users found in scope (dead type) |
| S10 | `AuditOperation::InitToken/OpenSession/CloseSession/WrapKey/UnwrapKey/DeriveKey/FindObjects/GetAttributeValue/Digest` | `src/audit/log.rs:55-123` | Variants defined but never emitted by the C ABI |
| S11 | Session-object ownership / destruction on close | `src/session/manager.rs:70-108` | Not implemented |
| S12 | `ActiveOperation::Sign/Verify` state serialization | `src/session/session.rs:170-193` | Hasher state not serialized (`0u32` param placeholder); a restored multi-part sign replays `data` only |
| S13 | `CKU_CONTEXT_SPECIFIC` / `CKA_ALWAYS_AUTHENTICATE` | `src/token/token.rs:679-681` | Rejected as `UserTypeInvalid`; per-operation re-auth unsupported |
| S14 | Handle "ensure_past" | `src/session/handle.rs:224-226` | Name is misleading: it reserves one value rather than advancing the counter; the set grows without bound |
| S15 | `chrono_timestamp()` | `src/store/backup.rs:454-460` | Placeholder string `"<n>s-since-epoch"`, not ISO-8601 as the doc says |

## Code review

**Quality and maintainability**

- **Authorization is spread out.** Security policy is split between `apply_attribute`/`read_attribute` (store), ad-hoc template loops in each ABI function (`C_GenerateKey`, `C_UnwrapKey`, `C_CopyObject` each re-implement attribute handling with different rules), and the daemon. This is the root cause of H3-02, H3-05 and H3-24. Recommendation: one `ObjectPolicy` module with `validate_create(class, template, session_role)`, `validate_copy`, `readable(attr)` and `searchable(attr)`, used by every front end.
- **Destructive semantics live in the wrong layer.** `Token::init_token` does not own wiping objects and sessions, so the C ABI and the daemon diverge (H3-01, H3-14).
- **Too much `pub` surface.** `StoredObject` fields are all `pub`, so any module can flip `sensitive` or `extractable`. Use private fields with monotonic setters (`make_sensitive()`, `make_non_extractable()`).
- **Stringly-typed operations** (`check_lifecycle("encrypt")`) and `u8` magic numbers for operation state. Prefer enums.
- **Two `read_ck_ulong` implementations** with different strictness (`attributes.rs:596`, `object.rs:417`).
- **Doc and comment drift:**
  - "fail-closed on corruption" (the lockout file is fail-open on deletion);
  - "rejects insecure ownership" (`config.rs:368-369`, which checks mode only);
  - "HSM must not continue ... with a compromised audit trail" (`log.rs:727-728`, but callers ignore the error);
  - "Falls back to the crate default (600k)" (`backup.rs:61-63`; actually 1M).

**Error handling**

- Security-relevant I/O failures are swallowed across the board: `persist_object`, `unpersist_object`, `LockoutStore::save`, `ObjectStore::clear`, `list_keys` iteration errors (`encrypted_store.rs:255-259`), `set_restrictive_permissions`, and audit disk writes. An HSM should fail closed on these.
- Errors are coarse: `GeneralError` is used for lifecycle denial, a non-destroyable object (`attributes.rs:309`; should be `CKR_ACTION_PROHIBITED`) and an invalid date (`attributes.rs:514,525`; should be `CKR_ATTRIBUTE_VALUE_INVALID`).
- There are panics in library paths: `spawn_worker(...).expect(..)` (`log.rs:503`) and `HsmCore::new().expect` (`core.rs:116`). They are behind `catch_unwind` in the ABI, but they abort daemon startup without a clean error.

**Concurrency**

- `logout_all` (`manager.rs:194-197`) takes session write locks while iterating DashMap shards (holding shard read guards). `close_all_sessions` takes the token `auth` mutex inside `DashMap::retain` (`manager.rs:96-107`), which holds a shard write lock. I found no concrete deadlock cycle in the current ABI (Possible only). Still, locking order across `DashMap` shard → `Session` `RwLock` → `Token.auth` is undocumented and fragile. Collect handles first, then lock individually, as `login_all` already does.
- `MAX_OBJECTS` check-then-insert (`attributes.rs:238-260`) is not atomic, so it can be exceeded by the number of concurrent creators.
- `parking_lot` locks do not poison, which is good for availability. However, a panic mid-update (for example inside `apply_attribute`) can leave a `StoredObject` partially mutated. `create_object` builds a fresh object first, so it is safe; `C_SetAttributeValue` mutates in place.

**Test gaps (no existing tests found for these properties)**

1. `C_InitToken` with a wrong or short PIN must leave objects and sessions intact (H3-01).
2. `C_GetAttributeValue(CKA_VALUE)` on a sensitive+extractable key must return `CKR_ATTRIBUTE_SENSITIVE`; same for `CKA_PRIVATE_EXPONENT` (H3-02).
3. Multi-slot object isolation through the C ABI (`tests/multi_slot.rs` only checks token independence) (H3-03).
4. Token state and lockout across a simulated restart (H3-04, H3-17).
5. Session objects destroyed on `C_CloseSession` (H3-07).
6. SO session cannot use or read private user keys (H3-06).
7. Audit rotation followed by `AuditLog::new_with_path` on the same path must *not* report tampering (H3-11).
8. Concurrency test for `open_session` racing `C_Logout` (H3-08).
9. Property and fuzz tests for `apply_attribute` with duplicate and contradictory templates (H3-24).
10. Restore of a crafted backup with `sensitive=false` / `CKA_TRUSTED` (H3-16).

## Performance improvement suggestions

| # | Location | Issue | Suggestion |
|---|---|---|---|
| P1 | `src/token/token.rs:579-605,644-650,407-417` | PBKDF2 (0.3–1 s) under the token-wide `auth` mutex serializes `C_OpenSession`, `C_GetTokenInfo` and other logins | Snapshot the hash under the lock, run PBKDF2 unlocked, then commit under the lock with a generation check (also fixes H3-09) |
| P2 | `src/audit/log.rs:402-423` | `open()` + `metadata()` + `fsync` per event | Keep a `BufWriter<File>` open; group-commit fsync every N events or T ms (sync only for auth and key-management events); track size in a counter instead of `metadata()` |
| P3 | `src/audit/log.rs:440-443` | `Vec::drain(..1)` memmoves about 100k events on every record once full | `VecDeque` with `pop_front`, or a ring buffer |
| P4 | `src/audit/log.rs:211` | `serde_json::to_vec` allocates per event for hashing, then serializes again for the file (`:411`) | Serialize the payload once, hash it, and reuse the bytes when writing the line |
| P5 | `src/store/encrypted_store.rs:116-117` | `HmacDrbg::new()` (OS entropy + instantiate) for every 12-byte nonce | Keep one DRBG per store under a mutex, or use a counter-based nonce with a random prefix per key |
| P6 | `src/store/encrypted_store.rs:119-120,197-198` | `Aes256Gcm::new` key schedule per call | Cache the cipher alongside `persist_key` (zeroize on logout) |
| P7 | `src/store/attributes.rs:128-132` + `encrypted_store.rs:160-188` | `load_from_store` opens one read transaction per key after `list_keys` opened another | Iterate the table once in a single read transaction and decrypt inline |
| P8 | `src/store/encrypted_store.rs:133-150` | One write transaction (fsync) per object | Batch API for bulk import and restore |
| P9 | `src/session/handle.rs:213` | `reserved.lock()` (mutex) on every object-handle allocation, and the set grows without bound | Check an `AtomicBool is_empty` first, or reserve by bumping the counter once at load time |
| P10 | `src/session/manager.rs:192-217` | `logout_all` / `has_ro_sessions` scan all sessions across all slots | Maintain per-slot session indices and an RO-session counter per token |
| P11 | `src/store/attributes.rs:371-392` | `find_objects` takes a read lock on every object and does a full match (intentional for timing) | Keep the full-scan property but pre-filter by slot via a per-slot map; avoid `Vec::with_capacity(total)` when the total is large |
| P12 | `src/store/backup.rs:105` | `objects.to_vec()` clones every object (including key material, mlock syscalls per key) | Serialize from a borrowed slice (`#[derive(Serialize)] struct BackupPayload<'a> { objects: &'a [StoredObject] }`) |
| P13 | `src/store/key_material.rs:21-44,77-84` | `mlock`/`munlock` syscall per key allocation and per clone | Use a pooled mlocked arena (for example `memsec` or a custom slab) for small keys |
| P14 | `src/store/backup.rs:419-451` | Passphrase is iterated twice (`chars().count()` plus the loop), with a `HashSet<char>` allocation | Count in the same loop; use a small bitset for ASCII |
