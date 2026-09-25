# H5 — craton-hsm-admin CLI & tooling scripts: offensive security review

Date: 2026-09-24. Worktree: `/home/user/craton-hsm-audit-wt` (branch `claude/modest-hamilton-y6ok79`).

## Scope & method

| Area | Files |
|---|---|
| Admin CLI crate | `tools/craton-hsm-admin/Cargo.toml`, `src/main.rs`, `src/output.rs`, `src/commands/{mod,token,pin,key,backup,audit}.rs` |
| Integrity tooling | `tools/compute-integrity-hmac.{sh,ps1}`, `tools/generate-integrity-keypair.{sh,ps1}`, `tools/sign-integrity.{sh,ps1}` |
| CI helpers | `scripts/ci-local.sh`, `scripts/local-ci.sh` |

Root-crate code read only to confirm behaviour: `src/core.rs`, `src/token/{token,slot}.rs`, `src/store/{attributes,backup,lockout_store,encrypted_store,object}.rs`, `src/audit/log.rs`, `src/config/config.rs`, `src/crypto/integrity.rs`, plus `rpassword 7.4.0` / `rtoolbox 0.0.3` sources from the cargo registry.

**Method:** static review only. Nothing was built, tested or executed. `shellcheck` and `pwsh` are not installed, so the scripts were reviewed by hand. Every finding cites code that was read. Confidence levels:

- **Confirmed:** the code path was traced end to end.
- **Likely:** the behaviour depends on the platform or runtime.
- **Possible:** it depends on how the tool is deployed.

Each finding has a one-sentence **Trigger condition** in place of exploit detail.

## Executive summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 4 |
| Medium | 7 |
| Low | 9 |
| Informational | 4 |
| **Total** | **24** |

**Root cause of most findings.** Every CLI invocation builds a new, private `HsmCore`:

- It has an empty, non-persistent `ObjectStore::new()` (`src/core.rs:135`).
- Its token always has `so_pin_hash`/`user_pin_hash = None` and `initialized = false` (`src/token/token.rs:157-170`).
- No code in the repository persists PIN hashes or loads token objects on this path.

The CLI shares only three on-disk artefacts with a real deployment: the lockout file, the audit log and the backup replay guard. As a result:

- It reports success for operations that have no lasting effect.
- Backups and audit exports are always empty.
- A tampered audit log is reported as valid.
- It still makes irreversible changes to the shared files.

Every authenticated subcommand (`key *`, `pin *`) always fails with "Token is not initialized".

**Top 5 risks**

1. **H5-01 High:** `token init` resets persisted PIN-lockout state with no authentication and no confirmation (`commands/token.rs:11-46` → `src/token/token.rs:411,440-445`).
2. **H5-02 High:** `backup` always produces a 0-object backup. `restore`, `key import/delete` and `token init` have no lasting effect but report success (`commands/backup.rs:108-114,220-244`; `src/core.rs:135`).
3. **H5-03 High:** `audit verify-chain` reports VALID for a tampered on-disk audit log, and the exports are always empty (`commands/audit.rs:65-96`; `src/audit/log.rs:550-569,922-935`).
4. **H5-04 High:** `restore` marks a backup as consumed before its objects are stored anywhere durable. A valid backup becomes permanently unrestorable (`commands/backup.rs:197-242`).
5. **H5-07 Medium:** `compute-integrity-hmac.sh` places the secret HMAC key in the `openssl` argument vector, although its comments say it does not (`tools/compute-integrity-hmac.sh:66-74`).

**Positive observations**

- PINs and passphrases are never taken from argv or the environment. They are read with `rpassword` from `/dev/tty` with no echo.
- Secrets are wrapped in `Zeroizing`.
- The Unix backup file is created with `create_new` (O_EXCL) and mode `0600`.
- The config loader rejects symlinked and group- or world-writable files.
- All bash scripts use `set -euo pipefail`.
- The CLI contains no `unsafe`, FFI or `dlopen`. Library loading from an environment variable exists only in `tools/pkcs11-spy`, which is outside H5's scope.

## Findings

### H5-01 [High] `token init` resets persisted lockout state without authentication or confirmation
- **Location:** `tools/craton-hsm-admin/src/commands/token.rs:11-46`. Root: `src/token/token.rs:157-170`, `:411`, `:440-445`; `src/store/lockout_store.rs:131-137`.
- **CWE:** CWE-306, CWE-307.
- **Confidence:** Confirmed.
- **Description:** A new `Token` loads the failed-login counters and lock flags from `<storage_path>/lockout_state.json`. It always starts with `initialized = false` and no PIN hashes. The branch that verifies an existing SO PIN (`if auth.initialized`) therefore never runs in the CLI. `init_token` resets all auth state and deletes the shared lockout file. The CLI does not check the token's state first and does not ask for confirmation. It prints "Token initialized successfully." even though the new SO PIN is lost when the process exits.
- **Trigger condition:** Running `token init` with a config whose `storage_path` points to a deployment's lockout file.
- **Impact:** Lockout counters and SO/User lock flags are cleared for the real deployment. This removes brute-force protection on PINs and erases the record of failed logins. The risk is greater where the CLI is delegated via sudo or runs as the service account.
- **Recommendation:**
  - Persist token-initialization state.
  - Require the current SO PIN before re-initializing.
  - Never call `LockoutStore::clear()` on a path that has not verified an existing SO PIN.
  - Require typed confirmation, with `--yes` for automation.
  - Audit every attempt.

### H5-02 [High] The CLI runs on a throwaway in-memory core: backups are empty and changes do not persist, yet it reports success
- **Location:**
  - `src/core.rs:135`: `ObjectStore::new()`. `with_persistence` and `load_from_store` are used only in `tests/persistence.rs`.
  - `commands/backup.rs:108-114`: export from an empty store.
  - `commands/backup.rs:220-244`: restore into a fresh core that is then discarded.
  - `commands/key.rs:160,194-209,279-283` and `commands/token.rs:13,40-45`.
  - Contradicting documentation: `docs/architecture.md:116`.
- **CWE:** CWE-440, CWE-684.
- **Confidence:** Confirmed.
- **Description:**
  - `backup` encrypts an empty store and prints "Backup created … (0 objects …)".
  - `restore` prints "Restored N objects" and then exits.
  - `key import`, `key delete` and `token init` change only process memory.
  - Every authenticated command fails its `is_initialized()` check (`key.rs:24-26`, `pin.rs:56-58,146-148`), so `key list`, `pin change` and `pin reset` cannot work.
- **Trigger condition:** Any invocation of `backup`, `restore`, `key *`, `pin *` or `token init`.
- **Impact:** Disaster recovery fails silently because backups are valid but empty. Operators get false assurance about token contents and about the administrative controls.
- **Recommendation:**
  - Make the CLI a client of the daemon (gRPC with mTLS), or open the persistent `EncryptedStore` and persist token/PIN state.
  - Until then, make these subcommands fail with "unsupported in standalone mode".
  - Refuse to write a 0-object backup unless `--allow-empty` is given.
  - Correct `docs/architecture.md`.

### H5-03 [High] `audit verify-chain` reports VALID for a tampered audit log; exports are always empty
- **Location:** `commands/audit.rs:65-96`. Root: `src/audit/log.rs:550-569` (the tamper result goes only into `tamper_flag`, and in-memory `entries` start empty), `:594-596` (`is_tamper_detected`, never called), `:922-935` (`verify_chain` walks only in-memory entries).
- **CWE:** CWE-354, CWE-778.
- **Confidence:** Confirmed.
- **Description:** Audit is enabled by default (`src/config/config.rs:160-167`). In that case `AuditLog::new_with_path` re-hashes the on-disk log, and on a broken chain it only logs an error and sets `tamper_flag`. The CLI then calls `verify_chain()` on the empty vector and prints `VALID` / `entries_verified: 0` with exit code 0. The error log is lost because no tracing subscriber is installed (H5-09). The `export-*` commands print empty output, and `dump` never prints entries.
- **Trigger condition:** Running `audit verify-chain` or `audit export-*` against a config whose audit log file exists, whether intact or modified.
- **Impact:** Integrity monitoring gives false negatives and the SIEM receives no events. This undermines the product's tamper-evidence claim.
- **Recommendation:**
  - Verify the on-disk file and its rotated generations directly.
  - At minimum, fail with a distinct exit code when `is_tamper_detected()` is true.
  - Report the number of entries verified from the file.
  - Make exports read the file, or refuse with an error.

### H5-04 [High] `restore` consumes the backup ID before the objects are stored durably
- **Location:** `commands/backup.rs:197-219` (IDs persisted), then `:220-242` (inserts into the ephemeral core, where failures only warn). Error mapping at `:205-210`.
- **CWE:** CWE-696.
- **Confidence:** Confirmed.
- **Description:** The replay guard is updated as soon as decryption succeeds, before any insert and regardless of whether any object is stored. With H5-02, the objects are discarded but the backup can never be restored again. Every library error, including a replay rejection, is shown as "wrong passphrase or corrupt file".
- **Trigger condition:** One `restore` run of a valid, in-date backup against the production config directory.
- **Impact:** The backup is permanently unusable, and the error message misleads the operator during an incident.
- **Recommendation:**
  - Record the ID only after all objects are committed, in the same transaction.
  - Roll back on partial failure.
  - Return distinct errors for passphrase, replay, age and serial problems.
  - Add a non-consuming `--verify-only` mode.

### H5-05 [Medium] Backup, restore and audit export perform no authentication
- **Location:** `commands/backup.rs:106-115` and `:171-244`; `commands/audit.rs:9-62`. Library contract: `src/audit/log.rs:784,794,807` ("Callers must verify SO authorization"). Restored attributes are not validated: `src/store/attributes.rs:268-281`.
- **CWE:** CWE-862, CWE-306.
- **Confidence:** Confirmed that no authentication is performed. Exploitability is Possible, because it is currently masked by H5-02.
- **Description:** `key *` and `pin *` authenticate first. The other commands do not:
  - `backup` exports every object under a passphrase chosen by whoever runs it.
  - `restore` inserts `StoredObject`s whose `sensitive`, `extractable`, `private` and `handle` fields come straight from the payload.
  - The audit commands need no SO login.

  Once persistence is wired in (the fix for H5-02), this becomes key export and key injection without a PIN.
- **Trigger condition:** Running `backup`, `restore` or `audit *` as any user who can read the config and data directory.
- **Impact:** Latent loss of key confidentiality and integrity, and exposure of audit data.
- **Recommendation:**
  - Require an SO login before backup, restore and audit.
  - Offer an M-of-N option for export.
  - On restore, re-validate objects through the `C_CreateObject` attribute rules and reassign their handles.

### H5-06 [Medium] Replay-guard file location, symlink handling and locking
- **Location:** `commands/backup.rs:187-191`. Root: `src/store/backup.rs:299-333` (load), `:351-381` (record); `src/store/encrypted_store.rs:286-296`.
- **CWE:** CWE-73, CWE-59, CWE-367, CWE-294.
- **Confidence:** Confirmed (path and link handling); Likely (race).
- **Description:**
  1. The guard is stored next to `--config`. With the default relative config path, `parent()` is empty, so the guard ends up in the current working directory. Another directory or a copy of the config gives an empty guard.
  2. `record` opens the file with `create+append` and no `O_NOFOLLOW`, then calls `set_permissions`, which follows symlinks.
  3. The replay check uses a snapshot taken when the guard is constructed, and the exclusive lock is taken only while appending. Two concurrent restores can both pass. This contradicts the comment at `src/store/backup.rs:348-350`.
- **Trigger condition:** Running `restore` from a different working directory or config location, or where `.craton_hsm_replay_guard` is a symbolic link.
- **Impact:**
  - Replay protection is bypassed.
  - A privileged run can have its append and permission change redirected to another file.
  - Duplicate restores can run concurrently.
- **Recommendation:**
  - Keep the guard under the validated `storage_path`.
  - Open it with `O_NOFOLLOW` and use `fchmod` on the file descriptor.
  - Hold the lock across load, check, record and commit.
  - Authenticate the guard contents.

### H5-07 [Medium] `compute-integrity-hmac.sh` puts the HMAC key in the process argument list; the tool is obsolete
- **Location:**
  - `tools/compute-integrity-hmac.sh:53-74`: the comments say the key never appears in argv, but line 74 passes `-macopt "hexkey:${HMAC_KEY_HEX}"`.
  - `:35-36`: the environment variable overrides the key-file argument.
  - `:32`: refers to `INTEGRITY_HMAC_KEY`, which no longer exists.
  - `src/crypto/integrity.rs:98-107`: HMAC verification has been removed.
- **CWE:** CWE-214, CWE-1164.
- **Confidence:** Confirmed.
- **Description:**
  - Hex-encoding does not remove the key from argv: `hexkey:<hex>` is an `openssl` argument and is visible in the process table while `openssl` runs. Staging the key in a temp file first (lines 58-68) does not help.
  - The key is also inherited by child processes through the environment.
  - The library no longer checks `.hmac` sidecars, so the script produces files that give no assurance while still asking for a secret.
- **Trigger condition:** Running the script on a host where other local users can list processes.
- **Impact:** The HMAC key is disclosed to local users, and operators are misled about the integrity protection in place.
- **Recommendation:**
  - Remove `compute-integrity-hmac.sh` and `.ps1` and point users to `sign-integrity.*`.
  - If an HMAC tool must remain, compute the MAC in a helper that reads the key from a 0600 file, never from argv or the environment.
  - Rotate any key that was used with this script.

### H5-08 [Medium] Release-signing private key is stored unencrypted; the PowerShell variant sets no ACL
- **Location:**
  - `tools/generate-integrity-keypair.sh:17-32`: `genpkey` without a cipher; the file is created under the caller's umask and only then `chmod 600`; the script `chmod 700`s whatever output directory it is given.
  - `tools/generate-integrity-keypair.ps1:15-38`: no ACL hardening; a custom `-OutputDir` inherits its parent's ACL.
- **CWE:** CWE-312, CWE-732.
- **Confidence:** Confirmed (no encryption, no ACL); Possible (exposure depends on the output directory).
- **Description:** The Ed25519 key that anchors binary integrity (`src/crypto/integrity.rs`) is a plaintext PEM file in the user's home or a caller-chosen directory. Nothing points users toward passphrase protection or a KMS/HSM.
- **Trigger condition:** Generating the key into a directory whose ACL or umask lets other principals read it, or into a directory that is backed up.
- **Impact:** Anyone holding a copy of the key can produce validly signed tampered binaries.
- **Recommendation:**
  - Sign in a KMS or HSM, or at least encrypt the PEM (`-aes-256-cbc -pass file:`).
  - Create the key with `umask 077` in a subshell.
  - Apply an owner-only ACL in PowerShell.
  - Do not `chmod` a directory the script did not create.
  - Document key custody.

### H5-09 [Medium] No tracing subscriber: the library's security warnings are discarded
- **Location:** `tools/craton-hsm-admin/src/main.rs:130-169`; `Cargo.toml:13-19` has no `tracing-subscriber`. Examples of lost messages:
  - `src/audit/log.rs:554-560`: tamper detected.
  - `src/store/lockout_store.rs:61-65`: lockout file corrupted.
  - `src/config/config.rs:521-531`: config parse errors that tell the user to "check logs for details".
- **CWE:** CWE-778, CWE-223.
- **Confidence:** Confirmed.
- **Description:** The core reports security-relevant conditions only through `tracing`. The CLI never installs a subscriber, so these messages are dropped, and user-facing errors point to logs that do not exist.
- **Trigger condition:** Any CLI run in which the core emits a warning or error through `tracing`.
- **Impact:** Operators never see tamper, lockout-corruption, replay-rejection or config-parse details. This makes H5-03 and H5-04 worse.
- **Recommendation:**
  - Install a `tracing_subscriber` that writes to stderr at WARN by default, adjustable with `-v` or `RUST_LOG`.
  - Turn important conditions, such as the tamper flag, into explicit CLI errors.

### H5-10 [Medium] Windows backup path: fails open on ACL errors, uses a predictable temp file, and overwrites existing files
- **Location:**
  - `commands/backup.rs:79-95`: a non-zero `icacls` exit or a spawn failure prints a warning and returns `Ok`.
  - `:132-160`: `.craton_hsm-backup-<pid>.tmp` is written with `std::fs::write`, then moved over the target with `std::fs::rename`.
  - `:52-56,69`: `whoami` and `icacls` are resolved through `PATH`.
- **CWE:** CWE-636, CWE-377, CWE-732, CWE-427.
- **Confidence:** Likely (Windows-only path, not run on Windows).
- **Description:**
  - If hardening the ACL fails, the backup is still moved into place with inherited ACLs.
  - `std::fs::write` reuses any existing file with the temp name and keeps its ACL. `/inheritance:r /grant:r` does not remove explicit ACEs that a pre-existing file already has.
  - `rename` replaces an existing output file, whereas the Unix path refuses to overwrite (`create_new`).
  - Resolving `whoami` through `PATH` has the same trust problem that the code comment attributes to `%USERNAME%`.
- **Trigger condition:** Running `backup` on Windows when `icacls` fails, when the output directory already contains a file with the temp name, or when the output path already exists.
- **Impact:** Encrypted key backups may be readable by other principals, which permits offline passphrase guessing. Existing backups can be overwritten silently.
- **Recommendation:**
  - Create the file with an explicit owner-only security descriptor and `CREATE_NEW` (`windows` crate), and drop `icacls`.
  - Fail closed on any ACL error.
  - Use a random temp name with `create_new`.
  - Refuse to overwrite the target.
  - Resolve tools by absolute `%SystemRoot%\System32` path.

### H5-11 [Medium] Config is found relative to the working directory, missing configs silently fall back to defaults, and "strict" loading is not strict
- **Location:**
  - `main.rs:12`: the default `craton_hsm.toml` is a relative path.
  - `commands/token.rs:153-160`: `load_config_strict` is documented as failing when the config is missing but is identical to `load_config`.
  - `src/config/config.rs:496-501`: a missing file yields `Default`.
  - `config.rs:187-189,211-213`: relative `storage_path` and `log_path` defaults.
- **CWE:** CWE-427, CWE-1188.
- **Confidence:** Confirmed.
- **Description:**
  - The CLI's effective config depends on the current directory.
  - A mistyped `--config` silently applies default settings, including CWD-relative store, lockout and audit paths and the default serial `0000000000000001`.
  - The message about the fallback is lost (H5-09).
  - Mutating commands such as `token init` still run.
- **Trigger condition:** Running any subcommand from an unintended directory, or with a `--config` path that does not exist.
- **Impact:** Operations act on unintended state files. A config file planted in a shared working directory can be picked up. Backups are bound to the default serial.
- **Recommendation:**
  - Require an explicit config path, or use an absolute system default.
  - Make mutating commands fail when the config is missing.
  - Resolve relative paths against the config file's directory.
  - Check that the config file is owned by the invoking or service user.

### H5-12 [Low] The PIN complexity policy is weak
- **Location:** `commands/pin.rs:12-45`, used by `pin.rs:120,200` and `token.rs:31`.
- **CWE:** CWE-521.
- **Confidence:** Confirmed.
- **Description:** The policy rejects only a single repeated character and strictly ascending or descending sequences. Values such as `12121212`, `abababab`, `password` or `11111112` pass. The redundant "2 distinct characters" check (lines 31-42) can never trigger after the repeated-character check. The rules are also not shared with the library, so the C ABI and daemon paths apply different rules.
- **Trigger condition:** Setting a new SO or User PIN made of a short repeating pattern or a dictionary word.
- **Impact:** PINs are easier to guess, which lowers the value of the lockout protection.
- **Recommendation:** Move the policy into the core (`Token::validate_pin`). Add a check against a common-PIN or deny list and a minimum number of distinct characters (for example ≥4). Unit-test the policy.

### H5-13 [Low] `key import` is effectively a placeholder and does not validate input
- **Location:** `commands/key.rs:158-215`: `fs::read` at 168, template at 183-191; `src/store/attributes.rs:233-262` (no length check on key material).
- **CWE:** CWE-20, CWE-1284.
- **Confidence:** Confirmed.
- **Description:**
  - The help text says "PEM or DER", but the raw file bytes are stored as `CKA_VALUE` for RSA and EC private keys. PKCS#11 RSA and EC private keys need component attributes, so the resulting object cannot be used.
  - AES key length (16/24/32 bytes) is not checked.
  - `CKA_PRIVATE=1` is set even when the user authenticated as SO.
  - Attribute integers are encoded with `to_le_bytes` but decoded with `from_ne_bytes` (`attributes.rs:596-604`), which breaks on big-endian targets.
- **Trigger condition:** Importing any RSA or EC key file, or an AES file whose length is not a valid key size.
- **Impact:** Unusable or malformed key objects are created while the CLI reports success.
- **Recommendation:** Parse PKCS#8/SEC1/PKCS#1 with the `pkcs8`, `sec1` and `rsa` crates and map the result to PKCS#11 attributes. Enforce AES key sizes. Encode with `to_ne_bytes` using `CK_ULONG`. Reject private-object creation under an SO login.

### H5-14 [Low] Role model not enforced for key operations, and object handles are truncated on Windows
- **Location:** `commands/key.rs:30-36` (any input other than `S`/`SO` silently means User), `:85` (`find_objects(&[], true)` for either role), `:225` (`handle as CK_OBJECT_HANDLE`); `main.rs:93-96`.
- **CWE:** CWE-285, CWE-197.
- **Confidence:** Confirmed; the truncation is Likely on LLP64 (Windows).
- **Description:**
  - An SO login can list and delete private user objects, which PKCS#11 does not allow.
  - On Windows `CK_ULONG` is 32-bit, so a `u64` handle above `u32::MAX` wraps to another handle. The confirmation prompt shows the truncated value, but `--force` skips the prompt.
  - An aborted delete returns exit code 0 (`key.rs:246-250`).
- **Trigger condition:** Running `key list` or `key delete` as SO, or passing a handle above 2^32 on Windows.
- **Impact:** Objects may be over-privileged or deleted by mistake, and scripts cannot tell an aborted delete from a successful one.
- **Recommendation:** Use `CK_OBJECT_HANDLE::try_from(handle)`. Make the role an explicit clap argument. Pass `is_logged_in` according to the user role. Return a non-zero exit code on abort.

### H5-15 [Low] Labels are printed without neutralising control characters, and label handling is inconsistent
- **Location:** `commands/key.rs:119,210,243`; `commands/token.rs:36-38,45`; `output.rs:91` (column width uses byte length).
- **CWE:** CWE-150, CWE-116.
- **Confidence:** Confirmed.
- **Description:**
  - Object labels are shown with `from_utf8_lossy` without filtering control characters. This includes the delete-confirmation prompt, where terminal escape sequences could hide the true object identity.
  - `token init` truncates the label to 32 bytes, possibly in the middle of a UTF-8 code point.
  - The CLI does not apply the printable-ASCII rule that the config validator enforces (`src/config/config.rs:551-568`).
  - The CLI echoes the untruncated label.
- **Trigger condition:** A label containing control or escape bytes or multibyte UTF-8, whether it came from a backup or from the command line.
- **Impact:** Misleading operator prompts and inconsistent label handling.
- **Recommendation:** Escape non-printable characters (for example with `char::escape_default`) in all table and prompt output. Validate CLI labels with the same rule as the config. Truncate on `char` boundaries.

### H5-16 [Low] Unbounded reads of user-supplied files, plus a redundant existence check
- **Location:** `commands/backup.rs:172-176` (`exists()` then `fs::read`), `commands/key.rs:168`.
- **CWE:** CWE-400, CWE-367.
- **Confidence:** Confirmed.
- **Description:** Both files are read completely into memory before any size check. The library caps key material at 8192 bytes (`attributes.rs:26,482-486`) only after the whole file has been read. The `exists()` pre-check is racy and adds nothing.
- **Trigger condition:** Passing a very large file or an endless stream (a device or FIFO) as `--input` or `--file`.
- **Impact:** The CLI process can exhaust memory (local DoS).
- **Recommendation:** Open the file once, check `metadata().is_file()` and its length against a cap (for example 64 MiB for backups and 16 KiB for keys), and read with `take(cap)`.

### H5-17 [Low] Panic paths reachable from environment or data
- **Location:** `src/core.rs:116` (`HsmCore::new` → `expect("DRBG instantiation …")`, which also fires when `AuditLog::new_with_path` fails at `:137`), called at every `commands/*.rs` entry point; `output.rs:18` (`unwrap`); `commands/key.rs:98,127` (`v * 8` on `CK_ULONG`).
- **CWE:** CWE-248, CWE-190.
- **Confidence:** Confirmed.
- **Description:** A rejected audit-log path, such as a symlink or a non-regular file, makes the CLI panic with a misleading DRBG/entropy message. `value_len * 8` overflows for crafted objects: it panics in debug builds and wraps in release builds.
- **Trigger condition:** A config whose audit log path fails validation, or an object with a very large `value_len`.
- **Impact:** Crashes with misleading diagnostics.
- **Recommendation:** Use `HsmCore::try_new` and map the error. Use `checked_mul` or `saturating_mul`. Remove the `unwrap` in `print_json_or_table`, which is also unused (see Stubs).

### H5-18 [Low] Local CI scripts overstate results and diverge from CI
- **Location:** `scripts/local-ci.sh:59-63` with `:104-106,115-120,158-160` (a job that skips via `skip_job` returns 0, so it is recorded as both SKIP and PASS); `:151-163` (audit passes when only one of cargo-audit or cargo-deny is installed); `:97-101` (`-A clippy::not_unsafe_ptr_arg_deref` hides unsound safe wrappers around raw pointers in an FFI crate); `scripts/ci-local.sh:170` (`--package craton_hsm`, while the package is named `craton-hsm`); the RUSTSEC ignore list is duplicated in `ci-local.sh:122-131`, `local-ci.sh:136-146` and `.github/workflows/security-audit.yml`, and includes RUSTSEC-2023-0071 (the rsa crate's Marvin timing attack); `local-ci.sh` never changes to the repository root.
- **CWE:** CWE-1068, CWE-693.
- **Confidence:** Confirmed.
- **Trigger condition:** Running the scripts on a machine missing nightly, miri, cargo-audit or cargo-deny, or from a subdirectory.
- **Impact:** False "All CI checks passed" results, and suppressed soundness lints.
- **Recommendation:** Track skips separately from passes. Fail the audit job when either tool is missing. Drop the `not_unsafe_ptr_arg_deref` allowance and fix the functions it flags, or mark them `unsafe`. Keep one ignore list in `deny.toml`/`audit.toml`, each entry with an expiry. Fix the package name. `cd` to the git top-level directory.

### H5-19 [Low] `sign-integrity.sh` uses a predictable sibling temp file and hides signing errors
- **Location:** `tools/sign-integrity.sh:54` (unused `HASH_BYTES` holding binary data in a shell variable), `:60-71` (`${HASH_TMPFILE}.sig` is created by openssl next to an `mktemp` file in a shared temp directory; `2>/dev/null` discards openssl's diagnostics).
- **CWE:** CWE-377, CWE-390.
- **Confidence:** Confirmed; exploitability is Possible and is limited by mitigations such as `protected_symlinks`.
- **Trigger condition:** Running the script where `$TMPDIR` is a shared world-writable directory.
- **Impact:** The signature output file could be pre-created or redirected, and signing failures give only a generic message.
- **Recommendation:** Create a private directory with `mktemp -d` and put both files in it. Show openssl's stderr on failure. Delete the unused variable.

### H5-20 [Low] Administrative operations are not recorded in the audit log
- **Location:** No `audit_log().record(...)` call anywhere in `tools/craton-hsm-admin/src/` (checked by grep). This affects token init, PIN change and reset, key import and delete, backup and restore.
- **CWE:** CWE-778.
- **Confidence:** Confirmed.
- **Trigger condition:** Any privileged CLI operation.
- **Impact:** Privileged actions leave no tamper-evident trace. Together with H5-01, a lockout reset is invisible.
- **Recommendation:** Record an audit event, including the result and the OS user, for every mutating subcommand and for failed CLI authentication.

### H5-21 [Informational] Documentation shows PINs as command-line arguments and subcommands that do not exist
- **Location:** `docs/examples.md:100-101,110-115` (`init-token --so-pin …`, `generate-key … --pin …`, `list-objects --pin …`). `docs/PRESENTATION.md:590-626` shows `status` fields, `key list` columns and `audit dump` entries that the CLI does not produce.
- **CWE:** CWE-214 (in the documented usage), CWE-1059.
- **Confidence:** Confirmed.
- **Description:** The CLI correctly prompts for PINs, but the docs teach operators to put PINs in argv and shell history, and they use sequential PINs that the CLI's own policy rejects.
- **Trigger condition:** An operator following `docs/examples.md`.
- **Recommendation:** Regenerate the examples from `craton-hsm-admin --help`. Never show PINs as arguments. Mark the presentation output as illustrative, or bring the CLI up to it.

### H5-22 [Informational] Integrity tooling has drifted from the library
- **Location:**
  - `tools/generate-integrity-keypair.sh:42` and `.ps1:58`: tell the user to paste a `const INTEGRITY_PUBLIC_KEY` into `src/crypto/integrity.rs`, but the library now reads `CRATON_HSM_INTEGRITY_PUBLIC_KEY` at build time (`src/crypto/integrity.rs:36-67`).
  - `tools/compute-integrity-hmac.ps1:42`: `ASCII.GetBytes` silently replaces non-ASCII characters and `.Trim()`s the key, while the bash version hashes raw bytes and strips only trailing newlines, so the two produce different MACs.
  - `tools/generate-integrity-keypair.ps1:41-52`: DER output captured through the PowerShell pipeline is decoded as text. When it contains no `0x0A` byte, it is kept as a single string (length ≥ 32), so the file-based fallback is skipped and characters are indexed as if they were bytes.
  - The PowerShell scripts do not set `$ErrorActionPreference = 'Stop'`.
- **Confidence:** Confirmed (instructions, encoding); Likely (DER capture behaviour).
- **Trigger condition:** Following the scripts' instructions, or running them on Windows.
- **Impact:** Keys may be pasted into the wrong place, MACs differ across platforms, and the printed public key may be wrong. All of these fail closed at verification time but break the release process.
- **Recommendation:**
  - Print the `CRATON_HSM_INTEGRITY_PUBLIC_KEY=<hex>` build variable instead of a const.
  - Always write DER with `-out` and read it with `ReadAllBytes`.
  - Finish with a sign/verify self-check.
  - Delete the HMAC scripts (H5-07).

### H5-23 [Informational] `.gitignore` does not exclude key material or CLI state files
- **Location:** `.gitignore` (only `craton_hsm_store` is relevant). No keys are currently tracked (checked with `git ls-files`).
- **Confidence:** Confirmed.
- **Trigger condition:** Running `generate-integrity-keypair.sh .`, or running the CLI from inside the repository.
- **Recommendation:** Add `*.pem`, `*.key`, `*-signing-key*`, `.craton_hsm_replay_guard`, `lockout_state.json`, `craton_hsm_audit.jsonl*` and `*.rhbk`.

### H5-24 [Informational] Copies of secrets remain in memory outside `Zeroizing`
- **Location:** `rpassword-7.4.0/src/lib.rs:49-55` (`BufReader` + `read_line` into a `SafeString`; growth reallocations and the `BufReader` buffer are not wiped); `commands/key.rs:31-32` (the role prompt uses a plain `String`, which is not secret); `commands/key.rs:183-204` (the template is zeroized manually, but `create_object` copies `CKA_VALUE` into a new `RawKeyMaterial`).
- **Confidence:** Likely.
- **Description:** This is a best-effort residue issue only. The CLI already wraps PINs and passphrases in `Zeroizing`.
- **Trigger condition:** A process memory dump or core file taken while the CLI is running or just after.
- **Recommendation:** Disable core dumps (`prctl(PR_SET_DUMPABLE, 0)` / `setrlimit(RLIMIT_CORE, 0)`) at startup. Consider reading PINs into a pre-sized `Zeroizing<Vec<u8>>`. Use `Zeroizing<Vec<u8>>` in attribute templates.

## Stubs, TODOs and unimplemented items

A grep for `todo!`, `unimplemented!`, `TODO`, `FIXME`, `XXX`, `HACK` and "not implemented" across the admin crate and the scripts found **no markers**. The items below are functional placeholders found by reading the code.

| Location | Item | Effect |
|---|---|---|
| `commands/backup.rs:106-114` | `backup` exports from a fresh in-memory store | Always 0 objects (H5-02) |
| `commands/backup.rs:171-244` | `restore` inserts into a throwaway core | No lasting effect; burns the backup ID (H5-02, H5-04) |
| `commands/key.rs:78-286`, `commands/pin.rs:48-214` | Authenticated commands | Unreachable, because the token is never initialized in a new process (H5-02) |
| `commands/token.rs:11-46` | `token init` | Only in-memory, except that it clears the lockout file (H5-01) |
| `commands/audit.rs:9-32` | `audit dump --last N` | `N` is only echoed back; no entries are printed |
| `commands/audit.rs:35-96` | exports and `verify-chain` | Operate on an empty in-memory log (H5-03) |
| `main.rs:79`, `commands/key.rs:157` ("PEM or DER") vs `key.rs:183-191` | `key import` | No PEM/DER parsing (H5-13) |
| `commands/token.rs:153-160` | `load_config_strict` | Identical to `load_config`; doc comment is inaccurate (H5-11) |
| `commands/key.rs:253-277` | "TOCTOU" re-verification before delete | Meaningless in a single-process ephemeral store |
| `output.rs:16-22,25-27` | `print_json_or_table`, `hex_string` | Dead code |
| `Cargo.toml:17` | `comfy-table` | Unused dependency |
| `main.rs:15-17` | global `--json` | Ignored by import, delete, pin, backup, restore and the audit exports |
| `docs/examples.md:100-115` | `init-token`, `init-pin`, `generate-key`, `list-objects` | Documented subcommands that do not exist; no key generation command at all |
| `tools/compute-integrity-hmac.{sh,ps1}` | HMAC sidecar tooling | Obsolete; the library no longer verifies `.hmac` (H5-07) |
| `tools/craton-hsm-admin/` | Tests | None; `cargo test -p craton-hsm-admin` in `.github/workflows/ci.yml:111-118` runs zero tests |

## Code review

- **Architecture.** Each CLI process builds its own `HsmCore` and does not load persisted state. This is the root cause of H5-01 to H5-04. Pick one model and use it everywhere:
  - an authenticated client of the daemon, or
  - a single-writer tool that opens the persisted `EncryptedStore` under an exclusive lock, loads the token/PIN state and uses `ObjectStore::with_persistence`.

  Until then, fail closed.
- **Duplication.** `load_config` is copy-pasted five times (`token.rs`, `pin.rs`, `key.rs`, `backup.rs`, `audit.rs`), plus a fake "strict" variant. The login-with-retry loop appears three times (`key.rs:40-65`, `pin.rs:67-99`, `pin.rs:151-182`). Move both into shared helpers, together with a RAII guard that logs out on drop. Several early `?` returns currently skip `logout()` (`key.rs:206,232,259,281`).
- **Error handling.** `Box<dyn Error>` built from strings loses the error class, and every library error is flattened with `{:?}` (`backup.rs:117,205-210`; `key.rs:197,281`). Introduce a `CliError` enum with documented exit codes (auth failed, not initialized, integrity failure, I/O, replay). `verify_chain` calls `std::process::exit(1)` inside a library-style function (`audit.rs:92`), which skips destructors, including the audit worker join.
- **Consistency.** The CLI's minimum passphrase length is 12 bytes (`backup.rs:9,17`) but the library requires 16 characters plus complexity (`src/store/backup.rs:36,76-86`). Users type and confirm a passphrase that is then rejected. Backup and restore pass `None` for PBKDF2 iterations, ignoring `config.security.pbkdf2_iterations`.
- **Clap usage.** Use `ValueEnum` for `--type`, `--user-type` and the role instead of free strings. Use `PathBuf` for paths. Make `--config` required or give it an absolute default. Expose `--yes` rather than a free-form stdin prompt so the CLI can be scripted.
- **Output.** `ObjectTable` column widths use byte length (`output.rs:91`), which misaligns non-ASCII labels. The label-escaping gap is covered in H5-15.
- **Lints.** Add `#![forbid(unsafe_code)]` and `#![deny(clippy::unwrap_used, clippy::expect_used)]` to the crate.
- **Test gaps.** The crate has no tests. Add:
  - unit tests for `validate_pin_complexity`;
  - `assert_cmd` tests for every subcommand's negative paths: missing config, wrong PIN, tampered audit log (expect a non-zero exit), replayed backup, empty-store backup refusal, handle overflow;
  - a regression test that `token init` does not touch `lockout_state.json` without SO verification.
- **Scripts.**
  - The bash scripts are generally careful: quoting, `set -euo pipefail`, `mktemp` with `umask 077`.
  - `openssl ... 2>/dev/null` hides diagnostics.
  - `${LIB_PATH%.*}` misbehaves for extension-less names inside dotted directories (`compute-integrity-hmac.sh:90`, `sign-integrity.sh` near the `.sig` path).
  - The PowerShell scripts lack `Set-StrictMode -Version Latest` and `$ErrorActionPreference='Stop'`.
  - The two CI helpers duplicate each other with different behaviour (clippy `-D` flags, audit-missing handling, semver package name). Keep one.

## Performance improvement suggestions

1. **Avoid building the full core for read-only commands** (`token.rs:52,108`; `audit.rs:*`). `HsmCore::try_new` (`src/core.rs:131-147`) instantiates the HMAC_DRBG, generates a state-HMAC key and, with audit enabled by default, re-hashes the entire audit log file (`src/audit/log.rs:550`, `recover_chain_from_file`) and spawns a writer thread. It does this even for `status` and `token info`. Add a lightweight constructor, or open only the component each command needs.
2. **Stream audit exports** (`audit.rs:35-62`). `export_json` and `export_ndjson` clone all entries and build one large `String`. `export_syslog` returns a `Vec<String>`, and each `println!` re-locks stdout. Write to a locked `BufWriter<StdoutLock>` entry by entry, reading the file with a bounded line reader.
3. **Replay guard** (`backup.rs:191-219`; `src/store/backup.rs:299-333`). The whole guard file is read into a `HashSet`, cloned (`consumed_ids_clone`), then fully re-scanned to find the one new ID. Return the new ID from `restore_backup` and append only that. Look up entries with a single locked read, or keep them in an indexed store, because the file grows without bound.
4. **Bounded, single-pass file reads** (`backup.rs:172-176`, `key.rs:168`). Replace `exists()` + `fs::read` with one `File::open`, a metadata length check, and `read_to_end` on a `take(cap)` reader. This saves a syscall and avoids reading oversized input.
5. **Backup memory footprint** (`backup.rs:114-117`). `export_all_objects()` clones every object, then `create_backup` serialises all of them to one JSON `Vec` and encrypts it in memory, holding about three plaintext copies at once. Serialise straight into the AEAD input, or use a chunked STREAM construction for large stores.
6. **Retry back-off sleeps** (`key.rs:52-62`, `pin.rs:83,94,164,175`). The CLI adds up to 5 seconds of `thread::sleep` on top of the token's own rate limit. Keep a single delay, and rely on the core's persisted back-off (`check_rate_limit`) instead of per-process sleeps, which do not stop parallel invocations anyway.
7. **Minor:** `hex_string` (`output.rs:25-27`) allocates one `String` per byte. Use `hex::encode`, or delete it since it is unused. `key list` calls `get_object` and re-locks per handle; iterate the store once and collect rows.
