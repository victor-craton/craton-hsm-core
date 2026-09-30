# Handoff — area: admin (branch `claude/audit-fixes-admin`)

Scope fixed in this branch: `tools/craton-hsm-admin/**`, `tools/*.sh`, `tools/*.ps1`,
`scripts/**`, `docs/examples.md` (CLI section), `docs/release-signing.md` (integrity-script section).
Findings: H5-01..H5-24, A3-15.

## 1. Switching the CLI to the persistent core (for the state agent) — H5-02

Every command obtains its core through ONE function:
`tools/craton-hsm-admin/src/admin_core.rs::open_core(cfg: &LoadedConfig) -> CliResult<AdminCore>`.
Today it calls `HsmCore::try_new(&cfg.config)` and returns `CoreMode::Ephemeral`; every command that
would have no lasting effect or needs the SO PIN calls `core.require_persistent("<op>")` and exits
with code 5 ("not supported in standalone mode") **before** prompting or touching any file:
`token init`, `pin change|reset`, `key list|import|delete`, `backup`, `restore` (not `--verify-only`),
`audit dump|export-*`.

To re-enable them once the persistent API exists:
1. In `open_core`, replace `HsmCore::try_new(&cfg.config)` with the persistent constructor
   (e.g. `HsmCore::open_persistent(&cfg.config)`), keep the `AuditChainBroken` → `CliError::Integrity`
   mapping, and return `CoreMode::Persistent`.
2. Remove the `#[allow(dead_code)]` on `CoreMode::Persistent`.
3. Nothing else changes: SO/User login (`AdminCore::login[_with_pin]`), typed confirmations
   (`prompt::confirm_typed`, `--yes`), audit records (`AdminCore::record`, only active in Persistent
   mode) and the fail-closed tamper check (`require_audit_intact`) are already wired.
4. `cfg.config.token.storage_path` / `audit.log_path` are already absolute (anchored to the config
   file's directory by `config::load_strict`) — the persistent constructor must use them as-is.
5. Update the integration tests in `tools/craton-hsm-admin/tests/cli.rs`
   (`key_and_pin_mutations_are_refused`, `token_init_refused_and_lockout_state_untouched`,
   `backup_refused_and_writes_nothing`, `restore_refused_and_replay_guard_not_created`) which assert
   exit code 5; replace them with positive/negative tests against a persisted token.

Requirements on that persistent constructor (so the CLI is safe):
- Load `initialized`, SO/User PIN hashes and label from disk; open `ObjectStore::with_persistence`
  + `load_from_store`.
- Take an **exclusive single-writer lock** on the storage directory (shared with the daemon/ABI),
  otherwise the CLI and daemon both append to the audit log and fork its hash chain, and both write
  the object store.

## 2. Core-library changes requested (not in my owned paths)

| ID | File / function | Change |
|---|---|---|
| H5-02/H5-04 | `src/store/attributes.rs` `ObjectStore::{create_object,insert_object,destroy_object}` / `persist_object` | Persistence errors are only logged. Return them so "committed" means durable; the CLI restore records the replay ID only after all inserts return Ok and rolls back on error. |
| H5-03 | `src/audit/log.rs` | Add public `AuditLog::verify_file(path) -> Result<Summary, ChainError>`, `read_entries(path, visitor)` and `format_syslog(&AuditEvent)`; the CLI currently mirrors the payload serialisation and syslog layout in `tools/craton-hsm-admin/src/audit_file.rs` (guarded by unit tests that compare against the real `AuditLog`). Switch to the core API when it exists. |
| H5-03 (bug) | `src/audit/log.rs::recover_chain_from_file` / `new_with_path` | After a rotation the current file's first event carries the previous generation's hash, but recovery always starts from `[0;32]` → a legitimately rotated log is flagged as TAMPERED on the next start. Recovery must seed from the last hash of `<path>.1` (and verify generations oldest→newest, as the CLI does). |
| H5-20 | `src/audit/log.rs::AuditOperation` | Add admin variants (e.g. `SetPin`, `InitPin`, `BackupExport`, `BackupRestore`, `AuditExport`). The CLI currently records `Login{user_type}`/`InitToken`/`CreateObject`/`DestroyObject`/`GetAttributeValue` with `key_id = "craton-hsm-admin:<action>:uid=<euid>"`. |
| H5-04 | `src/store/backup.rs::restore_backup` | All rejections return `DataInvalid`; return distinct errors (replay, stale/future, serial mismatch, malformed). Store the PBKDF2 iteration count in the header (CLI now passes `config.security.pbkdf2_iterations` for both create and restore). |
| H5-05 | `src/store/backup.rs::restore_backup` | Validate restored objects with the `C_CreateObject` attribute rules (`validate_deserialized_object` is not applied here). CLI already reassigns handles/slot and rejects key objects that are neither sensitive nor extractable. |
| H5-06 | `src/store/backup.rs::PersistentReplayGuard` | Library guard still: path chosen by caller, `create+append` without `O_NOFOLLOW`, path-based `set_restrictive_permissions`, lock only during append (TOCTOU). Apply the design of `tools/craton-hsm-admin/src/replay_guard.rs` (O_NOFOLLOW, fchmod on fd, lock held across load→check→commit→record, fsync) and authenticate the guard contents (HMAC under a token-bound key). |
| H5-01 | `src/token/token.rs::init_token` | For a token with `initialized == false`, `LockoutStore::clear()` runs without any SO verification. Refuse (or do not clear) when persisted lockout data is non-default. |
| H5-01 (ABI) | `src/pkcs11_abi/functions.rs` `C_InitToken` (~l.515-522) | `hsm.object_store.clear()` runs **before** `token.init_token` verifies the SO PIN — a wrong PIN still destroys all objects. Verify first, then clear. |
| H5-11 | `src/config/config.rs::load_from_path` / `validate` | Library still silently falls back to defaults for a missing file; `validate_path_safety` checks symlinks relative to CWD. Provide a strict loader and a base-dir-aware validate. The CLI implements both itself (`tools/craton-hsm-admin/src/config.rs`). |
| H5-12 | `src/token/token.rs::validate_pin` | Move the PIN policy (`tools/craton-hsm-admin/src/commands/pin.rs::validate_pin_complexity`: ≥8 chars floor, ≥4 distinct chars, no repeated unit/sequence, denylist) into the core so ABI/daemon enforce the same rules. |
| H5-17 | `src/core.rs::HsmCore::new` | `expect("DRBG …")` also fires for audit-log path errors (misleading). CLI uses `try_new`; consider deprecating `new`. |

## 3. For the ABI agent
- `scripts/local-ci.sh` no longer passes `-A clippy::not_unsafe_ptr_arg_deref` (H5-18). The local clippy job
  will fail until the flagged safe functions that dereference raw pointers are made `unsafe` or fixed.

## 4. For the CI agent (owned by CI)
- `.gitignore` (H5-23) add: `*.pem`, `*.key`, `*-signing-key*`, `.craton_hsm_replay_guard`,
  `lockout_state.json`, `craton_hsm_audit.jsonl*`, `*.rhbk`, `target-fix-*/`.
- `.github/workflows/ci.yml:149` still has `-A clippy::not_unsafe_ptr_arg_deref`: remove after the ABI fix.
- `.github/workflows/security-audit.yml:44-59` duplicates the RUSTSEC ignore list. Single source is now
  `scripts/audit-ignore.txt` (ID, review-by date, reason; expired entries fail). Make the workflow read it
  (or move everything to `.cargo/audit.toml` + `deny.toml` with expiry and point the script there).
- `cargo test -p craton-hsm-admin` now runs 47 tests (35 unit + 12 CLI integration); ensure it runs on
  Windows too (PowerShell scripts and the Windows backup path could not be executed here — only
  `cargo check --target x86_64-pc-windows-gnu` was run).
- `scripts/ci-local.sh` is now a deprecated wrapper around `scripts/local-ci.sh`.

## 5. For the docs owner (files outside my scope that still reference the removed HMAC tooling, H5-07/H5-22/A3-15)
- `docs/fips-mode-guide.md:80-99,196`, `docs/fips-140-3-certification.md:520-536,964-983`,
  `docs/PRESENTATION.md:173`, `docs/fips-gap-analysis.md:81`, `docs/architecture.md:241`,
  `CHANGELOG.md:23,113-114` → replace with the Ed25519 `.sig` flow (`tools/generate-integrity-keypair.*`,
  `tools/sign-integrity.*`, `CRATON_HSM_INTEGRITY_PUBLIC_KEY`); see `docs/release-signing.md` §4.
- `docs/architecture.md:116` claims the admin CLI manages persisted token state — it runs in
  standalone mode and refuses mutating commands until §1 is done.
- `docs/PRESENTATION.md:590-626` shows CLI output that does not exist (H5-21): mark illustrative or
  regenerate from `craton-hsm-admin --help`.
- Pre-existing, not mine: `benches/crypto_bench.rs:348` imports `craton_hsm_awslc` unconditionally, so
  `cargo check --workspace --all-targets` fails on the benches target (all other targets pass).

## 6. Not fixable in code
- Rotate any HMAC key ever used with the removed `compute-integrity-hmac.sh` (it was exposed in argv).
- Release-signing key custody (HSM/KMS, access control, backup policy) is organisational.
- M-of-N authorisation for backup export (H5-05 option) needs a product/policy decision.
- H5-24 residue: `rpassword` reads through a `BufReader`/growing `String` whose intermediate buffers are
  not wiped; mitigated by disabling core dumps + `PR_SET_DUMPABLE=0` at CLI start. Full fix needs a
  zeroizing terminal reader (upstream or custom).
