// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use super::Ctx;
use crate::admin_core::{open_core, Role};
use crate::error::{CliError, CliResult};
use crate::replay_guard::ReplayGuard;
use craton_hsm::audit::log::AuditOperation;
use craton_hsm::error::HsmError;
use craton_hsm::store::backup;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Matches the library's `MIN_PASSPHRASE_LEN` (characters, not bytes) so the
/// operator is not asked to confirm a passphrase that is then rejected.
const MIN_PASSPHRASE_CHARS: usize = 16;
/// Upper bound on a backup file read by `restore` (H5-16).
const MAX_BACKUP_BYTES: u64 = 64 * 1024 * 1024;

fn prompt_passphrase(confirm: bool) -> CliResult<Zeroizing<String>> {
    let passphrase = crate::prompt::read_secret("Enter backup passphrase: ")?;
    if passphrase.is_empty() {
        return Err(CliError::Usage("Passphrase must not be empty.".into()));
    }
    if confirm {
        if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
            return Err(CliError::Usage(format!(
                "Passphrase too short: at least {MIN_PASSPHRASE_CHARS} characters with at \
                 least 3 of: lowercase, uppercase, digits, symbols."
            )));
        }
        let again = crate::prompt::read_secret("Confirm backup passphrase: ")?;
        if *passphrase != *again {
            return Err(CliError::Usage("Passphrases do not match.".into()));
        }
    }
    Ok(passphrase)
}

/// Random hidden temp name in `dir` (never predictable, H5-10).
fn random_temp_path(dir: &Path) -> PathBuf {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    dir.join(format!(".craton_hsm-backup-{hex}.tmp"))
}

/// Create a new file that only the current user can access. Never follows
/// or reuses an existing path.
#[cfg(unix)]
fn create_private_new(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_new(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Absolute path of a Windows system tool (never resolved through PATH).
#[cfg(windows)]
fn system32_tool(name: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_dir())
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join(name)
}

/// Restrict `path` to the current user only; fails closed (H5-10).
#[cfg(windows)]
fn restrict_to_current_user(path: &Path) -> CliResult {
    use std::process::{Command, Stdio};
    let out = Command::new(system32_tool("whoami.exe"))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| CliError::Io(format!("Cannot run whoami: {e}")))?;
    if !out.status.success() {
        return Err(CliError::Io(
            "whoami failed; cannot restrict backup ACL".into(),
        ));
    }
    let user = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if user.is_empty() {
        return Err(CliError::Io("whoami returned an empty user name".into()));
    }
    let status = Command::new(system32_tool("icacls.exe"))
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("{user}:(R,W)"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .map_err(|e| CliError::Io(format!("Cannot run icacls: {e}")))?;
    if !status.success() {
        return Err(CliError::Io(format!(
            "icacls failed (exit {:?}); refusing to leave a backup with inherited ACLs",
            status.code()
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn restrict_to_current_user(_path: &Path) -> CliResult {
    // Unix files are created with mode 0600 by `create_private_new`.
    Ok(())
}

/// Write the backup: random temp file created with `create_new` and owner-only
/// permissions, fsynced, then moved into place. Without `force` an existing
/// output is never replaced (hard_link fails if the target exists).
fn write_backup_file(output: &Path, data: &[u8], force: bool) -> CliResult {
    if !force && std::fs::symlink_metadata(output).is_ok() {
        return Err(CliError::Refused(format!(
            "Output '{}' already exists; pass --force to replace it.",
            output.display()
        )));
    }
    let dir = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let tmp = random_temp_path(&dir);
    let result = (|| -> CliResult {
        let mut f = create_private_new(&tmp)
            .map_err(|e| CliError::Io(format!("Cannot create temporary backup file: {e}")))?;
        restrict_to_current_user(&tmp)?;
        f.write_all(data)
            .and_then(|_| f.sync_all())
            .map_err(|e| CliError::Io(format!("Cannot write backup file: {e}")))?;
        drop(f);
        if force {
            std::fs::rename(&tmp, output)
                .map_err(|e| CliError::Io(format!("Cannot move backup into place: {e}")))?;
        } else {
            std::fs::hard_link(&tmp, output).map_err(|e| {
                CliError::Io(format!(
                    "Cannot create '{}' (it may already exist): {e}",
                    output.display()
                ))
            })?;
            std::fs::remove_file(&tmp).ok();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Create an encrypted backup of all token objects. Requires SO login and a
/// typed confirmation; refuses to write an empty backup unless asked to.
pub fn create_backup(ctx: &Ctx, output: &Path, allow_empty: bool, force: bool) -> CliResult {
    let cfg = ctx.load_config()?;
    let core = open_core(&cfg)?;
    core.require_persistent("backup")?;
    core.require_audit_intact()?;
    let session = core.login(Role::So)?;

    let objects = core.hsm().object_store().export_all_objects();
    if objects.is_empty() && !allow_empty {
        return Err(CliError::Refused(
            "The token holds no objects; refusing to write an empty backup \
             (use --allow-empty to override)."
                .into(),
        ));
    }
    crate::prompt::confirm_typed(
        &format!(
            "This exports ALL {} token object(s), including key material, encrypted under a \
             passphrase.",
            objects.len()
        ),
        "backup",
        ctx.yes,
    )?;
    let passphrase = prompt_passphrase(true)?;

    let res = backup::create_backup(
        &objects,
        &passphrase,
        &cfg.config.token.serial_number,
        Some(cfg.config.security.pbkdf2_iterations),
    );
    let data = match res {
        Ok(d) => d,
        Err(HsmError::PinLenRange) | Err(HsmError::PinInvalid) => {
            return Err(CliError::Usage(
                "Passphrase rejected: at least 16 characters with 3 of 4 character classes.".into(),
            ))
        }
        Err(e) => return Err(CliError::General(format!("Backup creation failed: {e}"))),
    };
    let write = write_backup_file(output, &data, force);
    core.record(
        AuditOperation::GetAttributeValue,
        write
            .as_ref()
            .map(|_| ())
            .map_err(|_| &HsmError::GeneralError),
        &format!("backup:objects={}", objects.len()),
    )?;
    write?;
    drop(session);

    println!(
        "Backup created: {} ({} objects, {} bytes)",
        output.display(),
        objects.len(),
        data.len()
    );
    Ok(())
}

fn map_restore_error(e: HsmError) -> CliError {
    match e {
        HsmError::PinIncorrect => {
            CliError::BackupRejected("Wrong passphrase or corrupted backup file.".into())
        }
        HsmError::DataInvalid => CliError::BackupRejected(
            "Backup rejected: malformed, bound to a different token serial, older than 30 \
             days, from the future, or already restored (replay). See the warning above."
                .into(),
        ),
        other => CliError::General(format!("Backup restore failed: {other}")),
    }
}

/// Restore token objects from an encrypted backup.
///
/// The replay guard is locked for the whole operation and the backup ID is
/// recorded only after every object has been inserted; on any failure the
/// inserted objects are rolled back and the backup remains restorable (H5-04).
/// `--verify-only` decrypts and validates without restoring or consuming.
pub fn restore_backup(ctx: &Ctx, input: &Path, verify_only: bool) -> CliResult {
    let cfg = ctx.load_config()?;
    let data = crate::fsutil::read_bounded(input, MAX_BACKUP_BYTES, "backup file")?;

    if verify_only {
        let mut ids = ReplayGuard::read_only_ids(cfg.storage_dir())?;
        let passphrase = prompt_passphrase(false)?;
        let objects = backup::restore_backup(
            &data,
            &passphrase,
            &cfg.config.token.serial_number,
            None,
            Some(cfg.config.security.pbkdf2_iterations),
            Some(&mut ids),
        )
        .map_err(map_restore_error)?;
        println!(
            "Backup verified: {} object(s). Nothing was restored and the backup was not consumed.",
            objects.len()
        );
        return Ok(());
    }

    let core = open_core(&cfg)?;
    core.require_persistent("restore")?;
    core.require_audit_intact()?;
    let session = core.login(Role::So)?;
    crate::prompt::confirm_typed(
        "This imports all objects from the backup into the token.",
        "restore",
        ctx.yes,
    )?;
    let passphrase = prompt_passphrase(false)?;

    // Held until the end of the function: load → check → restore → record.
    let mut guard = ReplayGuard::open_locked(cfg.storage_dir())?;
    let mut ids = guard.consumed_ids().clone();
    let objects = backup::restore_backup(
        &data,
        &passphrase,
        &cfg.config.token.serial_number,
        None,
        Some(cfg.config.security.pbkdf2_iterations),
        Some(&mut ids),
    )
    .map_err(map_restore_error)?;
    let new_id = ids
        .difference(guard.consumed_ids())
        .next()
        .cloned()
        .ok_or_else(|| CliError::General("Backup ID was not reported by the library.".into()))?;

    let store = core.hsm().object_store();
    let mut inserted = Vec::with_capacity(objects.len());
    let outcome = (|| -> CliResult {
        for mut obj in objects {
            if obj.key_material.is_some() && !obj.sensitive && !obj.extractable {
                return Err(CliError::BackupRejected(
                    "Backup contains an inconsistent key object; nothing restored.".into(),
                ));
            }
            // Never trust handles/slots from the payload.
            obj.handle = store
                .next_handle()
                .map_err(|e| CliError::General(format!("Handle allocation failed: {e}")))?;
            obj.slot_id = 0;
            let h = store
                .insert_object(obj)
                .map_err(|e| CliError::General(format!("Failed to insert object: {e}")))?;
            inserted.push(h);
        }
        // HANDOFF: insert_object must report persistence failures so that
        // "committed" below really means durable.
        guard.record(&new_id)
    })();

    if let Err(e) = outcome {
        for h in &inserted {
            let _ = store.destroy_object(*h);
        }
        let _ = core.record(
            AuditOperation::CreateObject,
            Err(&HsmError::GeneralError),
            "restore",
        );
        return Err(e);
    }
    core.record(
        AuditOperation::CreateObject,
        Ok(()),
        &format!("restore:objects={}", inserted.len()),
    )?;
    drop(guard);
    drop(session);

    println!("Restored {} object(s) from backup.", inserted.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_write_never_overwrites_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("b.rhbk");
        write_backup_file(&out, b"one", false).unwrap();
        assert!(matches!(
            write_backup_file(&out, b"two", false),
            Err(CliError::Refused(_))
        ));
        assert_eq!(std::fs::read(&out).unwrap(), b"one");
        write_backup_file(&out, b"two", true).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"two");
        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&out).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0);
        }
    }

    #[test]
    fn temp_names_are_random() {
        let d = Path::new("/x");
        assert_ne!(random_temp_path(d), random_temp_path(d));
    }

    #[test]
    fn restore_errors_are_distinct() {
        assert!(matches!(
            map_restore_error(HsmError::PinIncorrect),
            CliError::BackupRejected(_)
        ));
        assert!(matches!(
            map_restore_error(HsmError::DataInvalid),
            CliError::BackupRejected(_)
        ));
    }
}
