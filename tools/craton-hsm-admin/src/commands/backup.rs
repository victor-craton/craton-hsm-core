// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use super::Ctx;
use crate::admin_core::{open_core, Role, SLOT};
use crate::error::{CliError, CliResult};
use craton_hsm::error::HsmError;
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

/// Options of `backup`.
pub struct BackupOptions {
    /// Write a backup even if no object is exported.
    pub allow_empty: bool,
    /// Replace an existing output file.
    pub force: bool,
    /// Also export non-extractable keys (explicit operator decision).
    pub include_non_extractable: bool,
}

/// Create an encrypted backup of the token objects of slot 0. Requires SO
/// login and a typed confirmation; refuses to write an empty backup unless
/// asked to. Non-extractable keys are not exported (A1-17) unless the
/// operator explicitly passes `--include-non-extractable`. The backup is
/// bound to the per-token random identity (H3-16) and the export is audited
/// synchronously by the core (`BackupExport`, H5-20).
pub fn create_backup(ctx: &Ctx, output: &Path, opts: BackupOptions) -> CliResult {
    let BackupOptions {
        allow_empty,
        force,
        include_non_extractable,
    } = opts;
    let cfg = ctx.load_config()?;
    let core = open_core(&cfg)?;
    core.require_persistent("backup")?;
    core.require_audit_intact()?;
    if !force && std::fs::symlink_metadata(output).is_ok() {
        return Err(CliError::Refused(format!(
            "Output '{}' already exists; pass --force to replace it.",
            output.display()
        )));
    }
    let session = core.login(Role::So)?;

    let count = core
        .hsm()
        .export_token_objects(SLOT, include_non_extractable)
        .map_err(|e| CliError::General(format!("Cannot enumerate token objects: {e}")))?
        .len();
    if count == 0 && !allow_empty {
        return Err(CliError::Refused(
            "The token holds no exportable objects; refusing to write an empty backup \
             (use --allow-empty to override)."
                .into(),
        ));
    }
    let scope = if include_non_extractable {
        "INCLUDING non-extractable keys"
    } else {
        "non-extractable keys are not exported"
    };
    crate::prompt::confirm_typed(
        &format!(
            "This exports {count} token object(s), including key material, encrypted under a \
             passphrase ({scope})."
        ),
        "backup",
        ctx.yes,
    )?;
    let passphrase = prompt_passphrase(true)?;

    let action = if include_non_extractable {
        "backup:include-non-extractable"
    } else {
        "backup"
    };
    let (data, exported) = match core.hsm().export_backup(
        SLOT,
        &passphrase,
        include_non_extractable,
        Some(&core.actor(action)),
    ) {
        Ok(d) => d,
        Err(HsmError::PinLenRange) | Err(HsmError::PinInvalid) => {
            return Err(CliError::Usage(
                "Passphrase rejected: at least 16 characters with 3 of 4 character classes.".into(),
            ))
        }
        Err(e) => return Err(CliError::General(format!("Backup creation failed: {e}"))),
    };
    let data = Zeroizing::new(data);
    write_backup_file(output, &data, force)?;
    drop(session);

    println!(
        "Backup created: {} ({} objects, {} bytes)",
        output.display(),
        exported,
        data.len()
    );
    Ok(())
}

fn map_restore_error(e: HsmError) -> CliError {
    match e {
        HsmError::PinIncorrect => {
            CliError::BackupRejected("Wrong passphrase or corrupted backup file.".into())
        }
        HsmError::BackupRejected(reason) => {
            CliError::BackupRejected(format!("Backup rejected: {reason}."))
        }
        HsmError::DataInvalid => CliError::BackupRejected("Backup rejected.".into()),
        other => CliError::General(format!("Backup restore failed: {other}")),
    }
}

/// Restore token objects from an encrypted backup (SO login required).
///
/// The core validates the backup (binding to this token, age, replay,
/// object policy), imports every object with fresh handles and records the
/// consumed backup ID **in the same store transaction**, so a failed restore
/// changes nothing and the backup stays restorable, while a completed one
/// can never be replayed (H5-04, H5-06). `--verify-only` decrypts and
/// validates without restoring or consuming.
pub fn restore_backup(ctx: &Ctx, input: &Path, verify_only: bool) -> CliResult {
    let cfg = ctx.load_config()?;
    let data = Zeroizing::new(crate::fsutil::read_bounded(
        input,
        MAX_BACKUP_BYTES,
        "backup file",
    )?);

    let core = open_core(&cfg)?;
    core.require_persistent("restore")?;
    core.require_audit_intact()?;
    let session = core.login(Role::So)?;

    if verify_only {
        let passphrase = prompt_passphrase(false)?;
        let n = core
            .hsm()
            .verify_backup(SLOT, &data, &passphrase, None)
            .map_err(map_restore_error)?;
        println!(
            "Backup verified: {n} object(s). Nothing was restored and the backup was not consumed."
        );
        return Ok(());
    }

    crate::prompt::confirm_typed(
        "This imports all objects from the backup into the token.",
        "restore",
        ctx.yes,
    )?;
    let passphrase = prompt_passphrase(false)?;
    let handles = core
        .hsm()
        .restore_backup(SLOT, &data, &passphrase, None, Some(&core.actor("restore")))
        .map_err(map_restore_error)?;
    drop(session);

    println!("Restored {} object(s) from backup.", handles.len());
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
        // H5-04: the reason is reported distinctly.
        match map_restore_error(HsmError::BackupRejected(
            craton_hsm::error::BackupRejection::Replayed,
        )) {
            CliError::BackupRejected(m) => assert!(m.contains("already restored"), "{m}"),
            other => panic!("unexpected {other:?}"),
        }
    }
}
