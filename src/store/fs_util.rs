// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Hardened filesystem helpers for every file the HSM creates (H3-12).
//!
//! All security-relevant files (persistent store, lock files, audit log and
//! its key/anchor, replay guard, backups) go through these helpers so that:
//!
//! * files are created **atomically with mode 0600** (`O_CREAT` + `mode`),
//!   never "create, then chmod";
//! * the final path component is never followed if it is a symlink
//!   (`O_NOFOLLOW`), and descriptors are not leaked to children (`O_CLOEXEC`);
//! * an existing file must be a regular file owned by the effective UID and
//!   must not be group/world accessible — otherwise we fail closed;
//! * whole-file replacements use a random, `O_EXCL` temp file in the same
//!   directory, `fsync` of the file, `rename`, then `fsync` of the directory;
//! * storage directories are created with mode 0700 and rejected when they are
//!   symlinks, not owned by us, or group/world writable.
//!
//! On Windows the owner-only DACL is applied through
//! [`set_restrictive_permissions`](crate::store::encrypted_store::set_restrictive_permissions)
//! and failures are propagated (fail closed, H3-29).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::error::{HsmError, HsmResult};

fn io_err(ctx: &str, path: &Path, e: io::Error) -> HsmError {
    tracing::error!("{} '{}': {}", ctx, path.display(), e);
    HsmError::DeviceError
}

/// Effective UID of the process.
#[cfg(unix)]
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid()
    }
}

#[cfg(unix)]
fn secure_flags(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    opts.mode(0o600);
}

#[cfg(not(unix))]
fn secure_flags(_opts: &mut OpenOptions) {}

/// Verify that an open descriptor refers to a regular file owned by the
/// effective UID with no group/other permission bits. On other platforms this
/// only checks that it is a regular file.
pub(crate) fn check_private_file(file: &File, path: &Path) -> HsmResult<()> {
    let meta = file
        .metadata()
        .map_err(|e| io_err("cannot stat", path, e))?;
    if !meta.file_type().is_file() {
        tracing::error!("'{}' is not a regular file", path.display());
        return Err(HsmError::DeviceError);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let euid = effective_uid();
        if meta.uid() != euid && meta.uid() != 0 {
            tracing::error!(
                "'{}' is owned by uid {} (expected {}) — refusing to use it",
                path.display(),
                meta.uid(),
                euid
            );
            return Err(HsmError::DeviceError);
        }
        if meta.mode() & 0o077 != 0 {
            tracing::error!(
                "'{}' has insecure permissions {:o} (must be 0600)",
                path.display(),
                meta.mode() & 0o777
            );
            return Err(HsmError::DeviceError);
        }
    }
    Ok(())
}

/// Create a brand-new private file (fails if the path already exists).
pub(crate) fn create_new_private(path: &Path) -> HsmResult<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    secure_flags(&mut opts);
    let f = opts
        .open(path)
        .map_err(|e| io_err("cannot create", path, e))?;
    #[cfg(windows)]
    crate::store::encrypted_store::set_restrictive_permissions(path)?;
    Ok(f)
}

/// Open (creating with 0600 if absent) a private file for read/write or
/// append, refusing symlinks and files with wrong ownership/permissions.
pub(crate) fn open_private(path: &Path, append: bool) -> HsmResult<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).create(true);
    if append {
        opts.append(true);
    } else {
        opts.write(true);
    }
    secure_flags(&mut opts);
    let existed = path.exists();
    let f = opts
        .open(path)
        .map_err(|e| io_err("cannot open", path, e))?;
    #[cfg(windows)]
    if !existed {
        crate::store::encrypted_store::set_restrictive_permissions(path)?;
    }
    let _ = existed;
    check_private_file(&f, path)?;
    Ok(f)
}

/// Open an existing file read-only without following a final symlink.
/// Returns `Ok(None)` if the file does not exist.
pub(crate) fn open_existing_readonly(path: &Path) -> HsmResult<Option<File>> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    match opts.open(path) {
        Ok(f) => {
            check_private_file(&f, path)?;
            Ok(Some(f))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err("cannot open", path, e)),
    }
}

/// `fsync` a directory so that a preceding create/rename is durable.
pub(crate) fn fsync_dir(dir: &Path) -> HsmResult<()> {
    #[cfg(unix)]
    {
        let d = File::open(if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        })
        .map_err(|e| io_err("cannot open directory", dir, e))?;
        d.sync_all()
            .map_err(|e| io_err("cannot fsync directory", dir, e))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Atomically replace `path` with `data`: random `O_EXCL` temp file in the
/// same directory, write + `fsync`, `rename`, `fsync` the directory.
pub(crate) fn atomic_write_private(path: &Path, data: &[u8]) -> HsmResult<()> {
    use rand::RngCore;
    let dir = path.parent().unwrap_or_else(|| Path::new(""));
    let mut rnd = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".to_string());
    let tmp: PathBuf = dir.join(format!(".{}.{}.tmp", file_name, hex::encode(rnd)));
    let result = (|| {
        let mut f = create_new_private(&tmp)?;
        f.write_all(data)
            .map_err(|e| io_err("cannot write", &tmp, e))?;
        f.sync_all().map_err(|e| io_err("cannot fsync", &tmp, e))?;
        drop(f);
        std::fs::rename(&tmp, path).map_err(|e| io_err("cannot rename into", path, e))?;
        fsync_dir(dir)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Read a whole private file (no symlink following). `Ok(None)` if absent.
pub(crate) fn read_private(path: &Path) -> HsmResult<Option<Vec<u8>>> {
    use std::io::Read;
    match open_existing_readonly(path)? {
        Some(mut f) => {
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)
                .map_err(|e| io_err("cannot read", path, e))?;
            Ok(Some(buf))
        }
        None => Ok(None),
    }
}

/// Create (mode 0700) or validate a private storage directory.
///
/// Rejects symlinks, non-directories, directories owned by another user
/// (other than root) and group/world-writable directories.
pub(crate) fn ensure_private_dir(dir: &Path) -> HsmResult<()> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    match std::fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            b.create(dir)
                .map_err(|e| io_err("cannot create directory", dir, e))?;
            #[cfg(windows)]
            crate::store::encrypted_store::set_restrictive_permissions(dir)?;
        }
        Err(e) => return Err(io_err("cannot stat directory", dir, e)),
    }
    let meta = std::fs::symlink_metadata(dir).map_err(|e| io_err("cannot stat", dir, e))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        tracing::error!(
            "storage directory '{}' is a symlink or not a directory",
            dir.display()
        );
        return Err(HsmError::DeviceError);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let euid = effective_uid();
        if meta.uid() != euid && meta.uid() != 0 {
            tracing::error!(
                "storage directory '{}' is owned by uid {} (expected {})",
                dir.display(),
                meta.uid(),
                euid
            );
            return Err(HsmError::DeviceError);
        }
        if meta.mode() & 0o022 != 0 {
            tracing::error!(
                "storage directory '{}' is group/world writable ({:o})",
                dir.display(),
                meta.mode() & 0o777
            );
            return Err(HsmError::DeviceError);
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn refuses_symlink_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("victim");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_private(&link, true).is_err());
        assert!(create_new_private(&link).is_err());
    }

    #[test]
    fn creates_with_0600_and_atomic_replace() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        atomic_write_private(&p, b"one").unwrap();
        atomic_write_private(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn rejects_world_writable_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("d");
        std::fs::create_dir(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ensure_private_dir(&d).is_err());
        let d2 = dir.path().join("d2/sub");
        ensure_private_dir(&d2).unwrap();
    }
}
