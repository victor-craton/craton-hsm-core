// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Ownership / permission checks shared by the loader (H6-06) and the log
//! file opener (H6-03).
//!
//! Trust rule (Unix): a file or directory is trusted when it is owned by root
//! or by the effective UID, and no *other* user can modify it. "Other users
//! can write" means the world-write bit, or the group-write bit when the group
//! is not the process's effective GID (user-private-group setups with umask
//! 002 stay usable). A directory that others can write to is accepted only if
//! it has the sticky bit (e.g. `/tmp`): then others cannot rename or delete
//! entries they do not own.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn egid() -> u32 {
    // SAFETY: getegid has no preconditions and cannot fail.
    unsafe { libc::getegid() }
}

fn others_can_write(m: &std::fs::Metadata) -> bool {
    let mode = m.mode();
    mode & 0o002 != 0 || (mode & 0o020 != 0 && m.gid() != egid())
}

fn check_owner(path: &Path, m: &std::fs::Metadata) -> Result<(), String> {
    let uid = m.uid();
    if uid != 0 && uid != euid() {
        return Err(format!(
            "{} is owned by uid {} (expected root or the effective uid {})",
            path.display(),
            uid,
            euid()
        ));
    }
    Ok(())
}

/// A regular file that nobody but root / the effective user can modify.
pub fn check_trusted_file(path: &Path, m: &std::fs::Metadata) -> Result<(), String> {
    if !m.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    check_owner(path, m)?;
    if others_can_write(m) {
        return Err(format!(
            "{} is writable by other users (mode {:o})",
            path.display(),
            m.mode() & 0o7777
        ));
    }
    Ok(())
}

/// A directory whose entries cannot be replaced by other users.
pub fn check_trusted_dir(path: &Path, m: &std::fs::Metadata) -> Result<(), String> {
    if !m.file_type().is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }
    check_owner(path, m)?;
    if others_can_write(m) && m.mode() & 0o1000 == 0 {
        return Err(format!(
            "{} is writable by other users without the sticky bit (mode {:o})",
            path.display(),
            m.mode() & 0o7777
        ));
    }
    Ok(())
}

/// Check every ancestor directory of a canonical (absolute, symlink-free) path.
pub fn check_trusted_ancestors(canonical: &Path) -> Result<(), String> {
    for dir in canonical.ancestors().skip(1) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let m =
            std::fs::metadata(dir).map_err(|e| format!("cannot stat {}: {e}", dir.display()))?;
        check_trusted_dir(dir, &m)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn world_writable_file_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("lib.so");
        std::fs::write(&p, b"x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        let m = std::fs::metadata(&p).unwrap();
        assert!(check_trusted_file(&p, &m)
            .unwrap_err()
            .contains("writable by other users"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let m = std::fs::metadata(&p).unwrap();
        check_trusted_file(&p, &m).unwrap();
    }

    #[test]
    fn world_writable_dir_needs_sticky_bit() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("dir");
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o777)).unwrap();
        let m = std::fs::metadata(&p).unwrap();
        assert!(check_trusted_dir(&p, &m).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let m = std::fs::metadata(&p).unwrap();
        check_trusted_dir(&p, &m).unwrap();
    }

    #[test]
    fn directory_is_not_a_trusted_file() {
        let d = tempfile::tempdir().unwrap();
        let m = std::fs::metadata(d.path()).unwrap();
        assert!(check_trusted_file(d.path(), &m).is_err());
    }
}
