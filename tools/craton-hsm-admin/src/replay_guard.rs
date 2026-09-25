// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Backup replay guard used by `restore` (H5-04, H5-06).
//!
//! Differences from `craton_hsm::store::backup::PersistentReplayGuard`:
//! - lives under the validated `storage_path` (not next to `--config` / CWD);
//! - opened once with `O_NOFOLLOW`, permissions fixed with `fchmod` on the
//!   descriptor (no path-based `chmod` that follows symlinks);
//! - the exclusive lock is held from load → check → restore → record, so two
//!   concurrent restores cannot both pass the check;
//! - the ID is only recorded (and fsynced) after the caller reports that the
//!   restored objects were committed.

use crate::error::{CliError, CliResult};
use fs2::FileExt;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const GUARD_FILE_NAME: &str = ".craton_hsm_replay_guard";
const MAX_GUARD_BYTES: u64 = 16 * 1024 * 1024;

pub struct ReplayGuard {
    file: File,
    ids: HashSet<String>,
    path: PathBuf,
}

fn io_err(path: &Path, what: &str, e: impl std::fmt::Display) -> CliError {
    CliError::Io(format!("Replay guard '{}': {what}: {e}", path.display()))
}

impl ReplayGuard {
    /// Open (creating if needed) and exclusively lock the guard in `storage_dir`.
    pub fn open_locked(storage_dir: &Path) -> CliResult<Self> {
        let dmeta = std::fs::symlink_metadata(storage_dir)
            .map_err(|e| io_err(storage_dir, "storage directory unavailable", e))?;
        if !dmeta.is_dir() {
            return Err(CliError::Refused(format!(
                "Storage path '{}' is not a directory (symlinks are refused).",
                storage_dir.display()
            )));
        }
        let path = storage_dir.join(GUARD_FILE_NAME);

        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        #[cfg(not(unix))]
        {
            if let Ok(m) = std::fs::symlink_metadata(&path) {
                if m.file_type().is_symlink() {
                    return Err(io_err(&path, "open", "refusing to follow a symbolic link"));
                }
            }
        }
        let mut file = opts.open(&path).map_err(|e| io_err(&path, "open", e))?;
        let meta = file.metadata().map_err(|e| io_err(&path, "stat", e))?;
        if !meta.is_file() {
            return Err(io_err(&path, "open", "not a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // File::set_permissions is fchmod(2) on the open descriptor.
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| io_err(&path, "fchmod", e))?;
        }

        file.lock_exclusive()
            .map_err(|e| io_err(&path, "lock", e))?;

        let mut content = String::new();
        file.seek(SeekFrom::Start(0))
            .map_err(|e| io_err(&path, "seek", e))?;
        (&mut file)
            .take(MAX_GUARD_BYTES + 1)
            .read_to_string(&mut content)
            .map_err(|e| io_err(&path, "read", e))?;
        if content.len() as u64 > MAX_GUARD_BYTES {
            return Err(io_err(&path, "read", "file too large"));
        }
        let ids = parse_ids(&content);
        Ok(Self { file, ids, path })
    }

    /// Read the consumed IDs without creating, locking or modifying anything
    /// (used by `restore --verify-only`). A missing guard means "none".
    pub fn read_only_ids(storage_dir: &Path) -> CliResult<HashSet<String>> {
        let path = storage_dir.join(GUARD_FILE_NAME);
        let file = match crate::fsutil::open_regular_nofollow(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
            Err(e) => return Err(io_err(&path, "open", e)),
        };
        let mut content = String::new();
        file.take(MAX_GUARD_BYTES + 1)
            .read_to_string(&mut content)
            .map_err(|e| io_err(&path, "read", e))?;
        if content.len() as u64 > MAX_GUARD_BYTES {
            return Err(io_err(&path, "read", "file too large"));
        }
        Ok(parse_ids(&content))
    }

    pub fn consumed_ids(&self) -> &HashSet<String> {
        &self.ids
    }

    /// Durably record `id` as consumed. Call only after the restored objects
    /// have been committed.
    pub fn record(&mut self, id: &str) -> CliResult {
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CliError::General("invalid backup id".into()));
        }
        writeln!(self.file, "{id}").map_err(|e| io_err(&self.path, "write", e))?;
        self.file
            .sync_all()
            .map_err(|e| io_err(&self.path, "fsync", e))?;
        self.ids.insert(id.to_string());
        Ok(())
    }
}

fn parse_ids(content: &str) -> HashSet<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

impl Drop for ReplayGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_persist_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut g = ReplayGuard::open_locked(dir.path()).unwrap();
            assert!(g.consumed_ids().is_empty());
            g.record("00ff").unwrap();
            assert!(g.record("not-hex\nX").is_err());
        }
        assert!(ReplayGuard::read_only_ids(dir.path())
            .unwrap()
            .contains("00ff"));
        let g = ReplayGuard::open_locked(dir.path()).unwrap();
        assert!(g.consumed_ids().contains("00ff"));
        assert_eq!(g.consumed_ids().len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(GUARD_FILE_NAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_guard() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join(GUARD_FILE_NAME)).unwrap();
        assert!(ReplayGuard::open_locked(dir.path()).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"");
    }

    #[test]
    fn read_only_does_not_create_guard() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ReplayGuard::read_only_ids(dir.path()).unwrap().is_empty());
        assert!(!dir.path().join(GUARD_FILE_NAME).exists());
    }

    #[test]
    fn missing_storage_dir_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ReplayGuard::open_locked(&dir.path().join("nope")).is_err());
    }
}
