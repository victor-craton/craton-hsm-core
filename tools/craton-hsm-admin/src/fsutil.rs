// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Filesystem helpers: single-open, bounded, symlink-refusing reads.

use crate::error::{CliError, CliResult};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

/// Open an existing file for reading without following a final symlink and
/// without blocking on FIFOs, then require that it is a regular file.
pub fn open_regular_nofollow(path: &Path) -> std::io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    #[cfg(windows)]
    {
        // `OpenOptions` follows reparse points on Windows; re-check the link
        // itself so that a symlinked input is refused on every platform.
        if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to follow a symbolic link",
            ));
        }
    }
    Ok(file)
}

/// Read a whole user-supplied file with a hard size cap (H5-16).
///
/// The file is opened exactly once; its type and length are checked on the
/// open descriptor and the read itself is bounded, so a device, FIFO or a file
/// that grows while being read cannot exhaust memory.
pub fn read_bounded(path: &Path, cap: u64, what: &str) -> CliResult<Zeroizing<Vec<u8>>> {
    let file = open_regular_nofollow(path).map_err(|e| {
        CliError::Io(format!(
            "Cannot open {what} '{}': {e}",
            crate::output::escape_display(&path.display().to_string())
        ))
    })?;
    let len = file
        .metadata()
        .map_err(|e| CliError::Io(format!("Cannot stat {what}: {e}")))?
        .len();
    if len > cap {
        return Err(CliError::Refused(format!(
            "{what} is too large ({len} bytes; maximum {cap} bytes)."
        )));
    }
    let capacity = usize::try_from(len).unwrap_or(0);
    let mut buf = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(cap.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| CliError::Io(format!("Cannot read {what}: {e}")))?;
    if buf.len() as u64 > cap {
        return Err(CliError::Refused(format!(
            "{what} grew beyond the maximum of {cap} bytes while being read."
        )));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_bounded_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big");
        std::fs::write(&p, vec![0u8; 100]).unwrap();
        let err = read_bounded(&p, 10, "test file").unwrap_err();
        assert!(matches!(err, CliError::Refused(_)));
        assert_eq!(read_bounded(&p, 100, "test file").unwrap().len(), 100);
    }

    #[test]
    fn read_bounded_rejects_directory_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_bounded(dir.path(), 10, "dir").is_err());
        assert!(read_bounded(&dir.path().join("missing"), 10, "missing").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn read_bounded_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"data").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_bounded(&link, 100, "link").is_err());
    }
}
