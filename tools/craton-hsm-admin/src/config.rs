// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Strict configuration loading for the admin CLI (H5-11).
//!
//! Unlike `HsmConfig::load_from_path`, a missing file is an error (the CLI
//! never silently falls back to defaults), the file must be owned by the
//! invoking user or root and must not be group/world-writable, its directory
//! must not be writable by other users, and all relative paths inside the
//! config are resolved against the config file's directory rather than the
//! current working directory.

use crate::error::{CliError, CliResult};
use craton_hsm::config::HsmConfig;
use std::path::{Path, PathBuf};

/// Absolute default configuration path (matches `docs/operator-runbook.md`).
#[cfg(not(windows))]
pub const DEFAULT_CONFIG_PATH: &str = "/etc/craton_hsm/craton_hsm.toml";
#[cfg(windows)]
pub const DEFAULT_CONFIG_PATH: &str = r"C:\ProgramData\craton_hsm\craton_hsm.toml";

/// Upper bound on the config file size.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// A validated configuration plus where it came from.
pub struct LoadedConfig {
    pub config: HsmConfig,
    /// Canonical path of the config file. Relative paths in the config have
    /// been resolved against its directory.
    pub path: PathBuf,
}

impl LoadedConfig {
    /// Directory holding persistent token state (lockout file, replay guard).
    pub fn storage_dir(&self) -> &Path {
        &self.config.token.storage_path
    }
}

fn config_err(path: &Path, msg: impl std::fmt::Display) -> CliError {
    CliError::Config(format!(
        "Config '{}': {msg}",
        crate::output::escape_display(&path.display().to_string())
    ))
}

/// Load, check and validate the configuration at `path`.
pub fn load_strict(path: &Path) -> CliResult<LoadedConfig> {
    let file = crate::fsutil::open_regular_nofollow(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => config_err(
            path,
            "file not found. Pass --config <path> explicitly; the CLI never falls back to \
             default settings.",
        ),
        _ => config_err(path, format!("cannot open ({e}); symlinks are refused")),
    })?;

    let canonical = path
        .canonicalize()
        .map_err(|e| config_err(path, format!("cannot resolve path: {e}")))?;
    let dir = canonical
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| config_err(path, "has no parent directory"))?;

    check_ownership_and_mode(&file, &dir, path)?;

    let config = parse(file, path)?;
    config
        .validate()
        .map_err(|e| config_err(path, format!("validation failed: {e}")))?;

    let config = anchor_paths(config, &dir);
    Ok(LoadedConfig {
        config,
        path: canonical,
    })
}

#[cfg(unix)]
fn check_ownership_and_mode(file: &std::fs::File, dir: &Path, path: &Path) -> CliResult {
    use std::os::unix::fs::MetadataExt;
    let euid = crate::sys::effective_uid();

    let meta = file
        .metadata()
        .map_err(|e| config_err(path, format!("cannot stat: {e}")))?;
    if meta.uid() != euid && meta.uid() != 0 {
        return Err(config_err(
            path,
            format!(
                "is owned by uid {} — must be owned by the invoking user (uid {euid}) or root",
                meta.uid()
            ),
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(config_err(
            path,
            format!(
                "has insecure permissions {:o} — must not be group- or world-writable",
                meta.mode() & 0o777
            ),
        ));
    }

    let dmeta =
        std::fs::metadata(dir).map_err(|e| config_err(path, format!("cannot stat dir: {e}")))?;
    if dmeta.uid() != euid && dmeta.uid() != 0 {
        return Err(config_err(
            path,
            format!(
                "directory '{}' is owned by uid {} — must be owned by the invoking user or root",
                dir.display(),
                dmeta.uid()
            ),
        ));
    }
    if dmeta.mode() & 0o022 != 0 {
        return Err(config_err(
            path,
            format!(
                "directory '{}' is group- or world-writable ({:o}); another user could \
                 replace the config",
                dir.display(),
                dmeta.mode() & 0o777
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_ownership_and_mode(_file: &std::fs::File, _dir: &Path, path: &Path) -> CliResult {
    // On Windows the library loader performs the ACL check (rejects files
    // writable by Everyone/Users/Authenticated Users); run it here as well.
    let s = path
        .to_str()
        .ok_or_else(|| config_err(path, "path is not valid UTF-8"))?;
    HsmConfig::load_from_path(s)
        .map(|_| ())
        .map_err(|e| config_err(path, format!("permission check failed: {e}")))
}

fn parse(file: std::fs::File, path: &Path) -> CliResult<HsmConfig> {
    use std::io::Read;
    let mut content = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut content)
        .map_err(|e| config_err(path, format!("cannot read: {e}")))?;
    if content.len() as u64 > MAX_CONFIG_BYTES {
        return Err(config_err(path, "file is too large"));
    }
    toml::from_str::<HsmConfig>(&content).map_err(|e| config_err(path, format!("parse error: {e}")))
}

/// Resolve relative state paths against the config file's directory so that
/// the CLI acts on the same files regardless of the current directory.
fn anchor_paths(mut config: HsmConfig, dir: &Path) -> HsmConfig {
    if config.token.storage_path.is_relative() {
        config.token.storage_path = dir.join(&config.token.storage_path);
    }
    if config.audit.log_path.is_relative() {
        config.audit.log_path = dir.join(&config.audit.log_path);
    }
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_cfg(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("craton_hsm.toml");
        std::fs::write(&p, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        p
    }

    #[test]
    fn missing_config_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_strict(&dir.path().join("nope.toml"))
            .err()
            .expect("must fail");
        assert!(matches!(err, CliError::Config(_)));
    }

    #[test]
    fn relative_paths_are_anchored_to_config_dir() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(
            dir.path(),
            "[token]\nstorage_path = \"store\"\n[audit]\nlog_path = \"audit.jsonl\"\n",
        );
        let loaded = load_strict(&p).unwrap();
        let canon = dir.path().canonicalize().unwrap();
        assert_eq!(loaded.config.token.storage_path, canon.join("store"));
        assert_eq!(loaded.config.audit.log_path, canon.join("audit.jsonl"));
        assert_eq!(loaded.path, canon.join("craton_hsm.toml"));
    }

    #[cfg(unix)]
    #[test]
    fn group_writable_config_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(dir.path(), "");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(matches!(load_strict(&p), Err(CliError::Config(_))));
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_config_dir_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(dir.path(), "");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let r = load_strict(&p);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(r, Err(CliError::Config(_))));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(dir.path(), "");
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(matches!(load_strict(&link), Err(CliError::Config(_))));
    }

    #[test]
    fn invalid_config_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(dir.path(), "[token]\nstorage_path = \"../escape\"\n");
        assert!(matches!(load_strict(&p), Err(CliError::Config(_))));
        let p = write_cfg(dir.path(), "this is = = not toml");
        assert!(matches!(load_strict(&p), Err(CliError::Config(_))));
    }
}
