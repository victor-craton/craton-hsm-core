// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Error type and documented process exit codes for the admin CLI.

use std::fmt;

/// Documented exit codes. Scripts can rely on these values.
pub mod exit_code {
    /// Unclassified failure.
    pub const GENERAL: i32 = 1;
    /// Invalid command-line usage (also used by clap).
    pub const USAGE: i32 = 2;
    /// Configuration file missing, unsafe or invalid.
    pub const CONFIG: i32 = 3;
    /// Authentication failed or the token is not initialized.
    pub const AUTH: i32 = 4;
    /// Operation refused (e.g. not supported in standalone mode, or a
    /// safety precondition failed).
    pub const REFUSED: i32 = 5;
    /// Integrity failure (audit chain broken / tampered).
    pub const INTEGRITY: i32 = 6;
    /// Filesystem or terminal I/O failure.
    pub const IO: i32 = 7;
    /// The operator aborted at a confirmation prompt.
    pub const ABORTED: i32 = 8;
    /// Backup rejected (wrong passphrase, replayed, stale, wrong token).
    pub const BACKUP_REJECTED: i32 = 9;
}

/// Help text appended to `--help` describing the exit codes.
pub const EXIT_CODE_HELP: &str = "\
Exit codes:
  0  success
  1  general failure
  2  invalid usage
  3  configuration missing, unsafe or invalid
  4  authentication failed / token not initialized
  5  operation refused (unsupported in standalone mode or unsafe precondition)
  6  integrity failure (audit log chain broken or tampered)
  7  I/O error
  8  aborted by operator
  9  backup rejected (wrong passphrase, replayed, stale or foreign backup)";

#[derive(Debug)]
pub enum CliError {
    General(String),
    Usage(String),
    Config(String),
    Auth(String),
    Refused(String),
    Integrity(String),
    Io(String),
    Aborted,
    BackupRejected(String),
}

pub type CliResult<T = ()> = Result<T, CliError>;

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::General(_) => exit_code::GENERAL,
            CliError::Usage(_) => exit_code::USAGE,
            CliError::Config(_) => exit_code::CONFIG,
            CliError::Auth(_) => exit_code::AUTH,
            CliError::Refused(_) => exit_code::REFUSED,
            CliError::Integrity(_) => exit_code::INTEGRITY,
            CliError::Io(_) => exit_code::IO,
            CliError::Aborted => exit_code::ABORTED,
            CliError::BackupRejected(_) => exit_code::BACKUP_REJECTED,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::General(m)
            | CliError::Usage(m)
            | CliError::Config(m)
            | CliError::Auth(m)
            | CliError::Refused(m)
            | CliError::Integrity(m)
            | CliError::Io(m)
            | CliError::BackupRejected(m) => f.write_str(m),
            CliError::Aborted => f.write_str("Aborted by operator."),
        }
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Io(format!("I/O error: {e}"))
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError::General(format!("JSON serialization failed: {e}"))
    }
}
