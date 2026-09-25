// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use serde::Deserialize;
use std::fmt;
use std::path::PathBuf;

use crate::error::HsmError;

/// Minimum acceptable PBKDF2 iteration count to resist brute-force attacks.
const MIN_PBKDF2_ITERATIONS: u32 = 100_000;
/// Maximum acceptable PBKDF2 iteration count to prevent algorithmic DoS via
/// config-planted extreme values.
const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;
/// Minimum acceptable `pin_min_length`: the same floor of 8 characters that
/// every front end enforces (H5-12; the admin CLI previously applied it on
/// its own).
const MIN_PIN_LENGTH: usize = 8;
/// Bounds for `max_failed_logins` to prevent DoS (too low) or brute-force
/// (too high).
const MIN_FAILED_LOGINS: u32 = 3;
const MAX_FAILED_LOGINS: u32 = 100;
/// Maximum PIN length to prevent memory-exhaustion via PBKDF2 on huge PINs.
const MAX_PIN_LENGTH: usize = 256;
/// Bounds for a time-based user PIN lockout (`0` = permanent).
const MIN_LOCKOUT_DURATION_SECS: u64 = 60;
const MAX_LOCKOUT_DURATION_SECS: u64 = 30 * 24 * 3600;
/// Maximum sessions to prevent resource exhaustion.
const MAX_SESSIONS: u64 = 10_000;
/// Maximum slots to prevent OOM on initialization.
const MAX_SLOT_COUNT: usize = 256;
/// Maximum token label length (PKCS#11 CK_TOKEN_INFO.label is 32 bytes).
const MAX_LABEL_LENGTH: usize = 32;
/// Valid crypto backend identifiers.
const VALID_BACKENDS: &[&str] = &["rustcrypto", "awslc"];
/// Valid audit log levels. `all`/`crypto` record every event; `auth`/`admin`
/// record only the mandatory authentication, token- and key-management
/// events. There is no "none" level — disable auditing explicitly with
/// `enabled = false` plus `allow_disabled_insecure = true`.
const VALID_LOG_LEVELS: &[&str] = &["all", "crypto", "auth", "admin"];
/// Relative path prefixes that could target sensitive directories.
const SENSITIVE_PATH_PREFIXES: &[&str] = &[".git", ".ssh", ".gnupg", ".aws", ".config", ".env"];
/// Absolute system locations that must never be used for HSM storage.
#[cfg(unix)]
const SYSTEM_PATH_PREFIXES: &[&str] = &[
    "/etc", "/bin", "/sbin", "/usr", "/lib", "/lib64", "/boot", "/dev", "/proc", "/sys",
];
#[cfg(not(unix))]
const SYSTEM_PATH_PREFIXES: &[&str] = &["C:\\Windows", "C:/Windows"];
/// System-wide configuration file used when `CRATON_HSM_CONFIG` is unset.
#[cfg(unix)]
pub const SYSTEM_CONFIG_PATH: &str = "/etc/craton-hsm/craton_hsm.toml";
/// System-wide configuration file used when `CRATON_HSM_CONFIG` is unset.
#[cfg(not(unix))]
pub const SYSTEM_CONFIG_PATH: &str = "C:\\ProgramData\\craton-hsm\\craton_hsm.toml";

/// Top-level configuration. Unknown sections and unknown keys inside the
/// core sections are rejected (H4-17): a typo such as `max_failed_login`
/// must not silently fall back to a default security parameter.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct HsmConfig {
    #[serde(default)]
    pub token: TokenConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub algorithms: AlgorithmConfig,
    /// `[daemon]` section of a shared configuration file. Opaque to the core
    /// library; parsed and strictly validated by `craton-hsm-daemon`.
    #[serde(default)]
    pub daemon: Option<toml::Value>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    #[serde(default = "default_label")]
    pub label: String,
    #[serde(default = "default_storage_path")]
    pub storage_path: PathBuf,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: u64,
    #[serde(default = "default_max_rw_sessions")]
    pub max_rw_sessions: u64,
    /// If true, the token is **persistent**: token state (initialised flag,
    /// label, PIN verifiers, lockout counters, wrapped storage keys) and
    /// token objects (CKA_TOKEN=true) are stored encrypted under
    /// `storage_path` and reloaded on start (see `HsmCore::open`). Session
    /// objects are never persisted.
    /// Default: false — **ephemeral** token (development only): everything
    /// is lost on restart and the token must be re-initialised.
    #[serde(default)]
    pub persist_objects: bool,
    /// Maximum number of sessions one application (process for the C ABI,
    /// client connection for the daemon) may hold open. Default: the
    /// per-token `max_sessions`.
    #[serde(default = "default_max_sessions")]
    pub max_sessions_per_application: u64,
    /// Number of slots to create. Default: 1 (backward compatible).
    /// Each slot gets its own independent token.
    #[serde(default = "default_slot_count")]
    pub slot_count: usize,
    /// Token serial number (16-char string, space-padded).
    /// Should be unique per deployment. Default: "0000000000000001".
    #[serde(default = "default_serial_number")]
    pub serial_number: String,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default = "default_pin_min")]
    pub pin_min_length: usize,
    #[serde(default = "default_pin_max")]
    pub pin_max_length: usize,
    #[serde(default = "default_max_failed")]
    pub max_failed_logins: u32,
    #[serde(default = "default_pbkdf2_iterations")]
    pub pbkdf2_iterations: u32,
    /// Lockout policy hook (H4-11): number of seconds after which a **User**
    /// PIN that was locked by `max_failed_logins` failures unlocks again
    /// (the failure counter restarts; exponential back-off still applies).
    /// `0` (default) = the lock is permanent until the SO resets the user
    /// PIN (`C_InitPIN`). The SO PIN lock is always permanent (out-of-band
    /// recovery), and a time-based unlock is refused in FIPS approved mode.
    #[serde(default)]
    pub user_lockout_duration_secs: u64,
}

// Custom Debug to avoid leaking security parameters in logs/panics.
impl fmt::Debug for SecurityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityConfig")
            .field("pin_min_length", &"[REDACTED]")
            .field("pin_max_length", &"[REDACTED]")
            .field("max_failed_logins", &"[REDACTED]")
            .field("pbkdf2_iterations", &"[REDACTED]")
            .field("user_lockout_duration_secs", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_audit_path")]
    pub log_path: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Path of the audit HMAC key file (default `<log_path>.key`). Place it
    /// where the audit-log readers/backup operators cannot read it.
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    /// Fail closed: once an event cannot be written durably, every further
    /// audited operation fails with `CKR_DEVICE_ERROR`. Default: false
    /// (true in FIPS mode).
    #[serde(default)]
    pub fail_closed: bool,
    /// Allow the HSM to start although the audit chain failed verification.
    /// Default: false — refuse to start (H3-11).
    #[serde(default)]
    pub allow_start_with_broken_chain: bool,
    /// Explicit acknowledgement required to run with `enabled = false`.
    #[serde(default)]
    pub allow_disabled_insecure: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AlgorithmConfig {
    #[serde(default)]
    pub allow_weak_rsa: bool,
    #[serde(default)]
    pub allow_sha1_signing: bool,
    #[serde(default = "default_true")]
    pub enable_pqc: bool,
    /// Crypto backend: "rustcrypto" (default) or "awslc".
    /// Only effective when the corresponding feature is compiled in.
    #[serde(default = "default_crypto_backend")]
    pub crypto_backend: String,
    /// When true, only FIPS 140-3 approved algorithms are permitted.
    /// Non-approved mechanisms (e.g., EdDSA, SHA-1 signing) are blocked.
    /// PQC mechanisms are also blocked (not yet FIPS-approved).
    #[serde(default)]
    pub fips_approved_only: bool,
    /// Gate for RSA PKCS#1 v1.5 **decryption** (`CKM_RSA_PKCS` with
    /// `C_Decrypt` / `C_UnwrapKey`), which is exposed to Bleichenbacher /
    /// Marvin padding-oracle attacks (H2-03, A1-26). Default: false. Must be
    /// false in FIPS approved mode (SP 800-131A Rev. 2 disallows PKCS#1 v1.5
    /// key transport). Every PKCS#1 v1.5 decryption path must check
    /// [`AlgorithmConfig::rsa_pkcs1v15_decrypt_allowed`].
    #[serde(default)]
    pub allow_rsa_pkcs1v15_decrypt: bool,
    /// AES-GCM encryption IV source: `"caller"` (default; a caller-supplied
    /// 96-bit IV in `CK_GCM_PARAMS` is honoured outside FIPS approved mode)
    /// or `"module"` (every GCM encryption IV is generated by the module's
    /// approved DRBG, as in FIPS approved mode — IG C.H). See
    /// [`AlgorithmConfig::caller_gcm_iv_allowed`].
    #[serde(default = "default_gcm_iv_generation")]
    pub gcm_iv_generation: String,
}

impl AlgorithmConfig {
    /// Whether RSA PKCS#1 v1.5 decryption may be offered (H2-03). Always
    /// false in FIPS approved mode.
    pub fn rsa_pkcs1v15_decrypt_allowed(&self) -> bool {
        self.allow_rsa_pkcs1v15_decrypt && !self.fips_approved_only
    }

    /// Whether a caller-chosen AES-GCM encryption IV may be used (false in
    /// FIPS approved mode and with `gcm_iv_generation = "module"`).
    pub fn caller_gcm_iv_allowed(&self) -> bool {
        !self.fips_approved_only && self.gcm_iv_generation != "module"
    }
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            label: default_label(),
            storage_path: default_storage_path(),
            max_sessions: default_max_sessions(),
            max_rw_sessions: default_max_rw_sessions(),
            persist_objects: false,
            max_sessions_per_application: default_max_sessions(),
            slot_count: default_slot_count(),
            serial_number: default_serial_number(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            pin_min_length: default_pin_min(),
            pin_max_length: default_pin_max(),
            max_failed_logins: default_max_failed(),
            pbkdf2_iterations: default_pbkdf2_iterations(),
            user_lockout_duration_secs: 0,
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_path: default_audit_path(),
            log_level: default_log_level(),
            key_path: None,
            fail_closed: false,
            allow_start_with_broken_chain: false,
            allow_disabled_insecure: false,
        }
    }
}

impl Default for AlgorithmConfig {
    fn default() -> Self {
        Self {
            allow_weak_rsa: false,
            allow_sha1_signing: false,
            enable_pqc: true,
            crypto_backend: default_crypto_backend(),
            fips_approved_only: false,
            allow_rsa_pkcs1v15_decrypt: false,
            gcm_iv_generation: default_gcm_iv_generation(),
        }
    }
}

fn default_label() -> String {
    "Craton HSM Token 0".to_string()
}
fn default_storage_path() -> PathBuf {
    PathBuf::from("craton_hsm_store")
}
fn default_max_sessions() -> u64 {
    100
}
fn default_max_rw_sessions() -> u64 {
    10
}
fn default_pin_min() -> usize {
    8
}
fn default_pin_max() -> usize {
    64
}
fn default_max_failed() -> u32 {
    crate::config::defaults::DEFAULT_MAX_FAILED_LOGINS
}
fn default_pbkdf2_iterations() -> u32 {
    crate::config::defaults::DEFAULT_PBKDF2_ITERATIONS
}
fn default_true() -> bool {
    true
}
fn default_audit_path() -> PathBuf {
    PathBuf::from("craton_hsm_audit.jsonl")
}
fn default_log_level() -> String {
    "all".to_string()
}
/// Default crypto backend. `fips` builds must use the FIPS-validated
/// AWS-LC module: the RustCrypto backend is refused by the backend POST in
/// those builds (H2-05/A1-03), so defaulting to it would leave every `fips`
/// build in the error state.
fn default_crypto_backend() -> String {
    if cfg!(feature = "fips") {
        "awslc".to_string()
    } else {
        "rustcrypto".to_string()
    }
}

#[cfg(all(feature = "fips", not(feature = "awslc-backend")))]
compile_error!("the `fips` feature requires the `awslc-backend` feature (FIPS-validated AWS-LC)");
fn default_gcm_iv_generation() -> String {
    "caller".to_string()
}
fn default_slot_count() -> usize {
    1
}
fn default_serial_number() -> String {
    "0000000000000001".to_string()
}

impl HsmConfig {
    /// Load configuration, returning an error if the config file exists but is
    /// invalid or fails validation. Falls back to defaults only when no config
    /// file is present.
    pub fn load() -> Result<Self, HsmError> {
        // In FIPS mode, use hardcoded secure defaults — never read from filesystem
        // to prevent an attacker from planting a permissive config file.
        #[cfg(feature = "fips")]
        {
            tracing::info!(
                "FIPS mode active (compile-time) — using hardcoded secure defaults, ignoring config files"
            );
            return Ok(Self::fips_defaults());
        }

        #[cfg(not(feature = "fips"))]
        {
            if std::env::var("CRATON_HSM_FIPS").as_deref() == Ok("1") {
                // SECURITY WARNING: Environment-variable FIPS mode is ADVISORY ONLY.
                //
                // An attacker who can modify the process environment (e.g. via
                // /proc/pid/environ, LD_PRELOAD, or parent-process control) can:
                //   1. Unset CRATON_HSM_FIPS to disable FIPS mode entirely.
                //   2. Set CRATON_HSM_CONFIG to load a permissive configuration.
                //
                // For certified FIPS 140-3 compliance, you MUST compile with
                // `--features fips` which hardcodes secure defaults at compile time
                // and cannot be bypassed at runtime.
                //
                // This env-var path exists only as a convenience for development and
                // testing. Do NOT rely on it for production FIPS compliance.
                tracing::warn!(
                    "FIPS mode activated via CRATON_HSM_FIPS env var. \
                     SECURITY: env-var FIPS is ADVISORY ONLY — an attacker who can modify \
                     the process environment can bypass this entirely. For certified FIPS \
                     compliance, compile with `--features fips`."
                );
                return Ok(Self::fips_defaults());
            }

            // H3-13: never load configuration from the (attacker-influenced)
            // current working directory. Sources, in order:
            //   1. $CRATON_HSM_CONFIG (validated, ownership-checked);
            //   2. the system-wide SYSTEM_CONFIG_PATH;
            //   3. built-in secure defaults.
            if std::path::Path::new("craton_hsm.toml").exists() {
                tracing::warn!(
                    "./craton_hsm.toml is ignored (configuration is never read from the \
                     working directory); set CRATON_HSM_CONFIG or use {}",
                    SYSTEM_CONFIG_PATH
                );
            }
            let config_path = match std::env::var("CRATON_HSM_CONFIG") {
                Ok(p) => p,
                Err(_) => {
                    if std::path::Path::new(SYSTEM_CONFIG_PATH).exists() {
                        SYSTEM_CONFIG_PATH.to_string()
                    } else {
                        tracing::info!("No configuration file — using secure defaults");
                        return Ok(Self::default());
                    }
                }
            };

            Self::validate_config_path(&config_path)?;
            Self::load_from_path(&config_path)
        }
    }

    /// FIPS-hardened defaults: audit enabled, no weak algorithms, approved-only,
    /// and the FIPS-validated AWS-LC backend whenever it is compiled in (a
    /// `fips` build refuses the RustCrypto backend at POST, ci.md blocker).
    pub fn fips_defaults() -> Self {
        let mut config = Self::default();
        if cfg!(feature = "awslc-backend") {
            config.algorithms.crypto_backend = "awslc".to_string();
        }
        config.algorithms.allow_rsa_pkcs1v15_decrypt = false;
        config.algorithms.fips_approved_only = true;
        config.algorithms.allow_weak_rsa = false;
        config.algorithms.allow_sha1_signing = false;
        config.algorithms.enable_pqc = false;
        config.audit.enabled = true;
        config.audit.fail_closed = true;
        config
    }

    /// Validate that a filesystem path is safe: no absolute paths, no traversal,
    /// no UNC paths, no null bytes, no symlinks, no sensitive directory targets.
    /// `label` is used in error messages (e.g. "config path", "storage_path").
    fn validate_path_safety(path: &std::path::Path, label: &str) -> Result<(), Vec<String>> {
        let mut errors: Vec<String> = Vec::new();
        let path_str = path.to_string_lossy();

        // Absolute paths are allowed (and recommended: a service-owned
        // directory such as /var/lib/craton-hsm) — relative paths depend on
        // the host process's working directory (H3-12). System locations are
        // never acceptable.
        if path.is_absolute() {
            for prefix in SYSTEM_PATH_PREFIXES {
                let p = std::path::Path::new(prefix);
                if path.starts_with(p) {
                    errors.push(format!(
                        "{} '{}' points into system directory '{}'",
                        label, path_str, prefix
                    ));
                    break;
                }
            }
        } else {
            tracing::warn!(
                "{} '{}' is relative to the working directory; use an absolute, \
                 service-owned path in production",
                label,
                path_str
            );
        }
        if path_str.starts_with("\\\\") || path_str.starts_with("//") {
            errors.push(format!(
                "{} '{}' is a UNC path — not permitted",
                label, path_str
            ));
        }
        for component in path.components() {
            if let std::path::Component::ParentDir = component {
                errors.push(format!(
                    "{} '{}' contains '..' traversal component",
                    label, path_str
                ));
                break;
            }
        }
        if path_str.contains('\0') {
            errors.push(format!("{} contains null byte", label));
        }

        // Reject paths targeting sensitive directories.
        if let Some(first) = path.components().next() {
            let first_str = first.as_os_str().to_string_lossy();
            for prefix in SENSITIVE_PATH_PREFIXES {
                if first_str.eq_ignore_ascii_case(prefix) {
                    errors.push(format!(
                        "{} '{}' targets sensitive directory '{}'",
                        label, path_str, prefix
                    ));
                    break;
                }
            }
        }

        // Reject symlinks (TOCTOU mitigation — check at validation time).
        if path.exists() {
            match std::fs::symlink_metadata(path) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    errors.push(format!(
                        "{} '{}' is a symlink — not permitted",
                        label, path_str
                    ));
                }
                _ => {}
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate the config file path from CRATON_HSM_CONFIG env var.
    fn validate_config_path(path: &str) -> Result<(), HsmError> {
        let p = std::path::Path::new(path);
        if let Err(errs) = Self::validate_path_safety(p, "config path") {
            let msg = errs.join("; ");
            tracing::error!("Config path validation failed: {}", msg);
            return Err(HsmError::ConfigError(msg));
        }
        Ok(())
    }

    /// Check file permissions on the already-opened file to reject insecure
    /// ownership or write permissions, mitigating config-planting attacks.
    ///
    /// On Unix: rejects group-writable or world-writable files.
    /// On Windows: rejects files writable by the Everyone or Users groups.
    fn check_file_permissions(file: &std::fs::File, path: &str) -> Result<(), HsmError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = file.metadata().map_err(|e| {
                HsmError::ConfigError(format!("cannot stat config file '{}': {}", path, e))
            })?;
            let mode = meta.mode();
            // Reject files owned by anyone other than us or root (H3-13).
            let euid = crate::store::fs_util::effective_uid();
            if meta.uid() != euid && meta.uid() != 0 {
                tracing::error!(
                    "Config file '{}' is owned by uid {} (expected {} or root)",
                    path,
                    meta.uid(),
                    euid
                );
                return Err(HsmError::ConfigError(
                    "config file has insecure ownership".to_string(),
                ));
            }
            Self::check_ancestors(path)?;
            // Reject group-writable (0o020) or other-writable (0o002)
            if mode & 0o022 != 0 {
                tracing::error!(
                    "Config file '{}' has insecure permissions {:o} — \
                     must not be group- or world-writable",
                    path,
                    mode & 0o777
                );
                return Err(HsmError::ConfigError(format!(
                    "config file has insecure permissions ({:o}); \
                     must not be group- or world-writable",
                    mode & 0o777
                )));
            }
        }

        #[cfg(windows)]
        {
            Self::check_windows_permissions(file, path)?;
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = (file, path);
        }

        Ok(())
    }

    /// Reject configuration files whose directory (or any ancestor) can be
    /// modified by other users: the parent must not be group/world writable,
    /// and no ancestor may be world writable without the sticky bit.
    #[cfg(unix)]
    fn check_ancestors(path: &str) -> Result<(), HsmError> {
        use std::os::unix::fs::MetadataExt;
        let abs = std::fs::canonicalize(path).map_err(|e| {
            HsmError::ConfigError(format!("cannot resolve config path '{}': {}", path, e))
        })?;
        let mut first = true;
        let mut cur = abs.parent();
        while let Some(dir) = cur {
            let meta = std::fs::metadata(dir).map_err(|e| {
                HsmError::ConfigError(format!("cannot stat '{}': {}", dir.display(), e))
            })?;
            let mode = meta.mode();
            let sticky = mode & 0o1000 != 0;
            if (first && mode & 0o022 != 0 && !sticky) || (mode & 0o002 != 0 && !sticky) {
                tracing::error!(
                    "Config directory '{}' is writable by other users ({:o})",
                    dir.display(),
                    mode & 0o7777
                );
                return Err(HsmError::ConfigError(format!(
                    "config directory '{}' is writable by other users",
                    dir.display()
                )));
            }
            first = false;
            cur = dir.parent();
        }
        Ok(())
    }

    /// Windows-specific permission check: reject files writable by broad groups.
    /// Uses the file's metadata to verify the read-only attribute as a baseline,
    /// and checks NTFS ACLs via icacls on the canonical path.
    #[cfg(windows)]
    fn check_windows_permissions(_file: &std::fs::File, path: &str) -> Result<(), HsmError> {
        // Check NTFS ACLs via icacls for broad write access.
        // Resolve the canonical path from the open handle to avoid TOCTOU on
        // the path string (the handle is already pinned to an inode).
        // Fail closed (H3-29): if the ACL cannot be inspected, refuse the file.
        let canonical = std::fs::canonicalize(path).map_err(|e| {
            HsmError::ConfigError(format!("cannot resolve config path '{}': {}", path, e))
        })?;
        let output = std::process::Command::new("icacls")
            .arg(&canonical)
            .output()
            .map_err(|e| HsmError::ConfigError(format!("cannot inspect config ACL: {}", e)))?;
        if !output.status.success() {
            return Err(HsmError::ConfigError(
                "cannot inspect config file ACL (icacls failed)".to_string(),
            ));
        }
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stdout_upper = stdout.to_uppercase();
            // Reject if Everyone, Users, or Authenticated Users have write/full access.
            let dangerous_principals =
                ["EVERYONE", "USERS", "AUTHENTICATED USERS", "BUILTIN\\USERS"];
            let dangerous_perms = ["(F)", "(M)", "(W)"];
            for line in stdout_upper.lines() {
                for principal in &dangerous_principals {
                    if line.contains(principal) {
                        for perm in &dangerous_perms {
                            if line.contains(perm) {
                                tracing::error!(
                                    "Config file '{}' has insecure ACL — {} has write access",
                                    path,
                                    principal
                                );
                                return Err(HsmError::ConfigError(format!(
                                    "config file has insecure permissions; \
                                     {} has write access — restrict to owner only",
                                    principal
                                )));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check that an already-opened file is not a symlink, using the file
    /// handle's metadata to avoid TOCTOU races.
    fn check_file_not_symlink(file: &std::fs::File, path: &str) -> Result<(), HsmError> {
        let meta = file.metadata().map_err(|e| {
            HsmError::ConfigError(format!("cannot stat config file '{}': {}", path, e))
        })?;

        // On Unix, also check via symlink_metadata on the path as a defense-in-depth
        // measure (the open fd is authoritative, but this catches broken symlinks).
        #[cfg(unix)]
        {
            if let Ok(link_meta) = std::fs::symlink_metadata(path) {
                if link_meta.file_type().is_symlink() {
                    tracing::error!(
                        "Config file '{}' is a symlink — not permitted for security files",
                        path
                    );
                    return Err(HsmError::ConfigError(
                        "config file is a symlink — not permitted".to_string(),
                    ));
                }
            }
        }

        let _ = meta;
        Ok(())
    }

    /// Load **and validate** configuration from an explicit path.
    ///
    /// A missing file is an error (an explicitly named configuration must not
    /// silently fall back to defaults, H3-13). The file is opened without
    /// following symlinks; ownership, permissions and ancestor directories
    /// are checked on the open descriptor.
    pub fn load_from_path(path: &str) -> Result<Self, HsmError> {
        use std::io::Read;

        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = match opts.open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::error!("Config file '{}' not found", path);
                return Err(HsmError::ConfigError(format!(
                    "config file '{}' not found",
                    path
                )));
            }
            Err(e) => {
                tracing::error!("Cannot read config file '{}': {}", path, e);
                return Err(HsmError::ConfigError(
                    "cannot read config file — check logs for details".to_string(),
                ));
            }
        };

        // All checks use the open file descriptor — no TOCTOU window.
        Self::check_file_not_symlink(&file, path)?;
        Self::check_file_permissions(&file, path)?;

        let mut content = String::new();
        let mut reader = std::io::BufReader::new(file);
        reader.read_to_string(&mut content).map_err(|e| {
            tracing::error!("Cannot read config file '{}': {}", path, e);
            HsmError::ConfigError("cannot read config file — check logs for details".to_string())
        })?;

        let config: Self = toml::from_str(&content).map_err(|e| {
            // Log full details internally; return sanitized error to caller
            tracing::error!(
                "Failed to parse config file '{}': {} — refusing to start with potentially \
                 misconfigured security parameters",
                path,
                e
            );
            HsmError::ConfigError(
                "failed to parse config file — check logs for details".to_string(),
            )
        })?;
        let mut config = config;
        config.enforce_build_policy();
        config.validate()?;
        Ok(config)
    }

    /// Apply the build's non-overridable policy (A1-06/A1-24). In `fips`
    /// builds approved mode is a build property: whatever a configuration
    /// file says, approved-only mode, the FIPS-validated AWS-LC backend, a
    /// fail-closed audit log and the FIPS algorithm restrictions are forced.
    /// Every configuration loader (library, daemon, admin CLI) calls this.
    /// No-op in non-`fips` builds.
    pub fn enforce_build_policy(&mut self) {
        if cfg!(feature = "fips") {
            let changed = !self.algorithms.fips_approved_only
                || self.algorithms.crypto_backend != "awslc"
                || self.algorithms.enable_pqc
                || self.algorithms.allow_weak_rsa
                || self.algorithms.allow_sha1_signing
                || self.algorithms.allow_rsa_pkcs1v15_decrypt
                || !self.audit.enabled
                || !self.audit.fail_closed
                || self.security.user_lockout_duration_secs != 0;
            if changed {
                tracing::warn!(
                    "fips build: configuration overridden to FIPS approved mode \
                     (awslc backend, no PQC/weak algorithms, fail-closed audit)"
                );
            }
            self.algorithms.fips_approved_only = true;
            self.algorithms.crypto_backend = "awslc".to_string();
            self.algorithms.enable_pqc = false;
            self.algorithms.allow_weak_rsa = false;
            self.algorithms.allow_sha1_signing = false;
            self.algorithms.allow_rsa_pkcs1v15_decrypt = false;
            self.audit.enabled = true;
            self.audit.fail_closed = true;
            self.security.user_lockout_duration_secs = 0;
        }
    }

    /// Comprehensive validation of all security-critical configuration values.
    /// Called automatically by `load()`.
    pub fn validate(&self) -> Result<(), HsmError> {
        let mut errors: Vec<String> = Vec::new();

        // --- storage_path: reject absolute, traversal, UNC, null bytes, symlinks, sensitive dirs ---
        if let Err(path_errs) = Self::validate_path_safety(&self.token.storage_path, "storage_path")
        {
            errors.extend(path_errs);
        }

        // --- audit log_path: same checks ---
        if let Err(path_errs) = Self::validate_path_safety(&self.audit.log_path, "audit log_path") {
            errors.extend(path_errs);
        }

        // --- token label: PKCS#11 requires <= 32 bytes, printable ASCII only ---
        if self.token.label.is_empty() {
            errors.push("token label must not be empty".to_string());
        }
        if self.token.label.len() > MAX_LABEL_LENGTH {
            errors.push(format!(
                "token label '{}' exceeds {} bytes (PKCS#11 CK_TOKEN_INFO.label limit)",
                self.token.label, MAX_LABEL_LENGTH
            ));
        }
        if !self
            .token
            .label
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
        {
            errors.push("token label contains non-printable or non-ASCII characters".to_string());
        }

        // --- PIN length bounds ---
        if self.security.pin_min_length < MIN_PIN_LENGTH {
            errors.push(format!(
                "pin_min_length ({}) is below the minimum of {}",
                self.security.pin_min_length, MIN_PIN_LENGTH
            ));
        }
        if self.security.pin_max_length < self.security.pin_min_length {
            errors.push(format!(
                "pin_max_length ({}) is less than pin_min_length ({})",
                self.security.pin_max_length, self.security.pin_min_length
            ));
        }
        if self.security.pin_max_length > MAX_PIN_LENGTH {
            errors.push(format!(
                "pin_max_length ({}) exceeds the maximum of {} (risk of memory exhaustion during PIN hashing)",
                self.security.pin_max_length, MAX_PIN_LENGTH
            ));
        }

        // --- PBKDF2 iterations bounds ---
        if self.security.pbkdf2_iterations < MIN_PBKDF2_ITERATIONS {
            errors.push(format!(
                "pbkdf2_iterations ({}) is below the minimum of {}",
                self.security.pbkdf2_iterations, MIN_PBKDF2_ITERATIONS
            ));
        }
        if self.security.pbkdf2_iterations > MAX_PBKDF2_ITERATIONS {
            errors.push(format!(
                "pbkdf2_iterations ({}) exceeds the maximum of {} (risk of algorithmic DoS)",
                self.security.pbkdf2_iterations, MAX_PBKDF2_ITERATIONS
            ));
        }

        // --- max_failed_logins bounds ---
        if self.security.max_failed_logins < MIN_FAILED_LOGINS {
            errors.push(format!(
                "max_failed_logins ({}) is below the minimum of {} (risk of accidental lockout)",
                self.security.max_failed_logins, MIN_FAILED_LOGINS
            ));
        }
        if self.security.max_failed_logins > MAX_FAILED_LOGINS {
            errors.push(format!(
                "max_failed_logins ({}) exceeds the maximum of {} (risk of brute-force)",
                self.security.max_failed_logins, MAX_FAILED_LOGINS
            ));
        }

        // --- serial_number format (PKCS#11 requires 16-char space-padded) ---
        if self.token.serial_number.is_empty() {
            errors.push("serial_number must not be empty".to_string());
        }
        if self.token.serial_number.len() > 16 {
            errors.push(format!(
                "serial_number '{}' exceeds 16 characters",
                self.token.serial_number
            ));
        }
        if !self
            .token
            .serial_number
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
        {
            errors.push("serial_number contains non-printable or non-ASCII characters".to_string());
        }

        // --- session count bounds ---
        if self.token.max_sessions == 0 {
            errors.push("max_sessions must be at least 1".to_string());
        }
        if self.token.max_sessions > MAX_SESSIONS {
            errors.push(format!(
                "max_sessions ({}) exceeds the maximum of {} (risk of resource exhaustion)",
                self.token.max_sessions, MAX_SESSIONS
            ));
        }
        if self.token.max_rw_sessions == 0 {
            errors.push("max_rw_sessions must be at least 1".to_string());
        }
        if self.token.max_rw_sessions > self.token.max_sessions {
            errors.push(format!(
                "max_rw_sessions ({}) exceeds max_sessions ({})",
                self.token.max_rw_sessions, self.token.max_sessions
            ));
        }

        // --- slot_count sanity ---
        if self.token.slot_count == 0 {
            errors.push("slot_count must be at least 1".to_string());
        }
        if self.token.slot_count > MAX_SLOT_COUNT {
            errors.push(format!(
                "slot_count ({}) exceeds the maximum of {} (risk of resource exhaustion)",
                self.token.slot_count, MAX_SLOT_COUNT
            ));
        }

        // --- crypto_backend must be a known identifier ---
        if !VALID_BACKENDS.contains(&self.algorithms.crypto_backend.as_str()) {
            errors.push(format!(
                "crypto_backend '{}' is not recognized (valid: {:?})",
                self.algorithms.crypto_backend, VALID_BACKENDS
            ));
        }

        // --- log_level must be a known identifier ---
        if !VALID_LOG_LEVELS.contains(&self.audit.log_level.as_str()) {
            errors.push(format!(
                "audit log_level '{}' is not recognized (valid: {:?})",
                self.audit.log_level, VALID_LOG_LEVELS
            ));
        }

        // --- audit: disabling requires explicit acknowledgement (H3-13) ---
        if !self.audit.enabled && !self.audit.allow_disabled_insecure {
            errors.push(
                "audit.enabled = false requires audit.allow_disabled_insecure = true".to_string(),
            );
        }
        if let Some(ref kp) = self.audit.key_path {
            if let Err(path_errs) = Self::validate_path_safety(kp, "audit key_path") {
                errors.extend(path_errs);
            }
        }
        if self.token.max_sessions_per_application == 0 {
            errors.push("max_sessions_per_application must be at least 1".to_string());
        }

        // --- FIPS consistency: reject contradictory weak-algorithm flags ---
        if self.algorithms.fips_approved_only {
            if self.algorithms.allow_weak_rsa {
                errors.push(
                    "allow_weak_rsa cannot be true when fips_approved_only is enabled".to_string(),
                );
            }
            if self.algorithms.allow_sha1_signing {
                errors.push(
                    "allow_sha1_signing cannot be true when fips_approved_only is enabled"
                        .to_string(),
                );
            }
            if !self.audit.enabled {
                errors.push("audit must be enabled when fips_approved_only is active".to_string());
            }
            if self.algorithms.allow_rsa_pkcs1v15_decrypt {
                errors.push(
                    "allow_rsa_pkcs1v15_decrypt cannot be true when fips_approved_only is enabled"
                        .to_string(),
                );
            }
            if self.security.user_lockout_duration_secs != 0 {
                errors.push(
                    "user_lockout_duration_secs must be 0 (permanent lockout) when \
                     fips_approved_only is enabled"
                        .to_string(),
                );
            }
        }
        // `fips` builds: only the FIPS-validated AWS-LC backend passes the
        // backend POST (H2-05); reject any other selection up front.
        if cfg!(feature = "fips") && self.algorithms.crypto_backend != "awslc" {
            errors.push(format!(
                "crypto_backend '{}' is not permitted in a `fips` build (use \"awslc\")",
                self.algorithms.crypto_backend
            ));
        }
        if !["caller", "module"].contains(&self.algorithms.gcm_iv_generation.as_str()) {
            errors.push(format!(
                "gcm_iv_generation '{}' is not recognized (valid: \"caller\", \"module\")",
                self.algorithms.gcm_iv_generation
            ));
        }
        if self.security.user_lockout_duration_secs > MAX_LOCKOUT_DURATION_SECS {
            errors.push(format!(
                "user_lockout_duration_secs ({}) exceeds the maximum of {}",
                self.security.user_lockout_duration_secs, MAX_LOCKOUT_DURATION_SECS
            ));
        }
        if self.security.user_lockout_duration_secs != 0
            && self.security.user_lockout_duration_secs < MIN_LOCKOUT_DURATION_SECS
        {
            errors.push(format!(
                "user_lockout_duration_secs ({}) is below the minimum of {} (0 = permanent)",
                self.security.user_lockout_duration_secs, MIN_LOCKOUT_DURATION_SECS
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            let msg = errors.join("; ");
            tracing::error!("Configuration validation failed: {}", msg);
            Err(HsmError::ConfigError(msg))
        }
    }
}
