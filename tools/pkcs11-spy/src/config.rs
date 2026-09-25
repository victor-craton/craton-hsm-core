// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Spy configuration, read once from the environment.
//!
//! | Variable | Meaning |
//! |---|---|
//! | `PKCS11_SPY_TARGET` | Absolute path of the real PKCS#11 module (required). |
//! | `PKCS11_SPY_LOG` | Log file path; `-` or `stderr` for stderr; `off` (or empty) to disable. Unset = disabled (with a one-time warning). |
//! | `PKCS11_SPY_REDUCED_TIMING` | Default on: millisecond timestamps/durations. `0`/`false`/`no`/`off` = microsecond precision (debugging opt-in). |
//!
//! SECURITY (H6-02): when the process runs in secure-execution mode
//! (setuid/setgid/file capabilities: `getauxval(AT_SECURE)` on Linux,
//! `issetugid()` on the BSDs/macOS, or real != effective IDs), **every**
//! `PKCS11_SPY_*` variable is ignored: no target is loaded (all calls fail
//! with `CKR_GENERAL_ERROR`) and nothing is written to a file. Whoever controls
//! a privileged program's environment must not be able to choose the code it
//! `dlopen`s or a file it appends to. The spy is a development tool and must
//! not be configured for privileged or production processes.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;

pub const ENV_TARGET: &str = "PKCS11_SPY_TARGET";
pub const ENV_LOG: &str = "PKCS11_SPY_LOG";
pub const ENV_REDUCED_TIMING: &str = "PKCS11_SPY_REDUCED_TIMING";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogDest {
    /// No logging. `warn` = print a one-time hint on stderr.
    Disabled {
        warn: Option<&'static str>,
    },
    /// Explicit opt-in via `PKCS11_SPY_LOG=-` / `stderr`.
    Stderr,
    File(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Raw target path, or the reason no target may be loaded.
    pub target: Result<PathBuf, &'static str>,
    pub log: LogDest,
    pub reduced_timing: bool,
    pub secure_execution: bool,
}

impl Config {
    /// Build the configuration from an environment lookup. Pure, for testing.
    pub fn from_env(secure_execution: bool, get: impl Fn(&str) -> Option<OsString>) -> Self {
        if secure_execution {
            return Config {
                target: Err("secure-execution mode (setuid/setgid/capabilities): \
                             PKCS11_SPY_* ignored, refusing to load a target module"),
                log: LogDest::Disabled {
                    warn: Some("secure-execution mode: PKCS11_SPY_* ignored, logging disabled"),
                },
                reduced_timing: true,
                secure_execution: true,
            };
        }

        let target = match get(ENV_TARGET) {
            Some(v) if !v.is_empty() => Ok(PathBuf::from(v)),
            _ => Err("PKCS11_SPY_TARGET is not set"),
        };

        let log = match get(ENV_LOG) {
            None => LogDest::Disabled {
                warn: Some(
                    "PKCS11_SPY_LOG is not set; call logging disabled \
                     (set PKCS11_SPY_LOG=<path>, or '-' for stderr)",
                ),
            },
            Some(v) => match v.to_str() {
                Some("") | Some("off") => LogDest::Disabled { warn: None },
                Some("-") | Some("stderr") => LogDest::Stderr,
                _ => LogDest::File(PathBuf::from(v)),
            },
        };

        let reduced_timing = match get(ENV_REDUCED_TIMING) {
            None => true,
            Some(v) => !matches!(
                v.to_str().map(|s| s.to_ascii_lowercase()).as_deref(),
                Some("0") | Some("false") | Some("no") | Some("off")
            ),
        };

        Config {
            target,
            log,
            reduced_timing,
            secure_execution: false,
        }
    }
}

/// The process-wide configuration (read once).
pub fn get() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(|| Config::from_env(secure_execution(), |k| std::env::var_os(k)))
}

/// True when the process runs with elevated privileges relative to its invoker.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn secure_execution() -> bool {
    // SAFETY: getauxval/getuid/geteuid/getgid/getegid have no preconditions.
    unsafe {
        libc::getauxval(libc::AT_SECURE) != 0
            || libc::getuid() != libc::geteuid()
            || libc::getgid() != libc::getegid()
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub fn secure_execution() -> bool {
    // SAFETY: issetugid/getuid/geteuid/getgid/getegid have no preconditions.
    unsafe {
        libc::issetugid() != 0
            || libc::getuid() != libc::geteuid()
            || libc::getgid() != libc::getegid()
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
))]
pub fn secure_execution() -> bool {
    // SAFETY: getuid/geteuid/getgid/getegid have no preconditions.
    unsafe { libc::getuid() != libc::geteuid() || libc::getgid() != libc::getegid() }
}

#[cfg(not(unix))]
pub fn secure_execution() -> bool {
    // Windows has no setuid equivalent; elevation is decided at process start
    // by the user who launches it.
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let m: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(v)))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn secure_execution_ignores_all_spy_variables() {
        let c = Config::from_env(
            true,
            env(&[
                (ENV_TARGET, "/tmp/evil.so"),
                (ENV_LOG, "/etc/shadow"),
                (ENV_REDUCED_TIMING, "0"),
            ]),
        );
        assert!(c.target.is_err());
        assert!(matches!(c.log, LogDest::Disabled { .. }));
        assert!(c.reduced_timing);
        assert!(c.secure_execution);
    }

    #[test]
    fn defaults_are_safe() {
        let c = Config::from_env(false, env(&[]));
        assert!(c.target.is_err());
        assert!(matches!(c.log, LogDest::Disabled { warn: Some(_) }));
        assert!(
            c.reduced_timing,
            "millisecond timing is the default (H6-09)"
        );
    }

    #[test]
    fn stderr_is_explicit_opt_in() {
        let c = Config::from_env(false, env(&[(ENV_LOG, "-")]));
        assert_eq!(c.log, LogDest::Stderr);
        let c = Config::from_env(false, env(&[(ENV_LOG, "stderr")]));
        assert_eq!(c.log, LogDest::Stderr);
        let c = Config::from_env(false, env(&[(ENV_LOG, "off")]));
        assert_eq!(c.log, LogDest::Disabled { warn: None });
        let c = Config::from_env(false, env(&[(ENV_LOG, "spy.jsonl")]));
        assert_eq!(c.log, LogDest::File(PathBuf::from("spy.jsonl")));
    }

    #[test]
    fn full_precision_timing_is_opt_in() {
        for v in ["0", "false", "FALSE", "no", "off"] {
            let c = Config::from_env(false, env(&[(ENV_REDUCED_TIMING, v)]));
            assert!(!c.reduced_timing, "{v}");
        }
        let c = Config::from_env(false, env(&[(ENV_REDUCED_TIMING, "1")]));
        assert!(c.reduced_timing);
    }

    #[test]
    fn this_test_process_is_not_secure_execution() {
        // Sanity check of the platform probe (tests do not run setuid).
        assert!(!secure_execution());
    }
}
