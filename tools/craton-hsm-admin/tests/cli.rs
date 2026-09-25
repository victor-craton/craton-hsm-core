// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! End-to-end tests of the admin CLI binary, focused on negative paths.
//! No test reaches a PIN prompt: stdin is closed and every case must fail
//! (or succeed) before any secret is requested.

use craton_hsm::audit::log::{AuditLog, AuditOperation, AuditResult};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const EXIT_USAGE: i32 = 2;
const EXIT_CONFIG: i32 = 3;
const EXIT_REFUSED: i32 = 5;
const EXIT_INTEGRITY: i32 = 6;
const EXIT_IO: i32 = 7;

struct Env {
    dir: tempfile::TempDir,
    config: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("craton_hsm.toml");
        std::fs::write(
            &config,
            "[token]\nstorage_path = \"store\"\n[audit]\nlog_path = \"audit.jsonl\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::create_dir(dir.path().join("store")).unwrap();
        Env { dir, config }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join(p)
    }

    fn run(&self, args: &[&str]) -> Output {
        run_in(
            self.dir.path(),
            &[&["--config", self.config.to_str().unwrap()], args].concat(),
        )
    }
}

fn run_in(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_craton-hsm-admin"))
        .args(args)
        .current_dir(cwd)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn write_audit_log(path: &Path, n: u64) {
    let log = AuditLog::new_with_path(path.to_path_buf()).unwrap();
    for i in 0..n {
        log.record(i, AuditOperation::Logout, AuditResult::Success, None)
            .unwrap();
    }
    log.flush();
}

#[test]
fn missing_config_fails_without_fallback() {
    let env = Env::new();
    let o = run_in(
        env.dir.path(),
        &[
            "--config",
            env.path("nope.toml").to_str().unwrap(),
            "status",
        ],
    );
    assert_eq!(code(&o), EXIT_CONFIG, "{}", stderr(&o));
}

#[test]
fn default_config_is_absolute_and_never_cwd() {
    let env = Env::new();
    // A craton_hsm.toml in the working directory must not be picked up.
    let o = run_in(env.dir.path(), &["--help"]);
    let help = String::from_utf8_lossy(&o.stdout);
    assert!(help.contains("/etc/craton_hsm/craton_hsm.toml") || cfg!(windows));
    if !Path::new("/etc/craton_hsm/craton_hsm.toml").exists() {
        let o = run_in(env.dir.path(), &["status"]);
        assert_eq!(code(&o), EXIT_CONFIG, "{}", stderr(&o));
    }
}

#[cfg(unix)]
#[test]
fn insecure_config_permissions_are_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    std::fs::set_permissions(&env.config, std::fs::Permissions::from_mode(0o666)).unwrap();
    let o = env.run(&["status"]);
    assert_eq!(code(&o), EXIT_CONFIG, "{}", stderr(&o));
}

#[test]
fn token_init_refused_and_lockout_state_untouched() {
    let env = Env::new();
    let lockout = env.path("store/lockout_state.json");
    let original = br#"{"failed_user_logins":7,"failed_so_logins":9,"user_pin_locked":true,"so_pin_locked":true}"#;
    std::fs::write(&lockout, original).unwrap();

    let o = env.run(&["token", "init", "--label", "Victim"]);
    assert_eq!(code(&o), EXIT_REFUSED, "{}", stderr(&o));
    assert!(stderr(&o).contains("standalone mode"));
    // H5-01 regression: the persisted lockout state must survive.
    assert_eq!(std::fs::read(&lockout).unwrap(), original);

    let o = env.run(&["--yes", "token", "init", "--label", "Victim"]);
    assert_eq!(code(&o), EXIT_REFUSED);
    assert_eq!(std::fs::read(&lockout).unwrap(), original);
}

#[test]
fn token_init_rejects_control_characters_in_label() {
    let env = Env::new();
    let o = env.run(&["token", "init", "--label", "bad\x1b[2Jlabel"]);
    assert_eq!(code(&o), EXIT_USAGE, "{}", stderr(&o));
    let o = env.run(&["token", "init", "--label", &"x".repeat(33)]);
    assert_eq!(code(&o), EXIT_USAGE);
}

#[test]
fn backup_refused_and_writes_nothing() {
    let env = Env::new();
    let out = env.path("backup.rhbk");
    let o = env.run(&["backup", "--output", out.to_str().unwrap()]);
    assert_eq!(code(&o), EXIT_REFUSED, "{}", stderr(&o));
    assert!(!out.exists());
}

#[test]
fn restore_refused_and_replay_guard_not_created() {
    let env = Env::new();
    let input = env.path("in.rhbk");
    std::fs::write(&input, b"RHBK-not-really").unwrap();
    let o = env.run(&["restore", "--input", input.to_str().unwrap()]);
    assert_eq!(code(&o), EXIT_REFUSED, "{}", stderr(&o));
    assert!(!env.path("store/.craton_hsm_replay_guard").exists());
    assert!(!env.path(".craton_hsm_replay_guard").exists());
}

#[test]
fn restore_missing_or_special_input_is_io_error() {
    let env = Env::new();
    let o = env.run(&["restore", "--input", env.path("missing").to_str().unwrap()]);
    assert_eq!(code(&o), EXIT_IO, "{}", stderr(&o));
    let o = env.run(&["restore", "--input", env.dir.path().to_str().unwrap()]);
    assert_eq!(code(&o), EXIT_IO, "{}", stderr(&o));
}

#[test]
fn key_and_pin_mutations_are_refused() {
    let env = Env::new();
    let key = env.path("aes.key");
    std::fs::write(&key, [7u8; 32]).unwrap();
    let key = key.to_str().unwrap();
    for args in [
        vec!["key", "list"],
        vec![
            "key", "import", "--file", key, "--label", "k", "--type", "aes",
        ],
        vec!["key", "delete", "--handle", "5", "--role", "user"],
        vec!["pin", "change"],
        vec!["pin", "change", "--user-type", "so"],
        vec!["pin", "reset"],
        vec!["audit", "export-json"],
        vec!["audit", "export-ndjson"],
        vec!["audit", "export-syslog"],
        vec!["audit", "dump"],
    ] {
        let o = env.run(&args);
        assert_eq!(code(&o), EXIT_REFUSED, "{args:?}: {}", stderr(&o));
        assert!(o.stdout.is_empty(), "{args:?} produced output");
    }
}

#[test]
fn usage_errors() {
    let env = Env::new();
    for args in [
        vec!["key", "delete", "--handle", "0", "--role", "user"],
        vec![
            "key", "import", "--file", "x", "--label", "k", "--type", "rsa",
        ],
        vec!["key", "delete", "--handle", "5"],
        vec!["audit", "dump", "--last", "0"],
        vec!["pin", "change", "--user-type", "root"],
    ] {
        let o = env.run(&args);
        assert_eq!(code(&o), EXIT_USAGE, "{args:?}: {}", stderr(&o));
    }
}

#[test]
fn audit_verify_chain_reads_persisted_log() {
    let env = Env::new();
    let log = env.path("audit.jsonl");

    // Missing log is not "valid".
    let o = env.run(&["audit", "verify-chain"]);
    assert_eq!(code(&o), EXIT_INTEGRITY, "{}", stderr(&o));

    write_audit_log(&log, 4);
    let o = env.run(&["--json", "audit", "verify-chain"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["status"], "valid");
    assert_eq!(v["entries_verified"], 4);

    // H5-03 regression: tampering must be reported with a non-zero exit.
    let text = std::fs::read_to_string(&log).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    lines[1] = lines[1].replace("\"session_handle\":1", "\"session_handle\":9");
    std::fs::write(&log, lines.join("\n")).unwrap();
    let o = env.run(&["--json", "audit", "verify-chain"]);
    assert_eq!(code(&o), EXIT_INTEGRITY, "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["status"], "broken");
}

#[test]
fn status_reports_ephemeral_state_and_tamper() {
    let env = Env::new();
    let o = env.run(&["--json", "status"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["state_source"], "ephemeral");

    let log = env.path("audit.jsonl");
    write_audit_log(&log, 3);
    let text = std::fs::read_to_string(&log).unwrap();
    std::fs::write(&log, text.replacen("Logout", "Initialize", 1)).unwrap();
    let o = env.run(&["status"]);
    assert_eq!(code(&o), EXIT_INTEGRITY, "{}", stderr(&o));
    // The core's tamper warning is now visible on stderr (H5-09).
    assert!(
        stderr(&o).to_lowercase().contains("tamper"),
        "{}",
        stderr(&o)
    );
}
