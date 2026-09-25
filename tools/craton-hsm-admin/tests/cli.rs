// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! End-to-end tests of the admin CLI binary.
//!
//! Negative paths run with stdin closed: every case must fail (or succeed)
//! before any secret is requested. Persistence round trips use a persistent
//! token (`token.persist_objects = true`) and feed PINs/passphrases through
//! `--secrets-from-stdin` (never argv/env).

use craton_hsm::audit::log::{AuditLog, AuditOperation, AuditResult};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const EXIT_USAGE: i32 = 2;
const EXIT_AUTH: i32 = 4;
const EXIT_BACKUP_REJECTED: i32 = 9;
const EXIT_CONFIG: i32 = 3;
const EXIT_REFUSED: i32 = 5;
const EXIT_INTEGRITY: i32 = 6;
const EXIT_IO: i32 = 7;

struct Env {
    dir: tempfile::TempDir,
    config: PathBuf,
}

const SO_PIN: &str = "Adm1n-So#4821";
const USER_PIN: &str = "Us3r-Adm#7390";
const PASSPHRASE: &str = "Backup-Passphrase-2026!";

impl Env {
    /// Ephemeral token (`persist_objects = false`).
    fn new() -> Self {
        Self::with_config(
            "[token]\nstorage_path = \"store\"\n[audit]\nlog_path = \"audit.jsonl\"\n",
        )
    }

    /// Persistent token with a fast (but valid) PBKDF2 work factor.
    fn persistent() -> Self {
        Self::with_config(
            "[token]\nstorage_path = \"store\"\npersist_objects = true\n\
             [security]\npbkdf2_iterations = 100000\n\
             [audit]\nlog_path = \"audit.jsonl\"\n",
        )
    }

    fn with_config(body: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("craton_hsm.toml");
        std::fs::write(&config, body).unwrap();
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

    /// Run with `--yes --secrets-from-stdin`, feeding `secrets` (one per line).
    fn run_secrets(&self, secrets: &[&str], args: &[&str]) -> Output {
        use std::io::Write;
        let mut child = Command::new(env!("CARGO_BIN_EXE_craton-hsm-admin"))
            .args(["--config", self.config.to_str().unwrap()])
            .args(["--yes", "--secrets-from-stdin"])
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("RUST_LOG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        {
            let mut stdin = child.stdin.take().unwrap();
            for s in secrets {
                writeln!(stdin, "{s}").unwrap();
            }
        }
        child.wait_with_output().unwrap()
    }

    /// Initialise the token and the User PIN.
    fn provision(&self) {
        let o = self.run_secrets(&[SO_PIN, SO_PIN], &["token", "init", "--label", "CliTest"]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        let o = self.run_secrets(&[SO_PIN, USER_PIN, USER_PIN], &["pin", "reset"]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
    }

    fn list_keys(&self) -> Vec<serde_json::Value> {
        let o = self.run_secrets(&[USER_PIN], &["--json", "key", "list"]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        serde_json::from_slice::<Vec<serde_json::Value>>(&o.stdout).unwrap()
    }

    fn import_key(&self, label: &str) -> u64 {
        let key = self.path(&format!("{label}.key"));
        std::fs::write(&key, [0x5a; 32]).unwrap();
        let o = self.run_secrets(
            &[USER_PIN],
            &[
                "key",
                "import",
                "--file",
                key.to_str().unwrap(),
                "--label",
                label,
                "--type",
                "aes",
            ],
        );
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        let keys = self.list_keys();
        keys.iter()
            .find(|k| k["label"] == label)
            .and_then(|k| k["handle"].as_u64())
            .expect("imported key listed")
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
fn token_init_refused_for_ephemeral_token() {
    let env = Env::new();
    let o = env.run(&["token", "init", "--label", "Victim"]);
    assert_eq!(code(&o), EXIT_REFUSED, "{}", stderr(&o));
    assert!(stderr(&o).contains("ephemeral"), "{}", stderr(&o));
    let o = env.run(&["--yes", "token", "init", "--label", "Victim"]);
    assert_eq!(code(&o), EXIT_REFUSED);
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
fn restore_refused_for_ephemeral_token() {
    let env = Env::new();
    let input = env.path("in.rhbk");
    std::fs::write(&input, b"RHBK-not-really").unwrap();
    let o = env.run(&["restore", "--input", input.to_str().unwrap()]);
    assert_eq!(code(&o), EXIT_REFUSED, "{}", stderr(&o));
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
fn key_and_pin_mutations_are_refused_for_ephemeral_token() {
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

// ── Persistent token: real round trips (H5-02) ─────────────────────────────

#[test]
fn init_then_login_state_persists() {
    let env = Env::persistent();
    let o = env.run(&["--json", "status"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["state_source"], "persistent");
    assert_eq!(v["token_initialized"], false);

    // A weak new SO PIN is rejected by the core PIN policy before anything
    // is written.
    let o = env.run_secrets(
        &["sopin123", "sopin123"],
        &["token", "init", "--label", "T"],
    );
    assert_eq!(code(&o), EXIT_USAGE, "{}", stderr(&o));

    env.provision();
    let o = env.run(&["--json", "status"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["token_initialized"], true, "initialisation must persist");
    assert!(env.list_keys().is_empty());

    // Wrong User PIN: authentication error (and no output).
    let o = env.run_secrets(
        &["Wrong-Pin#000", "Wrong-Pin#001", "Wrong-Pin#002"],
        &["key", "list"],
    );
    assert_eq!(code(&o), EXIT_AUTH, "{}", stderr(&o));
    // The right PIN still works (3 failures < 5 lockout threshold, but the
    // failures were counted persistently: one more good login resets them).
    assert!(env.list_keys().is_empty());

    // PIN change round trip.
    let new_pin = "N3w-User#5512";
    let o = env.run_secrets(&[USER_PIN, new_pin, new_pin], &["pin", "change"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = env.run_secrets(&[new_pin], &["--json", "key", "list"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
}

#[test]
fn key_import_list_delete_round_trip() {
    let env = Env::persistent();
    env.provision();
    let h = env.import_key("aes-one");
    let keys = env.list_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["sensitive"], true);
    assert_eq!(keys[0]["extractable"], false);
    // The SO does not see private (user) objects.
    let o = env.run_secrets(&[SO_PIN], &["--json", "key", "list", "--role", "so"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let so_view: Vec<serde_json::Value> = serde_json::from_slice(&o.stdout).unwrap();
    assert!(so_view.is_empty());
    // Private objects can only be deleted by the User.
    let hs = h.to_string();
    let o = env.run_secrets(
        &[SO_PIN],
        &["key", "delete", "--handle", &hs, "--role", "so"],
    );
    assert_eq!(code(&o), EXIT_REFUSED, "{}", stderr(&o));
    let o = env.run_secrets(
        &[USER_PIN],
        &["key", "delete", "--handle", &hs, "--role", "user"],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(env.list_keys().is_empty());
}

#[test]
fn backup_restore_round_trip_and_replay() {
    let env = Env::persistent();
    env.provision();
    let h = env.import_key("aes-backup");
    let out = env.path("token.rhbk");
    let outs = out.to_str().unwrap();

    // Non-extractable keys are not exported by default (A1-17).
    let o = env.run_secrets(&[SO_PIN], &["backup", "--output", outs]);
    assert_eq!(code(&o), EXIT_REFUSED, "{}", stderr(&o));
    assert!(!out.exists());

    let o = env.run_secrets(
        &[SO_PIN, PASSPHRASE, PASSPHRASE],
        &["backup", "--output", outs, "--include-non-extractable"],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "backup must be private");
    }

    // Verify-only does not consume the backup.
    let o = env.run_secrets(
        &[SO_PIN, PASSPHRASE],
        &["restore", "--input", outs, "--verify-only"],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));

    let hs = h.to_string();
    let o = env.run_secrets(
        &[USER_PIN],
        &["key", "delete", "--handle", &hs, "--role", "user"],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(env.list_keys().is_empty());

    // Wrong passphrase: rejected, nothing restored, backup not consumed.
    let o = env.run_secrets(
        &[SO_PIN, "Wrong-Passphrase-2026!"],
        &["restore", "--input", outs],
    );
    assert_eq!(code(&o), EXIT_BACKUP_REJECTED, "{}", stderr(&o));
    assert!(env.list_keys().is_empty());

    let o = env.run_secrets(&[SO_PIN, PASSPHRASE], &["restore", "--input", outs]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let keys = env.list_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["label"], "aes-backup");
    assert_ne!(
        keys[0]["handle"].as_u64(),
        Some(h),
        "fresh handle on restore"
    );

    // Replay of the same backup is rejected (H5-04/H5-06), with a distinct reason.
    let o = env.run_secrets(&[SO_PIN, PASSPHRASE], &["restore", "--input", outs]);
    assert_eq!(code(&o), EXIT_BACKUP_REJECTED, "{}", stderr(&o));
    assert!(stderr(&o).contains("already restored"), "{}", stderr(&o));
    assert_eq!(env.list_keys().len(), 1);

    // Every administrative action is in a valid chain, including the new
    // backup event types (H5-20).
    let o = env.run(&["audit", "verify-chain"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = env.run_secrets(&[SO_PIN], &["audit", "export-ndjson"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.contains("BackupExport"), "{text}");
    assert!(text.contains("BackupRestore"), "{text}");
    assert!(text.contains("craton-hsm-admin:restore"), "{text}");
}

#[test]
fn reinit_requires_so_pin_and_keeps_objects_on_failure() {
    let env = Env::persistent();
    env.provision();
    env.import_key("keep-me");
    let o = env.run_secrets(&["Wrong-So#99887"], &["token", "init", "--label", "Again"]);
    assert_eq!(code(&o), EXIT_AUTH, "{}", stderr(&o));
    assert_eq!(
        env.list_keys().len(),
        1,
        "a wrong SO PIN must not wipe objects"
    );
    let o = env.run_secrets(&[SO_PIN], &["token", "init", "--label", "Again"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = env.run(&["--json", "token", "info"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["user_pin_initialized"], false);
}

#[test]
fn store_locked_by_another_process_is_a_clear_error() {
    let env = Env::persistent();
    // Hold the single-writer locks like a running daemon would.
    let text = std::fs::read_to_string(&env.config).unwrap();
    let mut cfg: craton_hsm::config::HsmConfig = toml::from_str(&text).unwrap();
    cfg.token.storage_path = env.path("store");
    cfg.audit.log_path = env.path("audit.jsonl");
    let hsm = craton_hsm::core::HsmCore::open(&cfg).unwrap();
    let o = env.run(&["status"]);
    assert_eq!(code(&o), EXIT_REFUSED, "{}", stderr(&o));
    assert!(stderr(&o).contains("locked"), "{}", stderr(&o));
    drop(hsm);
    let o = env.run(&["status"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
}
