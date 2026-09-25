// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! JSON-lines logger for PKCS#11 spy calls.
//!
//! Record schema (one JSON object per line):
//!
//! ```text
//! {"ts":0.012,"seq":3,"pid":4242,"tid":1,"fn":"C_Sign","event":"call","args":{"session":1,"data_len":32}}
//! {"ts":0.014,"seq":4,"pid":4242,"tid":1,"fn":"C_Sign","event":"return","rv":"CKR_OK","rv_code":"0x00000000","duration_ms":2}
//! {"ts":0.015,"seq":5,"pid":4242,"tid":1,"fn":"C_GetFunctionList","event":"rejected","reason":"...","rv":"CKR_ARGUMENTS_BAD","rv_code":"0x00000007"}
//! {"ts":0.000,"seq":0,"pid":4242,"tid":1,"fn":"pkcs11-spy","event":"start","version":"0.3.0","unix_time":1700000000,"timing":"ms"}
//! {"ts":0.001,"seq":1,"pid":4242,"tid":1,"fn":"pkcs11-spy","event":"error","msg":"..."}
//! ```
//!
//! * `ts` — seconds since the logger started. Millisecond resolution (3
//!   decimals) by default; microseconds (6 decimals) only with
//!   `PKCS11_SPY_REDUCED_TIMING=0` (H6-09). The same quantisation is applied
//!   to both `call` and `return` records, and durations are `duration_ms`
//!   (reduced) or `duration_us` (full precision).
//! * `seq` — process-wide monotonically increasing record number; `tid` — a
//!   small per-thread number; together with `pid` they pair `call`/`return`
//!   records in multi-threaded and multi-process logs.
//!
//! I/O model (H6-10): each record is formatted into a thread-local buffer
//! *without any lock held* and then written with a single `write(2)` on an
//! `O_APPEND` descriptor, so records from concurrent threads and processes do
//! not interleave, no global lock serialises PKCS#11 calls, and a `fork()`
//! cannot inherit a held logger lock.

use crate::ckr::ckr_name;
use crate::config::{self, LogDest};
use crate::types::CK_RV;
use std::cell::RefCell;
use std::fmt::Write as _;
use std::fs::File;
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

enum Sink {
    Disabled,
    Stderr,
    File(File),
}

impl Sink {
    fn write(&self, bytes: &[u8]) {
        // Errors (ENOSPC, EPIPE, ...) are deliberately ignored: logging must
        // never change the result the application sees.
        match self {
            Sink::Disabled => {}
            Sink::Stderr => {
                let _ = std::io::stderr().lock().write_all(bytes);
            }
            Sink::File(f) => {
                let _ = (&*f).write_all(bytes);
            }
        }
    }
}

struct Logger {
    sink: Sink,
    start: Instant,
    reduced_timing: bool,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();
static SEQ: AtomicU64 = AtomicU64::new(0);
static NEXT_TID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static TID: u64 = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    static BUF: RefCell<String> = RefCell::new(String::with_capacity(256));
}

fn logger() -> &'static Logger {
    LOGGER.get_or_init(Logger::from_config)
}

/// Whether records are written at all. Callers skip argument formatting
/// entirely when this is false (`PKCS11_SPY_LOG=off` fast path).
pub fn enabled() -> bool {
    !matches!(logger().sink, Sink::Disabled)
}

impl Logger {
    fn from_config() -> Logger {
        let cfg = config::get();
        let sink = match &cfg.log {
            LogDest::Disabled { warn } => {
                if let Some(w) = warn {
                    eprintln!("pkcs11-spy: {w}");
                }
                Sink::Disabled
            }
            LogDest::Stderr => Sink::Stderr,
            LogDest::File(path) => match open_log_file(path) {
                Ok(f) => Sink::File(f),
                Err(e) => {
                    // H6-08: never silently redirect the log to a wider
                    // audience (stderr); disable logging instead.
                    eprintln!("pkcs11-spy: cannot use PKCS11_SPY_LOG ({e}); logging disabled");
                    Sink::Disabled
                }
            },
        };
        let lg = Logger {
            sink,
            start: Instant::now(),
            reduced_timing: cfg.reduced_timing,
        };
        let unix_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        lg.emit(lg.start, "pkcs11-spy", "start", |b| {
            let _ = write!(
                b,
                ",\"version\":\"{}\",\"unix_time\":{},\"timing\":\"{}\"",
                env!("CARGO_PKG_VERSION"),
                unix_time,
                if lg.reduced_timing { "ms" } else { "us" }
            );
        });
        lg
    }

    fn write_ts(&self, b: &mut String, d: Duration) {
        if self.reduced_timing {
            let _ = write!(b, "{}.{:03}", d.as_secs(), d.subsec_millis());
        } else {
            let _ = write!(b, "{}.{:06}", d.as_secs(), d.subsec_micros());
        }
    }

    /// Format one record into the thread-local buffer and write it with one call.
    fn emit(&self, at: Instant, func: &str, event: &str, body: impl FnOnce(&mut String)) {
        if matches!(self.sink, Sink::Disabled) {
            return;
        }
        let build = |b: &mut String| {
            b.clear();
            b.push_str("{\"ts\":");
            self.write_ts(b, at.saturating_duration_since(self.start));
            let tid = TID.try_with(|t| *t).unwrap_or(0);
            let _ = write!(
                b,
                ",\"seq\":{},\"pid\":{},\"tid\":{},\"fn\":\"{}\",\"event\":\"{}\"",
                SEQ.fetch_add(1, Ordering::Relaxed),
                std::process::id(),
                tid,
                func,
                event
            );
            body(b);
            b.push_str("}\n");
            self.sink.write(b.as_bytes());
        };
        let mut build = Some(build);
        let _ = BUF.try_with(|cell| {
            if let Ok(mut b) = cell.try_borrow_mut() {
                if let Some(f) = build.take() {
                    f(&mut b);
                }
            }
        });
        // Re-entrant use or TLS teardown: fall back to a fresh buffer.
        if let Some(f) = build {
            f(&mut String::new());
        }
    }
}

/// Log a function call entry. `args` writes a JSON object (`{...}`).
pub fn log_call(func: &'static str, at: Instant, args: impl FnOnce(&mut String)) {
    logger().emit(at, func, "call", |b| {
        b.push_str(",\"args\":");
        args(b);
    });
}

/// Log a function return. Timestamp and duration come from the two readings
/// taken around the forwarded call.
pub fn log_return(func: &'static str, rv: CK_RV, begin: Instant, end: Instant) {
    let lg = logger();
    let d = end.saturating_duration_since(begin);
    lg.emit(end, func, "return", |b| {
        let rv = crate::ckr::widen(rv);
        let _ = write!(
            b,
            ",\"rv\":\"{}\",\"rv_code\":\"0x{:08x}\"",
            ckr_name(rv),
            rv
        );
        if lg.reduced_timing {
            let _ = write!(b, ",\"duration_ms\":{}", d.as_millis());
        } else {
            let _ = write!(b, ",\"duration_us\":{}", d.as_micros());
        }
    });
}

/// Log a call that the spy answered itself without forwarding it (H6-14).
pub fn log_rejected(func: &'static str, reason: &'static str, rv: CK_RV) {
    logger().emit(Instant::now(), func, "rejected", |b| {
        let rv = crate::ckr::widen(rv);
        b.push_str(",\"reason\":");
        push_json_str(b, reason);
        let _ = write!(
            b,
            ",\"rv\":\"{}\",\"rv_code\":\"0x{:08x}\"",
            ckr_name(rv),
            rv
        );
    });
}

/// Log a spy-internal event (`error`, `warning`) with a free-text message.
pub fn log_event(kind: &'static str, msg: &str) {
    logger().emit(Instant::now(), "pkcs11-spy", kind, |b| {
        b.push_str(",\"msg\":");
        push_json_str(b, msg);
    });
}

/// Whether the sink is stderr (so callers do not print the same message twice).
pub fn is_stderr() -> bool {
    matches!(logger().sink, Sink::Stderr)
}

/// Append `s` as a JSON string literal (CWE-117: every free-text field in a
/// record MUST go through this function).
pub fn push_json_str(b: &mut String, s: &str) {
    b.push('"');
    for c in s.chars() {
        match c {
            '"' => b.push_str("\\\""),
            '\\' => b.push_str("\\\\"),
            '\n' => b.push_str("\\n"),
            '\r' => b.push_str("\\r"),
            '\t' => b.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(b, "\\u{:04x}", c as u32);
            }
            c => b.push(c),
        }
    }
    b.push('"');
}

// ── Log file opening (H6-03 / H6-07 / H6-08) ────────────────────────────────

/// Resolve the directory part of the log path. A bare file name (`spy.jsonl`)
/// has an *empty* parent, which means the current directory (H6-08).
fn split_log_path(path: &Path) -> Result<(&Path, &std::ffi::OsStr), String> {
    let name = path
        .file_name()
        .ok_or_else(|| format!("{} has no file name component", path.display()))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok((parent, name))
}

/// Open (or create) the log file safely:
/// * the parent directory is canonicalised and must be trusted
///   (owner root/euid, not writable by others unless sticky);
/// * the final component is opened with `O_NOFOLLOW` (no symlinks),
///   `O_NONBLOCK` (a FIFO without reader cannot hang the host),
///   `O_CLOEXEC` and mode 0600 *at creation*;
/// * the opened descriptor is `fstat`ed: regular file, owned by the effective
///   UID, exactly one link, no group/other permission bits.
///
/// Any failure disables logging (fail closed); nothing is `chmod`ed by path.
#[cfg(unix)]
pub(crate) fn open_log_file(path: &Path) -> Result<File, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let (parent, name) = split_log_path(path)?;
    let dir = std::fs::canonicalize(parent)
        .map_err(|e| format!("cannot resolve log directory {}: {e}", parent.display()))?;
    let dm = std::fs::metadata(&dir).map_err(|e| format!("cannot stat {}: {e}", dir.display()))?;
    crate::fsutil::check_trusted_dir(&dir, &dm)?;

    let full = dir.join(name);
    let f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&full)
        .map_err(|e| format!("cannot open {}: {e}", full.display()))?;
    let m = f
        .metadata()
        .map_err(|e| format!("cannot fstat {}: {e}", full.display()))?;
    if !m.file_type().is_file() {
        return Err(format!("{} is not a regular file", full.display()));
    }
    if m.uid() != crate::fsutil::euid() {
        return Err(format!(
            "{} is not owned by the effective user",
            full.display()
        ));
    }
    if m.nlink() != 1 {
        return Err(format!("{} has {} hard links", full.display(), m.nlink()));
    }
    if m.mode() & 0o077 != 0 {
        return Err(format!(
            "{} is accessible by group/other (mode {:o}); chmod 600 or remove it",
            full.display(),
            m.mode() & 0o7777
        ));
    }
    Ok(f)
}

/// Windows: refuse reparse points (symlinks/junctions) in the final component,
/// then restrict the DACL to the current user with `icacls`, run by absolute
/// path from the System32 directory (H6-07). If hardening fails the file is
/// not used (fail closed).
#[cfg(windows)]
pub(crate) fn open_log_file(path: &Path) -> Result<File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let (parent, name) = split_log_path(path)?;
    let dir = std::fs::canonicalize(parent)
        .map_err(|e| format!("cannot resolve log directory {}: {e}", parent.display()))?;
    let full = dir.join(name);
    let f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&full)
        .map_err(|e| format!("cannot open {}: {e}", full.display()))?;
    let m = f
        .metadata()
        .map_err(|e| format!("cannot stat {}: {e}", full.display()))?;
    if m.file_type().is_symlink() || !m.file_type().is_file() {
        return Err(format!("{} is not a regular file", full.display()));
    }
    win::restrict_to_current_user(&full)?;
    Ok(f)
}

#[cfg(windows)]
mod win {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemDirectoryW(lpBuffer: *mut u16, uSize: u32) -> u32;
    }

    fn system_dir() -> Result<PathBuf, String> {
        let mut buf = [0u16; 520];
        // SAFETY: the buffer is valid for `buf.len()` UTF-16 units.
        let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n == 0 || n >= buf.len() {
            return Err("GetSystemDirectoryW failed".into());
        }
        Ok(PathBuf::from(OsString::from_wide(&buf[..n])))
    }

    /// Run `whoami` and `icacls` by absolute System32 path (never through the
    /// DLL/EXE search order), check both exit statuses, and report failure so
    /// the caller disables logging instead of keeping an inherited ACL.
    pub fn restrict_to_current_user(file: &Path) -> Result<(), String> {
        let sys = system_dir()?;
        let out = Command::new(sys.join("whoami.exe"))
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("whoami failed: {e}"))?;
        let user = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !out.status.success() || user.is_empty() {
            return Err("whoami returned no user name".into());
        }
        let status = Command::new(sys.join("icacls.exe"))
            .arg(file)
            .args(["/inheritance:r", "/grant:r", &format!("{user}:(R,W)")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .map_err(|e| format!("icacls failed: {e}"))?;
        if !status.success() {
            return Err(format!("icacls exited with {status}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escaping() {
        let mut b = String::new();
        push_json_str(&mut b, "a\"b\\c\nd\u{1}e/é");
        assert_eq!(b, r#""a\"b\\c\nd\u0001e/é""#);
    }

    #[test]
    fn bare_file_name_resolves_to_current_directory() {
        let (parent, name) = split_log_path(Path::new("spy.jsonl")).unwrap();
        assert_eq!(parent, Path::new("."));
        assert_eq!(name, "spy.jsonl");
        let (parent, _) = split_log_path(Path::new("/var/log/spy.jsonl")).unwrap();
        assert_eq!(parent, Path::new("/var/log"));
        assert!(split_log_path(Path::new("..")).is_err());
    }

    #[cfg(unix)]
    mod unix {
        use super::super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        #[test]
        fn creates_file_with_mode_0600() {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("spy.jsonl");
            let f = open_log_file(&p).unwrap();
            assert_eq!(f.metadata().unwrap().mode() & 0o777, 0o600);
            // Reopening our own 0600 file is fine (append).
            drop(f);
            open_log_file(&p).unwrap();
        }

        #[test]
        fn symlink_is_not_followed() {
            let d = tempfile::tempdir().unwrap();
            let victim = d.path().join("victim");
            std::fs::write(&victim, b"keep").unwrap();
            let link = d.path().join("spy.jsonl");
            std::os::unix::fs::symlink(&victim, &link).unwrap();
            assert!(open_log_file(&link).is_err());
            assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        }

        #[test]
        fn existing_group_readable_file_is_rejected() {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("spy.jsonl");
            std::fs::write(&p, b"").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            let e = open_log_file(&p).unwrap_err();
            assert!(e.contains("group/other"), "{e}");
        }

        #[test]
        fn hard_linked_file_is_rejected() {
            let d = tempfile::tempdir().unwrap();
            let a = d.path().join("a");
            std::fs::write(&a, b"").unwrap();
            std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o600)).unwrap();
            let b = d.path().join("spy.jsonl");
            std::fs::hard_link(&a, &b).unwrap();
            assert!(open_log_file(&b).unwrap_err().contains("hard links"));
        }

        #[test]
        fn fifo_is_rejected_without_blocking() {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("spy.jsonl");
            let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
            // SAFETY: valid NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            // With no reader, O_NONBLOCK makes open() fail with ENXIO instead of hanging.
            assert!(open_log_file(&p).is_err());
        }

        #[test]
        fn world_writable_directory_without_sticky_is_rejected() {
            let d = tempfile::tempdir().unwrap();
            let sub = d.path().join("open");
            std::fs::create_dir(&sub).unwrap();
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o777)).unwrap();
            assert!(open_log_file(&sub.join("spy.jsonl")).is_err());
        }
    }
}
