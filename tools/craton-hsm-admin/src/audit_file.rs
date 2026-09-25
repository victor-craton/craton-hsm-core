// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Reading and verifying the persisted audit log (H5-03).
//!
//! The CLI must never report on an empty in-memory log: it reads the NDJSON
//! file named by `audit.log_path` and its rotated generations (`.N` … `.1`,
//! oldest first) and re-verifies the SHA-256 hash chain
//! `H_n = SHA-256(H_{n-1} || serialize(payload_n))` across all of them.
//!
//! The payload serialisation mirrors `craton_hsm::audit::log` (field order
//! `timestamp, session_handle, operation, key_id, result`); a unit test
//! writes a log with the real `AuditLog` and verifies it here so that any
//! drift is caught. HANDOFF: replace with a public core API
//! (`AuditLog::verify_file` / `read_entries`) once available.

use craton_hsm::audit::log::{AuditEvent, AuditOperation, AuditResult};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::BufRead;
use std::path::{Path, PathBuf};

/// Highest rotated generation the core keeps (`log.rs` MAX_ROTATED_FILES).
const MAX_GENERATION: u32 = 5;
/// Upper bound on one NDJSON line; audit events are a few hundred bytes.
const MAX_LINE_BYTES: usize = 64 * 1024;

#[derive(Serialize)]
struct Payload<'a> {
    timestamp: u64,
    session_handle: u64,
    operation: &'a AuditOperation,
    key_id: &'a Option<String>,
    result: &'a AuditResult,
}

/// Outcome of a successful verification.
#[derive(Debug)]
pub struct VerifySummary {
    pub entries: usize,
    pub files: Vec<PathBuf>,
    /// `false` when the oldest available generation does not start at the
    /// genesis hash (older generations were rotated away), so the start of
    /// the chain cannot be anchored.
    pub anchored_at_genesis: bool,
}

/// Why the log could not be verified.
#[derive(Debug)]
pub enum AuditFileError {
    /// The configured log file (and all generations) do not exist.
    Missing(PathBuf),
    /// Chain broken / file corrupted.
    Tampered {
        file: PathBuf,
        line: usize,
        index: usize,
        reason: String,
    },
    Io(PathBuf, std::io::Error),
}

impl std::fmt::Display for AuditFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditFileError::Missing(p) => write!(f, "audit log '{}' does not exist", p.display()),
            AuditFileError::Tampered {
                file,
                line,
                index,
                reason,
            } => write!(
                f,
                "audit chain BROKEN in '{}' at line {line} (entry index {index}): {reason}",
                file.display()
            ),
            AuditFileError::Io(p, e) => write!(f, "cannot read '{}': {e}", p.display()),
        }
    }
}

fn generation_path(base: &Path, generation: u32) -> PathBuf {
    let mut name = base.as_os_str().to_os_string();
    name.push(format!(".{generation}"));
    PathBuf::from(name)
}

/// Existing log files, oldest generation first, current file last.
pub fn log_files(base: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = (1..=MAX_GENERATION)
        .rev()
        .map(|g| generation_path(base, g))
        .filter(|p| std::fs::symlink_metadata(p).is_ok())
        .collect();
    if std::fs::symlink_metadata(base).is_ok() {
        files.push(base.to_path_buf());
    }
    files
}

fn chain_hash(prev: &[u8; 32], ev: &AuditEvent) -> Result<[u8; 32], String> {
    let payload = Payload {
        timestamp: ev.timestamp,
        session_handle: ev.session_handle,
        operation: &ev.operation,
        key_id: &ev.key_id,
        result: &ev.result,
    };
    let bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    h.update(prev);
    h.update(&bytes);
    Ok(h.finalize().into())
}

/// Read one line of at most `MAX_LINE_BYTES`. Returns `Ok(None)` at EOF.
fn read_line(reader: &mut impl BufRead, buf: &mut Vec<u8>) -> std::io::Result<Option<()>> {
    buf.clear();
    let n = std::io::Read::take(&mut *reader, MAX_LINE_BYTES as u64 + 1).read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_LINE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "line exceeds maximum length",
        ));
    }
    Ok(Some(()))
}

/// Walk every entry of the persisted log, verifying the hash chain, and hand
/// each verified entry to `visit`. Stops at the first broken link.
pub fn verify_and_visit(
    base: &Path,
    mut visit: impl FnMut(&AuditEvent) -> std::io::Result<()>,
) -> Result<VerifySummary, AuditFileError> {
    let files = log_files(base);
    if files.is_empty() {
        return Err(AuditFileError::Missing(base.to_path_buf()));
    }

    let mut running: Option<[u8; 32]> = None;
    let mut index = 0usize;
    let mut anchored = true;
    let mut buf = Vec::new();

    for path in &files {
        let file = crate::fsutil::open_regular_nofollow(path)
            .map_err(|e| AuditFileError::Io(path.clone(), e))?;
        let mut reader = std::io::BufReader::new(file);
        let mut line_no = 0usize;
        loop {
            let tampered = |line: usize, index: usize, reason: String| AuditFileError::Tampered {
                file: path.clone(),
                line,
                index,
                reason,
            };
            match read_line(&mut reader, &mut buf) {
                Ok(None) => break,
                Ok(Some(())) => {}
                Err(e) => return Err(tampered(line_no + 1, index, e.to_string())),
            }
            line_no += 1;
            let text = String::from_utf8_lossy(&buf);
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            let ev: AuditEvent = serde_json::from_str(text)
                .map_err(|e| tampered(line_no, index, format!("unparseable entry: {e}")))?;

            let expected = match running {
                Some(h) => h,
                None => {
                    // First entry overall. It must start at the genesis hash
                    // unless it lives in a rotated generation whose
                    // predecessors have been rotated away.
                    let genesis = [0u8; 32];
                    if ev.previous_hash != genesis {
                        if path.as_path() != base {
                            anchored = false;
                            ev.previous_hash
                        } else {
                            genesis
                        }
                    } else {
                        genesis
                    }
                }
            };
            if ev.previous_hash != expected {
                return Err(tampered(
                    line_no,
                    index,
                    "previous_hash does not match the chain".into(),
                ));
            }
            running = Some(chain_hash(&expected, &ev).map_err(|e| tampered(line_no, index, e))?);
            visit(&ev).map_err(|e| AuditFileError::Io(path.clone(), e))?;
            index += 1;
        }
    }

    Ok(VerifySummary {
        entries: index,
        files,
        anchored_at_genesis: anchored,
    })
}

/// Short operation name (serde variant name) without an exhaustive match, so
/// that new core variants do not break the CLI.
pub fn operation_name(op: &AuditOperation) -> String {
    match serde_json::to_value(op) {
        Ok(serde_json::Value::String(s)) => s,
        Ok(serde_json::Value::Object(m)) => m.keys().next().cloned().unwrap_or_default(),
        _ => "Unknown".to_string(),
    }
}

/// RFC 3339 UTC timestamp from a nanosecond UNIX timestamp.
pub fn format_rfc3339(nanos: u64) -> String {
    let secs = nanos / 1_000_000_000;
    let micros = (nanos % 1_000_000_000) / 1000;
    let days = secs / 86_400;
    let tod = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

pub fn result_string(r: &AuditResult) -> String {
    match r {
        AuditResult::Success => "SUCCESS".to_string(),
        AuditResult::Failure(rv) => format!("FAILURE(0x{rv:08X})"),
    }
}

fn escape_sd_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '"' | '\\' | ']') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn sanitize_msg_value(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && *c != '<' && *c != '>')
        .collect()
}

/// RFC 5424 line, same layout as `AuditLog::export_syslog`.
pub fn syslog_line(e: &AuditEvent) -> String {
    let severity = match e.result {
        AuditResult::Success => 6,
        AuditResult::Failure(_) => 4,
    };
    let priority = 10 * 8 + severity;
    let op = operation_name(&e.operation);
    let result = result_string(&e.result);
    let key = e.key_id.as_deref().unwrap_or("-");
    // Control characters are removed from every field, including SD values.
    let key_clean: String = key.chars().filter(|c| !c.is_control()).collect();
    format!(
        "<{priority}>1 {} craton_hsm craton_hsm - - [hsm@0 session=\"{}\" op=\"{}\" result=\"{}\" key=\"{}\"] session={} op={} result={} key={}",
        format_rfc3339(e.timestamp),
        e.session_handle,
        escape_sd_value(&op),
        escape_sd_value(&result),
        escape_sd_value(&key_clean),
        e.session_handle,
        sanitize_msg_value(&op),
        sanitize_msg_value(&result),
        sanitize_msg_value(key),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use craton_hsm::audit::log::AuditLog;

    fn write_real_log(path: &Path, n: usize) {
        let log = AuditLog::new_with_path(path.to_path_buf()).unwrap();
        for i in 0..n {
            log.record(
                i as u64,
                AuditOperation::Login { user_type: 1 },
                if i % 2 == 0 {
                    AuditResult::Success
                } else {
                    AuditResult::Failure(0xA0)
                },
                Some(format!("key-{i}")),
            )
            .unwrap();
        }
        log.flush();
        drop(log);
    }

    #[test]
    fn verifies_log_written_by_core() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        write_real_log(&p, 5);
        let mut seen = 0;
        let s = verify_and_visit(&p, |_| {
            seen += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(s.entries, 5);
        assert_eq!(seen, 5);
        assert!(s.anchored_at_genesis);
    }

    #[test]
    fn detects_modified_entry() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        write_real_log(&p, 4);
        let text = std::fs::read_to_string(&p).unwrap();
        let tampered = text.replacen("key-2", "key-X", 1);
        assert_ne!(text, tampered);
        std::fs::write(&p, tampered).unwrap();
        let err = verify_and_visit(&p, |_| Ok(())).unwrap_err();
        assert!(matches!(err, AuditFileError::Tampered { .. }), "{err}");
    }

    #[test]
    fn detects_deleted_and_truncated_head() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        write_real_log(&p, 4);
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // Remove a middle entry.
        let mut cut = lines.clone();
        cut.remove(2);
        std::fs::write(&p, cut.join("\n")).unwrap();
        assert!(matches!(
            verify_and_visit(&p, |_| Ok(())),
            Err(AuditFileError::Tampered { .. })
        ));
        // Remove the first entry (head truncation of the only file).
        std::fs::write(&p, lines[1..].join("\n")).unwrap();
        assert!(matches!(
            verify_and_visit(&p, |_| Ok(())),
            Err(AuditFileError::Tampered { .. })
        ));
        // Garbage line.
        std::fs::write(&p, format!("{}\nnot json\n", lines[0])).unwrap();
        assert!(matches!(
            verify_and_visit(&p, |_| Ok(())),
            Err(AuditFileError::Tampered { .. })
        ));
    }

    #[test]
    fn verifies_across_rotated_generations() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        write_real_log(&p, 6);
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // Simulate rotation: entries 0..2 in .2, 2..4 in .1, rest current.
        std::fs::write(generation_path(&p, 2), lines[0..2].join("\n")).unwrap();
        std::fs::write(generation_path(&p, 1), lines[2..4].join("\n")).unwrap();
        std::fs::write(&p, lines[4..].join("\n")).unwrap();
        let s = verify_and_visit(&p, |_| Ok(())).unwrap();
        assert_eq!(s.entries, 6);
        assert!(s.anchored_at_genesis);
        // Oldest generation rotated away: chain still verifies but unanchored.
        std::fs::remove_file(generation_path(&p, 2)).unwrap();
        let s = verify_and_visit(&p, |_| Ok(())).unwrap();
        assert_eq!(s.entries, 4);
        assert!(!s.anchored_at_genesis);
        // Missing middle generation is detected.
        std::fs::write(generation_path(&p, 2), lines[0..2].join("\n")).unwrap();
        std::fs::remove_file(generation_path(&p, 1)).unwrap();
        assert!(verify_and_visit(&p, |_| Ok(())).is_err());
    }

    #[test]
    fn missing_log_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            verify_and_visit(&dir.path().join("none.jsonl"), |_| Ok(())),
            Err(AuditFileError::Missing(_))
        ));
    }

    #[test]
    fn syslog_line_matches_core_format() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        write_real_log(&p, 2);
        let core_lines = {
            // Build expected lines through the core's own formatter.
            let log = AuditLog::new();
            for i in 0..2u64 {
                log.record(
                    i,
                    AuditOperation::Login { user_type: 1 },
                    if i % 2 == 0 {
                        AuditResult::Success
                    } else {
                        AuditResult::Failure(0xA0)
                    },
                    Some(format!("key-{i}")),
                )
                .unwrap();
            }
            log.flush();
            log.export_syslog()
        };
        let mut ours = Vec::new();
        verify_and_visit(&p, |e| {
            ours.push(syslog_line(e));
            Ok(())
        })
        .unwrap();
        assert_eq!(ours.len(), core_lines.len());
        // Timestamps differ between the two logs; compare the remainder.
        for (a, b) in ours.iter().zip(core_lines.iter()) {
            let strip = |s: &str| s.splitn(3, ' ').nth(2).unwrap_or_default().to_string();
            assert_eq!(strip(a), strip(b));
        }
    }

    #[test]
    fn rfc3339_formatting() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(
            format_rfc3339(1_700_000_000_123_456_000),
            "2023-11-14T22:13:20.123456Z"
        );
    }
}
