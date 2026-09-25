// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Audit commands. All of them read the persisted on-disk log (and its
//! rotated generations) and verify the hash chain while reading (H5-03).
//! Commands that reveal audit contents require SO authentication (H5-05).

use super::Ctx;
use crate::admin_core::{open_core, Role};
use crate::error::{CliError, CliResult};
use crate::output;
use craton_hsm::audit::log::{
    format_rfc3339, format_syslog, operation_name, AuditEvent, AuditFileSummary, AuditLog,
    AuditOperation, AuditResult, AuditVerifyError,
};
use std::collections::VecDeque;
use std::io::Write;

/// Upper bound for `audit dump --last`.
pub const MAX_DUMP_ENTRIES: usize = 100_000;

/// Export formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Ndjson,
    Syslog,
}

impl ExportFormat {
    fn name(self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Ndjson => "ndjson",
            ExportFormat::Syslog => "syslog",
        }
    }
}

fn file_error(e: AuditVerifyError) -> CliError {
    match e {
        AuditVerifyError::Io(..) | AuditVerifyError::Visitor(_) => {
            CliError::Io(format!("Audit log: {e}"))
        }
        AuditVerifyError::Missing(_)
        | AuditVerifyError::Tampered { .. }
        | AuditVerifyError::KeyUnavailable(..) => CliError::Integrity(format!("Audit log: {e}")),
    }
}

/// Verify the persisted log (all generations) with the core's offline
/// verifier (keyed chain, sequence numbers, rotation links, anchor; H5-03)
/// and visit each verified event.
fn verify(
    cfg: &crate::config::LoadedConfig,
    visit: impl FnMut(&AuditEvent) -> Result<(), String>,
) -> Result<AuditFileSummary, AuditVerifyError> {
    AuditLog::verify_files(&cfg.config.audit.log_path, &cfg.audit_key_path(), visit)
}

fn result_string(r: &AuditResult) -> String {
    match r {
        AuditResult::Success => "SUCCESS".to_string(),
        AuditResult::Failure(rv) => format!("FAILURE(0x{rv:08X})"),
    }
}

/// Authenticate the SO for commands that reveal audit contents, record the
/// access (`AuditExport`, H5-20) and release the core (and its locks) before
/// the log files are read.
fn so_gate(
    ctx: &Ctx,
    operation: &str,
    confirm: Option<&str>,
) -> CliResult<crate::config::LoadedConfig> {
    let cfg = ctx.load_config()?;
    let core = open_core(&cfg)?;
    core.require_persistent(operation)?;
    let session = core.login(Role::So)?;
    if let Some(phrase) = confirm {
        crate::prompt::confirm_typed(
            "This writes the complete audit trail to standard output.",
            phrase,
            ctx.yes,
        )?;
    }
    core.record(
        session.session(),
        AuditOperation::AuditExport,
        Ok(()),
        operation,
    )?;
    drop(session);
    drop(core);
    Ok(cfg)
}

/// Verify the persisted audit log hash chain. Exits non-zero (6) when the
/// chain is broken, a generation is missing, the key is unavailable or the
/// log does not exist. Does not reveal entry contents and takes no lock, so
/// it can run while the daemon is serving (read access to the log and its
/// key file is required).
pub fn verify_chain(ctx: &Ctx) -> CliResult {
    let cfg = ctx.load_config()?;
    match verify(&cfg, |_| Ok(())) {
        Ok(summary) => {
            if ctx.json {
                let value = serde_json::json!({
                    "status": "valid",
                    "entries_verified": summary.entries,
                    "anchored_at_genesis": summary.anchored_at_genesis,
                    "tail_anchor_present": summary.anchor_present,
                    "files": summary.files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                println!("Audit Chain Verification: VALID");
                println!("  Entries verified: {}", summary.entries);
                for f in &summary.files {
                    println!(
                        "  File:             {}",
                        output::escape_display(&f.display().to_string())
                    );
                }
            }
            if !summary.anchored_at_genesis {
                eprintln!(
                    "Warning: the oldest available generation does not start at the genesis \
                     value (older generations were rotated away); the start of the chain \
                     cannot be anchored."
                );
            }
            if !summary.anchor_present {
                eprintln!(
                    "Warning: no tail anchor found; truncation of the newest events cannot be \
                     ruled out."
                );
            }
            Ok(())
        }
        Err(e) => {
            if ctx.json {
                let value = match &e {
                    AuditVerifyError::Tampered { file, line, reason } => serde_json::json!({
                        "status": "broken",
                        "file": file.display().to_string(),
                        "line": line,
                        "reason": reason,
                    }),
                    AuditVerifyError::Missing(p) => serde_json::json!({
                        "status": "missing",
                        "file": p.display().to_string(),
                    }),
                    AuditVerifyError::KeyUnavailable(p, reason) => serde_json::json!({
                        "status": "key-unavailable",
                        "file": p.display().to_string(),
                        "reason": reason,
                    }),
                    AuditVerifyError::Io(p, err) => serde_json::json!({
                        "status": "error",
                        "file": p.display().to_string(),
                        "reason": err,
                    }),
                    AuditVerifyError::Visitor(err) => serde_json::json!({
                        "status": "error",
                        "reason": err,
                    }),
                };
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                eprintln!("Audit Chain Verification: FAILED");
            }
            Err(file_error(e))
        }
    }
}

fn entry_json(e: &AuditEvent) -> serde_json::Value {
    serde_json::json!({
        "seq": e.seq,
        "timestamp": format_rfc3339(e.timestamp),
        "session_handle": e.session_handle,
        "operation": e.operation,
        "key_id": e.key_id,
        "result": result_string(&e.result),
    })
}

/// Show the most recent `last` verified entries.
pub fn dump(ctx: &Ctx, last: usize) -> CliResult {
    if last == 0 || last > MAX_DUMP_ENTRIES {
        return Err(CliError::Usage(format!(
            "--last must be between 1 and {MAX_DUMP_ENTRIES}."
        )));
    }
    let cfg = so_gate(ctx, "audit dump", None)?;

    let mut ring: VecDeque<AuditEvent> = VecDeque::with_capacity(last.min(1024));
    let summary = verify(&cfg, |e| {
        if ring.len() == last {
            ring.pop_front();
        }
        ring.push_back(e.clone());
        Ok(())
    })
    .map_err(file_error)?;

    if ctx.json {
        let entries: Vec<_> = ring.iter().map(entry_json).collect();
        let value = serde_json::json!({
            "total_entries": summary.entries,
            "chain": "valid",
            "entries": entries,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Audit Log (chain verified)");
        println!("==========================");
        let mut table =
            output::ObjectTable::new(vec!["Timestamp", "Session", "Operation", "Result", "Key"]);
        for e in &ring {
            table.add_row(vec![
                format_rfc3339(e.timestamp),
                e.session_handle.to_string(),
                operation_name(&e.operation).to_string(),
                result_string(&e.result),
                e.key_id.clone().unwrap_or_else(|| "-".into()),
            ]);
        }
        print!("{table}");
        println!("\nShowing {} of {} entries.", ring.len(), summary.entries);
    }
    Ok(())
}

/// Export the verified persisted log to stdout. Each entry is emitted only
/// after its chain link verified; on a broken link output stops and the
/// command exits with the integrity error code.
pub fn export(ctx: &Ctx, format: ExportFormat) -> CliResult {
    let cfg = so_gate(
        ctx,
        &format!("audit export-{}", format.name()),
        Some("export"),
    )?;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut first = true;
    if format == ExportFormat::Json {
        out.write_all(b"[")?;
    }
    let res = verify(&cfg, |e| {
        let r: std::io::Result<()> = (|| {
            match format {
                ExportFormat::Json => {
                    if !first {
                        out.write_all(b",")?;
                    }
                    out.write_all(b"\n  ")?;
                    serde_json::to_writer(&mut out, e).map_err(std::io::Error::other)?;
                }
                ExportFormat::Ndjson => {
                    serde_json::to_writer(&mut out, e).map_err(std::io::Error::other)?;
                    out.write_all(b"\n")?;
                }
                ExportFormat::Syslog => {
                    writeln!(out, "{}", format_syslog(e))?;
                }
            }
            Ok(())
        })();
        first = false;
        r.map_err(|e| e.to_string())
    });
    if res.is_ok() && format == ExportFormat::Json {
        out.write_all(b"\n]\n")?;
    }
    out.flush()?;
    res.map(|_| ()).map_err(file_error)
}
