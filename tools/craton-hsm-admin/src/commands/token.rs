// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use super::Ctx;
use crate::admin_core::{open_core, prompt_new_pin, AdminCore, CoreMode, Role};
use crate::error::{CliError, CliResult};
use crate::output;
use craton_hsm::audit::log::AuditOperation;

/// PKCS#11 `CK_TOKEN_INFO.label` length.
const LABEL_LEN: usize = 32;

/// Validate a token/object label with the same rule the config validator
/// applies to `token.label`: 1..=32 bytes of printable ASCII (H5-15).
pub fn validate_label(label: &str) -> CliResult<[u8; LABEL_LEN]> {
    if label.is_empty() || label.len() > LABEL_LEN {
        return Err(CliError::Usage(format!(
            "Label must be 1 to {LABEL_LEN} bytes long."
        )));
    }
    if !label.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        return Err(CliError::Usage(
            "Label must contain printable ASCII characters only.".into(),
        ));
    }
    let mut padded = [b' '; LABEL_LEN];
    padded[..label.len()].copy_from_slice(label.as_bytes());
    Ok(padded)
}

/// Initialize (or re-initialize) the token.
///
/// - Re-initialization requires the current SO PIN.
/// - First-time initialization is refused if persisted lockout state exists,
///   because that state can then not be tied to a verifiable SO (H5-01).
/// - A typed confirmation is required (or `--yes`).
pub fn init(ctx: &Ctx, label: &str) -> CliResult {
    let label_bytes = validate_label(label)?;
    let cfg = ctx.load_config()?;
    let core = open_core(&cfg)?;
    core.require_persistent("token init")?;
    core.require_audit_intact()?;
    let token = core.token()?;

    let so_pin = if token.is_initialized() {
        // Verify the current SO PIN before anything is reset. C_InitToken
        // semantics: the SO PIN is kept.
        let (guard, pin) = core.login_with_pin(Role::So)?;
        drop(guard);
        pin
    } else {
        let lockout = cfg.storage_dir().join("lockout_state.json");
        if std::fs::symlink_metadata(&lockout).is_ok() {
            return Err(CliError::Refused(format!(
                "Token reports no SO PIN but persisted lockout state exists at '{}'. \
                 Refusing to clear it without SO verification; investigate and remove it \
                 manually if the token really is new.",
                lockout.display()
            )));
        }
        prompt_new_pin(&cfg, "SO")?
    };

    crate::prompt::confirm_typed(
        "This will initialize the token: ALL objects are destroyed and the User PIN is removed.",
        "initialize",
        ctx.yes,
    )?;

    let res = token.init_token(so_pin.as_bytes(), &label_bytes);
    core.record(
        AuditOperation::InitToken { slot_id: 0 },
        res.as_ref().map(|_| ()),
        "token-init",
    )?;
    res.map_err(|e| CliError::Auth(format!("Token initialization failed: {e}")))?;
    // Per PKCS#11, C_InitToken destroys all objects on the token.
    core.hsm().object_store().clear();

    println!("Token initialized successfully.");
    println!("  Label: {label}");
    Ok(())
}

fn warn_if_ephemeral(core: &AdminCore, json: bool) {
    if core.mode() == CoreMode::Ephemeral && !json {
        eprintln!(
            "Note: standalone mode — token state below is NOT loaded from persistent storage \
             (fresh in-memory core)."
        );
    }
}

fn state_source(core: &AdminCore) -> &'static str {
    match core.mode() {
        CoreMode::Ephemeral => "ephemeral",
        CoreMode::Persistent => "persistent",
    }
}

/// Display token information.
pub fn info(ctx: &Ctx) -> CliResult {
    let cfg = ctx.load_config()?;
    let core = open_core(&cfg)?;
    let token = core.token()?;
    warn_if_ephemeral(&core, ctx.json);

    let initialized = token.is_initialized();
    let user_pin_init = token.is_user_pin_initialized();
    let login_state = format!("{:?}", token.login_state());
    let flags = token.flags();

    if ctx.json {
        let value = serde_json::json!({
            "slot_id": 0,
            "state_source": state_source(&core),
            "initialized": initialized,
            "user_pin_initialized": user_pin_init,
            "login_state": login_state,
            "session_count": token.session_count(),
            "rw_session_count": token.rw_session_count(),
            "max_sessions": token.max_sessions(),
            "max_rw_sessions": token.max_rw_sessions(),
            "pin_min_len": token.pin_min_len(),
            "pin_max_len": token.pin_max_len(),
            "flags": format!("0x{:08x}", flags),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Token Information");
        println!("=================");
        output::print_table(&[
            ("Slot ID:", "0".to_string()),
            ("State Source:", state_source(&core).to_string()),
            ("Initialized:", initialized.to_string()),
            ("User PIN Init:", user_pin_init.to_string()),
            ("Login State:", login_state),
            (
                "Sessions:",
                format!("{}/{}", token.session_count(), token.max_sessions()),
            ),
            (
                "RW Sessions:",
                format!("{}/{}", token.rw_session_count(), token.max_rw_sessions()),
            ),
            (
                "PIN Length:",
                format!("{}-{}", token.pin_min_len(), token.pin_max_len()),
            ),
            ("Flags:", format!("0x{:08x}", flags)),
        ]);
    }

    Ok(())
}

/// Show overall HSM status. Does not expose object or audit contents.
pub fn status(ctx: &Ctx) -> CliResult {
    let cfg = ctx.load_config()?;
    let core = open_core(&cfg)?;
    let token = core.token()?;
    warn_if_ephemeral(&core, ctx.json);
    let audit_tamper = core.hsm().audit_log().is_tamper_detected();
    let config = &cfg.config;

    if ctx.json {
        let value = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "config_path": cfg.path.display().to_string(),
            "state_source": state_source(&core),
            "token_initialized": token.is_initialized(),
            "audit_enabled": config.audit.enabled,
            "audit_tamper_detected": audit_tamper,
            "config": {
                "max_sessions": config.token.max_sessions,
                "pqc_enabled": config.algorithms.enable_pqc,
            }
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Craton HSM Status");
        println!("=================");
        output::print_table(&[
            ("Version:", env!("CARGO_PKG_VERSION").to_string()),
            ("Config:", cfg.path.display().to_string()),
            ("State Source:", state_source(&core).to_string()),
            ("Token Init:", token.is_initialized().to_string()),
            ("Audit Enabled:", config.audit.enabled.to_string()),
            ("Audit Tamper:", audit_tamper.to_string()),
            ("Max Sessions:", config.token.max_sessions.to_string()),
            ("PQC Enabled:", config.algorithms.enable_pqc.to_string()),
        ]);
    }
    if audit_tamper {
        return Err(CliError::Integrity(
            "Audit log tamper detected. Run 'audit verify-chain' for details.".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_validation() {
        assert!(validate_label("MyToken").is_ok());
        assert_eq!(&validate_label("ab").unwrap()[..3], b"ab ");
        assert!(validate_label("").is_err());
        assert!(validate_label(&"x".repeat(33)).is_err());
        assert!(validate_label("bad\x1b[31m").is_err());
        assert!(validate_label("ключ").is_err());
    }
}
