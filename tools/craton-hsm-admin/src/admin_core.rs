// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! The single place where the admin CLI obtains an [`HsmCore`] (H5-02).
//!
//! # Standalone (ephemeral) mode
//!
//! The core library currently only offers `HsmCore::try_new`, which builds a
//! fresh, in-memory object store and a token with no persisted PIN state.
//! Anything a command changed through such a core would be lost when the
//! process exits, while side files shared with a real deployment (lockout
//! state, replay guard) would still be modified. Therefore every command that
//! needs the persisted token state calls [`AdminCore::require_persistent`]
//! and fails closed with [`CliError::Refused`] until [`open_core`] is switched
//! to the persistent constructor.
//!
//! # Switching to the persistent core
//!
//! When the core exposes a persistent open API (e.g.
//! `HsmCore::open_persistent(&HsmConfig) -> HsmResult<HsmCore>` that loads
//! token/PIN state and uses `ObjectStore::with_persistence` + `load_from_store`
//! under an exclusive single-writer lock), change the body of [`open_core`] to
//! call it and return `CoreMode::Persistent`. No command needs to change:
//! the refusals disappear and SO authentication, typed confirmation and
//! audit recording become active automatically.

use crate::config::LoadedConfig;
use crate::error::{CliError, CliResult};
use craton_hsm::audit::log::{AuditOperation, AuditResult};
use craton_hsm::core::HsmCore;
use craton_hsm::error::HsmError;
use craton_hsm::pkcs11_abi::constants::{CKU_SO, CKU_USER};
use craton_hsm::token::token::Token;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Maximum PIN prompts per invocation. The token's own persisted rate
/// limiting and lockout remain the primary brute-force control.
const MAX_AUTH_ATTEMPTS: u32 = 3;

/// PKCS#11 role used to authenticate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Role {
    /// Normal user (CKU_USER).
    User,
    /// Security Officer (CKU_SO).
    So,
}

impl Role {
    pub fn ck_user(self) -> craton_hsm::pkcs11_abi::types::CK_USER_TYPE {
        match self {
            Role::User => CKU_USER,
            Role::So => CKU_SO,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Role::User => "User",
            Role::So => "SO",
        }
    }
}

/// Whether the core the CLI operates on reflects the persisted token state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreMode {
    /// Fresh in-memory core: token state is NOT loaded from disk and changes
    /// are NOT persisted.
    Ephemeral,
    /// Core opened on the persisted token state.
    #[allow(dead_code)] // becomes live once `open_core` uses the persistent constructor
    Persistent,
}

pub struct AdminCore {
    hsm: HsmCore,
    mode: CoreMode,
}

/// Obtain the HSM core for a command. Every command goes through here.
pub fn open_core(cfg: &LoadedConfig) -> CliResult<AdminCore> {
    // HANDOFF: replace with the persistent constructor and CoreMode::Persistent.
    let hsm = HsmCore::try_new(&cfg.config).map_err(|e| match e {
        HsmError::AuditChainBroken(reason) => CliError::Integrity(format!(
            "Audit log cannot be opened safely ({reason}). Run 'audit verify-chain'."
        )),
        other => CliError::General(format!("Failed to initialise the HSM core: {other}")),
    })?;
    Ok(AdminCore {
        hsm,
        mode: CoreMode::Ephemeral,
    })
}

impl AdminCore {
    pub fn hsm(&self) -> &HsmCore {
        &self.hsm
    }

    pub fn mode(&self) -> CoreMode {
        self.mode
    }

    /// Fail closed if the operation would have no lasting effect because the
    /// core is not backed by persisted token state.
    pub fn require_persistent(&self, operation: &str) -> CliResult {
        match self.mode {
            CoreMode::Persistent => Ok(()),
            CoreMode::Ephemeral => Err(CliError::Refused(format!(
                "'{operation}' is not supported in standalone mode: this build of \
                 craton-hsm-admin cannot open the persisted token state, so the operation \
                 would have no lasting effect (and could not authenticate the Security \
                 Officer). No changes were made. Perform it through the PKCS#11 interface \
                 or the daemon instead."
            ))),
        }
    }

    /// Refuse to perform privileged operations when the audit trail is known
    /// to be compromised.
    pub fn require_audit_intact(&self) -> CliResult {
        if self.hsm.audit_log().is_tamper_detected() {
            return Err(CliError::Integrity(
                "Audit log tamper detected; refusing privileged operation. \
                 Run 'audit verify-chain' for details."
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn token(&self) -> CliResult<Arc<Token>> {
        self.hsm
            .slot_manager()
            .get_token(0)
            .map_err(|e| CliError::General(format!("Failed to access token: {e}")))
    }

    /// Authenticate `role` with PIN prompts. Returns a guard that logs out
    /// when dropped (including on every early `?` return).
    pub fn login(&self, role: Role) -> CliResult<LoginGuard> {
        self.login_with_pin(role).map(|(guard, _pin)| guard)
    }

    /// Like [`AdminCore::login`] but also returns the verified PIN (needed by
    /// `C_SetPIN`-style operations), wrapped in `Zeroizing`.
    pub fn login_with_pin(&self, role: Role) -> CliResult<(LoginGuard, Zeroizing<String>)> {
        let token = self.token()?;
        if !token.is_initialized() {
            return Err(CliError::Auth(
                "Token is not initialized. Run 'token init' first.".into(),
            ));
        }
        for attempt in 1..=MAX_AUTH_ATTEMPTS {
            let pin = crate::prompt::read_secret(&format!("Enter {} PIN: ", role.name()))?;
            match token.login(role.ck_user(), pin.as_bytes()) {
                Ok(()) => {
                    self.record(
                        AuditOperation::Login {
                            user_type: u64::from(role.ck_user()),
                        },
                        Ok(()),
                        "login",
                    )?;
                    return Ok((LoginGuard { token }, pin));
                }
                Err(e) => {
                    let _ = self.record(
                        AuditOperation::Login {
                            user_type: u64::from(role.ck_user()),
                        },
                        Err(&e),
                        "login",
                    );
                    match e {
                        HsmError::PinLocked => {
                            return Err(CliError::Auth(format!("{} PIN is locked.", role.name())))
                        }
                        HsmError::PinIncorrect if attempt < MAX_AUTH_ATTEMPTS => {
                            eprintln!(
                                "Authentication failed. {} attempt(s) remaining.",
                                MAX_AUTH_ATTEMPTS - attempt
                            );
                            std::thread::sleep(std::time::Duration::from_secs(1));
                        }
                        HsmError::PinIncorrect => break,
                        other => {
                            return Err(CliError::Auth(format!("Authentication failed: {other}")))
                        }
                    }
                }
            }
        }
        Err(CliError::Auth(
            "Authentication failed. Maximum attempts reached; further failures may lock the PIN."
                .into(),
        ))
    }

    /// Record an administrative event in the tamper-evident audit log (H5-20).
    ///
    /// Only active on a persistent core: an ephemeral core must not append to
    /// a log that a running daemon may be writing (two writers would fork the
    /// hash chain), and in ephemeral mode every mutating command is refused
    /// before reaching this point anyway.
    pub fn record(
        &self,
        operation: AuditOperation,
        result: Result<(), &HsmError>,
        action: &str,
    ) -> CliResult {
        if self.mode != CoreMode::Persistent {
            return Ok(());
        }
        let result = match result {
            Ok(()) => AuditResult::Success,
            Err(e) => AuditResult::Failure(hsm_error_code(e)),
        };
        let detail = format!("craton-hsm-admin:{action}:{}", os_user());
        self.hsm
            .audit_log()
            .record(0, operation, result, Some(detail))
            .map_err(|e| CliError::Integrity(format!("Failed to write audit record: {e}")))
    }
}

impl Drop for AdminCore {
    fn drop(&mut self) {
        // Make sure queued audit records reach the disk before exit.
        self.hsm.audit_log().flush();
    }
}

/// Logs the token out when dropped.
pub struct LoginGuard {
    token: Arc<Token>,
}

impl LoginGuard {
    pub fn token(&self) -> &Token {
        &self.token
    }
}

impl Drop for LoginGuard {
    fn drop(&mut self) {
        let _ = self.token.logout();
    }
}

/// Coarse numeric code for an audit failure record.
fn hsm_error_code(e: &HsmError) -> u64 {
    match e {
        HsmError::PinIncorrect => 0xA0,
        HsmError::PinLocked => 0xA4,
        HsmError::TokenNotInitialized => 0xE1,
        _ => 0x05,
    }
}

/// Identify the invoking OS user for audit records.
fn os_user() -> String {
    #[cfg(unix)]
    {
        format!("uid={}", crate::sys::effective_uid())
    }
    #[cfg(not(unix))]
    {
        "uid=unknown".to_string()
    }
}

/// Read and confirm a new PIN, enforcing the configured length limits and
/// the complexity policy.
pub fn prompt_new_pin(cfg: &LoadedConfig, what: &str) -> CliResult<Zeroizing<String>> {
    let pin = crate::prompt::read_secret(&format!("Enter new {what} PIN: "))?;
    let confirm = crate::prompt::read_secret(&format!("Confirm new {what} PIN: "))?;
    if *pin != *confirm {
        return Err(CliError::Usage(format!("{what} PINs do not match.")));
    }
    crate::commands::pin::validate_new_pin(&pin, &cfg.config).map_err(CliError::Usage)?;
    Ok(pin)
}
