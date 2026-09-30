// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! The single place where the admin CLI obtains an [`HsmCore`] (H5-02).
//!
//! [`open_core`] uses the persistent constructor `HsmCore::open`, which loads
//! the token state (initialised flag, label, PIN verifiers, lockout counters,
//! wrapped storage keys) from `token.storage_path` and takes the exclusive
//! single-writer locks on the encrypted store and on the audit log. While the
//! daemon (or another CLI instance) holds them, every command that needs the
//! core fails with a clear "stop the daemon first" error instead of forking
//! the audit chain or writing the store concurrently.
//!
//! With `token.persist_objects = false` the configured token is ephemeral:
//! nothing the CLI changed would survive, so every mutating command is
//! refused ([`AdminCore::require_persistent`]).
//!
//! Authentication uses the regular PKCS#11 session/login services of the
//! core (lockout, rate limiting and audit records are applied there), and the
//! pre-operational self-tests run before any command touches keys (A1-06).

use crate::config::LoadedConfig;
use crate::error::{CliError, CliResult};
use craton_hsm::audit::log::{AuditOperation, AuditResult};
use craton_hsm::core::HsmCore;
use craton_hsm::error::HsmError;
use craton_hsm::pkcs11_abi::constants::{CKF_RW_SESSION, CKF_SERIAL_SESSION, CKU_SO, CKU_USER};
use craton_hsm::pkcs11_abi::types::{CK_SESSION_HANDLE, CK_SLOT_ID};
use craton_hsm::token::token::Token;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Maximum PIN prompts per invocation. The token's own persisted rate
/// limiting and lockout remain the primary brute-force control.
const MAX_AUTH_ATTEMPTS: u32 = 3;

/// The CLI administers slot 0.
pub const SLOT: CK_SLOT_ID = 0;

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

/// Whether the core the CLI operates on reflects persisted token state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreMode {
    /// `token.persist_objects = false`: token state is not persisted, so
    /// changes would be lost when the CLI exits.
    Ephemeral,
    /// Core opened on the persisted token state.
    Persistent,
}

pub struct AdminCore {
    hsm: HsmCore,
    mode: CoreMode,
}

/// Obtain the HSM core for a command. Every command goes through here.
pub fn open_core(cfg: &LoadedConfig) -> CliResult<AdminCore> {
    let hsm = HsmCore::open(&cfg.config).map_err(|e| match e {
        HsmError::AuditChainBroken(reason) => CliError::Integrity(format!(
            "Audit log cannot be opened safely ({reason}). Run 'audit verify-chain'."
        )),
        HsmError::DeviceError => CliError::Refused(
            "The token store or audit log is locked by another process (single writer). \
             Stop the craton-hsm daemon (and any other craton-hsm-admin or PKCS#11 \
             application using this configuration) before running administrative commands."
                .into(),
        ),
        other => CliError::General(format!("Failed to initialise the HSM core: {other}")),
    })?;
    hsm.run_self_tests().map_err(|e| {
        CliError::Integrity(format!(
            "Pre-operational self-tests failed ({e}); the module is in the error state."
        ))
    })?;
    let mode = if hsm.object_store().has_persistence() {
        CoreMode::Persistent
    } else {
        CoreMode::Ephemeral
    };
    Ok(AdminCore { hsm, mode })
}

impl AdminCore {
    pub fn hsm(&self) -> &HsmCore {
        &self.hsm
    }

    pub fn mode(&self) -> CoreMode {
        self.mode
    }

    /// Fail closed if the operation would have no lasting effect because the
    /// configured token is not persistent.
    pub fn require_persistent(&self, operation: &str) -> CliResult {
        match self.mode {
            CoreMode::Persistent => Ok(()),
            CoreMode::Ephemeral => Err(CliError::Refused(format!(
                "'{operation}' is not supported for an ephemeral token: the configuration sets \
                 token.persist_objects = false, so the operation would have no lasting effect. \
                 No changes were made."
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
            .get_token(SLOT)
            .map_err(|e| CliError::General(format!("Failed to access token: {e}")))
    }

    /// Open an R/W session and authenticate `role` with PIN prompts
    /// (`C_Login` through the core: lockout, rate limit, audit record, and
    /// the slot's token objects are loaded). The returned guard logs out and
    /// closes the session when dropped (including on every early return).
    pub fn login(&self, role: Role) -> CliResult<LoginGuard<'_>> {
        self.login_with_pin(role).map(|(guard, _pin)| guard)
    }

    /// Like [`AdminCore::login`] but also returns the verified PIN (needed by
    /// `C_SetPIN`), wrapped in `Zeroizing`.
    pub fn login_with_pin(&self, role: Role) -> CliResult<(LoginGuard<'_>, Zeroizing<String>)> {
        let token = self.token()?;
        if !token.is_initialized() {
            return Err(CliError::Auth(
                "Token is not initialized. Run 'token init' first.".into(),
            ));
        }
        let session = self
            .hsm
            .open_process_session(SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION)
            .map_err(|e| CliError::General(format!("Cannot open a session: {e}")))?;
        let guard = LoginGuard {
            hsm: &self.hsm,
            session,
            logged_in: false,
        };
        let mut guard = guard;
        for attempt in 1..=MAX_AUTH_ATTEMPTS {
            let pin = crate::prompt::read_secret(&format!("Enter {} PIN: ", role.name()))?;
            match self.hsm.login(session, role.ck_user(), pin.as_bytes()) {
                Ok(()) => {
                    guard.logged_in = true;
                    return Ok((guard, pin));
                }
                Err(e) => match e {
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
                    HsmError::PinRateLimited if attempt < MAX_AUTH_ATTEMPTS => {
                        eprintln!("Too many recent attempts; waiting before retrying.");
                        std::thread::sleep(std::time::Duration::from_secs(5));
                    }
                    HsmError::PinIncorrect | HsmError::PinRateLimited => break,
                    other => return Err(CliError::Auth(format!("Authentication failed: {other}"))),
                },
            }
        }
        Err(CliError::Auth(
            "Authentication failed. Maximum attempts reached; further failures may lock the PIN."
                .into(),
        ))
    }

    /// Actor string recorded in audit events (H5-20).
    pub fn actor(&self, action: &str) -> String {
        format!("craton-hsm-admin:{action}:{}", os_user())
    }

    /// Record an administrative event in the tamper-evident audit log
    /// (synchronously: the command fails if the event cannot be made
    /// durable in fail-closed mode). Only active on a persistent core.
    pub fn record(
        &self,
        session: CK_SESSION_HANDLE,
        operation: AuditOperation,
        result: Result<(), &HsmError>,
        action: &str,
    ) -> CliResult {
        if self.mode != CoreMode::Persistent {
            return Ok(());
        }
        let result = match result {
            Ok(()) => AuditResult::Success,
            Err(e) => AuditResult::Failure(u64::from(craton_hsm::pkcs11_abi::types::CK_RV::from(
                e.clone(),
            ))),
        };
        self.hsm
            .audit_log()
            .record_sync(session as u64, operation, result, Some(self.actor(action)))
            .map_err(|e| CliError::Integrity(format!("Failed to write audit record: {e}")))
    }
}

impl Drop for AdminCore {
    fn drop(&mut self) {
        // Zeroize keys/PIN verifiers and make queued audit records durable.
        self.hsm.finalize();
    }
}

/// An authenticated R/W session; logs out and closes the session when
/// dropped.
pub struct LoginGuard<'a> {
    hsm: &'a HsmCore,
    session: CK_SESSION_HANDLE,
    logged_in: bool,
}

impl LoginGuard<'_> {
    pub fn session(&self) -> CK_SESSION_HANDLE {
        self.session
    }
}

impl Drop for LoginGuard<'_> {
    fn drop(&mut self) {
        if self.logged_in {
            let _ = self.hsm.logout(self.session);
        }
        let _ = self.hsm.close_session(self.session);
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
/// the core PIN policy (the same rules as C_InitPIN / C_SetPIN, H5-12).
pub fn prompt_new_pin(cfg: &LoadedConfig, what: &str) -> CliResult<Zeroizing<String>> {
    let pin = crate::prompt::read_secret(&format!("Enter new {what} PIN: "))?;
    let confirm = crate::prompt::read_secret(&format!("Confirm new {what} PIN: "))?;
    if *pin != *confirm {
        return Err(CliError::Usage(format!("{what} PINs do not match.")));
    }
    crate::commands::pin::validate_new_pin(&pin, &cfg.config).map_err(CliError::Usage)?;
    Ok(pin)
}
