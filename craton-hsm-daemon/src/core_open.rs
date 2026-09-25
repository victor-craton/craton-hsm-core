// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! The single place where the daemon constructs its `HsmCore` (H4-03).
//!
//! `HsmCore::open` loads the persistent token state (initialised flag,
//! label, PIN verifiers, lockout counters, wrapped storage keys) when
//! `token.persist_objects = true` and takes the store's exclusive
//! single-writer lock, so the daemon and the admin CLI can never write the
//! same store (or audit log) concurrently. Token objects of a slot become
//! available after the first successful PIN verification on that slot
//! (`HsmCore::verify_pin` unlocks the slot's storage key).
//!
//! The pre-operational self-tests (software CASTs, integrity test and the
//! CASTs of the selected backend) run before the daemon serves (A1-06).

use std::sync::Arc;

use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;
use craton_hsm::error::HsmError;

/// Open (or create) the HSM state for the daemon and run the self-tests.
pub fn open_core(config: &HsmConfig) -> Result<Arc<HsmCore>, String> {
    let core = HsmCore::open(config).map_err(|e| match e {
        HsmError::AuditChainBroken(reason) => format!(
            "audit log integrity check failed ({}); investigate, then set \
             audit.allow_start_with_broken_chain = true to override",
            reason
        ),
        HsmError::DeviceError => "failed to open the HSM state: the persistent store or audit \
             log is unavailable or locked by another process (is another daemon or \
             craton-hsm-admin running on the same storage_path / audit log?)"
            .to_string(),
        other => format!("failed to initialise HSM core: {:?}", other),
    })?;

    core.run_self_tests()
        .map_err(|e| format!("pre-operational self-tests failed: {:?}", e))?;
    tracing::info!("pre-operational self-tests passed");

    if core.object_store().has_persistence() {
        tracing::info!(
            "persistent token state loaded from {}",
            config.token.storage_path.display()
        );
    } else {
        tracing::warn!(
            "HSM state is EPHEMERAL (token.persist_objects = false): keys and token \
             initialisation are lost on restart. Only session objects (CKA_TOKEN=false) \
             can be created."
        );
    }
    Ok(Arc::new(core))
}
