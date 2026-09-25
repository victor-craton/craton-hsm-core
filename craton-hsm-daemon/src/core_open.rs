// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! The single place where the daemon constructs its `HsmCore` (H4-03).
//!
//! Persistence of token objects and token state (initialised flag, PIN
//! hashes, label) is implemented by the core library. When a persistent
//! constructor is available, switch the call below to it — nothing else in
//! the daemon needs to change: the daemon detects persistence at runtime via
//! `ObjectStore::has_persistence()` and only then accepts `CKA_TOKEN=true`
//! objects.

use std::sync::Arc;

use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;

/// Open (or create) the HSM state for the daemon.
pub fn open_core(config: &HsmConfig) -> Result<Arc<HsmCore>, String> {
    // NOTE(H4-03): replace `HsmCore::try_new` with the core's persistent
    // open API (see the daemon handoff notes) once it lands.
    let core =
        HsmCore::try_new(config).map_err(|e| format!("failed to initialise HSM core: {:?}", e))?;

    if core.object_store().has_persistence() {
        tracing::info!("persistent object store active");
    } else {
        if config.token.persist_objects {
            tracing::error!(
                "[token] persist_objects = true, but this build's HSM core does not persist \
                 objects or token state. Token objects (CKA_TOKEN=true) will be REFUSED."
            );
        }
        tracing::warn!(
            "HSM state is EPHEMERAL: keys and token initialisation are lost on restart. \
             Only session objects (CKA_TOKEN=false) can be created."
        );
    }
    Ok(Arc::new(core))
}
