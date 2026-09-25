// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
#![forbid(unsafe_code)]

//! Persists lockout counters (failed login counts and locked flags) to disk.
//!
//! Lockout state is NOT secret (it's security metadata, not key material), so
//! it is stored as plain JSON without encryption. This ensures that lockout
//! survives process restarts, preventing an attacker from resetting brute-force
//! counters by crashing or restarting the HSM process.
//!
//! The file is written atomically (random O_EXCL temp file + fsync + rename +
//! directory fsync) to avoid corruption from power loss mid-write.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Persisted lockout state for a single token.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LockoutData {
    pub failed_user_logins: u32,
    pub failed_so_logins: u32,
    #[serde(default)]
    pub failed_init_token_logins: u32,
    pub user_pin_locked: bool,
    pub so_pin_locked: bool,
}

impl LockoutData {
    /// Fail-closed state used when persisted counters are missing or corrupt.
    pub fn locked() -> Self {
        Self {
            user_pin_locked: true,
            so_pin_locked: true,
            failed_user_logins: u32::MAX,
            failed_so_logins: u32::MAX,
            failed_init_token_logins: u32::MAX,
        }
    }
}

/// Standalone file-backed persistence for lockout counters.
///
/// The token itself keeps lockout counters in the encrypted persistent store
/// (per slot); this file-based store remains for tooling. It is per-slot
/// (H3-17), written atomically with `O_NOFOLLOW`/0600 temp files and
/// `fsync` (H3-12), and `save` errors are propagated.
pub struct LockoutStore {
    path: PathBuf,
}

impl LockoutStore {
    /// Create a lockout store for slot 0 (legacy name `lockout_state.json`).
    pub fn new(storage_dir: &std::path::Path) -> Self {
        Self {
            path: storage_dir.join("lockout_state.json"),
        }
    }

    /// Create a per-slot lockout store (`lockout_slot{N}.json`).
    pub fn for_slot(storage_dir: &std::path::Path, slot: u64) -> Self {
        Self {
            path: storage_dir.join(format!("lockout_slot{}.json", slot)),
        }
    }

    /// Load persisted lockout data.
    ///
    /// A missing file yields fresh counters only when `expect_existing` is
    /// false (first boot); for an initialised token a missing, unreadable or
    /// corrupt file yields the locked state (fail closed).
    pub fn load_checked(&self, expect_existing: bool) -> LockoutData {
        match crate::store::fs_util::read_private(&self.path) {
            Ok(Some(content)) => match serde_json::from_slice::<LockoutData>(&content) {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(
                        "lockout state file is corrupted ({}), defaulting to locked state",
                        e
                    );
                    LockoutData::locked()
                }
            },
            Ok(None) if !expect_existing => LockoutData::default(),
            Ok(None) => {
                tracing::error!("lockout state file missing for initialised token — locking");
                LockoutData::locked()
            }
            Err(_) => LockoutData::locked(),
        }
    }

    /// Load persisted lockout data, returning defaults if the file doesn't
    /// exist (first boot) and the locked state on corruption.
    pub fn load(&self) -> LockoutData {
        self.load_checked(false)
    }

    /// Persist lockout data atomically. Errors are returned so callers can
    /// refuse the authentication attempt (fail closed).
    pub fn save(&self, data: &LockoutData) -> crate::error::HsmResult<()> {
        let json =
            serde_json::to_vec_pretty(data).map_err(|_| crate::error::HsmError::GeneralError)?;
        if let Some(parent) = self.path.parent() {
            crate::store::fs_util::ensure_private_dir(parent)?;
        }
        crate::store::fs_util::atomic_write_private(&self.path, &json)
    }

    /// Remove the lockout state file (called during token re-initialization).
    pub fn clear(&self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("failed to remove lockout state file: {}", e);
            }
        }
    }
}
