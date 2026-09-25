// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
pub mod audit;
pub mod backup;
pub mod key;
pub mod pin;
pub mod token;

use std::path::PathBuf;

/// Global options shared by every command.
pub struct Ctx {
    pub config_path: PathBuf,
    pub json: bool,
    /// Skip typed confirmations (authentication is still required).
    pub yes: bool,
}

impl Ctx {
    pub fn load_config(&self) -> crate::error::CliResult<crate::config::LoadedConfig> {
        crate::config::load_strict(&self.config_path)
    }
}
