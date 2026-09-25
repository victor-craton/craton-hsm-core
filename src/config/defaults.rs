// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Single source of truth for security-relevant defaults and constants
//! (H3-27). Every module that needs one of these values imports it from here
//! instead of re-declaring its own copy.

/// Default PBKDF2-HMAC-SHA256 iteration count for PIN hashing, storage KEK
/// derivation and backup passphrases (OWASP 2023 guidance for SHA-256).
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 600_000;

/// Default number of consecutive failed authentications before an account
/// (user or SO) is locked.
pub const DEFAULT_MAX_FAILED_LOGINS: u32 = 5;

/// Default minimum / maximum PIN length in bytes.
pub const DEFAULT_PIN_MIN_LEN: usize = 8;
/// Default maximum PIN length in bytes.
pub const DEFAULT_PIN_MAX_LEN: usize = 64;

/// Default per-token session limits.
pub const DEFAULT_MAX_SESSIONS: u64 = 100;
/// Default per-token read/write session limit.
pub const DEFAULT_MAX_RW_SESSIONS: u64 = 10;

/// Salt length for all PBKDF2 derivations (bytes).
pub const SALT_LEN: usize = 32;
/// AES-GCM nonce length (bytes).
pub const NONCE_LEN: usize = 12;
/// Symmetric key length used for storage keys (AES-256).
pub const KEY_LEN: usize = 32;

/// KDF identifier recorded alongside every stored PIN verifier / wrapped key
/// so parameters can be migrated later.
pub const KDF_PBKDF2_HMAC_SHA256: &str = "pbkdf2-hmac-sha256";
