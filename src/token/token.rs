// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
#![forbid(unsafe_code)]
//! Token state: initialisation, PIN management, login state, lockout and
//! session accounting.
//!
//! # Concurrency model
//!
//! All authentication state lives in one `auth` mutex. PBKDF2 (hundreds of
//! milliseconds) is **never** run while `auth` is held (H3-09/P1): each
//! authentication runs in three phases — (1) under `auth`: policy checks and
//! a *pre-incremented*, persisted failure counter; (2) without `auth`: PIN
//! stretching; (3) under `auth`: commit, with a PIN-epoch check. A per-role
//! `verify` mutex serialises concurrent attempts for the same account so the
//! rate limit cannot be bypassed by parallel threads, without blocking
//! unrelated calls (C_OpenSession, C_GetTokenInfo, ...).

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::config::defaults::{
    DEFAULT_MAX_FAILED_LOGINS, DEFAULT_MAX_RW_SESSIONS, DEFAULT_MAX_SESSIONS,
    DEFAULT_PBKDF2_ITERATIONS, DEFAULT_PIN_MAX_LEN, DEFAULT_PIN_MIN_LEN, KEY_LEN,
};
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::{CK_SLOT_ID, CK_ULONG};
use crate::store::encrypted_store::{fill_random, EncryptedStore};
use crate::store::lockout_store::LockoutData;
use crate::token::pin::{unwrap_key, wrap_key, PinVerifier};

/// Minimum number of distinct byte values required in a PIN.
const PIN_MIN_DISTINCT_BYTES: usize = 3;
/// Minimum number of character classes (lower, upper, digit, other) required.
/// Only enforced for ASCII-text PINs; binary PINs skip this check.
const PIN_MIN_CHAR_CLASSES: usize = 2;
/// Base delay (ms) after a failed login attempt; doubles with each consecutive failure.
const FAILED_LOGIN_BASE_DELAY_MS: u64 = 100;
/// Maximum delay cap (ms) for exponential backoff on failed logins.
const FAILED_LOGIN_MAX_DELAY_MS: u64 = 5000;

#[derive(Debug, Clone, PartialEq)]
pub enum LoginState {
    Public,
    UserLoggedIn,
    SoLoggedIn,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    User,
    So,
}

/// Persisted token record (per slot). PIN verifiers carry their own KDF
/// parameters; the slot DEK is stored only wrapped under PIN-derived KEKs.
#[derive(Serialize, Deserialize)]
struct TokenRecord {
    version: u32,
    initialized: bool,
    label: String,
    token_id: String,
    so_pin: Option<PinVerifier>,
    user_pin: Option<PinVerifier>,
    wrapped_dek_so: Option<String>,
    wrapped_dek_user: Option<String>,
}

/// Consolidated authentication and initialization state protected by a single
/// mutex.
struct AuthState {
    login: LoginState,
    initialized: bool,
    user_pin_initialized: bool,
    failed_user_logins: u32,
    failed_so_logins: u32,
    /// Failed SO PIN attempts made through `init_token` (informational; they
    /// also count towards `failed_so_logins` and the SO lockout).
    failed_init_token_logins: u32,
    user_pin_locked: bool,
    so_pin_locked: bool,
    /// Earliest time the next user login attempt is allowed (per-account rate limit).
    user_next_allowed: Option<Instant>,
    /// Earliest time the next SO authentication attempt is allowed.
    so_next_allowed: Option<Instant>,
    so_pin: Option<PinVerifier>,
    user_pin: Option<PinVerifier>,
    /// Bumped whenever a PIN verifier changes; phase-3 commits check it.
    pin_epoch: u64,
    /// Random per-token identity (bound into key wrapping and backups).
    token_id: [u8; 16],
    wrapped_dek_so: Option<Vec<u8>>,
    wrapped_dek_user: Option<Vec<u8>>,
    /// Unlocked slot DEK (persistent mode only).
    dek: Option<Zeroizing<[u8; KEY_LEN]>>,
    /// Set by `zeroize_secrets` (C_Finalize): every operation fails afterwards.
    finalized: bool,
}

impl AuthState {
    fn new() -> Self {
        Self {
            login: LoginState::Public,
            initialized: false,
            user_pin_initialized: false,
            failed_user_logins: 0,
            failed_so_logins: 0,
            failed_init_token_logins: 0,
            user_pin_locked: false,
            so_pin_locked: false,
            user_next_allowed: None,
            so_next_allowed: None,
            so_pin: None,
            user_pin: None,
            pin_epoch: 0,
            token_id: [0u8; 16],
            wrapped_dek_so: None,
            wrapped_dek_user: None,
            dek: None,
            finalized: false,
        }
    }

    fn lockout(&self) -> LockoutData {
        LockoutData {
            failed_user_logins: self.failed_user_logins,
            failed_so_logins: self.failed_so_logins,
            failed_init_token_logins: self.failed_init_token_logins,
            user_pin_locked: self.user_pin_locked,
            so_pin_locked: self.so_pin_locked,
        }
    }

    fn failures_mut(&mut self, role: Role) -> (&mut u32, &mut bool, &mut Option<Instant>) {
        match role {
            Role::User => (
                &mut self.failed_user_logins,
                &mut self.user_pin_locked,
                &mut self.user_next_allowed,
            ),
            Role::So => (
                &mut self.failed_so_logins,
                &mut self.so_pin_locked,
                &mut self.so_next_allowed,
            ),
        }
    }
}

/// Snapshot taken in phase 1 of an authentication.
struct AuthAttempt {
    verifier: PinVerifier,
    wrapped_dek: Option<Vec<u8>>,
    epoch: u64,
    token_id: [u8; 16],
}

pub struct Token {
    slot_id: CK_SLOT_ID,
    pub label: RwLock<[u8; 32]>,
    /// All authentication and initialization state under one lock.
    auth: Mutex<AuthState>,
    /// Serialises authentication attempts per role (see module docs).
    user_verify: Mutex<()>,
    so_verify: Mutex<()>,
    session_count: AtomicU64,
    rw_session_count: AtomicU64,
    max_sessions: u64,
    max_rw_sessions: u64,
    pin_min_len: usize,
    pin_max_len: usize,
    max_failed_logins: u32,
    /// PBKDF2 iteration count from config (used for new verifiers).
    pbkdf2_iterations: u32,
    /// Persistent store (token record, lockout counters, DEK keyring).
    store: Option<Arc<EncryptedStore>>,
}

impl Default for Token {
    fn default() -> Self {
        Self::new()
    }
}

impl Token {
    pub fn new() -> Self {
        Self::new_with_config(None)
    }

    /// Create an ephemeral (non-persistent) token for slot 0.
    pub fn new_with_config(config: Option<&crate::config::config::HsmConfig>) -> Self {
        Self::build(config, 0, None)
    }

    fn build(
        config: Option<&crate::config::config::HsmConfig>,
        slot_id: CK_SLOT_ID,
        store: Option<Arc<EncryptedStore>>,
    ) -> Self {
        let mut label = [b' '; 32];
        let label_str = config
            .map(|c| c.token.label.as_str())
            .unwrap_or("Craton HSM Token 0");
        let label_bytes = label_str.as_bytes();
        let copy_len = label_bytes.len().min(32);
        label[..copy_len].copy_from_slice(&label_bytes[..copy_len]);

        Self {
            slot_id,
            label: RwLock::new(label),
            auth: Mutex::new(AuthState::new()),
            user_verify: Mutex::new(()),
            so_verify: Mutex::new(()),
            session_count: AtomicU64::new(0),
            rw_session_count: AtomicU64::new(0),
            max_sessions: config
                .map(|c| c.token.max_sessions)
                .unwrap_or(DEFAULT_MAX_SESSIONS),
            max_rw_sessions: config
                .map(|c| c.token.max_rw_sessions)
                .unwrap_or(DEFAULT_MAX_RW_SESSIONS),
            pin_min_len: config
                .map(|c| c.security.pin_min_length)
                .unwrap_or(DEFAULT_PIN_MIN_LEN),
            pin_max_len: config
                .map(|c| c.security.pin_max_length)
                .unwrap_or(DEFAULT_PIN_MAX_LEN),
            max_failed_logins: config
                .map(|c| c.security.max_failed_logins)
                .unwrap_or(DEFAULT_MAX_FAILED_LOGINS),
            pbkdf2_iterations: config
                .map(|c| c.security.pbkdf2_iterations)
                .unwrap_or(DEFAULT_PBKDF2_ITERATIONS),
            store,
        }
    }

    /// Create a token for `slot_id`, loading its persisted record and lockout
    /// counters from `store` when persistence is enabled (H3-04).
    ///
    /// A persisted, initialised token whose lockout record is missing or
    /// unreadable starts with **both** accounts locked (fail closed, H3-17).
    pub fn open(
        config: &crate::config::config::HsmConfig,
        slot_id: CK_SLOT_ID,
        store: Option<Arc<EncryptedStore>>,
    ) -> HsmResult<Self> {
        let token = Self::build(Some(config), slot_id, store);
        let store = match &token.store {
            Some(s) => s.clone(),
            None => return Ok(token),
        };
        let rec = match store.get_meta(&Self::record_key(slot_id))? {
            Some(bytes) => serde_json::from_slice::<TokenRecord>(&bytes).map_err(|e| {
                tracing::error!("token record for slot {} is corrupt: {}", slot_id, e);
                HsmError::DeviceError
            })?,
            None => return Ok(token),
        };
        {
            let mut auth = token.auth.lock();
            auth.initialized = rec.initialized;
            auth.user_pin_initialized = rec.user_pin.is_some();
            auth.so_pin = rec.so_pin;
            auth.user_pin = rec.user_pin;
            let id = hex::decode(&rec.token_id).map_err(|_| HsmError::DeviceError)?;
            auth.token_id = id.try_into().map_err(|_| HsmError::DeviceError)?;
            auth.wrapped_dek_so = rec
                .wrapped_dek_so
                .map(|h| hex::decode(h).map_err(|_| HsmError::DeviceError))
                .transpose()?;
            auth.wrapped_dek_user = rec
                .wrapped_dek_user
                .map(|h| hex::decode(h).map_err(|_| HsmError::DeviceError))
                .transpose()?;
            let label = hex::decode(&rec.label).map_err(|_| HsmError::DeviceError)?;
            if label.len() == 32 {
                token.label.write().copy_from_slice(&label);
            }
            let lockout = match store.get_meta(&Self::lockout_key(slot_id)) {
                Ok(Some(b)) => serde_json::from_slice::<LockoutData>(&b).ok(),
                _ => None,
            };
            match lockout {
                Some(l) => {
                    auth.failed_user_logins = l.failed_user_logins;
                    auth.failed_so_logins = l.failed_so_logins;
                    auth.failed_init_token_logins = l.failed_init_token_logins;
                    auth.user_pin_locked = l.user_pin_locked;
                    auth.so_pin_locked = l.so_pin_locked;
                }
                None if auth.initialized => {
                    tracing::error!(
                        "lockout record for initialised slot {} missing or corrupt — \
                         locking both accounts (fail closed)",
                        slot_id
                    );
                    auth.user_pin_locked = true;
                    auth.so_pin_locked = true;
                }
                None => {}
            }
        }
        tracing::info!("loaded persisted token state for slot {}", slot_id);
        Ok(token)
    }

    fn record_key(slot: CK_SLOT_ID) -> String {
        format!("token/{}", slot as u64)
    }

    fn lockout_key(slot: CK_SLOT_ID) -> String {
        format!("lockout/{}", slot as u64)
    }

    /// Slot this token belongs to.
    pub fn slot_id(&self) -> CK_SLOT_ID {
        self.slot_id
    }

    /// True when token state is persisted.
    pub fn is_persistent(&self) -> bool {
        self.store.is_some()
    }

    /// Random per-token identity (stable across restarts when persistent;
    /// regenerated by `C_InitToken`). Used to bind backups (H3-16).
    pub fn token_id(&self) -> [u8; 16] {
        self.auth.lock().token_id
    }

    /// PBKDF2 iteration count used for new PIN verifiers.
    pub fn pbkdf2_iterations(&self) -> u32 {
        self.pbkdf2_iterations
    }

    /// Persist the current lockout counters (if persistent). Must be called
    /// with `auth` held. Errors are propagated: an authentication attempt is
    /// refused if its failure cannot be recorded (H3-17).
    fn persist_lockout(&self, auth: &AuthState) -> HsmResult<()> {
        if let Some(store) = &self.store {
            let bytes = serde_json::to_vec(&auth.lockout()).map_err(|_| HsmError::GeneralError)?;
            store.put_meta(&Self::lockout_key(self.slot_id), &bytes)?;
        }
        Ok(())
    }

    fn fresh_lockout_bytes() -> HsmResult<Vec<u8>> {
        serde_json::to_vec(&LockoutData::default()).map_err(|_| HsmError::GeneralError)
    }

    fn persist_record(&self, auth: &AuthState) -> HsmResult<()> {
        if let Some(store) = &self.store {
            let rec = TokenRecord {
                version: 1,
                initialized: auth.initialized,
                label: hex::encode(*self.label.read()),
                token_id: hex::encode(auth.token_id),
                so_pin: auth.so_pin.clone(),
                user_pin: auth.user_pin.clone(),
                wrapped_dek_so: auth.wrapped_dek_so.as_ref().map(hex::encode),
                wrapped_dek_user: auth.wrapped_dek_user.as_ref().map(hex::encode),
            };
            let bytes =
                Zeroizing::new(serde_json::to_vec(&rec).map_err(|_| HsmError::GeneralError)?);
            store.put_meta(&Self::record_key(self.slot_id), &bytes)?;
        }
        Ok(())
    }

    fn dek_aad(&self, role: Role, token_id: &[u8; 16]) -> Vec<u8> {
        let mut aad = b"craton-hsm/dek/v1".to_vec();
        aad.extend_from_slice(&(self.slot_id as u64).to_le_bytes());
        aad.push(match role {
            Role::User => b'U',
            Role::So => b'S',
        });
        aad.extend_from_slice(token_id);
        aad
    }

    fn validate_pin(&self, pin: &[u8]) -> HsmResult<()> {
        if pin.len() < self.pin_min_len || pin.len() > self.pin_max_len {
            return Err(HsmError::PinLenRange);
        }
        // PIN complexity: require minimum distinct byte values
        let mut seen = [false; 256];
        let mut distinct = 0usize;
        let mut has_lower = false;
        let mut has_upper = false;
        let mut has_digit = false;
        let mut has_other = false;
        let mut has_non_ascii = false;
        for &b in pin {
            if !seen[b as usize] {
                seen[b as usize] = true;
                distinct += 1;
            }
            match b {
                b'a'..=b'z' => has_lower = true,
                b'A'..=b'Z' => has_upper = true,
                b'0'..=b'9' => has_digit = true,
                0x20..=0x7E => has_other = true,
                _ => has_non_ascii = true,
            }
        }
        if distinct < PIN_MIN_DISTINCT_BYTES {
            return Err(HsmError::PinInvalid);
        }
        // Character-class check only applies to ASCII-text PINs.
        if !has_non_ascii {
            let class_count = [has_lower, has_upper, has_digit, has_other]
                .iter()
                .filter(|&&c| c)
                .count();
            if class_count < PIN_MIN_CHAR_CLASSES {
                return Err(HsmError::PinInvalid);
            }
        }
        Ok(())
    }

    /// Compute the exponential backoff duration for a given failure count.
    /// Delay = min(base * 2^(failures-1), max_cap).
    fn backoff_duration(failures: u32) -> Duration {
        if failures == 0 {
            return Duration::ZERO;
        }
        let shift = failures.saturating_sub(1).min(31);
        let delay_ms = FAILED_LOGIN_BASE_DELAY_MS.saturating_mul(1u64 << shift);
        Duration::from_millis(delay_ms.min(FAILED_LOGIN_MAX_DELAY_MS))
    }

    fn check_rate_limit(next_allowed: &Option<Instant>) -> HsmResult<()> {
        if let Some(deadline) = next_allowed {
            if Instant::now() < *deadline {
                tracing::warn!("login attempt rejected: rate-limited (backoff window active)");
                return Err(HsmError::PinRateLimited);
            }
        }
        Ok(())
    }

    fn verify_lock(&self, role: Role) -> &Mutex<()> {
        match role {
            Role::User => &self.user_verify,
            Role::So => &self.so_verify,
        }
    }

    /// Phase 1 of an authentication (auth held): lockout / rate-limit checks,
    /// pre-increment and persist the failure counter, snapshot the verifier.
    fn begin_attempt(&self, auth: &mut AuthState, role: Role) -> HsmResult<AuthAttempt> {
        let max = self.max_failed_logins;
        let (failed, locked, next) = auth.failures_mut(role);
        if *locked || *failed >= max {
            *locked = true;
            // Keep advancing the backoff even for locked accounts.
            *next = Some(Instant::now() + Self::backoff_duration(*failed));
            return Err(HsmError::PinLocked);
        }
        Self::check_rate_limit(next)?;
        *failed = failed.saturating_add(1);
        *next = Some(Instant::now() + Self::backoff_duration(*failed));
        self.persist_lockout(auth)?;
        let (verifier, wrapped_dek) = match role {
            Role::User => (auth.user_pin.clone(), auth.wrapped_dek_user.clone()),
            Role::So => (auth.so_pin.clone(), auth.wrapped_dek_so.clone()),
        };
        let verifier = verifier.ok_or(match role {
            Role::User => HsmError::UserPinNotInitialized,
            Role::So => HsmError::PinIncorrect,
        })?;
        Ok(AuthAttempt {
            verifier,
            wrapped_dek,
            epoch: auth.pin_epoch,
            token_id: auth.token_id,
        })
    }

    /// Phase 2 (no lock): verify the PIN and unwrap the DEK when persistent.
    /// Returns `Ok(None)` for a wrong PIN.
    fn verify_attempt(
        &self,
        att: &AuthAttempt,
        role: Role,
        pin: &[u8],
    ) -> HsmResult<Option<Option<Zeroizing<[u8; KEY_LEN]>>>> {
        let kek = match att.verifier.verify(pin) {
            Some(k) => k,
            None => return Ok(None),
        };
        if self.store.is_none() {
            return Ok(Some(None));
        }
        let wrapped = att.wrapped_dek.as_ref().ok_or_else(|| {
            tracing::error!("token record has no wrapped storage key for this role");
            HsmError::DeviceError
        })?;
        let dek = unwrap_key(&kek, wrapped, &self.dek_aad(role, &att.token_id)).map_err(|e| {
            tracing::error!(
                "storage key unwrap failed on slot {} — token record tampered?",
                self.slot_id
            );
            e
        })?;
        Ok(Some(Some(dek)))
    }

    /// Phase 3 failure bookkeeping (auth held).
    fn record_failure(&self, auth: &mut AuthState, role: Role) -> HsmError {
        let max = self.max_failed_logins;
        let (failed, locked, _) = auth.failures_mut(role);
        let failures = *failed;
        if failures >= max {
            *locked = true;
        }
        let locked = *locked;
        if let Err(e) = self.persist_lockout(auth) {
            return e;
        }
        if locked {
            tracing::warn!("PIN locked after {} failed attempts", failures);
            HsmError::PinLocked
        } else {
            tracing::warn!("PIN verification failed (attempt {})", failures);
            HsmError::PinIncorrect
        }
    }

    /// Undo a pre-increment when an attempt is aborted for reasons unrelated
    /// to the PIN (state changed concurrently).
    fn undo_attempt(&self, auth: &mut AuthState, role: Role) {
        let (failed, _, _) = auth.failures_mut(role);
        *failed = failed.saturating_sub(1);
        let _ = self.persist_lockout(auth);
    }

    fn record_success(&self, auth: &mut AuthState, role: Role) -> HsmResult<()> {
        let (failed, _, next) = auth.failures_mut(role);
        *failed = 0;
        *next = None;
        self.persist_lockout(auth)
    }

    fn install_dek(&self, auth: &mut AuthState, dek: Zeroizing<[u8; KEY_LEN]>) {
        if let Some(store) = &self.store {
            store.set_slot_key(self.slot_id, &dek);
        }
        auth.dek = Some(dek);
    }

    pub fn is_initialized(&self) -> bool {
        self.auth.lock().initialized
    }

    pub fn is_user_pin_initialized(&self) -> bool {
        self.auth.lock().user_pin_initialized
    }

    /// Returns a snapshot of the current login state.
    ///
    /// **Warning:** The returned value is a point-in-time snapshot. **Never** use
    /// it for authorization gates. Use [`with_login_state`](Self::with_login_state)
    /// or [`open_session_with`](Self::open_session_with) for atomic
    /// check-and-act.
    pub fn login_state(&self) -> LoginState {
        self.auth.lock().login.clone()
    }

    /// Atomically verify the caller is logged in as the required `expected` state.
    pub fn require_login(&self, expected: &LoginState) -> HsmResult<()> {
        let auth = self.auth.lock();
        if auth.login == *expected {
            Ok(())
        } else if auth.login == LoginState::Public {
            Err(HsmError::UserNotLoggedIn)
        } else {
            Err(HsmError::UserAnotherAlreadyLoggedIn)
        }
    }

    /// Atomically verify login state and execute a closure while holding the
    /// auth lock.
    pub fn with_login_state<F, T>(&self, expected: &LoginState, f: F) -> HsmResult<T>
    where
        F: FnOnce() -> HsmResult<T>,
    {
        let auth = self.auth.lock();
        if auth.login == *expected {
            f()
        } else if auth.login == LoginState::Public {
            Err(HsmError::UserNotLoggedIn)
        } else {
            Err(HsmError::UserAnotherAlreadyLoggedIn)
        }
    }

    pub fn session_count(&self) -> u64 {
        self.session_count.load(Ordering::SeqCst)
    }

    pub fn rw_session_count(&self) -> u64 {
        self.rw_session_count.load(Ordering::SeqCst)
    }

    pub fn max_sessions(&self) -> u64 {
        self.max_sessions
    }

    pub fn max_rw_sessions(&self) -> u64 {
        self.max_rw_sessions
    }

    pub fn pin_min_len(&self) -> CK_ULONG {
        self.pin_min_len as CK_ULONG
    }

    pub fn pin_max_len(&self) -> CK_ULONG {
        self.pin_max_len as CK_ULONG
    }

    /// Build the CK_TOKEN_INFO flags word.
    pub fn flags(&self) -> CK_ULONG {
        use crate::pkcs11_abi::constants::*;
        let mut flags: CK_ULONG = CKF_RNG | CKF_LOGIN_REQUIRED;

        let auth = self.auth.lock();

        if auth.initialized {
            flags |= CKF_TOKEN_INITIALIZED;
        }
        if auth.user_pin_initialized {
            flags |= CKF_USER_PIN_INITIALIZED;
        }
        if auth.user_pin_locked {
            flags |= CKF_USER_PIN_LOCKED;
        }
        if auth.so_pin_locked {
            flags |= CKF_SO_PIN_LOCKED;
        }
        flags
    }

    /// Initialize the token with an SO PIN and label **without** destroying
    /// any objects. Front ends must use [`crate::core::HsmCore::init_token`]
    /// (or [`init_token_with`](Self::init_token_with)) so the slot's objects
    /// are wiped after — and only after — SO authentication.
    pub fn init_token(&self, so_pin: &[u8], label: &[u8; 32]) -> HsmResult<()> {
        self.init_token_with(so_pin, label, || Ok(()))
    }

    /// Initialize (or re-initialize) the token (H1-01/H3-01/H3-14/H3-21).
    ///
    /// Order of operations:
    /// 1. validate the PIN policy (no side effects);
    /// 2. refuse with `SessionExists` while any session is open;
    /// 3. on an initialised token, authenticate the existing SO PIN under the
    ///    SO lockout policy: locked → `PinLocked` (recovery is out-of-band),
    ///    rate-limited, every failure counts towards `max_failed_logins`;
    /// 4. only then: write the new token record (fresh storage key — this
    ///    crypto-shreds all previously persisted objects), call `wipe` to
    ///    destroy the slot's objects, and reset authentication state.
    ///
    /// The auth lock is held during step 4, so no session can be opened
    /// concurrently. Session counters are never reset.
    pub fn init_token_with<F>(&self, so_pin: &[u8], label: &[u8; 32], wipe: F) -> HsmResult<()>
    where
        F: FnOnce() -> HsmResult<()>,
    {
        self.validate_pin(so_pin)?;
        let _v = self.so_verify.lock();

        // Phase 1
        let attempt = {
            let mut auth = self.auth.lock();
            if auth.finalized {
                return Err(HsmError::NotInitialized);
            }
            if self.session_count.load(Ordering::SeqCst) > 0 {
                return Err(HsmError::SessionExists);
            }
            if auth.initialized {
                let att = self.begin_attempt(&mut auth, Role::So)?;
                auth.failed_init_token_logins = auth.failed_init_token_logins.saturating_add(1);
                Some(att)
            } else {
                None
            }
        };

        // Phase 2 (no auth lock): verify existing SO PIN, build new verifier.
        let verified = match &attempt {
            Some(att) => att.verifier.verify(so_pin).is_some(),
            None => true,
        };
        let new_so = if verified {
            Some(PinVerifier::create(so_pin, self.pbkdf2_iterations)?)
        } else {
            None
        };

        // Phase 3
        let mut auth = self.auth.lock();
        if let Some(att) = &attempt {
            if att.epoch != auth.pin_epoch {
                self.undo_attempt(&mut auth, Role::So);
                return Err(HsmError::GeneralError);
            }
        }
        if !verified {
            tracing::warn!("init_token: SO PIN verification failed");
            return Err(self.record_failure(&mut auth, Role::So));
        }
        if self.session_count.load(Ordering::SeqCst) > 0 {
            if attempt.is_some() {
                self.undo_attempt(&mut auth, Role::So);
            }
            return Err(HsmError::SessionExists);
        }
        let (so_verifier, so_kek) = new_so.ok_or(HsmError::GeneralError)?;

        // Build the new state on the side; commit only after persistence.
        let mut token_id = [0u8; 16];
        fill_random(&mut token_id)?;
        let mut new_dek = None;
        let mut wrapped_so = None;
        if self.store.is_some() {
            let mut dek = Zeroizing::new([0u8; KEY_LEN]);
            fill_random(dek.as_mut())?;
            wrapped_so = Some(wrap_key(&so_kek, &dek, &self.dek_aad(Role::So, &token_id))?);
            new_dek = Some(dek);
        }

        let old_label = *self.label.read();
        *self.label.write() = *label;
        let prev = (
            auth.initialized,
            auth.so_pin.clone(),
            auth.user_pin.clone(),
            auth.token_id,
            auth.wrapped_dek_so.clone(),
            auth.wrapped_dek_user.clone(),
        );
        auth.initialized = true;
        auth.so_pin = Some(so_verifier);
        auth.user_pin = None;
        auth.token_id = token_id;
        auth.wrapped_dek_so = wrapped_so;
        auth.wrapped_dek_user = None;
        // Write fresh (zeroed) lockout counters *before* the token record, so
        // a crash in between never leaves an initialised token without a
        // lockout record (which would be treated as locked at next start).
        // Safe: the SO PIN has already been verified at this point.
        let fresh = Self::fresh_lockout_bytes();
        if let (Some(store), Ok(bytes)) = (&self.store, fresh) {
            if let Err(e) = store.put_meta(&Self::lockout_key(self.slot_id), &bytes) {
                *self.label.write() = old_label;
                auth.initialized = prev.0;
                auth.so_pin = prev.1;
                auth.user_pin = prev.2;
                auth.token_id = prev.3;
                auth.wrapped_dek_so = prev.4;
                auth.wrapped_dek_user = prev.5;
                return Err(e);
            }
        }
        if let Err(e) = self.persist_record(&auth) {
            // Roll back the in-memory state: nothing was destroyed.
            *self.label.write() = old_label;
            auth.initialized = prev.0;
            auth.so_pin = prev.1;
            auth.user_pin = prev.2;
            auth.token_id = prev.3;
            auth.wrapped_dek_so = prev.4;
            auth.wrapped_dek_user = prev.5;
            if attempt.is_some() {
                self.undo_attempt(&mut auth, Role::So);
            }
            return Err(e);
        }

        // Destroy the slot's objects (memory + persisted records).
        if let Err(e) = wipe() {
            tracing::error!("init_token: object wipe failed: {:?}", e);
            return Err(e);
        }

        auth.login = LoginState::Public;
        auth.user_pin_initialized = false;
        auth.failed_user_logins = 0;
        auth.failed_so_logins = 0;
        auth.failed_init_token_logins = 0;
        auth.user_pin_locked = false;
        auth.so_pin_locked = false;
        auth.user_next_allowed = None;
        auth.so_next_allowed = None;
        auth.pin_epoch = auth.pin_epoch.wrapping_add(1);
        match new_dek {
            Some(dek) => self.install_dek(&mut auth, dek),
            None => auth.dek = None,
        }
        self.persist_lockout(&auth)?;

        tracing::info!("token on slot {} initialized", self.slot_id);
        Ok(())
    }

    /// Initialize the user PIN (must be logged in as SO). PBKDF2 runs outside
    /// the auth lock; the storage key is wrapped under the new user KEK.
    pub fn init_pin(&self, pin: &[u8]) -> HsmResult<()> {
        {
            let auth = self.auth.lock();
            if auth.finalized {
                return Err(HsmError::NotInitialized);
            }
            if auth.login != LoginState::SoLoggedIn {
                return Err(HsmError::UserNotLoggedIn);
            }
        }
        self.validate_pin(pin)?;
        let (verifier, kek) = PinVerifier::create(pin, self.pbkdf2_iterations)?;

        let mut auth = self.auth.lock();
        if auth.login != LoginState::SoLoggedIn {
            return Err(HsmError::UserNotLoggedIn);
        }
        let wrapped = self.wrap_current_dek(&auth, &kek, Role::User)?;
        let prev = (auth.user_pin.clone(), auth.wrapped_dek_user.clone());
        auth.user_pin = Some(verifier);
        if self.store.is_some() {
            auth.wrapped_dek_user = wrapped;
        }
        if let Err(e) = self.persist_record(&auth) {
            auth.user_pin = prev.0;
            auth.wrapped_dek_user = prev.1;
            return Err(e);
        }
        auth.user_pin_initialized = true;
        auth.failed_user_logins = 0;
        auth.user_pin_locked = false;
        auth.user_next_allowed = None;
        auth.pin_epoch = auth.pin_epoch.wrapping_add(1);
        self.persist_lockout(&auth)?;

        tracing::info!("user PIN initialized by SO");
        Ok(())
    }

    fn wrap_current_dek(
        &self,
        auth: &AuthState,
        kek: &[u8; KEY_LEN],
        role: Role,
    ) -> HsmResult<Option<Vec<u8>>> {
        if self.store.is_none() {
            return Ok(None);
        }
        let dek = auth.dek.as_ref().ok_or_else(|| {
            tracing::error!("storage key not unlocked; cannot re-wrap");
            HsmError::DeviceError
        })?;
        Ok(Some(wrap_key(
            kek,
            dek,
            &self.dek_aad(role, &auth.token_id),
        )?))
    }

    /// Change PIN (user changes own PIN, or SO changes SO PIN).
    ///
    /// The old PIN is verified under the same lockout / rate-limit policy as
    /// `login`; the storage key is re-wrapped under the new PIN's KEK
    /// (re-key on PIN change, H3-15).
    pub fn set_pin(&self, old_pin: &[u8], new_pin: &[u8]) -> HsmResult<()> {
        self.validate_pin(new_pin)?;
        let role = match self.login_state() {
            LoginState::UserLoggedIn => Role::User,
            LoginState::SoLoggedIn => Role::So,
            LoginState::Public => return Err(HsmError::UserNotLoggedIn),
        };
        let _v = self.verify_lock(role).lock();
        let expected = match role {
            Role::User => LoginState::UserLoggedIn,
            Role::So => LoginState::SoLoggedIn,
        };
        let att = {
            let mut auth = self.auth.lock();
            if auth.finalized {
                return Err(HsmError::NotInitialized);
            }
            if auth.login != expected {
                return Err(HsmError::UserNotLoggedIn);
            }
            self.begin_attempt(&mut auth, role)?
        };
        let ok = att.verifier.verify(old_pin).is_some();
        let new = if ok {
            Some(PinVerifier::create(new_pin, self.pbkdf2_iterations)?)
        } else {
            None
        };

        let mut auth = self.auth.lock();
        if att.epoch != auth.pin_epoch || auth.login != expected {
            self.undo_attempt(&mut auth, role);
            return Err(HsmError::UserNotLoggedIn);
        }
        let (verifier, kek) = match new {
            Some(v) => v,
            None => return Err(self.record_failure(&mut auth, role)),
        };
        let wrapped = self.wrap_current_dek(&auth, &kek, role)?;
        let prev = match role {
            Role::User => (auth.user_pin.clone(), auth.wrapped_dek_user.clone()),
            Role::So => (auth.so_pin.clone(), auth.wrapped_dek_so.clone()),
        };
        match role {
            Role::User => {
                auth.user_pin = Some(verifier);
                if self.store.is_some() {
                    auth.wrapped_dek_user = wrapped;
                }
            }
            Role::So => {
                auth.so_pin = Some(verifier);
                if self.store.is_some() {
                    auth.wrapped_dek_so = wrapped;
                }
            }
        }
        if let Err(e) = self.persist_record(&auth) {
            match role {
                Role::User => {
                    auth.user_pin = prev.0;
                    auth.wrapped_dek_user = prev.1;
                }
                Role::So => {
                    auth.so_pin = prev.0;
                    auth.wrapped_dek_so = prev.1;
                }
            }
            return Err(e);
        }
        auth.pin_epoch = auth.pin_epoch.wrapping_add(1);
        self.record_success(&mut auth, role)?;
        tracing::info!(
            "{} PIN changed",
            if role == Role::User { "user" } else { "SO" }
        );
        Ok(())
    }

    /// Login as user type (CKU_USER or CKU_SO).
    ///
    /// Locked accounts are rejected immediately (the lock state is public
    /// via `CKF_*_PIN_LOCKED` anyway) and their backoff deadline still
    /// advances. The failure counter is incremented and persisted *before*
    /// the PIN is checked, so crashing the process mid-attempt cannot reset
    /// it. SO login is refused while read-only sessions exist
    /// (`CKR_SESSION_READ_ONLY_EXISTS`), checked atomically with the session
    /// counters. On success in persistent mode the slot storage key is
    /// unwrapped and installed.
    pub fn login(&self, user_type: CK_ULONG, pin: &[u8]) -> HsmResult<()> {
        use crate::pkcs11_abi::constants::*;
        let role = match user_type {
            CKU_USER => Role::User,
            CKU_SO => Role::So,
            _ => return Err(HsmError::UserTypeInvalid),
        };
        let _v = self.verify_lock(role).lock();

        let precheck = |auth: &AuthState| -> HsmResult<()> {
            if auth.finalized {
                return Err(HsmError::NotInitialized);
            }
            if !auth.initialized {
                return Err(HsmError::TokenNotInitialized);
            }
            match (role, &auth.login) {
                (Role::User, LoginState::UserLoggedIn) | (Role::So, LoginState::SoLoggedIn) => {
                    return Err(HsmError::UserAlreadyLoggedIn)
                }
                (_, LoginState::Public) => {}
                _ => return Err(HsmError::UserAnotherAlreadyLoggedIn),
            }
            if role == Role::User && !auth.user_pin_initialized {
                return Err(HsmError::UserPinNotInitialized);
            }
            if role == Role::So
                && self.session_count.load(Ordering::SeqCst)
                    > self.rw_session_count.load(Ordering::SeqCst)
            {
                return Err(HsmError::SessionReadOnlyExists);
            }
            Ok(())
        };

        // Phase 1
        let att = {
            let mut auth = self.auth.lock();
            precheck(&auth)?;
            self.begin_attempt(&mut auth, role)?
        };

        // Phase 2 (PBKDF2 without the auth lock)
        let verified = self.verify_attempt(&att, role, pin);

        // Phase 3
        let mut auth = self.auth.lock();
        if att.epoch != auth.pin_epoch {
            self.undo_attempt(&mut auth, role);
            return Err(HsmError::GeneralError);
        }
        if let Err(e) = precheck(&auth) {
            self.undo_attempt(&mut auth, role);
            return Err(e);
        }
        let dek = match verified {
            Ok(Some(dek)) => dek,
            Ok(None) => return Err(self.record_failure(&mut auth, role)),
            // Storage key unwrap failed: counts as a failure, fail closed.
            Err(e) => {
                let _ = self.record_failure(&mut auth, role);
                return Err(e);
            }
        };
        self.record_success(&mut auth, role)?;
        if let Some(dek) = dek {
            self.install_dek(&mut auth, dek);
        }
        auth.login = match role {
            Role::User => LoginState::UserLoggedIn,
            Role::So => LoginState::SoLoggedIn,
        };
        tracing::info!(
            "{} login succeeded on slot {}",
            if role == Role::User { "user" } else { "SO" },
            self.slot_id
        );
        Ok(())
    }

    pub fn logout(&self) -> HsmResult<()> {
        let mut auth = self.auth.lock();
        if auth.login == LoginState::Public {
            return Err(HsmError::UserNotLoggedIn);
        }
        tracing::info!("logout from {:?}", auth.login);
        auth.login = LoginState::Public;
        Ok(())
    }

    /// Atomically open a session (H3-08): under the auth lock, enforce the
    /// SO/RO rule and the session limits, increment the counters and call
    /// `f` with the current login state so the new session is created *and
    /// inserted* before any concurrent login/logout can run. Counters are
    /// rolled back if `f` fails.
    pub fn open_session_with<T>(
        &self,
        rw: bool,
        f: impl FnOnce(&LoginState) -> HsmResult<T>,
    ) -> HsmResult<T> {
        let auth = self.auth.lock();
        if auth.finalized {
            return Err(HsmError::NotInitialized);
        }
        if !rw && auth.login == LoginState::SoLoggedIn {
            return Err(HsmError::SessionReadWriteSoExists);
        }
        self.increment_locked(rw)?;
        match f(&auth.login) {
            Ok(v) => Ok(v),
            Err(e) => {
                self.decrement_locked(rw);
                Err(e)
            }
        }
    }

    fn increment_locked(&self, rw: bool) -> HsmResult<()> {
        let current = self.session_count.load(Ordering::SeqCst);
        if current >= self.max_sessions {
            return Err(HsmError::SessionCount);
        }
        if rw && self.rw_session_count.load(Ordering::SeqCst) >= self.max_rw_sessions {
            return Err(HsmError::SessionCount);
        }
        self.session_count.store(current + 1, Ordering::SeqCst);
        if rw {
            self.rw_session_count.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }

    fn decrement_locked(&self, rw: bool) -> bool {
        let current = self.session_count.load(Ordering::SeqCst);
        if current == 0 {
            return false;
        }
        if rw {
            let rw_current = self.rw_session_count.load(Ordering::SeqCst);
            if rw_current == 0 {
                return false;
            }
            self.rw_session_count
                .store(rw_current - 1, Ordering::SeqCst);
        }
        self.session_count.store(current - 1, Ordering::SeqCst);
        true
    }

    /// Atomically increment session count (prefer
    /// [`open_session_with`](Self::open_session_with)).
    pub fn increment_session_count(&self, rw: bool) -> HsmResult<()> {
        let _auth = self.auth.lock();
        self.increment_locked(rw)
    }

    /// Atomically decrement session count. When the last session of the
    /// token closes, the token returns to the public state (PKCS#11 §5.6,
    /// H1-06): a later session must log in again. Returns `Err` on underflow
    /// (double-close).
    pub fn decrement_session_count(&self, rw: bool) -> HsmResult<()> {
        let mut auth = self.auth.lock();
        if !self.decrement_locked(rw) {
            tracing::error!("decrement_session_count: count already 0 — possible double-close bug");
            return Err(HsmError::GeneralError);
        }
        if self.session_count.load(Ordering::SeqCst) == 0 && auth.login != LoginState::Public {
            tracing::info!(
                "last session on slot {} closed — logging token out",
                self.slot_id
            );
            auth.login = LoginState::Public;
        }
        Ok(())
    }

    /// Reset both session counters to zero.
    pub fn reset_session_counts(&self) {
        let mut auth = self.auth.lock();
        self.rw_session_count.store(0, Ordering::SeqCst);
        self.session_count.store(0, Ordering::SeqCst);
        auth.login = LoginState::Public;
    }

    /// Zeroize PIN verifiers and the unlocked storage key and make the token
    /// unusable (C_Finalize, A1-10).
    pub fn zeroize_secrets(&self) {
        let mut auth = self.auth.lock();
        auth.so_pin = None;
        auth.user_pin = None;
        auth.dek = None;
        auth.wrapped_dek_so = None;
        auth.wrapped_dek_user = None;
        auth.login = LoginState::Public;
        auth.finalized = true;
        if let Some(store) = &self.store {
            store.clear_slot_key(self.slot_id);
        }
    }
}
