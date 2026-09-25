// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Core HSM state — the central struct shared by C ABI, daemon, and admin CLI.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::audit::log::{AuditLog, AuditOperation, AuditResult};
use crate::config::{AlgorithmConfig, HsmConfig};
use crate::crypto::backend::CryptoBackend;
use crate::crypto::drbg::HmacDrbg;
#[cfg(feature = "rustcrypto-backend")]
use crate::crypto::rustcrypto_backend::RustCryptoBackend;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::{
    CK_FLAGS, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG,
};
use crate::session::manager::{ApplicationId, SessionManager, PROCESS_APPLICATION};
use crate::store::attributes::{ObjectContext, ObjectOrigin, ObjectStore, ZeroizingObjects};
use crate::store::encrypted_store::EncryptedStore;
use crate::store::object::StoredObject;
use crate::token::slot::SlotManager;
use zeroize::Zeroizing;

/// The global HSM state. Holds all managers needed for PKCS#11 operations.
pub struct HsmCore {
    pub(crate) slot_manager: SlotManager,
    pub(crate) session_manager: SessionManager,
    pub(crate) object_store: ObjectStore,
    pub(crate) audit_log: AuditLog,
    pub(crate) crypto_backend: Arc<dyn CryptoBackend>,
    /// SP 800-90A HMAC_DRBG instance for FIPS-compliant random number generation.
    pub(crate) drbg: parking_lot::Mutex<HmacDrbg>,
    /// Algorithm policy configuration (FIPS approved mode, PQC enable, weak RSA, etc.).
    /// Stored at runtime so crypto operations can enforce policy checks.
    pub(crate) algorithm_config: AlgorithmConfig,
    /// Token serial number (configurable, 16-char space-padded).
    pub(crate) serial_number: [u8; 16],
    /// Per-instance HMAC key for authenticating serialized operation state blobs
    /// (C_GetOperationState / C_SetOperationState). Generated randomly at init
    /// time to prevent callers from tampering with saved state (e.g., swapping
    /// key handles or mechanisms).
    pub(crate) state_hmac_key: Zeroizing<[u8; 32]>,
    /// Encrypted persistent store (token records + token objects) when
    /// `token.persist_objects = true`.
    pub(crate) persistent_store: Option<Arc<EncryptedStore>>,
    /// Set by [`HsmCore::finalize`]; the core must not be used afterwards.
    finalized: AtomicBool,
}

impl HsmCore {
    /// Build a 16-byte space-padded serial number from config string.
    fn make_serial(config: &HsmConfig) -> [u8; 16] {
        let mut serial = [b' '; 16];
        let s = config.token.serial_number.as_bytes();
        let len = s.len().min(16);
        serial[..len].copy_from_slice(&s[..len]);
        serial
    }

    /// Select the crypto backend based on config + compiled features.
    ///
    /// The built-in RustCrypto backend is the default. External backends
    /// (e.g., the FIPS-validated aws-lc-rs backend in `craton_hsm-awslc`)
    /// can be injected via [`HsmCore::new_with_backend`].
    fn select_crypto_backend(config: &HsmConfig) -> Arc<dyn CryptoBackend> {
        let requested = config.algorithms.crypto_backend.as_str();

        match requested {
            #[cfg(feature = "awslc-backend")]
            "awslc" => return Arc::new(crate::crypto::awslc_backend::AwsLcBackend),

            #[cfg(not(feature = "awslc-backend"))]
            "awslc" => {
                tracing::warn!(
                    "Config requests 'awslc' backend but awslc-backend feature not compiled. \
                     Use HsmCore::new_with_backend() to inject it. \
                     Falling back to rustcrypto."
                );
            }

            #[cfg(feature = "rustcrypto-backend")]
            "rustcrypto" => return Arc::new(RustCryptoBackend),

            #[cfg(not(feature = "rustcrypto-backend"))]
            "rustcrypto" => {
                tracing::warn!(
                    "Config requests 'rustcrypto' backend but rustcrypto-backend feature not compiled; falling back"
                );
            }

            other => {
                tracing::warn!(
                    "Unknown crypto_backend '{}' in config; using default",
                    other
                );
            }
        }

        // Fallback: prefer awslc-backend if compiled, else rustcrypto
        #[cfg(feature = "awslc-backend")]
        {
            return Arc::new(crate::crypto::awslc_backend::AwsLcBackend);
        }

        #[cfg(all(feature = "rustcrypto-backend", not(feature = "awslc-backend")))]
        {
            return Arc::new(RustCryptoBackend);
        }

        #[cfg(not(any(feature = "rustcrypto-backend", feature = "awslc-backend")))]
        {
            compile_error!(
                "No crypto backend available. Enable the `rustcrypto-backend` or \
                          `awslc-backend` feature, or inject a custom backend via \
                          HsmCore::new_with_backend()."
            );
        }
    }

    /// Create a new HsmCore from a loaded configuration.
    ///
    /// # Panics
    ///
    /// Panics if construction fails (DRBG, persistent store or audit log).
    /// Use [`HsmCore::open`] / [`HsmCore::try_new`] for a fallible alternative.
    pub fn new(config: &HsmConfig) -> Self {
        Self::try_new(config).expect("HsmCore construction failed (see logs)")
    }

    /// Generate a random 32-byte key for HMAC-binding operation state blobs.
    fn generate_state_hmac_key() -> Result<Zeroizing<[u8; 32]>, HsmError> {
        let mut key = Zeroizing::new([0u8; 32]);
        crate::store::encrypted_store::fill_random(key.as_mut())?;
        Ok(key)
    }

    /// Open the HSM described by `config`, **including its persistent state**.
    ///
    /// This is the constructor the daemon and the admin CLI must use
    /// (H4-03/H5-02). When `token.persist_objects = true` it:
    ///
    /// * creates/validates the private storage directory `token.storage_path`
    ///   (mode 0700, owned by the service account) and opens the encrypted
    ///   store `craton_hsm.redb` under an exclusive process lock;
    /// * loads each slot's token record (initialised flag, label, PIN
    ///   verifiers with their KDF parameters, wrapped storage keys) and its
    ///   lockout counters — a restart no longer re-opens `C_InitToken`;
    /// * loads a slot's token objects after the first successful login on
    ///   that slot (the storage key is wrapped under the PIN-derived KEKs).
    ///
    /// With `persist_objects = false` the token is **ephemeral**: all token
    /// state and objects are lost when the process exits.
    ///
    /// Fails if the audit log reports a broken chain, unless
    /// `audit.allow_start_with_broken_chain = true` (H3-11).
    pub fn open(config: &HsmConfig) -> Result<Self, HsmError> {
        Self::try_new(config)
    }

    /// Fallible constructor — see [`HsmCore::open`].
    pub fn try_new(config: &HsmConfig) -> Result<Self, HsmError> {
        Self::build(config, Self::select_crypto_backend(config))
    }

    /// Create a new HsmCore with an externally-provided crypto backend.
    ///
    /// # Panics
    ///
    /// Panics if construction fails. Use [`HsmCore::try_new_with_backend`]
    /// for a fallible alternative.
    pub fn new_with_backend(config: &HsmConfig, backend: Arc<dyn CryptoBackend>) -> Self {
        Self::try_new_with_backend(config, backend).expect("HsmCore construction failed")
    }

    /// Fallible constructor with an externally-provided crypto backend.
    pub fn try_new_with_backend(
        config: &HsmConfig,
        backend: Arc<dyn CryptoBackend>,
    ) -> Result<Self, HsmError> {
        Self::build(config, backend)
    }

    fn build(config: &HsmConfig, backend: Arc<dyn CryptoBackend>) -> Result<Self, HsmError> {
        let drbg = HmacDrbg::new().map_err(|_| HsmError::GeneralError)?;

        let persistent_store = if config.token.persist_objects {
            let store = EncryptedStore::open_in_dir(&config.token.storage_path)?;
            tracing::info!(
                "persistent token store opened at {}",
                config.token.storage_path.display()
            );
            Some(Arc::new(store))
        } else {
            tracing::warn!(
                "token.persist_objects = false: token state and objects are EPHEMERAL — \
                 the token is uninitialised after every restart. Enable persistence \
                 for production deployments."
            );
            None
        };

        let slot_manager = SlotManager::open(config, persistent_store.clone())?;
        let object_store = match &persistent_store {
            Some(s) => ObjectStore::with_shared_persistence(s.clone()),
            None => ObjectStore::new(),
        };

        let audit_log = AuditLog::from_config(&config.audit)?;
        if audit_log.is_tamper_detected() && !config.audit.allow_start_with_broken_chain {
            tracing::error!(
                "audit log integrity check failed — refusing to start \
                 (set audit.allow_start_with_broken_chain = true to override after investigation)"
            );
            return Err(HsmError::AuditChainBroken(
                "audit log integrity check failed at startup".to_string(),
            ));
        }

        let max_per_app = usize::try_from(config.token.max_sessions_per_application)
            .unwrap_or(usize::MAX);

        Ok(Self {
            slot_manager,
            session_manager: SessionManager::with_app_limit(max_per_app),
            object_store,
            audit_log,
            crypto_backend: backend,
            drbg: parking_lot::Mutex::new(drbg),
            algorithm_config: config.algorithms.clone(),
            serial_number: Self::make_serial(config),
            state_hmac_key: Self::generate_state_hmac_key()?,
            persistent_store,
            finalized: AtomicBool::new(false),
        })
    }

    /// Create with default configuration.
    ///
    /// Returns an error if the config file is present but malformed, or if
    /// any security parameter fails validation.
    pub fn new_default() -> Result<Self, HsmError> {
        let config = HsmConfig::load()?;
        Self::try_new(&config)
    }

    // ========================================================================
    // Token / session lifecycle services shared by every front end.
    // ========================================================================

    fn audit(&self, session: u64, op: AuditOperation, result: &HsmResult<()>) -> HsmResult<()> {
        let res = match result {
            Ok(()) => AuditResult::Success,
            Err(e) => AuditResult::Failure(CK_RV::from(e.clone()) as u64),
        };
        self.audit_log.record_sync(session, op, res, None)
    }

    fn check_live(&self) -> HsmResult<()> {
        if self.finalized.load(Ordering::Acquire) {
            return Err(HsmError::NotInitialized);
        }
        Ok(())
    }

    /// `C_InitToken` semantics for every front end (H1-01/H3-01/H3-14).
    ///
    /// Refuses with `SessionExists` while sessions are open on the slot,
    /// authenticates the existing SO PIN under the SO lockout policy, and
    /// only then destroys the slot's objects (memory and persistent store;
    /// other slots are untouched) and resets the token. The operation is
    /// audited synchronously.
    pub fn init_token(&self, slot_id: CK_SLOT_ID, so_pin: &[u8], label: &[u8; 32]) -> HsmResult<()> {
        self.check_live()?;
        let token = self.slot_manager.get_token(slot_id)?;
        let result = if self.session_manager.has_sessions(slot_id) {
            Err(HsmError::SessionExists)
        } else {
            token.init_token_with(so_pin, label, || {
                let n = self.object_store.clear_slot(slot_id)?;
                self.object_store.mark_slot_loaded(slot_id);
                tracing::info!("C_InitToken: destroyed {} object(s) on slot {}", n, slot_id);
                Ok(())
            })
        };
        let audit = self.audit(
            0,
            AuditOperation::InitToken {
                slot_id: slot_id as u64,
            },
            &result,
        );
        result?;
        audit
    }

    /// `C_InitPIN` (SO session required), audited.
    pub fn init_pin(&self, session: CK_SESSION_HANDLE, pin: &[u8]) -> HsmResult<()> {
        self.check_live()?;
        let sess = self.session_manager.get_session(session)?;
        let (slot, is_so) = {
            let s = sess.read();
            (s.slot_id, s.state.is_so())
        };
        let result = if !is_so {
            Err(HsmError::UserNotLoggedIn)
        } else {
            self.slot_manager.get_token(slot)?.init_pin(pin)
        };
        let audit = self.audit(
            session as u64,
            AuditOperation::InitPin {
                slot_id: slot as u64,
            },
            &result,
        );
        result?;
        audit
    }

    /// `C_SetPIN`, audited. Re-wraps the slot storage key (persistent mode).
    pub fn set_pin(
        &self,
        session: CK_SESSION_HANDLE,
        old_pin: &[u8],
        new_pin: &[u8],
    ) -> HsmResult<()> {
        self.check_live()?;
        let sess = self.session_manager.get_session(session)?;
        let (slot, rw) = {
            let s = sess.read();
            (s.slot_id, s.is_rw())
        };
        let result = if !rw {
            Err(HsmError::SessionReadOnly)
        } else {
            self.slot_manager.get_token(slot)?.set_pin(old_pin, new_pin)
        };
        let audit = self.audit(
            session as u64,
            AuditOperation::SetPin {
                slot_id: slot as u64,
            },
            &result,
        );
        result?;
        audit
    }

    /// `C_OpenSession` for application `app` (per-application caps).
    pub fn open_session(
        &self,
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
        app: ApplicationId,
    ) -> HsmResult<CK_SESSION_HANDLE> {
        self.check_live()?;
        let token = self.slot_manager.get_token(slot_id)?;
        let handle = self
            .session_manager
            .open_session_for_app(slot_id, flags, &token, app)?;
        let _ = self.audit_log.record(
            handle as u64,
            AuditOperation::OpenSession {
                slot_id: slot_id as u64,
            },
            AuditResult::Success,
            None,
        );
        Ok(handle)
    }

    /// `C_CloseSession`: closes the session, destroys its session objects
    /// (H3-07) and — when it was the last session — logs the token out
    /// (H1-06).
    pub fn close_session(&self, session: CK_SESSION_HANDLE) -> HsmResult<()> {
        let slot = self.session_manager.get_session(session)?.read().slot_id;
        let token = self.slot_manager.get_token(slot)?;
        self.session_manager.close_session(session, &token)?;
        self.object_store.destroy_session_objects(session);
        let _ = self.audit_log.record(
            session as u64,
            AuditOperation::CloseSession,
            AuditResult::Success,
            None,
        );
        Ok(())
    }

    /// `C_CloseAllSessions`: closes every session of the slot, destroys their
    /// session objects and logs the token out.
    pub fn close_all_sessions(&self, slot_id: CK_SLOT_ID) -> HsmResult<()> {
        let token = self.slot_manager.get_token(slot_id)?;
        for h in self.session_manager.close_all_sessions(slot_id, &token) {
            self.object_store.destroy_session_objects(h);
            let _ = self.audit_log.record(
                h as u64,
                AuditOperation::CloseSession,
                AuditResult::Success,
                None,
            );
        }
        Ok(())
    }

    /// `C_Login` for every front end: authenticates, promotes all sessions of
    /// the slot and, in persistent mode, loads the slot's token objects. If
    /// any step after the token login fails, the login is rolled back so
    /// token and session states never diverge (H3-21/H1-19).
    pub fn login(&self, session: CK_SESSION_HANDLE, user_type: CK_ULONG, pin: &[u8]) -> HsmResult<()> {
        self.check_live()?;
        let slot = self.session_manager.get_session(session)?.read().slot_id;
        let token = self.slot_manager.get_token(slot)?;
        let result = (|| {
            token.login(user_type, pin)?;
            let post = self
                .session_manager
                .login_all(slot, user_type)
                .and_then(|_| self.object_store.load_slot(slot).map(|_| ()));
            if let Err(e) = post {
                tracing::error!("login post-processing failed on slot {}: {:?}", slot, e);
                let _ = token.logout();
                let _ = self.session_manager.logout_all(slot);
                return Err(e);
            }
            Ok(())
        })();
        let audit = self.audit(
            session as u64,
            AuditOperation::Login {
                user_type: user_type as u64,
            },
            &result,
        );
        result?;
        audit
    }

    /// `C_Logout`.
    pub fn logout(&self, session: CK_SESSION_HANDLE) -> HsmResult<()> {
        let slot = self.session_manager.get_session(session)?.read().slot_id;
        let token = self.slot_manager.get_token(slot)?;
        token.logout()?;
        let r = self.session_manager.logout_all(slot);
        let _ = self.audit_log.record(
            session as u64,
            AuditOperation::Logout,
            AuditResult::Success,
            None,
        );
        r
    }

    /// Hex-encoded random per-token identity used to bind backups (H3-16).
    pub fn token_binding(&self, slot_id: CK_SLOT_ID) -> HsmResult<String> {
        Ok(hex::encode(self.slot_manager.get_token(slot_id)?.token_id()))
    }

    /// Export the token objects of an initialised slot for backup.
    pub fn export_token_objects(&self, slot_id: CK_SLOT_ID) -> HsmResult<ZeroizingObjects> {
        self.check_live()?;
        let token = self.slot_manager.get_token(slot_id)?;
        if !token.is_initialized() {
            return Err(HsmError::TokenNotInitialized);
        }
        Ok(self.object_store.export_slot_objects(slot_id))
    }

    /// Import restored objects into a slot as token objects with freshly
    /// allocated handles (H3-16). Returns the new handles.
    pub fn import_objects(
        &self,
        slot_id: CK_SLOT_ID,
        objects: Vec<StoredObject>,
    ) -> HsmResult<Vec<CK_OBJECT_HANDLE>> {
        self.check_live()?;
        self.slot_manager.get_token(slot_id)?;
        let ctx = ObjectContext::admin(slot_id);
        let mut handles = Vec::with_capacity(objects.len());
        for mut obj in objects {
            obj.handle = self.object_store.next_handle()?;
            obj.token_object = true;
            handles.push(
                self.object_store
                    .insert_object_in(obj, &ctx, ObjectOrigin::Restored)?,
            );
        }
        Ok(handles)
    }

    /// Zeroize all key material, PIN verifiers and storage keys and close
    /// every session (C_Finalize, A1-10). Persistent records are kept. The
    /// core refuses further use afterwards.
    pub fn finalize(&self) {
        if self.finalized.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self
            .audit_log
            .record(0, AuditOperation::Finalize, AuditResult::Success, None);
        for h in self.session_manager.drain_all() {
            self.object_store.destroy_session_objects(h);
        }
        for token in self.slot_manager.tokens() {
            token.zeroize_secrets();
        }
        self.object_store.evict_all();
        crate::crypto::sign::clear_rsa_key_cache();
        if let Some(store) = &self.persistent_store {
            store.clear_all_keys();
        }
        self.audit_log.flush();
    }

    /// True once [`finalize`](Self::finalize) has run.
    pub fn is_finalized(&self) -> bool {
        self.finalized.load(Ordering::Acquire)
    }

    /// Open a session for the in-process application (convenience).
    pub fn open_process_session(
        &self,
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
    ) -> HsmResult<CK_SESSION_HANDLE> {
        self.open_session(slot_id, flags, PROCESS_APPLICATION)
    }

    // ========================================================================
    // Public accessors for external workspace crates (daemon, admin CLI).
    // Internal code (pkcs11_abi) uses pub(crate) field access directly.
    // ========================================================================

    /// Returns a reference to the slot manager.
    pub fn slot_manager(&self) -> &SlotManager {
        &self.slot_manager
    }

    /// Returns a reference to the session manager.
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Returns a reference to the object store.
    pub fn object_store(&self) -> &ObjectStore {
        &self.object_store
    }

    /// Returns a reference to the audit log.
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Returns a reference to the active crypto backend.
    pub fn crypto_backend(&self) -> &Arc<dyn CryptoBackend> {
        &self.crypto_backend
    }

    /// Returns a reference to the algorithm configuration.
    pub fn algorithm_config(&self) -> &AlgorithmConfig {
        &self.algorithm_config
    }

    /// Returns a reference to the HMAC_DRBG instance (SP 800-90A).
    pub fn drbg(&self) -> &parking_lot::Mutex<HmacDrbg> {
        &self.drbg
    }
}

impl Drop for HsmCore {
    fn drop(&mut self) {
        // Zeroize keys and PIN verifiers even if C_Finalize was not called.
        self.finalize();
    }
}
