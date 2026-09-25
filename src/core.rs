// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Core HSM state — the central struct shared by C ABI, daemon, and admin CLI.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::audit::log::{AuditLog, AuditOperation, AuditResult};
use crate::config::{AlgorithmConfig, HsmConfig};
use crate::crypto::backend::CryptoBackend;
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
    /// Consumed backup IDs per slot for an **ephemeral** core (persistent
    /// cores keep them authenticated in the store, H5-06).
    ephemeral_backup_ids: parking_lot::Mutex<HashMap<CK_SLOT_ID, HashSet<String>>>,
    /// Minimum PBKDF2 iteration count accepted from a backup header.
    pbkdf2_iterations: u32,
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

        let max_per_app =
            usize::try_from(config.token.max_sessions_per_application).unwrap_or(usize::MAX);

        Ok(Self {
            slot_manager,
            session_manager: SessionManager::with_app_limit(max_per_app),
            object_store,
            audit_log,
            crypto_backend: backend,
            algorithm_config: config.algorithms.clone(),
            serial_number: Self::make_serial(config),
            state_hmac_key: Self::generate_state_hmac_key()?,
            persistent_store,
            finalized: AtomicBool::new(false),
            ephemeral_backup_ids: parking_lot::Mutex::new(HashMap::new()),
            pbkdf2_iterations: config.security.pbkdf2_iterations,
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
        self.audit_as(session, op, result, None)
    }

    fn audit_as(
        &self,
        session: u64,
        op: AuditOperation,
        result: &HsmResult<()>,
        actor: Option<&str>,
    ) -> HsmResult<()> {
        let res = match result {
            Ok(()) => AuditResult::Success,
            Err(e) => AuditResult::Failure(CK_RV::from(e.clone()) as u64),
        };
        self.audit_log
            .record_sync(session, op, res, actor.map(str::to_string))
    }

    fn check_live(&self) -> HsmResult<()> {
        if self.finalized.load(Ordering::Acquire) {
            return Err(HsmError::NotInitialized);
        }
        // audit.fail_closed: refuse security-relevant operations once the
        // audit trail can no longer be written (H3-11).
        self.audit_log.check_healthy()
    }

    /// `C_InitToken` semantics for every front end (H1-01/H3-01/H3-14).
    ///
    /// Refuses with `SessionExists` while sessions are open on the slot,
    /// authenticates the existing SO PIN under the SO lockout policy, and
    /// only then destroys the slot's objects (memory and persistent store;
    /// other slots are untouched) and resets the token. The operation is
    /// audited synchronously.
    pub fn init_token(
        &self,
        slot_id: CK_SLOT_ID,
        so_pin: &[u8],
        label: &[u8; 32],
    ) -> HsmResult<()> {
        self.init_token_by(slot_id, so_pin, label, None)
    }

    /// [`init_token`](Self::init_token) with an actor description recorded
    /// in the audit event (front ends that authenticate their callers: the
    /// daemon's client identity, the admin CLI's OS user).
    pub fn init_token_by(
        &self,
        slot_id: CK_SLOT_ID,
        so_pin: &[u8],
        label: &[u8; 32],
        actor: Option<&str>,
    ) -> HsmResult<()> {
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
        let audit = self.audit_as(
            0,
            AuditOperation::InitToken {
                slot_id: slot_id as u64,
            },
            &result,
            actor,
        );
        result?;
        audit
    }

    /// Verify a PIN without logging the token in (per-client login models,
    /// H4-01): lockout, rate limiting and PBKDF2-outside-the-lock as for
    /// `C_Login`; in persistent mode the slot storage key is unlocked and the
    /// slot's token objects are loaded. **Not audited** — the caller records
    /// the login with its own client attribution.
    pub fn verify_pin(
        &self,
        slot_id: CK_SLOT_ID,
        user_type: CK_ULONG,
        pin: &[u8],
    ) -> HsmResult<()> {
        self.check_live()?;
        let token = self.slot_manager.get_token(slot_id)?;
        token.verify_pin(user_type, pin)?;
        self.object_store.load_slot(slot_id).map(|_| ())
    }

    /// `C_InitPIN` for front ends that authenticate the SO per request
    /// (H4-01): verifies the SO PIN under the SO lockout policy and sets the
    /// user PIN atomically, without changing the token's login state. Audited
    /// as [`AuditOperation::InitPin`] with `actor` attribution.
    pub fn init_pin_with_so_pin(
        &self,
        slot_id: CK_SLOT_ID,
        so_pin: &[u8],
        new_pin: &[u8],
        actor: Option<&str>,
    ) -> HsmResult<()> {
        self.check_live()?;
        let token = self.slot_manager.get_token(slot_id)?;
        let result = token.init_pin_with_so_pin(so_pin, new_pin);
        let audit = self.audit_as(
            0,
            AuditOperation::InitPin {
                slot_id: slot_id as u64,
            },
            &result,
            actor,
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
    pub fn login(
        &self,
        session: CK_SESSION_HANDLE,
        user_type: CK_ULONG,
        pin: &[u8],
    ) -> HsmResult<()> {
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
        Ok(hex::encode(
            self.slot_manager.get_token(slot_id)?.token_id(),
        ))
    }

    /// Export the token objects of an initialised slot for backup.
    ///
    /// The slot must have been unlocked by a login (so persisted objects are
    /// loaded). Unless `include_non_extractable` is set, secret and private
    /// keys with `CKA_EXTRACTABLE=FALSE` are **not** exported, so the backup
    /// path does not bypass the object export policy (A1-17); the number of
    /// skipped keys is logged.
    pub fn export_token_objects(
        &self,
        slot_id: CK_SLOT_ID,
        include_non_extractable: bool,
    ) -> HsmResult<ZeroizingObjects> {
        self.check_live()?;
        let token = self.slot_manager.get_token(slot_id)?;
        if !token.is_initialized() {
            return Err(HsmError::TokenNotInitialized);
        }
        let all = self.object_store.export_slot_objects(slot_id).into_inner();
        let total = all.len();
        let kept: Vec<StoredObject> = all
            .into_iter()
            .filter(|o| {
                include_non_extractable
                    || !crate::store::object::is_secret_class(o.class)
                    || o.extractable
            })
            .collect();
        if kept.len() != total {
            tracing::warn!(
                "backup export: skipped {} non-extractable key(s) on slot {}",
                total - kept.len(),
                slot_id
            );
        }
        Ok(ZeroizingObjects::new(kept))
    }

    /// Import restored objects into a slot as token objects with freshly
    /// allocated handles (H3-16). Returns the new handles.
    ///
    /// All-or-nothing: the objects are persisted in one store transaction
    /// (P8) and only then made visible; on any error nothing was imported
    /// (H5-02/H5-04). In persistent mode the slot must have been unlocked by
    /// a login (or [`verify_pin`](Self::verify_pin)).
    pub fn import_objects(
        &self,
        slot_id: CK_SLOT_ID,
        objects: Vec<StoredObject>,
    ) -> HsmResult<Vec<CK_OBJECT_HANDLE>> {
        self.check_live()?;
        let token = self.slot_manager.get_token(slot_id)?;
        if !token.is_initialized() {
            return Err(HsmError::TokenNotInitialized);
        }
        let ctx = ObjectContext::admin(slot_id);
        let mut objs = ZeroizingObjects::new(objects).into_inner();
        for obj in objs.iter_mut() {
            obj.handle = self.object_store.next_handle()?;
            obj.token_object = true;
        }
        self.object_store
            .insert_objects_in(objs, &ctx, ObjectOrigin::Restored)
    }

    /// Create an encrypted backup of the token objects of `slot` (admin CLI /
    /// daemon backup service). The backup is bound to the per-token random
    /// identity ([`token_binding`](Self::token_binding), H3-16), encrypted
    /// under `passphrase` (PBKDF2 with the configured iteration count) and
    /// excludes non-extractable keys unless `include_non_extractable`
    /// (A1-17). Audited synchronously as [`AuditOperation::BackupExport`].
    ///
    /// The **caller must have authenticated the SO** (or the user, by
    /// policy) for this slot; in persistent mode the slot must be unlocked.
    /// Returns the backup blob and the number of exported objects.
    pub fn export_backup(
        &self,
        slot_id: CK_SLOT_ID,
        passphrase: &str,
        include_non_extractable: bool,
        actor: Option<&str>,
    ) -> HsmResult<(Vec<u8>, usize)> {
        let result = (|| {
            self.require_unlocked(slot_id)?;
            let objects = self.export_token_objects(slot_id, include_non_extractable)?;
            let binding = self.token_binding(slot_id)?;
            let blob = crate::store::backup::create_backup(
                &objects,
                passphrase,
                &binding,
                Some(self.pbkdf2_iterations),
            )?;
            Ok((blob, objects.len()))
        })();
        let count = result.as_ref().map(|(_, n)| *n as u64).unwrap_or(0);
        self.audit_as(
            0,
            AuditOperation::BackupExport {
                slot_id: slot_id as u64,
                object_count: count,
            },
            &result.as_ref().map(|_| ()).map_err(Clone::clone),
            actor,
        )?;
        result
    }

    /// Decrypt and validate a backup for `slot` without importing or
    /// consuming it (`restore --verify-only`). Returns the object count.
    pub fn verify_backup(
        &self,
        slot_id: CK_SLOT_ID,
        data: &[u8],
        passphrase: &str,
        max_age_secs: Option<u64>,
    ) -> HsmResult<usize> {
        self.check_live()?;
        let binding = self.token_binding(slot_id)?;
        let mut ids = self.consumed_backup_ids(slot_id)?;
        let objects = crate::store::backup::restore_backup(
            data,
            passphrase,
            &binding,
            max_age_secs,
            Some(self.pbkdf2_iterations),
            Some(&mut ids),
        )?;
        Ok(ZeroizingObjects::new(objects).len())
    }

    /// Restore a backup into `slot` (H3-16, H5-04, H5-05, H5-06):
    ///
    /// * the backup must be bound to this token, fresh, not yet consumed,
    ///   and every object passes the creation policy
    ///   ([`crate::store::backup::restore_backup`]);
    /// * objects get fresh handles and are imported **atomically** together
    ///   with the consumed backup ID (one store transaction in persistent
    ///   mode; the replay guard lives authenticated inside the database);
    /// * audited synchronously as [`AuditOperation::BackupRestore`].
    ///
    /// The **caller must have authenticated the SO** for this slot.
    pub fn restore_backup(
        &self,
        slot_id: CK_SLOT_ID,
        data: &[u8],
        passphrase: &str,
        max_age_secs: Option<u64>,
        actor: Option<&str>,
    ) -> HsmResult<Vec<CK_OBJECT_HANDLE>> {
        let result = (|| {
            self.require_unlocked(slot_id)?;
            let token = self.slot_manager.get_token(slot_id)?;
            if !token.is_initialized() {
                return Err(HsmError::TokenNotInitialized);
            }
            let binding = self.token_binding(slot_id)?;
            let before = self.consumed_backup_ids(slot_id)?;
            let mut ids = before.clone();
            let objects = crate::store::backup::restore_backup(
                data,
                passphrase,
                &binding,
                max_age_secs,
                Some(self.pbkdf2_iterations),
                Some(&mut ids),
            )?;
            let new_id = ids
                .difference(&before)
                .next()
                .cloned()
                .ok_or(HsmError::GeneralError)?;
            let mut objs = ZeroizingObjects::new(objects).into_inner();
            for obj in objs.iter_mut() {
                obj.handle = self.object_store.next_handle()?;
                obj.token_object = true;
            }
            let ctx = ObjectContext::admin(slot_id);
            if self.persistent_store.is_some() {
                self.object_store.insert_objects_recording(
                    objs,
                    &ctx,
                    ObjectOrigin::Restored,
                    Some(&new_id),
                )
            } else {
                let mut guard = self.ephemeral_backup_ids.lock();
                let set = guard.entry(slot_id).or_default();
                if set.contains(&new_id) {
                    return Err(HsmError::BackupRejected(
                        crate::error::BackupRejection::Replayed,
                    ));
                }
                let handles =
                    self.object_store
                        .insert_objects_in(objs, &ctx, ObjectOrigin::Restored)?;
                set.insert(new_id);
                Ok(handles)
            }
        })();
        let count = result.as_ref().map(|h| h.len() as u64).unwrap_or(0);
        self.audit_as(
            0,
            AuditOperation::BackupRestore {
                slot_id: slot_id as u64,
                object_count: count,
            },
            &result.as_ref().map(|_| ()).map_err(Clone::clone),
            actor,
        )?;
        result
    }

    fn consumed_backup_ids(&self, slot_id: CK_SLOT_ID) -> HsmResult<HashSet<String>> {
        match &self.persistent_store {
            Some(store) => store.consumed_backup_ids(slot_id),
            None => Ok(self
                .ephemeral_backup_ids
                .lock()
                .get(&slot_id)
                .cloned()
                .unwrap_or_default()),
        }
    }

    /// In persistent mode the slot's storage key must have been unlocked by
    /// an authentication since start.
    fn require_unlocked(&self, slot_id: CK_SLOT_ID) -> HsmResult<()> {
        self.check_live()?;
        self.slot_manager.get_token(slot_id)?;
        if let Some(store) = &self.persistent_store {
            if !store.has_slot_key(slot_id) {
                return Err(HsmError::UserNotLoggedIn);
            }
        }
        Ok(())
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

    /// Fill `out` from the module-wide approved SP 800-90A DRBG
    /// (`crypto::drbg::fill_random`: fork-aware, health-tested, latches the
    /// module error state on failure). Replaces the former per-core DRBG
    /// mutex, which was a global bottleneck (H4-12 perf).
    pub fn generate_random(&self, out: &mut [u8]) -> HsmResult<()> {
        if crate::crypto::self_test::is_error_state() {
            return Err(HsmError::GeneralError);
        }
        crate::crypto::drbg::fill_random(out)
    }

    /// Run the pre-operational self-tests (software CASTs, integrity test and
    /// the CASTs of the selected backend) for front ends that embed the core
    /// directly — the gRPC daemon and the admin CLI (A1-06). The C ABI runs
    /// them in `C_Initialize`. A failure latches the module error state.
    pub fn run_self_tests(&self) -> HsmResult<()> {
        crate::crypto::self_test::run_post_with_backend(
            self.crypto_backend.as_ref(),
            self.algorithm_config.fips_approved_only,
        )
    }
}

impl Drop for HsmCore {
    fn drop(&mut self) {
        // Zeroize keys and PIN verifiers even if C_Finalize was not called.
        self.finalize();
    }
}
