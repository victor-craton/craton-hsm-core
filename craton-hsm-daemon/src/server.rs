// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! gRPC HsmService implementation.
//!
//! Authorization model (H4-01):
//! - Every request carries the client identity established by the transport
//!   (`ConnInfo`, see `conn.rs`).
//! - Session handles are owned by the identity that opened them.
//! - Login state is kept per (identity, slot) in the daemon `Registry`; the
//!   core token is only used to verify PINs and is returned to the public
//!   state immediately, so one client's login never authorizes another.
//! - Key operations require the User role; the SO role (administrator
//!   certificates only) may only administer the token.
//!
//! CPU-bound work (PBKDF2, key generation, signing, hashing, DRBG output)
//! runs on the blocking pool, bounded by a semaphore (H4-12).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};
use zeroize::Zeroizing;

use craton_hsm::audit::log::{AuditOperation, AuditResult};
use craton_hsm::core::HsmCore;
use craton_hsm::crypto::mechanisms::{is_fips_approved, validate_mechanism_for_policy};
use craton_hsm::error::HsmError;
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::types::CK_ULONG;
use craton_hsm::store::object::StoredObject;
use craton_hsm::token::token::{LoginState, Token};

use crate::conn::{ConnInfo, RpcGuard};
use crate::mechanism::{
    cipher_alg_for, curve_from_params, is_ed25519_params, sign_alg_for, CipherAlg, Curve, SignAlg,
    ED25519_OID, P256_OID, P384_OID,
};
use crate::proto::hsm_service_server::HsmService;
use crate::proto::*;
use crate::registry::{Registry, Role, SessionView};
use crate::template::{
    proto_attrs_to_template, set_generated_provenance, validate, KeyKind, KeyTemplate,
    MAX_LABEL_LEN, MAX_SEARCH_VALUE_LEN,
};
use crate::throttle::Throttle;

/// Maximum number of attribute types per GetAttributeValue request (H4-07).
pub const MAX_ATTRIBUTE_TYPES: usize = 64;
/// Maximum number of handles returned by FindObjects.
pub const MAX_FIND_RESULTS: usize = 10_000;
/// DRBG output is produced in chunks so the global DRBG lock is never held
/// for a large request.
const RANDOM_CHUNK: usize = 64 * 1024;
/// Framing overhead reserved when budgeting response sizes.
const RESPONSE_OVERHEAD: usize = 1024;

// ── Redacting Debug for PIN-bearing messages (H4-19) ────────────────────────

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("session_handle", &self.session_handle)
            .field("user_type", &self.user_type)
            .field("pin", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for InitTokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitTokenRequest")
            .field("slot_id", &self.slot_id)
            .field("so_pin", &"[REDACTED]")
            .field("label", &self.label)
            .finish()
    }
}

impl std::fmt::Debug for InitPinRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitPinRequest")
            .field("session_handle", &self.session_handle)
            .field("so_pin", &"[REDACTED]")
            .field("pin", &"[REDACTED]")
            .finish()
    }
}

/// Service-level limits and policy.
#[derive(Clone, Debug)]
pub struct ServiceSettings {
    pub max_random_length: u32,
    pub max_digest_length: u32,
    pub max_response_bytes: u32,
    pub max_login_attempts: u32,
    pub login_cooldown: Duration,
    pub max_sessions_per_client: u32,
    pub max_objects_per_client: u32,
    pub max_blocking_tasks: usize,
}

/// Per-slot serialisation: `login` serialises PIN verification (so that the
/// throttle check → verify → record sequence is atomic, and the core token
/// can be used for verify-and-release); `init` excludes session creation
/// while InitToken runs.
struct SlotGate {
    login: Mutex<()>,
    init: RwLock<()>,
}

/// State shared between request handlers and background tasks.
pub struct Shared {
    hsm: Arc<HsmCore>,
    registry: Registry,
    login_throttle: Throttle,
    init_throttle: Throttle,
    gates: HashMap<CK_ULONG, Arc<SlotGate>>,
    settings: ServiceSettings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    /// Any logged-in role.
    Any,
    /// The User role (key usage).
    User,
    /// The SO role (token administration).
    So,
}

#[derive(Clone, Copy)]
enum Usage {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
}

impl Usage {
    fn lifecycle_op(self) -> &'static str {
        match self {
            Usage::Sign => "sign",
            Usage::Verify => "verify",
            Usage::Encrypt => "encrypt",
            Usage::Decrypt => "decrypt",
        }
    }
}

#[derive(Clone)]
pub struct HsmServiceImpl {
    shared: Arc<Shared>,
    blocking: Arc<Semaphore>,
}

fn lock_mutex(m: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Safely convert a u64 (from protobuf) to CK_ULONG without truncation.
fn to_ck_ulong(value: u64, field_name: &str) -> Result<CK_ULONG, Status> {
    value.try_into().map_err(|_| {
        Status::invalid_argument(format!(
            "{} value {} exceeds platform maximum",
            field_name, value
        ))
    })
}

fn fips_flag(mech: u64) -> bool {
    CK_ULONG::try_from(mech).map_or(false, is_fips_approved)
}

fn mech_of(m: &Option<Mechanism>) -> u64 {
    m.as_ref().map_or(0, |m| m.mechanism_type)
}

fn not_logged_in() -> Status {
    Status::permission_denied("Not logged in — call Login first")
}

fn is_pin_failure(e: &HsmError) -> bool {
    matches!(e, HsmError::PinIncorrect | HsmError::PinLocked)
}

/// The core token must be public before it is used for PIN verification.
/// The daemon never leaves it logged in, but be robust.
fn reset_core_login(token: &Token) {
    if token.login_state() != LoginState::Public {
        let _ = token.logout();
    }
}

/// Extract the connection info and mark the RPC as active on its connection.
fn begin<T>(request: Request<T>) -> Result<(ConnInfo, RpcGuard, T), Status> {
    let conn = request
        .extensions()
        .get::<ConnInfo>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("Client identity unavailable"))?;
    let guard = conn.activity.begin();
    Ok((conn, guard, request.into_inner()))
}

impl Shared {
    fn gate(&self, slot_id: CK_ULONG) -> Result<Arc<SlotGate>, Status> {
        self.gates
            .get(&slot_id)
            .cloned()
            .ok_or_else(|| Status::not_found("Slot not found"))
    }

    fn token(&self, slot_id: CK_ULONG) -> Result<Arc<Token>, Status> {
        self.hsm
            .slot_manager()
            .get_token(slot_id)
            .map_err(hsm_err_to_status)
    }

    fn persistent(&self) -> bool {
        self.hsm.object_store().has_persistence()
    }

    /// Record an audit event attributed to `client` (H4-26).
    fn audit_as(
        &self,
        client: &str,
        session_handle: u64,
        operation: AuditOperation,
        result: AuditResult,
        detail: Option<String>,
    ) -> Result<(), Status> {
        let key_id = match detail {
            Some(d) => format!("client={} {}", client, d),
            None => format!("client={}", client),
        };
        self.hsm
            .audit_log()
            .record(session_handle, operation, result, Some(key_id))
            .map_err(|e| {
                tracing::error!("Audit log write failed: {:?}", e);
                Status::internal("Audit system failure")
            })
    }

    fn audit(
        &self,
        conn: &ConnInfo,
        session_handle: u64,
        operation: AuditOperation,
        result: AuditResult,
        detail: Option<String>,
    ) -> Result<(), Status> {
        self.audit_as(&conn.identity.id, session_handle, operation, result, detail)
    }

    /// Destroy an object, clearing its per-key GCM/IV trackers (H4-15).
    fn destroy_object_now(&self, handle: CK_ULONG) -> Result<(), Status> {
        let obj = self
            .hsm
            .object_store()
            .get_object(handle)
            .map_err(hsm_err_to_status)?;
        self.hsm
            .object_store()
            .destroy_object(handle)
            .map_err(hsm_err_to_status)?;
        {
            let o = obj.read();
            if o.class == CKO_SECRET_KEY {
                if let Some(km) = &o.key_material {
                    craton_hsm::crypto::encrypt::remove_gcm_counter(km.as_bytes());
                }
            }
        }
        self.registry.release_object(handle);
        Ok(())
    }

    /// Destroy every object on a slot (InitToken). Returns the count.
    fn wipe_slot_objects(&self, slot_id: CK_ULONG) -> usize {
        let handles = self
            .hsm
            .object_store()
            .find_objects_for_slot(&[], true, Some(slot_id));
        let mut n = 0;
        for h in handles {
            match self.destroy_object_now(h) {
                Ok(()) => n += 1,
                Err(e) => tracing::error!(
                    handle = h,
                    "InitToken: failed to destroy object: {}",
                    e.message()
                ),
            }
        }
        n
    }

    /// Close a session: destroy its session objects, release the core
    /// session and end the owner's login when it was the last session.
    pub fn close_session(&self, handle: CK_ULONG) -> Result<(String, CK_ULONG), Status> {
        let rec = self
            .registry
            .take_session(handle)
            .ok_or_else(|| Status::not_found("Session not found"))?;
        for obj in &rec.objects {
            if let Err(e) = self.destroy_object_now(*obj) {
                tracing::warn!(
                    handle = obj,
                    "failed to destroy session object: {}",
                    e.message()
                );
            }
        }
        let token = self.token(rec.slot_id)?;
        self.hsm
            .session_manager()
            .close_session(handle, &token)
            .map_err(hsm_err_to_status)?;
        Ok((rec.owner.to_string(), rec.slot_id))
    }

    fn close_and_audit(&self, handles: Vec<CK_ULONG>, reason: &str) -> usize {
        let mut n = 0;
        for h in handles {
            match self.close_session(h) {
                Ok((owner, _)) => {
                    n += 1;
                    if let Err(e) = self.audit_as(
                        &owner,
                        h as u64,
                        AuditOperation::CloseSession,
                        AuditResult::Success,
                        Some(format!("reason={}", reason)),
                    ) {
                        tracing::error!(
                            "audit failed for {} session close: {}",
                            reason,
                            e.message()
                        );
                    }
                }
                Err(e) => tracing::debug!("session {} already gone: {}", h, e.message()),
            }
        }
        n
    }

    /// Close every session opened on a connection that has gone away (H4-10).
    pub fn cleanup_connection(&self, conn_id: u64) -> usize {
        let handles = self.registry.sessions_of_conn(conn_id);
        self.close_and_audit(handles, "disconnect")
    }

    /// Close sessions idle for longer than `timeout` (H4-10).
    pub fn reap_idle_sessions(&self, timeout: Duration) -> usize {
        let handles = self.registry.idle_sessions(timeout);
        self.close_and_audit(handles, "idle")
    }

    /// Flush the audit log (shutdown, admin operations).
    pub fn flush_audit(&self) {
        self.hsm.audit_log().flush();
    }

    /// Register ownership of a freshly inserted object; destroys it if the
    /// creating session vanished meanwhile.
    fn track_new_object(
        &self,
        owner: &Arc<str>,
        handle: CK_ULONG,
        token_object: bool,
        session: CK_ULONG,
    ) -> Result<(), Status> {
        let sess = if token_object { None } else { Some(session) };
        if self.registry.record_object(owner, handle, sess) {
            Ok(())
        } else {
            let _ = self.hsm.object_store().destroy_object(handle);
            Err(Status::not_found("Session not found"))
        }
    }
}

impl HsmServiceImpl {
    pub fn new(hsm: Arc<HsmCore>, settings: ServiceSettings) -> Self {
        let gates = hsm
            .slot_manager()
            .get_slot_ids()
            .into_iter()
            .map(|id| {
                (
                    id,
                    Arc::new(SlotGate {
                        login: Mutex::new(()),
                        init: RwLock::new(()),
                    }),
                )
            })
            .collect();
        let blocking = Arc::new(Semaphore::new(settings.max_blocking_tasks.max(1)));
        let shared = Shared {
            registry: Registry::new(
                settings.max_sessions_per_client as usize,
                settings.max_objects_per_client as usize,
            ),
            login_throttle: Throttle::new(
                "login",
                settings.max_login_attempts,
                settings.login_cooldown,
            ),
            init_throttle: Throttle::new(
                "InitToken",
                settings.max_login_attempts,
                settings.login_cooldown,
            ),
            gates,
            hsm,
            settings,
        };
        Self {
            shared: Arc::new(shared),
            blocking,
        }
    }

    pub fn shared(&self) -> Arc<Shared> {
        self.shared.clone()
    }

    /// Run CPU-bound / lock-heavy work on the blocking pool (H4-12). The
    /// permit travels with the task, so a request timeout cannot overcommit
    /// the pool.
    async fn blocking<F, R>(&self, f: F) -> Result<R, Status>
    where
        F: FnOnce(&Shared) -> Result<R, Status> + Send + 'static,
        R: Send + 'static,
    {
        let permit = self
            .blocking
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Status::unavailable("Service shutting down"))?;
        let shared = self.shared.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f(&shared)
        })
        .await
        .map_err(|e| {
            tracing::error!("blocking task failed: {}", e);
            Status::internal("Internal error")
        })?
    }

    /// Resolve a session handle owned by the calling client.
    fn session(&self, conn: &ConnInfo, handle: u64) -> Result<SessionView, Status> {
        let h = to_ck_ulong(handle, "session_handle")?;
        self.shared.registry.authorize(h, &conn.identity.id)
    }

    /// Require the calling client to hold `need` on `slot_id`.
    fn require(&self, conn: &ConnInfo, slot_id: CK_ULONG, need: Need) -> Result<Role, Status> {
        match (need, self.shared.registry.role(&conn.identity.id, slot_id)) {
            (_, None) => Err(not_logged_in()),
            (Need::Any, Some(r)) => Ok(r),
            (Need::User, Some(Role::User)) | (Need::So, Some(Role::So)) => Ok(need_role(need)),
            (Need::User, Some(Role::So)) => Err(Status::permission_denied(
                "This operation requires the User role; the SO may only administer the token",
            )),
            (Need::So, Some(Role::User)) => Err(Status::permission_denied("SO login required")),
        }
    }

    /// Audit a failed operation (best effort) and pass the result through.
    fn audited<T>(
        &self,
        conn: &ConnInfo,
        session_handle: u64,
        op: impl FnOnce() -> AuditOperation,
        detail: Option<String>,
        r: Result<T, Status>,
    ) -> Result<T, Status> {
        if let Err(st) = &r {
            if let Err(e) = self.shared.audit(
                conn,
                session_handle,
                op(),
                AuditResult::Failure(st.code() as u64),
                detail,
            ) {
                tracing::error!(
                    "audit write failed for denied/failed operation: {}",
                    e.message()
                );
            }
        }
        r
    }

    /// Reject token objects when the state is not persistent (H4-03) and in
    /// read-only sessions (H4-22).
    fn check_token_object(&self, t: &KeyTemplate, view: &SessionView) -> Result<(), Status> {
        if t.is_token_object() {
            if !self.shared.persistent() {
                return Err(Status::failed_precondition(
                    "Token objects (CKA_TOKEN=true) cannot be created: this daemon's HSM state \
                     is not persistent",
                ));
            }
            if !view.rw {
                return Err(Status::permission_denied("Session is read-only"));
            }
        }
        Ok(())
    }

    /// Look up a key for a crypto operation, enforcing slot isolation,
    /// session-object visibility, usage flags and lifecycle.
    fn load_key(
        &self,
        conn: &ConnInfo,
        view: &SessionView,
        key_handle: u64,
        usage: Usage,
    ) -> Result<Arc<parking_lot::RwLock<StoredObject>>, Status> {
        let h = to_ck_ulong(key_handle, "key_handle")?;
        let obj = self
            .shared
            .hsm
            .object_store()
            .get_object(h)
            .map_err(|_| Status::not_found("Key not found"))?;
        {
            let k = obj.read();
            if k.slot_id != view.slot_id
                || !self.shared.registry.object_visible(h, &conn.identity.id)
            {
                return Err(Status::not_found("Key not found"));
            }
            let allowed = match usage {
                Usage::Sign => k.can_sign,
                Usage::Verify => k.can_verify,
                Usage::Encrypt => k.can_encrypt,
                Usage::Decrypt => k.can_decrypt,
            };
            if !allowed {
                return Err(Status::permission_denied(
                    "Key not permitted for this operation",
                ));
            }
            k.check_lifecycle(usage.lifecycle_op()).map_err(|_| {
                Status::permission_denied("Key not permitted for this operation (lifecycle state)")
            })?;
        }
        Ok(obj)
    }
}

fn need_role(need: Need) -> Role {
    match need {
        Need::So => Role::So,
        _ => Role::User,
    }
}

#[tonic::async_trait]
impl HsmService for HsmServiceImpl {
    async fn open_session(
        &self,
        request: Request<OpenSessionRequest>,
    ) -> Result<Response<OpenSessionResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let slot = req.slot_id;
        let r = self.open_session_inner(&conn, &req).await;
        self.audited(
            &conn,
            0,
            || AuditOperation::OpenSession { slot_id: slot },
            None,
            r,
        )
    }

    async fn close_session(
        &self,
        request: Request<CloseSessionRequest>,
    ) -> Result<Response<CloseSessionResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let r = async {
            let view = self.session(&conn, req.session_handle)?;
            self.blocking(move |sh| sh.close_session(view.handle).map(|_| ()))
                .await?;
            self.shared.audit(
                &conn,
                req.session_handle,
                AuditOperation::CloseSession,
                AuditResult::Success,
                None,
            )?;
            Ok(Response::new(CloseSessionResponse {}))
        }
        .await;
        self.audited(
            &conn,
            req.session_handle,
            || AuditOperation::CloseSession,
            None,
            r,
        )
    }

    async fn login(
        &self,
        mut request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        // (H4-19) Move the PIN into a zeroizing buffer before anything else,
        // so every return path scrubs it. Copies held in HTTP/2 / tonic
        // decode buffers cannot be scrubbed; core dumps are disabled at
        // startup to limit exposure.
        let pin = Zeroizing::new(std::mem::take(&mut request.get_mut().pin));
        let (conn, _rpc, req) = begin(request)?;
        let user_type = req.user_type;
        let r = self.login_inner(&conn, &req, pin).await;
        self.audited(
            &conn,
            req.session_handle,
            || AuditOperation::Login { user_type },
            None,
            r,
        )
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let r = async {
            let view = self.session(&conn, req.session_handle)?;
            // (H4-01) Only the caller's own login ends.
            if !self
                .shared
                .registry
                .clear_login(&conn.identity.id, view.slot_id)
            {
                return Err(hsm_err_to_status(HsmError::UserNotLoggedIn));
            }
            self.shared.audit(
                &conn,
                req.session_handle,
                AuditOperation::Logout,
                AuditResult::Success,
                None,
            )?;
            Ok(Response::new(LogoutResponse {}))
        }
        .await;
        self.audited(
            &conn,
            req.session_handle,
            || AuditOperation::Logout,
            None,
            r,
        )
    }

    async fn get_token_info(
        &self,
        request: Request<GetTokenInfoRequest>,
    ) -> Result<Response<GetTokenInfoResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let slot_id = to_ck_ulong(req.slot_id, "slot_id")?;
        let view = self.session(&conn, req.session_handle)?;
        if view.slot_id != slot_id {
            return Err(Status::permission_denied(
                "Session does not belong to the requested slot",
            ));
        }
        let identity = conn.identity.clone();
        // Token getters take the token's auth mutex, which a concurrent PIN
        // verification may hold — run off the reactor.
        self.blocking(move |sh| {
            let token = sh.token(slot_id)?;
            let role = sh.registry.role(&identity.id, slot_id);
            let label = {
                let raw = *token.label.read();
                String::from_utf8_lossy(&raw).trim_end().to_string()
            };
            // (H4-25) Report only the caller's own state; token-wide counts
            // are for administrators.
            let (session_count, rw_session_count) = if identity.is_admin {
                (token.session_count(), token.rw_session_count())
            } else {
                sh.registry.session_counts(&identity.id, slot_id)
            };
            Ok(Response::new(GetTokenInfoResponse {
                label,
                initialized: token.is_initialized(),
                user_pin_initialized: token.is_user_pin_initialized(),
                login_state: role.map_or("Public", Role::as_str).to_string(),
                session_count,
                max_sessions: token.max_sessions(),
                rw_session_count,
                max_rw_sessions: token.max_rw_sessions(),
            }))
        })
        .await
    }

    async fn init_token(
        &self,
        mut request: Request<InitTokenRequest>,
    ) -> Result<Response<InitTokenResponse>, Status> {
        let so_pin = Zeroizing::new(std::mem::take(&mut request.get_mut().so_pin));
        let (conn, _rpc, req) = begin(request)?;
        let slot = req.slot_id;
        let r = self.init_token_inner(&conn, &req, so_pin).await;
        self.audited(
            &conn,
            0,
            || AuditOperation::InitToken { slot_id: slot },
            None,
            r,
        )
    }

    async fn init_pin(
        &self,
        mut request: Request<InitPinRequest>,
    ) -> Result<Response<InitPinResponse>, Status> {
        let so_pin = Zeroizing::new(std::mem::take(&mut request.get_mut().so_pin));
        let pin = Zeroizing::new(std::mem::take(&mut request.get_mut().pin));
        let (conn, _rpc, req) = begin(request)?;
        let r = self.init_pin_inner(&conn, &req, so_pin, pin).await;
        self.audited(
            &conn,
            req.session_handle,
            || AuditOperation::InitToken { slot_id: 0 },
            Some("op=InitPIN".into()),
            r,
        )
    }

    async fn generate_key(
        &self,
        request: Request<GenerateKeyRequest>,
    ) -> Result<Response<GenerateKeyResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let mech = mech_of(&req.mechanism);
        let sh = req.session_handle;
        let r = self.generate_key_inner(&conn, req).await;
        self.audited(
            &conn,
            sh,
            || AuditOperation::GenerateKey {
                mechanism: mech,
                key_length: 0,
                fips_approved: fips_flag(mech),
            },
            None,
            r,
        )
    }

    async fn generate_key_pair(
        &self,
        request: Request<GenerateKeyPairRequest>,
    ) -> Result<Response<GenerateKeyPairResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let mech = mech_of(&req.mechanism);
        let sh = req.session_handle;
        let r = self.generate_key_pair_inner(&conn, req).await;
        self.audited(
            &conn,
            sh,
            || AuditOperation::GenerateKeyPair {
                mechanism: mech,
                key_length: 0,
                fips_approved: fips_flag(mech),
            },
            None,
            r,
        )
    }

    async fn destroy_object(
        &self,
        request: Request<DestroyObjectRequest>,
    ) -> Result<Response<DestroyObjectResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let detail = Some(format!("handle={}", req.object_handle));
        let r = async {
            let view = self.session(&conn, req.session_handle)?;
            self.require(&conn, view.slot_id, Need::User)?;
            let h = to_ck_ulong(req.object_handle, "object_handle")?;
            let obj = self
                .shared
                .hsm
                .object_store()
                .get_object(h)
                .map_err(hsm_err_to_status)?;
            {
                let o = obj.read();
                if o.slot_id != view.slot_id
                    || !self.shared.registry.object_visible(h, &conn.identity.id)
                {
                    return Err(Status::not_found("Object not found"));
                }
                // (H4-22) Token objects may only be destroyed from R/W sessions.
                if o.token_object && !view.rw {
                    return Err(Status::permission_denied("Session is read-only"));
                }
            }
            self.blocking(move |sh| sh.destroy_object_now(h)).await?;
            self.shared.audit(
                &conn,
                req.session_handle,
                AuditOperation::DestroyObject,
                AuditResult::Success,
                Some(format!("handle={}", req.object_handle)),
            )?;
            Ok(Response::new(DestroyObjectResponse {}))
        }
        .await;
        self.audited(
            &conn,
            req.session_handle,
            || AuditOperation::DestroyObject,
            detail,
            r,
        )
    }

    async fn find_objects(
        &self,
        request: Request<FindObjectsRequest>,
    ) -> Result<Response<FindObjectsResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let view = self.session(&conn, req.session_handle)?;
        let role = self.require(&conn, view.slot_id, Need::Any)?;
        let template = proto_attrs_to_template(&req.template, MAX_SEARCH_VALUE_LEN)?;
        let max = if req.max_count == 0 {
            MAX_FIND_RESULTS
        } else {
            usize::try_from(req.max_count)
                .unwrap_or(usize::MAX)
                .min(MAX_FIND_RESULTS)
        };
        let owner = conn.identity.id.clone();
        let slot = view.slot_id;
        let handles = self
            .blocking(move |sh| {
                // Private objects are visible to the User role only.
                let found = sh.hsm.object_store().find_objects_for_slot(
                    &template,
                    role == Role::User,
                    Some(slot),
                );
                let mut v = sh.registry.filter_visible(found, &owner);
                v.truncate(max);
                Ok(v)
            })
            .await?;
        let result_handles: Vec<u64> = handles.into_iter().map(|h| h as u64).collect();
        self.shared.audit(
            &conn,
            req.session_handle,
            AuditOperation::FindObjects {
                result_count: u32::try_from(result_handles.len()).unwrap_or(u32::MAX),
            },
            AuditResult::Success,
            None,
        )?;
        Ok(Response::new(FindObjectsResponse {
            object_handles: result_handles,
        }))
    }

    async fn get_attribute_value(
        &self,
        request: Request<GetAttributeValueRequest>,
    ) -> Result<Response<GetAttributeValueResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let view = self.session(&conn, req.session_handle)?;
        // (H4-07) Bound and de-duplicate the requested attribute types.
        if req.attribute_types.len() > MAX_ATTRIBUTE_TYPES {
            return Err(Status::invalid_argument(format!(
                "At most {} attribute types may be requested",
                MAX_ATTRIBUTE_TYPES
            )));
        }
        let mut seen = HashSet::new();
        let mut types = Vec::with_capacity(req.attribute_types.len());
        for t in &req.attribute_types {
            if seen.insert(*t) {
                types.push((*t, to_ck_ulong(*t, "attribute_type")?));
            }
        }
        let h = to_ck_ulong(req.object_handle, "object_handle")?;
        let obj = self
            .shared
            .hsm
            .object_store()
            .get_object(h)
            .map_err(hsm_err_to_status)?;
        let budget =
            (self.shared.settings.max_response_bytes as usize).saturating_sub(RESPONSE_OVERHEAD);
        let attrs = {
            let o = obj.read();
            if o.slot_id != view.slot_id
                || !self.shared.registry.object_visible(h, &conn.identity.id)
            {
                return Err(Status::not_found("Object not found"));
            }
            // Private objects are readable by the User role only.
            if o.private {
                self.require(&conn, view.slot_id, Need::User)?;
            }
            let mut used = 0usize;
            let mut attrs = Vec::with_capacity(types.len());
            for (wire, ck) in &types {
                // Sensitive or absent attributes are returned empty.
                let value = craton_hsm::store::attributes::read_attribute(&o, *ck)
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                used = used.saturating_add(value.len() + 16);
                if used > budget {
                    return Err(Status::resource_exhausted(
                        "Requested attributes exceed the response size limit",
                    ));
                }
                attrs.push(Attribute {
                    attr_type: *wire,
                    value: value.to_vec(),
                });
            }
            attrs
        }; // object lock released before auditing
        self.shared.audit(
            &conn,
            req.session_handle,
            AuditOperation::GetAttributeValue,
            AuditResult::Success,
            Some(format!("handle={}", req.object_handle)),
        )?;
        Ok(Response::new(GetAttributeValueResponse {
            attributes: attrs,
        }))
    }

    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let mech = mech_of(&req.mechanism);
        let sh = req.session_handle;
        let detail = Some(format!("key={}", req.key_handle));
        let r = self.sign_inner(&conn, req).await;
        self.audited(
            &conn,
            sh,
            || AuditOperation::Sign {
                mechanism: mech,
                fips_approved: fips_flag(mech),
            },
            detail,
            r,
        )
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let mech = mech_of(&req.mechanism);
        let sh = req.session_handle;
        let detail = Some(format!("key={}", req.key_handle));
        let r = self.verify_inner(&conn, req).await;
        self.audited(
            &conn,
            sh,
            || AuditOperation::Verify {
                mechanism: mech,
                fips_approved: fips_flag(mech),
            },
            detail,
            r,
        )
    }

    async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let mech = mech_of(&req.mechanism);
        let sh = req.session_handle;
        let detail = Some(format!("key={}", req.key_handle));
        let r = self
            .cipher_inner(&conn, sh, req.mechanism, req.key_handle, req.data, false)
            .await
            .map(|encrypted_data| Response::new(EncryptResponse { encrypted_data }));
        self.audited(
            &conn,
            sh,
            || AuditOperation::Encrypt {
                mechanism: mech,
                fips_approved: fips_flag(mech),
            },
            detail,
            r,
        )
    }

    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let mech = mech_of(&req.mechanism);
        let sh = req.session_handle;
        let detail = Some(format!("key={}", req.key_handle));
        let r = self
            .cipher_inner(
                &conn,
                sh,
                req.mechanism,
                req.key_handle,
                req.encrypted_data,
                true,
            )
            .await
            .map(|data| Response::new(DecryptResponse { data }));
        self.audited(
            &conn,
            sh,
            || AuditOperation::Decrypt {
                mechanism: mech,
                fips_approved: fips_flag(mech),
            },
            detail,
            r,
        )
    }

    async fn digest(
        &self,
        request: Request<DigestRequest>,
    ) -> Result<Response<DigestResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let mech = mech_of(&req.mechanism);
        let sh = req.session_handle;
        let r = async {
            let view = self.session(&conn, req.session_handle)?;
            // Login is required to limit unauthenticated CPU use.
            self.require(&conn, view.slot_id, Need::Any)?;
            if req.data.len() > self.shared.settings.max_digest_length as usize {
                return Err(Status::invalid_argument(format!(
                    "Digest data size {} bytes exceeds maximum {} bytes",
                    req.data.len(),
                    self.shared.settings.max_digest_length
                )));
            }
            let mech_type = to_ck_ulong(mech, "mechanism_type")?;
            if !craton_hsm::crypto::mechanisms::is_digest_mechanism(mech_type) {
                return Err(Status::invalid_argument("Unsupported digest mechanism"));
            }
            // (H4-08) The core requires the caller to apply the SHA-1 / FIPS
            // policy for digests.
            validate_mechanism_for_policy(mech_type, self.shared.hsm.algorithm_config(), false)
                .map_err(|_| Status::permission_denied("Mechanism blocked by algorithm policy"))?;
            let data = req.data;
            let digest = self
                .blocking(move |_| {
                    craton_hsm::crypto::digest::compute_digest(mech_type, &data)
                        .map_err(hsm_err_to_status)
                })
                .await?;
            self.shared.audit(
                &conn,
                req.session_handle,
                AuditOperation::Digest {
                    mechanism: mech,
                    fips_approved: fips_flag(mech),
                },
                AuditResult::Success,
                None,
            )?;
            Ok(Response::new(DigestResponse { digest }))
        }
        .await;
        self.audited(
            &conn,
            sh,
            || AuditOperation::Digest {
                mechanism: mech,
                fips_approved: fips_flag(mech),
            },
            None,
            r,
        )
    }

    async fn generate_random(
        &self,
        request: Request<GenerateRandomRequest>,
    ) -> Result<Response<GenerateRandomResponse>, Status> {
        let (conn, _rpc, req) = begin(request)?;
        let view = self.session(&conn, req.session_handle)?;
        self.require(&conn, view.slot_id, Need::Any)?;
        let length: u32 = req.length.try_into().map_err(|_| {
            Status::invalid_argument(format!(
                "Requested length {} exceeds maximum representable size",
                req.length
            ))
        })?;
        if length > self.shared.settings.max_random_length {
            return Err(Status::invalid_argument(format!(
                "Requested {} bytes exceeds maximum {} bytes",
                length, self.shared.settings.max_random_length
            )));
        }
        let random_data = self
            .blocking(move |sh| {
                let mut buf = vec![0u8; length as usize];
                // (Perf) Release the global DRBG lock between chunks.
                for chunk in buf.chunks_mut(RANDOM_CHUNK) {
                    let mut drbg = sh.hsm.drbg().lock();
                    drbg.generate(chunk).map_err(|_| {
                        Status::internal("DRBG generation failed — health test failure")
                    })?;
                }
                Ok(buf)
            })
            .await?;
        self.shared.audit(
            &conn,
            req.session_handle,
            AuditOperation::GenerateRandom { length },
            AuditResult::Success,
            None,
        )?;
        Ok(Response::new(GenerateRandomResponse { random_data }))
    }
}

// ── Handler bodies ───────────────────────────────────────────────────────────

impl HsmServiceImpl {
    async fn open_session_inner(
        &self,
        conn: &ConnInfo,
        req: &OpenSessionRequest,
    ) -> Result<Response<OpenSessionResponse>, Status> {
        let slot_id = to_ck_ulong(req.slot_id, "slot_id")?;
        let rw = req.read_write;
        let flags = if rw {
            CKF_SERIAL_SESSION | CKF_RW_SESSION
        } else {
            CKF_SERIAL_SESSION
        };
        let gate = self.shared.gate(slot_id)?;
        let token = self.shared.token(slot_id)?;
        let owner = conn.identity.id.clone();
        // (H4-10) Per-client session quota.
        self.shared.registry.reserve_session(&owner, slot_id, rw)?;
        let conn_id = conn.conn_id;
        let handle = self
            .blocking(move |sh| {
                let _g = gate.init.read().unwrap_or_else(|p| p.into_inner());
                match sh
                    .hsm
                    .session_manager()
                    .open_session(slot_id, flags as CK_ULONG, &token)
                {
                    Ok(h) => {
                        // Registered inside the blocking task so the handle
                        // cannot be lost if the request future is dropped.
                        sh.registry.insert_session(h, owner, conn_id, slot_id, rw);
                        Ok(h)
                    }
                    Err(e) => {
                        sh.registry.cancel_reservation(&owner);
                        Err(hsm_err_to_status(e))
                    }
                }
            })
            .await?;
        self.shared.audit(
            conn,
            handle as u64,
            AuditOperation::OpenSession {
                slot_id: req.slot_id,
            },
            AuditResult::Success,
            Some(format!(
                "auth={} remote={}",
                if conn.identity.authenticated {
                    "mtls"
                } else {
                    "none"
                },
                conn.remote
                    .map_or_else(|| "-".to_string(), |a| a.to_string())
            )),
        )?;
        Ok(Response::new(OpenSessionResponse {
            session_handle: handle as u64,
        }))
    }

    async fn login_inner(
        &self,
        conn: &ConnInfo,
        req: &LoginRequest,
        pin: Zeroizing<Vec<u8>>,
    ) -> Result<Response<LoginResponse>, Status> {
        let user_type = to_ck_ulong(req.user_type, "user_type")?;
        let role = match user_type {
            CKU_USER => Role::User,
            CKU_SO => Role::So,
            CKU_CONTEXT_SPECIFIC => {
                return Err(Status::unimplemented(
                    "CKU_CONTEXT_SPECIFIC is not supported by the gRPC daemon",
                ))
            }
            _ => {
                return Err(Status::invalid_argument(format!(
                    "Invalid user_type {}. Expected CKU_SO (0) or CKU_USER (1)",
                    req.user_type
                )))
            }
        };
        let view = self.session(conn, req.session_handle)?;
        let slot_id = view.slot_id;
        let owner = conn.identity.id.clone();
        // (H4-11) Anonymous or non-admin peers cannot touch SO counters.
        if role == Role::So && !conn.identity.is_admin {
            return Err(Status::permission_denied(
                "SO login requires an administrator client certificate",
            ));
        }
        match self.shared.registry.role(&owner, slot_id) {
            Some(r) if r == role => return Err(Status::already_exists("Already logged in")),
            Some(_) => {
                return Err(Status::failed_precondition(
                    "Another user already logged in",
                ))
            }
            None => {}
        }
        if role == Role::So && self.shared.registry.has_ro_session(&owner, slot_id) {
            return Err(Status::failed_precondition("Read-only session exists"));
        }
        let gate = self.shared.gate(slot_id)?;
        let token = self.shared.token(slot_id)?;
        let key = format!("{}|{}|{}", owner, slot_id, user_type);
        let owner2 = owner.clone();
        self.blocking(move |sh| {
            let _g = lock_mutex(&gate.login);
            sh.login_throttle.check(&key)?;
            reset_core_login(&token);
            // Verify-and-release: the core token only verifies the PIN (with
            // its persistent lockout counters); the resulting login is kept
            // per client in the registry, never on the shared token.
            let r = token.login(user_type, &pin);
            if r.is_ok() {
                let _ = token.logout();
            }
            drop(pin);
            match r {
                Ok(()) => {
                    sh.login_throttle.clear(&key);
                    sh.registry.set_login(&owner2, slot_id, role)
                }
                Err(e) => {
                    if is_pin_failure(&e) {
                        sh.login_throttle.record_failure(&key);
                    }
                    Err(hsm_err_to_status(e))
                }
            }
        })
        .await?;
        if let Err(e) = self.shared.audit(
            conn,
            req.session_handle,
            AuditOperation::Login {
                user_type: req.user_type,
            },
            AuditResult::Success,
            None,
        ) {
            // Fail closed: do not keep an unaudited login.
            self.shared.registry.clear_login(&owner, slot_id);
            return Err(e);
        }
        Ok(Response::new(LoginResponse {}))
    }

    async fn init_token_inner(
        &self,
        conn: &ConnInfo,
        req: &InitTokenRequest,
        so_pin: Zeroizing<Vec<u8>>,
    ) -> Result<Response<InitTokenResponse>, Status> {
        // (H4-02) Token (re-)initialisation is an administrator operation.
        if !conn.identity.is_admin {
            return Err(Status::permission_denied(
                "InitToken requires an administrator client certificate",
            ));
        }
        let slot_id = to_ck_ulong(req.slot_id, "slot_id")?;
        if req.label.len() > 32 {
            return Err(Status::invalid_argument("Label exceeds 32 bytes"));
        }
        let mut label = [b' '; 32];
        label[..req.label.len()].copy_from_slice(req.label.as_bytes());
        let gate = self.shared.gate(slot_id)?;
        let token = self.shared.token(slot_id)?;
        let key = format!("{}|{}|init", conn.identity.id, slot_id);
        let destroyed = self
            .blocking(move |sh| {
                let _l = lock_mutex(&gate.login);
                let _w = gate.init.write().unwrap_or_else(|p| p.into_inner());
                sh.init_throttle.check(&key)?;
                // (H4-09) Like C_InitToken: refuse while sessions exist.
                if sh.registry.slot_has_sessions(slot_id) || token.session_count() > 0 {
                    return Err(Status::failed_precondition(
                        "Session exists — close all sessions on the slot before InitToken",
                    ));
                }
                reset_core_login(&token);
                match token.init_token(&so_pin, &label) {
                    Ok(()) => {
                        sh.init_throttle.clear(&key);
                        sh.registry.clear_slot_logins(slot_id);
                        // Destroy only after the SO PIN has been verified.
                        Ok(sh.wipe_slot_objects(slot_id))
                    }
                    Err(e) => {
                        if is_pin_failure(&e) {
                            sh.init_throttle.record_failure(&key);
                        }
                        Err(hsm_err_to_status(e))
                    }
                }
            })
            .await?;
        self.shared.audit(
            conn,
            0,
            AuditOperation::InitToken {
                slot_id: req.slot_id,
            },
            AuditResult::Success,
            Some(format!("destroyed_objects={}", destroyed)),
        )?;
        self.blocking(|sh| {
            sh.flush_audit();
            Ok(())
        })
        .await?;
        tracing::warn!(slot_id, client = %conn.identity.id, "Token initialized via gRPC");
        Ok(Response::new(InitTokenResponse {}))
    }

    async fn init_pin_inner(
        &self,
        conn: &ConnInfo,
        req: &InitPinRequest,
        so_pin: Zeroizing<Vec<u8>>,
        pin: Zeroizing<Vec<u8>>,
    ) -> Result<Response<InitPinResponse>, Status> {
        let view = self.session(conn, req.session_handle)?;
        self.require(conn, view.slot_id, Need::So)?;
        if !conn.identity.is_admin {
            return Err(Status::permission_denied(
                "InitPin requires an administrator client certificate",
            ));
        }
        let slot_id = view.slot_id;
        let gate = self.shared.gate(slot_id)?;
        let token = self.shared.token(slot_id)?;
        let key = format!("{}|{}|{}", conn.identity.id, slot_id, CKU_SO);
        self.blocking(move |sh| {
            let _g = lock_mutex(&gate.login);
            sh.login_throttle.check(&key)?;
            reset_core_login(&token);
            if let Err(e) = token.login(CKU_SO, &so_pin) {
                if is_pin_failure(&e) {
                    sh.login_throttle.record_failure(&key);
                }
                return Err(hsm_err_to_status(e));
            }
            let r = token.init_pin(&pin);
            let _ = token.logout();
            sh.login_throttle.clear(&key);
            r.map_err(hsm_err_to_status)
        })
        .await?;
        self.shared.audit(
            conn,
            req.session_handle,
            AuditOperation::InitToken {
                slot_id: slot_id as u64,
            },
            AuditResult::Success,
            Some("op=InitPIN".into()),
        )?;
        self.blocking(|sh| {
            sh.flush_audit();
            Ok(())
        })
        .await?;
        Ok(Response::new(InitPinResponse {}))
    }

    /// Mechanism allow-list + algorithm policy for key generation.
    fn keygen_mechanism(&self, mech: &Option<Mechanism>, pair: bool) -> Result<CK_ULONG, Status> {
        let mech = mech
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("mechanism required"))?;
        if !mech.parameter.is_empty() {
            return Err(Status::invalid_argument(
                "Key generation mechanisms take no parameters",
            ));
        }
        let mech_type = to_ck_ulong(mech.mechanism_type, "mechanism_type")?;
        let known = if pair {
            craton_hsm::crypto::mechanisms::is_keypair_gen_mechanism(mech_type)
        } else {
            craton_hsm::crypto::mechanisms::is_keygen_mechanism(mech_type)
        };
        if !known {
            return Err(Status::invalid_argument(
                "Unsupported key generation mechanism",
            ));
        }
        validate_mechanism_for_policy(mech_type, self.shared.hsm.algorithm_config(), false)
            .map_err(|_| Status::permission_denied("Mechanism blocked by algorithm policy"))?;
        Ok(mech_type)
    }

    async fn generate_key_inner(
        &self,
        conn: &ConnInfo,
        req: GenerateKeyRequest,
    ) -> Result<Response<GenerateKeyResponse>, Status> {
        let view = self.session(conn, req.session_handle)?;
        self.require(conn, view.slot_id, Need::User)?;
        let mech_type = self.keygen_mechanism(&req.mechanism, false)?;
        if mech_type != CKM_AES_KEY_GEN {
            return Err(Status::unimplemented("Only CKM_AES_KEY_GEN is supported"));
        }
        // (H4-06) Allow-listed caller template.
        let template = proto_attrs_to_template(&req.template, MAX_LABEL_LEN)?;
        let kt = validate(KeyKind::AesSecret, &template)?;
        let key_len = kt
            .value_len
            .ok_or_else(|| {
                Status::invalid_argument("CKA_VALUE_LEN required in template for key generation")
            })
            .and_then(|l| {
                usize::try_from(l).map_err(|_| Status::invalid_argument("CKA_VALUE_LEN too large"))
            })?;
        self.check_token_object(&kt, &view)?;
        let owner = conn.identity.id.clone();
        self.shared.registry.reserve_objects(&owner, 1)?;
        let fips_mode = self.shared.hsm.algorithm_config().fips_approved_only;
        let slot_id = view.slot_id;
        let session = view.handle;
        let owner2 = owner.clone();
        let handle = self
            .blocking(move |sh| {
                let build = || -> Result<CK_ULONG, Status> {
                    let material = craton_hsm::crypto::keygen::generate_aes_key(key_len, fips_mode)
                        .map_err(hsm_err_to_status)?;
                    let handle = sh
                        .hsm
                        .object_store()
                        .next_handle()
                        .map_err(hsm_err_to_status)?;
                    let mut obj = StoredObject::new(handle, CKO_SECRET_KEY);
                    obj.slot_id = slot_id;
                    obj.key_type = Some(CKK_AES);
                    obj.value_len = Some(key_len as CK_ULONG);
                    obj.key_material = Some(material);
                    obj.can_encrypt = true;
                    obj.can_decrypt = true;
                    obj.sensitive = true;
                    obj.extractable = false;
                    obj.private = true;
                    kt.apply(&mut obj);
                    set_generated_provenance(&mut obj, CKM_AES_KEY_GEN);
                    let token_object = obj.token_object;
                    let h = sh
                        .hsm
                        .object_store()
                        .insert_object(obj)
                        .map_err(hsm_err_to_status)?;
                    sh.track_new_object(&owner2, h, token_object, session)?;
                    Ok(h)
                };
                build().map_err(|e| {
                    sh.registry.unreserve_objects(&owner2, 1);
                    e
                })
            })
            .await?;
        if let Err(e) = self.shared.audit(
            conn,
            req.session_handle,
            AuditOperation::GenerateKey {
                mechanism: CKM_AES_KEY_GEN as u64,
                key_length: u32::try_from(key_len).unwrap_or(u32::MAX),
                fips_approved: is_fips_approved(CKM_AES_KEY_GEN),
            },
            AuditResult::Success,
            Some(format!("handle={}", handle)),
        ) {
            // Roll back: no unaudited key may survive.
            let _ = self.blocking(move |sh| sh.destroy_object_now(handle)).await;
            return Err(e);
        }
        Ok(Response::new(GenerateKeyResponse {
            key_handle: handle as u64,
        }))
    }

    async fn generate_key_pair_inner(
        &self,
        conn: &ConnInfo,
        req: GenerateKeyPairRequest,
    ) -> Result<Response<GenerateKeyPairResponse>, Status> {
        let view = self.session(conn, req.session_handle)?;
        self.require(conn, view.slot_id, Need::User)?;
        let mech_type = self.keygen_mechanism(&req.mechanism, true)?;
        let (pub_kind, priv_kind) = match mech_type {
            CKM_RSA_PKCS_KEY_PAIR_GEN => (KeyKind::RsaPublic, KeyKind::RsaPrivate),
            CKM_EC_KEY_PAIR_GEN => (KeyKind::EcPublic, KeyKind::EcPrivate),
            CKM_EDDSA => (KeyKind::EdPublic, KeyKind::EdPrivate),
            _ => {
                return Err(Status::unimplemented(
                    "This key pair generation mechanism is not supported by the gRPC daemon",
                ))
            }
        };
        // (H4-06) Validate both templates *before* allocating anything.
        let pub_t = validate(
            pub_kind,
            &proto_attrs_to_template(&req.public_template, MAX_LABEL_LEN)?,
        )?;
        let priv_t = validate(
            priv_kind,
            &proto_attrs_to_template(&req.private_template, MAX_LABEL_LEN)?,
        )?;
        enum Params {
            Rsa(u32),
            Ec(Curve),
            Ed,
        }
        let params = match pub_kind {
            KeyKind::RsaPublic => {
                let bits = pub_t.modulus_bits.ok_or_else(|| {
                    Status::invalid_argument("CKA_MODULUS_BITS required in public template")
                })?;
                // (H4-20) No silent truncation.
                Params::Rsa(
                    u32::try_from(bits)
                        .map_err(|_| Status::invalid_argument("CKA_MODULUS_BITS out of range"))?,
                )
            }
            KeyKind::EcPublic => {
                let p = pub_t.ec_params.as_deref().ok_or_else(|| {
                    Status::invalid_argument("CKA_EC_PARAMS required in public template")
                })?;
                // (H4-21) Exact OID match; no silent fallback to P-256.
                Params::Ec(curve_from_params(p).ok_or_else(|| {
                    Status::invalid_argument(
                        "Unsupported EC curve: only P-256 and P-384 named-curve OIDs are accepted",
                    )
                })?)
            }
            _ => {
                if let Some(p) = pub_t.ec_params.as_deref() {
                    if !is_ed25519_params(p) {
                        return Err(Status::invalid_argument(
                            "CKA_EC_PARAMS does not identify Ed25519",
                        ));
                    }
                }
                Params::Ed
            }
        };
        self.check_token_object(&pub_t, &view)?;
        self.check_token_object(&priv_t, &view)?;
        let owner = conn.identity.id.clone();
        self.shared.registry.reserve_objects(&owner, 2)?;
        let fips_mode = self.shared.hsm.algorithm_config().fips_approved_only;
        let slot_id = view.slot_id;
        let session = view.handle;
        let owner2 = owner.clone();

        let (pub_h, priv_h, key_length) = self
            .blocking(move |sh| {
                let build = || -> Result<(CK_ULONG, CK_ULONG, u32), Status> {
                    let store = sh.hsm.object_store();
                    let pub_handle = store.next_handle().map_err(hsm_err_to_status)?;
                    let priv_handle = store.next_handle().map_err(hsm_err_to_status)?;
                    let mut pub_obj = StoredObject::new(pub_handle, CKO_PUBLIC_KEY);
                    let mut priv_obj = StoredObject::new(priv_handle, CKO_PRIVATE_KEY);
                    pub_obj.slot_id = slot_id;
                    priv_obj.slot_id = slot_id;
                    priv_obj.sensitive = true;
                    priv_obj.extractable = false;
                    priv_obj.private = true;
                    let key_length = match params {
                        Params::Rsa(bits) => {
                            let (der, modulus, exp) =
                                craton_hsm::crypto::keygen::generate_rsa_key_pair(bits, fips_mode)
                                    .map_err(hsm_err_to_status)?;
                            pub_obj.key_type = Some(CKK_RSA);
                            pub_obj.modulus = Some(modulus.clone());
                            pub_obj.modulus_bits = Some(bits as CK_ULONG);
                            pub_obj.public_exponent = Some(exp.clone());
                            pub_obj.can_verify = true;
                            pub_obj.can_encrypt = true;
                            priv_obj.key_type = Some(CKK_RSA);
                            priv_obj.modulus = Some(modulus);
                            priv_obj.modulus_bits = Some(bits as CK_ULONG);
                            priv_obj.public_exponent = Some(exp);
                            priv_obj.key_material = Some(der);
                            priv_obj.can_sign = true;
                            priv_obj.can_decrypt = true;
                            bits
                        }
                        Params::Ec(curve) => {
                            let (sk, point, oid, len) = match curve {
                                Curve::P256 => {
                                    let (sk, pt) =
                                        craton_hsm::crypto::keygen::generate_ec_p256_key_pair()
                                            .map_err(hsm_err_to_status)?;
                                    (sk, pt, P256_OID, 256)
                                }
                                Curve::P384 => {
                                    let (sk, pt) =
                                        craton_hsm::crypto::keygen::generate_ec_p384_key_pair()
                                            .map_err(hsm_err_to_status)?;
                                    (sk, pt, P384_OID, 384)
                                }
                            };
                            pub_obj.key_type = Some(CKK_EC);
                            pub_obj.ec_params = Some(oid.to_vec());
                            pub_obj.ec_point = Some(point.clone());
                            pub_obj.can_verify = true;
                            priv_obj.key_type = Some(CKK_EC);
                            priv_obj.ec_params = Some(oid.to_vec());
                            priv_obj.ec_point = Some(point);
                            priv_obj.key_material = Some(sk);
                            priv_obj.can_sign = true;
                            len
                        }
                        Params::Ed => {
                            let (sk, pk) = craton_hsm::crypto::keygen::generate_ed25519_key_pair()
                                .map_err(hsm_err_to_status)?;
                            pub_obj.key_type = Some(CKK_EC_EDWARDS);
                            pub_obj.ec_params = Some(ED25519_OID.to_vec());
                            pub_obj.ec_point = Some(pk.clone());
                            pub_obj.can_verify = true;
                            priv_obj.key_type = Some(CKK_EC_EDWARDS);
                            priv_obj.ec_params = Some(ED25519_OID.to_vec());
                            priv_obj.ec_point = Some(pk);
                            priv_obj.key_material = Some(sk);
                            priv_obj.can_sign = true;
                            255
                        }
                    };
                    pub_t.apply(&mut pub_obj);
                    priv_t.apply(&mut priv_obj);
                    set_generated_provenance(&mut pub_obj, mech_type);
                    set_generated_provenance(&mut priv_obj, mech_type);
                    let pub_token = pub_obj.token_object;
                    let priv_token = priv_obj.token_object;

                    let pub_h = store.insert_object(pub_obj).map_err(hsm_err_to_status)?;
                    let priv_h = match store.insert_object(priv_obj) {
                        Ok(h) => h,
                        Err(e) => {
                            // No orphaned public key.
                            let _ = store.destroy_object(pub_h);
                            return Err(hsm_err_to_status(e));
                        }
                    };
                    if let Err(e) = sh.track_new_object(&owner2, pub_h, pub_token, session) {
                        let _ = store.destroy_object(priv_h);
                        return Err(e);
                    }
                    if let Err(e) = sh.track_new_object(&owner2, priv_h, priv_token, session) {
                        // pub_h is tracked: destroying it releases one slot.
                        let _ = sh.destroy_object_now(pub_h);
                        sh.registry.reserve_objects(&owner2, 1).ok();
                        return Err(e);
                    }
                    Ok((pub_h, priv_h, key_length))
                };
                build().map_err(|e| {
                    sh.registry.unreserve_objects(&owner2, 2);
                    e
                })
            })
            .await?;

        if let Err(e) = self.shared.audit(
            conn,
            req.session_handle,
            AuditOperation::GenerateKeyPair {
                mechanism: mech_type as u64,
                key_length,
                fips_approved: is_fips_approved(mech_type),
            },
            AuditResult::Success,
            Some(format!("pub={}, priv={}", pub_h, priv_h)),
        ) {
            let _ = self
                .blocking(move |sh| {
                    let _ = sh.destroy_object_now(pub_h);
                    let _ = sh.destroy_object_now(priv_h);
                    Ok(())
                })
                .await;
            return Err(e);
        }
        Ok(Response::new(GenerateKeyPairResponse {
            public_key_handle: pub_h as u64,
            private_key_handle: priv_h as u64,
        }))
    }

    /// Common preamble for crypto operations: session, User role, mechanism
    /// allow-list and policy.
    fn crypto_preamble(
        &self,
        conn: &ConnInfo,
        session_handle: u64,
        mech: &Option<Mechanism>,
        signing: bool,
    ) -> Result<(SessionView, CK_ULONG), Status> {
        let view = self.session(conn, session_handle)?;
        self.require(conn, view.slot_id, Need::User)?;
        let m = mech
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("mechanism required"))?;
        let mech_type = to_ck_ulong(m.mechanism_type, "mechanism_type")?;
        let known = if signing {
            craton_hsm::crypto::mechanisms::is_sign_mechanism(mech_type)
        } else {
            craton_hsm::crypto::mechanisms::is_encrypt_mechanism(mech_type)
        };
        if !known {
            return Err(Status::invalid_argument("Unsupported mechanism"));
        }
        validate_mechanism_for_policy(mech_type, self.shared.hsm.algorithm_config(), signing)
            .map_err(|_| Status::permission_denied("Mechanism blocked by algorithm policy"))?;
        Ok((view, mech_type))
    }

    async fn sign_inner(
        &self,
        conn: &ConnInfo,
        req: SignRequest,
    ) -> Result<Response<SignResponse>, Status> {
        let (view, mech_type) =
            self.crypto_preamble(conn, req.session_handle, &req.mechanism, true)?;
        let key = self.load_key(conn, &view, req.key_handle, Usage::Sign)?;
        let param = req
            .mechanism
            .as_ref()
            .map(|m| m.parameter.as_slice())
            .unwrap_or(&[]);
        // (H4-08) The mechanism selects the algorithm; the key must match.
        let alg = sign_alg_for(mech_type, param, &key.read())?;
        let data = req.data;
        let signature = self
            .blocking(move |_| {
                use craton_hsm::crypto::sign as s;
                let k = key.read();
                let kb = k
                    .key_material
                    .as_ref()
                    .ok_or_else(|| Status::internal("Key has no material"))?
                    .as_bytes();
                match alg {
                    SignAlg::RsaPkcs1(h) => s::rsa_pkcs1v15_sign(kb, &data, Some(h.to_core())),
                    SignAlg::RsaPss(h) => s::rsa_pss_sign(kb, &data, h.to_core()),
                    SignAlg::EcdsaP256Sha256 => s::ecdsa_p256_sign(kb, &data),
                    SignAlg::EcdsaP384Sha384 => s::ecdsa_p384_sign(kb, &data),
                    SignAlg::Ed25519 => s::ed25519_sign(kb, &data),
                }
                .map_err(hsm_err_to_status)
            })
            .await?;
        self.shared.audit(
            conn,
            req.session_handle,
            AuditOperation::Sign {
                mechanism: mech_type as u64,
                fips_approved: is_fips_approved(mech_type),
            },
            AuditResult::Success,
            Some(format!("key={} alg={:?}", req.key_handle, alg)),
        )?;
        Ok(Response::new(SignResponse { signature }))
    }

    async fn verify_inner(
        &self,
        conn: &ConnInfo,
        req: VerifyRequest,
    ) -> Result<Response<VerifyResponse>, Status> {
        let (view, mech_type) =
            self.crypto_preamble(conn, req.session_handle, &req.mechanism, true)?;
        let key = self.load_key(conn, &view, req.key_handle, Usage::Verify)?;
        let param = req
            .mechanism
            .as_ref()
            .map(|m| m.parameter.as_slice())
            .unwrap_or(&[]);
        let alg = sign_alg_for(mech_type, param, &key.read())?;
        let data = req.data;
        let signature = req.signature;
        let valid = self
            .blocking(move |_| {
                use craton_hsm::crypto::sign as s;
                let k = key.read();
                let missing = |what: &str| Status::internal(format!("Key missing {}", what));
                match alg {
                    SignAlg::RsaPkcs1(h) | SignAlg::RsaPss(h) => {
                        let n = k.modulus.as_ref().ok_or_else(|| missing("modulus"))?;
                        let e = k
                            .public_exponent
                            .as_ref()
                            .ok_or_else(|| missing("public exponent"))?;
                        if matches!(alg, SignAlg::RsaPss(_)) {
                            s::rsa_pss_verify(n, e, &data, &signature, h.to_core())
                        } else {
                            s::rsa_pkcs1v15_verify(n, e, &data, &signature, Some(h.to_core()))
                        }
                    }
                    SignAlg::EcdsaP256Sha256 | SignAlg::EcdsaP384Sha384 => {
                        let pt = k.ec_point.as_ref().ok_or_else(|| missing("public point"))?;
                        if alg == SignAlg::EcdsaP256Sha256 {
                            s::ecdsa_p256_verify(pt, &data, &signature)
                        } else {
                            s::ecdsa_p384_verify(pt, &data, &signature)
                        }
                    }
                    SignAlg::Ed25519 => {
                        let pk = k.ec_point.as_ref().ok_or_else(|| missing("public key"))?;
                        s::ed25519_verify(pk, &data, &signature)
                    }
                }
                .map_err(hsm_err_to_status)
            })
            .await?;
        self.shared.audit(
            conn,
            req.session_handle,
            AuditOperation::Verify {
                mechanism: mech_type as u64,
                fips_approved: is_fips_approved(mech_type),
            },
            AuditResult::Success,
            // (H4-26) Record the verification outcome.
            Some(format!(
                "key={} alg={:?} valid={}",
                req.key_handle, alg, valid
            )),
        )?;
        Ok(Response::new(VerifyResponse { valid }))
    }

    async fn cipher_inner(
        &self,
        conn: &ConnInfo,
        session_handle: u64,
        mechanism: Option<Mechanism>,
        key_handle: u64,
        input: Vec<u8>,
        decrypt: bool,
    ) -> Result<Vec<u8>, Status> {
        let (view, mech_type) = self.crypto_preamble(conn, session_handle, &mechanism, false)?;
        let usage = if decrypt {
            Usage::Decrypt
        } else {
            Usage::Encrypt
        };
        let key = self.load_key(conn, &view, key_handle, usage)?;
        let param = mechanism.map(|m| m.parameter).unwrap_or_default();
        let alg = cipher_alg_for(mech_type, &param, &key.read(), decrypt)?;
        let out = self
            .blocking(move |_| {
                use craton_hsm::crypto::encrypt as e;
                let k = key.read();
                let material = || -> Result<&[u8], Status> {
                    Ok(k.key_material
                        .as_ref()
                        .ok_or_else(|| Status::internal("Key has no material"))?
                        .as_bytes())
                };
                match (alg, decrypt) {
                    (CipherAlg::AesGcm, false) => e::aes_256_gcm_encrypt(material()?, &input),
                    (CipherAlg::AesGcm, true) => e::aes_256_gcm_decrypt(material()?, &input),
                    (CipherAlg::AesCbcPad, false) => {
                        e::aes_cbc_encrypt(material()?, &param, &input)
                    }
                    (CipherAlg::AesCbcPad, true) => e::aes_cbc_decrypt(material()?, &param, &input),
                    (CipherAlg::AesCtr, false) => e::aes_ctr_encrypt(material()?, &param, &input),
                    (CipherAlg::AesCtr, true) => e::aes_ctr_decrypt(material()?, &param, &input),
                    (CipherAlg::RsaOaepSha256, false) => {
                        let n = k
                            .modulus
                            .as_ref()
                            .ok_or_else(|| Status::internal("RSA key missing modulus"))?;
                        let x = k
                            .public_exponent
                            .as_ref()
                            .ok_or_else(|| Status::internal("RSA key missing public exponent"))?;
                        craton_hsm::crypto::sign::rsa_oaep_encrypt(
                            n,
                            x,
                            &input,
                            craton_hsm::crypto::sign::OaepHash::Sha256,
                        )
                    }
                    (CipherAlg::RsaOaepSha256, true) => craton_hsm::crypto::sign::rsa_oaep_decrypt(
                        material()?,
                        &input,
                        craton_hsm::crypto::sign::OaepHash::Sha256,
                    ),
                }
                .map_err(hsm_err_to_status)
            })
            .await?;
        let op = if decrypt {
            AuditOperation::Decrypt {
                mechanism: mech_type as u64,
                fips_approved: is_fips_approved(mech_type),
            }
        } else {
            AuditOperation::Encrypt {
                mechanism: mech_type as u64,
                fips_approved: is_fips_approved(mech_type),
            }
        };
        self.shared.audit(
            conn,
            session_handle,
            op,
            AuditResult::Success,
            Some(format!("key={} alg={:?}", key_handle, alg)),
        )?;
        Ok(out)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Convert HSM errors to gRPC Status without leaking internal details.
/// The variant is logged server-side (at info, since debug is compiled out
/// in the core's release configuration); clients get sanitized messages.
pub fn hsm_err_to_status(e: HsmError) -> Status {
    tracing::info!(error = ?e, "HSM operation failed");

    match e {
        // ── Authentication errors (deliberately vague) ──────────────────────
        HsmError::PinIncorrect | HsmError::PinLocked => {
            Status::unauthenticated("Authentication failed")
        }
        HsmError::PinInvalid => {
            Status::invalid_argument("PIN does not meet complexity requirements")
        }
        HsmError::PinLenRange => Status::invalid_argument("PIN length out of range"),
        HsmError::PinRateLimited => {
            Status::resource_exhausted("Too many attempts — try again later")
        }
        HsmError::UserNotLoggedIn => Status::permission_denied("Login required"),
        HsmError::UserAlreadyLoggedIn => Status::already_exists("Already logged in"),
        HsmError::UserAnotherAlreadyLoggedIn => {
            Status::failed_precondition("Another user already logged in")
        }
        HsmError::UserTypeInvalid => Status::invalid_argument("Invalid user type"),
        HsmError::UserPinNotInitialized => {
            Status::failed_precondition("User PIN not initialized — SO must call InitPin first")
        }

        // ── Session errors ──────────────────────────────────────────────────
        HsmError::SessionHandleInvalid => Status::not_found("Session not found"),
        HsmError::SessionCount => Status::resource_exhausted("Session limit reached"),
        HsmError::SessionReadOnly => Status::permission_denied("Session is read-only"),
        HsmError::SessionParallelNotSupported => {
            Status::invalid_argument("Parallel sessions not supported")
        }
        HsmError::SessionExists => Status::already_exists("Session already exists"),
        HsmError::SessionReadOnlyExists => Status::failed_precondition("Read-only session exists"),
        HsmError::SessionReadWriteSoExists => {
            Status::failed_precondition("R/W SO session already exists")
        }

        // ── Token/slot errors ───────────────────────────────────────────────
        HsmError::SlotIdInvalid => Status::not_found("Slot not found"),
        HsmError::TokenNotPresent => Status::not_found("Token not present"),
        HsmError::TokenNotInitialized => {
            Status::failed_precondition("Token not initialized — call InitToken first")
        }
        HsmError::TokenWriteProtected => Status::permission_denied("Token is write-protected"),
        HsmError::DeviceError => Status::internal("Device error"),
        HsmError::ActionProhibited => Status::permission_denied("Action prohibited"),

        // ── Object/attribute errors ─────────────────────────────────────────
        HsmError::ObjectHandleInvalid => Status::not_found("Object not found"),
        HsmError::AttributeTypeInvalid => Status::invalid_argument("Invalid attribute type"),
        HsmError::AttributeValueInvalid => Status::invalid_argument("Invalid attribute value"),
        HsmError::AttributeReadOnly => Status::permission_denied("Attribute is read-only"),
        HsmError::AttributeSensitive => {
            Status::permission_denied("Attribute is sensitive — cannot read")
        }
        HsmError::TemplateIncomplete => Status::invalid_argument("Template is incomplete"),
        HsmError::TemplateInconsistent => Status::invalid_argument("Template is inconsistent"),

        // ── Crypto/mechanism errors ─────────────────────────────────────────
        HsmError::MechanismInvalid => Status::invalid_argument("Unsupported mechanism"),
        HsmError::MechanismParamInvalid => Status::invalid_argument("Invalid mechanism parameters"),
        HsmError::KeyHandleInvalid => Status::not_found("Key not found"),
        HsmError::KeyTypeInconsistent => {
            Status::invalid_argument("Key type does not match mechanism")
        }
        HsmError::KeySizeRange => Status::invalid_argument("Key size out of range"),
        HsmError::KeyFunctionNotPermitted => {
            Status::permission_denied("Key not permitted for this operation")
        }
        HsmError::OperationActive => {
            Status::failed_precondition("Another operation is already active")
        }
        HsmError::OperationNotInitialized => {
            Status::failed_precondition("No operation initialized — call *Init first")
        }

        // ── Data errors ─────────────────────────────────────────────────────
        HsmError::ArgumentsBad => Status::invalid_argument("Invalid argument"),
        HsmError::DataInvalid => Status::invalid_argument("Invalid input data"),
        HsmError::DataLenRange => Status::invalid_argument("Input data length out of range"),
        HsmError::EncryptedDataInvalid => Status::invalid_argument("Invalid encrypted data"),
        HsmError::EncryptedDataLenRange => {
            Status::invalid_argument("Encrypted data length out of range")
        }
        HsmError::SignatureInvalid => Status::invalid_argument("Signature verification failed"),
        HsmError::SignatureLenRange => Status::invalid_argument("Signature length out of range"),
        HsmError::BufferTooSmall => Status::internal("Buffer too small"),

        // ── Capability errors ───────────────────────────────────────────────
        HsmError::FunctionNotSupported => Status::unimplemented("Operation not supported"),
        HsmError::RandomSeedNotSupported => Status::unimplemented("Random seed not supported"),

        // ── System errors (intentionally vague) ─────────────────────────────
        HsmError::NotInitialized => Status::failed_precondition("Cryptoki not initialized"),
        HsmError::AlreadyInitialized => Status::already_exists("Already initialized"),
        HsmError::GeneralError
        | HsmError::HostMemory
        | HsmError::DeviceMemory
        | HsmError::ConfigError(_)
        | HsmError::AuditChainBroken(_) => Status::internal("Internal error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::ClientIdentity;
    use craton_hsm::config::config::HsmConfig;
    use tonic::Code;

    // Test-only PINs (never used outside this test module).
    const SO_PIN: &[u8] = b"TestSo-Pin-01";
    const USER_PIN: &[u8] = b"TestUser-Pin-02";

    fn service_with(fips: bool) -> HsmServiceImpl {
        let mut cfg = HsmConfig::default();
        cfg.audit.enabled = false;
        cfg.security.pbkdf2_iterations = 1000;
        cfg.algorithms.fips_approved_only = fips;
        let hsm = Arc::new(HsmCore::try_new(&cfg).unwrap());
        HsmServiceImpl::new(
            hsm,
            ServiceSettings {
                max_random_length: 1024,
                max_digest_length: 4096,
                max_response_bytes: 1 << 20,
                max_login_attempts: 3,
                login_cooldown: Duration::from_secs(60),
                max_sessions_per_client: 4,
                max_objects_per_client: 16,
                max_blocking_tasks: 2,
            },
        )
    }

    fn service() -> HsmServiceImpl {
        service_with(false)
    }

    fn client(name: &str, admin: bool, conn_id: u64) -> ConnInfo {
        ConnInfo::new(
            conn_id,
            ClientIdentity {
                id: Arc::from(format!("cert:{}", name)),
                authenticated: true,
                is_admin: admin,
            },
            None,
        )
    }

    fn rq<T>(c: &ConnInfo, msg: T) -> Request<T> {
        let mut r = Request::new(msg);
        r.extensions_mut().insert(c.clone());
        r
    }

    fn ul(v: CK_ULONG) -> Vec<u8> {
        v.to_ne_bytes().to_vec()
    }

    fn mech(m: CK_ULONG) -> Option<Mechanism> {
        Some(Mechanism {
            mechanism_type: m as u64,
            parameter: vec![],
        })
    }

    async fn open(svc: &HsmServiceImpl, c: &ConnInfo) -> Result<u64, Status> {
        svc.open_session(rq(
            c,
            OpenSessionRequest {
                slot_id: 0,
                read_write: true,
            },
        ))
        .await
        .map(|r| r.into_inner().session_handle)
    }

    async fn login(
        svc: &HsmServiceImpl,
        c: &ConnInfo,
        sh: u64,
        user_type: CK_ULONG,
        pin: &[u8],
    ) -> Result<(), Status> {
        svc.login(rq(
            c,
            LoginRequest {
                session_handle: sh,
                user_type: user_type as u64,
                pin: pin.to_vec(),
            },
        ))
        .await
        .map(|_| ())
    }

    async fn random(svc: &HsmServiceImpl, c: &ConnInfo, sh: u64) -> Result<(), Status> {
        svc.generate_random(rq(
            c,
            GenerateRandomRequest {
                session_handle: sh,
                length: 16,
            },
        ))
        .await
        .map(|_| ())
    }

    async fn close(svc: &HsmServiceImpl, c: &ConnInfo, sh: u64) -> Result<(), Status> {
        svc.close_session(rq(c, CloseSessionRequest { session_handle: sh }))
            .await
            .map(|_| ())
    }

    /// Initialise the token and the User PIN as administrator.
    async fn provision(svc: &HsmServiceImpl) -> ConnInfo {
        let admin = client("admin", true, 100);
        svc.init_token(rq(
            &admin,
            InitTokenRequest {
                slot_id: 0,
                so_pin: SO_PIN.to_vec(),
                label: "test".into(),
            },
        ))
        .await
        .unwrap();
        let sh = open(svc, &admin).await.unwrap();
        login(svc, &admin, sh, CKU_SO, SO_PIN).await.unwrap();
        svc.init_pin(rq(
            &admin,
            InitPinRequest {
                session_handle: sh,
                so_pin: SO_PIN.to_vec(),
                pin: USER_PIN.to_vec(),
            },
        ))
        .await
        .unwrap();
        close(svc, &admin, sh).await.unwrap();
        admin
    }

    async fn user_session(svc: &HsmServiceImpl, c: &ConnInfo) -> u64 {
        let sh = open(svc, c).await.unwrap();
        login(svc, c, sh, CKU_USER, USER_PIN).await.unwrap();
        sh
    }

    #[tokio::test]
    async fn init_token_requires_admin_and_no_open_sessions() {
        let svc = service();
        let user = client("u", false, 1);
        let err = svc
            .init_token(rq(
                &user,
                InitTokenRequest {
                    slot_id: 0,
                    so_pin: SO_PIN.to_vec(),
                    label: "x".into(),
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);

        let admin = provision(&svc).await;
        let _sh = open(&svc, &user).await.unwrap();
        let err = svc
            .init_token(rq(
                &admin,
                InitTokenRequest {
                    slot_id: 0,
                    so_pin: SO_PIN.to_vec(),
                    label: "x".into(),
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn session_handles_are_bound_to_their_client() {
        let svc = service();
        provision(&svc).await;
        let a = client("a", false, 1);
        let b = client("b", false, 2);
        let sh = user_session(&svc, &a).await;
        assert!(random(&svc, &a, sh).await.is_ok());
        assert_eq!(
            random(&svc, &b, sh).await.unwrap_err().code(),
            Code::NotFound
        );
        assert_eq!(
            close(&svc, &b, sh).await.unwrap_err().code(),
            Code::NotFound
        );
        assert!(random(&svc, &a, sh).await.is_ok());
    }

    #[tokio::test]
    async fn login_and_logout_are_per_client() {
        let svc = service();
        provision(&svc).await;
        let a = client("a", false, 1);
        let b = client("b", false, 2);
        let sa = user_session(&svc, &a).await;
        let sb = open(&svc, &b).await.unwrap();
        // A's login does not authenticate B.
        assert_eq!(
            random(&svc, &b, sb).await.unwrap_err().code(),
            Code::PermissionDenied
        );
        // B's logout does not log A out.
        assert!(svc
            .logout(rq(&b, LogoutRequest { session_handle: sb }))
            .await
            .is_err());
        assert!(random(&svc, &a, sa).await.is_ok());
        // Wrong PIN from B does not affect A either.
        assert!(login(&svc, &b, sb, CKU_USER, b"Wrong-Pin-99")
            .await
            .is_err());
        assert!(random(&svc, &a, sa).await.is_ok());
        svc.logout(rq(&a, LogoutRequest { session_handle: sa }))
            .await
            .unwrap();
        assert_eq!(
            random(&svc, &a, sa).await.unwrap_err().code(),
            Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn so_role_is_admin_only_and_cannot_use_keys() {
        let svc = service();
        let admin = provision(&svc).await;
        let u = client("u", false, 1);
        let su = open(&svc, &u).await.unwrap();
        assert_eq!(
            login(&svc, &u, su, CKU_SO, SO_PIN)
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        let sa = open(&svc, &admin).await.unwrap();
        login(&svc, &admin, sa, CKU_SO, SO_PIN).await.unwrap();
        let err = svc
            .generate_key(rq(
                &admin,
                GenerateKeyRequest {
                    session_handle: sa,
                    mechanism: mech(CKM_AES_KEY_GEN),
                    template: vec![Attribute {
                        attr_type: CKA_VALUE_LEN as u64,
                        value: ul(32),
                    }],
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn key_templates_are_allow_listed_and_provenance_is_set() {
        let svc = service();
        provision(&svc).await;
        let a = client("a", false, 1);
        let sh = user_session(&svc, &a).await;
        let gen = |template: Vec<Attribute>| {
            svc.generate_key(rq(
                &a,
                GenerateKeyRequest {
                    session_handle: sh,
                    mechanism: mech(CKM_AES_KEY_GEN),
                    template,
                },
            ))
        };
        for (attr, value) in [
            (CKA_VALUE, vec![0x41; 32]),
            (CKA_CLASS, ul(CKO_PRIVATE_KEY)),
            (CKA_KEY_TYPE, ul(CKK_EC)),
            (CKA_LOCAL, vec![1]),
            (CKA_SIGN, vec![1]),
        ] {
            let err = gen(vec![
                Attribute {
                    attr_type: CKA_VALUE_LEN as u64,
                    value: ul(32),
                },
                Attribute {
                    attr_type: attr as u64,
                    value,
                },
            ])
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument, "attr 0x{:X}", attr);
        }
        // Token objects are refused while the state is not persistent.
        let err = gen(vec![
            Attribute {
                attr_type: CKA_VALUE_LEN as u64,
                value: ul(32),
            },
            Attribute {
                attr_type: CKA_TOKEN as u64,
                value: vec![1],
            },
        ])
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);

        let key = gen(vec![Attribute {
            attr_type: CKA_VALUE_LEN as u64,
            value: ul(32),
        }])
        .await
        .unwrap()
        .into_inner()
        .key_handle;
        let attrs = svc
            .get_attribute_value(rq(
                &a,
                GetAttributeValueRequest {
                    session_handle: sh,
                    object_handle: key,
                    attribute_types: vec![CKA_LOCAL as u64, CKA_VALUE as u64, CKA_LOCAL as u64],
                },
            ))
            .await
            .unwrap()
            .into_inner()
            .attributes;
        assert_eq!(attrs.len(), 2, "duplicates are collapsed");
        assert_eq!(attrs[0].value, vec![1u8]);
        assert!(attrs[1].value.is_empty(), "sensitive value never returned");

        let err = svc
            .get_attribute_value(rq(
                &a,
                GetAttributeValueRequest {
                    session_handle: sh,
                    object_handle: key,
                    attribute_types: (0..65).collect(),
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn mechanism_is_bound_to_key_type() {
        let svc = service();
        provision(&svc).await;
        let a = client("a", false, 1);
        let sh = user_session(&svc, &a).await;
        let pair = svc
            .generate_key_pair(rq(
                &a,
                GenerateKeyPairRequest {
                    session_handle: sh,
                    mechanism: mech(CKM_EDDSA),
                    public_template: vec![],
                    private_template: vec![],
                },
            ))
            .await
            .unwrap()
            .into_inner();
        let sign = |m: CK_ULONG| {
            svc.sign(rq(
                &a,
                SignRequest {
                    session_handle: sh,
                    mechanism: mech(m),
                    key_handle: pair.private_key_handle,
                    data: b"hello".to_vec(),
                },
            ))
        };
        assert_eq!(
            sign(CKM_ECDSA_SHA256).await.unwrap_err().code(),
            Code::InvalidArgument
        );
        let sig = sign(CKM_EDDSA).await.unwrap().into_inner().signature;
        let ok = svc
            .verify(rq(
                &a,
                VerifyRequest {
                    session_handle: sh,
                    mechanism: mech(CKM_EDDSA),
                    key_handle: pair.public_key_handle,
                    data: b"hello".to_vec(),
                    signature: sig,
                },
            ))
            .await
            .unwrap()
            .into_inner()
            .valid;
        assert!(ok);

        // EC generation rejects unknown curves instead of falling back.
        let err = svc
            .generate_key_pair(rq(
                &a,
                GenerateKeyPairRequest {
                    session_handle: sh,
                    mechanism: mech(CKM_EC_KEY_PAIR_GEN),
                    public_template: vec![Attribute {
                        attr_type: CKA_EC_PARAMS as u64,
                        value: vec![0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23], // P-521
                    }],
                    private_template: vec![],
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn sessions_and_session_objects_are_cleaned_up() {
        let svc = service();
        provision(&svc).await;
        let a = client("a", false, 7);
        let sh = user_session(&svc, &a).await;
        let key = svc
            .generate_key(rq(
                &a,
                GenerateKeyRequest {
                    session_handle: sh,
                    mechanism: mech(CKM_AES_KEY_GEN),
                    template: vec![Attribute {
                        attr_type: CKA_VALUE_LEN as u64,
                        value: ul(32),
                    }],
                },
            ))
            .await
            .unwrap()
            .into_inner()
            .key_handle;
        // Another client cannot see the session object.
        let b = client("b", false, 8);
        let sb = user_session(&svc, &b).await;
        let found = svc
            .find_objects(rq(
                &b,
                FindObjectsRequest {
                    session_handle: sb,
                    template: vec![],
                    max_count: 0,
                },
            ))
            .await
            .unwrap()
            .into_inner()
            .object_handles;
        assert!(!found.contains(&key));

        // Connection loss closes the sessions and destroys session objects.
        let shared = svc.shared();
        assert_eq!(shared.cleanup_connection(7), 1);
        assert!(shared
            .hsm
            .object_store()
            .get_object(key as CK_ULONG)
            .is_err());
        assert_eq!(
            random(&svc, &a, sh).await.unwrap_err().code(),
            Code::NotFound
        );
        // A's login ended with its last session.
        assert_eq!(shared.registry.role("cert:a", 0), None);
    }

    #[tokio::test]
    async fn per_client_session_quota() {
        let svc = service();
        let a = client("a", false, 1);
        for _ in 0..4 {
            open(&svc, &a).await.unwrap();
        }
        assert_eq!(
            open(&svc, &a).await.unwrap_err().code(),
            Code::ResourceExhausted
        );
        // Other clients are unaffected.
        assert!(open(&svc, &client("b", false, 2)).await.is_ok());
    }

    #[tokio::test]
    async fn digest_enforces_fips_policy() {
        let svc = service_with(true);
        provision(&svc).await;
        let a = client("a", false, 1);
        let sh = user_session(&svc, &a).await;
        let digest = |m: CK_ULONG| {
            svc.digest(rq(
                &a,
                DigestRequest {
                    session_handle: sh,
                    mechanism: mech(m),
                    data: b"abc".to_vec(),
                },
            ))
        };
        assert_eq!(
            digest(CKM_SHA_1).await.unwrap_err().code(),
            Code::PermissionDenied
        );
        assert_eq!(
            digest(CKM_SHA256).await.unwrap().into_inner().digest.len(),
            32
        );
    }

    #[test]
    fn pin_messages_do_not_debug_print_pins() {
        let s = format!(
            "{:?}",
            LoginRequest {
                session_handle: 1,
                user_type: 1,
                pin: b"secret-pin".to_vec(),
            }
        );
        assert!(!s.contains("secret") && s.contains("REDACTED"));
    }
}
