// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;

use super::handle::SessionHandleAllocator;
use super::session::Session;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::*;
use crate::token::token::{LoginState, Token};

/// Identifier of the application that owns a session. The C ABI uses
/// [`PROCESS_APPLICATION`] (one application per process); the daemon passes
/// an identifier of the authenticated client connection.
pub type ApplicationId = u64;

/// Application id used for sessions opened through the in-process C ABI.
pub const PROCESS_APPLICATION: ApplicationId = 0;

/// Lock ordering: `Token.auth` → `SessionManager.sessions` shard → `Session`
/// `RwLock`. Functions that iterate the session map collect handles first and
/// lock sessions individually afterwards (H3 concurrency notes).
pub struct SessionManager {
    sessions: DashMap<CK_SESSION_HANDLE, Arc<RwLock<Session>>>,
    handle_alloc: SessionHandleAllocator,
    /// Open sessions per application (per-application cap).
    per_app: DashMap<ApplicationId, usize>,
    max_sessions_per_app: usize,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self::with_app_limit(usize::MAX)
    }

    /// Session manager with a per-application open-session cap.
    pub fn with_app_limit(max_sessions_per_app: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            handle_alloc: SessionHandleAllocator::new(),
            per_app: DashMap::new(),
            max_sessions_per_app: max_sessions_per_app.max(1),
        }
    }

    /// Open a session for the in-process application.
    pub fn open_session(
        &self,
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
        token: &Token,
    ) -> HsmResult<CK_SESSION_HANDLE> {
        self.open_session_for_app(slot_id, flags, token, PROCESS_APPLICATION)
    }

    /// Open a session on behalf of `app`.
    ///
    /// The login-state read, the session-count increment, the derivation of
    /// the session state and the insertion into the session table all happen
    /// while the token's auth lock is held (H3-08), so a concurrent
    /// `C_Logout`/`C_Login` either sees the new session in `logout_all` /
    /// `login_all` or happens entirely before it.
    pub fn open_session_for_app(
        &self,
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
        token: &Token,
        app: ApplicationId,
    ) -> HsmResult<CK_SESSION_HANDLE> {
        // CKF_SERIAL_SESSION is mandatory per PKCS#11 spec
        if (flags & CKF_SERIAL_SESSION) == 0 {
            return Err(HsmError::SessionParallelNotSupported);
        }
        let is_rw = (flags & CKF_RW_SESSION) != 0;

        // Per-application cap (reserve first, release on failure).
        {
            let mut n = self.per_app.entry(app).or_insert(0);
            if *n >= self.max_sessions_per_app {
                return Err(HsmError::SessionCount);
            }
            *n += 1;
        }

        let result = token.open_session_with(is_rw, |login| {
            let mut session = Session::new(0, slot_id, flags);
            session.app_id = app;
            match login {
                LoginState::UserLoggedIn => session.on_user_login()?,
                LoginState::SoLoggedIn => session.on_so_login()?,
                LoginState::Public => {}
            }
            use dashmap::mapref::entry::Entry;
            for _ in 0..16 {
                let handle = self
                    .handle_alloc
                    .next_unused(|h| self.sessions.contains_key(&h))?;
                if let Entry::Vacant(v) = self.sessions.entry(handle) {
                    session.handle = handle;
                    v.insert(Arc::new(RwLock::new(session)));
                    return Ok(handle);
                }
            }
            Err(HsmError::GeneralError)
        });
        if result.is_err() {
            self.release_app(app);
        }
        result
    }

    fn release_app(&self, app: ApplicationId) {
        if let Some(mut n) = self.per_app.get_mut(&app) {
            *n = n.saturating_sub(1);
        }
        self.per_app.remove_if(&app, |_, n| *n == 0);
    }

    fn finish_close(&self, session: &Arc<RwLock<Session>>, token: &Token) -> HsmResult<()> {
        // Eagerly zeroize CSPs held in active operations rather than
        // relying on Arc refcount reaching zero (another thread may
        // still hold a clone from get_session).
        let (rw, app) = {
            let mut s = session.write();
            s.active_operation = None;
            s.find_context = None;
            s.closed = true;
            (s.is_rw(), s.app_id)
        };
        self.release_app(app);
        // Decrement after releasing the session lock (lock ordering). When
        // this was the token's last session, the token logs out (H1-06).
        token.decrement_session_count(rw)
    }

    /// Close one session. Callers that own an object store must also destroy
    /// the session's objects (see `HsmCore::close_session`).
    pub fn close_session(&self, handle: CK_SESSION_HANDLE, token: &Token) -> HsmResult<()> {
        let (_, session) = self
            .sessions
            .remove(&handle)
            .ok_or(HsmError::SessionHandleInvalid)?;
        self.finish_close(&session, token)
    }

    /// Close every session of `slot_id`. Returns the closed handles so the
    /// caller can destroy their session objects.
    pub fn close_all_sessions(&self, slot_id: CK_SLOT_ID, token: &Token) -> Vec<CK_SESSION_HANDLE> {
        let handles: Vec<CK_SESSION_HANDLE> = self
            .sessions
            .iter()
            .filter(|e| e.value().read().slot_id == slot_id)
            .map(|e| *e.key())
            .collect();
        let mut closed = Vec::with_capacity(handles.len());
        for h in handles {
            if let Some((_, session)) = self.sessions.remove(&h) {
                if let Err(e) = self.finish_close(&session, token) {
                    tracing::error!("close_all_sessions: decrement failed: {:?}", e);
                }
                closed.push(h);
            }
        }
        closed
    }

    pub fn get_session(&self, handle: CK_SESSION_HANDLE) -> HsmResult<Arc<RwLock<Session>>> {
        self.sessions
            .get(&handle)
            .map(|s| s.value().clone())
            .ok_or(HsmError::SessionHandleInvalid)
    }

    /// Handles of all open sessions of a slot.
    pub fn session_handles(&self, slot_id: CK_SLOT_ID) -> Vec<CK_SESSION_HANDLE> {
        self.sessions
            .iter()
            .filter(|e| e.value().read().slot_id == slot_id)
            .map(|e| *e.key())
            .collect()
    }

    /// True if any session is open on `slot_id`.
    pub fn has_sessions(&self, slot_id: CK_SLOT_ID) -> bool {
        self.sessions
            .iter()
            .any(|e| e.value().read().slot_id == slot_id)
    }

    /// Login across all sessions for a given slot.
    ///
    /// Idempotent: sessions that are already in the target state (e.g.
    /// opened after the token login and therefore already promoted) are
    /// skipped, so a concurrent `C_OpenSession` can no longer make
    /// `login_all` fail and roll back (H3-21). On any other error the
    /// sessions changed so far are rolled back and the error is returned;
    /// the caller must then log the token out.
    pub fn login_all(&self, slot_id: CK_SLOT_ID, user_type: CK_ULONG) -> HsmResult<()> {
        if user_type != CKU_USER && user_type != CKU_SO {
            return Err(HsmError::UserTypeInvalid);
        }
        let handles = self.session_handles(slot_id);
        let mut logged_in: Vec<CK_SESSION_HANDLE> = Vec::new();
        for &handle in &handles {
            let sess = match self.get_session(handle) {
                Ok(s) => s,
                Err(_) => continue, // closed meanwhile
            };
            let mut s = sess.write();
            if s.slot_id != slot_id || s.closed {
                continue;
            }
            let already = match user_type {
                CKU_USER => s.state.is_user(),
                _ => s.state.is_so(),
            };
            if already {
                continue;
            }
            let result = match user_type {
                CKU_USER => s.on_user_login(),
                _ => s.on_so_login(),
            };
            drop(s);
            if let Err(e) = result {
                for &rb in &logged_in {
                    if let Ok(rb_sess) = self.get_session(rb) {
                        let _ = rb_sess.write().on_logout();
                    }
                }
                return Err(e);
            }
            logged_in.push(handle);
        }
        Ok(())
    }

    /// Logout across all sessions for a given slot (user or SO).
    ///
    /// Collects handles first, then locks each session individually (no
    /// session lock is taken while a map shard is held). Every reachable
    /// session is attempted; the first error is returned.
    pub fn logout_all(&self, slot_id: CK_SLOT_ID) -> HsmResult<()> {
        let mut first_err: Option<HsmError> = None;
        for handle in self.session_handles(slot_id) {
            if let Ok(sess) = self.get_session(handle) {
                let mut s = sess.write();
                if s.slot_id == slot_id && s.state.is_authenticated() {
                    if let Err(e) = s.on_logout() {
                        tracing::error!("logout_all: failed to logout session {}: {:?}", handle, e);
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                    }
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    pub fn has_ro_sessions(&self, slot_id: CK_SLOT_ID) -> bool {
        self.sessions.iter().any(|entry| {
            let s = entry.value().read();
            s.slot_id == slot_id && !s.is_rw()
        })
    }

    /// Remove every session without touching token counters (used when the
    /// whole core is being finalized). Returns the removed handles.
    pub fn drain_all(&self) -> Vec<CK_SESSION_HANDLE> {
        let handles: Vec<CK_SESSION_HANDLE> = self.sessions.iter().map(|e| *e.key()).collect();
        for h in &handles {
            if let Some((_, s)) = self.sessions.remove(h) {
                let mut s = s.write();
                s.active_operation = None;
                s.find_context = None;
                s.closed = true;
            }
        }
        self.per_app.clear();
        handles
    }
}
