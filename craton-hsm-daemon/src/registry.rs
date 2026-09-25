// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Per-client authorization state (H4-01, H4-10, H4-15).
//!
//! The core library keeps one login state per token, shared by every caller
//! (the in-process PKCS#11 model). For a network service that is not
//! acceptable, so the daemon keeps its own state keyed by the authenticated
//! client identity:
//!
//! - every session handle is owned by the identity (and connection) that
//!   opened it; other identities cannot use or close it;
//! - login state is per (identity, slot) and ends when the client logs out or
//!   closes its last session on the slot; the core token is only used to
//!   verify PINs and is immediately returned to the public state;
//! - per-identity quotas bound sessions and objects;
//! - session objects (`CKA_TOKEN=false`) belong to the session that created
//!   them, are invisible to other identities and are destroyed with it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use craton_hsm::pkcs11_abi::types::CK_ULONG;
use tonic::Status;

/// PKCS#11 role held by a client on a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    User,
    So,
}

impl Role {
    /// Stable wire name (GetTokenInfo.login_state).
    pub fn as_str(self) -> &'static str {
        match self {
            Role::User => "UserLoggedIn",
            Role::So => "SoLoggedIn",
        }
    }
}

#[derive(Debug)]
pub struct SessionRecord {
    pub owner: Arc<str>,
    pub conn_id: u64,
    pub slot_id: CK_ULONG,
    pub rw: bool,
    last_used: Instant,
    /// Session objects created in this session.
    pub objects: Vec<CK_ULONG>,
}

/// What a handler learns about an authorized session.
#[derive(Clone, Copy, Debug)]
pub struct SessionView {
    pub handle: CK_ULONG,
    pub slot_id: CK_ULONG,
    pub rw: bool,
}

#[derive(Default, Debug)]
struct ClientState {
    sessions: usize,
    logins: HashMap<CK_ULONG, Role>,
    objects: usize,
}

impl ClientState {
    fn is_empty(&self) -> bool {
        self.sessions == 0 && self.logins.is_empty() && self.objects == 0
    }
}

#[derive(Default)]
struct Inner {
    sessions: HashMap<CK_ULONG, SessionRecord>,
    clients: HashMap<Arc<str>, ClientState>,
    /// Owner of every object created through the daemon, plus the owning
    /// session for session objects.
    objects: HashMap<CK_ULONG, (Arc<str>, Option<CK_ULONG>)>,
}

pub struct Registry {
    inner: Mutex<Inner>,
    max_sessions_per_client: usize,
    max_objects_per_client: usize,
}

fn not_found_session() -> Status {
    Status::not_found("Session not found")
}

impl Registry {
    pub fn new(max_sessions_per_client: usize, max_objects_per_client: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            max_sessions_per_client,
            max_objects_per_client,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn gc(inner: &mut Inner, owner: &Arc<str>) {
        if inner.clients.get(owner).map_or(false, |c| c.is_empty()) {
            inner.clients.remove(owner);
        }
    }

    /// Reserve one session slot for `owner` (per-identity quota).
    pub fn reserve_session(
        &self,
        owner: &Arc<str>,
        slot_id: CK_ULONG,
        rw: bool,
    ) -> Result<(), Status> {
        let mut inner = self.lock();
        let st = inner.clients.entry(owner.clone()).or_default();
        // PKCS#11: while the application is logged in as SO, only R/W
        // sessions may be opened.
        if !rw && st.logins.get(&slot_id) == Some(&Role::So) {
            Self::gc(&mut inner, owner);
            return Err(Status::failed_precondition(
                "R/W SO session exists — only read-write sessions may be opened",
            ));
        }
        if st.sessions >= self.max_sessions_per_client {
            Self::gc(&mut inner, owner);
            return Err(Status::resource_exhausted(
                "Per-client session limit reached — close unused sessions",
            ));
        }
        st.sessions += 1;
        Ok(())
    }

    /// Undo `reserve_session` when opening the core session failed.
    pub fn cancel_reservation(&self, owner: &Arc<str>) {
        let mut inner = self.lock();
        if let Some(st) = inner.clients.get_mut(owner) {
            st.sessions = st.sessions.saturating_sub(1);
        }
        Self::gc(&mut inner, owner);
    }

    /// Record a newly opened (and already reserved) session.
    pub fn insert_session(
        &self,
        handle: CK_ULONG,
        owner: Arc<str>,
        conn_id: u64,
        slot_id: CK_ULONG,
        rw: bool,
    ) {
        self.lock().sessions.insert(
            handle,
            SessionRecord {
                owner,
                conn_id,
                slot_id,
                rw,
                last_used: Instant::now(),
                objects: Vec::new(),
            },
        );
    }

    /// Authorize use of `handle` by `owner`. A handle owned by a different
    /// identity is reported exactly like a non-existent one.
    pub fn authorize(&self, handle: CK_ULONG, owner: &str) -> Result<SessionView, Status> {
        let mut inner = self.lock();
        let rec = inner
            .sessions
            .get_mut(&handle)
            .ok_or_else(not_found_session)?;
        if &*rec.owner != owner {
            return Err(not_found_session());
        }
        rec.last_used = Instant::now();
        Ok(SessionView {
            handle,
            slot_id: rec.slot_id,
            rw: rec.rw,
        })
    }

    pub fn role(&self, owner: &str, slot_id: CK_ULONG) -> Option<Role> {
        self.lock()
            .clients
            .get(owner)
            .and_then(|c| c.logins.get(&slot_id).copied())
    }

    fn has_session_on_slot(inner: &Inner, owner: &str, slot_id: CK_ULONG, ro_only: bool) -> bool {
        inner
            .sessions
            .values()
            .any(|s| &*s.owner == owner && s.slot_id == slot_id && (!ro_only || !s.rw))
    }

    pub fn has_ro_session(&self, owner: &str, slot_id: CK_ULONG) -> bool {
        Self::has_session_on_slot(&self.lock(), owner, slot_id, true)
    }

    /// Record a successful login. Fails if the client no longer has a
    /// session on the slot (it was closed concurrently) or already holds a
    /// role there.
    pub fn set_login(&self, owner: &Arc<str>, slot_id: CK_ULONG, role: Role) -> Result<(), Status> {
        let mut inner = self.lock();
        if !Self::has_session_on_slot(&inner, owner, slot_id, false) {
            return Err(not_found_session());
        }
        let st = inner.clients.entry(owner.clone()).or_default();
        match st.logins.get(&slot_id) {
            Some(r) if *r == role => Err(Status::already_exists("Already logged in")),
            Some(_) => Err(Status::failed_precondition(
                "Another user already logged in",
            )),
            None => {
                st.logins.insert(slot_id, role);
                Ok(())
            }
        }
    }

    /// Clear the client's login on the slot. Returns false if not logged in.
    pub fn clear_login(&self, owner: &Arc<str>, slot_id: CK_ULONG) -> bool {
        let mut inner = self.lock();
        let removed = inner
            .clients
            .get_mut(owner)
            .map_or(false, |c| c.logins.remove(&slot_id).is_some());
        Self::gc(&mut inner, owner);
        removed
    }

    /// Drop every client login on a slot (after InitToken).
    pub fn clear_slot_logins(&self, slot_id: CK_ULONG) {
        let mut inner = self.lock();
        for c in inner.clients.values_mut() {
            c.logins.remove(&slot_id);
        }
        inner.clients.retain(|_, c| !c.is_empty());
    }

    /// Remove a session record. When it was the owner's last session on the
    /// slot, the owner's login on that slot ends (PKCS#11 semantics).
    pub fn take_session(&self, handle: CK_ULONG) -> Option<SessionRecord> {
        let mut inner = self.lock();
        let rec = inner.sessions.remove(&handle)?;
        let still_open = Self::has_session_on_slot(&inner, &rec.owner, rec.slot_id, false);
        if let Some(st) = inner.clients.get_mut(&rec.owner) {
            st.sessions = st.sessions.saturating_sub(1);
            if !still_open {
                st.logins.remove(&rec.slot_id);
            }
        }
        let owner = rec.owner.clone();
        Self::gc(&mut inner, &owner);
        Some(rec)
    }

    pub fn sessions_of_conn(&self, conn_id: u64) -> Vec<CK_ULONG> {
        self.lock()
            .sessions
            .iter()
            .filter(|(_, s)| s.conn_id == conn_id)
            .map(|(h, _)| *h)
            .collect()
    }

    pub fn idle_sessions(&self, timeout: Duration) -> Vec<CK_ULONG> {
        let now = Instant::now();
        self.lock()
            .sessions
            .iter()
            .filter(|(_, s)| now.duration_since(s.last_used) >= timeout)
            .map(|(h, _)| *h)
            .collect()
    }

    pub fn slot_has_sessions(&self, slot_id: CK_ULONG) -> bool {
        self.lock().sessions.values().any(|s| s.slot_id == slot_id)
    }

    /// (sessions, rw sessions) owned by `owner` on `slot_id`.
    pub fn session_counts(&self, owner: &str, slot_id: CK_ULONG) -> (u64, u64) {
        let inner = self.lock();
        let mut n = 0u64;
        let mut rw = 0u64;
        for s in inner.sessions.values() {
            if &*s.owner == owner && s.slot_id == slot_id {
                n += 1;
                if s.rw {
                    rw += 1;
                }
            }
        }
        (n, rw)
    }

    /// Reserve `n` objects against the owner's quota.
    pub fn reserve_objects(&self, owner: &Arc<str>, n: usize) -> Result<(), Status> {
        let mut inner = self.lock();
        let st = inner.clients.entry(owner.clone()).or_default();
        if st.objects + n > self.max_objects_per_client {
            Self::gc(&mut inner, owner);
            return Err(Status::resource_exhausted(
                "Per-client object limit reached",
            ));
        }
        st.objects += n;
        Ok(())
    }

    /// Release `n` reserved-but-unused object slots.
    pub fn unreserve_objects(&self, owner: &Arc<str>, n: usize) {
        let mut inner = self.lock();
        if let Some(st) = inner.clients.get_mut(owner) {
            st.objects = st.objects.saturating_sub(n);
        }
        Self::gc(&mut inner, owner);
    }

    /// Record ownership of a created object (quota already reserved).
    /// Returns false if `session` no longer exists (the caller must then
    /// destroy the session object).
    pub fn record_object(
        &self,
        owner: &Arc<str>,
        obj: CK_ULONG,
        session: Option<CK_ULONG>,
    ) -> bool {
        let mut inner = self.lock();
        if let Some(sh) = session {
            match inner.sessions.get_mut(&sh) {
                Some(rec) => rec.objects.push(obj),
                None => return false,
            }
        }
        inner.objects.insert(obj, (owner.clone(), session));
        true
    }

    /// Forget an object (destroyed) and release its quota.
    pub fn release_object(&self, obj: CK_ULONG) {
        let mut inner = self.lock();
        if let Some((owner, session)) = inner.objects.remove(&obj) {
            if let Some(sh) = session {
                if let Some(rec) = inner.sessions.get_mut(&sh) {
                    rec.objects.retain(|h| *h != obj);
                }
            }
            if let Some(st) = inner.clients.get_mut(&owner) {
                st.objects = st.objects.saturating_sub(1);
            }
            Self::gc(&mut inner, &owner);
        }
    }

    /// Session objects are visible only to the identity that created them.
    pub fn object_visible(&self, obj: CK_ULONG, owner: &str) -> bool {
        match self.lock().objects.get(&obj) {
            Some((o, Some(_))) => &**o == owner,
            _ => true,
        }
    }

    /// Filter a handle list down to the objects visible to `owner`.
    pub fn filter_visible(&self, handles: Vec<CK_ULONG>, owner: &str) -> Vec<CK_ULONG> {
        let inner = self.lock();
        handles
            .into_iter()
            .filter(|h| match inner.objects.get(h) {
                Some((o, Some(_))) => &**o == owner,
                _ => true,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> Arc<str> {
        Arc::from(s)
    }

    #[test]
    fn foreign_handles_are_rejected() {
        let r = Registry::new(4, 4);
        let a = id("cert:a");
        r.reserve_session(&a, 0, true).unwrap();
        r.insert_session(10, a.clone(), 1, 0, true);
        assert!(r.authorize(10, "cert:a").is_ok());
        assert_eq!(
            r.authorize(10, "cert:b").unwrap_err().code(),
            tonic::Code::NotFound
        );
    }

    #[test]
    fn login_is_per_client_and_ends_with_last_session() {
        let r = Registry::new(4, 4);
        let a = id("cert:a");
        let b = id("cert:b");
        for (h, who) in [(1, &a), (2, &a), (3, &b)] {
            r.reserve_session(who, 0, true).unwrap();
            r.insert_session(h, who.clone(), 1, 0, true);
        }
        r.set_login(&a, 0, Role::User).unwrap();
        assert_eq!(r.role("cert:a", 0), Some(Role::User));
        assert_eq!(r.role("cert:b", 0), None);
        assert!(!r.clear_login(&b, 0)); // b's logout cannot affect a
        assert_eq!(r.role("cert:a", 0), Some(Role::User));
        r.take_session(1);
        assert_eq!(r.role("cert:a", 0), Some(Role::User));
        r.take_session(2);
        assert_eq!(r.role("cert:a", 0), None);
    }

    #[test]
    fn quotas_are_enforced() {
        let r = Registry::new(1, 1);
        let a = id("cert:a");
        r.reserve_session(&a, 0, true).unwrap();
        assert_eq!(
            r.reserve_session(&a, 0, true).unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        r.reserve_objects(&a, 1).unwrap();
        assert!(r.reserve_objects(&a, 1).is_err());
    }

    #[test]
    fn session_objects_are_private_to_owner() {
        let r = Registry::new(4, 4);
        let a = id("cert:a");
        r.reserve_session(&a, 0, true).unwrap();
        r.insert_session(5, a.clone(), 1, 0, true);
        r.reserve_objects(&a, 2).unwrap();
        assert!(r.record_object(&a, 100, Some(5)));
        assert!(r.record_object(&a, 101, None));
        assert!(!r.object_visible(100, "cert:b"));
        assert!(r.object_visible(101, "cert:b"));
        assert_eq!(r.filter_visible(vec![100, 101], "cert:b"), vec![101]);
        let rec = r.take_session(5).unwrap();
        assert_eq!(rec.objects, vec![100]);
    }

    #[test]
    fn so_login_blocks_read_only_sessions() {
        let r = Registry::new(4, 4);
        let a = id("cert:admin");
        r.reserve_session(&a, 0, true).unwrap();
        r.insert_session(1, a.clone(), 1, 0, true);
        r.set_login(&a, 0, Role::So).unwrap();
        assert!(r.reserve_session(&a, 0, false).is_err());
        assert!(r.reserve_session(&a, 0, true).is_ok());
    }
}
