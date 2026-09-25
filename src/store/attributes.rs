// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! In-memory object store with slot isolation, session-object ownership,
//! quotas, attribute policy and (optional) encrypted persistence.
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::*;
use crate::session::handle::ObjectHandleAllocator;
use crate::crypto::encrypt::{KeyStateSink, PersistedKeyUsage};
use crate::store::encrypted_store::{new_store_key, EncryptedStore, RecordInput};
use crate::store::key_material::RawKeyMaterial;
use crate::store::object::{
    is_secret_class, is_valid_ck_date, KeyLifecycleState, StoredObject,
    SENSITIVE_COMPONENT_ATTRIBUTES,
};

/// Maximum number of objects that can be stored simultaneously (all slots).
const MAX_OBJECTS: usize = 100_000;
/// Maximum number of objects per slot, so one tenant cannot exhaust the
/// global capacity of the others (H3-07).
const MAX_OBJECTS_PER_SLOT: usize = 10_000;
/// Maximum number of session objects owned by one session (H3-07).
const MAX_SESSION_OBJECTS_PER_SESSION: usize = 1_000;
/// Global byte budget for object contents (approximate sizes).
const MAX_TOTAL_BYTES: usize = 1024 * 1024 * 1024;
/// Per-slot byte budget.
const MAX_SLOT_BYTES: usize = 128 * 1024 * 1024;

/// Maximum allowed size for CKA_VALUE key material in bytes.
/// Largest supported key: 4096-bit RSA private key DER ≈ 2.4 KiB; PQC private
/// keys up to ~5 KiB. 8 KiB leaves headroom.
const MAX_KEY_MATERIAL_LEN: usize = 8192;
/// Maximum size / count of non-security "extra" attributes per object.
const MAX_EXTRA_ATTR_LEN: usize = 8192;
const MAX_EXTRA_ATTRS: usize = 64;

/// Non-security standard attributes that may be stored verbatim in
/// `extra_attributes`. Anything else in the standard range is rejected with
/// `CKR_ATTRIBUTE_TYPE_INVALID` (H1-09 / H3-05). Vendor-defined attributes
/// (`>= CKA_VENDOR_DEFINED`) are accepted as opaque data.
const ALLOWED_EXTRA_ATTRIBUTES: &[CK_ATTRIBUTE_TYPE] = &[
    CKA_APPLICATION,
    CKA_OBJECT_ID,
    CKA_CERTIFICATE_TYPE,
    CKA_ISSUER,
    CKA_SERIAL_NUMBER,
    CKA_SUBJECT,
    CKA_SIGN_RECOVER,
    CKA_VERIFY_RECOVER,
    0x0000_0087, // CKA_CERTIFICATE_CATEGORY
    0x0000_0088, // CKA_JAVA_MIDP_SECURITY_DOMAIN
    0x0000_0089, // CKA_URL
    0x0000_008A, // CKA_HASH_OF_SUBJECT_PUBLIC_KEY
    0x0000_008B, // CKA_HASH_OF_ISSUER_PUBLIC_KEY
    0x0000_008C, // CKA_NAME_HASH_ALGORITHM
    0x0000_0090, // CKA_CHECK_VALUE
    0x0000_0129, // CKA_PUBLIC_KEY_INFO
    0x0000_0130, // CKA_PRIME (domain parameter, public)
    0x0000_0131, // CKA_SUBPRIME
    0x0000_0132, // CKA_BASE
    0x0000_0133, // CKA_PRIME_BITS
    0x0000_0134, // CKA_SUBPRIME_BITS
    0x0000_0160, // CKA_VALUE_BITS
];

/// `CKA_ALWAYS_AUTHENTICATE` — only `FALSE` is supported (no
/// `CKU_CONTEXT_SPECIFIC` re-authentication).
const CKA_ALWAYS_AUTHENTICATE: CK_ATTRIBUTE_TYPE = 0x0000_0202;

/// Who is creating / accessing an object. Every creation path records the
/// real slot and the owning session so that slot isolation (H1-13/H3-03) and
/// session-object lifetime (H3-07) are enforced by the store itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectContext {
    /// Slot of the calling session.
    pub slot_id: CK_SLOT_ID,
    /// Calling session handle (0 for administrative/offline callers; such
    /// callers create session objects without an owner).
    pub session: CK_SESSION_HANDLE,
    /// Whether the caller is logged in as Security Officer (only the SO may
    /// set `CKA_TRUSTED`).
    pub is_so: bool,
}

impl ObjectContext {
    /// Context for a session.
    pub fn new(slot_id: CK_SLOT_ID, session: CK_SESSION_HANDLE, is_so: bool) -> Self {
        Self {
            slot_id,
            session,
            is_so,
        }
    }

    /// Administrative (sessionless) context for a slot.
    pub fn admin(slot_id: CK_SLOT_ID) -> Self {
        Self {
            slot_id,
            session: 0,
            is_so: false,
        }
    }
}

impl Default for ObjectContext {
    fn default() -> Self {
        Self::admin(0)
    }
}

/// Where an inserted object comes from. Determines the token-computed
/// provenance attributes (`CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`,
/// `CKA_NEVER_EXTRACTABLE`, `CKA_KEY_GEN_MECHANISM`) — callers can never
/// self-assert them (H1-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectOrigin {
    /// `C_CreateObject` / imported plaintext.
    Created,
    /// Generated on this token by `mechanism`.
    Generated {
        /// Key generation mechanism.
        mechanism: CK_MECHANISM_TYPE,
    },
    /// `C_UnwrapKey`.
    Unwrapped,
    /// `C_DeriveKey` from a base key with the given provenance.
    Derived {
        /// Base key `CKA_ALWAYS_SENSITIVE`.
        base_always_sensitive: bool,
        /// Base key `CKA_NEVER_EXTRACTABLE`.
        base_never_extractable: bool,
    },
    /// `C_CopyObject` (keeps the source's provenance).
    Copied,
    /// Restored from persistent storage or a backup (provenance kept but
    /// normalised for consistency).
    Restored,
}

#[derive(Default)]
struct Usage {
    total_count: usize,
    total_bytes: usize,
    per_slot: HashMap<CK_SLOT_ID, (usize, usize)>,
    per_session: HashMap<CK_SESSION_HANDLE, usize>,
}

/// In-memory object store with optional persistence.
///
/// When persistence is enabled, token objects (CKA_TOKEN=true) are written
/// to the [`EncryptedStore`] **before** the in-memory change is made, and
/// errors are propagated to the caller (H3-25). Session objects are never
/// persisted.
pub struct ObjectStore {
    objects: DashMap<CK_OBJECT_HANDLE, Arc<RwLock<StoredObject>>>,
    handle_alloc: ObjectHandleAllocator,
    /// Optional persistent backend (shared with the tokens, which own the
    /// per-slot DEKs in its keyring).
    persist_store: Option<Arc<EncryptedStore>>,
    /// Maps object handles to their opaque store keys (random hex strings).
    handle_to_store_key: Mutex<HashMap<CK_OBJECT_HANDLE, String>>,
    /// Slots whose persisted objects have been loaded into memory.
    loaded_slots: Mutex<HashSet<CK_SLOT_ID>>,
    usage: Mutex<Usage>,
    /// Per-slot handle index (P11): slot-scoped searches visit only the
    /// slot's objects instead of every object of every slot.
    slot_index: RwLock<HashMap<CK_SLOT_ID, HashSet<CK_OBJECT_HANDLE>>>,
}

/// Persists the usage state (GCM invocation lease, CTR ranges) of the AES key
/// held by one token object (H2-02/A1-15). Holds only a weak reference to the
/// store, so a finalized core never keeps the database (and its process lock)
/// alive through the crypto layer's global tracker.
struct ObjectKeyUsageSink {
    store: std::sync::Weak<EncryptedStore>,
    slot: CK_SLOT_ID,
    store_key: String,
    state: Mutex<PersistedKeyUsage>,
}

impl ObjectKeyUsageSink {
    fn write(&self, usage: &PersistedKeyUsage) -> HsmResult<()> {
        match self.store.upgrade() {
            Some(store) => store.put_key_usage(self.slot, &self.store_key, usage),
            // The store is gone (core finalized): nothing left to protect.
            None => Ok(()),
        }
    }
}

impl KeyStateSink for ObjectKeyUsageSink {
    fn sink_id(&self) -> &str {
        &self.store_key
    }

    fn persist_gcm_lease(&self, reserved: u64) -> HsmResult<()> {
        let mut st = self.state.lock();
        let mut next = st.clone();
        next.gcm_reserved = next.gcm_reserved.max(reserved);
        self.write(&next)?;
        *st = next;
        Ok(())
    }

    fn persist_ctr_ranges(&self, ranges: &[(u128, u128)]) -> HsmResult<()> {
        let mut st = self.state.lock();
        let mut next = st.clone();
        next.ctr_ranges = ranges.to_vec();
        self.write(&next)?;
        *st = next;
        Ok(())
    }
}

/// Objects whose key usage must be tracked durably (AES token keys).
fn tracks_key_usage(obj: &StoredObject) -> bool {
    obj.token_object
        && obj.class == CKO_SECRET_KEY
        && obj.key_type == Some(CKK_AES)
        && obj.key_material.is_some()
}

impl Default for ObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectStore {
    /// In-memory store without persistence.
    pub fn new() -> Self {
        Self {
            objects: DashMap::new(),
            handle_alloc: ObjectHandleAllocator::new(),
            persist_store: None,
            handle_to_store_key: Mutex::new(HashMap::new()),
            loaded_slots: Mutex::new(HashSet::new()),
            usage: Mutex::new(Usage::default()),
            slot_index: RwLock::new(HashMap::new()),
        }
    }

    fn index_add(&self, slot: CK_SLOT_ID, handle: CK_OBJECT_HANDLE) {
        self.slot_index
            .write()
            .entry(slot)
            .or_default()
            .insert(handle);
    }

    fn index_remove(&self, slot: CK_SLOT_ID, handle: CK_OBJECT_HANDLE) {
        let mut idx = self.slot_index.write();
        if let Some(set) = idx.get_mut(&slot) {
            set.remove(&handle);
            if set.is_empty() {
                idx.remove(&slot);
            }
        }
    }

    /// Attach the durable usage-state sink of a token AES key and restore
    /// its persisted state into the crypto layer's tracker.
    fn register_key_usage(&self, obj: &StoredObject, store_key: &str, persisted: PersistedKeyUsage) {
        let (store, km) = match (&self.persist_store, obj.key_material.as_ref()) {
            (Some(store), Some(km)) if tracks_key_usage(obj) => (store, km),
            _ => return,
        };
        let sink = std::sync::Arc::new(ObjectKeyUsageSink {
            store: Arc::downgrade(store),
            slot: obj.slot_id,
            store_key: store_key.to_string(),
            state: Mutex::new(persisted.clone()),
        });
        crate::crypto::encrypt::register_persistent_key(km.as_bytes(), &persisted, sink);
    }

    fn unregister_key_usage(&self, obj: &StoredObject, store_key: Option<&str>) {
        if let (Some(km), Some(k)) = (obj.key_material.as_ref(), store_key) {
            if tracks_key_usage(obj) {
                crate::crypto::encrypt::unregister_persistent_key(km.as_bytes(), k);
            }
        }
    }

    /// Create an ObjectStore with persistence enabled.
    pub fn with_persistence(store: EncryptedStore) -> Self {
        Self::with_shared_persistence(Arc::new(store))
    }

    /// Create an ObjectStore sharing an already-open persistent store.
    pub fn with_shared_persistence(store: Arc<EncryptedStore>) -> Self {
        let mut s = Self::new();
        s.persist_store = Some(store);
        s
    }

    /// The persistent backend, if enabled.
    pub fn persistence(&self) -> Option<&Arc<EncryptedStore>> {
        self.persist_store.as_ref()
    }

    /// Check if persistence is enabled
    pub fn has_persistence(&self) -> bool {
        self.persist_store.is_some()
    }

    /// Legacy single-slot API: install the storage key for slot 0.
    pub fn set_persist_key(&self, key: &Zeroizing<[u8; 32]>) {
        self.set_slot_key(0, key);
    }

    /// Install the unlocked storage key (DEK) for a slot.
    pub fn set_slot_key(&self, slot: CK_SLOT_ID, key: &Zeroizing<[u8; 32]>) {
        if let Some(store) = &self.persist_store {
            store.set_slot_key(slot, key);
        }
    }

    /// Legacy single-slot API: clear the storage key of slot 0.
    pub fn clear_persist_key(&self) {
        if let Some(store) = &self.persist_store {
            store.clear_slot_key(0);
        }
    }

    /// Load persisted token objects of every unlocked slot that has not been
    /// loaded yet. Returns the number of objects loaded.
    pub fn load_from_store(&self) -> HsmResult<usize> {
        let store = match &self.persist_store {
            Some(s) => s,
            None => return Ok(0),
        };
        let mut total = 0;
        for slot in store.unlocked_slots() {
            total += self.load_slot(slot)?;
        }
        Ok(total)
    }

    /// Load the persisted objects of `slot` (requires its DEK to be
    /// unlocked). Idempotent: a slot is loaded at most once.
    pub fn load_slot(&self, slot: CK_SLOT_ID) -> HsmResult<usize> {
        let store = match &self.persist_store {
            Some(s) => s,
            None => return Ok(0),
        };
        let mut loaded_slots = self.loaded_slots.lock();
        if loaded_slots.contains(&slot) {
            return Ok(0);
        }
        let records = store.load_slot_objects(slot)?;
        let mut loaded = 0;
        for rec in records {
            // KNOWN RESIDUAL RISK: serde_json may allocate temporary buffers
            // while parsing; mitigated by the Zeroizing plaintext buffer and
            // mlock of RawKeyMaterial after deserialization.
            let mut obj: StoredObject = match serde_json::from_slice(&rec.plaintext) {
                Ok(o) => o,
                Err(e) => {
                    tracing::warn!("Failed to deserialize object '{}': {}", rec.store_key, e);
                    continue;
                }
            };
            if let Err(reason) = validate_deserialized_object(&obj) {
                tracing::warn!(
                    "Rejected deserialized object '{}': {}",
                    rec.store_key,
                    reason
                );
                continue;
            }
            // The record's AAD binds slot and handle; enforce them.
            obj.slot_id = slot;
            obj.handle = rec.handle;
            obj.token_object = true;
            obj.owner_session = None;
            normalise_provenance(&mut obj, ObjectOrigin::Restored);
            if self.objects.contains_key(&obj.handle) {
                tracing::error!(
                    "persisted handle collision for '{}' — skipped",
                    rec.store_key
                );
                continue;
            }
            // Restore the durable key usage state (GCM lease, CTR ranges)
            // before the key becomes usable (H2-02/A1-15). A record that
            // fails authentication keeps the key out of service.
            let usage = if tracks_key_usage(&obj) {
                match store.get_key_usage(slot, &rec.store_key) {
                    Ok(u) => Some(u.unwrap_or_default()),
                    Err(e) => {
                        tracing::error!(
                            "key usage state of '{}' unreadable ({:?}) — key not loaded",
                            rec.store_key,
                            e
                        );
                        continue;
                    }
                }
            } else {
                None
            };
            let size = obj.approximate_size() as usize;
            if self.reserve(slot, None, size).is_err() {
                tracing::error!("object quota exhausted while loading slot {}", slot);
                break;
            }
            if let Some(u) = usage {
                self.register_key_usage(&obj, &rec.store_key, u);
            }
            self.handle_to_store_key
                .lock()
                .insert(obj.handle, rec.store_key.clone());
            self.index_add(slot, obj.handle);
            self.objects.insert(obj.handle, Arc::new(RwLock::new(obj)));
            loaded += 1;
        }
        loaded_slots.insert(slot);
        Ok(loaded)
    }

    /// Lazily load a slot's persisted objects once its DEK is unlocked.
    fn ensure_slot_loaded(&self, slot: CK_SLOT_ID) {
        if let Some(store) = &self.persist_store {
            if store.has_slot_key(slot) && !self.loaded_slots.lock().contains(&slot) {
                if let Err(e) = self.load_slot(slot) {
                    tracing::error!(
                        "failed to load persisted objects for slot {}: {:?}",
                        slot,
                        e
                    );
                }
            }
        }
    }

    /// Mark a slot as (re)initialised: nothing to load from storage.
    pub fn mark_slot_loaded(&self, slot: CK_SLOT_ID) {
        self.loaded_slots.lock().insert(slot);
    }

    // ------------------------------------------------------------------
    // Quotas
    // ------------------------------------------------------------------

    fn reserve(
        &self,
        slot: CK_SLOT_ID,
        session: Option<CK_SESSION_HANDLE>,
        bytes: usize,
    ) -> HsmResult<()> {
        let mut u = self.usage.lock();
        let (sc, sb) = u.per_slot.get(&slot).copied().unwrap_or((0, 0));
        if u.total_count >= MAX_OBJECTS
            || sc >= MAX_OBJECTS_PER_SLOT
            || u.total_bytes.saturating_add(bytes) > MAX_TOTAL_BYTES
            || sb.saturating_add(bytes) > MAX_SLOT_BYTES
        {
            return Err(HsmError::DeviceMemory);
        }
        if let Some(sess) = session {
            let n = u.per_session.get(&sess).copied().unwrap_or(0);
            if n >= MAX_SESSION_OBJECTS_PER_SESSION {
                return Err(HsmError::DeviceMemory);
            }
            u.per_session.insert(sess, n + 1);
        }
        u.total_count += 1;
        u.total_bytes = u.total_bytes.saturating_add(bytes);
        u.per_slot.insert(slot, (sc + 1, sb.saturating_add(bytes)));
        Ok(())
    }

    fn release(&self, slot: CK_SLOT_ID, session: Option<CK_SESSION_HANDLE>, bytes: usize) {
        let mut u = self.usage.lock();
        u.total_count = u.total_count.saturating_sub(1);
        u.total_bytes = u.total_bytes.saturating_sub(bytes);
        if let Some(e) = u.per_slot.get_mut(&slot) {
            e.0 = e.0.saturating_sub(1);
            e.1 = e.1.saturating_sub(bytes);
        }
        if let Some(sess) = session {
            if let Some(n) = u.per_session.get_mut(&sess) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    u.per_session.remove(&sess);
                }
            }
        }
    }

    fn adjust_bytes(&self, slot: CK_SLOT_ID, old: usize, new: usize) {
        let mut u = self.usage.lock();
        u.total_bytes = u.total_bytes.saturating_sub(old).saturating_add(new);
        if let Some(e) = u.per_slot.get_mut(&slot) {
            e.1 = e.1.saturating_sub(old).saturating_add(new);
        }
    }

    // ------------------------------------------------------------------
    // Persistence helpers
    // ------------------------------------------------------------------

    fn store_key_for(&self, obj: &StoredObject) -> HsmResult<String> {
        if let Some(k) = self.handle_to_store_key.lock().get(&obj.handle) {
            return Ok(k.clone());
        }
        new_store_key(obj.slot_id)
    }

    /// Serialize into a pre-sized zeroizing buffer (H3-20) and write the
    /// record. Returns the store key used.
    fn persist_object(&self, obj: &StoredObject) -> HsmResult<Option<String>> {
        if !obj.token_object {
            return Ok(None);
        }
        let store = match &self.persist_store {
            Some(s) => s,
            None => return Ok(None),
        };
        let store_key = self.store_key_for(obj)?;
        let cap = (obj.approximate_size() as usize).saturating_mul(4) + 4096;
        let mut buf = Zeroizing::new(Vec::with_capacity(cap));
        serde_json::to_writer(&mut *buf, obj).map_err(|e| {
            tracing::error!("Failed to serialize object {}: {}", obj.handle, e);
            HsmError::GeneralError
        })?;
        store.put_object(obj.slot_id, &store_key, obj.handle, &buf)?;
        Ok(Some(store_key))
    }

    fn unpersist_object(&self, obj: &StoredObject) -> HsmResult<()> {
        if !obj.token_object {
            return Ok(());
        }
        let store = match &self.persist_store {
            Some(s) => s,
            None => return Ok(()),
        };
        let key = self.handle_to_store_key.lock().get(&obj.handle).cloned();
        if let Some(key) = key {
            store.delete_object(obj.slot_id, &key)?;
            self.unregister_key_usage(obj, Some(&key));
            self.handle_to_store_key.lock().remove(&obj.handle);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Creation
    // ------------------------------------------------------------------

    /// Create a new object from a template in the default administrative
    /// context (slot 0, no owning session, not SO).
    pub fn create_object(
        &self,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> HsmResult<CK_OBJECT_HANDLE> {
        self.create_object_in(template, &ObjectContext::default())
    }

    /// Create a new object from a template (`C_CreateObject`).
    ///
    /// Enforces the attribute policy of [`apply_attribute_ctx`]: duplicate
    /// attributes are rejected, token-computed attributes are read-only,
    /// `CKA_TRUSTED` is SO-only, and unknown standard attributes are invalid.
    pub fn create_object_in(
        &self,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
        ctx: &ObjectContext,
    ) -> HsmResult<CK_OBJECT_HANDLE> {
        // Reject duplicate attribute types (H3-24).
        let mut seen = HashSet::with_capacity(template.len());
        for (t, _) in template {
            if !seen.insert(*t) {
                return Err(HsmError::TemplateInconsistent);
            }
        }

        let class = template
            .iter()
            .find(|(t, _)| *t == CKA_CLASS)
            .map(|(_, v)| read_ck_ulong(v).ok_or(HsmError::AttributeValueInvalid))
            .transpose()?
            .ok_or(HsmError::TemplateIncomplete)?;

        let handle = self.next_handle()?;
        let mut obj = StoredObject::new(handle, class);

        for (attr_type, value) in template {
            apply_attribute_ctx(&mut obj, *attr_type, value, ctx.is_so)?;
        }

        self.insert_object_in(obj, ctx, ObjectOrigin::Created)
    }

    /// Legacy insert: keeps `obj.slot_id`, no owning session, treats the
    /// object as imported (`CKA_LOCAL=FALSE`). Prefer
    /// [`insert_object_in`](Self::insert_object_in).
    pub fn insert_object(&self, obj: StoredObject) -> HsmResult<CK_OBJECT_HANDLE> {
        let ctx = ObjectContext::admin(obj.slot_id);
        self.insert_object_in(obj, &ctx, ObjectOrigin::Created)
    }

    /// Insert a pre-built object (keygen, unwrap, derive, copy, restore).
    ///
    /// The store assigns the real slot and owning session from `ctx`,
    /// computes provenance from `origin`, sanitises `extra_attributes`,
    /// enforces quotas, and persists token objects before making them
    /// visible. A live handle is never replaced.
    pub fn insert_object_in(
        &self,
        mut obj: StoredObject,
        ctx: &ObjectContext,
        origin: ObjectOrigin,
    ) -> HsmResult<CK_OBJECT_HANDLE> {
        if obj.handle == 0 {
            return Err(HsmError::GeneralError);
        }
        if obj.lifecycle_state == KeyLifecycleState::Destroyed {
            return Err(HsmError::TemplateInconsistent);
        }
        obj.slot_id = ctx.slot_id;
        obj.owner_session = if obj.token_object || ctx.session == 0 {
            None
        } else {
            Some(ctx.session)
        };
        sanitize_extra_attributes(&mut obj, ctx.is_so)?;
        normalise_provenance(&mut obj, origin);

        if obj.token_object {
            self.ensure_slot_loaded(ctx.slot_id);
        }

        let size = obj.approximate_size() as usize;
        let owner = obj.owner_session;
        let slot = obj.slot_id;
        self.reserve(slot, owner, size)?;

        let handle = obj.handle;
        if self.objects.contains_key(&handle) {
            self.release(slot, owner, size);
            return Err(HsmError::GeneralError);
        }

        // Persist first; only make the object visible once it is durable.
        let store_key = match self.persist_object(&obj) {
            Ok(k) => k,
            Err(e) => {
                self.release(slot, owner, size);
                return Err(e);
            }
        };

        use dashmap::mapref::entry::Entry;
        match self.objects.entry(handle) {
            Entry::Occupied(_) => {
                self.release(slot, owner, size);
                if let Some(k) = store_key {
                    if let Some(store) = &self.persist_store {
                        let _ = store.delete_object(slot, &k);
                    }
                }
                Err(HsmError::GeneralError)
            }
            Entry::Vacant(v) => {
                if let Some(k) = store_key {
                    self.register_key_usage(
                        &obj,
                        &k,
                        obj.key_material
                            .as_ref()
                            .map(|km| crate::crypto::encrypt::persisted_key_usage(km.as_bytes()))
                            .unwrap_or_default(),
                    );
                    self.handle_to_store_key.lock().insert(handle, k);
                }
                self.index_add(slot, handle);
                v.insert(Arc::new(RwLock::new(obj)));
                Ok(handle)
            }
        }
    }

    /// Insert several pre-built objects into one slot **atomically** (bulk
    /// import / backup restore). Token objects are persisted in a single
    /// store transaction (P8); if anything fails, nothing is inserted and
    /// the error is returned (H5-02/H5-04: "committed" means durable).
    /// Each object must carry a fresh handle from [`next_handle`](Self::next_handle).
    pub fn insert_objects_in(
        &self,
        objects: Vec<StoredObject>,
        ctx: &ObjectContext,
        origin: ObjectOrigin,
    ) -> HsmResult<Vec<CK_OBJECT_HANDLE>> {
        self.insert_objects_recording(objects, ctx, origin, None)
    }

    /// [`insert_objects_in`](Self::insert_objects_in) that also records a
    /// consumed backup ID in the persistent replay guard in the same store
    /// transaction (restore, H5-04/H5-06). Without persistence the ID is not
    /// recorded here (the caller keeps it).
    pub fn insert_objects_recording(
        &self,
        objects: Vec<StoredObject>,
        ctx: &ObjectContext,
        origin: ObjectOrigin,
        backup_id: Option<&str>,
    ) -> HsmResult<Vec<CK_OBJECT_HANDLE>> {
        let mut prepared = Vec::with_capacity(objects.len());
        let mut seen = HashSet::with_capacity(objects.len());
        for mut obj in objects {
            if obj.handle == 0 || !seen.insert(obj.handle) || self.objects.contains_key(&obj.handle)
            {
                return Err(HsmError::GeneralError);
            }
            if obj.lifecycle_state == KeyLifecycleState::Destroyed {
                return Err(HsmError::TemplateInconsistent);
            }
            obj.slot_id = ctx.slot_id;
            obj.owner_session = if obj.token_object || ctx.session == 0 {
                None
            } else {
                Some(ctx.session)
            };
            sanitize_extra_attributes(&mut obj, ctx.is_so)?;
            normalise_provenance(&mut obj, origin);
            prepared.push(obj);
        }
        let prepared = ZeroizingObjects::new(prepared);
        if prepared.iter().any(|o| o.token_object) {
            self.ensure_slot_loaded(ctx.slot_id);
        }

        // Quotas (rolled back on any failure).
        let mut reserved: Vec<(CK_SLOT_ID, Option<CK_SESSION_HANDLE>, usize)> = Vec::new();
        let rollback_quota = |reserved: &[(CK_SLOT_ID, Option<CK_SESSION_HANDLE>, usize)]| {
            for (slot, owner, size) in reserved {
                self.release(*slot, *owner, *size);
            }
        };
        for obj in prepared.iter() {
            let size = obj.approximate_size() as usize;
            if let Err(e) = self.reserve(obj.slot_id, obj.owner_session, size) {
                rollback_quota(&reserved);
                return Err(e);
            }
            reserved.push((obj.slot_id, obj.owner_session, size));
        }

        // Persist every token object in one transaction.
        let mut store_keys: Vec<Option<String>> = vec![None; prepared.len()];
        if let Some(store) = &self.persist_store {
            let mut bufs: Vec<(usize, String, Zeroizing<Vec<u8>>)> = Vec::new();
            for (i, obj) in prepared.iter().enumerate() {
                if !obj.token_object {
                    continue;
                }
                let key = match new_store_key(obj.slot_id) {
                    Ok(k) => k,
                    Err(e) => {
                        rollback_quota(&reserved);
                        return Err(e);
                    }
                };
                let cap = (obj.approximate_size() as usize).saturating_mul(4) + 4096;
                let mut buf = Zeroizing::new(Vec::with_capacity(cap));
                if serde_json::to_writer(&mut *buf, obj).is_err() {
                    rollback_quota(&reserved);
                    return Err(HsmError::GeneralError);
                }
                bufs.push((i, key, buf));
            }
            let records: Vec<RecordInput<'_>> = bufs
                .iter()
                .map(|(i, k, b)| RecordInput {
                    store_key: k,
                    handle: prepared[*i].handle,
                    plaintext: b,
                })
                .collect();
            if let Err(e) = store.put_objects_recording(ctx.slot_id, &records, backup_id) {
                rollback_quota(&reserved);
                return Err(e);
            }
            drop(records);
            for (i, k, _) in bufs {
                store_keys[i] = Some(k);
            }
        }

        // Make them visible.
        let mut handles = Vec::with_capacity(prepared.len());
        for (obj, key) in prepared.into_inner().into_iter().zip(store_keys) {
            let handle = obj.handle;
            if let Some(k) = key {
                self.register_key_usage(
                    &obj,
                    &k,
                    obj.key_material
                        .as_ref()
                        .map(|km| crate::crypto::encrypt::persisted_key_usage(km.as_bytes()))
                        .unwrap_or_default(),
                );
                self.handle_to_store_key.lock().insert(handle, k);
            }
            self.index_add(obj.slot_id, handle);
            self.objects.insert(handle, Arc::new(RwLock::new(obj)));
            handles.push(handle);
        }
        Ok(handles)
    }

    /// Allocate a new, unpredictable, currently-unused object handle.
    pub fn next_handle(&self) -> HsmResult<CK_OBJECT_HANDLE> {
        self.handle_alloc
            .next_unused(|h| self.objects.contains_key(&h))
    }

    // ------------------------------------------------------------------
    // Destruction
    // ------------------------------------------------------------------

    fn finish_removal(&self, obj_arc: &Arc<RwLock<StoredObject>>) {
        self.finish_removal_inner(obj_arc, true)
    }

    /// `destroyed = false` is used when objects are only evicted from memory
    /// (C_Finalize): their persisted copies live on, so per-key GCM counters
    /// must be kept to avoid nonce reuse after a re-initialisation.
    fn finish_removal_inner(&self, obj_arc: &Arc<RwLock<StoredObject>>, destroyed: bool) {
        let mut o = obj_arc.write();
        let size = o.approximate_size() as usize;
        let slot = o.slot_id;
        let owner = o.owner_session;
        self.index_remove(slot, o.handle);
        let store_key = self.handle_to_store_key.lock().get(&o.handle).cloned();
        self.unregister_key_usage(&o, store_key.as_deref());
        if let Some(km) = o.key_material.as_ref() {
            // Per-key AEAD IV/nonce tracking is intentionally kept: other
            // handles (copies, persisted records) may share the key bytes,
            // and resetting it would allow nonce reuse (H2-02).
            let _ = destroyed;
            if o.class == CKO_PRIVATE_KEY && o.key_type == Some(CKK_RSA) {
                // Evict the parsed RSA key from the crypto-layer cache (A1-10).
                crate::crypto::sign::evict_rsa_key(km.as_bytes());
            }
        }
        o.mark_destroyed();
        drop(o);
        self.release(slot, owner, size);
    }

    /// Destroy an object (legacy, no slot check).
    pub fn destroy_object(&self, handle: CK_OBJECT_HANDLE) -> HsmResult<()> {
        let slot = self.get_object(handle)?.read().slot_id;
        self.destroy_object_in(handle, slot)
    }

    /// Destroy an object belonging to `slot`.
    ///
    /// Honours `CKA_DESTROYABLE` (`CKR_ACTION_PROHIBITED`), deletes the
    /// persisted record **before** removing the object from memory (so a
    /// failed delete cannot resurrect it later, H3-25), then marks it
    /// destroyed and zeroizes its key material so cached operation
    /// references fail (H3-20).
    pub fn destroy_object_in(&self, handle: CK_OBJECT_HANDLE, slot: CK_SLOT_ID) -> HsmResult<()> {
        let obj_arc = self.get_object_in_slot(handle, slot)?;
        {
            // Hold the write lock across the persistent delete to serialize
            // against concurrent C_SetAttributeValue.
            let o = obj_arc.write();
            if !o.destroyable {
                return Err(HsmError::ActionProhibited);
            }
            self.unpersist_object(&o)?;
        }
        if self
            .objects
            .remove_if(&handle, |_, v| Arc::ptr_eq(v, &obj_arc))
            .is_none()
        {
            return Err(HsmError::ObjectHandleInvalid);
        }
        self.finish_removal(&obj_arc);
        Ok(())
    }

    /// Destroy every session object owned by `session` (C_CloseSession,
    /// C_CloseAllSessions, C_Finalize). Returns the number destroyed.
    pub fn destroy_session_objects(&self, session: CK_SESSION_HANDLE) -> usize {
        let handles: Vec<CK_OBJECT_HANDLE> = self
            .objects
            .iter()
            .filter(|e| e.value().read().owner_session == Some(session))
            .map(|e| *e.key())
            .collect();
        let mut n = 0;
        for h in handles {
            if let Some((_, arc)) = self.objects.remove(&h) {
                self.finish_removal(&arc);
                n += 1;
            }
        }
        n
    }

    /// Clear all objects of all slots from memory **and** persistent storage.
    pub fn clear(&self) {
        let mut slots: HashSet<CK_SLOT_ID> = self
            .objects
            .iter()
            .map(|e| e.value().read().slot_id)
            .collect();
        if let Some(store) = &self.persist_store {
            slots.extend(store.unlocked_slots());
        }
        for slot in slots {
            if let Err(e) = self.clear_slot(slot) {
                tracing::error!("Failed to clear slot {}: {:?}", slot, e);
            }
        }
    }

    /// Destroy every object of `slot` (C_InitToken), including its persisted
    /// records. Other slots are untouched.
    pub fn clear_slot(&self, slot: CK_SLOT_ID) -> HsmResult<usize> {
        if let Some(store) = &self.persist_store {
            if store.is_available() {
                store.clear_slot(slot)?;
            }
        }
        let handles: Vec<CK_OBJECT_HANDLE> = self
            .objects
            .iter()
            .filter(|e| e.value().read().slot_id == slot)
            .map(|e| *e.key())
            .collect();
        let mut n = 0;
        for h in handles {
            if let Some((_, arc)) = self.objects.remove(&h) {
                self.finish_removal(&arc);
                self.handle_to_store_key.lock().remove(&h);
                n += 1;
            }
        }
        Ok(n)
    }

    /// Remove every object from memory and zeroize it **without** touching
    /// persistent storage (C_Finalize / shutdown, A1-10). Also wipes the
    /// unlocked storage keys.
    pub fn evict_all(&self) {
        let handles: Vec<CK_OBJECT_HANDLE> = self.objects.iter().map(|e| *e.key()).collect();
        for h in handles {
            if let Some((_, arc)) = self.objects.remove(&h) {
                // Keep per-key GCM counters: a persisted (or re-imported) key
                // must never restart its nonce sequence.
                self.finish_removal_inner(&arc, false);
            }
        }
        self.handle_to_store_key.lock().clear();
        self.loaded_slots.lock().clear();
        if let Some(store) = &self.persist_store {
            store.clear_all_keys();
        }
    }

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    /// Get an object by handle (no slot check — administrative use only;
    /// PKCS#11 entry points must use [`get_object_in_slot`](Self::get_object_in_slot)).
    pub fn get_object(&self, handle: CK_OBJECT_HANDLE) -> HsmResult<Arc<RwLock<StoredObject>>> {
        self.objects
            .get(&handle)
            .map(|o| o.value().clone())
            .ok_or(HsmError::ObjectHandleInvalid)
    }

    /// Get an object by handle, only if it belongs to `slot` (H1-13/H3-03).
    /// Objects of other slots are reported as `ObjectHandleInvalid`.
    pub fn get_object_in_slot(
        &self,
        handle: CK_OBJECT_HANDLE,
        slot: CK_SLOT_ID,
    ) -> HsmResult<Arc<RwLock<StoredObject>>> {
        self.ensure_slot_loaded(slot);
        let arc = self.get_object(handle)?;
        {
            let o = arc.read();
            if o.slot_id != slot || o.lifecycle_state == KeyLifecycleState::Destroyed {
                return Err(HsmError::ObjectHandleInvalid);
            }
        }
        Ok(arc)
    }

    /// Get object size
    pub fn get_object_size(&self, handle: CK_OBJECT_HANDLE) -> HsmResult<CK_ULONG> {
        let obj = self.get_object(handle)?;
        let size = obj.read().approximate_size();
        Ok(size)
    }

    /// Number of objects currently held (all slots).
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Find objects matching a template in **all** slots (administrative use
    /// only). PKCS#11 entry points must use
    /// [`find_objects_for_slot`](Self::find_objects_for_slot).
    pub fn find_objects(
        &self,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
        is_logged_in: bool,
    ) -> Vec<CK_OBJECT_HANDLE> {
        self.find_objects_for_slot(template, is_logged_in, None)
    }

    /// Find objects matching a template, optionally scoped to a slot.
    ///
    /// Objects of other slots are skipped up front (P11); within the slot
    /// every object is fully template-matched (including private ones that
    /// will be filtered out) so timing does not reveal private-object counts.
    pub fn find_objects_for_slot(
        &self,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
        is_logged_in: bool,
        slot_id: Option<CK_ULONG>,
    ) -> Vec<CK_OBJECT_HANDLE> {
        let check = |obj: &StoredObject| {
            if obj.lifecycle_state == KeyLifecycleState::Destroyed {
                return false;
            }
            let matches = obj.matches_template(template);
            let visible = !obj.private || is_logged_in;
            matches && visible
        };
        let mut results = Vec::new();
        match slot_id {
            Some(slot) => {
                self.ensure_slot_loaded(slot);
                // Per-slot index (P11); handles snapshotted so no index lock
                // is held while object locks are taken.
                let handles: Vec<CK_OBJECT_HANDLE> = self
                    .slot_index
                    .read()
                    .get(&slot)
                    .map(|set| set.iter().copied().collect())
                    .unwrap_or_default();
                for h in handles {
                    if let Some(entry) = self.objects.get(&h) {
                        let obj = entry.value().read();
                        if obj.slot_id == slot && check(&obj) {
                            results.push(h);
                        }
                    }
                }
            }
            None => {
                for entry in self.objects.iter() {
                    if check(&entry.value().read()) {
                        results.push(*entry.key());
                    }
                }
            }
        }
        results
    }

    // ------------------------------------------------------------------
    // Modification
    // ------------------------------------------------------------------

    /// `C_SetAttributeValue` with PKCS#11 semantics (H1-09, H1-27, H3-25):
    ///
    /// * the whole template is validated on a copy and applied atomically;
    /// * `CKA_MODIFIABLE=FALSE` objects are read-only (`CKR_ACTION_PROHIBITED`);
    /// * `CKA_SENSITIVE` may only go FALSE→TRUE, `CKA_EXTRACTABLE` and
    ///   `CKA_COPYABLE` only TRUE→FALSE, `CKA_WRAP_WITH_TRUSTED` only
    ///   FALSE→TRUE; `CKA_TRUSTED` may only be changed by the SO;
    /// * token-computed and structural attributes are read-only;
    /// * token objects are persisted before the change becomes visible.
    pub fn set_attributes(
        &self,
        handle: CK_OBJECT_HANDLE,
        slot: CK_SLOT_ID,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
        is_so: bool,
    ) -> HsmResult<()> {
        let arc = self.get_object_in_slot(handle, slot)?;
        let mut guard = arc.write();
        if !guard.modifiable {
            return Err(HsmError::ActionProhibited);
        }
        let mut seen = HashSet::with_capacity(template.len());
        for (t, _) in template {
            if !seen.insert(*t) {
                return Err(HsmError::TemplateInconsistent);
            }
        }
        let mut new = guard.clone();
        for (t, v) in template {
            modify_attribute(&mut new, *t, v, is_so)?;
        }
        let old_size = guard.approximate_size() as usize;
        let new_size = new.approximate_size() as usize;
        if new.token_object {
            self.persist_object(&new)?;
        }
        *guard = new;
        drop(guard);
        self.adjust_bytes(slot, old_size, new_size);
        Ok(())
    }

    /// Mark a key compromised (SP 800-57): every further use is refused with
    /// `CKR_KEY_FUNCTION_NOT_PERMITTED` (H3-23 / S7). The change is persisted
    /// for token objects. Callers are responsible for authorising the request
    /// (administrative / SO-level operation).
    pub fn mark_compromised(&self, handle: CK_OBJECT_HANDLE, slot: CK_SLOT_ID) -> HsmResult<()> {
        let arc = self.get_object_in_slot(handle, slot)?;
        let mut guard = arc.write();
        let mut new = guard.clone();
        new.lifecycle_state = KeyLifecycleState::Compromised;
        if new.token_object {
            self.persist_object(&new)?;
        }
        *guard = new;
        Ok(())
    }

    /// Export all objects as cloned StoredObjects (for backup).
    ///
    /// Returns a `ZeroizingObjects` wrapper that zeroizes all key material
    /// when dropped, preventing callers from accidentally leaking plaintext
    /// key copies.
    pub fn export_all_objects(&self) -> ZeroizingObjects {
        let objects: Vec<StoredObject> = self
            .objects
            .iter()
            .map(|entry| entry.value().read().clone())
            .collect();
        ZeroizingObjects(objects)
    }

    /// Export the token objects of one slot (for backup).
    pub fn export_slot_objects(&self, slot: CK_SLOT_ID) -> ZeroizingObjects {
        self.ensure_slot_loaded(slot);
        let objects: Vec<StoredObject> = self
            .objects
            .iter()
            .filter_map(|entry| {
                let o = entry.value().read();
                (o.slot_id == slot && o.token_object).then(|| o.clone())
            })
            .collect();
        ZeroizingObjects(objects)
    }
}

/// Maximum `CKA_LABEL` / `CKA_ID` length (defence in depth against memory
/// and persistence amplification, H4-06).
pub const MAX_LABEL_ID_LEN: usize = 1024;

fn bounded_label_or_id(value: &[u8]) -> HsmResult<Vec<u8>> {
    if value.len() > MAX_LABEL_ID_LEN {
        return Err(HsmError::AttributeValueInvalid);
    }
    Ok(value.to_vec())
}

/// Parse a strict `CK_BBOOL` (exactly one byte).
fn read_bool(value: &[u8]) -> HsmResult<bool> {
    if value.len() != 1 {
        return Err(HsmError::AttributeValueInvalid);
    }
    Ok(value[0] != 0)
}

fn read_ulong_strict(value: &[u8]) -> HsmResult<CK_ULONG> {
    read_ck_ulong(value).ok_or(HsmError::AttributeValueInvalid)
}

fn parse_date(value: &[u8]) -> HsmResult<Option<[u8; 8]>> {
    if value.is_empty() {
        return Ok(None);
    }
    if !is_valid_ck_date(value) {
        return Err(HsmError::AttributeValueInvalid);
    }
    let mut date = [0u8; 8];
    date.copy_from_slice(value);
    Ok(Some(date))
}

/// Apply an attribute value to an object during creation (non-SO caller).
pub fn apply_attribute(
    obj: &mut StoredObject,
    attr_type: CK_ATTRIBUTE_TYPE,
    value: &[u8],
) -> HsmResult<()> {
    apply_attribute_ctx(obj, attr_type, value, false)
}

/// Apply an attribute value to an object during **creation**.
///
/// At creation time every creator-settable attribute may take any valid
/// value (one-way rules apply to later modifications only, H3-24). Values
/// are strictly typed (`CK_BBOOL` = 1 byte, `CK_ULONG` = native size, valid
/// `CK_DATE`). Token-computed attributes (`CKA_LOCAL`,
/// `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE`, `CKA_KEY_GEN_MECHANISM`)
/// are read-only; `CKA_TRUSTED=TRUE` requires the SO (H1-09); private-key
/// components are stored in zeroizing buffers (H3-02); unknown standard
/// attributes are rejected.
pub fn apply_attribute_ctx(
    obj: &mut StoredObject,
    attr_type: CK_ATTRIBUTE_TYPE,
    value: &[u8],
    is_so: bool,
) -> HsmResult<()> {
    match attr_type {
        CKA_CLASS => {
            if read_ulong_strict(value)? != obj.class {
                return Err(HsmError::TemplateInconsistent);
            }
        }
        CKA_KEY_TYPE => obj.key_type = Some(read_ulong_strict(value)?),
        CKA_LABEL => obj.label = bounded_label_or_id(value)?,
        CKA_ID => obj.id = bounded_label_or_id(value)?,
        CKA_TOKEN => obj.token_object = read_bool(value)?,
        CKA_PRIVATE => obj.private = read_bool(value)?,
        CKA_SENSITIVE => obj.sensitive = read_bool(value)?,
        CKA_EXTRACTABLE => obj.extractable = read_bool(value)?,
        CKA_MODIFIABLE => obj.modifiable = read_bool(value)?,
        CKA_DESTROYABLE => obj.destroyable = read_bool(value)?,
        CKA_COPYABLE => obj.copyable = read_bool(value)?,
        CKA_ENCRYPT => obj.can_encrypt = read_bool(value)?,
        CKA_DECRYPT => obj.can_decrypt = read_bool(value)?,
        CKA_SIGN => obj.can_sign = read_bool(value)?,
        CKA_VERIFY => obj.can_verify = read_bool(value)?,
        CKA_WRAP => obj.can_wrap = read_bool(value)?,
        CKA_UNWRAP => obj.can_unwrap = read_bool(value)?,
        CKA_DERIVE => obj.can_derive = read_bool(value)?,
        CKA_WRAP_WITH_TRUSTED => obj.wrap_with_trusted = read_bool(value)?,
        CKA_TRUSTED => {
            let v = read_bool(value)?;
            if v && !is_so {
                return Err(HsmError::AttributeReadOnly);
            }
            obj.trusted = v;
        }
        CKA_LOCAL | CKA_ALWAYS_SENSITIVE | CKA_NEVER_EXTRACTABLE | CKA_KEY_GEN_MECHANISM => {
            return Err(HsmError::AttributeReadOnly);
        }
        CKA_ALWAYS_AUTHENTICATE => {
            if read_bool(value)? {
                return Err(HsmError::AttributeValueInvalid);
            }
        }
        CKA_VALUE => {
            if value.len() > MAX_KEY_MATERIAL_LEN {
                return Err(HsmError::AttributeValueInvalid);
            }
            obj.key_material = Some(RawKeyMaterial::new(value.to_vec()));
        }
        t if SENSITIVE_COMPONENT_ATTRIBUTES.contains(&t) => {
            if obj.class != CKO_PRIVATE_KEY {
                return Err(HsmError::AttributeTypeInvalid);
            }
            if value.len() > MAX_KEY_MATERIAL_LEN {
                return Err(HsmError::AttributeValueInvalid);
            }
            obj.sensitive_attributes
                .insert(t, RawKeyMaterial::new(value.to_vec()));
        }
        CKA_MODULUS => obj.modulus = Some(value.to_vec()),
        CKA_MODULUS_BITS => obj.modulus_bits = Some(read_ulong_strict(value)?),
        CKA_PUBLIC_EXPONENT => obj.public_exponent = Some(value.to_vec()),
        CKA_EC_PARAMS => obj.ec_params = Some(value.to_vec()),
        CKA_EC_POINT => obj.ec_point = Some(value.to_vec()),
        CKA_VALUE_LEN => obj.value_len = Some(read_ulong_strict(value)?),
        CKA_START_DATE => obj.start_date = parse_date(value)?,
        CKA_END_DATE => obj.end_date = parse_date(value)?,
        t if t >= CKA_VENDOR_DEFINED || ALLOWED_EXTRA_ATTRIBUTES.contains(&t) => {
            // Limit extra attribute value size and count to prevent resource exhaustion
            if value.len() > MAX_EXTRA_ATTR_LEN {
                return Err(HsmError::AttributeValueInvalid);
            }
            if obj.extra_attributes.len() >= MAX_EXTRA_ATTRS
                && !obj.extra_attributes.contains_key(&t)
            {
                return Err(HsmError::TemplateInconsistent);
            }
            obj.extra_attributes.insert(t, value.to_vec());
        }
        _ => return Err(HsmError::AttributeTypeInvalid),
    }
    Ok(())
}

/// Apply a post-creation modification (`C_SetAttributeValue`).
fn modify_attribute(
    obj: &mut StoredObject,
    attr_type: CK_ATTRIBUTE_TYPE,
    value: &[u8],
    is_so: bool,
) -> HsmResult<()> {
    match attr_type {
        CKA_LABEL => obj.label = bounded_label_or_id(value)?,
        CKA_ID => obj.id = bounded_label_or_id(value)?,
        CKA_START_DATE => obj.start_date = parse_date(value)?,
        CKA_END_DATE => obj.end_date = parse_date(value)?,
        CKA_SUBJECT | CKA_APPLICATION => {
            if value.len() > MAX_EXTRA_ATTR_LEN {
                return Err(HsmError::AttributeValueInvalid);
            }
            obj.extra_attributes.insert(attr_type, value.to_vec());
        }
        CKA_SENSITIVE => {
            let v = read_bool(value)?;
            if obj.sensitive && !v {
                return Err(HsmError::AttributeReadOnly);
            }
            obj.sensitive = v;
        }
        CKA_EXTRACTABLE => {
            let v = read_bool(value)?;
            if !obj.extractable && v {
                return Err(HsmError::AttributeReadOnly);
            }
            obj.extractable = v;
        }
        CKA_COPYABLE => {
            let v = read_bool(value)?;
            if !obj.copyable && v {
                return Err(HsmError::AttributeReadOnly);
            }
            obj.copyable = v;
        }
        CKA_WRAP_WITH_TRUSTED => {
            let v = read_bool(value)?;
            if obj.wrap_with_trusted && !v {
                return Err(HsmError::AttributeReadOnly);
            }
            obj.wrap_with_trusted = v;
        }
        CKA_TRUSTED => {
            if !is_so {
                return Err(HsmError::AttributeReadOnly);
            }
            obj.trusted = read_bool(value)?;
        }
        _ => return Err(HsmError::AttributeReadOnly),
    }
    Ok(())
}

/// Migrate / reject security-relevant attributes that reached
/// `extra_attributes` through a caller-built object (e.g. a copy template).
fn sanitize_extra_attributes(obj: &mut StoredObject, is_so: bool) -> HsmResult<()> {
    for t in [
        CKA_LOCAL,
        CKA_ALWAYS_SENSITIVE,
        CKA_NEVER_EXTRACTABLE,
        CKA_KEY_GEN_MECHANISM,
        CKA_VALUE,
    ] {
        if obj.extra_attributes.contains_key(&t) {
            return Err(HsmError::AttributeReadOnly);
        }
    }
    for t in SENSITIVE_COMPONENT_ATTRIBUTES {
        if obj.extra_attributes.contains_key(t) {
            return Err(HsmError::AttributeReadOnly);
        }
    }
    if let Some(v) = obj.extra_attributes.remove(&CKA_TRUSTED) {
        let v = read_bool(&v)?;
        if v && !is_so {
            return Err(HsmError::AttributeReadOnly);
        }
        obj.trusted = v;
    }
    if let Some(v) = obj.extra_attributes.remove(&CKA_COPYABLE) {
        let v = read_bool(&v)?;
        if v && !obj.copyable {
            return Err(HsmError::AttributeReadOnly);
        }
        obj.copyable = v;
    }
    if let Some(v) = obj.extra_attributes.remove(&CKA_WRAP_WITH_TRUSTED) {
        let v = read_bool(&v)?;
        if !v && obj.wrap_with_trusted {
            return Err(HsmError::AttributeReadOnly);
        }
        obj.wrap_with_trusted = v;
    }
    if obj.extra_attributes.len() > MAX_EXTRA_ATTRS
        || obj
            .extra_attributes
            .values()
            .any(|v| v.len() > MAX_EXTRA_ATTR_LEN)
    {
        return Err(HsmError::TemplateInconsistent);
    }
    Ok(())
}

/// Compute the token-controlled provenance attributes.
fn normalise_provenance(obj: &mut StoredObject, origin: ObjectOrigin) {
    let is_key = matches!(obj.class, CKO_SECRET_KEY | CKO_PRIVATE_KEY | CKO_PUBLIC_KEY);
    if !is_key {
        obj.local = false;
        obj.always_sensitive = false;
        obj.never_extractable = false;
        obj.key_gen_mechanism = None;
        return;
    }
    match origin {
        ObjectOrigin::Generated { mechanism } => {
            obj.local = true;
            obj.key_gen_mechanism = Some(mechanism);
            obj.always_sensitive = obj.sensitive;
            obj.never_extractable = !obj.extractable;
        }
        ObjectOrigin::Created | ObjectOrigin::Unwrapped => {
            obj.local = false;
            obj.key_gen_mechanism = None;
            obj.always_sensitive = false;
            obj.never_extractable = false;
        }
        ObjectOrigin::Derived {
            base_always_sensitive,
            base_never_extractable,
        } => {
            obj.local = false;
            obj.key_gen_mechanism = None;
            obj.always_sensitive = base_always_sensitive && obj.sensitive;
            obj.never_extractable = base_never_extractable && !obj.extractable;
        }
        ObjectOrigin::Copied | ObjectOrigin::Restored => {
            obj.always_sensitive &= obj.sensitive;
            obj.never_extractable &= !obj.extractable;
        }
    }
    if obj.class == CKO_PUBLIC_KEY {
        // Public keys carry no secret: these flags are meaningless.
        obj.always_sensitive = false;
        obj.never_extractable = false;
    }
}

fn bool_bytes(b: bool) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(vec![u8::from(b)])
}

fn ulong_bytes(v: CK_ULONG) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(v.to_ne_bytes().to_vec())
}

fn plain(v: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(v.to_vec())
}

/// Returns true if `attr_type` names secret material of `obj` that the
/// sensitivity policy withholds (used for auditing sensitive reads).
pub fn is_protected_secret_attribute(obj: &StoredObject, attr_type: CK_ATTRIBUTE_TYPE) -> bool {
    is_secret_class(obj.class)
        && (attr_type == CKA_VALUE || SENSITIVE_COMPONENT_ATTRIBUTES.contains(&attr_type))
}

/// Read attribute value from a stored object.
///
/// Returns `Err(AttributeSensitive)` for secret material that must not leave
/// the token in plaintext: for secret/private keys, `CKA_VALUE` and every
/// private-key component (`CKA_PRIVATE_EXPONENT`, `CKA_PRIME_1/2`,
/// `CKA_EXPONENT_1/2`, `CKA_COEFFICIENT`) are only readable when the key is
/// `CKA_SENSITIVE=FALSE` **and** `CKA_EXTRACTABLE=TRUE` (H1-02/H3-02;
/// PKCS#11 §4.4 — extractable permits wrapping, never plaintext output of a
/// sensitive key). Returns `Ok(None)` if the attribute is not present /
/// invalid for the object. The value is returned in a zeroizing buffer.
pub fn read_attribute(
    obj: &StoredObject,
    attr_type: CK_ATTRIBUTE_TYPE,
) -> Result<Option<Zeroizing<Vec<u8>>>, HsmError> {
    let secret_class = is_secret_class(obj.class);
    let is_key = secret_class || obj.class == CKO_PUBLIC_KEY;
    let secret_readable = !obj.sensitive && obj.extractable;
    Ok(match attr_type {
        CKA_CLASS => Some(ulong_bytes(obj.class)),
        CKA_KEY_TYPE => obj.key_type.map(ulong_bytes),
        CKA_LABEL => Some(plain(&obj.label)),
        CKA_ID => Some(plain(&obj.id)),
        CKA_TOKEN => Some(bool_bytes(obj.token_object)),
        CKA_PRIVATE => Some(bool_bytes(obj.private)),
        CKA_SENSITIVE => Some(bool_bytes(obj.sensitive)),
        CKA_EXTRACTABLE => Some(bool_bytes(obj.extractable)),
        CKA_MODIFIABLE => Some(bool_bytes(obj.modifiable)),
        CKA_DESTROYABLE => Some(bool_bytes(obj.destroyable)),
        CKA_COPYABLE => Some(bool_bytes(obj.copyable)),
        CKA_ENCRYPT => Some(bool_bytes(obj.can_encrypt)),
        CKA_DECRYPT => Some(bool_bytes(obj.can_decrypt)),
        CKA_SIGN => Some(bool_bytes(obj.can_sign)),
        CKA_VERIFY => Some(bool_bytes(obj.can_verify)),
        CKA_WRAP => Some(bool_bytes(obj.can_wrap)),
        CKA_UNWRAP => Some(bool_bytes(obj.can_unwrap)),
        CKA_DERIVE => Some(bool_bytes(obj.can_derive)),
        CKA_TRUSTED => Some(bool_bytes(obj.trusted)),
        CKA_WRAP_WITH_TRUSTED => Some(bool_bytes(obj.wrap_with_trusted)),
        CKA_LOCAL if is_key => Some(bool_bytes(obj.local)),
        CKA_ALWAYS_SENSITIVE if secret_class => Some(bool_bytes(obj.always_sensitive)),
        CKA_NEVER_EXTRACTABLE if secret_class => Some(bool_bytes(obj.never_extractable)),
        CKA_KEY_GEN_MECHANISM if is_key => Some(ulong_bytes(
            obj.key_gen_mechanism.unwrap_or(CK_UNAVAILABLE_INFORMATION),
        )),
        CKA_VALUE => {
            if secret_class && !secret_readable {
                return Err(HsmError::AttributeSensitive);
            }
            obj.key_material.as_ref().map(|km| plain(km.as_bytes()))
        }
        t if SENSITIVE_COMPONENT_ATTRIBUTES.contains(&t) => {
            if obj.class != CKO_PRIVATE_KEY {
                None
            } else if !secret_readable {
                return Err(HsmError::AttributeSensitive);
            } else {
                obj.sensitive_attributes
                    .get(&t)
                    .map(|v| plain(v.as_bytes()))
            }
        }
        CKA_MODULUS => obj.modulus.as_deref().map(plain),
        CKA_MODULUS_BITS => obj.modulus_bits.map(ulong_bytes),
        CKA_PUBLIC_EXPONENT => obj.public_exponent.as_deref().map(plain),
        CKA_EC_PARAMS => obj.ec_params.as_deref().map(plain),
        CKA_EC_POINT => obj.ec_point.as_deref().map(plain),
        CKA_VALUE_LEN => obj.value_len.map(ulong_bytes),
        CKA_START_DATE => obj.start_date.map(|d| plain(&d)),
        CKA_END_DATE => obj.end_date.map(|d| plain(&d)),
        _ => obj.extra_attributes.get(&attr_type).map(|v| plain(v)),
    })
}

/// Parse a `CK_ULONG` from raw bytes. Strict: the input must be exactly
/// `size_of::<CK_ULONG>()` bytes (H3-24 — one parser for create and match).
pub fn read_ck_ulong(bytes: &[u8]) -> Option<CK_ULONG> {
    let size = std::mem::size_of::<CK_ULONG>();
    if bytes.len() != size {
        return None;
    }
    let mut buf = [0u8; std::mem::size_of::<CK_ULONG>()];
    buf.copy_from_slice(bytes);
    Some(CK_ULONG::from_ne_bytes(buf))
}

/// Defense-in-depth: validate that a deserialized `StoredObject` has sane
/// security-critical fields.
fn validate_deserialized_object(obj: &StoredObject) -> Result<(), &'static str> {
    // Handle 0 is CK_INVALID_HANDLE in PKCS#11
    if obj.handle == 0 {
        return Err("handle is CK_INVALID_HANDLE (0)");
    }
    // Lifecycle state "Destroyed" objects should never be persisted
    if obj.lifecycle_state == KeyLifecycleState::Destroyed {
        return Err("persisted object has Destroyed lifecycle state");
    }
    if obj
        .key_material
        .as_ref()
        .is_some_and(|k| k.len() > MAX_KEY_MATERIAL_LEN)
    {
        return Err("key material too large");
    }
    Ok(())
}

/// Validate a `StoredObject` from an untrusted source (backup restore)
/// against the same policy as object creation (H3-16): secret/private keys
/// must be sensitive unless the caller explicitly allows otherwise, and
/// `CKA_TRUSTED` claims are stripped. Provenance is normalised when the
/// object is inserted with [`ObjectOrigin::Restored`].
pub fn sanitize_restored_object(
    obj: &mut StoredObject,
    allow_non_sensitive: bool,
) -> HsmResult<()> {
    // Handles are re-allocated on import, so the backed-up handle value is
    // irrelevant here (only lifecycle / size invariants are checked).
    if obj.lifecycle_state == KeyLifecycleState::Destroyed
        || obj
            .key_material
            .as_ref()
            .is_some_and(|k| k.len() > MAX_KEY_MATERIAL_LEN)
    {
        tracing::warn!("restored object rejected: destroyed or oversized");
        return Err(HsmError::TemplateInconsistent);
    }
    if is_secret_class(obj.class) && !obj.sensitive && !allow_non_sensitive {
        return Err(HsmError::TemplateInconsistent);
    }
    if obj.label.len() > MAX_LABEL_ID_LEN || obj.id.len() > MAX_LABEL_ID_LEN {
        return Err(HsmError::AttributeValueInvalid);
    }
    obj.trusted = false;
    obj.extra_attributes.remove(&CKA_TRUSTED);
    sanitize_extra_attributes(obj, false)?;
    if obj
        .extra_attributes
        .keys()
        .any(|t| *t < CKA_VENDOR_DEFINED && !ALLOWED_EXTRA_ATTRIBUTES.contains(t))
    {
        return Err(HsmError::AttributeTypeInvalid);
    }
    Ok(())
}

/// Wrapper around `Vec<StoredObject>` that ensures all cloned key material
/// and sensitive metadata is zeroized when the collection is dropped.
pub struct ZeroizingObjects(Vec<StoredObject>);

impl ZeroizingObjects {
    /// Wrap a vector of objects.
    pub fn new(v: Vec<StoredObject>) -> Self {
        Self(v)
    }

    /// Take the objects out (the caller becomes responsible for them).
    pub fn into_inner(mut self) -> Vec<StoredObject> {
        std::mem::take(&mut self.0)
    }
}

impl std::ops::Deref for ZeroizingObjects {
    type Target = [StoredObject];
    fn deref(&self) -> &[StoredObject] {
        &self.0
    }
}

impl Drop for ZeroizingObjects {
    fn drop(&mut self) {
        for obj in self.0.iter_mut() {
            // RawKeyMaterial is zeroized by its own Drop impl, but we must
            // also zeroize other fields that may contain sensitive data.
            obj.label.zeroize();
            obj.id.zeroize();
            if let Some(ref mut pk) = obj.public_key_data {
                pk.zeroize();
            }
            if let Some(ref mut m) = obj.modulus {
                m.zeroize();
            }
            if let Some(ref mut e) = obj.public_exponent {
                e.zeroize();
            }
            if let Some(ref mut p) = obj.ec_params {
                p.zeroize();
            }
            if let Some(ref mut p) = obj.ec_point {
                p.zeroize();
            }
            for val in obj.extra_attributes.values_mut() {
                val.zeroize();
            }
        }
        // Now drop all elements (which triggers RawKeyMaterial::drop → zeroize key bytes)
        self.0.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_template(sensitive: bool, extractable: bool) -> Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> {
        vec![
            (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
            (CKA_KEY_TYPE, CKK_AES.to_ne_bytes().to_vec()),
            (CKA_VALUE, vec![7u8; 32]),
            (CKA_SENSITIVE, vec![u8::from(sensitive)]),
            (CKA_EXTRACTABLE, vec![u8::from(extractable)]),
        ]
    }

    #[test]
    fn sensitive_extractable_value_is_not_readable() {
        let s = ObjectStore::new();
        let h = s.create_object(&secret_template(true, true)).unwrap();
        let o = s.get_object(h).unwrap();
        assert!(matches!(
            read_attribute(&o.read(), CKA_VALUE),
            Err(HsmError::AttributeSensitive)
        ));
        let h2 = s.create_object(&secret_template(false, false)).unwrap();
        let o2 = s.get_object(h2).unwrap();
        assert!(matches!(
            read_attribute(&o2.read(), CKA_VALUE),
            Err(HsmError::AttributeSensitive)
        ));
        let h3 = s.create_object(&secret_template(false, true)).unwrap();
        let o3 = s.get_object(h3).unwrap();
        assert!(read_attribute(&o3.read(), CKA_VALUE).unwrap().is_some());
    }

    #[test]
    fn private_components_are_sensitive() {
        let s = ObjectStore::new();
        let t = vec![
            (CKA_CLASS, CKO_PRIVATE_KEY.to_ne_bytes().to_vec()),
            (CKA_KEY_TYPE, CKK_RSA.to_ne_bytes().to_vec()),
            (CKA_PRIVATE_EXPONENT, vec![1u8; 256]),
            (CKA_PRIME_1, vec![2u8; 128]),
        ];
        let h = s.create_object(&t).unwrap();
        let o = s.get_object(h).unwrap();
        let o = o.read();
        assert!(o.extra_attributes.is_empty());
        for a in [CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_COEFFICIENT] {
            assert!(matches!(
                read_attribute(&o, a),
                Err(HsmError::AttributeSensitive)
            ));
        }
    }

    #[test]
    fn provenance_and_trusted_cannot_be_self_asserted() {
        let s = ObjectStore::new();
        for a in [CKA_LOCAL, CKA_NEVER_EXTRACTABLE, CKA_ALWAYS_SENSITIVE] {
            let mut t = secret_template(true, false);
            t.push((a, vec![1]));
            assert!(matches!(
                s.create_object(&t),
                Err(HsmError::AttributeReadOnly)
            ));
        }
        let mut t = secret_template(true, false);
        t.push((CKA_TRUSTED, vec![1]));
        assert!(matches!(
            s.create_object(&t),
            Err(HsmError::AttributeReadOnly)
        ));
        let h = s
            .create_object_in(&t, &ObjectContext::new(0, 0, true))
            .unwrap();
        assert!(s.get_object(h).unwrap().read().trusted);
        // CKA_COPYABLE is honoured as a typed field.
        let mut t = secret_template(true, false);
        t.push((CKA_COPYABLE, vec![0]));
        let h = s.create_object(&t).unwrap();
        assert!(!s.get_object(h).unwrap().read().copyable);
    }

    #[test]
    fn duplicate_and_malformed_attributes_rejected() {
        let s = ObjectStore::new();
        let mut t = secret_template(true, false);
        t.push((CKA_LABEL, b"a".to_vec()));
        t.push((CKA_LABEL, b"b".to_vec()));
        assert!(matches!(
            s.create_object(&t),
            Err(HsmError::TemplateInconsistent)
        ));
        let mut t = secret_template(true, false);
        t.push((CKA_TOKEN, vec![1, 0]));
        assert!(s.create_object(&t).is_err());
        let mut t = secret_template(true, false);
        t.push((CKA_END_DATE, b"20250231".to_vec()));
        assert!(matches!(
            s.create_object(&t),
            Err(HsmError::AttributeValueInvalid)
        ));
    }

    #[test]
    fn slot_isolation_and_session_objects() {
        let s = ObjectStore::new();
        let h = s
            .create_object_in(
                &secret_template(true, false),
                &ObjectContext::new(1, 77, false),
            )
            .unwrap();
        assert!(s.get_object_in_slot(h, 1).is_ok());
        assert!(matches!(
            s.get_object_in_slot(h, 0),
            Err(HsmError::ObjectHandleInvalid)
        ));
        assert!(s.find_objects_for_slot(&[], true, Some(0)).is_empty());
        assert_eq!(s.find_objects_for_slot(&[], true, Some(1)), vec![h]);
        assert_eq!(s.destroy_session_objects(77), 1);
        assert!(s.get_object(h).is_err());
    }

    #[test]
    fn set_attributes_one_way_rules() {
        let s = ObjectStore::new();
        let h = s.create_object(&secret_template(false, true)).unwrap();
        s.set_attributes(h, 0, &[(CKA_SENSITIVE, vec![1])], false)
            .unwrap();
        assert!(s
            .set_attributes(h, 0, &[(CKA_SENSITIVE, vec![0])], false)
            .is_err());
        s.set_attributes(h, 0, &[(CKA_EXTRACTABLE, vec![0])], false)
            .unwrap();
        assert!(s
            .set_attributes(h, 0, &[(CKA_EXTRACTABLE, vec![1])], false)
            .is_err());
        assert!(s
            .set_attributes(h, 0, &[(CKA_TRUSTED, vec![1])], false)
            .is_err());
        assert!(s
            .set_attributes(h, 0, &[(CKA_LOCAL, vec![1])], false)
            .is_err());
    }

    #[test]
    fn destroyed_object_material_is_zeroized_for_cached_refs() {
        let s = ObjectStore::new();
        let h = s.create_object(&secret_template(true, false)).unwrap();
        let cached = s.get_object(h).unwrap();
        s.destroy_object_in(h, 0).unwrap();
        let c = cached.read();
        assert!(c.key_material.is_none());
        assert_eq!(c.lifecycle_state, KeyLifecycleState::Destroyed);
    }

    #[test]
    fn non_destroyable_is_action_prohibited() {
        let s = ObjectStore::new();
        let mut t = secret_template(true, false);
        t.push((CKA_DESTROYABLE, vec![0]));
        let h = s.create_object(&t).unwrap();
        assert!(matches!(
            s.destroy_object_in(h, 0),
            Err(HsmError::ActionProhibited)
        ));
    }
}
