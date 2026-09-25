// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Encrypted persistent store (redb) for token state and token objects.
//!
//! # Key hierarchy (A1-17, H3-15)
//!
//! * Each slot has a random 256-bit **data-encryption key (DEK)**, generated
//!   at `C_InitToken`. Object records are encrypted with AES-256-GCM under
//!   the DEK.
//! * The DEK is stored only **wrapped** (AES-256-GCM) under key-encryption
//!   keys derived from the SO PIN and the user PIN (PBKDF2-HMAC-SHA256 with a
//!   per-PIN random salt, see [`crate::token::pin`]). A PIN change re-wraps
//!   the DEK; `C_InitToken` generates a fresh DEK, crypto-shredding every
//!   previous record.
//! * Unwrapped DEKs live only in memory (the per-slot keyring of this store,
//!   `Zeroizing`), are installed on successful login and wiped on
//!   `C_Finalize` / drop / re-initialisation.
//!
//! # Record format and integrity
//!
//! Object record = `"CHO1" | slot | handle | generation | nonce | ciphertext`
//! with AAD = `"craton-hsm/object/v1" | store_key | slot | handle | generation`,
//! so a record cannot be moved to another key, slot or handle, and an older
//! generation of a record cannot be replayed. Each slot has an authenticated
//! **manifest** (HMAC-SHA256 under a DEK-derived key) listing every
//! `(store_key, generation)` pair plus a monotonic counter. Records not in the
//! manifest (resurrected / replayed) are quarantined instead of loaded; a
//! manifest with an invalid MAC fails closed.
//!
//! Whole-file rollback (replacing the entire database with an older copy) can
//! only be detected with an external monotonic counter (TPM NV index or
//! similar); see `docs` / handoff notes.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use parking_lot::{Mutex, RwLock};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::config::defaults::{
    DEFAULT_PBKDF2_ITERATIONS, KEY_LEN as DEFAULT_KEY_LEN, NONCE_LEN as DEFAULT_NONCE_LEN,
    SALT_LEN as DEFAULT_SALT_LEN,
};
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::{CK_OBJECT_HANDLE, CK_SLOT_ID};

/// PBKDF2 iteration count used when the caller does not supply one.
/// Single source of truth: [`crate::config::defaults::DEFAULT_PBKDF2_ITERATIONS`].
const PBKDF2_ITERATIONS: u32 = DEFAULT_PBKDF2_ITERATIONS;
const SALT_LEN: usize = DEFAULT_SALT_LEN;
const NONCE_LEN: usize = DEFAULT_NONCE_LEN;
const KEY_LEN: usize = DEFAULT_KEY_LEN;

/// Legacy blob table (generic encrypted key/value API).
const BLOBS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("blobs");
/// Encrypted object records.
const OBJECTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("objects");
/// Token records, lockout counters and manifests.
const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
/// Records that failed authentication or were not listed in the manifest.
const QUARANTINE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("quarantine");

const RECORD_MAGIC: &[u8; 4] = b"CHO1";
const RECORD_HEADER_LEN: usize = 4 + 8 + 8 + 8 + NONCE_LEN;
const OBJECT_AAD_LABEL: &[u8] = b"craton-hsm/object/v1";
const BLOB_AAD_LABEL: &[u8] = b"craton-hsm/blob/v1";
const MANIFEST_KEY_LABEL: &[u8] = b"craton-hsm/manifest-key/v1";

/// Default database file name inside the storage directory.
pub const DB_FILE_NAME: &str = "craton_hsm.redb";

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// Fill `buf` with random bytes from the module-wide approved SP 800-90A
/// DRBG (`crypto::drbg::fill_random`, fork-aware). DRBG failures are
/// propagated — there is no fallback to a non-approved RNG (crypto handoff
/// #13; a failed health test latches the module error state). Refuses to
/// return an all-zero buffer (H3-18).
pub(crate) fn fill_random(buf: &mut [u8]) -> HsmResult<()> {
    crate::crypto::drbg::fill_random(buf).map_err(|e| {
        tracing::error!("DRBG failure while generating storage randomness: {:?}", e);
        e
    })?;
    if buf.len() >= 8 && buf.iter().all(|&b| b == 0) {
        tracing::error!("RNG produced an all-zero buffer — refusing to use it");
        return Err(HsmError::GeneralError);
    }
    Ok(())
}

fn db_err<E: std::fmt::Display>(ctx: &'static str) -> impl Fn(E) -> HsmError {
    move |e| {
        tracing::error!("persistent store: {}: {}", ctx, e);
        HsmError::DeviceError
    }
}

fn slot_prefix(slot: CK_SLOT_ID) -> String {
    format!("s{:020}/", slot as u64)
}

/// Build the opaque store key for a slot (random, non-sequential).
pub(crate) fn new_store_key(slot: CK_SLOT_ID) -> HsmResult<String> {
    let mut rnd = [0u8; 16];
    fill_random(&mut rnd)?;
    Ok(format!("{}obj_{}", slot_prefix(slot), hex::encode(rnd)))
}

fn slot_of_store_key(store_key: &str) -> Option<CK_SLOT_ID> {
    let rest = store_key.strip_prefix('s')?;
    let (num, _) = rest.split_once('/')?;
    num.parse::<u64>().ok().map(|v| v as CK_SLOT_ID)
}

/// Authenticated per-slot manifest of `(store_key, generation)` pairs.
#[derive(Serialize, Deserialize, Default, Clone)]
struct Manifest {
    version: u32,
    /// Monotonic counter, bumped on every write to the slot.
    counter: u64,
    entries: BTreeMap<String, u64>,
    #[serde(default)]
    mac: String,
}

impl Manifest {
    fn mac_bytes(&self, slot: CK_SLOT_ID, dek: &[u8; KEY_LEN]) -> [u8; 32] {
        use hmac::Mac;
        let mut kmac = <HmacSha256 as Mac>::new_from_slice(dek).expect("any key length");
        kmac.update(MANIFEST_KEY_LABEL);
        let mkey = Zeroizing::new(kmac.finalize().into_bytes());
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&mkey).expect("any key length");
        mac.update(&(slot as u64).to_le_bytes());
        mac.update(&self.version.to_le_bytes());
        mac.update(&self.counter.to_le_bytes());
        for (k, g) in &self.entries {
            mac.update(&(k.len() as u64).to_le_bytes());
            mac.update(k.as_bytes());
            mac.update(&g.to_le_bytes());
        }
        mac.finalize().into_bytes().into()
    }

    fn seal(&mut self, slot: CK_SLOT_ID, dek: &[u8; KEY_LEN]) {
        self.version = 1;
        self.mac = hex::encode(self.mac_bytes(slot, dek));
    }

    fn verify(&self, slot: CK_SLOT_ID, dek: &[u8; KEY_LEN]) -> bool {
        use subtle::ConstantTimeEq;
        let expected = self.mac_bytes(slot, dek);
        match hex::decode(&self.mac) {
            Ok(m) if m.len() == 32 => m.ct_eq(&expected).into(),
            _ => false,
        }
    }
}

fn manifest_key(slot: CK_SLOT_ID) -> String {
    format!("manifest/{}", slot as u64)
}

/// Meta key of the persisted usage state (GCM lease, CTR ranges) of an
/// object record. Shares the slot prefix of the store key, so a slot's
/// usage records can be removed with one range delete.
fn key_usage_key(store_key: &str) -> String {
    format!("{}{}", KEY_USAGE_PREFIX, store_key)
}

const KEY_USAGE_PREFIX: &str = "keyusage/";
const BACKUP_IDS_AAD_LABEL: &[u8] = b"craton-hsm/backup-ids/v1";

/// Meta key of a slot's authenticated set of consumed backup IDs (replay
/// guard kept inside the single-writer database, H5-06).
fn backup_ids_key(slot: CK_SLOT_ID) -> String {
    format!("backupids/{}", slot as u64)
}

fn backup_ids_aad(slot: CK_SLOT_ID) -> Vec<u8> {
    let mut aad = BACKUP_IDS_AAD_LABEL.to_vec();
    aad.extend_from_slice(&(slot as u64).to_le_bytes());
    aad
}

fn open_backup_ids(
    cipher: &Aes256Gcm,
    slot: CK_SLOT_ID,
    value: &[u8],
) -> HsmResult<std::collections::BTreeSet<String>> {
    if value.len() < NONCE_LEN + 16 {
        return Err(HsmError::DeviceError);
    }
    let aad = backup_ids_aad(slot);
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&value[..NONCE_LEN]),
            Payload {
                msg: &value[NONCE_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| {
            tracing::error!("backup replay guard of slot {} failed authentication", slot);
            HsmError::DeviceError
        })?;
    serde_json::from_slice(&pt).map_err(|_| HsmError::DeviceError)
}

fn seal_backup_ids(
    cipher: &Aes256Gcm,
    slot: CK_SLOT_ID,
    ids: &std::collections::BTreeSet<String>,
) -> HsmResult<Vec<u8>> {
    let pt = serde_json::to_vec(ids).map_err(|_| HsmError::GeneralError)?;
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &pt,
                aad: &backup_ids_aad(slot),
            },
        )
        .map_err(|_| HsmError::GeneralError)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}
const KEY_USAGE_AAD_LABEL: &[u8] = b"craton-hsm/key-usage/v1";

/// An unlocked slot key: the DEK plus its cached AES-256-GCM key schedule
/// (P6 — no key expansion per record). Both are zeroized on drop.
struct SlotKey {
    dek: Zeroizing<[u8; KEY_LEN]>,
    cipher: Aes256Gcm,
}

impl SlotKey {
    fn new(dek: &[u8; KEY_LEN]) -> Self {
        Self {
            dek: Zeroizing::new(*dek),
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek)),
        }
    }
}

/// Plaintext of one object record for [`EncryptedStore::put_objects`].
pub struct RecordInput<'a> {
    /// Opaque store key (must belong to the slot).
    pub store_key: &'a str,
    /// Object handle bound into the record's AAD.
    pub handle: CK_OBJECT_HANDLE,
    /// Serialized object.
    pub plaintext: &'a [u8],
}

fn object_aad(store_key: &str, header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(OBJECT_AAD_LABEL.len() + store_key.len() + 32);
    aad.extend_from_slice(OBJECT_AAD_LABEL);
    aad.extend_from_slice(&(store_key.len() as u64).to_le_bytes());
    aad.extend_from_slice(store_key.as_bytes());
    aad.extend_from_slice(&header[4..28]);
    aad
}

/// A decrypted object record returned by [`EncryptedStore::load_slot_objects`].
pub struct LoadedRecord {
    /// Opaque store key of the record.
    pub store_key: String,
    /// Object handle bound into the record's AAD.
    pub handle: CK_OBJECT_HANDLE,
    /// Decrypted plaintext (zeroized on drop).
    pub plaintext: Zeroizing<Vec<u8>>,
}

/// Encrypted persistent store backed by redb.
///
/// The database file is protected by an exclusive file lock (via `fs2`) to
/// prevent concurrent access from multiple processes.
pub struct EncryptedStore {
    db: Option<RwLock<Database>>,
    path: Option<PathBuf>,
    /// Hold the lock file open for the lifetime of the store.
    /// The exclusive lock is released when this file handle is dropped.
    _lock_file: Option<File>,
    /// Unlocked per-slot data-encryption keys (zeroized on drop/clear).
    keyring: RwLock<HashMap<CK_SLOT_ID, SlotKey>>,
    /// Serializes read-modify-write of manifests.
    write_lock: Mutex<()>,
}

impl Drop for EncryptedStore {
    fn drop(&mut self) {
        // Zeroize every unlocked DEK before the memory is released.
        self.keyring.write().clear();
        // Release the exclusive lock by dropping the file handle.
        // We intentionally do NOT delete the lock file — removing it after
        // releasing the lock creates a TOCTOU race where another process
        // could acquire the (about-to-be-deleted) lock, only to have it
        // deleted out from under it, allowing a third process in.
        self._lock_file.take();
    }
}

impl EncryptedStore {
    /// Create a new encrypted store. If path is None, operates in memory-only mode.
    ///
    /// When a path is provided, acquires an exclusive file lock on
    /// `<path>.lock` (created `O_NOFOLLOW`, mode 0600, never truncated) to
    /// prevent concurrent access from another process. Returns an error if
    /// the database is already locked or any file has unsafe ownership or
    /// permissions.
    pub fn new(path: Option<&str>) -> HsmResult<Self> {
        match path {
            Some(p) => Self::open_file(Path::new(p)),
            None => Ok(Self {
                db: None,
                path: None,
                _lock_file: None,
                keyring: RwLock::new(HashMap::new()),
                write_lock: Mutex::new(()),
            }),
        }
    }

    /// Open (creating if necessary) the store inside a private storage
    /// directory (created with mode 0700 and validated for ownership).
    pub fn open_in_dir(dir: &Path) -> HsmResult<Self> {
        crate::store::fs_util::ensure_private_dir(dir)?;
        Self::open_file(&dir.join(DB_FILE_NAME))
    }

    fn open_file(p: &Path) -> HsmResult<Self> {
        let lock_path = PathBuf::from(format!("{}.lock", p.display()));
        let lock_file = crate::store::fs_util::open_private(&lock_path, false)?;

        use fs2::FileExt;
        lock_file.try_lock_exclusive().map_err(|e| {
            tracing::error!(
                "Database at '{}' is locked by another process: {}",
                p.display(),
                e
            );
            HsmError::DeviceError
        })?;

        // Open (creating atomically with mode 0600 and O_NOFOLLOW if absent)
        // the database file ourselves, validate ownership/permissions on the
        // descriptor, then hand that exact descriptor to redb — no window in
        // which the path could be swapped for a symlink (H3-12).
        let f = crate::store::fs_util::open_private(p, false)?;
        let db = redb::Builder::new().create_file(f).map_err(|e| {
            tracing::error!("Failed to open database at '{}': {}", p.display(), e);
            HsmError::DeviceError
        })?;

        Ok(Self {
            db: Some(RwLock::new(db)),
            path: Some(p.to_path_buf()),
            _lock_file: Some(lock_file),
            keyring: RwLock::new(HashMap::new()),
            write_lock: Mutex::new(()),
        })
    }

    /// Check if persistent storage is available
    pub fn is_available(&self) -> bool {
        self.db.is_some()
    }

    /// Path of the database file, if file-backed.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    // ------------------------------------------------------------------
    // Keyring (unlocked DEKs)
    // ------------------------------------------------------------------

    /// Install the unlocked data-encryption key for a slot.
    pub fn set_slot_key(&self, slot: CK_SLOT_ID, key: &Zeroizing<[u8; KEY_LEN]>) {
        self.keyring.write().insert(slot, SlotKey::new(key));
    }

    /// Remove (and zeroize) the unlocked key of a slot.
    pub fn clear_slot_key(&self, slot: CK_SLOT_ID) {
        self.keyring.write().remove(&slot);
    }

    /// Zeroize every unlocked key (C_Finalize).
    pub fn clear_all_keys(&self) {
        self.keyring.write().clear();
    }

    /// True if the slot's DEK is currently unlocked.
    pub fn has_slot_key(&self, slot: CK_SLOT_ID) -> bool {
        self.keyring.read().contains_key(&slot)
    }

    /// Slots whose DEK is currently unlocked.
    pub fn unlocked_slots(&self) -> Vec<CK_SLOT_ID> {
        self.keyring.read().keys().copied().collect()
    }

    fn with_slot_key<T>(
        &self,
        slot: CK_SLOT_ID,
        f: impl FnOnce(&[u8; KEY_LEN], &Aes256Gcm) -> HsmResult<T>,
    ) -> HsmResult<T> {
        let ring = self.keyring.read();
        let key = ring.get(&slot).ok_or_else(|| {
            tracing::warn!(
                "persistent store for slot {} is locked (no login since start)",
                slot
            );
            HsmError::UserNotLoggedIn
        })?;
        f(&key.dek, &key.cipher)
    }

    /// Read and authenticate the slot manifest inside a write transaction.
    fn read_manifest_rw(
        meta: &redb::Table<'_, &str, &[u8]>,
        slot: CK_SLOT_ID,
        dek: &[u8; KEY_LEN],
    ) -> HsmResult<Manifest> {
        match meta
            .get(manifest_key(slot).as_str())
            .map_err(db_err("read manifest"))?
        {
            Some(v) => {
                let m: Manifest =
                    serde_json::from_slice(v.value()).map_err(|_| HsmError::DeviceError)?;
                if !m.verify(slot, dek) {
                    tracing::error!("manifest MAC invalid for slot {} — refusing write", slot);
                    return Err(HsmError::DeviceError);
                }
                Ok(m)
            }
            None => Ok(Manifest::default()),
        }
    }

    /// Encrypt one record (header || ciphertext) under the next generation.
    fn seal_record(
        cipher: &Aes256Gcm,
        slot: CK_SLOT_ID,
        store_key: &str,
        handle: CK_OBJECT_HANDLE,
        generation: u64,
        plaintext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + plaintext.len() + 16);
        record.extend_from_slice(RECORD_MAGIC);
        record.extend_from_slice(&(slot as u64).to_le_bytes());
        record.extend_from_slice(&(handle as u64).to_le_bytes());
        record.extend_from_slice(&generation.to_le_bytes());
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce)?;
        record.extend_from_slice(&nonce);
        let aad = object_aad(store_key, &record);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| HsmError::GeneralError)?;
        record.extend_from_slice(&ct);
        Ok(record)
    }

    /// Encrypt and store several object records of one slot in a **single**
    /// transaction (P8: one commit/fsync for a bulk import or restore). Either
    /// every record is committed or none is.
    pub fn put_objects(&self, slot: CK_SLOT_ID, records: &[RecordInput<'_>]) -> HsmResult<()> {
        self.put_objects_recording(slot, records, None)
    }

    /// [`put_objects`](Self::put_objects) that also records `backup_id` in
    /// the slot's authenticated replay guard **in the same transaction**, so
    /// restored objects and the consumed backup ID commit atomically (H5-04,
    /// H5-06). Fails with `BackupRejected(Replayed)` if the ID was consumed.
    pub fn put_objects_recording(
        &self,
        slot: CK_SLOT_ID,
        records: &[RecordInput<'_>],
        backup_id: Option<&str>,
    ) -> HsmResult<()> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;
        if records
            .iter()
            .any(|r| slot_of_store_key(r.store_key) != Some(slot))
        {
            return Err(HsmError::GeneralError);
        }
        if records.is_empty() && backup_id.is_none() {
            return Ok(());
        }
        self.with_slot_key(slot, |dek, cipher| {
            let _w = self.write_lock.lock();
            let db = db.read();
            let txn = db.begin_write().map_err(db_err("begin write"))?;
            {
                let mut meta = txn.open_table(META_TABLE).map_err(db_err("open meta"))?;
                if let Some(id) = backup_id {
                    let mut ids = match meta
                        .get(backup_ids_key(slot).as_str())
                        .map_err(db_err("read backup ids"))?
                    {
                        Some(v) => open_backup_ids(cipher, slot, v.value())?,
                        None => Default::default(),
                    };
                    if !ids.insert(id.to_string()) {
                        return Err(HsmError::BackupRejected(
                            crate::error::BackupRejection::Replayed,
                        ));
                    }
                    let sealed = seal_backup_ids(cipher, slot, &ids)?;
                    meta.insert(backup_ids_key(slot).as_str(), sealed.as_slice())
                        .map_err(db_err("write backup ids"))?;
                }
                let mut manifest = Self::read_manifest_rw(&meta, slot, dek)?;
                let mut objs = txn
                    .open_table(OBJECTS_TABLE)
                    .map_err(db_err("open objects"))?;
                for r in records {
                    manifest.counter = manifest
                        .counter
                        .checked_add(1)
                        .ok_or(HsmError::DeviceError)?;
                    let generation = manifest.counter;
                    let record =
                        Self::seal_record(cipher, slot, r.store_key, r.handle, generation, r.plaintext)?;
                    objs.insert(r.store_key, record.as_slice())
                        .map_err(db_err("insert object"))?;
                    manifest.entries.insert(r.store_key.to_string(), generation);
                }
                manifest.seal(slot, dek);
                let mbytes = serde_json::to_vec(&manifest).map_err(|_| HsmError::GeneralError)?;
                meta.insert(manifest_key(slot).as_str(), mbytes.as_slice())
                    .map_err(db_err("write manifest"))?;
            }
            txn.commit().map_err(db_err("commit"))?;
            Ok(())
        })
    }

    /// Consumed backup IDs of a slot (authenticated under the slot DEK).
    pub fn consumed_backup_ids(&self, slot: CK_SLOT_ID) -> HsmResult<HashSet<String>> {
        let value = match self.get_meta(&backup_ids_key(slot))? {
            Some(v) => v,
            None => return Ok(HashSet::new()),
        };
        self.with_slot_key(slot, |_, cipher| {
            Ok(open_backup_ids(cipher, slot, &value)?.into_iter().collect())
        })
    }

    // ------------------------------------------------------------------
    // Key usage state (GCM invocation leases, CTR ranges; H2-02/A1-15)
    // ------------------------------------------------------------------

    fn key_usage_aad(slot: CK_SLOT_ID, store_key: &str) -> Vec<u8> {
        let mut aad = KEY_USAGE_AAD_LABEL.to_vec();
        aad.extend_from_slice(&(slot as u64).to_le_bytes());
        aad.extend_from_slice(store_key.as_bytes());
        aad
    }

    /// Durably store the usage state of the key held in object record
    /// `store_key` (AES-256-GCM under the slot DEK, bound to slot and record).
    pub fn put_key_usage(
        &self,
        slot: CK_SLOT_ID,
        store_key: &str,
        usage: &crate::crypto::encrypt::PersistedKeyUsage,
    ) -> HsmResult<()> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;
        if slot_of_store_key(store_key) != Some(slot) {
            return Err(HsmError::GeneralError);
        }
        let plaintext = serde_json::to_vec(usage).map_err(|_| HsmError::GeneralError)?;
        self.with_slot_key(slot, |_, cipher| {
            let mut nonce = [0u8; NONCE_LEN];
            fill_random(&mut nonce)?;
            let aad = Self::key_usage_aad(slot, store_key);
            let ct = cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| HsmError::GeneralError)?;
            let mut value = nonce.to_vec();
            value.extend_from_slice(&ct);
            let _w = self.write_lock.lock();
            let db = db.read();
            let txn = db.begin_write().map_err(db_err("begin write"))?;
            {
                let mut meta = txn.open_table(META_TABLE).map_err(db_err("open meta"))?;
                meta.insert(key_usage_key(store_key).as_str(), value.as_slice())
                    .map_err(db_err("write key usage"))?;
            }
            txn.commit().map_err(db_err("commit"))?;
            Ok(())
        })
    }

    /// Load the persisted usage state of a key. A record that fails
    /// authentication is reported as `DeviceError` (fail closed: the key must
    /// not be used with a possibly rewound counter).
    pub fn get_key_usage(
        &self,
        slot: CK_SLOT_ID,
        store_key: &str,
    ) -> HsmResult<Option<crate::crypto::encrypt::PersistedKeyUsage>> {
        let value = match self.get_meta(&key_usage_key(store_key))? {
            Some(v) => v,
            None => return Ok(None),
        };
        self.with_slot_key(slot, |_, cipher| {
            if value.len() < NONCE_LEN + 16 {
                return Err(HsmError::DeviceError);
            }
            let aad = Self::key_usage_aad(slot, store_key);
            let pt = cipher
                .decrypt(
                    Nonce::from_slice(&value[..NONCE_LEN]),
                    Payload {
                        msg: &value[NONCE_LEN..],
                        aad: &aad,
                    },
                )
                .map_err(|_| {
                    tracing::error!("key usage record '{}' failed authentication", store_key);
                    HsmError::DeviceError
                })?;
            serde_json::from_slice(&pt)
                .map(Some)
                .map_err(|_| HsmError::DeviceError)
        })
    }

    // ------------------------------------------------------------------
    // Object records
    // ------------------------------------------------------------------

    /// Encrypt and store an object record, updating the slot manifest in the
    /// same transaction. Requires the slot's DEK to be unlocked.
    pub fn put_object(
        &self,
        slot: CK_SLOT_ID,
        store_key: &str,
        handle: CK_OBJECT_HANDLE,
        plaintext: &[u8],
    ) -> HsmResult<()> {
        self.put_objects(
            slot,
            &[RecordInput {
                store_key,
                handle,
                plaintext,
            }],
        )
    }

    /// Delete an object record and remove it from the manifest.
    pub fn delete_object(&self, slot: CK_SLOT_ID, store_key: &str) -> HsmResult<()> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;
        self.with_slot_key(slot, |dek, _| {
            let _w = self.write_lock.lock();
            let db = db.read();
            let txn = db.begin_write().map_err(db_err("begin write"))?;
            {
                let mut meta = txn.open_table(META_TABLE).map_err(db_err("open meta"))?;
                let mut manifest = Self::read_manifest_rw(&meta, slot, dek)?;
                let mut objs = txn
                    .open_table(OBJECTS_TABLE)
                    .map_err(db_err("open objects"))?;
                objs.remove(store_key).map_err(db_err("remove object"))?;
                meta.remove(key_usage_key(store_key).as_str())
                    .map_err(db_err("remove key usage"))?;
                manifest.entries.remove(store_key);
                manifest.counter = manifest
                    .counter
                    .checked_add(1)
                    .ok_or(HsmError::DeviceError)?;
                manifest.seal(slot, dek);
                let mbytes = serde_json::to_vec(&manifest).map_err(|_| HsmError::GeneralError)?;
                meta.insert(manifest_key(slot).as_str(), mbytes.as_slice())
                    .map_err(db_err("write manifest"))?;
            }
            txn.commit().map_err(db_err("commit"))?;
            Ok(())
        })
    }

    /// Load and authenticate every object record of a slot in a single read
    /// transaction (P7). Records that fail authentication or are not listed
    /// in the manifest with the same generation are quarantined and skipped
    /// (H3-15). An invalid manifest MAC fails closed with `DeviceError`.
    pub fn load_slot_objects(&self, slot: CK_SLOT_ID) -> HsmResult<Vec<LoadedRecord>> {
        let db_lock = self.db.as_ref().ok_or(HsmError::GeneralError)?;
        let (loaded, bad) = self.with_slot_key(slot, |dek, cipher| {
            let db = db_lock.read();
            let txn = db.begin_read().map_err(db_err("begin read"))?;
            let manifest = match txn.open_table(META_TABLE) {
                Ok(meta) => match meta
                    .get(manifest_key(slot).as_str())
                    .map_err(db_err("read manifest"))?
                {
                    Some(v) => {
                        let m: Manifest = serde_json::from_slice(v.value())
                            .map_err(|_| HsmError::DeviceError)?;
                        if !m.verify(slot, dek) {
                            tracing::error!(
                                "manifest MAC invalid for slot {} — store tampered or wrong key",
                                slot
                            );
                            return Err(HsmError::DeviceError);
                        }
                        Some(m)
                    }
                    None => None,
                },
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(e) => return Err(db_err("open meta")(e)),
            };
            let manifest = manifest.unwrap_or_default();

            let mut loaded = Vec::new();
            let mut bad: Vec<(String, Vec<u8>)> = Vec::new();
            let objs = match txn.open_table(OBJECTS_TABLE) {
                Ok(t) => Some(t),
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(e) => return Err(db_err("open objects")(e)),
            };
            if let Some(objs) = objs {
                let prefix = slot_prefix(slot);
                let end = format!("s{:020}0", slot as u64);
                let range = objs
                    .range(prefix.as_str()..end.as_str())
                    .map_err(db_err("iterate objects"))?;
                for entry in range {
                    let (k, v) = entry.map_err(db_err("read object"))?;
                    let store_key = k.value().to_string();
                    let rec = v.value();
                    let ok = (|| -> Option<LoadedRecord> {
                        if rec.len() < RECORD_HEADER_LEN || &rec[0..4] != RECORD_MAGIC {
                            return None;
                        }
                        let rslot = u64::from_le_bytes(rec[4..12].try_into().ok()?);
                        let handle = u64::from_le_bytes(rec[12..20].try_into().ok()?);
                        let generation = u64::from_le_bytes(rec[20..28].try_into().ok()?);
                        if rslot != slot as u64 {
                            return None;
                        }
                        if manifest.entries.get(&store_key) != Some(&generation) {
                            tracing::error!(
                                "object record '{}' (generation {}) not in manifest — replay/resurrection?",
                                store_key,
                                generation
                            );
                            return None;
                        }
                        let aad = object_aad(&store_key, rec);
                        let pt = cipher
                            .decrypt(
                                Nonce::from_slice(&rec[28..28 + NONCE_LEN]),
                                Payload {
                                    msg: &rec[RECORD_HEADER_LEN..],
                                    aad: &aad,
                                },
                            )
                            .ok()?;
                        Some(LoadedRecord {
                            store_key: store_key.clone(),
                            handle: handle as CK_OBJECT_HANDLE,
                            plaintext: Zeroizing::new(pt),
                        })
                    })();
                    match ok {
                        Some(r) => loaded.push(r),
                        None => bad.push((store_key, rec.to_vec())),
                    }
                }
            }
            let present: std::collections::HashSet<&str> =
                loaded.iter().map(|r| r.store_key.as_str()).collect();
            for k in manifest.entries.keys() {
                if !present.contains(k.as_str()) && !bad.iter().any(|(b, _)| b == k) {
                    tracing::error!("object record '{}' listed in manifest is missing", k);
                }
            }
            Ok((loaded, bad))
        })?;

        if !bad.is_empty() {
            tracing::error!(
                "quarantining {} unauthenticated object record(s) for slot {}",
                bad.len(),
                slot
            );
            let _w = self.write_lock.lock();
            let db = db_lock.read();
            let txn = db.begin_write().map_err(db_err("begin write"))?;
            {
                let mut q = txn
                    .open_table(QUARANTINE_TABLE)
                    .map_err(db_err("open quarantine"))?;
                let mut objs = txn
                    .open_table(OBJECTS_TABLE)
                    .map_err(db_err("open objects"))?;
                for (k, v) in &bad {
                    q.insert(k.as_str(), v.as_slice())
                        .map_err(db_err("quarantine insert"))?;
                    objs.remove(k.as_str())
                        .map_err(db_err("quarantine remove"))?;
                }
            }
            txn.commit().map_err(db_err("commit"))?;
        }
        Ok(loaded)
    }

    /// Remove every object record and the manifest of a slot (C_InitToken),
    /// then compact the database so freed pages are released (best effort).
    pub fn clear_slot(&self, slot: CK_SLOT_ID) -> HsmResult<()> {
        let db_lock = self.db.as_ref().ok_or(HsmError::GeneralError)?;
        {
            let _w = self.write_lock.lock();
            let db = db_lock.read();
            let txn = db.begin_write().map_err(db_err("begin write"))?;
            {
                let prefix = slot_prefix(slot);
                let end = format!("s{:020}0", slot as u64);
                let mut objs = txn
                    .open_table(OBJECTS_TABLE)
                    .map_err(db_err("open objects"))?;
                objs.retain_in(prefix.as_str()..end.as_str(), |_, _| false)
                    .map_err(db_err("clear objects"))?;
                let mut q = txn
                    .open_table(QUARANTINE_TABLE)
                    .map_err(db_err("open quarantine"))?;
                q.retain_in(prefix.as_str()..end.as_str(), |_, _| false)
                    .map_err(db_err("clear quarantine"))?;
                let mut meta = txn.open_table(META_TABLE).map_err(db_err("open meta"))?;
                meta.remove(manifest_key(slot).as_str())
                    .map_err(db_err("remove manifest"))?;
                let ku_start = format!("{}{}", KEY_USAGE_PREFIX, prefix);
                let ku_end = format!("{}{}", KEY_USAGE_PREFIX, end);
                meta.retain_in(ku_start.as_str()..ku_end.as_str(), |_, _| false)
                    .map_err(db_err("clear key usage"))?;
                meta.remove(backup_ids_key(slot).as_str())
                    .map_err(db_err("remove backup ids"))?;
            }
            txn.commit().map_err(db_err("commit"))?;
        }
        self.compact();
        Ok(())
    }

    /// Compact the database (best effort) so pages of deleted records are
    /// released. Records are additionally crypto-shredded when the slot DEK
    /// is replaced by `C_InitToken`.
    pub fn compact(&self) {
        if let Some(db) = self.db.as_ref() {
            let _w = self.write_lock.lock();
            if let Err(e) = db.write().compact() {
                tracing::debug!("database compaction skipped: {}", e);
            }
        }
    }

    // ------------------------------------------------------------------
    // Metadata (token records, lockout counters)
    // ------------------------------------------------------------------

    /// Write a metadata value (durably committed).
    pub fn put_meta(&self, key: &str, value: &[u8]) -> HsmResult<()> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;
        let _w = self.write_lock.lock();
        let db = db.read();
        let txn = db.begin_write().map_err(db_err("begin write"))?;
        {
            let mut meta = txn.open_table(META_TABLE).map_err(db_err("open meta"))?;
            meta.insert(key, value).map_err(db_err("write meta"))?;
        }
        txn.commit().map_err(db_err("commit"))?;
        Ok(())
    }

    /// Read a metadata value.
    pub fn get_meta(&self, key: &str) -> HsmResult<Option<Vec<u8>>> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;
        let db = db.read();
        let txn = db.begin_read().map_err(db_err("begin read"))?;
        let meta = match txn.open_table(META_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(db_err("open meta")(e)),
        };
        let v = meta.get(key).map_err(db_err("read meta"))?;
        Ok(v.map(|v| v.value().to_vec()))
    }

    // ------------------------------------------------------------------
    // Legacy generic encrypted blob API
    // ------------------------------------------------------------------

    /// Store an encrypted blob under a key. The ciphertext is bound to
    /// `store_key` through the AEAD associated data.
    pub fn store_encrypted(
        &self,
        store_key: &str,
        plaintext: &[u8],
        encryption_key: &[u8; KEY_LEN],
    ) -> HsmResult<()> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        fill_random(&mut nonce_bytes)?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(encryption_key));
        let aad = [BLOB_AAD_LABEL, store_key.as_bytes()].concat();
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| HsmError::GeneralError)?;

        let mut stored = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        stored.extend_from_slice(&nonce_bytes);
        stored.extend_from_slice(&ciphertext);

        let _w = self.write_lock.lock();
        let db = db.read();
        let write_txn = db.begin_write().map_err(db_err("begin write"))?;
        {
            let mut table = write_txn
                .open_table(BLOBS_TABLE)
                .map_err(db_err("open blobs"))?;
            table
                .insert(store_key, stored.as_slice())
                .map_err(db_err("insert blob"))?;
        }
        write_txn.commit().map_err(db_err("commit"))?;
        Ok(())
    }

    /// Load and decrypt a blob. The returned buffer is `Zeroizing`.
    pub fn load_encrypted(
        &self,
        store_key: &str,
        encryption_key: &[u8; KEY_LEN],
    ) -> HsmResult<Option<Zeroizing<Vec<u8>>>> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;
        let db = db.read();
        let read_txn = db.begin_read().map_err(db_err("begin read"))?;
        let table = match read_txn.open_table(BLOBS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(db_err("open blobs")(e)),
        };
        let stored = match table.get(store_key).map_err(db_err("read blob"))? {
            Some(data) => data.value().to_vec(),
            None => return Ok(None),
        };
        if stored.len() < NONCE_LEN {
            return Err(HsmError::EncryptedDataInvalid);
        }
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(encryption_key));
        let aad = [BLOB_AAD_LABEL, store_key.as_bytes()].concat();
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&stored[..NONCE_LEN]),
                Payload {
                    msg: &stored[NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| HsmError::EncryptedDataInvalid)?;
        Ok(Some(Zeroizing::new(plaintext)))
    }

    /// Delete a stored blob.
    pub fn delete(&self, store_key: &str) -> HsmResult<()> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;
        let _w = self.write_lock.lock();
        let db = db.read();
        let write_txn = db.begin_write().map_err(db_err("begin write"))?;
        {
            let mut table = write_txn
                .open_table(BLOBS_TABLE)
                .map_err(db_err("open blobs"))?;
            table.remove(store_key).map_err(db_err("remove blob"))?;
        }
        write_txn.commit().map_err(db_err("commit"))?;
        Ok(())
    }

    /// List all blob keys. Iteration errors are propagated (fail closed).
    pub fn list_keys(&self) -> HsmResult<Vec<String>> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;
        let db = db.read();
        let read_txn = db.begin_read().map_err(db_err("begin read"))?;
        let table = match read_txn.open_table(BLOBS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(db_err("open blobs")(e)),
        };
        let mut keys = Vec::new();
        for entry in table.iter().map_err(db_err("iterate blobs"))? {
            let entry = entry.map_err(db_err("read blob key"))?;
            keys.push(entry.0.value().to_string());
        }
        Ok(keys)
    }

    /// Clear all blobs (legacy API).
    pub fn clear(&self) -> HsmResult<()> {
        let db = self.db.as_ref().ok_or(HsmError::GeneralError)?;
        {
            let _w = self.write_lock.lock();
            let db = db.read();
            let write_txn = db.begin_write().map_err(db_err("begin write"))?;
            {
                let _ = write_txn.delete_table(BLOBS_TABLE);
            }
            write_txn.commit().map_err(db_err("commit"))?;
        }
        self.compact();
        Ok(())
    }
}

/// Set restrictive file permissions (owner-only read/write) on a path.
/// On Unix, sets mode 0o600 (0o700 for directories). On Windows, sets a DACL
/// granting only the current user GENERIC_ALL (removing inherited ACEs).
///
/// Errors are propagated so callers can fail closed (H3-29).
pub fn set_restrictive_permissions(path: &std::path::Path) -> HsmResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::symlink_metadata(path).map_err(|e| {
            tracing::error!("cannot stat '{}': {}", path.display(), e);
            HsmError::DeviceError
        })?;
        if meta.file_type().is_symlink() {
            tracing::error!("refusing to chmod symlink '{}'", path.display());
            return Err(HsmError::DeviceError);
        }
        let mode = if meta.is_dir() { 0o700 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
            tracing::error!(
                "Failed to set restrictive permissions on '{}': {}",
                path.display(),
                e
            );
            HsmError::DeviceError
        })?;
    }
    #[cfg(windows)]
    {
        set_restrictive_permissions_windows(path).map_err(|e| {
            tracing::error!("{}", e);
            HsmError::DeviceError
        })?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
    }
    Ok(())
}

/// Windows implementation: set a DACL that grants only the current user
/// GENERIC_ALL, removing any inherited permissions from parent directories.
#[cfg(windows)]
#[allow(unsafe_code)]
fn set_restrictive_permissions_windows(path: &std::path::Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    // Convert path to null-terminated wide string
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: All FFI calls operate on valid handles and buffers with lengths
    // checked before use. The token handle is closed in all code paths.
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, GENERIC_ALL};
        use windows_sys::Win32::Security::Authorization::{
            SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, SET_ACCESS, SE_FILE_OBJECT,
            TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
        };
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
            PROTECTED_DACL_SECURITY_INFORMATION, PSID, TOKEN_QUERY, TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        // Get current user's SID from the process token
        let mut token_handle = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
            return Err(format!(
                "Failed to open process token for ACL setup on '{}'",
                path.display()
            ));
        }

        // Query token user info size
        let mut needed: u32 = 0;
        GetTokenInformation(
            token_handle,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 {
            CloseHandle(token_handle);
            return Err(format!(
                "Failed to query token user size for '{}'",
                path.display()
            ));
        }

        let mut token_buf: Vec<u8> = vec![0u8; needed as usize];
        if GetTokenInformation(
            token_handle,
            TokenUser,
            token_buf.as_mut_ptr() as *mut _,
            needed,
            &mut needed,
        ) == 0
        {
            CloseHandle(token_handle);
            return Err(format!(
                "Failed to get token user info for '{}'",
                path.display()
            ));
        }
        CloseHandle(token_handle);

        let token_user = &*(token_buf.as_ptr() as *const TOKEN_USER);
        let user_sid: PSID = token_user.User.Sid;

        // Build an EXPLICIT_ACCESS entry granting only the current user GENERIC_ALL
        let mut ea: EXPLICIT_ACCESS_W = std::mem::zeroed();
        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee = TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: user_sid as *mut u16,
        };

        // Create the new ACL
        let mut new_acl: *mut ACL = std::ptr::null_mut();
        let result = SetEntriesInAclW(1, &ea, std::ptr::null(), &mut new_acl);
        if result != 0 {
            return Err(format!(
                "SetEntriesInAclW failed ({}) for '{}'",
                result,
                path.display()
            ));
        }

        // Apply the DACL to the file with PROTECTED flag to block inheritance
        let result = SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_acl,
            std::ptr::null_mut(),
        );
        if !new_acl.is_null() {
            LocalFree(new_acl as *mut _);
        }
        if result != 0 {
            return Err(format!(
                "SetNamedSecurityInfoW failed ({}) for '{}'",
                result,
                path.display()
            ));
        }
        Ok(())
    }
}

/// Derive an encryption key from a PIN using PBKDF2-HMAC-SHA256.
/// Returns (derived_key, salt). If salt is None, generates a new random salt.
/// The derived key is wrapped in `Zeroizing` so it is cleared on drop.
///
/// `iterations` controls the PBKDF2 work factor. Pass the value from
/// `HsmConfig::security.pbkdf2_iterations` so that runtime config is honored.
/// Falls back to [`DEFAULT_PBKDF2_ITERATIONS`] if `None`.
///
/// Returns an error if no random salt can be generated (never an all-zero
/// salt, H3-18).
pub fn derive_key_from_pin(
    pin: &[u8],
    salt: Option<&[u8]>,
    iterations: Option<u32>,
) -> HsmResult<(Zeroizing<[u8; KEY_LEN]>, Vec<u8>)> {
    let salt_bytes = match salt {
        Some(s) => s.to_vec(),
        None => {
            let mut s = vec![0u8; SALT_LEN];
            fill_random(&mut s)?;
            s
        }
    };

    let iters = iterations.unwrap_or(PBKDF2_ITERATIONS);
    let mut derived_key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2_hmac_sha256(pin, &salt_bytes, iters, derived_key.as_mut())?;

    Ok((derived_key, salt_bytes))
}

/// PBKDF2-HMAC-SHA256 used for PIN verifiers, storage KEKs and backup
/// passphrases. In `fips` builds the FIPS-validated AWS-LC implementation is
/// used (A1-03; its PBKDF2 CAST is part of the POST), otherwise RustCrypto.
pub(crate) fn pbkdf2_hmac_sha256(
    secret: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> HsmResult<()> {
    if iterations == 0 {
        return Err(HsmError::ArgumentsBad);
    }
    #[cfg(feature = "fips")]
    {
        let iters = std::num::NonZeroU32::new(iterations).ok_or(HsmError::ArgumentsBad)?;
        aws_lc_rs::pbkdf2::derive(aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256, iters, salt, secret, out);
        Ok(())
    }
    #[cfg(not(feature = "fips"))]
    {
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(secret, salt, iterations, out);
        Ok(())
    }
}

/// Verify a PIN against a stored PBKDF2 hash.
/// The stored_hash format is: salt (32 bytes) || derived_key (32 bytes)
pub fn verify_pin_pbkdf2(stored_hash: &[u8], pin: &[u8], iterations: Option<u32>) -> bool {
    if stored_hash.len() != SALT_LEN + KEY_LEN {
        return false;
    }
    let salt = &stored_hash[..SALT_LEN];
    let stored_key = &stored_hash[SALT_LEN..];

    let derived_key = match derive_key_from_pin(pin, Some(salt), iterations) {
        Ok((k, _)) => k,
        Err(_) => return false,
    };

    use subtle::ConstantTimeEq;
    stored_key.ct_eq(derived_key.as_ref()).into()
}

/// Hash a PIN for storage using PBKDF2.
/// Returns `Zeroizing<Vec<u8>>` containing salt (32 bytes) || derived_key (32 bytes).
/// The wrapper ensures the derived key bytes are zeroized when dropped.
pub fn hash_pin_pbkdf2(pin: &[u8], iterations: Option<u32>) -> HsmResult<Zeroizing<Vec<u8>>> {
    let (derived_key, salt) = derive_key_from_pin(pin, None, iterations)?;
    let mut result = Zeroizing::new(Vec::with_capacity(SALT_LEN + KEY_LEN));
    result.extend_from_slice(&salt);
    result.extend_from_slice(derived_key.as_ref());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new([b; KEY_LEN])
    }

    #[test]
    fn object_records_roundtrip_and_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let store = EncryptedStore::open_in_dir(&dir.path().join("st")).unwrap();
        store.set_slot_key(3, &key(7));
        let k1 = new_store_key(3).unwrap();
        store.put_object(3, &k1, 42, b"hello").unwrap();
        let recs = store.load_slot_objects(3).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].handle, 42);
        assert_eq!(&recs[0].plaintext[..], b"hello");
        // Wrong key: manifest MAC fails closed.
        store.set_slot_key(3, &key(8));
        assert!(store.load_slot_objects(3).is_err());
        // Locked slot cannot write.
        assert!(store
            .put_object(4, &new_store_key(4).unwrap(), 1, b"x")
            .is_err());
    }

    #[test]
    fn replayed_record_is_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let store = EncryptedStore::open_in_dir(&dir.path().join("st")).unwrap();
        store.set_slot_key(0, &key(1));
        let k = new_store_key(0).unwrap();
        store.put_object(0, &k, 5, b"v1").unwrap();
        // Capture the old record, write a new generation, then replay the old one.
        let old = {
            let db = store.db.as_ref().unwrap().read();
            let txn = db.begin_read().unwrap();
            let t = txn.open_table(OBJECTS_TABLE).unwrap();
            let v = t.get(k.as_str()).unwrap().unwrap().value().to_vec();
            v
        };
        store.put_object(0, &k, 5, b"v2").unwrap();
        {
            let db = store.db.as_ref().unwrap().read();
            let txn = db.begin_write().unwrap();
            {
                let mut t = txn.open_table(OBJECTS_TABLE).unwrap();
                t.insert(k.as_str(), old.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }
        let recs = store.load_slot_objects(0).unwrap();
        assert!(recs.is_empty(), "replayed old generation must not load");
    }

    #[test]
    fn salt_is_never_all_zero() {
        let (_, salt) = derive_key_from_pin(b"pin", None, Some(1000)).unwrap();
        assert!(salt.iter().any(|&b| b != 0));
    }
}
