// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! HSM backup/restore — encrypted export of token objects.
//!
//! Backup file format (version 2):
//! ```text
//! [4 bytes: magic "RHBK"]
//! [4 bytes: version (2) as u32 LE]
//! [1 byte : KDF id (1 = PBKDF2-HMAC-SHA256)]
//! [4 bytes: PBKDF2 iterations as u32 LE]
//! [32 bytes: PBKDF2 salt]
//! [12 bytes: AES-GCM nonce]
//! [remaining: AES-256-GCM ciphertext of JSON payload]
//! ```
//!
//! The whole header is passed to AES-GCM as associated data, so magic,
//! version, KDF parameters, salt and nonce are authenticated (H3-16). The KDF
//! parameters travel with the backup, so changing `pbkdf2_iterations` does not
//! make old backups unreadable.
//!
//! Restored objects are validated with the same policy as object creation
//! ([`sanitize_restored_object`]): secret keys must be sensitive,
//! `CKA_TRUSTED` and provenance claims are stripped, and callers must
//! re-allocate handles when inserting them (see `HsmCore::import_objects`).
//!
//! **Binding:** pass a per-token random identity (e.g. `HsmCore::token_binding`)
//! as `token_serial` — the public serial number is not a secret binding.

use std::collections::HashSet;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};

use zeroize::Zeroizing;

use crate::config::defaults::{DEFAULT_PBKDF2_ITERATIONS, NONCE_LEN, SALT_LEN};
use crate::error::{HsmError, HsmResult};
use crate::store::attributes::{sanitize_restored_object, ZeroizingObjects};
use crate::store::encrypted_store::{derive_key_from_pin, fill_random};
use crate::store::object::StoredObject;

const BACKUP_MAGIC: &[u8; 4] = b"RHBK";
const BACKUP_VERSION: u32 = 2;
const KDF_PBKDF2_SHA256: u8 = 1;
const HEADER_LEN: usize = 4 + 4 + 1 + 4 + SALT_LEN + NONCE_LEN; // 57 bytes
const MIN_PASSPHRASE_LEN: usize = 16;
/// Bounds on the iteration count accepted from a backup header.
const MIN_BACKUP_ITERATIONS: u32 = 100_000;
const MAX_BACKUP_ITERATIONS: u32 = 10_000_000;

/// Inner JSON payload that gets encrypted in the backup file (borrowing
/// form used for serialization, P12 — no clone of every key).
#[derive(Serialize)]
struct BackupPayloadRef<'a> {
    version: u32,
    created: String,
    created_epoch: u64,
    backup_id: String,
    token_serial: &'a str,
    object_count: usize,
    objects: &'a [StoredObject],
}

/// Owned form used for deserialization.
#[derive(Deserialize)]
struct BackupPayload {
    version: u32,
    #[allow(dead_code)]
    created: String,
    /// Seconds since UNIX epoch — used for replay/staleness detection on restore.
    created_epoch: u64,
    /// Random identifier of this backup instance.
    backup_id: String,
    /// Token binding (per-token identity) that produced this backup.
    token_serial: String,
    object_count: usize,
    objects: Vec<StoredObject>,
}

/// Maximum allowed age of a backup in seconds (default: 30 days).
const DEFAULT_MAX_BACKUP_AGE_SECS: u64 = 30 * 24 * 3600;

/// Create an encrypted backup blob from a collection of objects.
///
/// `token_serial` binds the backup to a specific token — pass the per-token
/// random identity, not the public serial number.
///
/// `pbkdf2_iterations`: iteration count for the passphrase KDF; defaults to
/// [`DEFAULT_PBKDF2_ITERATIONS`] (600,000). It is recorded in the header.
pub fn create_backup(
    objects: &[StoredObject],
    passphrase: &str,
    token_serial: &str,
    pbkdf2_iterations: Option<u32>,
) -> HsmResult<Vec<u8>> {
    // Check character count, not byte count.
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(HsmError::PinLenRange);
    }
    if !check_passphrase_complexity(passphrase) {
        return Err(HsmError::PinInvalid);
    }
    let iterations = pbkdf2_iterations.unwrap_or(DEFAULT_PBKDF2_ITERATIONS);
    if !(MIN_BACKUP_ITERATIONS..=MAX_BACKUP_ITERATIONS).contains(&iterations) {
        return Err(HsmError::ArgumentsBad);
    }

    let mut id_bytes = [0u8; 16];
    fill_random(&mut id_bytes)?;
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let payload = BackupPayloadRef {
        version: BACKUP_VERSION,
        created: iso8601_timestamp(now_epoch),
        created_epoch: now_epoch,
        backup_id: hex::encode(id_bytes),
        token_serial,
        object_count: objects.len(),
        objects,
    };
    // Serialize into a pre-sized zeroizing buffer (H3-20).
    let cap = objects
        .iter()
        .map(|o| o.approximate_size() as usize * 4 + 1024)
        .sum::<usize>()
        + 1024;
    let mut json = Zeroizing::new(Vec::with_capacity(cap));
    serde_json::to_writer(&mut *json, &payload).map_err(|_| HsmError::GeneralError)?;

    let (key, salt) = derive_key_from_pin(passphrase.as_bytes(), None, Some(iterations))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    fill_random(&mut nonce_bytes)?;

    let mut output = Vec::with_capacity(HEADER_LEN + json.len() + 16);
    output.extend_from_slice(BACKUP_MAGIC);
    output.extend_from_slice(&BACKUP_VERSION.to_le_bytes());
    output.push(KDF_PBKDF2_SHA256);
    output.extend_from_slice(&iterations.to_le_bytes());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: json.as_ref(),
                aad: &output[..HEADER_LEN],
            },
        )
        .map_err(|_| HsmError::GeneralError)?;
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Restore objects from an encrypted backup blob.
///
/// `expected_serial`: the backup's token binding must match or restore is rejected.
/// `max_age_secs`: if `Some`, the backup must be younger than this many seconds.
///   Defaults to 30 days if `None`.  Pass `Some(0)` to disable age checking.
/// `pbkdf2_iterations`: optional *minimum* iteration count; the actual count
///   is read from the authenticated header.
/// `consumed_ids`: set of previously restored backup IDs (replay protection).
///   On success the new ID is inserted into the set — callers must persist it
///   only **after** the restored objects were committed.
///
/// Every returned object has passed [`sanitize_restored_object`]. Callers
/// must allocate fresh handles when inserting them.
///
/// Returns `HsmError::DataInvalid` for format/replay/policy errors and
/// `HsmError::PinIncorrect` for a wrong passphrase.
pub fn restore_backup(
    data: &[u8],
    passphrase: &str,
    expected_serial: &str,
    max_age_secs: Option<u64>,
    pbkdf2_iterations: Option<u32>,
    consumed_ids: Option<&mut HashSet<String>>,
) -> HsmResult<Vec<StoredObject>> {
    if data.len() < HEADER_LEN {
        return Err(HsmError::DataInvalid);
    }
    if &data[0..4] != BACKUP_MAGIC {
        return Err(HsmError::DataInvalid);
    }
    let version = u32::from_le_bytes(data[4..8].try_into().map_err(|_| HsmError::DataInvalid)?);
    if version != BACKUP_VERSION || data[8] != KDF_PBKDF2_SHA256 {
        return Err(HsmError::DataInvalid);
    }
    let iterations = u32::from_le_bytes(data[9..13].try_into().map_err(|_| HsmError::DataInvalid)?);
    let floor = pbkdf2_iterations
        .unwrap_or(MIN_BACKUP_ITERATIONS)
        .max(MIN_BACKUP_ITERATIONS);
    if iterations < floor || iterations > MAX_BACKUP_ITERATIONS {
        return Err(HsmError::DataInvalid);
    }
    let salt = &data[13..13 + SALT_LEN];
    let nonce_bytes = &data[13 + SALT_LEN..HEADER_LEN];

    let (key, _) = derive_key_from_pin(passphrase.as_bytes(), Some(salt), Some(iterations))?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: &data[HEADER_LEN..],
                    aad: &data[..HEADER_LEN],
                },
            )
            .map_err(|_| HsmError::PinIncorrect)?,
    );

    let payload: BackupPayload =
        serde_json::from_slice(&plaintext).map_err(|_| HsmError::DataInvalid)?;
    drop(plaintext);
    // From here on every exit path zeroizes the restored objects.
    let objects = ZeroizingObjects::new(payload.objects);

    if payload.version != BACKUP_VERSION || payload.object_count != objects.len() {
        tracing::warn!("Backup restore rejected: payload/header mismatch");
        return Err(HsmError::DataInvalid);
    }
    if payload.token_serial != expected_serial {
        tracing::warn!("Backup restore rejected: token binding mismatch");
        return Err(HsmError::DataInvalid);
    }
    match &consumed_ids {
        Some(ids) if ids.contains(&payload.backup_id) => {
            tracing::warn!(
                "Backup restore rejected: backup_id {} has already been consumed (replay attack?)",
                payload.backup_id
            );
            return Err(HsmError::DataInvalid);
        }
        Some(_) => {}
        None => tracing::warn!(
            "Backup replay protection disabled (consumed_ids=None). \
             This is unsafe for production — duplicate key imports are possible."
        ),
    }

    let max_age = match max_age_secs {
        Some(0) => None,
        Some(age) => Some(age),
        None => Some(DEFAULT_MAX_BACKUP_AGE_SECS),
    };
    if let Some(max) = max_age {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if payload.created_epoch > now + 300 {
            tracing::warn!("Backup restore rejected: timestamp is in the future");
            return Err(HsmError::DataInvalid);
        }
        if now.saturating_sub(payload.created_epoch) > max {
            tracing::warn!("Backup restore rejected: backup is too old");
            return Err(HsmError::DataInvalid);
        }
    }

    // Re-validate every object with the creation policy (H3-16).
    let mut objects = objects.into_inner();
    for obj in objects.iter_mut() {
        if let Err(e) = sanitize_restored_object(obj, false) {
            tracing::warn!(
                "Backup restore rejected: object failed policy check: {:?}",
                e
            );
            drop(ZeroizingObjects::new(objects));
            return Err(HsmError::DataInvalid);
        }
    }

    tracing::info!(
        "Backup restored: id={}, objects={}",
        payload.backup_id,
        objects.len()
    );
    if let Some(ids) = consumed_ids {
        ids.insert(payload.backup_id);
    }
    Ok(objects)
}

/// Persistent replay guard — tracks consumed backup IDs across restarts.
///
/// The file (one hex ID per line) is created with mode 0600 and
/// `O_NOFOLLOW`. [`check_and_record`](Self::check_and_record) re-reads the
/// file under an exclusive lock, so two concurrent restores cannot both pass
/// the check (H3-16). Deleting the file resets the guard — keep it on
/// storage the operator cannot trivially rewrite, and record IDs only after
/// the restored objects were committed.
pub struct PersistentReplayGuard {
    ids: HashSet<String>,
    path: Option<std::path::PathBuf>,
}

impl PersistentReplayGuard {
    /// Create a replay guard backed by a file at `path`.
    pub fn new(path: std::path::PathBuf) -> Self {
        let ids = Self::read_ids(&path);
        Self {
            ids,
            path: Some(path),
        }
    }

    fn read_ids(path: &std::path::Path) -> HashSet<String> {
        let mut ids = HashSet::new();
        match crate::store::fs_util::read_private(path) {
            Ok(Some(content)) => {
                for line in String::from_utf8_lossy(&content).lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        ids.insert(trimmed.to_string());
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    "Could not read replay guard file {}: {:?}",
                    path.display(),
                    e
                );
            }
        }
        ids
    }

    /// Create an in-memory-only replay guard (no persistence).
    pub fn in_memory() -> Self {
        Self {
            ids: HashSet::new(),
            path: None,
        }
    }

    /// Check if a backup ID has already been consumed.
    pub fn is_consumed(&self, id: &str) -> bool {
        self.ids.contains(id)
    }

    /// Atomically check that `id` is unused and record it (exclusive file
    /// lock held across re-read, check and append).
    pub fn check_and_record(&mut self, id: &str) -> HsmResult<()> {
        if let Some(path) = self.path.clone() {
            use fs2::FileExt;
            use std::io::Write;
            let mut file = crate::store::fs_util::open_private(&path, true)?;
            file.lock_exclusive().map_err(|e| {
                tracing::error!("Failed to lock replay guard file {}: {}", path.display(), e);
                HsmError::DeviceError
            })?;
            self.ids.extend(Self::read_ids(&path));
            if self.ids.contains(id) {
                return Err(HsmError::DataInvalid);
            }
            writeln!(file, "{}", id).map_err(|_| HsmError::DeviceError)?;
            file.sync_all().map_err(|_| HsmError::DeviceError)?;
        } else if self.ids.contains(id) {
            return Err(HsmError::DataInvalid);
        }
        self.ids.insert(id.to_string());
        Ok(())
    }

    /// Record a backup ID as consumed. Persists to file immediately.
    pub fn record(&mut self, id: String) -> HsmResult<()> {
        match self.check_and_record(&id) {
            Ok(()) | Err(HsmError::DataInvalid) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Get the inner set.
    pub fn consumed_ids(&self) -> &HashSet<String> {
        &self.ids
    }

    /// Clone the consumed IDs set for passing to `restore_backup`.
    pub fn consumed_ids_clone(&self) -> HashSet<String> {
        self.ids.clone()
    }
}

/// Check that a passphrase has sufficient entropy to resist brute-force.
///
/// **Policy A — character diversity**: at least 3 of 4 character classes
/// AND at least 6 unique characters.
/// **Policy B — length-based entropy**: at least 24 characters AND at least
/// 12 unique characters.
///
/// Single pass over the characters with a bitset for ASCII (P14).
fn check_passphrase_complexity(passphrase: &str) -> bool {
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut ascii_seen = [false; 128];
    let mut other_seen: Vec<char> = Vec::new();
    let mut unique_count = 0usize;
    let mut char_count = 0usize;

    for ch in passphrase.chars() {
        char_count += 1;
        if (ch as u32) < 128 {
            let i = ch as usize;
            if !ascii_seen[i] {
                ascii_seen[i] = true;
                unique_count += 1;
            }
        } else if !other_seen.contains(&ch) {
            other_seen.push(ch);
            unique_count += 1;
        }
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else {
            has_symbol = true;
        }
    }

    let class_count = has_lower as u8 + has_upper as u8 + has_digit as u8 + has_symbol as u8;
    let policy_a = class_count >= 3 && unique_count >= 6;
    let policy_b = char_count >= 24 && unique_count >= 12;
    policy_a || policy_b
}

/// ISO-8601 / RFC 3339 UTC timestamp (S15) without pulling in chrono.
fn iso8601_timestamp(secs: u64) -> String {
    let days = secs / 86400;
    let tod = secs % 86400;
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::object::StoredObject;

    fn make_test_object(
        handle: crate::pkcs11_abi::types::CK_OBJECT_HANDLE,
        label: &str,
    ) -> StoredObject {
        let mut obj = StoredObject::new(handle, 3); // CKO_SECRET_KEY
        obj.label = label.as_bytes().to_vec();
        obj.token_object = true;
        obj
    }

    const TEST_SERIAL: &str = "0000000000000001";

    #[test]
    fn round_trip_backup_restore() {
        let objects = vec![
            make_test_object(1, "key1"),
            make_test_object(2, "key2"),
            make_test_object(3, "key3"),
        ];

        let backup = create_backup(&objects, "Test-P@ssphr4se-Long", TEST_SERIAL, None).unwrap();
        let restored = restore_backup(
            &backup,
            "Test-P@ssphr4se-Long",
            TEST_SERIAL,
            Some(0),
            None,
            None,
        )
        .unwrap();

        assert_eq!(restored.len(), 3);
        assert_eq!(restored[0].label, b"key1");
        assert_eq!(restored[1].label, b"key2");
        assert_eq!(restored[2].label, b"key3");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let objects = vec![make_test_object(1, "key1")];
        let backup = create_backup(&objects, "C0rrect-P@ssphrase", TEST_SERIAL, None).unwrap();

        let result = restore_backup(
            &backup,
            "Wr0ng-P@ssphrase",
            TEST_SERIAL,
            Some(0),
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn empty_backup_is_valid() {
        let backup = create_backup(&[], "L0ng-P@ssphrase!", TEST_SERIAL, None).unwrap();
        let restored = restore_backup(
            &backup,
            "L0ng-P@ssphrase!",
            TEST_SERIAL,
            Some(0),
            None,
            None,
        )
        .unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn truncated_blob_fails() {
        let result = restore_backup(&[0u8; 10], "pass", TEST_SERIAL, Some(0), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_magic_fails() {
        let mut backup = create_backup(&[], "L0ng-P@ssphrase!", TEST_SERIAL, None).unwrap();
        backup[0] = b'X'; // corrupt magic
        let result = restore_backup(&backup, "pass", TEST_SERIAL, Some(0), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_serial_rejected() {
        let backup = create_backup(&[], "L0ng-P@ssphrase!", "serial-A0000000", None).unwrap();
        let result = restore_backup(
            &backup,
            "L0ng-P@ssphrase!",
            "serial-B0000000",
            Some(0),
            None,
            None,
        );
        assert!(result.is_err(), "Cross-token restore should be rejected");
    }

    #[test]
    fn iso_timestamp_format() {
        assert_eq!(iso8601_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_timestamp(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn header_is_authenticated() {
        let backup = create_backup(&[], "L0ng-P@ssphrase!", TEST_SERIAL, None).unwrap();
        let mut tampered = backup.clone();
        tampered[13] ^= 1; // salt byte
        assert!(restore_backup(
            &tampered,
            "L0ng-P@ssphrase!",
            TEST_SERIAL,
            Some(0),
            None,
            None
        )
        .is_err());
        let mut tampered = backup;
        tampered[9..13].copy_from_slice(&200_000u32.to_le_bytes()); // iterations
        assert!(restore_backup(
            &tampered,
            "L0ng-P@ssphrase!",
            TEST_SERIAL,
            Some(0),
            None,
            None
        )
        .is_err());
    }

    #[test]
    fn restore_rejects_non_sensitive_secret_and_strips_trusted() {
        let mut obj = make_test_object(1, "k");
        obj.sensitive = false;
        let backup = create_backup(&[obj], "L0ng-P@ssphrase!", TEST_SERIAL, None).unwrap();
        assert!(restore_backup(
            &backup,
            "L0ng-P@ssphrase!",
            TEST_SERIAL,
            Some(0),
            None,
            None
        )
        .is_err());

        let mut obj = make_test_object(2, "t");
        obj.trusted = true;
        let backup = create_backup(&[obj], "L0ng-P@ssphrase!", TEST_SERIAL, None).unwrap();
        let r = restore_backup(
            &backup,
            "L0ng-P@ssphrase!",
            TEST_SERIAL,
            Some(0),
            None,
            None,
        )
        .unwrap();
        assert!(!r[0].trusted);
    }

    #[test]
    fn replay_protection() {
        let backup = create_backup(&[], "L0ng-P@ssphrase!", TEST_SERIAL, None).unwrap();
        let mut consumed = HashSet::new();

        // First restore succeeds
        let result = restore_backup(
            &backup,
            "L0ng-P@ssphrase!",
            TEST_SERIAL,
            Some(0),
            None,
            Some(&mut consumed),
        );
        assert!(result.is_ok(), "First restore should succeed");
        assert_eq!(consumed.len(), 1);

        // Second restore of the same backup is rejected (replay)
        let result = restore_backup(
            &backup,
            "L0ng-P@ssphrase!",
            TEST_SERIAL,
            Some(0),
            None,
            Some(&mut consumed),
        );
        assert!(result.is_err(), "Replay of same backup should be rejected");
    }
}
