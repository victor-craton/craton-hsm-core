// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Tamper-evident audit log.
//!
//! # Integrity (H3-10, H3-11)
//!
//! Events form a **keyed** chain:
//! `H_n = HMAC-SHA256(K, H_{n-1} || serialize(payload_n))`, where the payload
//! includes a monotonic sequence number `seq`. `K` is a random 256-bit key
//! stored in a separate 0600 key file (`audit.key_path`, default
//! `<log_path>.key`) that is never written to the log, so a party that can
//! edit the log but not read the key cannot recompute the chain. After every
//! durable write a MAC-protected **anchor** (`<log_path>.anchor`: last `seq`
//! and chain value) is updated atomically, so truncating the tail or deleting
//! the log is detected on the next start. Rotation starts every new
//! generation with a `LogRotated` event chained to the previous generation,
//! so restarts after rotation verify cleanly.
//!
//! Operators should additionally forward events off-host (syslog/SIEM) —
//! whoever controls both the key file and the log can still rewrite history.
//!
//! # Durability and fail-closed behaviour
//!
//! Events are processed by a worker thread over a **bounded** queue
//! (back-pressure instead of unbounded memory, H3-22) with a persistent file
//! handle and group-commit `fsync`. [`AuditLog::record_sync`] waits until the
//! event is durable and returns an error if it could not be written; the
//! core uses it for authentication and key-management events. A failed disk
//! write sets a sticky failure flag; with `audit.fail_closed = true` every
//! later `record` call fails (`CKR_DEVICE_ERROR`).
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::BufRead;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::error::{HsmError, HsmResult};

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonic sequence number (0 for the first event ever written).
    #[serde(default)]
    pub seq: u64,
    pub timestamp: u64,
    pub session_handle: u64,
    pub operation: AuditOperation,
    pub key_id: Option<String>,
    pub result: AuditResult,
    pub previous_hash: [u8; 32],
}

/// The hashable payload of an audit event — excludes `previous_hash` so that
/// the chain hash `H_n = SHA-256(H_{n-1} || serialize(payload))` is
/// non-circular and cryptographically sound.
#[derive(Serialize)]
struct AuditEventPayload<'a> {
    seq: u64,
    timestamp: u64,
    session_handle: u64,
    operation: &'a AuditOperation,
    key_id: &'a Option<String>,
    result: &'a AuditResult,
}

impl AuditEvent {
    fn payload(&self) -> AuditEventPayload<'_> {
        AuditEventPayload {
            seq: self.seq,
            timestamp: self.timestamp,
            session_handle: self.session_handle,
            operation: &self.operation,
            key_id: &self.key_id,
            result: &self.result,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOperation {
    Initialize,
    Finalize,
    OpenSession {
        slot_id: u64,
    },
    CloseSession,
    Login {
        user_type: u64,
    },
    Logout,
    InitToken {
        slot_id: u64,
    },
    /// `fips_approved`: FIPS 140-3 IG 2.4.C algorithm indicator.
    /// `true` = approved algorithm, `false` = non-approved.
    GenerateKey {
        mechanism: u64,
        key_length: u32,
        fips_approved: bool,
    },
    GenerateKeyPair {
        mechanism: u64,
        key_length: u32,
        fips_approved: bool,
    },
    Sign {
        mechanism: u64,
        fips_approved: bool,
    },
    Verify {
        mechanism: u64,
        fips_approved: bool,
    },
    Encrypt {
        mechanism: u64,
        fips_approved: bool,
    },
    Decrypt {
        mechanism: u64,
        fips_approved: bool,
    },
    Digest {
        mechanism: u64,
        fips_approved: bool,
    },
    CreateObject,
    DestroyObject,
    GenerateRandom {
        length: u32,
    },
    WrapKey {
        mechanism: u64,
        fips_approved: bool,
    },
    UnwrapKey {
        mechanism: u64,
        fips_approved: bool,
    },
    DeriveKey {
        mechanism: u64,
        fips_approved: bool,
    },
    /// (#7-fix) Audit read operations for FIPS 140-3 compliance.
    FindObjects {
        result_count: u32,
    },
    GetAttributeValue,
    /// A request for secret key material through `C_GetAttributeValue`
    /// (granted or denied).
    GetAttributeValueSensitive {
        attribute: u64,
    },
    /// `C_InitPIN` (SO sets the user PIN).
    InitPin {
        slot_id: u64,
    },
    /// `C_SetPIN`.
    SetPin {
        slot_id: u64,
    },
    CopyObject,
    SetAttributeValue,
    /// First event of a new log generation after rotation; chains to the
    /// last event of the previous generation.
    LogRotated {
        previous_generation_last_seq: u64,
    },
    /// Encrypted backup of a slot's token objects was exported (H5-20).
    BackupExport {
        slot_id: u64,
        object_count: u64,
    },
    /// Objects were restored from an encrypted backup (H5-20).
    BackupRestore {
        slot_id: u64,
        object_count: u64,
    },
    /// Audit trail contents were read or exported by an administrator
    /// (H5-20).
    AuditExport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResult {
    Success,
    Failure(u64),
}

/// Which events are written (`audit.log_level`, S2).
///
/// Authentication, token-management and key-management events are always
/// recorded. `All`/`Crypto` additionally record routine cryptographic
/// operations (sign, verify, encrypt, decrypt, digest, random, find, read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLevel {
    /// Every event.
    All,
    /// Mandatory events only.
    Mandatory,
}

impl AuditLevel {
    /// Parse a config value (`all`, `crypto`, `auth`, `admin`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "all" | "crypto" => Some(AuditLevel::All),
            "auth" | "admin" => Some(AuditLevel::Mandatory),
            _ => None,
        }
    }

    fn records(self, op: &AuditOperation) -> bool {
        if self == AuditLevel::All {
            return true;
        }
        !matches!(
            op,
            AuditOperation::Sign { .. }
                | AuditOperation::Verify { .. }
                | AuditOperation::Encrypt { .. }
                | AuditOperation::Decrypt { .. }
                | AuditOperation::Digest { .. }
                | AuditOperation::GenerateRandom { .. }
                | AuditOperation::FindObjects { .. }
                | AuditOperation::GetAttributeValue
        )
    }
}

/// Commands sent to the background audit worker thread.
enum AuditCommand {
    Record {
        session_handle: u64,
        operation: AuditOperation,
        result: AuditResult,
        key_id: Option<String>,
        done: Option<std::sync::mpsc::SyncSender<HsmResult<()>>>,
    },
    Flush {
        done: std::sync::mpsc::SyncSender<()>,
    },
}

/// Maximum number of audit events retained in memory (ring buffer, P3).
const MAX_IN_MEMORY_ENTRIES: usize = 100_000;

/// Maximum audit log file size in bytes before rotation (100 MB).
const MAX_LOG_FILE_BYTES: u64 = 100 * 1024 * 1024;

/// Maximum number of rotated log file generations to keep.
const MAX_ROTATED_FILES: u32 = 5;

/// Capacity of the bounded queue between callers and the worker.
const AUDIT_QUEUE_CAPACITY: usize = 10_000;

/// Maximum events written between two `fsync`s (group commit, P2).
const GROUP_COMMIT_MAX: usize = 256;

const ANCHOR_LABEL: &[u8] = b"craton-hsm/audit-anchor/v1";

/// Maximum length of one NDJSON line accepted by offline verification.
const MAX_AUDIT_LINE_BYTES: usize = 64 * 1024;

/// Successful offline verification ([`AuditLog::verify_files`]).
#[derive(Debug, Clone)]
pub struct AuditFileSummary {
    /// Number of verified events.
    pub entries: u64,
    /// Files verified, oldest generation first.
    pub files: Vec<PathBuf>,
    /// `false` when the oldest available generation starts with a rotation
    /// header (older generations were rotated away), so the start of the
    /// chain cannot be anchored at the genesis value.
    pub anchored_at_genesis: bool,
    /// Whether a MAC-protected tail anchor was present and matched.
    pub anchor_present: bool,
    /// Sequence number of the last event, if any.
    pub last_seq: Option<u64>,
}

/// Why offline verification failed ([`AuditLog::verify_files`]).
#[derive(Debug, Clone)]
pub enum AuditVerifyError {
    /// Neither the log nor any rotated generation exists.
    Missing(PathBuf),
    /// The chain key could not be read.
    KeyUnavailable(PathBuf, String),
    /// Chain broken, file corrupted, truncated or reordered.
    Tampered {
        /// File in which the problem was found.
        file: PathBuf,
        /// 1-based line number (0 = file-level problem).
        line: usize,
        /// Description (never contains event contents).
        reason: String,
    },
    /// I/O error while reading.
    Io(PathBuf, String),
    /// The visitor callback failed (e.g. writing to stdout).
    Visitor(String),
}

impl std::fmt::Display for AuditVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditVerifyError::Missing(p) => write!(f, "audit log '{}' does not exist", p.display()),
            AuditVerifyError::KeyUnavailable(p, r) => {
                write!(f, "audit key '{}' unavailable: {r}", p.display())
            }
            AuditVerifyError::Tampered { file, line, reason } => write!(
                f,
                "audit chain BROKEN in '{}' at line {line}: {reason}",
                file.display()
            ),
            AuditVerifyError::Io(p, e) => write!(f, "cannot read '{}': {e}", p.display()),
            AuditVerifyError::Visitor(e) => write!(f, "output error: {e}"),
        }
    }
}

/// Result of attempting to recover the hash chain from an existing log file.
enum ChainRecoveryResult {
    /// No existing log (and no anchor) — start a fresh chain.
    NoFile,
    /// Chain recovered and verified; (last chain value, next seq, last ts).
    Verified([u8; 32], u64, u64),
    /// Chain is broken: the file is corrupt, tampered, truncated or unreadable.
    Broken(String),
}

/// Internal state protected by a single RwLock.
struct AuditLogState {
    entries: VecDeque<AuditEvent>,
    /// Chain value preceding `entries[0]` (H3-26).
    base_hash: [u8; 32],
    last_hash: [u8; 32],
    /// Monotonic timestamp floor.
    last_timestamp: u64,
}

struct Shared {
    state: RwLock<AuditLogState>,
    key: Zeroizing<[u8; 32]>,
    tamper_flag: AtomicBool,
    /// Sticky flag: an event could not be written durably.
    io_failed: AtomicBool,
    fail_closed: bool,
    level: AuditLevel,
}

/// Worker thread + queue + (for file-backed logs) the exclusive
/// cross-process lock. Shared by every `AuditLog` handle opened on the same
/// path in this process, so all of them append to one chain.
struct Backend {
    shared: Arc<Shared>,
    sender: parking_lot::Mutex<Option<std::sync::mpsc::SyncSender<AuditCommand>>>,
    worker: parking_lot::Mutex<Option<std::thread::JoinHandle<()>>>,
    _lock: Option<std::fs::File>,
}

impl Backend {
    fn sender(&self) -> Option<std::sync::mpsc::SyncSender<AuditCommand>> {
        self.sender.lock().clone()
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        // Drop sender to signal the worker to exit, then wait for it to
        // drain remaining events.
        self.sender.lock().take();
        if let Some(handle) = self.worker.lock().take() {
            let _ = handle.join();
        }
    }
}

/// Process-wide registry: one backend per canonical log path. A single
/// writer per chain is required; two independent writers appending to the
/// same file would corrupt the chain.
static REGISTRY: parking_lot::Mutex<
    Option<std::collections::HashMap<PathBuf, std::sync::Weak<Backend>>>,
> = parking_lot::Mutex::new(None);

/// Tamper-evident audit log (see module documentation).
pub struct AuditLog {
    backend: Arc<Backend>,
    shared: Arc<Shared>,
    /// Optional path for persistent NDJSON audit trail on disk.
    log_path: Option<PathBuf>,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the keyed chain value `HMAC(K, previous_hash || payload)`.
fn compute_chain_hash(key: &[u8; 32], previous_hash: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(previous_hash);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn payload_bytes(event: &AuditEvent) -> HsmResult<Vec<u8>> {
    serde_json::to_vec(&event.payload()).map_err(|e| {
        tracing::error!("Audit event payload serialization failed: {}", e);
        HsmError::GeneralError
    })
}

fn event_hash(key: &[u8; 32], event: &AuditEvent) -> HsmResult<[u8; 32]> {
    Ok(compute_chain_hash(
        key,
        &event.previous_hash,
        &payload_bytes(event)?,
    ))
}

#[derive(Serialize, Deserialize)]
struct Anchor {
    seq: u64,
    hash: String,
    mac: String,
}

impl Anchor {
    fn mac(key: &[u8; 32], seq: u64, hash: &[u8; 32]) -> [u8; 32] {
        use hmac::Mac;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("any key length");
        mac.update(ANCHOR_LABEL);
        mac.update(&seq.to_le_bytes());
        mac.update(hash);
        mac.finalize().into_bytes().into()
    }
}

fn anchor_path(log: &Path) -> PathBuf {
    let mut n = log.as_os_str().to_os_string();
    n.push(".anchor");
    PathBuf::from(n)
}

/// Default key-file path for a log path.
pub fn default_key_path(log: &Path) -> PathBuf {
    let mut n = log.as_os_str().to_os_string();
    n.push(".key");
    PathBuf::from(n)
}

fn write_anchor(log: &Path, key: &[u8; 32], seq: u64, hash: &[u8; 32]) -> HsmResult<()> {
    let a = Anchor {
        seq,
        hash: hex::encode(hash),
        mac: hex::encode(Anchor::mac(key, seq, hash)),
    };
    let bytes = serde_json::to_vec(&a).map_err(|_| HsmError::GeneralError)?;
    crate::store::fs_util::atomic_write_private(&anchor_path(log), &bytes)
}

fn read_anchor(log: &Path, key: &[u8; 32]) -> Result<Option<(u64, [u8; 32])>, String> {
    match crate::store::fs_util::read_private(&anchor_path(log)) {
        Ok(None) => Ok(None),
        Ok(Some(b)) => {
            let a: Anchor =
                serde_json::from_slice(&b).map_err(|e| format!("anchor corrupt: {e}"))?;
            let h: [u8; 32] = hex::decode(&a.hash)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or("anchor hash malformed")?;
            let m = hex::decode(&a.mac).map_err(|_| "anchor mac malformed")?;
            use subtle::ConstantTimeEq;
            if !bool::from(m.ct_eq(&Anchor::mac(key, a.seq, &h))) {
                return Err("anchor MAC invalid".to_string());
            }
            Ok(Some((a.seq, h)))
        }
        Err(e) => Err(format!("anchor unreadable: {e:?}")),
    }
}

/// Load the audit HMAC key, creating it (0600, `O_EXCL`) only for a brand
/// new log. A missing key for an existing log is reported as `Ok(None)`.
fn load_or_create_key(key_path: &Path, log_exists: bool) -> HsmResult<Option<Zeroizing<[u8; 32]>>> {
    if let Some(bytes) = crate::store::fs_util::read_private(key_path)? {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() != 32 {
            tracing::error!("audit key file {} is malformed", key_path.display());
            return Err(HsmError::DeviceError);
        }
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&bytes);
        return Ok(Some(k));
    }
    if log_exists {
        return Ok(None);
    }
    let mut k = Zeroizing::new([0u8; 32]);
    crate::store::encrypted_store::fill_random(k.as_mut())?;
    let mut f = crate::store::fs_util::create_new_private(key_path)?;
    f.write_all(k.as_ref()).map_err(|_| HsmError::DeviceError)?;
    f.sync_all().map_err(|_| HsmError::DeviceError)?;
    if let Some(dir) = key_path.parent() {
        crate::store::fs_util::fsync_dir(dir)?;
    }
    Ok(Some(k))
}

/// Validate the audit log path: the file (if present) must be a regular,
/// private file; the parent directory is canonicalized.
fn validate_log_path(path: &Path) -> Result<PathBuf, HsmError> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            tracing::error!("Audit log path is a symlink, refusing: {}", path.display());
            return Err(HsmError::AuditChainBroken(
                "audit log path is a symlink".to_string(),
            ));
        }
        if !meta.file_type().is_file() {
            tracing::error!("Audit log path is not a regular file: {}", path.display());
            return Err(HsmError::AuditChainBroken(
                "audit log path is not a regular file".to_string(),
            ));
        }
    }
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            let canonical_parent = parent.canonicalize().map_err(|e| {
                tracing::error!(
                    "Audit log path validation: cannot canonicalize parent {}: {}",
                    parent.display(),
                    e,
                );
                HsmError::GeneralError
            })?;
            let file_name = path.file_name().ok_or(HsmError::GeneralError)?;
            Ok(canonical_parent.join(file_name))
        }
        _ => Ok(path.to_path_buf()),
    }
}

/// Open (or create, 0600, `O_NOFOLLOW`) the audit log file for appending.
fn open_audit_file(path: &Path) -> Result<std::fs::File, HsmError> {
    crate::store::fs_util::open_private(path, true)
}

struct Writer {
    path: PathBuf,
    file: std::io::BufWriter<std::fs::File>,
    size: u64,
    /// Rotation threshold (bytes).
    max_bytes: u64,
}

struct WorkerCtx {
    shared: Arc<Shared>,
    writer: Option<Writer>,
    last_hash: [u8; 32],
    next_seq: u64,
    last_timestamp: u64,
}

impl WorkerCtx {
    fn build_event(
        &mut self,
        session_handle: u64,
        operation: AuditOperation,
        result: AuditResult,
        key_id: Option<String>,
    ) -> HsmResult<(AuditEvent, [u8; 32], Vec<u8>)> {
        let wall = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        )
        .unwrap_or(u64::MAX);
        let timestamp = if wall <= self.last_timestamp {
            self.last_timestamp.checked_add(1).ok_or_else(|| {
                tracing::error!("Audit timestamp space exhausted");
                HsmError::GeneralError
            })?
        } else {
            wall
        };
        let event = AuditEvent {
            seq: self.next_seq,
            timestamp,
            session_handle,
            operation,
            key_id,
            result,
            previous_hash: self.last_hash,
        };
        // Serialize the payload once for hashing and the full line once for
        // the file (P4).
        let hash = compute_chain_hash(&self.shared.key, &self.last_hash, &payload_bytes(&event)?);
        let line = serde_json::to_vec(&event).map_err(|_| HsmError::GeneralError)?;
        Ok((event, hash, line))
    }

    fn commit(&mut self, event: AuditEvent, hash: [u8; 32]) {
        self.last_hash = hash;
        self.next_seq += 1;
        self.last_timestamp = event.timestamp;
        let mut s = self.shared.state.write();
        s.last_hash = hash;
        s.last_timestamp = event.timestamp;
        s.entries.push_back(event);
        while s.entries.len() > MAX_IN_MEMORY_ENTRIES {
            if let Some(old) = s.entries.pop_front() {
                if let Ok(h) = event_hash(&self.shared.key, &old) {
                    s.base_hash = h;
                }
            }
        }
    }

    fn rotate(&mut self) -> HsmResult<()> {
        let w = match self.writer.take() {
            Some(w) => w,
            None => return Ok(()),
        };
        let path = w.path.clone();
        let max_bytes = w.max_bytes;
        let mut file = w.file.into_inner().map_err(|_| HsmError::DeviceError)?;
        file.flush().map_err(|_| HsmError::DeviceError)?;
        file.sync_all().map_err(|_| HsmError::DeviceError)?;
        drop(file);
        AuditLog::rotate_log_files(&path)?;
        let f = crate::store::fs_util::create_new_private(&path)?;
        self.writer = Some(Writer {
            path,
            file: std::io::BufWriter::new(f),
            size: 0,
            max_bytes,
        });
        // First event of the new generation chains to the old one.
        let prev_seq = self.next_seq.saturating_sub(1);
        let (ev, h, line) = self.build_event(
            0,
            AuditOperation::LogRotated {
                previous_generation_last_seq: prev_seq,
            },
            AuditResult::Success,
            None,
        )?;
        self.write_line(&line)?;
        self.commit(ev, h);
        Ok(())
    }

    fn write_line(&mut self, line: &[u8]) -> HsmResult<()> {
        if let Some(w) = self.writer.as_mut() {
            w.file
                .write_all(line)
                .and_then(|_| w.file.write_all(b"\n"))
                .map_err(|e| {
                    tracing::error!("Audit log write failed: {}", e);
                    HsmError::DeviceError
                })?;
            w.size += line.len() as u64 + 1;
        }
        Ok(())
    }

    fn sync(&mut self) -> HsmResult<()> {
        if let Some(w) = self.writer.as_mut() {
            w.file
                .flush()
                .and_then(|_| w.file.get_ref().sync_data())
                .map_err(|e| {
                    tracing::error!("Audit log fsync failed: {}", e);
                    HsmError::DeviceError
                })?;
            let path = w.path.clone();
            if self.next_seq > 0 {
                write_anchor(&path, &self.shared.key, self.next_seq - 1, &self.last_hash)?;
            }
        }
        Ok(())
    }

    fn process(
        &mut self,
        session_handle: u64,
        operation: AuditOperation,
        result: AuditResult,
        key_id: Option<String>,
    ) -> HsmResult<()> {
        if self.shared.tamper_flag.load(Ordering::Acquire) {
            return Err(HsmError::AuditChainBroken(
                "refusing to record: audit chain tamper previously detected".to_string(),
            ));
        }
        if self.writer.as_ref().is_some_and(|w| w.size >= w.max_bytes) {
            self.rotate()?;
        }
        let (event, hash, line) = self.build_event(session_handle, operation, result, key_id)?;
        // The in-memory chain only advances if the line reached the file.
        self.write_line(&line)?;
        self.commit(event, hash);
        Ok(())
    }
}

impl AuditLog {
    fn spawn_worker(
        mut ctx: WorkerCtx,
        receiver: std::sync::mpsc::Receiver<AuditCommand>,
    ) -> HsmResult<std::thread::JoinHandle<()>> {
        std::thread::Builder::new()
            .name("audit-worker".to_string())
            .spawn(move || {
                let mut pending_sync: Vec<std::sync::mpsc::SyncSender<HsmResult<()>>> = Vec::new();
                let mut pending_flush: Vec<std::sync::mpsc::SyncSender<()>> = Vec::new();
                let mut batch_err: Option<HsmError> = None;
                loop {
                    let first = match receiver.recv() {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let mut cmd = Some(first);
                    let mut n = 0;
                    while let Some(c) = cmd.take() {
                        match c {
                            AuditCommand::Record {
                                session_handle,
                                operation,
                                result,
                                key_id,
                                done,
                            } => {
                                let r = ctx.process(session_handle, operation, result, key_id);
                                if let Err(e) = &r {
                                    batch_err.get_or_insert(e.clone());
                                }
                                if let Some(d) = done {
                                    pending_sync.push(d);
                                }
                            }
                            AuditCommand::Flush { done } => pending_flush.push(done),
                        }
                        n += 1;
                        if n < GROUP_COMMIT_MAX {
                            cmd = receiver.try_recv().ok();
                        }
                    }
                    // Group commit: one fsync + anchor update per batch.
                    if let Err(e) = ctx.sync() {
                        batch_err.get_or_insert(e);
                    }
                    let res = match batch_err.take() {
                        Some(e) => {
                            if !matches!(e, HsmError::AuditChainBroken(_)) {
                                ctx.shared.io_failed.store(true, Ordering::Release);
                            }
                            Err(e)
                        }
                        None => Ok(()),
                    };
                    for d in pending_sync.drain(..) {
                        let _ = d.send(res.clone());
                    }
                    for d in pending_flush.drain(..) {
                        let _ = d.send(());
                    }
                }
                let _ = ctx.sync();
            })
            .map_err(|e| {
                tracing::error!("failed to spawn audit worker thread: {}", e);
                HsmError::GeneralError
            })
    }

    fn start(
        key: Zeroizing<[u8; 32]>,
        writer: Option<Writer>,
        recovered: ([u8; 32], u64, u64),
        tampered: bool,
        fail_closed: bool,
        level: AuditLevel,
        log_path: Option<PathBuf>,
        lock: Option<std::fs::File>,
    ) -> HsmResult<Self> {
        let (hash, next_seq, last_ts) = recovered;
        let shared = Arc::new(Shared {
            state: RwLock::new(AuditLogState {
                entries: VecDeque::new(),
                base_hash: hash,
                last_hash: hash,
                last_timestamp: last_ts,
            }),
            key,
            tamper_flag: AtomicBool::new(tampered),
            io_failed: AtomicBool::new(false),
            fail_closed,
            level,
        });
        let (sender, receiver) = std::sync::mpsc::sync_channel(AUDIT_QUEUE_CAPACITY);
        let worker = Self::spawn_worker(
            WorkerCtx {
                shared: Arc::clone(&shared),
                writer,
                last_hash: hash,
                next_seq,
                last_timestamp: last_ts,
            },
            receiver,
        )?;
        let backend = Arc::new(Backend {
            shared: Arc::clone(&shared),
            sender: parking_lot::Mutex::new(Some(sender)),
            worker: parking_lot::Mutex::new(Some(worker)),
            _lock: lock,
        });
        Ok(Self {
            backend,
            shared,
            log_path,
        })
    }

    /// In-memory audit log (no disk persistence) with a random per-instance
    /// chain key.
    pub fn new() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        {
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(key.as_mut());
        }
        Self::start(
            key,
            None,
            ([0u8; 32], 0, 0),
            false,
            false,
            AuditLevel::All,
            None,
            None,
        )
        .expect("failed to spawn audit worker thread")
    }

    /// Create an audit log with disk persistence at `path` (key file
    /// `<path>.key`, anchor `<path>.anchor`, fail-open, all events).
    ///
    /// If the existing log (or its anchor) fails verification the tamper
    /// flag is set permanently and `record()` refuses new events.
    pub fn new_with_path(path: PathBuf) -> Result<Self, HsmError> {
        let key_path = default_key_path(&path);
        Self::open_file(path, key_path, false, AuditLevel::All)
    }

    /// Build the audit log described by the configuration.
    pub fn from_config(cfg: &crate::config::config::AuditConfig) -> Result<Self, HsmError> {
        let level = AuditLevel::parse(&cfg.log_level)
            .ok_or_else(|| HsmError::ConfigError("invalid audit.log_level".to_string()))?;
        if !cfg.enabled {
            tracing::warn!("audit logging to disk is DISABLED (audit.enabled = false)");
            let mut key = Zeroizing::new([0u8; 32]);
            crate::store::encrypted_store::fill_random(key.as_mut())?;
            return Self::start(
                key,
                None,
                ([0u8; 32], 0, 0),
                false,
                false,
                level,
                None,
                None,
            );
        }
        let key_path = cfg
            .key_path
            .clone()
            .unwrap_or_else(|| default_key_path(&cfg.log_path));
        Self::open_file(cfg.log_path.clone(), key_path, cfg.fail_closed, level)
    }

    fn open_file(
        path: PathBuf,
        key_path: PathBuf,
        fail_closed: bool,
        level: AuditLevel,
    ) -> Result<Self, HsmError> {
        let path = validate_log_path(&path)?;
        let mut reg = REGISTRY.lock();
        let map = reg.get_or_insert_with(Default::default);
        if let Some(backend) = map.get(&path).and_then(|w| w.upgrade()) {
            // Another handle in this process already owns this log.
            let shared = Arc::clone(&backend.shared);
            return Ok(Self {
                backend,
                shared,
                log_path: Some(path),
            });
        }
        let log = Self::open_file_exclusive(path.clone(), key_path, fail_closed, level)?;
        map.retain(|_, w| w.strong_count() > 0);
        map.insert(path, Arc::downgrade(&log.backend));
        Ok(log)
    }

    fn open_file_exclusive(
        path: PathBuf,
        key_path: PathBuf,
        fail_closed: bool,
        level: AuditLevel,
    ) -> Result<Self, HsmError> {
        Self::open_file_exclusive_with_limit(path, key_path, fail_closed, level, MAX_LOG_FILE_BYTES)
    }

    fn open_file_exclusive_with_limit(
        path: PathBuf,
        key_path: PathBuf,
        fail_closed: bool,
        level: AuditLevel,
        max_bytes: u64,
    ) -> Result<Self, HsmError> {
        // Cross-process single-writer lock (<log>.lock, 0600, O_NOFOLLOW).
        let lock_path = {
            let mut n = path.as_os_str().to_os_string();
            n.push(".lock");
            PathBuf::from(n)
        };
        let lock = crate::store::fs_util::open_private(&lock_path, false)?;
        {
            use fs2::FileExt;
            lock.try_lock_exclusive().map_err(|_| {
                tracing::error!(
                    "audit log {} is in use by another process — configure a distinct \
                     audit.log_path per process",
                    path.display()
                );
                HsmError::DeviceError
            })?;
        }
        let log_exists = path.exists() || anchor_path(&path).exists();
        let key = match load_or_create_key(&key_path, log_exists)? {
            Some(k) => k,
            None => {
                tracing::error!(
                    "audit key file {} missing for existing log {} — cannot verify; \
                     treating as tampered",
                    key_path.display(),
                    path.display()
                );
                let mut k = Zeroizing::new([0u8; 32]);
                crate::store::encrypted_store::fill_random(k.as_mut())?;
                return Self::start(
                    k,
                    None,
                    ([0u8; 32], 0, 0),
                    true,
                    fail_closed,
                    level,
                    Some(path),
                    Some(lock),
                );
            }
        };

        let (recovered, tampered) = match Self::recover_chain_from_file(&path, &key) {
            ChainRecoveryResult::NoFile => (([0u8; 32], 0, 0), false),
            ChainRecoveryResult::Verified(h, seq, ts) => ((h, seq, ts), false),
            ChainRecoveryResult::Broken(reason) => {
                tracing::error!(
                    "Audit chain integrity check FAILED for {}: {}. \
                     Tamper flag set — record() will refuse new events.",
                    path.display(),
                    reason,
                );
                (([0u8; 32], 0, 0), true)
            }
        };
        let writer = if tampered {
            None
        } else {
            let f = open_audit_file(&path)?;
            let size = f.metadata().map(|m| m.len()).unwrap_or(0);
            Some(Writer {
                path: path.clone(),
                file: std::io::BufWriter::new(f),
                size,
                max_bytes,
            })
        };
        Self::start(
            key,
            writer,
            recovered,
            tampered,
            fail_closed,
            level,
            Some(path),
            Some(lock),
        )
    }

    /// Returns `true` if the audit log chain was found to be corrupt or
    /// tampered with during recovery. Once set, this flag is permanent.
    pub fn is_tamper_detected(&self) -> bool {
        self.shared.tamper_flag.load(Ordering::Acquire)
    }

    /// In fail-closed mode, returns an error once the log is unusable
    /// (tamper detected or a previous write failed) so callers can refuse
    /// security-relevant operations *before* performing them.
    pub fn check_healthy(&self) -> HsmResult<()> {
        if !self.shared.fail_closed {
            return Ok(());
        }
        if self.shared.tamper_flag.load(Ordering::Acquire)
            || self.shared.io_failed.load(Ordering::Acquire)
        {
            return Err(HsmError::DeviceError);
        }
        Ok(())
    }

    /// Returns `true` if an event could not be written durably.
    pub fn has_io_failure(&self) -> bool {
        self.shared.io_failed.load(Ordering::Acquire)
    }

    /// Verify the persisted log **and all its rotated generations** offline
    /// (oldest first: `<log>.5` … `<log>.1`, `<log>`), recomputing the keyed
    /// chain across generation boundaries, checking sequence numbers, the
    /// `LogRotated` links and the MAC-protected anchor, and hand every
    /// verified event to `visit` in order (H5-03). Stops at the first broken
    /// link; events are only visited after their link verified.
    ///
    /// This is the API for offline readers (admin CLI `audit verify-chain`,
    /// `dump`, `export-*`): it needs read access to the key file but never
    /// writes and takes no lock.
    pub fn verify_files(
        log_path: &Path,
        key_path: &Path,
        mut visit: impl FnMut(&AuditEvent) -> Result<(), String>,
    ) -> Result<AuditFileSummary, AuditVerifyError> {
        let mut files: Vec<PathBuf> = (1..=MAX_ROTATED_FILES)
            .rev()
            .map(|g| rotated_path(log_path, g))
            .filter(|p| std::fs::symlink_metadata(p).is_ok())
            .collect();
        if std::fs::symlink_metadata(log_path).is_ok() {
            files.push(log_path.to_path_buf());
        }
        let key = match crate::store::fs_util::read_private(key_path) {
            Ok(Some(k)) if k.len() == 32 => {
                let mut arr = Zeroizing::new([0u8; 32]);
                arr.copy_from_slice(&k);
                let mut k = k;
                k.iter_mut().for_each(|b| *b = 0);
                arr
            }
            Ok(Some(_)) => {
                return Err(AuditVerifyError::KeyUnavailable(
                    key_path.to_path_buf(),
                    "malformed key file".to_string(),
                ))
            }
            Ok(None) => {
                return Err(AuditVerifyError::KeyUnavailable(
                    key_path.to_path_buf(),
                    "key file missing".to_string(),
                ))
            }
            Err(e) => {
                return Err(AuditVerifyError::KeyUnavailable(
                    key_path.to_path_buf(),
                    format!("{e:?}"),
                ))
            }
        };
        let anchor = read_anchor(log_path, &key).map_err(|reason| AuditVerifyError::Tampered {
            file: anchor_path(log_path),
            line: 0,
            reason,
        })?;
        if files.is_empty() {
            return match anchor {
                None => Err(AuditVerifyError::Missing(log_path.to_path_buf())),
                Some((seq, _)) => Err(AuditVerifyError::Tampered {
                    file: log_path.to_path_buf(),
                    line: 0,
                    reason: format!("log missing but anchor records {} event(s)", seq + 1),
                }),
            };
        }

        let mut running: Option<[u8; 32]> = None;
        let mut next_seq: Option<u64> = None;
        let mut anchored_at_genesis = true;
        let mut anchor_seen = false;
        let mut entries = 0u64;
        let mut buf = Vec::new();
        for path in &files {
            let is_current = path.as_path() == log_path;
            let file = match crate::store::fs_util::open_existing_readonly(path) {
                Ok(Some(f)) => f,
                Ok(None) => return Err(AuditVerifyError::Missing(path.clone())),
                Err(e) => return Err(AuditVerifyError::Io(path.clone(), format!("{e:?}"))),
            };
            let mut reader = std::io::BufReader::new(file);
            let mut line_no = 0usize;
            let mut first_in_file = true;
            loop {
                let tampered = |line: usize, reason: String| AuditVerifyError::Tampered {
                    file: path.clone(),
                    line,
                    reason,
                };
                buf.clear();
                let n = std::io::Read::take(&mut reader, MAX_AUDIT_LINE_BYTES as u64 + 1)
                    .read_until(b'\n', &mut buf)
                    .map_err(|e| AuditVerifyError::Io(path.clone(), e.to_string()))?;
                if n == 0 {
                    break;
                }
                line_no += 1;
                if buf.len() > MAX_AUDIT_LINE_BYTES {
                    return Err(tampered(line_no, "line exceeds maximum length".into()));
                }
                let text = String::from_utf8_lossy(&buf);
                let text = text.trim();
                if text.is_empty() {
                    continue;
                }
                let ev: AuditEvent = serde_json::from_str(text)
                    .map_err(|e| tampered(line_no, format!("unparseable entry: {e}")))?;
                match (running, next_seq) {
                    (Some(h), Some(seq)) => {
                        if ev.seq != seq {
                            return Err(tampered(
                                line_no,
                                format!("sequence gap: expected {seq}, found {}", ev.seq),
                            ));
                        }
                        if ev.previous_hash != h {
                            return Err(tampered(line_no, "chain mismatch".into()));
                        }
                        if first_in_file {
                            // A new generation must start with its rotation
                            // header linking to the previous generation.
                            match ev.operation {
                                AuditOperation::LogRotated {
                                    previous_generation_last_seq,
                                } if previous_generation_last_seq + 1 == seq => {}
                                _ => {
                                    return Err(tampered(
                                        line_no,
                                        "generation does not start with a matching rotation header"
                                            .into(),
                                    ))
                                }
                            }
                        }
                    }
                    _ => {
                        // Oldest available event.
                        if ev.seq == 0 {
                            if ev.previous_hash != [0u8; 32] {
                                return Err(tampered(
                                    line_no,
                                    "first event does not start the chain".into(),
                                ));
                            }
                        } else if matches!(ev.operation, AuditOperation::LogRotated { .. }) {
                            // Older generations were rotated away.
                            anchored_at_genesis = false;
                        } else {
                            return Err(tampered(
                                line_no,
                                format!("log starts at seq {} without a rotation header", ev.seq),
                            ));
                        }
                    }
                }
                let h = event_hash(&key, &ev)
                    .map_err(|_| tampered(line_no, "serialization failed".into()))?;
                if is_current {
                    if let Some((aseq, ahash)) = anchor {
                        if aseq == ev.seq {
                            if ahash != h {
                                return Err(tampered(
                                    line_no,
                                    "anchor does not match the log (rewritten history?)".into(),
                                ));
                            }
                            anchor_seen = true;
                        }
                    }
                }
                visit(&ev).map_err(AuditVerifyError::Visitor)?;
                running = Some(h);
                next_seq = Some(ev.seq + 1);
                entries += 1;
                first_in_file = false;
            }
        }
        if let Some((aseq, _)) = anchor {
            if !anchor_seen {
                return Err(AuditVerifyError::Tampered {
                    file: log_path.to_path_buf(),
                    line: 0,
                    reason: format!(
                        "log truncated or replaced: anchored event seq {aseq} not found in the current file"
                    ),
                });
            }
        }
        Ok(AuditFileSummary {
            entries,
            files,
            anchored_at_genesis,
            anchor_present: anchor.is_some(),
            last_seq: next_seq.map(|n| n - 1),
        })
    }

    /// Verify a log file offline (e.g. from the admin CLI while the daemon
    /// owns the live log). Returns `(events, last_seq)`. Only the current
    /// generation is checked; see [`verify_files`](Self::verify_files) for
    /// the complete chain across rotated generations.
    pub fn verify_file(path: &Path, key_path: &Path) -> Result<(u64, u64), String> {
        let key = match load_or_create_key(key_path, true) {
            Ok(Some(k)) => k,
            _ => return Err("audit key unavailable".to_string()),
        };
        match Self::recover_chain_from_file(path, &key) {
            ChainRecoveryResult::NoFile => Ok((0, 0)),
            ChainRecoveryResult::Verified(_, next, _) => Ok((next, next.saturating_sub(1))),
            ChainRecoveryResult::Broken(r) => Err(r),
        }
    }

    /// Read the existing NDJSON audit log file, recompute the keyed chain,
    /// verify each link and the sequence numbers, and check the anchor.
    fn recover_chain_from_file(path: &Path, key: &[u8; 32]) -> ChainRecoveryResult {
        let anchor = match read_anchor(path, key) {
            Ok(a) => a,
            Err(e) => return ChainRecoveryResult::Broken(e),
        };
        let file = match crate::store::fs_util::open_existing_readonly(path) {
            Ok(Some(f)) => f,
            Ok(None) => {
                return match anchor {
                    None => ChainRecoveryResult::NoFile,
                    Some((seq, _)) => ChainRecoveryResult::Broken(format!(
                        "log file missing but anchor records {} event(s)",
                        seq + 1
                    )),
                };
            }
            Err(e) => {
                return ChainRecoveryResult::Broken(format!(
                    "could not open log file {}: {:?}",
                    path.display(),
                    e
                ))
            }
        };

        let reader = std::io::BufReader::new(file);
        let mut running_hash = [0u8; 32];
        let mut expected_seq: Option<u64> = None;
        let mut last_ts = 0u64;
        let mut anchor_seen = false;
        let mut count = 0u64;

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    return ChainRecoveryResult::Broken(format!(
                        "I/O error at line {}: {}",
                        line_num + 1,
                        e
                    ))
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event: AuditEvent = match serde_json::from_str(trimmed) {
                Ok(ev) => ev,
                Err(e) => {
                    return ChainRecoveryResult::Broken(format!(
                        "failed to deserialize line {}: {}",
                        line_num + 1,
                        e
                    ))
                }
            };
            match expected_seq {
                None => {
                    // First line: either the very first event (seq 0, zero
                    // chain) or the rotation header of a later generation.
                    if event.seq == 0 {
                        if event.previous_hash != [0u8; 32] {
                            return ChainRecoveryResult::Broken(
                                "first event does not start the chain".to_string(),
                            );
                        }
                    } else if !matches!(event.operation, AuditOperation::LogRotated { .. }) {
                        return ChainRecoveryResult::Broken(format!(
                            "log starts at seq {} without a rotation header (head truncated?)",
                            event.seq
                        ));
                    }
                }
                Some(seq) => {
                    if event.seq != seq {
                        return ChainRecoveryResult::Broken(format!(
                            "sequence gap at line {}: expected {}, found {}",
                            line_num + 1,
                            seq,
                            event.seq
                        ));
                    }
                    if event.previous_hash != running_hash {
                        return ChainRecoveryResult::Broken(format!(
                            "TAMPER DETECTED at line {}: chain mismatch",
                            line_num + 1
                        ));
                    }
                }
            }
            running_hash = match event_hash(key, &event) {
                Ok(h) => h,
                Err(_) => {
                    return ChainRecoveryResult::Broken(format!(
                        "serialization failed at line {}",
                        line_num + 1
                    ))
                }
            };
            if let Some((aseq, ahash)) = anchor {
                if aseq == event.seq {
                    if ahash != running_hash {
                        return ChainRecoveryResult::Broken(
                            "anchor does not match the log (rewritten history?)".to_string(),
                        );
                    }
                    anchor_seen = true;
                }
            }
            expected_seq = Some(event.seq + 1);
            last_ts = event.timestamp;
            count += 1;
        }

        match (expected_seq, anchor) {
            (None, None) => ChainRecoveryResult::NoFile,
            (None, Some(_)) => {
                ChainRecoveryResult::Broken("log is empty but anchor exists (truncated)".into())
            }
            (Some(next), Some((aseq, _))) if aseq >= next => ChainRecoveryResult::Broken(format!(
                "log truncated: anchor seq {} beyond last event {}",
                aseq,
                next - 1
            )),
            (Some(_), Some(_)) if !anchor_seen => {
                ChainRecoveryResult::Broken("anchor refers to an event not in this log".into())
            }
            (Some(next), anchor) => {
                if anchor.is_none() {
                    tracing::warn!(
                        "audit log {} has no anchor file; tail truncation cannot be ruled out",
                        path.display()
                    );
                }
                tracing::info!(
                    "Audit chain recovery: verified {} event(s) from {}",
                    count,
                    path.display()
                );
                ChainRecoveryResult::Verified(running_hash, next, last_ts)
            }
        }
    }

    /// Rotate the log files: shift existing generations downward.
    /// `.4` is deleted, `.3` → `.4`, … `.1` → `.2`, current → `.1`.
    fn rotate_log_files(path: &Path) -> Result<(), HsmError> {
        tracing::info!(
            "Audit log rotation: {} exceeds {} bytes, rotating.",
            path.display(),
            MAX_LOG_FILE_BYTES,
        );
        for gen in (1..MAX_ROTATED_FILES).rev() {
            let from = rotated_path(path, gen);
            let to = rotated_path(path, gen + 1);
            if std::fs::symlink_metadata(&from).is_ok() {
                std::fs::rename(&from, &to).map_err(|e| {
                    tracing::error!(
                        "Audit log rotation: failed to rename {} -> {}: {}",
                        from.display(),
                        to.display(),
                        e,
                    );
                    HsmError::DeviceError
                })?;
            }
        }
        let gen1 = rotated_path(path, 1);
        std::fs::rename(path, &gen1).map_err(|e| {
            tracing::error!("Audit log rotation: rename failed: {}", e);
            HsmError::DeviceError
        })?;
        if let Some(dir) = path.parent() {
            crate::store::fs_util::fsync_dir(dir)?;
        }
        Ok(())
    }

    fn precheck(&self, operation: &AuditOperation) -> HsmResult<bool> {
        if self.shared.tamper_flag.load(Ordering::Acquire) {
            return Err(HsmError::AuditChainBroken(
                "refusing to record: audit chain tamper previously detected".to_string(),
            ));
        }
        if self.shared.fail_closed && self.shared.io_failed.load(Ordering::Acquire) {
            return Err(HsmError::DeviceError);
        }
        Ok(self.shared.level.records(operation))
    }

    /// Record an audit event asynchronously (bounded queue; blocks when the
    /// queue is full).
    ///
    /// Returns `Err(AuditChainBroken)` if tamper has been detected, and — in
    /// fail-closed mode — `Err(DeviceError)` after a failed disk write.
    pub fn record(
        &self,
        session_handle: u64,
        operation: AuditOperation,
        result: AuditResult,
        key_id: Option<String>,
    ) -> HsmResult<()> {
        if !self.precheck(&operation)? {
            return Ok(());
        }
        let key_id = key_id.map(|s| sanitize_audit_field(&s));
        if let Some(sender) = self.backend.sender() {
            sender
                .send(AuditCommand::Record {
                    session_handle,
                    operation,
                    result,
                    key_id,
                    done: None,
                })
                .map_err(|_| HsmError::GeneralError)?;
        }
        Ok(())
    }

    /// Record an event and wait until it is durable (flushed and fsynced).
    /// Returns an error if it could not be written. With
    /// `audit.fail_closed = false` write errors are only logged.
    pub fn record_sync(
        &self,
        session_handle: u64,
        operation: AuditOperation,
        result: AuditResult,
        key_id: Option<String>,
    ) -> HsmResult<()> {
        if !self.precheck(&operation)? {
            return Ok(());
        }
        let key_id = key_id.map(|s| sanitize_audit_field(&s));
        let sender = match self.backend.sender() {
            Some(s) => s,
            None => return Ok(()),
        };
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        sender
            .send(AuditCommand::Record {
                session_handle,
                operation,
                result,
                key_id,
                done: Some(tx),
            })
            .map_err(|_| HsmError::GeneralError)?;
        let r = rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap_or(Err(HsmError::DeviceError));
        match r {
            Err(e) if self.shared.fail_closed => Err(e),
            Err(e) => {
                tracing::error!("audit event could not be made durable: {:?}", e);
                Ok(())
            }
            Ok(()) => Ok(()),
        }
    }

    /// Flush all pending audit events synchronously. Blocks until the
    /// background worker has processed every queued command, or until a
    /// 5-second timeout expires.
    pub fn flush(&self) {
        if let Some(sender) = self.backend.sender() {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            if sender.send(AuditCommand::Flush { done: tx }).is_ok() {
                let _ = rx.recv_timeout(std::time::Duration::from_secs(5));
            }
        }
    }

    /// Path of the on-disk log, if any.
    pub fn log_path(&self) -> Option<&Path> {
        self.log_path.as_deref()
    }

    /// # Security
    ///
    /// Callers must verify that the requesting session has Security Officer (SO)
    /// privileges before exposing audit data. This method does not enforce
    /// authorization internally.
    pub fn entry_count(&self) -> usize {
        // Read-your-writes: make every event recorded before this call visible.
        self.flush();
        self.shared.state.read().entries.len()
    }

    /// Get a clone of all audit entries (for export/inspection).
    ///
    /// # Security
    ///
    /// Callers must verify SO authorization. Prefer `get_entries_paginated()`
    /// for large logs to avoid cloning up to 100K entries at once.
    pub fn get_entries(&self) -> Vec<AuditEvent> {
        // Read-your-writes: make every event recorded before this call visible.
        self.flush();
        self.shared.state.read().entries.iter().cloned().collect()
    }

    /// Get a clone of the most recent `n` entries.
    ///
    /// # Security
    ///
    /// Callers must verify SO authorization before exposing audit data.
    pub fn get_recent_entries(&self, n: usize) -> Vec<AuditEvent> {
        // Read-your-writes: make every event recorded before this call visible.
        self.flush();
        let state = self.shared.state.read();
        let start = state.entries.len().saturating_sub(n);
        state.entries.iter().skip(start).cloned().collect()
    }

    /// Get a paginated window of entries. Returns entries in the range
    /// `[offset .. offset + limit]`, clamped to the available entries.
    /// Useful for UI or API consumers that cannot afford cloning 100K events.
    ///
    /// # Security
    ///
    /// Callers must verify SO authorization before exposing audit data.
    pub fn get_entries_paginated(&self, offset: usize, limit: usize) -> Vec<AuditEvent> {
        // Read-your-writes: make every event recorded before this call visible.
        self.flush();
        let state = self.shared.state.read();
        if offset >= state.entries.len() {
            return Vec::new();
        }
        state
            .entries
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Export all entries as a JSON array string.
    /// Snapshots entries under a read lock, then serializes after releasing it
    /// to avoid blocking `record()` during potentially slow serialization.
    ///
    /// # Security
    ///
    /// Callers must verify SO authorization before exposing audit data.
    pub fn export_json(&self) -> String {
        // Read-your-writes: make every event recorded before this call visible.
        self.flush();
        let entries = self.shared.state.read().entries.clone();
        serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string())
    }

    /// Export all entries as newline-delimited JSON (NDJSON/JSON Lines).
    /// Each line is a single JSON object — ideal for log aggregators and SIEM ingestion.
    /// Snapshots entries under a read lock, then serializes after releasing it.
    ///
    /// # Security
    ///
    /// Callers must verify SO authorization before exposing audit data.
    pub fn export_ndjson(&self) -> String {
        // Read-your-writes: make every event recorded before this call visible.
        self.flush();
        let entries = self.shared.state.read().entries.clone();
        entries
            .iter()
            .map(|e| {
                serde_json::to_string(e).unwrap_or_else(|err| {
                    tracing::error!(
                        "Audit export: failed to serialize event (session={}, ts={}): {}",
                        e.session_handle,
                        e.timestamp,
                        err,
                    );
                    // Produce a placeholder so line count is preserved and the
                    // consumer can detect the gap.
                    format!(
                        "{{\"error\":\"serialization_failed\",\"session_handle\":{},\"timestamp\":{}}}",
                        e.session_handle, e.timestamp
                    )
                })
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Export entries in syslog RFC 5424 format with structured data.
    /// Format: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG`
    /// Suitable for forwarding to syslog daemons or SIEM systems.
    /// Snapshots entries under a read lock, then formats after releasing it.
    ///
    /// # Security
    ///
    /// Callers must verify SO authorization before exposing audit data.
    pub fn export_syslog(&self) -> Vec<String> {
        // Read-your-writes: make every event recorded before this call visible.
        self.flush();
        let entries = self.shared.state.read().entries.clone();
        entries.iter().map(format_syslog).collect()
    }

    /// Verify the integrity of the in-memory audit log chain (starting from
    /// the chain value preceding the oldest retained entry, H3-26).
    /// Returns `Ok(count)` if the chain is valid,
    /// `Err(index)` with the index of the first broken link.
    pub fn verify_chain(&self) -> Result<usize, usize> {
        // Read-your-writes: make every event recorded before this call visible.
        self.flush();
        let state = self.shared.state.read();
        let mut expected_hash = state.base_hash;
        let mut expected_seq: Option<u64> = None;
        for (i, entry) in state.entries.iter().enumerate() {
            if entry.previous_hash != expected_hash {
                return Err(i);
            }
            if let Some(seq) = expected_seq {
                if entry.seq != seq {
                    return Err(i);
                }
            }
            match event_hash(&self.shared.key, entry) {
                Ok(h) => expected_hash = h,
                Err(_) => return Err(i),
            }
            expected_seq = Some(entry.seq + 1);
        }
        Ok(state.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(path: &Path, limit: u64) -> AuditLog {
        AuditLog::open_file_exclusive_with_limit(
            path.to_path_buf(),
            default_key_path(path),
            false,
            AuditLevel::All,
            limit,
        )
        .unwrap()
    }

    fn write_events(log: &AuditLog, n: usize) {
        for i in 0..n {
            log.record(
                i as u64,
                AuditOperation::Login { user_type: 1 },
                AuditResult::Success,
                Some(format!("key-{i}")),
            )
            .unwrap();
        }
        log.flush();
    }

    #[test]
    fn restart_after_rotation_is_not_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        {
            let log = open(&p, 2048);
            write_events(&log, 60);
            assert!(!log.is_tamper_detected());
        }
        assert!(rotated_path(&p, 1).exists(), "rotation must have happened");
        let log = open(&p, 2048);
        assert!(
            !log.is_tamper_detected(),
            "restart after rotation must verify"
        );
        write_events(&log, 3);
        assert_eq!(log.verify_chain(), Ok(3));
    }

    #[test]
    fn edit_truncation_and_deletion_are_detected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        {
            let log = open(&p, u64::MAX);
            write_events(&log, 5);
        }
        let original = std::fs::read_to_string(&p).unwrap();

        // Edit a field (attacker without the key cannot recompute the chain).
        std::fs::write(&p, original.replacen("key-1", "key-X", 1)).unwrap();
        assert!(open(&p, u64::MAX).is_tamper_detected());

        // Truncate the tail (anchor records the last event).
        let lines: Vec<&str> = original.lines().collect();
        std::fs::write(&p, lines[..3].join("\n") + "\n").unwrap();
        assert!(open(&p, u64::MAX).is_tamper_detected());

        // Delete the log entirely.
        std::fs::remove_file(&p).unwrap();
        assert!(open(&p, u64::MAX).is_tamper_detected());
    }

    #[test]
    fn mandatory_level_skips_routine_crypto_events() {
        assert!(!AuditLevel::Mandatory.records(&AuditOperation::Sign {
            mechanism: 1,
            fips_approved: true
        }));
        assert!(AuditLevel::Mandatory.records(&AuditOperation::InitToken { slot_id: 0 }));
        assert!(AuditLevel::All.records(&AuditOperation::GenerateRandom { length: 1 }));
    }
}

/// Build a rotated file path: `path.1`, `path.2`, etc.
fn rotated_path(base: &Path, generation: u32) -> PathBuf {
    let mut name = base.as_os_str().to_os_string();
    name.push(format!(".{}", generation));
    PathBuf::from(name)
}

/// Format an event as an RFC 5424 syslog line with structured data
/// (`<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG`), suitable for
/// forwarding to syslog daemons or SIEM systems. Field values are escaped /
/// sanitised against log injection. Public so offline tools (admin CLI)
/// produce exactly the same format as [`AuditLog::export_syslog`] (H5-03).
pub fn format_syslog(e: &AuditEvent) -> String {
    let severity = match &e.result {
        AuditResult::Success => 6,    // informational
        AuditResult::Failure(_) => 4, // warning
    };
    let facility = 10; // security/authorization (authpriv)
    let priority = facility * 8 + severity;
    let timestamp = format_rfc3339(e.timestamp);
    let op_name = format_operation_name(&e.operation);
    let result_str = match &e.result {
        AuditResult::Success => "SUCCESS".to_string(),
        AuditResult::Failure(rv) => format!("FAILURE(0x{:08X})", rv),
    };
    let key_str = e.key_id.as_deref().unwrap_or("-");
    // RFC 5424 §6.3.3: `"`, `\` and `]` are escaped inside SD param-values.
    let sd = format!(
        "[hsm@0 seq=\"{}\" session=\"{}\" op=\"{}\" result=\"{}\" key=\"{}\"]",
        e.seq,
        e.session_handle,
        escape_sd_value(op_name),
        escape_sd_value(&result_str),
        escape_sd_value(key_str),
    );
    let msg = format!(
        "session={} op={} result={} key={}",
        e.session_handle,
        sanitize_syslog_msg_value(op_name),
        sanitize_syslog_msg_value(&result_str),
        sanitize_syslog_msg_value(key_str),
    );
    // PROCID is the nil value "-" (no process topology leak).
    format!(
        "<{}>1 {} craton_hsm craton_hsm - - {} {}",
        priority, timestamp, sd, msg
    )
}

/// Short, stable name of an audit operation (syslog / CLI tables).
pub fn operation_name(op: &AuditOperation) -> &'static str {
    format_operation_name(op)
}

/// Format a nanosecond UNIX timestamp as RFC 3339 (used in syslog).
pub fn format_rfc3339(nanos: u64) -> String {
    let secs = nanos / 1_000_000_000;
    let subsec = nanos % 1_000_000_000;
    // Simple UTC timestamp without pulling in chrono
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Approximate date from days since epoch (good enough for audit logs)
    let (year, month, day) = days_to_ymd(days_since_epoch);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        year,
        month,
        day,
        hours,
        minutes,
        seconds,
        subsec / 1000
    )
}

/// Convert days since UNIX epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Sanitize a string field for audit records: strip control characters and limit length.
/// Prevents log injection attacks where a malicious key_id could contain newlines
/// or other control characters to forge audit log entries.
fn sanitize_audit_field(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(256).collect()
}

/// Escape a value for inclusion in RFC 5424 structured data.
/// Per RFC 5424 §6.3.3, the characters `"`, `\`, and `]` MUST be escaped
/// with a preceding `\` inside SD parameter values.
fn escape_sd_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' | '\\' | ']' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Sanitize a value for the human-readable MSG portion of syslog output.
/// Strips characters that could confuse syslog parsers: `<` and `>` (PRI
/// marker delimiters), control characters, and newlines.
fn sanitize_syslog_msg_value(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && *c != '<' && *c != '>')
        .collect()
}

/// Format an AuditOperation into a short name for syslog messages.
fn format_operation_name(op: &AuditOperation) -> &'static str {
    match op {
        AuditOperation::Initialize => "Initialize",
        AuditOperation::Finalize => "Finalize",
        AuditOperation::OpenSession { .. } => "OpenSession",
        AuditOperation::CloseSession => "CloseSession",
        AuditOperation::Login { .. } => "Login",
        AuditOperation::Logout => "Logout",
        AuditOperation::InitToken { .. } => "InitToken",
        AuditOperation::GenerateKey { .. } => "GenerateKey",
        AuditOperation::GenerateKeyPair { .. } => "GenerateKeyPair",
        AuditOperation::Sign { .. } => "Sign",
        AuditOperation::Verify { .. } => "Verify",
        AuditOperation::Encrypt { .. } => "Encrypt",
        AuditOperation::Decrypt { .. } => "Decrypt",
        AuditOperation::Digest { .. } => "Digest",
        AuditOperation::CreateObject => "CreateObject",
        AuditOperation::DestroyObject => "DestroyObject",
        AuditOperation::GenerateRandom { .. } => "GenerateRandom",
        AuditOperation::WrapKey { .. } => "WrapKey",
        AuditOperation::UnwrapKey { .. } => "UnwrapKey",
        AuditOperation::DeriveKey { .. } => "DeriveKey",
        AuditOperation::FindObjects { .. } => "FindObjects",
        AuditOperation::GetAttributeValue => "GetAttributeValue",
        AuditOperation::GetAttributeValueSensitive { .. } => "GetAttributeValueSensitive",
        AuditOperation::InitPin { .. } => "InitPIN",
        AuditOperation::SetPin { .. } => "SetPIN",
        AuditOperation::CopyObject => "CopyObject",
        AuditOperation::SetAttributeValue => "SetAttributeValue",
        AuditOperation::LogRotated { .. } => "LogRotated",
        AuditOperation::BackupExport { .. } => "BackupExport",
        AuditOperation::BackupRestore { .. } => "BackupRestore",
        AuditOperation::AuditExport => "AuditExport",
    }
}
