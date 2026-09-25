// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Symmetric encryption: a backend-agnostic **policy layer** plus the
//! RustCrypto AES primitives.
//!
//! Every backend's AES operations go through the policy functions in this
//! module (the `CryptoBackend` trait's provided methods call them), so the
//! controls below apply identically to the RustCrypto and AWS-LC backends
//! (H2-04):
//!
//! * **AES-GCM** (H2-01, H2-02, H2-12, A1-15): caller `CK_GCM_PARAMS` (IV,
//!   AAD, tag length) are honoured and the output is the standard
//!   `ciphertext || tag`. In FIPS approved mode the 96-bit IV must have been
//!   generated inside the module by the approved DRBG (SP 800-38D §8.2.2,
//!   IG C.H scenario 2); caller-chosen IVs are refused. Random IVs need no
//!   process-local counter state, so copying/destroying keys, `fork()` or
//!   restarts can no longer rewind an IV sequence. Per key the module
//!   enforces the SP 800-38D §8.3 limit of 2^32 invocations and rejects an
//!   exact (key, IV) repeat seen recently. The bookkeeping lock is released
//!   before the cipher runs.
//! * **AES-CBC** (H2-13, A2-10): `CKM_AES_CBC` is unpadded (input must be a
//!   multiple of 16 bytes); `CKM_AES_CBC_PAD` uses PKCS#7. The old 10 ms
//!   sleep is gone: it did not remove the CBC-PAD padding oracle (the return
//!   code *is* the oracle, inherent to the mechanism) and capped throughput.
//!   Use AES-GCM for authenticated encryption.
//! * **AES-CTR** (H2-11, H2-22): `CK_AES_CTR_PARAMS.ulCounterBits` is
//!   enforced (no counter-field wrap) and keystream *ranges* are tracked per
//!   key, so overlapping counter ranges (IV = X then IV = X+1) are rejected,
//!   not only identical IVs.
//!
//! Tracking state is keyed by SHA-256(key), is **not** reset on
//! `C_Initialize` or `C_DestroyObject` (only `C_InitToken`, which destroys all
//! keys, clears it) and is bounded by a least-recently-used eviction instead
//! of a global hard cap that any session could exhaust (cross-tenant DoS).
//! Residual limits (documented in the handoff): the state is per process, so
//! caller-chosen CTR/CBC IVs are not tracked across processes or restarts.

use aes_gcm::aead::consts::{U12, U13, U14, U15, U16};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::AesGcm;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::params::{CtrParams, GcmParams, GCM_IV_LEN};
use crate::error::{HsmError, HsmResult};

/// NIST SP 800-38D maximum plaintext length: 2^36 - 32 bytes.
const AES_GCM_MAX_PLAINTEXT: usize = (1usize << 36) - 32;
/// Practical single-shot cap (matches the ABI's 64 MiB buffer bound).
const AES_GCM_SINGLE_SHOT_MAX: usize = 64 * 1024 * 1024;
/// Maximum plaintext size for AES-CBC and AES-CTR operations.
const AES_CBC_CTR_MAX_PLAINTEXT: usize = 256 * 1024 * 1024;
/// SP 800-38D §8.3: at most 2^32 invocations per key with RBG-based IVs.
pub const GCM_MAX_INVOCATIONS_PER_KEY: u64 = 1u64 << 32;
/// Recently used GCM IVs remembered per key (exact-repeat detection).
const GCM_RECENT_IVS_PER_KEY: usize = 65_536;
/// Recently used CBC IVs remembered per key.
const CBC_RECENT_IVS_PER_KEY: usize = 100_000;
/// Maximum disjoint CTR keystream ranges tracked per key before the key must
/// be rotated (adjacent ranges are merged, so sequential use stays at 1).
const CTR_MAX_RANGES_PER_KEY: usize = 65_536;
/// Maximum number of keys with tracking state (LRU eviction beyond this).
const MAX_TRACKED_KEYS: usize = 65_536;

// ============================================================================
// Per-key tracking state
// ============================================================================

/// A bounded set remembering the most recent `cap` insertions.
struct RecentSet<T: Hash + Eq + Copy> {
    set: HashSet<T>,
    order: VecDeque<T>,
    cap: usize,
}

impl<T: Hash + Eq + Copy> RecentSet<T> {
    fn new(cap: usize) -> Self {
        Self {
            set: HashSet::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    /// Insert; returns `false` if the value is already present.
    fn insert(&mut self, v: T) -> bool {
        if self.set.contains(&v) {
            return false;
        }
        if self.order.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        self.set.insert(v);
        self.order.push_back(v);
        true
    }
}

struct KeyState {
    gcm_invocations: u64,
    gcm_ivs: RecentSet<[u8; GCM_IV_LEN]>,
    cbc_ivs: RecentSet<[u8; 16]>,
    /// Used CTR keystream ranges: start block -> end block (exclusive).
    ctr_ranges: BTreeMap<u128, u128>,
    last_used: u64,
}

impl KeyState {
    fn new() -> Self {
        Self {
            gcm_invocations: 0,
            gcm_ivs: RecentSet::new(GCM_RECENT_IVS_PER_KEY),
            cbc_ivs: RecentSet::new(CBC_RECENT_IVS_PER_KEY),
            ctr_ranges: BTreeMap::new(),
            last_used: 0,
        }
    }
}

static KEY_STATE: parking_lot::Mutex<Option<HashMap<[u8; 32], KeyState>>> =
    parking_lot::Mutex::new(None);
static USE_CLOCK: AtomicU64 = AtomicU64::new(0);

/// Stable per-key identifier (SHA-256 of the key; the key itself is never
/// stored).
fn key_id(key: &[u8]) -> [u8; 32] {
    Sha256::digest(key).into()
}

/// Run `f` on the tracking state of `kid` while holding the bookkeeping lock.
/// The lock is held only for the bookkeeping, never during encryption.
fn with_key_state<R>(kid: &[u8; 32], f: impl FnOnce(&mut KeyState) -> HsmResult<R>) -> HsmResult<R> {
    let mut guard = KEY_STATE.lock();
    let map = guard.get_or_insert_with(HashMap::new);
    if !map.contains_key(kid) && map.len() >= MAX_TRACKED_KEYS {
        // Evict the least-recently-used key instead of refusing service to
        // every new key (which let one session DoS all others).
        if let Some(victim) = map
            .iter()
            .min_by_key(|(_, s)| s.last_used)
            .map(|(k, _)| *k)
        {
            tracing::warn!(
                "Symmetric IV tracker full ({} keys) — evicting least recently used key state",
                MAX_TRACKED_KEYS
            );
            map.remove(&victim);
        }
    }
    let st = map.entry(*kid).or_insert_with(KeyState::new);
    st.last_used = USE_CLOCK.fetch_add(1, Ordering::Relaxed);
    f(st)
}

/// Clear all per-key tracking state. Only for `C_InitToken`, which destroys
/// every key on the token (so no tracked key can be used again).
pub fn force_reset_all_counters() {
    *KEY_STATE.lock() = None;
    tracing::info!("Symmetric IV/nonce tracking state cleared (token re-initialized).");
}

/// Alias of [`force_reset_all_counters`] retained for tests.
pub fn reset_iv_trackers() {
    force_reset_all_counters();
}

/// Number of GCM invocations recorded for `key` in this process. Exposed so
/// the object store can persist the count and restore it with
/// [`gcm_restore_invocation_count`] (see handoff: A1-15 persistence).
pub fn gcm_invocation_count(key: &[u8]) -> u64 {
    let kid = key_id(key);
    KEY_STATE
        .lock()
        .as_ref()
        .and_then(|m| m.get(&kid).map(|s| s.gcm_invocations))
        .unwrap_or(0)
}

/// Restore a persisted GCM invocation count (never lowers the current one).
pub fn gcm_restore_invocation_count(key: &[u8], count: u64) {
    let kid = key_id(key);
    let _ = with_key_state(&kid, |st| {
        st.gcm_invocations = st.gcm_invocations.max(count);
        Ok(())
    });
}

// ============================================================================
// AES-GCM policy
// ============================================================================

fn check_aes_key(key: &[u8]) -> HsmResult<()> {
    match key.len() {
        16 | 24 | 32 => Ok(()),
        _ => Err(HsmError::KeySizeRange),
    }
}

/// Generate a fresh 96-bit GCM IV from the module-wide approved DRBG.
pub fn gcm_generate_iv() -> HsmResult<[u8; GCM_IV_LEN]> {
    let mut iv = [0u8; GCM_IV_LEN];
    crate::crypto::drbg::fill_random(&mut iv)?;
    Ok(iv)
}

/// Output length of [`gcm_encrypt_with`] for a plaintext of `pt_len` bytes.
pub fn gcm_output_len(params: &GcmParams, pt_len: usize) -> usize {
    pt_len + params.tag_len() + if params.legacy_framing { GCM_IV_LEN } else { 0 }
}

/// AES-GCM encryption policy. `seal(key, iv, aad, tag_len, plaintext)` is
/// the backend primitive returning `ciphertext || tag`.
///
/// With `params.legacy_framing` the output is `IV || ciphertext || tag`
/// (deprecated vendor framing used when the caller supplies no
/// `CK_GCM_PARAMS`); the caller must then place a freshly generated IV in
/// `params.iv` (see `CryptoBackend::aes_gcm_encrypt`).
pub fn gcm_encrypt_with(
    key: &[u8],
    params: &GcmParams,
    plaintext: &[u8],
    fips_mode: bool,
    seal: impl FnOnce(&[u8], &[u8; GCM_IV_LEN], &[u8], usize, &[u8]) -> HsmResult<Vec<u8>>,
) -> HsmResult<Vec<u8>> {
    check_aes_key(key)?;
    if plaintext.len() > AES_GCM_SINGLE_SHOT_MAX || plaintext.len() > AES_GCM_MAX_PLAINTEXT {
        return Err(HsmError::DataLenRange);
    }
    let iv = params.iv;
    if fips_mode && !(params.iv_generated || params.legacy_framing) {
        // IG C.H: in approved mode the IV must be generated inside the module.
        tracing::error!("AES-GCM: caller-supplied IV refused in FIPS approved mode");
        return Err(HsmError::MechanismParamInvalid);
    }

    let kid = key_id(key);
    let count = with_key_state(&kid, |st| {
        if st.gcm_invocations >= GCM_MAX_INVOCATIONS_PER_KEY {
            tracing::error!(
                "AES-GCM per-key invocation limit (2^32) reached — rotate the key"
            );
            return Err(HsmError::KeyFunctionNotPermitted);
        }
        if !st.gcm_ivs.insert(iv) {
            tracing::error!("AES-GCM: IV reuse with the same key rejected");
            return Err(HsmError::MechanismParamInvalid);
        }
        st.gcm_invocations += 1;
        Ok(st.gcm_invocations)
    })?;
    if count == GCM_MAX_INVOCATIONS_PER_KEY * 3 / 4 {
        tracing::warn!("AES-GCM key at 75% of its invocation limit — schedule rotation");
    }

    let ct = seal(key, &iv, &params.aad, params.tag_len(), plaintext)?;
    if params.legacy_framing {
        let mut out = Vec::with_capacity(GCM_IV_LEN + ct.len());
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ct);
        Ok(out)
    } else {
        Ok(ct)
    }
}

/// AES-GCM decryption policy. `open(key, iv, aad, tag_len, ct_and_tag)` is
/// the backend primitive.
pub fn gcm_decrypt_with(
    key: &[u8],
    params: &GcmParams,
    data: &[u8],
    open: impl FnOnce(&[u8], &[u8; GCM_IV_LEN], &[u8], usize, &[u8]) -> HsmResult<Zeroizing<Vec<u8>>>,
) -> HsmResult<Zeroizing<Vec<u8>>> {
    check_aes_key(key)?;
    let tag_len = params.tag_len();
    let (iv, body) = if params.legacy_framing {
        if data.len() < GCM_IV_LEN + tag_len {
            return Err(HsmError::EncryptedDataLenRange);
        }
        let mut iv = [0u8; GCM_IV_LEN];
        iv.copy_from_slice(&data[..GCM_IV_LEN]);
        (iv, &data[GCM_IV_LEN..])
    } else {
        (params.iv, data)
    };
    if body.len() < tag_len {
        return Err(HsmError::EncryptedDataLenRange);
    }
    if body.len() - tag_len > AES_GCM_SINGLE_SHOT_MAX {
        return Err(HsmError::EncryptedDataLenRange);
    }
    open(key, &iv, &params.aad, tag_len, body)
}

// ============================================================================
// AES-CBC policy
// ============================================================================

/// AES-CBC encryption policy. `padding == false` is `CKM_AES_CBC` (input
/// must be block aligned); `true` is `CKM_AES_CBC_PAD` (PKCS#7).
pub fn cbc_encrypt_with(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    padding: bool,
    raw: impl FnOnce(&[u8], &[u8; 16], &[u8], bool) -> HsmResult<Vec<u8>>,
) -> HsmResult<Vec<u8>> {
    check_aes_key(key)?;
    if plaintext.len() > AES_CBC_CTR_MAX_PLAINTEXT {
        return Err(HsmError::DataLenRange);
    }
    if !padding && plaintext.len() % 16 != 0 {
        return Err(HsmError::DataLenRange);
    }
    let iv: [u8; 16] = iv.try_into().map_err(|_| HsmError::MechanismParamInvalid)?;
    // An all-zero IV almost always indicates an uninitialised buffer.
    if iv.iter().all(|&b| b == 0) {
        tracing::error!("AES-CBC encrypt rejected: all-zero IV");
        return Err(HsmError::MechanismParamInvalid);
    }
    let kid = key_id(key);
    with_key_state(&kid, |st| {
        if st.cbc_ivs.insert(iv) {
            Ok(())
        } else {
            tracing::error!("AES-CBC: IV reuse with the same key rejected");
            Err(HsmError::MechanismParamInvalid)
        }
    })?;
    raw(key, &iv, plaintext, padding)
}

/// AES-CBC decryption policy.
///
/// For `CKM_AES_CBC_PAD`, success versus `CKR_ENCRYPTED_DATA_INVALID` is an
/// inherent padding oracle of the mechanism; applications must authenticate
/// ciphertexts (or use AES-GCM).
pub fn cbc_decrypt_with(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    padding: bool,
    raw: impl FnOnce(&[u8], &[u8; 16], &[u8], bool) -> HsmResult<Zeroizing<Vec<u8>>>,
) -> HsmResult<Zeroizing<Vec<u8>>> {
    check_aes_key(key)?;
    let iv: [u8; 16] = iv.try_into().map_err(|_| HsmError::MechanismParamInvalid)?;
    if ciphertext.len() > AES_CBC_CTR_MAX_PLAINTEXT + 16
        || ciphertext.len() % 16 != 0
        || (padding && ciphertext.is_empty())
    {
        return Err(HsmError::EncryptedDataLenRange);
    }
    raw(key, &iv, ciphertext, padding)
}

// ============================================================================
// AES-CTR policy
// ============================================================================

fn ctr_blocks(len: usize) -> u128 {
    (len as u128).div_ceil(16)
}

/// Record the keystream range `[start, end)`; fails on overlap.
fn ctr_record_range(ranges: &mut BTreeMap<u128, u128>, start: u128, end: u128) -> HsmResult<()> {
    if start == end {
        return Ok(());
    }
    // Any existing range starting before `end` that ends after `start`?
    if let Some((_, &prev_end)) = ranges.range(..end).next_back() {
        if prev_end > start {
            return Err(HsmError::MechanismParamInvalid);
        }
    }
    let (mut new_start, mut new_end) = (start, end);
    // Merge with an adjacent predecessor / successor.
    if let Some((&s, &e)) = ranges.range(..start).next_back() {
        if e == start {
            ranges.remove(&s);
            new_start = s;
        }
    }
    if let Some(&e) = ranges.get(&end) {
        ranges.remove(&end);
        new_end = e;
    }
    if ranges.len() >= CTR_MAX_RANGES_PER_KEY {
        tracing::error!("AES-CTR: too many disjoint counter ranges for this key — rotate the key");
        return Err(HsmError::KeyFunctionNotPermitted);
    }
    ranges.insert(new_start, new_end);
    Ok(())
}

fn ctr_validate(key: &[u8], params: &CtrParams, len: usize) -> HsmResult<(u128, u128)> {
    check_aes_key(key)?;
    if len > AES_CBC_CTR_MAX_PLAINTEXT {
        return Err(HsmError::DataLenRange);
    }
    if params.cb.iter().all(|&b| b == 0) {
        tracing::error!("AES-CTR rejected: all-zero counter block");
        return Err(HsmError::MechanismParamInvalid);
    }
    let blocks = ctr_blocks(len);
    if blocks > params.blocks_available() {
        tracing::error!(
            "AES-CTR: data would wrap the {}-bit counter field",
            params.counter_bits
        );
        return Err(HsmError::DataLenRange);
    }
    let start = u128::from_be_bytes(params.cb);
    Ok((start, start + blocks))
}

/// AES-CTR encryption policy (counter-field overflow + keystream range
/// overlap detection).
pub fn ctr_encrypt_with(
    key: &[u8],
    params: &CtrParams,
    plaintext: &[u8],
    raw: impl FnOnce(&[u8], &[u8; 16], &[u8]) -> HsmResult<Vec<u8>>,
) -> HsmResult<Vec<u8>> {
    let (start, end) = ctr_validate(key, params, plaintext.len())?;
    let kid = key_id(key);
    with_key_state(&kid, |st| {
        ctr_record_range(&mut st.ctr_ranges, start, end).map_err(|e| {
            if matches!(e, HsmError::MechanismParamInvalid) {
                tracing::error!("AES-CTR: keystream reuse (overlapping counter range) rejected");
            }
            e
        })
    })?;
    raw(key, &params.cb, plaintext)
}

/// AES-CTR decryption policy (no reuse tracking: decryption must reuse the
/// encryption counter block).
pub fn ctr_decrypt_with(
    key: &[u8],
    params: &CtrParams,
    ciphertext: &[u8],
    raw: impl FnOnce(&[u8], &[u8; 16], &[u8]) -> HsmResult<Vec<u8>>,
) -> HsmResult<Zeroizing<Vec<u8>>> {
    ctr_validate(key, params, ciphertext.len())?;
    raw(key, &params.cb, ciphertext).map(Zeroizing::new)
}

// ============================================================================
// RustCrypto primitives (no policy)
// ============================================================================

macro_rules! gcm_dispatch {
    ($key:expr, $tag_len:expr, $f:ident, $($arg:expr),*) => {
        match ($key.len(), $tag_len) {
            (16, 12) => $f::<AesGcm<aes::Aes128, U12, U12>>($key, $($arg),*),
            (16, 13) => $f::<AesGcm<aes::Aes128, U12, U13>>($key, $($arg),*),
            (16, 14) => $f::<AesGcm<aes::Aes128, U12, U14>>($key, $($arg),*),
            (16, 15) => $f::<AesGcm<aes::Aes128, U12, U15>>($key, $($arg),*),
            (16, 16) => $f::<AesGcm<aes::Aes128, U12, U16>>($key, $($arg),*),
            (24, 12) => $f::<AesGcm<aes::Aes192, U12, U12>>($key, $($arg),*),
            (24, 13) => $f::<AesGcm<aes::Aes192, U12, U13>>($key, $($arg),*),
            (24, 14) => $f::<AesGcm<aes::Aes192, U12, U14>>($key, $($arg),*),
            (24, 15) => $f::<AesGcm<aes::Aes192, U12, U15>>($key, $($arg),*),
            (24, 16) => $f::<AesGcm<aes::Aes192, U12, U16>>($key, $($arg),*),
            (32, 12) => $f::<AesGcm<aes::Aes256, U12, U12>>($key, $($arg),*),
            (32, 13) => $f::<AesGcm<aes::Aes256, U12, U13>>($key, $($arg),*),
            (32, 14) => $f::<AesGcm<aes::Aes256, U12, U14>>($key, $($arg),*),
            (32, 15) => $f::<AesGcm<aes::Aes256, U12, U15>>($key, $($arg),*),
            (32, 16) => $f::<AesGcm<aes::Aes256, U12, U16>>($key, $($arg),*),
            (16 | 24 | 32, _) => Err(HsmError::MechanismParamInvalid),
            _ => Err(HsmError::KeySizeRange),
        }
    };
}

fn gcm_seal_generic<C: AeadInPlace + KeyInit>(
    key: &[u8],
    iv: &[u8; GCM_IV_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> HsmResult<Vec<u8>>
where
    C: aes_gcm::aead::AeadCore<NonceSize = U12>,
{
    let cipher = C::new_from_slice(key).map_err(|_| HsmError::KeySizeRange)?;
    let mut buf = Vec::with_capacity(plaintext.len() + 16);
    buf.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(iv), aad, &mut buf)
        .map_err(|_| {
            HsmError::DataLenRange
        })?;
    buf.extend_from_slice(&tag);
    Ok(buf)
}

fn gcm_open_generic<C: AeadInPlace + KeyInit>(
    key: &[u8],
    iv: &[u8; GCM_IV_LEN],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> HsmResult<Zeroizing<Vec<u8>>>
where
    C: aes_gcm::aead::AeadCore<NonceSize = U12>,
{
    let cipher = C::new_from_slice(key).map_err(|_| HsmError::KeySizeRange)?;
    let tag_len = <C as aes_gcm::aead::AeadCore>::TagSize::to_usize();
    if ct_and_tag.len() < tag_len {
        return Err(HsmError::EncryptedDataLenRange);
    }
    let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - tag_len);
    let mut buf = Zeroizing::new(ct.to_vec());
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(iv),
            aad,
            &mut buf,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| HsmError::EncryptedDataInvalid)?;
    Ok(buf)
}

use aes_gcm::aead::generic_array::typenum::Unsigned;

/// AES-GCM seal (RustCrypto): returns `ciphertext || tag`. Key sizes
/// 128/192/256, tag lengths 12..=16 bytes, 96-bit IV.
pub fn aes_gcm_seal_raw(
    key: &[u8],
    iv: &[u8; GCM_IV_LEN],
    aad: &[u8],
    tag_len: usize,
    plaintext: &[u8],
) -> HsmResult<Vec<u8>> {
    gcm_dispatch!(key, tag_len, gcm_seal_generic, iv, aad, plaintext)
}

/// AES-GCM open (RustCrypto): input `ciphertext || tag`.
pub fn aes_gcm_open_raw(
    key: &[u8],
    iv: &[u8; GCM_IV_LEN],
    aad: &[u8],
    tag_len: usize,
    ct_and_tag: &[u8],
) -> HsmResult<Zeroizing<Vec<u8>>> {
    gcm_dispatch!(key, tag_len, gcm_open_generic, iv, aad, ct_and_tag)
}

/// AES-CBC encrypt (RustCrypto, no policy).
pub fn aes_cbc_encrypt_raw(
    key: &[u8],
    iv: &[u8; 16],
    plaintext: &[u8],
    padding: bool,
) -> HsmResult<Vec<u8>> {
    use cbc::cipher::block_padding::{NoPadding, Pkcs7};
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    macro_rules! enc {
        ($aes:ty) => {{
            let e = cbc::Encryptor::<$aes>::new_from_slices(key, iv)
                .map_err(|_| HsmError::KeySizeRange)?;
            if padding {
                Ok(e.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
            } else {
                if plaintext.len() % 16 != 0 {
                    return Err(HsmError::DataLenRange);
                }
                Ok(e.encrypt_padded_vec_mut::<NoPadding>(plaintext))
            }
        }};
    }
    match key.len() {
        16 => enc!(aes::Aes128),
        24 => enc!(aes::Aes192),
        32 => enc!(aes::Aes256),
        _ => Err(HsmError::KeySizeRange),
    }
}

/// AES-CBC decrypt (RustCrypto, no policy). All padding / format failures
/// map to the same error.
pub fn aes_cbc_decrypt_raw(
    key: &[u8],
    iv: &[u8; 16],
    ciphertext: &[u8],
    padding: bool,
) -> HsmResult<Zeroizing<Vec<u8>>> {
    use cbc::cipher::block_padding::{NoPadding, Pkcs7};
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    if ciphertext.len() % 16 != 0 {
        return Err(HsmError::EncryptedDataLenRange);
    }
    macro_rules! dec {
        ($aes:ty) => {{
            let d = cbc::Decryptor::<$aes>::new_from_slices(key, iv)
                .map_err(|_| HsmError::KeySizeRange)?;
            // Decrypt in a zeroizing buffer so rejected plaintext never
            // lingers in freed memory.
            let mut buf = Zeroizing::new(ciphertext.to_vec());
            let n = if padding {
                d.decrypt_padded_mut::<Pkcs7>(&mut buf)
                    .map_err(|_| HsmError::EncryptedDataInvalid)?
                    .len()
            } else {
                d.decrypt_padded_mut::<NoPadding>(&mut buf)
                    .map_err(|_| HsmError::EncryptedDataInvalid)?
                    .len()
            };
            buf[n..].zeroize();
            buf.truncate(n);
            Ok(buf)
        }};
    }
    match key.len() {
        16 => dec!(aes::Aes128),
        24 => dec!(aes::Aes192),
        32 => dec!(aes::Aes256),
        _ => Err(HsmError::KeySizeRange),
    }
}

/// AES-CTR keystream application (RustCrypto, no policy; 128-bit
/// big-endian counter).
pub fn aes_ctr_apply_raw(key: &[u8], iv: &[u8; 16], data: &[u8]) -> HsmResult<Vec<u8>> {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    let mut output = data.to_vec();
    macro_rules! apply {
        ($aes:ty) => {{
            let mut c = ctr::Ctr128BE::<$aes>::new_from_slices(key, iv)
                .map_err(|_| HsmError::KeySizeRange)?;
            c.apply_keystream(&mut output);
        }};
    }
    match key.len() {
        16 => apply!(aes::Aes128),
        24 => apply!(aes::Aes192),
        32 => apply!(aes::Aes256),
        _ => return Err(HsmError::KeySizeRange),
    }
    Ok(output)
}

// ============================================================================
// Convenience wrappers over the RustCrypto primitives (policy applied)
// ============================================================================

/// AES-GCM encrypt with a module-generated IV using the deprecated framing
/// `IV || ciphertext || tag` (convenience for internal callers and tests;
/// the PKCS#11 path uses [`gcm_encrypt_with`] with `CK_GCM_PARAMS`).
pub fn aes_256_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
    gcm_encrypt_with(
        key,
        &GcmParams::legacy(gcm_generate_iv()?),
        plaintext,
        false,
        aes_gcm_seal_raw,
    )
}

/// Inverse of [`aes_256_gcm_encrypt`].
pub fn aes_256_gcm_decrypt(key: &[u8], data: &[u8]) -> HsmResult<Zeroizing<Vec<u8>>> {
    gcm_decrypt_with(
        key,
        &GcmParams::legacy([0u8; GCM_IV_LEN]),
        data,
        aes_gcm_open_raw,
    )
}

/// AES-CBC-PAD (PKCS#7) encrypt with policy checks.
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
    cbc_encrypt_with(key, iv, plaintext, true, aes_cbc_encrypt_raw)
}

/// AES-CBC-PAD (PKCS#7) decrypt.
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Zeroizing<Vec<u8>>> {
    cbc_decrypt_with(key, iv, ciphertext, true, aes_cbc_decrypt_raw)
}

/// AES-CBC encrypt, explicit padding choice (`false` = `CKM_AES_CBC`).
pub fn aes_cbc_encrypt_with_padding(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    padding: bool,
) -> HsmResult<Vec<u8>> {
    cbc_encrypt_with(key, iv, plaintext, padding, aes_cbc_encrypt_raw)
}

/// AES-CBC decrypt, explicit padding choice (`false` = `CKM_AES_CBC`).
pub fn aes_cbc_decrypt_with_padding(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    padding: bool,
) -> HsmResult<Zeroizing<Vec<u8>>> {
    cbc_decrypt_with(key, iv, ciphertext, padding, aes_cbc_decrypt_raw)
}

/// AES-CTR encrypt with a 16-byte counter block (128-bit counter) and
/// keystream-reuse detection.
pub fn aes_ctr_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
    let params = CtrParams::from_legacy_iv(iv)?;
    ctr_encrypt_with(key, &params, plaintext, aes_ctr_apply_raw)
}

/// AES-CTR decrypt with a 16-byte counter block.
pub fn aes_ctr_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Zeroizing<Vec<u8>>> {
    let params = CtrParams::from_legacy_iv(iv)?;
    ctr_decrypt_with(key, &params, ciphertext, aes_ctr_apply_raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_key() -> Vec<u8> {
        let mut k = vec![0u8; 32];
        crate::crypto::drbg::fill_random(&mut k).unwrap();
        k
    }

    #[test]
    fn gcm_aad_is_authenticated() {
        let key = fresh_key();
        let p = GcmParams::new(&[9u8; 12], b"context A", 128, false).unwrap();
        let ct = gcm_encrypt_with(&key, &p, b"secret", false, aes_gcm_seal_raw).unwrap();
        assert_eq!(ct.len(), 6 + 16);
        let pt = gcm_decrypt_with(&key, &p, &ct, aes_gcm_open_raw).unwrap();
        assert_eq!(&pt[..], b"secret");
        let other = GcmParams::new(&[9u8; 12], b"context B", 128, false).unwrap();
        assert!(matches!(
            gcm_decrypt_with(&key, &other, &ct, aes_gcm_open_raw),
            Err(HsmError::EncryptedDataInvalid)
        ));
    }

    #[test]
    fn gcm_truncated_tags_and_key_sizes() {
        for klen in [16usize, 24, 32] {
            let key = vec![0x11u8; klen];
            for bits in [96u32, 104, 112, 120, 128] {
                let iv = gcm_generate_iv().unwrap();
                let p = GcmParams::new(&iv, b"a", bits as _, true).unwrap();
                let ct = gcm_encrypt_with(&key, &p, b"hello", true, aes_gcm_seal_raw).unwrap();
                assert_eq!(ct.len(), 5 + (bits / 8) as usize);
                let pt = gcm_decrypt_with(&key, &p, &ct, aes_gcm_open_raw).unwrap();
                assert_eq!(&pt[..], b"hello");
            }
        }
    }

    #[test]
    fn gcm_iv_reuse_and_fips_caller_iv_rejected() {
        let key = fresh_key();
        let p = GcmParams::new(&[3u8; 12], b"", 128, false).unwrap();
        gcm_encrypt_with(&key, &p, b"one", false, aes_gcm_seal_raw).unwrap();
        assert!(gcm_encrypt_with(&key, &p, b"two", false, aes_gcm_seal_raw).is_err());
        let p2 = GcmParams::new(&[4u8; 12], b"", 128, false).unwrap();
        assert!(gcm_encrypt_with(&key, &p2, b"x", true, aes_gcm_seal_raw).is_err());
    }

    #[test]
    fn gcm_legacy_framing_roundtrip() {
        let key = fresh_key();
        let ct = aes_256_gcm_encrypt(&key, b"legacy").unwrap();
        assert_eq!(ct.len(), 12 + 6 + 16);
        assert_eq!(&aes_256_gcm_decrypt(&key, &ct).unwrap()[..], b"legacy");
    }

    #[test]
    fn cbc_unpadded_vs_padded() {
        let key = fresh_key();
        let iv = [7u8; 16];
        let ct = aes_cbc_encrypt_with_padding(&key, &iv, &[1u8; 32], false).unwrap();
        assert_eq!(ct.len(), 32, "CKM_AES_CBC must not add a padding block");
        assert!(aes_cbc_encrypt_with_padding(&key, &[8u8; 16], &[1u8; 31], false).is_err());
        let pt = aes_cbc_decrypt_with_padding(&key, &iv, &ct, false).unwrap();
        assert_eq!(&pt[..], &[1u8; 32]);
        let ct2 = aes_cbc_encrypt_with_padding(&key, &[9u8; 16], &[1u8; 32], true).unwrap();
        assert_eq!(ct2.len(), 48);
    }

    #[test]
    fn ctr_overlapping_ranges_rejected() {
        let key = fresh_key();
        let mut iv = [0u8; 16];
        iv[15] = 1;
        aes_ctr_encrypt(&key, &iv, &[0u8; 32]).unwrap(); // blocks 1,2
        let mut iv2 = iv;
        iv2[15] = 2; // overlaps block 2
        assert!(aes_ctr_encrypt(&key, &iv2, &[0u8; 16]).is_err());
        let mut iv3 = iv;
        iv3[15] = 3; // adjacent, fine
        aes_ctr_encrypt(&key, &iv3, &[0u8; 16]).unwrap();
    }

    #[test]
    fn ctr_counter_bits_enforced() {
        let key = fresh_key();
        let mut cb = [0x55u8; 16];
        cb[15] = 0xFF;
        let p = CtrParams::new(8, &cb).unwrap();
        // Only one block left in an 8-bit counter field.
        assert!(ctr_encrypt_with(&key, &p, &[0u8; 17], aes_ctr_apply_raw).is_err());
        ctr_encrypt_with(&key, &p, &[0u8; 16], aes_ctr_apply_raw).unwrap();
    }

    #[test]
    fn range_merge() {
        let mut r = BTreeMap::new();
        ctr_record_range(&mut r, 10, 20).unwrap();
        ctr_record_range(&mut r, 20, 30).unwrap();
        ctr_record_range(&mut r, 0, 10).unwrap();
        assert_eq!(r.len(), 1);
        assert!(ctr_record_range(&mut r, 29, 31).is_err());
        assert!(ctr_record_range(&mut r, 5, 6).is_err());
    }
}
