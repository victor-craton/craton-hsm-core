// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
#![deny(unsafe_op_in_unsafe_fn)]
// PKCS#11 C ABI exports — all exported functions with #[no_mangle].
// Every function uses catch_unwind at the FFI boundary to prevent panics
// from crossing into C code (undefined behavior).
//
// # Safety — Unsafe Code in This Module
//
// All unsafe code in this module falls into a small number of patterns,
// all at the PKCS#11 C ABI boundary. No unsafe exists in crypto paths.
//
// **Pattern 1 — Dereferencing caller-provided output pointers:**
//   `unsafe { *p_info = info; }` or `unsafe { *pul_count = n; }`
//   SAFETY: The PKCS#11 spec requires the caller to provide valid, aligned,
//   writable pointers for output parameters. Null checks are performed where
//   specified by the spec. The function signature guarantees size/alignment.
//
// **Pattern 2 — Constructing slices from (pointer, length) pairs:**
//   `unsafe { slice::from_raw_parts(ptr, len) }` / `from_raw_parts_mut`
//   SAFETY: The PKCS#11 caller is required to provide a valid buffer of at
//   least `len` bytes. Null pointer checks are done before slice construction.
//   The resulting slice borrows for the duration of the function call only.
//
// **Pattern 3 — Reading CK_MECHANISM through a raw pointer:**
//   `unsafe { (*p_mechanism).mechanism }`
//   SAFETY: p_mechanism is checked for null before dereferencing. The caller
//   must provide a valid, aligned CK_MECHANISM struct per PKCS#11 spec.
//
// **Pattern 4 — Casting CK_C_INITIALIZE_ARGS pointer:**
//   `unsafe { &*(p_init_args as *const CK_C_INITIALIZE_ARGS) }`
//   SAFETY: Only performed after null check. The caller must pass a valid
//   CK_C_INITIALIZE_ARGS struct or NULL per PKCS#11 §5.10.
//
// **Pattern 5 — Multi-field struct dereference in extract_mechanism_param:**
//   `unsafe { let mech = &*p_mechanism; ... slice::from_raw_parts(...) }`
//   SAFETY: p_mechanism validity ensured by Pattern 3 guard. The p_parameter
//   field and parameter_len are checked before slice construction.
//
// **Pattern 6 — Dual output pointer dereference in C_GenerateKeyPair:**
//   `unsafe { *ph_public_key = pub_handle; *ph_private_key = priv_handle; }`
//   SAFETY: Both output pointers are checked for null at function entry.
//   The caller must provide valid, aligned, writable CK_OBJECT_HANDLE pointers.
//
// Every exported function is itself `pub unsafe extern "C" fn` with a
// `# Safety` section (H1-22): calling it from Rust is only sound when the
// caller upholds the PKCS#11 pointer contract. Helpers that dereference raw
// pointers are `unsafe fn` as well.

use std::cell::RefCell;
use std::collections::HashSet;
use std::panic::catch_unwind;
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use crate::audit::log::{AuditOperation, AuditResult};
use crate::core::HsmCore;
use crate::crypto::backend::CryptoBackend;
use crate::crypto::{mechanisms, pairwise_test, pqc, sign};
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::*;
use crate::session::session::{
    ActiveOperation, FindContext, MessageOperation, Session, SignParams, OP_STATE_MAX_DATA_LEN,
    OP_TYPE_DECRYPT, OP_TYPE_DIGEST, OP_TYPE_ENCRYPT, OP_TYPE_SIGN, OP_TYPE_VERIFY,
};
use crate::store::attributes::ObjectOrigin;
use crate::store::key_material::RawKeyMaterial;
use crate::store::object::{KeyLifecycleState, KeyUsage, StoredObject};
use zeroize::Zeroizing;

/// Global singleton — PKCS#11 §5.10 requires exactly one `C_Initialize` / `C_Finalize`
/// pair per process. Uses `Mutex<Option<...>>` so `C_Finalize` can reset the state,
/// allowing a subsequent `C_Initialize` to succeed (required by PKCS#11 spec).
///
/// Uses `parking_lot::Mutex` for lower uncontended overhead (spin-then-park
/// instead of immediate syscall). No poisoning — panics are caught by `catch_unwind`.
static HSM: parking_lot::Mutex<Option<Arc<HsmCore>>> = parking_lot::Mutex::new(None);
static POST_FAILED: AtomicBool = AtomicBool::new(false);

/// Generation counter — bumped on every C_Initialize / C_Finalize to invalidate
/// thread-local caches of the HSM reference.
static HSM_GENERATION: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Thread-local cache of the HSM to avoid a mutex lock on every C_* call.
    /// Stores `(Weak<HsmCore>, generation)`: a *weak* reference, so that
    /// `C_Finalize` really releases (and zeroizes) the core even while other
    /// threads still have a cache entry (A1-10 / H1-25). Invalidated when the
    /// generation changes or the core has been finalized.
    static CACHED_HSM: RefCell<Option<(Weak<HsmCore>, u64)>> = const { RefCell::new(None) };
}
/// Maximum bytes that multi-part Update functions may accumulate before
/// returning CKR_DATA_LEN_RANGE.  64 MiB is generous for any realistic
/// HSM workload while still bounding memory consumption.
const MAX_MULTIPART_ACCUMULATION: usize = 64 * 1024 * 1024;
/// Maximum PIN length in bytes. Defense-in-depth bound to prevent
/// `slice::from_raw_parts` with a caller-supplied length that exceeds
/// the actual allocation. 256 bytes is far above any realistic PIN.
const MAX_PIN_BYTES: usize = 256;
/// Maximum single-shot data buffer (encrypt/decrypt/sign/verify input).
/// Same as multi-part bound — 64 MiB.
const MAX_SINGLE_BUFFER: usize = 64 * 1024 * 1024;
/// Maximum number of attributes in a template. Defense-in-depth bound
/// to prevent `slice::from_raw_parts` with a caller-supplied count that
/// exceeds the actual allocation. 256 attributes is far above any
/// realistic PKCS#11 template.
const MAX_TEMPLATE_ATTRS: usize = 256;
/// Maximum size of a single attribute value in bytes. Defense-in-depth
/// bound to prevent `slice::from_raw_parts` with a bogus `value_len`
/// that exceeds the actual allocation. 64 KiB is far above any
/// realistic PKCS#11 attribute (RSA-4096 modulus is 512 bytes, PQC
/// keys are a few KiB).
const MAX_ATTR_VALUE_LEN: usize = 64 * 1024;
/// PID recorded at C_Initialize time; used for fork detection on Unix.
static INIT_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Get the current process ID (portable).
fn current_pid() -> u32 {
    #[cfg(unix)]
    {
        (unsafe { libc::getpid() }) as u32
    }
    #[cfg(windows)]
    {
        unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() }
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Fork detection unavailable on this platform (e.g., WASM).
        // PID 0 disables the init_pid != current_pid() check in get_hsm().
        use std::sync::Once;
        static WARN_ONCE: Once = Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!("Fork detection unavailable: unsupported platform (not unix/windows)");
        });
        0
    }
}

/// Check if FIPS POST (or conditional self-test) has failed.
/// Used by integration tests to verify error state behavior.
pub fn is_post_failed() -> bool {
    POST_FAILED.load(Ordering::Acquire)
}

fn get_hsm() -> Result<Arc<HsmCore>, CK_RV> {
    if POST_FAILED.load(Ordering::Acquire) || crate::crypto::self_test::is_error_state() {
        return Err(CKR_GENERAL_ERROR);
    }

    // Fork detection: if the current PID differs from the PID at init time,
    // this process is a fork child that inherited stale state.
    // PKCS#11 §5.10: the child must call C_Initialize before using the library.
    let init_pid = INIT_PID.load(Ordering::Acquire);
    if init_pid != 0 && init_pid != current_pid() {
        CACHED_HSM.with(|c| *c.borrow_mut() = None);
        tracing::error!(
            "Fork detected: initialized in PID {} but running in PID {}. \
             The child process must call C_Initialize.",
            init_pid,
            current_pid()
        );
        return Err(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    // Fast path: check thread-local cache (avoids mutex lock on every C_* call).
    let current_gen = HSM_GENERATION.load(Ordering::Acquire);
    let cached = CACHED_HSM.with(|c| {
        let borrow = c.borrow();
        match &*borrow {
            Some((weak, gen)) if *gen == current_gen => weak.upgrade(),
            _ => None,
        }
    });
    if let Some(hsm) = cached {
        if !hsm.is_finalized() {
            return Ok(hsm);
        }
    }

    // Slow path: lock mutex, clone Arc, cache a weak reference in TLS.
    let hsm = {
        let guard = HSM.lock();
        guard.as_ref().cloned()
    };
    let hsm = match hsm {
        // A finalized core must never serve requests (A1-10).
        Some(h) if !h.is_finalized() => h,
        _ => {
            CACHED_HSM.with(|c| *c.borrow_mut() = None);
            return Err(CKR_CRYPTOKI_NOT_INITIALIZED);
        }
    };
    CACHED_HSM.with(|c| {
        *c.borrow_mut() = Some((Arc::downgrade(&hsm), current_gen));
    });
    Ok(hsm)
}

/// Like [`get_hsm`] but also validates the session handle, so that stubs
/// report `CKR_CRYPTOKI_NOT_INITIALIZED` / `CKR_SESSION_HANDLE_INVALID`
/// before `CKR_FUNCTION_NOT_SUPPORTED` (A2-22).
fn check_session_only(session: CK_SESSION_HANDLE) -> CK_RV {
    let hsm = match get_hsm() {
        Ok(h) => h,
        Err(rv) => return rv,
    };
    match hsm.session_manager.get_session(session) {
        Ok(_) => CKR_OK,
        Err(e) => err_to_rv(e),
    }
}

// ---------------------------------------------------------------------------
// Audit (H3-11 / A3-20): security-relevant events are recorded; with
// `audit.fail_closed = true` an unusable audit trail makes the operation fail
// with CKR_DEVICE_ERROR (checked before the operation and again when the
// event is written).
// ---------------------------------------------------------------------------

/// Refuse a security-relevant operation up front when the audit trail is
/// unusable in fail-closed mode.
fn audit_gate(hsm: &HsmCore) -> Result<(), CK_RV> {
    hsm.audit_log.check_healthy().map_err(|_| CKR_DEVICE_ERROR)
}

fn audit_result(rv: CK_RV) -> AuditResult {
    if rv == CKR_OK {
        AuditResult::Success
    } else {
        AuditResult::Failure(rv as u64)
    }
}

fn audit_policy(hsm: &HsmCore, r: HsmResult<()>) -> Result<(), CK_RV> {
    match r {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::error!("audit event could not be recorded: {:?}", e);
            // Fail closed only when configured (check_healthy is Ok in
            // fail-open mode).
            audit_gate(hsm)
        }
    }
}

/// Record an audit event (asynchronous; used for routine crypto operations).
fn audit(
    hsm: &HsmCore,
    session: CK_SESSION_HANDLE,
    op: AuditOperation,
    result: AuditResult,
) -> Result<(), CK_RV> {
    audit_policy(hsm, hsm.audit_log.record(session as u64, op, result, None))
}

/// Record an audit event durably (key management, object management).
fn audit_sync(
    hsm: &HsmCore,
    session: CK_SESSION_HANDLE,
    op: AuditOperation,
    result: AuditResult,
    key_id: Option<String>,
) -> Result<(), CK_RV> {
    audit_policy(
        hsm,
        hsm.audit_log
            .record_sync(session as u64, op, result, key_id),
    )
}

// ---------------------------------------------------------------------------
// Caller buffers (H1-23): lengths are checked against a bound *before* a
// slice is built from them.
// ---------------------------------------------------------------------------

/// Build an input slice from a caller `(pointer, length)` pair.
///
/// Returns `err` if the length exceeds `max`, and `CKR_ARGUMENTS_BAD` for a
/// NULL pointer with a non-zero length.
///
/// # Safety
/// When `p` is non-null it must point to `len` readable bytes that stay
/// valid and unmodified for the lifetime `'a`.
unsafe fn caller_slice<'a>(
    p: *const u8,
    len: CK_ULONG,
    max: usize,
    err: CK_RV,
) -> Result<&'a [u8], CK_RV> {
    let len = usize::try_from(len).map_err(|_| err)?;
    if len > max {
        return Err(err);
    }
    if len == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: non-null, length bounded, validity per the function contract.
    Ok(unsafe { slice::from_raw_parts(p, len) })
}

// ---------------------------------------------------------------------------
// Central key-use authorization (H1-03/04/10/11/12/15/20, A1-30).
// ---------------------------------------------------------------------------

/// Map a lifecycle / usage error to its PKCS#11 return value.
fn usage_rv(e: HsmError) -> CK_RV {
    match e {
        HsmError::ObjectHandleInvalid => CKR_KEY_HANDLE_INVALID,
        _ => CKR_KEY_FUNCTION_NOT_PERMITTED,
    }
}

/// Key type (and, for asymmetric algorithms, class) that `mechanism`
/// requires for `usage`. `None` means the mechanism imposes no constraint.
fn required_key(
    mechanism: CK_MECHANISM_TYPE,
    usage: KeyUsage,
) -> Option<(CK_OBJECT_CLASS, CK_KEY_TYPE)> {
    let asym_class = match usage {
        KeyUsage::Sign | KeyUsage::Decrypt | KeyUsage::Unwrap | KeyUsage::Derive => CKO_PRIVATE_KEY,
        KeyUsage::Verify | KeyUsage::Encrypt | KeyUsage::Wrap => CKO_PUBLIC_KEY,
    };
    let kt = match mechanism {
        CKM_AES_GCM | CKM_AES_CBC | CKM_AES_CBC_PAD | CKM_AES_CTR | CKM_AES_KEY_WRAP
        | CKM_AES_KEY_WRAP_KWP => return Some((CKO_SECRET_KEY, CKK_AES)),
        CKM_RSA_PKCS
        | CKM_SHA256_RSA_PKCS
        | CKM_SHA384_RSA_PKCS
        | CKM_SHA512_RSA_PKCS
        | CKM_RSA_PKCS_PSS
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA512_RSA_PKCS_PSS
        | CKM_RSA_PKCS_OAEP => CKK_RSA,
        CKM_ECDSA
        | CKM_ECDSA_SHA256
        | CKM_ECDSA_SHA384
        | CKM_ECDSA_SHA512
        | CKM_ECDH1_DERIVE
        | CKM_ECDH1_COFACTOR_DERIVE => CKK_EC,
        CKM_EDDSA => CKK_EC_EDWARDS,
        m if pqc::is_ml_dsa_mechanism(m) => CKK_ML_DSA,
        m if pqc::is_slh_dsa_mechanism(m) => CKK_SLH_DSA,
        m if pqc::is_ml_kem_mechanism(m) => CKK_ML_KEM,
        _ => return None,
    };
    Some((asym_class, kt))
}

/// `CKR_KEY_TYPE_INCONSISTENT` unless the key's class and type fit the
/// mechanism (cross-algorithm key use, H1-15 / A1-30).
fn check_key_type(
    mechanism: CK_MECHANISM_TYPE,
    usage: KeyUsage,
    obj: &StoredObject,
) -> Result<(), CK_RV> {
    if let Some((class, key_type)) = required_key(mechanism, usage) {
        if obj.class != class || obj.key_type != Some(key_type) {
            tracing::warn!(
                "key class/type 0x{:x}/{:?} inconsistent with mechanism 0x{:x}",
                obj.class,
                obj.key_type,
                mechanism
            );
            return Err(CKR_KEY_TYPE_INCONSISTENT);
        }
    }
    Ok(())
}

/// Visibility rule for objects (PKCS#11 §4.4, H1-05): private objects are
/// only accessible to the normal user.
fn check_visible(sess: &Session, obj: &StoredObject) -> Result<(), CK_RV> {
    if obj.private && !sess.state.is_user() {
        return Err(CKR_USER_NOT_LOGGED_IN);
    }
    Ok(())
}

/// The single key-use gate: visibility (login), usage attribute, SP 800-57
/// lifecycle, and key class/type versus mechanism. The slot is enforced by
/// `get_object_in_slot`.
fn authorize_key_use(
    sess: &Session,
    obj: &StoredObject,
    usage: KeyUsage,
    mechanism: CK_MECHANISM_TYPE,
) -> Result<(), CK_RV> {
    check_visible(sess, obj)?;
    let permitted = match usage {
        KeyUsage::Encrypt => obj.can_encrypt,
        KeyUsage::Decrypt => obj.can_decrypt,
        KeyUsage::Sign => obj.can_sign,
        KeyUsage::Verify => obj.can_verify,
        KeyUsage::Wrap => obj.can_wrap,
        KeyUsage::Unwrap => obj.can_unwrap,
        KeyUsage::Derive => obj.can_derive,
    };
    if !permitted {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    obj.check_usage(usage).map_err(usage_rv)?;
    check_key_type(mechanism, usage, obj)
}

/// `CKA_ALWAYS_AUTHENTICATE` of a private key (A2-20).
fn always_authenticate(obj: &StoredObject) -> bool {
    obj.class == CKO_PRIVATE_KEY
        && obj
            .extra_attributes
            .get(&CKA_ALWAYS_AUTHENTICATE)
            .is_some_and(|v| v.first().is_some_and(|b| *b != 0))
}

/// Binding authenticated into operation-state blobs (H1-04): a saved state
/// only restores into the same session of the same slot.
fn op_state_binding(session: CK_SESSION_HANDLE, slot: CK_SLOT_ID) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&(session as u64).to_le_bytes());
    b[8..].copy_from_slice(&(slot as u64).to_le_bytes());
    b
}

// ---------------------------------------------------------------------------
// Key-creation templates (H1-14 / H1-28): one strict parser for C_GenerateKey,
// C_GenerateKeyPair, C_UnwrapKey and C_DeriveKey. Attributes are typed and
// validated by the store's creation rules; unknown attributes are rejected,
// restrictive attributes are honoured, token-computed attributes are
// read-only, and attributes the token computes itself cannot be supplied.
// ---------------------------------------------------------------------------

/// Attributes whose value is produced by the key-generation / unwrap /
/// derive operation and therefore cannot appear in its template.
const COMPUTED_KEY_ATTRIBUTES: &[CK_ATTRIBUTE_TYPE] = &[
    CKA_VALUE,
    CKA_MODULUS,
    CKA_EC_POINT,
    CKA_PRIVATE_EXPONENT,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_COEFFICIENT,
    CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT,
    CKA_EC_PARAMS,
    CKA_VALUE_LEN,
];

/// Apply a key-creation template to `obj` (whose class, key type and
/// defaults are already set). Attributes listed in `handled` were consumed by
/// the caller (e.g. `CKA_VALUE_LEN`, `CKA_MODULUS_BITS`) and are skipped.
fn apply_key_template(
    obj: &mut StoredObject,
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    handled: &[CK_ATTRIBUTE_TYPE],
    is_so: bool,
) -> Result<(), CK_RV> {
    let mut seen = HashSet::with_capacity(template.len());
    for (attr_type, value) in template {
        let t = *attr_type;
        if !seen.insert(t) {
            return Err(CKR_TEMPLATE_INCONSISTENT);
        }
        if handled.contains(&t) {
            continue;
        }
        match t {
            CKA_CLASS => {
                if crate::store::attributes::read_ck_ulong(value) != Some(obj.class) {
                    return Err(CKR_TEMPLATE_INCONSISTENT);
                }
            }
            CKA_KEY_TYPE => {
                if crate::store::attributes::read_ck_ulong(value) != obj.key_type {
                    return Err(CKR_TEMPLATE_INCONSISTENT);
                }
            }
            CKA_ALWAYS_AUTHENTICATE => {
                let v = parse_ck_bbool(value)?;
                if obj.class != CKO_PRIVATE_KEY {
                    return Err(CKR_ATTRIBUTE_TYPE_INVALID);
                }
                if v {
                    obj.extra_attributes
                        .insert(CKA_ALWAYS_AUTHENTICATE, vec![1]);
                } else {
                    obj.extra_attributes.remove(&CKA_ALWAYS_AUTHENTICATE);
                }
            }
            t if COMPUTED_KEY_ATTRIBUTES.contains(&t) => {
                return Err(CKR_TEMPLATE_INCONSISTENT);
            }
            _ => crate::store::attributes::apply_attribute_ctx(obj, t, value, is_so)
                .map_err(err_to_rv)?,
        }
    }
    Ok(())
}

/// Parse a `CK_ULONG` attribute strictly (exact native size).
fn template_ulong(
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    attr: CK_ATTRIBUTE_TYPE,
) -> Result<Option<CK_ULONG>, CK_RV> {
    match template.iter().find(|(t, _)| *t == attr) {
        None => Ok(None),
        Some((_, v)) => crate::store::attributes::read_ck_ulong(v)
            .map(Some)
            .ok_or(CKR_ATTRIBUTE_VALUE_INVALID),
    }
}

/// Session requirements for creating an object (H1-10 / A2-21): token
/// objects need a read/write session; secret and private keys, and any
/// private object, need the normal user to be logged in.
fn check_create_allowed(sess: &Session, obj: &StoredObject) -> Result<(), CK_RV> {
    if obj.token_object && !sess.is_rw() {
        return Err(CKR_SESSION_READ_ONLY);
    }
    let secret = crate::store::object::is_secret_class(obj.class);
    if (secret || obj.private) && !sess.state.is_user() {
        return Err(CKR_USER_NOT_LOGGED_IN);
    }
    Ok(())
}

/// Helper: convert HsmError to CK_RV
fn err_to_rv(e: HsmError) -> CK_RV {
    e.into()
}

// ---------------------------------------------------------------------------
// Typed mechanism-parameter parsing (H1-16 / H2-22 / A2-09 / A2-12).
// Standard CK_*_PARAMS structures are parsed here, while their embedded
// pointers are valid (during *Init / C_DeriveKey), into the pointer-free
// canonical encodings of `crate::crypto::params`.
// ---------------------------------------------------------------------------

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Clone, Copy)]
struct CkGcmParams {
    p_iv: *mut u8,
    ul_iv_len: CK_ULONG,
    ul_iv_bits: CK_ULONG,
    p_aad: *const u8,
    ul_aad_len: CK_ULONG,
    ul_tag_bits: CK_ULONG,
}

/// Pre-v2.40 `CK_GCM_PARAMS` layout (no `ulIvBits`), still emitted by some
/// clients.
#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Clone, Copy)]
struct CkGcmParamsV230 {
    p_iv: *mut u8,
    ul_iv_len: CK_ULONG,
    p_aad: *const u8,
    ul_aad_len: CK_ULONG,
    ul_tag_bits: CK_ULONG,
}

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Clone, Copy)]
struct CkRsaPkcsOaepParams {
    hash_alg: CK_ULONG,
    mgf: CK_ULONG,
    source: CK_ULONG,
    p_source_data: *const u8,
    ul_source_data_len: CK_ULONG,
}

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Clone, Copy)]
struct CkRsaPkcsPssParams {
    hash_alg: CK_ULONG,
    mgf: CK_ULONG,
    s_len: CK_ULONG,
}

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Clone, Copy)]
struct CkAesCtrParams {
    ul_counter_bits: CK_ULONG,
    cb: [u8; 16],
}

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Clone, Copy)]
struct CkEcdh1DeriveParams {
    kdf: CK_ULONG,
    ul_shared_data_len: CK_ULONG,
    p_shared_data: *const u8,
    ul_public_data_len: CK_ULONG,
    p_public_data: *const u8,
}

/// Read a parameter struct `T` if `pParameter` is non-NULL and
/// `ulParameterLen == size_of::<T>()`.
///
/// SAFETY: `p_mechanism` must be a valid, non-null `CK_MECHANISM` pointer.
unsafe fn read_param_struct<T: Copy>(p_mechanism: CK_MECHANISM_PTR) -> Option<T> {
    // SAFETY: see function contract; the size is checked before reading.
    unsafe {
        let mech = &*p_mechanism;
        if mech.p_parameter.is_null() || mech.parameter_len as usize != std::mem::size_of::<T>() {
            return None;
        }
        Some(std::ptr::read_unaligned(mech.p_parameter as *const T))
    }
}

/// Copy a caller buffer referenced from inside a parameter struct.
///
/// SAFETY: the caller guarantees `p` points to `len` readable bytes when
/// non-null (PKCS#11 contract for mechanism parameters).
unsafe fn copy_param_bytes(p: *const u8, len: CK_ULONG) -> Result<Vec<u8>, CK_RV> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if p.is_null() || len as usize > MAX_SINGLE_BUFFER {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    // SAFETY: see function contract.
    Ok(unsafe { slice::from_raw_parts(p, len as usize) }.to_vec())
}

/// Parse and canonicalize the mechanism parameter of an encrypt/decrypt
/// operation at `C_EncryptInit` / `C_DecryptInit` time.
unsafe fn canonical_cipher_param(
    hsm: &HsmCore,
    p_mechanism: CK_MECHANISM_PTR,
    mechanism: CK_MECHANISM_TYPE,
    encrypt: bool,
) -> Result<Vec<u8>, CK_RV> {
    use crate::crypto::params::{CtrParams, GcmParams, OaepParams, GCM_IV_LEN};
    // SAFETY: p_mechanism is non-null (checked by the callers).
    let mech = unsafe { &*p_mechanism };
    let has_param = !mech.p_parameter.is_null() && mech.parameter_len != 0;
    match mechanism {
        CKM_AES_GCM => {
            if !has_param {
                // Deprecated vendor framing: module-generated IV per
                // operation, output IV || ciphertext || tag, no AAD.
                tracing::warn!(
                    "CKM_AES_GCM without CK_GCM_PARAMS: using deprecated IV||ct||tag framing"
                );
                return Ok(Vec::new());
            }
            if mech.parameter_len as usize == GCM_IV_LEN {
                // Compatibility form: the parameter is a bare 96-bit IV (no
                // AAD, 128-bit tag). Honoured as a caller IV; refused for
                // encryption in FIPS approved mode (IG C.H).
                let iv = unsafe { extract_mechanism_param(p_mechanism) }?;
                if encrypt && hsm.algorithm_config.fips_approved_only {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                return GcmParams::new(&iv, &[], 128, false)
                    .map(|p| p.encode())
                    .map_err(err_to_rv);
            }
            // SAFETY: size checked by read_param_struct.
            let (p_iv, iv_len, p_aad, aad_len, tag_bits) = if let Some(g) =
                unsafe { read_param_struct::<CkGcmParams>(p_mechanism) }
            {
                (g.p_iv, g.ul_iv_len, g.p_aad, g.ul_aad_len, g.ul_tag_bits)
            } else if let Some(g) = unsafe { read_param_struct::<CkGcmParamsV230>(p_mechanism) } {
                (g.p_iv, g.ul_iv_len, g.p_aad, g.ul_aad_len, g.ul_tag_bits)
            } else {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            };
            // SAFETY: pointers come from the caller's CK_GCM_PARAMS.
            let aad = unsafe { copy_param_bytes(p_aad, aad_len) }?;
            let params = if encrypt && hsm.algorithm_config.fips_approved_only {
                // FIPS 140-3 IG C.H: the IV is generated inside the module by
                // the approved DRBG and returned to the caller through pIv.
                if p_iv.is_null() || iv_len as usize != GCM_IV_LEN {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                let mut iv = [0u8; GCM_IV_LEN];
                hsm.crypto_backend
                    .generate_random(&mut iv)
                    .map_err(err_to_rv)?;
                // SAFETY: pIv is non-null and ulIvLen (== 12) bytes long.
                unsafe { std::ptr::copy_nonoverlapping(iv.as_ptr(), p_iv, GCM_IV_LEN) };
                GcmParams::new(&iv, &aad, tag_bits, true)
            } else {
                // SAFETY: as above.
                let iv = unsafe { copy_param_bytes(p_iv, iv_len) }?;
                GcmParams::new(&iv, &aad, tag_bits, false)
            };
            params.map(|p| p.encode()).map_err(err_to_rv)
        }
        CKM_RSA_PKCS_OAEP => {
            // SAFETY: size checked by read_param_struct.
            let o = unsafe { read_param_struct::<CkRsaPkcsOaepParams>(p_mechanism) }
                .ok_or(CKR_MECHANISM_PARAM_INVALID)?;
            // SAFETY: pointer comes from the caller's CK_RSA_PKCS_OAEP_PARAMS.
            let label = unsafe { copy_param_bytes(o.p_source_data, o.ul_source_data_len) }?;
            OaepParams::from_ck(o.hash_alg, o.mgf, o.source, &label)
                .map(|p| p.encode())
                .map_err(err_to_rv)
        }
        CKM_AES_CTR => {
            let params = if mech.parameter_len == 16 {
                // Legacy encoding: raw 16-byte counter block.
                CtrParams::from_legacy_iv(&unsafe { extract_mechanism_param(p_mechanism) }?)
            } else {
                // SAFETY: size checked by read_param_struct.
                let c = unsafe { read_param_struct::<CkAesCtrParams>(p_mechanism) }
                    .ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                CtrParams::new(c.ul_counter_bits, &c.cb)
            }
            .map_err(err_to_rv)?;
            if params.cb.iter().all(|&b| b == 0) && encrypt {
                tracing::error!("C_EncryptInit: all-zero counter block rejected for AES-CTR");
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
            Ok(params.encode())
        }
        CKM_AES_CBC | CKM_AES_CBC_PAD => {
            let iv = unsafe { extract_mechanism_param(p_mechanism) }?;
            if iv.len() != 16 {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
            if encrypt && iv.iter().all(|&b| b == 0) {
                tracing::error!("C_EncryptInit: all-zero IV rejected for AES-CBC");
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
            Ok(iv)
        }
        _ => unsafe { extract_mechanism_param(p_mechanism) },
    }
}

/// Decode the canonical GCM parameters stored at *Init (empty = deprecated
/// framing).
fn stored_gcm_params(mech_param: &[u8]) -> HsmResult<crate::crypto::params::GcmParams> {
    use crate::crypto::params::GcmParams;
    if mech_param.is_empty() {
        Ok(GcmParams::legacy([0u8; crate::crypto::params::GCM_IV_LEN]))
    } else {
        GcmParams::decode(mech_param)
    }
}

/// Validate `CK_RSA_PKCS_PSS_PARAMS` supplied with a hash-specific PSS
/// mechanism at `C_SignInit` / `C_VerifyInit` (H2-21): if present they must
/// match the mechanism's hash, MGF1 hash and salt length.
unsafe fn validate_pss_init_params(
    p_mechanism: CK_MECHANISM_PTR,
    mechanism: CK_MECHANISM_TYPE,
) -> Result<(), CK_RV> {
    if !sign::is_pss_mechanism(mechanism) {
        return Ok(());
    }
    // SAFETY: p_mechanism is non-null (checked by the callers).
    let mech = unsafe { &*p_mechanism };
    if mech.p_parameter.is_null() || mech.parameter_len == 0 {
        return Ok(());
    }
    // SAFETY: size checked by read_param_struct.
    let p = unsafe { read_param_struct::<CkRsaPkcsPssParams>(p_mechanism) }
        .ok_or(CKR_MECHANISM_PARAM_INVALID)?;
    crate::crypto::params::PssParams::from_ck(p.hash_alg, p.mgf, p.s_len)
        .and_then(|pp| pp.check_consistent_with(mechanism))
        .map_err(|_| CKR_MECHANISM_PARAM_INVALID)
}

/// Resolve the curve of an EC key object from `CKA_EC_PARAMS`. Absent
/// parameters default to P-256 (legacy objects); anything present but not
/// exactly the P-256 / P-384 namedCurve OID is rejected (A1-25).
fn ec_curve_of(obj: &StoredObject) -> HsmResult<sign::EcCurve> {
    match obj.ec_params.as_deref() {
        None | Some([]) => Ok(sign::EcCurve::P256),
        Some(p) => sign::EcCurve::from_ec_params(p).ok_or(HsmError::KeyTypeInconsistent),
    }
}

// ============================================================================
// Core library functions
// ============================================================================

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_Initialize(p_init_args: CK_VOID_PTR) -> CK_RV {
    catch_unwind(|| {
        // Validate CK_C_INITIALIZE_ARGS (PKCS#11 §5.4, A2-19 / H1-25).
        if !p_init_args.is_null() {
            // SAFETY: p_init_args is non-null (checked above). Caller must provide a valid
            // CK_C_INITIALIZE_ARGS per PKCS#11 §5.4. (Pattern 4). Read unaligned:
            // the struct may be packed on Windows.
            let args =
                unsafe { std::ptr::read_unaligned(p_init_args as *const CK_C_INITIALIZE_ARGS) };
            if let Err(rv) = validate_init_args(&args) {
                return rv;
            }
        }

        let mut guard = HSM.lock();

        if guard.is_some() {
            let init_pid = INIT_PID.load(Ordering::Acquire);
            if init_pid != 0 && init_pid != current_pid() {
                // Fork child (H1-24): the inherited core belongs to the
                // parent — its audit writer thread does not exist here and
                // its files must not be touched. Leak it without running
                // destructors and initialise a fresh core.
                tracing::warn!("C_Initialize in a fork child: discarding the inherited state");
                if let Some(inherited) = guard.take() {
                    std::mem::forget(inherited);
                }
                CACHED_HSM.with(|c| *c.borrow_mut() = None);
            } else {
                return CKR_CRYPTOKI_ALREADY_INITIALIZED;
            }
        }

        // Reset POST failure flag so re-initialization after C_Finalize gets a fresh chance.
        // If POST fails again below, POST_FAILED will be set back to true.
        POST_FAILED.store(false, Ordering::Release);

        // Run FIPS 140-3 Power-On Self-Tests before any crypto service is available
        if let Err(_) = crate::crypto::self_test::run_post() {
            POST_FAILED.store(true, Ordering::Release);
            return CKR_GENERAL_ERROR;
        }

        let config = match crate::config::config::HsmConfig::load() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Configuration loading/validation failed: {}", e);
                return CKR_GENERAL_ERROR;
            }
        };
        let core = match HsmCore::try_new(&config) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                tracing::error!("HSM core initialization failed: {}", e);
                return CKR_GENERAL_ERROR;
            }
        };

        // CASTs through the backend that will serve requests; in `fips`
        // builds this also refuses a non-validated backend (H2-05 / A1-04).
        if crate::crypto::self_test::run_backend_post(
            core.crypto_backend.as_ref(),
            core.algorithm_config.fips_approved_only,
        )
        .is_err()
        {
            POST_FAILED.store(true, Ordering::Release);
            return CKR_GENERAL_ERROR;
        }

        // Record the PID for fork detection
        INIT_PID.store(current_pid(), Ordering::Release);
        if audit_sync(
            &core,
            0,
            AuditOperation::Initialize,
            AuditResult::Success,
            None,
        )
        .is_err()
        {
            // Fail closed: the audit trail cannot be written (H3-11).
            core.finalize();
            return CKR_DEVICE_ERROR;
        }
        *guard = Some(core);
        // Bump generation so any stale TLS caches from a prior init/finalize
        // cycle are invalidated.
        HSM_GENERATION.fetch_add(1, Ordering::Release);
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Validate `CK_C_INITIALIZE_ARGS` (PKCS#11 §5.4):
/// * `pReserved` must be NULL;
/// * the four mutex callbacks are either all NULL or all non-NULL;
/// * application-supplied callbacks without `CKF_OS_LOCKING_OK` cannot be
///   honoured (the module always uses OS primitives) → `CKR_CANT_LOCK`;
/// * `CKF_LIBRARY_CANT_CREATE_OS_THREADS` cannot be honoured (the audit log
///   uses a writer thread) → `CKR_NEED_TO_CREATE_THREADS`.
fn validate_init_args(args: &CK_C_INITIALIZE_ARGS) -> Result<(), CK_RV> {
    let reserved = args.p_reserved;
    if !reserved.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let set = [
        args.create_mutex.is_some(),
        args.destroy_mutex.is_some(),
        args.lock_mutex.is_some(),
        args.unlock_mutex.is_some(),
    ];
    let all = set.iter().all(|b| *b);
    let none = set.iter().all(|b| !*b);
    if !all && !none {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let flags = args.flags;
    if flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS != 0 {
        return Err(CKR_NEED_TO_CREATE_THREADS);
    }
    if all && flags & CKF_OS_LOCKING_OK == 0 {
        return Err(CKR_CANT_LOCK);
    }
    Ok(())
}

/// Parse a decimal version component at compile time.
const fn parse_version_component(s: &str) -> u8 {
    let b = s.as_bytes();
    let mut v: u32 = 0;
    let mut i = 0;
    while i < b.len() {
        v = v * 10 + (b[i] - b'0') as u32;
        i += 1;
    }
    if v > 255 {
        255
    } else {
        v as u8
    }
}

/// Library / firmware version reported by `C_GetInfo`, `C_GetSlotInfo` and
/// `C_GetTokenInfo`: the crate's major.minor version (A3-16 / A2 note 8).
pub const LIBRARY_VERSION: CK_VERSION = CK_VERSION {
    major: parse_version_component(env!("CARGO_PKG_VERSION_MAJOR")),
    minor: parse_version_component(env!("CARGO_PKG_VERSION_MINOR")),
};

/// Cryptoki version implemented by the module (the v3.0 interface is
/// available through `C_GetInterface`, A2-01).
pub const CRYPTOKI_VERSION_3_0: CK_VERSION = CK_VERSION { major: 3, minor: 0 };
/// Version of the `CK_FUNCTION_LIST` returned by `C_GetFunctionList`.
pub const CRYPTOKI_VERSION_2_40: CK_VERSION = CK_VERSION {
    major: 2,
    minor: 40,
};

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_Finalize(p_reserved: CK_VOID_PTR) -> CK_RV {
    catch_unwind(|| {
        if !p_reserved.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let mut guard = HSM.lock();

        let init_pid = INIT_PID.load(Ordering::Acquire);
        if guard.is_some() && init_pid != 0 && init_pid != current_pid() {
            // Fork child (H1-24): never audit into, flush or zeroize the
            // parent's state from here; just drop our reference to it.
            if let Some(inherited) = guard.take() {
                std::mem::forget(inherited);
            }
            INIT_PID.store(0, Ordering::Release);
            HSM_GENERATION.fetch_add(1, Ordering::Release);
            CACHED_HSM.with(|c| *c.borrow_mut() = None);
            return CKR_OK;
        }

        let hsm = match guard.as_ref() {
            Some(h) => h.clone(),
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };

        // Zeroize keys, PIN verifiers and storage keys and close all sessions
        // (A1-10); records the Finalize audit event and flushes the log.
        hsm.finalize();

        // Release cached parsed RSA private keys (A1-10 / H2-10).
        crate::crypto::sign::clear_rsa_key_cache();

        // Reset state so a subsequent C_Initialize can succeed (PKCS#11 spec compliant)
        *guard = None;
        INIT_PID.store(0, Ordering::Release);
        // Invalidate all thread-local HSM caches.
        HSM_GENERATION.fetch_add(1, Ordering::Release);
        CACHED_HSM.with(|c| *c.borrow_mut() = None);
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GetInfo(p_info: CK_INFO_PTR) -> CK_RV {
    catch_unwind(|| {
        if get_hsm().is_err() {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let mut info = CK_INFO {
            cryptoki_version: CRYPTOKI_VERSION_3_0,
            manufacturer_id: [b' '; 32],
            flags: 0,
            library_description: [b' '; 32],
            library_version: LIBRARY_VERSION,
        };
        pad_string(&mut info.manufacturer_id, "Craton HSM Project");
        pad_string(&mut info.library_description, "Craton HSM Software HSM");

        // SAFETY: p_info non-null (checked above), caller provides aligned writable CK_INFO. (Pattern 1)
        unsafe {
            *p_info = info;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    catch_unwind(|| {
        if pp_function_list.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        unsafe {
            *pp_function_list = &FUNCTION_LIST as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ============================================================================
// Slot and Token management
// ============================================================================

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GetSlotList(
    token_present: CK_BBOOL,
    p_slot_list: CK_SLOT_ID_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        // In this software HSM, all slots always have a token present.
        // When token_present is CK_TRUE, we filter to only slots with tokens —
        // which is all of them. The parameter is accepted for spec compliance.
        let _ = token_present;
        let slots = hsm.slot_manager.get_slot_ids();

        if p_slot_list.is_null() {
            unsafe {
                *pul_count = slots.len() as CK_ULONG;
            }
            return CKR_OK;
        }

        let count = unsafe { *pul_count } as usize;
        if count < slots.len() {
            unsafe {
                *pul_count = slots.len() as CK_ULONG;
            }
            return CKR_BUFFER_TOO_SMALL;
        }

        let slot_slice = unsafe { slice::from_raw_parts_mut(p_slot_list, slots.len()) };
        for (i, &slot_id) in slots.iter().enumerate() {
            slot_slice[i] = slot_id;
        }
        unsafe {
            *pul_count = slots.len() as CK_ULONG;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GetSlotInfo(slot_id: CK_SLOT_ID, p_info: CK_SLOT_INFO_PTR) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if let Err(e) = hsm.slot_manager.validate_slot(slot_id) {
            return err_to_rv(e);
        }

        let mut info = CK_SLOT_INFO {
            slot_description: [b' '; 64],
            manufacturer_id: [b' '; 32],
            flags: CKF_SLOT_TOKEN_PRESENT,
            hardware_version: LIBRARY_VERSION,
            firmware_version: LIBRARY_VERSION,
        };
        pad_string(&mut info.slot_description, "Craton HSM Virtual Slot");
        pad_string(&mut info.manufacturer_id, "Craton HSM Project");

        unsafe {
            *p_info = info;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GetTokenInfo(slot_id: CK_SLOT_ID, p_info: CK_TOKEN_INFO_PTR) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let token = match hsm.slot_manager.get_token(slot_id) {
            Ok(t) => t,
            Err(e) => return err_to_rv(e),
        };

        let mut info = CK_TOKEN_INFO {
            label: *token.label.read(),
            manufacturer_id: [b' '; 32],
            model: [b' '; 16],
            serial_number: hsm.serial_number,
            flags: token.flags(),
            max_session_count: token.max_sessions() as CK_ULONG,
            session_count: token.session_count() as CK_ULONG,
            max_rw_session_count: token.max_rw_sessions() as CK_ULONG,
            rw_session_count: token.rw_session_count() as CK_ULONG,
            max_pin_len: token.pin_max_len(),
            min_pin_len: token.pin_min_len(),
            total_public_memory: CK_UNAVAILABLE_INFORMATION,
            free_public_memory: CK_UNAVAILABLE_INFORMATION,
            total_private_memory: CK_UNAVAILABLE_INFORMATION,
            free_private_memory: CK_UNAVAILABLE_INFORMATION,
            hardware_version: LIBRARY_VERSION,
            firmware_version: LIBRARY_VERSION,
            utc_time: [b' '; 16],
        };
        pad_string(&mut info.manufacturer_id, "Craton HSM Project");
        pad_string(&mut info.model, "Craton HSM");

        unsafe {
            *p_info = info;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_InitToken(
    slot_id: CK_SLOT_ID,
    p_pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
    p_label: CK_UTF8CHAR_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_pin.is_null() || p_label.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let token = match hsm.slot_manager.get_token(slot_id) {
            Ok(t) => t,
            Err(e) => return err_to_rv(e),
        };

        if (pin_len as usize) > MAX_PIN_BYTES {
            return CKR_PIN_LEN_RANGE;
        }
        // SAFETY: p_pin non-null (checked above), caller must provide pin_len valid bytes. (Pattern 2)
        let pin = unsafe { slice::from_raw_parts(p_pin, pin_len as usize) };
        // SAFETY: p_label non-null (checked above), PKCS#11 labels are always 32 bytes. (Pattern 2)
        let label_bytes = unsafe { slice::from_raw_parts(p_label, 32) };
        let mut label = [b' '; 32];
        label.copy_from_slice(label_bytes);

        drop(token);

        // H1-01/H3-01: HsmCore::init_token returns CKR_SESSION_EXISTS while
        // sessions are open, verifies the existing SO PIN under the SO
        // lockout policy, and only then destroys this slot's objects (and
        // their per-key counters) — never other slots'.
        match hsm.init_token(slot_id, pin, &label) {
            Ok(()) => CKR_OK,
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_InitPIN(
    session: CK_SESSION_HANDLE,
    p_pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_pin.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let sess = sess.read();
        let token = match hsm.slot_manager.get_token(sess.slot_id) {
            Ok(t) => t,
            Err(e) => return err_to_rv(e),
        };

        // PKCS#11: C_InitPIN requires SO role
        if !sess.state.is_so() {
            return CKR_USER_NOT_LOGGED_IN;
        }
        drop(sess);
        drop(token);
        if (pin_len as usize) > MAX_PIN_BYTES {
            return CKR_PIN_LEN_RANGE;
        }
        let pin = unsafe { slice::from_raw_parts(p_pin, pin_len as usize) };
        match hsm.init_pin(session, pin) {
            Ok(()) => CKR_OK,
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_SetPIN(
    session: CK_SESSION_HANDLE,
    p_old_pin: CK_UTF8CHAR_PTR,
    old_len: CK_ULONG,
    p_new_pin: CK_UTF8CHAR_PTR,
    new_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_old_pin.is_null() || p_new_pin.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let sess = sess.read();
        let token = match hsm.slot_manager.get_token(sess.slot_id) {
            Ok(t) => t,
            Err(e) => return err_to_rv(e),
        };

        // PKCS#11 §5.6: C_SetPIN is only permitted in a R/W session (H1-30).
        if !sess.is_rw() {
            return CKR_SESSION_READ_ONLY;
        }
        if (old_len as usize) > MAX_PIN_BYTES || (new_len as usize) > MAX_PIN_BYTES {
            return CKR_PIN_LEN_RANGE;
        }
        drop(sess);
        drop(token);
        // SAFETY: non-null (checked above); lengths bounded by MAX_PIN_BYTES.
        let old_pin = unsafe { slice::from_raw_parts(p_old_pin, old_len as usize) };
        // SAFETY: as above.
        let new_pin = unsafe { slice::from_raw_parts(p_new_pin, new_len as usize) };
        match hsm.set_pin(session, old_pin, new_pin) {
            Ok(()) => CKR_OK,
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GetMechanismList(
    slot_id: CK_SLOT_ID,
    p_mechanism_list: CK_MECHANISM_TYPE_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if let Err(e) = hsm.slot_manager.validate_slot(slot_id) {
            return err_to_rv(e);
        }

        // Filter mechanisms by algorithm policy (FIPS mode, PQC enable, etc.)
        let mechs = mechanisms::supported_mechanisms_filtered(&hsm.algorithm_config);

        if p_mechanism_list.is_null() {
            unsafe {
                *pul_count = mechs.len() as CK_ULONG;
            }
            return CKR_OK;
        }

        let count = unsafe { *pul_count } as usize;
        if count < mechs.len() {
            unsafe {
                *pul_count = mechs.len() as CK_ULONG;
            }
            return CKR_BUFFER_TOO_SMALL;
        }

        let out = unsafe { slice::from_raw_parts_mut(p_mechanism_list, mechs.len()) };
        for (i, &m) in mechs.iter().enumerate() {
            out[i] = m;
        }
        unsafe {
            *pul_count = mechs.len() as CK_ULONG;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GetMechanismInfo(
    slot_id: CK_SLOT_ID,
    mechanism_type: CK_MECHANISM_TYPE,
    p_info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if let Err(e) = hsm.slot_manager.validate_slot(slot_id) {
            return err_to_rv(e);
        }

        // Only mechanisms that C_GetMechanismList reports for the current
        // algorithm policy have mechanism information (H1-35).
        if !mechanisms::supported_mechanisms_filtered(&hsm.algorithm_config)
            .contains(&mechanism_type)
        {
            return CKR_MECHANISM_INVALID;
        }

        let info = match mechanism_type {
            CKM_RSA_PKCS_KEY_PAIR_GEN => CK_MECHANISM_INFO {
                min_key_size: 2048 as CK_ULONG,
                max_key_size: 4096 as CK_ULONG,
                flags: CKF_GENERATE_KEY_PAIR_FLAG,
            },
            CKM_RSA_PKCS | CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS => {
                CK_MECHANISM_INFO {
                    min_key_size: 2048 as CK_ULONG,
                    max_key_size: 4096 as CK_ULONG,
                    flags: CKF_SIGN_FLAG | CKF_VERIFY_FLAG,
                }
            }
            CKM_RSA_PKCS_PSS
            | CKM_SHA256_RSA_PKCS_PSS
            | CKM_SHA384_RSA_PKCS_PSS
            | CKM_SHA512_RSA_PKCS_PSS => CK_MECHANISM_INFO {
                min_key_size: 2048 as CK_ULONG,
                max_key_size: 4096 as CK_ULONG,
                flags: CKF_SIGN_FLAG | CKF_VERIFY_FLAG,
            },
            CKM_RSA_PKCS_OAEP => CK_MECHANISM_INFO {
                min_key_size: 2048 as CK_ULONG,
                max_key_size: 4096 as CK_ULONG,
                flags: CKF_ENCRYPT_FLAG | CKF_DECRYPT_FLAG,
            },
            CKM_EC_KEY_PAIR_GEN => CK_MECHANISM_INFO {
                min_key_size: 256 as CK_ULONG,
                max_key_size: 384 as CK_ULONG,
                flags: CKF_GENERATE_KEY_PAIR_FLAG,
            },
            CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512 => {
                CK_MECHANISM_INFO {
                    min_key_size: 256 as CK_ULONG,
                    max_key_size: 384 as CK_ULONG,
                    flags: CKF_SIGN_FLAG | CKF_VERIFY_FLAG,
                }
            }
            CKM_ECDH1_DERIVE | CKM_ECDH1_COFACTOR_DERIVE => CK_MECHANISM_INFO {
                min_key_size: 256 as CK_ULONG,
                max_key_size: 384 as CK_ULONG,
                flags: CKF_DERIVE_FLAG,
            },
            CKM_EDDSA => CK_MECHANISM_INFO {
                min_key_size: 256 as CK_ULONG,
                max_key_size: 256 as CK_ULONG,
                flags: CKF_SIGN_FLAG | CKF_VERIFY_FLAG | CKF_GENERATE_KEY_PAIR_FLAG,
            },
            CKM_AES_KEY_GEN => CK_MECHANISM_INFO {
                min_key_size: 16 as CK_ULONG,
                max_key_size: 32 as CK_ULONG,
                flags: CKF_GENERATE_FLAG,
            },
            // AES-GCM is also available through the v3.0 message-based API
            // (single-part C_EncryptMessage / C_DecryptMessage).
            CKM_AES_GCM => CK_MECHANISM_INFO {
                min_key_size: 16 as CK_ULONG,
                max_key_size: 32 as CK_ULONG,
                flags: CKF_ENCRYPT_FLAG
                    | CKF_DECRYPT_FLAG
                    | CKF_MESSAGE_ENCRYPT
                    | CKF_MESSAGE_DECRYPT,
            },
            CKM_AES_CBC | CKM_AES_CBC_PAD | CKM_AES_CTR => CK_MECHANISM_INFO {
                min_key_size: 16 as CK_ULONG,
                max_key_size: 32 as CK_ULONG,
                flags: CKF_ENCRYPT_FLAG | CKF_DECRYPT_FLAG,
            },
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => CK_MECHANISM_INFO {
                min_key_size: 16 as CK_ULONG,
                max_key_size: 32 as CK_ULONG,
                flags: CKF_WRAP_FLAG | CKF_UNWRAP_FLAG,
            },
            CKM_SHA_1 | CKM_SHA256 | CKM_SHA384 | CKM_SHA512 | CKM_SHA3_256 | CKM_SHA3_384
            | CKM_SHA3_512 => CK_MECHANISM_INFO {
                min_key_size: 0 as CK_ULONG,
                max_key_size: 0 as CK_ULONG,
                flags: CKF_DIGEST_FLAG,
            },
            // Post-Quantum: ML-KEM (Key Encapsulation)
            CKM_ML_KEM_512 | CKM_ML_KEM_768 | CKM_ML_KEM_1024 => CK_MECHANISM_INFO {
                min_key_size: 512 as CK_ULONG,
                max_key_size: 1024 as CK_ULONG,
                flags: CKF_GENERATE_KEY_PAIR_FLAG | CKF_DERIVE_FLAG,
            },
            // Post-Quantum: ML-DSA (Digital Signatures)
            CKM_ML_DSA_44 | CKM_ML_DSA_65 | CKM_ML_DSA_87 => CK_MECHANISM_INFO {
                min_key_size: 44 as CK_ULONG,
                max_key_size: 87 as CK_ULONG,
                flags: CKF_GENERATE_KEY_PAIR_FLAG | CKF_SIGN_FLAG | CKF_VERIFY_FLAG,
            },
            // Post-Quantum: SLH-DSA (Hash-Based Signatures)
            CKM_SLH_DSA_SHA2_128S | CKM_SLH_DSA_SHA2_256S => CK_MECHANISM_INFO {
                min_key_size: 128 as CK_ULONG,
                max_key_size: 256 as CK_ULONG,
                flags: CKF_GENERATE_KEY_PAIR_FLAG | CKF_SIGN_FLAG | CKF_VERIFY_FLAG,
            },
            _ => return CKR_MECHANISM_INVALID,
        };

        unsafe {
            *p_info = info;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ============================================================================
// Session management
// ============================================================================

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_OpenSession(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _p_application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    ph_session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if ph_session.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        match hsm.open_session(slot_id, flags, crate::session::manager::PROCESS_APPLICATION) {
            Ok(handle) => {
                unsafe {
                    *ph_session = handle;
                }
                CKR_OK
            }
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_CloseSession(session: CK_SESSION_HANDLE) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        // Closes the session, destroys its session objects (H3-07) and logs
        // the token out when this was its last session (H1-06).
        match hsm.close_session(session) {
            Ok(()) => CKR_OK,
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_CloseAllSessions(slot_id: CK_SLOT_ID) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        match hsm.close_all_sessions(slot_id) {
            Ok(()) => CKR_OK,
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GetSessionInfo(
    session: CK_SESSION_HANDLE,
    p_info: CK_SESSION_INFO_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };

        unsafe {
            *p_info = sess.read().get_info();
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_Login(
    session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    p_pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    // SAFETY: forwarded caller contract.
    catch_unwind(|| unsafe { login_impl(session, user_type, p_pin, pin_len) })
        .unwrap_or(CKR_GENERAL_ERROR)
}

/// Shared implementation of `C_Login` / `C_LoginUser`.
///
/// # Safety
/// `p_pin` must point to `pin_len` readable bytes when non-null.
unsafe fn login_impl(
    session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    p_pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    let hsm = match get_hsm() {
        Ok(h) => h,
        Err(rv) => return rv,
    };

    let sess = match hsm.session_manager.get_session(session) {
        Ok(s) => s,
        Err(e) => return err_to_rv(e),
    };
    let slot_id = sess.read().slot_id;
    if let Err(e) = hsm.slot_manager.get_token(slot_id) {
        return err_to_rv(e);
    }

    // A NULL PIN is reserved for a protected authentication path, which
    // this token does not have (CKF_PROTECTED_AUTHENTICATION_PATH is not
    // set): it must not be verified as an empty PIN (H1-30).
    if p_pin.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if (pin_len as usize) > MAX_PIN_BYTES {
        return CKR_PIN_LEN_RANGE;
    }
    // SAFETY: non-null (checked above), length bounded by MAX_PIN_BYTES.
    let pin = unsafe { slice::from_raw_parts(p_pin, pin_len as usize) };

    if user_type == CKU_CONTEXT_SPECIFIC {
        return context_specific_login(&hsm, session, &sess, pin);
    }

    // SO login not allowed if there are RO sessions (the token re-checks this
    // atomically; this early check only gives the specific error code).
    if user_type == CKU_SO && hsm.session_manager.has_ro_sessions(slot_id) {
        return CKR_SESSION_READ_ONLY_EXISTS;
    }

    // Token login + session promotion + (persistent) object load, rolled
    // back as a unit on failure; audited by the core.
    match hsm.login(session, user_type, pin) {
        Ok(()) => CKR_OK,
        Err(e) => err_to_rv(e),
    }
}

/// `C_Login(CKU_CONTEXT_SPECIFIC)` (A2-20): re-authenticates the normal user
/// for the active operation of a key with `CKA_ALWAYS_AUTHENTICATE=TRUE`.
/// The PIN is verified under the same lockout / rate-limit policy as a
/// normal login; success only unlocks the current operation.
fn context_specific_login(
    hsm: &HsmCore,
    session: CK_SESSION_HANDLE,
    sess: &Arc<parking_lot::RwLock<Session>>,
    pin: &[u8],
) -> CK_RV {
    let slot_id = {
        let s = sess.read();
        if !s.state.is_user() {
            return CKR_USER_NOT_LOGGED_IN;
        }
        if s.active_operation.is_none() || !s.context_login_required {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        s.slot_id
    };
    let token = match hsm.slot_manager.get_token(slot_id) {
        Ok(t) => t,
        Err(e) => return err_to_rv(e),
    };
    let result = token.verify_pin(CKU_USER, pin);
    let rv = match &result {
        Ok(()) => CKR_OK,
        Err(e) => CK_RV::from(e.clone()),
    };
    if let Err(arv) = audit_sync(
        hsm,
        session,
        AuditOperation::Login {
            user_type: CKU_CONTEXT_SPECIFIC as u64,
        },
        audit_result(rv),
        None,
    ) {
        return arv;
    }
    if rv == CKR_OK {
        let mut s = sess.write();
        if s.active_operation.is_some() {
            s.context_login_required = false;
        } else {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
    }
    rv
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_Logout(session: CK_SESSION_HANDLE) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        // Token logout + logout of every session of the slot (audited).
        match hsm.logout(session) {
            Ok(()) => CKR_OK,
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ============================================================================
// Object management
// ============================================================================

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_CreateObject(
    session: CK_SESSION_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    ph_object: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_template.is_null() || ph_object.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        if let Err(rv) = audit_gate(&hsm) {
            return rv;
        }

        // SAFETY: p_template non-null (checked above); caller contract.
        let template = match unsafe { parse_template(p_template, count) } {
            Ok(t) => t,
            Err(rv) => return rv,
        };

        // Session requirements (PKCS#11 §5.7, H1-28 / A2-21): session objects
        // may be created in R/O sessions, token objects need R/W; secret and
        // private keys and every private object (CKA_PRIVATE defaults to
        // TRUE) need the normal user.
        let class = match template_ulong(&template, CKA_CLASS) {
            Ok(Some(c)) => c,
            Ok(None) => return CKR_TEMPLATE_INCOMPLETE,
            Err(rv) => return rv,
        };
        let token_object = match template_bool(&template, CKA_TOKEN) {
            Ok(v) => v.unwrap_or(false),
            Err(rv) => return rv,
        };
        let private = match template_bool(&template, CKA_PRIVATE) {
            Ok(v) => v.unwrap_or(true),
            Err(rv) => return rv,
        };
        // EC keys must name a supported curve (A1-25): an unusable key is
        // refused at creation instead of failing at first use.
        if let Some((_, params)) = template.iter().find(|(t, _)| *t == CKA_EC_PARAMS) {
            let is_ec = matches!(template_ulong(&template, CKA_KEY_TYPE), Ok(Some(CKK_EC)));
            if is_ec && sign::EcCurve::from_ec_params(params).is_none() {
                return CKR_CURVE_NOT_SUPPORTED;
            }
        }
        let ctx = {
            let s = sess.read();
            let mut probe = StoredObject::new(1, class);
            probe.token_object = token_object;
            probe.private = private;
            if let Err(rv) = check_create_allowed(&s, &probe) {
                return rv;
            }
            // Objects carry the session's real slot and owner (H1-13, H3-07).
            s.object_ctx()
        };

        let result = hsm.object_store.create_object_in(&template, &ctx);
        let rv = match &result {
            Ok(_) => CKR_OK,
            Err(e) => CK_RV::from(e.clone()),
        };
        let audited = audit_sync(
            &hsm,
            session,
            AuditOperation::CreateObject,
            audit_result(rv),
            result.as_ref().ok().map(|h| format!("handle={h}")),
        );
        match result {
            Ok(handle) => {
                if let Err(arv) = audited {
                    // Fail closed: do not hand out an unaudited object.
                    let _ = hsm.object_store.destroy_object_in(handle, ctx.slot_id);
                    return arv;
                }
                // SAFETY: ph_object non-null (checked above).
                unsafe {
                    *ph_object = handle;
                }
                CKR_OK
            }
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Parse a `CK_BBOOL` template attribute strictly.
fn template_bool(
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    attr: CK_ATTRIBUTE_TYPE,
) -> Result<Option<bool>, CK_RV> {
    match template.iter().find(|(t, _)| *t == attr) {
        None => Ok(None),
        Some((_, v)) => parse_ck_bbool(v).map(Some),
    }
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DestroyObject(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let (slot, rw, user) = {
            let s = sess.read();
            (s.slot_id, s.is_rw(), s.state.is_user())
        };
        if let Err(rv) = audit_gate(&hsm) {
            return rv;
        }

        // Private objects need the normal user (H1-07); token objects need a
        // R/W session, session objects may be destroyed from R/O sessions.
        let rv = match hsm.object_store.get_object_in_slot(object, slot) {
            Ok(o) => {
                let o = o.read();
                if o.private && !user {
                    CKR_USER_NOT_LOGGED_IN
                } else if o.token_object && !rw {
                    CKR_SESSION_READ_ONLY
                } else {
                    CKR_OK
                }
            }
            Err(e) => err_to_rv(e),
        };

        // The store checks CKA_DESTROYABLE (CKR_ACTION_PROHIBITED), deletes
        // any persisted record first and zeroizes the key material — no
        // plaintext copy is made here.
        let rv = if rv == CKR_OK {
            match hsm.object_store.destroy_object_in(object, slot) {
                Ok(()) => CKR_OK,
                Err(e) => err_to_rv(e),
            }
        } else {
            rv
        };
        if let Err(arv) = audit_sync(
            &hsm,
            session,
            AuditOperation::DestroyObject,
            audit_result(rv),
            Some(format!("handle={object}")),
        ) {
            return arv;
        }
        rv
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GetObjectSize(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    pul_size: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_size.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        // Lock order: session before object (H1-36).
        let (slot, user) = {
            let s = sess.read();
            (s.slot_id, s.state.is_user())
        };

        // PKCS#11 §4.4: Private objects must not be accessible without login.
        let obj_ref = match hsm.object_store.get_object_in_slot(object, slot) {
            Ok(o) => o,
            Err(e) => return err_to_rv(e),
        };
        let size = {
            let o = obj_ref.read();
            if o.private && !user {
                return CKR_USER_NOT_LOGGED_IN;
            }
            o.approximate_size()
        };
        // SAFETY: pul_size non-null (checked above).
        unsafe {
            *pul_size = size;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GetAttributeValue(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_template.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // Bound the caller-supplied count before building a slice (H1-23).
        if count as usize > MAX_TEMPLATE_ATTRS {
            return CKR_ARGUMENTS_BAD;
        }
        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        // Lock order: session before object (H1-36).
        let (slot, user) = {
            let s = sess.read();
            (s.slot_id, s.state.is_user())
        };

        let obj = match hsm.object_store.get_object_in_slot(object, slot) {
            Ok(o) => o,
            Err(e) => return err_to_rv(e),
        };
        let obj = obj.read();

        // PKCS#11 §4.4: Private objects must not be accessible without login.
        if obj.private && !user {
            return CKR_USER_NOT_LOGGED_IN;
        }

        // SAFETY: p_template non-null (checked above), count bounded, caller provides
        // count valid CK_ATTRIBUTEs. We write back value_len and optionally copy data
        // into p_value buffers. (Pattern 2)
        let attrs = unsafe { slice::from_raw_parts_mut(p_template, count as usize) };
        let mut rv = CKR_OK;

        for attr in attrs.iter_mut() {
            // Audit every request for secret key material (granted or not).
            if crate::store::attributes::is_protected_secret_attribute(&obj, attr.attr_type) {
                if let Err(arv) = audit(
                    &hsm,
                    session,
                    AuditOperation::GetAttributeValueSensitive {
                        attribute: attr.attr_type as u64,
                    },
                    if obj.sensitive || !obj.extractable {
                        AuditResult::Failure(CKR_ATTRIBUTE_SENSITIVE as u64)
                    } else {
                        AuditResult::Success
                    },
                ) {
                    return arv;
                }
            }
            let value = if attr.attr_type == CKA_ALWAYS_AUTHENTICATE && obj.class == CKO_PRIVATE_KEY
            {
                Ok(Some(Zeroizing::new(vec![u8::from(always_authenticate(
                    &obj,
                ))])))
            } else {
                crate::store::attributes::read_attribute(&obj, attr.attr_type)
            };
            match value {
                Ok(Some(value)) => {
                    if attr.p_value.is_null() {
                        attr.value_len = value.len() as CK_ULONG;
                    } else if (attr.value_len as usize) < value.len() {
                        // PKCS#11 §5.7 (C_GetAttributeValue) case 5: the
                        // length is set to CK_UNAVAILABLE_INFORMATION (H1-26).
                        attr.value_len = CK_UNAVAILABLE_INFORMATION;
                        rv = CKR_BUFFER_TOO_SMALL;
                    } else {
                        // SAFETY: p_value non-null, buffer size verified >= value.len() above.
                        let dest = unsafe {
                            slice::from_raw_parts_mut(attr.p_value as *mut u8, value.len())
                        };
                        dest.copy_from_slice(&value);
                        attr.value_len = value.len() as CK_ULONG;
                    }
                }
                Ok(None) => {
                    attr.value_len = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                }
                Err(HsmError::AttributeSensitive) => {
                    attr.value_len = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_ATTRIBUTE_SENSITIVE;
                }
                Err(_) => {
                    attr.value_len = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_GENERAL_ERROR;
                }
            }
        }
        rv
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_SetAttributeValue(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_template.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        // Lock order: session before object (H1-36).
        let (slot, is_so, user, rw) = {
            let s = sess.read();
            (s.slot_id, s.state.is_so(), s.state.is_user(), s.is_rw())
        };
        if let Err(rv) = audit_gate(&hsm) {
            return rv;
        }
        {
            let obj = match hsm.object_store.get_object_in_slot(object, slot) {
                Ok(o) => o,
                Err(e) => return err_to_rv(e),
            };
            let o = obj.read();
            // PKCS#11 §4.4: Private objects must not be accessible without login.
            if o.private && !user {
                return CKR_USER_NOT_LOGGED_IN;
            }
            // Session objects may be modified from R/O sessions (A2-21).
            if o.token_object && !rw {
                return CKR_SESSION_READ_ONLY;
            }
        }

        // SAFETY: p_template non-null (checked above); caller contract.
        let template = match unsafe { parse_template(p_template, count) } {
            Ok(t) => t,
            Err(rv) => return rv,
        };
        // Atomic, persisted modification with PKCS#11 one-way rules,
        // CKA_MODIFIABLE and SO-only CKA_TRUSTED enforced by the store
        // (H1-09 / H1-27 / A2-21).
        let result = hsm
            .object_store
            .set_attributes(object, slot, &template, is_so);
        let rv = match &result {
            Ok(()) => CKR_OK,
            Err(e) => CK_RV::from(e.clone()),
        };
        if let Err(arv) = audit_sync(
            &hsm,
            session,
            AuditOperation::SetAttributeValue,
            audit_result(rv),
            Some(format!("handle={object}")),
        ) {
            return arv;
        }
        rv
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_FindObjectsInit(
    session: CK_SESSION_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if sess.find_context.is_some() {
            return CKR_OPERATION_ACTIVE;
        }

        let template = if count == 0 {
            Template::default()
        } else if p_template.is_null() {
            return CKR_ARGUMENTS_BAD;
        } else {
            // SAFETY: p_template non-null; caller contract.
            match unsafe { parse_template(p_template, count) } {
                Ok(t) => t,
                Err(rv) => return rv,
            }
        };

        // Private objects are only visible to the normal user (H1-05).
        let is_user = sess.state.is_user();
        let results =
            hsm.object_store
                .find_objects_for_slot(&template, is_user, Some(sess.slot_id));
        if let Err(rv) = audit(
            &hsm,
            session,
            AuditOperation::FindObjects {
                result_count: u32::try_from(results.len()).unwrap_or(u32::MAX),
            },
            AuditResult::Success,
        ) {
            return rv;
        }

        sess.find_context = Some(FindContext {
            results,
            position: 0,
        });

        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_FindObjects(
    session: CK_SESSION_HANDLE,
    ph_object: CK_OBJECT_HANDLE_PTR,
    max_count: CK_ULONG,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if ph_object.is_null() || pul_count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let ctx = match sess.find_context.as_mut() {
            Some(c) => c,
            None => return CKR_OPERATION_NOT_INITIALIZED,
        };

        let remaining = ctx.results.len() - ctx.position;
        let to_return = remaining.min(max_count as usize);
        let out = unsafe { slice::from_raw_parts_mut(ph_object, to_return) };

        for i in 0..to_return {
            out[i] = ctx.results[ctx.position + i];
        }
        ctx.position += to_return;

        unsafe {
            *pul_count = to_return as CK_ULONG;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_FindObjectsFinal(session: CK_SESSION_HANDLE) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if sess.find_context.is_none() {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        sess.find_context = None;
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ============================================================================
// Crypto operations
// ============================================================================

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_EncryptInit(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if sess.active_operation.is_some() {
            return CKR_OPERATION_ACTIVE;
        }

        // SAFETY: p_mechanism non-null (checked above), caller provides valid CK_MECHANISM. (Pattern 3)
        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_encrypt_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }

        if let Err(rv) = audit_gate(&hsm) {
            return rv;
        }
        // Verify key exists, is visible, has CKA_ENCRYPT, is active and fits
        // the mechanism (central gate).
        let obj = match hsm.object_store.get_object_in_slot(key, sess.slot_id) {
            Ok(o) => o,
            Err(_) => return CKR_KEY_HANDLE_INVALID,
        };
        if let Err(rv) = authorize_key_use(&sess, &obj.read(), KeyUsage::Encrypt, mechanism) {
            return rv;
        }

        // Parse CK_GCM_PARAMS / CK_RSA_PKCS_OAEP_PARAMS / CK_AES_CTR_PARAMS
        // now, while their embedded pointers are valid (H1-16). Rejects
        // all-zero CBC/CTR IVs early.
        let mech_param = match unsafe { canonical_cipher_param(&hsm, p_mechanism, mechanism, true) }
        {
            Ok(p) => p,
            Err(rv) => return rv,
        };

        sess.context_login_required = false;
        sess.active_operation = Some(ActiveOperation::Encrypt {
            mechanism,
            key_handle: key,
            mechanism_param: Zeroizing::new(mech_param),
            data: Zeroizing::new(Vec::new()),
            cached_object: Some(obj.clone()),
        });
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Helper to extract mechanism parameter bytes (empty for a NULL / empty
/// parameter). An oversized parameter is `CKR_MECHANISM_PARAM_INVALID`
/// instead of being treated as empty (H1-16).
///
/// # Safety
/// `p_mechanism` must be a valid, non-null `CK_MECHANISM` pointer whose
/// `pParameter` points to `ulParameterLen` readable bytes when non-null.
unsafe fn extract_mechanism_param(p_mechanism: CK_MECHANISM_PTR) -> Result<Vec<u8>, CK_RV> {
    // SAFETY: function contract.
    let mech = unsafe { &*p_mechanism };
    // SAFETY: function contract; the length is bounded before the slice is built.
    unsafe {
        caller_slice(
            mech.p_parameter as *const u8,
            mech.parameter_len,
            MAX_SINGLE_BUFFER,
            CKR_MECHANISM_PARAM_INVALID,
        )
    }
    .map(|p| p.to_vec())
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_Encrypt(
    session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    p_encrypted_data: CK_BYTE_PTR,
    pul_encrypted_data_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_data.is_null() || pul_encrypted_data_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let (mechanism, key_handle, mech_param) = match &sess.active_operation {
            Some(ActiveOperation::Encrypt {
                mechanism,
                key_handle,
                mechanism_param,
                ..
            }) => (*mechanism, *key_handle, mechanism_param.clone()),
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        if (data_len as usize) > MAX_SINGLE_BUFFER {
            sess.active_operation = None;
            return CKR_DATA_LEN_RANGE;
        }
        let data = unsafe { slice::from_raw_parts(p_data, data_len as usize) };

        // Get key material
        let obj = match hsm
            .object_store
            .get_object_in_slot(key_handle, sess.slot_id)
        {
            Ok(o) => o,
            Err(e) => {
                sess.active_operation = None;
                return err_to_rv(e);
            }
        };
        let obj = obj.read();
        let key_bytes = match &obj.key_material {
            Some(km) => km.as_bytes(),
            None => {
                sess.active_operation = None;
                return CKR_KEY_HANDLE_INVALID;
            }
        };

        // Exact output size, computed WITHOUT performing the encryption: it
        // answers the length query and rejects a too-small buffer while
        // preserving the operation (no AES-GCM IV is consumed, H1-26).
        {
            let estimated = match mechanism {
                CKM_AES_GCM => match stored_gcm_params(&mech_param) {
                    // ciphertext || tag (plus the IV for the deprecated framing)
                    Ok(p) => crate::crypto::encrypt::gcm_output_len(&p, data.len()),
                    Err(e) => {
                        sess.active_operation = None;
                        return err_to_rv(e);
                    }
                },
                // CBC (no padding) output = input length
                CKM_AES_CBC => data.len(),
                // CBC-PAD always adds 1..=16 bytes of padding
                CKM_AES_CBC_PAD => (data.len() / 16 + 1) * 16,
                CKM_AES_CTR => data.len(),
                CKM_RSA_PKCS_OAEP => {
                    // RSA-OAEP output = modulus size in bytes
                    match &obj.modulus {
                        Some(m) => m.len() - m.iter().position(|b| *b != 0).unwrap_or(m.len()),
                        None => {
                            sess.active_operation = None;
                            return CKR_KEY_HANDLE_INVALID;
                        }
                    }
                }
                _ => {
                    sess.active_operation = None;
                    return CKR_MECHANISM_INVALID;
                }
            };
            if p_encrypted_data.is_null() {
                // SAFETY: pul_encrypted_data_len non-null (checked above).
                unsafe {
                    *pul_encrypted_data_len = estimated as CK_ULONG;
                }
                return CKR_OK;
            }
            // SAFETY: as above.
            if (unsafe { *pul_encrypted_data_len } as usize) < estimated {
                // SAFETY: as above.
                unsafe {
                    *pul_encrypted_data_len = estimated as CK_ULONG;
                }
                return CKR_BUFFER_TOO_SMALL;
            }
        }

        let fips_mode = hsm.algorithm_config.fips_approved_only;
        let result: HsmResult<Vec<u8>> = match mechanism {
            CKM_AES_GCM => stored_gcm_params(&mech_param).and_then(|p| {
                hsm.crypto_backend
                    .aes_gcm_encrypt(key_bytes, &p, data, fips_mode)
            }),
            CKM_AES_CBC | CKM_AES_CBC_PAD => hsm.crypto_backend.aes_cbc_encrypt(
                key_bytes,
                &mech_param,
                data,
                mechanism == CKM_AES_CBC_PAD,
            ),
            CKM_AES_CTR => crate::crypto::params::CtrParams::decode(&mech_param)
                .and_then(|p| hsm.crypto_backend.aes_ctr_encrypt(key_bytes, &p, data)),
            CKM_RSA_PKCS_OAEP => {
                let modulus = match &obj.modulus {
                    Some(m) => m.as_slice(),
                    None => {
                        sess.active_operation = None;
                        return CKR_KEY_HANDLE_INVALID;
                    }
                };
                let pub_exp = match &obj.public_exponent {
                    Some(e) => e.as_slice(),
                    None => {
                        sess.active_operation = None;
                        return CKR_KEY_HANDLE_INVALID;
                    }
                };
                crate::crypto::params::OaepParams::decode(&mech_param).and_then(|p| {
                    hsm.crypto_backend
                        .rsa_oaep_encrypt(modulus, pub_exp, data, &p)
                })
            }
            _ => {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
        };

        sess.active_operation = None;
        let audit_op = AuditOperation::Encrypt {
            mechanism: mechanism as u64,
            fips_approved: mechanisms::is_fips_approved(mechanism),
        };
        match result {
            Ok(encrypted) => {
                if let Err(rv) = audit(&hsm, session, audit_op, AuditResult::Success) {
                    return rv;
                }
                // SAFETY: pul_encrypted_data_len non-null (checked above).
                let buf_len = unsafe { *pul_encrypted_data_len } as usize;
                if buf_len < encrypted.len() {
                    // SAFETY: as above.
                    unsafe {
                        *pul_encrypted_data_len = encrypted.len() as CK_ULONG;
                    }
                    return CKR_BUFFER_TOO_SMALL;
                }

                // SAFETY: the buffer holds at least encrypted.len() bytes.
                let out = unsafe { slice::from_raw_parts_mut(p_encrypted_data, encrypted.len()) };
                out.copy_from_slice(&encrypted);
                // SAFETY: as above.
                unsafe {
                    *pul_encrypted_data_len = encrypted.len() as CK_ULONG;
                }
                CKR_OK
            }
            Err(e) => {
                let rv = err_to_rv(e);
                if let Err(arv) = audit(&hsm, session, audit_op, AuditResult::Failure(rv as u64)) {
                    return arv;
                }
                rv
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DecryptInit(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if sess.active_operation.is_some() {
            return CKR_OPERATION_ACTIVE;
        }

        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_encrypt_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }

        if let Err(rv) = audit_gate(&hsm) {
            return rv;
        }
        let obj = match hsm.object_store.get_object_in_slot(key, sess.slot_id) {
            Ok(o) => o,
            Err(_) => return CKR_KEY_HANDLE_INVALID,
        };
        let needs_context_login = {
            let obj_read = obj.read();
            if let Err(rv) = authorize_key_use(&sess, &obj_read, KeyUsage::Decrypt, mechanism) {
                return rv;
            }
            always_authenticate(&obj_read)
        };

        let mech_param =
            match unsafe { canonical_cipher_param(&hsm, p_mechanism, mechanism, false) } {
                Ok(p) => p,
                Err(rv) => return rv,
            };
        sess.context_login_required = needs_context_login;
        sess.active_operation = Some(ActiveOperation::Decrypt {
            mechanism,
            key_handle: key,
            mechanism_param: Zeroizing::new(mech_param),
            data: Zeroizing::new(Vec::new()),
            cached_object: Some(obj.clone()),
        });
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_Decrypt(
    session: CK_SESSION_HANDLE,
    p_encrypted_data: CK_BYTE_PTR,
    encrypted_data_len: CK_ULONG,
    p_data: CK_BYTE_PTR,
    pul_data_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_encrypted_data.is_null() || pul_data_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        // CKA_ALWAYS_AUTHENTICATE: C_Login(CKU_CONTEXT_SPECIFIC) first (A2-20).
        if sess.context_login_required
            && matches!(sess.active_operation, Some(ActiveOperation::Decrypt { .. }))
        {
            return CKR_USER_NOT_LOGGED_IN;
        }

        let (mechanism, key_handle, mech_param) = match &sess.active_operation {
            Some(ActiveOperation::Decrypt {
                mechanism,
                key_handle,
                mechanism_param,
                ..
            }) => (*mechanism, *key_handle, mechanism_param.clone()),
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        if (encrypted_data_len as usize) > MAX_SINGLE_BUFFER {
            sess.active_operation = None;
            return CKR_DATA_LEN_RANGE;
        }
        let data = unsafe { slice::from_raw_parts(p_encrypted_data, encrypted_data_len as usize) };

        let obj = match hsm
            .object_store
            .get_object_in_slot(key_handle, sess.slot_id)
        {
            Ok(o) => o,
            Err(e) => {
                sess.active_operation = None;
                return err_to_rv(e);
            }
        };
        let obj = obj.read();
        let key_bytes = match &obj.key_material {
            Some(km) => km.as_bytes(),
            None => {
                sess.active_operation = None;
                return CKR_KEY_HANDLE_INVALID;
            }
        };

        // Length query: estimate output size WITHOUT performing the actual
        // decryption, preserving the operation state for the real call.
        if p_data.is_null() {
            let estimated = match mechanism {
                CKM_AES_GCM => match stored_gcm_params(&mech_param) {
                    Ok(p) => data.len().saturating_sub(
                        p.tag_len()
                            + if p.legacy_framing {
                                crate::crypto::params::GCM_IV_LEN
                            } else {
                                0
                            },
                    ),
                    Err(e) => {
                        sess.active_operation = None;
                        return err_to_rv(e);
                    }
                },
                CKM_AES_CBC | CKM_AES_CBC_PAD => data.len(),
                CKM_AES_CTR => data.len(),
                CKM_RSA_PKCS_OAEP => {
                    // RSA-OAEP plaintext is at most modulus size
                    data.len()
                }
                _ => {
                    sess.active_operation = None;
                    return CKR_MECHANISM_INVALID;
                }
            };
            unsafe {
                *pul_data_len = estimated as CK_ULONG;
            }
            return CKR_OK;
        }

        let result: HsmResult<Zeroizing<Vec<u8>>> = match mechanism {
            CKM_AES_GCM => stored_gcm_params(&mech_param)
                .and_then(|p| hsm.crypto_backend.aes_gcm_decrypt(key_bytes, &p, data)),
            CKM_AES_CBC | CKM_AES_CBC_PAD => hsm.crypto_backend.aes_cbc_decrypt(
                key_bytes,
                &mech_param,
                data,
                mechanism == CKM_AES_CBC_PAD,
            ),
            CKM_AES_CTR => crate::crypto::params::CtrParams::decode(&mech_param)
                .and_then(|p| hsm.crypto_backend.aes_ctr_decrypt(key_bytes, &p, data)),
            CKM_RSA_PKCS_OAEP => crate::crypto::params::OaepParams::decode(&mech_param)
                .and_then(|p| hsm.crypto_backend.rsa_oaep_decrypt(key_bytes, data, &p)),
            _ => {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
        };

        let audit_op = AuditOperation::Decrypt {
            mechanism: mechanism as u64,
            fips_approved: mechanisms::is_fips_approved(mechanism),
        };
        match result {
            Ok(decrypted) => {
                // SAFETY: pul_data_len non-null (checked above).
                let buf_len = unsafe { *pul_data_len } as usize;
                if buf_len < decrypted.len() {
                    // The plaintext length is only known after decryption;
                    // the operation is kept for the retry (PKCS#11 §5.2).
                    // SAFETY: as above.
                    unsafe {
                        *pul_data_len = decrypted.len() as CK_ULONG;
                    }
                    return CKR_BUFFER_TOO_SMALL;
                }
                sess.active_operation = None;
                // Record before releasing the plaintext (fail-closed audit).
                if let Err(rv) = audit(&hsm, session, audit_op, AuditResult::Success) {
                    return rv;
                }

                // SAFETY: the buffer holds at least decrypted.len() bytes.
                let out = unsafe { slice::from_raw_parts_mut(p_data, decrypted.len()) };
                out.copy_from_slice(&decrypted);
                // SAFETY: as above.
                unsafe {
                    *pul_data_len = decrypted.len() as CK_ULONG;
                }
                CKR_OK
            }
            Err(e) => {
                sess.active_operation = None;
                let rv = err_to_rv(e);
                if let Err(arv) = audit(&hsm, session, audit_op, AuditResult::Failure(rv as u64)) {
                    return arv;
                }
                rv
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_SignInit(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if !sess.state.is_user() {
            return CKR_USER_NOT_LOGGED_IN;
        }
        if sess.active_operation.is_some() {
            return CKR_OPERATION_ACTIVE;
        }

        // SAFETY: p_mechanism non-null (checked above). (Pattern 3)
        let mechanism = unsafe { (*p_mechanism).mechanism };

        // Explicit SHA-1 rejection: CKM_SHA1_RSA_PKCS is deprecated per
        // NIST SP 800-131A Rev.2.  Block it at the ABI boundary regardless
        // of what the mechanisms module says, as defense-in-depth.
        if mechanism == CKM_SHA1_RSA_PKCS {
            tracing::error!(
                "C_SignInit: SHA-1 based RSA signing (CKM_SHA1_RSA_PKCS) is prohibited"
            );
            return CKR_MECHANISM_INVALID;
        }

        if !mechanisms::is_sign_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check (signing context)
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, true)
        {
            return rv;
        }
        // CK_RSA_PKCS_PSS_PARAMS / CK_SIGN_ADDITIONAL_CONTEXT (A2-13, H2-20/21).
        // SAFETY: p_mechanism non-null (checked above).
        let params = match unsafe { parse_sign_params(p_mechanism, mechanism) } {
            Ok(p) => p,
            Err(rv) => return rv,
        };
        if let Err(rv) = audit_gate(&hsm) {
            return rv;
        }

        let obj = match hsm.object_store.get_object_in_slot(key, sess.slot_id) {
            Ok(o) => o,
            Err(_) => return CKR_KEY_HANDLE_INVALID,
        };
        let needs_context_login = {
            let obj_read = obj.read();
            if let Err(rv) = authorize_key_use(&sess, &obj_read, KeyUsage::Sign, mechanism) {
                return rv;
            }
            always_authenticate(&obj_read)
        };

        // Create a hasher if the mechanism has a built-in hash (for multi-part support)
        let hasher = sign::sign_mechanism_to_digest_mechanism(mechanism)
            .and_then(|digest_mech| hsm.crypto_backend.create_hasher(digest_mech).ok());

        sess.context_login_required = needs_context_login;
        sess.active_operation = Some(ActiveOperation::Sign {
            mechanism,
            key_handle: key,
            data: Zeroizing::new(Vec::new()),
            hasher,
            params,
            state_saveable: true,
            cached_object: Some(obj.clone()),
        });
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// `CK_SIGN_ADDITIONAL_CONTEXT` (PKCS#11 v3.2) for ML-DSA / SLH-DSA.
#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Clone, Copy)]
struct CkSignAdditionalContext {
    hedge_variant: CK_ULONG,
    p_context: *const u8,
    ul_context_len: CK_ULONG,
}

/// Parse the mechanism parameter of a sign / verify operation at `*Init`:
/// * `CKM_RSA_PKCS_PSS` requires `CK_RSA_PKCS_PSS_PARAMS` (A2-13);
/// * explicit PSS parameters of the hash-specific PSS mechanisms must match
///   them (H2-21);
/// * ML-DSA / SLH-DSA accept an optional `CK_SIGN_ADDITIONAL_CONTEXT`
///   (context string and hedging, H2-20).
///
/// # Safety
/// `p_mechanism` must be a valid, non-null `CK_MECHANISM` pointer whose
/// parameter pointers are valid for their lengths.
unsafe fn parse_sign_params(
    p_mechanism: CK_MECHANISM_PTR,
    mechanism: CK_MECHANISM_TYPE,
) -> Result<SignParams, CK_RV> {
    // SAFETY: function contract.
    let mech = unsafe { &*p_mechanism };
    let has_param = !mech.p_parameter.is_null() && mech.parameter_len != 0;
    if mechanism == CKM_RSA_PKCS_PSS {
        // SAFETY: size checked by read_param_struct.
        let p = unsafe { read_param_struct::<CkRsaPkcsPssParams>(p_mechanism) }
            .ok_or(CKR_MECHANISM_PARAM_INVALID)?;
        return crate::crypto::params::PssParams::from_ck(p.hash_alg, p.mgf, p.s_len)
            .map(SignParams::Pss)
            .map_err(|_| CKR_MECHANISM_PARAM_INVALID);
    }
    if sign::is_pss_mechanism(mechanism) {
        // SAFETY: function contract.
        unsafe { validate_pss_init_params(p_mechanism, mechanism) }?;
        return Ok(SignParams::None);
    }
    if pqc::is_ml_dsa_mechanism(mechanism) || pqc::is_slh_dsa_mechanism(mechanism) {
        if !has_param {
            return Ok(SignParams::None);
        }
        // SAFETY: size checked by read_param_struct.
        let c = unsafe { read_param_struct::<CkSignAdditionalContext>(p_mechanism) }
            .ok_or(CKR_MECHANISM_PARAM_INVALID)?;
        if c.ul_context_len > 255 {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }
        // SAFETY: pointer and length come from the caller's structure.
        let context = unsafe { copy_param_bytes(c.p_context, c.ul_context_len) }?;
        let deterministic = match c.hedge_variant {
            CKH_HEDGE_PREFERRED | CKH_HEDGE_REQUIRED => false,
            CKH_DETERMINISTIC_REQUIRED => true,
            _ => return Err(CKR_MECHANISM_PARAM_INVALID),
        };
        return Ok(SignParams::Pqc {
            context,
            deterministic,
        });
    }
    Ok(SignParams::None)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_Sign(
    session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_data.is_null() || pul_signature_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let (mechanism, key_handle, params) = match &sess.active_operation {
            Some(ActiveOperation::Sign {
                mechanism,
                key_handle,
                params,
                ..
            }) => (*mechanism, *key_handle, params.clone()),
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };
        // CKA_ALWAYS_AUTHENTICATE: C_Login(CKU_CONTEXT_SPECIFIC) first (A2-20).
        if sess.context_login_required {
            return CKR_USER_NOT_LOGGED_IN;
        }

        // SAFETY: p_data non-null; length bounded before the slice is built.
        let data = match unsafe {
            caller_slice(p_data, data_len, MAX_SINGLE_BUFFER, CKR_DATA_LEN_RANGE)
        } {
            Ok(d) => d,
            Err(rv) => {
                sess.active_operation = None;
                return rv;
            }
        };

        let obj = match hsm
            .object_store
            .get_object_in_slot(key_handle, sess.slot_id)
        {
            Ok(o) => o,
            Err(e) => {
                sess.active_operation = None;
                return err_to_rv(e);
            }
        };
        let obj = obj.read();
        let key_bytes = match &obj.key_material {
            Some(km) => km.as_bytes(),
            None => {
                sess.active_operation = None;
                return CKR_KEY_HANDLE_INVALID;
            }
        };

        // Exact signature length, known before signing: answers the length
        // query and rejects a too-small buffer WITHOUT performing the
        // signature (no nonce consumption, operation preserved; H1-26).
        let sig_len = match signature_len(mechanism, &obj) {
            Some(n) => n,
            None => {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
        };
        if p_signature.is_null() {
            // SAFETY: pul_signature_len non-null (checked above).
            unsafe {
                *pul_signature_len = sig_len as CK_ULONG;
            }
            return CKR_OK;
        }
        // SAFETY: pul_signature_len non-null (checked above).
        if (unsafe { *pul_signature_len } as usize) < sig_len {
            // SAFETY: as above.
            unsafe {
                *pul_signature_len = sig_len as CK_ULONG;
            }
            return CKR_BUFFER_TOO_SMALL;
        }

        let result = sign_single_shot(
            &*hsm.crypto_backend,
            mechanism,
            key_bytes,
            data,
            &obj,
            &params,
        );
        drop(obj);
        sess.active_operation = None;
        // SAFETY: p_signature non-null and its capacity was checked above.
        unsafe {
            finish_sign(
                &hsm,
                session,
                mechanism,
                result,
                p_signature,
                pul_signature_len,
            )
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Audit a completed signature and copy it to the caller's buffer.
///
/// # Safety
/// `p_signature` must be non-null and valid for `*pul_signature_len` bytes;
/// `pul_signature_len` must be valid for reads and writes.
unsafe fn finish_sign(
    hsm: &HsmCore,
    session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    result: HsmResult<Vec<u8>>,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    let op = AuditOperation::Sign {
        mechanism: mechanism as u64,
        fips_approved: mechanisms::is_fips_approved(mechanism),
    };
    match result {
        Ok(signature) => {
            // Record before releasing the signature (fail-closed audit).
            if let Err(rv) = audit(hsm, session, op, AuditResult::Success) {
                return rv;
            }
            // SAFETY: function contract.
            let buf_len = unsafe { *pul_signature_len } as usize;
            if buf_len < signature.len() {
                // Cannot happen: the exact length was checked beforehand.
                // SAFETY: function contract.
                unsafe {
                    *pul_signature_len = signature.len() as CK_ULONG;
                }
                return CKR_GENERAL_ERROR;
            }
            // SAFETY: buffer holds at least signature.len() bytes (checked above).
            let out = unsafe { slice::from_raw_parts_mut(p_signature, signature.len()) };
            out.copy_from_slice(&signature);
            // SAFETY: function contract.
            unsafe {
                *pul_signature_len = signature.len() as CK_ULONG;
            }
            CKR_OK
        }
        Err(e) => {
            let rv = err_to_rv(e);
            if let Err(arv) = audit(hsm, session, op, AuditResult::Failure(rv as u64)) {
                return arv;
            }
            rv
        }
    }
}

/// Signature produced by `CKM_RSA_PKCS_PSS` over a caller-supplied digest
/// (the input must have the length of the parameter hash).
fn check_pss_digest_len(p: &crate::crypto::params::PssParams, data: &[u8]) -> HsmResult<()> {
    if data.len() != p.hash.output_len() {
        return Err(HsmError::DataLenRange);
    }
    Ok(())
}

/// ML-DSA / SLH-DSA context and hedging from the operation parameters.
fn pqc_context(params: &SignParams) -> (&[u8], pqc::PqcSigning) {
    match params {
        SignParams::Pqc {
            context,
            deterministic,
        } => (
            context.as_slice(),
            if *deterministic {
                pqc::PqcSigning::Deterministic
            } else {
                pqc::PqcSigning::Hedged
            },
        ),
        _ => (&[], pqc::PqcSigning::Hedged),
    }
}

/// Single-shot sign: hash + sign in one step (used by C_Sign and C_SignFinal for non-hashed mechanisms)
fn sign_single_shot(
    backend: &dyn CryptoBackend,
    mechanism: CK_MECHANISM_TYPE,
    key_bytes: &[u8],
    data: &[u8],
    obj: &crate::store::object::StoredObject,
    params: &SignParams,
) -> HsmResult<Vec<u8>> {
    if mechanism == CKM_RSA_PKCS_PSS {
        // Generic PSS: the input is the message digest (A2-13).
        let SignParams::Pss(p) = params else {
            return Err(HsmError::MechanismParamInvalid);
        };
        check_pss_digest_len(p, data)?;
        backend.rsa_pss_sign_prehashed(key_bytes, data, p.hash)
    } else if sign::is_pss_mechanism(mechanism) {
        let hash = sign::pss_mechanism_to_hash(mechanism)?;
        backend.rsa_pss_sign(key_bytes, data, hash)
    } else if sign::is_ecdsa_mechanism(mechanism) {
        let key_type = obj.key_type.unwrap_or(0);
        match key_type {
            CKK_EC => {
                // Hash per mechanism; CKM_ECDSA signs the caller's hash as-is
                // (H2-07 / A1-13). Output is raw r || s (A2-07).
                let hash = sign::ecdsa_mechanism_to_hash(mechanism)?;
                backend.ecdsa_sign(ec_curve_of(obj)?, key_bytes, data, hash)
            }
            _ => Err(HsmError::KeyTypeInconsistent),
        }
    } else if sign::is_eddsa_mechanism(mechanism) {
        backend.ed25519_sign(key_bytes, data)
    } else if let Some(variant) = pqc::mechanism_to_ml_dsa_variant(mechanism) {
        let (ctx, mode) = pqc_context(params);
        pqc::ml_dsa_sign_with(key_bytes, data, variant, ctx, mode)
    } else if let Some(variant) = pqc::mechanism_to_slh_dsa_variant(mechanism) {
        let (ctx, mode) = pqc_context(params);
        pqc::slh_dsa_sign_with(key_bytes, data, variant, ctx, mode)
    } else if pqc::is_hybrid_mechanism(mechanism) {
        // Removed (H2-19): it signed with the public CKA_EC_POINT.
        Err(HsmError::MechanismInvalid)
    } else {
        // RSA PKCS#1 v1.5
        let hash_alg = sign::mechanism_to_hash(mechanism);
        backend.rsa_pkcs1v15_sign(key_bytes, data, hash_alg)
    }
}

/// Prehashed sign: used by C_SignFinal when data was hashed via multi-part C_SignUpdate.
/// The `digest` is the finalized hash output.
fn sign_prehashed(
    backend: &dyn CryptoBackend,
    mechanism: CK_MECHANISM_TYPE,
    key_bytes: &[u8],
    digest: &[u8],
    obj: &crate::store::object::StoredObject,
) -> HsmResult<Vec<u8>> {
    if sign::is_pss_mechanism(mechanism) {
        let hash = sign::pss_mechanism_to_hash(mechanism)?;
        backend.rsa_pss_sign_prehashed(key_bytes, digest, hash)
    } else if sign::is_ecdsa_mechanism(mechanism) {
        let key_type = obj.key_type.unwrap_or(0);
        match key_type {
            // `digest` was computed with the mechanism's hash.
            CKK_EC => backend.ecdsa_sign_prehashed(ec_curve_of(obj)?, key_bytes, digest),
            _ => Err(HsmError::KeyTypeInconsistent),
        }
    } else {
        // RSA PKCS#1 v1.5 prehashed
        let hash_alg = sign::mechanism_to_hash(mechanism).ok_or(HsmError::MechanismInvalid)?;
        backend.rsa_pkcs1v15_sign_prehashed(key_bytes, digest, hash_alg)
    }
}

/// Single-shot verify: hash + verify in one step (used by C_Verify and C_VerifyFinal for non-hashed mechanisms)
fn verify_single_shot(
    backend: &dyn CryptoBackend,
    mechanism: CK_MECHANISM_TYPE,
    data: &[u8],
    signature: &[u8],
    obj: &crate::store::object::StoredObject,
    params: &SignParams,
) -> HsmResult<bool> {
    if sign::is_pss_mechanism(mechanism) {
        let modulus = obj.modulus.as_deref().ok_or(HsmError::KeyHandleInvalid)?;
        let pub_exp = obj
            .public_exponent
            .as_deref()
            .ok_or(HsmError::KeyHandleInvalid)?;
        if mechanism == CKM_RSA_PKCS_PSS {
            let SignParams::Pss(p) = params else {
                return Err(HsmError::MechanismParamInvalid);
            };
            check_pss_digest_len(p, data)?;
            return backend.rsa_pss_verify_prehashed(modulus, pub_exp, data, signature, p.hash);
        }
        let hash = sign::pss_mechanism_to_hash(mechanism)?;
        backend.rsa_pss_verify(modulus, pub_exp, data, signature, hash)
    } else if sign::is_ecdsa_mechanism(mechanism) {
        let ec_point = obj.ec_point.as_deref().ok_or(HsmError::KeyHandleInvalid)?;
        let hash = sign::ecdsa_mechanism_to_hash(mechanism)?;
        backend.ecdsa_verify(ec_curve_of(obj)?, ec_point, data, signature, hash)
    } else if sign::is_eddsa_mechanism(mechanism) {
        let pub_key = obj
            .public_key_data
            .as_deref()
            .or(obj.ec_point.as_deref())
            .ok_or(HsmError::KeyHandleInvalid)?;
        backend.ed25519_verify(pub_key, data, signature)
    } else if let Some(variant) = pqc::mechanism_to_ml_dsa_variant(mechanism) {
        let pub_key = obj
            .public_key_data
            .as_deref()
            .ok_or(HsmError::KeyHandleInvalid)?;
        let (ctx, _) = pqc_context(params);
        pqc::ml_dsa_verify_with_context(pub_key, data, signature, variant, ctx)
    } else if let Some(variant) = pqc::mechanism_to_slh_dsa_variant(mechanism) {
        let pub_key = obj
            .public_key_data
            .as_deref()
            .ok_or(HsmError::KeyHandleInvalid)?;
        let (ctx, _) = pqc_context(params);
        pqc::slh_dsa_verify_with_context(pub_key, data, signature, variant, ctx)
    } else if pqc::is_hybrid_mechanism(mechanism) {
        Err(HsmError::MechanismInvalid)
    } else {
        // RSA PKCS#1 v1.5
        let modulus = obj.modulus.as_deref().ok_or(HsmError::KeyHandleInvalid)?;
        let pub_exp = obj
            .public_exponent
            .as_deref()
            .ok_or(HsmError::KeyHandleInvalid)?;
        let hash_alg = sign::mechanism_to_hash(mechanism);
        backend.rsa_pkcs1v15_verify(modulus, pub_exp, data, signature, hash_alg)
    }
}

/// Prehashed verify: used by C_VerifyFinal when data was hashed via multi-part C_VerifyUpdate.
/// The `digest` is the finalized hash output.
fn verify_prehashed(
    backend: &dyn CryptoBackend,
    mechanism: CK_MECHANISM_TYPE,
    digest: &[u8],
    signature: &[u8],
    obj: &crate::store::object::StoredObject,
) -> HsmResult<bool> {
    if sign::is_pss_mechanism(mechanism) {
        let modulus = obj.modulus.as_deref().ok_or(HsmError::KeyHandleInvalid)?;
        let pub_exp = obj
            .public_exponent
            .as_deref()
            .ok_or(HsmError::KeyHandleInvalid)?;
        let hash = sign::pss_mechanism_to_hash(mechanism)?;
        backend.rsa_pss_verify_prehashed(modulus, pub_exp, digest, signature, hash)
    } else if sign::is_ecdsa_mechanism(mechanism) {
        let ec_point = obj.ec_point.as_deref().ok_or(HsmError::KeyHandleInvalid)?;
        backend.ecdsa_verify_prehashed(ec_curve_of(obj)?, ec_point, digest, signature)
    } else {
        // RSA PKCS#1 v1.5 prehashed
        let modulus = obj.modulus.as_deref().ok_or(HsmError::KeyHandleInvalid)?;
        let pub_exp = obj
            .public_exponent
            .as_deref()
            .ok_or(HsmError::KeyHandleInvalid)?;
        let hash_alg = sign::mechanism_to_hash(mechanism).ok_or(HsmError::MechanismInvalid)?;
        backend.rsa_pkcs1v15_verify_prehashed(modulus, pub_exp, digest, signature, hash_alg)
    }
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_VerifyInit(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if sess.active_operation.is_some() {
            return CKR_OPERATION_ACTIVE;
        }

        // SAFETY: p_mechanism non-null (checked above). (Pattern 3)
        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_sign_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check (verify is not a signing context)
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }
        // SAFETY: p_mechanism non-null (checked above).
        let params = match unsafe { parse_sign_params(p_mechanism, mechanism) } {
            Ok(p) => p,
            Err(rv) => return rv,
        };
        if let Err(rv) = audit_gate(&hsm) {
            return rv;
        }

        let obj = match hsm.object_store.get_object_in_slot(key, sess.slot_id) {
            Ok(o) => o,
            Err(_) => return CKR_KEY_HANDLE_INVALID,
        };
        if let Err(rv) = authorize_key_use(&sess, &obj.read(), KeyUsage::Verify, mechanism) {
            return rv;
        }

        // Create a hasher if the mechanism has a built-in hash (for multi-part support)
        let hasher = sign::sign_mechanism_to_digest_mechanism(mechanism)
            .and_then(|digest_mech| hsm.crypto_backend.create_hasher(digest_mech).ok());

        sess.context_login_required = false;
        sess.active_operation = Some(ActiveOperation::Verify {
            mechanism,
            key_handle: key,
            data: Zeroizing::new(Vec::new()),
            hasher,
            params,
            state_saveable: true,
            cached_object: Some(obj.clone()),
        });
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_Verify(
    session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    signature_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_data.is_null() || p_signature.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let (mechanism, key_handle, params) = match &sess.active_operation {
            Some(ActiveOperation::Verify {
                mechanism,
                key_handle,
                params,
                ..
            }) => (*mechanism, *key_handle, params.clone()),
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        // SAFETY: non-null pointers; lengths bounded before slices are built.
        let (data, signature) = match unsafe {
            caller_slice(p_data, data_len, MAX_SINGLE_BUFFER, CKR_DATA_LEN_RANGE).and_then(|d| {
                caller_slice(
                    p_signature,
                    signature_len,
                    MAX_SINGLE_BUFFER,
                    CKR_DATA_LEN_RANGE,
                )
                .map(|s| (d, s))
            })
        } {
            Ok(v) => v,
            Err(rv) => {
                sess.active_operation = None;
                return rv;
            }
        };

        let obj = match hsm
            .object_store
            .get_object_in_slot(key_handle, sess.slot_id)
        {
            Ok(o) => o,
            Err(e) => {
                sess.active_operation = None;
                return err_to_rv(e);
            }
        };
        let obj = obj.read();

        let result = verify_single_shot(
            &*hsm.crypto_backend,
            mechanism,
            data,
            signature,
            &obj,
            &params,
        );

        sess.active_operation = None;
        finish_verify(&hsm, session, mechanism, result)
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Map and audit a verification result.
fn finish_verify(
    hsm: &HsmCore,
    session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    result: HsmResult<bool>,
) -> CK_RV {
    let rv = match result {
        Ok(true) => CKR_OK,
        Ok(false) => CKR_SIGNATURE_INVALID,
        Err(e) => err_to_rv(e),
    };
    if let Err(arv) = audit(
        hsm,
        session,
        AuditOperation::Verify {
            mechanism: mechanism as u64,
            fips_approved: mechanisms::is_fips_approved(mechanism),
        },
        audit_result(rv),
    ) {
        return arv;
    }
    rv
}

// ============================================================================
// Key generation
// ============================================================================

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GenerateKey(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    p_template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() || ph_key.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };

        // SAFETY: p_mechanism non-null (checked above). (Pattern 3)
        let mechanism = unsafe { (*p_mechanism).mechanism };
        if mechanism != CKM_AES_KEY_GEN {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }
        if let Err(rv) = audit_gate(&hsm) {
            return rv;
        }

        // SAFETY: caller contract (NULL is accepted only with count == 0).
        let template = match unsafe { parse_template(p_template, count) } {
            Ok(t) => t,
            Err(rv) => return rv,
        };

        // CKA_VALUE_LEN (default 32 for AES-256), strictly typed.
        let key_len = match template_ulong(&template, CKA_VALUE_LEN) {
            Ok(v) => v.unwrap_or(32) as usize,
            Err(rv) => return rv,
        };
        if key_len != 16 && key_len != 24 && key_len != 32 {
            return CKR_KEY_SIZE_RANGE;
        }

        // Build the object and validate the template BEFORE generating.
        let handle = match hsm.object_store.next_handle() {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };
        let mut obj = StoredObject::new(handle, CKO_SECRET_KEY);
        obj.key_type = Some(CKK_AES);
        obj.value_len = Some(key_len as CK_ULONG);
        obj.can_encrypt = true;
        obj.can_decrypt = true;
        obj.sensitive = true;
        obj.extractable = false;
        obj.private = true;
        let ctx = {
            let s = sess.read();
            if let Err(rv) =
                apply_key_template(&mut obj, &template, &[CKA_VALUE_LEN], s.state.is_so())
            {
                return rv;
            }
            // Secret keys need the normal user; token objects a R/W session (H1-10).
            if let Err(rv) = check_create_allowed(&s, &obj) {
                return rv;
            }
            s.object_ctx()
        };

        obj.key_material = match hsm
            .crypto_backend
            .generate_aes_key(key_len, hsm.algorithm_config.fips_approved_only)
        {
            Ok(k) => Some(k),
            Err(e) => return err_to_rv(e),
        };

        let result =
            hsm.object_store
                .insert_object_in(obj, &ctx, ObjectOrigin::Generated { mechanism });
        let rv = match &result {
            Ok(_) => CKR_OK,
            Err(e) => CK_RV::from(e.clone()),
        };
        let audited = audit_sync(
            &hsm,
            session,
            AuditOperation::GenerateKey {
                mechanism: mechanism as u64,
                key_length: key_len as u32,
                fips_approved: mechanisms::is_fips_approved(mechanism),
            },
            audit_result(rv),
            result.as_ref().ok().map(|h| format!("handle={h}")),
        );
        let handle = match result {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };
        if let Err(arv) = audited {
            let _ = hsm.object_store.destroy_object_in(handle, ctx.slot_id);
            return arv;
        }

        // SAFETY: ph_key non-null (checked above).
        unsafe {
            *ph_key = handle;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GenerateKeyPair(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    p_public_key_template: CK_ATTRIBUTE_PTR,
    public_key_attr_count: CK_ULONG,
    p_private_key_template: CK_ATTRIBUTE_PTR,
    private_key_attr_count: CK_ULONG,
    ph_public_key: CK_OBJECT_HANDLE_PTR,
    ph_private_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() || ph_public_key.is_null() || ph_private_key.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };

        // SAFETY: p_mechanism non-null (checked above). (Pattern 3)
        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_keypair_gen_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }
        if let Err(rv) = audit_gate(&hsm) {
            return rv;
        }

        // SAFETY: caller contract (NULL is accepted only with count == 0).
        let pub_template =
            match unsafe { parse_template(p_public_key_template, public_key_attr_count) } {
                Ok(t) => t,
                Err(rv) => return rv,
            };
        // SAFETY: as above.
        let priv_template =
            match unsafe { parse_template(p_private_key_template, private_key_attr_count) } {
                Ok(t) => t,
                Err(rv) => return rv,
            };

        let (ctx, is_so) = {
            let s = sess.read();
            (s.object_ctx(), s.state.is_so())
        };
        let check = |pub_obj: &StoredObject, priv_obj: &StoredObject| -> Result<(), CK_RV> {
            let s = sess.read();
            check_create_allowed(&s, pub_obj)?;
            check_create_allowed(&s, priv_obj)
        };
        let result = match mechanism {
            CKM_RSA_PKCS_KEY_PAIR_GEN => {
                generate_rsa_keypair(&hsm, is_so, &pub_template, &priv_template, &check)
            }
            CKM_EC_KEY_PAIR_GEN => {
                generate_ec_keypair(&hsm, is_so, &pub_template, &priv_template, &check)
            }
            CKM_EDDSA => {
                generate_ed25519_keypair(&hsm, is_so, &pub_template, &priv_template, &check)
            }
            m if pqc::is_ml_kem_mechanism(m)
                || pqc::is_ml_dsa_mechanism(m)
                || pqc::is_slh_dsa_mechanism(m) =>
            {
                generate_pqc_keypair(
                    &hsm,
                    is_so,
                    mechanism,
                    &pub_template,
                    &priv_template,
                    &check,
                )
            }
            _ => return CKR_MECHANISM_INVALID,
        };
        let (pub_obj, priv_obj, key_length) = match result {
            Ok(r) => r,
            Err(rv) => return rv,
        };

        // Insert both halves; never leave an orphaned public key (H1-31).
        let origin = ObjectOrigin::Generated { mechanism };
        let inserted = hsm
            .object_store
            .insert_object_in(pub_obj, &ctx, origin)
            .and_then(|pub_handle| {
                match hsm.object_store.insert_object_in(priv_obj, &ctx, origin) {
                    Ok(priv_handle) => Ok((pub_handle, priv_handle)),
                    Err(e) => {
                        let _ = hsm.object_store.destroy_object_in(pub_handle, ctx.slot_id);
                        Err(e)
                    }
                }
            });
        let rv = match &inserted {
            Ok(_) => CKR_OK,
            Err(e) => CK_RV::from(e.clone()),
        };
        let audited = audit_sync(
            &hsm,
            session,
            AuditOperation::GenerateKeyPair {
                mechanism: mechanism as u64,
                key_length,
                fips_approved: mechanisms::is_fips_approved(mechanism),
            },
            audit_result(rv),
            inserted
                .as_ref()
                .ok()
                .map(|(p, k)| format!("public={p},private={k}")),
        );
        let (pub_handle, priv_handle) = match inserted {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };
        if let Err(arv) = audited {
            let _ = hsm.object_store.destroy_object_in(priv_handle, ctx.slot_id);
            let _ = hsm.object_store.destroy_object_in(pub_handle, ctx.slot_id);
            return arv;
        }

        // SAFETY: both output pointers are non-null (checked above). (Pattern 6)
        unsafe {
            *ph_public_key = pub_handle;
            *ph_private_key = priv_handle;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// A generated key pair (public object, private object, key size for audit).
type KeyPairObjects = (StoredObject, StoredObject, u32);

/// Session requirement check applied to both halves before generation.
type CreateCheck<'a> = dyn Fn(&StoredObject, &StoredObject) -> Result<(), CK_RV> + 'a;

/// Build the two key objects with their per-class defaults and apply the
/// caller templates (H1-14) **before** any key material is generated.
fn keypair_prototypes(
    hsm: &HsmCore,
    key_type: CK_KEY_TYPE,
    is_so: bool,
    pub_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    priv_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    handled: &[CK_ATTRIBUTE_TYPE],
    defaults: impl Fn(&mut StoredObject, &mut StoredObject),
    check: &CreateCheck<'_>,
) -> Result<(StoredObject, StoredObject), CK_RV> {
    let mut pub_obj = StoredObject::new(
        hsm.object_store.next_handle().map_err(err_to_rv)?,
        CKO_PUBLIC_KEY,
    );
    pub_obj.key_type = Some(key_type);
    pub_obj.private = false;
    pub_obj.sensitive = false;
    let mut priv_obj = StoredObject::new(
        hsm.object_store.next_handle().map_err(err_to_rv)?,
        CKO_PRIVATE_KEY,
    );
    priv_obj.key_type = Some(key_type);
    priv_obj.sensitive = true;
    priv_obj.extractable = false;
    priv_obj.private = true;
    defaults(&mut pub_obj, &mut priv_obj);
    apply_key_template(&mut pub_obj, pub_template, handled, is_so)?;
    apply_key_template(&mut priv_obj, priv_template, handled, is_so)?;
    check(&pub_obj, &priv_obj)?;
    Ok((pub_obj, priv_obj))
}

/// Mark a pairwise-consistency-test failure (FIPS 140-3 §9.6): the module
/// enters the error state.
fn pct_failed(what: &str) -> CK_RV {
    tracing::error!("{what} pairwise consistency test failed — entering error state");
    POST_FAILED.store(true, Ordering::Release);
    CKR_GENERAL_ERROR
}

/// RSA key pair generation helper
fn generate_rsa_keypair(
    hsm: &HsmCore,
    is_so: bool,
    pub_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    priv_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    check: &CreateCheck<'_>,
) -> Result<KeyPairObjects, CK_RV> {
    // CK_ULONG is validated before narrowing (H1-31).
    let modulus_bits = match template_ulong(pub_template, CKA_MODULUS_BITS)? {
        Some(b) => u32::try_from(b).map_err(|_| CKR_KEY_SIZE_RANGE)?,
        None => 2048,
    };
    // Only e = 65537 is generated; any other requested exponent is refused
    // rather than silently replaced.
    if let Some((_, e)) = pub_template.iter().find(|(t, _)| *t == CKA_PUBLIC_EXPONENT) {
        let first = e.iter().position(|b| *b != 0).unwrap_or(e.len());
        if e[first..] != [0x01, 0x00, 0x01] {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }
    let (mut pub_obj, mut priv_obj) = keypair_prototypes(
        hsm,
        CKK_RSA,
        is_so,
        pub_template,
        priv_template,
        &[CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT],
        |p, k| {
            p.can_verify = true;
            p.can_encrypt = true;
            k.can_sign = true;
            k.can_decrypt = true;
        },
        check,
    )?;

    let (private_key_der, modulus, pub_exp) = hsm
        .crypto_backend
        .generate_rsa_key_pair(modulus_bits, hsm.algorithm_config.fips_approved_only)
        .map_err(err_to_rv)?;

    // FIPS 140-3 §9.6: Pairwise consistency test
    if pairwise_test::rsa_pairwise_test(
        hsm.crypto_backend.as_ref(),
        &private_key_der,
        &modulus,
        &pub_exp,
    )
    .is_err()
    {
        return Err(pct_failed("RSA"));
    }

    pub_obj.modulus = Some(modulus.clone());
    pub_obj.modulus_bits = Some(modulus_bits as CK_ULONG);
    pub_obj.public_exponent = Some(pub_exp.clone());
    priv_obj.key_material = Some(private_key_der);
    priv_obj.modulus = Some(modulus);
    priv_obj.modulus_bits = Some(modulus_bits as CK_ULONG);
    priv_obj.public_exponent = Some(pub_exp);
    Ok((pub_obj, priv_obj, modulus_bits))
}

/// DER of the P-256 namedCurve OID (1.2.840.10045.3.1.7).
const P256_EC_PARAMS: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// EC key pair generation helper (P-256 / P-384)
fn generate_ec_keypair(
    hsm: &HsmCore,
    is_so: bool,
    pub_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    priv_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    check: &CreateCheck<'_>,
) -> Result<KeyPairObjects, CK_RV> {
    // Determine curve from CKA_EC_PARAMS in the public template
    let ec_params = pub_template
        .iter()
        .find(|(t, _)| *t == CKA_EC_PARAMS)
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    // A CKA_EC_PARAMS in the private template must name the same curve.
    if let Some((_, v)) = priv_template.iter().find(|(t, _)| *t == CKA_EC_PARAMS) {
        if *v != ec_params {
            return Err(CKR_TEMPLATE_INCONSISTENT);
        }
    }

    // Strict curve selection (A1-25): absent parameters default to P-256
    // (recorded explicitly on the objects), anything other than the P-256 /
    // P-384 namedCurve OID is rejected.
    let (curve, ec_params) = if ec_params.is_empty() {
        (sign::EcCurve::P256, P256_EC_PARAMS.to_vec())
    } else {
        (
            sign::EcCurve::from_ec_params(&ec_params).ok_or(CKR_CURVE_NOT_SUPPORTED)?,
            ec_params,
        )
    };
    let (mut pub_obj, mut priv_obj) = keypair_prototypes(
        hsm,
        CKK_EC,
        is_so,
        pub_template,
        priv_template,
        &[CKA_EC_PARAMS],
        |p, k| {
            p.can_verify = true;
            k.can_sign = true;
            k.can_derive = true;
        },
        check,
    )?;

    let is_p384 = curve == sign::EcCurve::P384;
    let (private_key, public_key, key_bits) = if is_p384 {
        let (priv_key, pub_key) = hsm
            .crypto_backend
            .generate_ec_p384_key_pair()
            .map_err(err_to_rv)?;
        (priv_key, pub_key, 384u32)
    } else {
        let (priv_key, pub_key) = hsm
            .crypto_backend
            .generate_ec_p256_key_pair()
            .map_err(err_to_rv)?;
        (priv_key, pub_key, 256u32)
    };

    // FIPS 140-3 §9.6: Pairwise consistency test
    let pairwise_result = if is_p384 {
        pairwise_test::ecdsa_p384_pairwise_test(
            hsm.crypto_backend.as_ref(),
            &private_key,
            &public_key,
        )
    } else {
        pairwise_test::ecdsa_p256_pairwise_test(
            hsm.crypto_backend.as_ref(),
            &private_key,
            &public_key,
        )
    };
    if pairwise_result.is_err() {
        return Err(pct_failed("ECDSA"));
    }

    pub_obj.ec_params = Some(ec_params.clone());
    pub_obj.ec_point = Some(public_key.clone());
    priv_obj.key_material = Some(private_key);
    priv_obj.ec_params = Some(ec_params);
    priv_obj.ec_point = Some(public_key);
    Ok((pub_obj, priv_obj, key_bits))
}

/// Ed25519 key pair generation helper
fn generate_ed25519_keypair(
    hsm: &HsmCore,
    is_so: bool,
    pub_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    priv_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    check: &CreateCheck<'_>,
) -> Result<KeyPairObjects, CK_RV> {
    let (mut pub_obj, mut priv_obj) = keypair_prototypes(
        hsm,
        CKK_EC_EDWARDS,
        is_so,
        pub_template,
        priv_template,
        &[],
        |p, k| {
            p.can_verify = true;
            k.can_sign = true;
        },
        check,
    )?;
    let (private_key, public_key) = hsm
        .crypto_backend
        .generate_ed25519_key_pair()
        .map_err(err_to_rv)?;

    // FIPS 140-3 §9.6: Pairwise consistency test
    if pairwise_test::ed25519_pairwise_test(hsm.crypto_backend.as_ref(), &private_key, &public_key)
        .is_err()
    {
        return Err(pct_failed("Ed25519"));
    }

    pub_obj.public_key_data = Some(public_key.clone());
    pub_obj.ec_point = Some(public_key.clone());
    priv_obj.key_material = Some(private_key);
    priv_obj.public_key_data = Some(public_key.clone());
    priv_obj.ec_point = Some(public_key);
    Ok((pub_obj, priv_obj, 256))
}

/// PQC key pair generation helper (ML-KEM, ML-DSA, SLH-DSA)
fn generate_pqc_keypair(
    hsm: &HsmCore,
    is_so: bool,
    mechanism: CK_MECHANISM_TYPE,
    pub_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    priv_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    check: &CreateCheck<'_>,
) -> Result<KeyPairObjects, CK_RV> {
    let key_type = if pqc::is_ml_kem_mechanism(mechanism) {
        CKK_ML_KEM
    } else if pqc::is_ml_dsa_mechanism(mechanism) {
        CKK_ML_DSA
    } else if pqc::is_slh_dsa_mechanism(mechanism) {
        CKK_SLH_DSA
    } else {
        return Err(CKR_MECHANISM_INVALID);
    };
    let (mut pub_obj, mut priv_obj) = keypair_prototypes(
        hsm,
        key_type,
        is_so,
        pub_template,
        priv_template,
        &[],
        |p, k| {
            p.can_verify = key_type != CKK_ML_KEM;
            p.can_derive = key_type == CKK_ML_KEM; // KEM uses derive for encapsulate
            k.can_sign = key_type != CKK_ML_KEM;
            k.can_derive = key_type == CKK_ML_KEM; // KEM uses derive for decapsulate
        },
        check,
    )?;

    let (private_key, public_key, key_bits, variant_name) =
        if let Some(variant) = pqc::mechanism_to_ml_kem_variant(mechanism) {
            let (dk_seed, ek_bytes) = pqc::ml_kem_keygen(variant).map_err(err_to_rv)?;
            let (bits, name) = match variant {
                pqc::MlKemVariant::MlKem512 => (512u32, "ML-KEM-512"),
                pqc::MlKemVariant::MlKem768 => (768, "ML-KEM-768"),
                pqc::MlKemVariant::MlKem1024 => (1024, "ML-KEM-1024"),
            };
            (dk_seed, ek_bytes, bits, name)
        } else if let Some(variant) = pqc::mechanism_to_ml_dsa_variant(mechanism) {
            let (sk_seed, vk_bytes) = pqc::ml_dsa_keygen(variant).map_err(err_to_rv)?;
            let (bits, name) = match variant {
                pqc::MlDsaVariant::MlDsa44 => (44u32, "ML-DSA-44"),
                pqc::MlDsaVariant::MlDsa65 => (65, "ML-DSA-65"),
                pqc::MlDsaVariant::MlDsa87 => (87, "ML-DSA-87"),
            };
            (sk_seed, vk_bytes, bits, name)
        } else if let Some(variant) = pqc::mechanism_to_slh_dsa_variant(mechanism) {
            let (sk_bytes, vk_bytes) = pqc::slh_dsa_keygen(variant).map_err(err_to_rv)?;
            let (bits, name) = match variant {
                pqc::SlhDsaVariant::Sha2_128s => (128u32, "SLH-DSA-SHA2-128s"),
                pqc::SlhDsaVariant::Sha2_256s => (256, "SLH-DSA-SHA2-256s"),
            };
            (sk_bytes, vk_bytes, bits, name)
        } else {
            return Err(CKR_MECHANISM_INVALID);
        };

    // FIPS 140-3 §9.6: Pairwise consistency test for PQC key pairs
    let pairwise_result = match key_type {
        CKK_ML_KEM => pairwise_test::ml_kem_pairwise_test(&private_key, &public_key, variant_name),
        CKK_ML_DSA => pairwise_test::ml_dsa_pairwise_test(&private_key, &public_key, variant_name),
        _ => pairwise_test::slh_dsa_pairwise_test(&private_key, &public_key, variant_name),
    };
    if pairwise_result.is_err() {
        return Err(pct_failed("PQC"));
    }

    pub_obj.public_key_data = Some(public_key.clone());
    priv_obj.key_material = Some(private_key);
    priv_obj.public_key_data = Some(public_key);
    Ok((pub_obj, priv_obj, key_bits))
}

// ============================================================================
// Random generation
// ============================================================================

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_SeedRandom(
    session: CK_SESSION_HANDLE,
    _p_seed: CK_BYTE_PTR,
    _seed_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        let _ = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        // Mix the caller's seed into the SP 800-90A DRBG as additional input
        // (it never replaces the entropy input). A2-16.
        if _p_seed.is_null() && _seed_len != 0 {
            return CKR_ARGUMENTS_BAD;
        }
        if (_seed_len as usize) > MAX_SINGLE_BUFFER {
            return CKR_ARGUMENTS_BAD;
        }
        let seed: &[u8] = if _seed_len == 0 {
            &[]
        } else {
            // SAFETY: non-null with length bound checked above.
            unsafe { slice::from_raw_parts(_p_seed, _seed_len as usize) }
        };
        match hsm.crypto_backend.seed_random(seed) {
            Ok(()) => CKR_OK,
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GenerateRandom(
    session: CK_SESSION_HANDLE,
    p_random_data: CK_BYTE_PTR,
    random_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_random_data.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if (random_len as usize) > MAX_SINGLE_BUFFER {
            return CKR_DATA_LEN_RANGE;
        }
        let _ = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };

        // SP 800-90A DRBG with health tests (A1-01 / A2-16); the AWS-LC
        // backend uses its own validated DRBG.
        let data = unsafe { slice::from_raw_parts_mut(p_random_data, random_len as usize) };
        if let Err(e) = hsm.crypto_backend.generate_random(data) {
            data.fill(0);
            return err_to_rv(e);
        }

        if let Err(rv) = audit(
            &hsm,
            session,
            AuditOperation::GenerateRandom {
                length: random_len as u32,
            },
            AuditResult::Success,
        ) {
            data.fill(0);
            return rv;
        }

        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ============================================================================
// Stubs for unimplemented functions (return CKR_FUNCTION_NOT_SUPPORTED)
// ============================================================================

/// Common body of the unsupported functions: `CKR_CRYPTOKI_NOT_INITIALIZED`
/// and `CKR_SESSION_HANDLE_INVALID` take precedence over
/// `CKR_FUNCTION_NOT_SUPPORTED` (A2-22).
fn not_supported(session: CK_SESSION_HANDLE) -> CK_RV {
    catch_unwind(|| match check_session_only(session) {
        CKR_OK => CKR_FUNCTION_NOT_SUPPORTED,
        rv => rv,
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Largest state blob `C_SetOperationState` accepts (header, parameters,
/// data and tag).
const OP_STATE_MAX_BLOB: usize = 21 + 64 * 1024 + 4 + OP_STATE_MAX_DATA_LEN + 32;

/// C_GetOperationState saves the cryptographic operation state of a session.
/// Supports the two-call idiom: if pOperationState is NULL, only the length is returned.
///
/// Encrypt / decrypt operations (in particular AES-GCM with a module IV,
/// A1-15) and digests that absorbed key material (`C_DigestKey`, H1-12) are
/// unsaveable. The blob is authenticated together with the session handle
/// and slot, so it can only be restored into the same session (H1-04).
///
/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GetOperationState(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    pulOperationStateLen: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pulOperationStateLen.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(hSession) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let sess = sess.read();

        let op = match &sess.active_operation {
            Some(op) => op,
            None => return CKR_OPERATION_NOT_INITIALIZED,
        };

        // Encrypt/Decrypt operations are not saveable: restoring an AES-GCM
        // operation would re-use its IV (A1-15), and key material must never
        // be part of a state blob.
        if matches!(
            op,
            ActiveOperation::Encrypt { .. } | ActiveOperation::Decrypt { .. }
        ) {
            return CKR_STATE_UNSAVEABLE;
        }

        let binding = op_state_binding(hSession, sess.slot_id);
        let state_blob = match op.serialize_state(&hsm.state_hmac_key, &binding) {
            Ok(v) => v,
            Err(_) => return CKR_STATE_UNSAVEABLE,
        };

        if pOperationState.is_null() {
            // Length-only query
            // SAFETY: pulOperationStateLen non-null (checked above).
            unsafe {
                *pulOperationStateLen = state_blob.len() as CK_ULONG;
            }
            return CKR_OK;
        }

        // SAFETY: pulOperationStateLen non-null (checked above).
        let buf_len = unsafe { *pulOperationStateLen } as usize;
        if buf_len < state_blob.len() {
            // SAFETY: as above.
            unsafe {
                *pulOperationStateLen = state_blob.len() as CK_ULONG;
            }
            return CKR_BUFFER_TOO_SMALL;
        }

        // SAFETY: the caller's buffer holds at least state_blob.len() bytes.
        let out = unsafe { slice::from_raw_parts_mut(pOperationState, state_blob.len()) };
        out.copy_from_slice(&state_blob);
        // SAFETY: as above.
        unsafe {
            *pulOperationStateLen = state_blob.len() as CK_ULONG;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// C_SetOperationState restores the cryptographic operation state of a session.
///
/// The session is validated first; the blob must have been saved from the
/// same session (H1-04). For sign / verify states the key is re-authorized
/// exactly like `C_SignInit` / `C_VerifyInit` (login, usage attribute,
/// lifecycle, key type, slot, algorithm policy); `hAuthenticationKey` may
/// only name the key recorded in the state (`CKR_KEY_CHANGED` otherwise),
/// and keys are refused for digests (`CKR_KEY_NOT_NEEDED`). Hash-then-sign
/// states restore their hashed input (H1-17).
///
/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_SetOperationState(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    ulOperationStateLen: CK_ULONG,
    hEncryptionKey: CK_OBJECT_HANDLE,
    hAuthenticationKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pOperationState.is_null() || ulOperationStateLen == 0 {
            return CKR_ARGUMENTS_BAD;
        }

        // Validate the session first (A2-05).
        let sess_arc = match hsm.session_manager.get_session(hSession) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let slot = sess_arc.read().slot_id;

        // SAFETY: non-null; the length is bounded before the slice is built.
        let blob = match unsafe {
            caller_slice(
                pOperationState,
                ulOperationStateLen,
                OP_STATE_MAX_BLOB,
                CKR_SAVED_STATE_INVALID,
            )
        } {
            Ok(b) => b,
            Err(rv) => return rv,
        };

        let binding = op_state_binding(hSession, slot);
        let (op_type, mechanism, key_handle, param, data) =
            match ActiveOperation::deserialize_state(blob, &hsm.state_hmac_key, &binding) {
                Ok(v) => v,
                Err(_) => return CKR_SAVED_STATE_INVALID,
            };

        let mut sess = sess_arc.write();
        let (active_op, needs_context_login) = match op_type {
            // Digest: reconstruct hasher and re-feed accumulated data
            OP_TYPE_DIGEST => {
                if hEncryptionKey != 0 || hAuthenticationKey != 0 {
                    return CKR_KEY_NOT_NEEDED;
                }
                if !mechanisms::is_digest_mechanism(mechanism) {
                    return CKR_SAVED_STATE_INVALID;
                }
                if let Err(rv) = mechanisms::validate_mechanism_for_policy(
                    mechanism,
                    &hsm.algorithm_config,
                    false,
                ) {
                    return rv;
                }
                let mut hasher = match hsm.crypto_backend.create_hasher(mechanism) {
                    Ok(h) => h,
                    Err(_) => return CKR_SAVED_STATE_INVALID,
                };
                hasher.update(&data);
                (
                    ActiveOperation::Digest {
                        mechanism,
                        hasher: Some(hasher),
                        accumulated_input: data,
                        key_absorbed: false,
                        state_saveable: true,
                    },
                    false,
                )
            }
            OP_TYPE_SIGN | OP_TYPE_VERIFY => {
                if hEncryptionKey != 0 {
                    return CKR_KEY_NOT_NEEDED;
                }
                if hAuthenticationKey != 0 && hAuthenticationKey != key_handle {
                    return CKR_KEY_CHANGED;
                }
                let is_sign = op_type == OP_TYPE_SIGN;
                if !mechanisms::is_sign_mechanism(mechanism) || mechanism == CKM_SHA1_RSA_PKCS {
                    return CKR_SAVED_STATE_INVALID;
                }
                if let Err(rv) = mechanisms::validate_mechanism_for_policy(
                    mechanism,
                    &hsm.algorithm_config,
                    is_sign,
                ) {
                    return rv;
                }
                let params = match SignParams::decode(&param) {
                    Ok(p) => p,
                    Err(_) => return CKR_SAVED_STATE_INVALID,
                };
                if is_sign && !sess.state.is_user() {
                    return CKR_USER_NOT_LOGGED_IN;
                }
                let obj = match hsm.object_store.get_object_in_slot(key_handle, slot) {
                    Ok(o) => o,
                    Err(_) => return CKR_KEY_HANDLE_INVALID,
                };
                // Same authorization as C_SignInit / C_VerifyInit (H1-04).
                let usage = if is_sign {
                    KeyUsage::Sign
                } else {
                    KeyUsage::Verify
                };
                let needs_context_login = {
                    let o = obj.read();
                    if let Err(rv) = authorize_key_use(&sess, &o, usage, mechanism) {
                        return rv;
                    }
                    is_sign && always_authenticate(&o)
                };
                // Hash-then-sign: map the sign mechanism to its digest and
                // re-feed the saved hashed input (H1-17).
                let hasher = match sign::sign_mechanism_to_digest_mechanism(mechanism) {
                    Some(dm) => match hsm.crypto_backend.create_hasher(dm) {
                        Ok(mut h) => {
                            h.update(&data);
                            Some(h)
                        }
                        Err(_) => return CKR_SAVED_STATE_INVALID,
                    },
                    None => None,
                };
                let op = if is_sign {
                    ActiveOperation::Sign {
                        mechanism,
                        key_handle,
                        data,
                        hasher,
                        params,
                        state_saveable: true,
                        cached_object: Some(obj.clone()),
                    }
                } else {
                    ActiveOperation::Verify {
                        mechanism,
                        key_handle,
                        data,
                        hasher,
                        params,
                        state_saveable: true,
                        cached_object: Some(obj.clone()),
                    }
                };
                (op, needs_context_login)
            }
            // Encrypt/Decrypt: never saved, never restorable.
            OP_TYPE_ENCRYPT | OP_TYPE_DECRYPT => return CKR_SAVED_STATE_INVALID,
            _ => return CKR_SAVED_STATE_INVALID,
        };

        sess.context_login_required = needs_context_login;
        sess.active_operation = Some(active_op);
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Usage attributes that a copy may only turn off, never on (H1-08).
const COPY_USAGE_ATTRIBUTES: &[CK_ATTRIBUTE_TYPE] = &[
    CKA_ENCRYPT,
    CKA_DECRYPT,
    CKA_SIGN,
    CKA_VERIFY,
    CKA_WRAP,
    CKA_UNWRAP,
    CKA_DERIVE,
];

/// Apply one `C_CopyObject` template attribute to the copy, enforcing the
/// PKCS#11 copy rules and this token's policy (H1-08):
/// * `CKA_CLASS` / `CKA_KEY_TYPE` cannot change;
/// * if the source is not modifiable, only `CKA_TOKEN`, `CKA_PRIVATE`
///   (FALSE→TRUE), `CKA_LABEL` and `CKA_ID` may be given;
/// * usage attributes may only go TRUE→FALSE;
/// * `CKA_PRIVATE` may not be cleared on key objects;
/// * `CKA_SENSITIVE` / `CKA_WRAP_WITH_TRUSTED` / `CKA_ALWAYS_AUTHENTICATE`
///   only FALSE→TRUE, `CKA_EXTRACTABLE` / `CKA_COPYABLE` / `CKA_DESTROYABLE` /
///   `CKA_MODIFIABLE` only TRUE→FALSE;
/// * `CKA_TRUSTED` is SO-only; token-computed and key-material attributes
///   are read-only; unknown attributes are invalid.
fn apply_copy_attribute(
    obj: &mut StoredObject,
    src_modifiable: bool,
    attr_type: CK_ATTRIBUTE_TYPE,
    value: &[u8],
    is_so: bool,
) -> Result<(), CK_RV> {
    use crate::store::attributes::read_ck_ulong;
    let is_key = matches!(obj.class, CKO_SECRET_KEY | CKO_PRIVATE_KEY | CKO_PUBLIC_KEY);
    match attr_type {
        CKA_CLASS => {
            if read_ck_ulong(value) != Some(obj.class) {
                return Err(CKR_TEMPLATE_INCONSISTENT);
            }
            return Ok(());
        }
        CKA_KEY_TYPE => {
            if read_ck_ulong(value) != obj.key_type {
                return Err(CKR_TEMPLATE_INCONSISTENT);
            }
            return Ok(());
        }
        CKA_TOKEN => {
            obj.token_object = parse_ck_bbool(value)?;
            return Ok(());
        }
        CKA_PRIVATE => {
            let v = parse_ck_bbool(value)?;
            if obj.private && !v && is_key {
                return Err(CKR_TEMPLATE_INCONSISTENT);
            }
            if obj.private && !v && !src_modifiable {
                return Err(CKR_ATTRIBUTE_READ_ONLY);
            }
            obj.private = v;
            return Ok(());
        }
        CKA_LABEL => {
            obj.label = value.to_vec();
            return Ok(());
        }
        CKA_ID => {
            obj.id = value.to_vec();
            return Ok(());
        }
        _ => {}
    }
    if !src_modifiable {
        return Err(CKR_ATTRIBUTE_READ_ONLY);
    }
    if COPY_USAGE_ATTRIBUTES.contains(&attr_type) {
        let v = parse_ck_bbool(value)?;
        let field = match attr_type {
            CKA_ENCRYPT => &mut obj.can_encrypt,
            CKA_DECRYPT => &mut obj.can_decrypt,
            CKA_SIGN => &mut obj.can_sign,
            CKA_VERIFY => &mut obj.can_verify,
            CKA_WRAP => &mut obj.can_wrap,
            CKA_UNWRAP => &mut obj.can_unwrap,
            _ => &mut obj.can_derive,
        };
        if v && !*field {
            return Err(CKR_TEMPLATE_INCONSISTENT);
        }
        *field = v;
        return Ok(());
    }
    // One-way booleans: `true` = may only become TRUE.
    let one_way = |field: &mut bool, v: bool, up: bool| -> Result<(), CK_RV> {
        if (up && *field && !v) || (!up && !*field && v) {
            return Err(CKR_TEMPLATE_INCONSISTENT);
        }
        *field = v;
        Ok(())
    };
    match attr_type {
        CKA_SENSITIVE => one_way(&mut obj.sensitive, parse_ck_bbool(value)?, true),
        CKA_WRAP_WITH_TRUSTED => one_way(&mut obj.wrap_with_trusted, parse_ck_bbool(value)?, true),
        CKA_EXTRACTABLE => one_way(&mut obj.extractable, parse_ck_bbool(value)?, false),
        CKA_COPYABLE => one_way(&mut obj.copyable, parse_ck_bbool(value)?, false),
        CKA_DESTROYABLE => one_way(&mut obj.destroyable, parse_ck_bbool(value)?, false),
        CKA_MODIFIABLE => one_way(&mut obj.modifiable, parse_ck_bbool(value)?, false),
        CKA_ALWAYS_AUTHENTICATE => {
            let v = parse_ck_bbool(value)?;
            if obj.class != CKO_PRIVATE_KEY {
                return Err(CKR_ATTRIBUTE_TYPE_INVALID);
            }
            let mut cur = always_authenticate(obj);
            one_way(&mut cur, v, true)?;
            if cur {
                obj.extra_attributes
                    .insert(CKA_ALWAYS_AUTHENTICATE, vec![1]);
            }
            Ok(())
        }
        CKA_TRUSTED => {
            if !is_so {
                return Err(CKR_ATTRIBUTE_READ_ONLY);
            }
            obj.trusted = parse_ck_bbool(value)?;
            Ok(())
        }
        CKA_START_DATE | CKA_END_DATE | CKA_SUBJECT | CKA_APPLICATION => {
            crate::store::attributes::apply_attribute_ctx(obj, attr_type, value, is_so)
                .map_err(err_to_rv)
        }
        CKA_LOCAL | CKA_ALWAYS_SENSITIVE | CKA_NEVER_EXTRACTABLE | CKA_KEY_GEN_MECHANISM => {
            Err(CKR_ATTRIBUTE_READ_ONLY)
        }
        t if COMPUTED_KEY_ATTRIBUTES.contains(&t) => Err(CKR_ATTRIBUTE_READ_ONLY),
        t if t >= CKA_VENDOR_DEFINED => {
            crate::store::attributes::apply_attribute_ctx(obj, t, value, is_so).map_err(err_to_rv)
        }
        _ => Err(CKR_ATTRIBUTE_TYPE_INVALID),
    }
}

/// C_CopyObject creates a copy of an existing object with optional
/// attribute modifications from the template (PKCS#11 §5.7, H1-08):
/// `CKA_COPYABLE=FALSE` objects cannot be copied (`CKR_ACTION_PROHIBITED`),
/// the copy rules of [`apply_copy_attribute`] are enforced, private objects
/// need the normal user, token copies need a R/W session, compromised or
/// destroyed keys cannot be copied, and the copy is audited.
///
/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_CopyObject(
    session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    ph_new_object: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if ph_new_object.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        // Verify session is valid
        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let sess = sess.read();
        if let Err(rv) = audit_gate(&hsm) {
            return rv;
        }

        // A NULL template is only valid with a zero count; oversized counts
        // are rejected, never clamped (H1-23).
        // SAFETY: caller contract.
        let template = match unsafe { parse_template(p_template, count) } {
            Ok(t) => t,
            Err(rv) => return rv,
        };
        let mut seen = HashSet::with_capacity(template.len());
        if template.iter().any(|(t, _)| !seen.insert(*t)) {
            return CKR_TEMPLATE_INCONSISTENT;
        }

        // Get source object
        let src_arc = match hsm.object_store.get_object_in_slot(h_object, sess.slot_id) {
            Ok(o) => o,
            Err(_) => return CKR_OBJECT_HANDLE_INVALID,
        };
        let mut new_obj = {
            let src_obj = src_arc.read();
            // Private objects require the normal user.
            if let Err(rv) = check_visible(&sess, &src_obj) {
                return rv;
            }
            // CKA_COPYABLE=FALSE (PKCS#11 v3.0: CKR_ACTION_PROHIBITED).
            if !src_obj.copyable {
                return CKR_ACTION_PROHIBITED;
            }
            // Compromised / destroyed keys must not be propagated (H1-20).
            if matches!(
                src_obj.effective_lifecycle_state(),
                KeyLifecycleState::Compromised | KeyLifecycleState::Destroyed
            ) {
                return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
            src_obj.clone()
        };
        let src_modifiable = new_obj.modifiable;
        for (attr_type, value) in template.iter() {
            if let Err(rv) = apply_copy_attribute(
                &mut new_obj,
                src_modifiable,
                *attr_type,
                value,
                sess.state.is_so(),
            ) {
                return rv;
            }
        }
        if let Err(rv) = check_create_allowed(&sess, &new_obj) {
            return rv;
        }

        // Assign a new handle
        new_obj.handle = match hsm.object_store.next_handle() {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };

        let ctx = sess.object_ctx();
        let result = hsm
            .object_store
            .insert_object_in(new_obj, &ctx, ObjectOrigin::Copied);
        let rv = match &result {
            Ok(_) => CKR_OK,
            Err(e) => CK_RV::from(e.clone()),
        };
        let audited = audit_sync(
            &hsm,
            session,
            AuditOperation::CopyObject,
            audit_result(rv),
            Some(match &result {
                Ok(h) => format!("source={h_object},copy={h}"),
                Err(_) => format!("source={h_object}"),
            }),
        );
        let handle = match result {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };
        if let Err(arv) = audited {
            let _ = hsm.object_store.destroy_object_in(handle, ctx.slot_id);
            return arv;
        }

        // SAFETY: ph_new_object non-null (checked above).
        unsafe {
            *ph_new_object = handle;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Exact signature length for `mechanism` with key `obj` (used for length
/// queries and to reject too-small buffers before signing, H1-26).
fn signature_len(mechanism: CK_MECHANISM_TYPE, obj: &StoredObject) -> Option<usize> {
    if sign::is_pss_mechanism(mechanism)
        || mechanism == CKM_RSA_PKCS
        || sign::mechanism_to_hash(mechanism).is_some()
    {
        // RSA: signature length = modulus size in bytes
        if let Some(bits) = obj.modulus_bits {
            return Some((bits as usize).div_ceil(8));
        }
        if let Some(ref m) = obj.modulus {
            let first = m.iter().position(|b| *b != 0).unwrap_or(m.len());
            return Some(m.len() - first);
        }
        None
    } else if sign::is_ecdsa_mechanism(mechanism) {
        // PKCS#11 raw r || s: 64 bytes (P-256) / 96 bytes (P-384).
        ec_curve_of(obj).ok().map(|c| c.signature_len())
    } else if sign::is_eddsa_mechanism(mechanism) {
        Some(64) // Ed25519
    } else if let Some(v) = pqc::mechanism_to_ml_dsa_variant(mechanism) {
        // FIPS 204 Table 2 signature sizes.
        Some(match v {
            pqc::MlDsaVariant::MlDsa44 => 2420,
            pqc::MlDsaVariant::MlDsa65 => 3309,
            pqc::MlDsaVariant::MlDsa87 => 4627,
        })
    } else if let Some(v) = pqc::mechanism_to_slh_dsa_variant(mechanism) {
        // FIPS 205 Table 2 signature sizes.
        Some(match v {
            pqc::SlhDsaVariant::Sha2_128s => 7856,
            pqc::SlhDsaVariant::Sha2_256s => 29_792,
        })
    } else {
        None
    }
}

/// Check if an encrypt/decrypt mechanism supports multi-part operations.
/// AES-GCM and RSA-OAEP are single-shot only.
fn encrypt_mechanism_supports_multipart(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(mechanism, CKM_AES_CBC | CKM_AES_CBC_PAD | CKM_AES_CTR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_EncryptUpdate(
    session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    _p_encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_part.is_null() || pul_encrypted_part_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        match &mut sess.active_operation {
            Some(ActiveOperation::Encrypt {
                mechanism, data, ..
            }) => {
                if !encrypt_mechanism_supports_multipart(*mechanism) {
                    sess.active_operation = None;
                    return CKR_MECHANISM_INVALID;
                }

                // SAFETY: p_part non-null; the length is bounded first (H1-23).
                let part_data = match unsafe {
                    caller_slice(
                        p_part,
                        part_len,
                        MAX_MULTIPART_ACCUMULATION,
                        CKR_DATA_LEN_RANGE,
                    )
                } {
                    Ok(d) => d,
                    Err(rv) => {
                        sess.active_operation = None;
                        return rv;
                    }
                };
                if data.len().saturating_add(part_data.len()) > MAX_MULTIPART_ACCUMULATION {
                    sess.active_operation = None;
                    return CKR_DATA_LEN_RANGE;
                }
                data.extend_from_slice(part_data);

                // Accumulation mode: output 0 bytes in Update, all output in Final
                // SAFETY: pul_encrypted_part_len non-null (checked above).
                unsafe {
                    *pul_encrypted_part_len = 0;
                }
                CKR_OK
            }
            _ => CKR_OPERATION_NOT_INITIALIZED,
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_EncryptFinal(
    session: CK_SESSION_HANDLE,
    p_last_encrypted_part: CK_BYTE_PTR,
    pul_last_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_last_encrypted_part_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        // Length query: report a conservative upper-bound WITHOUT
        // consuming the operation state so subsequent Final call works.
        if p_last_encrypted_part.is_null() {
            let estimated_len = match &sess.active_operation {
                Some(ActiveOperation::Encrypt {
                    mechanism, data, ..
                }) => {
                    if !encrypt_mechanism_supports_multipart(*mechanism) {
                        sess.active_operation = None;
                        return CKR_MECHANISM_INVALID;
                    }
                    // AES-CBC_PAD may add up to one block (16 bytes); others output same length
                    data.len() + 16
                }
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };
            unsafe {
                *pul_last_encrypted_part_len = estimated_len as CK_ULONG;
            }
            return CKR_OK;
        }

        // Pre-check: verify the caller's buffer can hold the conservative
        // estimate BEFORE consuming accumulated data, so the operation is
        // preserved on CKR_BUFFER_TOO_SMALL (PKCS#11 spec compliant).
        {
            let (mech, data_ref) = match &sess.active_operation {
                Some(ActiveOperation::Encrypt {
                    mechanism, data, ..
                }) => (*mechanism, data),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };
            if !encrypt_mechanism_supports_multipart(mech) {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
            let estimated = data_ref.len() + 16; // CBC-PAD may add one block
            let buf_len = unsafe { *pul_last_encrypted_part_len } as usize;
            if buf_len < estimated {
                unsafe {
                    *pul_last_encrypted_part_len = estimated as CK_ULONG;
                }
                // Operation preserved — caller can retry with a larger buffer
                return CKR_BUFFER_TOO_SMALL;
            }
        }

        let (mechanism, key_handle, mech_param, data, cached_object) =
            match &mut sess.active_operation {
                Some(ActiveOperation::Encrypt {
                    mechanism,
                    key_handle,
                    mechanism_param,
                    data,
                    cached_object,
                }) => (
                    *mechanism,
                    *key_handle,
                    mechanism_param.clone(),
                    std::mem::take(data),
                    cached_object.take(),
                ),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };

        let obj = if let Some(cached) = cached_object {
            cached
        } else {
            match hsm
                .object_store
                .get_object_in_slot(key_handle, sess.slot_id)
            {
                Ok(o) => o,
                Err(e) => {
                    sess.active_operation = None;
                    return err_to_rv(e);
                }
            }
        };
        let obj = obj.read();
        let key_bytes = match &obj.key_material {
            Some(km) => km.as_bytes(),
            None => {
                sess.active_operation = None;
                return CKR_KEY_HANDLE_INVALID;
            }
        };

        let result: HsmResult<Vec<u8>> = match mechanism {
            CKM_AES_CBC | CKM_AES_CBC_PAD => hsm.crypto_backend.aes_cbc_encrypt(
                key_bytes,
                &mech_param,
                &data,
                mechanism == CKM_AES_CBC_PAD,
            ),
            CKM_AES_CTR => crate::crypto::params::CtrParams::decode(&mech_param)
                .and_then(|p| hsm.crypto_backend.aes_ctr_encrypt(key_bytes, &p, &data)),
            _ => {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
        };

        match result {
            Ok(encrypted) => {
                let out =
                    unsafe { slice::from_raw_parts_mut(p_last_encrypted_part, encrypted.len()) };
                out.copy_from_slice(&encrypted);
                unsafe {
                    *pul_last_encrypted_part_len = encrypted.len() as CK_ULONG;
                }

                sess.active_operation = None;
                if let Err(rv) = audit(
                    &hsm,
                    session,
                    AuditOperation::Encrypt {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Success,
                ) {
                    return rv;
                }
                CKR_OK
            }
            Err(e) => {
                sess.active_operation = None;
                err_to_rv(e)
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DecryptUpdate(
    session: CK_SESSION_HANDLE,
    p_encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    _p_part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_encrypted_part.is_null() || pul_part_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        // CKA_ALWAYS_AUTHENTICATE: C_Login(CKU_CONTEXT_SPECIFIC) first (A2-20).
        if sess.context_login_required
            && matches!(sess.active_operation, Some(ActiveOperation::Decrypt { .. }))
        {
            return CKR_USER_NOT_LOGGED_IN;
        }

        match &mut sess.active_operation {
            Some(ActiveOperation::Decrypt {
                mechanism, data, ..
            }) => {
                if !encrypt_mechanism_supports_multipart(*mechanism) {
                    sess.active_operation = None;
                    return CKR_MECHANISM_INVALID;
                }

                // SAFETY: p_encrypted_part non-null; the length is bounded first (H1-23).
                let part_data = match unsafe {
                    caller_slice(
                        p_encrypted_part,
                        encrypted_part_len,
                        MAX_MULTIPART_ACCUMULATION,
                        CKR_ENCRYPTED_DATA_LEN_RANGE,
                    )
                } {
                    Ok(d) => d,
                    Err(rv) => {
                        sess.active_operation = None;
                        return rv;
                    }
                };
                if data.len().saturating_add(part_data.len()) > MAX_MULTIPART_ACCUMULATION {
                    sess.active_operation = None;
                    return CKR_DATA_LEN_RANGE;
                }
                data.extend_from_slice(part_data);

                // Accumulation mode: output 0 bytes in Update, all output in Final
                unsafe {
                    *pul_part_len = 0;
                }
                CKR_OK
            }
            _ => CKR_OPERATION_NOT_INITIALIZED,
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DecryptFinal(
    session: CK_SESSION_HANDLE,
    p_last_part: CK_BYTE_PTR,
    pul_last_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_last_part_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        // CKA_ALWAYS_AUTHENTICATE: C_Login(CKU_CONTEXT_SPECIFIC) first (A2-20).
        if sess.context_login_required
            && matches!(sess.active_operation, Some(ActiveOperation::Decrypt { .. }))
        {
            return CKR_USER_NOT_LOGGED_IN;
        }

        // Length query: report a conservative upper-bound WITHOUT
        // consuming the operation state so subsequent Final call works.
        if p_last_part.is_null() {
            let estimated_len = match &sess.active_operation {
                Some(ActiveOperation::Decrypt {
                    mechanism, data, ..
                }) => {
                    if !encrypt_mechanism_supports_multipart(*mechanism) {
                        sess.active_operation = None;
                        return CKR_MECHANISM_INVALID;
                    }
                    // Decrypted output is at most the ciphertext length
                    data.len()
                }
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };
            unsafe {
                *pul_last_part_len = estimated_len as CK_ULONG;
            }
            return CKR_OK;
        }

        // Pre-check: verify the caller's buffer can hold the conservative
        // estimate BEFORE consuming accumulated data, so the operation is
        // preserved on CKR_BUFFER_TOO_SMALL (PKCS#11 spec compliant).
        {
            let (mech, data_ref) = match &sess.active_operation {
                Some(ActiveOperation::Decrypt {
                    mechanism, data, ..
                }) => (*mechanism, data),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };
            if !encrypt_mechanism_supports_multipart(mech) {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
            // Decrypted output is at most the ciphertext length
            let estimated = data_ref.len();
            let buf_len = unsafe { *pul_last_part_len } as usize;
            if buf_len < estimated {
                unsafe {
                    *pul_last_part_len = estimated as CK_ULONG;
                }
                // Operation preserved — caller can retry with a larger buffer
                return CKR_BUFFER_TOO_SMALL;
            }
        }

        let (mechanism, key_handle, mech_param, data, cached_object) =
            match &mut sess.active_operation {
                Some(ActiveOperation::Decrypt {
                    mechanism,
                    key_handle,
                    mechanism_param,
                    data,
                    cached_object,
                }) => (
                    *mechanism,
                    *key_handle,
                    mechanism_param.clone(),
                    std::mem::take(data),
                    cached_object.take(),
                ),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };

        let obj = if let Some(cached) = cached_object {
            cached
        } else {
            match hsm
                .object_store
                .get_object_in_slot(key_handle, sess.slot_id)
            {
                Ok(o) => o,
                Err(e) => {
                    sess.active_operation = None;
                    return err_to_rv(e);
                }
            }
        };
        let obj = obj.read();
        let key_bytes = match &obj.key_material {
            Some(km) => km.as_bytes(),
            None => {
                sess.active_operation = None;
                return CKR_KEY_HANDLE_INVALID;
            }
        };

        let result: HsmResult<Zeroizing<Vec<u8>>> = match mechanism {
            CKM_AES_CBC | CKM_AES_CBC_PAD => hsm.crypto_backend.aes_cbc_decrypt(
                key_bytes,
                &mech_param,
                &data,
                mechanism == CKM_AES_CBC_PAD,
            ),
            CKM_AES_CTR => crate::crypto::params::CtrParams::decode(&mech_param)
                .and_then(|p| hsm.crypto_backend.aes_ctr_decrypt(key_bytes, &p, &data)),
            _ => {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
        };

        match result {
            Ok(decrypted) => {
                let out = unsafe { slice::from_raw_parts_mut(p_last_part, decrypted.len()) };
                out.copy_from_slice(&decrypted);
                unsafe {
                    *pul_last_part_len = decrypted.len() as CK_ULONG;
                }

                sess.active_operation = None;
                if let Err(rv) = audit(
                    &hsm,
                    session,
                    AuditOperation::Decrypt {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Success,
                ) {
                    return rv;
                }
                CKR_OK
            }
            Err(e) => {
                sess.active_operation = None;
                err_to_rv(e)
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DigestInit(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if sess.active_operation.is_some() {
            return CKR_OPERATION_ACTIVE;
        }

        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_digest_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check (digest is not a signing context)
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }

        let hasher = match hsm.crypto_backend.create_hasher(mechanism) {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };

        sess.context_login_required = false;
        sess.active_operation = Some(ActiveOperation::Digest {
            mechanism,
            hasher: Some(hasher),
            accumulated_input: Zeroizing::new(Vec::new()),
            key_absorbed: false,
            state_saveable: true,
        });
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_Digest(
    session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    p_digest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_data.is_null() || pul_digest_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let (mechanism, out_len) = match &sess.active_operation {
            Some(ActiveOperation::Digest {
                accumulated_input,
                mechanism,
                hasher,
                key_absorbed,
                state_saveable,
            }) => {
                // PKCS#11: C_Digest is single-shot; reject if DigestUpdate /
                // DigestKey was already called.
                if !accumulated_input.is_empty() || *key_absorbed || !*state_saveable {
                    sess.active_operation = None;
                    return CKR_OPERATION_ACTIVE;
                }
                (*mechanism, hasher.as_ref().map(|h| h.output_len()))
            }
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        // Length query / buffer check before hashing; the operation is kept
        // on CKR_BUFFER_TOO_SMALL (PKCS#11 §5.2, H1-26).
        if let Some(n) = out_len {
            if p_digest.is_null() {
                // SAFETY: pul_digest_len non-null (checked above).
                unsafe {
                    *pul_digest_len = n as CK_ULONG;
                }
                return CKR_OK;
            }
            // SAFETY: as above.
            if (unsafe { *pul_digest_len } as usize) < n {
                // SAFETY: as above.
                unsafe {
                    *pul_digest_len = n as CK_ULONG;
                }
                return CKR_BUFFER_TOO_SMALL;
            }
        }

        // SAFETY: p_data non-null; length bounded before the slice is built.
        let data = match unsafe {
            caller_slice(p_data, data_len, MAX_SINGLE_BUFFER, CKR_DATA_LEN_RANGE)
        } {
            Ok(d) => d,
            Err(rv) => {
                sess.active_operation = None;
                return rv;
            }
        };
        let result = hsm.crypto_backend.compute_digest(mechanism, data);

        match result {
            Ok(digest_out) => {
                if p_digest.is_null() {
                    // SAFETY: pul_digest_len non-null (checked above).
                    unsafe {
                        *pul_digest_len = digest_out.len() as CK_ULONG;
                    }
                    return CKR_OK;
                }

                // SAFETY: as above.
                let buf_len = unsafe { *pul_digest_len } as usize;
                if buf_len < digest_out.len() {
                    // SAFETY: as above.
                    unsafe {
                        *pul_digest_len = digest_out.len() as CK_ULONG;
                    }
                    return CKR_BUFFER_TOO_SMALL;
                }

                sess.active_operation = None;
                if let Err(rv) = audit(
                    &hsm,
                    session,
                    AuditOperation::Digest {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Success,
                ) {
                    return rv;
                }
                // SAFETY: the buffer holds at least digest_out.len() bytes.
                let out = unsafe { slice::from_raw_parts_mut(p_digest, digest_out.len()) };
                out.copy_from_slice(&digest_out);
                // SAFETY: as above.
                unsafe {
                    *pul_digest_len = digest_out.len() as CK_ULONG;
                }
                CKR_OK
            }
            Err(e) => {
                sess.active_operation = None;
                err_to_rv(e)
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DigestUpdate(
    session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_part.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        match &mut sess.active_operation {
            Some(ActiveOperation::Digest {
                hasher,
                accumulated_input,
                state_saveable,
                ..
            }) => {
                // SAFETY: p_part non-null; the length is bounded first (H1-23).
                let data = match unsafe {
                    caller_slice(
                        p_part,
                        part_len,
                        MAX_MULTIPART_ACCUMULATION,
                        CKR_DATA_LEN_RANGE,
                    )
                } {
                    Ok(d) => d,
                    Err(rv) => {
                        sess.active_operation = None;
                        return rv;
                    }
                };
                if let Some(h) = hasher.as_mut() {
                    h.update(data);
                }
                // A copy of the input is kept only while it still fits in a
                // state blob; beyond that the operation becomes unsaveable
                // instead of buffering up to 64 MiB per session (H1-32).
                if *state_saveable {
                    if accumulated_input.len().saturating_add(data.len()) <= OP_STATE_MAX_DATA_LEN {
                        accumulated_input.extend_from_slice(data);
                    } else {
                        zeroize::Zeroize::zeroize(&mut **accumulated_input);
                        *state_saveable = false;
                    }
                }
                CKR_OK
            }
            _ => CKR_OPERATION_NOT_INITIALIZED,
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// C_DigestKey feeds the value of a secret key into an active digest
/// operation, as if C_DigestUpdate had been called with the key's value.
///
/// Only secret keys (CKO_SECRET_KEY) that are visible to the session
/// (private keys need the normal user, H1-12), neither sensitive nor
/// unextractable, and not compromised can be digested; others return
/// `CKR_KEY_INDIGESTIBLE` / `CKR_USER_NOT_LOGGED_IN`. The key bytes are
/// never kept in the operation state: the digest becomes unsaveable.
///
/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DigestKey(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        // Check active digest operation FIRST (per PKCS#11 spec)
        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();
        if !matches!(sess.active_operation, Some(ActiveOperation::Digest { .. })) {
            return CKR_OPERATION_NOT_INITIALIZED;
        }

        // Look up the key object (lock order: session before object)
        let key_arc = match hsm.object_store.get_object_in_slot(key, sess.slot_id) {
            Ok(o) => o,
            Err(_) => return CKR_KEY_HANDLE_INVALID,
        };
        let key_obj = key_arc.read();

        // Private keys need the normal user (H1-12).
        if let Err(rv) = check_visible(&sess, &key_obj) {
            return rv;
        }
        // Only secret keys can be digested
        if key_obj.class != CKO_SECRET_KEY {
            return CKR_KEY_INDIGESTIBLE;
        }
        // Sensitive or unextractable keys must not be digested — feeding raw
        // key bytes into a hash leaks information about the key.
        if key_obj.sensitive || !key_obj.extractable {
            return CKR_KEY_INDIGESTIBLE;
        }
        if matches!(
            key_obj.effective_lifecycle_state(),
            KeyLifecycleState::Compromised | KeyLifecycleState::Destroyed
        ) {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        let key_bytes = match &key_obj.key_material {
            Some(km) => km.as_bytes(),
            None => return CKR_KEY_INDIGESTIBLE,
        };

        match &mut sess.active_operation {
            Some(ActiveOperation::Digest {
                hasher,
                accumulated_input,
                key_absorbed,
                ..
            }) => {
                if let Some(h) = hasher.as_mut() {
                    h.update(key_bytes);
                }
                // Key material must never appear in a state blob (H1-12).
                zeroize::Zeroize::zeroize(&mut **accumulated_input);
                *key_absorbed = true;
                CKR_OK
            }
            _ => CKR_OPERATION_NOT_INITIALIZED,
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DigestFinal(
    session: CK_SESSION_HANDLE,
    p_digest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_digest_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        // Output size, known WITHOUT consuming the hasher.
        let (mechanism, out_len) = match &sess.active_operation {
            Some(ActiveOperation::Digest {
                hasher: Some(h),
                mechanism,
                ..
            }) => (*mechanism, h.output_len()),
            Some(ActiveOperation::Digest { hasher: None, .. }) => {
                sess.active_operation = None;
                return CKR_OPERATION_NOT_INITIALIZED;
            }
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };
        if p_digest.is_null() {
            // SAFETY: pul_digest_len non-null (checked above).
            unsafe {
                *pul_digest_len = out_len as CK_ULONG;
            }
            return CKR_OK;
        }
        // PKCS#11 §5.2: CKR_BUFFER_TOO_SMALL does not terminate the
        // operation — check before finalizing (H1-26).
        // SAFETY: as above.
        if (unsafe { *pul_digest_len } as usize) < out_len {
            // SAFETY: as above.
            unsafe {
                *pul_digest_len = out_len as CK_ULONG;
            }
            return CKR_BUFFER_TOO_SMALL;
        }

        // Real finalization: consume the hasher and produce output.
        let hasher = match sess.active_operation.take() {
            Some(ActiveOperation::Digest {
                hasher: Some(h), ..
            }) => h,
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };
        let digest_out = hasher.finalize();
        if let Err(rv) = audit(
            &hsm,
            session,
            AuditOperation::Digest {
                mechanism: mechanism as u64,
                fips_approved: mechanisms::is_fips_approved(mechanism),
            },
            AuditResult::Success,
        ) {
            return rv;
        }
        // SAFETY: the buffer holds at least out_len == digest_out.len() bytes.
        let out = unsafe { slice::from_raw_parts_mut(p_digest, digest_out.len()) };
        out.copy_from_slice(&digest_out);
        // SAFETY: as above.
        unsafe {
            *pul_digest_len = digest_out.len() as CK_ULONG;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_SignUpdate(
    session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_part.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();
        // CKA_ALWAYS_AUTHENTICATE: C_Login(CKU_CONTEXT_SPECIFIC) first (A2-20).
        if sess.context_login_required
            && matches!(sess.active_operation, Some(ActiveOperation::Sign { .. }))
        {
            return CKR_USER_NOT_LOGGED_IN;
        }

        let rv = match &mut sess.active_operation {
            Some(ActiveOperation::Sign {
                mechanism,
                hasher,
                data,
                state_saveable,
                ..
            }) => {
                // SAFETY: p_part non-null (checked above).
                unsafe { absorb_part(*mechanism, hasher, data, state_saveable, p_part, part_len) }
            }
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };
        if rv != CKR_OK {
            sess.active_operation = None;
        }
        rv
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Absorb one `C_SignUpdate` / `C_VerifyUpdate` part.
///
/// Hash-then-sign mechanisms feed the hasher and keep a bounded copy of the
/// hashed input so `C_GetOperationState` can save the operation faithfully
/// (H1-17); beyond `OP_STATE_MAX_DATA_LEN` the copy is dropped and the
/// operation becomes unsaveable (H1-32). Other mechanisms accumulate the raw
/// data (bounded by `MAX_MULTIPART_ACCUMULATION`).
///
/// # Safety
/// `p_part` must be non-null and point to `part_len` readable bytes.
unsafe fn absorb_part(
    mechanism: CK_MECHANISM_TYPE,
    hasher: &mut Option<Box<dyn crate::crypto::digest::DigestAccumulator>>,
    data: &mut Zeroizing<Vec<u8>>,
    state_saveable: &mut bool,
    p_part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    // SAFETY: function contract; the length is bounded first (H1-23).
    let part = match unsafe {
        caller_slice(
            p_part,
            part_len,
            MAX_MULTIPART_ACCUMULATION,
            CKR_DATA_LEN_RANGE,
        )
    } {
        Ok(p) => p,
        Err(rv) => return rv,
    };
    if let Some(h) = hasher.as_mut() {
        // Multi-part with built-in hash: feed data to the hasher
        h.update(part);
        if *state_saveable {
            if data.len().saturating_add(part.len()) <= OP_STATE_MAX_DATA_LEN {
                data.extend_from_slice(part);
            } else {
                zeroize::Zeroize::zeroize(&mut **data);
                *state_saveable = false;
            }
        }
        CKR_OK
    } else if sign::sign_mechanism_supports_multipart(mechanism) {
        // Mechanism supports multi-part but hasher creation failed
        CKR_GENERAL_ERROR
    } else {
        // Mechanism without built-in hash (e.g., CKM_RSA_PKCS):
        // accumulate raw data for the final operation
        if data.len().saturating_add(part.len()) > MAX_MULTIPART_ACCUMULATION {
            return CKR_DATA_LEN_RANGE;
        }
        data.extend_from_slice(part);
        if data.len() > OP_STATE_MAX_DATA_LEN {
            *state_saveable = false;
        }
        CKR_OK
    }
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_SignFinal(
    session: CK_SESSION_HANDLE,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_signature_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();
        // CKA_ALWAYS_AUTHENTICATE: C_Login(CKU_CONTEXT_SPECIFIC) first (A2-20).
        if sess.context_login_required
            && matches!(sess.active_operation, Some(ActiveOperation::Sign { .. }))
        {
            return CKR_USER_NOT_LOGGED_IN;
        }

        let (mechanism, key_handle, cached) = match &sess.active_operation {
            Some(ActiveOperation::Sign {
                mechanism,
                key_handle,
                cached_object,
                ..
            }) => (*mechanism, *key_handle, cached_object.clone()),
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };
        let obj = match cached {
            Some(o) => o,
            None => match hsm
                .object_store
                .get_object_in_slot(key_handle, sess.slot_id)
            {
                Ok(o) => o,
                Err(e) => {
                    sess.active_operation = None;
                    return err_to_rv(e);
                }
            },
        };
        let obj = obj.read();

        // Exact signature length, known WITHOUT consuming the hasher: the
        // length query and CKR_BUFFER_TOO_SMALL keep the operation (H1-26).
        let sig_len = match signature_len(mechanism, &obj) {
            Some(n) => n,
            None => {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
        };
        if p_signature.is_null() {
            // SAFETY: pul_signature_len non-null (checked above).
            unsafe {
                *pul_signature_len = sig_len as CK_ULONG;
            }
            return CKR_OK;
        }
        // SAFETY: as above.
        if (unsafe { *pul_signature_len } as usize) < sig_len {
            // SAFETY: as above.
            unsafe {
                *pul_signature_len = sig_len as CK_ULONG;
            }
            return CKR_BUFFER_TOO_SMALL;
        }

        let (hasher, data, params) = match sess.active_operation.take() {
            Some(ActiveOperation::Sign {
                hasher,
                data,
                params,
                ..
            }) => (hasher, data, params),
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };
        let key_bytes = match &obj.key_material {
            Some(km) => km.as_bytes(),
            None => return CKR_KEY_HANDLE_INVALID,
        };

        let result = if let Some(h) = hasher {
            // Multi-part with built-in hash: finalize hash, then prehash sign
            let digest = h.finalize();
            sign_prehashed(&*hsm.crypto_backend, mechanism, key_bytes, &digest, &obj)
        } else {
            // Accumulated raw data: sign directly (same as C_Sign)
            sign_single_shot(
                &*hsm.crypto_backend,
                mechanism,
                key_bytes,
                &data,
                &obj,
                &params,
            )
        };
        drop(obj);
        // SAFETY: p_signature non-null and its capacity was checked above.
        unsafe {
            finish_sign(
                &hsm,
                session,
                mechanism,
                result,
                p_signature,
                pul_signature_len,
            )
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_SignRecoverInit(
    session: CK_SESSION_HANDLE,
    _m: CK_MECHANISM_PTR,
    _k: CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_SignRecover(
    session: CK_SESSION_HANDLE,
    _d: CK_BYTE_PTR,
    _dl: CK_ULONG,
    _sig: CK_BYTE_PTR,
    _sl: CK_ULONG_PTR,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_VerifyUpdate(
    session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_part.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let rv = match &mut sess.active_operation {
            Some(ActiveOperation::Verify {
                mechanism,
                hasher,
                data,
                state_saveable,
                ..
            }) => {
                // SAFETY: p_part non-null (checked above).
                unsafe { absorb_part(*mechanism, hasher, data, state_saveable, p_part, part_len) }
            }
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };
        if rv != CKR_OK {
            sess.active_operation = None;
        }
        rv
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_VerifyFinal(
    session: CK_SESSION_HANDLE,
    p_signature: CK_BYTE_PTR,
    signature_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_signature.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let (mechanism, key_handle, hasher, data, params, cached_object) =
            match sess.active_operation.take() {
                Some(ActiveOperation::Verify {
                    mechanism,
                    key_handle,
                    hasher,
                    data,
                    params,
                    cached_object,
                    ..
                }) => (mechanism, key_handle, hasher, data, params, cached_object),
                other => {
                    sess.active_operation = other;
                    return CKR_OPERATION_NOT_INITIALIZED;
                }
            };

        // SAFETY: p_signature non-null; the length is bounded first (H1-23).
        let signature = match unsafe {
            caller_slice(
                p_signature,
                signature_len,
                MAX_SINGLE_BUFFER,
                CKR_SIGNATURE_LEN_RANGE,
            )
        } {
            Ok(s) => s,
            Err(rv) => return rv,
        };

        let obj = match cached_object {
            Some(cached) => cached,
            None => match hsm
                .object_store
                .get_object_in_slot(key_handle, sess.slot_id)
            {
                Ok(o) => o,
                Err(e) => return err_to_rv(e),
            },
        };
        let obj = obj.read();

        let result = if let Some(h) = hasher {
            // Multi-part with built-in hash: finalize hash, then prehash verify
            let digest = h.finalize();
            verify_prehashed(&*hsm.crypto_backend, mechanism, &digest, signature, &obj)
        } else {
            // Accumulated raw data: verify directly (same as C_Verify)
            verify_single_shot(
                &*hsm.crypto_backend,
                mechanism,
                &data,
                signature,
                &obj,
                &params,
            )
        };
        finish_verify(&hsm, session, mechanism, result)
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_VerifyRecoverInit(
    session: CK_SESSION_HANDLE,
    _m: CK_MECHANISM_PTR,
    _k: CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_VerifyRecover(
    session: CK_SESSION_HANDLE,
    _sig: CK_BYTE_PTR,
    _sl: CK_ULONG,
    _d: CK_BYTE_PTR,
    _dl: CK_ULONG_PTR,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DigestEncryptUpdate(
    session: CK_SESSION_HANDLE,
    _p: CK_BYTE_PTR,
    _pl: CK_ULONG,
    _e: CK_BYTE_PTR,
    _el: CK_ULONG_PTR,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DecryptDigestUpdate(
    session: CK_SESSION_HANDLE,
    _e: CK_BYTE_PTR,
    _el: CK_ULONG,
    _d: CK_BYTE_PTR,
    _dl: CK_ULONG_PTR,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_SignEncryptUpdate(
    session: CK_SESSION_HANDLE,
    _p: CK_BYTE_PTR,
    _pl: CK_ULONG,
    _e: CK_BYTE_PTR,
    _el: CK_ULONG_PTR,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DecryptVerifyUpdate(
    session: CK_SESSION_HANDLE,
    _e: CK_BYTE_PTR,
    _el: CK_ULONG,
    _d: CK_BYTE_PTR,
    _dl: CK_ULONG_PTR,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_WrapKey(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    wrapping_key: CK_OBJECT_HANDLE,
    key: CK_OBJECT_HANDLE,
    p_wrapped_key: CK_BYTE_PTR,
    pul_wrapped_key_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() || pul_wrapped_key_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };

        // SAFETY: p_mechanism non-null (checked above). (Pattern 3)
        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_wrap_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }
        if let Err(rv) = audit_gate(&hsm) {
            return rv;
        }

        let rv = wrap_key_checked(&hsm, &sess, mechanism, wrapping_key, key);
        let (wrapped, target_label) = match rv {
            Ok(v) => v,
            Err(rv) => {
                if let Err(arv) = audit_sync(
                    &hsm,
                    session,
                    AuditOperation::WrapKey {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Failure(rv as u64),
                    Some(format!("wrapping_key={wrapping_key},key={key}")),
                ) {
                    return arv;
                }
                return rv;
            }
        };

        if p_wrapped_key.is_null() {
            // SAFETY: pul_wrapped_key_len non-null (checked above).
            unsafe {
                *pul_wrapped_key_len = wrapped.len() as CK_ULONG;
            }
            return CKR_OK;
        }
        // SAFETY: as above.
        let buf_len = unsafe { *pul_wrapped_key_len } as usize;
        if buf_len < wrapped.len() {
            // SAFETY: as above.
            unsafe {
                *pul_wrapped_key_len = wrapped.len() as CK_ULONG;
            }
            return CKR_BUFFER_TOO_SMALL;
        }

        // Every export of key material is audited (H1-03); the wrapped key
        // is released only once the event is recorded.
        if let Err(arv) = audit_sync(
            &hsm,
            session,
            AuditOperation::WrapKey {
                mechanism: mechanism as u64,
                fips_approved: mechanisms::is_fips_approved(mechanism),
            },
            AuditResult::Success,
            Some(format!(
                "wrapping_key={wrapping_key},key={key}{target_label}"
            )),
        ) {
            return arv;
        }
        // SAFETY: the buffer holds at least wrapped.len() bytes (checked above).
        let out = unsafe { slice::from_raw_parts_mut(p_wrapped_key, wrapped.len()) };
        out.copy_from_slice(&wrapped);
        // SAFETY: pul_wrapped_key_len non-null (checked above).
        unsafe {
            *pul_wrapped_key_len = wrapped.len() as CK_ULONG;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Output length of AES key wrap (RFC 3394) / key wrap with padding
/// (RFC 5649) for an `n`-byte key, or `None` when `n` cannot be wrapped.
fn wrap_output_len(n: usize, padded: bool) -> Option<usize> {
    if padded {
        if n == 0 {
            None
        } else {
            Some(8 + n.div_ceil(8).max(1) * 8)
        }
    } else if n >= 16 && n % 8 == 0 {
        Some(n + 8)
    } else {
        None
    }
}

/// Authorize and perform a key wrap (H1-03 / H1-20 / H3-23):
/// * the wrapping key passes the central key-use gate (login for private
///   keys, `CKA_WRAP`, lifecycle, AES secret key);
/// * the key being wrapped must be visible to the session (private keys need
///   the normal user), `CKA_EXTRACTABLE=TRUE` (`CKR_KEY_UNEXTRACTABLE`),
///   not compromised / pre-active, and — if `CKA_WRAP_WITH_TRUSTED` — wrapped
///   only under a `CKA_TRUSTED` key (`CKR_KEY_NOT_WRAPPABLE`);
/// * a sensitive or private key is never wrapped under a wrapping key that
///   is itself non-sensitive or public (its value would be readable, which
///   would export the wrapped key in plaintext);
/// * SP 800-57 strength (the KEK must be at least as strong as the key).
///
/// Returns the wrapped key and a note for the audit record.
fn wrap_key_checked(
    hsm: &HsmCore,
    sess: &Arc<parking_lot::RwLock<Session>>,
    mechanism: CK_MECHANISM_TYPE,
    wrapping_key: CK_OBJECT_HANDLE,
    key: CK_OBJECT_HANDLE,
) -> Result<(Zeroizing<Vec<u8>>, String), CK_RV> {
    let sess = sess.read();
    let wk_arc = hsm
        .object_store
        .get_object_in_slot(wrapping_key, sess.slot_id)
        .map_err(|_| CKR_WRAPPING_KEY_HANDLE_INVALID)?;
    let key_arc = hsm
        .object_store
        .get_object_in_slot(key, sess.slot_id)
        .map_err(|_| CKR_KEY_HANDLE_INVALID)?;
    if Arc::ptr_eq(&wk_arc, &key_arc) {
        // A key cannot protect itself.
        return Err(CKR_KEY_NOT_WRAPPABLE);
    }
    let wk_obj = wk_arc.read();
    authorize_key_use(&sess, &wk_obj, KeyUsage::Wrap, mechanism).map_err(|rv| match rv {
        CKR_KEY_TYPE_INCONSISTENT => CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
        other => other,
    })?;
    let wk_bytes = match &wk_obj.key_material {
        Some(km) => km.as_bytes(),
        None => return Err(CKR_WRAPPING_KEY_HANDLE_INVALID),
    };

    let key_obj = key_arc.read();
    check_visible(&sess, &key_obj)?;
    if !crate::store::object::is_secret_class(key_obj.class) {
        return Err(CKR_KEY_NOT_WRAPPABLE);
    }
    if !key_obj.extractable {
        return Err(CKR_KEY_UNEXTRACTABLE);
    }
    match key_obj.effective_lifecycle_state() {
        KeyLifecycleState::Compromised | KeyLifecycleState::PreActivation => {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED)
        }
        KeyLifecycleState::Destroyed => return Err(CKR_KEY_HANDLE_INVALID),
        _ => {}
    }
    // PKCS#11: CKA_WRAP_WITH_TRUSTED — only a CKA_TRUSTED (SO-set) key may wrap it.
    if key_obj.wrap_with_trusted && !wk_obj.trusted {
        return Err(CKR_KEY_NOT_WRAPPABLE);
    }
    // Never downgrade the protection of the wrapped key.
    if (key_obj.sensitive && !wk_obj.sensitive) || (key_obj.private && !wk_obj.private) {
        tracing::warn!("C_WrapKey: wrapping key is less protected than the key to wrap");
        return Err(CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
    }
    let key_bytes = match &key_obj.key_material {
        Some(km) => km.as_bytes(),
        None => return Err(CKR_KEY_NOT_WRAPPABLE),
    };
    // SP 800-57: the KEK must be at least as strong as the wrapped key
    // (enforced in approved mode, logged otherwise). H2-14.
    let target_strength = crate::crypto::wrap::key_security_strength(
        key_obj.key_type.unwrap_or(CKK_VENDOR_DEFINED),
        key_bytes.len(),
        key_obj.modulus_bits,
        key_obj.ec_params.as_deref(),
    );
    crate::crypto::wrap::check_wrap_strength(
        wk_bytes.len(),
        target_strength,
        hsm.algorithm_config.fips_approved_only,
    )
    .map_err(err_to_rv)?;
    let padded = mechanism == CKM_AES_KEY_WRAP_KWP;
    if wrap_output_len(key_bytes.len(), padded).is_none() {
        return Err(CKR_KEY_SIZE_RANGE);
    }
    // Wrap while the object locks are held: no plaintext key copies (H1-21).
    let wrapped = hsm
        .crypto_backend
        .aes_key_wrap(wk_bytes, key_bytes, padded)
        .map_err(err_to_rv)?;
    let note = if key_obj.label.is_empty() {
        String::new()
    } else {
        format!(",label={}", String::from_utf8_lossy(&key_obj.label))
    };
    Ok((Zeroizing::new(wrapped), note))
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_UnwrapKey(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    unwrapping_key: CK_OBJECT_HANDLE,
    p_wrapped_key: CK_BYTE_PTR,
    wrapped_key_len: CK_ULONG,
    p_template: CK_ATTRIBUTE_PTR,
    attr_count: CK_ULONG,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() || p_wrapped_key.is_null() || ph_key.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };

        // SAFETY: p_mechanism non-null (checked above). (Pattern 3)
        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_wrap_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }
        if let Err(rv) = audit_gate(&hsm) {
            return rv;
        }

        // Defense-in-depth: bound wrapped_key_len before slice construction
        // SAFETY: p_wrapped_key non-null (checked above).
        let wrapped_data = match unsafe {
            caller_slice(
                p_wrapped_key,
                wrapped_key_len,
                MAX_SINGLE_BUFFER,
                CKR_WRAPPED_KEY_LEN_RANGE,
            )
        } {
            Ok(d) => d,
            Err(rv) => return rv,
        };
        // SAFETY: caller contract (NULL is accepted only with attr_count == 0).
        let template = match unsafe { parse_template(p_template, attr_count) } {
            Ok(t) => t,
            Err(rv) => return rv,
        };
        // Only secret AES keys can be unwrapped: CKA_CLASS / CKA_KEY_TYPE are
        // honoured and anything else is refused instead of being silently
        // stored as an AES key (H1-14).
        match template_ulong(&template, CKA_CLASS) {
            Ok(None) | Ok(Some(CKO_SECRET_KEY)) => {}
            Ok(Some(_)) => return CKR_TEMPLATE_INCONSISTENT,
            Err(rv) => return rv,
        }
        match template_ulong(&template, CKA_KEY_TYPE) {
            Ok(None) | Ok(Some(CKK_AES)) => {}
            Ok(Some(_)) => return CKR_TEMPLATE_INCONSISTENT,
            Err(rv) => return rv,
        }
        let requested_len = match template_ulong(&template, CKA_VALUE_LEN) {
            Ok(v) => v,
            Err(rv) => return rv,
        };

        let handle = match hsm.object_store.next_handle() {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };
        let mut obj = StoredObject::new(handle, CKO_SECRET_KEY);
        obj.key_type = Some(CKK_AES);
        obj.sensitive = true;
        obj.extractable = false; // secure default: unwrapped keys are non-extractable
        obj.private = true;
        obj.can_encrypt = true;
        obj.can_decrypt = true;

        let unwrapped = {
            let s = sess.read();
            if let Err(rv) =
                apply_key_template(&mut obj, &template, &[CKA_VALUE_LEN], s.state.is_so())
            {
                return rv;
            }
            // Unwrapping creates a secret key: normal user; token objects need R/W (H1-10).
            if let Err(rv) = check_create_allowed(&s, &obj) {
                return rv;
            }

            // Get unwrapping key (central gate: login, CKA_UNWRAP, lifecycle, type).
            let uk_arc = match hsm
                .object_store
                .get_object_in_slot(unwrapping_key, s.slot_id)
            {
                Ok(o) => o,
                Err(_) => return CKR_UNWRAPPING_KEY_HANDLE_INVALID,
            };
            let uk_obj = uk_arc.read();
            if let Err(rv) = authorize_key_use(&s, &uk_obj, KeyUsage::Unwrap, mechanism) {
                return match rv {
                    CKR_KEY_TYPE_INCONSISTENT => CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
                    other => other,
                };
            }
            // PKCS#11: sensitivity is inherited from a sensitive unwrapping key.
            if uk_obj.sensitive && !obj.sensitive {
                return CKR_TEMPLATE_INCONSISTENT;
            }
            let uk_bytes = match &uk_obj.key_material {
                Some(km) => km.as_bytes(),
                None => return CKR_UNWRAPPING_KEY_HANDLE_INVALID,
            };
            match hsm.crypto_backend.aes_key_unwrap(
                uk_bytes,
                wrapped_data,
                mechanism == CKM_AES_KEY_WRAP_KWP,
            ) {
                Ok(u) => u,
                Err(HsmError::DataLenRange) => return CKR_WRAPPED_KEY_LEN_RANGE,
                Err(HsmError::EncryptedDataInvalid)
                | Err(HsmError::DataInvalid)
                | Err(HsmError::EncryptedDataLenRange) => return CKR_WRAPPED_KEY_INVALID,
                Err(e) => return err_to_rv(e),
            }
        };
        let len = unwrapped.len();
        if len != 16 && len != 24 && len != 32 {
            return CKR_WRAPPED_KEY_INVALID;
        }
        if requested_len.is_some_and(|r| r as usize != len) {
            return CKR_TEMPLATE_INCONSISTENT;
        }
        obj.value_len = Some(len as CK_ULONG);
        obj.key_material = Some(RawKeyMaterial::new(unwrapped.to_vec()));
        drop(unwrapped); // Zeroizing

        let ctx = sess.read().object_ctx();
        let result = hsm
            .object_store
            .insert_object_in(obj, &ctx, ObjectOrigin::Unwrapped);
        let rv = match &result {
            Ok(_) => CKR_OK,
            Err(e) => CK_RV::from(e.clone()),
        };
        let audited = audit_sync(
            &hsm,
            session,
            AuditOperation::UnwrapKey {
                mechanism: mechanism as u64,
                fips_approved: mechanisms::is_fips_approved(mechanism),
            },
            audit_result(rv),
            Some(match &result {
                Ok(h) => format!("unwrapping_key={unwrapping_key},key={h}"),
                Err(_) => format!("unwrapping_key={unwrapping_key}"),
            }),
        );
        let handle = match result {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };
        if let Err(arv) = audited {
            let _ = hsm.object_store.destroy_object_in(handle, ctx.slot_id);
            return arv;
        }
        // SAFETY: ph_key non-null (checked above).
        unsafe {
            *ph_key = handle;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DeriveKey(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    base_key: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    attr_count: CK_ULONG,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() || ph_key.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };

        // SAFETY: p_mechanism non-null (checked above). (Pattern 3)
        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_derive_mechanism(mechanism) && !mechanisms::is_kem_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }
        if let Err(rv) = audit_gate(&hsm) {
            return rv;
        }

        // SAFETY: caller contract (NULL is accepted only with attr_count == 0).
        let template = match unsafe { parse_template(p_template, attr_count) } {
            Ok(t) => t,
            Err(rv) => return rv,
        };
        match template_ulong(&template, CKA_CLASS) {
            Ok(None) | Ok(Some(CKO_SECRET_KEY)) => {}
            Ok(Some(_)) => return CKR_TEMPLATE_INCONSISTENT,
            Err(rv) => return rv,
        }
        match template_ulong(&template, CKA_KEY_TYPE) {
            Ok(None) | Ok(Some(CKK_AES)) => {}
            Ok(Some(_)) => return CKR_TEMPLATE_INCONSISTENT,
            Err(rv) => return rv,
        }
        // Parse CKA_VALUE_LEN early so ECDH can derive exactly the right length.
        let requested_len = match template_ulong(&template, CKA_VALUE_LEN) {
            Ok(v) => v.map(|v| v as usize),
            Err(rv) => return rv,
        };
        // Validate requested length is a valid AES key size
        if let Some(req_len) = requested_len {
            if req_len != 16 && req_len != 24 && req_len != 32 {
                return CKR_KEY_SIZE_RANGE;
            }
        }

        let handle = match hsm.object_store.next_handle() {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };
        let mut obj = StoredObject::new(handle, CKO_SECRET_KEY);
        obj.key_type = Some(CKK_AES);
        obj.sensitive = true;
        obj.extractable = false;
        obj.private = true;
        obj.can_encrypt = true;
        obj.can_decrypt = true;

        // ML-KEM: the parameter is the ciphertext. ECDH: CK_ECDH1_DERIVE_PARAMS
        // (kdf, pSharedData, pPublicData) — or, for backward compatibility,
        // the raw peer point (X9.63 SHA-256 KDF, no shared data). H2-06/A2-12.
        let (kem_ciphertext, ecdh_params) = if pqc::is_ml_kem_mechanism(mechanism) {
            // SAFETY: p_mechanism non-null (checked above).
            let ct = match unsafe { extract_mechanism_param(p_mechanism) } {
                Ok(ct) if !ct.is_empty() => ct,
                Ok(_) => return CKR_MECHANISM_PARAM_INVALID,
                Err(rv) => return rv,
            };
            (ct, None)
        } else {
            // SAFETY: size checked by read_param_struct.
            let parsed =
                if let Some(p) = unsafe { read_param_struct::<CkEcdh1DeriveParams>(p_mechanism) } {
                    // SAFETY: pointers come from the caller's CK_ECDH1_DERIVE_PARAMS.
                    let shared =
                        match unsafe { copy_param_bytes(p.p_shared_data, p.ul_shared_data_len) } {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                    // SAFETY: as above.
                    let public =
                        match unsafe { copy_param_bytes(p.p_public_data, p.ul_public_data_len) } {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                    crate::crypto::params::EcdhParams::from_ck(p.kdf, &shared, &public)
                } else {
                    // SAFETY: p_mechanism non-null (checked above).
                    match unsafe { extract_mechanism_param(p_mechanism) } {
                        Ok(point) => crate::crypto::params::EcdhParams::from_legacy_point(&point),
                        Err(rv) => return rv,
                    }
                };
            match parsed {
                Ok(p) => (Vec::new(), Some(p)),
                Err(e) => return err_to_rv(e),
            }
        };

        let (shared_secret, bk_origin) = {
            let s = sess.read();
            if let Err(rv) =
                apply_key_template(&mut obj, &template, &[CKA_VALUE_LEN], s.state.is_so())
            {
                return rv;
            }
            // Deriving creates a secret key: normal user; token objects need R/W (H1-10).
            if let Err(rv) = check_create_allowed(&s, &obj) {
                return rv;
            }

            // Base key: central gate — login, CKA_DERIVE, lifecycle, key
            // type (EC / ML-KEM private key) (H1-11 / H1-20).
            let bk_arc = match hsm.object_store.get_object_in_slot(base_key, s.slot_id) {
                Ok(o) => o,
                Err(_) => return CKR_KEY_HANDLE_INVALID,
            };
            let bk_obj = bk_arc.read();
            if let Err(rv) = authorize_key_use(&s, &bk_obj, KeyUsage::Derive, mechanism) {
                return rv;
            }
            // PKCS#11: if the base key is sensitive, the derived key must be too.
            if bk_obj.sensitive && !obj.sensitive {
                return CKR_TEMPLATE_INCONSISTENT;
            }
            let bk_bytes = match &bk_obj.key_material {
                Some(km) => km.as_bytes(),
                None => return CKR_KEY_HANDLE_INVALID,
            };
            let origin = ObjectOrigin::Derived {
                base_always_sensitive: bk_obj.always_sensitive,
                base_never_extractable: bk_obj.never_extractable,
            };
            let secret = if let Some(variant) = pqc::mechanism_to_ml_kem_variant(mechanism) {
                // ML-KEM decapsulation: base key is dk seed, param is ciphertext
                match pqc::ml_kem_decapsulate(bk_bytes, &kem_ciphertext, variant) {
                    Ok(ss) => RawKeyMaterial::new(ss.to_vec()),
                    Err(e) => return err_to_rv(e),
                }
            } else {
                let curve = match ec_curve_of(&bk_obj) {
                    Ok(c) => c,
                    Err(_) => return CKR_CURVE_NOT_SUPPORTED,
                };
                let Some(params) = ecdh_params.as_ref() else {
                    return CKR_MECHANISM_PARAM_INVALID;
                };
                match hsm.crypto_backend.ecdh_derive(
                    curve,
                    bk_bytes,
                    params,
                    requested_len.unwrap_or(32),
                    hsm.algorithm_config.fips_approved_only,
                ) {
                    Ok(s) => s,
                    Err(e) => return err_to_rv(e),
                }
            };
            (secret, origin)
        };

        // Validate the derived secret is a valid AES key size
        let secret_len = shared_secret.len();
        if secret_len != 16 && secret_len != 24 && secret_len != 32 {
            return CKR_KEY_SIZE_RANGE;
        }
        if requested_len.is_some_and(|r| r != secret_len) {
            return CKR_TEMPLATE_INCONSISTENT;
        }
        obj.key_material = Some(shared_secret);
        obj.value_len = Some(secret_len as CK_ULONG);

        let ctx = sess.read().object_ctx();
        let result = hsm.object_store.insert_object_in(obj, &ctx, bk_origin);
        let rv = match &result {
            Ok(_) => CKR_OK,
            Err(e) => CK_RV::from(e.clone()),
        };
        let audited = audit_sync(
            &hsm,
            session,
            AuditOperation::DeriveKey {
                mechanism: mechanism as u64,
                fips_approved: mechanisms::is_fips_approved(mechanism),
            },
            audit_result(rv),
            Some(match &result {
                Ok(h) => format!("base_key={base_key},key={h}"),
                Err(_) => format!("base_key={base_key}"),
            }),
        );
        let handle = match result {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };
        if let Err(arv) = audited {
            let _ = hsm.object_store.destroy_object_in(handle, ctx.slot_id);
            return arv;
        }
        // SAFETY: ph_key non-null (checked above).
        unsafe {
            *ph_key = handle;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionStatus(session: CK_SESSION_HANDLE) -> CK_RV {
    // Legacy function: CKR_FUNCTION_NOT_PARALLEL after the initialization
    // and session checks (A2-22 / H1-35).
    catch_unwind(|| match check_session_only(session) {
        CKR_OK => CKR_FUNCTION_NOT_PARALLEL,
        rv => rv,
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_CancelFunction(session: CK_SESSION_HANDLE) -> CK_RV {
    catch_unwind(|| match check_session_only(session) {
        CKR_OK => CKR_FUNCTION_NOT_PARALLEL,
        rv => rv,
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_WaitForSlotEvent(
    _flags: CK_FLAGS,
    _slot: CK_SLOT_ID_PTR,
    _reserved: CK_VOID_PTR,
) -> CK_RV {
    catch_unwind(|| match get_hsm() {
        Ok(_) => CKR_FUNCTION_NOT_SUPPORTED,
        Err(rv) => rv,
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ============================================================================
// PKCS#11 v3.0 functions (A2-01)
// ============================================================================

/// Interface name of both function lists (`"PKCS 11"`, NUL-terminated).
static INTERFACE_NAME: [u8; 8] = *b"PKCS 11\0";

/// The interfaces returned by `C_GetInterfaceList` / `C_GetInterface`: the
/// v3.0 function list (default) and the v2.40 one.
struct Interfaces([CK_INTERFACE; 2]);
// SAFETY: the table only holds pointers to immutable statics.
unsafe impl Sync for Interfaces {}

static INTERFACES: Interfaces = Interfaces([
    CK_INTERFACE {
        pInterfaceName: INTERFACE_NAME.as_ptr() as *mut CK_UTF8CHAR,
        pFunctionList: &FUNCTION_LIST_3_0 as *const CK_FUNCTION_LIST_3_0 as CK_VOID_PTR,
        flags: 0,
    },
    CK_INTERFACE {
        pInterfaceName: INTERFACE_NAME.as_ptr() as *mut CK_UTF8CHAR,
        pFunctionList: &FUNCTION_LIST as *const CK_FUNCTION_LIST as CK_VOID_PTR,
        flags: 0,
    },
]);

/// Versions of the entries of [`INTERFACES`].
const INTERFACE_VERSIONS: [CK_VERSION; 2] = [CRYPTOKI_VERSION_3_0, CRYPTOKI_VERSION_2_40];

/// `C_GetInterfaceList` (v3.0 §5.2): lists the "PKCS 11" v3.0 and v2.40
/// interfaces. May be called before `C_Initialize`.
///
/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_GetInterfaceList(
    p_interfaces_list: CK_INTERFACE_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        if pul_count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let n = INTERFACES.0.len();
        if p_interfaces_list.is_null() {
            // SAFETY: pul_count non-null (checked above).
            unsafe {
                *pul_count = n as CK_ULONG;
            }
            return CKR_OK;
        }
        // SAFETY: as above.
        if (unsafe { *pul_count } as usize) < n {
            // SAFETY: as above.
            unsafe {
                *pul_count = n as CK_ULONG;
            }
            return CKR_BUFFER_TOO_SMALL;
        }
        for (i, iface) in INTERFACES.0.iter().enumerate() {
            // SAFETY: the caller's array holds at least n entries (checked above).
            unsafe { std::ptr::write_unaligned(p_interfaces_list.add(i), *iface) };
        }
        // SAFETY: as above.
        unsafe {
            *pul_count = n as CK_ULONG;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// `C_GetInterface` (v3.0 §5.2): returns the first interface matching the
/// optional name, the optional version and all requested flags. With no name
/// and no version the default (v3.0) interface is returned. May be called
/// before `C_Initialize`.
///
/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. `pInterfaceName`, when non-NULL, must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn C_GetInterface(
    p_interface_name: CK_UTF8CHAR_PTR,
    p_version: CK_VERSION_PTR,
    pp_interface: CK_INTERFACE_PTR_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    catch_unwind(|| {
        if pp_interface.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let name_matches = if p_interface_name.is_null() {
            true
        } else {
            // Compare with "PKCS 11" (bounded read of a NUL-terminated string).
            let want = &INTERFACE_NAME[..INTERFACE_NAME.len() - 1];
            let mut ok = true;
            for (i, expected) in want.iter().chain(std::iter::once(&0u8)).enumerate() {
                // SAFETY: the caller's string is NUL-terminated; we stop at the
                // first mismatch or NUL, so we never read past its terminator.
                let c = unsafe { *p_interface_name.add(i) };
                if c != *expected {
                    ok = false;
                    break;
                }
            }
            ok
        };
        if !name_matches {
            return CKR_ARGUMENTS_BAD;
        }
        let wanted_version = if p_version.is_null() {
            None
        } else {
            // SAFETY: non-null CK_VERSION supplied by the caller.
            Some(unsafe { std::ptr::read_unaligned(p_version) })
        };
        for (i, iface) in INTERFACES.0.iter().enumerate() {
            let v = INTERFACE_VERSIONS[i];
            if let Some(w) = wanted_version {
                if w.major != v.major || w.minor != v.minor {
                    continue;
                }
            }
            if iface.flags & flags != flags {
                continue;
            }
            // SAFETY: pp_interface non-null (checked above); the pointee is a
            // static that lives for the whole program.
            unsafe {
                *pp_interface = &INTERFACES.0[i] as *const CK_INTERFACE as CK_INTERFACE_PTR;
            }
            return CKR_OK;
        }
        CKR_ARGUMENTS_BAD
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// `C_LoginUser` (v3.0): like `C_Login`, with a user name. The token has a
/// single normal user and a single SO, so the name is validated (UTF-8,
/// consistent pointer/length) but not used for authentication.
///
/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_LoginUser(
    session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    p_pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
    p_username: CK_UTF8CHAR_PTR,
    username_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        if let Err(rv) = get_hsm() {
            return rv;
        }
        // SAFETY: caller contract; the length is bounded first.
        let name = match unsafe {
            caller_slice(p_username, username_len, MAX_PIN_BYTES, CKR_ARGUMENTS_BAD)
        } {
            Ok(n) => n,
            Err(rv) => return rv,
        };
        if std::str::from_utf8(name).is_err() {
            return CKR_ARGUMENTS_BAD;
        }
        // SAFETY: forwarded caller contract.
        unsafe { login_impl(session, user_type, p_pin, pin_len) }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// `C_SessionCancel` (v3.0): terminates the active operations selected by
/// `flags` (`CKF_ENCRYPT`, `CKF_DECRYPT`, `CKF_DIGEST`, `CKF_SIGN`,
/// `CKF_VERIFY`, `CKF_FIND_OBJECTS`, `CKF_MESSAGE_ENCRYPT`,
/// `CKF_MESSAGE_DECRYPT`, ...). Operations of other kinds are left alone.
///
/// # Safety
///
/// PKCS#11 C ABI entry point; takes no pointer arguments.
#[no_mangle]
pub unsafe extern "C" fn C_SessionCancel(session: CK_SESSION_HANDLE, flags: CK_FLAGS) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();
        let cancel = match &sess.active_operation {
            Some(ActiveOperation::Encrypt { .. }) => flags & CKF_ENCRYPT != 0,
            Some(ActiveOperation::Decrypt { .. }) => flags & CKF_DECRYPT != 0,
            Some(ActiveOperation::Digest { .. }) => flags & CKF_DIGEST != 0,
            Some(ActiveOperation::Sign { .. }) => flags & CKF_SIGN != 0,
            Some(ActiveOperation::Verify { .. }) => flags & CKF_VERIFY != 0,
            None => false,
        };
        if cancel {
            sess.active_operation = None;
            sess.context_login_required = false;
        }
        if flags & CKF_FIND_OBJECTS != 0 {
            sess.find_context = None;
        }
        let cancel_msg = match &sess.message_op {
            Some(m) if m.encrypt => flags & CKF_MESSAGE_ENCRYPT != 0,
            Some(_) => flags & CKF_MESSAGE_DECRYPT != 0,
            None => false,
        };
        if cancel_msg {
            sess.message_op = None;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// `CK_GCM_MESSAGE_PARAMS` (v3.0 message-based AES-GCM).
#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Clone, Copy)]
struct CkGcmMessageParams {
    p_iv: *mut u8,
    ul_iv_len: CK_ULONG,
    ul_iv_fixed_bits: CK_ULONG,
    iv_generator: CK_ULONG,
    p_tag: *mut u8,
    ul_tag_bits: CK_ULONG,
}

/// Read a `CK_GCM_MESSAGE_PARAMS` passed as a per-message parameter.
///
/// # Safety
/// `p` must point to `len` readable bytes when non-null.
unsafe fn read_gcm_message_params(
    p: CK_VOID_PTR,
    len: CK_ULONG,
) -> Result<CkGcmMessageParams, CK_RV> {
    if p.is_null() || len as usize != std::mem::size_of::<CkGcmMessageParams>() {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    // SAFETY: size checked; caller contract.
    Ok(unsafe { std::ptr::read_unaligned(p as *const CkGcmMessageParams) })
}

/// Shared implementation of `C_MessageEncryptInit` / `C_MessageDecryptInit`
/// (only `CKM_AES_GCM` is supported).
///
/// # Safety
/// `p_mechanism` must be a valid `CK_MECHANISM` pointer or NULL.
unsafe fn message_crypt_init(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
    encrypt: bool,
) -> CK_RV {
    let hsm = match get_hsm() {
        Ok(h) => h,
        Err(rv) => return rv,
    };
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let sess = match hsm.session_manager.get_session(session) {
        Ok(s) => s,
        Err(e) => return err_to_rv(e),
    };
    let mut sess = sess.write();
    if sess.message_op.is_some() {
        return CKR_OPERATION_ACTIVE;
    }
    // SAFETY: p_mechanism non-null (checked above). (Pattern 3)
    let mechanism = unsafe { (*p_mechanism).mechanism };
    if mechanism != CKM_AES_GCM {
        return CKR_MECHANISM_INVALID;
    }
    if let Err(rv) =
        mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
    {
        return rv;
    }
    if let Err(rv) = audit_gate(&hsm) {
        return rv;
    }
    let obj = match hsm.object_store.get_object_in_slot(key, sess.slot_id) {
        Ok(o) => o,
        Err(_) => return CKR_KEY_HANDLE_INVALID,
    };
    let usage = if encrypt {
        KeyUsage::Encrypt
    } else {
        KeyUsage::Decrypt
    };
    if let Err(rv) = authorize_key_use(&sess, &obj.read(), usage, mechanism) {
        return rv;
    }
    sess.message_op = Some(MessageOperation {
        encrypt,
        mechanism,
        key_handle: key,
        cached_object: obj,
    });
    CKR_OK
}

/// One single-part AES-GCM message (`C_EncryptMessage` / `C_DecryptMessage`).
///
/// # Safety
/// All pointer arguments must satisfy the PKCS#11 contract for their lengths.
#[allow(clippy::too_many_arguments)]
unsafe fn crypt_message(
    session: CK_SESSION_HANDLE,
    encrypt: bool,
    p_parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    p_aad: CK_BYTE_PTR,
    aad_len: CK_ULONG,
    p_in: CK_BYTE_PTR,
    in_len: CK_ULONG,
    p_out: CK_BYTE_PTR,
    pul_out_len: CK_ULONG_PTR,
) -> CK_RV {
    use crate::crypto::params::{GcmParams, GCM_IV_LEN};
    let hsm = match get_hsm() {
        Ok(h) => h,
        Err(rv) => return rv,
    };
    let sess = match hsm.session_manager.get_session(session) {
        Ok(s) => s,
        Err(e) => return err_to_rv(e),
    };
    let sess = sess.read();
    let (mechanism, obj) = match &sess.message_op {
        Some(m) if m.encrypt == encrypt => (m.mechanism, m.cached_object.clone()),
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if pul_out_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // SAFETY: caller contract.
    let params = match unsafe { read_gcm_message_params(p_parameter, parameter_len) } {
        Ok(p) => p,
        Err(rv) => return rv,
    };
    // SAFETY: caller contract; lengths are bounded first.
    let (aad, input) = match unsafe {
        caller_slice(
            p_aad,
            aad_len,
            crate::crypto::params::GCM_MAX_AAD_LEN,
            CKR_ARGUMENTS_BAD,
        )
        .and_then(|a| {
            caller_slice(p_in, in_len, MAX_SINGLE_BUFFER, CKR_DATA_LEN_RANGE).map(|d| (a, d))
        })
    } {
        Ok(v) => v,
        Err(rv) => return rv,
    };
    let out_len = input.len();
    if p_out.is_null() {
        // SAFETY: pul_out_len non-null (checked above).
        unsafe {
            *pul_out_len = out_len as CK_ULONG;
        }
        return CKR_OK;
    }
    // SAFETY: as above.
    if (unsafe { *pul_out_len } as usize) < out_len {
        // SAFETY: as above.
        unsafe {
            *pul_out_len = out_len as CK_ULONG;
        }
        return CKR_BUFFER_TOO_SMALL;
    }
    let iv_len = params.ul_iv_len as usize;
    let tag_bits = params.ul_tag_bits;
    if params.p_iv.is_null() || iv_len != GCM_IV_LEN || params.p_tag.is_null() {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    let tag_len = match usize::try_from(tag_bits) {
        Ok(b) if b % 8 == 0 => b / 8,
        _ => return CKR_MECHANISM_PARAM_INVALID,
    };
    let fips = hsm.algorithm_config.fips_approved_only;

    let obj = obj.read();
    let key_bytes = match &obj.key_material {
        Some(km) => km.as_bytes(),
        None => return CKR_KEY_HANDLE_INVALID,
    };
    let audit_op_enc = AuditOperation::Encrypt {
        mechanism: mechanism as u64,
        fips_approved: mechanisms::is_fips_approved(mechanism),
    };
    let audit_op_dec = AuditOperation::Decrypt {
        mechanism: mechanism as u64,
        fips_approved: mechanisms::is_fips_approved(mechanism),
    };

    if encrypt {
        // IV generation (v3.0 CKG_*): the module generates the whole 96-bit IV
        // from the approved RBG for CKG_GENERATE / CKG_GENERATE_RANDOM (IG C.H
        // scenario 2) and returns it through pIv; a caller IV
        // (CKG_NO_GENERATE) is refused in FIPS approved mode.
        let fixed_bits = params.ul_iv_fixed_bits;
        let (iv, generated) = match params.iv_generator {
            CKG_NO_GENERATE => {
                if fips {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                // SAFETY: pIv non-null, 12 bytes (checked above).
                let mut iv = [0u8; GCM_IV_LEN];
                iv.copy_from_slice(unsafe { slice::from_raw_parts(params.p_iv, GCM_IV_LEN) });
                (iv, false)
            }
            CKG_GENERATE | CKG_GENERATE_RANDOM if fixed_bits == 0 => {
                let mut iv = [0u8; GCM_IV_LEN];
                if let Err(e) = hsm.crypto_backend.generate_random(&mut iv) {
                    return err_to_rv(e);
                }
                (iv, true)
            }
            _ => return CKR_MECHANISM_PARAM_INVALID,
        };
        let gcm = match GcmParams::new(&iv, aad, tag_bits, generated) {
            Ok(p) => p,
            Err(e) => return err_to_rv(e),
        };
        let result = hsm
            .crypto_backend
            .aes_gcm_encrypt(key_bytes, &gcm, input, fips);
        let sealed = match result {
            Ok(v) => v,
            Err(e) => {
                let rv = err_to_rv(e);
                if let Err(arv) =
                    audit(&hsm, session, audit_op_enc, AuditResult::Failure(rv as u64))
                {
                    return arv;
                }
                return rv;
            }
        };
        if sealed.len() != out_len + tag_len {
            return CKR_GENERAL_ERROR;
        }
        if let Err(rv) = audit(&hsm, session, audit_op_enc, AuditResult::Success) {
            return rv;
        }
        // SAFETY: capacities checked above (out buffer >= out_len; pTag holds
        // ulTagBits / 8 bytes, pIv 12 bytes per the parameter contract).
        unsafe {
            std::ptr::copy_nonoverlapping(sealed.as_ptr(), p_out, out_len);
            std::ptr::copy_nonoverlapping(sealed[out_len..].as_ptr(), params.p_tag, tag_len);
            if generated {
                std::ptr::copy_nonoverlapping(iv.as_ptr(), params.p_iv, GCM_IV_LEN);
            }
            *pul_out_len = out_len as CK_ULONG;
        }
        CKR_OK
    } else {
        // SAFETY: pIv non-null and 12 bytes; pTag holds ulTagBits / 8 bytes.
        let (iv, tag) = unsafe {
            (
                slice::from_raw_parts(params.p_iv as *const u8, GCM_IV_LEN),
                slice::from_raw_parts(params.p_tag as *const u8, tag_len),
            )
        };
        let gcm = match GcmParams::new(iv, aad, tag_bits, false) {
            Ok(p) => p,
            Err(e) => return err_to_rv(e),
        };
        let mut ct = Vec::with_capacity(input.len() + tag_len);
        ct.extend_from_slice(input);
        ct.extend_from_slice(tag);
        let result = hsm.crypto_backend.aes_gcm_decrypt(key_bytes, &gcm, &ct);
        let plain = match result {
            Ok(p) => p,
            Err(e) => {
                let rv = err_to_rv(e);
                if let Err(arv) =
                    audit(&hsm, session, audit_op_dec, AuditResult::Failure(rv as u64))
                {
                    return arv;
                }
                return rv;
            }
        };
        if plain.len() != out_len {
            return CKR_GENERAL_ERROR;
        }
        if let Err(rv) = audit(&hsm, session, audit_op_dec, AuditResult::Success) {
            return rv;
        }
        // SAFETY: the output buffer holds at least out_len bytes (checked above).
        unsafe {
            std::ptr::copy_nonoverlapping(plain.as_ptr(), p_out, out_len);
            *pul_out_len = out_len as CK_ULONG;
        }
        CKR_OK
    }
}

/// End a message-based encrypt / decrypt context.
fn message_crypt_final(session: CK_SESSION_HANDLE, encrypt: bool) -> CK_RV {
    let hsm = match get_hsm() {
        Ok(h) => h,
        Err(rv) => return rv,
    };
    let sess = match hsm.session_manager.get_session(session) {
        Ok(s) => s,
        Err(e) => return err_to_rv(e),
    };
    let mut sess = sess.write();
    match &sess.message_op {
        Some(m) if m.encrypt == encrypt => {
            sess.message_op = None;
            CKR_OK
        }
        _ => CKR_OPERATION_NOT_INITIALIZED,
    }
}

/// Multi-part messages (`C_*MessageBegin` / `C_*MessageNext`) are not
/// supported (`CKF_MULTI_MESSAGE` is not advertised).
fn message_multipart(session: CK_SESSION_HANDLE, encrypt: bool) -> CK_RV {
    let hsm = match get_hsm() {
        Ok(h) => h,
        Err(rv) => return rv,
    };
    let sess = match hsm.session_manager.get_session(session) {
        Ok(s) => s,
        Err(e) => return err_to_rv(e),
    };
    let sess = sess.read();
    match &sess.message_op {
        Some(m) if m.encrypt == encrypt => CKR_FUNCTION_NOT_SUPPORTED,
        _ => CKR_OPERATION_NOT_INITIALIZED,
    }
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_MessageEncryptInit(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    // SAFETY: forwarded caller contract.
    catch_unwind(|| unsafe { message_crypt_init(session, p_mechanism, key, true) })
        .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_EncryptMessage(
    session: CK_SESSION_HANDLE,
    p_parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    p_associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
    p_plaintext: CK_BYTE_PTR,
    plaintext_len: CK_ULONG,
    p_ciphertext: CK_BYTE_PTR,
    pul_ciphertext_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        // SAFETY: forwarded caller contract.
        unsafe {
            crypt_message(
                session,
                true,
                p_parameter,
                parameter_len,
                p_associated_data,
                associated_data_len,
                p_plaintext,
                plaintext_len,
                p_ciphertext,
                pul_ciphertext_len,
            )
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_EncryptMessageBegin(
    session: CK_SESSION_HANDLE,
    _p_parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
    _p_associated_data: CK_BYTE_PTR,
    _associated_data_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| message_multipart(session, true)).unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_EncryptMessageNext(
    session: CK_SESSION_HANDLE,
    _p_parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
    _p_plaintext_part: CK_BYTE_PTR,
    _plaintext_part_len: CK_ULONG,
    _p_ciphertext_part: CK_BYTE_PTR,
    _pul_ciphertext_part_len: CK_ULONG_PTR,
    _flags: CK_FLAGS,
) -> CK_RV {
    catch_unwind(|| message_multipart(session, true)).unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_MessageEncryptFinal(session: CK_SESSION_HANDLE) -> CK_RV {
    catch_unwind(|| message_crypt_final(session, true)).unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_MessageDecryptInit(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    // SAFETY: forwarded caller contract.
    catch_unwind(|| unsafe { message_crypt_init(session, p_mechanism, key, false) })
        .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DecryptMessage(
    session: CK_SESSION_HANDLE,
    p_parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    p_associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
    p_ciphertext: CK_BYTE_PTR,
    ciphertext_len: CK_ULONG,
    p_plaintext: CK_BYTE_PTR,
    pul_plaintext_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        // SAFETY: forwarded caller contract.
        unsafe {
            crypt_message(
                session,
                false,
                p_parameter,
                parameter_len,
                p_associated_data,
                associated_data_len,
                p_ciphertext,
                ciphertext_len,
                p_plaintext,
                pul_plaintext_len,
            )
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DecryptMessageBegin(
    session: CK_SESSION_HANDLE,
    _p_parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
    _p_associated_data: CK_BYTE_PTR,
    _associated_data_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| message_multipart(session, false)).unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_DecryptMessageNext(
    session: CK_SESSION_HANDLE,
    _p_parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
    _p_ciphertext_part: CK_BYTE_PTR,
    _ciphertext_part_len: CK_ULONG,
    _p_plaintext_part: CK_BYTE_PTR,
    _pul_plaintext_part_len: CK_ULONG_PTR,
    _flags: CK_FLAGS,
) -> CK_RV {
    catch_unwind(|| message_multipart(session, false)).unwrap_or(CKR_GENERAL_ERROR)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_MessageDecryptFinal(session: CK_SESSION_HANDLE) -> CK_RV {
    catch_unwind(|| message_crypt_final(session, false)).unwrap_or(CKR_GENERAL_ERROR)
}

// Message-based signing is not supported (no mechanism advertises
// CKF_MESSAGE_SIGN / CKF_MESSAGE_VERIFY); the functions report
// CKR_FUNCTION_NOT_SUPPORTED after the initialization and session checks.

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_MessageSignInit(
    session: CK_SESSION_HANDLE,
    _p_mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_SignMessage(
    session: CK_SESSION_HANDLE,
    _p_parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
    _p_data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _p_signature: CK_BYTE_PTR,
    _pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_SignMessageBegin(
    session: CK_SESSION_HANDLE,
    _p_parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_SignMessageNext(
    session: CK_SESSION_HANDLE,
    _p_parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
    _p_data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _p_signature: CK_BYTE_PTR,
    _pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_MessageSignFinal(session: CK_SESSION_HANDLE) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_MessageVerifyInit(
    session: CK_SESSION_HANDLE,
    _p_mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_VerifyMessage(
    session: CK_SESSION_HANDLE,
    _p_parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
    _p_data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _p_signature: CK_BYTE_PTR,
    _signature_len: CK_ULONG,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_VerifyMessageBegin(
    session: CK_SESSION_HANDLE,
    _p_parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_VerifyMessageNext(
    session: CK_SESSION_HANDLE,
    _p_parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
    _p_data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _p_signature: CK_BYTE_PTR,
    _signature_len: CK_ULONG,
) -> CK_RV {
    not_supported(session)
}

/// # Safety
///
/// PKCS#11 C ABI entry point. The caller must follow the PKCS#11 calling
/// convention: every non-NULL pointer argument must be properly aligned and
/// valid for reads (inputs) or writes (outputs) of the size implied by the
/// PKCS#11 specification and the accompanying length argument for the whole
/// duration of the call, and buffers must not be mutated concurrently by
/// another thread. NULL is accepted only where the specification allows it.
#[no_mangle]
pub unsafe extern "C" fn C_MessageVerifyFinal(session: CK_SESSION_HANDLE) -> CK_RV {
    not_supported(session)
}

// ============================================================================
// Static function list
// ============================================================================

/// The v2.40 function list returned by `C_GetFunctionList` (version 2.40,
/// A2-01 / A3-16).
static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CRYPTOKI_VERSION_2_40,
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    C_GetOperationState,
    C_SetOperationState,
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    C_SignRecoverInit,
    C_SignRecover,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    C_VerifyRecoverInit,
    C_VerifyRecover,
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    C_GetFunctionStatus,
    C_CancelFunction,
    C_WaitForSlotEvent,
};

/// The v3.0 function list returned by `C_GetInterface` (A2-01).
static FUNCTION_LIST_3_0: CK_FUNCTION_LIST_3_0 = CK_FUNCTION_LIST_3_0 {
    version: CRYPTOKI_VERSION_3_0,
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    C_GetOperationState,
    C_SetOperationState,
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    C_SignRecoverInit,
    C_SignRecover,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    C_VerifyRecoverInit,
    C_VerifyRecover,
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    C_GetFunctionStatus,
    C_CancelFunction,
    C_WaitForSlotEvent,
    C_GetInterfaceList,
    C_GetInterface,
    C_LoginUser,
    C_SessionCancel,
    C_MessageEncryptInit,
    C_EncryptMessage,
    C_EncryptMessageBegin,
    C_EncryptMessageNext,
    C_MessageEncryptFinal,
    C_MessageDecryptInit,
    C_DecryptMessage,
    C_DecryptMessageBegin,
    C_DecryptMessageNext,
    C_MessageDecryptFinal,
    C_MessageSignInit,
    C_SignMessage,
    C_SignMessageBegin,
    C_SignMessageNext,
    C_MessageSignFinal,
    C_MessageVerifyInit,
    C_VerifyMessage,
    C_VerifyMessageBegin,
    C_VerifyMessageNext,
    C_MessageVerifyFinal,
};

// ============================================================================
// Helpers
// ============================================================================

/// Returns `true` if `attr_type` is a CK_BBOOL attribute per PKCS#11.
#[allow(dead_code)]
fn is_bool_attribute(attr_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attr_type,
        CKA_TOKEN
            | CKA_PRIVATE
            | CKA_SENSITIVE
            | CKA_EXTRACTABLE
            | CKA_ENCRYPT
            | CKA_DECRYPT
            | CKA_SIGN
            | CKA_VERIFY
            | CKA_WRAP
            | CKA_UNWRAP
            | CKA_DERIVE
            | CKA_MODIFIABLE
            | CKA_DESTROYABLE
            | CKA_COPYABLE
            | CKA_TRUSTED
            | CKA_LOCAL
            | CKA_ALWAYS_SENSITIVE
            | CKA_NEVER_EXTRACTABLE
            | CKA_WRAP_WITH_TRUSTED
    )
}

/// Parse a CK_BBOOL value from attribute bytes.
/// Returns `CKR_ATTRIBUTE_VALUE_INVALID` if `value.len()` is not exactly
/// `std::mem::size_of::<CK_BBOOL>()` (1 byte), per PKCS#11 spec.
fn parse_ck_bbool(value: &[u8]) -> Result<bool, CK_RV> {
    if value.len() != std::mem::size_of::<CK_BBOOL>() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    Ok(value[0] != 0)
}

/// A parsed attribute template. Values may carry secret key material
/// (`CKA_VALUE`, private-key components), so they are zeroized on drop
/// (H1-21).
#[derive(Default)]
struct Template(Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>);

impl Drop for Template {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for (_, v) in self.0.iter_mut() {
            v.zeroize();
        }
    }
}

impl std::ops::Deref for Template {
    type Target = [(CK_ATTRIBUTE_TYPE, Vec<u8>)];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Parse a PKCS#11 attribute template from C pointers into safe Rust types.
///
/// Returns `Err(CKR_ARGUMENTS_BAD)` if `count` exceeds `MAX_TEMPLATE_ATTRS`
/// or an attribute has a NULL `pValue` with a non-zero length (H1-23), and
/// `Err(CKR_ATTRIBUTE_VALUE_INVALID)` if a value exceeds
/// `MAX_ATTR_VALUE_LEN`. Lengths are checked before any slice is built.
///
/// # Safety
/// `p_template` must point to `count` valid `CK_ATTRIBUTE` structs, and each
/// non-NULL `pValue` must point to `ulValueLen` readable bytes.
unsafe fn parse_template(p_template: CK_ATTRIBUTE_PTR, count: CK_ULONG) -> Result<Template, CK_RV> {
    let count_usize = count as usize;

    // Reject template counts exceeding the safety limit rather than silently
    // clamping — the caller must know their template was not fully processed.
    if count_usize > MAX_TEMPLATE_ATTRS {
        tracing::error!(
            "parse_template: count {} exceeds MAX_TEMPLATE_ATTRS ({})",
            count_usize,
            MAX_TEMPLATE_ATTRS
        );
        return Err(CKR_ARGUMENTS_BAD);
    }
    if count_usize == 0 {
        return Ok(Template::default());
    }
    if p_template.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }

    // SAFETY: p_template validated by caller, count matches array length. (Pattern 2)
    let attrs = unsafe { slice::from_raw_parts(p_template, count_usize) };
    let mut result = Template(Vec::with_capacity(count_usize));
    for attr in attrs {
        let atype = { attr.attr_type };
        // SAFETY: caller contract; the length is bounded before the slice is built.
        let value = match unsafe {
            caller_slice(
                attr.p_value as *const u8,
                attr.value_len,
                MAX_ATTR_VALUE_LEN,
                CKR_ATTRIBUTE_VALUE_INVALID,
            )
        } {
            Ok(v) => v.to_vec(),
            Err(rv) => {
                tracing::error!(
                    "parse_template: attribute 0x{:08X} has an invalid value length",
                    atype
                );
                return Err(rv);
            }
        };
        result.0.push((atype, value));
    }
    Ok(result)
}
