// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! PKCS#11 spy — a logging interposer for any PKCS#11 v2.40 / v3.0 module.
//!
//! Usage:
//!   * `PKCS11_SPY_TARGET` — absolute path of the real PKCS#11 module.
//!   * `PKCS11_SPY_LOG` — log file path (`-` = stderr, `off` = disabled;
//!     unset = disabled with a warning).
//!   * `PKCS11_SPY_REDUCED_TIMING` — default on (ms timing); `0` for µs.
//!
//! Load this library as the PKCS#11 provider in the application.
//!
//! # Architecture (H6-01 / H6-05)
//!
//! `C_GetFunctionList` returns the spy's **own** `CK_FUNCTION_LIST` (v2.40)
//! and `C_GetInterfaceList` / `C_GetInterface` return spy-owned `CK_INTERFACE`
//! records whose tables (`CK_FUNCTION_LIST` v2.40 and, when the target offers
//! one, `CK_FUNCTION_LIST_3_0`) point at the spy's logging wrappers. Every
//! wrapper forwards through the target's function table, which is resolved
//! once at load time (no per-call `dlsym`). A NULL target entry, or a v3.0
//! function on a target without a v3.0 interface, yields
//! `CKR_FUNCTION_NOT_SUPPORTED`. PKCS#11 v3.2 additions (`C_EncapsulateKey`,
//! `C_DecapsulateKey`, `C_VerifySignature*`, `C_Async*`,
//! `C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated`,
//! `C_GetSessionValidationFlags`) are deliberately **not** offered: the spy
//! advertises only the interfaces it can fully log ("PKCS 11" 3.0 and 2.40),
//! so a v3.2 application falls back to the 3.0 interface.
//!
//! # Transparency (H6-14)
//!
//! Arguments are forwarded unchanged; the spy never substitutes its own
//! validation for the module's (e.g. `C_GetInfo(NULL)` reaches the module).
//! The only calls the spy answers itself are the ones it implements:
//! `C_GetFunctionList`, `C_GetInterfaceList`, `C_GetInterface`. Those emit an
//! `"event":"rejected"` record when refused.
//!
//! # Robustness (H6-04 / H6-12)
//!
//! Every exported function body runs inside `catch_unwind`; configuration or
//! load errors return `CKR_GENERAL_ERROR`, never a panic across `extern "C"`.
//! Self-targeting, symbol interposition, re-entry during loading and runaway
//! recursion (depth > 16 per thread) are detected and return an error.
//!
//! # Redaction policy (H6-15 / H6-16) — enforced by `tests::redaction_policy`
//!
//! | Category | Policy |
//! |---|---|
//! | PIN / password bytes **and lengths** (`C_Login`, `C_LoginUser`, `C_InitPIN`, `C_SetPIN`, `C_InitToken`) | never logged |
//! | User names (`C_LoginUser`), token labels (`C_InitToken`) | never logged (may carry PII) |
//! | Attribute templates and values | never read; only the attribute count |
//! | Data buffers (plaintext, ciphertext, signature, digest, wrapped key, random, op-state, AAD) | never read; input lengths only |
//! | Mechanism | the `mechanism` type only; `pParameter` is never read |
//! | Message parameters (`pParameter` of `C_*Message*`) | length only |
//! | Handles, slot IDs, flags, user type, counts, return codes | logged |
//! | Timing | milliseconds by default; microseconds opt-in |
//!
//! Rules for any future output-side logging: read an output pointer only
//! after the call returns and only if non-NULL; log `*pulLen` only when `rv`
//! is `CKR_OK` or `CKR_BUFFER_TOO_SMALL`; never read an output *buffer*;
//! treat `CK_UNAVAILABLE_INFORMATION` (`!0`) as "unavailable", never as a
//! size; cap template iteration and check `pTemplate != NULL` when
//! `ulCount > 0`; every free-text field goes through
//! `logger::push_json_str` (CWE-117).
//!
//! # Safety
//!
//! All exported `C_*` functions are `unsafe extern "C"`: callers must honour
//! the PKCS#11 contract for each function (valid pointers of the documented
//! types, or NULL where the specification allows it). The spy forwards those
//! pointers unchanged to the target, which has the same contract.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
// Per-function safety docs would repeat the crate-level `# Safety` section
// above for 95 PKCS#11 entry points.
#![allow(clippy::missing_safety_doc)]
#![deny(unsafe_op_in_unsafe_fn)]

mod ckr;
mod config;
#[cfg(unix)]
mod fsutil;
mod loader;
mod logger;
mod types;

use std::cell::Cell;
use std::ffi::{c_char, CStr};
use std::fmt::{self, Write as _};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::OnceLock;
use std::time::Instant;
use types::*;

// ── Dispatch ────────────────────────────────────────────────────────────────

/// Maximum nesting of spy entry points on one thread before calls are
/// refused (guards against unbounded recursion, H6-12).
const MAX_DEPTH: u32 = 16;

thread_local! {
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

struct DepthGuard(bool);

impl DepthGuard {
    fn enter() -> Option<DepthGuard> {
        match DEPTH.try_with(|d| {
            let v = d.get();
            if v >= MAX_DEPTH {
                false
            } else {
                d.set(v + 1);
                true
            }
        }) {
            Ok(true) => Some(DepthGuard(true)),
            Ok(false) => None,
            // TLS already torn down (call from a thread-exit destructor).
            Err(_) => Some(DepthGuard(false)),
        }
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        if self.0 {
            let _ = DEPTH.try_with(|d| d.set(d.get().saturating_sub(1)));
        }
    }
}

/// Run `f`, converting any panic into `CKR_GENERAL_ERROR` (H6-04).
fn guarded(f: impl FnOnce() -> CK_RV) -> CK_RV {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| {
        let _ = catch_unwind(|| logger::log_event("error", "panic caught at the FFI boundary"));
        CKR_GENERAL_ERROR
    })
}

/// The single dispatch path for every entry point: log the call (arguments
/// are formatted only when logging is enabled), resolve the cached target,
/// forward, log the return.
fn dispatch(
    name: &'static str,
    args: impl FnOnce(&mut String),
    call: impl FnOnce(&'static loader::Target) -> CK_RV,
) -> CK_RV {
    guarded(|| {
        let Some(_depth) = DepthGuard::enter() else {
            logger::log_rejected(
                name,
                "re-entrancy depth limit exceeded (does the target call back into the spy?)",
                CKR_GENERAL_ERROR,
            );
            return CKR_GENERAL_ERROR;
        };
        let begin = Instant::now();
        if logger::enabled() {
            logger::log_call(name, begin, args);
        }
        let rv = match loader::target() {
            Ok(t) => call(t),
            Err(rv) => rv,
        };
        logger::log_return(name, rv, begin, Instant::now());
        rv
    })
}

/// A call the spy answers itself without forwarding (only for the functions
/// the spy implements).
fn reject(name: &'static str, reason: &'static str, rv: CK_RV) -> CK_RV {
    guarded(|| {
        logger::log_rejected(name, reason, rv);
        rv
    })
}

// ── Argument formatting helpers ─────────────────────────────────────────────

/// JSON value for the mechanism type of a caller-supplied `CK_MECHANISM`.
struct Mech(Option<CK_ULONG>);

impl fmt::Display for Mech {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(m) => write!(f, "\"0x{m:08x}\""),
            None => f.write_str("null"),
        }
    }
}

/// Read only the leading `mechanism` field of a `CK_MECHANISM`.
///
/// # Safety
/// `p` must be NULL or point to a readable `CK_MECHANISM` — the PKCS#11
/// caller contract, which the target relies on as well. `pParameter` is
/// never read.
unsafe fn mech(p: CK_MECHANISM_PTR) -> Mech {
    if p.is_null() {
        Mech(None)
    } else {
        // SAFETY: see the function contract; unaligned read because Windows
        // Cryptoki structs are 1-byte packed.
        Mech(Some(unsafe { ptr::read_unaligned(p as *const CK_ULONG) }))
    }
}

/// JSON value telling whether an opaque pointer argument is NULL (never
/// dereferenced).
fn present<T>(p: *const T) -> &'static str {
    if p.is_null() {
        "null"
    } else {
        "\"present\""
    }
}

// ── Forwarding wrappers ─────────────────────────────────────────────────────

/// Generate a `#[no_mangle] pub unsafe extern "C"` wrapper that logs the call
/// and forwards it through the target's v2.40 (`v2`) or v3.0 (`v3`) table.
/// The part after `=>` is the `write!` format for the `args` JSON object; it
/// must respect the redaction policy (checked by `tests::redaction_policy`).
macro_rules! spy_fn {
    ($tbl:ident $name:ident ( $($p:ident : $t:ty),* $(,)? ) => $($fmt:tt)+) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name($($p: $t),*) -> CK_RV {
            dispatch(
                stringify!($name),
                move |w: &mut String| {
                    let _ = write!(w, $($fmt)+);
                },
                move |t| match t.$tbl().and_then(|l| l.$name) {
                    // SAFETY: the arguments are forwarded unchanged to the
                    // target's implementation of the same function; the
                    // function-list field type fixes the prototype.
                    Some(f) => unsafe { f($($p),*) },
                    None => CKR_FUNCTION_NOT_SUPPORTED,
                },
            )
        }
    };
}

// Initialization & Info
spy_fn!(v2 C_Initialize(pInitArgs: CK_VOID_PTR)
    => "{{\"init_args\":{}}}", present(pInitArgs));
spy_fn!(v2 C_Finalize(pReserved: CK_VOID_PTR) => "{{}}");
// H6-14: forwarded as-is, including a NULL pInfo (the module decides).
spy_fn!(v2 C_GetInfo(pInfo: CK_INFO_PTR) => "{{}}");

// Slot & Token Management
spy_fn!(v2 C_GetSlotList(tokenPresent: CK_BBOOL, pSlotList: CK_SLOT_ID_PTR, pulCount: CK_ULONG_PTR)
    => "{{\"token_present\":{}}}", tokenPresent);
spy_fn!(v2 C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR)
    => "{{\"slot\":{}}}", slotID);
spy_fn!(v2 C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR)
    => "{{\"slot\":{}}}", slotID);
// SECURITY: SO PIN, its length and the label are never logged.
spy_fn!(v2 C_InitToken(slotID: CK_SLOT_ID, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG, pLabel: CK_UTF8CHAR_PTR)
    => "{{\"slot\":{}}}", slotID);
spy_fn!(v2 C_GetMechanismList(slotID: CK_SLOT_ID, pMechList: CK_MECHANISM_TYPE_PTR, pulCount: CK_ULONG_PTR)
    => "{{\"slot\":{}}}", slotID);
spy_fn!(v2 C_GetMechanismInfo(slotID: CK_SLOT_ID, mechType: CK_MECHANISM_TYPE, pInfo: CK_MECHANISM_INFO_PTR)
    => "{{\"slot\":{},\"mechanism\":\"0x{:08x}\"}}", slotID, mechType);

// Session Management
spy_fn!(v2 C_OpenSession(slotID: CK_SLOT_ID, flags: CK_FLAGS, pApplication: CK_VOID_PTR, Notify: CK_NOTIFY, phSession: CK_SESSION_HANDLE_PTR)
    => "{{\"slot\":{},\"flags\":\"0x{:x}\"}}", slotID, flags);
spy_fn!(v2 C_CloseSession(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);
spy_fn!(v2 C_CloseAllSessions(slotID: CK_SLOT_ID)
    => "{{\"slot\":{}}}", slotID);
spy_fn!(v2 C_GetSessionInfo(hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR)
    => "{{\"session\":{}}}", hSession);
// SECURITY: PIN and PIN length never logged. user_type (SO/USER/CONTEXT_SPECIFIC)
// is not secret and is useful for audit (H6-16).
spy_fn!(v2 C_Login(hSession: CK_SESSION_HANDLE, userType: CK_USER_TYPE, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG)
    => "{{\"session\":{},\"user_type\":{}}}", hSession, userType);
spy_fn!(v2 C_Logout(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);

// PIN Management — PINs and PIN lengths never logged
spy_fn!(v2 C_InitPIN(hSession: CK_SESSION_HANDLE, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG)
    => "{{\"session\":{}}}", hSession);
spy_fn!(v2 C_SetPIN(hSession: CK_SESSION_HANDLE, pOldPin: CK_UTF8CHAR_PTR, ulOldLen: CK_ULONG, pNewPin: CK_UTF8CHAR_PTR, ulNewLen: CK_ULONG)
    => "{{\"session\":{}}}", hSession);

// Object Management
spy_fn!(v2 C_CreateObject(hSession: CK_SESSION_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phObject: CK_OBJECT_HANDLE_PTR)
    => "{{\"session\":{},\"attr_count\":{}}}", hSession, ulCount);
spy_fn!(v2 C_CopyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phNewObject: CK_OBJECT_HANDLE_PTR)
    => "{{\"session\":{},\"object\":{},\"attr_count\":{}}}", hSession, hObject, ulCount);
spy_fn!(v2 C_DestroyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"object\":{}}}", hSession, hObject);
spy_fn!(v2 C_GetObjectSize(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pulSize: CK_ULONG_PTR)
    => "{{\"session\":{},\"object\":{}}}", hSession, hObject);
spy_fn!(v2 C_GetAttributeValue(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG)
    => "{{\"session\":{},\"object\":{},\"attr_count\":{}}}", hSession, hObject, ulCount);
spy_fn!(v2 C_SetAttributeValue(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG)
    => "{{\"session\":{},\"object\":{},\"attr_count\":{}}}", hSession, hObject, ulCount);
spy_fn!(v2 C_FindObjectsInit(hSession: CK_SESSION_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG)
    => "{{\"session\":{},\"attr_count\":{}}}", hSession, ulCount);
spy_fn!(v2 C_FindObjects(hSession: CK_SESSION_HANDLE, phObject: CK_OBJECT_HANDLE_PTR, ulMaxObjectCount: CK_ULONG, pulObjectCount: CK_ULONG_PTR)
    => "{{\"session\":{},\"max_count\":{}}}", hSession, ulMaxObjectCount);
spy_fn!(v2 C_FindObjectsFinal(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);

// Encryption
spy_fn!(v2 C_EncryptInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"mechanism\":{},\"key\":{}}}", hSession, unsafe { mech(pMechanism) }, hKey);
spy_fn!(v2 C_Encrypt(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pEncryptedData: CK_BYTE_PTR, pulEncryptedDataLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"data_len\":{}}}", hSession, ulDataLen);
spy_fn!(v2 C_EncryptUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"part_len\":{}}}", hSession, ulPartLen);
spy_fn!(v2 C_EncryptFinal(hSession: CK_SESSION_HANDLE, pLastEncryptedPart: CK_BYTE_PTR, pulLastEncryptedPartLen: CK_ULONG_PTR)
    => "{{\"session\":{}}}", hSession);

// Decryption
spy_fn!(v2 C_DecryptInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"mechanism\":{},\"key\":{}}}", hSession, unsafe { mech(pMechanism) }, hKey);
spy_fn!(v2 C_Decrypt(hSession: CK_SESSION_HANDLE, pEncryptedData: CK_BYTE_PTR, ulEncryptedDataLen: CK_ULONG, pData: CK_BYTE_PTR, pulDataLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"enc_data_len\":{}}}", hSession, ulEncryptedDataLen);
spy_fn!(v2 C_DecryptUpdate(hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"enc_part_len\":{}}}", hSession, ulEncryptedPartLen);
spy_fn!(v2 C_DecryptFinal(hSession: CK_SESSION_HANDLE, pLastPart: CK_BYTE_PTR, pulLastPartLen: CK_ULONG_PTR)
    => "{{\"session\":{}}}", hSession);

// Digest
spy_fn!(v2 C_DigestInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR)
    => "{{\"session\":{},\"mechanism\":{}}}", hSession, unsafe { mech(pMechanism) });
spy_fn!(v2 C_Digest(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pDigest: CK_BYTE_PTR, pulDigestLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"data_len\":{}}}", hSession, ulDataLen);
spy_fn!(v2 C_DigestUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG)
    => "{{\"session\":{},\"part_len\":{}}}", hSession, ulPartLen);
spy_fn!(v2 C_DigestKey(hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"key\":{}}}", hSession, hKey);
spy_fn!(v2 C_DigestFinal(hSession: CK_SESSION_HANDLE, pDigest: CK_BYTE_PTR, pulDigestLen: CK_ULONG_PTR)
    => "{{\"session\":{}}}", hSession);

// Signing
spy_fn!(v2 C_SignInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"mechanism\":{},\"key\":{}}}", hSession, unsafe { mech(pMechanism) }, hKey);
spy_fn!(v2 C_Sign(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"data_len\":{}}}", hSession, ulDataLen);
spy_fn!(v2 C_SignUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG)
    => "{{\"session\":{},\"part_len\":{}}}", hSession, ulPartLen);
spy_fn!(v2 C_SignFinal(hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR)
    => "{{\"session\":{}}}", hSession);
spy_fn!(v2 C_SignRecoverInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"mechanism\":{},\"key\":{}}}", hSession, unsafe { mech(pMechanism) }, hKey);
spy_fn!(v2 C_SignRecover(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"data_len\":{}}}", hSession, ulDataLen);

// Verification
spy_fn!(v2 C_VerifyInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"mechanism\":{},\"key\":{}}}", hSession, unsafe { mech(pMechanism) }, hKey);
spy_fn!(v2 C_Verify(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG)
    => "{{\"session\":{},\"data_len\":{},\"sig_len\":{}}}", hSession, ulDataLen, ulSignatureLen);
spy_fn!(v2 C_VerifyUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG)
    => "{{\"session\":{},\"part_len\":{}}}", hSession, ulPartLen);
spy_fn!(v2 C_VerifyFinal(hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG)
    => "{{\"session\":{},\"sig_len\":{}}}", hSession, ulSignatureLen);
spy_fn!(v2 C_VerifyRecoverInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"mechanism\":{},\"key\":{}}}", hSession, unsafe { mech(pMechanism) }, hKey);
spy_fn!(v2 C_VerifyRecover(hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG, pData: CK_BYTE_PTR, pulDataLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"sig_len\":{}}}", hSession, ulSignatureLen);

// Dual-function operations
spy_fn!(v2 C_DigestEncryptUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"part_len\":{}}}", hSession, ulPartLen);
spy_fn!(v2 C_DecryptDigestUpdate(hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"enc_part_len\":{}}}", hSession, ulEncryptedPartLen);
spy_fn!(v2 C_SignEncryptUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"part_len\":{}}}", hSession, ulPartLen);
spy_fn!(v2 C_DecryptVerifyUpdate(hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"enc_part_len\":{}}}", hSession, ulEncryptedPartLen);

// Key management
spy_fn!(v2 C_GenerateKey(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR)
    => "{{\"session\":{},\"mechanism\":{},\"attr_count\":{}}}", hSession, unsafe { mech(pMechanism) }, ulCount);
spy_fn!(v2 C_GenerateKeyPair(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, pPublicKeyTemplate: CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount: CK_ULONG, pPrivateKeyTemplate: CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount: CK_ULONG, phPublicKey: CK_OBJECT_HANDLE_PTR, phPrivateKey: CK_OBJECT_HANDLE_PTR)
    => "{{\"session\":{},\"mechanism\":{},\"pub_attrs\":{},\"priv_attrs\":{}}}", hSession, unsafe { mech(pMechanism) }, ulPublicKeyAttributeCount, ulPrivateKeyAttributeCount);
spy_fn!(v2 C_WrapKey(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hWrappingKey: CK_OBJECT_HANDLE, hKey: CK_OBJECT_HANDLE, pWrappedKey: CK_BYTE_PTR, pulWrappedKeyLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"mechanism\":{},\"wrapping_key\":{},\"key\":{}}}", hSession, unsafe { mech(pMechanism) }, hWrappingKey, hKey);
spy_fn!(v2 C_UnwrapKey(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hUnwrappingKey: CK_OBJECT_HANDLE, pWrappedKey: CK_BYTE_PTR, ulWrappedKeyLen: CK_ULONG, pTemplate: CK_ATTRIBUTE_PTR, ulAttributeCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR)
    => "{{\"session\":{},\"mechanism\":{},\"unwrapping_key\":{},\"wrapped_len\":{},\"attr_count\":{}}}", hSession, unsafe { mech(pMechanism) }, hUnwrappingKey, ulWrappedKeyLen, ulAttributeCount);
spy_fn!(v2 C_DeriveKey(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hBaseKey: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulAttributeCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR)
    => "{{\"session\":{},\"mechanism\":{},\"base_key\":{},\"attr_count\":{}}}", hSession, unsafe { mech(pMechanism) }, hBaseKey, ulAttributeCount);

// Random
spy_fn!(v2 C_SeedRandom(hSession: CK_SESSION_HANDLE, pSeed: CK_BYTE_PTR, ulSeedLen: CK_ULONG)
    => "{{\"session\":{},\"seed_len\":{}}}", hSession, ulSeedLen);
spy_fn!(v2 C_GenerateRandom(hSession: CK_SESSION_HANDLE, pRandomData: CK_BYTE_PTR, ulRandomLen: CK_ULONG)
    => "{{\"session\":{},\"random_len\":{}}}", hSession, ulRandomLen);

// State management
spy_fn!(v2 C_GetOperationState(hSession: CK_SESSION_HANDLE, pOperationState: CK_BYTE_PTR, pulOperationStateLen: CK_ULONG_PTR)
    => "{{\"session\":{}}}", hSession);
spy_fn!(v2 C_SetOperationState(hSession: CK_SESSION_HANDLE, pOperationState: CK_BYTE_PTR, ulOperationStateLen: CK_ULONG, hEncryptionKey: CK_OBJECT_HANDLE, hAuthenticationKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"state_len\":{}}}", hSession, ulOperationStateLen);

// Parallel function management (legacy) and events
spy_fn!(v2 C_GetFunctionStatus(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);
spy_fn!(v2 C_CancelFunction(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);
spy_fn!(v2 C_WaitForSlotEvent(flags: CK_FLAGS, pSlot: CK_SLOT_ID_PTR, pReserved: CK_VOID_PTR)
    => "{{\"flags\":\"0x{:x}\"}}", flags);

// ── PKCS#11 v3.0 functions (H6-05) ──────────────────────────────────────────
// Forwarded through the target's CK_FUNCTION_LIST_3_0; CKR_FUNCTION_NOT_SUPPORTED
// when the target has no v3.0 interface.

// SECURITY: PIN, PIN length and user name (PII) are never logged.
spy_fn!(v3 C_LoginUser(hSession: CK_SESSION_HANDLE, userType: CK_USER_TYPE, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG, pUsername: CK_UTF8CHAR_PTR, ulUsernameLen: CK_ULONG)
    => "{{\"session\":{},\"user_type\":{}}}", hSession, userType);
spy_fn!(v3 C_SessionCancel(hSession: CK_SESSION_HANDLE, flags: CK_FLAGS)
    => "{{\"session\":{},\"flags\":\"0x{:x}\"}}", hSession, flags);

spy_fn!(v3 C_MessageEncryptInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"mechanism\":{},\"key\":{}}}", hSession, unsafe { mech(pMechanism) }, hKey);
spy_fn!(v3 C_EncryptMessage(hSession: CK_SESSION_HANDLE, pParameter: CK_VOID_PTR, ulParameterLen: CK_ULONG, pAssociatedData: CK_BYTE_PTR, ulAssociatedDataLen: CK_ULONG, pPlaintext: CK_BYTE_PTR, ulPlaintextLen: CK_ULONG, pCiphertext: CK_BYTE_PTR, pulCiphertextLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"param_len\":{},\"aad_len\":{},\"data_len\":{}}}", hSession, ulParameterLen, ulAssociatedDataLen, ulPlaintextLen);
spy_fn!(v3 C_EncryptMessageBegin(hSession: CK_SESSION_HANDLE, pParameter: CK_VOID_PTR, ulParameterLen: CK_ULONG, pAssociatedData: CK_BYTE_PTR, ulAssociatedDataLen: CK_ULONG)
    => "{{\"session\":{},\"param_len\":{},\"aad_len\":{}}}", hSession, ulParameterLen, ulAssociatedDataLen);
spy_fn!(v3 C_EncryptMessageNext(hSession: CK_SESSION_HANDLE, pParameter: CK_VOID_PTR, ulParameterLen: CK_ULONG, pPlaintextPart: CK_BYTE_PTR, ulPlaintextPartLen: CK_ULONG, pCiphertextPart: CK_BYTE_PTR, pulCiphertextPartLen: CK_ULONG_PTR, flags: CK_FLAGS)
    => "{{\"session\":{},\"param_len\":{},\"part_len\":{},\"flags\":\"0x{:x}\"}}", hSession, ulParameterLen, ulPlaintextPartLen, flags);
spy_fn!(v3 C_MessageEncryptFinal(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);

spy_fn!(v3 C_MessageDecryptInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"mechanism\":{},\"key\":{}}}", hSession, unsafe { mech(pMechanism) }, hKey);
spy_fn!(v3 C_DecryptMessage(hSession: CK_SESSION_HANDLE, pParameter: CK_VOID_PTR, ulParameterLen: CK_ULONG, pAssociatedData: CK_BYTE_PTR, ulAssociatedDataLen: CK_ULONG, pCiphertext: CK_BYTE_PTR, ulCiphertextLen: CK_ULONG, pPlaintext: CK_BYTE_PTR, pulPlaintextLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"param_len\":{},\"aad_len\":{},\"enc_data_len\":{}}}", hSession, ulParameterLen, ulAssociatedDataLen, ulCiphertextLen);
spy_fn!(v3 C_DecryptMessageBegin(hSession: CK_SESSION_HANDLE, pParameter: CK_VOID_PTR, ulParameterLen: CK_ULONG, pAssociatedData: CK_BYTE_PTR, ulAssociatedDataLen: CK_ULONG)
    => "{{\"session\":{},\"param_len\":{},\"aad_len\":{}}}", hSession, ulParameterLen, ulAssociatedDataLen);
spy_fn!(v3 C_DecryptMessageNext(hSession: CK_SESSION_HANDLE, pParameter: CK_VOID_PTR, ulParameterLen: CK_ULONG, pCiphertextPart: CK_BYTE_PTR, ulCiphertextPartLen: CK_ULONG, pPlaintextPart: CK_BYTE_PTR, pulPlaintextPartLen: CK_ULONG_PTR, flags: CK_FLAGS)
    => "{{\"session\":{},\"param_len\":{},\"enc_part_len\":{},\"flags\":\"0x{:x}\"}}", hSession, ulParameterLen, ulCiphertextPartLen, flags);
spy_fn!(v3 C_MessageDecryptFinal(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);

spy_fn!(v3 C_MessageSignInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"mechanism\":{},\"key\":{}}}", hSession, unsafe { mech(pMechanism) }, hKey);
spy_fn!(v3 C_SignMessage(hSession: CK_SESSION_HANDLE, pParameter: CK_VOID_PTR, ulParameterLen: CK_ULONG, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"param_len\":{},\"data_len\":{}}}", hSession, ulParameterLen, ulDataLen);
spy_fn!(v3 C_SignMessageBegin(hSession: CK_SESSION_HANDLE, pParameter: CK_VOID_PTR, ulParameterLen: CK_ULONG)
    => "{{\"session\":{},\"param_len\":{}}}", hSession, ulParameterLen);
spy_fn!(v3 C_SignMessageNext(hSession: CK_SESSION_HANDLE, pParameter: CK_VOID_PTR, ulParameterLen: CK_ULONG, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"param_len\":{},\"data_len\":{}}}", hSession, ulParameterLen, ulDataLen);
spy_fn!(v3 C_MessageSignFinal(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);

spy_fn!(v3 C_MessageVerifyInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"mechanism\":{},\"key\":{}}}", hSession, unsafe { mech(pMechanism) }, hKey);
spy_fn!(v3 C_VerifyMessage(hSession: CK_SESSION_HANDLE, pParameter: CK_VOID_PTR, ulParameterLen: CK_ULONG, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG)
    => "{{\"session\":{},\"param_len\":{},\"data_len\":{},\"sig_len\":{}}}", hSession, ulParameterLen, ulDataLen, ulSignatureLen);
spy_fn!(v3 C_VerifyMessageBegin(hSession: CK_SESSION_HANDLE, pParameter: CK_VOID_PTR, ulParameterLen: CK_ULONG)
    => "{{\"session\":{},\"param_len\":{}}}", hSession, ulParameterLen);
spy_fn!(v3 C_VerifyMessageNext(hSession: CK_SESSION_HANDLE, pParameter: CK_VOID_PTR, ulParameterLen: CK_ULONG, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG)
    => "{{\"session\":{},\"param_len\":{},\"data_len\":{},\"sig_len\":{}}}", hSession, ulParameterLen, ulDataLen, ulSignatureLen);
spy_fn!(v3 C_MessageVerifyFinal(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);

// ── Spy-owned function tables and interfaces (H6-01 / H6-05) ────────────────

/// Invoke `$m!($($pre)* <all v2.40 function names> $(, extra)*)`.
macro_rules! with_v2_names {
    ($m:ident ! ( $($pre:tt)* ) $(, $extra:ident)*) => {
        $m!($($pre)*
            C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList, C_GetSlotList,
            C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo,
            C_InitToken, C_InitPIN, C_SetPIN, C_OpenSession, C_CloseSession,
            C_CloseAllSessions, C_GetSessionInfo, C_GetOperationState,
            C_SetOperationState, C_Login, C_Logout, C_CreateObject, C_CopyObject,
            C_DestroyObject, C_GetObjectSize, C_GetAttributeValue, C_SetAttributeValue,
            C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal, C_EncryptInit,
            C_Encrypt, C_EncryptUpdate, C_EncryptFinal, C_DecryptInit, C_Decrypt,
            C_DecryptUpdate, C_DecryptFinal, C_DigestInit, C_Digest, C_DigestUpdate,
            C_DigestKey, C_DigestFinal, C_SignInit, C_Sign, C_SignUpdate, C_SignFinal,
            C_SignRecoverInit, C_SignRecover, C_VerifyInit, C_Verify, C_VerifyUpdate,
            C_VerifyFinal, C_VerifyRecoverInit, C_VerifyRecover, C_DigestEncryptUpdate,
            C_DecryptDigestUpdate, C_SignEncryptUpdate, C_DecryptVerifyUpdate,
            C_GenerateKey, C_GenerateKeyPair, C_WrapKey, C_UnwrapKey, C_DeriveKey,
            C_SeedRandom, C_GenerateRandom, C_GetFunctionStatus, C_CancelFunction,
            C_WaitForSlotEvent $(, $extra)*)
    };
}

/// Build a function-list literal whose every entry is the spy's wrapper of
/// the same name. The struct literal must name every field, so the compiler
/// checks completeness and each wrapper's prototype.
macro_rules! build_list {
    ($ty:ident, $maj:expr, $min:expr; $($f:ident),*) => {
        $ty { version: CK_VERSION { major: $maj, minor: $min }, $($f: Some($f)),* }
    };
}

static SPY_FUNCTION_LIST: CK_FUNCTION_LIST = with_v2_names!(build_list!(CK_FUNCTION_LIST, 2, 40;));

static SPY_FUNCTION_LIST_3_0: CK_FUNCTION_LIST_3_0 = with_v2_names!(
    build_list!(CK_FUNCTION_LIST_3_0, 3, 0;),
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
    C_MessageVerifyFinal
);

pub(crate) fn spy_function_list() -> &'static CK_FUNCTION_LIST {
    &SPY_FUNCTION_LIST
}

pub(crate) fn spy_function_list_3_0() -> &'static CK_FUNCTION_LIST_3_0 {
    &SPY_FUNCTION_LIST_3_0
}

const INTERFACE_NAME: &[u8] = b"PKCS 11\0";

/// The interfaces the spy offers: "PKCS 11" 3.0 (only when the target has a
/// v3.0 interface; it is then the default) and "PKCS 11" 2.40.
struct Interfaces(Vec<(CK_INTERFACE, CK_VERSION)>);

// SAFETY: the raw pointers refer to immutable statics of this library.
unsafe impl Send for Interfaces {}
unsafe impl Sync for Interfaces {}

fn interfaces(t: &loader::Target) -> &'static [(CK_INTERFACE, CK_VERSION)] {
    static IFACES: OnceLock<Interfaces> = OnceLock::new();
    &IFACES
        .get_or_init(|| {
            let name = INTERFACE_NAME.as_ptr() as *mut u8;
            let mut v = Vec::with_capacity(2);
            if t.has_v3() {
                v.push((
                    CK_INTERFACE {
                        pInterfaceName: name,
                        pFunctionList: &SPY_FUNCTION_LIST_3_0 as *const _ as CK_VOID_PTR,
                        flags: t.iface_flags,
                    },
                    CK_VERSION { major: 3, minor: 0 },
                ));
            }
            v.push((
                CK_INTERFACE {
                    pInterfaceName: name,
                    pFunctionList: &SPY_FUNCTION_LIST as *const _ as CK_VOID_PTR,
                    flags: t.iface_flags,
                },
                CK_VERSION {
                    major: 2,
                    minor: 40,
                },
            ));
            Interfaces(v)
        })
        .0
}

/// Returns the spy's own function table (H6-01) — never the target's.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if ppFunctionList.is_null() {
        return reject(
            "C_GetFunctionList",
            "ppFunctionList is NULL",
            CKR_ARGUMENTS_BAD,
        );
    }
    dispatch(
        "C_GetFunctionList",
        |w| w.push_str("{}"),
        move |_t| {
            // SAFETY: checked non-NULL above; the caller supplies a writable
            // CK_FUNCTION_LIST_PTR. The table is immutable static data.
            unsafe { *ppFunctionList = &SPY_FUNCTION_LIST as *const _ as CK_FUNCTION_LIST_PTR };
            CKR_OK
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn C_GetInterfaceList(
    pInterfacesList: CK_INTERFACE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    if pulCount.is_null() {
        return reject("C_GetInterfaceList", "pulCount is NULL", CKR_ARGUMENTS_BAD);
    }
    dispatch(
        "C_GetInterfaceList",
        move |w| {
            let _ = write!(w, "{{\"list\":{}}}", present(pInterfacesList));
        },
        move |t| {
            let ifs = interfaces(t);
            let n = ifs.len() as CK_ULONG;
            // SAFETY: pulCount checked non-NULL; pInterfacesList, when
            // non-NULL, holds *pulCount CK_INTERFACE entries (caller contract).
            unsafe {
                if pInterfacesList.is_null() {
                    *pulCount = n;
                    return CKR_OK;
                }
                if *pulCount < n {
                    *pulCount = n;
                    return CKR_BUFFER_TOO_SMALL;
                }
                for (i, (iface, _)) in ifs.iter().enumerate() {
                    ptr::write_unaligned(pInterfacesList.add(i), *iface);
                }
                *pulCount = n;
            }
            CKR_OK
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn C_GetInterface(
    pInterfaceName: CK_UTF8CHAR_PTR,
    pVersion: CK_VERSION_PTR,
    ppInterface: CK_INTERFACE_PTR_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    if ppInterface.is_null() {
        return reject("C_GetInterface", "ppInterface is NULL", CKR_ARGUMENTS_BAD);
    }
    // SAFETY: caller contract — pInterfaceName is NULL or NUL-terminated and
    // pVersion is NULL or points to a CK_VERSION.
    let name: Option<&[u8]> = (!pInterfaceName.is_null())
        .then(|| unsafe { CStr::from_ptr(pInterfaceName as *const c_char) }.to_bytes());
    let version = (!pVersion.is_null()).then(|| unsafe { ptr::read_unaligned(pVersion) });
    dispatch(
        "C_GetInterface",
        move |w| {
            w.push_str("{\"name\":");
            match name {
                Some(n) => {
                    let s = String::from_utf8_lossy(&n[..n.len().min(64)]);
                    logger::push_json_str(w, &s);
                }
                None => w.push_str("null"),
            }
            match version {
                Some(v) => {
                    let _ = write!(w, ",\"version\":\"{}.{}\"", { v.major }, { v.minor });
                }
                None => w.push_str(",\"version\":null"),
            }
            let _ = write!(w, ",\"flags\":\"0x{flags:x}\"}}");
        },
        move |t| {
            if name.is_some_and(|n| n != &INTERFACE_NAME[..INTERFACE_NAME.len() - 1]) {
                return CKR_ARGUMENTS_BAD;
            }
            let found = interfaces(t).iter().find(|(iface, v)| {
                version.map_or(true, |want| want == *v) && ({ iface.flags } & flags) == flags
            });
            match found {
                Some((iface, _)) => {
                    // SAFETY: ppInterface checked non-NULL; the record lives
                    // in a static for the life of the library.
                    unsafe { *ppInterface = iface as *const CK_INTERFACE as CK_INTERFACE_PTR };
                    CKR_OK
                }
                None => CKR_ARGUMENTS_BAD,
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spy_tables_point_at_spy_wrappers() {
        let l = spy_function_list();
        assert_eq!(
            { l.version },
            CK_VERSION {
                major: 2,
                minor: 40
            }
        );
        assert_eq!(
            l.C_GetFunctionList.unwrap() as usize,
            C_GetFunctionList as *const () as usize
        );
        assert_eq!(l.C_Sign.unwrap() as usize, C_Sign as *const () as usize);
        let l3 = spy_function_list_3_0();
        assert_eq!({ l3.version }, CK_VERSION { major: 3, minor: 0 });
        assert_eq!(l3.C_Sign.unwrap() as usize, C_Sign as *const () as usize);
        assert_eq!(
            l3.C_GetInterface.unwrap() as usize,
            C_GetInterface as *const () as usize
        );
        assert_eq!(
            l3.C_MessageVerifyFinal.unwrap() as usize,
            C_MessageVerifyFinal as *const () as usize
        );
    }

    #[test]
    fn panics_are_converted_to_ckr_general_error() {
        assert_eq!(guarded(|| panic!("boom")), CKR_GENERAL_ERROR);
        assert_eq!(guarded(|| CKR_OK), CKR_OK);
    }

    #[test]
    fn recursion_depth_is_bounded() {
        let guards: Vec<_> = (0..MAX_DEPTH)
            .map(|_| DepthGuard::enter().unwrap())
            .collect();
        assert!(DepthGuard::enter().is_none(), "depth limit not enforced");
        drop(guards);
        assert!(DepthGuard::enter().is_some(), "depth not released");
    }

    #[test]
    fn null_output_pointers_are_rejected_without_loading() {
        // SAFETY: NULL is exactly the case under test; nothing is dereferenced.
        unsafe {
            assert_eq!(C_GetFunctionList(ptr::null_mut()), CKR_ARGUMENTS_BAD);
            assert_eq!(
                C_GetInterfaceList(ptr::null_mut(), ptr::null_mut()),
                CKR_ARGUMENTS_BAD
            );
            assert_eq!(
                C_GetInterface(ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0),
                CKR_ARGUMENTS_BAD
            );
        }
    }

    #[test]
    fn mechanism_type_only_is_read() {
        #[repr(C)]
        struct Mechanism {
            mechanism: CK_ULONG,
            p_parameter: *mut u8,
            len: CK_ULONG,
        }
        let mut m = Mechanism {
            mechanism: 0x1082,
            p_parameter: ptr::null_mut(),
            len: 0,
        };
        // SAFETY: valid CK_MECHANISM-shaped value / NULL.
        unsafe {
            assert_eq!(
                mech(&mut m as *mut Mechanism as CK_MECHANISM_PTR).to_string(),
                "\"0x00001082\""
            );
            assert_eq!(mech(ptr::null_mut()).to_string(), "null");
        }
        let _ = (m.p_parameter, m.len);
    }

    /// H6-15 / H6-16: codified redaction policy. Scans every `spy_fn!`
    /// invocation in this file and checks that its log-format arguments never
    /// reference a PIN/username length or any pointer argument other than
    /// `pMechanism` (only via `mech(..)`) and `pInitArgs` (only via
    /// `present(..)`).
    #[test]
    fn redaction_policy() {
        const SECRET_LENGTHS: &[&str] = &["ulPinLen", "ulOldLen", "ulNewLen", "ulUsernameLen"];
        let src = include_str!("lib.rs");
        let body = &src[..src.find("#[cfg(test)]").unwrap()];
        let mut checked = 0;
        for inv in body.split("\nspy_fn!(").skip(1) {
            let inv = &inv[..inv.find(");").expect("unterminated spy_fn!")];
            let (sig, fmt) = inv.split_once("=>").expect("spy_fn! without =>");
            let name = sig.split(['(', ' ']).nth(1).unwrap();
            let idents: Vec<&str> = fmt
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|s| !s.is_empty())
                .collect();
            for (i, id) in idents.iter().enumerate() {
                assert!(
                    !SECRET_LENGTHS.contains(id),
                    "{name}: logs secret length `{id}`"
                );
                // Hungarian-notation pointer arguments: pX…, phX…, pulX….
                let is_pointer = ["p", "ph", "pul"].iter().any(|pre| {
                    id.strip_prefix(pre)
                        .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_uppercase()))
                });
                if is_pointer {
                    let prev = if i > 0 { idents[i - 1] } else { "" };
                    let ok = (*id == "pMechanism" && prev == "mech")
                        || (*id == "pInitArgs" && prev == "present");
                    assert!(ok, "{name}: log format reads pointer argument `{id}`");
                }
            }
            checked += 1;
        }
        assert_eq!(
            checked,
            68 - 1 + 24 - 2,
            "every forwarded function is covered"
        );
    }
}
