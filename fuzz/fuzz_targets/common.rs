// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Shared fuzz-harness setup (A3-13).
//!
//! Initialises the module once per fuzzing process and provisions slot 0 with
//! an SO PIN and a User PIN that satisfy the default PIN policy (minimum
//! length 8, at least 3 distinct bytes and 2 character classes), so that the
//! authenticated key-generation / crypto / attribute paths are actually
//! reachable. Previously the targets logged in with `b"1234"` on an
//! uninitialised token, which always failed, so those paths were never fuzzed.
//!
//! Fuzz targets must never feed fuzzer-controlled PINs into `C_Login` for the
//! provisioned token: repeated failures would lock the User PIN and silently
//! turn the remaining iterations into unauthenticated no-ops.

#![allow(dead_code, unused_unsafe)]

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions;
use craton_hsm::pkcs11_abi::types::*;
use std::sync::Once;

/// Security Officer PIN used to provision the fuzzing token.
pub const SO_PIN: &[u8] = b"FuzzSo!2026-pin";
/// User PIN set by the SO during provisioning.
pub const USER_PIN: &[u8] = b"FuzzUsr!2026-pin";

static INIT: Once = Once::new();

/// Initialise the library and provision the token exactly once per process.
pub fn ensure_init() {
    INIT.call_once(|| {
        // `unsafe` blocks keep this helper compiling once the exported
        // PKCS#11 functions become `unsafe extern "C"` (A3-14).
        let rv = unsafe { functions::C_Initialize(std::ptr::null_mut()) };
        assert!(
            rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
            "C_Initialize failed: {rv:#x}"
        );
        provision_token();
    });
}

fn provision_token() {
    let mut label = [b' '; 32];
    label[..9].copy_from_slice(b"FuzzToken");
    let rv = unsafe {
        functions::C_InitToken(
            0,
            SO_PIN.as_ptr() as *mut _,
            SO_PIN.len() as CK_ULONG,
            label.as_mut_ptr() as *mut _,
        )
    };
    assert_eq!(rv, CKR_OK, "C_InitToken failed: {rv:#x}");

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        functions::C_OpenSession(
            0,
            CKF_SERIAL_SESSION | CKF_RW_SESSION,
            std::ptr::null_mut(),
            None,
            &mut session,
        )
    };
    assert_eq!(rv, CKR_OK, "C_OpenSession failed: {rv:#x}");

    let rv = unsafe {
        functions::C_Login(
            session,
            CKU_SO,
            SO_PIN.as_ptr() as *mut _,
            SO_PIN.len() as CK_ULONG,
        )
    };
    assert_eq!(rv, CKR_OK, "C_Login(SO) failed: {rv:#x}");

    let rv = unsafe {
        functions::C_InitPIN(
            session,
            USER_PIN.as_ptr() as *mut _,
            USER_PIN.len() as CK_ULONG,
        )
    };
    assert_eq!(rv, CKR_OK, "C_InitPIN failed: {rv:#x}");

    let rv = unsafe { functions::C_Logout(session) };
    assert_eq!(rv, CKR_OK, "C_Logout failed: {rv:#x}");
    let rv = unsafe { functions::C_CloseSession(session) };
    assert_eq!(rv, CKR_OK, "C_CloseSession failed: {rv:#x}");
}

/// Log the provisioned User in on `session`.
pub fn login_user(session: CK_SESSION_HANDLE) -> CK_RV {
    unsafe {
        functions::C_Login(
            session,
            CKU_USER,
            USER_PIN.as_ptr() as *mut _,
            USER_PIN.len() as CK_ULONG,
        )
    }
}
