// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Regression tests for the second wave of PKCS#11 ABI audit fixes
//! (H1-03/04/07/08/10/12/17/20/26/30, A2-01/13/19/20/21/22, H2-20).
//!
//! ABI tests share global state: run with `--test-threads=1`.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

const SO_PIN: &[u8] = b"S0pin-47";
const USER_PIN: &[u8] = b"Us3rpin9";

fn ensure_init() {
    let rv = unsafe { C_Initialize(ptr::null_mut()) };
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
}

fn open_session(rw: bool) -> CK_SESSION_HANDLE {
    let mut s: CK_SESSION_HANDLE = 0;
    let flags = CKF_SERIAL_SESSION | if rw { CKF_RW_SESSION } else { 0 };
    let rv = unsafe { C_OpenSession(0, flags, ptr::null_mut(), None, &mut s) };
    assert_eq!(rv, CKR_OK);
    s
}

fn login(s: CK_SESSION_HANDLE, user: CK_ULONG, pin: &[u8]) -> CK_RV {
    unsafe { C_Login(s, user, pin.as_ptr() as *mut _, pin.len() as CK_ULONG) }
}

/// Fresh token with a user PIN; returns a R/W session that is not logged in.
fn fresh_token() -> CK_SESSION_HANDLE {
    ensure_init();
    let _ = unsafe { C_CloseAllSessions(0) };
    let mut label = [b' '; 32];
    label[..6].copy_from_slice(b"Wave2A");
    let rv = unsafe {
        C_InitToken(
            0,
            SO_PIN.as_ptr() as *mut _,
            SO_PIN.len() as CK_ULONG,
            label.as_mut_ptr(),
        )
    };
    assert_eq!(rv, CKR_OK);
    let s = open_session(true);
    assert_eq!(login(s, CKU_SO, SO_PIN), CKR_OK);
    let rv = unsafe { C_InitPIN(s, USER_PIN.as_ptr() as *mut _, USER_PIN.len() as CK_ULONG) };
    assert_eq!(rv, CKR_OK);
    assert_eq!(unsafe { C_Logout(s) }, CKR_OK);
    s
}

fn user_session() -> CK_SESSION_HANDLE {
    let s = fresh_token();
    assert_eq!(login(s, CKU_USER, USER_PIN), CKR_OK);
    s
}

fn attr<T>(t: CK_ATTRIBUTE_TYPE, v: &T) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        attr_type: t,
        p_value: v as *const T as *mut _,
        value_len: std::mem::size_of::<T>() as CK_ULONG,
    }
}

fn mech(m: CK_MECHANISM_TYPE) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: m,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    }
}

/// Generate an AES-256 key with the given boolean attributes.
fn gen_aes(s: CK_SESSION_HANDLE, extra: &[(CK_ATTRIBUTE_TYPE, CK_BBOOL)]) -> CK_OBJECT_HANDLE {
    let len: CK_ULONG = 32;
    let mut tmpl = vec![attr(CKA_VALUE_LEN, &len)];
    for (t, v) in extra {
        tmpl.push(attr(*t, v));
    }
    let mut m = mech(CKM_AES_KEY_GEN);
    let mut h: CK_OBJECT_HANDLE = 0;
    let rv = unsafe { C_GenerateKey(s, &mut m, tmpl.as_mut_ptr(), tmpl.len() as CK_ULONG, &mut h) };
    assert_eq!(rv, CKR_OK, "C_GenerateKey: {rv:#x}");
    h
}

const P256_OID: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

fn gen_keypair(
    s: CK_SESSION_HANDLE,
    m: CK_MECHANISM_TYPE,
    priv_extra: &[(CK_ATTRIBUTE_TYPE, CK_BBOOL)],
) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), CK_RV> {
    let bits: CK_ULONG = 2048;
    let mut pub_t = match m {
        CKM_EC_KEY_PAIR_GEN => vec![CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: P256_OID.as_ptr() as *mut _,
            value_len: P256_OID.len() as CK_ULONG,
        }],
        CKM_RSA_PKCS_KEY_PAIR_GEN => vec![attr(CKA_MODULUS_BITS, &bits)],
        _ => vec![],
    };
    let mut priv_t: Vec<CK_ATTRIBUTE> = priv_extra.iter().map(|(t, v)| attr(*t, v)).collect();
    let mut mm = mech(m);
    let (mut pubk, mut privk) = (0, 0);
    let rv = unsafe {
        C_GenerateKeyPair(
            s,
            &mut mm,
            pub_t.as_mut_ptr(),
            pub_t.len() as CK_ULONG,
            priv_t.as_mut_ptr(),
            priv_t.len() as CK_ULONG,
            &mut pubk,
            &mut privk,
        )
    };
    if rv == CKR_OK {
        Ok((pubk, privk))
    } else {
        Err(rv)
    }
}

fn sign(s: CK_SESSION_HANDLE, m: &mut CK_MECHANISM, k: CK_OBJECT_HANDLE, data: &[u8]) -> Vec<u8> {
    assert_eq!(unsafe { C_SignInit(s, m, k) }, CKR_OK);
    let mut sig = vec![0u8; 8192];
    let mut len = sig.len() as CK_ULONG;
    let rv = unsafe {
        C_Sign(
            s,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            sig.as_mut_ptr(),
            &mut len,
        )
    };
    assert_eq!(rv, CKR_OK, "C_Sign: {rv:#x}");
    sig.truncate(len as usize);
    sig
}

fn verify(
    s: CK_SESSION_HANDLE,
    m: &mut CK_MECHANISM,
    k: CK_OBJECT_HANDLE,
    data: &[u8],
    sig: &[u8],
) -> CK_RV {
    assert_eq!(unsafe { C_VerifyInit(s, m, k) }, CKR_OK);
    unsafe {
        C_Verify(
            s,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            sig.as_ptr() as *mut _,
            sig.len() as CK_ULONG,
        )
    }
}

// ---------------------------------------------------------------------------
// A2-01 / A3-16: interfaces and versions
// ---------------------------------------------------------------------------

#[test]
fn v3_interfaces_and_versions() {
    // Interface discovery works before C_Initialize as well.
    let mut n: CK_ULONG = 0;
    assert_eq!(
        unsafe { C_GetInterfaceList(ptr::null_mut(), &mut n) },
        CKR_OK
    );
    assert_eq!(n, 2);
    let mut small: CK_ULONG = 1;
    let mut list = [CK_INTERFACE {
        pInterfaceName: ptr::null_mut(),
        pFunctionList: ptr::null_mut(),
        flags: 0,
    }; 2];
    assert_eq!(
        unsafe { C_GetInterfaceList(list.as_mut_ptr(), &mut small) },
        CKR_BUFFER_TOO_SMALL
    );
    assert_eq!(small, 2);
    assert_eq!(
        unsafe { C_GetInterfaceList(list.as_mut_ptr(), &mut n) },
        CKR_OK
    );
    for iface in &list {
        let name = unsafe { std::ffi::CStr::from_ptr(iface.pInterfaceName as *const _) };
        assert_eq!(name.to_bytes(), b"PKCS 11");
    }
    let v3 = unsafe { &*(list[0].pFunctionList as *const CK_FUNCTION_LIST_3_0) };
    assert_eq!((v3.version.major, v3.version.minor), (3, 0));
    let v2 = unsafe { &*(list[1].pFunctionList as *const CK_FUNCTION_LIST) };
    assert_eq!((v2.version.major, v2.version.minor), (2, 40));

    // Default interface = v3.0; an explicit 2.40 request gets the v2 list.
    let mut p: CK_INTERFACE_PTR = ptr::null_mut();
    assert_eq!(
        unsafe { C_GetInterface(ptr::null_mut(), ptr::null_mut(), &mut p, 0) },
        CKR_OK
    );
    let fl = unsafe { &*((*p).pFunctionList as *const CK_FUNCTION_LIST_3_0) };
    assert_eq!(fl.version.major, 3);
    let mut want = CK_VERSION {
        major: 2,
        minor: 40,
    };
    let mut name = *b"PKCS 11\0";
    assert_eq!(
        unsafe { C_GetInterface(name.as_mut_ptr(), &mut want, &mut p, 0) },
        CKR_OK
    );
    let fl2 = unsafe { &*((*p).pFunctionList as *const CK_FUNCTION_LIST) };
    assert_eq!((fl2.version.major, fl2.version.minor), (2, 40));
    let mut bad = *b"Vendor\0";
    assert_eq!(
        unsafe { C_GetInterface(bad.as_mut_ptr(), ptr::null_mut(), &mut p, 0) },
        CKR_ARGUMENTS_BAD
    );
    // No fork-safe interface is offered.
    assert_eq!(
        unsafe {
            C_GetInterface(
                ptr::null_mut(),
                ptr::null_mut(),
                &mut p,
                CKF_INTERFACE_FORK_SAFE,
            )
        },
        CKR_ARGUMENTS_BAD
    );

    // C_GetFunctionList returns the v2.40 table.
    let mut f: *mut CK_FUNCTION_LIST = ptr::null_mut();
    assert_eq!(unsafe { C_GetFunctionList(&mut f) }, CKR_OK);
    assert_eq!(unsafe { ((*f).version.major, (*f).version.minor) }, (2, 40));

    // The 3.0 table is usable: call C_Initialize / C_GetInfo through it.
    let rv = unsafe { (fl.C_Initialize)(ptr::null_mut()) };
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
    let mut info: CK_INFO = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { (fl.C_GetInfo)(&mut info) }, CKR_OK);
    assert_eq!(
        (info.cryptoki_version.major, info.cryptoki_version.minor),
        (3, 0)
    );
    let lib = (info.library_version.major, info.library_version.minor);
    let expected = (
        env!("CARGO_PKG_VERSION_MAJOR").parse::<u8>().unwrap(),
        env!("CARGO_PKG_VERSION_MINOR").parse::<u8>().unwrap(),
    );
    assert_eq!(lib, expected);
}

// ---------------------------------------------------------------------------
// A2-19: C_Initialize argument validation; A2-22 stubs; A1-10 finalize
// ---------------------------------------------------------------------------

extern "C" fn fake_mutex(_p: *mut CK_VOID_PTR) -> CK_RV {
    CKR_OK
}
extern "C" fn fake_mutex2(_p: CK_VOID_PTR) -> CK_RV {
    CKR_OK
}

#[test]
fn initialize_args_and_uninitialized_stubs() {
    let mut args = CK_C_INITIALIZE_ARGS {
        create_mutex: None,
        destroy_mutex: None,
        lock_mutex: None,
        unlock_mutex: None,
        flags: 0,
        p_reserved: 1 as CK_VOID_PTR,
    };
    let p = &mut args as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR;
    assert_eq!(unsafe { C_Initialize(p) }, CKR_ARGUMENTS_BAD);
    args.p_reserved = ptr::null_mut();
    args.create_mutex = Some(fake_mutex);
    assert_eq!(unsafe { C_Initialize(p) }, CKR_ARGUMENTS_BAD);
    args.destroy_mutex = Some(fake_mutex2);
    args.lock_mutex = Some(fake_mutex2);
    args.unlock_mutex = Some(fake_mutex2);
    assert_eq!(unsafe { C_Initialize(p) }, CKR_CANT_LOCK);
    args.flags = CKF_LIBRARY_CANT_CREATE_OS_THREADS | CKF_OS_LOCKING_OK;
    assert_eq!(unsafe { C_Initialize(p) }, CKR_NEED_TO_CREATE_THREADS);

    // Start from an uninitialized library.
    let _ = unsafe { C_Finalize(ptr::null_mut()) };
    assert_eq!(
        unsafe { C_SignRecoverInit(1, ptr::null_mut(), 0) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
    assert_eq!(
        unsafe { C_GetFunctionStatus(1) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
    assert_eq!(
        unsafe { C_WaitForSlotEvent(0, ptr::null_mut(), ptr::null_mut()) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
    assert_eq!(
        unsafe { C_MessageSignInit(1, ptr::null_mut(), 0) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );

    // Callbacks together with CKF_OS_LOCKING_OK are accepted.
    args.flags = CKF_OS_LOCKING_OK;
    assert_eq!(unsafe { C_Initialize(p) }, CKR_OK);
    let s = open_session(false);
    assert_eq!(
        unsafe { C_SignRecoverInit(s, ptr::null_mut(), 0) },
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        unsafe { C_SignRecoverInit(0xdead_beef, ptr::null_mut(), 0) },
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(unsafe { C_CancelFunction(s) }, CKR_FUNCTION_NOT_PARALLEL);

    // A session of a finalized core is gone after re-initialisation (A1-10).
    assert_eq!(unsafe { C_Finalize(ptr::null_mut()) }, CKR_OK);
    let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { C_GetSessionInfo(s, &mut info) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
    ensure_init();
    assert_eq!(
        unsafe { C_GetSessionInfo(s, &mut info) },
        CKR_SESSION_HANDLE_INVALID
    );
}

// ---------------------------------------------------------------------------
// H1-10 / H1-07 / A2-21 / H1-30: login and session rules
// ---------------------------------------------------------------------------

#[test]
fn key_creation_and_destruction_require_user() {
    let s = fresh_token();
    // Public session: no key generation (H1-10).
    let len: CK_ULONG = 32;
    let mut tmpl = [attr(CKA_VALUE_LEN, &len)];
    let mut m = mech(CKM_AES_KEY_GEN);
    let mut h = 0;
    assert_eq!(
        unsafe { C_GenerateKey(s, &mut m, tmpl.as_mut_ptr(), 1, &mut h) },
        CKR_USER_NOT_LOGGED_IN
    );
    assert_eq!(
        gen_keypair(s, CKM_EC_KEY_PAIR_GEN, &[]),
        Err(CKR_USER_NOT_LOGGED_IN)
    );
    // SO session: no key generation either.
    assert_eq!(login(s, CKU_SO, SO_PIN), CKR_OK);
    assert_eq!(
        unsafe { C_GenerateKey(s, &mut m, tmpl.as_mut_ptr(), 1, &mut h) },
        CKR_USER_NOT_LOGGED_IN
    );
    assert_eq!(unsafe { C_Logout(s) }, CKR_OK);

    // A private key created by the user cannot be destroyed by a public session (H1-07).
    assert_eq!(login(s, CKU_USER, USER_PIN), CKR_OK);
    let k = gen_aes(s, &[]);
    let other = open_session(true);
    assert_eq!(unsafe { C_Logout(s) }, CKR_OK);
    assert_eq!(unsafe { C_DestroyObject(other, k) }, CKR_USER_NOT_LOGGED_IN);

    // Unknown / computed template attributes are rejected (H1-14).
    assert_eq!(login(s, CKU_USER, USER_PIN), CKR_OK);
    let t: CK_BBOOL = CK_TRUE;
    let mut bad = [attr(CKA_VALUE_LEN, &len), attr(CKA_LOCAL, &t)];
    assert_eq!(
        unsafe { C_GenerateKey(s, &mut m, bad.as_mut_ptr(), 2, &mut h) },
        CKR_ATTRIBUTE_READ_ONLY
    );
    let v = [0u8; 32];
    let mut bad2 = [
        attr(CKA_VALUE_LEN, &len),
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE,
            p_value: v.as_ptr() as *mut _,
            value_len: 32,
        },
    ];
    assert_eq!(
        unsafe { C_GenerateKey(s, &mut m, bad2.as_mut_ptr(), 2, &mut h) },
        CKR_TEMPLATE_INCONSISTENT
    );
    // Restrictive attributes are honoured.
    let f: CK_BBOOL = CK_FALSE;
    let k2 = gen_aes(s, &[(CKA_DESTROYABLE, f), (CKA_COPYABLE, f)]);
    assert_eq!(unsafe { C_DestroyObject(s, k2) }, CKR_ACTION_PROHIBITED);
}

#[test]
fn read_only_sessions_and_pin_edge_cases() {
    let s = user_session();
    let ro = open_session(false);
    // Session objects may be created in R/O sessions (A2-21)...
    let class: CK_OBJECT_CLASS = CKO_DATA;
    let f: CK_BBOOL = CK_FALSE;
    let t: CK_BBOOL = CK_TRUE;
    let mut tmpl = [attr(CKA_CLASS, &class), attr(CKA_PRIVATE, &f)];
    let mut h = 0;
    assert_eq!(
        unsafe { C_CreateObject(ro, tmpl.as_mut_ptr(), 2, &mut h) },
        CKR_OK
    );
    // ...but token objects need a R/W session.
    let mut tmpl2 = [
        attr(CKA_CLASS, &class),
        attr(CKA_PRIVATE, &f),
        attr(CKA_TOKEN, &t),
    ];
    assert_eq!(
        unsafe { C_CreateObject(ro, tmpl2.as_mut_ptr(), 3, &mut h) },
        CKR_SESSION_READ_ONLY
    );
    // C_SetPIN in a R/O session (H1-30).
    let newpin = b"userpin2";
    assert_eq!(
        unsafe {
            C_SetPIN(
                ro,
                USER_PIN.as_ptr() as *mut _,
                USER_PIN.len() as CK_ULONG,
                newpin.as_ptr() as *mut _,
                newpin.len() as CK_ULONG,
            )
        },
        CKR_SESSION_READ_ONLY
    );
    // A NULL PIN is not an empty PIN (H1-30).
    assert_eq!(unsafe { C_Logout(s) }, CKR_OK);
    assert_eq!(
        unsafe { C_Login(s, CKU_USER, ptr::null_mut(), 4) },
        CKR_ARGUMENTS_BAD
    );
    // C_LoginUser (v3.0): user name accepted, PIN verified.
    let user = b"alice";
    assert_eq!(
        unsafe {
            C_LoginUser(
                s,
                CKU_USER,
                USER_PIN.as_ptr() as *mut _,
                USER_PIN.len() as CK_ULONG,
                user.as_ptr() as *mut _,
                user.len() as CK_ULONG,
            )
        },
        CKR_OK
    );
}

// ---------------------------------------------------------------------------
// H1-03 / H1-20: C_WrapKey authorization
// ---------------------------------------------------------------------------

#[test]
fn wrap_key_authorizes_the_wrapped_key() {
    let s = user_session();
    let t: CK_BBOOL = CK_TRUE;
    let f: CK_BBOOL = CK_FALSE;
    let kek = gen_aes(s, &[(CKA_WRAP, t)]);
    let target = gen_aes(s, &[(CKA_EXTRACTABLE, t)]);
    let unextractable = gen_aes(s, &[]);
    let weak_kek = gen_aes(
        s,
        &[(CKA_WRAP, t), (CKA_SENSITIVE, f), (CKA_EXTRACTABLE, t)],
    );
    let mut m = mech(CKM_AES_KEY_WRAP_KWP);
    let mut buf = [0u8; 128];
    let mut len = buf.len() as CK_ULONG;
    assert_eq!(
        unsafe { C_WrapKey(s, &mut m, kek, target, buf.as_mut_ptr(), &mut len) },
        CKR_OK
    );
    assert_eq!(len, 40);
    let mut len = buf.len() as CK_ULONG;
    assert_eq!(
        unsafe { C_WrapKey(s, &mut m, kek, unextractable, buf.as_mut_ptr(), &mut len) },
        CKR_KEY_UNEXTRACTABLE
    );
    // A sensitive key is never wrapped under a readable (non-sensitive) key.
    let mut len = buf.len() as CK_ULONG;
    assert_eq!(
        unsafe { C_WrapKey(s, &mut m, weak_kek, target, buf.as_mut_ptr(), &mut len) },
        CKR_WRAPPING_KEY_TYPE_INCONSISTENT
    );
    // Length query does not need the buffer and does not wrap twice.
    let mut len: CK_ULONG = 0;
    assert_eq!(
        unsafe { C_WrapKey(s, &mut m, kek, target, ptr::null_mut(), &mut len) },
        CKR_OK
    );
    assert_eq!(len, 40);
    // Without login the private key to wrap is invisible.
    assert_eq!(unsafe { C_Logout(s) }, CKR_OK);
    let mut len = buf.len() as CK_ULONG;
    assert_eq!(
        unsafe { C_WrapKey(s, &mut m, kek, target, buf.as_mut_ptr(), &mut len) },
        CKR_USER_NOT_LOGGED_IN
    );
}

// ---------------------------------------------------------------------------
// H1-08: C_CopyObject rules
// ---------------------------------------------------------------------------

#[test]
fn copy_object_cannot_escalate() {
    let s = user_session();
    let t: CK_BBOOL = CK_TRUE;
    let f: CK_BBOOL = CK_FALSE;
    let k = gen_aes(s, &[(CKA_ENCRYPT, t), (CKA_DECRYPT, f)]);
    let mut out = 0;
    // Usage flags cannot be switched on in the copy.
    let mut tmpl = [attr(CKA_DECRYPT, &t)];
    assert_eq!(
        unsafe { C_CopyObject(s, k, tmpl.as_mut_ptr(), 1, &mut out) },
        CKR_TEMPLATE_INCONSISTENT
    );
    // A key cannot be made public by copying.
    let mut tmpl = [attr(CKA_PRIVATE, &f)];
    assert_eq!(
        unsafe { C_CopyObject(s, k, tmpl.as_mut_ptr(), 1, &mut out) },
        CKR_TEMPLATE_INCONSISTENT
    );
    // Provenance cannot be forged.
    let mut tmpl = [attr(CKA_LOCAL, &t)];
    assert_eq!(
        unsafe { C_CopyObject(s, k, tmpl.as_mut_ptr(), 1, &mut out) },
        CKR_ATTRIBUTE_READ_ONLY
    );
    // Turning usage off and hardening is fine.
    let mut tmpl = [attr(CKA_ENCRYPT, &f), attr(CKA_COPYABLE, &f)];
    assert_eq!(
        unsafe { C_CopyObject(s, k, tmpl.as_mut_ptr(), 2, &mut out) },
        CKR_OK
    );
    // CKA_COPYABLE=FALSE objects cannot be copied (v3.0 CKR_ACTION_PROHIBITED).
    let mut out2 = 0;
    assert_eq!(
        unsafe { C_CopyObject(s, out, ptr::null_mut(), 0, &mut out2) },
        CKR_ACTION_PROHIBITED
    );
    // A non-modifiable source only allows TOKEN/PRIVATE/LABEL/ID.
    let nm = gen_aes(s, &[(CKA_MODIFIABLE, f), (CKA_ENCRYPT, t)]);
    let mut tmpl = [attr(CKA_ENCRYPT, &f)];
    assert_eq!(
        unsafe { C_CopyObject(s, nm, tmpl.as_mut_ptr(), 1, &mut out2) },
        CKR_ATTRIBUTE_READ_ONLY
    );
    let label = b"copy";
    let mut tmpl = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label.as_ptr() as *mut _,
        value_len: 4,
    }];
    assert_eq!(
        unsafe { C_CopyObject(s, nm, tmpl.as_mut_ptr(), 1, &mut out2) },
        CKR_OK
    );
}

// ---------------------------------------------------------------------------
// H1-04 / H1-12 / H1-17: operation state
// ---------------------------------------------------------------------------

fn sign_update(s: CK_SESSION_HANDLE, part: &[u8]) {
    assert_eq!(
        unsafe { C_SignUpdate(s, part.as_ptr() as *mut _, part.len() as CK_ULONG) },
        CKR_OK
    );
}

fn get_state(s: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
    let mut len: CK_ULONG = 0;
    let rv = unsafe { C_GetOperationState(s, ptr::null_mut(), &mut len) };
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut st = vec![0u8; len as usize];
    let rv = unsafe { C_GetOperationState(s, st.as_mut_ptr(), &mut len) };
    assert_eq!(rv, CKR_OK);
    st.truncate(len as usize);
    Ok(st)
}

#[test]
fn hash_then_sign_state_round_trip() {
    let s = user_session();
    let (pubk, privk) = gen_keypair(s, CKM_EC_KEY_PAIR_GEN, &[]).unwrap();
    let mut m = mech(CKM_ECDSA_SHA256);
    assert_eq!(unsafe { C_SignInit(s, &mut m, privk) }, CKR_OK);
    sign_update(s, b"hello ");
    let state = get_state(s).expect("sign state is saveable");
    // Abandon the operation, restore it and finish.
    assert_eq!(unsafe { C_SessionCancel(s, CKF_SIGN) }, CKR_OK);
    let rv =
        unsafe { C_SetOperationState(s, state.as_ptr() as *mut _, state.len() as CK_ULONG, 0, 0) };
    assert_eq!(rv, CKR_OK);
    sign_update(s, b"world");
    let mut sig = [0u8; 64];
    let mut len: CK_ULONG = 10;
    // CKR_BUFFER_TOO_SMALL keeps the operation (H1-26).
    assert_eq!(
        unsafe { C_SignFinal(s, sig.as_mut_ptr(), &mut len) },
        CKR_BUFFER_TOO_SMALL
    );
    assert_eq!(len, 64);
    assert_eq!(
        unsafe { C_SignFinal(s, sig.as_mut_ptr(), &mut len) },
        CKR_OK
    );
    // The signature covers the full message, including the part absorbed
    // before the save (H1-17).
    assert_eq!(verify(s, &mut m, pubk, b"hello world", &sig), CKR_OK);
    assert_eq!(
        verify(s, &mut m, pubk, b"world", &sig),
        CKR_SIGNATURE_INVALID
    );

    // A different authentication key is refused; restoring into another
    // session is refused (H1-04).
    assert_eq!(unsafe { C_SignInit(s, &mut m, privk) }, CKR_OK);
    let state = get_state(s).unwrap();
    let rv = unsafe {
        C_SetOperationState(
            s,
            state.as_ptr() as *mut _,
            state.len() as CK_ULONG,
            0,
            pubk,
        )
    };
    assert_eq!(rv, CKR_KEY_CHANGED);
    let other = open_session(true);
    let rv = unsafe {
        C_SetOperationState(
            other,
            state.as_ptr() as *mut _,
            state.len() as CK_ULONG,
            0,
            0,
        )
    };
    assert_eq!(rv, CKR_SAVED_STATE_INVALID);
    // After logout the private key cannot be bound again.
    assert_eq!(unsafe { C_Logout(s) }, CKR_OK);
    let rv =
        unsafe { C_SetOperationState(s, state.as_ptr() as *mut _, state.len() as CK_ULONG, 0, 0) };
    assert_eq!(rv, CKR_USER_NOT_LOGGED_IN);
}

#[test]
fn digest_key_is_never_exported_in_state() {
    let s = user_session();
    let t: CK_BBOOL = CK_TRUE;
    let f: CK_BBOOL = CK_FALSE;
    let k = gen_aes(s, &[(CKA_SENSITIVE, f), (CKA_EXTRACTABLE, t)]);
    let mut m = mech(CKM_SHA256);
    assert_eq!(unsafe { C_DigestInit(s, &mut m) }, CKR_OK);
    assert!(get_state(s).is_ok());
    assert_eq!(unsafe { C_DigestKey(s, k) }, CKR_OK);
    assert_eq!(get_state(s), Err(CKR_STATE_UNSAVEABLE));
    let mut out = [0u8; 32];
    let mut len: CK_ULONG = 8;
    assert_eq!(
        unsafe { C_DigestFinal(s, out.as_mut_ptr(), &mut len) },
        CKR_BUFFER_TOO_SMALL
    );
    assert_eq!(len, 32);
    assert_eq!(
        unsafe { C_DigestFinal(s, out.as_mut_ptr(), &mut len) },
        CKR_OK
    );
    // Without login a private key cannot be digested (H1-12).
    assert_eq!(unsafe { C_Logout(s) }, CKR_OK);
    assert_eq!(unsafe { C_DigestInit(s, &mut m) }, CKR_OK);
    assert_eq!(unsafe { C_DigestKey(s, k) }, CKR_USER_NOT_LOGGED_IN);
}

// ---------------------------------------------------------------------------
// A2-13 generic RSA-PSS, H2-20 ML-DSA context, A2-20 context-specific login
// ---------------------------------------------------------------------------

#[repr(C)]
struct PssParams {
    hash_alg: CK_ULONG,
    mgf: CK_ULONG,
    s_len: CK_ULONG,
}

#[test]
fn generic_rsa_pss_with_params() {
    let s = user_session();
    let mut n: CK_ULONG = 0;
    assert_eq!(
        unsafe { C_GetMechanismList(0, ptr::null_mut(), &mut n) },
        CKR_OK
    );
    let mut mechs = vec![0; n as usize];
    assert_eq!(
        unsafe { C_GetMechanismList(0, mechs.as_mut_ptr(), &mut n) },
        CKR_OK
    );
    assert!(mechs.contains(&CKM_RSA_PKCS_PSS));

    let (pubk, privk) = gen_keypair(s, CKM_RSA_PKCS_KEY_PAIR_GEN, &[]).unwrap();
    let msg = b"interoperable PSS";
    use sha2::Digest;
    let digest = sha2::Sha256::digest(msg);
    let mut p = PssParams {
        hash_alg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        s_len: 32,
    };
    let mut m = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_PSS,
        p_parameter: &mut p as *mut PssParams as *mut _,
        parameter_len: std::mem::size_of::<PssParams>() as CK_ULONG,
    };
    let sig = sign(s, &mut m, privk, &digest);
    assert_eq!(sig.len(), 256);
    assert_eq!(verify(s, &mut m, pubk, &digest, &sig), CKR_OK);
    // The same signature verifies with the hash-specific mechanism over the message.
    let mut m2 = mech(CKM_SHA256_RSA_PKCS_PSS);
    assert_eq!(verify(s, &mut m2, pubk, msg, &sig), CKR_OK);
    // Missing parameters are invalid.
    let mut bare = mech(CKM_RSA_PKCS_PSS);
    assert_eq!(
        unsafe { C_SignInit(s, &mut bare, privk) },
        CKR_MECHANISM_PARAM_INVALID
    );
}

#[repr(C)]
struct SignContext {
    hedge: CK_ULONG,
    p_context: *const u8,
    context_len: CK_ULONG,
}

#[test]
fn ml_dsa_context_strings() {
    let s = user_session();
    let (pubk, privk) = gen_keypair(s, CKM_ML_DSA_44, &[]).unwrap();
    let ctx = b"app-context";
    let mut c = SignContext {
        hedge: CKH_DETERMINISTIC_REQUIRED,
        p_context: ctx.as_ptr(),
        context_len: ctx.len() as CK_ULONG,
    };
    let mut m = CK_MECHANISM {
        mechanism: CKM_ML_DSA_44,
        p_parameter: &mut c as *mut SignContext as *mut _,
        parameter_len: std::mem::size_of::<SignContext>() as CK_ULONG,
    };
    let sig1 = sign(s, &mut m, privk, b"msg");
    let sig2 = sign(s, &mut m, privk, b"msg");
    assert_eq!(sig1.len(), 2420);
    assert_eq!(sig1, sig2, "deterministic variant");
    assert_eq!(verify(s, &mut m, pubk, b"msg", &sig1), CKR_OK);
    let mut plain = mech(CKM_ML_DSA_44);
    assert_eq!(
        verify(s, &mut plain, pubk, b"msg", &sig1),
        CKR_SIGNATURE_INVALID
    );
}

#[test]
fn always_authenticate_requires_context_specific_login() {
    let s = user_session();
    let t: CK_BBOOL = CK_TRUE;
    let (pubk, privk) =
        gen_keypair(s, CKM_EC_KEY_PAIR_GEN, &[(CKA_ALWAYS_AUTHENTICATE, t)]).unwrap();
    let mut m = mech(CKM_ECDSA_SHA256);
    assert_eq!(unsafe { C_SignInit(s, &mut m, privk) }, CKR_OK);
    let mut sig = [0u8; 64];
    let mut len = sig.len() as CK_ULONG;
    let data = b"payload";
    let do_sign = |len: &mut CK_ULONG, sig: &mut [u8; 64]| unsafe {
        C_Sign(
            s,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            sig.as_mut_ptr(),
            len,
        )
    };
    assert_eq!(do_sign(&mut len, &mut sig), CKR_USER_NOT_LOGGED_IN);
    assert_eq!(
        login(s, CKU_CONTEXT_SPECIFIC, b"wrongpin9"),
        CKR_PIN_INCORRECT
    );
    assert_eq!(login(s, CKU_CONTEXT_SPECIFIC, USER_PIN), CKR_OK);
    assert_eq!(do_sign(&mut len, &mut sig), CKR_OK);
    assert_eq!(verify(s, &mut m, pubk, data, &sig), CKR_OK);
    // Every use needs a fresh context-specific login.
    assert_eq!(unsafe { C_SignInit(s, &mut m, privk) }, CKR_OK);
    let mut len = sig.len() as CK_ULONG;
    assert_eq!(do_sign(&mut len, &mut sig), CKR_USER_NOT_LOGGED_IN);
    // Without such an operation context-specific login is refused.
    assert_eq!(unsafe { C_SessionCancel(s, CKF_SIGN) }, CKR_OK);
    assert_eq!(
        login(s, CKU_CONTEXT_SPECIFIC, USER_PIN),
        CKR_OPERATION_NOT_INITIALIZED
    );
    // The attribute reads back.
    let mut v: CK_BBOOL = 0;
    let mut a = [attr(CKA_ALWAYS_AUTHENTICATE, &mut v)];
    assert_eq!(
        unsafe { C_GetAttributeValue(s, privk, a.as_mut_ptr(), 1) },
        CKR_OK
    );
    assert_eq!(v, CK_TRUE);
}

// ---------------------------------------------------------------------------
// A2-01 message-based AES-GCM
// ---------------------------------------------------------------------------

#[repr(C)]
struct GcmMessageParams {
    p_iv: *mut u8,
    iv_len: CK_ULONG,
    iv_fixed_bits: CK_ULONG,
    iv_generator: CK_ULONG,
    p_tag: *mut u8,
    tag_bits: CK_ULONG,
}

#[test]
fn message_based_aes_gcm() {
    let s = user_session();
    let t: CK_BBOOL = CK_TRUE;
    let k = gen_aes(s, &[(CKA_ENCRYPT, t), (CKA_DECRYPT, t)]);
    let mut info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { C_GetMechanismInfo(0, CKM_AES_GCM, &mut info) },
        CKR_OK
    );
    assert_ne!(info.flags & CKF_MESSAGE_ENCRYPT, 0);
    assert_eq!(info.flags & CKF_MULTI_MESSAGE, 0);

    let mut m = mech(CKM_AES_GCM);
    assert_eq!(unsafe { C_MessageEncryptInit(s, &mut m, k) }, CKR_OK);
    assert_eq!(
        unsafe { C_MessageEncryptInit(s, &mut m, k) },
        CKR_OPERATION_ACTIVE
    );
    let mut iv = [0u8; 12];
    let mut tag = [0u8; 16];
    let mut p = GcmMessageParams {
        p_iv: iv.as_mut_ptr(),
        iv_len: 12,
        iv_fixed_bits: 0,
        iv_generator: CKG_GENERATE_RANDOM,
        p_tag: tag.as_mut_ptr(),
        tag_bits: 128,
    };
    let aad = b"header";
    let pt = b"message-based plaintext";
    let mut ct = vec![0u8; pt.len()];
    let mut ct_len = ct.len() as CK_ULONG;
    let rv = unsafe {
        C_EncryptMessage(
            s,
            &mut p as *mut GcmMessageParams as *mut _,
            std::mem::size_of::<GcmMessageParams>() as CK_ULONG,
            aad.as_ptr() as *mut _,
            aad.len() as CK_ULONG,
            pt.as_ptr() as *mut _,
            pt.len() as CK_ULONG,
            ct.as_mut_ptr(),
            &mut ct_len,
        )
    };
    assert_eq!(rv, CKR_OK);
    assert_ne!(iv, [0u8; 12], "module-generated IV is returned");
    assert_eq!(
        unsafe { C_EncryptMessageBegin(s, ptr::null_mut(), 0, ptr::null_mut(), 0) },
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(unsafe { C_MessageEncryptFinal(s) }, CKR_OK);

    assert_eq!(unsafe { C_MessageDecryptInit(s, &mut m, k) }, CKR_OK);
    p.iv_generator = CKG_NO_GENERATE;
    let mut out = vec![0u8; pt.len()];
    let mut out_len = out.len() as CK_ULONG;
    let rv = unsafe {
        C_DecryptMessage(
            s,
            &mut p as *mut GcmMessageParams as *mut _,
            std::mem::size_of::<GcmMessageParams>() as CK_ULONG,
            aad.as_ptr() as *mut _,
            aad.len() as CK_ULONG,
            ct.as_ptr() as *mut _,
            ct.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_eq!(rv, CKR_OK);
    assert_eq!(&out[..], &pt[..]);
    // A modified AAD fails authentication.
    let bad_aad = b"HEADER";
    let rv = unsafe {
        C_DecryptMessage(
            s,
            &mut p as *mut GcmMessageParams as *mut _,
            std::mem::size_of::<GcmMessageParams>() as CK_ULONG,
            bad_aad.as_ptr() as *mut _,
            bad_aad.len() as CK_ULONG,
            ct.as_ptr() as *mut _,
            ct.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_ne!(rv, CKR_OK);
    assert_eq!(unsafe { C_SessionCancel(s, CKF_MESSAGE_DECRYPT) }, CKR_OK);
    assert_eq!(
        unsafe { C_MessageDecryptFinal(s) },
        CKR_OPERATION_NOT_INITIALIZED
    );
    assert_eq!(
        unsafe { C_MessageSignInit(s, &mut m, k) },
        CKR_FUNCTION_NOT_SUPPORTED
    );
}

// ---------------------------------------------------------------------------
// H1-26: C_GetAttributeValue buffer too small
// ---------------------------------------------------------------------------

#[test]
fn get_attribute_value_too_small_is_unavailable() {
    let s = user_session();
    let k = gen_aes(s, &[]);
    let mut small = [0u8; 2];
    let mut a = [CK_ATTRIBUTE {
        attr_type: CKA_KEY_TYPE,
        p_value: small.as_mut_ptr() as *mut _,
        value_len: 2,
    }];
    assert_eq!(
        unsafe { C_GetAttributeValue(s, k, a.as_mut_ptr(), 1) },
        CKR_BUFFER_TOO_SMALL
    );
    assert_eq!(a[0].value_len, CK_UNAVAILABLE_INFORMATION);
}
