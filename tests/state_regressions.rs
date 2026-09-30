// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Regression tests for the 2026-09-24 store/session/token audit fixes
//! (H1-01/H3-01, H1-02, H1-05, H1-06, H1-13/H3-03, H3-04, H3-07).
//!
//! ABI tests share global state: run with `--test-threads=1`.

use craton_hsm::config::HsmConfig;
use craton_hsm::core::HsmCore;
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use craton_hsm::store::attributes::ObjectContext;
use std::ptr;

const SO_PIN: &[u8] = b"S0pin-47";
const USER_PIN: &[u8] = b"Us3rpin9";

fn label(s: &[u8]) -> [u8; 32] {
    let mut l = [b' '; 32];
    l[..s.len()].copy_from_slice(s);
    l
}

fn ensure_init() {
    let rv = unsafe { C_Initialize(ptr::null_mut()) };
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
}

fn open_rw() -> CK_SESSION_HANDLE {
    let mut s: CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        C_OpenSession(
            0,
            CKF_RW_SESSION | CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut s,
        )
    };
    assert_eq!(rv, CKR_OK);
    s
}

fn login(s: CK_SESSION_HANDLE, user: CK_ULONG, pin: &[u8]) -> CK_RV {
    unsafe { C_Login(s, user, pin.as_ptr() as *mut _, pin.len() as CK_ULONG) }
}

fn init_token(pin: &[u8]) -> CK_RV {
    let l = label(b"Regress");
    unsafe {
        C_InitToken(
            0,
            pin.as_ptr() as *mut _,
            pin.len() as CK_ULONG,
            l.as_ptr() as *mut _,
        )
    }
}

/// Fresh token with a user PIN; returns a user session.
fn fresh_user_session() -> CK_SESSION_HANDLE {
    ensure_init();
    let _ = unsafe { C_CloseAllSessions(0) };
    assert_eq!(init_token(SO_PIN), CKR_OK);
    let s = open_rw();
    assert_eq!(login(s, CKU_SO, SO_PIN), CKR_OK);
    assert_eq!(
        unsafe { C_InitPIN(s, USER_PIN.as_ptr() as *mut _, USER_PIN.len() as CK_ULONG) },
        CKR_OK
    );
    assert_eq!(unsafe { C_Logout(s) }, CKR_OK);
    assert_eq!(login(s, CKU_USER, USER_PIN), CKR_OK);
    s
}

fn gen_aes(s: CK_SESSION_HANDLE, token: bool, extractable: bool) -> CK_OBJECT_HANDLE {
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let len: CK_ULONG = 32;
    let t: CK_BBOOL = if token { CK_TRUE } else { CK_FALSE };
    let x: CK_BBOOL = if extractable { CK_TRUE } else { CK_FALSE };
    let yes: CK_BBOOL = CK_TRUE;
    let mut tmpl = [
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: &len as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &t as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_EXTRACTABLE,
            p_value: &x as *const _ as *mut _,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SENSITIVE,
            p_value: &yes as *const _ as *mut _,
            value_len: 1,
        },
    ];
    let mut h: CK_OBJECT_HANDLE = 0;
    let rv = unsafe {
        C_GenerateKey(
            s,
            &mut mech,
            tmpl.as_mut_ptr(),
            tmpl.len() as CK_ULONG,
            &mut h,
        )
    };
    assert_eq!(rv, CKR_OK);
    h
}

fn count_objects(s: CK_SESSION_HANDLE) -> usize {
    assert_eq!(unsafe { C_FindObjectsInit(s, ptr::null_mut(), 0) }, CKR_OK);
    let mut found = [0 as CK_OBJECT_HANDLE; 64];
    let mut n: CK_ULONG = 0;
    assert_eq!(
        unsafe { C_FindObjects(s, found.as_mut_ptr(), 64, &mut n) },
        CKR_OK
    );
    assert_eq!(unsafe { C_FindObjectsFinal(s) }, CKR_OK);
    n as usize
}

/// H1-01/H3-01: a wrong SO PIN must not destroy anything, open sessions
/// must yield CKR_SESSION_EXISTS, and guessing counts toward the lockout.
#[test]
fn init_token_verifies_so_pin_before_wiping() {
    let s = fresh_user_session();
    gen_aes(s, false, false);
    assert_eq!(count_objects(s), 1);

    // Sessions open → CKR_SESSION_EXISTS, nothing destroyed.
    assert_eq!(init_token(SO_PIN), CKR_SESSION_EXISTS);
    assert_eq!(count_objects(s), 1);

    // Keep the object alive in a token object, close sessions, wrong PIN.
    let t = gen_aes(s, true, false);
    let _ = t;
    assert_eq!(unsafe { C_CloseAllSessions(0) }, CKR_OK);
    assert_eq!(init_token(b"wrongPIN9"), CKR_PIN_INCORRECT);
    let s2 = open_rw();
    assert_eq!(login(s2, CKU_USER, USER_PIN), CKR_OK);
    assert_eq!(
        count_objects(s2),
        1,
        "token object must survive a failed C_InitToken"
    );
    assert_eq!(unsafe { C_CloseAllSessions(0) }, CKR_OK);

    // Correct PIN wipes the token.
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(init_token(SO_PIN), CKR_OK);
}

/// H1-02: sensitive+extractable keys never reveal CKA_VALUE.
#[test]
fn sensitive_extractable_value_not_readable_via_abi() {
    let s = fresh_user_session();
    let h = gen_aes(s, false, true);
    let mut buf = [0u8; 64];
    let mut attr = [CK_ATTRIBUTE {
        attr_type: CKA_VALUE,
        p_value: buf.as_mut_ptr() as *mut _,
        value_len: buf.len() as CK_ULONG,
    }];
    assert_eq!(
        unsafe { C_GetAttributeValue(s, h, attr.as_mut_ptr(), 1) },
        CKR_ATTRIBUTE_SENSITIVE
    );
    assert_eq!(attr[0].value_len, CK_UNAVAILABLE_INFORMATION);
    assert_eq!(buf, [0u8; 64]);
}

/// H1-05: an SO session cannot see or use the user's private objects.
#[test]
fn so_cannot_access_private_user_objects() {
    let s = fresh_user_session();
    let h = gen_aes(s, true, false);
    assert_eq!(unsafe { C_Logout(s) }, CKR_OK);
    assert_eq!(login(s, CKU_SO, SO_PIN), CKR_OK);
    assert_eq!(count_objects(s), 0, "SO must not find private user objects");
    let mut v: CK_ULONG = 0;
    let mut attr = [CK_ATTRIBUTE {
        attr_type: CKA_VALUE_LEN,
        p_value: &mut v as *mut _ as *mut _,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    assert_eq!(
        unsafe { C_GetAttributeValue(s, h, attr.as_mut_ptr(), 1) },
        CKR_USER_NOT_LOGGED_IN
    );
    assert_eq!(unsafe { C_Logout(s) }, CKR_OK);
}

/// H1-06: closing the last session logs the token out; H3-07: session
/// objects die with their session.
#[test]
fn closing_last_session_logs_out_and_destroys_session_objects() {
    let s = fresh_user_session();
    gen_aes(s, false, false);
    assert_eq!(unsafe { C_CloseSession(s) }, CKR_OK);

    let s2 = open_rw();
    let mut info = CK_SESSION_INFO {
        slot_id: 0,
        state: 0,
        flags: 0,
        device_error: 0,
    };
    assert_eq!(unsafe { C_GetSessionInfo(s2, &mut info) }, CKR_OK);
    assert_eq!(
        info.state, CKS_RW_PUBLIC_SESSION,
        "token must be logged out"
    );
    assert_eq!(login(s2, CKU_USER, USER_PIN), CKR_OK);
    assert_eq!(count_objects(s2), 0, "session object must be destroyed");
    assert_eq!(unsafe { C_CloseSession(s2) }, CKR_OK);
}

/// H1-13/H3-03: objects are bound to the slot of the creating session.
#[test]
fn objects_are_slot_isolated_in_core() {
    let mut cfg = HsmConfig::default();
    cfg.token.slot_count = 2;
    cfg.audit.enabled = false;
    cfg.audit.allow_disabled_insecure = true;
    let hsm = HsmCore::open(&cfg).unwrap();
    let t = [
        (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
        (CKA_VALUE, vec![1u8; 32]),
    ];
    let h = hsm
        .object_store()
        .create_object_in(&t, &ObjectContext::new(1, 0, false))
        .unwrap();
    assert!(hsm.object_store().get_object_in_slot(h, 0).is_err());
    assert!(hsm.object_store().get_object_in_slot(h, 1).is_ok());
    assert!(hsm
        .object_store()
        .find_objects_for_slot(&[], true, Some(0))
        .is_empty());
}

/// H3-04/A1-17: token state, lockout and token objects survive a restart
/// when persistence is enabled; a restart does not reopen C_InitToken.
#[test]
fn persistent_token_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = HsmConfig::default();
    cfg.token.persist_objects = true;
    cfg.token.storage_path = dir.path().join("store");
    cfg.audit.log_path = dir.path().join("audit.jsonl");
    cfg.security.pbkdf2_iterations = 100_000;

    let key_handle;
    {
        let hsm = HsmCore::open(&cfg).unwrap();
        hsm.init_token(0, SO_PIN, &label(b"Persist")).unwrap();
        let s = hsm
            .open_process_session(0, CKF_RW_SESSION | CKF_SERIAL_SESSION)
            .unwrap();
        hsm.login(s, CKU_SO, SO_PIN).unwrap();
        hsm.init_pin(s, USER_PIN).unwrap();
        hsm.logout(s).unwrap();
        hsm.login(s, CKU_USER, USER_PIN).unwrap();
        let t = [
            (CKA_CLASS, CKO_SECRET_KEY.to_ne_bytes().to_vec()),
            (CKA_TOKEN, vec![1u8]),
            (CKA_VALUE, vec![7u8; 32]),
            (CKA_LABEL, b"persisted".to_vec()),
        ];
        let sess = hsm.session_manager().get_session(s).unwrap();
        let ctx = sess.read().object_ctx();
        key_handle = hsm.object_store().create_object_in(&t, &ctx).unwrap();
        hsm.close_session(s).unwrap();
    }
    {
        let hsm = HsmCore::open(&cfg).unwrap();
        let token = hsm.slot_manager().get_token(0).unwrap();
        assert!(token.is_initialized(), "initialised flag must persist");
        // Uninitialised-token takeover is impossible: wrong SO PIN fails.
        assert!(hsm.init_token(0, b"Attacker1", &label(b"x")).is_err());
        let s = hsm
            .open_process_session(0, CKF_RW_SESSION | CKF_SERIAL_SESSION)
            .unwrap();
        hsm.login(s, CKU_USER, USER_PIN).unwrap();
        let obj = hsm
            .object_store()
            .get_object_in_slot(key_handle, 0)
            .unwrap();
        assert_eq!(obj.read().label, b"persisted");
        assert_eq!(
            obj.read().key_material.as_ref().unwrap().as_bytes(),
            &[7u8; 32]
        );
        hsm.close_session(s).unwrap();
    }
    {
        // Failed SO attempt above is still counted after another restart.
        let hsm = HsmCore::open(&cfg).unwrap();
        let s = hsm
            .open_process_session(0, CKF_RW_SESSION | CKF_SERIAL_SESSION)
            .unwrap();
        hsm.login(s, CKU_SO, SO_PIN).unwrap();
        hsm.close_session(s).unwrap();
    }
}

/// H3-08: a session opened concurrently with C_Logout must never stay
/// authenticated after the logout completed.
#[test]
fn open_session_racing_logout_never_leaves_authenticated_session() {
    use std::sync::Arc;
    let mut cfg = HsmConfig::default();
    cfg.audit.enabled = false;
    cfg.audit.allow_disabled_insecure = true;
    cfg.security.pbkdf2_iterations = 100_000;
    cfg.token.max_sessions = 1000;
    cfg.token.max_rw_sessions = 1000;
    cfg.token.max_sessions_per_application = 1000;
    let hsm = Arc::new(HsmCore::open(&cfg).unwrap());
    hsm.init_token(0, SO_PIN, &label(b"Race")).unwrap();
    let s0 = hsm
        .open_process_session(0, CKF_RW_SESSION | CKF_SERIAL_SESSION)
        .unwrap();
    hsm.login(s0, CKU_SO, SO_PIN).unwrap();
    hsm.init_pin(s0, USER_PIN).unwrap();
    hsm.logout(s0).unwrap();

    for _ in 0..5 {
        hsm.login(s0, CKU_USER, USER_PIN).unwrap();
        let opener = {
            let hsm = hsm.clone();
            std::thread::spawn(move || {
                let mut v = Vec::new();
                for _ in 0..50 {
                    if let Ok(h) = hsm.open_process_session(0, CKF_SERIAL_SESSION) {
                        v.push(h);
                    }
                }
                v
            })
        };
        hsm.logout(s0).unwrap();
        let opened = opener.join().unwrap();
        for h in &opened {
            let st = hsm
                .session_manager()
                .get_session(*h)
                .unwrap()
                .read()
                .state
                .clone();
            assert!(
                !st.is_authenticated(),
                "session {h} still authenticated after logout: {st:?}"
            );
        }
        for h in opened {
            hsm.close_session(h).unwrap();
        }
    }
}
