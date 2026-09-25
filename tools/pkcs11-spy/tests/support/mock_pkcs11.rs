// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Minimal mock PKCS#11 module used by the pkcs11-spy integration tests.
//! Compiled at test time with `rustc --crate-type cdylib` (Unix layout only).
//!
//! * C_Initialize / C_Finalize → CKR_OK
//! * C_GetInfo(NULL) → vendor code 0x80001234 (checks the spy forwards NULL)
//! * C_Login / C_LoginUser → CKR_PIN_INCORRECT
//! * C_GenerateRandom → fills the buffer with 0x42
//! * C_SessionCancel → CKR_OK
//! * every other entry is NULL (the spy must answer CKR_FUNCTION_NOT_SUPPORTED)
//! * C_GetInterface offers "PKCS 11" 3.0 unless MOCK_NO_V3 is set.
#![allow(non_snake_case, clippy::missing_safety_doc)]

use std::ffi::{c_ulong, c_void};
use std::sync::OnceLock;

type RV = c_ulong;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Version {
    major: u8,
    minor: u8,
}

#[repr(C)]
pub struct List {
    version: Version,
    f: [usize; 92],
}

#[repr(C)]
pub struct Interface {
    name: *const u8,
    list: *const c_void,
    flags: c_ulong,
}

struct Tables {
    v2: List,
    v3: List,
    iface: Interface,
}
unsafe impl Sync for Tables {}
unsafe impl Send for Tables {}

extern "C" fn initialize(_: *mut c_void) -> RV {
    0
}
extern "C" fn finalize(_: *mut c_void) -> RV {
    0
}
extern "C" fn get_info(p: *mut c_void) -> RV {
    if p.is_null() {
        0x8000_1234
    } else {
        0
    }
}
extern "C" fn login(_h: c_ulong, _u: c_ulong, _p: *const u8, _l: c_ulong) -> RV {
    0xA0
}
unsafe extern "C" fn generate_random(_h: c_ulong, p: *mut u8, n: c_ulong) -> RV {
    std::ptr::write_bytes(p, 0x42, n as usize);
    0
}
extern "C" fn login_user(
    _h: c_ulong,
    _u: c_ulong,
    _p: *const u8,
    _l: c_ulong,
    _un: *const u8,
    _ul: c_ulong,
) -> RV {
    0xA0
}
extern "C" fn session_cancel(_h: c_ulong, _f: c_ulong) -> RV {
    0
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut f = [0usize; 92];
        f[0] = initialize as *const () as usize;
        f[1] = finalize as *const () as usize;
        f[2] = get_info as *const () as usize;
        f[3] = C_GetFunctionList as *const () as usize;
        f[18] = login as *const () as usize;
        f[64] = generate_random as *const () as usize;
        let mut f3 = f;
        f3[69] = C_GetInterface as *const () as usize;
        f3[70] = login_user as *const () as usize;
        f3[71] = session_cancel as *const () as usize;
        let t = Tables {
            v2: List {
                version: Version {
                    major: 2,
                    minor: 40,
                },
                f,
            },
            v3: List {
                version: Version { major: 3, minor: 0 },
                f: f3,
            },
            iface: Interface {
                name: b"PKCS 11\0".as_ptr(),
                list: std::ptr::null(),
                flags: 0,
            },
        };
        t
    })
}

fn v3_list() -> *const List {
    &tables().v3
}

#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp: *mut *const List) -> RV {
    if pp.is_null() {
        return 7;
    }
    *pp = &tables().v2;
    0
}

#[no_mangle]
pub unsafe extern "C" fn C_GetInterface(
    _name: *const u8,
    ver: *const Version,
    pp: *mut *const Interface,
    _flags: c_ulong,
) -> RV {
    if std::env::var_os("MOCK_NO_V3").is_some() {
        return 0x54;
    }
    if pp.is_null() || (!ver.is_null() && (*ver).major != 3) {
        return 7;
    }
    static IFACE: OnceLock<usize> = OnceLock::new();
    let p = *IFACE.get_or_init(|| {
        let i = Box::new(Interface {
            name: tables().iface.name,
            list: v3_list() as *const c_void,
            flags: 1,
        });
        Box::into_raw(i) as usize
    });
    *pp = p as *const Interface;
    0
}

/// Test hook: address of the mock's own v3.0 table.
#[no_mangle]
pub extern "C" fn mock_v3_list() -> *const List {
    v3_list()
}
