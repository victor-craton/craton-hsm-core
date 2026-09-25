// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Minimal PKCS#11 ABI definitions used by the spy.
//!
//! The spy is standalone (no dependency on the `craton-hsm` crate) so it can
//! wrap any PKCS#11 module. `CK_ULONG` is `unsigned long` in the C headers,
//! i.e. `c_ulong`: 64-bit on LP64 Unix, 32-bit on Win64. The spy must be
//! built for the same target as the module it wraps.
//!
//! Struct layout follows the OASIS headers: on Windows every Cryptoki struct is
//! 1-byte packed (`#pragma pack(push, cryptoki, 1)`), elsewhere natural `repr(C)`
//! — the same convention as `src/pkcs11_abi/types.rs` in the root crate.
#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::ffi::c_void;

pub type CK_ULONG = std::ffi::c_ulong;
pub type CK_RV = CK_ULONG;
pub type CK_BYTE = u8;
pub type CK_BBOOL = u8;
pub type CK_VOID_PTR = *mut c_void;
pub type CK_BYTE_PTR = *mut CK_BYTE;
pub type CK_ULONG_PTR = *mut CK_ULONG;
pub type CK_FLAGS = CK_ULONG;
pub type CK_SLOT_ID = CK_ULONG;
pub type CK_SESSION_HANDLE = CK_ULONG;
pub type CK_OBJECT_HANDLE = CK_ULONG;
pub type CK_MECHANISM_TYPE = CK_ULONG;
pub type CK_USER_TYPE = CK_ULONG;
pub type CK_UTF8CHAR_PTR = *mut u8;
pub type CK_SLOT_ID_PTR = *mut CK_SLOT_ID;
pub type CK_SESSION_HANDLE_PTR = *mut CK_SESSION_HANDLE;
pub type CK_OBJECT_HANDLE_PTR = *mut CK_OBJECT_HANDLE;
pub type CK_MECHANISM_TYPE_PTR = *mut CK_MECHANISM_TYPE;
pub type CK_NOTIFY =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_ULONG, CK_VOID_PTR) -> CK_RV>;

// Opaque struct pointers — forwarded, never inspected (except the leading
// `mechanism` field of CK_MECHANISM, see `lib.rs::mech`).
pub type CK_INFO_PTR = CK_VOID_PTR;
pub type CK_SLOT_INFO_PTR = CK_VOID_PTR;
pub type CK_TOKEN_INFO_PTR = CK_VOID_PTR;
pub type CK_SESSION_INFO_PTR = CK_VOID_PTR;
pub type CK_MECHANISM_PTR = CK_VOID_PTR;
pub type CK_MECHANISM_INFO_PTR = CK_VOID_PTR;
pub type CK_ATTRIBUTE_PTR = CK_VOID_PTR;

// ── Return codes used by the spy itself ─────────────────────────────────────
pub const CKR_OK: CK_RV = 0x0000_0000;
pub const CKR_GENERAL_ERROR: CK_RV = 0x0000_0005;
pub const CKR_ARGUMENTS_BAD: CK_RV = 0x0000_0007;
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x0000_0054;
pub const CKR_BUFFER_TOO_SMALL: CK_RV = 0x0000_0150;

pub const CKF_INTERFACE_FORK_SAFE: CK_FLAGS = 0x0000_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
pub struct CK_VERSION {
    pub major: CK_BYTE,
    pub minor: CK_BYTE,
}
pub type CK_VERSION_PTR = *mut CK_VERSION;

#[derive(Clone, Copy)]
#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
pub struct CK_INTERFACE {
    pub pInterfaceName: *mut u8,
    pub pFunctionList: CK_VOID_PTR,
    pub flags: CK_FLAGS,
}
pub type CK_INTERFACE_PTR = *mut CK_INTERFACE;
pub type CK_INTERFACE_PTR_PTR = *mut CK_INTERFACE_PTR;

pub type CK_FUNCTION_LIST_PTR = *mut CK_FUNCTION_LIST;
pub type CK_FUNCTION_LIST_PTR_PTR = *mut CK_FUNCTION_LIST_PTR;

/// Declares a function-list struct whose entries are nullable function
/// pointers. Field order MUST match the OASIS `pkcs11f.h` order exactly.
macro_rules! function_list {
    (
        $(#[$m:meta])*
        pub struct $name:ident {
            $( $f:ident ( $($a:ty),* ); )*
        }
    ) => {
        $(#[$m])*
        #[derive(Clone, Copy)]
        #[cfg_attr(target_os = "windows", repr(C, packed))]
        #[cfg_attr(not(target_os = "windows"), repr(C))]
        pub struct $name {
            pub version: CK_VERSION,
            $( pub $f: Option<unsafe extern "C" fn($($a),*) -> CK_RV>, )*
        }
    };
}

// The v2.40 entries, shared verbatim as the prefix of the v3.0 list.
macro_rules! v2_entries {
    ($mac:ident, $(#[$m:meta])* $name:ident { $($extra:tt)* }) => {
        $mac! {
            $(#[$m])*
            pub struct $name {
                C_Initialize(CK_VOID_PTR);
                C_Finalize(CK_VOID_PTR);
                C_GetInfo(CK_INFO_PTR);
                C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR);
                C_GetSlotList(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
                C_GetSlotInfo(CK_SLOT_ID, CK_SLOT_INFO_PTR);
                C_GetTokenInfo(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
                C_GetMechanismList(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
                C_GetMechanismInfo(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR);
                C_InitToken(CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR);
                C_InitPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG);
                C_SetPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG);
                C_OpenSession(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR);
                C_CloseSession(CK_SESSION_HANDLE);
                C_CloseAllSessions(CK_SLOT_ID);
                C_GetSessionInfo(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR);
                C_GetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
                C_SetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);
                C_Login(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG);
                C_Logout(CK_SESSION_HANDLE);
                C_CreateObject(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
                C_CopyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
                C_DestroyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
                C_GetObjectSize(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR);
                C_GetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
                C_SetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
                C_FindObjectsInit(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
                C_FindObjects(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR);
                C_FindObjectsFinal(CK_SESSION_HANDLE);
                C_EncryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
                C_Encrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
                C_EncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
                C_EncryptFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
                C_DecryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
                C_Decrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
                C_DecryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
                C_DecryptFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
                C_DigestInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR);
                C_Digest(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
                C_DigestUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
                C_DigestKey(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
                C_DigestFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
                C_SignInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
                C_Sign(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
                C_SignUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
                C_SignFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
                C_SignRecoverInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
                C_SignRecover(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
                C_VerifyInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
                C_Verify(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
                C_VerifyUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
                C_VerifyFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
                C_VerifyRecoverInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
                C_VerifyRecover(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
                C_DigestEncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
                C_DecryptDigestUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
                C_SignEncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
                C_DecryptVerifyUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
                C_GenerateKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
                C_GenerateKeyPair(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
                C_WrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
                C_UnwrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
                C_DeriveKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
                C_SeedRandom(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
                C_GenerateRandom(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
                C_GetFunctionStatus(CK_SESSION_HANDLE);
                C_CancelFunction(CK_SESSION_HANDLE);
                C_WaitForSlotEvent(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR);
                $($extra)*
            }
        }
    };
}

v2_entries!(function_list,
    /// PKCS#11 v2.40 `CK_FUNCTION_LIST` (68 entries).
    CK_FUNCTION_LIST {});

v2_entries!(function_list,
/// PKCS#11 v3.0 `CK_FUNCTION_LIST_3_0` (the 68 v2.40 entries + 24 new ones).
CK_FUNCTION_LIST_3_0 {
    C_GetInterfaceList(CK_INTERFACE_PTR, CK_ULONG_PTR);
    C_GetInterface(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS);
    C_LoginUser(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG);
    C_SessionCancel(CK_SESSION_HANDLE, CK_FLAGS);
    C_MessageEncryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    C_EncryptMessage(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    C_EncryptMessageBegin(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
    C_EncryptMessageNext(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_FLAGS);
    C_MessageEncryptFinal(CK_SESSION_HANDLE);
    C_MessageDecryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    C_DecryptMessage(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    C_DecryptMessageBegin(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
    C_DecryptMessageNext(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_FLAGS);
    C_MessageDecryptFinal(CK_SESSION_HANDLE);
    C_MessageSignInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    C_SignMessage(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    C_SignMessageBegin(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG);
    C_SignMessageNext(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    C_MessageSignFinal(CK_SESSION_HANDLE);
    C_MessageVerifyInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    C_VerifyMessage(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
    C_VerifyMessageBegin(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG);
    C_VerifyMessageNext(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
    C_MessageVerifyFinal(CK_SESSION_HANDLE);
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn function_list_sizes_match_spec_entry_counts() {
        let p = size_of::<usize>();
        // Header is CK_VERSION (2 bytes) padded to pointer alignment (or packed on Windows).
        let hdr = if cfg!(target_os = "windows") { 2 } else { p };
        assert_eq!(size_of::<CK_FUNCTION_LIST>(), hdr + 68 * p);
        assert_eq!(size_of::<CK_FUNCTION_LIST_3_0>(), hdr + 92 * p);
    }
}
