// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! `CK_RV` → name table (PKCS#11 v2.40, v3.0, v3.1 and v3.2 return codes).

use std::fmt;

pub const CKR_VENDOR_DEFINED: u64 = 0x8000_0000;

/// Every return code defined by the OASIS headers, sorted by value.
static CKR_NAMES: &[(u64, &str)] = &[
    (0x000, "CKR_OK"),
    (0x001, "CKR_CANCEL"),
    (0x002, "CKR_HOST_MEMORY"),
    (0x003, "CKR_SLOT_ID_INVALID"),
    (0x005, "CKR_GENERAL_ERROR"),
    (0x006, "CKR_FUNCTION_FAILED"),
    (0x007, "CKR_ARGUMENTS_BAD"),
    (0x008, "CKR_NO_EVENT"),
    (0x009, "CKR_NEED_TO_CREATE_THREADS"),
    (0x00A, "CKR_CANT_LOCK"),
    (0x010, "CKR_ATTRIBUTE_READ_ONLY"),
    (0x011, "CKR_ATTRIBUTE_SENSITIVE"),
    (0x012, "CKR_ATTRIBUTE_TYPE_INVALID"),
    (0x013, "CKR_ATTRIBUTE_VALUE_INVALID"),
    (0x01B, "CKR_ACTION_PROHIBITED"),
    (0x020, "CKR_DATA_INVALID"),
    (0x021, "CKR_DATA_LEN_RANGE"),
    (0x030, "CKR_DEVICE_ERROR"),
    (0x031, "CKR_DEVICE_MEMORY"),
    (0x032, "CKR_DEVICE_REMOVED"),
    (0x040, "CKR_ENCRYPTED_DATA_INVALID"),
    (0x041, "CKR_ENCRYPTED_DATA_LEN_RANGE"),
    (0x042, "CKR_AEAD_DECRYPT_FAILED"),
    (0x050, "CKR_FUNCTION_CANCELED"),
    (0x051, "CKR_FUNCTION_NOT_PARALLEL"),
    (0x054, "CKR_FUNCTION_NOT_SUPPORTED"),
    (0x060, "CKR_KEY_HANDLE_INVALID"),
    (0x062, "CKR_KEY_SIZE_RANGE"),
    (0x063, "CKR_KEY_TYPE_INCONSISTENT"),
    (0x064, "CKR_KEY_NOT_NEEDED"),
    (0x065, "CKR_KEY_CHANGED"),
    (0x066, "CKR_KEY_NEEDED"),
    (0x067, "CKR_KEY_INDIGESTIBLE"),
    (0x068, "CKR_KEY_FUNCTION_NOT_PERMITTED"),
    (0x069, "CKR_KEY_NOT_WRAPPABLE"),
    (0x06A, "CKR_KEY_UNEXTRACTABLE"),
    (0x070, "CKR_MECHANISM_INVALID"),
    (0x071, "CKR_MECHANISM_PARAM_INVALID"),
    (0x082, "CKR_OBJECT_HANDLE_INVALID"),
    (0x090, "CKR_OPERATION_ACTIVE"),
    (0x091, "CKR_OPERATION_NOT_INITIALIZED"),
    (0x0A0, "CKR_PIN_INCORRECT"),
    (0x0A1, "CKR_PIN_INVALID"),
    (0x0A2, "CKR_PIN_LEN_RANGE"),
    (0x0A3, "CKR_PIN_EXPIRED"),
    (0x0A4, "CKR_PIN_LOCKED"),
    (0x0B0, "CKR_SESSION_CLOSED"),
    (0x0B1, "CKR_SESSION_COUNT"),
    (0x0B3, "CKR_SESSION_HANDLE_INVALID"),
    (0x0B4, "CKR_SESSION_PARALLEL_NOT_SUPPORTED"),
    (0x0B5, "CKR_SESSION_READ_ONLY"),
    (0x0B6, "CKR_SESSION_EXISTS"),
    (0x0B7, "CKR_SESSION_READ_ONLY_EXISTS"),
    (0x0B8, "CKR_SESSION_READ_WRITE_SO_EXISTS"),
    (0x0C0, "CKR_SIGNATURE_INVALID"),
    (0x0C1, "CKR_SIGNATURE_LEN_RANGE"),
    (0x0D0, "CKR_TEMPLATE_INCOMPLETE"),
    (0x0D1, "CKR_TEMPLATE_INCONSISTENT"),
    (0x0E0, "CKR_TOKEN_NOT_PRESENT"),
    (0x0E1, "CKR_TOKEN_NOT_RECOGNIZED"),
    (0x0E2, "CKR_TOKEN_WRITE_PROTECTED"),
    (0x0F0, "CKR_UNWRAPPING_KEY_HANDLE_INVALID"),
    (0x0F1, "CKR_UNWRAPPING_KEY_SIZE_RANGE"),
    (0x0F2, "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"),
    (0x100, "CKR_USER_ALREADY_LOGGED_IN"),
    (0x101, "CKR_USER_NOT_LOGGED_IN"),
    (0x102, "CKR_USER_PIN_NOT_INITIALIZED"),
    (0x103, "CKR_USER_TYPE_INVALID"),
    (0x104, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN"),
    (0x105, "CKR_USER_TOO_MANY_TYPES"),
    (0x110, "CKR_WRAPPED_KEY_INVALID"),
    (0x112, "CKR_WRAPPED_KEY_LEN_RANGE"),
    (0x113, "CKR_WRAPPING_KEY_HANDLE_INVALID"),
    (0x114, "CKR_WRAPPING_KEY_SIZE_RANGE"),
    (0x115, "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"),
    (0x120, "CKR_RANDOM_SEED_NOT_SUPPORTED"),
    (0x121, "CKR_RANDOM_NO_RNG"),
    (0x130, "CKR_DOMAIN_PARAMS_INVALID"),
    (0x140, "CKR_CURVE_NOT_SUPPORTED"),
    (0x150, "CKR_BUFFER_TOO_SMALL"),
    (0x160, "CKR_SAVED_STATE_INVALID"),
    (0x170, "CKR_INFORMATION_SENSITIVE"),
    (0x180, "CKR_STATE_UNSAVEABLE"),
    (0x190, "CKR_CRYPTOKI_NOT_INITIALIZED"),
    (0x191, "CKR_CRYPTOKI_ALREADY_INITIALIZED"),
    (0x1A0, "CKR_MUTEX_BAD"),
    (0x1A1, "CKR_MUTEX_NOT_LOCKED"),
    (0x1B0, "CKR_NEW_PIN_MODE"),
    (0x1B1, "CKR_NEXT_OTP"),
    (0x1B5, "CKR_EXCEEDED_MAX_ITERATIONS"),
    (0x1B6, "CKR_FIPS_SELF_TEST_FAILED"),
    (0x1B7, "CKR_LIBRARY_LOAD_FAILED"),
    (0x1B8, "CKR_PIN_TOO_WEAK"),
    (0x1B9, "CKR_PUBLIC_KEY_INVALID"),
    (0x200, "CKR_FUNCTION_REJECTED"),
    (0x201, "CKR_TOKEN_RESOURCE_EXCEEDED"),
    (0x202, "CKR_OPERATION_CANCEL_FAILED"),
    (0x203, "CKR_KEY_EXHAUSTED"),
    (0x204, "CKR_PENDING"),
    (0x205, "CKR_SESSION_ASYNC_NOT_SUPPORTED"),
    (0x206, "CKR_SEED_RANDOM_REQUIRED"),
    (0x207, "CKR_OPERATION_NOT_VALIDATED"),
    (0x208, "CKR_TOKEN_NOT_INITIALIZED"),
    (0x209, "CKR_PARAMETER_SET_NOT_SUPPORTED"),
];

/// A displayable return-code name: the standard name, `CKR_VENDOR_DEFINED+0x…`
/// for vendor codes, or `CKR_UNKNOWN_0x…` for undefined standard codes.
/// Output contains only `[A-Z0-9_+x]`, so it is safe to embed in JSON unescaped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CkrName {
    Known(&'static str),
    Vendor(u64),
    Unknown(u64),
}

impl fmt::Display for CkrName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CkrName::Known(s) => f.write_str(s),
            CkrName::Vendor(off) => write!(f, "CKR_VENDOR_DEFINED+0x{off:x}"),
            CkrName::Unknown(rv) => write!(f, "CKR_UNKNOWN_0x{rv:08x}"),
        }
    }
}

/// Widen a `CK_RV` (`c_ulong`: 32-bit on Windows, 64-bit on LP64) to `u64`.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
pub fn widen(rv: crate::types::CK_RV) -> u64 {
    rv as u64
}

pub fn ckr_name(rv: u64) -> CkrName {
    if rv >= CKR_VENDOR_DEFINED {
        return CkrName::Vendor(rv - CKR_VENDOR_DEFINED);
    }
    match CKR_NAMES.binary_search_by_key(&rv, |&(code, _)| code) {
        Ok(i) => CkrName::Known(CKR_NAMES[i].1),
        Err(_) => CkrName::Unknown(rv),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        assert!(CKR_NAMES.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn previously_missing_codes_are_named() {
        for (rv, name) in [
            (0x08, "CKR_NO_EVENT"),
            (0x1B, "CKR_ACTION_PROHIBITED"),
            (0x41, "CKR_ENCRYPTED_DATA_LEN_RANGE"),
            (0x6A, "CKR_KEY_UNEXTRACTABLE"),
            (0x91, "CKR_OPERATION_NOT_INITIALIZED"),
            (0xA3, "CKR_PIN_EXPIRED"),
            (0x115, "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"),
            (0x140, "CKR_CURVE_NOT_SUPPORTED"),
            (0x1B9, "CKR_PUBLIC_KEY_INVALID"),
            (0x200, "CKR_FUNCTION_REJECTED"),
            (0x202, "CKR_OPERATION_CANCEL_FAILED"),
        ] {
            assert_eq!(ckr_name(rv).to_string(), name);
        }
    }

    #[test]
    fn vendor_and_unknown_codes() {
        assert_eq!(ckr_name(0x8000_0000).to_string(), "CKR_VENDOR_DEFINED+0x0");
        assert_eq!(
            ckr_name(0x8000_1234).to_string(),
            "CKR_VENDOR_DEFINED+0x1234"
        );
        assert_eq!(ckr_name(0x4).to_string(), "CKR_UNKNOWN_0x00000004");
    }

    #[test]
    fn names_are_json_safe() {
        for &(_, n) in CKR_NAMES {
            assert!(n
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'));
        }
    }
}
