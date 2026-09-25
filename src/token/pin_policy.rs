// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
#![forbid(unsafe_code)]
//! PIN complexity policy enforced by the core for **every** front end
//! (`C_InitToken`, `C_InitPIN`, `C_SetPIN`, the gRPC daemon and the admin
//! CLI), so that no interface accepts weaker PINs than another (H5-12).
//!
//! A new PIN must:
//!
//! 1. be between the configured `pin_min_length` and `pin_max_length`
//!    bytes long (the configuration floor is 8) → `CKR_PIN_LEN_RANGE`;
//! 2. contain at least [`MIN_DISTINCT`] distinct characters (bytes for
//!    non-text PINs) → `CKR_PIN_INVALID`;
//! 3. for ASCII text PINs, use at least [`MIN_CHAR_CLASSES`] of the classes
//!    lower case / upper case / digit / other → `CKR_PIN_INVALID`;
//! 4. not be a repetition of a shorter unit (`aaaaaaaa`, `12121212`,
//!    `abcabcabc`) → `CKR_PIN_INVALID`;
//! 5. not be a strictly ascending or descending run (`12345678`, `hgfedcba`)
//!    → `CKR_PIN_INVALID`;
//! 6. not be (case-insensitively) one of the [`DENYLIST`] entries, nor
//!    contain the word `password` → `CKR_PIN_INVALID`.
//!
//! The policy applies only when a PIN is **set**; login attempts with any
//! PIN are verified normally (so existing PINs keep working).

use crate::error::{HsmError, HsmResult};

/// Minimum number of distinct characters (or bytes) in a new PIN.
pub const MIN_DISTINCT: usize = 4;
/// Minimum number of character classes for ASCII text PINs.
pub const MIN_CHAR_CLASSES: usize = 2;

/// Commonly used PINs/passwords (compared lower-case). Includes the PINs that
/// were published as examples in earlier documentation and deployment
/// samples (A3-01/H4-05), which must be treated as compromised.
pub const DENYLIST: &[&str] = &[
    "00000000",
    "11111111",
    "12341234",
    "12344321",
    "11223344",
    "12121212",
    "123123123",
    "12345678",
    "123456789",
    "1234567890",
    "87654321",
    "98765432",
    "01234567",
    "1q2w3e4r",
    "1qaz2wsx",
    "zaq12wsx",
    "qwertyui",
    "qwertyuiop",
    "qwerty12",
    "qwerty123",
    "asdfghjk",
    "asdfasdf",
    "zxcvbnm1",
    "abcd1234",
    "abc12345",
    "abcdefgh",
    "password",
    "password1",
    "passw0rd",
    "p@ssw0rd",
    "p@ssword",
    "letmein1",
    "iloveyou",
    "admin123",
    "administrator",
    "changeme",
    "changeit",
    "welcome1",
    "trustno1",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "superman",
    "monkey12",
    "security",
    "secret12",
    "default1",
    "test1234",
    "testtest",
    "cratonhsm",
    "hsmadmin",
    "sopin123",
    "userpin1",
    "pkcs11pin",
];

/// Validate a new PIN against the configured length bounds and the
/// complexity rules above.
pub fn validate_new_pin(pin: &[u8], min_len: usize, max_len: usize) -> HsmResult<()> {
    if pin.len() < min_len || pin.len() > max_len {
        return Err(HsmError::PinLenRange);
    }
    check_complexity(pin).map_err(|reason| {
        tracing::debug!("new PIN rejected: {}", reason);
        HsmError::PinInvalid
    })
}

/// Complexity rules 2–6 (length is checked separately). Returns a
/// human-readable reason on failure (never containing the PIN).
pub fn check_complexity(pin: &[u8]) -> Result<(), &'static str> {
    // Work on characters for UTF-8 text, on bytes otherwise.
    let units: Vec<u32> = match std::str::from_utf8(pin) {
        Ok(s) => s.chars().map(|c| c as u32).collect(),
        Err(_) => pin.iter().map(|&b| u32::from(b)).collect(),
    };
    let n = units.len();

    let mut distinct = units.clone();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < MIN_DISTINCT {
        return Err("PIN must contain at least 4 distinct characters");
    }

    if pin.is_ascii() {
        let mut classes = [false; 4];
        for &b in pin {
            let idx = match b {
                b'a'..=b'z' => 0,
                b'A'..=b'Z' => 1,
                b'0'..=b'9' => 2,
                _ => 3,
            };
            classes[idx] = true;
        }
        if classes.iter().filter(|&&c| c).count() < MIN_CHAR_CLASSES {
            return Err("PIN must mix at least two character classes");
        }
    }

    // A short unit repeated, e.g. "abababab", "abcabcabc".
    if n > 1
        && (1..=n / 2)
            .any(|unit| n % unit == 0 && units.chunks(unit).all(|c| c == &units[..unit]))
    {
        return Err("PIN must not be a repeated character or pattern");
    }

    // Strictly ascending / descending runs.
    if n >= 4 {
        let asc = units.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
        let desc = units.windows(2).all(|w| w[0] == w[1].wrapping_add(1));
        if asc || desc {
            return Err("PIN must not be a sequential pattern");
        }
    }

    if let Ok(s) = std::str::from_utf8(pin) {
        let lower = s.to_lowercase();
        if DENYLIST.contains(&lower.as_str()) || lower.contains("password") {
            return Err("PIN is a commonly used value");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_weak_pins() {
        for weak in [
            "aaaaaaaa",
            "12345678",
            "87654321",
            "abcdefgh",
            "12121212",
            "abababab",
            "password",
            "MyPassword99",
            "qwertyui",
            "1q2w3e4r",
            "aabbaabb",
            "sopin123",
            "userpin1",
            "USERPIN1",
            "abcabcabc",
        ] {
            assert!(
                validate_new_pin(weak.as_bytes(), 8, 64).is_err(),
                "{weak} accepted"
            );
        }
    }

    #[test]
    fn accepts_reasonable_pins() {
        for ok in [
            "7391-2846",
            "Tr0ub4dor&3",
            "correct horse battery",
            "59g!Kx2q",
            "S0pin-47",
            "Us3rpin9",
        ] {
            assert!(validate_new_pin(ok.as_bytes(), 8, 64).is_ok(), "{ok} rejected");
        }
    }

    #[test]
    fn length_bounds() {
        assert!(matches!(
            validate_new_pin(b"7k2!", 8, 64),
            Err(HsmError::PinLenRange)
        ));
        assert!(matches!(
            validate_new_pin(b"7k2!9x5qz", 4, 8),
            Err(HsmError::PinLenRange)
        ));
    }

    #[test]
    fn binary_pins_need_distinct_bytes() {
        assert!(validate_new_pin(&[0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe], 8, 64).is_err());
        assert!(validate_new_pin(&[0xff, 0x10, 0x80, 0x33, 0x91, 0x07, 0xc4, 0x5a], 8, 64).is_ok());
    }
}
