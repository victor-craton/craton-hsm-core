// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::*;
use crate::store::key_material::RawKeyMaterial;

/// Key lifecycle state per SP 800-57 Part 1.
///
/// Controls which cryptographic operations are permitted on a key:
/// - **PreActivation**: Key created but not yet at its `start_date`. No operations permitted.
/// - **Active**: Normal use — all permitted operations allowed.
/// - **Deactivated**: Past `end_date` — can verify/decrypt but cannot sign/encrypt.
/// - **Compromised**: Manually marked — blocked from all operations.
/// - **Destroyed**: Pending physical deletion — handle is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyLifecycleState {
    PreActivation,
    Active,
    Deactivated,
    Compromised,
    Destroyed,
}

impl Default for KeyLifecycleState {
    fn default() -> Self {
        KeyLifecycleState::Active
    }
}

/// Serde default helper for boolean fields that default to true.
fn default_true() -> bool {
    true
}

/// Internal representation of a PKCS#11 object stored in the token.
/// Serializable for persistence to the encrypted store.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredObject {
    pub handle: CK_OBJECT_HANDLE,
    /// Slot that owns this object. Used for slot-scoped isolation in multi-slot
    /// deployments — objects created on one slot are not visible from another.
    #[serde(default)]
    pub slot_id: CK_ULONG,
    pub class: CK_OBJECT_CLASS,
    pub key_type: Option<CK_KEY_TYPE>,
    pub label: Vec<u8>,
    pub id: Vec<u8>,
    pub token_object: bool,
    pub private: bool,
    pub sensitive: bool,
    pub extractable: bool,
    pub modifiable: bool,
    pub destroyable: bool,
    /// PKCS#11 CKA_COPYABLE: whether C_CopyObject is allowed on this object
    #[serde(default = "default_true")]
    pub copyable: bool,
    /// Permission attributes
    pub can_encrypt: bool,
    pub can_decrypt: bool,
    pub can_sign: bool,
    pub can_verify: bool,
    pub can_wrap: bool,
    pub can_unwrap: bool,
    pub can_derive: bool,
    /// Key material (only for key objects)
    pub key_material: Option<RawKeyMaterial>,
    /// Public key data (for asymmetric keys)
    pub public_key_data: Option<Vec<u8>>,
    /// RSA specific
    pub modulus: Option<Vec<u8>>,
    pub modulus_bits: Option<CK_ULONG>,
    pub public_exponent: Option<Vec<u8>>,
    /// EC specific
    pub ec_params: Option<Vec<u8>>,
    pub ec_point: Option<Vec<u8>>,
    /// AES specific
    pub value_len: Option<CK_ULONG>,
    /// Arbitrary additional attributes
    pub extra_attributes: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,

    // ========================================================================
    // Key lifecycle fields (SP 800-57)
    // ========================================================================
    /// CKA_START_DATE: PKCS#11 CK_DATE format (YYYYMMDD, 8 ASCII bytes)
    /// Key is pre-activation before this date.
    #[serde(default)]
    pub start_date: Option<[u8; 8]>,

    /// CKA_END_DATE: PKCS#11 CK_DATE format (YYYYMMDD, 8 ASCII bytes)
    /// Key is deactivated after this date.
    #[serde(default)]
    pub end_date: Option<[u8; 8]>,

    /// SP 800-57 lifecycle state
    #[serde(default)]
    pub lifecycle_state: KeyLifecycleState,

    /// Creation time (Unix epoch seconds)
    #[serde(default)]
    pub creation_time: u64,

    // ========================================================================
    // Token-computed / policy attributes (H1-09, H3-05). These are typed
    // fields rather than `extra_attributes` entries so that policy checks read
    // an authoritative value that callers cannot self-assert.
    // ========================================================================
    /// CKA_TRUSTED — may only be set to TRUE by the Security Officer.
    #[serde(default)]
    pub trusted: bool,
    /// CKA_WRAP_WITH_TRUSTED — key may only be wrapped by a trusted key.
    /// One-way: FALSE → TRUE only.
    #[serde(default)]
    pub wrap_with_trusted: bool,
    /// CKA_LOCAL — key was generated on this token (computed, read-only).
    #[serde(default)]
    pub local: bool,
    /// CKA_ALWAYS_SENSITIVE — key has always had CKA_SENSITIVE=TRUE (computed).
    #[serde(default)]
    pub always_sensitive: bool,
    /// CKA_NEVER_EXTRACTABLE — key has never had CKA_EXTRACTABLE=TRUE (computed).
    #[serde(default)]
    pub never_extractable: bool,
    /// CKA_KEY_GEN_MECHANISM — mechanism used to generate the key (computed).
    #[serde(default)]
    pub key_gen_mechanism: Option<CK_MECHANISM_TYPE>,
    /// Private-key components supplied as separate attributes
    /// (CKA_PRIVATE_EXPONENT, CKA_PRIME_1/2, CKA_EXPONENT_1/2,
    /// CKA_COEFFICIENT). Held in mlocked, zeroize-on-drop buffers and subject
    /// to the same sensitivity policy as CKA_VALUE (H3-02).
    #[serde(default)]
    pub sensitive_attributes: HashMap<CK_ATTRIBUTE_TYPE, RawKeyMaterial>,
    /// Session that owns a session object (`CKA_TOKEN=FALSE`). Session objects
    /// are destroyed when this session closes (H3-07). Never persisted.
    #[serde(skip)]
    pub owner_session: Option<CK_SESSION_HANDLE>,
}

/// Private-key component attributes that must never be revealed in plaintext
/// when the object is sensitive or non-extractable.
pub const SENSITIVE_COMPONENT_ATTRIBUTES: &[CK_ATTRIBUTE_TYPE] = &[
    CKA_PRIVATE_EXPONENT,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_COEFFICIENT,
];

/// Returns true for object classes whose value is secret key material.
pub fn is_secret_class(class: CK_OBJECT_CLASS) -> bool {
    class == CKO_SECRET_KEY || class == CKO_PRIVATE_KEY
}

/// Key usage requested of an object — replaces stringly-typed operation names
/// in lifecycle checks (H3-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Wrap,
    Unwrap,
    Derive,
}

impl KeyUsage {
    /// Operations that only *process* existing protected data and are
    /// therefore still allowed for a deactivated key (SP 800-57).
    fn allowed_when_deactivated(self) -> bool {
        matches!(
            self,
            KeyUsage::Verify | KeyUsage::Decrypt | KeyUsage::Unwrap
        )
    }

    /// Parse the legacy string names used by older call sites.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "encrypt" => KeyUsage::Encrypt,
            "decrypt" => KeyUsage::Decrypt,
            "sign" => KeyUsage::Sign,
            "verify" => KeyUsage::Verify,
            "wrap" => KeyUsage::Wrap,
            "unwrap" => KeyUsage::Unwrap,
            "derive" => KeyUsage::Derive,
            _ => return None,
        })
    }
}

impl StoredObject {
    /// Create an object with PKCS#11 per-class defaults.
    ///
    /// Secret and private keys default to the secure profile
    /// (`CKA_SENSITIVE=TRUE`, `CKA_EXTRACTABLE=FALSE`); other classes (data,
    /// certificates, public keys) carry no secret and default to
    /// `CKA_SENSITIVE=FALSE`, `CKA_EXTRACTABLE=TRUE`.
    pub fn new(handle: CK_OBJECT_HANDLE, class: CK_OBJECT_CLASS) -> Self {
        let secret = is_secret_class(class);
        Self {
            handle,
            slot_id: 0,
            class,
            key_type: None,
            label: Vec::new(),
            id: Vec::new(),
            token_object: false,
            private: true,
            sensitive: secret,
            extractable: !secret,
            modifiable: true,
            destroyable: true,
            copyable: true,
            can_encrypt: false,
            can_decrypt: false,
            can_sign: false,
            can_verify: false,
            can_wrap: false,
            can_unwrap: false,
            can_derive: false,
            key_material: None,
            public_key_data: None,
            modulus: None,
            modulus_bits: None,
            public_exponent: None,
            ec_params: None,
            ec_point: None,
            value_len: None,
            extra_attributes: HashMap::new(),
            start_date: None,
            end_date: None,
            lifecycle_state: KeyLifecycleState::Active,
            creation_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            trusted: false,
            wrap_with_trusted: false,
            local: false,
            always_sensitive: false,
            never_extractable: false,
            key_gen_mechanism: None,
            sensitive_attributes: HashMap::new(),
            owner_session: None,
        }
    }

    /// Mark the object destroyed and zeroize its secret material so that any
    /// operation still holding a cached `Arc` to it fails (H3-20).
    pub fn mark_destroyed(&mut self) {
        self.lifecycle_state = KeyLifecycleState::Destroyed;
        self.key_material = None; // RawKeyMaterial::drop zeroizes
        self.sensitive_attributes.clear();
        self.can_encrypt = false;
        self.can_decrypt = false;
        self.can_sign = false;
        self.can_verify = false;
        self.can_wrap = false;
        self.can_unwrap = false;
        self.can_derive = false;
    }

    /// Check if a template matches this object (partial template matching per PKCS#11).
    ///
    /// Uses a bitwise u8 accumulator instead of early returns or boolean
    /// short-circuit to avoid leaking information about which attribute
    /// caused a mismatch via timing side-channels. All template attributes
    /// are always evaluated regardless of whether earlier attributes already
    /// failed to match. Variable-length comparisons (labels, IDs) use
    /// constant-time equality from the `subtle` crate.
    pub fn matches_template(&self, template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        // Matching and reading use a single source of truth (H3-28): every
        // template attribute is compared against the value that
        // `read_attribute` would return. Sensitive attributes never match.
        // Use u8 accumulator with bitwise AND to prevent boolean short-circuit
        let mut matched: u8 = 1;
        for (attr_type, value) in template {
            let attr_match: u8 = match crate::store::attributes::read_attribute(self, *attr_type) {
                Ok(Some(stored)) => ct_bytes_eq(&stored, value),
                _ => 0,
            };
            // Bitwise AND avoids boolean short-circuit optimization
            matched &= attr_match;
        }
        matched == 1
    }

    /// Get the approximate size of this object in bytes.
    /// Saturates to `CK_ULONG::MAX` on overflow instead of truncating.
    pub fn approximate_size(&self) -> CK_ULONG {
        let mut size: usize = std::mem::size_of::<StoredObject>();
        if let Some(ref km) = self.key_material {
            size = size.saturating_add(km.len());
        }
        if let Some(ref pk) = self.public_key_data {
            size = size.saturating_add(pk.len());
        }
        if let Some(ref m) = self.modulus {
            size = size.saturating_add(m.len());
        }
        size = size.saturating_add(self.label.len());
        size = size.saturating_add(self.id.len());
        for v in self.extra_attributes.values() {
            size = size.saturating_add(v.len());
        }
        for v in self.sensitive_attributes.values() {
            size = size.saturating_add(v.len());
        }
        if let Some(ref v) = self.public_exponent {
            size = size.saturating_add(v.len());
        }
        if let Some(ref v) = self.ec_params {
            size = size.saturating_add(v.len());
        }
        if let Some(ref v) = self.ec_point {
            size = size.saturating_add(v.len());
        }
        CK_ULONG::try_from(size).unwrap_or(CK_ULONG::MAX)
    }
}

/// Custom Debug: never log key material
impl fmt::Debug for StoredObject {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("StoredObject")
            .field("handle", &self.handle)
            .field("class", &self.class)
            .field("key_type", &self.key_type)
            .field("label_len", &self.label.len())
            .field("sensitive", &self.sensitive)
            .field("extractable", &self.extractable)
            .field("lifecycle_state", &self.lifecycle_state)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl StoredObject {
    /// Check whether the given operation type is permitted by this key's
    /// lifecycle state (SP 800-57).
    ///
    /// Returns `Ok(())` if the operation is allowed, or an appropriate error.
    ///
    /// Rules:
    /// - **Active**: all operations permitted
    /// - **PreActivation**: no operations permitted
    /// - **Deactivated**: verify/decrypt/unwrap allowed; sign/encrypt/wrap blocked
    /// - **Compromised**: all operations blocked
    /// - **Destroyed**: key handle is invalid
    pub fn check_lifecycle(&self, operation: &str) -> Result<(), crate::error::HsmError> {
        // Unknown operation names are a programming error: deny (fail closed)
        // instead of silently applying the wrong policy.
        let usage = KeyUsage::from_name(operation)
            .ok_or(crate::error::HsmError::KeyFunctionNotPermitted)?;
        self.check_usage(usage)
    }

    /// Typed lifecycle check (SP 800-57) for a key usage. Returns
    /// `KeyFunctionNotPermitted` when the lifecycle state forbids the usage and
    /// `ObjectHandleInvalid` for destroyed objects.
    pub fn check_usage(&self, usage: KeyUsage) -> Result<(), crate::error::HsmError> {
        use crate::error::HsmError;
        match self.effective_lifecycle_state() {
            KeyLifecycleState::Active => Ok(()),
            KeyLifecycleState::PreActivation => Err(HsmError::KeyFunctionNotPermitted),
            KeyLifecycleState::Deactivated if usage.allowed_when_deactivated() => Ok(()),
            KeyLifecycleState::Deactivated => Err(HsmError::KeyFunctionNotPermitted),
            KeyLifecycleState::Compromised => Err(HsmError::KeyFunctionNotPermitted),
            KeyLifecycleState::Destroyed => Err(HsmError::ObjectHandleInvalid),
        }
    }

    /// Compute the effective lifecycle state, taking date fields into account.
    ///
    /// If the explicit lifecycle_state is Active, check dates:
    /// - If start_date is set and in the future → PreActivation
    /// - If end_date is set and in the past → Deactivated
    /// Otherwise returns the explicit lifecycle_state.
    pub fn effective_lifecycle_state(&self) -> KeyLifecycleState {
        if self.lifecycle_state != KeyLifecycleState::Active {
            return self.lifecycle_state;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check start_date (YYYYMMDD ASCII)
        if let Some(start) = &self.start_date {
            if let Some(start_epoch) = ck_date_to_epoch(start) {
                if now < start_epoch {
                    return KeyLifecycleState::PreActivation;
                }
            }
        }

        // Check end_date (YYYYMMDD ASCII)
        if let Some(end) = &self.end_date {
            if let Some(end_epoch) = ck_date_to_epoch(end) {
                if now > end_epoch {
                    return KeyLifecycleState::Deactivated;
                }
            }
        }

        KeyLifecycleState::Active
    }
}

/// Convert a CK_DATE (YYYYMMDD, 8 ASCII bytes) to a Unix epoch timestamp.
/// Returns the epoch for midnight UTC of the given date.
///
/// Uses a constant-time formula (no loops) to compute days since epoch.
fn ck_date_to_epoch(date: &[u8; 8]) -> Option<u64> {
    let s = std::str::from_utf8(date).ok()?;
    let year: u64 = s[0..4].parse().ok()?;
    let month: u64 = s[4..6].parse().ok()?;
    let day: u64 = s[6..8].parse().ok()?;

    if !is_valid_ck_date(date) {
        return None;
    }

    // Count leap years from 1970 to year-1 using closed-form formula
    let leap_years_before = |y: u64| -> u64 {
        if y == 0 {
            return 0;
        }
        let y = y - 1;
        y / 4 - y / 100 + y / 400
    };
    let leaps = leap_years_before(year) - leap_years_before(1970);
    let years_elapsed = year - 1970;
    let mut days = years_elapsed * 365 + leaps;

    // Cumulative days before each month (non-leap year)
    const CUMULATIVE_DAYS: [u64; 13] = [0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    days += CUMULATIVE_DAYS[month as usize];
    // Add leap day if past February in a leap year
    if month > 2 && is_leap_year(year) {
        days += 1;
    }
    days += day - 1;

    Some(days * 86400)
}

/// Strictly validate a CK_DATE (`YYYYMMDD`, ASCII digits, real calendar
/// date between 1970 and 2200). Rejects e.g. `20250231` (H3-23).
pub fn is_valid_ck_date(date: &[u8]) -> bool {
    if date.len() != 8 || !date.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> u64 {
        date[r]
            .iter()
            .fold(0u64, |acc, b| acc * 10 + u64::from(b - b'0'))
    };
    let (year, month, day) = (num(0..4), num(4..6), num(6..8));
    if !(1970..=2200).contains(&year) || !(1..=12).contains(&month) || day < 1 {
        return false;
    }
    const DAYS: [u64; 13] = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let max = if month == 2 && is_leap_year(year) {
        29
    } else {
        DAYS[month as usize]
    };
    day <= max
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Constant-time byte slice equality comparison.
/// Returns 1 if equal, 0 if not. If lengths differ, returns 0 immediately
/// (length difference is not considered secret in PKCS#11 template matching).
fn ct_bytes_eq(a: &[u8], b: &[u8]) -> u8 {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return 0;
    }
    a.ct_eq(b).unwrap_u8()
}
