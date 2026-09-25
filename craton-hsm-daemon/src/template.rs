// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Caller-template validation for key generation (H4-06 / A3-02).
//!
//! The daemon never passes caller templates to the generic
//! `apply_attribute`. Instead each key kind has an explicit allow-list of
//! attributes a caller may set, security-critical attributes can only move
//! in the safe direction (sensitive → true, extractable → false, ...),
//! variable-length values are bounded, and provenance attributes
//! (`CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE`,
//! `CKA_KEY_GEN_MECHANISM`) are set by the daemon itself.

use std::collections::HashSet;

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::types::CK_ULONG;
use craton_hsm::store::object::StoredObject;
use tonic::Status;

use crate::proto::Attribute;

/// Maximum number of entries in any template (H4-07).
pub const MAX_TEMPLATE_ATTRS: usize = 32;
/// Maximum length of CKA_LABEL / CKA_ID (H4-06).
pub const MAX_LABEL_LEN: usize = 256;
/// Maximum length of any value in a search template.
pub const MAX_SEARCH_VALUE_LEN: usize = 1024;

/// Attributes a caller may never supply when generating a key: they are
/// either derived from the mechanism / generated key material or describe
/// provenance that must be set by the HSM itself.
pub const FORBIDDEN_TEMPLATE_ATTRS: &[CK_ULONG] = &[
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_VALUE,
    CKA_MODULUS,
    CKA_PRIVATE_EXPONENT,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_COEFFICIENT,
    CKA_EC_POINT,
    CKA_LOCAL,
    CKA_KEY_GEN_MECHANISM,
    CKA_ALWAYS_SENSITIVE,
    CKA_NEVER_EXTRACTABLE,
    CKA_TRUSTED,
    CKA_WRAP_WITH_TRUSTED,
];

/// Kind of object being generated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    AesSecret,
    RsaPublic,
    RsaPrivate,
    EcPublic,
    EcPrivate,
    EdPublic,
    EdPrivate,
}

impl KeyKind {
    fn is_public(self) -> bool {
        matches!(
            self,
            KeyKind::RsaPublic | KeyKind::EcPublic | KeyKind::EdPublic
        )
    }

    /// Usage flags that are meaningful for this kind.
    fn usage_allowed(self, attr: CK_ULONG) -> bool {
        match self {
            KeyKind::AesSecret => matches!(attr, CKA_ENCRYPT | CKA_DECRYPT | CKA_WRAP | CKA_UNWRAP),
            KeyKind::RsaPublic => matches!(attr, CKA_VERIFY | CKA_ENCRYPT),
            KeyKind::RsaPrivate => matches!(attr, CKA_SIGN | CKA_DECRYPT),
            KeyKind::EcPublic | KeyKind::EdPublic => attr == CKA_VERIFY,
            KeyKind::EcPrivate | KeyKind::EdPrivate => attr == CKA_SIGN,
        }
    }

    /// Generation parameters accepted in the template of this kind.
    fn param_allowed(self, attr: CK_ULONG) -> bool {
        match self {
            KeyKind::AesSecret => attr == CKA_VALUE_LEN,
            KeyKind::RsaPublic => matches!(attr, CKA_MODULUS_BITS | CKA_PUBLIC_EXPONENT),
            KeyKind::EcPublic | KeyKind::EdPublic => attr == CKA_EC_PARAMS,
            _ => false,
        }
    }
}

/// A validated caller template.
#[derive(Debug, Default)]
pub struct KeyTemplate {
    pub label: Option<Vec<u8>>,
    pub id: Option<Vec<u8>>,
    pub token: Option<bool>,
    pub private: Option<bool>,
    pub sensitive: Option<bool>,
    pub extractable: Option<bool>,
    pub modifiable: Option<bool>,
    pub start_date: Option<Option<[u8; 8]>>,
    pub end_date: Option<Option<[u8; 8]>>,
    /// (attribute, value) usage flags.
    pub usage: Vec<(CK_ULONG, bool)>,
    pub value_len: Option<CK_ULONG>,
    pub modulus_bits: Option<CK_ULONG>,
    pub ec_params: Option<Vec<u8>>,
}

fn inconsistent(msg: String) -> Status {
    Status::invalid_argument(format!("Template is inconsistent: {}", msg))
}

fn parse_bool(attr: CK_ULONG, v: &[u8]) -> Result<bool, Status> {
    match v {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(inconsistent(format!(
            "attribute 0x{:X} must be a one-byte CK_BBOOL",
            attr
        ))),
    }
}

fn parse_ulong(attr: CK_ULONG, v: &[u8]) -> Result<CK_ULONG, Status> {
    if v.len() != std::mem::size_of::<CK_ULONG>() {
        return Err(inconsistent(format!(
            "attribute 0x{:X} must be a {}-byte CK_ULONG",
            attr,
            std::mem::size_of::<CK_ULONG>()
        )));
    }
    craton_hsm::store::attributes::read_ck_ulong(v)
        .ok_or_else(|| inconsistent(format!("attribute 0x{:X} is malformed", attr)))
}

fn parse_date(attr: CK_ULONG, v: &[u8]) -> Result<Option<[u8; 8]>, Status> {
    match v.len() {
        0 => Ok(None),
        8 if v.iter().all(u8::is_ascii_digit) => {
            let mut d = [0u8; 8];
            d.copy_from_slice(v);
            Ok(Some(d))
        }
        _ => Err(inconsistent(format!(
            "attribute 0x{:X} must be an 8-digit CK_DATE",
            attr
        ))),
    }
}

/// Convert protobuf attributes to (type, value) pairs, bounding the count
/// and each value length.
pub fn proto_attrs_to_template(
    attrs: &[Attribute],
    max_value_len: usize,
) -> Result<Vec<(CK_ULONG, Vec<u8>)>, Status> {
    if attrs.len() > MAX_TEMPLATE_ATTRS {
        return Err(Status::invalid_argument(format!(
            "Template has {} attributes; at most {} are allowed",
            attrs.len(),
            MAX_TEMPLATE_ATTRS
        )));
    }
    attrs
        .iter()
        .map(|a| {
            let attr_type: CK_ULONG = a.attr_type.try_into().map_err(|_| {
                Status::invalid_argument(format!(
                    "attribute type 0x{:016X} exceeds platform maximum",
                    a.attr_type
                ))
            })?;
            if a.value.len() > max_value_len {
                return Err(Status::invalid_argument(format!(
                    "attribute 0x{:X} value too long ({} bytes, max {})",
                    attr_type,
                    a.value.len(),
                    max_value_len
                )));
            }
            Ok((attr_type, a.value.clone()))
        })
        .collect()
}

/// Validate a caller template for key generation of `kind`.
pub fn validate(kind: KeyKind, template: &[(CK_ULONG, Vec<u8>)]) -> Result<KeyTemplate, Status> {
    if template.len() > MAX_TEMPLATE_ATTRS {
        return Err(inconsistent("too many attributes".into()));
    }
    let mut seen = HashSet::new();
    let mut t = KeyTemplate::default();
    for (attr, v) in template {
        let attr = *attr;
        if !seen.insert(attr) {
            return Err(inconsistent(format!("duplicate attribute 0x{:X}", attr)));
        }
        if FORBIDDEN_TEMPLATE_ATTRS.contains(&attr) {
            return Err(inconsistent(format!(
                "attribute 0x{:X} is set by the HSM and may not be supplied",
                attr
            )));
        }
        match attr {
            CKA_LABEL | CKA_ID => {
                if v.len() > MAX_LABEL_LEN {
                    return Err(inconsistent(format!(
                        "attribute 0x{:X} exceeds {} bytes",
                        attr, MAX_LABEL_LEN
                    )));
                }
                if attr == CKA_LABEL {
                    t.label = Some(v.clone());
                } else {
                    t.id = Some(v.clone());
                }
            }
            CKA_TOKEN => t.token = Some(parse_bool(attr, v)?),
            CKA_PRIVATE => {
                let b = parse_bool(attr, v)?;
                // Secret and private keys stay private; public keys may be
                // made readable without login.
                if !b && !kind.is_public() {
                    return Err(inconsistent(
                        "CKA_PRIVATE=false on a secret/private key".into(),
                    ));
                }
                t.private = Some(b);
            }
            CKA_SENSITIVE if !kind.is_public() => {
                if !parse_bool(attr, v)? {
                    return Err(inconsistent("CKA_SENSITIVE may only be true".into()));
                }
                t.sensitive = Some(true);
            }
            CKA_EXTRACTABLE if !kind.is_public() => {
                if parse_bool(attr, v)? {
                    return Err(inconsistent("CKA_EXTRACTABLE may only be false".into()));
                }
                t.extractable = Some(false);
            }
            CKA_MODIFIABLE => t.modifiable = Some(parse_bool(attr, v)?),
            CKA_DESTROYABLE => {
                // A non-destroyable object could never be cleaned up.
                if !parse_bool(attr, v)? {
                    return Err(inconsistent(
                        "CKA_DESTROYABLE=false is not permitted".into(),
                    ));
                }
            }
            CKA_START_DATE => t.start_date = Some(parse_date(attr, v)?),
            CKA_END_DATE => t.end_date = Some(parse_date(attr, v)?),
            a if kind.usage_allowed(a) => t.usage.push((a, parse_bool(a, v)?)),
            CKA_VALUE_LEN if kind.param_allowed(attr) => t.value_len = Some(parse_ulong(attr, v)?),
            CKA_MODULUS_BITS if kind.param_allowed(attr) => {
                t.modulus_bits = Some(parse_ulong(attr, v)?)
            }
            CKA_PUBLIC_EXPONENT if kind.param_allowed(attr) => {
                // The generator always uses F4 (65537); accept only that.
                let trimmed: &[u8] = {
                    let start = v.iter().position(|b| *b != 0).unwrap_or(v.len());
                    &v[start..]
                };
                if trimmed != [0x01, 0x00, 0x01] {
                    return Err(inconsistent(
                        "only CKA_PUBLIC_EXPONENT 65537 is supported".into(),
                    ));
                }
            }
            CKA_EC_PARAMS if kind.param_allowed(attr) => {
                if v.len() > 64 {
                    return Err(inconsistent("CKA_EC_PARAMS too long".into()));
                }
                t.ec_params = Some(v.clone());
            }
            other => {
                return Err(inconsistent(format!(
                    "attribute 0x{:X} is not permitted for this key type",
                    other
                )));
            }
        }
    }
    if let (Some(Some(s)), Some(Some(e))) = (t.start_date, t.end_date) {
        if s > e {
            return Err(inconsistent("CKA_START_DATE is after CKA_END_DATE".into()));
        }
    }
    Ok(t)
}

impl KeyTemplate {
    /// Apply the validated caller choices to a freshly generated object.
    pub fn apply(&self, obj: &mut StoredObject) {
        if let Some(l) = &self.label {
            obj.label = l.clone();
        }
        if let Some(i) = &self.id {
            obj.id = i.clone();
        }
        if let Some(b) = self.token {
            obj.token_object = b;
        }
        if let Some(b) = self.private {
            obj.private = b;
        }
        if let Some(b) = self.sensitive {
            obj.sensitive = b;
        }
        if let Some(b) = self.extractable {
            obj.extractable = b;
        }
        if let Some(b) = self.modifiable {
            obj.modifiable = b;
        }
        if let Some(d) = self.start_date {
            obj.start_date = d;
        }
        if let Some(d) = self.end_date {
            obj.end_date = d;
        }
        for (attr, b) in &self.usage {
            match *attr {
                CKA_ENCRYPT => obj.can_encrypt = *b,
                CKA_DECRYPT => obj.can_decrypt = *b,
                CKA_WRAP => obj.can_wrap = *b,
                CKA_UNWRAP => obj.can_unwrap = *b,
                CKA_SIGN => obj.can_sign = *b,
                CKA_VERIFY => obj.can_verify = *b,
                _ => {}
            }
        }
    }

    pub fn is_token_object(&self) -> bool {
        self.token.unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ul(v: CK_ULONG) -> Vec<u8> {
        v.to_ne_bytes().to_vec()
    }

    #[test]
    fn forbidden_attributes_are_rejected_for_every_kind() {
        for kind in [
            KeyKind::AesSecret,
            KeyKind::RsaPublic,
            KeyKind::RsaPrivate,
            KeyKind::EcPublic,
            KeyKind::EcPrivate,
            KeyKind::EdPublic,
            KeyKind::EdPrivate,
        ] {
            for attr in FORBIDDEN_TEMPLATE_ATTRS {
                let err = validate(kind, &[(*attr, vec![1u8; 8])]).unwrap_err();
                assert_eq!(
                    err.code(),
                    tonic::Code::InvalidArgument,
                    "{:?} {:X}",
                    kind,
                    attr
                );
            }
        }
    }

    #[test]
    fn one_way_attributes_only_move_in_safe_direction() {
        assert!(validate(KeyKind::AesSecret, &[(CKA_SENSITIVE, vec![0])]).is_err());
        assert!(validate(KeyKind::AesSecret, &[(CKA_EXTRACTABLE, vec![1])]).is_err());
        assert!(validate(KeyKind::AesSecret, &[(CKA_PRIVATE, vec![0])]).is_err());
        assert!(validate(KeyKind::AesSecret, &[(CKA_DESTROYABLE, vec![0])]).is_err());
        assert!(validate(KeyKind::AesSecret, &[(CKA_SENSITIVE, vec![1])]).is_ok());
        assert!(validate(KeyKind::RsaPublic, &[(CKA_PRIVATE, vec![0])]).is_ok());
    }

    #[test]
    fn usage_flags_must_match_key_type() {
        assert!(validate(KeyKind::AesSecret, &[(CKA_SIGN, vec![1])]).is_err());
        assert!(validate(KeyKind::EcPrivate, &[(CKA_DECRYPT, vec![1])]).is_err());
        assert!(validate(KeyKind::EcPrivate, &[(CKA_DERIVE, vec![1])]).is_err());
        assert!(validate(KeyKind::RsaPrivate, &[(CKA_DECRYPT, vec![1])]).is_ok());
    }

    #[test]
    fn sizes_duplicates_and_unknown_attributes_are_bounded() {
        assert!(validate(KeyKind::AesSecret, &[(CKA_LABEL, vec![b'a'; 257])]).is_err());
        assert!(validate(
            KeyKind::AesSecret,
            &[(CKA_LABEL, b"a".to_vec()), (CKA_LABEL, b"b".to_vec())]
        )
        .is_err());
        assert!(validate(KeyKind::AesSecret, &[(0x8000_1234, vec![0])]).is_err());
        let many: Vec<Attribute> = (0..33)
            .map(|i| Attribute {
                attr_type: i,
                value: vec![],
            })
            .collect();
        assert!(proto_attrs_to_template(&many, 16).is_err());
    }

    #[test]
    fn generation_parameters_are_parsed() {
        let t = validate(
            KeyKind::AesSecret,
            &[(CKA_VALUE_LEN, ul(32)), (CKA_TOKEN, vec![1])],
        )
        .unwrap();
        assert_eq!(t.value_len, Some(32));
        assert!(t.is_token_object());
        assert!(validate(KeyKind::AesSecret, &[(CKA_VALUE_LEN, vec![32, 0, 0, 0])]).is_err());
        assert!(validate(KeyKind::RsaPublic, &[(CKA_PUBLIC_EXPONENT, vec![1, 0, 1])]).is_ok());
        assert!(validate(KeyKind::RsaPublic, &[(CKA_PUBLIC_EXPONENT, vec![3])]).is_err());
    }

    #[test]
    fn provenance_is_set_by_the_store() {
        use craton_hsm::store::attributes::{
            read_attribute, ObjectContext, ObjectOrigin, ObjectStore,
        };
        let store = ObjectStore::new();
        let mut obj = StoredObject::new(store.next_handle().unwrap(), CKO_SECRET_KEY);
        obj.key_type = Some(CKK_AES);
        obj.sensitive = true;
        obj.extractable = false;
        // A caller-forged provenance claim is refused (H1-09).
        let mut forged = obj.clone();
        forged.extra_attributes.insert(CKA_LOCAL, vec![1]);
        assert!(store
            .insert_object_in(forged, &ObjectContext::admin(0), ObjectOrigin::Created)
            .is_err());
        let h = store
            .insert_object_in(
                obj,
                &ObjectContext::admin(0),
                ObjectOrigin::Generated {
                    mechanism: CKM_AES_KEY_GEN,
                },
            )
            .unwrap();
        let o = store.get_object(h).unwrap();
        let o = o.read();
        assert_eq!(
            read_attribute(&o, CKA_LOCAL).unwrap().as_deref().map(|v| v.to_vec()),
            Some(vec![1u8])
        );
        assert_eq!(
            read_attribute(&o, CKA_NEVER_EXTRACTABLE)
                .unwrap()
                .as_deref()
                .map(|v| v.to_vec()),
            Some(vec![1u8])
        );
    }
}
