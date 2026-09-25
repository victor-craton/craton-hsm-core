// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Mechanism ↔ key binding (H4-08, H4-21).
//!
//! The algorithm that runs is chosen from the *mechanism*, and the key must
//! match it; a mismatch is rejected before any cryptographic operation. The
//! EC curve is identified by an exact DER OID match.

use craton_hsm::crypto::sign::HashAlg;
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::types::CK_ULONG;
use craton_hsm::store::object::StoredObject;
use tonic::Status;

/// DER OID for secp256r1 / prime256v1 (1.2.840.10045.3.1.7).
pub const P256_OID: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// DER OID for secp384r1 (1.3.132.0.34).
pub const P384_OID: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
/// DER OID for Ed25519 (1.3.101.112).
pub const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
/// DER PrintableString "edwards25519" (PKCS#11 v3.0 curve name form).
pub const ED25519_NAME: &[u8] = b"\x13\x0cedwards25519";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

/// Identify a NIST curve from CKA_EC_PARAMS by exact OID match.
pub fn curve_from_params(params: &[u8]) -> Option<Curve> {
    if params == P256_OID {
        Some(Curve::P256)
    } else if params == P384_OID {
        Some(Curve::P384)
    } else {
        None
    }
}

pub fn is_ed25519_params(params: &[u8]) -> bool {
    params == ED25519_OID || params == ED25519_NAME
}

fn mismatch() -> Status {
    Status::invalid_argument("Key type does not match mechanism")
}

fn unsupported(what: &str) -> Status {
    Status::unimplemented(format!("{} is not supported by the gRPC daemon", what))
}

/// Signature algorithm actually executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignAlg {
    RsaPkcs1(HashAlg2),
    RsaPss(HashAlg2),
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
}

/// `HashAlg` from the core does not implement `PartialEq`; mirror it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg2 {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg2 {
    pub fn to_core(self) -> HashAlg {
        match self {
            HashAlg2::Sha256 => HashAlg::Sha256,
            HashAlg2::Sha384 => HashAlg::Sha384,
            HashAlg2::Sha512 => HashAlg::Sha512,
        }
    }
}

/// Bind a sign/verify mechanism to the key. `parameter` must be empty:
/// mechanisms that need parameters (generic PSS) are not offered.
pub fn sign_alg_for(
    mech: CK_ULONG,
    parameter: &[u8],
    key: &StoredObject,
) -> Result<SignAlg, Status> {
    if !parameter.is_empty() {
        return Err(Status::invalid_argument(
            "Mechanism parameters are not supported for this mechanism",
        ));
    }
    let key_type = key.key_type;
    let alg = match mech {
        CKM_SHA256_RSA_PKCS => SignAlg::RsaPkcs1(HashAlg2::Sha256),
        CKM_SHA384_RSA_PKCS => SignAlg::RsaPkcs1(HashAlg2::Sha384),
        CKM_SHA512_RSA_PKCS => SignAlg::RsaPkcs1(HashAlg2::Sha512),
        CKM_SHA256_RSA_PKCS_PSS => SignAlg::RsaPss(HashAlg2::Sha256),
        CKM_SHA384_RSA_PKCS_PSS => SignAlg::RsaPss(HashAlg2::Sha384),
        CKM_SHA512_RSA_PKCS_PSS => SignAlg::RsaPss(HashAlg2::Sha512),
        CKM_RSA_PKCS => return Err(unsupported("Raw CKM_RSA_PKCS (use CKM_SHA*_RSA_PKCS)")),
        CKM_RSA_PKCS_PSS => {
            return Err(unsupported(
                "Generic CKM_RSA_PKCS_PSS (use CKM_SHA*_RSA_PKCS_PSS)",
            ))
        }
        CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 => {
            if key_type != Some(CKK_EC) {
                return Err(mismatch());
            }
            let curve = key
                .ec_params
                .as_deref()
                .and_then(curve_from_params)
                .ok_or_else(|| Status::invalid_argument("Key has unsupported EC parameters"))?;
            return match (mech, curve) {
                (CKM_ECDSA_SHA256, Curve::P256) => Ok(SignAlg::EcdsaP256Sha256),
                (CKM_ECDSA_SHA384, Curve::P384) => Ok(SignAlg::EcdsaP384Sha384),
                _ => Err(unsupported("This ECDSA hash/curve combination")),
            };
        }
        CKM_ECDSA | CKM_ECDSA_SHA512 => {
            return Err(unsupported("CKM_ECDSA (pre-hashed) / CKM_ECDSA_SHA512"))
        }
        CKM_EDDSA => {
            if key_type != Some(CKK_EC_EDWARDS) {
                return Err(mismatch());
            }
            return Ok(SignAlg::Ed25519);
        }
        _ => return Err(unsupported("This signature mechanism")),
    };
    if key_type != Some(CKK_RSA) {
        return Err(mismatch());
    }
    Ok(alg)
}

/// Cipher actually executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherAlg {
    AesGcm,
    AesCbcPad,
    AesCtr,
    RsaOaepSha256,
}

/// Bind an encrypt/decrypt mechanism to the key (and validate parameters).
pub fn cipher_alg_for(
    mech: CK_ULONG,
    parameter: &[u8],
    key: &StoredObject,
    decrypt: bool,
) -> Result<CipherAlg, Status> {
    let aes_key = key.key_type == Some(CKK_AES) && key.class == CKO_SECRET_KEY;
    match mech {
        CKM_AES_GCM => {
            if !parameter.is_empty() {
                return Err(Status::invalid_argument(
                    "CKM_AES_GCM parameters are not supported: the IV is generated internally \
                     and prepended to the ciphertext",
                ));
            }
            if !aes_key {
                return Err(mismatch());
            }
            Ok(CipherAlg::AesGcm)
        }
        CKM_AES_CBC_PAD | CKM_AES_CTR => {
            if parameter.len() != 16 {
                return Err(Status::invalid_argument(
                    "AES-CBC/CTR requires a 16-byte IV in the mechanism parameter",
                ));
            }
            if !aes_key {
                return Err(mismatch());
            }
            Ok(if mech == CKM_AES_CTR {
                CipherAlg::AesCtr
            } else {
                CipherAlg::AesCbcPad
            })
        }
        CKM_AES_CBC => Err(unsupported("Unpadded CKM_AES_CBC (use CKM_AES_CBC_PAD)")),
        CKM_RSA_PKCS_OAEP => {
            if !parameter.is_empty() {
                return Err(Status::invalid_argument(
                    "CKM_RSA_PKCS_OAEP parameters are not supported (SHA-256/MGF1-SHA-256, no label)",
                ));
            }
            if key.key_type != Some(CKK_RSA) {
                return Err(mismatch());
            }
            if decrypt && key.class != CKO_PRIVATE_KEY {
                return Err(mismatch());
            }
            Ok(CipherAlg::RsaOaepSha256)
        }
        _ => Err(unsupported("This encryption mechanism")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(class: CK_ULONG, kt: CK_ULONG, params: Option<&[u8]>) -> StoredObject {
        let mut o = StoredObject::new(1, class);
        o.key_type = Some(kt);
        o.ec_params = params.map(|p| p.to_vec());
        o
    }

    #[test]
    fn ed25519_key_only_with_eddsa() {
        let k = key(CKO_PRIVATE_KEY, CKK_EC_EDWARDS, None);
        assert_eq!(sign_alg_for(CKM_EDDSA, &[], &k).unwrap(), SignAlg::Ed25519);
        assert!(sign_alg_for(CKM_ECDSA_SHA256, &[], &k).is_err());
        assert!(sign_alg_for(CKM_SHA256_RSA_PKCS, &[], &k).is_err());
    }

    #[test]
    fn ecdsa_hash_must_match_curve() {
        let p256 = key(CKO_PRIVATE_KEY, CKK_EC, Some(P256_OID));
        assert_eq!(
            sign_alg_for(CKM_ECDSA_SHA256, &[], &p256).unwrap(),
            SignAlg::EcdsaP256Sha256
        );
        assert!(sign_alg_for(CKM_ECDSA_SHA384, &[], &p256).is_err());
        assert!(sign_alg_for(CKM_ECDSA, &[], &p256).is_err());
        let p384 = key(CKO_PRIVATE_KEY, CKK_EC, Some(P384_OID));
        assert_eq!(
            sign_alg_for(CKM_ECDSA_SHA384, &[], &p384).unwrap(),
            SignAlg::EcdsaP384Sha384
        );
    }

    #[test]
    fn exact_curve_oid_match() {
        let mut padded = vec![0xFF];
        padded.extend_from_slice(P384_OID);
        assert_eq!(curve_from_params(&padded), None);
        assert_eq!(curve_from_params(P384_OID), Some(Curve::P384));
        assert_eq!(curve_from_params(&[]), None);
    }

    #[test]
    fn cipher_requires_matching_key() {
        let aes = key(CKO_SECRET_KEY, CKK_AES, None);
        let rsa_pub = key(CKO_PUBLIC_KEY, CKK_RSA, None);
        assert_eq!(
            cipher_alg_for(CKM_AES_GCM, &[], &aes, false).unwrap(),
            CipherAlg::AesGcm
        );
        assert!(cipher_alg_for(CKM_AES_GCM, &[], &rsa_pub, false).is_err());
        assert!(cipher_alg_for(CKM_RSA_PKCS_OAEP, &[], &aes, false).is_err());
        assert!(cipher_alg_for(CKM_RSA_PKCS_OAEP, &[], &rsa_pub, true).is_err());
        assert!(cipher_alg_for(CKM_RSA_PKCS_OAEP, &[], &rsa_pub, false).is_ok());
        assert!(cipher_alg_for(CKM_AES_CBC, &[0; 16], &aes, false).is_err());
    }
}
