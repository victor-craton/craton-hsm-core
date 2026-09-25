// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! aws-lc-rs CryptoBackend implementation — FIPS-validated AWS-LC library.
//!
//! Compiled only when the `awslc-backend` feature is enabled (implied by the
//! `fips` feature). This is the inline variant of the `craton_hsm-awslc`
//! enterprise crate.
//!
//! All AES operations pass through the backend-independent policy layer of
//! `CryptoBackend` (provided methods), so IV handling, reuse detection and
//! limits are identical to the RustCrypto backend (H2-04). ECDH returns the
//! shared secret `Z`; the KDF is applied by the shared `ecdh_derive`, so both
//! backends derive identical keys.
//!
//! Multi-part (prehashed) RSA and ECDSA operations use AWS-LC's
//! `sign_digest` / `verify_digest` (the digest is computed by this module's
//! AWS-LC hasher), not RustCrypto (H2-03 / A1-03). A few combinations that
//! AWS-LC cannot express (e.g. ECDSA P-256 with SHA-384, raw PKCS#1 v1.5
//! over non-DigestInfo data, GCM tags shorter than 128 bits on decryption,
//! AES-192 key-wrap KEKs) fall back to RustCrypto in non-FIPS builds and are
//! refused in `fips` builds.

use aws_lc_rs::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    agreement, cipher, digest,
    key_wrap::{self, KeyEncryptionKey, KeyWrap, KeyWrapPadded},
    rand as awslc_rand, rsa as awslc_rsa,
    signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair},
};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::backend::CryptoBackend;
use crate::crypto::digest::DigestAccumulator;
use crate::crypto::params::{OaepParams, GCM_IV_LEN};
use crate::crypto::sign::{EcCurve, HashAlg, OaepHash};
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;
use crate::store::key_material::RawKeyMaterial;

/// FIPS-validated crypto backend using aws-lc-rs.
pub struct AwsLcBackend;

/// Fallback to the RustCrypto implementation for combinations AWS-LC cannot
/// express. Refused in `fips` builds (non-validated code).
fn rustcrypto_fallback<T>(what: &str, f: impl FnOnce() -> HsmResult<T>) -> HsmResult<T> {
    if cfg!(feature = "fips") {
        tracing::error!(
            "{}: not available from the validated module in FIPS builds",
            what
        );
        return Err(HsmError::MechanismInvalid);
    }
    tracing::debug!("{}: using RustCrypto fallback (not FIPS validated)", what);
    f()
}

fn digest_alg(hash: HashAlg) -> &'static digest::Algorithm {
    match hash {
        HashAlg::Sha256 => &digest::SHA256,
        HashAlg::Sha384 => &digest::SHA384,
        HashAlg::Sha512 => &digest::SHA512,
    }
}

fn rsa_pkcs1_alg(hash: HashAlg) -> &'static dyn signature::RsaEncoding {
    match hash {
        HashAlg::Sha256 => &signature::RSA_PKCS1_SHA256,
        HashAlg::Sha384 => &signature::RSA_PKCS1_SHA384,
        HashAlg::Sha512 => &signature::RSA_PKCS1_SHA512,
    }
}

fn rsa_pss_alg(hash: HashAlg) -> &'static dyn signature::RsaEncoding {
    match hash {
        HashAlg::Sha256 => &signature::RSA_PSS_SHA256,
        HashAlg::Sha384 => &signature::RSA_PSS_SHA384,
        HashAlg::Sha512 => &signature::RSA_PSS_SHA512,
    }
}

fn rsa_pkcs1_params(hash: HashAlg) -> &'static signature::RsaParameters {
    match hash {
        HashAlg::Sha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        HashAlg::Sha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
        HashAlg::Sha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
    }
}

fn rsa_pss_params(hash: HashAlg) -> &'static signature::RsaParameters {
    match hash {
        HashAlg::Sha256 => &signature::RSA_PSS_2048_8192_SHA256,
        HashAlg::Sha384 => &signature::RSA_PSS_2048_8192_SHA384,
        HashAlg::Sha512 => &signature::RSA_PSS_2048_8192_SHA512,
    }
}

fn hash_for_digest_len(len: usize) -> Option<HashAlg> {
    match len {
        32 => Some(HashAlg::Sha256),
        48 => Some(HashAlg::Sha384),
        64 => Some(HashAlg::Sha512),
        _ => None,
    }
}

fn import_digest(digest_bytes: &[u8], hash: HashAlg) -> HsmResult<digest::Digest> {
    digest::Digest::import_less_safe(digest_bytes, digest_alg(hash))
        .map_err(|_| HsmError::DataLenRange)
}

/// DER-encode a PKCS#1 `RSAPublicKey` for `UnparsedPublicKey`.
fn rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    fn len(out: &mut Vec<u8>, l: usize) {
        if l < 0x80 {
            out.push(l as u8);
        } else {
            let bytes = (l as u32).to_be_bytes();
            let skip = bytes.iter().position(|&b| b != 0).unwrap_or(3);
            out.push(0x80 | (4 - skip) as u8);
            out.extend_from_slice(&bytes[skip..]);
        }
    }
    fn int(out: &mut Vec<u8>, v: &[u8]) {
        let first = v
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(v.len().saturating_sub(1));
        let v = &v[first.min(v.len())..];
        let pad = v.first().is_some_and(|&b| b & 0x80 != 0);
        out.push(0x02);
        len(out, v.len() + usize::from(pad));
        if pad {
            out.push(0);
        }
        out.extend_from_slice(v);
    }
    let mut body = Vec::new();
    int(&mut body, n);
    int(&mut body, e);
    let mut out = vec![0x30];
    len(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

fn ec_point(public_key: &[u8]) -> &[u8] {
    // Accept a DER OCTET STRING wrapped point as well as a raw X9.62 point.
    match public_key.first() {
        Some(0x04) if matches!(public_key.len(), 65 | 97) => public_key,
        _ => crate::crypto::params::der_octet_string_inner(public_key).unwrap_or(public_key),
    }
}

fn raw_ecdsa_to_der(curve: EcCurve, sig: &[u8]) -> Option<Vec<u8>> {
    match curve {
        EcCurve::P256 => p256::ecdsa::Signature::from_slice(sig)
            .ok()
            .map(|s| s.to_der().as_bytes().to_vec()),
        EcCurve::P384 => p384::ecdsa::Signature::from_slice(sig)
            .ok()
            .map(|s| s.to_der().as_bytes().to_vec()),
    }
}

/// ECDSA verification algorithm (for a raw fixed-format signature when the
/// hash is the curve default, otherwise the ASN.1 variant).
fn ecdsa_verify_alg(
    curve: EcCurve,
    hash: HashAlg,
) -> (&'static signature::EcdsaVerificationAlgorithm, bool) {
    match (curve, hash) {
        (EcCurve::P256, HashAlg::Sha256) => (&signature::ECDSA_P256_SHA256_FIXED, true),
        (EcCurve::P256, HashAlg::Sha384) => (&signature::ECDSA_P256_SHA384_ASN1, false),
        (EcCurve::P256, HashAlg::Sha512) => (&signature::ECDSA_P256_SHA512_ASN1, false),
        (EcCurve::P384, HashAlg::Sha384) => (&signature::ECDSA_P384_SHA384_FIXED, true),
        (EcCurve::P384, HashAlg::Sha256) => (&signature::ECDSA_P384_SHA256_ASN1, false),
        (EcCurve::P384, HashAlg::Sha512) => (&signature::ECDSA_P384_SHA512_ASN1, false),
    }
}

fn ecdsa_key_pair(curve: EcCurve, private_key_bytes: &[u8]) -> HsmResult<EcdsaKeyPair> {
    let (sign_alg, agree_alg) = match curve {
        EcCurve::P256 => (
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &agreement::ECDH_P256,
        ),
        EcCurve::P384 => (
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            &agreement::ECDH_P384,
        ),
    };
    let pub_key = derive_ec_public_key(private_key_bytes, agree_alg)?;
    EcdsaKeyPair::from_private_key_and_public_key(sign_alg, private_key_bytes, &pub_key)
        .map_err(|_| HsmError::KeyHandleInvalid)
}

fn curve_default_hash(curve: EcCurve) -> HashAlg {
    match curve {
        EcCurve::P256 => HashAlg::Sha256,
        EcCurve::P384 => HashAlg::Sha384,
    }
}

impl CryptoBackend for AwsLcBackend {
    fn name(&self) -> &'static str {
        "awslc"
    }

    fn is_fips_validated(&self) -> bool {
        aws_lc_rs::try_fips_mode().is_ok()
    }

    // ========================================================================
    // RNG (AWS-LC's approved CTR_DRBG with its own entropy source)
    // ========================================================================

    fn generate_random(&self, out: &mut [u8]) -> HsmResult<()> {
        awslc_rand::fill(out).map_err(|_| {
            out.zeroize();
            HsmError::GeneralError
        })
    }

    fn seed_random(&self, _seed: &[u8]) -> HsmResult<()> {
        // AWS-LC exposes no API to mix caller seed material into its DRBG.
        Err(HsmError::RandomSeedNotSupported)
    }

    // ========================================================================
    // RSA
    // ========================================================================

    fn rsa_pkcs1v15_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>> {
        match hash_alg {
            Some(hash) => {
                let key_pair = awslc_rsa::KeyPair::from_pkcs8(private_key_der)
                    .map_err(|_| HsmError::KeyHandleInvalid)?;
                let rng = awslc_rand::SystemRandom::new();
                let mut sig = vec![0u8; key_pair.public_modulus_len()];
                key_pair
                    .sign(rsa_pkcs1_alg(hash), &rng, data, &mut sig)
                    .map_err(|_| HsmError::GeneralError)?;
                Ok(sig)
            }
            // CKM_RSA_PKCS: a SHA-2 DigestInfo is signed with AWS-LC.
            None => match crate::crypto::sign::parse_digest_info(data) {
                Some((hash, digest_bytes)) => {
                    self.rsa_pkcs1v15_sign_prehashed(private_key_der, digest_bytes, hash)
                }
                None => rustcrypto_fallback("raw CKM_RSA_PKCS signing", || {
                    crate::crypto::sign::rsa_pkcs1v15_sign(private_key_der, data, None)
                }),
            },
        }
    }

    fn rsa_pkcs1v15_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature_bytes: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<bool> {
        match hash_alg {
            Some(hash) => {
                let components = awslc_rsa::PublicKeyComponents {
                    n: modulus,
                    e: public_exponent,
                };
                Ok(components
                    .verify(rsa_pkcs1_params(hash), data, signature_bytes)
                    .is_ok())
            }
            None => match crate::crypto::sign::parse_digest_info(data) {
                Some((hash, digest_bytes)) => self.rsa_pkcs1v15_verify_prehashed(
                    modulus,
                    public_exponent,
                    digest_bytes,
                    signature_bytes,
                    hash,
                ),
                None => rustcrypto_fallback("raw CKM_RSA_PKCS verification", || {
                    crate::crypto::sign::rsa_pkcs1v15_verify(
                        modulus,
                        public_exponent,
                        data,
                        signature_bytes,
                        None,
                    )
                }),
            },
        }
    }

    fn rsa_pss_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        let key_pair = awslc_rsa::KeyPair::from_pkcs8(private_key_der)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let rng = awslc_rand::SystemRandom::new();
        let mut sig = vec![0u8; key_pair.public_modulus_len()];
        key_pair
            .sign(rsa_pss_alg(hash_alg), &rng, data, &mut sig)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(sig)
    }

    fn rsa_pss_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature_bytes: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        let components = awslc_rsa::PublicKeyComponents {
            n: modulus,
            e: public_exponent,
        };
        Ok(components
            .verify(rsa_pss_params(hash_alg), data, signature_bytes)
            .is_ok())
    }

    fn rsa_pkcs1v15_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest_bytes: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        let key_pair = awslc_rsa::KeyPair::from_pkcs8(private_key_der)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let d = import_digest(digest_bytes, hash_alg)?;
        let mut sig = vec![0u8; key_pair.public_modulus_len()];
        key_pair
            .sign_digest(rsa_pkcs1_alg(hash_alg), &d, &mut sig)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(sig)
    }

    fn rsa_pkcs1v15_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest_bytes: &[u8],
        signature_bytes: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        let d = import_digest(digest_bytes, hash_alg)?;
        let der = rsa_public_key_der(modulus, public_exponent);
        let pk = signature::UnparsedPublicKey::new(rsa_pkcs1_params(hash_alg), der);
        Ok(pk.verify_digest(&d, signature_bytes).is_ok())
    }

    fn rsa_pss_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest_bytes: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        let key_pair = awslc_rsa::KeyPair::from_pkcs8(private_key_der)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let d = import_digest(digest_bytes, hash_alg)?;
        let mut sig = vec![0u8; key_pair.public_modulus_len()];
        key_pair
            .sign_digest(rsa_pss_alg(hash_alg), &d, &mut sig)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(sig)
    }

    fn rsa_pss_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest_bytes: &[u8],
        signature_bytes: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        let d = import_digest(digest_bytes, hash_alg)?;
        let der = rsa_public_key_der(modulus, public_exponent);
        let pk = signature::UnparsedPublicKey::new(rsa_pss_params(hash_alg), der);
        Ok(pk.verify_digest(&d, signature_bytes).is_ok())
    }

    // ========================================================================
    // ECDSA (raw r || s) and Ed25519
    // ========================================================================

    fn ecdsa_sign(
        &self,
        curve: EcCurve,
        private_key_bytes: &[u8],
        data: &[u8],
        hash: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>> {
        let default = curve_default_hash(curve);
        match hash {
            Some(h) if h == default => {
                let key_pair = ecdsa_key_pair(curve, private_key_bytes)?;
                let rng = awslc_rand::SystemRandom::new();
                let sig = key_pair
                    .sign(&rng, data)
                    .map_err(|_| HsmError::GeneralError)?;
                Ok(sig.as_ref().to_vec())
            }
            None if hash_for_digest_len(data.len()) == Some(default) => {
                let key_pair = ecdsa_key_pair(curve, private_key_bytes)?;
                let d = import_digest(data, default)?;
                let sig = key_pair
                    .sign_digest(&d)
                    .map_err(|_| HsmError::GeneralError)?;
                Ok(sig.as_ref().to_vec())
            }
            _ => rustcrypto_fallback("ECDSA with a non-default hash", || {
                crate::crypto::sign::ecdsa_sign(curve, private_key_bytes, data, hash)
            }),
        }
    }

    fn ecdsa_verify(
        &self,
        curve: EcCurve,
        public_key_sec1: &[u8],
        data: &[u8],
        sig: &[u8],
        hash: Option<HashAlg>,
    ) -> HsmResult<bool> {
        if sig.len() != curve.signature_len() {
            return Ok(false);
        }
        let point = ec_point(public_key_sec1);
        let digest_hash = match hash {
            Some(h) => h,
            None => match hash_for_digest_len(data.len()) {
                Some(h) => h,
                None => {
                    return rustcrypto_fallback("CKM_ECDSA with a non-SHA-2 digest length", || {
                        crate::crypto::sign::ecdsa_verify(curve, public_key_sec1, data, sig, None)
                    })
                }
            },
        };
        let (alg, fixed) = ecdsa_verify_alg(curve, digest_hash);
        let encoded;
        let sig_bytes: &[u8] = if fixed {
            sig
        } else {
            match raw_ecdsa_to_der(curve, sig) {
                Some(d) => {
                    encoded = d;
                    &encoded
                }
                None => return Ok(false),
            }
        };
        let pk = signature::UnparsedPublicKey::new(alg, point);
        Ok(match hash {
            Some(_) => pk.verify(data, sig_bytes).is_ok(),
            None => {
                let d = import_digest(data, digest_hash)?;
                pk.verify_digest(&d, sig_bytes).is_ok()
            }
        })
    }

    fn ed25519_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        if private_key_bytes.len() != 32 {
            return Err(HsmError::KeyHandleInvalid);
        }
        let key_pair = Ed25519KeyPair::from_seed_unchecked(private_key_bytes)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        Ok(key_pair.sign(data).as_ref().to_vec())
    }

    fn ed25519_verify(
        &self,
        public_key_bytes: &[u8],
        data: &[u8],
        signature_bytes: &[u8],
    ) -> HsmResult<bool> {
        // Reject small-order ("weak") public keys before verification (H2-16).
        crate::crypto::sign::ed25519_parse_public_key(public_key_bytes)?;
        if signature_bytes.len() != 64 {
            return Err(HsmError::SignatureLenRange);
        }
        let pub_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
        Ok(pub_key.verify(data, signature_bytes).is_ok())
    }

    // ========================================================================
    // AES primitives
    // ========================================================================

    fn aes_gcm_seal(
        &self,
        key: &[u8],
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        tag_len: usize,
        plaintext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        if !(12..=16).contains(&tag_len) {
            return Err(HsmError::MechanismParamInvalid);
        }
        let sealing_key = LessSafeKey::new(gcm_unbound_key(key)?);
        let mut in_out = plaintext.to_vec();
        let tag = sealing_key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(*iv),
                Aad::from(aad),
                &mut in_out,
            )
            .map_err(|_| HsmError::GeneralError)?;
        in_out.extend_from_slice(&tag.as_ref()[..tag_len]);
        Ok(in_out)
    }

    fn aes_gcm_open(
        &self,
        key: &[u8],
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        tag_len: usize,
        ct_and_tag: &[u8],
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        if tag_len != 16 {
            // AWS-LC's AEAD API only verifies full-length tags.
            return rustcrypto_fallback("AES-GCM decryption with a truncated tag", || {
                crate::crypto::encrypt::aes_gcm_open_raw(key, iv, aad, tag_len, ct_and_tag)
            });
        }
        if ct_and_tag.len() < tag_len {
            return Err(HsmError::EncryptedDataLenRange);
        }
        let opening_key = LessSafeKey::new(gcm_unbound_key(key)?);
        let mut in_out = Zeroizing::new(ct_and_tag.to_vec());
        let pt_len = opening_key
            .open_in_place(
                Nonce::assume_unique_for_key(*iv),
                Aad::from(aad),
                &mut in_out,
            )
            .map_err(|_| HsmError::EncryptedDataInvalid)?
            .len();
        in_out.truncate(pt_len);
        Ok(in_out)
    }

    fn aes_cbc_encrypt_raw(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        plaintext: &[u8],
        padding: bool,
    ) -> HsmResult<Vec<u8>> {
        let unbound = cipher::UnboundCipherKey::new(aes_cipher_alg(key)?, key)
            .map_err(|_| HsmError::KeySizeRange)?;
        let context = cipher::EncryptionContext::Iv128(aws_lc_rs::iv::FixedLength::from(iv));
        let mut data = plaintext.to_vec();
        if padding {
            let k = cipher::PaddedBlockEncryptingKey::cbc_pkcs7(unbound)
                .map_err(|_| HsmError::GeneralError)?;
            k.less_safe_encrypt(&mut data, context)
                .map_err(|_| HsmError::GeneralError)?;
        } else {
            if plaintext.len() % 16 != 0 {
                return Err(HsmError::DataLenRange);
            }
            let k = cipher::EncryptingKey::cbc(unbound).map_err(|_| HsmError::GeneralError)?;
            k.less_safe_encrypt(&mut data, context)
                .map_err(|_| HsmError::GeneralError)?;
        }
        Ok(data)
    }

    fn aes_cbc_decrypt_raw(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        ciphertext: &[u8],
        padding: bool,
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        if ciphertext.len() % 16 != 0 {
            return Err(HsmError::EncryptedDataLenRange);
        }
        let unbound = cipher::UnboundCipherKey::new(aes_cipher_alg(key)?, key)
            .map_err(|_| HsmError::KeySizeRange)?;
        let context = cipher::DecryptionContext::Iv128(aws_lc_rs::iv::FixedLength::from(iv));
        // Decrypt in place in a zeroizing buffer and truncate (no copies).
        let mut data = Zeroizing::new(ciphertext.to_vec());
        let n = if padding {
            let k = cipher::PaddedBlockDecryptingKey::cbc_pkcs7(unbound)
                .map_err(|_| HsmError::GeneralError)?;
            k.decrypt(&mut data, context)
                .map_err(|_| HsmError::EncryptedDataInvalid)?
                .len()
        } else {
            let k = cipher::DecryptingKey::cbc(unbound).map_err(|_| HsmError::GeneralError)?;
            k.decrypt(&mut data, context)
                .map_err(|_| HsmError::EncryptedDataInvalid)?
                .len()
        };
        data[n..].zeroize();
        data.truncate(n);
        Ok(data)
    }

    fn aes_ctr_apply(&self, key: &[u8], iv: &[u8; 16], data: &[u8]) -> HsmResult<Vec<u8>> {
        let unbound = cipher::UnboundCipherKey::new(aes_cipher_alg(key)?, key)
            .map_err(|_| HsmError::KeySizeRange)?;
        let enc_key = cipher::EncryptingKey::ctr(unbound).map_err(|_| HsmError::GeneralError)?;
        let context = cipher::EncryptionContext::Iv128(aws_lc_rs::iv::FixedLength::from(iv));
        let mut output = data.to_vec();
        enc_key
            .less_safe_encrypt(&mut output, context)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(output)
    }

    // ========================================================================
    // RSA-OAEP (label honoured; MGF1 hash == OAEP hash)
    // ========================================================================

    fn rsa_oaep_encrypt(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        plaintext: &[u8],
        params: &OaepParams,
    ) -> HsmResult<Vec<u8>> {
        let components = awslc_rsa::PublicKeyComponents {
            n: modulus,
            e: public_exponent,
        };
        let pub_enc_key: awslc_rsa::PublicEncryptingKey = components
            .try_into()
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let oaep_key = awslc_rsa::OaepPublicEncryptingKey::new(pub_enc_key)
            .map_err(|_| HsmError::GeneralError)?;
        let mut ciphertext = vec![0u8; oaep_key.ciphertext_size()];
        let label = (!params.label.is_empty()).then_some(&params.label[..]);
        let n = oaep_key
            .encrypt(oaep_alg(params.hash), plaintext, &mut ciphertext, label)
            .map_err(|_| HsmError::DataLenRange)?
            .len();
        ciphertext.truncate(n);
        Ok(ciphertext)
    }

    fn rsa_oaep_decrypt(
        &self,
        private_key_der: &[u8],
        ciphertext: &[u8],
        params: &OaepParams,
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        let priv_key = awslc_rsa::PrivateDecryptingKey::from_pkcs8(private_key_der)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let oaep_key = awslc_rsa::OaepPrivateDecryptingKey::new(priv_key)
            .map_err(|_| HsmError::GeneralError)?;
        let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len()]);
        let label = (!params.label.is_empty()).then_some(&params.label[..]);
        let n = oaep_key
            .decrypt(oaep_alg(params.hash), ciphertext, &mut plaintext, label)
            .map_err(|_| HsmError::EncryptedDataInvalid)?
            .len();
        plaintext[n..].zeroize();
        plaintext.truncate(n);
        Ok(plaintext)
    }

    // ========================================================================
    // Key generation
    // ========================================================================

    fn generate_aes_key(
        &self,
        key_len_bytes: usize,
        _fips_mode: bool,
    ) -> HsmResult<RawKeyMaterial> {
        match key_len_bytes {
            16 | 24 | 32 => {}
            _ => return Err(HsmError::KeySizeRange),
        }
        let mut key = Zeroizing::new(vec![0u8; key_len_bytes]);
        awslc_rand::fill(&mut key).map_err(|_| HsmError::GeneralError)?;
        Ok(RawKeyMaterial::new(key.to_vec()))
    }

    fn generate_rsa_key_pair(
        &self,
        modulus_bits: u32,
        _fips_mode: bool,
    ) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
        let key_size = match modulus_bits {
            2048 => awslc_rsa::KeySize::Rsa2048,
            3072 => awslc_rsa::KeySize::Rsa3072,
            4096 => awslc_rsa::KeySize::Rsa4096,
            _ => return Err(HsmError::KeySizeRange),
        };
        let key_pair =
            awslc_rsa::KeyPair::generate(key_size).map_err(|_| HsmError::GeneralError)?;
        use aws_lc_rs::encoding::AsDer;
        let pkcs8_der = key_pair.as_der().map_err(|_| HsmError::GeneralError)?;
        let der_bytes = Zeroizing::new(pkcs8_der.as_ref().to_vec());
        let pub_key_der = key_pair.public_key().as_ref();
        let (modulus, exponent) = parse_rsa_spki(pub_key_der)?;
        Ok((RawKeyMaterial::new(der_bytes.to_vec()), modulus, exponent))
    }

    fn generate_ec_p256_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        generate_ec(&agreement::ECDH_P256)
    }

    fn generate_ec_p384_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        generate_ec(&agreement::ECDH_P384)
    }

    fn generate_ed25519_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        let mut seed = Zeroizing::new([0u8; 32]);
        awslc_rand::fill(&mut *seed).map_err(|_| HsmError::GeneralError)?;
        let key_pair =
            Ed25519KeyPair::from_seed_unchecked(&*seed).map_err(|_| HsmError::GeneralError)?;
        let pub_bytes = key_pair.public_key().as_ref().to_vec();
        Ok((RawKeyMaterial::new(seed.to_vec()), pub_bytes))
    }

    // ========================================================================
    // Digest
    // ========================================================================

    fn compute_digest(&self, mechanism: CK_MECHANISM_TYPE, data: &[u8]) -> HsmResult<Vec<u8>> {
        let alg = mechanism_to_digest_alg(mechanism)?;
        Ok(digest::digest(alg, data).as_ref().to_vec())
    }

    fn digest_output_len(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<usize> {
        let alg = mechanism_to_digest_alg(mechanism)?;
        Ok(alg.output_len())
    }

    fn create_hasher(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<Box<dyn DigestAccumulator>> {
        let alg = mechanism_to_digest_alg(mechanism)?;
        Ok(Box::new(AwsLcHasher {
            context: digest::Context::new(alg),
            output_len: alg.output_len(),
        }))
    }

    // ========================================================================
    // Key wrap/unwrap (SP 800-38F KW / KWP)
    // ========================================================================

    fn aes_key_wrap(
        &self,
        wrapping_key: &[u8],
        key_to_wrap: &[u8],
        padded: bool,
    ) -> HsmResult<Vec<u8>> {
        let Some(kw_alg) = kw_alg(wrapping_key) else {
            return rustcrypto_fallback("AES-192 key wrap", || {
                if padded {
                    crate::crypto::wrap::aes_key_wrap_padded(wrapping_key, key_to_wrap)
                } else {
                    crate::crypto::wrap::aes_key_wrap(wrapping_key, key_to_wrap)
                }
            });
        };
        let kek =
            KeyEncryptionKey::new(kw_alg, wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
        if padded {
            if key_to_wrap.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            let mut output = vec![0u8; key_to_wrap.len().div_ceil(8) * 8 + 8];
            let n = kek
                .wrap_with_padding(key_to_wrap, &mut output)
                .map_err(|_| HsmError::GeneralError)?
                .len();
            output.truncate(n);
            Ok(output)
        } else {
            if key_to_wrap.len() % 8 != 0 || key_to_wrap.len() < 16 {
                return Err(HsmError::DataLenRange);
            }
            let mut output = vec![0u8; key_to_wrap.len() + 8];
            let n = kek
                .wrap(key_to_wrap, &mut output)
                .map_err(|_| HsmError::GeneralError)?
                .len();
            output.truncate(n);
            Ok(output)
        }
    }

    fn aes_key_unwrap(
        &self,
        wrapping_key: &[u8],
        wrapped_key: &[u8],
        padded: bool,
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        let Some(kw_alg) = kw_alg(wrapping_key) else {
            return rustcrypto_fallback("AES-192 key unwrap", || {
                if padded {
                    crate::crypto::wrap::aes_key_unwrap_padded(wrapping_key, wrapped_key)
                } else {
                    crate::crypto::wrap::aes_key_unwrap(wrapping_key, wrapped_key)
                }
            });
        };
        if wrapped_key.len() % 8 != 0 || wrapped_key.len() < if padded { 16 } else { 24 } {
            return Err(HsmError::DataLenRange);
        }
        let kek =
            KeyEncryptionKey::new(kw_alg, wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
        let mut output = Zeroizing::new(vec![0u8; wrapped_key.len()]);
        let n = if padded {
            kek.unwrap_with_padding(wrapped_key, &mut output)
                .map_err(|_| HsmError::EncryptedDataInvalid)?
                .len()
        } else {
            kek.unwrap(wrapped_key, &mut output)
                .map_err(|_| HsmError::EncryptedDataInvalid)?
                .len()
        };
        output[n..].zeroize();
        output.truncate(n);
        Ok(output)
    }

    // ========================================================================
    // Key agreement (KAS-ECC-SSC primitive)
    // ========================================================================

    fn ecdh_raw(
        &self,
        curve: EcCurve,
        private_key_bytes: &[u8],
        peer_public_key: &[u8],
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        let alg = match curve {
            EcCurve::P256 => &agreement::ECDH_P256,
            EcCurve::P384 => &agreement::ECDH_P384,
        };
        let my_private = agreement::PrivateKey::from_private_key(alg, private_key_bytes)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let peer = agreement::UnparsedPublicKey::new(alg, ec_point(peer_public_key));
        agreement::agree(&my_private, peer, HsmError::MechanismParamInvalid, |z| {
            Ok(Zeroizing::new(z.to_vec()))
        })
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn gcm_unbound_key(key: &[u8]) -> HsmResult<UnboundKey> {
    let alg = match key.len() {
        16 => &aead::AES_128_GCM,
        24 => &aead::AES_192_GCM,
        32 => &aead::AES_256_GCM,
        _ => return Err(HsmError::KeySizeRange),
    };
    UnboundKey::new(alg, key).map_err(|_| HsmError::KeySizeRange)
}

fn aes_cipher_alg(key: &[u8]) -> HsmResult<&'static cipher::Algorithm> {
    match key.len() {
        16 => Ok(&cipher::AES_128),
        24 => Ok(&cipher::AES_192),
        32 => Ok(&cipher::AES_256),
        _ => Err(HsmError::KeySizeRange),
    }
}

fn kw_alg(kek: &[u8]) -> Option<&'static key_wrap::AesBlockCipher> {
    match kek.len() {
        16 => Some(&key_wrap::AES_128),
        32 => Some(&key_wrap::AES_256),
        _ => None,
    }
}

fn oaep_alg(hash_alg: OaepHash) -> &'static awslc_rsa::OaepAlgorithm {
    match hash_alg {
        OaepHash::Sha256 => &awslc_rsa::OAEP_SHA256_MGF1SHA256,
        OaepHash::Sha384 => &awslc_rsa::OAEP_SHA384_MGF1SHA384,
        OaepHash::Sha512 => &awslc_rsa::OAEP_SHA512_MGF1SHA512,
    }
}

fn generate_ec(alg: &'static agreement::Algorithm) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    let private_key = agreement::PrivateKey::generate(alg).map_err(|_| HsmError::GeneralError)?;
    let public_key = private_key
        .compute_public_key()
        .map_err(|_| HsmError::GeneralError)?;
    use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};
    let priv_bytes: EcPrivateKeyBin = private_key
        .as_be_bytes()
        .map_err(|_| HsmError::GeneralError)?;
    let sk = Zeroizing::new(priv_bytes.as_ref().to_vec());
    Ok((
        RawKeyMaterial::new(sk.to_vec()),
        public_key.as_ref().to_vec(),
    ))
}

fn derive_ec_public_key(
    private_key_bytes: &[u8],
    alg: &'static agreement::Algorithm,
) -> HsmResult<Vec<u8>> {
    let private_key = agreement::PrivateKey::from_private_key(alg, private_key_bytes)
        .map_err(|_| HsmError::KeyHandleInvalid)?;
    let public_key = private_key
        .compute_public_key()
        .map_err(|_| HsmError::GeneralError)?;
    Ok(public_key.as_ref().to_vec())
}

fn mechanism_to_digest_alg(mechanism: CK_MECHANISM_TYPE) -> HsmResult<&'static digest::Algorithm> {
    match mechanism {
        CKM_SHA_1 => Ok(&digest::SHA1_FOR_LEGACY_USE_ONLY),
        CKM_SHA256 => Ok(&digest::SHA256),
        CKM_SHA384 => Ok(&digest::SHA384),
        CKM_SHA512 => Ok(&digest::SHA512),
        CKM_SHA3_256 => Ok(&digest::SHA3_256),
        CKM_SHA3_384 => Ok(&digest::SHA3_384),
        CKM_SHA3_512 => Ok(&digest::SHA3_512),
        _ => Err(HsmError::MechanismInvalid),
    }
}

fn parse_rsa_spki(der: &[u8]) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let mut r = DerReader::new(der);
    r.enter_sequence()?;
    let tag = r.read_tag()?;

    if tag == 0x02 {
        let modulus_len = r.read_length()?;
        let modulus = r.read_bytes(modulus_len)?;
        let modulus = if !modulus.is_empty() && modulus[0] == 0x00 {
            &modulus[1..]
        } else {
            modulus
        };
        let exponent = r.read_integer()?;
        Ok((modulus.to_vec(), exponent.to_vec()))
    } else if tag == 0x30 {
        let alg_len = r.read_length()?;
        r.skip(alg_len)?;
        let bit_tag = r.read_tag()?;
        if bit_tag != 0x03 {
            return Err(HsmError::GeneralError);
        }
        let _bit_len = r.read_length()?;
        r.skip(1)?;
        r.enter_sequence()?;
        let modulus = r.read_integer()?;
        let exponent = r.read_integer()?;
        Ok((modulus.to_vec(), exponent.to_vec()))
    } else {
        Err(HsmError::GeneralError)
    }
}

struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_tag(&mut self) -> HsmResult<u8> {
        let tag = *self.data.get(self.pos).ok_or(HsmError::GeneralError)?;
        self.pos += 1;
        Ok(tag)
    }

    fn read_length(&mut self) -> HsmResult<usize> {
        let first = *self.data.get(self.pos).ok_or(HsmError::GeneralError)? as usize;
        self.pos += 1;
        if first < 0x80 {
            Ok(first)
        } else {
            let num_bytes = first & 0x7F;
            if num_bytes > 4 || self.pos + num_bytes > self.data.len() {
                return Err(HsmError::GeneralError);
            }
            let mut len = 0usize;
            for _ in 0..num_bytes {
                len = (len << 8) | (self.data[self.pos] as usize);
                self.pos += 1;
            }
            Ok(len)
        }
    }

    fn enter_sequence(&mut self) -> HsmResult<usize> {
        if self.read_tag()? != 0x30 {
            return Err(HsmError::GeneralError);
        }
        self.read_length()
    }

    fn read_integer(&mut self) -> HsmResult<&'a [u8]> {
        if self.read_tag()? != 0x02 {
            return Err(HsmError::GeneralError);
        }
        let len = self.read_length()?;
        let mut bytes = self.read_bytes(len)?;
        if bytes.len() > 1 && bytes[0] == 0x00 {
            bytes = &bytes[1..];
        }
        Ok(bytes)
    }

    fn read_bytes(&mut self, len: usize) -> HsmResult<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(HsmError::GeneralError)?;
        if end > self.data.len() {
            return Err(HsmError::GeneralError);
        }
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn skip(&mut self, len: usize) -> HsmResult<()> {
        self.read_bytes(len).map(|_| ())
    }
}

struct AwsLcHasher {
    context: digest::Context,
    output_len: usize,
}

impl DigestAccumulator for AwsLcHasher {
    fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.context.finish().as_ref().to_vec()
    }

    fn output_len(&self) -> usize {
        self.output_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All backend CASTs pass through AWS-LC (A1-04: POST exercises the
    /// configured backend).
    #[test]
    fn backend_casts_pass_on_awslc() {
        crate::crypto::self_test::run_backend_post(&AwsLcBackend, false)
            .expect("AWS-LC backend CASTs");
    }

    /// Cross-backend differential test: both backends agree on ECDH-derived
    /// keys, GCM ciphertexts, raw ECDSA format and KWP output (H2-04).
    #[cfg(feature = "rustcrypto-backend")]
    #[test]
    fn differential_against_rustcrypto() {
        use crate::crypto::params::{EcdhParams, CKD_SHA256_KDF};
        use crate::crypto::rustcrypto_backend::RustCryptoBackend;
        let aws = AwsLcBackend;
        let rc = RustCryptoBackend;
        let (a_sk, a_pk) = rc.generate_ec_p256_key_pair().unwrap();
        let (b_sk, b_pk) = aws.generate_ec_p256_key_pair().unwrap();
        let pa = EcdhParams::from_ck(CKD_SHA256_KDF, b"x", &b_pk).unwrap();
        let pb = EcdhParams::from_ck(CKD_SHA256_KDF, b"x", &a_pk).unwrap();
        let ka = rc
            .ecdh_derive(EcCurve::P256, a_sk.as_bytes(), &pa, 32, true)
            .unwrap();
        let kb = aws
            .ecdh_derive(EcCurve::P256, b_sk.as_bytes(), &pb, 32, true)
            .unwrap();
        assert_eq!(ka.as_bytes(), kb.as_bytes());

        let key = [7u8; 32];
        let iv = [9u8; 12];
        let c1 = rc.aes_gcm_seal(&key, &iv, b"aad", 16, b"pt").unwrap();
        let c2 = aws.aes_gcm_seal(&key, &iv, b"aad", 16, b"pt").unwrap();
        assert_eq!(c1, c2);

        let sig = aws
            .ecdsa_sign(EcCurve::P256, b_sk.as_bytes(), b"m", Some(HashAlg::Sha256))
            .unwrap();
        assert!(rc
            .ecdsa_verify(EcCurve::P256, &b_pk, b"m", &sig, Some(HashAlg::Sha256))
            .unwrap());

        let kek = [3u8; 32];
        assert_eq!(
            rc.aes_key_wrap(&kek, b"odd-length key", true).unwrap(),
            aws.aes_key_wrap(&kek, b"odd-length key", true).unwrap()
        );
    }
}
