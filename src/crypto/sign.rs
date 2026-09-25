// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Signature, verification and RSA encryption primitives (RustCrypto).
//!
//! # RSA side channels (H2-03 / A1-26, RUSTSEC-2023-0071 "Marvin")
//!
//! The `rsa` 0.9 crate performs private-key exponentiation with
//! `num-bigint-dig`, which is not constant time, and no fixed release exists.
//! Mitigations applied here:
//! - **Every** private-key operation supplies an RNG so the crate applies
//!   base blinding: PKCS#1 v1.5 signing uses `sign_with_rng`, PSS signing uses
//!   `Pss::new_blinded` (plain `Pss::new` does *not* blind in rsa 0.9), and
//!   OAEP decryption uses `decrypt_blinded`.
//! - RSA PKCS#1 v1.5 *decryption* (the classic Bleichenbacher/Marvin oracle)
//!   is not offered by this module at all; `CKM_RSA_PKCS` is sign/verify only.
//! - FIPS builds (`--features fips`) are required to use the AWS-LC backend,
//!   whose RSA implementation is constant time, for all RSA private-key
//!   operations (see `crypto::self_test::run_backend_post`).
//!
//! Residual risk: blinding reduces but does not provably eliminate timing
//! leakage from the non-constant-time bignum code on the RustCrypto backend.
//! Deployments exposed to co-located attackers must use the AWS-LC backend.
//!
//! # ECDSA
//!
//! ECDSA signatures use the PKCS#11 format (raw `r || s`, each zero-padded to
//! the group order length — A2-07). The hash is chosen by the mechanism
//! (`CKM_ECDSA_SHA*`); for `CKM_ECDSA` the input is already a hash and is
//! used as-is with FIPS 186-5 bits2int truncation (H2-07 / A1-13).

use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use zeroize::Zeroizing;

use crate::crypto::drbg::DrbgRng;
use crate::crypto::params::OaepParams;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;

// ============================================================================
// Algorithm identifiers
// ============================================================================

/// Hash algorithm used by a signature mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    /// Digest output length in bytes.
    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    /// Hash `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Sha256::digest(data).to_vec(),
            HashAlg::Sha384 => Sha384::digest(data).to_vec(),
            HashAlg::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// The corresponding PKCS#11 digest mechanism.
    pub fn digest_mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            HashAlg::Sha256 => CKM_SHA256,
            HashAlg::Sha384 => CKM_SHA384,
            HashAlg::Sha512 => CKM_SHA512,
        }
    }

    fn pkcs1v15_scheme(self) -> Pkcs1v15Sign {
        match self {
            HashAlg::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
            HashAlg::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
            HashAlg::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
        }
    }

    /// PSS scheme with salt length = hash length. `blinded` enables RSA base
    /// blinding of the private-key operation (the output is a standard
    /// RSASSA-PSS signature either way).
    fn pss_scheme(self, blinded: bool) -> Pss {
        match (self, blinded) {
            (HashAlg::Sha256, true) => Pss::new_blinded::<Sha256>(),
            (HashAlg::Sha384, true) => Pss::new_blinded::<Sha384>(),
            (HashAlg::Sha512, true) => Pss::new_blinded::<Sha512>(),
            (HashAlg::Sha256, false) => Pss::new::<Sha256>(),
            (HashAlg::Sha384, false) => Pss::new::<Sha384>(),
            (HashAlg::Sha512, false) => Pss::new::<Sha512>(),
        }
    }
}

/// Hash algorithm selection for RSA-OAEP (hash and MGF1 hash are identical).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OaepHash {
    Sha256,
    Sha384,
    Sha512,
}

/// Supported elliptic curves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    P256,
    P384,
}

/// DER-encoded namedCurve OID for P-256 (1.2.840.10045.3.1.7).
pub const P256_OID_DER: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// DER-encoded namedCurve OID for P-384 (1.3.132.0.34).
pub const P384_OID_DER: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

impl EcCurve {
    /// Strictly parse `CKA_EC_PARAMS` (DER `ECParameters`). Only the
    /// namedCurve OIDs of P-256 and P-384 are accepted; anything else
    /// (other curves, explicit parameters, garbage) returns `None` (A1-25).
    pub fn from_ec_params(ec_params: &[u8]) -> Option<EcCurve> {
        if ec_params == P256_OID_DER {
            Some(EcCurve::P256)
        } else if ec_params == P384_OID_DER {
            Some(EcCurve::P384)
        } else {
            None
        }
    }

    /// Field element / scalar length in bytes.
    pub fn field_len(self) -> usize {
        match self {
            EcCurve::P256 => 32,
            EcCurve::P384 => 48,
        }
    }

    /// Length of a PKCS#11 raw `r || s` signature.
    pub fn signature_len(self) -> usize {
        2 * self.field_len()
    }

    /// DER OID for `CKA_EC_PARAMS`.
    pub fn oid_der(self) -> &'static [u8] {
        match self {
            EcCurve::P256 => P256_OID_DER,
            EcCurve::P384 => P384_OID_DER,
        }
    }
}

// ============================================================================
// RSA private key cache (H2-10 / A1-10)
// ============================================================================
//
// Parsing PKCS#8 DER into an `RsaPrivateKey` (bignum reconstruction and CRT
// precomputation) is expensive, so parsed keys are cached behind an `Arc`
// (no per-operation deep clone). Entries are keyed by HMAC-SHA256 under a
// per-process random key (so the cache does not retain a plain hash of the
// private key) and are evicted explicitly:
// - `evict_rsa_key(der)` from `C_DestroyObject`;
// - `clear_rsa_key_cache()` from `C_Finalize` and `C_InitToken`.
// `RsaPrivateKey` zeroizes its bignums on drop, so dropping the last `Arc`
// scrubs the cached key.

const RSA_KEY_CACHE_MAX: usize = 64;

static RSA_KEY_CACHE: parking_lot::Mutex<Option<HashMap<[u8; 32], Arc<RsaPrivateKey>>>> =
    parking_lot::Mutex::new(None);
static RSA_CACHE_ID_KEY: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();

fn rsa_cache_id(der: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let key = RSA_CACHE_ID_KEY.get_or_init(|| {
        let mut k = Zeroizing::new([0u8; 32]);
        if crate::crypto::drbg::fill_random(&mut *k).is_err() {
            // Fall back to OS randomness for the cache key only; it is not a
            // security-critical secret (it merely blinds the cache index).
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut *k);
        }
        k
    });
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key[..]).expect("HMAC accepts any key length");
    mac.update(der);
    mac.finalize().into_bytes().into()
}

/// Parse an RSA private key from PKCS#8 DER, using the cache when possible.
fn parse_rsa_private_key(der: &[u8]) -> HsmResult<Arc<RsaPrivateKey>> {
    let id = rsa_cache_id(der);
    {
        let guard = RSA_KEY_CACHE.lock();
        if let Some(k) = guard.as_ref().and_then(|m| m.get(&id)) {
            return Ok(Arc::clone(k));
        }
    }
    let key = Arc::new(RsaPrivateKey::from_pkcs8_der(der).map_err(|_| HsmError::KeyHandleInvalid)?);
    let mut guard = RSA_KEY_CACHE.lock();
    let map = guard.get_or_insert_with(HashMap::new);
    if map.len() >= RSA_KEY_CACHE_MAX {
        // Simple bounded strategy: drop everything (keys zeroize on drop).
        map.clear();
    }
    map.insert(id, Arc::clone(&key));
    Ok(key)
}

/// Evict a single key from the RSA cache. Call when the key object is
/// destroyed (`C_DestroyObject`).
pub fn evict_rsa_key(private_key_der: &[u8]) {
    let id = rsa_cache_id(private_key_der);
    if let Some(map) = RSA_KEY_CACHE.lock().as_mut() {
        map.remove(&id);
    }
}

/// Clear the RSA key cache. Call on `C_Finalize`, `C_InitToken` and
/// whenever all key material must be released.
pub fn clear_rsa_key_cache() {
    *RSA_KEY_CACHE.lock() = None;
}

/// Number of cached RSA keys (diagnostics / tests).
pub fn rsa_key_cache_len() -> usize {
    RSA_KEY_CACHE.lock().as_ref().map_or(0, |m| m.len())
}

// ============================================================================
// Shared validation
// ============================================================================

/// Minimum RSA modulus size in bits (SP 800-131A Rev 2).
const RSA_MIN_MODULUS_BITS: usize = 2048;

/// Maximum data size for sign/verify operations (64 MiB).
const SIGN_MAX_DATA_SIZE: usize = 64 * 1024 * 1024;

fn validate_data_size(data: &[u8]) -> HsmResult<()> {
    if data.len() > SIGN_MAX_DATA_SIZE {
        tracing::warn!(
            "Sign/verify data size {} exceeds maximum {} bytes — rejecting",
            data.len(),
            SIGN_MAX_DATA_SIZE
        );
        return Err(HsmError::DataLenRange);
    }
    Ok(())
}

/// Validate that a pre-computed digest has the correct length.
fn validate_digest_length(digest: &[u8], hash_alg: HashAlg) -> HsmResult<()> {
    if digest.len() != hash_alg.output_len() {
        tracing::error!(
            "Prehash digest length mismatch: got {} bytes, expected {} for {:?}",
            digest.len(),
            hash_alg.output_len(),
            hash_alg
        );
        return Err(HsmError::DataLenRange);
    }
    Ok(())
}

fn validate_rsa_private_key_size(private_key: &RsaPrivateKey) -> HsmResult<()> {
    let modulus_bits = private_key.n().bits();
    if modulus_bits < RSA_MIN_MODULUS_BITS {
        tracing::warn!(
            "Rejecting RSA operation: key size {} bits is below minimum {} bits",
            modulus_bits,
            RSA_MIN_MODULUS_BITS
        );
        return Err(HsmError::KeySizeRange);
    }
    Ok(())
}

fn validate_rsa_public_key_size(modulus: &[u8]) -> HsmResult<()> {
    let significant = modulus
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(modulus.len());
    let significant_bytes = &modulus[significant..];
    let modulus_bits = if significant_bytes.is_empty() {
        0
    } else {
        (significant_bytes.len() - 1) * 8 + (8 - significant_bytes[0].leading_zeros() as usize)
    };
    if modulus_bits < RSA_MIN_MODULUS_BITS {
        tracing::warn!(
            "Rejecting RSA operation: key size {} bits is below minimum {} bits",
            modulus_bits,
            RSA_MIN_MODULUS_BITS
        );
        return Err(HsmError::KeySizeRange);
    }
    Ok(())
}

fn rsa_public_key(modulus: &[u8], public_exponent: &[u8]) -> HsmResult<RsaPublicKey> {
    validate_rsa_public_key_size(modulus)?;
    let n = rsa::BigUint::from_bytes_be(modulus);
    let e = rsa::BigUint::from_bytes_be(public_exponent);
    RsaPublicKey::new(n, e).map_err(|_| HsmError::KeyHandleInvalid)
}

fn rsa_private_key(der: &[u8]) -> HsmResult<Arc<RsaPrivateKey>> {
    let key = parse_rsa_private_key(der)?;
    validate_rsa_private_key_size(&key)?;
    Ok(key)
}

// ============================================================================
// RSA PKCS#1 v1.5
// ============================================================================

/// DER `DigestInfo` prefixes (RFC 8017 §9.2 note 1).
const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const DIGEST_INFO_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const DIGEST_INFO_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// If `data` is exactly a SHA-256/384/512 `DigestInfo`, return the hash
/// algorithm and the digest.
pub fn parse_digest_info(data: &[u8]) -> Option<(HashAlg, &[u8])> {
    for (prefix, alg) in [
        (DIGEST_INFO_SHA256, HashAlg::Sha256),
        (DIGEST_INFO_SHA384, HashAlg::Sha384),
        (DIGEST_INFO_SHA512, HashAlg::Sha512),
    ] {
        if data.len() == prefix.len() + alg.output_len() && data.starts_with(prefix) {
            return Some((alg, &data[prefix.len()..]));
        }
    }
    None
}

/// RSA PKCS#1 v1.5 sign (blinded).
///
/// With `Some(hash)` the data is hashed and wrapped in a `DigestInfo`
/// (`CKM_SHAx_RSA_PKCS`). With `None` (`CKM_RSA_PKCS`) the caller-supplied
/// data — normally a DER `DigestInfo` — is EMSA-PKCS1-v1_5 encoded as-is.
pub fn rsa_pkcs1v15_sign(
    private_key_der: &[u8],
    data: &[u8],
    hash_alg: Option<HashAlg>,
) -> HsmResult<Vec<u8>> {
    validate_data_size(data)?;
    let key = rsa_private_key(private_key_der)?;
    let mut rng = DrbgRng::new()?;
    match hash_alg {
        Some(alg) => {
            let digest = alg.digest(data);
            key.sign_with_rng(&mut rng, alg.pkcs1v15_scheme(), &digest)
                .map_err(|_| HsmError::GeneralError)
        }
        None => key
            .sign_with_rng(&mut rng, Pkcs1v15Sign::new_unprefixed(), data)
            // Input longer than k - 11 bytes.
            .map_err(|_| HsmError::DataLenRange),
    }
}

/// RSA PKCS#1 v1.5 verify.
///
/// Verification re-encodes the expected EMSA-PKCS1-v1_5 block and compares
/// it in full (no ASN.1 parsing of the recovered block), so the
/// Bleichenbacher'06 low-exponent forgery does not apply, including for the
/// raw `CKM_RSA_PKCS` form (`hash_alg == None`).
pub fn rsa_pkcs1v15_verify(
    modulus: &[u8],
    public_exponent: &[u8],
    data: &[u8],
    signature: &[u8],
    hash_alg: Option<HashAlg>,
) -> HsmResult<bool> {
    validate_data_size(data)?;
    let public_key = rsa_public_key(modulus, public_exponent)?;
    if signature.len() != public_key.size() {
        return Ok(false);
    }
    Ok(match hash_alg {
        Some(alg) => {
            let digest = alg.digest(data);
            public_key
                .verify(alg.pkcs1v15_scheme(), &digest, signature)
                .is_ok()
        }
        None => public_key
            .verify(Pkcs1v15Sign::new_unprefixed(), data, signature)
            .is_ok(),
    })
}

/// RSA PKCS#1 v1.5 sign with a pre-computed digest (blinded).
pub(crate) fn rsa_pkcs1v15_sign_prehashed(
    private_key_der: &[u8],
    digest: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<Vec<u8>> {
    validate_digest_length(digest, hash_alg)?;
    let key = rsa_private_key(private_key_der)?;
    let mut rng = DrbgRng::new()?;
    key.sign_with_rng(&mut rng, hash_alg.pkcs1v15_scheme(), digest)
        .map_err(|_| HsmError::GeneralError)
}

/// RSA PKCS#1 v1.5 verify with a pre-computed digest.
pub(crate) fn rsa_pkcs1v15_verify_prehashed(
    modulus: &[u8],
    public_exponent: &[u8],
    digest: &[u8],
    signature: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<bool> {
    validate_digest_length(digest, hash_alg)?;
    let public_key = rsa_public_key(modulus, public_exponent)?;
    Ok(public_key
        .verify(hash_alg.pkcs1v15_scheme(), digest, signature)
        .is_ok())
}

// ============================================================================
// RSA-PSS (salt length = hash length, MGF1 with the message hash)
// ============================================================================

/// RSA-PSS sign (blinded; salt from the DRBG).
pub fn rsa_pss_sign(private_key_der: &[u8], data: &[u8], hash_alg: HashAlg) -> HsmResult<Vec<u8>> {
    validate_data_size(data)?;
    let digest = hash_alg.digest(data);
    rsa_pss_sign_prehashed(private_key_der, &digest, hash_alg)
}

/// RSA-PSS verify.
pub fn rsa_pss_verify(
    modulus: &[u8],
    public_exponent: &[u8],
    data: &[u8],
    signature: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<bool> {
    validate_data_size(data)?;
    let digest = hash_alg.digest(data);
    rsa_pss_verify_prehashed(modulus, public_exponent, &digest, signature, hash_alg)
}

/// RSA-PSS sign with a pre-computed digest (blinded; salt from the DRBG).
pub(crate) fn rsa_pss_sign_prehashed(
    private_key_der: &[u8],
    digest: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<Vec<u8>> {
    validate_digest_length(digest, hash_alg)?;
    let key = rsa_private_key(private_key_der)?;
    let mut rng = DrbgRng::new()?;
    key.sign_with_rng(&mut rng, hash_alg.pss_scheme(true), digest)
        .map_err(|_| HsmError::GeneralError)
}

/// RSA-PSS verify with a pre-computed digest (salt length must equal the
/// hash length).
pub(crate) fn rsa_pss_verify_prehashed(
    modulus: &[u8],
    public_exponent: &[u8],
    digest: &[u8],
    signature: &[u8],
    hash_alg: HashAlg,
) -> HsmResult<bool> {
    validate_digest_length(digest, hash_alg)?;
    let public_key = rsa_public_key(modulus, public_exponent)?;
    if signature.len() != public_key.size() {
        return Ok(false);
    }
    Ok(public_key
        .verify(hash_alg.pss_scheme(false), digest, signature)
        .is_ok())
}

// ============================================================================
// RSA-OAEP
// ============================================================================

fn oaep_padding(params: &OaepParams) -> HsmResult<Oaep> {
    // The rsa 0.9 crate stores the label as a `String`; binary labels that
    // are not valid UTF-8 cannot be represented and are rejected rather than
    // silently altered.
    let label = if params.label.is_empty() {
        None
    } else {
        Some(
            std::str::from_utf8(&params.label)
                .map_err(|_| HsmError::MechanismParamInvalid)?
                .to_owned(),
        )
    };
    Ok(match (params.hash, label) {
        (OaepHash::Sha256, None) => Oaep::new::<Sha256>(),
        (OaepHash::Sha384, None) => Oaep::new::<Sha384>(),
        (OaepHash::Sha512, None) => Oaep::new::<Sha512>(),
        (OaepHash::Sha256, Some(l)) => Oaep::new_with_label::<Sha256, _>(l),
        (OaepHash::Sha384, Some(l)) => Oaep::new_with_label::<Sha384, _>(l),
        (OaepHash::Sha512, Some(l)) => Oaep::new_with_label::<Sha512, _>(l),
    })
}

/// RSA-OAEP encrypt (empty label).
pub fn rsa_oaep_encrypt(
    modulus: &[u8],
    public_exponent: &[u8],
    plaintext: &[u8],
    hash_alg: OaepHash,
) -> HsmResult<Vec<u8>> {
    rsa_oaep_encrypt_with_params(modulus, public_exponent, plaintext, &OaepParams::new(hash_alg))
}

/// RSA-OAEP encrypt honouring the OAEP label (H1-16).
pub fn rsa_oaep_encrypt_with_params(
    modulus: &[u8],
    public_exponent: &[u8],
    plaintext: &[u8],
    params: &OaepParams,
) -> HsmResult<Vec<u8>> {
    let public_key = rsa_public_key(modulus, public_exponent)?;
    let mut rng = DrbgRng::new()?;
    public_key
        .encrypt(&mut rng, oaep_padding(params)?, plaintext)
        .map_err(|_| HsmError::DataLenRange)
}

/// RSA-OAEP decrypt (empty label).
pub fn rsa_oaep_decrypt(
    private_key_der: &[u8],
    ciphertext: &[u8],
    hash_alg: OaepHash,
) -> HsmResult<Zeroizing<Vec<u8>>> {
    rsa_oaep_decrypt_with_params(private_key_der, ciphertext, &OaepParams::new(hash_alg))
}

/// RSA-OAEP decrypt (blinded) honouring the OAEP label.
pub fn rsa_oaep_decrypt_with_params(
    private_key_der: &[u8],
    ciphertext: &[u8],
    params: &OaepParams,
) -> HsmResult<Zeroizing<Vec<u8>>> {
    let key = rsa_private_key(private_key_der)?;
    let padding = oaep_padding(params)?;
    let mut rng = DrbgRng::new()?;
    key.decrypt_blinded(&mut rng, padding, ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| HsmError::EncryptedDataInvalid)
}

// ============================================================================
// ECDSA (P-256 / P-384) — PKCS#11 raw r || s
// ============================================================================

/// Compute the value that is signed: the mechanism hash of `data`, or `data`
/// itself for `CKM_ECDSA` (`hash == None`).
fn ecdsa_input(data: &[u8], hash: Option<HashAlg>) -> HsmResult<Vec<u8>> {
    validate_data_size(data)?;
    Ok(match hash {
        Some(alg) => alg.digest(data),
        None => data.to_vec(),
    })
}

/// Parse a SEC1 public point given raw or DER OCTET STRING wrapped.
fn parse_sec1<T>(point: &[u8], parse: impl Fn(&[u8]) -> Option<T>) -> HsmResult<T> {
    parse(point)
        .or_else(|| crate::crypto::params::der_octet_string_inner(point).and_then(&parse))
        .ok_or(HsmError::KeyHandleInvalid)
}

/// ECDSA sign (hedged: RFC 6979 nonce mixed with DRBG randomness).
///
/// Returns the PKCS#11 raw signature `r || s`. `hash == None` is
/// `CKM_ECDSA`: `data` is the caller's hash (it must be at least half the
/// field length; longer inputs are truncated per FIPS 186-5 bits2int).
pub fn ecdsa_sign(
    curve: EcCurve,
    private_key_bytes: &[u8],
    data: &[u8],
    hash: Option<HashAlg>,
) -> HsmResult<Vec<u8>> {
    let prehash = ecdsa_input(data, hash)?;
    ecdsa_sign_prehash(curve, private_key_bytes, &prehash)
}

fn ecdsa_sign_prehash(
    curve: EcCurve,
    private_key_bytes: &[u8],
    prehash: &[u8],
) -> HsmResult<Vec<u8>> {
    use ecdsa::signature::hazmat::RandomizedPrehashSigner;
    let mut rng = DrbgRng::new()?;
    match curve {
        EcCurve::P256 => {
            let sk = p256::ecdsa::SigningKey::from_slice(private_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let sig: p256::ecdsa::Signature = sk
                .sign_prehash_with_rng(&mut rng, prehash)
                .map_err(|_| HsmError::DataLenRange)?;
            Ok(sig.to_bytes().to_vec())
        }
        EcCurve::P384 => {
            let sk = p384::ecdsa::SigningKey::from_slice(private_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let sig: p384::ecdsa::Signature = sk
                .sign_prehash_with_rng(&mut rng, prehash)
                .map_err(|_| HsmError::DataLenRange)?;
            Ok(sig.to_bytes().to_vec())
        }
    }
}

/// ECDSA verify of a PKCS#11 raw `r || s` signature.
///
/// Both high-S and low-S forms verify (FIPS 186-5 does not mandate low-S;
/// requiring it would reject signatures from standard signers).
pub fn ecdsa_verify(
    curve: EcCurve,
    public_key_sec1: &[u8],
    data: &[u8],
    signature: &[u8],
    hash: Option<HashAlg>,
) -> HsmResult<bool> {
    let prehash = ecdsa_input(data, hash)?;
    ecdsa_verify_prehash(curve, public_key_sec1, &prehash, signature)
}

fn ecdsa_verify_prehash(
    curve: EcCurve,
    public_key_sec1: &[u8],
    prehash: &[u8],
    signature: &[u8],
) -> HsmResult<bool> {
    use ecdsa::signature::hazmat::PrehashVerifier;
    if signature.len() != curve.signature_len() {
        return Ok(false);
    }
    match curve {
        EcCurve::P256 => {
            let vk = parse_sec1(public_key_sec1, |p| {
                p256::ecdsa::VerifyingKey::from_sec1_bytes(p).ok()
            })?;
            let Ok(sig) = p256::ecdsa::Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(vk.verify_prehash(prehash, &sig).is_ok())
        }
        EcCurve::P384 => {
            let vk = parse_sec1(public_key_sec1, |p| {
                p384::ecdsa::VerifyingKey::from_sec1_bytes(p).ok()
            })?;
            let Ok(sig) = p384::ecdsa::Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(vk.verify_prehash(prehash, &sig).is_ok())
        }
    }
}

/// ECDSA P-256 with SHA-256 (raw `r || s` output).
pub fn ecdsa_p256_sign(private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
    ecdsa_sign(EcCurve::P256, private_key_bytes, data, Some(HashAlg::Sha256))
}

/// ECDSA P-256 with SHA-256 verify (raw `r || s`).
pub fn ecdsa_p256_verify(
    public_key_sec1: &[u8],
    data: &[u8],
    signature: &[u8],
) -> HsmResult<bool> {
    ecdsa_verify(EcCurve::P256, public_key_sec1, data, signature, Some(HashAlg::Sha256))
}

/// ECDSA P-384 with SHA-384 (raw `r || s` output).
pub fn ecdsa_p384_sign(private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
    ecdsa_sign(EcCurve::P384, private_key_bytes, data, Some(HashAlg::Sha384))
}

/// ECDSA P-384 with SHA-384 verify (raw `r || s`).
pub fn ecdsa_p384_verify(
    public_key_sec1: &[u8],
    data: &[u8],
    signature: &[u8],
) -> HsmResult<bool> {
    ecdsa_verify(EcCurve::P384, public_key_sec1, data, signature, Some(HashAlg::Sha384))
}

// ============================================================================
// Ed25519 (RFC 8032, FIPS 186-5)
// ============================================================================

/// Ed25519 sign (deterministic per RFC 8032).
pub fn ed25519_sign(private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
    use ed25519_dalek::{Signer, SigningKey};

    validate_data_size(data)?;
    let key_array: Zeroizing<[u8; 32]> = Zeroizing::new(
        private_key_bytes
            .try_into()
            .map_err(|_| HsmError::KeyHandleInvalid)?,
    );
    // SigningKey implements ZeroizeOnDrop.
    let signing_key = SigningKey::from_bytes(&key_array);
    Ok(signing_key.sign(data).to_bytes().to_vec())
}

/// Parse an Ed25519 public key, rejecting small-order ("weak") keys.
pub(crate) fn ed25519_parse_public_key(
    public_key_bytes: &[u8],
) -> HsmResult<ed25519_dalek::VerifyingKey> {
    let key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| HsmError::KeyHandleInvalid)?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key_array)
        .map_err(|_| HsmError::KeyHandleInvalid)?;
    if vk.is_weak() {
        tracing::warn!("Ed25519: rejecting small-order public key");
        return Err(HsmError::KeyHandleInvalid);
    }
    Ok(vk)
}

/// Ed25519 verify using strict verification (H2-16): rejects small-order
/// public keys and small-order `R`, and non-canonical `S`.
pub fn ed25519_verify(
    public_key_bytes: &[u8],
    data: &[u8],
    signature_bytes: &[u8],
) -> HsmResult<bool> {
    validate_data_size(data)?;
    let verifying_key = ed25519_parse_public_key(public_key_bytes)?;
    let sig_array: [u8; 64] = match signature_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return Err(HsmError::SignatureLenRange),
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
    Ok(verifying_key.verify_strict(data, &signature).is_ok())
}

// ============================================================================
// Mechanism helpers
// ============================================================================

/// Map CKM mechanism to optional hash algorithm (for PKCS#1 v1.5 RSA).
/// `CKM_RSA_PKCS` maps to `None` (raw DigestInfo signing).
pub fn mechanism_to_hash(mechanism: CK_MECHANISM_TYPE) -> Option<HashAlg> {
    match mechanism {
        CKM_SHA256_RSA_PKCS => Some(HashAlg::Sha256),
        CKM_SHA384_RSA_PKCS => Some(HashAlg::Sha384),
        CKM_SHA512_RSA_PKCS => Some(HashAlg::Sha512),
        _ => None,
    }
}

/// Map an ECDSA mechanism to its hash. `CKM_ECDSA` maps to `None`
/// (input is already a hash).
pub fn ecdsa_mechanism_to_hash(mechanism: CK_MECHANISM_TYPE) -> HsmResult<Option<HashAlg>> {
    match mechanism {
        CKM_ECDSA => Ok(None),
        CKM_ECDSA_SHA256 => Ok(Some(HashAlg::Sha256)),
        CKM_ECDSA_SHA384 => Ok(Some(HashAlg::Sha384)),
        CKM_ECDSA_SHA512 => Ok(Some(HashAlg::Sha512)),
        _ => Err(HsmError::MechanismInvalid),
    }
}

/// Map a CKM PSS mechanism to its hash algorithm.
///
/// `CKM_RSA_PKCS_PSS` requires `CK_RSA_PKCS_PSS_PARAMS` (see
/// [`crate::crypto::params::PssParams`]) and returns `MechanismParamInvalid`.
pub fn pss_mechanism_to_hash(mechanism: CK_MECHANISM_TYPE) -> HsmResult<HashAlg> {
    match mechanism {
        CKM_SHA256_RSA_PKCS_PSS => Ok(HashAlg::Sha256),
        CKM_SHA384_RSA_PKCS_PSS => Ok(HashAlg::Sha384),
        CKM_SHA512_RSA_PKCS_PSS => Ok(HashAlg::Sha512),
        CKM_RSA_PKCS_PSS => Err(HsmError::MechanismParamInvalid),
        _ => Err(HsmError::MechanismInvalid),
    }
}

/// Check if mechanism is an RSA-PSS mechanism.
pub fn is_pss_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        CKM_RSA_PKCS_PSS | CKM_SHA256_RSA_PKCS_PSS | CKM_SHA384_RSA_PKCS_PSS | CKM_SHA512_RSA_PKCS_PSS
    )
}

/// Check if mechanism is an ECDSA mechanism.
pub fn is_ecdsa_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512
    )
}

/// Check if mechanism is EdDSA.
pub fn is_eddsa_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    mechanism == CKM_EDDSA
}

/// Check if a sign mechanism supports multi-part (C_SignUpdate/C_SignFinal).
/// Only mechanisms with a built-in hash algorithm support multi-part.
pub fn sign_mechanism_supports_multipart(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        CKM_SHA256_RSA_PKCS
            | CKM_SHA384_RSA_PKCS
            | CKM_SHA512_RSA_PKCS
            | CKM_SHA256_RSA_PKCS_PSS
            | CKM_SHA384_RSA_PKCS_PSS
            | CKM_SHA512_RSA_PKCS_PSS
            | CKM_ECDSA_SHA256
            | CKM_ECDSA_SHA384
            | CKM_ECDSA_SHA512
    )
}

/// Map a sign mechanism to the corresponding digest mechanism for creating
/// hashers. Returns `None` for mechanisms without a built-in hash.
pub fn sign_mechanism_to_digest_mechanism(
    mechanism: CK_MECHANISM_TYPE,
) -> Option<CK_MECHANISM_TYPE> {
    match mechanism {
        CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS | CKM_ECDSA_SHA256 => Some(CKM_SHA256),
        CKM_SHA384_RSA_PKCS | CKM_SHA384_RSA_PKCS_PSS | CKM_ECDSA_SHA384 => Some(CKM_SHA384),
        CKM_SHA512_RSA_PKCS | CKM_SHA512_RSA_PKCS_PSS | CKM_ECDSA_SHA512 => Some(CKM_SHA512),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_params_strict() {
        assert_eq!(EcCurve::from_ec_params(P256_OID_DER), Some(EcCurve::P256));
        assert_eq!(EcCurve::from_ec_params(P384_OID_DER), Some(EcCurve::P384));
        // secp256k1 and garbage containing the P-384 OID are rejected.
        assert_eq!(
            EcCurve::from_ec_params(&[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A]),
            None
        );
        let mut junk = vec![0xFF];
        junk.extend_from_slice(P384_OID_DER);
        assert_eq!(EcCurve::from_ec_params(&junk), None);
    }

    #[test]
    fn ecdsa_hash_binding() {
        let (sk, pk) = crate::crypto::keygen::generate_ec_p256_key_pair().unwrap();
        let msg = b"hash binding";
        let sig = ecdsa_sign(EcCurve::P256, sk.as_bytes(), msg, Some(HashAlg::Sha512)).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(ecdsa_verify(EcCurve::P256, &pk, msg, &sig, Some(HashAlg::Sha512)).unwrap());
        // A SHA-512 signature must not verify as SHA-256.
        assert!(!ecdsa_verify(EcCurve::P256, &pk, msg, &sig, Some(HashAlg::Sha256)).unwrap());
        // CKM_ECDSA over the SHA-512 digest is the same signature scheme.
        let digest = HashAlg::Sha512.digest(msg);
        assert!(ecdsa_verify(EcCurve::P256, &pk, &digest, &sig, None).unwrap());
    }

    #[test]
    fn rsa_cache_evict_and_clear() {
        let (sk, n, e) = crate::crypto::keygen::generate_rsa_key_pair(2048, false).unwrap();
        let sig = rsa_pkcs1v15_sign(sk.as_bytes(), b"m", Some(HashAlg::Sha256)).unwrap();
        assert!(rsa_pkcs1v15_verify(&n, &e, b"m", &sig, Some(HashAlg::Sha256)).unwrap());
        assert!(rsa_key_cache_len() >= 1);
        evict_rsa_key(sk.as_bytes());
        let id = rsa_cache_id(sk.as_bytes());
        assert!(RSA_KEY_CACHE
            .lock()
            .as_ref()
            .map_or(true, |m| !m.contains_key(&id)));
        clear_rsa_key_cache();
        assert_eq!(rsa_key_cache_len(), 0);
    }

    #[test]
    fn rsa_raw_pkcs1_digest_info() {
        let (sk, n, e) = crate::crypto::keygen::generate_rsa_key_pair(2048, false).unwrap();
        let mut di = DIGEST_INFO_SHA256.to_vec();
        di.extend_from_slice(&Sha256::digest(b"payload"));
        let raw = rsa_pkcs1v15_sign(sk.as_bytes(), &di, None).unwrap();
        // Raw signing of a SHA-256 DigestInfo equals CKM_SHA256_RSA_PKCS.
        assert!(rsa_pkcs1v15_verify(&n, &e, b"payload", &raw, Some(HashAlg::Sha256)).unwrap());
        assert!(rsa_pkcs1v15_verify(&n, &e, &di, &raw, None).unwrap());
        assert_eq!(parse_digest_info(&di).map(|(a, _)| a), Some(HashAlg::Sha256));
    }

    #[test]
    fn ed25519_rejects_weak_key() {
        // The identity point (small order) encoded as y = 1.
        let mut weak = [0u8; 32];
        weak[0] = 1;
        assert!(ed25519_verify(&weak, b"m", &[0u8; 64]).is_err());
    }
}
