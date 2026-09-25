// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Key generation (RustCrypto). All randomness comes from the module-wide
//! SP 800-90A DRBG (`crypto::drbg`).
//!
//! Approved-mode key sizes follow SP 800-131A Rev 2 (H2-21): AES-128/192/256
//! and RSA >= 2048 bits are all acceptable, so `fips_mode` no longer rejects
//! AES-128 or RSA-2048 (which also removes a backend inconsistency with the
//! AWS-LC backend).

use zeroize::Zeroizing;

use crate::crypto::drbg::DrbgRng;
use crate::error::{HsmError, HsmResult};
use crate::store::key_material::RawKeyMaterial;

/// Generate an AES key of 16, 24 or 32 bytes.
///
/// `fips_mode` is accepted for API compatibility; all three AES key sizes are
/// approved.
pub fn generate_aes_key(key_len_bytes: usize, _fips_mode: bool) -> HsmResult<RawKeyMaterial> {
    match key_len_bytes {
        16 | 24 | 32 => {}
        _ => return Err(HsmError::KeySizeRange),
    }
    let mut key = Zeroizing::new(vec![0u8; key_len_bytes]);
    crate::crypto::drbg::fill_random(&mut key)?;
    Ok(RawKeyMaterial::new(key.to_vec()))
}

/// Generate an RSA key pair (2048, 3072 or 4096 bits).
/// Returns (private_key_pkcs8_der, public_modulus, public_exponent).
pub fn generate_rsa_key_pair(
    modulus_bits: u32,
    _fips_mode: bool,
) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
    use rsa::traits::PublicKeyParts;
    use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};

    match modulus_bits {
        2048 | 3072 | 4096 => {}
        _ => return Err(HsmError::KeySizeRange),
    }

    let mut rng = DrbgRng::new()?;
    let private_key =
        RsaPrivateKey::new(&mut rng, modulus_bits as usize).map_err(|_| HsmError::GeneralError)?;

    let modulus = private_key.n().to_bytes_be();
    let pub_exp = private_key.e().to_bytes_be();

    // `SecretDocument` zeroizes its buffer on drop.
    let der = private_key
        .to_pkcs8_der()
        .map_err(|_| HsmError::GeneralError)?;
    Ok((
        RawKeyMaterial::new(der.as_bytes().to_vec()),
        modulus,
        pub_exp,
    ))
}

/// Generate an EC P-256 key pair. Returns (private_scalar, public_point_uncompressed).
pub fn generate_ec_p256_key_pair() -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    use elliptic_curve::sec1::ToEncodedPoint;
    let mut rng = DrbgRng::new()?;
    let secret_key = p256::SecretKey::random(&mut rng);
    let pub_point = secret_key.public_key().to_encoded_point(false);
    let sk = Zeroizing::new(secret_key.to_bytes());
    Ok((
        RawKeyMaterial::new(sk.to_vec()),
        pub_point.as_bytes().to_vec(),
    ))
}

/// Generate an EC P-384 key pair. Returns (private_scalar, public_point_uncompressed).
pub fn generate_ec_p384_key_pair() -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    use elliptic_curve::sec1::ToEncodedPoint;
    let mut rng = DrbgRng::new()?;
    let secret_key = p384::SecretKey::random(&mut rng);
    let pub_point = secret_key.public_key().to_encoded_point(false);
    let sk = Zeroizing::new(secret_key.to_bytes());
    Ok((
        RawKeyMaterial::new(sk.to_vec()),
        pub_point.as_bytes().to_vec(),
    ))
}

/// Generate an Ed25519 key pair. Returns (seed, public_key).
pub fn generate_ed25519_key_pair() -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    let mut seed = Zeroizing::new([0u8; 32]);
    crate::crypto::drbg::fill_random(&mut *seed)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    Ok((
        RawKeyMaterial::new(seed.to_vec()),
        verifying_key.to_bytes().to_vec(),
    ))
}
