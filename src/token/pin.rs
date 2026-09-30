// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! PIN verifiers and storage-key wrapping.
//!
//! A PIN is stretched once with PBKDF2-HMAC-SHA256 (random 256-bit salt per
//! PIN, iteration count recorded with the verifier so parameters can be
//! migrated, H3-27). Two independent values are derived from the stretched
//! master secret with HMAC-SHA256 domain separation:
//!
//! * the **verifier** (stored) — compared in constant time on login;
//! * the **KEK** (never stored) — wraps the slot's data-encryption key.
//!
//! So a single PBKDF2 run both authenticates the PIN and unlocks storage, and
//! the stored verifier alone reveals nothing about the KEK.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::config::defaults::{KDF_PBKDF2_HMAC_SHA256, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{HsmError, HsmResult};
use crate::store::encrypted_store::fill_random;

const VERIFIER_LABEL: &[u8] = b"craton-hsm/pin-verifier/v1";
const KEK_LABEL: &[u8] = b"craton-hsm/dek-kek/v1";
/// Lower bound accepted when verifying a stored verifier (defence against a
/// tampered record that weakens the work factor).
const MIN_VERIFY_ITERATIONS: u32 = 10_000;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// Stored PIN verifier (no secret that allows recovering the KEK).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PinVerifier {
    #[zeroize(skip)]
    kdf: String,
    iterations: u32,
    #[serde(with = "hex_array")]
    salt: [u8; SALT_LEN],
    #[serde(with = "hex_array")]
    verifier: [u8; 32],
}

impl std::fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinVerifier")
            .field("kdf", &self.kdf)
            .field("iterations", &self.iterations)
            .finish_non_exhaustive()
    }
}

fn hmac_label(key: &[u8], label: &[u8]) -> Zeroizing<[u8; 32]> {
    use hmac::Mac;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(label);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn stretch(pin: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut master = Zeroizing::new([0u8; 32]);
    // Iterations are validated (>= MIN_VERIFY_ITERATIONS / config bounds)
    // before we get here, so the only error (0 iterations) cannot occur.
    if crate::store::encrypted_store::pbkdf2_hmac_sha256(
        pin,
        salt,
        iterations.max(1),
        master.as_mut(),
    )
    .is_err()
    {
        master.iter_mut().for_each(|b| *b = 0);
    }
    master
}

impl PinVerifier {
    /// Create a verifier for `pin`. Returns the verifier and the KEK.
    pub fn create(pin: &[u8], iterations: u32) -> HsmResult<(Self, Zeroizing<[u8; KEY_LEN]>)> {
        // A verifier that `verify` would refuse makes the account unusable:
        // reject weak parameters when the PIN is set, not at the next login.
        if iterations < MIN_VERIFY_ITERATIONS {
            tracing::error!(
                "PBKDF2 iteration count {} below the minimum of {}",
                iterations,
                MIN_VERIFY_ITERATIONS
            );
            return Err(HsmError::ArgumentsBad);
        }
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        let master = stretch(pin, &salt, iterations);
        let verifier = hmac_label(master.as_ref(), VERIFIER_LABEL);
        let kek = hmac_label(master.as_ref(), KEK_LABEL);
        Ok((
            Self {
                kdf: KDF_PBKDF2_HMAC_SHA256.to_string(),
                iterations,
                salt,
                verifier: *verifier,
            },
            kek,
        ))
    }

    /// Verify `pin` in constant time. Returns the KEK on success.
    pub fn verify(&self, pin: &[u8]) -> Option<Zeroizing<[u8; KEY_LEN]>> {
        use subtle::ConstantTimeEq;
        if self.kdf != KDF_PBKDF2_HMAC_SHA256 || self.iterations < MIN_VERIFY_ITERATIONS {
            tracing::error!("stored PIN verifier has unsupported/weak parameters");
            return None;
        }
        let master = stretch(pin, &self.salt, self.iterations);
        let candidate = hmac_label(master.as_ref(), VERIFIER_LABEL);
        if bool::from(candidate.as_ref().ct_eq(&self.verifier)) {
            Some(hmac_label(master.as_ref(), KEK_LABEL))
        } else {
            None
        }
    }

    /// PBKDF2 iteration count recorded in this verifier.
    pub fn iterations(&self) -> u32 {
        self.iterations
    }
}

/// Wrap a data-encryption key under a KEK (AES-256-GCM, `nonce || ct`).
pub fn wrap_key(kek: &[u8; KEY_LEN], key: &[u8; KEY_LEN], aad: &[u8]) -> HsmResult<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: key, aad })
        .map_err(|_| HsmError::GeneralError)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap a key produced by [`wrap_key`]. Fails (`DeviceError`) on any
/// authentication failure — which indicates a tampered token record.
pub fn unwrap_key(
    kek: &[u8; KEY_LEN],
    blob: &[u8],
    aad: &[u8],
) -> HsmResult<Zeroizing<[u8; KEY_LEN]>> {
    if blob.len() != NONCE_LEN + KEY_LEN + 16 {
        return Err(HsmError::DeviceError);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&blob[..NONCE_LEN]),
                Payload {
                    msg: &blob[NONCE_LEN..],
                    aad,
                },
            )
            .map_err(|_| HsmError::DeviceError)?,
    );
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&pt);
    Ok(out)
}

mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("wrong length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_roundtrip_and_kek_consistency() {
        let (v, kek) = PinVerifier::create(b"Correct-PIN1", 10_000).unwrap();
        let kek2 = v.verify(b"Correct-PIN1").unwrap();
        assert_eq!(*kek, *kek2);
        assert!(v.verify(b"wrong").is_none());
        let json = serde_json::to_string(&v).unwrap();
        let v2: PinVerifier = serde_json::from_str(&json).unwrap();
        assert!(v2.verify(b"Correct-PIN1").is_some());
    }

    #[test]
    fn wrap_unwrap() {
        let kek = [1u8; 32];
        let dek = [2u8; 32];
        let w = wrap_key(&kek, &dek, b"aad").unwrap();
        assert_eq!(*unwrap_key(&kek, &w, b"aad").unwrap(), dek);
        assert!(unwrap_key(&kek, &w, b"other").is_err());
    }
}
