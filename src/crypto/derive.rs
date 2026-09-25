// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! ECDH key agreement (SP 800-56A r3 KAS-ECC-SSC) and key derivation.
//!
//! The shared secret `Z` is the x-coordinate of `d_A * Q_B` (the "primitive"
//! computed identically by every backend via `CryptoBackend::ecdh_raw`). Key
//! derivation from `Z` is done here, backend-independently, as selected by
//! `CK_ECDH1_DERIVE_PARAMS.kdf` (H2-06, A1-14, A2-12):
//!
//! * `CKD_SHA{224,256,384,512}_KDF`: ANSI X9.63 KDF, which is the
//!   SP 800-56C r2 one-step KDF with a hash function:
//!   `K(i) = H(Z || counter_i || SharedInfo)`, 32-bit big-endian counter
//!   starting at 1; `pSharedData` is the `SharedInfo`/`FixedInfo`.
//! * `CKD_NULL`: the leftmost bytes of `Z` (not an approved KDF, IG D.F —
//!   refused in FIPS approved mode).
//!
//! Both parties derive the same key because nothing party-specific enters the
//! derivation other than what the caller puts in `pSharedData`.
//!
//! Public-key validation: the peer point is decoded with
//! `PublicKey::from_sec1_bytes`, which performs the SP 800-56A r3
//! §5.6.2.3.3 full validation for these prime-order curves (point on the
//! curve, not the identity, coordinates in range; for cofactor h = 1 the
//! order check is implied). `CKM_ECDH1_COFACTOR_DERIVE` is therefore
//! identical to `CKM_ECDH1_DERIVE` for P-256/P-384.

use p256::ecdh::diffie_hellman as p256_dh;
use p384::ecdh::diffie_hellman as p384_dh;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use crate::crypto::params::{der_octet_string_inner, EcdhKdf, EcdhParams};
use crate::crypto::sign::EcCurve;
use crate::error::{HsmError, HsmResult};
use crate::store::key_material::RawKeyMaterial;

/// Maximum derived key length.
const MAX_OKM_LEN: usize = 64;

fn parse_peer<T>(point: &[u8], parse: impl Fn(&[u8]) -> Option<T>) -> HsmResult<T> {
    parse(point)
        .or_else(|| der_octet_string_inner(point).and_then(&parse))
        .ok_or_else(|| {
            tracing::error!("ECDH: invalid or off-curve peer public key");
            HsmError::MechanismParamInvalid
        })
}

/// KAS-ECC-SSC primitive: returns the shared secret `Z` (RustCrypto).
pub fn ecdh_raw(
    curve: EcCurve,
    private_key_bytes: &[u8],
    peer_public_key: &[u8],
) -> HsmResult<Zeroizing<Vec<u8>>> {
    match curve {
        EcCurve::P256 => {
            let sk = p256::SecretKey::from_slice(private_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let peer = parse_peer(peer_public_key, |p| p256::PublicKey::from_sec1_bytes(p).ok())?;
            let shared = p256_dh(sk.to_nonzero_scalar(), peer.as_affine());
            Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
        }
        EcCurve::P384 => {
            let sk = p384::SecretKey::from_slice(private_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let peer = parse_peer(peer_public_key, |p| p384::PublicKey::from_sec1_bytes(p).ok())?;
            let shared = p384_dh(sk.to_nonzero_scalar(), peer.as_affine());
            Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
        }
    }
}

fn x963<D: Digest>(z: &[u8], shared_info: &[u8], out_len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(out_len + 64));
    let mut counter: u32 = 1;
    while out.len() < out_len {
        let mut h = D::new();
        h.update(z);
        h.update(counter.to_be_bytes());
        h.update(shared_info);
        let block = Zeroizing::new(h.finalize().to_vec());
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(out_len);
    out
}

/// ANSI X9.63 / SP 800-56C r2 one-step hash KDF.
pub fn x963_kdf(
    kdf: EcdhKdf,
    z: &[u8],
    shared_info: &[u8],
    out_len: usize,
) -> HsmResult<Zeroizing<Vec<u8>>> {
    if out_len == 0 || out_len > MAX_OKM_LEN {
        return Err(HsmError::KeySizeRange);
    }
    Ok(match kdf {
        EcdhKdf::Sha224 => x963::<Sha224>(z, shared_info, out_len),
        EcdhKdf::Sha256 => x963::<Sha256>(z, shared_info, out_len),
        EcdhKdf::Sha384 => x963::<Sha384>(z, shared_info, out_len),
        EcdhKdf::Sha512 => x963::<Sha512>(z, shared_info, out_len),
        EcdhKdf::Null => return Err(HsmError::MechanismParamInvalid),
    })
}

/// Derive `key_len` bytes of key material from the shared secret `z`
/// according to `params.kdf`.
pub fn derive_key_from_shared_secret(
    z: &[u8],
    params: &EcdhParams,
    key_len: usize,
    fips_mode: bool,
) -> HsmResult<RawKeyMaterial> {
    if key_len == 0 || key_len > MAX_OKM_LEN {
        return Err(HsmError::KeySizeRange);
    }
    match params.kdf {
        EcdhKdf::Null => {
            if fips_mode {
                tracing::error!(
                    "ECDH with CKD_NULL (raw shared secret as key) is not approved in FIPS mode"
                );
                return Err(HsmError::MechanismParamInvalid);
            }
            if key_len > z.len() {
                return Err(HsmError::KeySizeRange);
            }
            Ok(RawKeyMaterial::new(z[..key_len].to_vec()))
        }
        kdf => {
            let okm = x963_kdf(kdf, z, &params.shared_data, key_len)?;
            Ok(RawKeyMaterial::new(okm.to_vec()))
        }
    }
}

/// HKDF-SHA256 (RFC 5869). Used by the self-test KAT.
pub fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out_len: usize,
) -> HsmResult<Zeroizing<Vec<u8>>> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new(vec![0u8; out_len]);
    hk.expand(info, &mut okm)
        .map_err(|_| HsmError::KeySizeRange)?;
    Ok(okm)
}

fn validate_okm_len(len: usize) -> HsmResult<()> {
    if len == 0 || len > MAX_OKM_LEN {
        tracing::error!("ECDH: requested key length {} out of range", len);
        return Err(HsmError::KeySizeRange);
    }
    Ok(())
}

/// ECDH P-256 followed by the X9.63 SHA-256 KDF with empty shared info.
/// `okm_len` defaults to 32. Both parties obtain the same key.
pub fn ecdh_p256(
    private_key_bytes: &[u8],
    peer_public_key_sec1: &[u8],
    okm_len: Option<usize>,
) -> HsmResult<RawKeyMaterial> {
    let len = okm_len.unwrap_or(32);
    validate_okm_len(len)?;
    let z = ecdh_raw(EcCurve::P256, private_key_bytes, peer_public_key_sec1)?;
    let okm = x963_kdf(EcdhKdf::Sha256, &z, &[], len)?;
    Ok(RawKeyMaterial::new(okm.to_vec()))
}

/// ECDH P-384 followed by the X9.63 SHA-384 KDF with empty shared info.
/// `okm_len` defaults to 48. Both parties obtain the same key.
pub fn ecdh_p384(
    private_key_bytes: &[u8],
    peer_public_key_sec1: &[u8],
    okm_len: Option<usize>,
) -> HsmResult<RawKeyMaterial> {
    let len = okm_len.unwrap_or(48);
    validate_okm_len(len)?;
    let z = ecdh_raw(EcCurve::P384, private_key_bytes, peer_public_key_sec1)?;
    let okm = x963_kdf(EcdhKdf::Sha384, &z, &[], len)?;
    Ok(RawKeyMaterial::new(okm.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keygen;

    #[test]
    fn two_parties_agree() {
        let (a_sk, a_pk) = keygen::generate_ec_p256_key_pair().unwrap();
        let (b_sk, b_pk) = keygen::generate_ec_p256_key_pair().unwrap();
        let params = EcdhParams::from_ck(crate::crypto::params::CKD_SHA256_KDF, b"ctx", &b_pk)
            .unwrap();
        let za = ecdh_raw(EcCurve::P256, a_sk.as_bytes(), &b_pk).unwrap();
        let zb = ecdh_raw(EcCurve::P256, b_sk.as_bytes(), &a_pk).unwrap();
        assert_eq!(za, zb);
        let ka = derive_key_from_shared_secret(&za, &params, 32, true).unwrap();
        let kb = derive_key_from_shared_secret(&zb, &params, 32, true).unwrap();
        assert_eq!(ka.as_bytes(), kb.as_bytes());
        let null = EcdhParams::from_ck(crate::crypto::params::CKD_NULL, b"", &b_pk).unwrap();
        assert!(derive_key_from_shared_secret(&za, &null, 32, true).is_err());
        let raw = derive_key_from_shared_secret(&za, &null, 16, false).unwrap();
        assert_eq!(raw.as_bytes(), &za[..16]);
    }

    #[test]
    fn rejects_off_curve_point() {
        let (a_sk, _) = keygen::generate_ec_p256_key_pair().unwrap();
        let mut bad = vec![0x04u8];
        bad.extend_from_slice(&[0x01; 64]);
        assert!(ecdh_raw(EcCurve::P256, a_sk.as_bytes(), &bad).is_err());
    }
}
