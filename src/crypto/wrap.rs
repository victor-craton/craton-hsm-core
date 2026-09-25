// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! AES Key Wrap (SP 800-38F KW / RFC 3394) and AES Key Wrap with Padding
//! (SP 800-38F KWP / RFC 5649) — RustCrypto implementation.
//!
//! The unwrap integrity checks (ICV / AIV, message-length indicator and
//! padding) are evaluated in constant time with `subtle` and all failures map
//! to one error (H2-14). Unwrapped key material is returned in a
//! [`Zeroizing`] buffer and intermediate buffers are scrubbed (H2-09).
//!
//! AES-128, AES-192 and AES-256 KEKs are accepted in every mode: AES-128 key
//! wrapping is approved (SP 800-38F, SP 800-131A Rev 2). What approved mode
//! additionally requires is that the KEK is at least as strong as the key it
//! protects (SP 800-57 Pt 1 §5.6.1) — see [`check_wrap_strength`].

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::CK_ULONG;

/// RFC 3394 default initial value.
const KW_IV: [u8; 8] = [0xA6; 8];
/// RFC 5649 alternative initial value prefix.
const KWP_AIV_PREFIX: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];
/// Upper bound on the size of a key accepted for wrapping.
const MAX_WRAP_INPUT: usize = 64 * 1024;

/// Block-cipher abstraction over the three AES key sizes.
trait Block {
    fn enc(&self, block: &mut [u8; 16]);
    fn dec(&self, block: &mut [u8; 16]);
}

impl<C: BlockEncrypt + BlockDecrypt> Block for C {
    fn enc(&self, block: &mut [u8; 16]) {
        self.encrypt_block(GenericArray::from_mut_slice(block));
    }
    fn dec(&self, block: &mut [u8; 16]) {
        self.decrypt_block(GenericArray::from_mut_slice(block));
    }
}

fn with_kek<R>(kek: &[u8], f: impl FnOnce(&dyn Block) -> R) -> HsmResult<R> {
    match kek.len() {
        16 => Ok(f(
            &aes::Aes128::new_from_slice(kek).map_err(|_| HsmError::KeySizeRange)?
        )),
        24 => Ok(f(
            &aes::Aes192::new_from_slice(kek).map_err(|_| HsmError::KeySizeRange)?
        )),
        32 => Ok(f(
            &aes::Aes256::new_from_slice(kek).map_err(|_| HsmError::KeySizeRange)?
        )),
        _ => Err(HsmError::KeySizeRange),
    }
}

/// RFC 3394 §2.2.1 wrapping process W with initial value `a`.
fn w(c: &dyn Block, a: [u8; 8], plaintext: &[u8]) -> Vec<u8> {
    let n = plaintext.len() / 8;
    let mut out = vec![0u8; 8 + plaintext.len()];
    out[8..].copy_from_slice(plaintext);
    let mut a = a;
    let mut b = Zeroizing::new([0u8; 16]);
    for j in 0..6u64 {
        for i in 1..=n {
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(&out[8 * i..8 * i + 8]);
            c.enc(&mut b);
            let t = (n as u64) * j + i as u64;
            a.copy_from_slice(&b[..8]);
            for (x, y) in a.iter_mut().zip(t.to_be_bytes()) {
                *x ^= y;
            }
            out[8 * i..8 * i + 8].copy_from_slice(&b[8..]);
        }
    }
    out[..8].copy_from_slice(&a);
    out
}

/// RFC 3394 §2.2.2 unwrapping process W^-1. Returns (A, P) without checking A.
fn w_inv(c: &dyn Block, ciphertext: &[u8]) -> ([u8; 8], Zeroizing<Vec<u8>>) {
    let n = ciphertext.len() / 8 - 1;
    let mut a = [0u8; 8];
    a.copy_from_slice(&ciphertext[..8]);
    let mut r = Zeroizing::new(ciphertext[8..].to_vec());
    let mut b = Zeroizing::new([0u8; 16]);
    for j in (0..6u64).rev() {
        for i in (1..=n).rev() {
            let t = (n as u64) * j + i as u64;
            for (x, y) in a.iter_mut().zip(t.to_be_bytes()) {
                *x ^= y;
            }
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(&r[8 * (i - 1)..8 * i]);
            c.dec(&mut b);
            a.copy_from_slice(&b[..8]);
            r[8 * (i - 1)..8 * i].copy_from_slice(&b[8..]);
        }
    }
    (a, r)
}

/// AES Key Wrap (RFC 3394 / SP 800-38F KW). Input must be a multiple of
/// 8 bytes and at least 16 bytes.
pub fn aes_key_wrap(wrapping_key: &[u8], key_to_wrap: &[u8]) -> HsmResult<Vec<u8>> {
    if key_to_wrap.len() % 8 != 0 || key_to_wrap.len() < 16 || key_to_wrap.len() > MAX_WRAP_INPUT {
        return Err(HsmError::DataLenRange);
    }
    with_kek(wrapping_key, |c| w(c, KW_IV, key_to_wrap))
}

/// AES Key Unwrap (RFC 3394 / SP 800-38F KW) with constant-time ICV check.
pub fn aes_key_unwrap(wrapping_key: &[u8], wrapped_key: &[u8]) -> HsmResult<Zeroizing<Vec<u8>>> {
    if wrapped_key.len() % 8 != 0
        || wrapped_key.len() < 24
        || wrapped_key.len() > MAX_WRAP_INPUT + 8
    {
        return Err(HsmError::DataLenRange);
    }
    let (mut a, mut p) = with_kek(wrapping_key, |c| w_inv(c, wrapped_key))?;
    let ok = a.ct_eq(&KW_IV);
    a.zeroize();
    if bool::from(ok) {
        Ok(p)
    } else {
        p.zeroize();
        Err(HsmError::EncryptedDataInvalid)
    }
}

/// AES Key Wrap with Padding (RFC 5649 / SP 800-38F KWP). Accepts any key
/// length from 1 byte (e.g. PKCS#8 RSA/EC private keys).
pub fn aes_key_wrap_padded(wrapping_key: &[u8], key_to_wrap: &[u8]) -> HsmResult<Vec<u8>> {
    if key_to_wrap.is_empty() || key_to_wrap.len() > MAX_WRAP_INPUT {
        return Err(HsmError::DataLenRange);
    }
    let mli = key_to_wrap.len() as u32;
    let mut aiv = [0u8; 8];
    aiv[..4].copy_from_slice(&KWP_AIV_PREFIX);
    aiv[4..].copy_from_slice(&mli.to_be_bytes());
    let padded_len = key_to_wrap.len().div_ceil(8) * 8;
    let mut padded = Zeroizing::new(vec![0u8; padded_len]);
    padded[..key_to_wrap.len()].copy_from_slice(key_to_wrap);
    with_kek(wrapping_key, |c| {
        if padded_len == 8 {
            // RFC 5649 §4.1: a single 64-bit block is encrypted with AES in
            // ECB mode together with the AIV.
            let mut b = Zeroizing::new([0u8; 16]);
            b[..8].copy_from_slice(&aiv);
            b[8..].copy_from_slice(&padded);
            c.enc(&mut b);
            b.to_vec()
        } else {
            w(c, aiv, &padded)
        }
    })
}

/// AES Key Unwrap with Padding (RFC 5649) with constant-time checks of the
/// AIV prefix, message length indicator and zero padding.
pub fn aes_key_unwrap_padded(
    wrapping_key: &[u8],
    wrapped_key: &[u8],
) -> HsmResult<Zeroizing<Vec<u8>>> {
    if wrapped_key.len() % 8 != 0
        || wrapped_key.len() < 16
        || wrapped_key.len() > MAX_WRAP_INPUT + 8
    {
        return Err(HsmError::DataLenRange);
    }
    let (mut a, mut p) = with_kek(wrapping_key, |c| {
        if wrapped_key.len() == 16 {
            let mut b = Zeroizing::new([0u8; 16]);
            b.copy_from_slice(wrapped_key);
            c.dec(&mut b);
            let mut a = [0u8; 8];
            a.copy_from_slice(&b[..8]);
            (a, Zeroizing::new(b[8..].to_vec()))
        } else {
            w_inv(c, wrapped_key)
        }
    })?;
    let n = p.len(); // padded length (multiple of 8)
    let mut ok: Choice = a[..4].ct_eq(&KWP_AIV_PREFIX);
    let mli = u32::from_be_bytes([a[4], a[5], a[6], a[7]]) as u64;
    // 8*(n/8 - 1) < MLI <= n  (constant-time comparisons on u64)
    use subtle::ConstantTimeGreater;
    let lower = (n as u64).saturating_sub(8);
    ok &= mli.ct_gt(&lower);
    ok &= !mli.ct_gt(&(n as u64));
    // Padding bytes beyond MLI must be zero (checked over all of the last
    // 8 bytes without branching on MLI).
    let mut pad_nonzero = 0u8;
    for (idx, byte) in p.iter().enumerate().skip(n.saturating_sub(8)) {
        let beyond = (idx as u64).ct_gt(&(mli.wrapping_sub(1))) | (mli.ct_eq(&0));
        pad_nonzero |= u8::conditional_select(&0, byte, beyond);
    }
    ok &= pad_nonzero.ct_eq(&0);
    a.zeroize();
    if bool::from(ok) {
        p.truncate(mli as usize);
        Ok(p)
    } else {
        p.zeroize();
        Err(HsmError::EncryptedDataInvalid)
    }
}

use subtle::ConditionallySelectable;

// ============================================================================
// Key-strength policy (SP 800-57 Part 1 Rev 5, Table 2)
// ============================================================================

/// Security strength (bits) of a key, for the KEK-strength check.
pub fn key_security_strength(
    key_type: CK_ULONG,
    key_len_bytes: usize,
    modulus_bits: Option<CK_ULONG>,
    ec_params: Option<&[u8]>,
) -> u32 {
    match key_type {
        CKK_RSA => match modulus_bits.unwrap_or(0) {
            0..=2047 => 80,
            2048..=3071 => 112,
            3072..=7679 => 128,
            7680..=15359 => 192,
            _ => 256,
        },
        CKK_EC => match ec_params.and_then(crate::crypto::sign::EcCurve::from_ec_params) {
            Some(crate::crypto::sign::EcCurve::P384) => 192,
            _ => 128,
        },
        CKK_EC_EDWARDS | CKK_EC_MONTGOMERY => 128,
        // PQC keys: the stored seed length does not reveal the parameter
        // set; use the lowest category (128) to stay permissive.
        CKK_ML_KEM | CKK_ML_DSA | CKK_SLH_DSA => 128,
        // AES and generic secrets: key length, capped at 256.
        _ => ((key_len_bytes * 8) as u32).min(256),
    }
}

/// Check that an AES KEK of `kek_len_bytes` is at least as strong as a key of
/// strength `target_bits`. Enforced in FIPS approved mode; logged otherwise.
pub fn check_wrap_strength(
    kek_len_bytes: usize,
    target_bits: u32,
    fips_mode: bool,
) -> HsmResult<()> {
    let kek_bits = (kek_len_bytes * 8) as u32;
    if kek_bits >= target_bits {
        return Ok(());
    }
    if fips_mode {
        tracing::error!(
            "Key wrap refused: {}-bit KEK is weaker than the {}-bit-strength key (SP 800-57)",
            kek_bits,
            target_bits
        );
        Err(HsmError::KeySizeRange)
    } else {
        tracing::warn!(
            "Key wrap: {}-bit KEK is weaker than the {}-bit-strength key being wrapped",
            kek_bits,
            target_bits
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn rfc3394_4_6() {
        let kek = h("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key = h("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
        let ct = aes_key_wrap(&kek, &key).unwrap();
        assert_eq!(
            ct,
            h("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
        );
        assert_eq!(&aes_key_unwrap(&kek, &ct).unwrap()[..], &key[..]);
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(aes_key_unwrap(&kek, &bad).is_err());
    }

    #[test]
    fn rfc5649_vectors() {
        let kek = h("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let k20 = h("c37b7e6492584340bed12207808941155068f738");
        let c20 = h("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");
        assert_eq!(aes_key_wrap_padded(&kek, &k20).unwrap(), c20);
        assert_eq!(&aes_key_unwrap_padded(&kek, &c20).unwrap()[..], &k20[..]);
        let k7 = h("466f7250617369");
        let c7 = h("afbeb0f07dfbf5419200f2ccb50bb24f");
        assert_eq!(aes_key_wrap_padded(&kek, &k7).unwrap(), c7);
        assert_eq!(&aes_key_unwrap_padded(&kek, &c7).unwrap()[..], &k7[..]);
        let mut bad = c20.clone();
        bad[31] ^= 0x80;
        assert!(aes_key_unwrap_padded(&kek, &bad).is_err());
        // A KW blob is not a valid KWP blob.
        let kw = aes_key_wrap(&kek, &[0u8; 16]).unwrap();
        assert!(aes_key_unwrap_padded(&kek, &kw).is_err());
    }

    #[test]
    fn kwp_all_lengths_roundtrip() {
        let kek = [0x42u8; 16];
        for len in 1..=70usize {
            let key: Vec<u8> = (0..len as u8).collect();
            let ct = aes_key_wrap_padded(&kek, &key).unwrap();
            assert_eq!(&aes_key_unwrap_padded(&kek, &ct).unwrap()[..], &key[..]);
        }
    }

    #[test]
    fn strength_policy() {
        assert!(check_wrap_strength(16, 112, true).is_ok());
        assert!(check_wrap_strength(16, 192, true).is_err());
        assert!(check_wrap_strength(16, 192, false).is_ok());
        assert_eq!(key_security_strength(CKK_RSA, 0, Some(3072), None), 128);
        assert_eq!(key_security_strength(CKK_AES, 32, None, None), 256);
    }
}
