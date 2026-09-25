// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Default CryptoBackend implementation using RustCrypto crates.
//! Zero-cost delegation to the free functions in the sibling modules.
//!
//! This backend is **not** a FIPS 140-3 validated module
//! (`is_fips_validated() == false`); `fips` builds refuse to run approved
//! services on it.

use zeroize::Zeroizing;

use super::backend::CryptoBackend;
use super::digest::DigestAccumulator;
use super::params::{OaepParams, GCM_IV_LEN};
use super::sign::{EcCurve, HashAlg};
use crate::error::HsmResult;
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;
use crate::store::key_material::RawKeyMaterial;

/// Zero-sized struct — all state lives in the underlying RustCrypto crates.
pub struct RustCryptoBackend;

impl CryptoBackend for RustCryptoBackend {
    fn name(&self) -> &'static str {
        "rustcrypto"
    }

    // ========================================================================
    // Signing
    // ========================================================================

    fn rsa_pkcs1v15_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_pkcs1v15_sign(private_key_der, data, hash_alg)
    }

    fn rsa_pkcs1v15_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<bool> {
        super::sign::rsa_pkcs1v15_verify(modulus, public_exponent, data, signature, hash_alg)
    }

    fn rsa_pss_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_pss_sign(private_key_der, data, hash_alg)
    }

    fn rsa_pss_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        super::sign::rsa_pss_verify(modulus, public_exponent, data, signature, hash_alg)
    }

    fn ecdsa_sign(
        &self,
        curve: EcCurve,
        private_key_bytes: &[u8],
        data: &[u8],
        hash: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>> {
        super::sign::ecdsa_sign(curve, private_key_bytes, data, hash)
    }

    fn ecdsa_verify(
        &self,
        curve: EcCurve,
        public_key_sec1: &[u8],
        data: &[u8],
        signature: &[u8],
        hash: Option<HashAlg>,
    ) -> HsmResult<bool> {
        super::sign::ecdsa_verify(curve, public_key_sec1, data, signature, hash)
    }

    fn ed25519_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        super::sign::ed25519_sign(private_key_bytes, data)
    }

    fn ed25519_verify(
        &self,
        public_key_bytes: &[u8],
        data: &[u8],
        signature_bytes: &[u8],
    ) -> HsmResult<bool> {
        super::sign::ed25519_verify(public_key_bytes, data, signature_bytes)
    }

    // ========================================================================
    // Prehashed signing
    // ========================================================================

    fn rsa_pkcs1v15_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_pkcs1v15_sign_prehashed(private_key_der, digest, hash_alg)
    }

    fn rsa_pkcs1v15_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        super::sign::rsa_pkcs1v15_verify_prehashed(
            modulus,
            public_exponent,
            digest,
            signature,
            hash_alg,
        )
    }

    fn rsa_pss_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_pss_sign_prehashed(private_key_der, digest, hash_alg)
    }

    fn rsa_pss_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        super::sign::rsa_pss_verify_prehashed(modulus, public_exponent, digest, signature, hash_alg)
    }

    // ========================================================================
    // Symmetric primitives
    // ========================================================================

    fn aes_gcm_seal(
        &self,
        key: &[u8],
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        tag_len: usize,
        plaintext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        super::encrypt::aes_gcm_seal_raw(key, iv, aad, tag_len, plaintext)
    }

    fn aes_gcm_open(
        &self,
        key: &[u8],
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        tag_len: usize,
        ct_and_tag: &[u8],
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        super::encrypt::aes_gcm_open_raw(key, iv, aad, tag_len, ct_and_tag)
    }

    fn aes_cbc_encrypt_raw(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        plaintext: &[u8],
        padding: bool,
    ) -> HsmResult<Vec<u8>> {
        super::encrypt::aes_cbc_encrypt_raw(key, iv, plaintext, padding)
    }

    fn aes_cbc_decrypt_raw(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        ciphertext: &[u8],
        padding: bool,
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        super::encrypt::aes_cbc_decrypt_raw(key, iv, ciphertext, padding)
    }

    fn aes_ctr_apply(&self, key: &[u8], iv: &[u8; 16], data: &[u8]) -> HsmResult<Vec<u8>> {
        super::encrypt::aes_ctr_apply_raw(key, iv, data)
    }

    // ========================================================================
    // RSA-OAEP
    // ========================================================================

    fn rsa_oaep_encrypt(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        plaintext: &[u8],
        params: &OaepParams,
    ) -> HsmResult<Vec<u8>> {
        super::sign::rsa_oaep_encrypt_with_params(modulus, public_exponent, plaintext, params)
    }

    fn rsa_oaep_decrypt(
        &self,
        private_key_der: &[u8],
        ciphertext: &[u8],
        params: &OaepParams,
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        super::sign::rsa_oaep_decrypt_with_params(private_key_der, ciphertext, params)
    }

    // ========================================================================
    // Key generation
    // ========================================================================

    fn generate_aes_key(&self, key_len_bytes: usize, fips_mode: bool) -> HsmResult<RawKeyMaterial> {
        super::keygen::generate_aes_key(key_len_bytes, fips_mode)
    }

    fn generate_rsa_key_pair(
        &self,
        modulus_bits: u32,
        fips_mode: bool,
    ) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
        super::keygen::generate_rsa_key_pair(modulus_bits, fips_mode)
    }

    fn generate_ec_p256_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        super::keygen::generate_ec_p256_key_pair()
    }

    fn generate_ec_p384_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        super::keygen::generate_ec_p384_key_pair()
    }

    fn generate_ed25519_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        super::keygen::generate_ed25519_key_pair()
    }

    // ========================================================================
    // Digest
    // ========================================================================

    fn compute_digest(&self, mechanism: CK_MECHANISM_TYPE, data: &[u8]) -> HsmResult<Vec<u8>> {
        super::digest::compute_digest(mechanism, data)
    }

    fn digest_output_len(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<usize> {
        super::digest::digest_output_len(mechanism)
    }

    fn create_hasher(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<Box<dyn DigestAccumulator>> {
        super::digest::create_hasher(mechanism)
    }

    // ========================================================================
    // Key wrap/unwrap
    // ========================================================================

    fn aes_key_wrap(
        &self,
        wrapping_key: &[u8],
        key_to_wrap: &[u8],
        padded: bool,
    ) -> HsmResult<Vec<u8>> {
        if padded {
            super::wrap::aes_key_wrap_padded(wrapping_key, key_to_wrap)
        } else {
            super::wrap::aes_key_wrap(wrapping_key, key_to_wrap)
        }
    }

    fn aes_key_unwrap(
        &self,
        wrapping_key: &[u8],
        wrapped_key: &[u8],
        padded: bool,
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        if padded {
            super::wrap::aes_key_unwrap_padded(wrapping_key, wrapped_key)
        } else {
            super::wrap::aes_key_unwrap(wrapping_key, wrapped_key)
        }
    }

    // ========================================================================
    // Key agreement
    // ========================================================================

    fn ecdh_raw(
        &self,
        curve: EcCurve,
        private_key_bytes: &[u8],
        peer_public_key: &[u8],
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        super::derive::ecdh_raw(curve, private_key_bytes, peer_public_key)
    }
}
