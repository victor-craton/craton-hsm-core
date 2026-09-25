// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Crypto backend trait — abstracts all classical crypto operations behind a
//! trait interface so a FIPS-validated backend (aws-lc-rs) can be swapped in
//! without modifying the PKCS#11 ABI layer.
//!
//! The trait has two kinds of methods:
//! - **Primitives** (required): raw algorithm implementations with explicit,
//!   typed parameters (IV, AAD, tag length, hash, KDF inputs — H2-22).
//! - **Policy entry points** (provided; implementors must not override
//!   them): `aes_gcm_encrypt`, `aes_cbc_encrypt`, `aes_ctr_encrypt`,
//!   `ecdh_derive`, ... These apply the backend-independent controls in
//!   `crypto::encrypt` / `crypto::derive` (IV generation and reuse
//!   detection, invocation limits, size caps, KDF selection) before calling
//!   the primitives, so every backend gets identical protection and produces
//!   identical results (H2-04).
//!
//! PQC operations are excluded: no alternative PQC backends exist yet.

use zeroize::Zeroizing;

use super::digest::DigestAccumulator;
use super::params::{CtrParams, EcdhParams, GcmParams, OaepParams, GCM_IV_LEN};
use super::sign::{EcCurve, HashAlg};
use crate::error::HsmResult;
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;
use crate::store::key_material::RawKeyMaterial;

/// Combined crypto backend trait. Implementors provide all classical crypto operations.
pub trait CryptoBackend: Send + Sync {
    // ========================================================================
    // Identity
    // ========================================================================

    /// Short backend name for logs and diagnostics.
    fn name(&self) -> &'static str {
        "custom"
    }

    /// `true` only for a backend that is a FIPS 140-3 validated module
    /// operating in its approved mode. `fips` builds refuse to start with a
    /// backend that returns `false` (H2-05 / A1-03).
    fn is_fips_validated(&self) -> bool {
        false
    }

    // ========================================================================
    // Random number generation
    // ========================================================================

    /// Fill `out` from the backend's approved DRBG (`C_GenerateRandom`).
    /// Default: the module-wide SP 800-90A HMAC_DRBG.
    fn generate_random(&self, out: &mut [u8]) -> HsmResult<()> {
        super::drbg::fill_random(out)
    }

    /// Mix caller-supplied seed material into the DRBG (`C_SeedRandom`).
    fn seed_random(&self, seed: &[u8]) -> HsmResult<()> {
        super::drbg::seed_random(seed)
    }

    // ========================================================================
    // Signing
    // ========================================================================

    /// RSA PKCS#1 v1.5 sign. `None` = `CKM_RSA_PKCS` (data is a DigestInfo).
    fn rsa_pkcs1v15_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>>;

    fn rsa_pkcs1v15_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<bool>;

    fn rsa_pss_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>>;

    fn rsa_pss_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool>;

    /// ECDSA sign, PKCS#11 raw `r || s` output. `hash == None` is
    /// `CKM_ECDSA` (data is the message hash).
    fn ecdsa_sign(
        &self,
        curve: EcCurve,
        private_key_bytes: &[u8],
        data: &[u8],
        hash: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>>;

    /// ECDSA verify of a PKCS#11 raw `r || s` signature.
    fn ecdsa_verify(
        &self,
        curve: EcCurve,
        public_key_sec1: &[u8],
        data: &[u8],
        signature: &[u8],
        hash: Option<HashAlg>,
    ) -> HsmResult<bool>;

    fn ed25519_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>>;

    fn ed25519_verify(
        &self,
        public_key_bytes: &[u8],
        data: &[u8],
        signature_bytes: &[u8],
    ) -> HsmResult<bool>;

    // ========================================================================
    // Prehashed signing (multi-part C_SignUpdate/C_SignFinal)
    // ========================================================================

    fn rsa_pkcs1v15_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>>;

    fn rsa_pkcs1v15_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool>;

    fn rsa_pss_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>>;

    fn rsa_pss_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool>;

    /// ECDSA over a digest computed by the module (multi-part), any length.
    fn ecdsa_sign_prehashed(
        &self,
        curve: EcCurve,
        private_key_bytes: &[u8],
        digest: &[u8],
    ) -> HsmResult<Vec<u8>> {
        self.ecdsa_sign(curve, private_key_bytes, digest, None)
    }

    /// ECDSA verify over a digest computed by the module (multi-part).
    fn ecdsa_verify_prehashed(
        &self,
        curve: EcCurve,
        public_key_sec1: &[u8],
        digest: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool> {
        self.ecdsa_verify(curve, public_key_sec1, digest, signature, None)
    }

    // ========================================================================
    // Symmetric primitives (no policy — call the policy entry points below)
    // ========================================================================

    /// AES-GCM seal: returns `ciphertext || tag` (tag of `tag_len` bytes).
    fn aes_gcm_seal(
        &self,
        key: &[u8],
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        tag_len: usize,
        plaintext: &[u8],
    ) -> HsmResult<Vec<u8>>;

    /// AES-GCM open: input `ciphertext || tag`.
    fn aes_gcm_open(
        &self,
        key: &[u8],
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        tag_len: usize,
        ct_and_tag: &[u8],
    ) -> HsmResult<Zeroizing<Vec<u8>>>;

    /// AES-CBC encrypt; `padding` selects PKCS#7 (`CKM_AES_CBC_PAD`).
    fn aes_cbc_encrypt_raw(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        plaintext: &[u8],
        padding: bool,
    ) -> HsmResult<Vec<u8>>;

    /// AES-CBC decrypt; `padding` selects PKCS#7 (`CKM_AES_CBC_PAD`).
    fn aes_cbc_decrypt_raw(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        ciphertext: &[u8],
        padding: bool,
    ) -> HsmResult<Zeroizing<Vec<u8>>>;

    /// AES-CTR keystream application (128-bit big-endian counter block).
    fn aes_ctr_apply(&self, key: &[u8], iv: &[u8; 16], data: &[u8]) -> HsmResult<Vec<u8>>;

    // ========================================================================
    // Symmetric policy entry points (provided — do not override)
    // ========================================================================

    /// `CKM_AES_GCM` encrypt honouring `CK_GCM_PARAMS`.
    fn aes_gcm_encrypt(
        &self,
        key: &[u8],
        params: &GcmParams,
        plaintext: &[u8],
        fips_mode: bool,
    ) -> HsmResult<Vec<u8>> {
        let fresh;
        let params = if params.legacy_framing {
            // Deprecated framing: a fresh IV from this backend's approved RBG
            // for every operation.
            let mut iv = [0u8; GCM_IV_LEN];
            self.generate_random(&mut iv)?;
            fresh = GcmParams::legacy(iv);
            &fresh
        } else {
            params
        };
        super::encrypt::gcm_encrypt_with(key, params, plaintext, fips_mode, |k, iv, aad, t, p| {
            self.aes_gcm_seal(k, iv, aad, t, p)
        })
    }

    /// `CKM_AES_GCM` decrypt honouring `CK_GCM_PARAMS`.
    fn aes_gcm_decrypt(
        &self,
        key: &[u8],
        params: &GcmParams,
        data: &[u8],
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        super::encrypt::gcm_decrypt_with(key, params, data, |k, iv, aad, t, c| {
            self.aes_gcm_open(k, iv, aad, t, c)
        })
    }

    /// `CKM_AES_CBC` (`padding == false`) / `CKM_AES_CBC_PAD` encrypt.
    fn aes_cbc_encrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
        padding: bool,
    ) -> HsmResult<Vec<u8>> {
        super::encrypt::cbc_encrypt_with(key, iv, plaintext, padding, |k, iv, p, pad| {
            self.aes_cbc_encrypt_raw(k, iv, p, pad)
        })
    }

    /// `CKM_AES_CBC` (`padding == false`) / `CKM_AES_CBC_PAD` decrypt.
    fn aes_cbc_decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        padding: bool,
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        super::encrypt::cbc_decrypt_with(key, iv, ciphertext, padding, |k, iv, c, pad| {
            self.aes_cbc_decrypt_raw(k, iv, c, pad)
        })
    }

    /// `CKM_AES_CTR` encrypt honouring `CK_AES_CTR_PARAMS`.
    fn aes_ctr_encrypt(
        &self,
        key: &[u8],
        params: &CtrParams,
        plaintext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        super::encrypt::ctr_encrypt_with(key, params, plaintext, |k, iv, d| {
            self.aes_ctr_apply(k, iv, d)
        })
    }

    /// `CKM_AES_CTR` decrypt honouring `CK_AES_CTR_PARAMS`.
    fn aes_ctr_decrypt(
        &self,
        key: &[u8],
        params: &CtrParams,
        ciphertext: &[u8],
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        super::encrypt::ctr_decrypt_with(key, params, ciphertext, |k, iv, d| {
            self.aes_ctr_apply(k, iv, d)
        })
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
    ) -> HsmResult<Vec<u8>>;

    fn rsa_oaep_decrypt(
        &self,
        private_key_der: &[u8],
        ciphertext: &[u8],
        params: &OaepParams,
    ) -> HsmResult<Zeroizing<Vec<u8>>>;

    // ========================================================================
    // Key generation
    // ========================================================================

    fn generate_aes_key(&self, key_len_bytes: usize, fips_mode: bool) -> HsmResult<RawKeyMaterial>;

    /// Returns (private_key_der, public_modulus, public_exponent)
    fn generate_rsa_key_pair(
        &self,
        modulus_bits: u32,
        fips_mode: bool,
    ) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)>;

    /// Returns (private_key_bytes, public_key_sec1_uncompressed)
    fn generate_ec_p256_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)>;

    /// Returns (private_key_bytes, public_key_sec1_uncompressed)
    fn generate_ec_p384_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)>;

    /// Returns (private_key_bytes, public_key_bytes)
    fn generate_ed25519_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)>;

    // ========================================================================
    // Digest
    // ========================================================================

    fn compute_digest(&self, mechanism: CK_MECHANISM_TYPE, data: &[u8]) -> HsmResult<Vec<u8>>;
    fn digest_output_len(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<usize>;
    fn create_hasher(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<Box<dyn DigestAccumulator>>;

    // ========================================================================
    // Key wrap/unwrap
    // ========================================================================

    /// AES key wrap: `padded == false` is `CKM_AES_KEY_WRAP` (RFC 3394),
    /// `true` is `CKM_AES_KEY_WRAP_KWP` (RFC 5649).
    fn aes_key_wrap(
        &self,
        wrapping_key: &[u8],
        key_to_wrap: &[u8],
        padded: bool,
    ) -> HsmResult<Vec<u8>>;

    /// AES key unwrap (see [`CryptoBackend::aes_key_wrap`]).
    fn aes_key_unwrap(
        &self,
        wrapping_key: &[u8],
        wrapped_key: &[u8],
        padded: bool,
    ) -> HsmResult<Zeroizing<Vec<u8>>>;

    // ========================================================================
    // Key agreement / derivation
    // ========================================================================

    /// KAS-ECC-SSC primitive: the shared secret `Z` (x-coordinate), after
    /// full validation of the peer public key.
    fn ecdh_raw(
        &self,
        curve: EcCurve,
        private_key_bytes: &[u8],
        peer_public_key: &[u8],
    ) -> HsmResult<Zeroizing<Vec<u8>>>;

    /// `CKM_ECDH1_DERIVE`: `Z` from [`CryptoBackend::ecdh_raw`] followed by
    /// the KDF selected in `params` (provided — identical on all backends).
    fn ecdh_derive(
        &self,
        curve: EcCurve,
        private_key_bytes: &[u8],
        params: &EcdhParams,
        key_len: usize,
        fips_mode: bool,
    ) -> HsmResult<RawKeyMaterial> {
        let z = self.ecdh_raw(curve, private_key_bytes, &params.public_data)?;
        super::derive::derive_key_from_shared_secret(&z, params, key_len, fips_mode)
    }
}
