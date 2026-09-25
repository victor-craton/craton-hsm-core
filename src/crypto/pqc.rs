// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Post-Quantum Cryptography implementations
//! - ML-KEM (FIPS 203): Key Encapsulation Mechanism
//! - ML-DSA (FIPS 204): Digital Signature Algorithm
//! - SLH-DSA (FIPS 205): Stateless Hash-Based Digital Signature
//!
//! Notes (H2-19, H2-20):
//! - ML-DSA and SLH-DSA signing is **hedged** by default (FIPS 204 §3.4 /
//!   FIPS 205 §9.2 recommendation): fresh randomness from the module DRBG is
//!   mixed into every signature. The deterministic variants and PKCS#11 v3.2
//!   style context strings are available through `*_sign_with`.
//! - Shared secrets and seeds are returned in zeroizing containers; the
//!   crates' `zeroize` features scrub expanded secret keys on drop.
//! - The previous vendor hybrid ML-DSA+ECDSA mechanism was removed: it took
//!   the ECDSA "private key" from the public `CKA_EC_POINT` attribute and had
//!   no domain separation between the component signatures.

use zeroize::Zeroizing;

use crate::error::{HsmError, HsmResult};
use crate::store::key_material::RawKeyMaterial;
use ml_kem::KeyExport;

/// DRBG-backed RNG implementing the rand_core 0.10 traits used by the PQC
/// crates. Routes all PQC randomness through the module-wide SP 800-90A DRBG.
struct PqcDrbgRng;

/// `Error = Infallible`: a DRBG failure latches the module error state and
/// aborts the process (a shared library must not unwind across FFI, and
/// continuing would produce weak keys).
impl rand_core_new::TryRng for PqcDrbgRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        if crate::crypto::drbg::fill_random(dest).is_err() {
            tracing::error!("FATAL: DRBG generate failed in PQC RNG — aborting process");
            std::process::abort();
        }
        Ok(())
    }
}

impl rand_core_new::TryCryptoRng for PqcDrbgRng {}

fn new_rng() -> HsmResult<PqcDrbgRng> {
    if crate::crypto::self_test::is_error_state() {
        return Err(HsmError::GeneralError);
    }
    Ok(PqcDrbgRng)
}

// ============================================================================
// ML-KEM (FIPS 203) — Key Encapsulation
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemVariant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

macro_rules! ml_kem_dispatch {
    ($variant:expr, $P:ident => $body:expr) => {
        match $variant {
            MlKemVariant::MlKem512 => {
                type $P = ml_kem::MlKem512;
                $body
            }
            MlKemVariant::MlKem768 => {
                type $P = ml_kem::MlKem768;
                $body
            }
            MlKemVariant::MlKem1024 => {
                type $P = ml_kem::MlKem1024;
                $body
            }
        }
    };
}

/// Generate an ML-KEM keypair. Returns (dk_seed (d || z, 64 bytes), ek_bytes).
pub fn ml_kem_keygen(variant: MlKemVariant) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    let mut seed = Zeroizing::new([0u8; 64]);
    crate::crypto::drbg::fill_random(&mut *seed)?;
    ml_kem_keygen_from_seed(variant, &seed)
}

/// FIPS 203 ML-KEM.KeyGen_internal from the seed `d || z` (64 bytes).
pub fn ml_kem_keygen_from_seed(
    variant: MlKemVariant,
    seed: &[u8; 64],
) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    let mut s: ml_kem::Seed = (*seed).into();
    let ek = ml_kem_dispatch!(variant, P => {
        let dk = ml_kem::DecapsulationKey::<P>::from_seed(s);
        dk.encapsulation_key().to_bytes()[..].to_vec()
    });
    zeroize::Zeroize::zeroize(&mut s);
    Ok((RawKeyMaterial::new(seed.to_vec()), ek))
}

/// ML-KEM encapsulate: given ek bytes, produce (ciphertext, shared_secret).
pub fn ml_kem_encapsulate(
    ek_bytes: &[u8],
    variant: MlKemVariant,
) -> HsmResult<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    use ml_kem::kem::Encapsulate;
    let mut rng = new_rng()?;
    ml_kem_dispatch!(variant, P => {
        let key: ml_kem::kem::Key<ml_kem::EncapsulationKey<P>> =
            ek_bytes.try_into().map_err(|_| HsmError::KeyHandleInvalid)?;
        let ek = ml_kem::EncapsulationKey::<P>::new(&key).map_err(|_| HsmError::KeyHandleInvalid)?;
        let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
        Ok((ct[..].to_vec(), Zeroizing::new(ss[..].to_vec())))
    })
}

/// FIPS 203 ML-KEM.Encaps_internal with caller-supplied randomness `m`.
/// **Known-answer testing only.**
#[doc(hidden)]
pub fn ml_kem_encapsulate_deterministic(
    ek_bytes: &[u8],
    variant: MlKemVariant,
    m: &[u8; 32],
) -> HsmResult<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let m: ml_kem::B32 = (*m).into();
    ml_kem_dispatch!(variant, P => {
        let key: ml_kem::kem::Key<ml_kem::EncapsulationKey<P>> =
            ek_bytes.try_into().map_err(|_| HsmError::KeyHandleInvalid)?;
        let ek = ml_kem::EncapsulationKey::<P>::new(&key).map_err(|_| HsmError::KeyHandleInvalid)?;
        let (ct, ss) = ek.encapsulate_deterministic(&m);
        Ok((ct[..].to_vec(), Zeroizing::new(ss[..].to_vec())))
    })
}

/// ML-KEM decapsulate: given the dk seed and a ciphertext, recover the shared
/// secret (implicit rejection yields a pseudo-random secret on tampering).
pub fn ml_kem_decapsulate(
    dk_seed: &[u8],
    ciphertext: &[u8],
    variant: MlKemVariant,
) -> HsmResult<Zeroizing<Vec<u8>>> {
    use ml_kem::kem::Decapsulate;
    if dk_seed.len() != 64 {
        return Err(HsmError::KeyHandleInvalid);
    }
    let mut seed: ml_kem::Seed = dk_seed.try_into().map_err(|_| HsmError::KeyHandleInvalid)?;
    let result = ml_kem_dispatch!(variant, P => {
        let dk = ml_kem::DecapsulationKey::<P>::from_seed(seed);
        match ciphertext.try_into() {
            Ok(ct) => Ok(Zeroizing::new(dk.decapsulate(&ct)[..].to_vec())),
            Err(_) => Err(HsmError::EncryptedDataInvalid),
        }
    });
    zeroize::Zeroize::zeroize(&mut seed);
    result
}

// ============================================================================
// ML-DSA (FIPS 204) — Digital Signatures
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaVariant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

/// Signing variant for ML-DSA / SLH-DSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcSigning {
    /// Randomized ("hedged") signing — the default and recommended mode.
    Hedged,
    /// Deterministic signing (FIPS 204 `rnd = 0^256`, FIPS 205
    /// `opt_rand = PK.seed`).
    Deterministic,
}

macro_rules! ml_dsa_dispatch {
    ($variant:expr, $P:ident => $body:expr) => {
        match $variant {
            MlDsaVariant::MlDsa44 => {
                type $P = ml_dsa::MlDsa44;
                $body
            }
            MlDsaVariant::MlDsa65 => {
                type $P = ml_dsa::MlDsa65;
                $body
            }
            MlDsaVariant::MlDsa87 => {
                type $P = ml_dsa::MlDsa87;
                $body
            }
        }
    };
}

/// Generate an ML-DSA keypair. Returns (signing_key_seed_32bytes, verifying_key_bytes).
pub fn ml_dsa_keygen(variant: MlDsaVariant) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    let mut seed = Zeroizing::new([0u8; 32]);
    crate::crypto::drbg::fill_random(&mut *seed)?;
    ml_dsa_keygen_from_seed(variant, &seed)
}

/// FIPS 204 ML-DSA.KeyGen_internal from the seed ξ (32 bytes).
pub fn ml_dsa_keygen_from_seed(
    variant: MlDsaVariant,
    seed: &[u8; 32],
) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    use ml_dsa::KeyGen;
    let mut xi: ml_dsa::B32 = (*seed).into();
    let vk = ml_dsa_dispatch!(variant, P => {
        let kp = P::from_seed(&xi);
        kp.verifying_key().encode()[..].to_vec()
    });
    zeroize::Zeroize::zeroize(&mut xi);
    Ok((RawKeyMaterial::new(seed.to_vec()), vk))
}

/// ML-DSA sign (hedged, empty context).
pub fn ml_dsa_sign(
    signing_key_seed: &[u8],
    data: &[u8],
    variant: MlDsaVariant,
) -> HsmResult<Vec<u8>> {
    ml_dsa_sign_with(signing_key_seed, data, variant, &[], PqcSigning::Hedged)
}

/// ML-DSA sign with a context string (<= 255 bytes) and signing variant.
pub fn ml_dsa_sign_with(
    signing_key_seed: &[u8],
    data: &[u8],
    variant: MlDsaVariant,
    context: &[u8],
    mode: PqcSigning,
) -> HsmResult<Vec<u8>> {
    use ml_dsa::KeyGen;
    if context.len() > 255 {
        return Err(HsmError::MechanismParamInvalid);
    }
    let seed: &[u8; 32] = signing_key_seed
        .try_into()
        .map_err(|_| HsmError::KeyHandleInvalid)?;
    let mut xi: ml_dsa::B32 = (*seed).into();
    let result = ml_dsa_dispatch!(variant, P => {
        let kp = P::from_seed(&xi);
        let sig = match mode {
            PqcSigning::Hedged => {
                let mut rng = new_rng()?;
                kp.signing_key().sign_randomized(data, context, &mut rng)
            }
            PqcSigning::Deterministic => kp.signing_key().sign_deterministic(data, context),
        };
        sig.map(|s| s.encode()[..].to_vec())
            .map_err(|_| HsmError::GeneralError)
    });
    zeroize::Zeroize::zeroize(&mut xi);
    result
}

/// ML-DSA verify (empty context).
pub fn ml_dsa_verify(
    verifying_key_bytes: &[u8],
    data: &[u8],
    signature: &[u8],
    variant: MlDsaVariant,
) -> HsmResult<bool> {
    ml_dsa_verify_with_context(verifying_key_bytes, data, signature, variant, &[])
}

/// ML-DSA verify with a context string.
pub fn ml_dsa_verify_with_context(
    verifying_key_bytes: &[u8],
    data: &[u8],
    signature: &[u8],
    variant: MlDsaVariant,
    context: &[u8],
) -> HsmResult<bool> {
    if context.len() > 255 {
        return Err(HsmError::MechanismParamInvalid);
    }
    ml_dsa_dispatch!(variant, P => {
        let vk_enc: ml_dsa::EncodedVerifyingKey<P> = verifying_key_bytes
            .try_into()
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let vk = ml_dsa::VerifyingKey::<P>::decode(&vk_enc);
        let sig = match ml_dsa::Signature::<P>::try_from(signature) {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };
        Ok(vk.verify_with_context(data, context, &sig))
    })
}

// ============================================================================
// SLH-DSA (FIPS 205) — Hash-Based Signatures
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlhDsaVariant {
    Sha2_128s,
    Sha2_256s,
}

macro_rules! slh_dispatch {
    ($variant:expr, $P:ident => $body:expr) => {
        match $variant {
            SlhDsaVariant::Sha2_128s => {
                type $P = slh_dsa::Sha2_128s;
                $body
            }
            SlhDsaVariant::Sha2_256s => {
                type $P = slh_dsa::Sha2_256s;
                $body
            }
        }
    };
}

/// Generate an SLH-DSA keypair. Returns (signing_key_bytes, verifying_key_bytes).
pub fn slh_dsa_keygen(variant: SlhDsaVariant) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    use slh_dsa::signature::Keypair;
    let mut rng = new_rng()?;
    slh_dispatch!(variant, P => {
        let sk = slh_dsa::SigningKey::<P>::new(&mut rng);
        let vk = sk.verifying_key();
        let sk_bytes = Zeroizing::new(sk.to_bytes()[..].to_vec());
        Ok((RawKeyMaterial::new(sk_bytes.to_vec()), vk.to_bytes()[..].to_vec()))
    })
}

/// SLH-DSA sign (hedged, empty context).
pub fn slh_dsa_sign(
    signing_key_bytes: &[u8],
    data: &[u8],
    variant: SlhDsaVariant,
) -> HsmResult<Vec<u8>> {
    slh_dsa_sign_with(signing_key_bytes, data, variant, &[], PqcSigning::Hedged)
}

/// SLH-DSA sign with a context string (<= 255 bytes) and signing variant.
pub fn slh_dsa_sign_with(
    signing_key_bytes: &[u8],
    data: &[u8],
    variant: SlhDsaVariant,
    context: &[u8],
    mode: PqcSigning,
) -> HsmResult<Vec<u8>> {
    if context.len() > 255 {
        return Err(HsmError::MechanismParamInvalid);
    }
    slh_dispatch!(variant, P => {
        let sk = slh_dsa::SigningKey::<P>::try_from(signing_key_bytes)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        // opt_rand is n bytes (16 for the 128-bit, 32 for the 256-bit set).
        let n = signing_key_bytes.len() / 4;
        let mut rand = Zeroizing::new(vec![0u8; n]);
        let opt_rand = match mode {
            PqcSigning::Hedged => {
                crate::crypto::drbg::fill_random(&mut rand)?;
                Some(&rand[..])
            }
            PqcSigning::Deterministic => None,
        };
        let sig = sk
            .try_sign_with_context(data, context, opt_rand)
            .map_err(|_| HsmError::GeneralError)?;
        Ok(sig.to_bytes()[..].to_vec())
    })
}

/// SLH-DSA verify (empty context).
pub fn slh_dsa_verify(
    verifying_key_bytes: &[u8],
    data: &[u8],
    signature: &[u8],
    variant: SlhDsaVariant,
) -> HsmResult<bool> {
    slh_dsa_verify_with_context(verifying_key_bytes, data, signature, variant, &[])
}

/// SLH-DSA verify with a context string.
pub fn slh_dsa_verify_with_context(
    verifying_key_bytes: &[u8],
    data: &[u8],
    signature: &[u8],
    variant: SlhDsaVariant,
    context: &[u8],
) -> HsmResult<bool> {
    if context.len() > 255 {
        return Err(HsmError::MechanismParamInvalid);
    }
    slh_dispatch!(variant, P => {
        let vk = slh_dsa::VerifyingKey::<P>::try_from(verifying_key_bytes)
            .map_err(|_| HsmError::KeyHandleInvalid)?;
        let sig = match slh_dsa::Signature::<P>::try_from(signature) {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };
        Ok(vk.try_verify_with_context(data, context, &sig).is_ok())
    })
}

// ============================================================================
// Helpers
// ============================================================================

pub fn mechanism_to_ml_kem_variant(
    mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE,
) -> Option<MlKemVariant> {
    use crate::pkcs11_abi::constants::*;
    match mechanism {
        CKM_ML_KEM_512 => Some(MlKemVariant::MlKem512),
        CKM_ML_KEM_768 => Some(MlKemVariant::MlKem768),
        CKM_ML_KEM_1024 => Some(MlKemVariant::MlKem1024),
        _ => None,
    }
}

pub fn mechanism_to_ml_dsa_variant(
    mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE,
) -> Option<MlDsaVariant> {
    use crate::pkcs11_abi::constants::*;
    match mechanism {
        CKM_ML_DSA_44 => Some(MlDsaVariant::MlDsa44),
        CKM_ML_DSA_65 => Some(MlDsaVariant::MlDsa65),
        CKM_ML_DSA_87 => Some(MlDsaVariant::MlDsa87),
        _ => None,
    }
}

pub fn mechanism_to_slh_dsa_variant(
    mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE,
) -> Option<SlhDsaVariant> {
    use crate::pkcs11_abi::constants::*;
    match mechanism {
        CKM_SLH_DSA_SHA2_128S => Some(SlhDsaVariant::Sha2_128s),
        CKM_SLH_DSA_SHA2_256S => Some(SlhDsaVariant::Sha2_256s),
        _ => None,
    }
}

pub fn is_ml_kem_mechanism(mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE) -> bool {
    mechanism_to_ml_kem_variant(mechanism).is_some()
}

pub fn is_ml_dsa_mechanism(mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE) -> bool {
    mechanism_to_ml_dsa_variant(mechanism).is_some()
}

pub fn is_slh_dsa_mechanism(mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE) -> bool {
    mechanism_to_slh_dsa_variant(mechanism).is_some()
}

/// The vendor hybrid ML-DSA+ECDSA mechanism is no longer supported
/// (H2-19 / A2-18). Retained so callers can recognise and reject it.
pub fn is_hybrid_mechanism(mechanism: crate::pkcs11_abi::types::CK_MECHANISM_TYPE) -> bool {
    mechanism == crate::pkcs11_abi::constants::CKM_HYBRID_ML_DSA_ECDSA
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa_hedged_differs_deterministic_repeats() {
        let (sk, vk) = ml_dsa_keygen(MlDsaVariant::MlDsa44).unwrap();
        let a = ml_dsa_sign(sk.as_bytes(), b"m", MlDsaVariant::MlDsa44).unwrap();
        let b = ml_dsa_sign(sk.as_bytes(), b"m", MlDsaVariant::MlDsa44).unwrap();
        assert_ne!(a, b, "hedged signatures must be randomized");
        assert!(ml_dsa_verify(&vk, b"m", &a, MlDsaVariant::MlDsa44).unwrap());
        let d1 = ml_dsa_sign_with(
            sk.as_bytes(),
            b"m",
            MlDsaVariant::MlDsa44,
            b"ctx",
            PqcSigning::Deterministic,
        )
        .unwrap();
        let d2 = ml_dsa_sign_with(
            sk.as_bytes(),
            b"m",
            MlDsaVariant::MlDsa44,
            b"ctx",
            PqcSigning::Deterministic,
        )
        .unwrap();
        assert_eq!(d1, d2);
        assert!(ml_dsa_verify_with_context(&vk, b"m", &d1, MlDsaVariant::MlDsa44, b"ctx").unwrap());
        assert!(!ml_dsa_verify(&vk, b"m", &d1, MlDsaVariant::MlDsa44).unwrap());
    }
}
