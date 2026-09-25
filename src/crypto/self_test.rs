// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! FIPS 140-3 pre-operational self-tests (POST), cryptographic algorithm
//! self-tests (CASTs) and the module error state (A1-04, H2-08).
//!
//! Every CAST compares the **full output** against a fixed known answer
//! (no round-trip "KATs"); signature CASTs use fixed keys. Sources:
//! FIPS 180-4 / FIPS 202 examples, RFC 4231, the McGrew–Viega GCM test cases,
//! SP 800-38A F.2.5 / F.5.5, RFC 3394 §4.6, RFC 5649 §6, RFC 8032 §7.1,
//! RFC 5869 A.1, RFC 7914 §11 (PBKDF2-HMAC-SHA256), the NIST CAVP HMAC_DRBG
//! vector, and vectors produced with independent implementations (OpenSSL 3
//! for RSA / ECDSA / ECDH, pyca/cryptography for X9.63-KDF and KWP with a
//! 256-bit KEK, kyber-py / dilithium-py / slh-dsa (Python) for ML-KEM,
//! ML-DSA and SLH-DSA). The RSA/PQC artefacts live in `src/crypto/kat/`.
//! The RSA key there is a **test key** used only by the self-test.
//!
//! Ordering (IG 10.3.B): the SHA-256, SHA-512 and Ed25519 CASTs run before
//! the software integrity test that uses those algorithms.
//!
//! Two entry points:
//! - [`run_post`]: algorithm tests for the software implementations used
//!   regardless of backend (digests/HMAC/DRBG/KDFs/PQC, integrity test).
//! - [`run_backend_post`]: CASTs executed **through the selected
//!   `CryptoBackend`** (AES-GCM/CBC/CTR/KW/KWP, RSA, ECDSA, ECDH, Ed25519,
//!   digests, RNG). In `fips` builds it also refuses a backend that is not a
//!   validated module (H2-05 / A1-03).
//!
//! Any failure latches the module error state ([`enter_error_state`]); the
//! PKCS#11 layer refuses all services while it is set. IV-reuse trackers and
//! other global state are *not* touched by the self-tests.

use std::sync::atomic::{AtomicBool, Ordering};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::backend::CryptoBackend;
use crate::crypto::params::{EcdhKdf, OaepParams};
use crate::crypto::sign::{EcCurve, HashAlg, OaepHash};
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;

// ============================================================================
// Error state
// ============================================================================

static ERROR_STATE: AtomicBool = AtomicBool::new(false);

/// Enter the module error state (latched until the next successful POST).
pub fn enter_error_state(reason: &str) {
    if !ERROR_STATE.swap(true, Ordering::AcqRel) {
        tracing::error!("Cryptographic module entering ERROR STATE: {}", reason);
    }
}

/// Whether the module is in the error state.
pub fn is_error_state() -> bool {
    ERROR_STATE.load(Ordering::Acquire)
}

fn fail(what: &str) -> HsmError {
    enter_error_state(what);
    HsmError::GeneralError
}

fn check(ok: bool, what: &str) -> HsmResult<()> {
    if ok {
        Ok(())
    } else {
        tracing::error!("Self-test failed: {}", what);
        Err(fail(what))
    }
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("static KAT hex")
}

fn eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

// ============================================================================
// Known-answer vectors
// ============================================================================

const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const SHA384_ABC: &str = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
const SHA512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
const SHA3_256_ABC: &str = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
const SHA3_384_ABC: &str = "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25";
const SHA3_512_ABC: &str = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";

// RFC 4231 test case 2
const HMAC_KEY: &[u8] = b"Jefe";
const HMAC_DATA: &[u8] = b"what do ya want for nothing?";
const HMAC_SHA256: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
const HMAC_SHA384: &str = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649";
const HMAC_SHA512: &str = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";

// RFC 8032 §7.1 TEST 1 (empty message)
const ED25519_SK: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const ED25519_PK: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const ED25519_SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

// McGrew–Viega GCM test cases 16 (AES-256) and 4 (AES-128)
const GCM_KEY256: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
const GCM_KEY128: &str = "feffe9928665731c6d6a8f9467308308";
const GCM_IV: &str = "cafebabefacedbaddecaf888";
const GCM_PT: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
const GCM_AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
const GCM_CT256: &str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b";
const GCM_CT128: &str = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47";

// SP 800-38A F.2.5 (CBC-AES256) and F.5.5 (CTR-AES256)
const AES256_KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const CBC_IV: &str = "000102030405060708090a0b0c0d0e0f";
const CTR_IV: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const SP800_38A_PT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
const CBC_CT: &str = "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b";
const CTR_CT: &str = "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6";

// RFC 3394 §4.6 (256-bit KEK, 256-bit key) and KWP with the same KEK
const KW_KEK: &str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
const KW_KEY: &str = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
const KW_CT: &str = "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21";
const KWP_KEY: &str = "c37b7e6492584340bed12207808941155068f738";
const KWP_CT: &str = "29b7fa191c2165684374eee9f74595e2a42bace75c425b3053efa26ffe1bb32f";

// RSA-2048 test key (OpenSSL 3 generated); message and known answers
const RSA_KAT_PK8: &[u8] = include_bytes!("kat/rsa2048.pk8");
const RSA_KAT_N: &[u8] = include_bytes!("kat/rsa2048.n");
const RSA_KAT_E: &[u8] = &[0x01, 0x00, 0x01];
const RSA_KAT_MSG: &[u8] = b"Craton HSM RSA KAT message";
const RSA_KAT_PKCS1_SHA256_SIG: &[u8] = include_bytes!("kat/rsa_pkcs1_sha256.sig");
const RSA_KAT_PSS_SHA256_SIG: &[u8] = include_bytes!("kat/rsa_pss_sha256.sig");
const RSA_KAT_OAEP_SHA256_CT: &[u8] = include_bytes!("kat/rsa_oaep_sha256.ct");

// ECDSA / ECDH (OpenSSL 3 / pyca-generated signatures; raw r || s)
const P256_D: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const P256_Q: &str = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
const EC_KAT_MSG: &[u8] = b"Craton HSM ECDSA KAT message";
const P256_SIG: &str = "ac04800e3520deb3be2b7d2539a7e9e93e41a07f76e34a608b749b067b10f2b8116d4d59befec535b4446bd1a7db66494d102f4bd832ad08e2adc284694e7c35";
const P384_Q: &str = "04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720";
const P384_SIG: &str = "77d67d0be87ceef9418bd0beca15c6646cbfe871297d0742ece29834fc52c7823a220d83f9a12d6d86e7bf665389e0bc85f6457dc5d1ef5e294b9971305b2187cd8e67f83c0074b4af23a4d8f7e467b6f790492ba64fa2ca2426645e920b85d4";
const ECDH_QB: &str = "04119f2f047902782ab0c9e27a54aff5eb9b964829ca99c06b02ddba95b0a3f6d08f52b726664cac366fc98ac7a012b2682cbd962e5acb544671d41b9445704d1d";
const ECDH_Z: &str = "d7f9d24e542ba405488220a065e71b0e125974c10d065e4522291e5453fa9531";
const X963_SHARED_INFO: &[u8] = b"CratonHSM KAS KAT";
const X963_SHA256_32: &str = "7a7f1239f6d369eae3ccc016ee8799a538b3be6f85d7eb36835acd67f5b311ca";

// RFC 5869 A.1 (HKDF-SHA256) and RFC 7914 §11 (PBKDF2-HMAC-SHA256, c = 1)
const HKDF_IKM: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
const HKDF_SALT: &str = "000102030405060708090a0b0c";
const HKDF_INFO: &str = "f0f1f2f3f4f5f6f7f8f9";
const HKDF_OKM: &str = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
const PBKDF2_OUT: &str = "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783";

// ML-KEM-768 (kyber-py): seed d||z = 00..3f, m = a5*32
const MLKEM_EK_SHA256: &str = "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9";
const MLKEM_CT: &[u8] = include_bytes!("kat/mlkem768.ct");
const MLKEM_SS: &str = "e99b5205edfaec7c0a9686684256dfd4a25a4ff4d760ef69f913e9878c05c4ca";
const MLKEM_REJECT_SS: &str = "9e40bf84f54a7d492b103ac3e0779474c4e7c1e43dadeca06c7d3a5d321020cf";

// ML-DSA-44 (dilithium-py): xi = 20..3f, deterministic, empty context
const MLDSA_MSG: &[u8] = b"Craton HSM ML-DSA KAT message";
const MLDSA_VK_SHA256: &str = "098600b859a74a77370f560491923a2fed4464b245e8c7aff5255eb28bb3abf1";
const MLDSA_SIG_SHA256: &str = "73afdc2b859fc345cf42bf61702b873d22f1371d5aeaf9c6fddaf8b5bf2b1dfb";

// SLH-DSA-SHA2-128s (Python slh-dsa): pure, empty context, deterministic
const SLH_PK: &str = "202122232425262728292a2b2c2d2e2f990ce6298792b128846a8e4a3a68954c";
const SLH_MSG: &[u8] = b"Craton HSM SLH-DSA KAT message";
const SLH_SIG: &[u8] = include_bytes!("kat/slhdsa128s.sig");

// ============================================================================
// Entry points
// ============================================================================

/// Pre-operational self-tests for the software implementations used
/// independently of the selected backend, including the integrity test.
/// Clears a previous error state first; any failure latches it again.
pub fn run_post() -> HsmResult<()> {
    ERROR_STATE.store(false, Ordering::Release);
    let r = run_post_inner();
    if r.is_err() {
        enter_error_state("power-on self-test failed");
    }
    r
}

fn run_post_inner() -> HsmResult<()> {
    // IG 10.3.B: CASTs for the integrity-test algorithms come first.
    sha2_kats()?;
    ed25519_software_kat()?;

    // §9.4 software integrity test (Ed25519 over SHA-256 of the module).
    if let Err(msg) = crate::crypto::integrity::check_integrity() {
        tracing::error!("POST: Software integrity test failed: {}", msg);
        return Err(fail("software integrity test"));
    }

    sha3_kats()?;
    hmac_kats()?;
    crate::crypto::drbg::drbg_kat().map_err(|_| fail("HMAC_DRBG KAT"))?;
    kdf_kats()?;
    ml_kem_kat()?;
    ml_dsa_kat()?;
    slh_dsa_kat()?;
    Ok(())
}

/// CASTs executed through `backend` (the implementation that serves the
/// cryptographic services). In `fips` builds a backend that is not a
/// validated module is refused. `fips_approved_only` reflects the runtime
/// approved-mode configuration.
pub fn run_backend_post(backend: &dyn CryptoBackend, fips_approved_only: bool) -> HsmResult<()> {
    #[cfg(feature = "fips")]
    if !backend.is_fips_validated() {
        let _ = fips_approved_only;
        return Err(fail(
            "FIPS build: the selected crypto backend is not a validated module (use crypto_backend = \"awslc\")",
        ));
    }
    #[cfg(not(feature = "fips"))]
    if fips_approved_only && !backend.is_fips_validated() {
        tracing::warn!(
            "FIPS approved mode is configured but the '{}' backend is not a FIPS-validated \
             module; services are NOT FIPS approved. Build with --features fips.",
            backend.name()
        );
    }
    let r = backend_casts(backend);
    if r.is_err() {
        enter_error_state("backend self-test failed");
    }
    r
}

/// Convenience: [`run_post`] followed by [`run_backend_post`]. Embedders that
/// construct `HsmCore` directly (daemon, admin tools) should call this.
pub fn run_post_with_backend(
    backend: &dyn CryptoBackend,
    fips_approved_only: bool,
) -> HsmResult<()> {
    run_post()?;
    run_backend_post(backend, fips_approved_only)
}

// ============================================================================
// Software CASTs
// ============================================================================

fn sha2_kats() -> HsmResult<()> {
    use sha2::{Digest, Sha256, Sha384, Sha512};
    check(eq(&Sha256::digest(b"abc"), &h(SHA256_ABC)), "SHA-256 KAT")?;
    check(eq(&Sha384::digest(b"abc"), &h(SHA384_ABC)), "SHA-384 KAT")?;
    check(eq(&Sha512::digest(b"abc"), &h(SHA512_ABC)), "SHA-512 KAT")
}

fn sha3_kats() -> HsmResult<()> {
    use sha3::{Digest, Sha3_256, Sha3_384, Sha3_512};
    check(eq(&Sha3_256::digest(b"abc"), &h(SHA3_256_ABC)), "SHA3-256 KAT")?;
    check(eq(&Sha3_384::digest(b"abc"), &h(SHA3_384_ABC)), "SHA3-384 KAT")?;
    check(eq(&Sha3_512::digest(b"abc"), &h(SHA3_512_ABC)), "SHA3-512 KAT")
}

fn hmac_kats() -> HsmResult<()> {
    use hmac::{Hmac, Mac};
    fn mac<M: Mac + hmac::digest::KeyInit>(expected: &str) -> bool {
        let Ok(mut m) = <M as Mac>::new_from_slice(HMAC_KEY) else {
            return false;
        };
        m.update(HMAC_DATA);
        eq(&m.finalize().into_bytes(), &h(expected))
    }
    check(mac::<Hmac<sha2::Sha256>>(HMAC_SHA256), "HMAC-SHA256 KAT")?;
    check(mac::<Hmac<sha2::Sha384>>(HMAC_SHA384), "HMAC-SHA384 KAT")?;
    check(mac::<Hmac<sha2::Sha512>>(HMAC_SHA512), "HMAC-SHA512 KAT")
}

/// Ed25519 sign + verify KAT on the RustCrypto implementation (the
/// integrity-test algorithm).
fn ed25519_software_kat() -> HsmResult<()> {
    let sig = crate::crypto::sign::ed25519_sign(&h(ED25519_SK), b"")
        .map_err(|_| fail("Ed25519 sign KAT"))?;
    check(eq(&sig, &h(ED25519_SIG)), "Ed25519 sign KAT")?;
    let ok = crate::crypto::sign::ed25519_verify(&h(ED25519_PK), b"", &sig).unwrap_or(false);
    let mut bad = sig.clone();
    bad[0] ^= 1;
    let bad_ok = crate::crypto::sign::ed25519_verify(&h(ED25519_PK), b"", &bad).unwrap_or(true);
    check(ok && !bad_ok, "Ed25519 verify KAT")
}

fn kdf_kats() -> HsmResult<()> {
    let okm = crate::crypto::derive::hkdf_sha256(&h(HKDF_SALT), &h(HKDF_IKM), &h(HKDF_INFO), 42)
        .map_err(|_| fail("HKDF KAT"))?;
    check(eq(&okm, &h(HKDF_OKM)), "HKDF-SHA256 KAT")?;

    let mut out = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"passwd", b"salt", 1, &mut *out);
    check(eq(&*out, &h(PBKDF2_OUT)), "PBKDF2-HMAC-SHA256 KAT")?;

    let k = crate::crypto::derive::x963_kdf(EcdhKdf::Sha256, &h(ECDH_Z), X963_SHARED_INFO, 32)
        .map_err(|_| fail("X9.63 KDF KAT"))?;
    check(eq(&k, &h(X963_SHA256_32)), "X9.63-KDF (SP 800-56C one-step) KAT")
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(data).to_vec()
}

/// ML-KEM-768: KeyGen, Encaps, Decaps and implicit rejection (FIPS 203).
fn ml_kem_kat() -> HsmResult<()> {
    use crate::crypto::pqc::{self, MlKemVariant::MlKem768};
    let mut seed = [0u8; 64];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8;
    }
    let (dk, ek) = pqc::ml_kem_keygen_from_seed(MlKem768, &seed).map_err(|_| fail("ML-KEM KAT"))?;
    check(eq(&sha256(&ek), &h(MLKEM_EK_SHA256)), "ML-KEM-768 KeyGen KAT")?;
    let (ct, ss) = pqc::ml_kem_encapsulate_deterministic(&ek, MlKem768, &[0xA5; 32])
        .map_err(|_| fail("ML-KEM KAT"))?;
    check(eq(&ct, MLKEM_CT) && eq(&ss, &h(MLKEM_SS)), "ML-KEM-768 Encaps KAT")?;
    let ss2 = pqc::ml_kem_decapsulate(dk.as_bytes(), MLKEM_CT, MlKem768)
        .map_err(|_| fail("ML-KEM KAT"))?;
    check(eq(&ss2, &h(MLKEM_SS)), "ML-KEM-768 Decaps KAT")?;
    let mut bad = MLKEM_CT.to_vec();
    bad[0] ^= 1;
    let rej = pqc::ml_kem_decapsulate(dk.as_bytes(), &bad, MlKem768)
        .map_err(|_| fail("ML-KEM KAT"))?;
    check(eq(&rej, &h(MLKEM_REJECT_SS)), "ML-KEM-768 implicit rejection KAT")
}

/// ML-DSA-44: KeyGen, deterministic Sign and Verify (FIPS 204).
fn ml_dsa_kat() -> HsmResult<()> {
    use crate::crypto::pqc::{self, MlDsaVariant::MlDsa44, PqcSigning};
    let mut xi = [0u8; 32];
    for (i, b) in xi.iter_mut().enumerate() {
        *b = 32 + i as u8;
    }
    let (sk, vk) = pqc::ml_dsa_keygen_from_seed(MlDsa44, &xi).map_err(|_| fail("ML-DSA KAT"))?;
    check(eq(&sha256(&vk), &h(MLDSA_VK_SHA256)), "ML-DSA-44 KeyGen KAT")?;
    let sig = pqc::ml_dsa_sign_with(sk.as_bytes(), MLDSA_MSG, MlDsa44, &[], PqcSigning::Deterministic)
        .map_err(|_| fail("ML-DSA KAT"))?;
    check(eq(&sha256(&sig), &h(MLDSA_SIG_SHA256)), "ML-DSA-44 Sign KAT")?;
    let ok = pqc::ml_dsa_verify(&vk, MLDSA_MSG, &sig, MlDsa44).unwrap_or(false);
    let bad_ok = pqc::ml_dsa_verify(&vk, b"other", &sig, MlDsa44).unwrap_or(true);
    check(ok && !bad_ok, "ML-DSA-44 Verify KAT")
}

/// SLH-DSA-SHA2-128s: verification of a known signature (FIPS 205). The
/// signing CAST is covered by the pairwise consistency test at key
/// generation; a signing KAT here would add ~seconds to every POST.
fn slh_dsa_kat() -> HsmResult<()> {
    use crate::crypto::pqc::{self, SlhDsaVariant::Sha2_128s};
    let pk = h(SLH_PK);
    let ok = pqc::slh_dsa_verify(&pk, SLH_MSG, SLH_SIG, Sha2_128s).unwrap_or(false);
    let mut bad = SLH_SIG.to_vec();
    bad[100] ^= 1;
    let bad_ok = pqc::slh_dsa_verify(&pk, SLH_MSG, &bad, Sha2_128s).unwrap_or(true);
    check(ok && !bad_ok, "SLH-DSA-SHA2-128s Verify KAT")
}

// ============================================================================
// Backend CASTs
// ============================================================================

fn backend_casts(b: &dyn CryptoBackend) -> HsmResult<()> {
    // Digests
    for (mech, exp) in [
        (CKM_SHA256, SHA256_ABC),
        (CKM_SHA384, SHA384_ABC),
        (CKM_SHA512, SHA512_ABC),
        (CKM_SHA3_256, SHA3_256_ABC),
        (CKM_SHA3_384, SHA3_384_ABC),
        (CKM_SHA3_512, SHA3_512_ABC),
    ] {
        let d = b.compute_digest(mech, b"abc").map_err(|_| fail("digest KAT"))?;
        check(eq(&d, &h(exp)), "backend digest KAT")?;
    }

    // AES-GCM encrypt and decrypt (AES-256 and AES-128)
    let iv: [u8; 12] = h(GCM_IV).try_into().expect("12-byte IV");
    for (key, exp) in [(GCM_KEY256, GCM_CT256), (GCM_KEY128, GCM_CT128)] {
        let ct = b
            .aes_gcm_seal(&h(key), &iv, &h(GCM_AAD), 16, &h(GCM_PT))
            .map_err(|_| fail("AES-GCM KAT"))?;
        check(eq(&ct, &h(exp)), "AES-GCM encrypt KAT")?;
        let pt = b
            .aes_gcm_open(&h(key), &iv, &h(GCM_AAD), 16, &h(exp))
            .map_err(|_| fail("AES-GCM KAT"))?;
        check(eq(&pt, &h(GCM_PT)), "AES-GCM decrypt KAT")?;
        let mut bad = h(exp);
        bad[0] ^= 1;
        check(
            b.aes_gcm_open(&h(key), &iv, &h(GCM_AAD), 16, &bad).is_err(),
            "AES-GCM tag check KAT",
        )?;
    }

    // AES-CBC / AES-CTR (SP 800-38A), through the primitives so the IV-reuse
    // trackers are not touched.
    let key = h(AES256_KEY);
    let cbc_iv: [u8; 16] = h(CBC_IV).try_into().expect("16-byte IV");
    let ctr_iv: [u8; 16] = h(CTR_IV).try_into().expect("16-byte IV");
    let ct = b
        .aes_cbc_encrypt_raw(&key, &cbc_iv, &h(SP800_38A_PT), false)
        .map_err(|_| fail("AES-CBC KAT"))?;
    check(eq(&ct, &h(CBC_CT)), "AES-CBC encrypt KAT")?;
    let pt = b
        .aes_cbc_decrypt_raw(&key, &cbc_iv, &h(CBC_CT), false)
        .map_err(|_| fail("AES-CBC KAT"))?;
    check(eq(&pt, &h(SP800_38A_PT)), "AES-CBC decrypt KAT")?;
    let ct = b
        .aes_ctr_apply(&key, &ctr_iv, &h(SP800_38A_PT))
        .map_err(|_| fail("AES-CTR KAT"))?;
    check(eq(&ct, &h(CTR_CT)), "AES-CTR KAT")?;

    // AES-KW / AES-KWP (SP 800-38F)
    let kek = h(KW_KEK);
    let w = b
        .aes_key_wrap(&kek, &h(KW_KEY), false)
        .map_err(|_| fail("AES-KW KAT"))?;
    check(eq(&w, &h(KW_CT)), "AES-KW wrap KAT")?;
    let u = b
        .aes_key_unwrap(&kek, &h(KW_CT), false)
        .map_err(|_| fail("AES-KW KAT"))?;
    check(eq(&u, &h(KW_KEY)), "AES-KW unwrap KAT")?;
    let w = b
        .aes_key_wrap(&kek, &h(KWP_KEY), true)
        .map_err(|_| fail("AES-KWP KAT"))?;
    check(eq(&w, &h(KWP_CT)), "AES-KWP wrap KAT")?;
    let u = b
        .aes_key_unwrap(&kek, &h(KWP_CT), true)
        .map_err(|_| fail("AES-KWP KAT"))?;
    check(eq(&u, &h(KWP_KEY)), "AES-KWP unwrap KAT")?;

    // RSA: PKCS#1 v1.5 SigGen (deterministic) with a fixed key, SigVer,
    // PSS SigVer and OAEP decryption of known answers.
    let sig = b
        .rsa_pkcs1v15_sign(RSA_KAT_PK8, RSA_KAT_MSG, Some(HashAlg::Sha256))
        .map_err(|_| fail("RSA KAT"))?;
    check(eq(&sig, RSA_KAT_PKCS1_SHA256_SIG), "RSA PKCS#1 v1.5 SigGen KAT")?;
    let ok = b
        .rsa_pkcs1v15_verify(RSA_KAT_N, RSA_KAT_E, RSA_KAT_MSG, RSA_KAT_PKCS1_SHA256_SIG, Some(HashAlg::Sha256))
        .unwrap_or(false);
    check(ok, "RSA PKCS#1 v1.5 SigVer KAT")?;
    let ok = b
        .rsa_pss_verify(RSA_KAT_N, RSA_KAT_E, RSA_KAT_MSG, RSA_KAT_PSS_SHA256_SIG, HashAlg::Sha256)
        .unwrap_or(false);
    check(ok, "RSA-PSS SigVer KAT")?;
    let pt = b
        .rsa_oaep_decrypt(RSA_KAT_PK8, RSA_KAT_OAEP_SHA256_CT, &OaepParams::new(OaepHash::Sha256))
        .map_err(|_| fail("RSA-OAEP KAT"))?;
    check(eq(&pt, RSA_KAT_MSG), "RSA-OAEP decrypt KAT")?;
    // Release the KAT key from the parsed-key cache.
    crate::crypto::sign::evict_rsa_key(RSA_KAT_PK8);

    // ECDSA: SigVer of known signatures (P-256/SHA-256, P-384/SHA-384) and a
    // SigGen with a fixed key checked by verification.
    let d = h(P256_D);
    let q = h(P256_Q);
    let ok = b
        .ecdsa_verify(EcCurve::P256, &q, EC_KAT_MSG, &h(P256_SIG), Some(HashAlg::Sha256))
        .unwrap_or(false);
    check(ok, "ECDSA P-256 SigVer KAT")?;
    let ok = b
        .ecdsa_verify(EcCurve::P384, &h(P384_Q), EC_KAT_MSG, &h(P384_SIG), Some(HashAlg::Sha384))
        .unwrap_or(false);
    check(ok, "ECDSA P-384 SigVer KAT")?;
    let mut bad = h(P256_SIG);
    bad[5] ^= 1;
    let bad_ok = b
        .ecdsa_verify(EcCurve::P256, &q, EC_KAT_MSG, &bad, Some(HashAlg::Sha256))
        .unwrap_or(true);
    check(!bad_ok, "ECDSA SigVer negative KAT")?;
    let sig = b
        .ecdsa_sign(EcCurve::P256, &d, EC_KAT_MSG, Some(HashAlg::Sha256))
        .map_err(|_| fail("ECDSA SigGen KAT"))?;
    let ok = b
        .ecdsa_verify(EcCurve::P256, &q, EC_KAT_MSG, &sig, Some(HashAlg::Sha256))
        .unwrap_or(false);
    check(ok && sig.len() == 64, "ECDSA P-256 SigGen KAT")?;

    // KAS-ECC-SSC primitive (shared secret Z).
    let z = b
        .ecdh_raw(EcCurve::P256, &d, &h(ECDH_QB))
        .map_err(|_| fail("ECDH KAT"))?;
    check(eq(&z, &h(ECDH_Z)), "KAS-ECC-SSC P-256 KAT")?;

    // Ed25519 through the backend.
    let sig = b
        .ed25519_sign(&h(ED25519_SK), b"")
        .map_err(|_| fail("Ed25519 KAT"))?;
    check(eq(&sig, &h(ED25519_SIG)), "Ed25519 sign KAT (backend)")?;
    let ok = b.ed25519_verify(&h(ED25519_PK), b"", &sig).unwrap_or(false);
    check(ok, "Ed25519 verify KAT (backend)")?;

    // RNG availability (the DRBG itself has its own KAT).
    let mut r = Zeroizing::new([0u8; 32]);
    b.generate_random(&mut *r).map_err(|_| fail("RNG"))?;
    check(r.iter().any(|&x| x != 0), "RNG output sanity")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_post_passes() {
        run_post().expect("POST self-tests should pass");
    }

    #[cfg(all(feature = "rustcrypto-backend", not(feature = "fips")))]
    #[test]
    fn test_backend_post_passes() {
        let b = crate::crypto::rustcrypto_backend::RustCryptoBackend;
        run_backend_post(&b, false).expect("backend CASTs should pass");
    }
}
