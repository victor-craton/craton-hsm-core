// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Regression tests (through the PKCS#11 C ABI) for the crypto audit fixes:
//! - H2-01 / H1-16 / A2-09: CK_GCM_PARAMS IV, AAD and tag length are honoured
//! - H2-13 / A2-10: CKM_AES_CBC is unpadded, CKM_AES_CBC_PAD pads
//! - H2-07 / A2-07 / A2-08: ECDSA raw r||s and mechanism hash binding
//! - H2-06 / A2-12: CK_ECDH1_DERIVE_PARAMS — both parties derive the same key
//! - A1-01 / A2-16: C_GenerateRandom / C_SeedRandom through the DRBG

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
struct CkGcmParams {
    p_iv: *mut u8,
    ul_iv_len: CK_ULONG,
    ul_iv_bits: CK_ULONG,
    p_aad: *const u8,
    ul_aad_len: CK_ULONG,
    ul_tag_bits: CK_ULONG,
}

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
struct CkEcdh1DeriveParams {
    kdf: CK_ULONG,
    ul_shared_data_len: CK_ULONG,
    p_shared_data: *const u8,
    ul_public_data_len: CK_ULONG,
    p_public_data: *const u8,
}

const CKD_SHA256_KDF: CK_ULONG = 0x6;
const P256_OID: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

fn setup_user_session() -> CK_SESSION_HANDLE {
    let rv = unsafe { C_Initialize(ptr::null_mut()) };
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"CryptPar");
    let rv = unsafe {
        C_InitToken(
            0,
            so_pin.as_ptr() as *mut _,
            so_pin.len() as CK_ULONG,
            label.as_ptr() as *mut _,
        )
    };
    assert_eq!(rv, CKR_OK, "C_InitToken failed");
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        C_OpenSession(
            0,
            CKF_RW_SESSION | CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut session,
        )
    };
    assert_eq!(rv, CKR_OK);
    let rv = unsafe {
        C_Login(
            session,
            CKU_SO,
            so_pin.as_ptr() as *mut _,
            so_pin.len() as CK_ULONG,
        )
    };
    assert_eq!(rv, CKR_OK);
    let user_pin = b"userpin1";
    let rv = unsafe {
        C_InitPIN(
            session,
            user_pin.as_ptr() as *mut _,
            user_pin.len() as CK_ULONG,
        )
    };
    assert_eq!(rv, CKR_OK);
    assert_eq!(unsafe { C_Logout(session) }, CKR_OK);
    let rv = unsafe {
        C_Login(
            session,
            CKU_USER,
            user_pin.as_ptr() as *mut _,
            user_pin.len() as CK_ULONG,
        )
    };
    assert_eq!(rv, CKR_OK);
    session
}

fn generate_aes_key(session: CK_SESSION_HANDLE, len: CK_ULONG) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len = ck_ulong_bytes(len);
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: value_len.as_ptr() as CK_VOID_PTR,
            value_len: value_len.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = unsafe {
        C_GenerateKey(
            session,
            &mut mechanism,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut key,
        )
    };
    assert_eq!(rv, CKR_OK, "C_GenerateKey: 0x{:08X}", rv);
    key
}

fn encrypt(
    session: CK_SESSION_HANDLE,
    mech: &mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let rv = unsafe { C_EncryptInit(session, mech, key) };
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut out = vec![0u8; data.len() + 64];
    let mut out_len = out.len() as CK_ULONG;
    let rv = unsafe {
        C_Encrypt(
            session,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    if rv != CKR_OK {
        return Err(rv);
    }
    out.truncate(out_len as usize);
    Ok(out)
}

fn decrypt(
    session: CK_SESSION_HANDLE,
    mech: &mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let rv = unsafe { C_DecryptInit(session, mech, key) };
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut out = vec![0u8; data.len() + 64];
    let mut out_len = out.len() as CK_ULONG;
    let rv = unsafe {
        C_Decrypt(
            session,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    if rv != CKR_OK {
        return Err(rv);
    }
    out.truncate(out_len as usize);
    Ok(out)
}

fn gcm_mech(params: &mut CkGcmParams) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: params as *mut _ as CK_VOID_PTR,
        parameter_len: std::mem::size_of::<CkGcmParams>() as CK_ULONG,
    }
}

#[test]
fn gcm_params_aad_tag_and_cbc_padding() {
    let session = setup_user_session();

    // ---- AES-GCM with CK_GCM_PARAMS (AES-128 key, 96-bit tag, AAD) ----
    let key = generate_aes_key(session, 16);
    let mut iv = [0x5Au8; 12];
    let aad = b"header: context A";
    let mut p = CkGcmParams {
        p_iv: iv.as_mut_ptr(),
        ul_iv_len: 12,
        ul_iv_bits: 96,
        p_aad: aad.as_ptr(),
        ul_aad_len: aad.len() as CK_ULONG,
        ul_tag_bits: 96,
    };
    let pt = b"authenticated GCM payload";
    let ct = encrypt(session, &mut gcm_mech(&mut p), key, pt).unwrap();
    assert_eq!(
        ct.len(),
        pt.len() + 12,
        "standard ct || 96-bit tag, no IV prefix"
    );
    let dec = decrypt(session, &mut gcm_mech(&mut p), key, &ct).unwrap();
    assert_eq!(&dec[..], pt);

    // Different AAD must fail authentication (AAD is really bound now).
    let other_aad = b"header: context B";
    let mut p2 = CkGcmParams {
        p_iv: iv.as_mut_ptr(),
        ul_iv_len: 12,
        ul_iv_bits: 96,
        p_aad: other_aad.as_ptr(),
        ul_aad_len: other_aad.len() as CK_ULONG,
        ul_tag_bits: 96,
    };
    assert_eq!(
        decrypt(session, &mut gcm_mech(&mut p2), key, &ct),
        Err(CKR_ENCRYPTED_DATA_INVALID)
    );

    // Re-using the same (key, IV) for another encryption is rejected.
    assert!(encrypt(session, &mut gcm_mech(&mut p), key, b"again").is_err());

    // Unsupported tag length is rejected at init.
    let mut iv2 = [0x11u8; 12];
    let mut bad = CkGcmParams {
        p_iv: iv2.as_mut_ptr(),
        ul_iv_len: 12,
        ul_iv_bits: 96,
        p_aad: ptr::null(),
        ul_aad_len: 0,
        ul_tag_bits: 64,
    };
    assert_eq!(
        unsafe { C_EncryptInit(session, &mut gcm_mech(&mut bad), key) },
        CKR_MECHANISM_PARAM_INVALID
    );

    // ---- CKM_AES_CBC is unpadded, CKM_AES_CBC_PAD pads ----
    let key = generate_aes_key(session, 32);
    let iv_a = [0x21u8; 16];
    let mut cbc = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        p_parameter: iv_a.as_ptr() as CK_VOID_PTR,
        parameter_len: 16,
    };
    let ct = encrypt(session, &mut cbc, key, &[7u8; 32]).unwrap();
    assert_eq!(ct.len(), 32, "CKM_AES_CBC must not add a padding block");
    let dec = decrypt(session, &mut cbc, key, &ct).unwrap();
    assert_eq!(dec, vec![7u8; 32]);
    let iv_b = [0x22u8; 16];
    let mut cbc = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        p_parameter: iv_b.as_ptr() as CK_VOID_PTR,
        parameter_len: 16,
    };
    assert_eq!(
        encrypt(session, &mut cbc, key, &[7u8; 31]),
        Err(CKR_DATA_LEN_RANGE)
    );
    let iv_c = [0x23u8; 16];
    let mut cbc_pad = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        p_parameter: iv_c.as_ptr() as CK_VOID_PTR,
        parameter_len: 16,
    };
    let ct = encrypt(session, &mut cbc_pad, key, &[7u8; 32]).unwrap();
    assert_eq!(ct.len(), 48, "CKM_AES_CBC_PAD adds a full padding block");

    // ---- RNG through the DRBG ----
    let mut buf = [0u8; 64];
    assert_eq!(
        unsafe { C_GenerateRandom(session, buf.as_mut_ptr(), 64) },
        CKR_OK
    );
    assert_ne!(buf, [0u8; 64]);
    let seed = [1u8, 2, 3, 4];
    assert_eq!(
        unsafe { C_SeedRandom(session, seed.as_ptr() as *mut _, 4) },
        CKR_OK
    );
}

fn generate_ec_keypair(session: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut pub_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: P256_OID.as_ptr() as CK_VOID_PTR,
            value_len: P256_OID.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut priv_template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DERIVE,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let (mut pub_key, mut priv_key) = (0, 0);
    let rv = unsafe {
        C_GenerateKeyPair(
            session,
            &mut mechanism,
            pub_template.as_mut_ptr(),
            pub_template.len() as CK_ULONG,
            priv_template.as_mut_ptr(),
            priv_template.len() as CK_ULONG,
            &mut pub_key,
            &mut priv_key,
        )
    };
    assert_eq!(rv, CKR_OK, "EC keygen: 0x{:08X}", rv);
    (pub_key, priv_key)
}

fn read_ec_point(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> Vec<u8> {
    let mut t = [CK_ATTRIBUTE {
        attr_type: CKA_EC_POINT,
        p_value: ptr::null_mut(),
        value_len: 0,
    }];
    assert_eq!(
        unsafe { C_GetAttributeValue(session, key, t.as_mut_ptr(), 1) },
        CKR_OK
    );
    let mut buf = vec![0u8; t[0].value_len as usize];
    t[0].p_value = buf.as_mut_ptr() as CK_VOID_PTR;
    assert_eq!(
        unsafe { C_GetAttributeValue(session, key, t.as_mut_ptr(), 1) },
        CKR_OK
    );
    buf.truncate(t[0].value_len as usize);
    buf
}

fn sign(
    session: CK_SESSION_HANDLE,
    mech: CK_MECHANISM_TYPE,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
) -> Vec<u8> {
    let mut m = CK_MECHANISM {
        mechanism: mech,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    assert_eq!(unsafe { C_SignInit(session, &mut m, key) }, CKR_OK);
    let mut sig = vec![0u8; 256];
    let mut len = sig.len() as CK_ULONG;
    let rv = unsafe {
        C_Sign(
            session,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            sig.as_mut_ptr(),
            &mut len,
        )
    };
    assert_eq!(rv, CKR_OK, "C_Sign: 0x{:08X}", rv);
    sig.truncate(len as usize);
    sig
}

fn verify(
    session: CK_SESSION_HANDLE,
    mech: CK_MECHANISM_TYPE,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
    sig: &[u8],
) -> CK_RV {
    let mut m = CK_MECHANISM {
        mechanism: mech,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    assert_eq!(unsafe { C_VerifyInit(session, &mut m, key) }, CKR_OK);
    unsafe {
        C_Verify(
            session,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            sig.as_ptr() as *mut _,
            sig.len() as CK_ULONG,
        )
    }
}

fn derive(
    session: CK_SESSION_HANDLE,
    base: CK_OBJECT_HANDLE,
    peer: &[u8],
    shared: &[u8],
) -> CK_OBJECT_HANDLE {
    let mut params = CkEcdh1DeriveParams {
        kdf: CKD_SHA256_KDF,
        ul_shared_data_len: shared.len() as CK_ULONG,
        p_shared_data: shared.as_ptr(),
        ul_public_data_len: peer.len() as CK_ULONG,
        p_public_data: peer.as_ptr(),
    };
    let mut mech = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        p_parameter: &mut params as *mut _ as CK_VOID_PTR,
        parameter_len: std::mem::size_of::<CkEcdh1DeriveParams>() as CK_ULONG,
    };
    let ck_true: CK_BBOOL = CK_TRUE;
    let len = ck_ulong_bytes(32);
    let mut t = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: len.as_ptr() as CK_VOID_PTR,
            value_len: len.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut key = 0;
    let rv = unsafe {
        C_DeriveKey(
            session,
            &mut mech,
            base,
            t.as_mut_ptr(),
            t.len() as CK_ULONG,
            &mut key,
        )
    };
    assert_eq!(rv, CKR_OK, "C_DeriveKey: 0x{:08X}", rv);
    key
}

#[test]
fn ecdsa_raw_signatures_and_ecdh_agreement() {
    let session = setup_user_session();
    let (pub_a, priv_a) = generate_ec_keypair(session);
    let data = b"ECDSA mechanism hash binding";

    // Raw r || s (64 bytes for P-256), SHA-384 honoured on a P-256 key.
    let sig = sign(session, CKM_ECDSA_SHA384, priv_a, data);
    assert_eq!(sig.len(), 64);
    assert_eq!(verify(session, CKM_ECDSA_SHA384, pub_a, data, &sig), CKR_OK);
    assert_eq!(
        verify(session, CKM_ECDSA_SHA256, pub_a, data, &sig),
        CKR_SIGNATURE_INVALID,
        "a SHA-384 signature must not verify as ECDSA-SHA256"
    );
    // CKM_ECDSA signs the caller's hash without hashing it again.
    use sha2::Digest;
    let digest = sha2::Sha384::digest(data);
    assert_eq!(verify(session, CKM_ECDSA, pub_a, &digest, &sig), CKR_OK);
    let sig2 = sign(session, CKM_ECDSA, priv_a, &digest);
    assert_eq!(
        verify(session, CKM_ECDSA_SHA384, pub_a, data, &sig2),
        CKR_OK
    );

    // ECDH: both parties derive the same AES key (symmetric KDF input).
    let (pub_b, priv_b) = generate_ec_keypair(session);
    let point_a = read_ec_point(session, pub_a);
    let point_b = read_ec_point(session, pub_b);
    let key_a = derive(session, priv_a, &point_b, b"shared-info");
    let key_b = derive(session, priv_b, &point_a, b"shared-info");
    let mut iv = [0x33u8; 12];
    let mut p = CkGcmParams {
        p_iv: iv.as_mut_ptr(),
        ul_iv_len: 12,
        ul_iv_bits: 96,
        p_aad: ptr::null(),
        ul_aad_len: 0,
        ul_tag_bits: 128,
    };
    let ct = encrypt(session, &mut gcm_mech(&mut p), key_a, b"agreed").unwrap();
    let pt = decrypt(session, &mut gcm_mech(&mut p), key_b, &ct);
    assert_eq!(
        pt.as_deref(),
        Ok(&b"agreed"[..]),
        "parties must agree on the derived key"
    );
}
