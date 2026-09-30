# Crypto area — handoff (branch `claude/audit-fixes-crypto`)

Owner of this file: crypto agent. Items below need changes **outside** `src/crypto/**`
(or are not fixable in code). Finding IDs refer to the 2026-09-24 audit reports.

## New/changed crypto APIs other areas must know about

- `CryptoBackend` trait (src/crypto/backend.rs) changed shape:
  - typed params: `aes_gcm_encrypt(key, &GcmParams, pt, fips_mode)`, `aes_gcm_decrypt(key, &GcmParams, ct)`,
    `aes_cbc_encrypt/decrypt(key, iv, data, padding: bool)`, `aes_ctr_encrypt/decrypt(key, &CtrParams, data)`,
    `rsa_oaep_encrypt/decrypt(.., &OaepParams)`, `aes_key_wrap/unwrap(kek, data, padded: bool)`,
    `ecdsa_sign/verify(curve, key, data, [sig], hash: Option<HashAlg>)` (raw `r||s`), `ecdh_raw(curve, sk, peer) -> Z`,
    `ecdh_derive(curve, sk, &EcdhParams, key_len, fips_mode)`, `generate_random`, `seed_random`, `is_fips_validated`, `name`.
  - The AES/ECDH "policy entry points" are provided methods; backends implement only the `*_raw`/seal/open primitives.
  - All decrypt/unwrap/decapsulate APIs now return `Zeroizing<Vec<u8>>`.
- ECDSA signatures everywhere (ABI, `sign::ecdsa_p256_sign` etc.) are PKCS#11 raw `r||s` (64/96 bytes), not DER (A2-07).
- `crypto::self_test::{enter_error_state, is_error_state, run_post, run_backend_post, run_post_with_backend}`.
- `crypto::sign::{evict_rsa_key, clear_rsa_key_cache}`; `crypto::encrypt::{gcm_invocation_count, gcm_restore_invocation_count, force_reset_all_counters}`.
- `crypto::params` holds canonical param encodings plus PKCS#11 constants missing from `pkcs11_abi::constants`
  (`CKG_MGF1_*`, `CKZ_DATA_SPECIFIED`, `CKD_*`, `CKR_CURVE_NOT_SUPPORTED`, `CKR_DOMAIN_PARAMS_INVALID`).
- Mechanism list changes: `CKM_HYBRID_ML_DSA_ECDSA` removed (H2-19/A2-18); generic `CKM_RSA_PKCS_PSS` de-advertised
  (see below); `CKM_EDDSA` now FIPS-approved (FIPS 186-5); AES-128 and RSA-2048 allowed in approved mode (H2-21).
- `CKM_AES_GCM` without `CK_GCM_PARAMS` (NULL parameter) keeps a **deprecated** vendor framing
  (module IV, output `IV||ct||tag`) so existing callers/tests keep working; with `CK_GCM_PARAMS` the behaviour is
  standard (`ct||tag`, caller IV/AAD/tag length honoured; in FIPS approved mode the module generates the IV and
  writes it back to `pIv` at `C_EncryptInit`, IG C.H).
- ECDH: `CK_ECDH1_DERIVE_PARAMS` is parsed (kdf, pSharedData, pPublicData); a raw peer point is still accepted
  (legacy) and uses the X9.63 SHA-256 KDF. `CKD_NULL` refused in FIPS mode.

## Changes needed outside src/crypto (please pick up)

### pkcs11_abi (non-call-site parts) — ABI owner
1. **A2-13 / H2-21 generic `CKM_RSA_PKCS_PSS`**: `ActiveOperation::Sign/Verify` (src/session/session.rs) has no
   `mechanism_param`, so `CK_RSA_PKCS_PSS_PARAMS` cannot reach `C_Sign`. Add `mechanism_param: Zeroizing<Vec<u8>>`
   to Sign/Verify, store the raw params in `C_SignInit/C_VerifyInit`, then in `sign_single_shot`/`verify_single_shot`
   (functions.rs) for `CKM_RSA_PKCS_PSS`: `let p = crypto::params::PssParams::from_ck(hashAlg, mgf, sLen)?;` and call
   `backend.rsa_pss_sign_prehashed(key, data, p.hash)` / `rsa_pss_verify_prehashed` (input is the digest). Then
   re-add `CKM_RSA_PKCS_PSS` to `mechanisms::is_sign_mechanism` and `supported_mechanisms`.
2. **H2-20 ML-DSA/SLH-DSA context strings**: same session plumbing; parse PKCS#11 3.2 `CK_SIGN_ADDITIONAL_CONTEXT`
   `{hedgeVariant, pContext, ulContextLen}` at SignInit and call `pqc::ml_dsa_sign_with(.., ctx, PqcSigning::{Hedged,Deterministic})`
   / `ml_dsa_verify_with_context` (same for `slh_dsa_*`). Hedged signing is already the default.
3. **Operation state + GCM IV (A1-15)**: `C_GetOperationState` should return `CKR_STATE_UNSAVEABLE` for an active
   `CKM_AES_GCM` *encrypt* operation; restoring a saved state would re-use a module-generated IV. (The crypto layer
   rejects exact (key, IV) repeats seen in the last 65 536 GCM encryptions per key as defence in depth.)
4. Move `CKR_CURVE_NOT_SUPPORTED`, `CKR_DOMAIN_PARAMS_INVALID`, `CKG_MGF1_*`, `CKZ_DATA_SPECIFIED`, `CKD_*` from
   `crypto::params` into `pkcs11_abi/constants.rs` and add `CKR_WRAPPED_KEY_LEN_RANGE` mapping for unwrap length errors
   (crypto returns `HsmError::DataLenRange`; an `HsmError::WrappedKeyLenRange` variant in src/error.rs would be better).
5. `C_GetMechanismInfo` (functions.rs ~l.680-760): update ranges/flags — GCM now supports 16..32-byte keys (was only
   32), `CKM_AES_KEY_WRAP_KWP` is real RFC 5649, `CKM_RSA_PKCS` sign/verify works, remove the hybrid entry and generic
   `CKM_RSA_PKCS_PSS` until item 1 is done; ECDSA signature sizes are now 64/96 bytes.
6. EC key generation still defaults to P-256 when `CKA_EC_PARAMS` is **absent** (lenient, kept for existing tests);
   PKCS#11 says `CKR_TEMPLATE_INCOMPLETE`. Unknown curves are rejected with `CKR_CURVE_NOT_SUPPORTED` (A1-25).
   `C_CreateObject/C_UnwrapKey` should also validate `CKA_EC_PARAMS` with `sign::EcCurve::from_ec_params`.
7. A1-30: key-type/mechanism consistency at `*Init` (`CKR_KEY_TYPE_INCONSISTENT`) is not implemented.
8. `extract_mechanism_param` still returns an empty Vec for oversized parameters instead of
   `CKR_MECHANISM_PARAM_INVALID` (H1-16 last bullet) — typed parsers now check exact struct sizes, but the generic
   helper should also fail.

### session / store / token — store & session owners
9. **A1-15 / H2-02 / H2-11 persistence**: GCM invocation counts and CTR keystream ranges are process-local. Persist per
   key object (vendor attribute or store metadata) using `encrypt::gcm_invocation_count(key)` and restore with
   `encrypt::gcm_restore_invocation_count(key, n)` when objects are loaded. With module-generated random 96-bit IVs
   (FIPS mode) uniqueness does not depend on this state; the persisted count enforces the SP 800-38D 2^32 limit
   across restarts. Caller-chosen CTR/CBC IVs are only tracked per process.
10. **H2-11 DoS**: call `crypto::encrypt::force_reset_all_counters()` only from `C_InitToken` (already). Session keys
    are not removed from the tracker at `C_CloseSession`; the tracker now uses LRU eviction (65 536 keys) instead of
    a hard global cap, so it cannot be exhausted into a denial of service.
11. **H2-18 / A1-10 (src/store/key_material.rs)**: `mlock` is now reference-counted per page inside
    `crypto::mlock` (safe to keep calling `munlock_buffer` in `Drop`, including for buffers whose lock failed).
    Please surface failures (`crypto::mlock::mlock_failure_count()`) as a metric/status and consider `new_strict`
    in FIPS/production mode; document mlock as best effort.
12. **A1-10 zeroization on C_Finalize**: crypto clears its RSA cache on `C_Finalize`/`C_InitToken` and evicts on
    `C_DestroyObject`. The object store, PIN hashes and TLS `CACHED_HSM` copies are still not zeroized on finalize
    (ABI/store owners).
13. `encrypted_store.rs:443-448` ignores DRBG failures (`let _ = drbg.generate(..)`) — must propagate the error
    (the DRBG now latches the module error state on health-test failure). Prefer `crypto::drbg::fill_random`.
14. PBKDF2 PIN hashing (encrypted_store) runs on RustCrypto even with the AWS-LC backend (A1-03). In `fips` builds use
    `aws_lc_rs::pbkdf2` (PBKDF2 CAST is in POST: RFC 7914 vector).

### core / config — core/config owner
15. **H2-05 / A1-03**: `fips` now implies `awslc-backend`, and `run_backend_post` refuses a non-validated backend
    in `fips` builds, so `C_Initialize` fails if config selects `crypto_backend = "rustcrypto"`. Change
    `config.rs` so `fips_defaults()` (and `default_crypto_backend()` under `cfg(feature = "fips")`) select `"awslc"`,
    and make `validate()` reject `fips_approved_only = true` with a non-awslc backend in `fips` builds.
    Recommended FIPS build: `cargo build --release --no-default-features --features fips`.
16. **A1-26 / H2-03 config**: add `algorithms.allow_rsa_pkcs1v15_decrypt` (default `false`, documented). Note: RSA
    PKCS#1 v1.5 *decryption* is not implemented at all today (`CKM_RSA_PKCS` is sign/verify only), so nothing to
    gate yet; the switch must gate any future implementation. Also add `algorithms.gcm_iv_generation =
    "module"|"caller"` if caller IVs should be refused outside FIPS mode as well.
17. `HsmCore.drbg` (src/core.rs) is now unused: all module randomness uses `crypto::drbg::fill_random`
    (module-wide, fork-aware) or the backend's `generate_random`. Remove the field or make it delegate.
18. Daemon/admin CLI construct `HsmCore` without POST (A1-06): call
    `crypto::self_test::run_post_with_backend(core.crypto_backend().as_ref(), fips_approved_only)` before serving.

### daemon (craton-hsm-daemon/src/server.rs) — daemon owner
19. ECDSA sign/verify via `crypto::sign::ecdsa_p256_*` now produce/accept raw `r||s` (was DER). gRPC clients that
    expected DER must convert. `aes_cbc_encrypt/decrypt` free functions remain PKCS#7 (CBC-PAD); for `CKM_AES_CBC`
    use `encrypt::aes_cbc_{en,de}crypt_with_padding(.., mech == CKM_AES_CBC_PAD)`. Decrypt helpers return
    `Zeroizing<Vec<u8>>` (one mechanical `.to_vec()` was added in `decrypt`).

### supply chain / CI — CI owner
20. **MSRV**: `rust-version = "1.75"` in Cargo.toml is too low for the code base (other modules use APIs newer than
    1.75; the crypto module no longer uses `LazyLock`). Bump `rust-version` (owned by CI agent).
21. `deny.toml` ignores RUSTSEC-2023-0071 with the rationale "we mitigate by not exposing raw RSA decryption" — update:
    mitigations are RSA blinding on every private op (rsa 0.9 `sign_with_rng`, `Pss::new_blinded`,
    `decrypt_blinded`), no PKCS#1 v1.5 decryption service, and mandatory AWS-LC in `fips` builds. Residual risk:
    RustCrypto bignum code is still not constant time. Make the exception time-boxed (until `rsa` 0.10).
22. CI should build/test `--features awslc-backend` (requires Go + CMake) and `--no-default-features --features fips`;
    `src/crypto/awslc_backend.rs` has a cross-backend differential test (`differential_against_rustcrypto`).

### docs — docs owner
23. Update security policy / FIPS docs: DRBG description (module-wide HMAC_DRBG, RCT/APT on entropy input, CAVP KAT),
    CAST list (see `src/crypto/self_test.rs` module doc), integrity test behaviour (fail closed in `fips` builds,
    Ed25519 with strict verification), GCM IV construction (IG C.H scenario 2: 96-bit IV from the approved DRBG,
    2^32 invocations/key), ECDSA raw format, ECDH KDFs, removed hybrid mechanism, mlock best effort.

## Residual risks / partially fixed
- **H2-03 Marvin**: RustCrypto backend RSA private ops are blinded but `num-bigint-dig` is not constant time;
  no fixed `rsa` release exists. Only the AWS-LC backend (mandatory in `fips` builds) is constant time.
- AWS-LC `LessSafeKey` GCM sealing with a module-generated IV is reported by AWS-LC's own service indicator as not
  approved (its approved path is `RandomizedNonceKey`, which cannot return the IV at `C_EncryptInit`). The module-level
  IG C.H argument must be made in the Security Policy.
- AWS-LC cannot express ECDSA P-256+SHA-384/512, P-384+SHA-256/512, raw PKCS#1 v1.5 over non-DigestInfo data,
  truncated GCM tags on decryption, or AES-192 KW KEKs: RustCrypto fallback in non-FIPS builds, refused in `fips` builds.
  AWS-LC's `sign_digest` (multi-part signing) is flagged "not allowed" by its indicator.
- HMAC internal state (`hmac` 0.12 ipad/opad) is not zeroized (no zeroize feature in that crate); DRBG K/V and all
  outputs are.
- SLH-DSA CAST covers verification only (signing CAST would add seconds to POST); keygen is covered by the PCT.
- Integrity test hashes the on-disk file (TOCTOU vs mapped image, A1-28/H2-17) — documented.

## Not fixable in code
- A1-02: ESV certificate / min-entropy justification for the OS entropy source (the module implements RCT/APT with
  H = 4 bits/byte cut-offs only).
- CAVP/ACVP certificates for the exact AWS-LC build and OE; CMVP boundary documentation for the embedded AWS-LC module
  (A1-03 / A1-06).
- Signed release artefacts (`.sig` sidecar, `CRATON_HSM_INTEGRITY_PUBLIC_KEY`) must be produced by the release
  pipeline (A1-05).
- PQC mechanisms use vendor-defined codes and pre-release crates without audit history (H2-20); pinned exactly.

## Additional notes (end of crypto session)
- `CKM_AES_GCM` also accepts a bare 12-byte IV as the mechanism parameter (compatibility with existing callers/tests:
  caller IV, no AAD, 128-bit tag; refused for encryption in FIPS approved mode). Standard `CK_GCM_PARAMS` (v2.40 and
  the older layout without `ulIvBits`) are parsed by exact struct size.
- `CKM_RSA_PKCS_OAEP` now requires `CK_RSA_PKCS_OAEP_PARAMS` at `*Init` (NULL → `CKR_MECHANISM_PARAM_INVALID`), as the
  standard requires; `tests/rsa_abi_comprehensive.rs` was updated to pass real params (its 4 OAEP tests failed before).
- Pre-existing test failures observed identically on the unmodified baseline (not caused by crypto changes; mostly
  PIN-policy violations in test PINs, owner: tests/token): `multipart_encrypt_decrypt`, `multipart_sign_verify`,
  `supplementary_functions` (all 15), `pkcs11_compliance::test_full_pkcs11_lifecycle`,
  `pkcs11_compliance_extended` (at C_SetPIN "newuserpin"), `random_and_session::test_set_pin`,
  `pkcs11_conformance::{test_audit_log_chain_integrity,test_audit_log_injection_prevention,test_login_lockout}`,
  `pqc_abi_comprehensive::test_ml_dsa_null_output_gets_size` (estimate 4672 vs 2420), `zeroization` (2 flaky
  post-drop memory heuristics). Because of the PIN failures, `multipart_*` tests do not currently exercise the
  crypto paths; `tests/crypto_abi_params.rs` adds ABI coverage with a policy-compliant PIN.
