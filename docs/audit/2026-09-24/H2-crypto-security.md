# H2 — Cryptography module: offensive security review

**Target:** `craton-hsm` 0.9.1 (root crate), `src/crypto/` · **Date:** 2026-09-24 · **Branch:** `claude/modest-hamilton-y6ok79` (worktree `/home/user/craton-hsm-audit-wt`)

## Scope & method

**In scope:** all 17 files in `src/crypto/`: `awslc_backend.rs`, `backend.rs`, `derive.rs`, `digest.rs`, `drbg.rs`, `encrypt.rs`, `integrity.rs`, `keygen.rs`, `mechanisms.rs`, `mlock.rs`, `mod.rs`, `pairwise_test.rs`, `pqc.rs`, `rustcrypto_backend.rs`, `self_test.rs`, `sign.rs` and `wrap.rs`, plus `Cargo.toml` and `Cargo.lock` for dependency versions and features.

**Method:**
- Static review only. Nothing was built, tested or run.
- To confirm how attacker-controlled input reaches the crypto layer, I read the call sites in `src/pkcs11_abi/functions.rs`, `src/core.rs`, `src/config/config.rs` and `src/store/key_material.rs`. The ABI layer is covered by another agent; I cite it only as evidence.
- To confirm library behaviour, I read the dependency sources in `~/.cargo/registry`: `rsa-0.9.10`, `aes-kw-0.2.1`, `aes-0.8.4`, `ml-dsa-0.1.0-rc.7`, `ml-kem-0.3.0-rc.0` and `slh-dsa-0.2.0-rc.4`.

**Locked versions that matter to the findings:**

| Area | Crates |
|---|---|
| RSA | rsa 0.9.10, num-bigint-dig 0.8.6 |
| Elliptic curves | p256 0.13.2, p384 0.13.1, ecdsa 0.16.9, ed25519-dalek 2.2.0 |
| Symmetric | aes 0.8.4, aes-gcm 0.10.3, aes-kw 0.2.1 |
| Post-quantum (pre-release) | ml-kem 0.3.0-rc.0, ml-dsa 0.1.0-rc.7, slh-dsa 0.2.0-rc.4 |
| FIPS backend | aws-lc-rs 1.16.2 with aws-lc-fips-sys 0.13.13 |

**Confidence levels:**
- **Confirmed:** I traced the code path end to end and read the library source where relevant.
- **Likely:** the reasoning is sound but depends on runtime or library behaviour I did not execute.
- **Possible:** plausible, but needs more investigation.

## Executive summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 3 |
| Medium | 8 |
| Low | 9 |
| Informational | 2 |
| **Total** | **22** |

**Top 5 risks:**

1. **H2-01, AES-GCM ignores `CK_GCM_PARAMS`.** The caller's AAD, IV and tag length are all silently dropped. Ciphertexts are not bound to their context, so one encrypted in context A decrypts cleanly in context B.
2. **H2-02, AES-GCM nonces can repeat.** A nonce is a 32-bit random prefix plus a counter. Both live only in process memory and are keyed by a hash of the key bytes. Three routes reset or clone that state:
   - copying a key and destroying the copy;
   - `fork()` followed by `C_Finalize`/`C_Initialize`;
   - several processes sharing one token.

   A user who holds only `CKA_ENCRYPT` can use the first route to make a (key, nonce) pair repeat. Once that happens, GCM loses both confidentiality and integrity for the key.
3. **H2-03, RSA private-key operations are unblinded and not constant-time.** This covers OAEP decryption and PKCS#1 v1.5 signing. Timing side channels can leak the key (Marvin / RUSTSEC-2023-0071, plus classic unblinded CRT timing). The `rsa` 0.9 line has no fix.
4. **H2-04 and H2-05, the "FIPS" story does not hold up.**
   - `--features fips` still runs the non-validated RustCrypto backend.
   - The aws-lc backend skips every hardening control that `encrypt.rs` implements.
   - The aws-lc backend derives different ECDH keys from the same inputs (raw shared secret instead of HKDF).
   - Power-on self-tests exercise only RustCrypto.
   - Several KATs are roundtrip tests rather than known-answer tests (H2-08).
5. **H2-06 and H2-07, protocol errors in the default backend.**
   - The ECDH HKDF `info` string puts *our* public key first, so the two parties always derive different keys.
   - The ECDSA mechanism's hash is ignored: `CKM_ECDSA` hashes its input a second time, and `CKM_ECDSA_SHA384/512` on P-256 signs SHA-256 instead.

---

## Findings

### H2-01 [High] AES-GCM ignores `CK_GCM_PARAMS`: AAD is never authenticated, and the caller's IV and tag length are dropped

- **Location:**
  - `src/crypto/backend.rs:146-147`: the trait has no IV, AAD or tag parameter.
  - `src/crypto/encrypt.rs:226-306` (encrypt) and `:380-398` (decrypt).
  - `src/crypto/awslc_backend.rs:405-448`: uses `Aad::empty()`.
  - Call sites: `src/pkcs11_abi/functions.rs:1616` and `:1861`.
  - `aes_256_gcm_encrypt_with_aad` / `_decrypt_with_aad` (`encrypt.rs:315`, `:407`) exist but nothing outside `encrypt.rs` calls them.
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature), CWE-325 (Missing Cryptographic Step)
- **Confidence:** Confirmed
- **Description:**
  - `C_EncryptInit` stores the raw `pParameter` bytes (`functions.rs:1470`, `:1495`).
  - For `CKM_AES_GCM`, `C_Encrypt` calls `aes_256_gcm_encrypt(key_bytes, data)` without them.
  - A standard PKCS#11 caller supplies `CK_GCM_PARAMS { pIv, ulIvLen, pAAD, ulAADLen, ulTagBits }`. The IV is replaced with an internal nonce, the AAD is discarded, and `ulTagBits` is ignored (the tag is always 128 bits).
  - The call still returns `CKR_OK`, so the application believes its AAD is authenticated.
  - The output is `nonce || ct || tag`, not the standard `ct || tag`. A ciphertext produced elsewhere with a caller-chosen IV therefore cannot be decrypted.
  - GCM also accepts only 32-byte keys (`encrypt.rs:227`), although `C_GetMechanismInfo` advertises 16–32 (`functions.rs:730-734`).
- **Trigger condition:** any `C_EncryptInit`/`C_DecryptInit` with `CKM_AES_GCM` and a `CK_GCM_PARAMS` whose `ulAADLen > 0`, caller IV or `ulTagBits != 128`. The parameters are silently ignored and the call returns `CKR_OK`.
- **Impact:** Integrity and authentication of the associated data are silently lost. Standard GCM interoperability is broken: an external IV cannot be used, and tag-length negotiation is not possible.
- **Recommendation:**
  1. Parse `CK_GCM_PARAMS` in the ABI layer.
  2. Extend the trait to `aes_gcm_encrypt(key, iv_policy, aad, tag_bits, pt)`.
  3. Reject `ulTagBits < 96` unless an explicit policy allows it, and reject any tag length not in {96, 104, 112, 120, 128}.
  4. Either honour a caller IV (PKCS#11 v3.0 `CKM_AES_GCM`) or implement PKCS#11 3.0 message-based encryption with `CKG_GENERATE_COUNTER`. In the second case, return the generated IV through `pIv` rather than prepending it.
  5. At minimum, fail with `CKR_MECHANISM_PARAM_INVALID` when `ulAADLen > 0` until AAD is supported.
  6. Support AES-128 and AES-192 GCM, or advertise 32 bytes only.

### H2-02 [High] AES-GCM nonce uniqueness is process-local and can be reset by an attacker, giving deterministic nonce reuse

- **Location:**
  - Nonce construction: `src/crypto/encrypt.rs:34-35` and `:42-43` (in-memory maps keyed by `SHA-256(key)`), `:113-124` (random 4-byte prefix per key), `:243-268` (counter starts at 0), `:291-294` (nonce = prefix || counter).
  - `remove_gcm_counter`, `encrypt.rs:73-79`, drops both the counter and the prefix.
  - Called from `C_DestroyObject`: `src/pkcs11_abi/functions.rs:1090-1103`.
  - `C_CopyObject` deep-clones key material: `functions.rs:3552`.
  - `reset_gcm_counters` deliberately keeps the maps (`encrypt.rs:60-68`). A `fork()` child therefore inherits the parent's prefix and counter.
  - Fork path: `C_Finalize` (`functions.rs:280-307`) followed by `C_Initialize`.
- **CWE:** CWE-323 (Reusing a Nonce, Key Pair in Encryption), CWE-330
- **Confidence:** Confirmed (code path). Attack cost is estimated.
- **Description:** Uniqueness rests on a 32-bit random prefix, a counter that restarts at 0, and state that exists only in process memory, keyed by the hash of the key *bytes* rather than by the object. Four independent routes lead to reuse:
  1. **Copy and destroy.** Two handles can share key material (via `C_CopyObject`, or two `C_UnwrapKey` calls on the same blob). Destroying one handle erases the shared counter and prefix. The next encryption under the surviving handle draws a new 32-bit prefix and restarts at counter 0.
  2. **Fork.** The child inherits `GCM_NONCE_PREFIXES` and `GCM_ENCRYPT_COUNTERS`. PKCS#11 requires the child to call `C_Finalize` and `C_Initialize`, and neither clears GCM state. Parent and child then emit identical nonce sequences under the same key.
  3. **Multiple processes or restarts.** Every process loading the library starts at counter 0 with a fresh 32-bit prefix. By the birthday bound, prefix collisions become likely after about 2^16 process lifetimes per key, and a collision repeats nonces from counter 0 onward.
  4. **The 2^31 cap is per process.** It does not bound total invocations across restarts.
- **Trigger condition:** any of the following resets or duplicates the per-key nonce state while the key is still in use:
  - destroying one of two handles that share key bytes (for example, after `C_CopyObject`);
  - `fork()` followed by `C_Finalize` and `C_Initialize` in the child;
  - running multiple processes or restarts against the same token.

  The nonce stream then restarts at counter 0 under a new 32-bit prefix, or is identical in both processes after a fork. By the birthday bound, prefix collisions become likely after about 2^16 resets.
- **Impact:** GCM confidentiality and integrity fail for any key an unprivileged user can encrypt with. The attacker can forge ciphertexts that the HSM, or another consumer of the key, accepts as authentic. The fork route leads to accidental reuse in ordinary pre-forking servers (nginx, Apache, PHP-FPM, Python multiprocessing).
- **Recommendation:**
  - Stop deriving nonce state from volatile, hash-of-key maps. Choose one of:
    - (a) a 96-bit random nonce per message from the DRBG, with a per-key invocation limit persisted in the object store (SP 800-38D §8.3 limits random nonces to 2^32 per key);
    - (b) a persisted per-object counter (for example, `CKA_` vendor attribute or store metadata) combined with a per-process random field of at least 64 bits.
  - Key the state by object identity (store UUID), not by key bytes.
  - Never reset it on `C_DestroyObject` of a *different* handle.
  - Detect `fork()` (PID change) and regenerate prefixes.
  - Consider SIV modes (AES-GCM-SIV) for nonce-misuse resistance.

### H2-03 [High] RSA private-key operations are unblinded and variable-time (Marvin / RUSTSEC-2023-0071)

- **Location:**
  - `src/crypto/sign.rs:435-449`: `private_key.decrypt(padding, ciphertext)`, which in rsa 0.9 means no RNG and therefore no blinding.
  - `sign.rs:211-231`: `pkcs1v15::SigningKey::sign(data)`, which reaches `sign::<DummyRng>(None, …)` (`rsa-0.9.10/src/pkcs1v15/signing_key.rs:160-161`).
  - `sign.rs:703-705`: `private_key.sign(scheme, digest)`, where `rsa-0.9.10/src/key.rs:439` passes `Option::<&mut DummyRng>::None`.
  - `src/crypto/awslc_backend.rs:237-239`: multi-part PKCS#1 v1.5 signing also falls back to unblinded RustCrypto under the aws-lc backend.
  - Dependency: `rsa = "0.9"`, locked at 0.9.10.
- **CWE:** CWE-208 (Observable Timing Discrepancy), CWE-385 (Covert Timing Channel)
- **Confidence:** Confirmed that blinding is off (library source read). Practical exploitability is Likely.
- **Description:**
  - rsa 0.9.x uses `num-bigint-dig` modular exponentiation, which is not constant-time. RUSTSEC-2023-0071 ("Marvin Attack") has no patched 0.9 release.
  - The crate mitigates part of the leak only when an RNG is supplied, which enables base blinding. The HSM supplies one only for PSS.
  - OAEP decryption and every PKCS#1 v1.5 signature run the CRT exponentiation directly on attacker-chosen input:
    - for OAEP, the ciphertext;
    - for signing, the message, which fully determines the padded representative.
  - The OAEP *unpadding* itself is constant-time (`rsa-0.9.10/src/algorithms/oaep.rs:214-234`). The exponentiation is not.
- **Trigger condition:** any `C_Decrypt(CKM_RSA_PKCS_OAEP)` or `C_Sign(CKM_SHAx_RSA_PKCS)` whose input the caller controls. The input reaches an unblinded, variable-time CRT exponentiation, whose timing an observer can measure.
- **Impact:** Recovery of the RSA private key, or decryption of past key-transport ciphertexts. This is the central asset an HSM exists to protect.
- **Recommendation:**
  - Short term: always use the blinded APIs, i.e. `private_key.decrypt_blinded(&mut DrbgRng::new()?, padding, ct)` and `pkcs1v15::SigningKey::sign_with_rng(&mut rng, msg)` / `private_key.sign_with_rng(&mut rng, scheme, digest)`.
  - Medium term: move RSA private operations to aws-lc (constant-time BN), or to `rsa` 0.10 once it lands on `crypto-bigint`.
  - Track RUSTSEC-2023-0071 in `cargo audit` with an explicit, time-boxed exception.

### H2-04 [Medium] Backend parity: the aws-lc backend skips every hardening control and computes different results

- **Location:** `src/crypto/awslc_backend.rs`:
  - `:405-427`: GCM uses a random nonce with no counter or limit.
  - `:450-502`: CBC has no zero-IV check, no IV-reuse tracking, no size cap and no timing floor.
  - `:504-510` and `:793-817`: CTR has no IV tracking.
  - `:560-598`: `_fips_mode` is ignored, so AES-128 is allowed.
  - `:674-724`: `_fips_mode` is ignored for key wrap, and 24-byte KEKs are rejected.
  - `:730-778`: ECDH returns the *raw* shared secret.
  - `:221-399`: prehashed operations run on RustCrypto; `:269` uses `OsRng`, not the DRBG.
- **CWE:** CWE-693 (Protection Mechanism Failure), CWE-1068 (Inconsistency Between Implementation and Documented Design)
- **Confidence:** Confirmed
- **Description:** All protective logic (IV-reuse tracking, zero-IV rejection, GCM counters, size caps, CBC timing floor, `fips_mode` key-size policy) lives in the RustCrypto free functions in `encrypt.rs`, `keygen.rs` and `wrap.rs`. It is not in a shared policy layer above `CryptoBackend`. Selecting `crypto_backend = "awslc"` therefore silently removes every one of these controls. The two backends also produce different *outputs* for the same inputs:
  - **ECDH:** RustCrypto runs HKDF (`derive.rs:142-156`); aws-lc returns the truncated x-coordinate. Switching backends changes every derived key.
  - **Multi-part signing:** under aws-lc it runs on RustCrypto without blinding (see H2-03).
  - **RSA verify limits:** RustCrypto caps the modulus at 4096 bits (`RsaPublicKey::MAX_SIZE`); aws-lc accepts up to 8192 bits.
  - **`CKM_RSA_PKCS` with no hash:** the backends return different error codes, `MechanismParamInvalid` versus `MechanismInvalid`.
- **Trigger condition:** setting `crypto_backend = "awslc"`, the only route to the FIPS-validated library. All `encrypt.rs` controls are skipped, and ECDH and multi-part-signing outputs change.
- **Impact:** Security controls depend on configuration. Derived keys diverge silently. Backend switching invalidates keys.
- **Recommendation:**
  - Move nonce and IV policy, limits and `fips_mode` checks into a backend-agnostic wrapper (for example `struct PolicyBackend<B: CryptoBackend>`) that every backend passes through.
  - Make KDF selection an explicit parameter (`CKD_NULL`, `CKD_SHA256_KDF`, and so on) instead of a per-backend default.
  - Add cross-backend differential tests.

### H2-05 [Medium] The `fips` feature does not select a validated module, and POST exercises only RustCrypto

- **Location:**
  - `Cargo.toml` `[features] fips = []`: the feature does not enable `awslc-backend`.
  - `src/config/config.rs:217-219`: the default backend is `"rustcrypto"`.
  - `src/config/config.rs:234-240` and `:278-286`: `fips_defaults()` keeps that default.
  - `src/core.rs:54-100`: backend selection.
  - `src/crypto/self_test.rs:21-66`: every KAT calls `crate::crypto::encrypt::*`, `sign::*` and `keygen::*` directly, never `hsm.crypto_backend`.
  - `src/crypto/mechanisms.rs:164-206`: the approved-mechanism table.
- **CWE:** CWE-693, CWE-1188 (Insecure Default Initialization)
- **Confidence:** Confirmed
- **Description:**
  - A `cargo build --features fips` artifact hardcodes `fips_approved_only = true` but runs every operation through RustCrypto, which is not validated.
  - With `awslc-backend` enabled, POST still tests the RustCrypto implementations rather than the backend that serves requests (aws-lc runs its own POST internally).
  - Multi-part signing, PQC, the DRBG and all digests in `encrypt.rs` remain RustCrypto regardless of backend.
  - Separately, `CRATON_HSM_FIPS=1` without the compile-time feature enables policy but not the integrity-file requirement (`integrity.rs:118-143` is compile-time only).
- **Impact:** Deployments may claim FIPS 140-3 operation while running unvalidated code. The self-test evidence does not cover the implementation actually in use.
- **Recommendation:**
  - Make `fips = ["awslc-backend"]`.
  - In FIPS builds, reject `crypto_backend != "awslc"` at startup.
  - Run KATs against `&dyn CryptoBackend` after backend selection.
  - Refuse non-backend code paths (RustCrypto prehash, PQC) while `fips_approved_only` is set.

### H2-06 [Medium] The ECDH HKDF `info` string is asymmetric, so two honest parties never derive the same key; KDF parameters are ignored

- **Location:** `src/crypto/derive.rs:56-68` (P-256) and `:102-114` (P-384), where `info = OID || len || OUR_pub || PEER_pub_as_supplied`. KDF parameters are dropped at `src/pkcs11_abi/functions.rs:5316-5360`, where the mechanism parameter is used as the raw peer point.
- **CWE:** CWE-325, CWE-684 (Incorrect Provision of Specified Functionality)
- **Confidence:** Confirmed
- **Description:** Each side places *its own* public key first:
  - Party A computes `HKDF(Z, info = OID‖L‖Q_A‖Q_B)`.
  - Party B computes `HKDF(Z, info = OID‖L‖Q_B‖Q_A)`.

  The OKM always differs, even between two keys inside the same HSM. The peer key is inserted exactly as the caller encoded it, so compressed and uncompressed encodings of the same point also produce different keys. The `CK_ECDH1_DERIVE_PARAMS` fields (`kdf`, `pSharedData`) are not parsed: the whole parameter blob is treated as a SEC1 point, and the fixed salt `"CratonHSM-ECDH-HKDF-Salt-v1"` makes the scheme proprietary. Point validation itself is sound: `PublicKey::from_sec1_bytes` rejects off-curve and identity points.
- **Impact:** ECDH key agreement does not work between parties. That invites dangerous workarounds, such as exporting raw secrets or disabling the KDF. It also fails silently against any standard peer.
- **Recommendation:** Build `info` from a canonical ordering, e.g. `min(Q_A, Q_B) ‖ max(Q_A, Q_B)` over uncompressed encodings, or from explicit initiator/responder roles (SP 800-56A `PartyUInfo`/`PartyVInfo`). Better still, implement the PKCS#11 KDFs (`CKD_NULL`, `CKD_SHA256_KDF`, and so on) from parsed `CK_ECDH1_DERIVE_PARAMS`, using `pSharedData` as `OtherInfo`.

### H2-07 [Medium] The ECDSA mechanism's hash is ignored: `CKM_ECDSA` double-hashes, and SHA-384/512 variants fall back to the curve default

- **Location:** `src/crypto/backend.rs:53-69` and `src/crypto/sign.rs:465-531` take no hash parameter. P-256 always uses SHA-256 and P-384 always uses SHA-384. Dispatch: `src/pkcs11_abi/functions.rs:2162-2175` and `:2246-2254`. Multi-part: `sign.rs:670-679` and `:822-839`.
- **CWE:** CWE-347, CWE-327
- **Confidence:** Confirmed
- **Description:**
  - **`CKM_ECDSA`:** by specification the input is a precomputed hash. The HSM hashes it again and signs `H(H(m))`, so the signatures fail standard verification.
  - **`CKM_ECDSA_SHA384` / `CKM_ECDSA_SHA512` on P-256:** single-part calls sign `SHA-256(m)`. Multi-part calls fail with `DataLenRange` (`validate_digest_length`, `sign.rs:831`). The same key and mechanism give different behaviour depending on the API style.
  - **Verification:** it also ignores the mechanism. `C_Verify(CKM_ECDSA_SHA512)` accepts a plain ECDSA-SHA256 signature. This is a hash-algorithm confusion that a relying party checking "this was signed with SHA-512" cannot detect.
- **Impact:** Signatures do not interoperate, the effective hash is weaker than the one requested, and mechanism confusion occurs at verification time.
- **Recommendation:** Pass `HashAlg` (or `None` for raw) through the trait. For `CKM_ECDSA`, call `sign_prehash` / `verify_prehash` on the caller's bytes, with the FIPS 186-5 bits2int truncation. For the hashed variants, hash with the requested algorithm.

### H2-08 [Medium] Many self-tests are roundtrip tests rather than KATs; algorithm, DRBG and entropy coverage is missing

- **Location:** `src/crypto/self_test.rs`:
  - `:225-269`: the GCM "KAT" only checks roundtrip plus "tag non-zero". The known tag for AES-256-GCM with a zero key and zero nonce, `530f8afbc74536b9a963b4f1c4cb738b`, is never compared.
  - `:341-358` (RSA), `:361-371` (ECDSA), `:378-388` (ML-DSA) and `:391-405` (ML-KEM): each generates a *fresh random* key and performs a sign/verify or encapsulate/decapsulate roundtrip.
  - `:414-438` (RNG) and `:442-462` (DRBG): "not all zeros / two draws differ" checks with no known answer.
- **CWE:** CWE-1025 (Comparison Using Wrong Factors), CWE-754
- **Confidence:** Confirmed
- **Description:**
  - FIPS 140-3 IG 10.3.A requires known-answer tests for each approved algorithm. A symmetric bug that affects both halves of a roundtrip, such as a wrong curve constant or a wrong GHASH, passes these tests.
  - **No KATs at all for:** AES-KW/KWP, HKDF/ECDH (KAS), P-384, SHA3-384/512, RSA-PSS, RSA-OAEP, Ed25519, SLH-DSA, AES-128/192, or the HMAC-DRBG instantiate/generate/reseed functions (SP 800-90A §11.3).
  - **The DRBG cannot be KAT-tested as written,** because `generate()` always reseeds from `OsRng` (`drbg.rs:191-192`).
  - **No SP 800-90B start-up or continuous health tests** (repetition count, adaptive proportion) are run on the entropy input.
  - **The POST depends on RNG behaviour** and costs an RSA-2048 key generation on every `C_Initialize` (`self_test.rs:343`).
- **Impact:** Self-tests give false assurance, and certification evidence is inadequate.
- **Recommendation:**
  - Replace every roundtrip with fixed-vector KATs from the CAVP, ACVP and NIST PQC test vectors, and compare full outputs.
  - For signatures, use deterministic KATs: RFC 6979 vectors for ECDSA, and fixed-seed vectors for ML-DSA and ML-KEM.
  - Add a `HmacDrbg::instantiate_with(entropy, nonce, pers)` / `generate_no_pr` path used only by POST.
  - Run the KATs through the selected backend (see H2-05).

### H2-09 [Medium] Key-material hygiene: `zeroize` features are off in the crypto dependencies, and decrypted or unwrapped secrets are left in freed heap

- **Location:**
  - `Cargo.lock`: `aes`, `aes-gcm`, `aes-kw`, `hkdf`, `hmac`, `sha2`, `ml-kem`, `ml-dsa` and `slh-dsa` have no `zeroize` dependency edge. Their optional `zeroize` features (`aes-0.8.4/Cargo.toml:58-70`, `ml-dsa-0.1.0-rc.7/Cargo.toml:62-66`, `ml-kem-0.3.0-rc.0/Cargo.toml:61-64`, `slh-dsa-0.2.0-rc.4/Cargo.toml:45-48`) are not enabled.
  - `awslc_backend.rs:442-447` and `:497-501`: GCM and CBC decryption leave the plaintext in the `in_out`/`data` buffer after `.to_vec()`.
  - `awslc_backend.rs:549-553`: OAEP `plaintext` buffer.
  - `awslc_backend.rs:719-723`: the unwrapped key in `output`.
  - `awslc_backend.rs:639-645`: the Ed25519 `seed` stack array.
  - `wrap.rs:81`, `:91` and `:101`: successful unwraps return a plain `Vec<u8>`.
  - `pqc.rs:146`, `:191`, `:198` and `:207`: the ML-KEM shared secret is returned as a plain `Vec`, and the `ss`/`dk` arrays are not zeroized.
  - `derive.rs:146`: the HKDF PRK inside `Hkdf` is not zeroized.
- **CWE:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse), CWE-244
- **Confidence:** Confirmed
- **Description:**
  - Without `aes/zeroize`, every `Aes256Gcm`, `Kek` and cbc/ctr instance frees its expanded key schedule unscrubbed. That schedule is equivalent to the key.
  - Without `ml-dsa/zeroize`, the `Drop` that scrubs `s1`, `s2`, `t0` and `K` (`ml-dsa-0.1.0-rc.7/src/lib.rs:290-303`) is compiled out. Every `ml_dsa_sign` expands the full secret key onto the heap and stack and leaves it there.
  - `slh-dsa` and `ml-kem` behave the same way.
  - Plaintext buffers from aws-lc decryption and key unwrap are copied into new `Vec`s, and the originals are dropped without zeroization.
  - The `RawKeyMaterial` and `mlock` effort is undermined by these unscrubbed copies.
- **Impact:** Key material persists in freed memory, where core dumps, swap (the copies are not mlocked), a memory-disclosure bug or a cold-boot attack can recover it.
- **Recommendation:**
  - Enable `aes = { features = ["zeroize"] }` and `aes-gcm/zeroize`, and turn on the `zeroize` features of `ml-kem`, `ml-dsa` and `slh-dsa`.
  - Return `Zeroizing<Vec<u8>>` or `RawKeyMaterial` from every decrypt, unwrap and decapsulate function.
  - In `awslc_backend.rs`, truncate the `in_out` buffer in place instead of copying, or wrap it in `Zeroizing`.

### H2-10 [Medium] The RSA parsed-key cache is never cleared and outlives `C_DestroyObject`; its "zeroizing" `Drop` is dead code

- **Location:**
  - `src/crypto/sign.rs:68-100`: `RSA_KEY_CACHE`.
  - `clear_rsa_key_cache()` (`:98`) has **no callers** anywhere in `src/`, contrary to its doc comment "Called on C_Finalize / C_InitToken".
  - `sign.rs:44-66`: `ZeroizingRsaKey::drop`.
- **CWE:** CWE-459 (Incomplete Cleanup), CWE-226
- **Confidence:** Confirmed
- **Description:**
  - Up to 64 parsed `RsaPrivateKey`s (d, p, q, dP, dQ, qInv as bignums) stay resident in a process-global map indefinitely. They survive `C_DestroyObject`, `C_Logout`, `C_Finalize` and `C_InitToken`, and are evicted only when the 65th distinct key arrives.
  - The custom `Drop` achieves nothing:
    - it exports the key to PKCS#8, creating two more transient copies of the secret, and scrubs one of them;
    - it then calls `RsaPrivateKey::from_components(3, 3, 1, vec![3])`, which always returns `Err(NprimesTooSmall)` (`rsa-0.9.10/src/key.rs:254-257`), so the "overwrite" branch never runs.
  - The real scrubbing comes from rsa's own `Drop`, `key.rs:76-84`.
- **Impact:**
  - A key the user believes is destroyed stays in process memory.
  - The cache is keyed by `SHA-256(DER)`, and the SHA-256 of a private-key DER is kept for the life of the process.
  - Every drop pays a needless PKCS#8 encoding.
- **Recommendation:**
  - Call a new `evict_rsa_key(der)` from `C_DestroyObject`, and `clear_rsa_key_cache()` from `C_Finalize`, `C_InitToken` and `C_Logout`, or key the cache by object handle and generation.
  - Delete `ZeroizingRsaKey` and rely on `RsaPrivateKey: ZeroizeOnDrop`.
  - Consider not caching private keys at all when `fips_approved_only` is set.

### H2-11 [Medium] CBC/CTR IV-reuse detection is easy to bypass, and its global cap is a cross-tenant DoS

- **Location:**
  - `src/crypto/encrypt.rs:136-206`: tracker keyed by `SHA-256(key)`.
  - `:148` and `:159-167`: `MAX_TRACKED_KEYS = 10_000` is process-global.
  - `:209-211`: `reset_iv_trackers()`, called on every POST (`self_test.rs:25-26`), i.e. on every `C_Initialize` (`functions.rs:244`, `:251`).
  - `:645-657`: CTR checks exact IV equality only.
- **CWE:** CWE-323, CWE-400 (Uncontrolled Resource Consumption)
- **Confidence:** Confirmed
- **Description:**
  - **Bypasses:**
    1. Any application in the process can call `C_Finalize` and then `C_Initialize` to wipe the tracker.
    2. A process restart wipes it too.
    3. For CTR, only identical 16-byte IVs are caught. Encrypting 32 bytes under IV = X and then under IV = X+1 reuses keystream block X+1 (a two-time pad), and the tracker does not notice.
    4. `ulCounterBits` from `CK_AES_CTR_PARAMS` is ignored, so counter-overflow policy cannot be enforced.
  - **DoS:** a single low-privilege session can generate 10,000 session AES keys and CBC- or CTR-encrypt once with each. Session objects are never removed from the tracker, because only `C_DestroyObject` calls `remove_gcm_counter`. After that, `check_iv_reuse` returns `CKR_GENERAL_ERROR` for *every new key of every user* (`:159-167`) until the next re-initialisation. Similarly, after 100,000 IVs a key is permanently barred from CBC and CTR encryption (`:194-202`).
- **Impact:** A protection that looks strong but is not, plus an availability attack across tenants.
- **Recommendation:**
  - For CTR, generate the counter block inside the HSM, or track (IV, blocks) ranges per key with persisted high-water marks.
  - Do not clear trackers on `C_Initialize`.
  - Scope caps per session or per object and evict entries on session close.
  - Consider dropping the tracker for CBC, where caller-chosen unpredictable IVs are the real requirement, and generating IVs internally instead.

### H2-12 [Low] GCM state maps grow without bound, and a DashMap shard lock is held for the entire encryption

- **Location:** `src/crypto/encrypt.rs:34-35` and `:42-43` (no cap), `:244-246` and `:330-332` (`RefMut` held until the function returns).
- **CWE:** CWE-400, CWE-833
- **Confidence:** Confirmed
- **Description:**
  - Every key ever used for GCM adds two entries that are removed only on `C_DestroyObject`. Session keys and C_Finalize cycles never shrink the maps.
  - `counter` is a `dashmap::RefMut`, which holds a shard *write* lock while AES-GCM runs over up to `AES_GCM_MAX_PLAINTEXT = 2^36-32` bytes (`:14`). That serialises all GCM encryptions of keys in the same shard.
  - `aes_cbc_decrypt` sleeps for 10 ms while the caller holds the key object's read lock (`functions.rs:1572` onward).
- **Impact:** Memory exhaustion in long-running processes, and a throughput collapse or amplification lever.
- **Recommendation:** Copy the counter value out with `fetch_update` and drop the `RefMut` before encrypting. Add caps and LRU eviction consistent with H2-02's persisted counters. Cap single-shot GCM at a practical size, for example 64 MiB, matching `MAX_SINGLE_BUFFER`.

### H2-13 [Low] `CKM_AES_CBC` is implemented as CBC-PAD; a padding oracle remains through the return code; the 10 ms sleep does not help

- **Location:** `src/pkcs11_abi/functions.rs:1617` and `:1862`, which route `CKM_AES_CBC | CKM_AES_CBC_PAD` to the same code; `src/crypto/encrypt.rs:522-534` (PKCS#7 always); `:546-619` (decrypt with the sleep floor).
- **CWE:** CWE-209, CWE-684
- **Confidence:** Confirmed
- **Description:**
  - Raw `CKM_AES_CBC` must not pad. Encrypting a block-aligned plaintext adds an extra block.
  - Decrypting raw-CBC data from another system either fails, or *silently strips* trailing bytes that happen to look like valid padding (for example a final byte of `0x01`). This is silent data corruption.
  - For CBC-PAD, success versus `CKR_ENCRYPTED_DATA_INVALID` is itself the Vaudenay oracle. The 10 ms `sleep` only equalises timing, which is not the signal, and it caps each thread at about 100 decrypts per second.
- **Impact:** Interoperability failures and silent truncation. The padding-oracle exposure remains for any service that relays decrypt results.
- **Recommendation:** Implement raw CBC (`NoPadding`, rejecting non-multiples of 16) for `CKM_AES_CBC`. Remove the sleep, and document that CBC-PAD decryption is an oracle by design. Steer users to GCM.

### H2-14 [Low] `CKM_AES_KEY_WRAP_KWP` is advertised but implemented as RFC 3394 KW; unwrap uses a non-constant-time integrity check

- **Location:** `src/crypto/mechanisms.rs:85` and `:123-124` advertise KWP. `src/crypto/wrap.rs:11-105` uses only `Kek::wrap`/`unwrap` (RFC 3394), and the mechanism is never passed down (`functions.rs:5066`, `:5170`). The comparison is at `aes-kw-0.2.1/src/lib.rs:238`: `block[..IV_LEN] == IV[..]`.
- **CWE:** CWE-684, CWE-208
- **Confidence:** Confirmed
- **Description:**
  - KWP (RFC 5649) callers get KW output, which peers cannot unwrap.
  - Non-multiple-of-8 keys, including every PKCS#8 RSA or EC private key, are rejected with `DataLenRange`.
  - There is no check that the wrapping key is at least as strong as the wrapped key; AES-128 can wrap an RSA-4096 key.
  - The 8-byte integrity check uses slice `==`. The timing signal is small and depends on the attacker-controlled blob, so risk is low.
- **Recommendation:** Pass the mechanism to the backend and use `Kek::wrap_with_padding` / `unwrap_with_padding` for KWP. Enforce the SP 800-57 strength ordering. Prefer a constant-time IV comparison, for example through the aws-lc path.

### H2-15 [Low] DRBG health testing checks the wrong thing and does not latch; some randomness bypasses the DRBG

- **Location:**
  - `src/crypto/drbg.rs:185-226` (`generate`) and `:230-238` (`health_check`).
  - `drbg.rs:78` and `:161`: `OsRng.fill_bytes`, which panics on failure.
  - `src/pkcs11_abi/functions.rs:3280-3284`: `C_GenerateRandom` uses `OsRng` directly.
  - `src/crypto/awslc_backend.rs:269`: `OsRng` for PSS salt.
- **CWE:** CWE-330, CWE-754
- **Confidence:** Confirmed
- **Description:**
  - The "continuous test" compares consecutive DRBG *output* blocks, which is statistically meaningless (probability 2^-256). No test is run on the *entropy input*, which is what SP 800-90B §4.4 requires (RCT/APT).
  - A fresh DRBG is built for every operation, so single-block requests (32 bytes or fewer, e.g. every GCM prefix and ECDSA nonce seed) are never tested.
  - On failure, `HmacDrbg::generate` returns an error without setting `POST_FAILED`. Only the `DrbgRng` adapter aborts the process.
  - `max_number_of_bits_per_request` (2^19) is not enforced.
  - `C_GenerateRandom` and the aws-lc PSS path skip the DRBG entirely, contradicting `drbg.rs:248-249`.
- **Impact:** Mostly compliance. A stuck or low-entropy OS source would not be detected.
- **Recommendation:**
  - Implement the RCT and APT on raw `getrandom` output.
  - Latch a module-wide error state on any DRBG or health failure.
  - Use `try_fill_bytes` and map errors instead of panicking.
  - Route `C_GenerateRandom` through a shared DRBG.
  - Enforce the 64 KiB per-request limit.

### H2-16 [Low] Signature verification is not strict (Ed25519 small-order keys, ECDSA high-S); the placeholder integrity key is forgeable

- **Location:** `src/crypto/sign.rs:594` (`verifying_key.verify`, not `verify_strict`), `sign.rs:490-492` and `:528-530` (ECDSA accepts high-S), `src/crypto/integrity.rs:66` (all-zero placeholder key), `:146-151` and `:199-214`.
- **CWE:** CWE-347
- **Confidence:** Likely (library semantics)
- **Description:**
  - `ed25519_dalek::VerifyingKey::verify` is cofactorless and accepts small-order public keys and small-order R values.
  - The all-zero placeholder `INTEGRITY_PUBLIC_KEY` decompresses to a small-order point (order 4). Non-strict verification against a small-order key does not give signature security.
  - The warning at `:147-150` says "Signature verification will fail". That is not guaranteed.
  - This matters only in non-FIPS builds with a `.sig` file present, because FIPS builds reject the placeholder.
- **Trigger condition:** a non-FIPS build compiled without `CRATON_HSM_INTEGRITY_PUBLIC_KEY`, with a `.sig` sidecar present. For user keys, any `C_Verify(CKM_EDDSA)` against a small-order public key, or any ECDSA signature supplied in high-S form.
  - ECDSA verification accepts both (r, s) and (r, n−s), which is malleable.
- **Recommendation:** Use `verify_strict` everywhere, including integrity. Reject weak keys in `ed25519_verify`. In non-FIPS builds, treat the placeholder key as "integrity disabled" rather than attempting verification. Optionally normalise or require low-S for ECDSA.

### H2-17 [Low] The integrity self-test fails open

- **Location:** `src/crypto/integrity.rs:85-94` (unknown module path gives `Ok`, even in FIPS builds) and `:127-143` (missing `.sig` gives `Ok` in non-FIPS builds).
- **CWE:** CWE-636 (Not Failing Securely)
- **Confidence:** Confirmed
- **Description:**
  - An attacker who modifies the library deletes the sidecar `.sig`, and the check passes in any non-FIPS build.
  - In FIPS builds, a `dladdr` failure (for example static linking into the daemon, or an unusual loader) also passes.
  - The check hashes the on-disk file rather than the mapped image, so there is a time-of-check/time-of-use gap after load.
- **Recommendation:** In FIPS builds, return `Err` when the module path cannot be resolved. Consider embedding the expected digest into a signed section, or verifying `/proc/self/map_files` for the mapped segments.

### H2-18 [Low] `mlock` is page-granular but applied per buffer; `munlock` on drop unlocks other live keys, and failures are only logged

- **Location:** `src/crypto/mlock.rs:13-48`; `src/store/key_material.rs:39-41` (only warns on failure) and `:86-92` (`munlock` in `Drop`).
- **CWE:** CWE-591 (Sensitive Data Storage in Improperly Locked Memory)
- **Confidence:** Confirmed (Linux `mlock` locks do not stack)
- **Description:**
  - Many small `RawKeyMaterial` boxes share heap pages. Dropping one key calls `munlock` on its range, which unlocks every page it touches, including pages holding other live keys. Those pages then become swappable.
  - The default `RLIMIT_MEMLOCK` (often 64 KiB, or 8 MiB on newer distros) is quickly exhausted, and later failures are silently ignored.
- **Recommendation:** Allocate key material from a dedicated, page-aligned, locked arena (for example the `memsec` or `secrets` crates), or reference-count page locks. Use `MADV_DONTDUMP`. Surface an error, or a metric, when locking fails.

### H2-19 [Low] Hybrid ML-DSA+ECDSA signing takes the "ECDSA private key" from the public `CKA_EC_POINT`, and the scheme has no domain separation

- **Location:** `src/pkcs11_abi/functions.rs:2184-2191`, which passes `CKA_EC_POINT` as `ecdsa_sk_bytes`; `src/crypto/pqc.rs:427-441` and `:447-488`.
- **CWE:** CWE-321, CWE-347
- **Confidence:** Confirmed (code path)
- **Description:**
  - An uncompressed EC point is 65 bytes, so `SigningKey::from_slice` rejects it and the mechanism always fails.
  - If an object is created with a 24–32-byte `CKA_EC_POINT`, the classical half is signed with a *public* value, so anyone can forge it.
  - No key-generation path exists for `CKM_HYBRID_ML_DSA_ECDSA`.
  - Both components sign the same message with no label or combiner, so each component can be stripped and reused as a standalone `CKM_ECDSA_SHA256` or ML-DSA signature on keys that are also used on their own.
- **Recommendation:** Store the ECDSA secret as proper key material in a linked private object. Adopt a composite-signature construction (IETF `draft-ietf-lamps-pq-composite-sigs`) with a domain-separation prefix. Until then, remove the mechanism from `supported_mechanisms()`.

### H2-20 [Low] PQC API use: deterministic ML-DSA with no context; pre-release crates; secret outputs not zeroized

- **Location:** `src/crypto/pqc.rs:279`, `:284` and `:289` (`Signer::sign` becomes `raw_sign_deterministic(msg, &[])` per `ml-dsa-0.1.0-rc.7/src/lib.rs:563-575`); `Cargo.toml` (ml-kem 0.3.0-rc.0, ml-dsa 0.1.0-rc.7, slh-dsa 0.2.0-rc.4); `pqc.rs:145-146` and `:190-207`.
- **CWE:** CWE-1104 (Use of Unmaintained Third Party Components), CWE-226
- **Confidence:** Confirmed
- **Description:**
  - FIPS 204 recommends the *hedged* variant. The deterministic variant is more exposed to fault attacks, a point the codebase itself makes for ECDSA at `sign.rs:458-464`.
  - PKCS#11 3.2 context strings (`CK_SIGN_ADDITIONAL_CONTEXT`) and HashML-DSA are not supported.
  - All three PQC crates are release candidates with unstable APIs and no audit history. Their `zeroize` features are off (see H2-09).
  - ML-KEM decapsulation re-expands the key from its seed on every call. That is correct, but the expanded key is never scrubbed.
  - Validation is sound: ML-KEM `EncapsulationKey::new` runs the modulus check, and verifying-key and signature decoding is length-checked.
- **Recommendation:** Use `sign_randomized` with the DRBG (hedged), expose context strings, pin exact PQC versions with a tracking issue for 1.0, and enable `zeroize`.

### H2-21 [Informational] FIPS policy inaccuracies and ignored PSS/OAEP parameters

- **Location:** `src/crypto/keygen.rs:33` and `src/crypto/wrap.rs:20` and `:67` (AES-128 rejected "per FIPS 140-3", although AES-128 is approved); `keygen.rs:60` (RSA-2048 generation rejected, but 2048-bit keys are accepted for use at `sign.rs:105`); `mechanisms.rs:160-162` (Ed25519 marked non-approved, although FIPS 186-5 approves it); `sign.rs:617-625` (the `CKM_RSA_PKCS_PSS` generic mechanism is unusable, and for the hashed variants `CK_RSA_PKCS_PSS_PARAMS` hashAlg/mgf/sLen are never validated because sLen is fixed to hLen); `functions.rs:197-219` (OAEP `mgf` and `pSourceData` label ignored).
- **Confidence:** Confirmed
- **Impact:** Over-restriction and inconsistent policy. Silent parameter mismatches produce signatures or ciphertexts peers reject. A non-empty OAEP label is silently not bound.
- **Recommendation:** Align with SP 800-131A Rev 2 and FIPS 186-5. Parse and validate the PSS and OAEP params, rejecting any mismatch between MGF hash and hash, any sLen other than the supported one, and any non-empty label unless supported.

### H2-22 [Informational] Non-standard mechanism-parameter encodings cause silent interoperability failures

- **Location:** `functions.rs:1626-1631` (`CKM_AES_CTR` expects a raw 16-byte IV, whereas `CK_AES_CTR_PARAMS` is 24 bytes on LP64 and is rejected); `functions.rs:5316-5360` (ECDH treats the whole `CK_ECDH1_DERIVE_PARAMS` blob as the peer point); `encrypt.rs:301-305` (GCM output is prefixed with the nonce).
- **Confidence:** Confirmed
- **Impact:** Standards-compliant PKCS#11 clients (OpenSSL pkcs11-provider, NSS, Java SunPKCS11) fail, which pushes integrators toward ad-hoc encodings.
- **Recommendation:** Parse the standard structs in the ABI layer and pass typed parameters into the crypto trait.

---

## Stubs, TODOs and unimplemented items

| Location | Item | Impact |
|---|---|---|
| `Cargo.toml` (`getrandom_new` / `rand_core_new` aliases) | `TODO: Remove aliases once RustCrypto migrates to rand_core 0.10` | Two RNG ecosystems in one binary, which complicates auditing |
| `src/crypto/integrity.rs:21-68` | All-zero **placeholder** integrity public key when `CRATON_HSM_INTEGRITY_PUBLIC_KEY` is unset | Integrity silently disabled in non-FIPS builds; forgeable (H2-16) |
| `src/crypto/sign.rs:98` | `clear_rsa_key_cache()` is never called; the doc says it is called on `C_Finalize` / `C_InitToken` | Destroyed keys stay resident (H2-10) |
| `src/crypto/sign.rs:57-64` | Dummy-key overwrite in `ZeroizingRsaKey::drop` always fails (dead code) | Misleading claim of zeroization |
| `src/crypto/sign.rs:232-236`, `:279-284` | `CKM_RSA_PKCS` (raw or no hash) is advertised (`mechanisms.rs:11`, `:98`) but always returns `MechanismParamInvalid` | Mechanism is effectively unimplemented |
| `src/crypto/sign.rs:622` | `CKM_RSA_PKCS_PSS` (generic, parameterised) returns `MechanismParamInvalid` and has no parameter parser | Advertised but unimplemented |
| `src/crypto/wrap.rs` | `CKM_AES_KEY_WRAP_KWP` has no RFC 5649 implementation | Mislabelled mechanism (H2-14) |
| `src/crypto/pqc.rs:425-488` | Hybrid mechanism has no key generation and signs with the public point | Broken feature (H2-19) |
| `src/crypto/encrypt.rs:315`, `:407` | `*_with_aad` GCM functions are never called by the ABI | AAD support is stubbed out (H2-01) |
| `src/crypto/encrypt.rs:687-700` | Deprecated `aes_ctr_crypt` without IV tracking still exported as `pub` | Foot-gun for internal callers |
| `src/crypto/digest.rs:10-12` | `HASHER_ZEROIZE_BUF_SIZE`, marked `#[allow(dead_code)]` | Dead constant |
| `src/crypto/awslc_backend.rs:204-219` | Prehashed operations "lack aws-lc APIs, use RustCrypto" | FIPS boundary gap (H2-04, H2-05) |
| `src/crypto/self_test.rs` | No KATs for KW/KWP, HKDF, P-384, PSS, OAEP, Ed25519, SLH-DSA, SHA3-384/512 or DRBG | Incomplete POST (H2-08) |
| `src/crypto/drbg.rs:362-381` | `test_drbg_deterministic` checks only that two instances match, not NIST CAVP vectors | No DRBG KAT |

No `todo!()`, `unimplemented!()`, `FIXME`, `XXX` or `HACK` markers appear in `src/crypto/`. Every `unwrap()`/`expect()` outside tests is on an already-validated length or a constant HMAC key size (`encrypt.rs:514`, `:653`; `drbg.rs:117-199`), and none can panic on attacker input.

## Code review

**Architecture**
- The `CryptoBackend` trait is too low-level and too narrow. It has no IV, AAD, tag, hash or KDF parameters, which is the root cause of H2-01, H2-06 and H2-07.
- Security policy is spread across RustCrypto free functions instead of a shared layer (H2-04).
- PQC code bypasses the trait completely.
- Recommendation: introduce typed parameter structs (`GcmParams`, `EcdsaParams { hash: Option<HashAlg> }`, `EcdhParams { kdf, shared_info, peer }`) and a policy decorator around the backend.

**Global mutable state**
- Five process-global `LazyLock<DashMap>`s hold security state: the GCM counters, GCM prefixes, IV trackers and RSA cache.
- They are keyed by key bytes rather than object identity. They are not fork-aware, not persisted, and reset at inconsistent lifecycle points (H2-02, H2-10, H2-11).
- This state should be owned by `HsmCore` and the object store.

**Error handling**
- Most crypto failures collapse into `GeneralError`, which is fine for oracles but makes diagnosis hard.
- `rsa_pkcs1v15_sign` with `None` returns `MechanismParamInvalid` in one backend and `MechanismInvalid` in the other.
- `DrbgRng::fill_bytes` calls `abort()`. That is defensible, but it happens only in the adapter; direct `HmacDrbg` users get an `Err` and no latch.

**Idioms**
- Many `match hash_alg { Sha256 => {…}, Sha384 => {…}, Sha512 => {…} }` blocks repeat the same body (for example `sign.rs:210-231` and `:308-324`). A generic helper `fn with_hash<D: Digest…>` would remove about 300 lines.
- `aes_256_gcm_encrypt` and `_with_aad` duplicate the CAS loop.
- `debug_assert!` in `digest.rs:153-157` becomes a no-op in release builds. Make it a `const` assertion.

**Unsafe code**
- `GenericHasher::drop` (`digest.rs:142-177`) zeroes raw bytes of `D` and suppresses its `Drop`. This is sound only for plain-old-data hashers, and the property is not enforced at compile time.
- It is simpler to enable `sha2/zeroize` (sha2 0.11) or use `Zeroizing<D>`.
- `unsafe impl Send/Sync for AwsLcHasher` (`awslc_backend.rs:963-964`) is probably unnecessary, since `digest::Context` is `Send`. It hides future regressions.

**Build hygiene**
- `rust-version = "1.75"`, but `std::sync::LazyLock` needs 1.80 (`encrypt.rs:34`, `sign.rs:21`).
- `cipher = "0.5"` and `secrecy = "0.10"` are declared but unused in `src/`.
- `aws-lc-rs` is built with `features = ["fips"]`, which requires Go and CMake at build time; this is not documented.

**Test gaps**
- No negative tests for GCM with AAD or tag lengths.
- No test for CTR overlapping-counter reuse.
- No two-party ECDH agreement test, which would have caught H2-06.
- No cross-backend differential tests.
- No `C_CopyObject`/`C_DestroyObject` nonce-reset test.
- No fork test.
- No NIST CAVP/ACVP vectors.
- No constant-time testing (for example dudect) of the RSA paths.

**Documentation versus code**
- Several comments claim guarantees the code does not provide:
  - `encrypt.rs:41`: "guarantees nonce uniqueness … across restarts";
  - `sign.rs:96`: "Called on C_Finalize";
  - `drbg.rs:12`: "SP 800-90B §4.9" health test;
  - `self_test.rs:9-16`: "KATs cover all approved algorithms".
- These should be corrected so reviewers are not misled.

## Performance improvement suggestions

1. **DRBG per call, reseed per generate** (`drbg.rs:185-192`, `keygen.rs:19-22`, `DrbgRng` in `sign.rs`, `pqc.rs`).
   - Every `fill_bytes`/`next_u32` does a `getrandom` syscall and about 7 HMAC-SHA256 computations.
   - RSA key generation calls the RNG hundreds of times.
   - Suggestion: keep one DRBG per thread, fork-aware through a PID check. Reseed on interval or on request, and use prediction resistance only where policy demands it.
   - Expected gain: large for RSA and EC key generation and for high-rate ECDSA signing.
2. **Shard lock held during GCM** (`encrypt.rs:244-305`). Take the counter value with `fetch_update`, drop the `RefMut`, and only then encrypt. This removes serialisation across keys and threads.
3. **`SHA-256(key)` computed twice per GCM encryption** (`gcm_key_id` at `:243` and inside `gcm_nonce_prefix` at `:114`) and again per CBC/CTR operation. Compute it once and pass it down, or key by object ID.
4. **Cipher instance built per call** (`Aes256Gcm::new` at `encrypt.rs:284`, `UnboundKey::new` in aws-lc). The AES key schedule and GHASH table are rebuilt for every operation. Cache a keyed cipher context in the session's active operation (zeroizing on drop).
5. **RSA cache clone per operation** (`sign.rs:80`). `RsaPrivateKey::clone()` copies every bignum and the precomputed CRT values. Store `Arc<RsaPrivateKey>` and borrow it instead. Remove the PKCS#8 export in `ZeroizingRsaKey::drop` (`sign.rs:49-52`), which costs a DER encoding on every eviction.
6. **CBC decrypt 10 ms sleep** (`encrypt.rs:612-616`). It caps throughput at about 100 operations per second per thread and adds no security (H2-13). Remove it.
7. **POST generates an RSA-2048 key on every `C_Initialize`** (`self_test.rs:343`), which takes 100–1000 ms. A fixed-key KAT is faster and a better test (H2-08).
8. **ML-KEM and ML-DSA re-expand keys from their seeds on every operation** (`pqc.rs:185`, `:278`). Cache the expanded key per session or operation, scrubbed with `zeroize` enabled.
9. **`aes_ctr_apply` / `aes_cbc_*` copy the input with `to_vec()`** (`encrypt.rs:729`). Encrypting in place in a caller-provided buffer would avoid a copy of up to 256 MiB.
