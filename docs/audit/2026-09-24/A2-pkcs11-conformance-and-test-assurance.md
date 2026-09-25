# A2 — PKCS#11 v3.0 conformance & test assurance assessment

| Item | Value |
|---|---|
| Target | craton-hsm (`craton_hsm` crate, PKCS#11 C ABI in `src/pkcs11_abi/`) |
| Revision | `2f76874` ("Open-source initial commit"), worktree `/home/user/craton-hsm-audit-wt` |
| Report date | 2026-09-25 (audit series 2026-09-24) |
| Requested by | Code owner |
| Review type | Static source review only. No build, test, clippy or fuzz runs were performed by the author. One lint measurement was supplied by the audit orchestrator and is marked as such. |
| Companion reports | A1 (FIPS 140-3 readiness), A3 (supply chain / stub inventory), H1 (ABI security), H2 (crypto), H3 (store/session/token) |

## Scope, standards & method

**In scope**

- The exported C ABI: `src/pkcs11_abi/functions.rs`, `types.rs`, `constants.rs`.
- The code those entry points call for session state, object storage, attribute policy and mechanism dispatch: `src/session/`, `src/store/attributes.rs`, `src/store/object.rs`, `src/token/token.rs`, and `src/crypto/{sign,encrypt,wrap,derive,pqc,mechanisms}.rs`.
- Test assurance: `tests/*.rs` (35 integration test files, 689 `#[test]` functions), `fuzz/fuzz_targets/*.rs` (12 targets), `tests/interop/`, and the CI workflow `.github/workflows/ci.yml`.
- Documentation claims in `README.md` and `docs/*.md` that describe PKCS#11 behaviour.

**Out of scope:** the gRPC daemon, the admin CLI, pkcs11-spy, and deployment artefacts (see H4, H5, H6, A3). Cryptographic strength and FIPS module boundary questions are covered by H2 and A1. They are mentioned here only where they affect PKCS#11 conformance.

**Reference standards**

- OASIS *PKCS #11 Cryptographic Token Interface Base Specification Version 3.0* (June 2020), in particular §5 (function list and interfaces), §4.4 (object visibility and roles), §4.14 (secret-key attributes, `CKA_SENSITIVE`/`CKA_EXTRACTABLE`), §5.6 (session management and roles), and §5.7 (`C_InitToken`).
- OASIS *PKCS #11 Current Mechanisms Specification Version 3.0*: §2.3 (ECDSA signature encoding), §2.3.x (ECDH1 derive parameters), §2.14 (AES-CBC / CBC-PAD), §2.15 (AES-GCM `CK_GCM_PARAMS`), §2.1.x (RSA PKCS #1 and PSS), and §2.14.x (AES key wrap and KWP).
- OASIS *PKCS #11 Profiles Version 3.0* (Baseline Provider, Extended Provider, Authentication Token).
- Common Criteria v3.1 R5 assurance classes, used as a lens rather than as a formal evaluation: ADV_FSP (functional specification accuracy), ATE_COV/ATE_FUN (test coverage and depth), and AGD_OPE (guidance accuracy).

**Method**

1. List every `#[no_mangle] extern "C"` export and compare it with the v2.40 `CK_FUNCTION_LIST` and the v3.0 `CK_FUNCTION_LIST_3_0`.
2. Trace each entry point for argument validation, role and session-state checks, and attribute policy.
3. For every mechanism returned by `C_GetMechanismList`, compare parameter parsing and output encoding with the Mechanisms specification.
4. Review the tests for what they actually assert, whether they can pass against the current code, and where their vectors come from.
5. Cross-check documentation claims against the code.

A previous auditor's unsaved results were supplied as leads. Each lead was re-verified against the source. Only items confirmed in code are reported, and several additional items found during verification are included.

**Severity scale:** *Critical* means the item blocks any conformance claim, or breaks a core security invariant of the token model. *High* means a normative requirement is violated in a way that breaks interoperability or access control for common clients. *Medium* means a normative deviation with limited reach, or a significant assurance gap. *Low* means a minor deviation or a hygiene issue. *Informational* means an observation with no direct conformance impact.

## Overall verdict with rationale

**Verdict: NOT READY. The module does not conform to PKCS#11 v3.0, and it is not certification-ready as a v2.40 provider either.**

Rationale:

1. **The version claim is unsupported (A2-01).** The library exports exactly the 68 functions of the v2.40 function list and none of the 24 functions added in v3.0. Even so, `CK_INFO.cryptokiVersion` and `CK_FUNCTION_LIST.version` both report 3.0. Because `C_GetInterfaceList`/`C_GetInterface` are missing, no v3.0 profile (Baseline, Extended, Authentication Token) can be claimed.
2. **Core token-model invariants are violated (A2-02 to A2-05):**
   - `C_InitToken` destroys every object before it authenticates the SO.
   - The SO role is granted user-object access.
   - `CKA_SENSITIVE` does not prevent `CKA_VALUE` disclosure.
   - `C_SetOperationState` binds operations to keys without authorization checks.

   Each of these contradicts a normative "shall" in the Base Specification.
3. **Several widely used mechanisms are not interoperable (A2-07 to A2-13):**
   - ECDSA signatures are DER-encoded rather than raw `r||s`.
   - `CK_GCM_PARAMS` is ignored.
   - `CKM_AES_CBC` pads.
   - `CKM_AES_KEY_WRAP_KWP` is actually RFC 3394 key wrap.
   - ECDH ignores `CK_ECDH1_DERIVE_PARAMS`.
   - `CKM_RSA_PKCS` and `CKM_RSA_PKCS_PSS` are advertised but can never succeed.

   Standard consumers (OpenSSL pkcs11 provider, p11-kit, NSS, SunPKCS11, pkcs11-tool) either fail or produce data that other implementations cannot process.
4. **Features documented as implemented are absent (A2-15 to A2-18, A2-28):** object persistence, multi-slot isolation, the hybrid X25519+ML-KEM mechanism, and a DRBG-backed `C_GenerateRandom`.
5. **Test evidence cannot support an ATE claim (A2-23 to A2-26):**
   - At least two ABI tests contradict the code and are expected to fail.
   - Several tests codify non-conformant behaviour.
   - There are no Wycheproof, CAVP or ACVP vectors at ABI level.
   - The fuzz harnesses never reach an authenticated state.
   - `cargo clippy --all-targets` fails with 116 errors, and CI suppresses the dominant lint.

The positive side:

- The v2.40 function table is complete, and its order matches the specification.
- Most entry points validate NULL pointers and are wrapped in `catch_unwind`.
- The two-call length idiom is generally implemented.
- The stub functions return the correct codes: `CKR_FUNCTION_NOT_SUPPORTED`, or `CKR_FUNCTION_NOT_PARALLEL` for the two legacy functions.

The findings are remediable. Most are local to the ABI layer or to mechanism parameter parsing.

## Function coverage matrix

Legend:

- **Implemented:** the function behaves substantially as specified.
- **Partial:** the function is implemented but deviates from a normative requirement (see the finding).
- **Stub:** the function is exported but only returns a fixed error.
- **Missing:** the function is not exported and has no function-list slot.

Line numbers refer to `src/pkcs11_abi/functions.rs` unless stated otherwise.

### v2.40 `CK_FUNCTION_LIST` (68 entries; table at `functions.rs:5459-5529`, order matches the specification)

| # | Function | Status | Notes |
|---|---|---|---|
| 1 | C_Initialize | Partial | `:226`. `CK_C_INITIALIZE_ARGS` is dereferenced but never validated: `pReserved`, mutex-callback consistency and `CKF_LIBRARY_CANT_CREATE_OS_THREADS` are ignored (A2-19). |
| 2 | C_Finalize | Implemented | `:280`. Rejects non-NULL `pReserved`. |
| 3 | C_GetInfo | Partial | `:310`. Reports `cryptokiVersion` 3.0 (`:320`) without the 3.0 interface (A2-01). |
| 4 | C_GetFunctionList | Partial | `:339`. The returned list's `version` field is 3.0 (`:5460`), but its layout is the v2.40 `CK_FUNCTION_LIST` (A2-01). |
| 5 | C_GetSlotList | Implemented | `:357` |
| 6 | C_GetSlotInfo | Implemented | `:405` |
| 7 | C_GetTokenInfo | Implemented | `:437`. Flags come from `token.rs:364-378`. |
| 8 | C_GetMechanismList | Partial | `:612`. Lists mechanisms that can never succeed (`CKM_RSA_PKCS` sign, `CKM_RSA_PKCS_PSS`) or that are implemented as another mechanism (`CKM_AES_KEY_WRAP_KWP`) (A2-11, A2-13). |
| 9 | C_GetMechanismInfo | Partial | `:660`. AES-GCM advertises 16–32-byte keys, but only 32-byte keys work (A2-09). |
| 10 | C_InitToken | Partial | `:484`. Destroys all objects and closes sessions before verifying the SO PIN. Does not return `CKR_SESSION_EXISTS` (A2-02). |
| 11 | C_InitPIN | Implemented | `:531`. Requires the SO role. |
| 12 | C_SetPIN | Implemented | `:572` |
| 13 | C_OpenSession | Implemented | `:786` |
| 14 | C_CloseSession | Partial | `:821`. Session objects created by the session are not destroyed (A2-14). |
| 15 | C_CloseAllSessions | Partial | `:848`. Same session-object issue as C_CloseSession (A2-14). |
| 16 | C_GetSessionInfo | Implemented | `:866` |
| 17 | C_GetOperationState | Partial | `:3311`. Hash-then-sign state is serialised without the hashed input (A2-06). |
| 18 | C_SetOperationState | Partial | `:3381`. No login, key-usage, private-object or lifecycle checks when binding `hAuthenticationKey`. The session is validated only after the blob is decoded (A2-05, A2-06). |
| 19 | C_Login | Partial | `:893`. `CKU_CONTEXT_SPECIFIC` is rejected with `CKR_USER_TYPE_INVALID` (`token.rs:679-680`) (A2-20). |
| 20 | C_Logout | Implemented | `:961` |
| 21 | C_CreateObject | Partial | `:1000`. Rejects read-only sessions even for session objects (`:1021`) (A2-21). |
| 22 | C_CopyObject | Implemented | `:3508`. Policy concerns are covered in H1-08. |
| 23 | C_DestroyObject | Implemented | `:1066`. Authorization concerns are covered in H1-07. |
| 24 | C_GetObjectSize | Implemented | `:1119` |
| 25 | C_GetAttributeValue | Partial | `:1160`. Reveals `CKA_VALUE` of sensitive keys that are also extractable. The SO can read private objects (A2-03, A2-04). |
| 26 | C_SetAttributeValue | Partial | `:1232`. Only `CKA_LABEL` and `CKA_ID` are modifiable (`:1284-1289`) (A2-21). |
| 27 | C_FindObjectsInit | Partial | `:1299`. Not scoped to the session's slot. The SO sees private objects (A2-03, A2-15). |
| 28 | C_FindObjects | Implemented | `:1343` |
| 29 | C_FindObjectsFinal | Implemented | `:1387` |
| 30 | C_EncryptInit | Partial | `:1414`. The mechanism parameter is kept as raw bytes, and `CK_GCM_PARAMS` is not parsed (A2-09). |
| 31 | C_Encrypt | Partial | `:1525`. The GCM output format and `CKM_AES_CBC` padding are non-standard (A2-09, A2-10). |
| 32 | C_EncryptUpdate | Implemented | `:3789`. Input is buffered, and output is produced at Final. The specification permits this. |
| 33 | C_EncryptFinal | Partial | `:3840`. Same mechanism deviations as C_Encrypt (A2-10). |
| 34 | C_DecryptInit | Partial | `:1713`. Same parameter handling as C_EncryptInit (A2-09). |
| 35 | C_Decrypt | Partial | `:1781`. Same mechanism deviations as C_Encrypt (A2-09, A2-10). |
| 36 | C_DecryptUpdate | Implemented | `:4000` |
| 37 | C_DecryptFinal | Partial | `:4052`. Same mechanism deviations as C_Decrypt (A2-10). |
| 38 | C_DigestInit | Implemented | `:4212` |
| 39 | C_Digest | Implemented | `:4259` |
| 40 | C_DigestUpdate | Implemented | `:4340` |
| 41 | C_DigestKey | Implemented | `:4390`. Authorization concerns are covered in H1-12. |
| 42 | C_DigestFinal | Implemented | `:4459` |
| 43 | C_SignInit | Implemented | `:1944`. Checks login, `CKA_SIGN` and lifecycle, but the SO passes the login check (A2-03). |
| 44 | C_Sign | Partial | `:2025`. ECDSA output is DER. The ECDSA hash is ignored. `CKM_RSA_PKCS`/`CKM_RSA_PKCS_PSS` always fail (A2-07, A2-08, A2-13). |
| 45 | C_SignUpdate | Implemented | `:4542` |
| 46 | C_SignFinal | Partial | `:4597`. ECDSA output is DER. `CKA_SIGN` is not re-checked after C_SetOperationState (A2-05, A2-07). |
| 47 | C_SignRecoverInit | Stub | `:4736`. Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| 48 | C_SignRecover | Stub | `:4745`. Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| 49 | C_VerifyInit | Implemented | `:2338` |
| 50 | C_Verify | Partial | `:2409`. Requires DER ECDSA signatures (A2-07). |
| 51 | C_VerifyUpdate | Implemented | `:4756` |
| 52 | C_VerifyFinal | Partial | `:4811`. Requires DER ECDSA signatures (A2-07). |
| 53 | C_VerifyRecoverInit | Stub | `:4919`. Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| 54 | C_VerifyRecover | Stub | `:4928`. Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| 55 | C_DigestEncryptUpdate | Stub | `:4939`. Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| 56 | C_DecryptDigestUpdate | Stub | `:4950`. Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| 57 | C_SignEncryptUpdate | Stub | `:4961`. Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| 58 | C_DecryptVerifyUpdate | Stub | `:4972`. Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| 59 | C_GenerateKey | Implemented | `:2508`. Authorization concerns are covered in H1-10. |
| 60 | C_GenerateKeyPair | Implemented | `:2688` |
| 61 | C_WrapKey | Partial | `:4983`. KWP is implemented as RFC 3394 key wrap (A2-11). |
| 62 | C_UnwrapKey | Partial | `:5101`. Same KWP deviation as C_WrapKey (A2-11). |
| 63 | C_DeriveKey | Partial | `:5263`. ECDH ignores `CK_ECDH1_DERIVE_PARAMS` and applies a proprietary KDF (A2-12). |
| 64 | C_SeedRandom | Implemented | `:3238`. Returns `CKR_RANDOM_SEED_NOT_SUPPORTED`, which is permitted. Documentation claims otherwise (A2-16). |
| 65 | C_GenerateRandom | Partial | `:3259`. Uses `OsRng` directly, not the documented DRBG, and has no continuous test (A2-16). |
| 66 | C_GetFunctionStatus | Stub (legacy) | `:5437`. Returns `CKR_FUNCTION_NOT_PARALLEL`, as the specification requires for legacy functions. |
| 67 | C_CancelFunction | Stub (legacy) | `:5442`. Returns `CKR_FUNCTION_NOT_PARALLEL`, as the specification requires for legacy functions. |
| 68 | C_WaitForSlotEvent | Stub | `:5447`. Returns `CKR_FUNCTION_NOT_SUPPORTED`, which is permitted. |

Totals for v2.40: Implemented 28, Partial 29, Stub 11 (9 return `CKR_FUNCTION_NOT_SUPPORTED`, 2 legacy functions return `CKR_FUNCTION_NOT_PARALLEL`), Missing 0.

### v3.0 additions to `CK_FUNCTION_LIST_3_0` (24 entries)

A search of `src/` finds no definition, declaration or type for any of the functions below. `CK_INTERFACE` and `CK_FUNCTION_LIST_3_0` are also absent.

| # | Function | Status | Notes |
|---|---|---|---|
| 69 | C_GetInterfaceList | Missing | This is the mandatory v3.0 discovery entry point, so v3.0 clients cannot locate the 3.0 table (A2-01). |
| 70 | C_GetInterface | Missing | Mandatory v3.0 entry point (A2-01). |
| 71 | C_LoginUser | Missing | Not exported (A2-01). |
| 72 | C_SessionCancel | Missing | Not exported (A2-01). |
| 73 | C_MessageEncryptInit | Missing | Not exported (A2-01). |
| 74 | C_EncryptMessage | Missing | Not exported (A2-01). |
| 75 | C_EncryptMessageBegin | Missing | Not exported (A2-01). |
| 76 | C_EncryptMessageNext | Missing | Not exported (A2-01). |
| 77 | C_MessageEncryptFinal | Missing | Not exported (A2-01). |
| 78 | C_MessageDecryptInit | Missing | Not exported (A2-01). |
| 79 | C_DecryptMessage | Missing | Not exported (A2-01). |
| 80 | C_DecryptMessageBegin | Missing | Not exported (A2-01). |
| 81 | C_DecryptMessageNext | Missing | Not exported (A2-01). |
| 82 | C_MessageDecryptFinal | Missing | Not exported (A2-01). |
| 83 | C_MessageSignInit | Missing | Not exported (A2-01). |
| 84 | C_SignMessage | Missing | Not exported (A2-01). |
| 85 | C_SignMessageBegin | Missing | Not exported (A2-01). |
| 86 | C_SignMessageNext | Missing | Not exported (A2-01). |
| 87 | C_MessageSignFinal | Missing | Not exported (A2-01). |
| 88 | C_MessageVerifyInit | Missing | Not exported (A2-01). |
| 89 | C_VerifyMessage | Missing | Not exported (A2-01). |
| 90 | C_VerifyMessageBegin | Missing | Not exported (A2-01). |
| 91 | C_VerifyMessageNext | Missing | Not exported (A2-01). |
| 92 | C_MessageVerifyFinal | Missing | Not exported (A2-01). |

Totals for the v3.0 additions: 0 of 24 present.

## Findings

Each finding lists its location, a description, the conformance/security impact, and a recommendation. "Related" points to overlapping findings in the companion reports of this audit series.

### A2-01 [Critical] PKCS#11 v3.0 conformance claim is unsupported: no v3.0 interface, but the version fields report 3.0

- **Location:**
  - `src/pkcs11_abi/functions.rs:320` (`CK_INFO.cryptoki_version = {3, 0}`)
  - `src/pkcs11_abi/functions.rs:5459-5529` (`static FUNCTION_LIST`, `version: {3, 0}` at `:5460`)
  - `README.md:13,17`
  - `docs/api-reference.md:7`
- **Description:**
  - The library exports 68 `#[no_mangle] extern "C"` functions, exactly the v2.40 `CK_FUNCTION_LIST`.
  - None of the 24 functions added in v3.0 exists in the source tree. This includes the mandatory discovery functions `C_GetInterfaceList` and `C_GetInterface`, plus `C_LoginUser`, `C_SessionCancel` and the 20 `C_Message*`/`C_*Message*` functions.
  - The types `CK_INTERFACE` and `CK_FUNCTION_LIST_3_0` are not defined.
  - Even so, both `C_GetInfo` and the function list returned by `C_GetFunctionList` report version 3.0.
  - Tests assert the 3.0 value (`tests/pkcs11_compliance.rs:40-41`, `tests/pkcs11_conformance.rs:777-781`), so the mismatch is codified.
- **Conformance/security impact:**
  - Base Spec v3.0 §5.4 requires a v3.0 token to provide `C_GetInterfaceList`/`C_GetInterface`. None of the v3.0 profiles can be claimed without them.
  - The v2.40 table carries a 3.0 version. Consumers that use the `version` field to decide whether to treat the table as `CK_FUNCTION_LIST_3_0` could read past the end of the 68-entry structure, which is undefined behaviour in the consumer.
  - The documentation (ADV_FSP, AGD_OPE) misstates the functional interface.
- **Recommendation:**
  - Choose one of two paths:
    - **(a) Declare v2.40:** set both version fields to `{2, 40}`, and correct the README, the API reference and the tests.
    - **(b) Implement the v3.0 interface:** add `C_GetInterfaceList`/`C_GetInterface` returning a v2.40 "PKCS 11" interface (version 2.40) and a `CK_FUNCTION_LIST_3_0` interface (version 3.0). Implement or stub (`CKR_FUNCTION_NOT_SUPPORTED`) all 24 new entries, and keep `C_GetFunctionList` returning the v2.40-layout table with version 2.40.
  - In either case, state the targeted OASIS profile explicitly in the documentation.

### A2-02 [Critical] C_InitToken destroys all objects and closes all sessions before verifying the SO PIN, and does not return CKR_SESSION_EXISTS

- **Location:**
  - `src/pkcs11_abi/functions.rs:514-522`: `close_all_sessions` at `:515`, `object_store.clear()` at `:518`, `force_reset_all_counters()` at `:520`, then `token.init_token` at `:522`.
  - `src/token/token.rs:403-431`: the SO PIN is verified only here.
- **Description:** The ABI function performs these steps in order:
  1. Closes every session on the slot.
  2. Clears the object store, which is global to all slots (see A2-15).
  3. Resets every AES-GCM, CBC and CTR counter and IV tracker.
  4. Only then calls `Token::init_token`, which validates the PIN format and verifies the existing SO PIN.

  A call that fails at step 4 because of an incorrect PIN, a PIN-policy violation or rate-limiting has already completed steps 1–3. In addition, the Base Specification requires `CKR_SESSION_EXISTS` when sessions are open. This implementation closes them silently instead.
- **Conformance/security impact:**
  - This violates Base Spec §5.6 (C_InitToken), which requires SO authentication of an initialized token before re-initialization, and requires `CKR_SESSION_EXISTS` when sessions are open.
  - The object destruction and loss of availability are not bound to any authenticated role, so they breach the integrity/availability invariant of the token model.
  - Resetting nonce and IV reuse tracking without re-keying also weakens the controls described in H2-02.
- **Recommendation:**
  - Verify the SO PIN, including rate limiting, first.
  - Return `CKR_SESSION_EXISTS` if any session is open on the slot.
  - Only after successful authentication, destroy the objects belonging to that slot and reset the per-key counters for those keys only.
  - Add negative ABI tests: wrong SO PIN leaves objects intact, and open sessions yield `CKR_SESSION_EXISTS`.
- **Related:** H1-01, H3-01, H3-14.

### A2-03 [High] The Security Officer role is treated as a logged-in user for access to private objects and cryptographic operations

- **Location:**
  - `src/session/session.rs:38-43` (`is_logged_in()` returns true for `RwSO`).
  - Consumers of `is_logged_in()` in `src/pkcs11_abi/functions.rs`: `:1041`, `:1142`, `:1186`, `:1265`, `:1329-1330`, `:1458`, `:1755`, `:1964`, `:2380`, `:3542`, `:5004`, `:5129`.
  - `src/store/attributes.rs:385`.
- **Description:** `SessionState::is_logged_in()` matches `RoUser | RwUser | RwSO`. Every access-control check for private objects and for starting a signature uses this predicate, so an SO session can:
  - see private objects in `C_FindObjects`;
  - read their attributes;
  - start `C_SignInit`, `C_EncryptInit`, `C_DecryptInit` and `C_VerifyInit` with private keys;
  - wrap and unwrap with them.
- **Conformance/security impact:**
  - Base Spec §4.4/§5.6 limits "R/W SO Functions" sessions to public objects. Private objects are accessible only to the normal user.
  - This breaks the role separation that the Authentication Token profile and any CC/FIPS role model depend on.
- **Recommendation:**
  - Introduce distinct predicates, for example `is_user()` and `is_so()`.
  - Gate private-object visibility and key-use operations on `is_user()` only.
  - Add ABI tests confirming that an SO session cannot enumerate, read or use `CKA_PRIVATE=TRUE` objects.
- **Related:** H1-05, H3-06.

### A2-04 [High] C_GetAttributeValue returns CKA_VALUE for keys with CKA_SENSITIVE=TRUE when CKA_EXTRACTABLE=TRUE

- **Location:**
  - `src/store/attributes.rs:566-580` (`read_attribute`, `CKA_VALUE` arm).
  - Called from `src/pkcs11_abi/functions.rs:1196`.
  - Codified by `tests/attribute_validation.rs:34-42`.
- **Description:** The code blocks `CKA_VALUE` only when `sensitive && !extractable`. The code comment describes a "sensitive + extractable ⇒ readable" convention. That convention does not exist in the standard.
- **Conformance/security impact:**
  - Base Spec §4.14 and the private-key/secret-key attribute tables require that when `CKA_SENSITIVE` is TRUE, `CKA_VALUE` (and the private components) cannot be revealed in plaintext outside the token. `C_GetAttributeValue` must return `CKR_ATTRIBUTE_SENSITIVE`.
  - `CKA_EXTRACTABLE` governs only wrapping (`C_WrapKey`), not plaintext attribute reads.
  - Keys that applications mark sensitive are therefore disclosed in the clear, contrary to the object's stated policy.
- **Recommendation:**
  - Return `CKR_ATTRIBUTE_SENSITIVE` for `CKA_VALUE` (and the RSA/EC private components) whenever `sensitive` is true, regardless of `extractable`.
  - Invert the test at `tests/attribute_validation.rs:34`.
  - Add an ABI-level test through `C_GetAttributeValue`.
- **Related:** H1-02, H3-02.

### A2-05 [High] C_SetOperationState binds a restored sign/verify operation to a caller-chosen key without authorization checks

- **Location:**
  - `src/pkcs11_abi/functions.rs:3381-3497`, in particular the `hAuthenticationKey` selection and bare existence check at `:3426-3435` (sign) and `:3456-3464` (verify).
  - The session is fetched only at `:3488`.
  - `C_SignFinal` at `:4597` does not re-check `CKA_SIGN`.
- **Description:**
  - When a caller supplies `hAuthenticationKey`, it replaces the key handle recorded in the authenticated state blob.
  - The only check applied to that key is that the handle exists.
  - The code does not check:
    - that the session is logged in (compare `C_SignInit` at `:1964`);
    - the private-object visibility rule;
    - `CKA_SIGN` or `CKA_VERIFY` (compare `:1999`);
    - lifecycle dates (compare `:2003`);
    - that the key type is compatible with the mechanism;
    - that the key belongs to the session's slot.
  - The session handle is validated only after the blob is decoded and the operation is rebuilt.
  - The subsequent `C_SignUpdate`/`C_SignFinal` path trusts the operation as initialized and does not repeat the `C_SignInit` checks.
- **Conformance/security impact:**
  - Base Spec §5.6 (C_SetOperationState) states that supplied keys must be ones the application could use for that operation, and that the restored state must be equivalent to a properly initialized operation.
  - The function therefore offers a path to key use that bypasses the authorization controls enforced on `C_SignInit`/`C_VerifyInit`.
  - This is also an undocumented service. `docs/fips-140-3-certification.md:334-336` lists the function as "not implemented".
- **Recommendation:**
  - Validate the session first.
  - Factor the complete `*Init` authorization logic (login, visibility, usage attribute, lifecycle, key type and mechanism compatibility, slot) into a shared helper, and call it for any key supplied or restored in `C_SetOperationState`.
  - Return `CKR_KEY_NOT_NEEDED` or `CKR_KEY_CHANGED` as the specification requires.
  - Alternatively, return `CKR_FUNCTION_NOT_SUPPORTED` for sign/verify state until this is done.
- **Related:** H1-04.

### A2-06 [Medium] Saved operation state loses the input for hash-then-sign/verify mechanisms, so restored operations sign a different message

- **Location:**
  - `src/pkcs11_abi/functions.rs:4576-4587` (`C_SignUpdate` feeds the hasher and leaves `data` empty) and `:4790-4801` (`C_VerifyUpdate`).
  - `src/session/session.rs:128` (`serialize_state` writes `data` only).
  - `src/pkcs11_abi/functions.rs:3426-3485` (restore re-hashes the empty `data`).
- **Description:**
  - For mechanisms with a built-in hash (for example `CKM_SHA256_RSA_PKCS` and `CKM_ECDSA_SHA256`), multi-part input goes only to the incremental hasher.
  - `C_GetOperationState` serialises the `data` buffer, which is empty in this case, and not the hasher state.
  - After `C_SetOperationState` a fresh hasher is created, so the resulting signature or verification covers only the input supplied after restoration.
- **Conformance/security impact:**
  - The specification requires the restored operation to continue exactly where it left off.
  - Here, signatures are computed over a message other than the one the application supplied, and verification results do not reflect the full input. This is a functional correctness failure.
  - `tests/operation_state.rs` exercises only digest save/restore, so the defect is not detected.
- **Recommendation:**
  - Either serialise the full accumulated input for hash-then-sign mechanisms (bounded by `OP_STATE_MAX_DATA_LEN`), or return `CKR_STATE_UNSAVEABLE` for them.
  - Add ABI tests that sign in two parts across a save/restore and compare the result with a single-part signature, verified with an independent implementation.
- **Related:** H1-17.

### A2-07 [High] ECDSA signatures are DER-encoded instead of the PKCS#11 raw r||s format

- **Location:**
  - `src/crypto/sign.rs:475`, `:513` (single-part P-256/P-384 sign).
  - `src/crypto/sign.rs:838`, `:883` (prehashed sign).
  - `src/crypto/sign.rs:491`, `:529`, `:855`, `:900` (verify uses `from_der`).
  - `src/crypto/awslc_backend.rs:350`, `:364`, `:382`, `:396`.
  - `src/crypto/pqc.rs:432` (the hybrid signature embeds DER ECDSA).
- **Description:** Every ECDSA sign path returns `signature.to_der()`, and every verify path accepts only DER.
- **Conformance/security impact:**
  - Mechanisms Spec v3.0 §2.3.1 defines the ECDSA signature as the concatenation `r || s`, each value zero-padded to the byte length of the group order: 64 bytes for P-256 and 96 bytes for P-384.
  - Standard PKCS#11 consumers (OpenSSL pkcs11 provider/engine, NSS, SunPKCS11, pkcs11-tool, p11-kit clients) convert this raw form to DER themselves. Against this module they will:
    - produce doubly wrapped or malformed signatures;
    - reject valid signatures created elsewhere;
    - size buffers incorrectly, because `C_Sign` with a NULL buffer returns a DER-based estimate.
  - ECDSA interoperability, which the Baseline Provider profile covers, therefore fails.
- **Recommendation:**
  - Emit the fixed-length raw `r||s` form (`Signature::to_bytes()` / `from_slice`) at the ABI boundary in both backends.
  - Keep DER only inside vendor-defined composite formats if needed, and document it.
  - Add ABI-level tests with external vectors (for example Wycheproof `ecdsa_secp256r1_sha256_p1363_test.json`).

### A2-08 [Medium] The ECDSA mechanism hash is ignored in single-part operations, and CKM_ECDSA hashes its input again

- **Location:**
  - `src/pkcs11_abi/functions.rs:2153-2176` (`sign_single_shot` ECDSA branch calls `ecdsa_p256_sign`/`ecdsa_p384_sign` regardless of mechanism).
  - The equivalent verify path starts at `:2232`.
  - `src/crypto/sign.rs:465-476` (`sign_with_rng` applies the curve's default digest).
  - `src/crypto/sign.rs:822-831` (the prehashed path requires a 32-byte digest for P-256).
- **Description:**
  - In single-part `C_Sign`/`C_Verify`, all ECDSA mechanisms go to a signer that hashes the input with the curve's default hash: SHA-256 for P-256 and SHA-384 for P-384.
  - As a result, `CKM_ECDSA`, whose input is already a hash, is hashed a second time.
  - `CKM_ECDSA_SHA384`/`CKM_ECDSA_SHA512` with a P-256 key actually use SHA-256.
  - The multi-part path hashes with the mechanism's algorithm and then rejects digests whose length does not match the curve default. The same mechanism therefore behaves differently in single-part and multi-part use.
- **Conformance/security impact:**
  - This violates Mechanisms Spec §2.3.6–§2.3.7. Signatures made with `CKM_ECDSA` over a caller-computed hash do not verify elsewhere, and hash-parameterised mechanisms do not provide the declared hash strength.
- **Recommendation:**
  - For `CKM_ECDSA`, use a prehash signer over the supplied data, truncated or left-padded per SEC 1.
  - For `CKM_ECDSA_SHAxxx`, hash with the declared algorithm and then call the prehash signer, in both the single-part and multi-part paths.
  - Add cross-mechanism KATs.
- **Related:** H2-07.

### A2-09 [High] CKM_AES_GCM ignores CK_GCM_PARAMS (IV, AAD, tag length) and uses a non-standard output format

- **Location:**
  - `src/pkcs11_abi/functions.rs:1470-1490` (the parameter is kept as raw bytes, and GCM is exempt from validation).
  - `src/pkcs11_abi/functions.rs:1585-1588` and `:1616` (C_Encrypt).
  - `src/pkcs11_abi/functions.rs:1839-1842` and `:1861` (C_Decrypt).
  - `src/crypto/encrypt.rs:226-229` (only 32-byte keys are accepted).
  - `src/crypto/encrypt.rs:315`, `:407` (AAD-capable functions with no callers).
  - `src/pkcs11_abi/functions.rs:730-734` (mechanism info advertises 16–32-byte keys).
- **Description:**
  - The mechanism parameter is never interpreted as `CK_GCM_PARAMS`. The caller's `pIv`/`ulIvLen`, `pAAD`/`ulAADLen` and `ulTagBits` are all ignored.
  - The module generates its own 96-bit nonce and returns `nonce || ciphertext || tag`. On decrypt it expects the same framing.
  - AAD-capable helpers exist but are unreachable from the ABI.
  - Only AES-256 keys work, although `C_GetMechanismInfo` reports a 16–32-byte key range.
- **Conformance/security impact:**
  - Mechanisms Spec v3.0 §2.15 (the AES-GCM section) requires `CK_GCM_PARAMS`, and specifies the ciphertext output as `ciphertext || tag` with the IV supplied by the caller.
  - Standard clients (TLS stacks, JCE `GCMParameterSpec`, OpenSSL provider) will:
    - fail to decrypt data from this module;
    - have data encrypted with an IV they did not choose;
    - silently lose integrity protection for data they intended to bind as AAD, because the AAD is never processed.
  - Advertising 128/192-bit key support that does not work is a functional-specification inaccuracy.
- **Recommendation:**
  - Parse and validate `CK_GCM_PARAMS` (IV length, `ulTagBits` in {96..128} or the permitted set, AAD length bound) and emit `ciphertext || tag`.
  - If the policy is to generate nonces inside the module, implement the v3.0 message-based API (`C_EncryptMessage` with `CKG_GENERATE*` IV generators) rather than altering `C_Encrypt` semantics.
  - Support or stop advertising 128/192-bit keys.
  - Add Wycheproof `aes_gcm_test.json` vectors at ABI level.
- **Related:** H1-16, H2-01.

### A2-10 [Medium] CKM_AES_CBC is implemented as CKM_AES_CBC_PAD (PKCS#7 padding)

- **Location:**
  - `src/pkcs11_abi/functions.rs:1589`, `:1617`, `:1843`, `:1862`, `:3946`, `:4159` (a shared `CKM_AES_CBC | CKM_AES_CBC_PAD` arm).
  - `src/crypto/encrypt.rs:522`, `:528` (`encrypt_padded_vec_mut::<Pkcs7>`).
- **Description:** Both mechanisms go to the same padded implementation. As a result:
  - `CKM_AES_CBC` accepts input that is not block-aligned instead of returning `CKR_DATA_LEN_RANGE`;
  - `CKM_AES_CBC` adds a full padding block to aligned input;
  - `CKM_AES_CBC` strips padding on decrypt.
- **Conformance/security impact:**
  - Mechanisms Spec §2.14 defines `CKM_AES_CBC` as unpadded, with input a multiple of the block size.
  - Ciphertext produced here is one block longer than expected by peers, and decrypting standard unpadded CBC data fails or returns `CKR_ENCRYPTED_DATA_INVALID`.
  - The padded decrypt path also exposes a padding-validity signal through the return code for a mechanism whose callers do not expect one.
- **Recommendation:**
  - Implement `CKM_AES_CBC` with `NoPadding`, enforcing block alignment on both directions and in multi-part Final.
  - Keep PKCS#7 for `CKM_AES_CBC_PAD` only.
  - Add NIST SP 800-38A vectors through the ABI for both mechanisms.
- **Related:** H2-13.

### A2-11 [Medium] CKM_AES_KEY_WRAP_KWP is advertised but implemented as RFC 3394 (KW), not RFC 5649 (KWP)

- **Location:**
  - `src/crypto/mechanisms.rs:85` (`is_wrap_mechanism` includes KWP).
  - `src/crypto/mechanisms.rs:124` (listed in `supported_mechanisms`).
  - `src/pkcs11_abi/functions.rs:735-739` (mechanism info).
  - `src/pkcs11_abi/functions.rs:5066`, `:5170` (both mechanisms call `aes_key_wrap`/`aes_key_unwrap`).
  - `src/crypto/wrap.rs:7-52` (`Kek::wrap`, RFC 3394, requires a multiple of 8 bytes).
- **Description:** No RFC 5649 code path exists, so `CKM_AES_KEY_WRAP_KWP`:
  - produces KW output with the RFC 3394 default IV;
  - rejects keys whose length is not a multiple of 8 bytes.
- **Conformance/security impact:**
  - Mechanisms Spec v3.0 (§2.14, AES Key Wrap) defines KWP as RFC 5649 / SP 800-38F KWP, with the alternative IV and a length indicator.
  - Wrapped blobs are not interchangeable with any conformant token, and odd-length payloads (for example some EC private keys) cannot be wrapped.
  - `docs/api-reference.md:159` names a non-existent `CKM_AES_KEY_WRAP_PAD`.
- **Recommendation:**
  - Implement KWP (`aes_kw::KekAes*::wrap_with_padding` or equivalent), or remove KWP from the mechanism list and the documentation.
  - Add RFC 5649 §6 test vectors.
- **Related:** H2-14.

### A2-12 [Medium] ECDH1 derive does not parse CK_ECDH1_DERIVE_PARAMS and applies a proprietary KDF

- **Location:**
  - `src/pkcs11_abi/functions.rs:5317-5360` (`mech_param` is passed straight to `ecdh_p256`/`ecdh_p384` as the peer public key).
  - `src/crypto/derive.rs:25-68`, `:80-114` (HKDF-SHA256 with the fixed salt `CratonHSM-ECDH-HKDF-Salt-v1` at `:135` and a module-specific `info` string).
  - `src/crypto/mechanisms.rs:90` (`CKM_ECDH1_COFACTOR_DERIVE` shares the path).
- **Description:**
  - The mechanism parameter is treated as a raw SEC1 point rather than a `CK_ECDH1_DERIVE_PARAMS` structure. The `kdf`, `pSharedData` and `pPublicData` fields are therefore not honoured.
  - The shared secret is always passed through a module-specific HKDF construction, and `CKD_NULL` is not supported.
  - The cofactor variant is identical to the plain variant.
- **Conformance/security impact:**
  - This violates Mechanisms Spec §2.3.x (ECDH). Any standard caller passing a `CK_ECDH1_DERIVE_PARAMS*` gets its structure bytes interpreted as a curve point, which fails.
  - Callers that do get a result obtain a key no other implementation can reproduce. H2-06 also notes that the `info` string is asymmetric between the parties.
  - Key agreement with external peers is not possible.
- **Recommendation:**
  - Parse `CK_ECDH1_DERIVE_PARAMS`.
  - Support at least `CKD_NULL` and the `CKD_SHA*_KDF` X9.63 KDFs with `pSharedData`.
  - Drop the fixed-salt HKDF, or move it to a documented vendor mechanism.
  - Implement or de-list `CKM_ECDH1_COFACTOR_DERIVE`.
  - Add interop tests with OpenSSL-derived shared secrets.
- **Related:** H1-11, H2-06, H2-22.

### A2-13 [Medium] CKM_RSA_PKCS (sign/verify) and CKM_RSA_PKCS_PSS are advertised but can never succeed

- **Location:**
  - `src/crypto/mechanisms.rs:98`, `:102` (listed in `supported_mechanisms`).
  - `src/pkcs11_abi/functions.rs:683-697` (mechanism info with `CKF_SIGN_FLAG | CKF_VERIFY_FLAG`).
  - `src/crypto/sign.rs:600-609` (`mechanism_to_hash(CKM_RSA_PKCS)` returns `None`).
  - `src/crypto/sign.rs:232-236`, `:279-284` (`None` is rejected on sign and verify).
  - `src/crypto/sign.rs:622` (`CKM_RSA_PKCS_PSS` always returns `MechanismParamInvalid`).
  - `src/crypto/awslc_backend.rs:47`, `:69` (`None` returns `MechanismInvalid`).
- **Description:**
  - Raw PKCS #1 v1.5 signing, where the caller supplies the DigestInfo, is rejected unconditionally.
  - The generic `CKM_RSA_PKCS_PSS` mechanism never parses `CK_RSA_PKCS_PSS_PARAMS`, so it always fails.
  - Both mechanisms nevertheless appear in `C_GetMechanismList` and have `C_GetMechanismInfo` entries.
- **Conformance/security impact:**
  - Base Spec §5.5 requires that listed mechanisms be supported with the reported flags.
  - Many clients use `CKM_RSA_PKCS` with a precomputed DigestInfo, and `CKM_RSA_PKCS_PSS` with explicit parameters. This includes TLS stacks, OpenSSL, the NSS certificate tools and Java `NONEwithRSA`. Against this module they discover support and then fail at run time.
  - The rejection rationale in the code (Bleichenbacher low-exponent forgery) applies to lax verification parsers, not to signing a caller-supplied DigestInfo.
- **Recommendation:**
  - Implement `CKM_RSA_PKCS` sign/verify over caller-supplied DigestInfo, using strict encoding comparison on verify.
  - Implement `CK_RSA_PKCS_PSS_PARAMS` parsing (`hashAlg`, `mgf`, `sLen`) for the generic PSS mechanism, and validate consistency for the hash-specific variants.
  - Otherwise, remove both mechanisms from the list. Tests in `tests/pkcs11_info_functions.rs:251-290` would need corresponding updates.

### A2-14 [Medium] Session objects are not bound to their session and survive C_CloseSession / C_CloseAllSessions

- **Location:**
  - `src/store/object.rs:47-116` (no owning-session field).
  - `src/session/manager.rs:70-87`, `:88-110` (`close_session`/`close_all_sessions` do not touch the object store).
  - `src/pkcs11_abi/functions.rs:821`, `:848`.
- **Description:**
  - Objects created with `CKA_TOKEN=FALSE` are stored in the same global map as token objects, with no record of the creating session.
  - Closing the session or all sessions does not destroy them.
  - Other sessions see them in the same way as token objects.
- **Conformance/security impact:**
  - Base Spec §4.4/§5.6 requires session objects to be destroyed when their session is closed, and to be visible only within the application that created them.
  - Temporary keys persist beyond their intended lifetime, which conflicts with CSP-zeroisation expectations (see A1) and allows unbounded growth.
- **Recommendation:**
  - Record the owning session handle on session objects.
  - Destroy and zeroise them in `close_session`, `close_all_sessions`, `C_Finalize` and token re-initialization.
  - Add ABI tests confirming that a session object's handle is invalid after its session closes.
- **Related:** H1-18, H3-07.

### A2-15 [Medium] No per-slot object isolation: all slots share one object store

- **Location:**
  - `src/core.rs:22`, `:135`, `:172` (a single `ObjectStore`).
  - `src/store/object.rs:111` (`slot_id: 0` is the only value ever assigned; no writer exists in `src/`).
  - `src/store/attributes.rs:356-362` (`find_objects` always passes `slot_id = None`).
  - `src/pkcs11_abi/functions.rs:518` (`clear()` removes every slot's objects).
  - `docs/configuration-reference.md:36,140` (`slot_count`).
- **Description:**
  - The code supports configuring multiple slots (`slot_count`), each with its own token and PIN state.
  - Objects, however, are neither tagged with nor filtered by slot. As a result:
    - `C_FindObjects` returns objects from every slot;
    - object handles are accepted from any slot's session;
    - `C_InitToken` on one slot destroys the objects of all slots.
  - The comment on `find_objects_for_slot` (`attributes.rs:364-368`) claims cross-slot access is prevented, but the scoping parameter is never set.
- **Conformance/security impact:**
  - Base Spec §2/§4 model each token as a separate object container.
  - A user authenticated on slot N gains access to objects of slot M, which defeats per-slot PINs.
  - Multi-slot deployments do not meet the documented isolation model.
- **Recommendation:**
  - Set `slot_id` on every object at creation, generation, unwrap, derive and copy.
  - Scope find, get-object, destroy and `clear` operations to the session's slot.
  - Alternatively, instantiate one `ObjectStore` per slot.
  - Until then, reject `slot_count > 1` in configuration validation.
  - Add ABI multi-slot isolation tests. `tests/multi_slot.rs` currently checks only slot enumeration and token state.
- **Related:** H1-13, H3-03.

### A2-16 [Medium] C_GenerateRandom and C_SeedRandom bypass the SP 800-90A DRBG, contrary to the documentation

- **Location:**
  - `src/pkcs11_abi/functions.rs:3238-3256` (C_SeedRandom: comment "We use OsRng", returns `CKR_RANDOM_SEED_NOT_SUPPORTED` at `:3253`).
  - `src/pkcs11_abi/functions.rs:3259-3300` (C_GenerateRandom: `OsRng.fill_bytes` at `:3284`, no health test).
  - `src/crypto/drbg.rs` (the DRBG exists and is used for ECDSA nonces).
- **Description:**
  - The public RNG service draws directly from the OS CSPRNG. It does not use the module's HMAC_DRBG, and it applies no continuous test.
  - The documentation says otherwise in several places:
    - `docs/api-reference.md:140-141` says C_GenerateRandom uses the SP 800-90A HMAC_DRBG and that C_SeedRandom "provides additional entropy".
    - `docs/fips-140-3-certification.md:332` and `docs/security-policy.md:214` state that all random generation uses the DRBG.
    - `docs/audit-scope.md:105` states that a continuous RNG test runs on every `C_GenerateRandom` call.
- **Conformance/security impact:**
  - Returning `CKR_RANDOM_SEED_NOT_SUPPORTED` is itself permitted by PKCS#11.
  - The discrepancy matters for the functional specification (ADV_FSP), the security-policy accuracy (AGD), and any FIPS approved-mode claim for the RNG service (see A1).
- **Recommendation:** Either route C_GenerateRandom through the DRBG (with health tests and reseed handling) and optionally mix the C_SeedRandom input as additional input, or correct all four documents.
- **Related:** H2-15, A1.

### A2-17 [Medium] Token-object persistence is documented and configurable but never implemented; CKA_TOKEN=TRUE objects do not persist

- **Location:**
  - `src/config/config.rs:62`, `:144` (`persist_objects`, parsed but never read).
  - `src/store/attributes.rs:61` (`with_persistence`), `:96` (`set_persist_key`), `:103` (`clear_persist_key`), none of which has a caller in `src/` or in the daemon.
  - `src/core.rs:135`, `:172` (`ObjectStore::new()` without persistence).
  - `docs/configuration-reference.md:35`, `:139`.
  - `docs/fork-safety.md:51`.
- **Description:**
  - Setting `persist_objects = true` has no effect.
  - The encrypted-store wiring exists as unreachable code.
  - Every token object, together with the token's initialized state, is lost when the library is unloaded or the process restarts.
- **Conformance/security impact:**
  - Base Spec §4.4 defines token objects (`CKA_TOKEN=TRUE`) as persisting across sessions and application instances. The module accepts `CKA_TOKEN=TRUE` and reports it back via `C_GetAttributeValue`, but does not honour it.
  - The configuration reference and the fork-safety documentation describe behaviour that does not exist (AGD_OPE).
- **Recommendation:**
  - Wire persistence behind `persist_objects`, including the key-derivation and lock-file behaviour described in `docs/fork-safety.md`.
  - Alternatively, reject `persist_objects = true` at configuration validation and document the token as volatile.
  - Add a persistence round-trip test at ABI level. `tests/persistence.rs` tests the store type in isolation.
- **Related:** H3-04, A1-17, A3.

### A2-18 [Medium] The documented hybrid X25519+ML-KEM-768 mechanism is absent, and the implemented hybrid ML-DSA+ECDSA mechanism takes its classical private key from CKA_EC_POINT

- **Location:**
  - `README.md:23`, `docs/api-reference.md:161`, `docs/PRESENTATION.md:88` (documented `CKM_HYBRID_X25519_ML_KEM_768`).
  - `src/pkcs11_abi/constants.rs:134-143` (vendor mechanisms; no X25519 hybrid is defined, and no X25519 dependency exists in `Cargo.toml`).
  - `src/pkcs11_abi/functions.rs:2184-2191` and `:2283` (the hybrid key is read from `CKA_EC_POINT`).
  - `src/crypto/pqc.rs:427-440` (`hybrid_sign` treats that value as the ECDSA private scalar and always uses ML-DSA-65).
  - `src/store/attributes.rs:585` (`CKA_EC_POINT` is returned without a sensitivity check).
- **Description:**
  - The only hybrid mechanism implemented is the vendor-defined `CKM_HYBRID_ML_DSA_ECDSA` (`0x80000030`).
  - The classical half of its signing key is taken from `CKA_EC_POINT` of the ML-DSA private-key object. Under PKCS#11, that attribute is a public-key attribute and is always readable.
  - `C_SetAttributeValue` rejects `CKA_EC_POINT` (see A2-21), so the mechanism cannot be provisioned through the path its own test uses (A2-23).
  - The ML-DSA parameter set is fixed at 65, whatever the key's actual variant.
  - Vendor-defined codes are used for ML-KEM, ML-DSA and SLH-DSA (`0x80000001`–`0x80000021`). This is permitted, but it is not interoperable with the mechanism identifiers standardised in later OASIS PKCS#11 revisions.
- **Conformance/security impact:**
  - The documented feature is missing (ADV_FSP).
  - Private key material is placed in an attribute that the specification defines as public. `CKA_SENSITIVE` therefore does not protect it, and `C_GetAttributeValue` discloses it.
  - The mechanism is not usable through standard object management.
- **Recommendation:**
  - Remove the X25519+ML-KEM claims, or implement the mechanism with a documented parameter structure.
  - Redesign the ML-DSA+ECDSA hybrid to reference a separate EC private-key object by handle, or to store the scalar in a sensitive vendor attribute that the `CKA_SENSITIVE` rules cover.
  - Derive the ML-DSA variant from the key.
  - Plan migration to the standard PQC mechanism codes once they are adopted.
- **Related:** H2-19, H2-20.

### A2-19 [Low] C_Initialize does not validate CK_C_INITIALIZE_ARGS

- **Location:** `src/pkcs11_abi/functions.rs:235-241`.
- **Description:** When `pInitArgs` is non-NULL, the structure is dereferenced and then ignored. None of the following is checked:
  - that `pReserved` is NULL;
  - that the four mutex callbacks are either all NULL or all non-NULL;
  - whether `CKF_LIBRARY_CANT_CREATE_OS_THREADS` is set.

  The code comment states "mutex callbacks … we ignore them".
- **Conformance/security impact:**
  - Base Spec §5.4 (C_Initialize) requires `CKR_ARGUMENTS_BAD` for a non-NULL `pReserved` or a partially supplied callback set.
  - It also requires `CKR_CANT_LOCK` when the application demands its own locking model and the library cannot honour it without OS locking.
  - Conformance-suite tests for these cases will fail.
- **Recommendation:**
  - Implement the argument-validation matrix from the specification.
  - Since the module always uses OS primitives, return `CKR_CANT_LOCK` if callbacks are supplied without `CKF_OS_LOCKING_OK`.

### A2-20 [Low] CKU_CONTEXT_SPECIFIC and CKA_ALWAYS_AUTHENTICATE are not supported

- **Location:**
  - `src/token/token.rs:679-680` (unknown user types return `UserTypeInvalid`).
  - `src/pkcs11_abi/constants.rs:242` (the constant is defined but unused).
  - No handling of `CKA_ALWAYS_AUTHENTICATE` exists in `src/`.
- **Description:** `C_Login(CKU_CONTEXT_SPECIFIC)` returns `CKR_USER_TYPE_INVALID`. Keys cannot require per-operation re-authentication.
- **Conformance/security impact:**
  - Base Spec §4.9/§5.6 define context-specific login for keys with `CKA_ALWAYS_AUTHENTICATE=TRUE`. It is a required element of the Authentication Token profile.
  - Without it, the module cannot claim that profile or offer signature-key protection of the kind expected by qualified-signature deployments.
- **Recommendation:** Implement `CKA_ALWAYS_AUTHENTICATE` on private keys and `CKU_CONTEXT_SPECIFIC` login bound to the current operation, or document the limitation and the profiles that are excluded.

### A2-21 [Low] Object-management functions are more restrictive than the specification, and C_SetAttributeValue is not atomic

- **Location:**
  - `src/pkcs11_abi/functions.rs:1277-1290` (C_SetAttributeValue accepts only `CKA_LABEL`/`CKA_ID`).
  - `src/pkcs11_abi/functions.rs:1021-1023` (C_CreateObject requires a read/write session even for `CKA_TOKEN=FALSE`).
  - `src/store/attributes.rs:439-453` (the one-way rules for `CKA_SENSITIVE`/`CKA_EXTRACTABLE` exist but cannot be reached from C_SetAttributeValue).
- **Description:**
  - The code comment cites "§4.1.2: Only CKA_LABEL and CKA_ID are modifiable". The specification does not say this.
  - Under the specification, many attributes are modifiable when `CKA_MODIFIABLE=TRUE`:
    - `CKA_SENSITIVE` may go from FALSE to TRUE;
    - `CKA_EXTRACTABLE` may go from TRUE to FALSE;
    - key-usage flags are modifiable;
    - `CKA_START_DATE`/`CKA_END_DATE` are modifiable.
  - The template is applied attribute by attribute. A rejected attribute after `CKA_LABEL` leaves the label changed while the call returns an error.
  - Read-only sessions cannot create session objects, which the specification permits.
- **Conformance/security impact:**
  - This is conservative with respect to security, but it breaks applications that harden keys after creation, for example by setting `CKA_SENSITIVE=TRUE` or clearing `CKA_EXTRACTABLE`. It also blocks read-only-session workflows.
  - The partial update violates the expectation that a failed call leaves the object unchanged.
- **Recommendation:**
  - Implement the per-attribute modifiability tables of the Base Specification (§4.x "Common attributes" footnote 8 semantics), including the one-way transitions already present in `attributes.rs`.
  - Validate the whole template before applying any of it.
  - Permit session-object creation in read-only sessions.

### A2-22 [Informational] Stub functions skip the initialization and session checks

- **Location:** `src/pkcs11_abi/functions.rs:4736-4753`, `:4919-4980`, `:5437-5453`.
- **Description:**
  - 9 functions return only `CKR_FUNCTION_NOT_SUPPORTED`: `C_SignRecoverInit`, `C_SignRecover`, `C_VerifyRecoverInit`, `C_VerifyRecover`, the four dual-function updates, and `C_WaitForSlotEvent`.
  - The legacy `C_GetFunctionStatus` and `C_CancelFunction` return `CKR_FUNCTION_NOT_PARALLEL`.
  - These return codes are all permitted.
  - The stubs do not first return `CKR_CRYPTOKI_NOT_INITIALIZED` before `C_Initialize`, or `CKR_SESSION_HANDLE_INVALID` for bad handles, as the other entry points do.
- **Conformance/security impact:** This is minor. Conformance suites that test pre-initialization behaviour uniformly across the function list may flag it.
- **Recommendation:** Call `get_hsm()` and validate the session in each stub before returning the unsupported code. Record the stubs in the functional specification.

### A2-23 [Medium] The test suite contains ABI tests that contradict the implementation and tests that codify non-conformant behaviour

- **Location and description:**
  - **`tests/multipart_encrypt_decrypt.rs:295-343`:**
    - One AES key and one fixed IV (`:299-302`) are used for several CBC-PAD encryptions: `:313`, then `:326`, then `:341-342`. CTR follows the same pattern (`:352`, `:369`, `:382-383`).
    - `aes_cbc_encrypt`/`aes_ctr_encrypt` reject a repeated key/IV pair (`src/crypto/encrypt.rs:152-205`, called at `:515` and `:654`) with `CKR_MECHANISM_PARAM_INVALID`.
    - Under the default RustCrypto backend, the second encryption is therefore expected to fail the `CKR_OK` assertion in the helper.
    - The "cross-validation" step asserts that identical ciphertext is produced under a reused IV, so it can only pass if reuse detection is absent.
  - **`tests/pqc_abi_comprehensive.rs:970-1080`:** The hybrid test calls `C_SetAttributeValue(CKA_EC_POINT)` at `:1047` and `:1060` and asserts `CKR_OK`. `C_SetAttributeValue` rejects every attribute except `CKA_LABEL`/`CKA_ID` with `CKR_ATTRIBUTE_READ_ONLY` (`functions.rs:1284-1289`), so the test is expected to fail at `:1048`.
  - **`tests/fips_approved_mode.rs:277`:** The test is `#[ignore = "RSA keygen returns CKR_MECHANISM_PARAM_INVALID — needs investigation"]`. This is an acknowledged, open functional defect in RSA key generation under FIPS mode.
  - **Tests that assert non-conformant behaviour:**
    - `tests/attribute_validation.rs:34-42` (a sensitive and extractable key's value is readable; A2-04).
    - `tests/pkcs11_compliance.rs:40-41` and `tests/pkcs11_conformance.rs:777-781` (version 3.0; A2-01).
    - `tests/pkcs11_info_functions.rs:251-290` (`CKM_RSA_PKCS` is listed with sign/verify flags; A2-13).
- **Conformance/security impact:**
  - Both "expected to fail" tests are listed in the blocking CI step (`.github/workflows/ci.yml:79-109`). This means one of two things: CI is not green at this revision, or the observed behaviour differs from this static analysis. Either way, the test evidence cannot currently be relied on.
  - Tests that encode non-conformant behaviour will fail once the corresponding findings are fixed, and they give false assurance until then (ATE_FUN).
- **Recommendation:**
  - Run the ABI suites and record the results.
  - Use a fresh IV per encryption, or a fresh key per sub-test, in `multipart_encrypt_decrypt.rs`. Replace the IV-reuse cross-check with a comparison against SP 800-38A vectors.
  - Provision the hybrid key through a supported path.
  - Resolve or re-scope the ignored FIPS test.
  - Change the non-conformant assertions at the same time as the corresponding code fixes.

### A2-24 [Medium] Fuzzing does not reach authenticated states, is not run in CI, and one harness breaks the API contract

- **Location:**
  - Fixed `"1234"` PINs: `fuzz/fuzz_targets/fuzz_keygen.rs:80`, `fuzz_derive_key.rs:61`, `fuzz_multipart_crypto.rs:61`, `fuzz_rsa_ops.rs:52`, `fuzz_set_attribute.rs:62`, `fuzz_wrap_unwrap.rs:60`.
  - Fixed `"12345678"` PINs: `fuzz_init_token.rs:90`, `:125`, `:141`, `:162`.
  - PIN policy: `src/token/token.rs:208-248` (length at least `pin_min_length`, default 8 per `src/config/config.rs:196-198`; at least 3 distinct bytes; at least 2 character classes for ASCII).
  - `fuzz/fuzz_targets/fuzz_init_token.rs:85-106`.
  - `.github/workflows/*.yml`, which contain no fuzz job.
- **Description:**
  - No fuzz target calls `C_InitPIN`, and none uses a PIN that satisfies the module's PIN policy:
    - `"1234"` fails the length check;
    - `"12345678"` fails the character-class check.
  - Every `C_Login(CKU_USER)` in the harnesses therefore fails. The keygen, derive, wrap/unwrap, multipart, RSA and set-attribute targets only exercise the unauthenticated rejection paths, not the parsing and cryptographic code behind them.
  - The fuzz-derived-PIN variants can at most initialize the token with an unknown SO PIN. They never create a user PIN.
  - `fuzz_init_token_random_label` passes a fuzz-sized label buffer of 0–63 bytes to `C_InitToken`. The API contract fixes this buffer at 32 bytes, and `functions.rs:510` reads 32 bytes, so the harness itself can produce out-of-bounds reads of its own input. Crashes found there would be harness artefacts.
  - Fuzzing is not part of CI.
- **Conformance/security impact:**
  - The claim that the fuzzing campaign covers the cryptographic ABI (`docs/audit-scope.md:143`) is not supported.
  - Memory-safety assurance for the authenticated code paths, which hold most of the `unsafe` pointer handling, rests on unit tests alone.
- **Recommendation:**
  - Add a shared fuzz fixture that initializes the token with a policy-compliant SO PIN, calls `C_InitPIN` with a compliant user PIN, and logs in.
  - Always pass a 32-byte label buffer.
  - Add a bounded fuzz smoke job (for example 60 s per target) to CI, and keep a persisted corpus.

### A2-25 [Medium] Known-answer coverage is thin and not at the ABI level; there are no Wycheproof, CAVP or ACVP vector sets

- **Location:**
  - `tests/crypto_vectors.rs` (19 tests), `tests/crypto_vectors_phase2.rs` (56 tests).
  - `tests/operation_state.rs`.
  - `tests/interop/` (shell scripts not invoked by CI).
  - A search for `wycheproof|cavp|acvp` finds no matches in `tests/`, `src/`, `fuzz/` or `tools/`.
- **Description:**
  - Of the 75 functions in the two "vector" files, about 13 compare against fixed expected outputs. These are SP 800-38A CBC/CTR, SHA-2 "abc", RFC 4231 HMAC and a few others.
  - The rest are sign/verify or encrypt/decrypt round-trips, tamper checks, and size checks.
  - Every fixed-vector test calls internal Rust functions (`craton_hsm::crypto::*`), not the C ABI. They therefore cannot detect ABI-level encoding or parameter defects such as A2-07 to A2-12, which would all pass a round-trip test.
  - Save/restore is tested only for digests (A2-06).
  - The OpenSSL and SunPKCS11 interop scripts (`tests/interop/openssl_pkcs11.sh`, `java_sunpkcs11.sh`) are not executed in CI.
- **Conformance/security impact:**
  - Round-trip tests cannot establish conformance to an external specification (ATE_FUN depth).
  - Several interoperability failures in this report exist alongside a passing-by-design suite.
- **Recommendation:**
  - Add an ABI-level vector harness that loads Wycheproof JSON (AES-GCM, AES-CBC-PKCS5, AES-KW/KWP, ECDSA P1363 and DER, ECDH, RSA PKCS#1/PSS/OAEP) and NIST CAVP/ACVP response files, and drives them through `C_*` functions.
  - Run the interop scripts, and a PKCS#11 conformance tool such as pkcs11-tool `--test`, in CI.
- **Related:** H2-08.

### A2-26 [Low] Static-analysis hygiene: clippy fails on all targets, and CI suppresses the dominant lint

- **Location:**
  - Orchestrator measurement: `cargo clippy --workspace --all-targets` reports 116 errors. 112 are `clippy::not_unsafe_ptr_arg_deref` in `src/pkcs11_abi/functions.rs`, and 4 are `clippy::absurd_extreme_comparisons` in `src/session/handle.rs`, where the `MAX_HANDLE <= u32::MAX as u64` comparisons at `:61` and `:70` are the evident source.
  - `.github/workflows/ci.yml:143-149`: the job runs `cargo clippy --workspace` without `--all-targets` and with `-A clippy::not_unsafe_ptr_arg_deref`.
- **Description:**
  - The lint flags public safe `fn`s that dereference raw-pointer arguments. For `extern "C"` ABI functions this is expected, but it is also exactly the class of code that most needs review.
  - The CI suppression is global rather than scoped to the ABI module with a justification. Test and bench targets are not linted.
- **Conformance/security impact:** This is not a direct conformance issue. For an evaluation, it weakens evidence of development-process control (ALC/ADV_IMP), because unsafe-boundary lints are silenced wholesale.
- **Recommendation:**
  - Scope the allowance with `#![allow(clippy::not_unsafe_ptr_arg_deref)]` on `pkcs11_abi::functions` only, with a comment referencing the `// SAFETY:` convention. Alternatively, declare the exports `unsafe extern "C"`.
  - Replace the constant comparisons with `cfg(target_pointer_width)`.
  - Add `--all-targets` to the CI clippy invocation.

### A2-27 [Informational] Dead or unreachable code related to conformance features

- **Location and description:**
  - `src/pkcs11_abi/functions.rs:5536-5537`: `is_bool_attribute`, marked `#[allow(dead_code)]`. Boolean attributes are parsed ad hoc elsewhere.
  - `src/crypto/encrypt.rs:315` (`aes_256_gcm_encrypt_with_aad`) and `:407` (`aes_256_gcm_decrypt_with_aad`): no callers, so GCM AAD is unreachable (A2-09).
  - `src/store/attributes.rs:371-392` (`find_objects_for_slot`): reachable only through `find_objects` with `slot_id = None`, so the slot filter is dead (A2-15).
  - `src/store/attributes.rs:61`, `:96`, `:103` and `src/config/config.rs:62`: the persistence wiring is never invoked (A2-17).
- **Conformance/security impact:** Dead security-relevant code gives a misleading impression of implemented controls during review (ADV_IMP).
- **Recommendation:** Wire the functions in as part of fixing A2-09, A2-15 and A2-17, or remove them.

### A2-28 [Low] Documentation materially overstates the implemented PKCS#11 interface

- **Location:** See the "Documentation vs code discrepancies" table below.
- **Description:** The README, the API reference, the FIPS certification document, the security policy, the audit-scope document and the configuration reference describe items that do not match the code:
  - the version claim;
  - the function count;
  - DRBG use and health testing;
  - persistence;
  - multi-slot isolation;
  - hybrid KEM support;
  - mechanism names;
  - the implemented status of the operation-state functions.
- **Conformance/security impact:**
  - Guidance (AGD_OPE/AGD_PRE) and functional-specification (ADV_FSP) evidence would be rejected in an evaluation.
  - Integrators relying on the documentation will make incorrect security assumptions, for example about persistence or slot separation.
- **Recommendation:**
  - Reconcile every row of the table below.
  - Generate the function and mechanism tables from the code (the export list and `supported_mechanisms()`), with a CI check that fails when documentation and code diverge.

## Test assurance assessment

### Inventory

| Asset | Quantity | Observations |
|---|---|---|
| Integration test files (`tests/*.rs`) | 35 files, 689 `#[test]` functions | Split in CI into a parallel "pure" group and a serial ABI group (`ci.yml:63-109`). |
| Library unit tests (`cargo test --lib`) | Present | Includes the self-test and handle-allocator tests. |
| Fuzz targets (`fuzz/fuzz_targets/`) | 12 | Not run in CI. Never reach the logged-in state (A2-24). |
| Interop scripts (`tests/interop/`) | 2 scripts + `pkcs11.cfg` | Not run in CI. SoftHSM2 is installed in CI only for benchmarks (`ci.yml:202-211`). |
| Miri | `ci.yml:184` | Limited to `crypto::zeroize`, `crypto::digest` and `crypto::integrity`. The ABI module is not covered. |
| Coverage (tarpaulin) | `ci.yml:297` | Excludes `tests/fips_*`. No coverage threshold is enforced. |

### Coverage gaps (ATE_COV)

| Area | Gap |
|---|---|
| v3.0 interface | Not implemented, so there are no tests (A2-01). |
| Role separation | No test that an SO session is denied private objects (A2-03). |
| `C_InitToken` negative paths | No test that a wrong SO PIN preserves objects, and no test for `CKR_SESSION_EXISTS` (A2-02). |
| Sensitive attributes via ABI | Only the store-level function is tested, and it asserts the non-conformant rule (A2-04). |
| `C_SetOperationState` for sign/verify | Not tested. Only digest save/restore is exercised (A2-05, A2-06). |
| Mechanism parameter structures | No test passes `CK_GCM_PARAMS`, `CK_ECDH1_DERIVE_PARAMS`, `CK_RSA_PKCS_PSS_PARAMS` or `CK_RSA_PKCS_OAEP_PARAMS` as the specification defines them (A2-09, A2-12, A2-13). |
| Output encodings | No ABI test checks ECDSA signature length or format against the specification (A2-07). |
| Session-object lifetime | No test that session objects disappear on `C_CloseSession` (A2-14). |
| Multi-slot isolation | `tests/multi_slot.rs` checks slot enumeration only, not object isolation (A2-15). |
| Persistence | `tests/persistence.rs` exercises the store type directly. The ABI path is never configured for persistence (A2-17). |
| Argument validation for `C_Initialize` | Not tested (A2-19). |
| Stubs before initialization | Not tested (A2-22). |

### Weak or incorrect tests (ATE_FUN)

- **Tests expected to fail against the current code:**
  - `tests/multipart_encrypt_decrypt.rs::test_multipart_encrypt_decrypt`, because key/IV reuse trips the module's reuse detector.
  - `tests/pqc_abi_comprehensive.rs::test_hybrid_ml_dsa_ecdsa_sign_verify`, because it depends on a `C_SetAttributeValue` that the module rejects.

  See A2-23.
- **Tests that encode non-conformant behaviour:**
  - `tests/attribute_validation.rs:34` (sensitive and extractable key is readable).
  - `tests/pkcs11_compliance.rs:40-41` and `tests/pkcs11_conformance.rs:777-781` (version 3.0).
  - `tests/pkcs11_info_functions.rs:251-290` (`CKM_RSA_PKCS` is advertised).
- **Ignored test:** `tests/fips_approved_mode.rs:277`, where RSA key generation in FIPS mode returns `CKR_MECHANISM_PARAM_INVALID` and the root cause is unknown.
- **Round-trip-dominated vector files:** about 13 of 75 tests have fixed expected outputs. None of them runs through the ABI (A2-25).
- **Test naming:** Files named `pkcs11_compliance*.rs` and `pkcs11_conformance.rs` test the module's own behaviour. They are not traceable to specification clauses. There is no requirement-to-test traceability matrix.

### Fuzzing quality

- Twelve libFuzzer targets exist and are structurally reasonable: selector byte, fuzz-derived templates, NULL-pointer variants.
- **Reachability:** fixed PINs fail the module's policy, and no target calls `C_InitPIN`. Authenticated code paths are therefore never fuzzed (A2-24).
- **Harness correctness:** `fuzz_init_token_random_label` passes label buffers shorter than the fixed 32 bytes the API requires (A2-24).
- **Operationalisation:** there is no CI job, no seed corpus, and no crash triage record in the repository.
- **Assessment:** the fuzzing that is present gives assurance for input validation on unauthenticated paths only.

### KAT sources

| Source | Where | ABI-level? |
|---|---|---|
| NIST SP 800-38A (AES-256-CBC, CTR) | `tests/crypto_vectors.rs:221-300` | No (internal functions) |
| NIST FIPS 180-4 examples (SHA-256/384/512 "abc") | `tests/crypto_vectors.rs:304-350`, `src/crypto/self_test.rs` | No |
| RFC 4231 (HMAC-SHA-256/384 TC2) | `tests/crypto_vectors.rs:353+`, self-test | No |
| GCM test key (McGrew/Viega case key) | `tests/crypto_vectors.rs:197-218` | No, and it is a round-trip, not a KAT, because the nonce is generated internally |
| Wycheproof | None | Not applicable |
| NIST CAVP / ACVP response files | None | Not applicable |
| RFC 5649 (KWP), RFC 3394 §4 (KW) | None found at ABI level | Not applicable |

**Assessment:** the test suite demonstrates internal self-consistency, not conformance to external specifications. For an ATE claim, ABI-level external vectors and clause-traceable tests are required. See A2-23 and A2-25 for the recommendations.

## Documentation vs code discrepancies

| # | Document claim (location) | Code reality (location) | Finding |
|---|---|---|---|
| D1 | "A PKCS#11 v3.0-compliant Software HSM" (`README.md:13`). The library implements PKCS#11 v3.0 (`README.md:17`). | No v3.0 functions or interfaces exist. Only the version fields say 3.0 (`functions.rs:320`, `:5460`). | A2-01 |
| D2 | "exports 70+ … functions conforming to PKCS#11 v3.0" (`docs/api-reference.md:7`) | 68 exports, the v2.40 set (`functions.rs`). | A2-01 |
| D3 | `C_GenerateRandom`: "Generate random bytes via SP 800-90A HMAC_DRBG" (`docs/api-reference.md:140`, `docs/fips-140-3-certification.md:332`, `docs/security-policy.md:214`) | `OsRng.fill_bytes` (`functions.rs:3284`). | A2-16 |
| D4 | `C_SeedRandom`: "Provide additional entropy to the DRBG" (`docs/api-reference.md:141`) | Returns `CKR_RANDOM_SEED_NOT_SUPPORTED` (`functions.rs:3253`). | A2-16 |
| D5 | "a continuous RNG test runs on every `C_GenerateRandom` call" (`docs/audit-scope.md:105`) | No test in `C_GenerateRandom` (`functions.rs:3259-3300`). | A2-16 |
| D6 | `C_GetOperationState`/`C_SetOperationState` listed as "Not Implemented" (`docs/fips-140-3-certification.md:334-336`) | Both are implemented (`functions.rs:3311`, `:3381`). The api-reference (`:147-148`) says they are implemented. | A2-05, A2-28 |
| D7 | `persist_objects`: "Persist token objects to disk (AES-256-GCM encrypted)" (`docs/configuration-reference.md:35`). Lock-file behaviour when persistence is enabled (`docs/fork-safety.md:51`). | The flag is never read, and the persistence API has no callers (`config.rs:62`; `attributes.rs:61,96,103`). | A2-17 |
| D8 | Multi-slot support via `slot_count` (`docs/configuration-reference.md:36,140`, `docs/architecture.md:73`). The code comment claims cross-slot access is prevented (`attributes.rs:364-368`). | One shared object store. `slot_id` is always 0, and the slot filter is never applied (`object.rs:111`, `attributes.rs:361`). | A2-15 |
| D9 | "hybrid X25519+ML-KEM-768" (`README.md:23`), `CKM_HYBRID_X25519_ML_KEM_768` (`docs/api-reference.md:161`), "Hybrid X25519 + ML-KEM-768" (`docs/PRESENTATION.md:88`) | No such mechanism. The only hybrid is `CKM_HYBRID_ML_DSA_ECDSA` (`constants.rs:143`). | A2-18 |
| D10 | AES mechanism `CKM_AES_KEY_WRAP_PAD` (`docs/api-reference.md:159`) | The code defines `CKM_AES_KEY_WRAP_KWP` (`constants.rs:125`), implemented as RFC 3394 (`wrap.rs:7`). | A2-11 |
| D11 | Fuzz target `fuzz_c_abi` covers C_CreateObject, C_FindObjects, C_GenerateRandom, sessions and digest (`docs/audit-scope.md:143`). By implication the campaign covers the ABI. | No fuzz target reaches an authenticated session, and fuzzing is not run in CI. | A2-24 |
| D12 | The AES-GCM/CBC/CTR mechanisms are presented as standard PKCS#11 mechanisms (`docs/api-reference.md:159`) | GCM ignores `CK_GCM_PARAMS` and `CKM_AES_CBC` pads (`functions.rs:1616-1617`). | A2-09, A2-10 |
| D13 | ECDSA is presented as a standard mechanism (`docs/api-reference.md:157`) | Signatures are DER, not the PKCS#11 raw concatenation of r and s (`sign.rs:475`). | A2-07 |

## Stubs, TODOs and unimplemented items

A search of `src/` for `TODO|FIXME|XXX|todo!|unimplemented!` finds nothing. Unimplemented functionality instead shows up as stub functions, silent parameter drops, and unreachable code, listed below.

| # | Item | Location | Kind | Finding |
|---|---|---|---|---|
| S1 | `C_SignRecoverInit`, `C_SignRecover` | `functions.rs:4736`, `:4745` | Stub (`CKR_FUNCTION_NOT_SUPPORTED`) | A2-22 |
| S2 | `C_VerifyRecoverInit`, `C_VerifyRecover` | `functions.rs:4919`, `:4928` | Stub (`CKR_FUNCTION_NOT_SUPPORTED`) | A2-22 |
| S3 | `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate` | `functions.rs:4939`, `:4950`, `:4961`, `:4972` | Stub (`CKR_FUNCTION_NOT_SUPPORTED`) | A2-22 |
| S4 | `C_WaitForSlotEvent` | `functions.rs:5447` | Stub (`CKR_FUNCTION_NOT_SUPPORTED`) | A2-22 |
| S5 | `C_GetFunctionStatus`, `C_CancelFunction` | `functions.rs:5437`, `:5442` | Legacy (`CKR_FUNCTION_NOT_PARALLEL`, as specified) | Not applicable |
| S6 | All 24 v3.0 functions | Not present | Missing | A2-01 |
| S7 | `CK_C_INITIALIZE_ARGS` handling | `functions.rs:235-241` | Parsed and ignored | A2-19 |
| S8 | `CK_GCM_PARAMS` | `functions.rs:1470-1490`, `:1616` | Parameter ignored | A2-09 |
| S9 | `CK_ECDH1_DERIVE_PARAMS` (KDF, shared data) | `functions.rs:5317` | Parameter misread | A2-12 |
| S10 | `CK_RSA_PKCS_PSS_PARAMS` for `CKM_RSA_PKCS_PSS` | `sign.rs:622` | Not parsed, so the mechanism always fails | A2-13 |
| S11 | Raw `CKM_RSA_PKCS` sign/verify | `sign.rs:232-236`, `:279-284` | Always rejected | A2-13 |
| S12 | `CKM_AES_KEY_WRAP_KWP` | `wrap.rs:7-52` | Mapped to KW | A2-11 |
| S13 | `CKM_ECDH1_COFACTOR_DERIVE` | `mechanisms.rs:90` | Aliased to plain ECDH | A2-12 |
| S14 | `CKU_CONTEXT_SPECIFIC` / `CKA_ALWAYS_AUTHENTICATE` | `token.rs:679-680`, `constants.rs:242` | Not supported | A2-20 |
| S15 | `is_bool_attribute` | `functions.rs:5536-5537` | Dead code (`#[allow(dead_code)]`) | A2-27 |
| S16 | `aes_256_gcm_encrypt_with_aad` / `aes_256_gcm_decrypt_with_aad` | `encrypt.rs:315`, `:407` | No callers | A2-27 |
| S17 | `find_objects_for_slot` slot filter | `attributes.rs:371-392` | Only called with `None` | A2-27 |
| S18 | Persistence wiring (`with_persistence`, `set_persist_key`, `clear_persist_key`, `persist_objects`) | `attributes.rs:61`, `:96`, `:103`; `config.rs:62` | No callers or readers | A2-17 |
| S19 | Hybrid X25519+ML-KEM-768 | Documentation only | Not implemented | A2-18 |
| S20 | FIPS-mode RSA key generation | `tests/fips_approved_mode.rs:277` | `#[ignore]`d with an open defect | A2-23 |

## Code review notes

These observations support the findings or are relevant to remediation. They do not carry a separate severity.

1. **ABI hygiene is generally good.**
   - Almost all non-stub entry points are wrapped in `catch_unwind(...).unwrap_or(CKR_GENERAL_ERROR)`, with 60 occurrences in `functions.rs`.
   - They check NULL output pointers before writing.
   - They implement the two-call length idiom without consuming nonces (`functions.rs:1578-1612`, `:2078-2092`).
   - The `// SAFETY:` comment convention is present but sparse: 16 comments for 125 `unsafe {}` blocks.
2. **Template-count handling is inconsistent.**
   - `parse_template` rejects counts above `MAX_TEMPLATE_ATTRS` (`functions.rs:5585-5596`).
   - `C_CopyObject` silently clamps (`:3567`). Attributes beyond the limit are therefore ignored while the call reports success.
   - `C_GetAttributeValue` applies no bound (`:1192`).
   - One validated parser should be used for all template inputs.
3. **Mechanism parameters are handled as untyped bytes.** `extract_mechanism_param` (used at `:1470`, `:1767`, `:5317`) returns raw bytes, and each mechanism interprets them ad hoc. This is the common root cause of A2-09, A2-12 and A2-13. A typed layer would address all three: for each mechanism, validate `ulParameterLen == sizeof(CK_*_PARAMS)` and read fields from a `#[repr(C)]` struct.
4. **Authorization checks are duplicated per entry point** rather than centralised. The omissions in A2-05, and the related H1-07, H1-10 and H1-11, follow from that. A single `authorize_key_use(session, key, usage, mechanism)` helper would make the model auditable.
5. **The ECDSA key/curve selection heuristic is loose.** `is_p384_params` (`functions.rs:2146-2151`) accepts any `CKA_EC_PARAMS` that contains the P-384 OID as a substring, and treats everything else as P-256. Unsupported curves should be rejected explicitly with `CKR_CURVE_NOT_SUPPORTED`.
6. **Backend parity.** The optional aws-lc backend (`src/crypto/awslc_backend.rs`) repeats the DER encoding (A2-07), and may differ in IV-reuse enforcement (see H2-04). Conformance tests should run against both backend feature sets.
7. **PQC helper `unwrap()`s.** `functions.rs:2179`, `:2182`, `:2267`, `:2274`, `:3026`, `:3033` and `:3040` unwrap after an `is_*_mechanism` guard. They cannot currently panic, and `catch_unwind` would contain a panic anyway. Converting them to `?` with `CKR_MECHANISM_INVALID` would remove the reliance on that guard.
8. **Version reporting.** Besides A2-01, `library_version` is `{0, 1}` (`functions.rs:324`), while the crate and release notes use other version numbers. The two should be aligned for traceability (ALC_CMC).

## Summary of severity counts

| Severity | Count | Findings |
|---|---|---|
| Critical | 2 | A2-01, A2-02 |
| High | 5 | A2-03, A2-04, A2-05, A2-07, A2-09 |
| Medium | 14 | A2-06, A2-08, A2-10, A2-11, A2-12, A2-13, A2-14, A2-15, A2-16, A2-17, A2-18, A2-23, A2-24, A2-25 |
| Low | 5 | A2-19, A2-20, A2-21, A2-26, A2-28 |
| Informational | 2 | A2-22, A2-27 |
| **Total** | **28** | |

**Minimum set for a credible v2.40 Baseline Provider claim:**

- A2-01 option (a);
- A2-02 to A2-05;
- A2-07, A2-09, A2-10 and A2-13;
- A2-14 and A2-15;
- A2-23 and A2-25.

**Additionally required for a v3.0 claim:** A2-01 option (b), A2-20 (Authentication Token profile), and the message-based API.

*End of report A2.*
