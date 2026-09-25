# H1 — PKCS#11 ABI layer: offensive security review

## Scope & method

**In scope (root crate `craton-hsm`):** `src/pkcs11_abi/functions.rs` (5,622 lines), `src/pkcs11_abi/types.rs`, `src/pkcs11_abi/constants.rs`, `src/pkcs11_abi/mod.rs`, `src/lib.rs`, `src/core.rs`, `src/error.rs`, `src/platform_acl.rs`.

**Method.** This was a static review only: nothing was built, tested or run. I read every exported `extern "C"` entry point and traced each one into `src/session`, `src/token`, `src/store` and `src/crypto`, but only far enough to confirm or rule out an ABI-layer finding. Other reviewers cover those modules in depth. Each finding below cites file:line references that I checked against the tree at branch `claude/modest-hamilton-y6ok79`.

**Threat model.** The library is loaded into a host process. The following actors are in scope:
- untrusted or less-trusted code in the same process, such as plugins, a p11-kit proxy consumer, or a multi-component app;
- an application or thread that holds a *public* (not logged-in) session;
- a logged-in USER who tries to go beyond the key-usage policy;
- an SO who tries to reach USER-private material;
- a caller that passes malformed pointers or lengths.

Line numbers refer to `src/pkcs11_abi/functions.rs` unless another file is named.

Confidence levels:
- **Confirmed**: the code path was read end to end.
- **Likely**: the code path was confirmed, but the impact depends on how the product is deployed or used.
- **Possible**: plausible, but not fully traced.

## Executive summary (preliminary — superseded by the final summary at the end of this report)

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 8 |
| Medium | 11 |
| Low | 9 |
| Informational | 3 |
| **Total** | **32** |

The FFI plumbing is careful in most places: `catch_unwind` wraps every non-trivial entry point, output pointers are null-checked, and output buffers are length-checked before writes. The serious problems are in **authorization and attribute-policy logic**. Several entry points do not check role or `CKA_PRIVATE`, several attribute rules are inverted, and saved operation state can be re-bound to any key.

**Top 5 risks**

1. **H1-01 (Critical).** `C_InitToken` wipes every object on every slot, and resets GCM/IV counters, *before* it checks the SO PIN (`functions.rs:515-522`). Any caller can destroy all keys with a wrong PIN.
2. **H1-02 (High).** `C_GetAttributeValue` returns `CKA_VALUE` in plaintext for keys that are `CKA_SENSITIVE=TRUE` and `CKA_EXTRACTABLE=TRUE` (`store/attributes.rs:566-579`). This defeats the core PKCS#11 sensitivity guarantee.
3. **H1-03 (High).** `C_WrapKey` never checks login or `CKA_PRIVATE` on the key being wrapped (`functions.rs:5040-5060`). The wrapping key can be a public key that a public session generated itself. The result is that extractable private keys can be exported without authentication.
4. **H1-04 (High).** `C_SetOperationState` accepts any `hAuthenticationKey` and skips the CKA_SIGN/CKA_VERIFY, login, lifecycle and slot checks (`functions.rs:3421-3478`). A restored operation can be finished in a public session.
5. **H1-05 / H1-06 (High).** SO sessions count as "logged in" for access to private objects (`session/session.rs:38-43`). Separately, closing all sessions never logs the token out, so later sessions inherit USER or SO login without a PIN.

## Findings

### H1-01 [Critical] C_InitToken destroys all objects before it verifies the SO PIN

- **Location:** `functions.rs:515-522` (`close_all_sessions` → `object_store.clear()` → `force_reset_all_counters()` → `token.init_token(...)`); `src/store/attributes.rs:333-343` (`clear` also clears the persistent store); `src/token/token.rs:403-431` (PIN check happens only inside `init_token`).
- **CWE:** CWE-696 (Incorrect Behavior Order), CWE-306 (Missing Authentication for Critical Function), CWE-862.
- **Confidence:** Confirmed.
- **Description:** The ABI closes the slot's sessions, clears the *entire* object store (every slot, plus the persistent store if one is configured), and resets all AES-GCM nonce counters and CBC/CTR IV trackers. Only after that does it call `token.init_token()`, which is where the SO PIN is verified and where PIN-length validation (`validate_pin`) runs. A wrong or invalid SO PIN therefore returns `CKR_PIN_INCORRECT` / `CKR_PIN_LEN_RANGE` after the destruction has already happened.

  Two related problems:
  - `init_token` checks only the rate limit on a previously-initialized token, not `so_pin_locked` (`token.rs:411-431`). A correct PIN also clears the SO lockout (`reset_for_init`, `token.rs:78-89`). SO lockout is therefore not enforced on this path; only the ≤5 s backoff applies (`token.rs:254-261`).
  - Contrary to PKCS#11, open sessions are closed forcibly instead of returning `CKR_SESSION_EXISTS`.
- **Trigger condition:** Any caller that can load the module calls `C_InitToken` on an initialized token with an arbitrary PIN.
- **Impact:** Unauthenticated, irreversible loss of all key material (availability and integrity). GCM counter state is also reset for any key that survives elsewhere, for example keys still referenced by `cached_object` in sessions on other slots.
- **Recommendation:** Verify the SO PIN first, holding the token's auth lock, and wipe only on success. Scope the wipe to the slot's objects. Return `CKR_SESSION_EXISTS` when sessions are open. Enforce `so_pin_locked` in `init_token`. Suggested order:
  ```rust
  if hsm.session_manager.has_sessions(slot_id) { return CKR_SESSION_EXISTS; }
  match token.init_token(pin, &label) {           // verifies SO PIN first
      Ok(()) => { hsm.object_store.clear_slot(slot_id); /* reset counters for removed keys */ CKR_OK }
      Err(e) => err_to_rv(e),
  }
  ```

### H1-02 [High] CKA_SENSITIVE bypass: sensitive but extractable keys are readable in plaintext

- **Location:** `src/store/attributes.rs:566-579` (`read_attribute`, `CKA_VALUE` arm), reached from `C_GetAttributeValue` at `functions.rs:1195-1210`.
- **CWE:** CWE-200, CWE-284.
- **Confidence:** Confirmed.
- **Description:** `CKA_VALUE` is blocked only when `sensitive && !extractable`. When `sensitive=TRUE, extractable=TRUE`, which is the usual profile for keys that may leave the token only wrapped, the raw key bytes are returned. That includes RSA/EC private-key DER held in `key_material`. PKCS#11 requires that the value of a `CKA_SENSITIVE=TRUE` key is never revealed in plaintext; `CKA_EXTRACTABLE` only permits wrapping. The in-code comment describes this as intentional, but it contradicts the specification.
- **Trigger condition:** `C_GetAttributeValue(CKA_VALUE)` on a key that has `CKA_SENSITIVE=TRUE` and `CKA_EXTRACTABLE=TRUE`. The key must be visible to the session: private objects need login (or SO, see H1-05); public ones need nothing.
- **Impact:** Plaintext disclosure of keys that are meant to be protected.
- **Recommendation:** In `read_attribute`, return `AttributeSensitive` whenever `obj.sensitive` is true. Apply the same rule to the private components (`CKA_PRIVATE_EXPONENT`, primes, EC `CKA_VALUE`) for any object with `sensitive || !extractable`. Add a regression test.

### H1-03 [High] C_WrapKey does not authorize the key being wrapped

- **Location:** `functions.rs:5004` (login state captured once), `5024` (the `private` check applies only to the *wrapping* key), `5041-5060` (no `private`/login check on the target key); `C_GenerateKey` at `2508-2530` has no login check (see H1-10).
- **CWE:** CWE-862 (Missing Authorization).
- **Confidence:** Confirmed.
- **Description:** The target key is checked only for `extractable` and `CKA_WRAP_WITH_TRUSTED`. A public session can supply a wrapping key that is itself public (`CKA_PRIVATE=FALSE`, `CKA_WRAP=TRUE`, non-sensitive). Such a key can be created without login through `C_GenerateKey` template overrides (`2600-2617`), and its value can then be read with `C_GetAttributeValue`. There is also no audit record for the export.
- **Trigger condition:** A not-logged-in session calls `C_WrapKey` with a public wrapping key and the handle of a `CKA_PRIVATE=TRUE`, `CKA_EXTRACTABLE=TRUE` key.
- **Impact:** Unauthenticated export of private extractable keys (confidentiality).
- **Recommendation:** After loading `key_obj`, add `if key_obj.private && !is_logged_in { return CKR_USER_NOT_LOGGED_IN; }`. Require USER role, not SO (see H1-05). Refuse wrapping keys that are non-sensitive or public when the target is private. Record an audit event for every wrap.


### H1-04 [High] C_SetOperationState re-binds a saved operation to any key, with no authorization re-check

- **Location:** `functions.rs:3381-3496`. Sign branch at `3426-3454`; verify branch at `3456-3482`. The only check is `get_object(resolved_key).is_err()` at `3433` and `3462`; the session operation is overwritten at `3493`. `_hEncryptionKey` is ignored. The blob format is in `src/session/session.rs:128-218` (serialize) and `src/session/session.rs:228-305` (deserialize).
- **CWE:** CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), CWE-639.
- **Confidence:** Confirmed.
- **Description:** When a non-zero `hAuthenticationKey` is passed, it replaces the key handle recorded in the HMAC-protected blob. The function only checks that the handle exists. It does **not** re-apply any of the checks that `C_SignInit`/`C_VerifyInit` perform:
  - `can_sign` / `can_verify`;
  - `CKA_PRIVATE` versus the session's login state (`C_SignInit` requires login at `1964`);
  - `check_lifecycle`;
  - key type versus mechanism;
  - whether the key belongs to the session's slot.

  The blob is authenticated with a per-process key (`core.rs:36`, `generate_state_hmac_key` at `core.rs:120`). It is not bound to a session handle, slot, or login state, so a blob saved in one session can be restored into any other session, including a public one. The session's existing `active_operation` is overwritten without `CKR_OPERATION_ACTIVE`. The mechanism is not re-validated against the algorithm policy.
- **Trigger condition:** A session restores any valid state blob of sign/verify type and supplies a different `hAuthenticationKey`, or restores the blob into a session that is not logged in.
- **Impact:** A key can be used for signing even though its `CKA_SIGN` is FALSE, the key is not active, or the caller is not logged in. For private keys this bypasses authentication for the signing primitive (integrity).
- **Recommendation:** Build the restored operation through the same validation helper that `C_SignInit`/`C_VerifyInit` use (login, `can_sign`/`can_verify`, lifecycle, key type, slot, policy). Bind the blob to `(session handle, slot_id, login generation)` by including them in the HMAC input. Reject a replacement key handle unless it refers to the same key object that was recorded in the blob.
  ```rust
  let obj = validate_sign_key(&hsm, &sess, mechanism, resolved_key)?; // shared with C_SignInit
  ```

### H1-05 [High] SO sessions count as "logged in" for access to private (USER) objects

- **Location:** `src/session/session.rs:38-43`. `is_logged_in()` includes `RwSO`. It is used as the only gate for private-object access at `functions.rs:1041, 1142, 1186, 1265, 1329, 1458, 1755, 1964, 2380, 3542, 5004, 5129`.
- **CWE:** CWE-269 (Improper Privilege Management), CWE-863.
- **Confidence:** Confirmed.
- **Description:** In PKCS#11 the SO administers the token (C_InitPIN, token policy) but has no access to the normal user's private objects. Every private-object gate in the ABI calls `state.is_logged_in()`, which returns true for `RwSO`. An SO session can therefore:
  - find, read attributes of, modify, copy and destroy USER-private objects;
  - sign with USER private keys (`C_SignInit` checks only `is_logged_in()`);
  - decrypt with them;
  - wrap them (together with H1-03).
- **Trigger condition:** A session in which the SO is logged in references a `CKA_PRIVATE=TRUE` object.
- **Impact:** Role separation between SO and USER is lost. Anyone who knows the SO PIN has full use of USER keys (confidentiality and integrity).
- **Recommendation:** Add `SessionState::is_user()` (true only for `RoUser | RwUser`) and use it for every private-object and key-use check. Keep `is_so()` for C_InitPIN only. Add negative tests that exercise every entry point with an SO session.

### H1-06 [High] Closing all sessions does not log out the token; later sessions inherit the login

- **Location:** `src/session/manager.rs:70-86` (`close_session`) and `88-110` (`close_all_sessions`), neither of which touches the token's login state. `src/token/token.rs:730-755` (`decrement_session_count` does not log out when the count reaches 0). `src/session/manager.rs:49-54` (`open_session` inherits `token.login_state()`).
- **CWE:** CWE-613 (Insufficient Session Expiration), CWE-287.
- **Confidence:** Confirmed.
- **Description:** PKCS#11 §5.6 requires that when the last session to a token is closed, the token returns to the public state, so that a later `C_Login` is needed. Here `AuthState.login` stays `UserLoggedIn`/`SoLoggedIn` after `C_CloseSession` of the last session and after `C_CloseAllSessions`. Only `C_Logout` and `C_InitToken` reset it. Any session opened later by any code in the process is promoted to `RoUser`/`RwUser`/`RwSO` without a PIN.
- **Trigger condition:** A component closes its sessions without calling `C_Logout`, then a different component opens a new session on the same slot.
- **Impact:** Authentication bypass across components in the same process. For example, a plugin or p11-kit consumer loaded after an application finished its work gets USER or SO rights.
- **Recommendation:** In `decrement_session_count`, reset `auth.login` to `Public` when `session_count` reaches 0, under the same `auth` lock. Call a `token.on_all_sessions_closed()` hook from `close_all_sessions`. Add a regression test: login → close all → open → `C_GetSessionInfo` must report a public state.

### H1-07 [High] C_DestroyObject destroys private objects without login

- **Location:** `functions.rs:1066-1116`. The session is checked only for R/W (`1077`) and the object only for `destroyable` (`1087`). `src/store/attributes.rs:292-315` (`destroy_object`) has no authorization either.
- **CWE:** CWE-862 (Missing Authorization), CWE-284.
- **Confidence:** Confirmed.
- **Description:** Other object entry points (`C_GetAttributeValue`, `C_SetAttributeValue`, `C_GetObjectSize`, `C_CopyObject`) reject `CKA_PRIVATE=TRUE` objects in a public session, but `C_DestroyObject` does not. `CKA_DESTROYABLE` defaults to TRUE (`store/object.rs:121`), and `C_GenerateKey`/`C_GenerateKeyPair` never let the caller clear it (see H1-14). The object is also not checked against the session's slot (see H1-13).
- **Trigger condition:** A public R/W session calls `C_DestroyObject` with the handle of a private key. Handles come from the scrambled allocator, so a caller has to learn or guess them, but H1-13 and H1-05 widen who can see handles.
- **Impact:** Unauthenticated, irreversible destruction of private keys (availability and integrity). This is a narrower version of H1-01 that does not need `C_InitToken`.
- **Recommendation:** Add the same gate used elsewhere (with H1-05 applied), and record an audit event on failure as well:
  ```rust
  if obj_read.private && !sess.read().state.is_user() { return CKR_USER_NOT_LOGGED_IN; }
  if obj_read.slot_id != sess.read().slot_id { return CKR_OBJECT_HANDLE_INVALID; }
  ```
  Return `CKR_ACTION_PROHIBITED` (v3.0) instead of `CKR_ATTRIBUTE_READ_ONLY` for non-destroyable objects.

### H1-08 [High] C_CopyObject lets the copy escape the source object's policy

- **Location:** `functions.rs:3508-3738`. `CKA_MODIFIABLE` of the source is never consulted. Usage flags can be turned on at `3654-3719` (`CKA_PRIVATE` 3654, `CKA_MODIFIABLE` 3660, `CKA_SIGN` 3684, `CKA_WRAP` 3696, `CKA_DERIVE` 3708, and so on). Any other attribute is stored verbatim in `extra_attributes` at `3720-3724`. The template count is clamped silently at `3567`.
- **CWE:** CWE-284, CWE-269, CWE-1220 (Insufficient Granularity of Access Control).
- **Confidence:** Confirmed.
- **Description:** `C_SetAttributeValue` correctly limits post-creation changes to `CKA_LABEL`/`CKA_ID` (`1276-1292`). `C_CopyObject` does not apply that policy. For any object with `copyable=true`, which is always the case (see H1-14), a caller can create a copy with the following changes:
  - `CKA_SIGN`/`CKA_DECRYPT`/`CKA_WRAP`/`CKA_UNWRAP`/`CKA_DERIVE` turned on, even when the source has them off or has `CKA_MODIFIABLE=FALSE`;
  - `CKA_PRIVATE=FALSE`. PKCS#11 permits changing `CKA_PRIVATE` during a copy, but combined with H1-02 and H1-03 it moves a private, sensitive-but-extractable key into the public domain;
  - `CKA_WRAP_WITH_TRUSTED=FALSE` written into `extra_attributes`. The specification makes this attribute sticky once TRUE, and `C_WrapKey` reads it from `extra_attributes` (`5051-5058`), so the copy loses the wrap-with-trusted restriction;
  - forged `CKA_TRUSTED`, `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE` or `CKA_NEVER_EXTRACTABLE` values (see H1-09).

  The copy also inherits the source's `slot_id` and lifecycle state with no check against the caller's slot.
- **Trigger condition:** A logged-in session, or a public session for public objects, calls `C_CopyObject` on an existing key with a template that sets usage or protection attributes to different values.
- **Impact:** The key-usage policy is bypassed: a key restricted to verify or encrypt becomes usable for sign, decrypt, wrap or derive. `CKA_WRAP_WITH_TRUSTED` protection can be removed, and private keys can be made public.
- **Recommendation:**
  - If `!src.modifiable`, allow only `CKA_TOKEN`, `CKA_PRIVATE` (FALSE→TRUE only), `CKA_LABEL` and `CKA_ID`.
  - Never allow a usage flag to go from FALSE to TRUE.
  - Forbid TRUE→FALSE for `CKA_PRIVATE` on key classes, as token policy.
  - Treat `CKA_WRAP_WITH_TRUSTED`, `CKA_TRUSTED`, `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE`, `CKA_COPYABLE` (FALSE only) and `CKA_DESTROYABLE` (FALSE only) as typed fields with one-way rules.
  - Return `CKR_ATTRIBUTE_TYPE_INVALID` for unknown types instead of storing them.
  - Use `parse_template` in place of the hand-written loop, so that an oversized count is rejected rather than clamped.

### H1-09 [High] CKA_TRUSTED and the provenance attributes can be set by any creator, so CKA_WRAP_WITH_TRUSTED has no effect

- **Location:** `src/store/attributes.rs:528-537` (the catch-all `_ =>` arm of `apply_attribute` stores any attribute, including `CKA_TRUSTED`, `CKA_WRAP_WITH_TRUSTED`, `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE` and `CKA_COPYABLE`, in `extra_attributes`); `src/store/attributes.rs:589` (`read_attribute` reports them back as if they were authoritative); `functions.rs:1000-1062` (`C_CreateObject`); `functions.rs:5030-5058` (`C_WrapKey` trusts `extra_attributes[CKA_TRUSTED]`).
- **CWE:** CWE-269, CWE-345 (Insufficient Verification of Data Authenticity), CWE-915.
- **Confidence:** Confirmed.
- **Description:** In PKCS#11, only the SO may set `CKA_TRUSTED=TRUE`. `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE` are computed by the token and cannot be set by a template. Here any R/W session can create a secret key through `C_CreateObject` with `CKA_TRUSTED=TRUE` and a caller-chosen `CKA_VALUE`, and `C_WrapKey` will accept it as a trusted wrapping key. The token never computes `CKA_ALWAYS_SENSITIVE` or `CKA_NEVER_EXTRACTABLE`, so relying parties that make decisions from those attributes can be misled. Examples are attestation, CA key ceremonies, and KMIP bridges. `CKA_COPYABLE=FALSE` supplied at creation is stored only in `extra_attributes`, while `C_CopyObject` checks the separate `copyable` field, which is always true.
- **Trigger condition:** Any object creation (`C_CreateObject`, or `C_CopyObject` via H1-08) with a template that contains one of these attributes.
- **Impact:** `CKA_WRAP_WITH_TRUSTED` gives no protection, and provenance attributes can be forged. A logged-in USER can export keys marked wrap-with-trusted under a wrapping key whose value the USER chose.
- **Recommendation:**
  - Model these attributes as typed fields of `StoredObject`.
  - Reject them in creation templates with `CKR_ATTRIBUTE_READ_ONLY`, except `CKA_TRUSTED`, which is allowed only when the session is SO and whose value is kept thereafter.
  - Compute `LOCAL`, `ALWAYS_SENSITIVE` and `NEVER_EXTRACTABLE` in the keygen, unwrap and derive paths.
  - Map `CKA_COPYABLE` to `obj.copyable`.
  - Change the fallback in `apply_attribute` to reject unknown attribute types in the `CKA_*` range with `CKR_ATTRIBUTE_TYPE_INVALID`, and allow vendor-defined types only on an explicit allow-list.

### H1-10 [High] Key-creating functions do not require login

- **Location:** `C_GenerateKey` `functions.rs:2508-2685` (only an R/W check at `2528`), `C_GenerateKeyPair` `2688-2778`, `C_UnwrapKey` `5101-5260` (login state is captured but only applied to the *unwrapping* key), `C_DeriveKey` `5263-5434`.
- **CWE:** CWE-306, CWE-862.
- **Confidence:** Confirmed.
- **Description:** `C_CreateObject` rejects key classes in a public session (`1041`), but the four key-creating functions have no equivalent check. In a public R/W session, `C_GenerateKey` accepts template overrides for `CKA_PRIVATE`, `CKA_SENSITIVE` and `CKA_EXTRACTABLE` (`2600-2617`, the arms starting at `2600`, `2606` and `2612`), so it can mint a public, non-sensitive AES key with `CKA_WRAP=TRUE`. That is the building block H1-03 depends on. Token objects (`CKA_TOKEN=TRUE`) can also be planted with a chosen `CKA_ID`/`CKA_LABEL`. A logged-in application that later looks up keys by label or ID may then encrypt data under a key whose value the planter can read.
- **Trigger condition:** A not-logged-in R/W session calls any of the four functions.
- **Impact:** Unauthenticated creation of keys (which enables H1-03), object squatting and confusion for later USER sessions, and resource exhaustion of the 10,000-object store (`attributes.rs:21`).
- **Recommendation:** Require a USER login (`is_user()`) for every call that creates a private or secret key, and for any template with `CKA_TOKEN=TRUE`. If public-session generation of public objects is a product requirement, force `CKA_PRIVATE=TRUE`/`CKA_SENSITIVE=TRUE` for secret keys that are created without login, and forbid `CKA_WRAP`/`CKA_UNWRAP` on them.

### H1-11 [Medium] C_DeriveKey uses the base key without login, lifecycle or key-type checks, and misreads the mechanism parameter

- **Location:** `functions.rs:5300-5314` (the base key is checked only for `can_derive`, at `5305`); `5317-5320` (the raw mechanism-parameter bytes are used as the peer point or ciphertext); `5342-5361`.
- **CWE:** CWE-862, CWE-20, CWE-843 (Type Confusion).
- **Confidence:** Confirmed (authorization); Likely (interoperability impact).
- **Description:**
  - Unlike `C_EncryptInit`/`C_SignInit`, the base key is not checked for `CKA_PRIVATE` against the session's login state, for `check_lifecycle("derive")`, or for class and key type. A public session can therefore run ECDH or ML-KEM decapsulation with a USER private key.
  - `CKM_ECDH1_DERIVE` is specified to take a `CK_ECDH1_DERIVE_PARAMS` structure (kdf, shared data, public-data pointer), but the code treats `pParameter` as the encoded peer point itself. Standard callers pass the structure, and its bytes, including pointer values, are then parsed as a curve point. The KDF field is not honoured; HKDF is applied implicitly.
  - Any base key whose `ec_params` are not recognised as P-384 goes through the P-256 path.
- **Trigger condition:** `C_DeriveKey` is called from a public R/W session on a private EC or ML-KEM key that has `CKA_DERIVE=TRUE`, or it is called with a standard `CK_ECDH1_DERIVE_PARAMS`.
- **Impact:** A private-key operation runs without authentication. The derived object defaults to private, sensitive and non-extractable, which limits the direct disclosure, but objects can be created without authentication and the operation can be used as an oracle. There is also a non-interoperable, error-prone parameter ABI.
- **Recommendation:**
  - Add the login, lifecycle and key-type gate.
  - Parse `CK_ECDH1_DERIVE_PARAMS` with an exact `size_of` check, dereference `pPublicData` using its own length bound, support `CKD_NULL`, and reject unknown KDFs.
  - Reject unknown curves with `CKR_CURVE_NOT_SUPPORTED`.

### H1-12 [Medium] C_DigestKey has no login check, and the digested key bytes are exported in plaintext by C_GetOperationState

- **Location:** `functions.rs:4390-4456`. The key is fetched at `4411` and checked only for class (`4418`) and `sensitive` (`4424`). The raw key bytes are appended to `accumulated_input` at `4449`. `C_GetOperationState` `3311-3375` serializes that buffer (`3346`, `3368`) through `src/session/session.rs:194-204`, which stores the digest branch's `accumulated_input` verbatim. The blob is MACed, not encrypted.
- **CWE:** CWE-862, CWE-312 (Cleartext Storage of Sensitive Information), CWE-200.
- **Confidence:** Confirmed.
- **Description:** `C_DigestKey` does not check `CKA_PRIVATE` against the session's login state. It also keeps the key bytes in `accumulated_input` so that the digest can be re-created on restore. `C_GetOperationState` for a digest operation then returns a blob that contains those bytes in the clear. For a `CKA_PRIVATE=TRUE`, `CKA_SENSITIVE=FALSE` secret key, a session that is not logged in cannot read `CKA_VALUE` (`1186`) but can obtain the same bytes through this path. Separately, a public session gets `H(key)` for any non-sensitive private key.
- **Trigger condition:** A not-logged-in session digests a private, non-sensitive secret key and then saves the operation state.
- **Impact:** The login requirement on private, non-sensitive secret-key values is bypassed (confidentiality). In the logged-in case, key material is also copied into a caller-visible buffer that is not zeroized.
- **Recommendation:**
  - Add the private/login gate (with H1-05 applied).
  - Also refuse keys with `extractable == false`, as the doc comment at `4383-4388` states.
  - Mark any digest operation that has absorbed key material as unsaveable (a `key_absorbed: bool` flag, then `CKR_STATE_UNSAVEABLE`), or serialize the hasher's internal state instead of its input.
  - If a state blob must carry secrets, encrypt it (AEAD) rather than only MACing it.

### H1-13 [Medium] No slot isolation for objects: one global ObjectStore, and object handles are accepted from any slot

- **Location:** `src/core.rs:135` and `172` (one `ObjectStore::new()` shared by all slots); `src/store/object.rs:111` (`slot_id` always 0 and never assigned elsewhere); `src/store/attributes.rs:356-362` (`find_objects` passes `slot_id = None`); `functions.rs:1330`. No object-handle entry point compares `obj.slot_id` with `sess.slot_id`. `src/token/slot.rs:28-41` creates `slot_count` independent tokens, each with its own PINs.
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-653 (Improper Isolation).
- **Confidence:** Confirmed code path; Likely impact (requires `token.slot_count > 1`, default 1, `config.rs:220-222`).
- **Description:** Each slot has its own token, SO/USER PINs and login state, but objects are global. A USER logged into slot 1 with slot 1's PIN has `is_logged_in()==true`, and every private object of slot 0 then passes the private-object gates. `C_FindObjects` enumerates objects from all slots. `C_InitToken` on any slot wipes every slot (H1-01). `find_objects_for_slot` exists but is never called.
- **Trigger condition:** A deployment with more than one slot and a user who knows the PIN of any one slot.
- **Impact:** Tenant separation between slots is lost: private keys of other slots can be used, read (subject to H1-02) and destroyed.
- **Recommendation:**
  - Set `obj.slot_id = sess.slot_id` in every creation path.
  - Make `ObjectStore::get_object` take the session's slot and return `ObjectHandleInvalid` on a mismatch.
  - Use `find_objects_for_slot(.., Some(sess.slot_id))`.
  - Make `clear()` slot-scoped. Alternatively, give each slot its own `ObjectStore`.

### H1-14 [Medium] Key-creation templates silently drop restrictive attributes

- **Location:** The catch-all `_ => {}` arms at `functions.rs:2660` (`C_GenerateKey`), `3156` (`apply_pub_template`), `3227` (`apply_priv_template`), `5247` (`C_UnwrapKey`) and `5421` (`C_DeriveKey`). `C_UnwrapKey` forces `CKO_SECRET_KEY`/`CKK_AES` at `5192-5193` whatever the template says. `src/store/attributes.rs:415-540` (`apply_attribute`) has no arm for `CKA_COPYABLE`.
- **CWE:** CWE-1284/CWE-20 (Improper Input Validation), CWE-693 (Protection Mechanism Failure).
- **Confidence:** Confirmed.
- **Description:** PKCS#11 requires `CKR_ATTRIBUTE_TYPE_INVALID` or `CKR_TEMPLATE_INCONSISTENT` when a template contains attributes that cannot be honoured. Instead, restrictive requests are silently ignored and `CKR_OK` is returned. Examples:
  - `CKA_MODIFIABLE=FALSE`, `CKA_DESTROYABLE=FALSE`, `CKA_COPYABLE=FALSE`, `CKA_WRAP_WITH_TRUSTED=TRUE`, `CKA_SIGN/VERIFY/DERIVE=FALSE` on `C_GenerateKey`;
  - `CKA_PRIVATE`, `CKA_WRAP`, `CKA_UNWRAP`, `CKA_SIGN`, `CKA_KEY_TYPE` and `CKA_CLASS` on `C_UnwrapKey`, so an unwrapped RSA or EC key is stored as "AES";
  - `CKA_MODIFIABLE`, `CKA_DESTROYABLE`, `CKA_COPYABLE`, `CKA_ENCRYPT`, `CKA_WRAP_WITH_TRUSTED` in the key-pair private template.

  `CKA_COPYABLE=FALSE` given to `C_CreateObject` is not enforced either (see H1-09). Date attributes of the wrong length are silently ignored in the keygen paths but rejected in `apply_attribute`.
- **Trigger condition:** An application requests a restrictive attribute in any keygen, unwrap or derive template.
- **Impact:** The application believes a key is non-destroyable, non-copyable or wrap-with-trusted when it is not. This weakens the defences that H1-07 and H1-08 would otherwise be limited by.
- **Recommendation:** Build every creation path on one `apply_template(obj, template, CreationContext)` that knows each attribute's type, length and permitted values. Reject unknown or unsupported attributes, and honour `CKA_CLASS`/`CKA_KEY_TYPE` on unwrap, with `CKR_TEMPLATE_INCONSISTENT` on mismatch.

### H1-15 [Medium] No check that key class or type matches the mechanism in the *Init functions (cross-algorithm key use)

- **Location:** `C_EncryptInit` `functions.rs:1450-1468`, `C_DecryptInit` `1748-1765`, `C_SignInit` `1993-2006`, `C_VerifyInit` `2373-2391`, `C_WrapKey`/`C_UnwrapKey` (`5018-5040`, `5143-5160`). The key bytes go straight to backends that dispatch on length alone (for example `src/crypto/encrypt.rs:516-537`).
- **CWE:** CWE-693, CWE-843 (Type Confusion), CWE-327.
- **Confidence:** Confirmed code path; Possible exploitability.
- **Description:** None of the Init functions compares `obj.class`/`obj.key_type` with the mechanism (`CKR_KEY_TYPE_INCONSISTENT`). An EC P-256 private key stores its raw 32-byte scalar (`src/crypto/keygen.rs:93`), and `CKA_DECRYPT=TRUE` can be requested in the key-pair private template (`3162-3228`). That key is then accepted by `CKM_AES_CTR`/`CKM_AES_CBC` as an AES-256 key. `CKO_DATA` objects with `CKA_VALUE` and usage flags, which can be created without login (only key classes are gated, `1031-1043`), are accepted as keys for every mechanism.
- **Trigger condition:** An operation is initialised with a key handle whose type differs from the mechanism's key type.
- **Impact:** The same secret is used under different algorithms, which invalidates their separate security arguments. It also gives a block-cipher oracle keyed by an EC private scalar, and makes the key-usage policy harder to reason about.
- **Recommendation:** Add a `mechanisms::required_key(mech) -> (CK_OBJECT_CLASS, &[CK_KEY_TYPE])` table and check it in every Init, and in wrap, unwrap and derive. Accept only `CKO_SECRET_KEY`/`CKO_PRIVATE_KEY`/`CKO_PUBLIC_KEY` objects as appropriate.

### H1-16 [Medium] Mechanism parameters are ignored or misread (GCM, CBC and OAEP semantics)

- **Location:**
  - `extract_mechanism_param` at `functions.rs:1507-1522`: returns an empty `Vec` for `parameter_len > 64 MiB` instead of an error.
  - `C_Encrypt`/`C_Decrypt` GCM at `1616` and `1861`: `CK_GCM_PARAMS` is never parsed.
  - CBC at `1617` and `1862`, and at `3946` and `4159` for multi-part: `CKM_AES_CBC` and `CKM_AES_CBC_PAD` share one path, and `src/crypto/encrypt.rs:516-537` always applies PKCS#7 padding.
  - `parse_oaep_hash` at `197-219`: reads only `hashAlg`, and not `mgf`, `source` or `pSourceData`.
- **CWE:** CWE-20, CWE-354 (Improper Validation of Integrity Check Value), CWE-436 (Interpretation Conflict).
- **Confidence:** Confirmed.
- **Description:**
  - **GCM.** `CKM_AES_GCM` ignores the caller's IV, AAD and `ulTagBits`, generates its own nonce, and returns `nonce‖ct‖tag`. An application that passes AAD believes the AAD is authenticated, but it is not bound to the ciphertext. Standard `CK_GCM_PARAMS` output cannot be decrypted elsewhere.
  - **CBC.** `CKM_AES_CBC`, which by definition has no padding, pads. It is therefore not interoperable, and it makes padding validity observable for a mechanism that should have no padding check.
  - **OAEP.** An OAEP `pSourceData` label is silently dropped, and so is an `mgf` that differs from `hashAlg`.
  - **Parameter size.** The length of the parameter structure is never compared with `size_of::<CK_*_PARAMS>()`, so a truncated or oversized struct is accepted.
- **Trigger condition:** A standards-conformant caller supplies `CK_GCM_PARAMS` with AAD, an OAEP label, or uses unpadded `CKM_AES_CBC`.
- **Impact:** Integrity is silently lost for AAD, padding-validity differences appear for `CKM_AES_CBC`, and output cannot be read by other PKCS#11 implementations. Callers may make security decisions on the false assumption that AAD is authenticated.
- **Recommendation:** Add per-mechanism typed parsers such as `parse_gcm_params(&CK_MECHANISM) -> Result<GcmParams, CK_RV>`:
  - check `parameter_len == size_of::<CK_GCM_PARAMS>()`;
  - bound-check and copy `pIv`/`pAAD` using their own lengths;
  - use `aes_256_gcm_encrypt_with_aad` (`encrypt.rs:315`);
  - reject a caller IV if the token generates IVs (`CKR_MECHANISM_PARAM_INVALID`), or use the IV-generator semantics of v3.0.

  Split the CBC mechanisms and implement true no-padding CBC, rejecting input that is not block-aligned. Validate every OAEP field. Return `CKR_MECHANISM_PARAM_INVALID` for oversized parameters instead of treating them as empty.

### H1-17 [Medium] Restored hash-then-sign and hash-then-verify operations lose their state, so the wrong message is signed or verified

- **Location:** `SignUpdate` feeds the hasher and leaves `data` empty (`functions.rs:4576-4586`); `VerifyUpdate` does the same (`4790-4800`). `serialize_state` saves only `data` for sign and verify (`src/session/session.rs:170-193`). `C_SetOperationState` calls `create_hasher(mechanism)` with the *sign* mechanism (`functions.rs:3439`, `3467`), which `src/crypto/digest.rs:62` rejects, so `hasher = None`. `C_SignFinal`/`C_VerifyFinal` then fall back to `sign_single_shot`/`verify_single_shot` over the empty `data` (`4692`, `4870`).
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature), CWE-372 (Incomplete Internal State Distinction).
- **Confidence:** Confirmed.
- **Description:** Take `CKM_SHA256_RSA_PKCS`, `CKM_ECDSA_SHA256` or any other mechanism with a built-in hash. Save the state after one or more Update calls and restore it. The resulting operation:
  - signs, or verifies against, the empty message instead of the data already absorbed;
  - rejects further Update calls with `CKR_GENERAL_ERROR` (`4579-4582`).

  `C_GetOperationState` returns `CKR_OK`, so the caller gets no warning.
- **Trigger condition:** An application saves and restores a multi-part sign or verify operation that uses a hash-then-sign mechanism.
- **Impact:** Signatures are produced over data the caller did not intend (integrity). Verification succeeds for any message whenever the signature is a valid signature of the empty message, which is a signature-verification bypass for applications that use state save and restore.
- **Recommendation:** Until the hasher state itself can be serialized, return `CKR_STATE_UNSAVEABLE` for sign and verify operations whose `hasher.is_some()`. Otherwise, accumulate raw input as the digest path does, and on restore map the sign mechanism to its digest mechanism (`sign::sign_mechanism_to_digest_mechanism`). Add a round-trip test that compares the result with a sign operation that was never saved.

### H1-18 [Medium] Session objects outlive their sessions

- **Location:** `src/session/manager.rs:70-86` and `88-110`: closing sessions never removes objects that have `token_object == false`. `StoredObject` has no field recording the owning session (`src/store/object.rs:42-104`). The store limit is `src/store/attributes.rs:21`.
- **CWE:** CWE-459 (Incomplete Cleanup), CWE-226, CWE-400.
- **Confidence:** Confirmed.
- **Description:** PKCS#11 requires session objects (`CKA_TOKEN=FALSE`) to be destroyed when the session that created them closes, or when all sessions are closed. Here they stay in the global store until `C_Finalize` or `C_InitToken`. They also remain usable from any later session, subject only to the private check (see H1-05 and H1-06). The key material stays resident, and the objects count toward the 10,000-object limit.
- **Trigger condition:** An application creates session keys (derived, unwrapped or generated with the default `CKA_TOKEN=FALSE`) and closes the session.
- **Impact:** Ephemeral keys remain in memory and usable after their intended lifetime. Normal use gradually exhausts the object store, after which every create returns `CKR_DEVICE_MEMORY` (availability).
- **Recommendation:** Add `owner_session: Option<CK_SESSION_HANDLE>` to `StoredObject` and set it for session objects. In `close_session`/`close_all_sessions`, remove the owned objects, which zeroizes them via `RawKeyMaterial`, and drop their GCM counter entries. Restrict session-object visibility to sessions of the same slot and application.

### H1-19 [Medium] C_Login ignores failure of the per-session login update; token and session login states diverge

- **Location:** `functions.rs:916` (a racy RO-session check), `932` (`let _ = hsm.session_manager.login_all(...)`); `src/session/manager.rs:133-185` (rollback of sessions, but not of the token); `src/session/manager.rs:39-44` (`open_session` makes its RO/SO decision from a snapshot).
- **CWE:** CWE-367 (TOCTOU), CWE-252 (Unchecked Return Value), CWE-662.
- **Confidence:** Likely (requires a concurrent RO `C_OpenSession`).
- **Description:** `token.login()` commits `SoLoggedIn` before `login_all` runs. If an RO session is opened between the `has_ro_sessions` check and `login_all`, then `on_so_login` fails with `SessionReadOnly` (`session.rs:419-427`). `login_all` rolls back the sessions it already promoted, but the token stays `SoLoggedIn` and `C_Login` returns `CKR_OK`. The result is a token in SO state with public sessions. Any session opened afterwards is promoted to SO, but only if it is R/W. Equally, `open_session` can admit a new RO session while SO login is in progress.
- **Trigger condition:** An RO `C_OpenSession` runs concurrently with an SO `C_Login` on the same slot.
- **Impact:** Login state becomes inconsistent. The spec invariant that no RO session exists while the SO is logged in is broken, and `C_Logout` may fail on some sessions.
- **Recommendation:** Serialize login, logout and open-session per slot under the token `auth` lock, which open-session already takes in `increment_session_count`. Perform the RO check and the `login_all` promotion inside that critical section. On a `login_all` error, call `token.logout()` and return the error.

### H1-20 [Medium] SP 800-57 lifecycle state is enforced only in Encrypt/Decrypt/Sign/VerifyInit

- **Location:** `check_lifecycle` is called only at `functions.rs:1465`, `1762`, `2003` and `2387`. It is absent from `C_WrapKey` (`4983-5098`, for both keys), `C_UnwrapKey` (`5101-5260`), `C_DeriveKey` (`5263-5434`), `C_DigestKey` (`4390-4456`), `C_SetOperationState` (`3381-3496`, see H1-04) and `C_CopyObject`. The policy itself is at `src/store/object.rs:283-305`.
- **CWE:** CWE-324 (Use of a Key Past its Expiration Date), CWE-672.
- **Confidence:** Confirmed.
- **Description:** A key that is `Compromised`, `PreActivation`, or past `CKA_END_DATE` can still wrap, unwrap, derive and be digested. The lifecycle model states that a compromised key must be blocked from all operations and a deactivated key must not protect new data. Wrapping is exactly that: it protects new data.
- **Trigger condition:** A wrap, unwrap or derive operation that references a key whose effective lifecycle state is not `Active`.
- **Impact:** Key-management policy is bypassed. For example, key material continues to be exported under a wrapping key that is known to be compromised.
- **Recommendation:** Centralize the key-use gate, `authorize_key_use(sess, obj, KeyUse::Wrap | Unwrap | Derive | …)`, covering login, usage flag, lifecycle, key type and slot. Call it from every function that takes a key handle, and apply it to both the wrapping key and the target key in `C_WrapKey`. Map lifecycle errors to `CKR_KEY_FUNCTION_NOT_PERMITTED` consistently. Today `check_lifecycle` returns `GeneralError`, which callers remap by hand.

### H1-21 [Medium] Plaintext key material is copied into heap buffers that are never zeroized

- **Location:**
  - `functions.rs:1094` (`C_DestroyObject` copies the key only to compute a counter id);
  - `4430` (`C_DigestKey`);
  - `5037` and `5061` (`C_WrapKey`, the wrapping key and the key to be wrapped);
  - `5157` (`C_UnwrapKey`, the unwrapping key) and `5194` (`unwrapped.clone()`; the original `Vec` from the backend is dropped without being zeroized);
  - `5309` (`C_DeriveKey`);
  - `parse_template` at `5617`, where `CKA_VALUE` (a secret key or private-key DER) passed to `C_CreateObject` lands in a plain `Vec<u8>`;
  - `src/store/attributes.rs:579` (`read_attribute` clones `CKA_VALUE` into a plain `Vec`, which `C_GetAttributeValue` drops after copying it to the caller).
- **CWE:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse), CWE-316 (Cleartext Storage of Sensitive Information in Memory).
- **Confidence:** Confirmed.
- **Description:** The module otherwise takes care to zeroize secrets: it uses `RawKeyMaterial`, `Zeroizing` operation buffers, and cites FIPS 140-3 §7.7 in its comments. These ABI paths, however, clone raw key bytes into ordinary `Vec<u8>` values that are freed without being cleared, leaving copies of the keys in freed heap memory.
- **Trigger condition:** Any wrap, unwrap, derive, digest-key, destroy or create-with-value call, or any read of `CKA_VALUE`.
- **Impact:** Key material stays in freed heap memory, where core dumps, swap, allocator reuse or a memory-disclosure bug elsewhere in the process can expose it. This also conflicts with the zeroization claims made for the module.
- **Recommendation:**
  - Work on `&[u8]` borrowed from `RawKeyMaterial` while the object lock is held, instead of cloning (for example, call the backend inside the `obj.read()` scope).
  - Where an owned copy is unavoidable, use `Zeroizing<Vec<u8>>`.
  - Have `parse_template` return `Zeroizing<Vec<u8>>` values.
  - Store the SHA-256 key id in `StoredObject` so that `C_DestroyObject` needs no copy.
  - Have backends return `Zeroizing` or `RawKeyMaterial`.

### H1-22 [Medium] Unsound public API: 112 safe `pub extern "C" fn` items dereference raw pointers, and CI suppresses the lint

- **Location:** All exported functions in `src/pkcs11_abi/functions.rs`, reachable as `craton_hsm::pkcs11_abi::functions::*` (`src/lib.rs:25-26`, `src/pkcs11_abi/mod.rs:4`). Also the private safe helpers `extract_mechanism_param` (`1507`) and `parse_template` (`5581`). CI uses `-A clippy::not_unsafe_ptr_arg_deref` (`.github/workflows/ci.yml:149`).
- **CWE:** CWE-758 (Reliance on Undefined, Unspecified, or Implementation-Defined Behavior), CWE-822 (Untrusted Pointer Dereference).
- **Confidence:** Confirmed (static; `cargo clippy` reports 112 `not_unsafe_ptr_arg_deref` errors in this file, as noted by the requester).
- **Description:** The functions are declared as safe Rust (`pub extern "C" fn`) but dereference caller-supplied raw pointers without an `unsafe` contract. Any safe Rust code in the workspace (tests, the daemon, admin CLI or external crates) can cause undefined behaviour without writing `unsafe`, for example by passing a dangling non-null pointer. This violates Rust's soundness guarantee, and it hides the actual safety preconditions from reviewers and from `#![deny(unsafe_op_in_unsafe_fn)]`, which the file already enables (line 3) but which has no effect on safe functions. Suppressing the lint in CI means new unsound entry points will not be caught.
- **Trigger condition:** A Rust caller invokes an exported function through the crate path with an invalid pointer or a length that exceeds its buffer.
- **Impact:** Memory-safety violations reachable from safe code. The C ABI itself is unchanged, because C callers have no safe/unsafe distinction.
- **Recommendation:** Declare the exports as `pub unsafe extern "C" fn` with `/// # Safety` sections. This does not change the C ABI or `CK_FUNCTION_LIST` compatibility, because `unsafe extern "C" fn` pointers can populate the list. Alternatively, make the module `pub(crate)` and expose safe wrappers that take slices. Make the pointer-taking helpers `unsafe fn`. Remove `-A clippy::not_unsafe_ptr_arg_deref` from CI once this is done.

### H1-23 [Low] Slices are built from caller lengths before bounds checks, and inconsistently

- **Location:**
  - Update functions build the slice before comparing with `MAX_MULTIPART_ACCUMULATION`: `functions.rs:3820` (EncryptUpdate), `4032` (DecryptUpdate), `4366` (DigestUpdate), `4569` (SignUpdate), `4783` (VerifyUpdate).
  - No bound at all: `4849` (VerifyFinal `signature_len`), `3397` (SetOperationState), `1192` (GetAttributeValue `count`).
  - `3567` (`C_CopyObject` clamps the count silently instead of rejecting it).
  - `5602` (`parse_template` treats `p_value == NULL && value_len > 0` as an empty value).
- **CWE:** CWE-130 (Improper Handling of Length Parameter Inconsistency), CWE-20.
- **Confidence:** Confirmed.
- **Description:** Elsewhere the module creates slices only after capping lengths (`MAX_SINGLE_BUFFER`, `MAX_TEMPLATE_ATTRS`, `MAX_ATTR_VALUE_LEN`). In the locations listed, `slice::from_raw_parts` is called first, with a length the caller controls. A length whose byte size exceeds `isize::MAX` violates the `from_raw_parts` precondition even if the slice is never read. A NULL `pValue` paired with a non-zero length should be `CKR_ARGUMENTS_BAD`, not an empty attribute (which, for example, sets boolean attributes to FALSE).
- **Trigger condition:** A caller passes a length that is inconsistent with its buffer.
- **Impact:** Undefined behaviour or out-of-bounds reads, but only for callers that already violate the API contract. The inconsistency also weakens the defence-in-depth claims in the module header.
- **Recommendation:** Add a single helper, `unsafe fn caller_slice<'a>(p: *const u8, len: CK_ULONG, max: usize) -> Result<&'a [u8], CK_RV>`, that checks null/len consistency and the maximum *before* `from_raw_parts`. Use it everywhere. Reject oversized counts rather than clamping them.

### H1-24 [Low] Fork handling: a child process cannot reinitialize, and a child's C_Finalize writes to the parent's audit log

- **Location:** `functions.rs:143-161` (`get_hsm` fork detection at `149-161`); `229-232` (`C_Initialize` returns `CKR_CRYPTOKI_ALREADY_INITIALIZED` whenever the static `HSM` is `Some`, which it always is in a fork child); `280-307` (`C_Finalize` does not check the PID and writes and flushes an audit record).
- **CWE:** CWE-664 (Improper Control of a Resource Through its Lifetime), CWE-362.
- **Confidence:** Confirmed (logic); Likely (audit-chain impact depends on how `AuditLog` shares its file handle).
- **Description:** After a `fork()`, `get_hsm` correctly returns `CKR_CRYPTOKI_NOT_INITIALIZED`, and says in its log that the child must call `C_Initialize`. But `C_Initialize` in the child sees `guard.is_some()` and fails. The child can only proceed by calling `C_Finalize` first. That call records a `Finalize` audit event and flushes it through the audit state inherited from the parent. Both processes then append to the same tamper-evident chain from diverging in-memory chain heads. If another thread held `HSM` (a `parking_lot` mutex) or an internal lock at the moment of fork, the child deadlocks.
- **Trigger condition:** A host process forks after `C_Initialize`, and the child follows the PKCS#11 guidance to call `C_Initialize`.
- **Impact:** The library cannot be used in fork children without a non-standard call sequence, and the audit chain may fork or become corrupted.
- **Recommendation:** In `C_Initialize`, if `INIT_PID != current_pid()`, discard the inherited core without running its destructors (`std::mem::forget` of the `Arc`, so the parent's files are not touched), then initialize fresh. Make `C_Finalize` in a fork child skip auditing. Register a `pthread_atfork` child handler that sets a flag, which also removes the per-call `getpid` (see Performance).

### H1-25 [Low] C_Initialize ignores CK_C_INITIALIZE_ARGS; C_Finalize leaves the core alive in other threads' caches

- **Location:** `functions.rs:234-241` (`_args` is read and discarded); `functions.rs:78-82` and `280-307` (`CACHED_HSM` is cleared only on the calling thread).
- **CWE:** CWE-20, CWE-226.
- **Confidence:** Confirmed.
- **Description:**
  - **Argument validation.** `pReserved != NULL` and a partially supplied set of mutex callbacks must return `CKR_ARGUMENTS_BAD`. Callbacks supplied without `CKF_OS_LOCKING_OK` require `CKR_CANT_LOCK`, or else the supplied callbacks must be used. `CKF_LIBRARY_CANT_CREATE_OS_THREADS` is not considered. None of these is checked.
  - **Finalize.** `C_Finalize` drops only the global `Arc` and the calling thread's cache. Every other thread that has called into the library keeps an `Arc<HsmCore>` in thread-local storage until that thread's next call or its exit. Until then the whole object store, including key material, stays resident after `C_Finalize` has returned, and `C_Finalize` does not close sessions, log out, or zeroize anything explicitly.
- **Trigger condition:** A caller passes malformed initialization arguments, or calls `C_Finalize` while worker threads that have used the library stay idle.
- **Impact:** Spec non-compliance. Key material remains in memory after finalization.
- **Recommendation:** Validate the arguments as §5.4 requires. In `C_Finalize`, explicitly close all sessions, log out all tokens and clear the object store before dropping the global reference, so that stale `Arc`s point at an emptied core. Alternatively, keep a `Weak` in TLS.

### H1-26 [Low] Deviations from the two-call and CKR_BUFFER_TOO_SMALL rules

- **Location:** `C_DigestFinal` `functions.rs:4519-4525` and `C_SignFinal` `4699-4704` end the operation on `CKR_BUFFER_TOO_SMALL`. `C_GetAttributeValue` `1200-1202` sets `ulValueLen` to the required length instead of `CK_UNAVAILABLE_INFORMATION`. `C_Encrypt` (`1663-1671`), `C_Sign` (`2098-2104`) and `C_WrapKey` (`5066-5087`) perform the full cryptographic operation before discovering that the buffer is too small, or in order to answer a length query.
- **CWE:** CWE-573 (Improper Following of Specification by Caller/Callee), CWE-400.
- **Confidence:** Confirmed.
- **Description:** PKCS#11 §5.2 says that a call returning `CKR_BUFFER_TOO_SMALL` does not terminate the operation. The comment at `4523` states the opposite. Callers that retry with a larger buffer receive `CKR_OPERATION_NOT_INITIALIZED`, and the hashed data is lost. For `C_GetAttributeValue`, v2.40 and v3.0 §5.7 specify `CK_UNAVAILABLE_INFORMATION` in a too-small attribute. Computing the full RSA, PQC or wrap operation only to discard it wastes CPU, and for ECDSA it consumes a nonce.
- **Trigger condition:** A caller supplies a buffer that is too small.
- **Impact:** Interoperability failures and wasted computation. A single-operation retry loop can repeatedly trigger expensive signing operations.
- **Recommendation:** In the Final functions, check the buffer against a pre-computed exact output length (`h.output_len()`, or the length from `estimated_signature_len`) *before* taking the hasher, and keep the operation on `CKR_BUFFER_TOO_SMALL`. Compute the required length for `C_WrapKey` arithmetically (RFC 3394/5649). Follow the specification for `ulValueLen`.

### H1-27 [Low] C_SetAttributeValue is non-atomic, not persisted, and stricter than the specification

- **Location:** `functions.rs:1232-1296`, in particular the loop at `1276-1292`.
- **CWE:** CWE-460 (Improper Cleanup on Thrown Exception), CWE-662.
- **Confidence:** Confirmed.
- **Description:**
  - **Non-atomic.** Template entries are applied one at a time, and the function returns on the first disallowed attribute. A template of `[CKA_LABEL, CKA_SENSITIVE]` therefore changes the label and returns `CKR_ATTRIBUTE_READ_ONLY`. PKCS#11 requires all-or-nothing.
  - **Not persisted.** Changes are not written back to the persistent store (`persist_object` is not called), which becomes relevant once persistence is wired up (H1-34).
  - **Too strict.** The function refuses permitted one-way transitions: `CKA_SENSITIVE` FALSE→TRUE and `CKA_EXTRACTABLE` TRUE→FALSE. Applications cannot harden an existing key in place, and some fall back to `C_CopyObject`, which is weaker (H1-08).
  - **Unbounded values.** `CKA_LABEL`/`CKA_ID` values are bounded only by `MAX_ATTR_VALUE_LEN` (64 KiB).
- **Trigger condition:** A mixed template, or a request to harden a key.
- **Impact:** Partial updates that are hard to diagnose, and a practical push toward the less safe copy path.
- **Recommendation:** Validate the whole template first, then apply it. Allow the one-way hardening transitions and update `ALWAYS_SENSITIVE`/`NEVER_EXTRACTABLE` accordingly. Persist token objects after modification.

### H1-28 [Low] C_CreateObject: weak attribute typing, and login rules only partly applied

- **Location:** `functions.rs:1000-1062`, with the key-class login gate at `1031-1043`. `src/store/attributes.rs:433-480`: boolean attributes are decoded as `!value.is_empty() && value[0] != 0` with no length check. `src/store/attributes.rs:506-527`: a malformed date returns `GeneralError`. The validator `is_bool_attribute` (`functions.rs:5536-5560`) is dead code.
- **CWE:** CWE-20, CWE-1287 (Improper Validation of Specified Type of Input), CWE-862.
- **Confidence:** Confirmed.
- **Description:** The problems in this path are:
  - **Boolean attributes.** Values of the wrong length are accepted instead of producing `CKR_ATTRIBUTE_VALUE_INVALID`, and an empty value means FALSE. For example, `CKA_SENSITIVE` with `ulValueLen=0` silently creates a non-sensitive key.
  - **Private objects without login.** A public R/W session may create `CKA_PRIVATE=TRUE` data, certificate and public-key objects. PKCS#11 permits only public objects without login.
  - **R/O sessions.** R/O sessions are refused outright, although they may create session objects.
  - **Template consistency.** Class-specific consistency is not checked (for example, `CKA_KEY_TYPE` must be present for keys, and `CKA_VALUE` length must match `CKA_VALUE_LEN`).
  - **Error codes.** Errors from `apply_attribute` are mapped by the generic `HsmError`→`CK_RV` conversion. For example, an oversized extra attribute gives `CKR_ARGUMENTS_BAD` instead of `CKR_ATTRIBUTE_VALUE_INVALID`.
- **Trigger condition:** A template with malformed or omitted attribute values.
- **Impact:** A key's protection attributes can differ from what the caller intended, and non-standard error behaviour.
- **Recommendation:** Wire `is_bool_attribute` and `parse_ck_bbool` into `apply_attribute` (move them to `store::attributes`). Require login for `CKA_PRIVATE=TRUE` objects of every class, and for `CKA_TOKEN=TRUE` private objects. Allow R/O sessions to create session objects. Validate required attributes per class.

### H1-29 [Low] Handle allocators wrap around, and colliding inserts replace live sessions or objects

- **Location:** `src/session/handle.rs:14` (`MAX_HANDLE = CK_ULONG::MAX`) and `148-172` (the counter wraps to 0); `src/session/manager.rs:66` (`sessions.insert` overwrites); `src/store/attributes.rs:260` and `279` (`objects.insert` overwrites).
- **CWE:** CWE-190, CWE-672 (Operation on a Resource after Expiration or Release).
- **Confidence:** Possible (requires about 2^32 allocations on platforms with a 32-bit `CK_ULONG`, such as Windows).
- **Description:** The allocators are Feistel permutations of a counter that wraps. After a full cycle, a new handle equals the handle of the oldest allocation. If that session or object is still alive, `DashMap::insert` silently replaces it. The previous holder's handle then refers to the new session or object, which may be at a different privilege level.
- **Trigger condition:** A long-running process on a 32-bit `CK_ULONG` platform that opens about 4.3 billion sessions or creates that many objects.
- **Impact:** Handle confusion between callers, leading to use of another caller's session state or object.
- **Recommendation:** Insert with `entry(handle).or_insert` / `vacant` and retry on collision. Alternatively, refuse to wrap (`CKR_SESSION_COUNT`/`CKR_DEVICE_MEMORY`).

### H1-30 [Low] PIN handling edge cases: C_SetPIN in R/O sessions, NULL PIN treated as empty, PBKDF2 run under the slot-wide auth lock

- **Location:** `functions.rs:572-610` (`C_SetPIN` has no R/O-session check); `functions.rs:919-927` (a NULL `pPin` with any `ulPinLen` becomes an empty PIN); `src/token/token.rs:576-684` (`login` holds `auth` across PBKDF2 at 600,000 iterations); `481-567` (`set_pin`); `403-452` (`init_token`); `187-198` (`persist_lockout` does file I/O under `auth`).
- **CWE:** CWE-20, CWE-400, CWE-833.
- **Confidence:** Confirmed.
- **Description:**
  - **R/O sessions.** PKCS#11 requires `CKR_SESSION_READ_ONLY` for `C_SetPIN` in an R/O session.
  - **NULL PIN.** A NULL `pPin` is reserved for the protected authentication path, which is not advertised (`CKF_PROTECTED_AUTHENTICATION_PATH` is absent). It should give `CKR_ARGUMENTS_BAD`. Instead the attempt is verified as an empty PIN and counts toward lockout.
  - **Auth lock held during PBKDF2.** `increment_session_count`, `decrement_session_count`, `flags()`, `login_state()` and `require_login` all take the same `auth` mutex. Every `C_Login`/`C_SetPIN` therefore blocks `C_OpenSession`, `C_CloseSession` and `C_GetTokenInfo` for that slot for the PBKDF2 duration plus a synchronous file write. The rate-limit backoff bounds how often this can happen per account, but successful logins, and the first failed attempt after each backoff window, still take the lock.
- **Trigger condition:** Concurrent `C_Login` traffic against a slot in use by other threads, or a caller that passes a NULL PIN.
- **Impact:** Latency spikes and partial denial of service for other threads, spec deviations, and lockout counters consumed by malformed calls.
- **Recommendation:** Return `CKR_ARGUMENTS_BAD` for a NULL PIN, and `CKR_SESSION_READ_ONLY` in `C_SetPIN`. In `login`, snapshot the hash and the rate-limit state under `auth`, release the lock, run PBKDF2, then re-acquire the lock and commit using a generation counter. Move the lockout persistence outside the lock, or to a writer thread, while keeping the fail-closed ordering.

### H1-31 [Low] Key-pair generation: an unknown EC curve silently becomes P-256, RSA size is truncated, and inserts are not atomic

- **Location:** `functions.rs:2853-2873` (any `CKA_EC_PARAMS` other than P-384, including a missing or unrecognized one, generates P-256); `2786` (`CKA_MODULUS_BITS as u32`); `2837-2842`, `2923-2928`, `2980-2985` and `3082-3087` (the public-key object is inserted before the private one, and there is no rollback).
- **CWE:** CWE-1284, CWE-681 (Incorrect Conversion between Numeric Types), CWE-459.
- **Confidence:** Confirmed (fallback and truncation); Likely (orphaned public key when the store is near `MAX_OBJECTS`).
- **Description:**
  - **Curve fallback.** A request for P-521 (or a malformed OID) returns a P-256 key and `CKR_OK`, instead of `CKR_CURVE_NOT_SUPPORTED`/`CKR_DOMAIN_PARAMS_INVALID`.
  - **Truncation.** A 64-bit `CKA_MODULUS_BITS` is truncated before validation. For example, `2^32 + 2048` is treated as 2048.
  - **Non-atomic insert.** If the private-key insert fails, the public-key object remains without its private half.
- **Trigger condition:** Unsupported curve parameters, out-of-range modulus bits, or a store near capacity.
- **Impact:** The generated key is weaker than, or different from, the one requested. There is also clutter from orphaned objects.
- **Recommendation:** Match the curve OID exactly and reject anything else. Validate `CK_ULONG` values with `u32::try_from`. Insert both objects under one store operation, or remove the public object on failure.

### H1-32 [Low] Memory used by multi-part operations is bounded per session, not in total

- **Location:** `functions.rs:86` (`MAX_MULTIPART_ACCUMULATION` = 64 MiB per operation); EncryptUpdate and DecryptUpdate buffer the whole message (`3820-3830`, `4032-4040`); DigestUpdate keeps a full copy of its input next to the hasher (`4366-4376`); `src/token/token.rs:15` (100 sessions per slot by default, and each slot has its own limit).
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling).
- **Confidence:** Confirmed.
- **Description:** Every session may hold 64 MiB of buffered data: plaintext for CBC and CTR, which do no streaming, or a duplicate of the digest input kept only to support `C_GetOperationState`, which cannot serialize more than 4 MiB anyway (`session.rs:115`). A per-slot limit of 100 sessions allows about 6.4 GiB per slot, with no global cap. The buffers are `Zeroizing`, so this is purely a resource issue.
- **Trigger condition:** Many concurrent sessions, each feeding large multi-part inputs.
- **Impact:** Memory exhaustion, which ends in an OOM kill of the host process (availability).
- **Recommendation:** Stream CBC and CTR, emitting output in each Update and keeping at most one block. Stop recording `accumulated_input` beyond `OP_STATE_MAX_DATA_LEN` and mark such operations unsaveable. Add a global byte budget, for example an `AtomicUsize` in `HsmCore`, that is charged by every accumulator.

### H1-33 [Low] Windows audit-file ACL: unaligned casts and a DACL applied only after the file is created

- **Location:** `src/platform_acl.rs:89` (`Vec<u8>` cast to `&TOKEN_USER`); `102` (`Vec<u8>` cast to `*mut ACL`); `118-126` (DACL applied to an existing path). The caller is `src/audit/log.rs:297-316`, which opens the file first and continues on failure.
- **CWE:** CWE-367 (TOCTOU), CWE-732 (Incorrect Permission Assignment), CWE-758.
- **Confidence:** Likely (the alignment issue is UB by Rust rules but benign with the default Windows heap); Confirmed (ordering).
- **Description:**
  - **Alignment.** A `Vec<u8>` allocation is only guaranteed 1-byte alignment. Taking `&*(ptr as *const TOKEN_USER)` requires pointer alignment, and `ACL` requires 4-byte alignment.
  - **Permission window.** The audit file is created with inherited ACLs and restricted afterwards. It is then used by path, not by handle, so it can be read in that window or swapped, depending on the directory's permissions.
  - **Access mask.** The DACL grants only `GENERIC_READ | GENERIC_WRITE`, not `DELETE`, which can later interfere with rotation.
- **Trigger condition:** Windows builds with audit logging to a directory that is shared or has broad inherited permissions.
- **Impact:** A short window in which the audit log is readable, and undefined behaviour in Rust terms.
- **Recommendation:**
  - Allocate aligned buffers (`Vec<u64>`, or `std::alloc` with `Layout::from_size_align`) or read the SID with `ptr::read_unaligned`.
  - Create the file with a security descriptor (`CreateFileW` with `SECURITY_ATTRIBUTES`), or apply `SetSecurityInfo` on the open handle.
  - Fail closed, or at least refuse to write, if restricting the file fails.

### H1-34 [Informational] Token objects are never persisted through the PKCS#11 ABI

- **Location:** `src/core.rs:135` and `172` (`ObjectStore::new()`, never `with_persistence`); `set_persist_key`, `load_from_store` and `find_objects_for_slot` (`src/store/attributes.rs`) are not called anywhere in the ABI.
- **CWE:** CWE-1059 (Insufficient Technical Documentation) / functional defect.
- **Confidence:** Confirmed.
- **Description:** `CKA_TOKEN=TRUE` objects live only in memory and disappear at `C_Finalize` or process exit, although the documentation and object model describe encrypted persistence. The persistence code (`persist_object`, and the missing re-persist after `C_SetAttributeValue`, H1-27) is effectively dead in this build. The PIN lockout counters *are* persisted (`token.rs:187-198`).
- **Trigger condition:** Any use of `CKA_TOKEN=TRUE`.
- **Impact:** Applications that rely on token objects lose their keys, which is an availability and correctness issue. It also means the security review of the persistence code cannot be exercised through the ABI.
- **Recommendation:** Either wire up `with_persistence` in `HsmCore::try_new`, with persist-key derivation at USER login and clearing at logout, or report `CKF_WRITE_PROTECTED`-style semantics and refuse `CKA_TOKEN=TRUE` with `CKR_TEMPLATE_INCONSISTENT` until persistence is wired.

### H1-35 [Informational] Specification and interoperability deviations

- **Location / items:**
  - ECDSA signatures are DER-encoded (`src/crypto/sign.rs:475`, `513`, `838`, `883`). PKCS#11 `CKM_ECDSA*` requires raw `r‖s`.
  - `C_GetMechanismInfo` (`functions.rs:660-779`) answers for mechanisms that the algorithm policy filters out of `C_GetMechanismList` (for example SHA-1 or PQC when disabled). Its `ulMinKeySize`/`ulMaxKeySize` for the ML-DSA mechanisms are variant numbers (44 to 87), not key sizes.
  - `C_GenerateRandom` (`3284`) uses `OsRng` directly and bypasses the SP 800-90A `HmacDrbg` held in `HsmCore` (`core.rs:26`), which matters for the FIPS boundary story.
  - `CK_INFO.cryptokiVersion` and `CK_FUNCTION_LIST.version` claim 3.0 (`320`, `5460`), but `C_GetInterfaceList`, `C_GetInterface`, `C_LoginUser`, `C_SessionCancel` and the message-based functions are absent.
  - `HsmError::TokenNotInitialized` maps to `CKR_TOKEN_NOT_RECOGNIZED` (`src/error.rs:130`). A non-destroyable object returns `CKR_ATTRIBUTE_READ_ONLY` instead of `CKR_ACTION_PROHIBITED`.
  - `C_GetFunctionStatus`, `C_CancelFunction` and `C_WaitForSlotEvent` (`5437-5453`) neither check initialization nor use `catch_unwind`. They are trivial, but inconsistent with the rest of the module.
- **CWE:** CWE-573.
- **Confidence:** Confirmed.
- **Impact:** Interoperability failures with standard consumers (OpenSSL pkcs11 provider, p11-kit, Java SunPKCS11), and possible misreporting of FIPS status.
- **Recommendation:** Convert ECDSA signatures to and from fixed-width `r‖s` at the ABI boundary. Filter `C_GetMechanismInfo` through the same policy as the list. Route `C_GenerateRandom` through `hsm.drbg`. Either advertise 2.40 or implement the v3.0 interface functions. Align the error codes.

### H1-36 [Low] Inconsistent session/object lock order can deadlock two threads that share a session

- **Location:** Object lock first, then session lock: `C_SetAttributeValue` (`functions.rs:1262` `obj.write()`, then `1265` `sess.read()`), `C_GetAttributeValue` (`1184` then `1186`), `C_GetObjectSize` (`1142`). Session lock first, then object lock: `C_EncryptInit` (`1432` `sess.write()`, then `1456` `obj.read()`), and likewise `C_DecryptInit`, `C_SignInit`, `C_VerifyInit`, `C_Encrypt`/`C_Decrypt`/`C_Sign`/`C_*Final`, and `C_CopyObject` (`3529` then `3539`).
- **CWE:** CWE-833 (Deadlock).
- **Confidence:** Likely (requires two threads using the same session handle concurrently).
- **Description:** `parking_lot::RwLock` is task-fair, so a pending writer blocks new readers. Consider two threads:
  - thread A runs `C_SetAttributeValue(S, O)` and holds `O` for writing while it waits to read `S`;
  - thread B runs `C_EncryptInit(S, …, O)` and holds `S` for writing while it waits to read `O`.

  Neither can proceed. With a third, unrelated thread waiting to write, even read/read orderings can deadlock.
- **Trigger condition:** A multi-threaded application issues object-attribute calls and crypto-init calls on the same session at the same time.
- **Impact:** The two threads hang permanently, and so does every later caller that touches that session or object (availability).
- **Recommendation:** Adopt a single documented lock order, session before object, everywhere. For example, in `C_SetAttributeValue` and `C_GetAttributeValue`, snapshot the session state (`let logged_in = sess.read().state.is_user();`) *before* locking the object. Add a lock-order assertion in debug builds, or use `parking_lot`'s `deadlock_detection` feature in tests.

## Stubs, TODOs and unimplemented items

No `TODO`, `FIXME`, `todo!()` or `unimplemented!()` markers exist in the in-scope files. The table lists functional stubs and code that is dead or ignored.

| Location | Item | Impact |
|---|---|---|
| `functions.rs:4736-4753` | `C_SignRecoverInit` / `C_SignRecover` return `CKR_FUNCTION_NOT_SUPPORTED` | Recoverable-signature mechanisms are unavailable. The stub is safe. |
| `functions.rs:4919-4936` | `C_VerifyRecoverInit` / `C_VerifyRecover` return `CKR_FUNCTION_NOT_SUPPORTED` | Same as above. |
| `functions.rs:4939-4980` | `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate` return `CKR_FUNCTION_NOT_SUPPORTED` | Dual-function operations are unavailable. The stubs are safe, but they do not validate the session or initialization state. |
| `functions.rs:5437-5444` | `C_GetFunctionStatus` / `C_CancelFunction` always return `CKR_FUNCTION_NOT_PARALLEL` | Legacy behaviour, acceptable. No initialization check (H1-35). |
| `functions.rs:5447-5453` | `C_WaitForSlotEvent` returns `CKR_FUNCTION_NOT_SUPPORTED` | Event-driven consumers must poll. No initialization check. |
| `functions.rs:3238-3256` | `C_SeedRandom` returns `CKR_RANDOM_SEED_NOT_SUPPORTED` | Spec-permitted. |
| `functions.rs:3341-3343` | `C_GetOperationState` returns `CKR_STATE_UNSAVEABLE` for encrypt/decrypt | Spec-permitted. Sign/verify state is saved but restored incorrectly (H1-17). |
| `functions.rs:3386` | `C_SetOperationState` ignores `hEncryptionKey` | Consistent with the point above. `hAuthenticationKey` is not authorized (H1-04). |
| `functions.rs:2533` | `C_GenerateKey` supports only `CKM_AES_KEY_GEN` | No generic-secret or HMAC keys can be generated. |
| `functions.rs:5066`, `5170` | `C_WrapKey` / `C_UnwrapKey` support only AES-KW/KWP; RSA-OAEP wrapping and unwrap into non-AES key types are unsupported | Unwrapped keys are always labelled `CKK_AES` (H1-14). |
| `functions.rs:234-241` | `CK_C_INITIALIZE_ARGS` is read and discarded | H1-25. |
| `functions.rs:786-793` | `C_OpenSession` ignores `pApplication` and `Notify` | Notification callbacks are never delivered. Acceptable. |
| `functions.rs:371-374` | `C_GetSlotList` ignores `tokenPresent` | Every slot always has a token. Acceptable. |
| `src/token/token.rs:679-681` | `CKU_CONTEXT_SPECIFIC` → `CKR_USER_TYPE_INVALID`; `CKA_ALWAYS_AUTHENTICATE` is not implemented anywhere | Keys cannot require per-operation re-authentication. The attribute is stored as an extra attribute and silently not enforced. |
| `functions.rs:5536-5560` | `is_bool_attribute` is `#[allow(dead_code)]` | A validator exists but is not used (H1-28). |
| `src/store/attributes.rs:371-392` | `find_objects_for_slot` is never called with `Some(slot)` | Slot isolation is not wired (H1-13). |
| `src/store/attributes.rs:96-230`, `src/core.rs:135` | Persistence (`with_persistence`, `set_persist_key`, `load_from_store`, `persist_object`) is unused | Token objects are not persisted (H1-34). |
| `functions.rs:320`, `5460` | Version 3.0 is advertised, but there is no `C_GetInterface*`, `C_LoginUser`, `C_SessionCancel` or message API | v3.0 consumers fall back or fail (H1-35). |
| `src/crypto/encrypt.rs:315` | `aes_256_gcm_encrypt_with_aad` exists but is not reachable from the ABI | GCM AAD is ignored (H1-16). |

## Code review

The following observations are structural. They explain why the findings above cluster the way they do, and suggest changes that would stop them from recurring.

1. **There is no central authorization gate.** Each of the roughly 25 functions that take a key or object handle builds its own checks, and every one uses a different subset of: login, `CKA_PRIVATE`, usage flag, lifecycle, key type, slot and R/W. H1-03, -04, -05, -07, -10, -11, -12, -15 and -20 are all instances of a missing element. Recommendation: a single `fn authorize(sess: &Session, obj: &StoredObject, use_: KeyUse) -> Result<(), CK_RV>` in `pkcs11_abi`, called by every entry point that takes a handle, plus a table-driven test that runs every entry point against every combination of session state and object attributes.
2. **Seven template parsers disagree with one another.** `apply_attribute`, the `C_GenerateKey` loop, `apply_pub_template`, `apply_priv_template`, the `C_UnwrapKey` loop, the `C_DeriveKey` loop and the `C_CopyObject` loop each implement different subsets and different rules. Boolean length is enforced in some and not others, dates are rejected in one and ignored in the rest, and unknown attributes are stored in one and dropped in the others. Root cause of H1-08, -09, -14 and -28. Recommendation: one attribute schema table (type, length, class applicability, who may set it, mutability, one-way direction) and one `apply_template(ctx)` function.
3. **Login state has two sources of truth.** `Token.auth.login` and `Session.state` are updated in separate critical sections, and the ABI reads the session copy only. That is how H1-06 (the token stays logged in) and H1-19 (divergence) arise. Recommendation: derive the session's effective state from the token's state plus the session's R/W flag at the time of each call, and drop the per-session copy. At the least, update both under the token `auth` lock.
4. **Too much repeated FFI plumbing.** There are 57 `catch_unwind` bodies, 53 `match get_hsm()` blocks, and repeated `get_session`/`get_object`/length-check code across a single 5,622-line file. This repetition makes omissions easy (the three trivial functions lack `catch_unwind`; the Update functions lack the length cap). Recommendation: an `ffi_entry!` macro, or a helper `fn with_session<F>(h, f)`, that does `catch_unwind`, `get_hsm`, the session lookup and pointer checks. Split the file into `general.rs`, `session.rs`, `object.rs`, `crypto.rs` and `keymgmt.rs`.
5. **Audit coverage is incomplete, and audit failures are ignored.** All 23 `audit_log.record` call sites discard their result (`let _ =`). Security-relevant state changes are not audited at all: `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`, `C_CopyObject`, `C_SetAttributeValue`, `C_SetOperationState` and `C_DigestKey`. Recommendation: audit every key-management and PIN-management call, including failures. Decide explicitly (through configuration) whether audit write failure is fail-open or fail-closed, and surface it as `CKR_DEVICE_ERROR` when fail-closed.
6. **Unsafe contract hygiene.** The module header claims "43 unsafe blocks (41 in this file)", while the file contains 125 `unsafe {` blocks. The six-pattern `SAFETY` comment does not cover the Update functions, which build slices before bounds checks (H1-23), or the fact that the exported functions are safe `fn`s (H1-22). Recommendation: after H1-22, add per-block `// SAFETY:` comments and turn on `clippy::undocumented_unsafe_blocks`.
7. **Error mapping discards information.** `Err(_) => return CKR_KEY_HANDLE_INVALID` hides `ObjectHandleInvalid` versus a lock or store error. `check_lifecycle` returns `GeneralError`, which each caller must remap. `PinRateLimited` becomes `CKR_FUNCTION_FAILED`, which applications treat as fatal. Recommendation: have typed errors carry their intended `CK_RV`, and avoid wildcard error arms.
8. **Lock discipline is inconsistent.** The session and object lock order is reversed in places (H1-36). The token `auth` mutex is held across PBKDF2 and file I/O (H1-30). The session write lock is held across the 10 ms padding-oracle sleep in `aes_cbc_decrypt` (see Performance). Recommendation: document the lock hierarchy in `core.rs`, and keep crypto work and I/O outside locks where the state allows it.
9. **Test gaps suggested by the findings.** There are no negative authorization tests for: an SO session using USER objects; a public session calling Destroy, Wrap, Derive, DigestKey or SetOperationState; closing all sessions and then opening a new one; access across slots; C_CopyObject escalation; or a state round-trip for hash-then-sign. Recommendation: add them as a `tests/abi_authz.rs` matrix before fixing, so the fixes can be verified.
10. **What is done well.** Every non-trivial entry point is wrapped in `catch_unwind`. Output pointers are null-checked consistently. Output buffers are length-checked before writes in the single-part paths. Operation buffers are `Zeroizing`. Handles are unpredictable (Feistel-scrambled). PIN verification is constant-time PBKDF2 with persistent lockout. GCM nonce-uniqueness is tracked per key. Search timing is kept constant (`find_objects_for_slot`, `matches_template`).

## Performance improvement suggestions

| # | Location | Issue | Suggestion |
|---|---|---|---|
| P1 | `functions.rs:149-152` (`get_hsm`) | `getpid()` runs on every C_* call. glibc stopped caching the PID in 2.25, so this is a real syscall each time. | Register `pthread_atfork(child = set FORKED flag)` once in `C_Initialize` and test an `AtomicBool` instead. |
| P2 | `functions.rs:143-186` | Every call clones an `Arc<HsmCore>` (an atomic increment and decrement), even on the TLS fast path. | Return a borrowed guard from `CACHED_HSM.with(..)`, or pass `&HsmCore` into a closure, to avoid refcount traffic on hot paths. |
| P3 | `src/crypto/encrypt.rs:612-616` via `C_Decrypt` (`functions.rs:1862`) and `C_DecryptFinal` | A 10 ms minimum sleep per CBC decrypt, taken while the session **write** lock and the key object's read lock are held. Throughput is capped at about 100 operations per second per session, and other threads touching that session or key object stall. | Use constant-time unpadding (the `subtle`-based PKCS#7 check) instead of a sleep. At minimum, release the session lock before the sleep. |
| P4 | `functions.rs:3820-3830`, `4032-4040` | CBC/CTR multi-part buffers up to 64 MiB and encrypts everything in Final: O(n) memory and no pipelining. | Stream the data: keep a cipher state in `ActiveOperation` and emit whole blocks from each Update, retaining at most one block (plus one pad block for CBC_PAD decrypt). |
| P5 | `functions.rs:4366-4376` | DigestUpdate both hashes and stores all input, duplicating up to 64 MiB, to support state save. | Serialize the hasher state (the `sha2` crates expose block-level state through `digest::core_api`), or cap `accumulated_input` at `OP_STATE_MAX_DATA_LEN` and mark larger operations unsaveable. |
| P6 | `functions.rs:4504` | `C_DigestFinal` clones `accumulated_input` (up to 64 MiB) into `_acc_input`, which is never used. | Remove the clone. |
| P7 | `functions.rs:1553`, `1809`, `3918`, `4131` | `mechanism_param.clone()` allocates on every Encrypt/Decrypt call. | Borrow the parameter from the operation while the session guard is held, or use `std::mem::take` when the operation completes. |
| P8 | `functions.rs:1663-1671`, `2098-2104`, `4697-4704`, `5066-5087` | `C_Encrypt`, `C_Sign`, `C_SignFinal` and `C_WrapKey` perform the full cryptographic operation before finding the buffer too small, or in order to answer a length query. RSA-4096, SLH-DSA and ML-DSA signing are expensive. | Compare the caller's buffer with a precomputed exact or upper-bound length before running the cryptography (see H1-26). |
| P9 | `src/token/token.rs:576-684` | PBKDF2 at 600,000 iterations runs under the slot-wide `auth` mutex, which serializes `C_OpenSession`/`C_CloseSession`/`C_GetTokenInfo` behind every login. | Run PBKDF2 outside the lock and commit under it using a generation check (see H1-30). |
| P10 | `src/token/token.rs:187-198` | Pretty-printed JSON is written to the lockout file on *every* successful login and PIN change, under the lock. | Write only when the counters actually change, which is not the case on a success when they are already zero. Use compact serialization and write from a background thread with fsync ordering. |
| P11 | `functions.rs:1091-1094`, `src/crypto/encrypt.rs:100-103` | `C_DestroyObject` copies the key and computes SHA-256 over it to find its counter entry. The GCM path also hashes the key on every encryption. | Compute the key id once at object creation, store it in `StoredObject`, and pass it to the counter functions. |
| P12 | `src/store/attributes.rs:371-392` | `find_objects` takes a read lock on every object for every search, with a full-capacity `Vec`. That is O(N) lock traffic for up to 10,000 objects. | Keep a per-slot, per-class index (for example `DashMap<(slot, class), Vec<handle>>`). Keep the constant-time template match within the candidate set if the timing property is required. |
| P13 | `src/session/manager.rs:133-217` | `login_all`, `logout_all` and `has_ro_sessions` iterate over **all** sessions of all slots. | Index sessions by slot (`DashMap<slot, DashSet<handle>>`). |
| P14 | `functions.rs:1206-1208` and `read_attribute` | Each attribute read allocates a fresh `Vec` (including a key copy for `CKA_VALUE`) only to copy it into the caller's buffer. | Add `read_attribute_into(&obj, type, &mut [u8]) -> Result<usize>` so values are written directly, which also fixes part of H1-21. |

## Executive summary (final, supersedes the counts above)

| Severity | Count | Findings |
|---|---|---|
| Critical | 1 | H1-01 |
| High | 9 | H1-02, H1-03, H1-04, H1-05, H1-06, H1-07, H1-08, H1-09, H1-10 |
| Medium | 12 | H1-11 to H1-22 |
| Low | 12 | H1-23 to H1-33, H1-36 |
| Informational | 2 | H1-34, H1-35 |
| **Total** | **36** | |

| ID | Severity | Title | Primary location |
|---|---|---|---|
| H1-01 | Critical | C_InitToken destroys all objects before it verifies the SO PIN | `functions.rs:515-522` |
| H1-02 | High | Sensitive but extractable keys are readable in plaintext | `store/attributes.rs:566-579` |
| H1-03 | High | C_WrapKey does not authorize the key being wrapped | `functions.rs:5041-5061` |
| H1-04 | High | C_SetOperationState re-binds to any key with no authorization | `functions.rs:3426-3493` |
| H1-05 | High | SO counts as logged in for USER-private objects | `session/session.rs:38-43` |
| H1-06 | High | Closing all sessions does not log out the token | `session/manager.rs:70-110`, `token/token.rs:730-755` |
| H1-07 | High | C_DestroyObject has no private/login check | `functions.rs:1066-1116` |
| H1-08 | High | C_CopyObject escapes MODIFIABLE, usage flags and WRAP_WITH_TRUSTED | `functions.rs:3508-3738` |
| H1-09 | High | CKA_TRUSTED and provenance attributes can be set by the caller | `store/attributes.rs:528-537`, `functions.rs:5030-5058` |
| H1-10 | High | Keygen, unwrap and derive do not require login | `functions.rs:2508-2685`, `2688-2778`, `5101-5260`, `5263-5434` |
| H1-11 | Medium | C_DeriveKey base-key authorization and parameter parsing | `functions.rs:5300-5361` |
| H1-12 | Medium | C_DigestKey login bypass and plaintext key in the state blob | `functions.rs:4390-4456`, `3311-3375` |
| H1-13 | Medium | No slot isolation for objects | `core.rs:135`, `store/attributes.rs:356-362` |
| H1-14 | Medium | Templates silently drop restrictive attributes | `functions.rs:2660`, `3156`, `3227`, `5247`, `5421` |
| H1-15 | Medium | No key-type/mechanism consistency check | `functions.rs:1450-1468` (and the other *Init functions) |
| H1-16 | Medium | GCM, CBC and OAEP mechanism parameters ignored or misread | `functions.rs:1507-1522`, `1616-1617`, `197-219` |
| H1-17 | Medium | Restored hash-then-sign/verify state signs or verifies the wrong data | `functions.rs:3439`, `3467`, `4692`, `4870` |
| H1-18 | Medium | Session objects outlive their sessions | `session/manager.rs:70-110` |
| H1-19 | Medium | C_Login ignores the login_all failure; states diverge | `functions.rs:916`, `932` |
| H1-20 | Medium | Lifecycle not enforced for wrap, unwrap, derive and digest-key | `functions.rs:4983-5434` |
| H1-21 | Medium | Key material copied into non-zeroized buffers | `functions.rs:1094`, `4430`, `5037`, `5061`, `5157`, `5194`, `5309`, `5617` |
| H1-22 | Medium | Unsound safe `extern "C"` API (112 clippy errors, lint suppressed in CI) | `functions.rs` (all exports), `.github/workflows/ci.yml:149` |
| H1-23 | Low | Slices built from caller lengths before bounds checks | `functions.rs:3820`, `4032`, `4366`, `4569`, `4783`, `4849`, `3397`, `1192` |
| H1-24 | Low | Fork child cannot reinitialize; audit written from the child | `functions.rs:229-232`, `280-307` |
| H1-25 | Low | Init args ignored; Finalize leaves the core alive in TLS caches | `functions.rs:234-241`, `78-82` |
| H1-26 | Low | Two-call / BUFFER_TOO_SMALL deviations | `functions.rs:4519-4525`, `4699-4704`, `1200-1202` |
| H1-27 | Low | C_SetAttributeValue non-atomic, not persisted, too strict | `functions.rs:1276-1292` |
| H1-28 | Low | C_CreateObject attribute typing and login rules | `store/attributes.rs:433-480`, `functions.rs:1031-1043` |
| H1-29 | Low | Handle wrap-around replaces live entries | `session/handle.rs:148-172`, `session/manager.rs:66` |
| H1-30 | Low | PIN edge cases; PBKDF2 under the slot auth lock | `functions.rs:572-610`, `919-927`, `token/token.rs:576-684` |
| H1-31 | Low | EC curve fallback, RSA size truncation, non-atomic key-pair insert | `functions.rs:2786`, `2853-2873` |
| H1-32 | Low | Multi-part memory bounded per session, not in total | `functions.rs:86`, `3820-3830`, `4366-4376` |
| H1-33 | Low | Windows ACL: unaligned casts; DACL applied after creation | `platform_acl.rs:89`, `102`, `118-126` |
| H1-34 | Info | Token objects never persisted | `core.rs:135`, `172` |
| H1-35 | Info | Spec and interoperability deviations (ECDSA DER, v3.0 claim, DRBG bypass) | `crypto/sign.rs:475`, `functions.rs:320`, `3284` |
| H1-36 | Low | Session/object lock-order inversion (deadlock) | `functions.rs:1262-1265` vs `1432-1456` |

**Corrections to the preliminary summary above.**
- The final count is 36, not 32. There are 12 Medium and 12 Low findings rather than 11 and 9, and 2 Informational rather than 3.
- The line range for H1-04 is `functions.rs:3381-3496`; the substitution happens at `3426-3482`.
- H1-05 and H1-06 are separate High findings.

**Recommended fix order.**
1. H1-01, H1-06, H1-05 and H1-07. These are small, local changes that close authentication bypasses and destruction without authentication.
2. A central `authorize()` gate. This closes H1-03, H1-04, H1-10, H1-11, H1-12, H1-15 and H1-20 together.
3. A unified attribute schema. This closes H1-02, H1-08, H1-09, H1-14 and H1-28.
4. H1-17, H1-13 and H1-16, which carry integrity and tenant-isolation risk.
5. H1-22, H1-21 and H1-23: soundness and hygiene.
