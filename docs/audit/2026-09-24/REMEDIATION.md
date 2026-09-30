# Remediation status — 2026-09-24 audit

Status of **every** finding of the nine reports of the
[2026-09-24 security and certification-readiness audit](README.md)
(H1–H6, A1–A3; 244 findings) after the remediation work on
`claude/audit-fixes`. This table was built from the wave-1 fix branches
(crypto, state, daemon, admin, spy, ci) and their hand-off notes, the
wave-2 release/supply-chain/docs branch (`claude/audit-fixes2-rel`) and
`git log`; commit IDs are the short hashes on those branches.

> **Status note:** the wave-2 rows were reconciled against the wave-2 commit
> messages. "Fixed (wave 2)" means a commit on `claude/audit-fixes2-abi` or
> `claude/audit-fixes2-core` names the finding; it has **not** been re-verified
> finding by finding. The rows still open after wave 2 are H1-32, H1-33,
> A2-23, A2-27, A3-19 and A3-21. See [HANDOFF.md](HANDOFF.md).

## Legend

| Status | Meaning |
|---|---|
| **Fixed** | Fixed in code / configuration / documentation; regression test where practical. |
| **Partially fixed** | The exploitable or non-conformant part is fixed; a residual is described in *Notes* (often a design limit or an owner action). |
| **Fixed (wave 2)** | Named in a wave-2 commit message; not independently re-verified. |
| **Open — not completed in wave 2** | Wave-2 agents stopped (usage limit) before reaching it. |
| **Not fixable in code** | Needs an organisational, certification or repository-settings action — see [Owner actions](#not-fixable-in-code--owner-actions). |
| **Documented** | Observation; accepted and described in the documentation. |
| **Open (unassigned)** | Requires code, not assigned to any agent yet. |

## Summary

| Status | Findings |
|---|---|
| Fixed | 152 |
| Partially fixed | 47 |
| Fixed in wave 2 (ABI, core, daemon, admin; per commit messages — verify against the test run in [HANDOFF.md](HANDOFF.md)) | 35 |
| Open — not completed in wave 2 (usage limit reached) | 6 |
| Documented | 2 |
| Open (unassigned) | 1 |
| n/a (positive observations) | 1 |
| **Total** | **244** |

No finding is *entirely* unfixable in code; the residual parts that need owner action are named in the *Notes* column and collected under [Owner actions](#not-fixable-in-code--owner-actions).

Cross-cutting top issues from the [consolidated summary](README.md#top-cross-cutting-issues-de-duplicated):

| # | Issue | Status |
|---|---|---|
| 1 | `C_InitToken` wipes before SO-PIN check (H1-01, H3-01, A1-07, A2-02) | Fixed (state) |
| 2 | Daemon login state shared by all clients (H4-01) | Fixed (daemon) |
| 3 | `CKA_SENSITIVE` bypass (H1-02, H3-02, A1-08, A2-04) | Fixed (state) |
| 4 | SO as user, logout on close, missing login checks (H1-03..H1-10, H3-06, A2-03, A2-05) | Partially fixed: role separation and logout fixed (state); Wrap/SetOperationState/Destroy/Copy/key-creation checks pending wave-2 (abi) |
| 5 | No persistence (H3-04, H4-02, H4-03, H5-02, A1-17) | Fixed in the core (state); daemon/CLI switch to `HsmCore::open` pending wave-2 (core) |
| 6 | AES-GCM params and nonce state (H2-01, H2-02, A1-15, A2-09) | Params fixed (crypto); counter persistence pending wave-2 (core) |
| 7 | Marvin / suppressed advisory (H2-03, A1-26, A3-05) | Partially fixed: blinding, honest time-boxed exception, AWS-LC in `fips` builds; no upstream fix |
| 8 | No slot isolation (H1-13, H3-03, A2-15) | Fixed (state) |
| 9 | Committed credentials / public endpoint (A3-01, H4-05) | Removed from the tree; rotation, endpoint shutdown and history scrub are owner actions |
| 10 | Daemon key-generation templates (H4-06, A3-02) | Fixed (daemon) |
| 11 | pkcs11-spy bypass / setuid env (H6-01, H6-02) | Fixed (spy) |
| 12 | `C_GenerateRandom` bypasses DRBG (A1-01, A1-02, A2-16) | Fixed (crypto); ESV is an owner action |
| 13 | `fips` feature on RustCrypto, round-trip POST, optional integrity (A1-03..05, H2-05, H2-08, A3-04) | CASTs and fail-closed integrity fixed; `fips_defaults()` → `awslc` pending wave-2 (core) |
| 14 | 112 safe `extern "C"` fns deref raw pointers (H1-22, A2-26, A3-14) | Lint gate restored (ci); `unsafe extern "C"` pending wave-2 (abi) |
| 15 | Unkeyed audit chain, fail-open, verify-chain (H3-10, H3-11, H5-03) | Core fixed (keyed chain + anchor, fail-closed); ABI error propagation (abi) and CLI verifier switch to `AuditLog::verify_file` (core) pending |

## Findings

### H1 — PKCS#11 ABI layer ([report](H1-pkcs11-abi-security.md))

| ID | Severity | Finding | Status | Fixed by (commit / area) | Notes |
|---|---|---|---|---|---|
| H1-01 | Critical | C_InitToken destroys all objects before it verifies the SO PIN | **Fixed** | state `e751482` `6ed0a17` `61f8076` | `HsmCore::init_token`: SessionExists, SO PIN verified under lockout, then only that slot is wiped |
| H1-02 | High | CKA_SENSITIVE bypass: sensitive but extractable keys are readable in plaintext | **Fixed** | state `e751482` `6ed0a17` `61f8076` | `CKA_VALUE`/private components never returned for sensitive or non-extractable keys |
| H1-03 | High | C_WrapKey does not authorize the key being wrapped | **Fixed (wave 2)** | — | C_WrapKey must check the wrapped key's private/login status and `KeyUsage::Wrap` (state.md) |
| H1-04 | High | C_SetOperationState re-binds a saved operation to any key, with no authorization re-check | **Fixed (wave 2)** | state (slot-scoped lookup) | C_SetOperationState must re-check authorization/usage of the restored key |
| H1-05 | High | SO sessions count as "logged in" for access to private (USER) objects | **Fixed** | state `e751482` `6ed0a17` `61f8076` | only `CKU_USER` sessions are "logged in" for key use / private objects |
| H1-06 | High | Closing all sessions does not log out the token; later sessions inherit the login | **Fixed** | state `e751482` `6ed0a17` `61f8076` | closing the last session logs the token out (`hsm.close_session` / `close_all_sessions`) |
| H1-07 | High | C_DestroyObject destroys private objects without login | **Fixed (wave 2)** | state (store: `CKR_ACTION_PROHIBITED` for non-destroyable) | C_DestroyObject must require user login for `CKA_PRIVATE` objects |
| H1-08 | High | C_CopyObject lets the copy escape the source object's policy | **Fixed (wave 2)** | state (provenance attrs rejected on copy) | C_CopyObject copy rules for PRIVATE/TOKEN/MODIFIABLE/usage flags |
| H1-09 | High | CKA_TRUSTED and the provenance attributes can be set by any creator, so CKA_WRAP_WITH_TRUSTED has no effect | **Fixed** | state `e751482` `6ed0a17` `61f8076` | `CKA_TRUSTED`/provenance attributes not self-assertable (`ObjectOrigin`) |
| H1-10 | High | Key-creating functions do not require login | **Fixed (wave 2)** | — | login requirement + template validation for key-creating functions |
| H1-11 | Medium | C_DeriveKey uses the base key without login, lifecycle or key-type checks, and misreads the mechanism param… | **Fixed (wave 2)** | crypto (`CK_ECDH1_DERIVE_PARAMS` parsed) | C_DeriveKey login/lifecycle/key-type checks |
| H1-12 | Medium | C_DigestKey has no login check, and the digested key bytes are exported in plaintext by C_GetOperationState | **Fixed (wave 2)** | — | C_DigestKey login check; digested key bytes in saved operation state |
| H1-13 | Medium | No slot isolation for objects: one global ObjectStore, and object handles are accepted from any slot | **Fixed** | state `e751482` `6ed0a17` `61f8076` | per-slot object lookup (`get_object_in_slot`, slot-scoped find) |
| H1-14 | Medium | Key-creation templates silently drop restrictive attributes | **Fixed (wave 2)** | — | reject/validate unknown template attributes (`apply_attribute_ctx` semantics) |
| H1-15 | Medium | No check that key class or type matches the mechanism in the *Init functions (cross-algorithm key use) | **Fixed (wave 2)** | — | key-type/mechanism consistency at `*Init` (`CKR_KEY_TYPE_INCONSISTENT`) — same as A1-30 |
| H1-16 | Medium | Mechanism parameters are ignored or misread (GCM, CBC and OAEP semantics) | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | typed GCM/CBC/OAEP/CTR/ECDH params honoured; generic `extract_mechanism_param` still returns empty for oversized params (abi) |
| H1-17 | Medium | Restored hash-then-sign and hash-then-verify operations lose their state, so the wrong message is signed or… | **Fixed (wave 2)** | — | hash-then-sign state lost on C_SetOperationState (= A2-06) |
| H1-18 | Medium | Session objects outlive their sessions | **Fixed** | state `e751482` `6ed0a17` `61f8076` | session objects destroyed on close |
| H1-19 | Medium | C_Login ignores failure of the per-session login update; token and session login states diverge | **Fixed** | state `e751482` `6ed0a17` `61f8076` | `HsmCore::login` is atomic and rolled back on failure |
| H1-20 | Medium | SP 800-57 lifecycle state is enforced only in Encrypt/Decrypt/Sign/VerifyInit | **Fixed (wave 2)** | state (`check_lifecycle` fails closed) | lifecycle/usage checks in C_WrapKey/UnwrapKey/DeriveKey/CopyObject |
| H1-21 | Medium | Plaintext key material is copied into heap buffers that are never zeroized | **Fixed (wave 2)** | — | `Zeroizing` for key copies in C_WrapKey/C_DeriveKey |
| H1-22 | Medium | Unsound public API: 112 safe `pub extern "C" fn` items dereference raw pointers, and CI suppresses the lint | **Fixed (wave 2)** | ci (lint no longer suppressed) | make exports `unsafe extern "C"`; callers in tests/fuzz need `unsafe {}` |
| H1-23 | Low | Slices are built from caller lengths before bounds checks, and inconsistently | **Fixed (wave 2)** | — | bounds checks before slice construction |
| H1-24 | Low | Fork handling: a child process cannot reinitialize, and a child's C_Finalize writes to the parent's audit log | **Fixed (wave 2)** | — | fork handling / child C_Finalize audit write |
| H1-25 | Low | C_Initialize ignores CK_C_INITIALIZE_ARGS; C_Finalize leaves the core alive in other threads' caches | **Fixed (wave 2)** | — | validate `CK_C_INITIALIZE_ARGS`; drop finalized core from thread-local caches |
| H1-26 | Low | Deviations from the two-call and CKR_BUFFER_TOO_SMALL rules | **Fixed (wave 2)** | — | two-call / `CKR_BUFFER_TOO_SMALL` rules |
| H1-27 | Low | C_SetAttributeValue is non-atomic, not persisted, and stricter than the specification | **Partially fixed** | state `e751482` `6ed0a17` `61f8076` | SetAttributeValue persisted; atomicity/spec strictness pending abi |
| H1-28 | Low | C_CreateObject: weak attribute typing, and login rules only partly applied | **Fixed (wave 2)** | — | C_CreateObject attribute typing and login rules |
| H1-29 | Low | Handle allocators wrap around, and colliding inserts replace live sessions or objects | **Fixed** | state `e751482` `6ed0a17` `61f8076` | CSPRNG handles checked against live tables; occupied entries never replaced (H3-19) |
| H1-30 | Low | PIN handling edge cases: C_SetPIN in R/O sessions, NULL PIN treated as empty, PBKDF2 run under the slot-wid… | **Partially fixed** | state `e751482` `6ed0a17` `61f8076` | PBKDF2 outside the auth lock (H3-09); R/O C_SetPIN and NULL-PIN handling pending abi |
| H1-31 | Low | Key-pair generation: an unknown EC curve silently becomes P-256, RSA size is truncated, and inserts are not… | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | unknown curves rejected (`CKR_CURVE_NOT_SUPPORTED`); absent CKA_EC_PARAMS default, RSA size truncation, atomic inserts pending abi |
| H1-32 | Low | Memory used by multi-part operations is bounded per session, not in total | **Open — not completed in wave 2** | — | global bound for multi-part operation memory |
| H1-33 | Low | Windows audit-file ACL: unaligned casts and a DACL applied only after the file is created | **Open — not completed in wave 2** | — | `src/platform_acl.rs` Windows DACL at creation |
| H1-34 | Informational | Token objects are never persisted through the PKCS#11 ABI | **Fixed** | state `e751482` `6ed0a17` `61f8076` | token objects persisted through the ABI when `persist_objects = true` |
| H1-35 | Informational | Specification and interoperability deviations | **Fixed (wave 2)** | — | remaining specification/interoperability deviations |
| H1-36 | Low | Inconsistent session/object lock order can deadlock two threads that share a session | **Fixed (wave 2)** | — | session/object lock order |

### H2 — Cryptography ([report](H2-crypto-security.md))

| ID | Severity | Finding | Status | Fixed by (commit / area) | Notes |
|---|---|---|---|---|---|
| H2-01 | High | AES-GCM ignores `CK_GCM_PARAMS`: AAD is never authenticated, and the caller's IV and tag length are dropped | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | `CK_GCM_PARAMS` IV/AAD/tag length honoured; module IV in approved mode |
| H2-02 | High | AES-GCM nonce uniqueness is process-local and can be reset by an attacker, giving deterministic nonce reuse | **Fixed (wave 2)** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` (random 96-bit module IVs, (key,IV) repeat rejection) | persist GCM invocation counts per key across restarts |
| H2-03 | High | RSA private-key operations are unblinded and variable-time (Marvin / RUSTSEC-2023-0071) | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f`; rel `d4b891a` | blinding on every RustCrypto RSA private op; no v1.5 decryption; AWS-LC in fips builds. Bignum not constant time — no fixed `rsa` release (see Not fixable) |
| H2-04 | Medium | Backend parity: the aws-lc backend skips every hardening control and computes different results | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | AWS-LC backend parity (typed params, raw ECDH Z, zeroized buffers) |
| H2-05 | Medium | The `fips` feature does not select a validated module, and POST exercises only RustCrypto | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | `fips` implies `awslc-backend`, POST refuses non-validated backend; `fips_defaults()` must select `awslc` (core) — until then `--features fips` with default features stays in the error state (CI `features` job gate) |
| H2-06 | Medium | The ECDH HKDF `info` string is asymmetric, so two honest parties never derive the same key; KDF parameters… | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | symmetric SP 800-56C KDFs, KDF params honoured |
| H2-07 | Medium | The ECDSA mechanism's hash is ignored: `CKM_ECDSA` double-hashes, and SHA-384/512 variants fall back to the… | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | mechanism hash honoured, raw `r‖s` |
| H2-08 | Medium | Many self-tests are roundtrip tests rather than KATs; algorithm, DRBG and entropy coverage is missing | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | fixed-vector CASTs for all approved algorithms through the active backend |
| H2-09 | Medium | Key-material hygiene: `zeroize` features are off in the crypto dependencies, and decrypted or unwrapped sec… | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | zeroize features enabled, decrypt APIs return `Zeroizing`; `hmac` 0.12 internal state not zeroizable |
| H2-10 | Medium | The RSA parsed-key cache is never cleared and outlives `C_DestroyObject`; its "zeroizing" `Drop` is dead code | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f`; state | RSA cache evicted on destroy, cleared on C_Finalize/C_InitToken |
| H2-11 | Medium | CBC/CTR IV-reuse detection is easy to bypass, and its global cap is a cross-tenant DoS | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | CTR range tracking, LRU tracker (no global cap DoS); caller IVs tracked per process only |
| H2-12 | Low | GCM state maps grow without bound, and a DashMap shard lock is held for the entire encryption | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | bounded GCM state, lock released before encryption |
| H2-13 | Low | `CKM_AES_CBC` is implemented as CBC-PAD; a padding oracle remains through the return code; the 10 ms sleep… | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | unpadded `CKM_AES_CBC`, sleep removed |
| H2-14 | Low | `CKM_AES_KEY_WRAP_KWP` is advertised but implemented as RFC 3394 KW; unwrap uses a non-constant-time integr… | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | real RFC 5649 KWP, constant-time unwrap check |
| H2-15 | Low | DRBG health testing checks the wrong thing and does not latch; some randomness bypasses the DRBG | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | SP 800-90A DRBG with RCT/APT, latched failures |
| H2-16 | Low | Signature verification is not strict (Ed25519 small-order keys, ECDSA high-S); the placeholder integrity ke… | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | strict Ed25519 / low-S ECDSA; placeholder key refused in fips builds |
| H2-17 | Low | The integrity self-test fails open | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | integrity test fails closed in fips builds; TOCTOU documented |
| H2-18 | Low | `mlock` is page-granular but applied per buffer; `munlock` on drop unlocks other live keys, and failures ar… | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | refcounted per-page mlock; surfacing `mlock_failure_count()` as status is open (core) |
| H2-19 | Low | Hybrid ML-DSA+ECDSA signing takes the "ECDSA private key" from the public `CKA_EC_POINT`, and the scheme ha… | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | hybrid ML-DSA+ECDSA removed |
| H2-20 | Low | PQC API use: deterministic ML-DSA with no context; pre-release crates; secret outputs not zeroized | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | hedged ML-DSA/SLH-DSA, exact pins, zeroized outputs; context-string plumbing pending abi; pre-release crates remain (documented risk) |
| H2-21 | Informational | FIPS policy inaccuracies and ignored PSS/OAEP parameters | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f`; docs | policy table corrected; generic `CKM_RSA_PKCS_PSS` params pending abi |
| H2-22 | Informational | Non-standard mechanism-parameter encodings cause silent interoperability failures | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | standard parameter structures parsed by exact size |

### H3 — Store / session / token / audit / config ([report](H3-store-session-token-audit-security.md))

| ID | Severity | Finding | Status | Fixed by (commit / area) | Notes |
|---|---|---|---|---|---|
| H3-01 | Critical | C_InitToken destroys all objects (all slots) and closes all sessions *before* SO-PIN verification | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-02 | High | Sensitive key material readable through C_GetAttributeValue | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-03 | High | No slot isolation of objects on the C ABI path | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-04 | High | Token and objects are never persisted: restart re-opens token ownership; `persist_objects`, lockout persist… | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-05 | Medium | Security-relevant attributes are self-assertable; `CKA_COPYABLE=FALSE` is silently ignored | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-06 | Medium | SO sessions are treated as "logged in" for user objects (role separation broken) | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-07 | Medium | Session objects outlive their session; global object cap enables unauthenticated DoS | **Partially fixed** | state `e751482` `6ed0a17` `61f8076` | session objects bound to and destroyed with their session; `MAX_OBJECTS` is still a global cap across slots (daemon adds a per-client quota) |
| H3-08 | Medium | Race between `open_session` and `C_Logout` leaves a session authenticated after logout | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-09 | Medium | Token-wide DoS: PBKDF2 runs under the global `auth` mutex; locked accounts are unthrottled | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-10 | Medium | Audit "tamper-evidence" uses an unkeyed hash chain with no anchor | **Fixed** | state `e751482` `6ed0a17` `61f8076` | keyed HMAC chain + MAC-protected anchor |
| H3-11 | Medium | Audit subsystem fails open; rotation guarantees a false tamper and silent loss of auditing on restart | **Partially fixed** | state `e751482` `6ed0a17` `61f8076` | core audit fail-closed/bounded/rotation fixed; ABI must propagate `record` errors when `audit.fail_closed` (abi) |
| H3-12 | Medium | Unsafe filesystem handling: symlink-following predictable paths, create-then-chmod, CWD-relative storage | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-13 | Medium | Config can be planted from CWD or an environment variable; ownership not checked; security fields silently… | **Fixed** | state `e751482` `6ed0a17` `61f8076` | no CWD config, ownership/permission checks; `deny_unknown_fields` on core sections pending core (H4-17) |
| H3-14 | Medium | Re-initialization semantics: C_InitToken SO-PIN guessing never locks out; `Token::init_token` does not own… | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-15 | Medium, latent | Encrypted store design: no AAD, no rollback/deletion detection, PIN-bound key with no re-key or salt storage | **Partially fixed** | state `e751482` `6ed0a17` `61f8076` | AAD, manifest, re-key, salt storage done; whole-file rollback needs an external monotonic counter (not fixable in code) |
| H3-16 | Medium | Backup/restore: header not authenticated, KDF parameters not recorded, restored objects trusted as-is, repl… | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-17 | Low | Lockout store: unauthenticated, shared by all slots, save errors swallowed | **Partially fixed** | state `e751482` `6ed0a17` `61f8076` | per-slot counters persisted and save errors surfaced; counters cannot be authenticated before login (not fixable without a device secret) |
| H3-18 | Low | PBKDF2 salt can silently be all-zero | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-19 | Low | Handle generation: non-cryptographic permutation; handles act as bearer capabilities in the daemon; wrap-ar… | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-20 | Low | Zeroization gaps for key material and PIN-derived secrets | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-21 | Low | Session accounting races and C_InitToken session semantics | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-22 | Low | Unbounded audit channel and O(n) in-memory trimming | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-23 | Low | Lifecycle enforcement incomplete and stringly-typed | **Partially fixed** | state `e751482` `6ed0a17` `61f8076` | `check_lifecycle` fails closed; ABI call sites pending (H1-20) |
| H3-24 | Low | `C_CreateObject` template semantics and duplicate attributes | **Partially fixed** | state `e751482` `6ed0a17` `61f8076` | store-level template checks; ABI attribute typing (H1-28) pending abi |
| H3-25 | Low | `C_SetAttributeValue` / `destroy_object` persistence errors silently ignored (resurrection) | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-26 | Informational | In-memory `verify_chain` false positives; timestamp floor reset | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-27 | Informational | Inconsistent security defaults and constants | **Fixed** | state `e751482` `6ed0a17` `61f8076` | `src/config/defaults.rs` single source |
| H3-28 | Informational | Search templates on boolean attributes never match | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| H3-29 | Informational | Windows ACL helper and permission fallbacks fail open | **Fixed** | state `e751482` `6ed0a17` `61f8076` | Windows ACL helpers fail closed |

### H4 — gRPC daemon and deployment ([report](H4-daemon-security.md))

| ID | Severity | Finding | Status | Fixed by (commit / area) | Notes |
|---|---|---|---|---|---|
| H4-01 | Critical | Login state is token-global and not bound to any client; SO and User are not separated | **Fixed** | daemon `61612af` |  |
| H4-02 | High | Unauthenticated `InitToken` on a token that is uninitialised at every start: the first caller becomes SO | **Fixed** | daemon `61612af` |  |
| H4-03 | High | Key material and token state are never persisted by the daemon, despite chart persistence settings | **Fixed (wave 2)** | daemon `61612af` (refuses CKA_TOKEN while ephemeral) | daemon `open_core` → persistent `HsmCore::open`; note `try_new` already opens the persistent store since the state merge — verify end to end |
| H4-04 | High | TLS handshake runs inside the accept loop with no timeout; no connection cap, idle timeout or keepalive | **Fixed** | daemon `61612af` |  |
| H4-05 | High | Committed PINs, a public plaintext test endpoint and disabled certificate validation in client artefacts | **Partially fixed** | kreya `513515f` | credentials/endpoint removed from the tree, TLS validation re-enabled; PIN rotation, endpoint shutdown and history scrub are owner actions |
| H4-06 | High | Caller templates can override security-critical key attributes (key injection, type confusion, forged prove… | **Fixed** | daemon `61612af` |  |
| H4-07 | High | Memory amplification: unbounded `attribute_types` and large in-flight messages can OOM the pod | **Fixed** | daemon `61612af` |  |
| H4-08 | Medium | Mechanism not bound to key type; FIPS and algorithm-policy bypass; Digest skips policy and audit | **Fixed** | daemon `61612af` |  |
| H4-09 | Medium | Daemon `InitToken` does not close sessions, destroy objects or reset counters (key remanence, session-limit… | **Fixed** | daemon `61612af` |  |
| H4-10 | Medium | Pre-auth session exhaustion; session handles are unbound bearer tokens and are never reaped | **Fixed** | daemon `61612af` |  |
| H4-11 | Medium | Login throttling and lockout: shared per slot, counts non-PIN errors, racy, and allows anonymous persistent… | **Partially fixed** | daemon `61612af` | per-client throttling; time-based lockout / admin unlock path is a core design item |
| H4-12 | Medium | CPU-bound crypto and PBKDF2 run on async worker threads, some while holding the token mutex; timeouts canno… | **Fixed** | daemon `61612af` |  |
| H4-13 | Medium | Health checks cannot pass: no health service, and probes speak plaintext to a TLS-only port | **Fixed** | deploy `7e83360` | tonic-health on `health_bind`, probes fixed |
| H4-14 | Medium | Helm security settings are silently ignored (security.toml, CRL, lockout policy) | **Fixed** | deploy `7e83360` | security settings rendered into the single config |
| H4-15 | Medium | Object lifecycle and resource leaks: session objects outlive sessions; global object cap; DestroyObject ski… | **Fixed** | daemon `61612af` |  |
| H4-16 | Medium | SIGTERM is not handled (and is ignored as PID 1); the audit queue is fire-and-forget, unbounded, and lost o… | **Fixed** | daemon `61612af`; state (bounded audit queue) | SIGTERM drain + audit flush |
| H4-17 | Medium | mTLS is optional by default in the daemon, and misspelled config keys are silently ignored | **Partially fixed** | daemon `61612af` | `[daemon]` and top-level keys strict, mTLS mandatory; `deny_unknown_fields` inside core sections pending core |
| H4-18 | Low | CRL handling: loaded once, expiry not enforced, single DER file, documentation claims PEM | **Fixed** | daemon `61612af` |  |
| H4-19 | Low | PIN zeroization is incomplete | **Partially fixed** | daemon `61612af` `00cf3df` | PIN buffers zeroized; transport buffers cannot be scrubbed (documented) |
| H4-20 | Low | Numeric truncation and missing validation of configuration values | **Fixed** | daemon `61612af` |  |
| H4-21 | Low | EC key generation silently falls back to P-256 and stores the caller's (mismatching) `CKA_EC_PARAMS` | **Fixed** | daemon `61612af` |  |
| H4-22 | Low | No read-only session enforcement for object-mutating RPCs | **Fixed** | daemon `61612af` |  |
| H4-23 | Low | Dockerfile: build is broken as committed; supply-chain and hygiene gaps | **Fixed** | deploy `7e83360`; rel `bc36c8f` (CI container build) |  |
| H4-24 | Low | Helm deployment hygiene: RWO volume with RollingUpdate, mutable image tag, broad optional egress, label-bas… | **Fixed** | deploy `7e83360` |  |
| H4-25 | Low | GetTokenInfo discloses token-global login state to any session holder | **Fixed** | daemon `61612af` |  |
| H4-26 | Informational | Audit coverage gaps | **Partially fixed** | daemon `61612af` | daemon audits all RPCs; `AuditOperation::InitPin` / client-identity field pending core |
| H4-27 | Informational | Logging configuration | **Fixed** | daemon `61612af` |  |
| H4-28 | Informational | Documentation, proto comments and dead code are inconsistent with the implementation | **Fixed** | daemon `61612af`; rel docs |  |

### H5 — Admin CLI and tooling scripts ([report](H5-admin-cli-security.md))

| ID | Severity | Finding | Status | Fixed by (commit / area) | Notes |
|---|---|---|---|---|---|
| H5-01 | High | `token init` resets persisted lockout state without authentication or confirmation | **Fixed** | admin `20c5c9e` |  |
| H5-02 | High | The CLI runs on a throwaway in-memory core: backups are empty and changes do not persist, yet it reports su… | **Fixed (wave 2)** | admin `20c5c9e` (fail-closed standalone mode, exit 5) | `admin_core::open_core` → persistent `HsmCore::open`; re-enable commands and update CLI tests |
| H5-03 | High | `audit verify-chain` reports VALID for a tampered audit log; exports are always empty | **Fixed (wave 2)** | admin `20c5c9e` | CLI verifier mirrors the old **unkeyed** SHA-256 chain; the core log is now a keyed HMAC chain → switch to `AuditLog::verify_file(log, key)` |
| H5-04 | High | `restore` consumes the backup ID before the objects are stored durably | **Fixed** | admin `20c5c9e` |  |
| H5-05 | Medium | Backup, restore and audit export perform no authentication | **Fixed** | admin `20c5c9e` |  |
| H5-06 | Medium | Replay-guard file location, symlink handling and locking | **Partially fixed** | admin `20c5c9e` | CLI replay guard hardened; library `PersistentReplayGuard` hardening/authentication pending core |
| H5-07 | Medium | `compute-integrity-hmac.sh` puts the HMAC key in the process argument list; the tool is obsolete | **Fixed** | admin `d35e40e` | HMAC scripts deleted; rotating any key used with them is an owner action |
| H5-08 | Medium | Release-signing private key is stored unencrypted; the PowerShell variant sets no ACL | **Fixed** | admin `bd7f71a` |  |
| H5-09 | Medium | No tracing subscriber: the library's security warnings are discarded | **Fixed** | admin `20c5c9e` |  |
| H5-10 | Medium | Windows backup path: fails open on ACL errors, uses a predictable temp file, and overwrites existing files | **Fixed** | admin `20c5c9e` |  |
| H5-11 | Medium | Config is found relative to the working directory, missing configs silently fall back to defaults, and "str… | **Fixed** | admin `20c5c9e` |  |
| H5-12 | Low | The PIN complexity policy is weak | **Partially fixed** | admin `20c5c9e` | CLI policy strengthened; core `validate_pin` still weaker (core) |
| H5-13 | Low | `key import` is effectively a placeholder and does not validate input | **Fixed** | admin `20c5c9e` |  |
| H5-14 | Low | Role model not enforced for key operations, and object handles are truncated on Windows | **Fixed** | admin `20c5c9e` |  |
| H5-15 | Low | Labels are printed without neutralising control characters, and label handling is inconsistent | **Fixed** | admin `20c5c9e` |  |
| H5-16 | Low | Unbounded reads of user-supplied files, plus a redundant existence check | **Fixed** | admin `20c5c9e` |  |
| H5-17 | Low | Panic paths reachable from environment or data | **Fixed** | admin `20c5c9e` |  |
| H5-18 | Low | Local CI scripts overstate results and diverge from CI | **Fixed** | admin `d35e40e` |  |
| H5-19 | Low | `sign-integrity.sh` uses a predictable sibling temp file and hides signing errors | **Fixed** | admin `bd7f71a` |  |
| H5-20 | Low | Administrative operations are not recorded in the audit log | **Partially fixed** | admin `20c5c9e` | admin actions audited via existing variants; dedicated `AuditOperation` variants pending core |
| H5-21 | Informational | Documentation shows PINs as command-line arguments and subcommands that do not exist | **Fixed** | admin `9512df2`; docs (ci wave-1 `a91bbc8` `4e8d19b` `52c077f` …; rel wave-2 `53b37e1` `9399de7` `a0b396f` `2c4e877`) |  |
| H5-22 | Informational | Integrity tooling has drifted from the library | **Fixed** | admin `bd7f71a`; docs |  |
| H5-23 | Informational | `.gitignore` does not exclude key material or CLI state files | **Fixed** | ci `0c9b821`; rel `08877de` |  |
| H5-24 | Informational | Copies of secrets remain in memory outside `Zeroizing` | **Partially fixed** | admin `20c5c9e` | core dumps disabled, `PR_SET_DUMPABLE=0`; `rpassword` intermediate buffers not wiped |

### H6 — pkcs11-spy ([report](H6-pkcs11-spy-security.md))

| ID | Severity | Finding | Status | Fixed by (commit / area) | Notes |
|---|---|---|---|---|---|
| H6-01 | High | `C_GetFunctionList` returns the real module's function table, so the spy is bypassed for nearly all clients | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-02 | Medium | Environment-driven configuration is trusted in secure-execution (setuid/setgid/capability) contexts | **Partially fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` | `PKCS11_SPY_*` ignored in secure-execution mode; not configuring the spy for privileged processes is operational |
| H6-03 | Medium | Log file creation follows symlinks, accepts existing or foreign files and non-regular files, and sets permi… | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-04 | Medium | Configuration errors `panic!` inside `extern "C"` functions and abort the host process (UB on older toolcha… | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-05 | Medium | The PKCS#11 v3.0 interface is not implemented or forwarded | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-06 | Low | Target library selection: relative paths, no owner/permission checks, heuristic extension test, overstated… | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-07 | Low | Windows log ACL hardening spawns `whoami`/`icacls` by name from inside the host process and ignores failures | **Partially fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` | System32 absolute paths, fail closed; short ACL window on Windows remains (needs `windows-sys` DACL at creation) |
| H6-08 | Low | The documented relative log path silently falls back to stderr; the default sink is stderr | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-09 | Low | "Reduced timing" mode leaves microsecond timestamps in place; full precision is the default | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-10 | Low | Logger lock held across blocking, non-atomic multi-syscall writes (stall, interleaving, fork) | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-11 | Low | Loading via `/proc/self/fd/N` breaks `$ORIGIN` dependency resolution and self-location in target modules | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-12 | Low | Self-targeting and re-entrant initialization can recurse without bound or deadlock | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-13 | Informational | `ckr_name` is incomplete; unmapped codes are logged as `CKR_UNKNOWN` | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-14 | Informational | `spy_fn_checked!` changes module behaviour and uses magic numbers | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-15 | Informational | Caller buffers are never dereferenced (sound today); rules for adding output-side logging | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-16 | Informational | Data-minimisation assessment and recommended redaction policy | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0` |  |
| H6-17 | Informational | Documentation drift, no tests, undeclared MSRV | **Fixed** | spy `eabf192` `69894c0` `84415d1` `d889f3b` `93d90a0`; rel `bc36c8f` (CI builds the cdylib before spy tests) |  |

### A1 — FIPS 140-3 readiness ([report](A1-fips-140-3-readiness.md))

| ID | Severity | Finding | Status | Fixed by (commit / area) | Notes |
|---|---|---|---|---|---|
| A1-01 | Blocker | `C_GenerateRandom` bypasses the SP 800-90A DRBG and returns raw OS RNG output | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | `C_GenerateRandom` served by the module DRBG / AWS-LC DRBG |
| A1-02 | Blocker | No compliant entropy source (ESV) and no SP 800-90A health testing/CAST for the HMAC_DRBG | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | RCT/APT, start-up test, DRBG KAT; ESV certificate is an owner action |
| A1-03 | Blocker | Approved services run on non-validated implementations, even when the "FIPS" configuration is used | **Fixed (wave 2)** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | fips builds refuse non-validated backends; `fips_defaults()` → `awslc` and remaining RustCrypto-only services (core) |
| A1-04 | Blocker | Pre-operational and conditional self-tests don't meet IG 10.3.A/10.3.B and don't test the implementations i… | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` |  |
| A1-05 | Blocker | Software integrity test is optional, bypassable, uses an unvalidated algorithm, and is documented as a diff… | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f`; ci `315a716`; rel `869b94a` | fails closed, release signs `.sig`, CI tests the fail-closed path; Ed25519 runs on unvalidated `ed25519-dalek` |
| A1-06 | Blocker | Cryptographic boundary, module identity and versioning are inconsistent; the in-boundary crypto is reachabl… | **Partially fixed** | docs (ci wave-1 `a91bbc8` `4e8d19b` `52c077f` …; rel wave-2 `53b37e1` `9399de7` `a0b396f` `2c4e877`) | one boundary definition; `C_GetInfo.libraryVersion` still 0.1 (abi); rlib API not POST-gated |
| A1-07 | Major | `C_InitToken` destroys all objects (all slots) and closes sessions *before* verifying the SO PIN | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| A1-08 | Major | Plaintext export of keys that are both sensitive and extractable; the documented export rule differs | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| A1-09 | Major | Error-state semantics differ from the documentation; failure handling is inconsistent | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | latched error state; residual abort in infallible RNG adapter = A3-19 |
| A1-10 | Major | SSP zeroization gaps: module shutdown, key destroy, cached RSA keys and transient copies | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f`; state `e751482` `6ed0a17` `61f8076` | RSA cache + keys/PINs/storage keys zeroized at finalize; `get_hsm()` cache and plain `Vec` key copies in ABI pending abi |
| A1-11 | Major | Approved service indicator (IG 2.4.C) is inadequate and inaccurate | **Open (unassigned)** | docs | no API-visible approved-service indicator; unused `last_operation_fips_approved` should be implemented or removed |
| A1-12 | Major | Roles/services mapping in the SP does not match code; several services lack authorization checks | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| A1-13 | Major | ECDSA hash/mechanism binding is wrong in single-part operations; signature format is not PKCS#11 | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` |  |
| A1-14 | Major | ECDH key derivation does not follow SP 800-56A r3/56C r2; the two backends derive different keys; RustCrypt… | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` |  |
| A1-15 | Major | AES-GCM IV generation doesn't clearly satisfy IG C.H; GCM parameters ignored; documented key sizes unsupported | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | module IVs in approved mode; counter persistence (core) and `CKR_STATE_UNSAVEABLE` for GCM encrypt state (abi) pending |
| A1-16 | Minor | Mechanism semantics diverge from PKCS#11 and from the approved-algorithm table | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | generic `CKM_RSA_PKCS_PSS` params pending abi |
| A1-17 | Major | Persistent storage and storage-key claims are not implemented; backup design conflicts with SSP policy | **Fixed** | state `e751482` `6ed0a17` `61f8076` | whole-file rollback detection not fixable in code |
| A1-18 | Major | SSP/CSP table is incomplete and partly wrong | **Fixed** | docs (ci wave-1 `a91bbc8` `4e8d19b` `52c077f` …; rel wave-2 `53b37e1` `9399de7` `a0b396f` `2c4e877`) |  |
| A1-19 | Major | Operational environment not specified for validation | **Partially fixed** | ci `76a96ed` | tested OEs pinned; ACVP per OE is an owner action |
| A1-20 | Major | Life-cycle assurance: no FIPS build/delivery pipeline, CI gaps, guidance inconsistent with code | **Fixed** | ci `f52efe5` `0ee4b0a` `d150fc0` `6561b78` `315a716` `c6dd2e0`; rel `bc36c8f` `869b94a` |  |
| A1-21 | Minor | Approved-algorithm status statements are out of date; transition dates not addressed | **Fixed** | docs (ci wave-1 `a91bbc8` `4e8d19b` `52c077f` …; rel wave-2 `53b37e1` `9399de7` `a0b396f` `2c4e877`) |  |
| A1-22 | Minor | `C_GetOperationState`/`C_SetOperationState` are implemented but documented as unsupported; they are an undo… | **Fixed** | docs (ci wave-1 `a91bbc8` `4e8d19b` `52c077f` …; rel wave-2 `53b37e1` `9399de7` `a0b396f` `2c4e877`) |  |
| A1-23 | Minor | PIN policy, default-PIN and lockout documentation don't match code; `C_InitToken` offers unlimited SO PIN g… | **Fixed** | state `e751482` `6ed0a17` `61f8076`; docs |  |
| A1-24 | Major | Approved-mode activation is advisory and has no status output | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f`; docs | fips build is non-overridable; mode/status output via `C_GetInfo` open (abi) |
| A1-25 | Minor | EC domain parameters not validated; unknown curves are processed as P-256 | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | unknown curves rejected; absent `CKA_EC_PARAMS` default and CreateObject/UnwrapKey validation pending abi |
| A1-26 | Major | "Mitigation of other attacks" claims are inaccurate: known RSA timing advisory suppressed | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f`; rel `d4b891a`; docs | blinding applied, claims corrected; not constant time |
| A1-27 | Observation | Physical and non-invasive security "N/A" claims | **Documented** | docs (ci wave-1 `a91bbc8` `4e8d19b` `52c077f` …; rel wave-2 `53b37e1` `9399de7` `a0b396f` `2c4e877`) |  |
| A1-28 | Observation | Integrity check reads the file on disk (TOCTOU) and depends on `dli_fname` | **Documented** | docs (ci wave-1 `a91bbc8` `4e8d19b` `52c077f` …; rel wave-2 `53b37e1` `9399de7` `a0b396f` `2c4e877`) | accepted at Level 1 |
| A1-29 | Observation | Level 1 PCT/POST performance and DoS considerations | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | fixed-key CASTs |
| A1-30 | Minor | Services use keys without key-type/mechanism consistency checks | **Fixed (wave 2)** | — | = H1-15 |
| A1-31 | Minor | Audit log "algorithm indicator" and tamper-evidence are not security functions in the FIPS sense | **Fixed** | state `e751482` `6ed0a17` `61f8076`; docs | keyed chain; still not a FIPS security function |
| A1-32 | Minor | Documentation references stale file/line citations throughout | **Fixed** | docs (ci wave-1 `a91bbc8` `4e8d19b` `52c077f` …; rel wave-2 `53b37e1` `9399de7` `a0b396f` `2c4e877`) |  |

### A2 — PKCS#11 conformance and test assurance ([report](A2-pkcs11-conformance-and-test-assurance.md))

| ID | Severity | Finding | Status | Fixed by (commit / area) | Notes |
|---|---|---|---|---|---|
| A2-01 | Critical | PKCS#11 v3.0 conformance claim is unsupported: no v3.0 interface, but the version fields report 3.0 | **Fixed (wave 2)** | docs | v3.0 interface functions (`C_GetInterfaceList`/`C_GetInterface`), `CK_FUNCTION_LIST.version` 2.40, library version |
| A2-02 | Critical | C_InitToken destroys all objects and closes all sessions before verifying the SO PIN, and does not return C… | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| A2-03 | High | The Security Officer role is treated as a logged-in user for access to private objects and cryptographic op… | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| A2-04 | High | C_GetAttributeValue returns CKA_VALUE for keys with CKA_SENSITIVE=TRUE when CKA_EXTRACTABLE=TRUE | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| A2-05 | High | C_SetOperationState binds a restored sign/verify operation to a caller-chosen key without authorization checks | **Fixed (wave 2)** | — | = H1-04 |
| A2-06 | Medium | Saved operation state loses the input for hash-then-sign/verify mechanisms, so restored operations sign a d… | **Fixed (wave 2)** | — | = H1-17 |
| A2-07 | High | ECDSA signatures are DER-encoded instead of the PKCS#11 raw r\|\|s format | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` |  |
| A2-08 | Medium | The ECDSA mechanism hash is ignored in single-part operations, and CKM_ECDSA hashes its input again | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` |  |
| A2-09 | High | CKM_AES_GCM ignores CK_GCM_PARAMS (IV, AAD, tag length) and uses a non-standard output format | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` |  |
| A2-10 | Medium | CKM_AES_CBC is implemented as CKM_AES_CBC_PAD (PKCS#7 padding) | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` |  |
| A2-11 | Medium | CKM_AES_KEY_WRAP_KWP is advertised but implemented as RFC 3394 (KW), not RFC 5649 (KWP) | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` |  |
| A2-12 | Medium | ECDH1 derive does not parse CK_ECDH1_DERIVE_PARAMS and applies a proprietary KDF | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` |  |
| A2-13 | Medium | CKM_RSA_PKCS (sign/verify) and CKM_RSA_PKCS_PSS are advertised but can never succeed | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` | `CKM_RSA_PKCS` sign/verify works; generic PSS de-advertised until params plumbing (abi) |
| A2-14 | Medium | Session objects are not bound to their session and survive C_CloseSession / C_CloseAllSessions | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| A2-15 | Medium | No per-slot object isolation: all slots share one object store | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| A2-16 | Medium | C_GenerateRandom and C_SeedRandom bypass the SP 800-90A DRBG, contrary to the documentation | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` |  |
| A2-17 | Medium | Token-object persistence is documented and configurable but never implemented; CKA_TOKEN=TRUE objects do no… | **Fixed** | state `e751482` `6ed0a17` `61f8076` |  |
| A2-18 | Medium | The documented hybrid X25519+ML-KEM-768 mechanism is absent, and the implemented hybrid ML-DSA+ECDSA mechan… | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f`; docs | hybrid mechanism removed; docs no longer claim X25519+ML-KEM |
| A2-19 | Low | C_Initialize does not validate CK_C_INITIALIZE_ARGS | **Fixed (wave 2)** | — | = H1-25 |
| A2-20 | Low | CKU_CONTEXT_SPECIFIC and CKA_ALWAYS_AUTHENTICATE are not supported | **Fixed (wave 2)** | — | `CKU_CONTEXT_SPECIFIC` / `CKA_ALWAYS_AUTHENTICATE` |
| A2-21 | Low | Object-management functions are more restrictive than the specification, and C_SetAttributeValue is not atomic | **Fixed (wave 2)** | — | = H1-27 |
| A2-22 | Informational | Stub functions skip the initialization and session checks | **Fixed (wave 2)** | — | stub functions: initialization/session checks |
| A2-23 | Medium | The test suite contains ABI tests that contradict the implementation and tests that codify non-conformant b… | **Open — not completed in wave 2** | crypto (tests updated) | full test suite green; tests asserting non-conformant behaviour |
| A2-24 | Medium | Fuzzing does not reach authenticated states, is not run in CI, and one harness breaks the API contract | **Fixed** | ci `a52fb13`; ci `f52efe5` `0ee4b0a` `d150fc0` `6561b78` `315a716` `c6dd2e0` |  |
| A2-25 | Medium | Known-answer coverage is thin and not at the ABI level; there are no Wycheproof, CAVP or ACVP vector sets | **Partially fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` (`tests/crypto_abi_params.rs`) | fixed-vector CASTs; no Wycheproof/ACVP vector sets |
| A2-26 | Low | Static-analysis hygiene: clippy fails on all targets, and CI suppresses the dominant lint | **Fixed (wave 2)** | ci (lint gate) | `absurd_extreme_comparisons` in session/handle.rs, `not_unsafe_ptr_arg_deref` |
| A2-27 | Informational | Dead or unreachable code related to conformance features | **Open — not completed in wave 2** | — | dead conformance code |
| A2-28 | Low | Documentation materially overstates the implemented PKCS#11 interface | **Fixed** | docs (ci wave-1 `a91bbc8` `4e8d19b` `52c077f` …; rel wave-2 `53b37e1` `9399de7` `a0b396f` `2c4e877`) | statements about v3.0 interface functions to be re-verified after abi wave 2 |

### A3 — Supply chain, SDLC, governance ([report](A3-supply-chain-sdlc-and-stub-inventory.md))

| ID | Severity | Finding | Status | Fixed by (commit / area) | Notes |
|---|---|---|---|---|---|
| A3-01 | High | Public "remote test server" endpoint and SO/User PINs committed, with TLS validation disabled | **Partially fixed** | ci `0c9b821` `0ee4b0a`; kreya `513515f`; rel `08877de` | files removed, secret scan, package include list; endpoint/PIN rotation/history = owner actions |
| A3-02 | High | Daemon `GenerateKey`/`GenerateKeyPair` apply arbitrary caller templates; the forbidden-attribute list is de… | **Fixed** | daemon `61612af` |  |
| A3-03 | High | Release pipeline: ungated, not `--locked`, and builds only the root package (admin/daemon never released) | **Fixed** | ci `315a716` |  |
| A3-04 | High | Shipped binaries never exercise the FIPS software-integrity test (no build-time public key, no `.sig`, non-… | **Fixed** | ci `315a716` `e6a45b7`; crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f` |  |
| A3-05 | High | Suppressed advisories: false justification for RSA Marvin, mTLS stack advisory ignored, overdue review, inc… | **Fixed** | ci `d150fc0`; rel `e77b3ad` `d4b891a` | lockfile advisories cleared (`cargo deny` all four checks pass, `cargo audit` clean with the 2 justified ignores) |
| A3-06 | Medium | Security checks are advisory only; `cargo deny` bans/sources never enforced | **Fixed** | ci `0ee4b0a` | making the checks *required* is a repository setting |
| A3-07 | Medium | Pre-release cryptographic crates in the approved path; duplicate SHA-2/SHA-3/HMAC implementations not cover… | **Fixed** | crypto `39a09f5` `f9e55f2` `c9651ab` `bfad9d6` `e4f1283` `bf84685` `2c49195` `4edda08` `687897f`; ci `c6dd2e0`; rel docs | exact pins, deny skips with reasons, risk statement |
| A3-08 | Medium | Toolchain unpinned and declared MSRV false; Docker builder too old for the lockfile | **Fixed** | ci `6561b78`; deploy `7e83360`; rel `e77b3ad` |  |
| A3-09 | Medium | Container and Helm deliverables cannot produce a working, correctly configured deployment | **Fixed** | deploy `7e83360`; rel `bc36c8f` | CI builds the image and feeds the rendered Helm config to the daemon; no kind end-to-end test yet |
| A3-10 | Medium | GitHub Actions hardening gaps | **Fixed** | ci `f52efe5` `c6dd2e0` | `CLA_TOKEN` scoping is an owner action |
| A3-11 | Medium | No SBOM, non-reproducible artifacts, and release verification docs don't match the workflow | **Partially fixed** | ci `315a716` | SBOM, SHA256SUMS, cosign, provenance; bit-for-bit reproducibility not verified |
| A3-12 | Medium | Third-party license attribution is incorrect and incomplete; binary distributions ship no notices | **Partially fixed** | ci `7184f85` `315a716` | NOTICE/THIRD-PARTY-LICENSES in tarballs; container image still ships no LICENSE/NOTICE (`.dockerignore` excludes them — deploy owner) |
| A3-13 | Medium | Fuzzing infrastructure is non-functional and not run | **Fixed** | ci `a52fb13` `f52efe5` |  |
| A3-14 | Medium | UB tooling coverage is illusory, and a lint that would flag unsound FFI signatures is suppressed | **Fixed (wave 2)** | ci (Miri scope, lint) | `unsafe extern "C"` exports; ASan job not added |
| A3-15 | Medium | `compute-integrity-hmac.sh` leaks the HMAC key through process arguments, contrary to its own comments | **Fixed** | admin `d35e40e` |  |
| A3-16 | Medium | "PKCS#11 v3.0" identity claims vs a v2.40 function set; module version reported as 0.1 | **Partially fixed** | docs (ci wave-1 `a91bbc8` `4e8d19b` `52c077f` …; rel wave-2 `53b37e1` `9399de7` `a0b396f` `2c4e877`) | version fields in code pending abi |
| A3-17 | Low | Configuration-management and versioning inconsistencies | **Partially fixed** | ci `35800a3`; rel CHANGELOG | history/signed tags are owner actions |
| A3-18 | Low | Governance documents and enforcement are misaligned | **Fixed** | ci `85d7c8b` `cf8d1a1` `c6dd2e0` | `security@` alias + PGP key are owner actions |
| A3-19 | Low | Library aborts the host process on DRBG failure | **Open — not completed in wave 2** | crypto (most aborts removed) | residual `abort()` in the infallible RNG adapter |
| A3-20 | Low | Silently discarded results in security-relevant paths | **Partially fixed** | state `e751482` `6ed0a17` `61f8076` (`login_all` rollback) | audit `record` results still discarded on the ABI path (abi) |
| A3-21 | Low | Test and documentation evidence that would not survive lab scrutiny | **Open — not completed in wave 2** | — | `#[ignore]` RSA keygen test, post-free reads in `tests/zeroization.rs`, interop default PINs, interop tests not in CI |
| A3-22 | Low | Documentation-build tooling is unmaintained and unpinned; generated PDF committed | **Partially fixed** | ci `31f1622` | stale PDF removed; root `package.json` still unpinned without lockfile (unassigned) |
| A3-23 | Low | Committed local agent settings; crate package ships non-source content | **Fixed** | ci `0c9b821` `6561b78`; rel `08877de` |  |
| A3-24 | Low | `unsafe` code documentation and soundness nits outside the ABI layer | **Partially fixed** | docs | claims corrected; `digest.rs` const assert, `AwsLcHasher` unsafe impls, SAFETY comments in integrity.rs pending core |
| A3-25 | Low | Duplicate and diverging local-CI scripts | **Fixed** | admin `d35e40e` |  |
| A3-26 | Informational | Unused direct dependencies and library-imposed tracing caps | **Fixed** | crypto `4edda08`; rel `c5caeae` |  |
| A3-27 | Informational | Build scripts | **Fixed** | ci `f52efe5`; deploy `7e83360` | protoc pinned in CI and in the Dockerfile (SHA-256 verified) |
| A3-28 | Informational | Positive observations (for balance) | **n/a** | — | positive observations |

## Not fixable in code / owner actions

These items cannot be closed by a code change in this repository. They are
required before a production release or a FIPS 140-3 submission.

### Credentials and exposure (A3-01, H4-05, H5-07)
- **Rotate the exposed test PINs** (the SO/User PINs that were committed in
  `kreya/` and the manual-test docs, and reused in `tests/fips_approved_mode.rs`)
  everywhere they were used, and treat them as compromised.
- **Take the public test endpoint offline** (`185.177.116.16:9898`), or
  re-initialise it, firewall it and put it behind TLS + mTLS.
- **Scrub git history** (`git filter-repo`) of the committed PINs/endpoint if
  required by policy; the values remain in history and in any fork.
- Rotate any HMAC key that was ever used with the removed
  `compute-integrity-hmac.sh` (it was exposed in `argv`).
- Enable GitHub **secret scanning and push protection**.

### Repository settings (A3-03, A3-04, A3-06, A3-10, A3-17, A3-18)
- Repository **variable `CRATON_HSM_INTEGRITY_PUBLIC_KEY`** (64 hex chars) —
  the release workflow refuses to build without it.
- **Protected environments:** `release` (required reviewers, tag rule `v*`,
  secrets `CRATON_HSM_INTEGRITY_SIGNING_KEY` and optional
  `CRATON_HSM_INTEGRITY_SIGNING_KEY_PASSPHRASE`) and `crates-io` (required
  reviewers).
- **crates.io Trusted Publishing** for `release.yml` / environment
  `crates-io`; then delete the old `CARGO_REGISTRY_TOKEN` secret.
- **Branch protection** on `main` with required checks `CI` and
  `Security Audit`; **tag protection** (maintainers only, signed annotated
  tags); require signed commits; publish full history or signed tags for past
  releases.
- **`CLA_TOKEN`**: fine-grained PAT scoped to `craton-co/cla-signatures` only.
- Create a `security@` alias and publish a PGP key in `SECURITY.md`.
- Release-signing key custody (HSM/KMS, access control, backup) and M-of-N
  authorisation for backup export are policy decisions (H5-05, H5-08).

### FIPS 140-3 certification (A1-02, A1-03, A1-05, A1-06, A1-19, A1-11)
- **ESV certificate** and min-entropy justification for the OS entropy source
  (the module only implements RCT/APT health tests).
- **CAVP/ACVP certificates** for the exact AWS-LC build and each claimed
  operational environment; CMVP boundary documentation for the embedded
  AWS-LC module; CST lab engagement; SP 800-140B formatted Security Policy.
- Moving the integrity-test signature verification (Ed25519) onto a
  validated implementation.

### Design limits (documented)
- Whole-database rollback (older redb file + audit anchor) needs an external
  monotonic counter (TPM NV index / HSM counter) — H3-15/H3-17/A1-17.
- Lockout counters cannot be authenticated before login without a device
  secret — H3-17.
- Off-host audit forwarding (syslog/SIEM) is an operational control — H3-10.
- Secure deletion inside redb free pages / media-level erasure — H3-15.
- RustCrypto `rsa` is not constant time until a fixed release (`rsa` 0.10);
  use AWS-LC (mandatory in `fips` builds) — H2-03/A1-26.
- PQC crates are pre-release (exactly pinned, documented risk) — H2-20/A3-07.
- The pkcs11-spy must never be configured for privileged processes — H6-02.
- Long-running fuzzing (OSS-Fuzz / ClusterFuzzLite) — A3-13; bit-for-bit
  reproducibility verification by an independent rebuild — A3-11.
- Base-image digests, protoc and `grpc_health_probe` checksums need periodic
  refresh (e.g. Renovate) and the published image should be signed — H4-23.
