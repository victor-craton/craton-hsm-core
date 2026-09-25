# Craton HSM — security & certification-readiness audit (2026-09-24)

Audited revision: `2f76874` (version 0.9.1). The audit was a static review by parallel reviewers, one per crate, with the root crate split into three areas, plus three certification auditors. A baseline build, clippy and test run backs it up.

## Reports

| ID | Report | Scope | Crit | High | Med | Low | Info | Total |
|---|---|---|---|---|---|---|---|---|
| H1 | [PKCS#11 ABI layer](H1-pkcs11-abi-security.md) | `src/pkcs11_abi`, `lib.rs`, `core.rs`, `error.rs`, `platform_acl.rs` | 1 | 9 | 12 | 12 | 2 | 36 |
| H2 | [Cryptography](H2-crypto-security.md) | `src/crypto` | 0 | 3 | 8 | 9 | 2 | 22 |
| H3 | [Store / session / token / audit / config](H3-store-session-token-audit-security.md) | `src/store`, `session`, `token`, `audit`, `config` | 1 | 4 | 11 | 9 | 4 | 29 |
| H4 | [gRPC daemon & deployment](H4-daemon-security.md) | `craton-hsm-daemon`, `deploy/`, `kreya/` | 1 | 6 | 10 | 8 | 3 | 28 |
| H5 | [Admin CLI & tooling scripts](H5-admin-cli-security.md) | `tools/craton-hsm-admin`, `tools/*.sh/.ps1`, `scripts/` | 0 | 4 | 7 | 9 | 4 | 24 |
| H6 | [pkcs11-spy](H6-pkcs11-spy-security.md) | `tools/pkcs11-spy` | 0 | 1 | 4 | 7 | 5 | 17 |
| A2 | [PKCS#11 v3.0 conformance & test assurance](A2-pkcs11-conformance-and-test-assurance.md) | ABI conformance, tests, fuzzing, docs | 2 | 5 | 14 | 5 | 2 | 28 |
| A3 | [Supply chain, SDLC, governance & stub inventory](A3-supply-chain-sdlc-and-stub-inventory.md) | Cargo, CI/CD, release, governance docs, repo-wide stubs | 0 | 6 | 13 | 9 | 3 | 31 |
| A1 | [FIPS 140-3 readiness](A1-fips-140-3-readiness.md) | Code and documentation against ISO/IEC 19790 / SP 800-140x | 6 Blocker | 15 Major | 8 Minor | — | 3 Obs. | 32 |

Findings overlap between reports on purpose. The same defect seen from the attacker's side and from the auditor's side is cross-referenced rather than merged. The next section de-duplicates the most important ones.

## Verdicts

- **Security posture:** not production-ready. There are 3 independent Critical defects and more than 25 High ones. Most sit in authorization and attribute-policy logic, not in memory safety. The FFI plumbing (`catch_unwind`, pointer and length checks) is generally careful.
- **FIPS 140-3:** **not ready** (A1). There are 6 blockers: the RNG bypasses the DRBG, there is no ESV entropy source, approved services run on unvalidated RustCrypto code, the self-tests are round-trips rather than known-answer tests, the integrity test is optional, and the module boundary is defined inconsistently.
- **PKCS#11 v3.0 conformance:** **not ready** (A2). All 68 v2.40 functions are exported and none of the 24 v3.0 functions, yet version 3.0 is reported. Several mechanisms do not interoperate.
- **Supply chain / SDLC:** **Partial** (A3). The release pipeline is not gated, the committed credentials must be removed, and there is no SBOM or reproducible build.

## Top cross-cutting issues (de-duplicated)

| # | Severity | Issue | Reports |
|---|---|---|---|
| 1 | Critical | `C_InitToken` wipes every object on every slot, and resets GCM counters, **before** it verifies the SO PIN. Unlimited SO-PIN guessing on this path. | H1-01, H3-01, A1-07, A2-02 |
| 2 | Critical | Daemon login state is shared by all gRPC clients. After one login, any peer can use the keys. | H4-01 |
| 3 | Critical / High | CKA_SENSITIVE bypass: sensitive+extractable keys return `CKA_VALUE`, and private-key components are returned without a check. | H1-02, H3-02, A1-08, A2-04 |
| 4 | High | SO counts as a logged-in user. Closing sessions does not log out. Destroy, keygen, unwrap and derive need no login. `C_SetOperationState` and `C_WrapKey` authorization gaps. | H1-03..H1-10, H3-06, A2-03, A2-05 |
| 5 | High | No persistence: `persist_objects` is ignored and PIN hashes and objects are memory-only. After a restart, the first caller becomes SO. The admin CLI works on a throw-away core, so backups are always empty. | H3-04, H4-02, H4-03, H5-02, A1-17 |
| 6 | High | AES-GCM ignores `CK_GCM_PARAMS` (IV, AAD, tag length). The nonce/counter state can repeat across copies, forks and restarts. | H2-01, H2-02, A1-15, A2-09 |
| 7 | High | RSA private-key operations are exposed to the Marvin timing attack (RUSTSEC-2023-0071), and the advisory is suppressed with an inaccurate justification. | H2-03, A1-26, A3-05 |
| 8 | High | No slot isolation: one global object store. | H1-13, H3-03, A2-15 |
| 9 | High | Credentials are committed: a public plaintext test endpoint and its SO/User PINs in `kreya/` and the manual-test docs. Certificate validation is disabled. | A3-01, H4-05 |
| 10 | High | Daemon key-generation templates accept `CKA_VALUE`/`CKA_CLASS`, so callers can supply their own key material. The forbidden-attribute list is dead code. | H4-06, A3-02 |
| 11 | High | pkcs11-spy returns the real module's function table, so it logs almost nothing. It trusts `PKCS11_SPY_*` environment variables in setuid contexts. | H6-01, H6-02 |
| 12 | Blocker | `C_GenerateRandom` returns raw OS randomness. The SP 800-90A DRBG is unused, and there is no continuous RNG test and no DRBG known-answer test. | A1-01, A1-02, A2-16 |
| 13 | Blocker | The `fips` feature still uses the unvalidated RustCrypto backend. Power-on self-tests are round-trips. The integrity check is skipped if the module path is not found. | A1-03..A1-05, H2-05, H2-08, A3-04 |
| 14 | Medium | Soundness: 112 public safe `extern "C" fn` dereference raw pointers (`clippy::not_unsafe_ptr_arg_deref`, suppressed in CI). | H1-22, A2-26, A3-14 |
| 15 | Medium | The audit hash chain is unkeyed. Auditing fails open after log rotation. Key events are not audited. `admin audit verify-chain` reports VALID on a tampered log. | H3-10, H3-11, H5-03 |

## Baseline build & test evidence (measured, not inferred)

- `cargo clippy --workspace --all-targets` **fails: 116 errors**. 112 are `not_unsafe_ptr_arg_deref` in `src/pkcs11_abi/functions.rs` and 4 are `absurd_extreme_comparisons` in `src/session/handle.rs`. There are also about 995 warnings, mostly `missing_docs`.
- The workspace build needs `protoc` for the daemon. It is not documented as a prerequisite in the install guide.
- `cargo check --all-targets` fails: `benches/crypto_bench.rs` imports a crate that does not exist (`craton_hsm_awslc`).
- `cargo test --workspace -- --test-threads=1` (as CI runs the ABI tests): **682 passed, 34 failed, 1 ignored** across 39 test binaries. The failing suites are `drbg_tests` (1), `multipart_encrypt_decrypt` (1), `multipart_sign_verify` (1), `negative_edge_cases` (4), `pkcs11_compliance` (1), `pkcs11_compliance_extended` (1), `pkcs11_conformance` (3), `pqc_abi_comprehensive` (2), `random_and_session` (1), `rsa_abi_comprehensive` (1), `security_properties` (1), `supplementary_functions` (15) and `zeroization` (2). Most failures come from test SO PINs that violate the module's own PIN policy, IV-reuse detection, and the ECDH/OAEP/PQC issues described in H2 and A2. This confirms A2-23: the CI test gate cannot be green at this revision.
- With the default multi-threaded test harness, the ABI suites fail en masse because they share global PKCS#11 state. They must run with `--test-threads=1`.

## Stubs, TODOs and unimplemented items

There are no `todo!()`, `unimplemented!()`, FIXME or HACK markers in production code. The functional stubs are listed in each report and in the full inventory in [A3 § stub inventory](A3-supply-chain-sdlc-and-stub-inventory.md). They include:

- 9 PKCS#11 functions that only return `CKR_FUNCTION_NOT_SUPPORTED`, and none of the 24 v3.0 functions.
- `persist_objects` and the encrypted store are never wired.
- Advertised-but-broken mechanisms: `CKM_RSA_PKCS`, `CKM_RSA_PKCS_PSS`, KWP, the hybrid KEM, and GCM with AAD.
- Admin CLI `audit dump --last`, backup and restore.
- One `#[ignore]` test (`tests/fips_approved_mode.rs:277`).

## Performance (summary)

The top items, with details in each report's performance section:

- Stop creating and reseeding a DRBG on every call.
- Hash PINs outside the token-wide lock.
- Use a fixed-key RSA self-test instead of generating RSA-2048 on every `C_Initialize`.
- Release the map lock before GCM encryption.
- Remove the 10 ms CBC sleep.
- Keep the RSA key cache in an `Arc`.
- Use a `VecDeque` for the audit buffer, and batch fsyncs.
- Resolve pkcs11-spy targets once and write one buffered record per call.
- Move daemon crypto to `spawn_blocking`.

## Method notes

- All reviews were static. Only the orchestrator ran builds and tests, using a unique target directory (`target-audit-baseline-20260924`) that was deleted afterwards.
- Several reviewer runs were interrupted mid-write by an automated content filter because of offensive "attack scenario" phrasing. Those reports (H1 from H1-04 on, H4, H5, H6 and A2) were completed or re-run in a defensive format. Each finding has a one-sentence *trigger condition* instead of exploit detail. No findings were dropped because of the interruptions, and every re-run re-verified its findings against the code.
- Credential values found in the repository are referenced by file and line only. They are not reproduced in these reports.
