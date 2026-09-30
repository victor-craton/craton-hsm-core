# Handoff — 2026-09-24 audit remediation

Written 2026-09-30 when the remediation session ended early (the wave-2
agents hit a usage limit). It states what is done, what was verified, what
was not, and how to carry on.

## 1. Where things are

| Item | State |
|---|---|
| Audited revision | `2f76874` (`main`, version 0.9.1) |
| Audit reports | `docs/audit/2026-09-24/` (`README.md` = consolidated summary; `H1`–`H6`, `A1`–`A3`) |
| Fix branch (**integration**) | `claude/audit-fixes`, branched from `dev`. It contains every fix below. |
| Finding-by-finding status | [`REMEDIATION.md`](REMEDIATION.md) (244 findings) |
| Per-area hand-off notes from the fix agents | [`handoffs/`](handoffs/) (`crypto`, `state`, `daemon`, `admin`, `spy`, `ci`, `wave2-core`, `wave2-rel`) |
| CHANGELOG | `CHANGELOG.md` → `Unreleased` |

Merge order on `claude/audit-fixes`: wave 1 (`state`, `ci`, `spy`, `admin`, `daemon`, `crypto`) → wave 2
(`rel`, `core`, `abi`) → test-PIN migration → this hand-off.

**Push status.** Every push from the session that produced this work was refused
with HTTP 403 (`Resource not accessible by integration`), for git and for the
GitHub API. If the branch is not on the remote yet, fix GitHub access first
(reconnect at https://claude.ai/connect-github and make sure the Claude GitHub
App is installed on the repository), then run:

```bash
git push -u origin claude/audit-fixes
```

`dev` was created locally from `main` and has **not** been pushed either.

**History note.** The first version of the A3 report and of `REMEDIATION.md` quoted the
address and PIN values of the exposed test server (they are already present in `main`
via `kreya/`, `docs/postman-grpc-manual-tests.md` and `tests/fips_approved_mode.rs`). The
tip of `claude/audit-fixes` no longer contains them, but earlier local commits do
(`d0f385e` on `claude/modest-hamilton-y6ok79`, its merge `f6dfe17` on `dev`, and the merge of `dev`
into `claude/audit-fixes`). A `git filter-branch` scrub of those unpushed commits was attempted
and was blocked by the session's permission policy, so it was **not** done. If you want the
values out of the pushed history, rewrite those unpushed commits before the first push (the
values to remove are the host address and the two PINs named in `kreya/remote.krenv`), or
squash-merge the branch. Since the same values are already in `main`, rotating them
(§6, item 1) matters more than the rewrite.

## 2. What changed (summary)

- **Critical / High security fixes.** `C_InitToken` verifies the SO PIN (with lockout)
  before it wipes anything, and returns `CKR_SESSION_EXISTS` while sessions are open.
  Sensitive keys and private-key components are never returned. The SO no longer counts as a
  logged-in user; closing the last session logs the token out. Slots are isolated. Key creation,
  destroy, wrap, copy, derive, digest-key and `C_SetOperationState` are authorized. The gRPC
  daemon has per-client sessions and login, an admin-gated `InitToken`, and a template
  whitelist. Persistence is real (encrypted store, PIN hashes, lockout, token objects, GCM/CTR
  usage state). The audit chain is keyed (HMAC), anchored and rotation-safe.
- **Crypto.** DRBG-backed `C_GenerateRandom`/`C_SeedRandom`, fixed-vector self-tests for all
  approved algorithms run through the active backend, honoured `CK_GCM_PARAMS`, raw `r||s` ECDSA
  with the mechanism's hash, interoperable ECDH KDFs, RFC 5649 KWP, blinded RSA, strict Ed25519,
  fail-closed integrity check in `fips` builds, and `fips` implies the AWS-LC backend.
- **Conformance.** `C_GetInterfaceList` / `C_GetInterface` / `C_LoginUser` / `C_SessionCancel`,
  message-based AES-GCM, stub functions check initialization, `C_Initialize` argument validation.
  All exports are `pub unsafe extern "C" fn`; `clippy::not_unsafe_ptr_arg_deref` is no longer
  suppressed.
- **Tooling.** pkcs11-spy wraps the function table and hardens its loader and logger. The admin CLI
  works on the persistent token with SO login and typed confirmation. The HMAC integrity scripts
  are removed.
- **Supply chain / SDLC.** Toolchain pinned to 1.94.1, MSRV 1.89, advisories cleared with
  `cargo update`, `deny.toml` honest and time-boxed, gated and signed release workflow, SBOM,
  container and Helm jobs, and a corrected crate `include` list (it dropped the self-test KAT
  files, so the published crate would not have built).
- **Docs.** Rewritten to match the code (module boundary, SSP table, integrity scheme, config
  reference, runbook).

### Behaviour changes operators and integrators will notice

| Change | Effect |
|---|---|
| Core PIN policy (`src/token/pin_policy.rs`) | Weak PINs are refused at `C_InitToken`/`C_InitPIN`/`C_SetPIN` (min 8 bytes, ≥ 4 distinct characters, ≥ 2 character classes, no repetition, no runs, denylist). **The published test PINs `sopin123` and `userpin1` are now on the denylist.** |
| `C_InitToken` | Fails with `CKR_SESSION_EXISTS` while sessions are open; wipes only the target slot. |
| SO role | Cannot use or read user keys. |
| ECDSA | Signatures are raw `r‖s`. Any consumer of the old DER output must change. |
| AES-GCM | Honours `CK_GCM_PARAMS`; the no-parameter form keeps the old `IV‖ct‖tag` framing (deprecated); output for parameterised calls is `ct‖tag`. Caller IVs are refused in FIPS mode. |
| `CKM_AES_CBC` | Now **unpadded**. Use `CKM_AES_CBC_PAD` for PKCS#7. |
| Hybrid ML-DSA+ECDSA / X25519+ML-KEM mechanism | Removed. |
| Config | Unknown keys in any core section are fatal. `pin_min_length` below 8 is rejected. `fips` builds force approved-only mode + AWS-LC in every loader. The system config `/etc/craton-hsm/craton_hsm.toml` is accepted. |
| Admin CLI | Works on the persistent token and needs the daemon **stopped** (single-writer lock, exit 5). Backups are bound to the token instance. |
| Backup restore | Atomic; replay guard is inside the encrypted store. |
| `HsmCore::drbg()` | Removed; use `HsmCore::generate_random`. |

## 3. What was verified (measured)

On the merged `claude/audit-fixes` tree:

- `cargo check --workspace --all-targets`: passes.
- `cargo clippy --workspace --all-targets -- -D clippy::correctness -D clippy::suspicious -A deprecated -A clippy::incompatible_msrv`
  (the CI command **without** the old `-A clippy::not_unsafe_ptr_arg_deref`): passes.
  At the audited revision it failed with 116 errors.
- `Cargo.lock` and `fuzz/Cargo.lock` are in sync (`cargo metadata --locked`).
- Wave-1 and wave-2 agents each ran their own targeted suites green (reported in
  `handoffs/*.md` §Verification): spy 27 unit + 7 integration, admin 35 unit + 12 CLI,
  daemon 40, core lib 45 (default backend) / 47 (AWS-LC), and the ABI/state regression suites.
- `cargo deny check` (all four sections) and `cargo audit` clean with two justified ignores.
- All workflows pass PyYAML and actionlint; `helm lint --strict` and `helm template` pass.

## 4. What was NOT verified — do these first

1. **The full serial test suite on the merged tree has not completed.**
   `cargo test --workspace --no-fail-fast -- --test-threads=1` was started twice and stopped
   (once to migrate the test PINs, once at the end of the session). Run it and triage:
   ```bash
   cargo test --workspace --no-fail-fast -- --test-threads=1 2>&1 | tee full-test.log
   ```
   It takes on the order of an hour. **At the audited revision it gave 682 passed / 34 failed /
   1 ignored** (failing suites: `drbg_tests`, `multipart_encrypt_decrypt`, `multipart_sign_verify`,
   `negative_edge_cases`, `pkcs11_compliance`, `pkcs11_compliance_extended`, `pkcs11_conformance`,
   `pqc_abi_comprehensive`, `random_and_session`, `rsa_abi_comprehensive`, `security_properties`,
   `supplementary_functions`, `zeroization`). Wave 2 was supposed to make it green; the last
   test-PIN migration (`sopin123`→`S0pin-47`, `userpin1`→`Us3rpin9`, tests + admin CLI tests) has
   never been run. Expect some remaining failures, especially in tests that assumed the old
   behaviour (order of found handles, DER ECDSA, padded CBC, SO login semantics).
2. The ABI agent stopped mid-way and left **no hand-off file** for the ABI area. Its commits are
   the record: `7b796ca`, `0989eca`, `6ec4818`, `f388c94`, `36fdede`, `70b5846`, `afd33f3` and the
   A1-25 curve check on `claude/audit-fixes2-abi`. Note that `Token::verify_pin` (core semantics:
   verify without logging in, for the daemon) and `Token::verify_logged_in_pin` (re-authentication
   of the current role, for `CKU_CONTEXT_SPECIFIC`) are two separate methods after the merge.
3. Windows and macOS code paths were only cross-compiled (spy, admin). The PowerShell scripts were
   never run. No Docker daemon was available: the `Dockerfile` was not built.
4. `REMEDIATION.md` "Fixed (wave 2)" rows come from wave-2 commit messages, not from re-checking
   each finding.

## 5. Findings still open after wave 2

| ID | What | Notes |
|---|---|---|
| H1-32 | Multi-part operation memory is bounded per session, not globally | add a global budget |
| H1-33 | Windows audit-file ACL: unaligned casts, DACL applied after creation | needs `windows-sys` |
| A2-23 | Test suite contradicts implementation in places | depends on the full-suite triage above |
| A2-27 | Dead conformance-related code | remove or wire up |
| A3-19 | Library aborts the host on DRBG failure (residual aborts) | return `CKR_DEVICE_ERROR` |
| A3-21 | Test/doc evidence that would not survive lab scrutiny | KAT provenance, Wycheproof/ACVP vectors at ABI level |
| A1-11 | Approved-service indicator not queryable through the API | unassigned |
| A3-22 | Root `package.json` unpinned | pin or drop |

Residuals of *partially fixed* findings are in the *Notes* column of `REMEDIATION.md` and in
the "Not fixable in code / residual" sections of `handoffs/`. The largest:

- whole-database rollback detection needs an external monotonic counter (H3-15, H3-17, A1-15);
- RSA private-key bignum arithmetic in `rsa` 0.9 is still not constant time (H2-03, RUSTSEC-2023-0071);
- pooled mlocked arena (P13) not done;
- Windows config-ACL check still parses `icacls` output (H3-29);
- kind end-to-end smoke test and proto/Kreya consistency check were not added to CI.

## 6. Owner actions — cannot be done in code

1. **Rotate or decommission the exposed test server and its PINs.** `kreya/remote.krenv`,
   the request JSONs and the manual-test doc in the audited revision pointed at a public
   plaintext gRPC endpoint and carried working SO/User PINs, with certificate validation
   disabled. The files are cleaned on this branch, but the values remain in `main` history and
   in the crates.io package of any earlier release. Treat the PINs as compromised, shut the
   host down or re-initialise it, and scrub history if required. (Values are deliberately not
   repeated in this repository's audit documents.)
2. FIPS 140-3 blockers that are not code: an **ESV entropy-source certificate**, **CAVP/ACVP
   certificates** for the algorithm implementations (in practice: validate the AWS-LC module as
   the approved-mode provider), a defined tested operating-environment list, and a lab engagement.
3. Repository/organisation settings the release pipeline needs: the
   `CRATON_HSM_INTEGRITY_PUBLIC_KEY` variable, protected environments `release` and
   `crates-io`, crates.io trusted publishing, tag and branch protection, a fine-grained
   `CLA_TOKEN`, and the integrity-signing key custody procedure.
4. Pin third-party GitHub Actions and container images by digest where the handoffs list tags
   that could not be resolved offline (`handoffs/ci.md`, `handoffs/daemon.md`).

## 7. How to continue

```bash
git fetch origin && git checkout claude/audit-fixes
export CARGO_TARGET_DIR=$PWD/target-audit-fixes   # unique name; delete when done
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0
cargo check --workspace --all-targets
cargo test --workspace --no-fail-fast -- --test-threads=1     # ABI suites MUST be serial
cargo clippy --workspace --all-targets -- -D clippy::correctness -D clippy::suspicious \
    -A deprecated -A clippy::incompatible_msrv
```

`protoc` is required to build the daemon (`apt-get install protobuf-compiler`).
Suggested order: (1) full test triage, (2) the open list in §5, (3) re-verify the
"Fixed (wave 2)" rows, (4) run the CI workflows on a PR, (5) owner actions in §6.

## 8. Method notes

- Static audit by parallel reviewers; only the orchestrator built and ran anything.
- Some reviewer runs were interrupted by an automated content filter while writing
  attack-oriented text, and were redone as defensive reviews (a *trigger condition* per finding
  instead of exploit detail). No findings were dropped.
- Commit messages on the fix branches are one line each.
