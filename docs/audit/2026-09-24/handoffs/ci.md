# Handoff — area `ci` (branch `claude/audit-fixes-ci`, worktree /home/user/hsm-fix-ci)

Scope: .github/**, deny.toml, rust-toolchain.toml, root Cargo.toml [package]
metadata, NOTICE, SECURITY/CONTRIBUTING/GOVERNANCE/ROADMAP/CHANGELOG/README,
.gitignore, .claude/settings.local.json, fuzz/**, docs/** (except the parts
owned by daemon/admin/spy agents).

## 1. Integrator: run these right after merging all areas

1. **Cargo.lock security updates (A3-05/A3-06)** — verified to clear every
   RustSec advisory except the two justified ignores, and to keep MSRV 1.89:
   ```
   cargo update -p anyhow -p crossbeam-epoch -p h2 -p rand@0.8.5 -p rustls \
                -p rustls-webpki -p der@0.8.0 -p spin@0.9.8
   ```
   (anyhow RUSTSEC-2026-0190, crossbeam-epoch 2026-0204, h2 2026-0258,
   rand 2026-0097, rustls 2026-0285, rustls-webpki 2026-0098/0099/0104,
   yanked der 0.8.0 and spin 0.9.8.) If other agents already bumped these,
   re-run `cargo deny --workspace --all-features check` and fix what remains.
   Then refresh the fuzz lockfile the same way:
   `cp Cargo.lock fuzz/Cargo.lock && (cd fuzz && cargo check --bins)` (the
   fuzz crate has its own workspace; this keeps the versions identical).
2. `cargo deny --workspace --all-features check` must pass (all four
   sections). New duplicate crate versions introduced by other agents fail
   `[bans] multiple-versions = "deny"` — add a `skip` entry with a reason in
   deny.toml or remove the duplicate.
3. **`publish = false`** must be added to `tools/craton-hsm-admin/Cargo.toml`,
   `craton-hsm-daemon/Cargo.toml` and `tools/pkcs11-spy/Cargo.toml`
   `[package]` (they are never published; without it `cargo deny`
   `wildcards = "deny"` fails on their `path` dependency on `craton-hsm`).
   Owners: admin / daemon / spy agents (not my paths).
4. **Every new `tests/*.rs` file** added by other agents must be listed in one
   of the two `cargo test` lists of `.github/workflows/ci.yml`
   (`build-and-test` job); the `fmt-check` job fails otherwise (by design).
5. **Clippy gate:** ci.yml no longer allows `clippy::not_unsafe_ptr_arg_deref`
   or `clippy::incompatible_msrv`, and now runs `--all-targets`. On the
   pre-merge tree it fails with 112 `not_unsafe_ptr_arg_deref` errors in
   `src/pkcs11_abi/functions.rs` (A3-14) and 4
   `absurd_extreme_comparisons` in `src/session/handle.rs:61,70,152,201`
   (A2-26: use `cfg(target_pointer_width)`). The wave-2 ABI agent is to make
   the exports `pub unsafe extern "C" fn`; after that, **all Rust callers
   (tests/, benches/, fuzz/fuzz_targets/*.rs, tools/pkcs11-spy tests,
   daemon/admin if they call C_* directly) need `unsafe {}` blocks** —
   `fuzz/fuzz_targets/common.rs` already uses `unsafe` (with
   `#![allow(unused_unsafe)]`), the other 12 fuzz targets do not.
6. MSRV job: `cargo +1.89.0 check --locked --workspace` must pass. If merged
   code uses newer std APIs, either raise `rust-version` in Cargo.toml **and**
   `RUST_MSRV` in ci.yml together, or avoid the API.
7. Toolchain is pinned to **1.94.1** (`rust-toolchain.toml`); rustup
   auto-installs it on first `cargo` use (network needed once).
8. `.github/workflows/*.yml` were validated with PyYAML and actionlint 1.7.12.

## 2. Docs describe INTENDED behaviour of concurrent work — verify after merge

I aligned the docs with the in-progress designs visible in the other
worktrees. Re-check each statement against the merged code; fix the doc (or
the code) if they differ.

| Doc statement | Where | Depends on |
|---|---|---|
| `C_GenerateRandom` served by the process-wide HMAC_DRBG (AWS-LC DRBG with awslc backend); entropy RCT/APT health tests; reseed 2^16; 2^19 bits/request; DRBG KAT in POST | fips-140-3-certification.md §8.2, security-policy.md §5, api-reference.md, faq.md, architecture.md, security-model.md | crypto (A1-01/A1-02) |
| Self-test order SHA-256/512 + Ed25519 CAST → integrity → CASTs (list in §9.2), backend CASTs through selected backend, latched error state cleared only by C_Finalize + successful C_Initialize | fips-140-3-certification.md §9, fips-mode-guide.md §5, architecture.md, security-model.md, troubleshooting.md, operator-runbook.md | crypto (A1-04/A1-09) |
| `fips` builds fail closed on missing `.sig`, placeholder key, unresolvable module path; refuse non-validated backend | release-signing.md, fips-mode-guide.md §3, fips-140-3-certification.md §4.1 | crypto (A1-05/A1-03) |
| Mechanism semantics: CBC unpadded vs CBC_PAD, real KWP, `CK_GCM_PARAMS`/`CK_AES_CTR_PARAMS` honoured, module-generated GCM IVs in approved mode, ECDSA raw r‖s, CKM_RSA_PKCS sign/verify of DigestInfo, generic CKM_RSA_PKCS_PSS and CKM_HYBRID_ML_DSA_ECDSA not advertised, Ed25519 approved, CKD_NULL refused in approved mode, 39 mechanisms | fips-140-3-certification.md App. A, api-reference.md, audit-scope.md, security-policy.md §5, fips-mode-guide.md §2, README | crypto (A1-13..16, H2) |
| RSA parsed-key cache cleared on C_Finalize/C_InitToken | fips-140-3-certification.md §8.1/§8.6 | crypto (A1-10) |
| `self_test::run_post_with_backend` exists for rlib embedders | api-reference.md | crypto |
| C_InitToken: SO PIN verified first, per slot, SO lockout applies, CKR_SESSION_EXISTS with open sessions | fips-140-3-certification.md §3.2, operator-runbook.md, gap analysis | state (A1-07) |
| Key use requires the User role; SO not "logged in" for key use | fips-140-3-certification.md §3.2, security-policy.md §3, security-model.md | state (A1-12) |
| CKA_VALUE never returned for sensitive OR non-extractable keys | fips-140-3-certification.md §8.4, security-policy.md §6, security-model.md | state (A1-08) |
| Persistence: per-slot random DEK, wrapped under SO/User PIN-derived KEKs (PBKDF2), AES-256-GCM records with AAD, HMAC manifest, crypto-shred on C_InitToken, keyring wiped on C_Finalize; lockout counters per slot | fips-140-3-certification.md §8.1/§8.5, security-policy.md §6, configuration-reference.md, faq.md, architecture.md | state (A1-17) |
| All volatile SSPs zeroized at C_Finalize | fips-140-3-certification.md §8.6 | state + crypto (A1-10) |
| `C_GetInterfaceList` / `C_GetInterface` exported ("PKCS 11" interface); `C_GetFunctionList` returns the v2.40 list | README, api-reference.md, faq.md, architecture.md, fips-140-3-certification.md §2.2, security-policy.md | ABI (wave 2) / whoever implements v3.0 interface functions |
| `C_GetInfo.libraryVersion` = package major.minor (0.9) | fips-140-3-certification.md §1.1 (flagged as "must be checked") | ABI (A3-16) — **functions.rs:324, :422-423, :468-469 still hard-code 0.1; CK_FUNCTION_LIST.version 3.0 on a v2.40 struct at functions.rs:5459** |
| Daemon: mandatory config, `[daemon]` fields incl. `tls_client_ca`, `allow_no_client_auth`, `admin_client_cert_sha256`, per-client authz | configuration-reference.md, install.md, operator-runbook.md | daemon (H4) |
| Admin CLI subcommands (`token init/info`, `pin change --user-type user|so`, `pin reset`, `key list --role`, `key import --type aes`, `key delete --handle --role`, `audit dump/verify-chain/export-*`, `backup --output`, `restore --input [--verify-only]`), prompts only, audit logging of admin actions | operator-runbook.md, install.md, faq.md | admin (H5) |
| `tools/sign-integrity.sh <lib> <key>` interface, `CRATON_HSM_SIGNING_KEY_PASS_FILE`; `.sig` = hex(Ed25519(SHA-256(file))) in `<stem>.sig` | .github/workflows/release.yml (package job), release-signing.md | admin (tools) + crypto (integrity.rs). **If the .sig format changes, update release.yml's independent verification step.** |
| A1-25 (EC params validation) and A1-30 (key-type consistency) marked "Open (verify)" in fips-gap-analysis.md | fips-gap-analysis.md | crypto/ABI — update the row if fixed |
| Multi-slot isolation (A2-15 / doc D8): configuration-reference.md still documents `slot_count` as independent tokens | configuration-reference.md, architecture.md | state — verify the slot filter is applied |

**Critical integration issue found:** in both the state and crypto worktrees
`HsmConfig::fips_defaults()` leaves `crypto_backend = "rustcrypto"`, while the
crypto agent's `run_backend_post()` refuses non-validated backends in `fips`
builds. Result: every `fips` build stays in the error state. Fix (owner of
`src/config/config.rs`): in `fips_defaults()` set
`crypto_backend = "awslc"` under `#[cfg(feature = "awslc-backend")]`, and add
`#[cfg(all(feature = "fips", not(feature = "awslc-backend")))] compile_error!(...)`.
The release workflow's `-fips` flavour smoke test (`C_Initialize` must return
CKR_OK) will fail the release until this is fixed.

## 3. Changes needed outside my paths (with finding IDs)

| Finding | File / function | Change |
|---|---|---|
| A3-09 | `deploy/Dockerfile:16` | Builder `rust:1.83-bookworm` cannot build the lockfile (MSRV 1.89): use ≥1.89 (ideally 1.94.1 = rust-toolchain.toml); copy `rust-toolchain.toml` into the build context. |
| A3-09 | `deploy/Dockerfile:59` | `COPY craton_hsm.toml` — no such file is tracked; commit a sample config or drop the COPY. |
| A3-09 | `deploy/Dockerfile:69` | `cargo test -p craton_hsm` → `-p craton-hsm` (package name). |
| A3-09 | `deploy/helm/craton-hsm/templates/configmap.yaml` | `storage_path = "/data/..."` and `log_path = "/data/..."` are absolute and rejected by config validation — use relative paths with `workingDir: /data`, or allow an absolute base dir in the validator. Set `persist_objects = true` when `persistence.enabled`. |
| A3-09 | `templates/secret-security.yaml` + daemon | `security.toml` is mounted but never loaded → PIN/lockout values in values.yaml are silently ignored. Render `[security]` into the main config instead. |
| A3-09 | `deployment.yaml` probes + daemon | gRPC health service not registered; kubelet gRPC probes cannot do TLS. Implement `tonic-health` and use exec probes or a loopback plaintext health port. |
| A3-09 | `craton-hsm-daemon/src/main.rs` `shutdown_signal()` | handle SIGTERM, not only ctrl_c (daemon agent may have done it). |
| A3-12 | `deploy/.dockerignore` excludes `LICENSE*`, `*.md` | Ship LICENSE, NOTICE (and THIRD-PARTY-LICENSES) in the image (`COPY LICENSE NOTICE /usr/share/doc/craton-hsm/`). |
| A3-27 | `deploy/Dockerfile` | pin `protobuf-compiler` / `apt-get install` versions (CI pins protoc 36.2). |
| A3-26 | root `Cargo.toml [dependencies]` (crypto agent) | remove unused `cipher = "0.5"` and `secrecy`; move tracing `max_level_info`/`release_max_level_info` caps from the library to the binaries. Fix the commented `craton_hsm-awslc` dev-dependency comment (says "enterprise repo"; the AWS-LC backend is in-tree). |
| A3-07 | root `Cargo.toml` (crypto agent) | consider exact pins (`=`) for the PQC release candidates. |
| A3-16 | `src/pkcs11_abi/functions.rs` (ABI agent) | `CK_FUNCTION_LIST.version` → 2.40 (3.0 only for the `CK_FUNCTION_LIST_3_0` returned by `C_GetInterface`); derive `library_version` from `CARGO_PKG_VERSION_MAJOR/MINOR`. |
| A3-14 / A2-26 | `src/pkcs11_abi/functions.rs`, `src/session/handle.rs` | see §1.5. Add `// SAFETY:` comments; consider `#![warn(clippy::undocumented_unsafe_blocks)]`. Add Miri-friendly unit tests for `parse_template`/buffer helpers under `pkcs11_abi::` and for `crypto::digest` zeroization (the Miri CI job already filters on these module paths). |
| A3-19 | `src/crypto/drbg.rs` `fill_bytes` abort, `src/crypto/pqc.rs` | residual `std::process::abort()` in the infallible RNG adapter (crypto agent kept one) — latch error state + return error where the trait allows. |
| A3-20 | `src/pkcs11_abi/functions.rs` | propagate `login_all` failure; define audit-write failure policy (state agent added `audit.fail_closed`). |
| A3-21 | `tests/fips_approved_mode.rs:277` `#[ignore]` RSA keygen; `tests/zeroization.rs` reads freed memory; `tests/interop/*.sh` default PIN `1234` violates policy and interop tests never run in CI | test owners. |
| A3-22 | root `package.json` (not in my paths) | pin versions + commit a lockfile, or move PDF generation to a pinned container; `html-pdf`/`markdown-pdf` depend on abandoned PhantomJS. I deleted the stale `docs/fips-140-3-certification.pdf`; if a PDF is needed, generate it in CI and attach it to the release. |
| A3-01 | `tests/fips_approved_mode.rs:51,80` | PINs `<redacted-pin>` / `<redacted-pin>` were also used on the (now removed) public remote host — rotate on any real deployment; fine as test data. |

## 4. Not fixable in code (organisational / repository settings)

- Take the public "remote test server" (`<redacted-host>`, A3-01) offline or rotate its PINs; purge `kreya/remote.krenv` from history if required.
- Repository settings required by the new release workflow (documented in docs/release-signing.md): variable `CRATON_HSM_INTEGRITY_PUBLIC_KEY`; environment `release` (required reviewers, tag rule `v*`) with secrets `CRATON_HSM_INTEGRITY_SIGNING_KEY` (+ optional `..._PASSPHRASE`); environment `crates-io` (required reviewers) + crates.io Trusted Publishing for `release.yml`/`crates-io`; delete the old `CARGO_REGISTRY_TOKEN` secret; tag protection (maintainers only, signed tags); branch protection on `main` with required checks `CI` and `Security Audit`; enable GitHub push protection / secret scanning.
- `CLA_TOKEN` must be a fine-grained PAT scoped to `craton-co/cla-signatures` only (A3-10).
- Publish full VCS history or signed annotated tags for past releases; require signed commits (A3-17).
- Create a `security@` alias and publish a PGP key in SECURITY.md (A3-18; SECURITY.md currently falls back to dev@craton.com.ar).
- FIPS: ESV for the entropy source, ACVP on the claimed OEs, CST lab engagement, SP 800-140B formatted SP (A1-02/A1-19; see docs/fips-gap-analysis.md "Organisational items").
- Long-running fuzz campaigns / OSS-Fuzz or ClusterFuzzLite enrolment (A3-13; CI only runs 60 s per target).
- Bit-for-bit reproducibility verification (independent rebuild) — not implemented (A3-11 partial).
- Pin third-party action SHAs are real (verified with `git ls-remote` / `git fetch <sha>`): the previous `taiki-e/install-action@37461a1d...` pin did not exist and was replaced with v2.87.20 `9983c65e...`.

## 5. Merge-conflict notes

- `docs/release-signing.md`: the admin agent inserted a "Module Self-Integrity Signature" section; my rewrite contains that section verbatim (as "## Module self-integrity signature"). Resolve by taking my version.
- `docs/examples.md`: I only changed lines 1-94 (pkcs11-tool/Python/Java PIN handling); the admin agent's CLI-section hunk starts at line 95. Keep both.
- `Cargo.lock`: I did **not** modify it (see §1.1).
- `fuzz/Cargo.lock` regenerated from the pre-merge root lockfile; re-sync after merge (§1.1).
- `docs/postman-grpc-manual-tests.md`, the spy part of `docs/install.md` (section "Using the Spy Wrapper") and `tools/*` untouched by me.

## 6. Mechanical edit outside my paths

- `benches/crypto_bench.rs`: the AWS-LC comparison block referenced the
  non-existent `craton_hsm_awslc` crate unconditionally, so
  `cargo check --workspace --all-targets` (and the new
  `clippy --all-targets` CI step) failed on the original tree. Now uses
  `craton_hsm::crypto::awslc_backend::AwsLcBackend` behind
  `#[cfg(feature = "awslc-backend")]` (commits 4a34e0a, 3c6c91d).
- Verified on the pre-merge tree: `cargo check --workspace --all-targets` OK,
  `cargo +1.89.0 check --workspace` OK, and with
  `-A clippy::not_unsafe_ptr_arg_deref -A clippy::absurd_extreme_comparisons`
  the CI clippy command reports no other correctness/suspicious errors on
  all targets.

## 7. Status per A3 finding (this branch)

| ID | Status |
|---|---|
| A3-01 | Partially fixed: crate `include` list, trufflehog secret scan, .gitignore; kreya/postman are daemon-agent paths; host shutdown not fixable in code |
| A3-02 | Daemon agent |
| A3-03 | Fixed (gated, --locked, all binaries, trusted publishing, protected env) |
| A3-04 | Fixed on the release side (key embedded, .sig produced + verified, tamper smoke test); fail-closed code = crypto agent |
| A3-05 | Fixed in deny.toml/CI; lockfile bump = integrator command §1.1 |
| A3-06 | Fixed (all four deny checks, PR trigger, yanked/unmaintained/unsound/wildcards/duplicates deny); making it a required check = repo setting |
| A3-07 | Fixed (docs, Dependabot security updates, deny skip list); exact pins = crypto agent |
| A3-08 | Fixed (toolchain 1.94.1, MSRV 1.89 + CI job, lint allow removed); Dockerfile builder = §3 |
| A3-09 | Deferred to deploy/daemon owners (§3); Helm lint/template + insecure-config assertions added to CI; docs corrected |
| A3-10 | Fixed (top-level permissions everywhere, all actions SHA-pinned incl. semver-checks and CLA, job-scoped CLA perms, push-only Pages, semver package name); PAT scoping = not fixable |
| A3-11 | Partially fixed (CycloneDX SBOM, SHA256SUMS, cosign bundles, provenance, deterministic tar, path remap, docs match); bit-reproducibility not verified |
| A3-12 | Fixed (NOTICE, THIRD-PARTY-LICENSES + LICENSE/NOTICE in tarballs, ring exception removed); container image = §3 |
| A3-13 | Fixed (crate name, lockfile, PIN provisioning, 60 s CI smoke of all 12 targets, docs) |
| A3-14 | Partially fixed (Miri scope, `-A not_unsafe_ptr_arg_deref` removed); `unsafe extern` = ABI wave 2; ASan job not added |
| A3-15 | Admin agent (scripts removed); docs updated |
| A3-16 | Docs fixed; code (function-list/library version) = ABI agent §3 |
| A3-17 | Partially fixed (CHANGELOG Unreleased + corrections, release tag/CHANGELOG check); history/tags = not fixable |
| A3-18 | Fixed (CODEOWNERS, SECURITY.md policy, GOVERNANCE); security@ + PGP = not fixable |
| A3-19/20/21 | Deferred (§3) |
| A3-22 | Partially fixed (stale PDF removed); package.json = §3 |
| A3-23 | Fixed |
| A3-24 | Docs claims fixed; code nits = crypto agent |
| A3-25 | Admin agent |
| A3-26 | Crypto agent (§3) |
| A3-27 | Partially fixed (protoc pinned in CI); Docker = §3 |
