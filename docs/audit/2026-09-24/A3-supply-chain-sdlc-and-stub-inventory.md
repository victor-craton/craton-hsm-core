# A3 — Supply chain, SDLC, governance & stub inventory

Audited worktree: `/home/user/craton-hsm-audit-wt`. Branch `claude/modest-hamilton-y6ok79`, commit `2f76874` ("Open-source initial commit"). Package `craton-hsm` 0.9.1.
Audit date: 2026-09-24. Auditor role: supply-chain / SDLC certification-readiness reviewer (A3).

---

## Scope, standards & method

**Scope (as assigned):**

- **A. Supply chain & build.** Covers `Cargo.toml` (root, `tools/craton-hsm-admin`, `tools/pkcs11-spy`, `craton-hsm-daemon`, `fuzz`), `Cargo.lock`, `fuzz/Cargo.lock`, `deny.toml`, `rust-toolchain.toml`, both `build.rs` files, `package.json`, `.editorconfig` and `rustfmt.toml`.
- **B. CI/CD & release.** Covers `.github/workflows/{ci,cla,release,security-audit}.yml`, `.github/dependabot.yml`, `CODEOWNERS`, `docs/release-signing.md`, `scripts/*.sh` and `tools/*.sh|*.ps1`.
- **C. Governance & documentation.** Covers these files:
  - `SECURITY.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `CLA.md`, `CODE_OF_CONDUCT.md`, `LICENSE`, `NOTICE`, `ROADMAP.md` and `CHANGELOG.md`.
  - The listed `docs/*.md` files.
  - `.claude/settings.local.json`, `deploy/` and `kreya/`.
  - A repo-wide secret sweep.
- **D. Stub inventory.** A repo-wide sweep for stubs, TODOs, unimplemented code and `unsafe` usage.

**Reference frameworks:**

- **FIPS 140-3 / ISO 19790.** §7.11 life-cycle assurance: configuration management, design, finite state model, development, testing, delivery and operation, and guidance. Also §7.10.2 software/firmware integrity (only where it touches the release pipeline).
- **Common Criteria Part 3 ALC.** ALC_CMC, ALC_CMS, ALC_DEL, ALC_DVS, ALC_FLR, ALC_LCD and ALC_TAT.
- **SLSA v1.0.** Build track L1–L3 and source requirements.
- **OpenSSF Scorecard checks.** Token-Permissions, Pinned-Dependencies, Dangerous-Workflow, Branch-Protection (not observable), Signed-Releases, Packaging, Fuzzing, SAST, Vulnerabilities, Security-Policy, License, Dependency-Update-Tool, CI-Tests and SBOM.
- **NIST SSDF SP 800-218.** Practice groups PO, PS, PW and RV.

**Method and constraints:**

- **No compilation.** Only read-only commands were run:
  - `cargo metadata --format-version 1 --no-deps`.
  - `cargo metadata --format-version 1 --locked`, which downloaded crate metadata. It succeeded, which proves `Cargo.lock` is consistent with the manifests.
  - `cargo tree` (`-d`, `-i`, `-p`).
  - `cargo package --list`.
- **Build context.** A throw-away copy of the Docker build context was created in the scratchpad (manifests only) to check manifest resolution. It has since been deleted.
- **No tracked file was modified.**
- **Evidence** is cited as `file:line`.
- **Confidence levels:**
  - **H** means directly observed in code or config, or reproduced with cargo.
  - **M** means inferred from well-known tool semantics.
  - **L** means an external fact I could not verify offline (for example, RUSTSEC advisory contents).
- **Excluded from sweeps:** the untracked `target-audit-baseline-20260924/` build directory in the worktree. It is not part of the repository.

---

## Overall verdict with rationale

**Verdict: NOT READY. Supply-chain and SDLC controls are "Partial" at best. Several certification-blocking gaps exist in the release pipeline, configuration management and delivery.**

**What works:**

- Most GitHub Actions are SHA-pinned.
- The release job produces keyless cosign signatures and a GitHub build-provenance attestation.
- `Cargo.lock` is committed and consistent (`cargo metadata --locked` succeeded).
- `deny.toml` bans unknown registries and git sources.
- The Dockerfile pins base images by digest.
- `SECURITY.md` exists and uses GitHub private advisories.
- The Helm chart has a strong default security context.

**What falls short of FIPS 140-3 life-cycle assurance, CC ALC_CMC/ALC_DEL/ALC_FLR, SLSA Build L3 and SSDF PS/PW/RV expectations:**

1. **Delivery (ALC_DEL / FIPS §7.11 delivery and operation).** The release workflow is not gated on tests or audits and builds without `--locked`.
   - It builds only the root package, so the admin and daemon binaries it tries to ship are never built.
   - It never embeds the integrity public key or produces the `.sig` sidecar. As a result, **the software-integrity self-test is inert in every shipped binary.**
   - There is no SBOM and no reproducibility. The published signing/verification guide does not match what the workflow produces.
2. **Flaw remediation (ALC_FLR / SSDF RV).**
   - Nine RUSTSEC advisories are suppressed in CI. One suppression rests on a factually wrong justification: RSA-OAEP decryption *is* exposed.
   - Another suppression covers the daemon's mTLS certificate-validation library.
   - The ignore lists are inconsistent between `cargo audit` and `cargo deny`, and the quarterly review is overdue by more than 6 months.
   - The security audit is not a PR or release gate.
3. **Configuration management (ALC_CMC/ALC_CMS).**
   - The whole history is one unsigned squashed commit with no tags. The CHANGELOG describes ten releases with no VCS trace.
   - The toolchain floats (`stable`). The declared MSRV (1.75) is false: `redb 3.1.1` needs 1.89.
   - Production crypto depends on ten pre-release crates. These bring in second copies of SHA-2, SHA-3 and HMAC that the POST KATs never exercise.
4. **Development security and testing (ALC_DVS/ALC_TAT / SSDF PW.7–PW.8).**
   - The fuzz harness does not resolve (`craton_hsm` vs `craton-hsm`).
   - Miri covers 3 pure-Rust tests and none of the 125 `unsafe` blocks.
   - The clippy lint that would flag safe `extern "C"` functions dereferencing raw pointers is explicitly suppressed.
5. **Operational guidance and deployment.**
   - The shipped Dockerfile and Helm chart cannot produce a working, correctly configured deployment. Security settings in the Helm secret are silently ignored.
   - A public IP of a plaintext "remote test server", together with the SO and User PINs, is committed in `kreya/` and in the docs, and ships in the crates.io package.
6. **Documentation accuracy.** At least 40 discrepancies were found between the docs and reality (see table). These include:
   - "PKCS#11 v3.0-compliant": no v3.0 functions exist.
   - An HMAC integrity check that no longer exists.
   - A count of 5 fuzz targets (there are 12).
   - A count of 43 `unsafe` blocks in `functions.rs` (there are 125).
   - Wrong Helm paths and defaults.
   - Incorrect third-party license attribution.

**Severity counts:** Critical 0 · High 6 · Medium 13 · Low 9 · Informational 3 (31 findings).

---

## Readiness matrix

| Control (framework ref) | Status | Evidence | Gap |
|---|---|---|---|
| Source integrity / version history (CC ALC_CMC.3–4, SLSA Source, SSDF PS.1) | Not met | `git log` shows one commit `2f76874`, signature status `N` (unsigned). No tags exist locally. | No traceable history for versions 0.1.0–0.9.1 (CHANGELOG.md:7-209). No signed commits or tags, although GOVERNANCE.md:74 requires signed tags. |
| Configuration item list and CM scope (ALC_CMS) | Partial | `Cargo.lock` committed and consistent (`cargo metadata --locked` OK). | `fuzz/Cargo.lock` is stale (no `craton-hsm`, `redb 2.6.3`). Toolchain unpinned (rust-toolchain.toml:2). The PDF is a generated artifact with no provenance. |
| Toolchain pinning and reproducible build (SLSA Build, FIPS §7.11 dev) | Not met | rust-toolchain.toml:2 `channel = "stable"`. release.yml:42 has no `--locked`, no `--remap-path-prefix` and no SOURCE_DATE_EPOCH. release.yml:91 runs `tar` without deterministic flags. | Builds are neither reproducible nor verifiable by a third party. |
| Declared MSRV accuracy | Not met | Cargo.toml:14 says `rust-version = "1.75"`. The lockfile's `redb 3.1.1` needs 1.89. `libloading 0.9` needs 1.88. `criterion 0.8` needs 1.86. The edition-2024 crates need 1.85. | CI hides the problem with `-A clippy::incompatible_msrv` (ci.yml:148). |
| Dependency vulnerability management (SSDF RV.1, Scorecard Vulnerabilities, ALC_FLR) | Not met | security-audit.yml:43-59 ignores 9 advisories; deny.toml:7 ignores only 1. Comment "last reviewed 2026-03-21" (security-audit.yml:43). | The review is more than 6 months old. The RUSTSEC-2023-0071 justification is false (see A3-05). Checks are not gating (A3-06). |
| Dependency policy enforcement (bans/sources/licenses) | Partial | deny.toml:38-43 denies unknown git sources and registries. | CI runs only `cargo deny check advisories licenses` (security-audit.yml:62), so `bans` and `sources` are never enforced. `multiple-versions = "warn"` (deny.toml:34). |
| Pre-release dependency control | Not met | 10 pre-release crates in Cargo.lock (see A3-07). dependabot.yml:12-16 ignores the PQC crates. | Pre-release primitives are in the module's approved-algorithm path, and no update signal exists for them. |
| Automated dependency updates (Scorecard Dependency-Update-Tool) | Partial | dependabot.yml covers `cargo` at `/` and `github-actions`. | Not covered: `fuzz/`, `package.json` (npm) and `deploy/Dockerfile` (docker). |
| CI test gate (Scorecard CI-Tests, SSDF PW.8) | Partial | ci.yml:64-118 runs all 35 integration test files (verified by diffing `tests/*.rs` against ci.yml). | Doc-tests are not run. `fips` and `awslc-backend` features are never built or tested. Interop scripts are not run. One FIPS-mode test is `#[ignore]` (tests/fips_approved_mode.rs:277). |
| Static analysis (Scorecard SAST, SSDF PW.7) | Partial | Clippy runs with `-D correctness -D suspicious` (ci.yml:146-149). | `-A clippy::not_unsafe_ptr_arg_deref` hides the unsound safe-FFI pattern. No CodeQL or other SAST. Docs claim `-D warnings`. |
| Dynamic analysis: fuzzing (Scorecard Fuzzing, SSDF PW.8) | Not met | 12 fuzz targets exist. | `fuzz/Cargo.toml:13-14` depends on `craton_hsm`, which does not resolve (`cargo tree`: "no matching package found … perhaps you meant: craton-hsm"). Not run in CI. |
| UB detection (Miri/sanitizers) | Not met | ci.yml:184 filters to `crypto::zeroize crypto::digest crypto::integrity`. | `crypto::zeroize` does not exist. `crypto::digest` has no tests. Only 3 `integrity` tests run, and none of them touch `unsafe` code. |
| GitHub token least privilege (Scorecard Token-Permissions) | Not met | No top-level `permissions:` in ci.yml, security-audit.yml or release.yml. | Default token scope applies to every job except `docs` and `github-release`. |
| Action pinning (Scorecard Pinned-Dependencies) | Partial | Most actions are SHA-pinned. | ci.yml:160 uses `obi1kenobi/cargo-semver-checks-action@v2`. cla.yml:20 uses `contributor-assistant/github-action@v2.6.1`, which receives a PAT. Dockerfile:19-21 runs `apt-get install` unpinned. |
| Dangerous workflow patterns | Met (with note) | cla.yml uses `pull_request_target` but does not check out PR code. No `${{ github.event.* }}` appears in `run:`. | A tag-pinned third-party action runs with `secrets.CLA_TOKEN` (cla.yml:22-23). |
| Release signing (Scorecard Signed-Releases, ALC_DEL) | Partial | release.yml:98-105 runs cosign `sign-blob` (keyless). release.yml:107-112 runs `attest-build-provenance`. | The docs describe `.bundle` files, `SHA256SUMS`, per-binary signatures and `--locked`, none of which exist. No documented certificate identity to verify against. |
| Build provenance (SLSA Build L2/L3) | Partial (L2-like) | GitHub-hosted runner with an attestation of the tarballs. | Not an isolated reusable builder (no L3). The attested subjects are repacked tarballs made in a different job from the one that built the binaries. |
| SBOM (SSDF PS.3.2, EO 14028) | Not met | No SBOM step. No `cargo-auditable` or `cargo-cyclonedx`. | Absent. |
| Module integrity key management (FIPS §7.10.2 / §7.11) | Not met | `src/crypto/integrity.rs:39-67` reads `CRATON_HSM_INTEGRITY_PUBLIC_KEY` at build time. release.yml sets neither this variable nor a `.sig`. | Every released binary carries the all-zero placeholder key, and the check is skipped at runtime (integrity.rs:127-142). |
| Release gating (ALC_LCD, GOVERNANCE.md:70-74) | Not met | release.yml triggers on `v*` tags with no `needs:` on CI or audit. `publish-crate` runs in parallel with `github-release`. | The release process described in GOVERNANCE.md is not enforced. |
| Vulnerability disclosure (ALC_FLR.2, Scorecard Security-Policy) | Partial | SECURITY.md:9, :18-22. | No fallback contact or PGP key, no embargo or CVE-assignment policy. Upstream dependency issues are declared out of scope (SECURITY.md:62). "0.8.x supported" has no branch or tag evidence. |
| Code review and ownership (Scorecard Code-Review, CODEOWNERS) | Partial | .github/CODEOWNERS:1-18. | Crypto-team ownership omits `src/token/token.rs`, which GOVERNANCE.md:16 requires. Branch protection cannot be observed from the repo. |
| Licensing and third-party notices | Partial | LICENSE (Apache-2.0) and NOTICE are present. | NOTICE misattributes licenses (A3-12). Release tarballs and the container image ship no LICENSE, NOTICE or third-party texts. |
| Secrets hygiene | Not met | No private keys or API tokens found. | A public test-server IP plus SO/User PINs are committed (kreya/remote.krenv:3-5 and elsewhere) and ship in the crate package. |
| Guidance docs accurate (FIPS §7.11 guidance, CC AGD) | Not met | See the discrepancy table (40+ items). | Install, Helm and verification instructions fail as written. |
| Deployment artifacts (delivery and operation) | Not met | Dockerfile:59 and :69, Helm configmap.yaml:15/:25, deployment.yaml:75-88. | The image cannot be built and the chart's pods cannot start or become Ready (A3-09). |

---

## Findings

### A3-01 [High] Public "remote test server" endpoint and SO/User PINs committed, with TLS validation disabled

- **Location:**
  - `kreya/remote.krenv:3-5` (`server_url` pointing at a public plaintext gRPC host, with `so_pin_b64` and `user_pin_b64`)
  - `kreya/default.krenv:4-5`
  - `kreya/craton-hsm/HsmService/01-InitToken/InitToken-request.json:3`
  - `kreya/craton-hsm/HsmService/03-LoginSO/LoginSO-request.json:4`
  - `kreya/directory.krpref` (`"disableServerCertificateValidation": true`)
  - `docs/postman-grpc-manual-tests.md:20` and `:34-35` (a plaintext PIN table with the SO and User PINs)
  - `tests/fips_approved_mode.rs:51` and `:80`
  - `cargo package --list` shows `kreya/remote.krenv` and `.claude/settings.local.json` inside the crate that would be published.
- **Description:** The repository names a routable public IPv4 host that serves the HSM gRPC API over `http://`, meaning plaintext h2c. It also publishes the base64-encoded SO and User PINs used against that host. The Kreya project disables server-certificate validation globally. The daemon itself refuses plaintext on non-loopback addresses (`craton-hsm-daemon/src/main.rs:168-178`). A plaintext endpoint on a public IP therefore implies a modified build, an older build, or a TLS-stripping proxy — all of which are outside the documented security posture. Because `Cargo.toml` has no `include` or `exclude` list, these files also go to crates.io on `cargo publish` (release.yml:66-69).
- **Impact:**
  - If the host is live, anyone can initialise the token, log in as SO or User, and generate, use or destroy keys on it.
  - The same PINs appear in the test suite, so they are likely reused.
  - Any accredited lab that sees committed credentials plus a disabled-TLS client configuration will record a finding against ALC_DVS and the development environment.
  - Confidence: H for the committed data. The host's reachability was not probed.
- **Recommendation:**
  - Take the host offline or rotate its PINs, and remove `kreya/remote.krenv` from the repository and its history.
  - Replace literal PINs with `{{env}}` variables.
  - Remove `disableServerCertificateValidation`.
  - Add `package.include = ["src/**", "Cargo.toml", "LICENSE", "NOTICE", "README.md", "build.rs"]` to `Cargo.toml`.
  - Add a secret-scanning pre-commit hook and CI job (gitleaks or trufflehog), and enable GitHub push protection.

### A3-02 [High] Daemon `GenerateKey`/`GenerateKeyPair` apply arbitrary caller templates; the forbidden-attribute list is dead code

- **Location:**
  - `craton-hsm-daemon/src/server.rs:328-339`: `#[allow(dead_code)] const FORBIDDEN_TEMPLATE_ATTRS`, documented as "Retained for use when mechanism dispatch is implemented (#20)".
  - `server.rs:703-713`: generic `apply_attribute` loop over the whole template in `generate_key`.
  - `server.rs:894-906`: the same loop for the public and private templates in `generate_key_pair`.
  - `src/store/attributes.rs:482-487`: `CKA_VALUE` replaces `key_material`.
  - `src/store/attributes.rs:421-426`: `CKA_CLASS` and `CKA_KEY_TYPE` are overwritten.
  - Contrast `src/pkcs11_abi/functions.rs:2589-2651` (within `C_GenerateKey`), which applies an explicit whitelist of attributes.
- **Description:**
  - The daemon generates key material with the DRBG, then passes every caller-supplied template attribute through the generic `apply_attribute`.
  - A caller can include `CKA_VALUE` to replace the "generated" key with bytes of its choosing. This bypasses the approved key-generation service while the audit record still reports `GenerateKey … fips_approved`.
  - A caller can also overwrite `CKA_CLASS` or `CKA_KEY_TYPE`, or change `CKA_MODULUS` or `CKA_EC_POINT` on the public half of a pair so that it no longer matches the private half (after the pairwise-consistency test has already run).
  - `CKA_SENSITIVE` and `CKA_EXTRACTABLE` are protected only by the one-way rules in `apply_attribute`.
  - The C ABI path does not have this weakness, so the two interfaces enforce different policies.
- **Impact:**
  - Key-provenance integrity is lost: `CKA_LOCAL` semantics, and keys that look generated but are attacker-chosen.
  - A mismatched public/private key pair can be created.
  - Class confusion may weaken read-access policy on key objects (not fully exercised; confidence M).
  - The daemon is network-facing, and the ports-and-interfaces row of audit-scope.md:170 lists "gRPC API".
  - Confidence: H for the template pass-through; M for downstream exploitability.
- **Recommendation:**
  - Share one template-validation function between the ABI and the daemon, using a whitelist.
  - Reject `CKA_VALUE`, `CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE`, the key-component attributes, and anything in `FORBIDDEN_TEMPLATE_ATTRS` with `CKR_ATTRIBUTE_READ_ONLY` or `TEMPLATE_INCONSISTENT`.
  - Add gRPC negative tests for these cases.

### A3-03 [High] Release pipeline: ungated, not `--locked`, and builds only the root package (admin/daemon never released)

- **Location:**
  - `.github/workflows/release.yml:3-6` (trigger on `v*` tags only)
  - `:41-42` (`cargo build --release --target …`, with no `--locked` and no `--workspace`)
  - `:48-51` (uploads `craton-hsm-admin*` and `craton-hsm-daemon*`)
  - `:54-69` (`publish-crate` runs `needs: build` only, in parallel with `github-release`, with a long-lived `CARGO_REGISTRY_TOKEN`)
  - Root `Cargo.toml:1-2` (workspace with a root package and no `default-members`)
- **Description:**
  - In a workspace whose root manifest has a `[package]`, plain `cargo build` builds only that root package. The admin and daemon binaries are therefore never built, and the upload globs for them match nothing. `actions/upload-artifact` only warns about this.
  - No job depends on CI or on the security-audit workflow.
  - A tag push publishes to crates.io and GitHub Releases with no tests, no `cargo audit`, no `cargo deny` and no tag-to-`Cargo.toml` version check. This contradicts GOVERNANCE.md:70-74.
  - Neither the build nor the publish uses `--locked`.
  - The `build` and `publish-crate` jobs inherit the default token permissions (no top-level `permissions:`).
- **Impact:**
  - The released artifacts are not those that were tested.
  - Lockfile drift can produce a release with dependency versions that were never audited.
  - Operators receive tarballs without the documented daemon or CLI.
  - A compromised or mistaken tag goes straight to crates.io.
  - Confidence: H.
- **Recommendation:**
  - Add `--locked --workspace` to the build (or `-p` for each shipped binary).
  - Add a `verify` job that runs the full test matrix, `cargo audit`, `cargo deny check` (all sections) and a tag-version check, and make every publish job `needs:` it.
  - Move `cargo publish` behind a protected `environment:` with required reviewers, and switch to crates.io trusted publishing (OIDC) instead of a static token.
  - Set top-level `permissions: contents: read`.

### A3-04 [High] Shipped binaries never exercise the FIPS software-integrity test (no build-time public key, no `.sig`, non-`fips` feature set)

- **Location:**
  - `src/crypto/integrity.rs:39-67`: the key comes from `option_env!("CRATON_HSM_INTEGRITY_PUBLIC_KEY")` and falls back to `[0u8; 32]`.
  - `:88-96`: if the module path is unknown, the function returns `Ok(())` even under the `fips` feature, because this happens before the `#[cfg(feature="fips")]` checks.
  - `:127-142`: a missing `.sig` file means the check is skipped in non-fips builds.
  - `.github/workflows/release.yml:41-42`: default features, with neither the environment variable nor a signing step.
  - `tools/sign-integrity.sh` exists but no workflow calls it.
- **Description:**
  - Release builds use default features (`rustcrypto-backend`, not `fips`). They set no integrity public key and produce no `libcraton_hsm.sig`.
  - At `C_Initialize`, the integrity self-test logs "skipping" and passes.
  - The README (lines 26 and 109) and audit-scope.md:79-85 advertise "17 POST self-tests (integrity + 16 KATs)" as protection that is in force.
  - Separately, the `fips`-feature path fails open when `dladdr` or `GetModuleHandleExW` cannot resolve the module path (integrity.rs:88-96).
- **Impact:**
  - FIPS 140-3 §7.10.2 (software/firmware integrity test with an approved technique) is unmet for every delivered artifact.
  - The claim of a runtime integrity check is misleading to operators and labs.
  - Confidence: H.
- **Recommendation:**
  - In release.yml, inject the public key from a protected environment variable, build with `--features fips` for the certified configuration, sign with the private key held in a protected environment or HSM, and ship `.sig` files inside the tarballs.
  - Make an unresolvable module path fail closed under `fips`.
  - Add a release-smoke test that loads the tarball's library and asserts that the integrity self-test *ran*.

### A3-05 [High] Suppressed advisories: false justification for RSA Marvin, mTLS stack advisory ignored, overdue review, inconsistent ignore lists

- **Location:**
  - `deny.toml:5-7`: "We mitigate by not exposing raw RSA decryption".
  - `.github/workflows/security-audit.yml:43-59`: nine `--ignore` flags, with "last reviewed 2026-03-21" and "review quarterly".
  - `scripts/ci-local.sh:122-131` and `scripts/local-ci.sh:136-146` duplicate the list.
  - RSA-OAEP decryption is reachable from `C_Decrypt` via `src/pkcs11_abi/functions.rs:1878-1887` → `src/crypto/rustcrypto_backend.rs:222-228` → `src/crypto/sign.rs:422` (`rsa::Oaep`).
  - Lockfile: `rsa 0.9.10`, `rustls-webpki 0.103.10`, `rustls-pemfile 2.2.0`.
  - The daemon uses `WebPkiClientVerifier` with CRLs (`craton-hsm-daemon/src/tls.rs:14`, `:70-74`).
- **Description:**
  - **RUSTSEC-2023-0071 (Marvin timing side channel in `rsa`).** It is suppressed on the grounds that raw RSA decryption is not exposed. However, `CKM_RSA_PKCS_OAEP` decryption with the `rsa` crate *is* exposed through the PKCS#11 ABI, and the daemon's Decrypt RPC also exists. The mitigation claim is false.
  - **RUSTSEC-2026-0049 (rustls-webpki).** It is suppressed as "update pending". rustls-webpki is the library that validates client certificates and CRLs for the daemon's mTLS. I could not retrieve the advisory text offline (confidence L on its specifics), but ignoring any advisory on the authentication library of a network-facing HSM needs a written risk acceptance.
  - **RUSTSEC-2025-0134** (rustls-pemfile, marked unmaintained) is also ignored.
  - **Inconsistent lists.** `cargo deny` ignores only one advisory, so it will fail on any advisory that `cargo audit` ignores and that is present in the default-feature graph. Either the job is permanently red or someone is not looking at it.
  - **Overdue review.** The last review date is more than six months before this audit, against a stated quarterly cadence.
- **Impact:**
  - ALC_FLR and SSDF RV.2 require tracked, justified and time-bound risk acceptance. What exists is undocumented, stale and partly incorrect.
  - The certification lab will treat RUSTSEC-2023-0071 as an open side-channel issue in an approved service.
  - Confidence: H for the exposure and the inconsistency; L for the content of the 2026 advisories.
- **Recommendation:**
  - Keep a single source of truth: a `deny.toml` `[advisories] ignore` entry with a `reason` and an expiry for each advisory. Drop the `cargo audit --ignore` flags or generate them from that file.
  - Remove the false Marvin statement. Either disable RSA decryption under the `rsa` crate in FIPS or approved mode (route it to aws-lc) or document the residual risk.
  - Upgrade `rustls-webpki`, and replace `rustls-pemfile` with `rustls-pki-types` PEM parsing.
  - Add a scheduled issue or reminder for advisory review.

### A3-06 [Medium] Security checks are advisory only; `cargo deny` bans/sources never enforced

- **Location:**
  - `.github/workflows/security-audit.yml:5-15`: schedule and push-to-main only, when manifest paths change. No `pull_request` trigger.
  - `:62`: `cargo deny check advisories licenses`.
  - `deny.toml:32-36`: `multiple-versions = "warn"`, no `deny` list, no `wildcards` rule.
  - `deny.toml:38-43`: sources are configured but never checked.
- **Description:**
  - Dependency and Dependabot PRs merge without an audit gate.
  - The `sources` policy (no git or unknown registries) and the `bans` policy are never evaluated, so the good configuration at deny.toml:40-43 has no effect.
  - There is no `yanked = "deny"` setting and no explicit `unmaintained` policy.
- **Impact:** A malicious or vulnerable dependency can land on `main` and in a release between weekly runs. This fails SSDF PW.4/RV.1 and Scorecard "Vulnerabilities". Confidence: H.
- **Recommendation:**
  - Run `cargo deny check` (all sections) and `cargo audit` on every PR and in the release `verify` job.
  - Set `multiple-versions = "deny"` with an explicit `skip` list, `wildcards = "deny"` and `yanked = "deny"`.
  - Make the job a required status check.

### A3-07 [Medium] Pre-release cryptographic crates in the approved path; duplicate SHA-2/SHA-3/HMAC implementations not covered by KATs; updates suppressed

- **Location:**
  - `Cargo.toml:48-50`: `ml-kem 0.3.0-rc.0`, `ml-dsa 0.1.0-rc.7`, `slh-dsa 0.2.0-rc.4`.
  - Transitive pre-release crates in Cargo.lock: `hmac 0.13.0-rc.6`, `sha2 0.11.0-rc.5`, `sha3 0.11.0-rc.9`, `signature 3.0.0-rc.10`, `pkcs8 0.11.0-rc.11`, `spki 0.8.0-rc.4` and `kem 0.3.0-rc.6`.
  - `cargo tree -i sha3@0.11.0-rc.9` shows `ml-dsa`, `ml-kem` and `slh-dsa` as dependents. `sha2@0.11.0-rc.5` and `hmac@0.13.0-rc.6` come from `slh-dsa`.
  - 23 crates have duplicate versions, including digest, sha2, sha3, hmac, keccak, cipher, der, pkcs8, spki, signature, rand_core ×2, getrandom ×3 and windows-sys ×3.
  - `.github/dependabot.yml:12-16` ignores the three PQC crates entirely.
  - `Cargo.toml:56` has a TODO about the aliases.
- **Description:**
  - Release candidates carry no API or security stability guarantee, and none of their versions have CAVP validation.
  - The PQC algorithms hash with a *different* SHA-3 (and, for SLH-DSA, SHA-2 and HMAC) implementation than the one the POST KATs test (`sha2 0.10`, `sha3 0.10`). The PQC POST entries are also roundtrips rather than KATs (docs/audit-scope.md:98-99), and there is no SLH-DSA entry.
  - Dependabot's ignore rule removes version-update PRs, and may also suppress security-update PRs for these crates (confidence M).
- **Impact:**
  - A lab cannot map these algorithm implementations to validated ones.
  - Self-test coverage has a hole: the SHA-3 inside ML-DSA and ML-KEM is never KAT'd.
  - Supply-chain churn is high.
  - Confidence: H.
- **Recommendation:**
  - Exclude PQC from the certified configuration (as fips-mode-guide.md suggests), or pin exact versions with `=`.
  - Add PQC KATs using the NIST ACVP vectors.
  - Replace the Dependabot `ignore` with `update-types: ["version-update:semver-major"]` so that security updates still flow.
  - Track the duplicate versions with a deny `skip` list and an owner.

### A3-08 [Medium] Toolchain unpinned and declared MSRV false; Docker builder too old for the lockfile

- **Location:**
  - `rust-toolchain.toml:2` (`channel = "stable"`).
  - `Cargo.toml:14` (`rust-version = "1.75"`).
  - `cargo metadata` `rust_version` values: `redb 3.1.1` = 1.89, `libloading 0.9.0` = 1.88, `criterion 0.8.2` = 1.86; many edition-2024 crates = 1.85.
  - `.github/workflows/ci.yml:148` (`-A clippy::incompatible_msrv`).
  - `deploy/Dockerfile:16` (`rust:1.83-bookworm`), where `rust-toolchain.toml` is not copied into the build context.
  - CONTRIBUTING.md:9 and docs/install.md:7 ("Rust 1.75+").
- **Description:**
  - Every CI or release run uses whatever `stable` is on that day.
  - The published MSRV is wrong by 14 minor versions, and the clippy lint that would detect this is disabled.
  - The Dockerfile's 1.83 toolchain cannot build `redb 3.1.1` or the edition-2024 crates under `--locked`, so the image build fails.
- **Impact:** FIPS §7.11 and ALC_CMC expect the development tools, and their versions, to be under configuration management. The build is non-reproducible and the documented prerequisites are wrong. Confidence: H.
- **Recommendation:**
  - Pin an exact toolchain (for example `channel = "1.89.0"`) and update it deliberately.
  - Set `rust-version` to the true minimum and add an MSRV CI job.
  - Remove `-A clippy::incompatible_msrv`.
  - Base the Docker builder on the pinned version.

### A3-09 [Medium] Container and Helm deliverables cannot produce a working, correctly configured deployment

- **Location and description:**
  - `deploy/Dockerfile:59`: `COPY craton_hsm.toml craton_hsm.toml`, but no such file is tracked (`git ls-files` finds nothing), so the build fails.
  - `Dockerfile:69`: `cargo test --release -p craton_hsm`. The package is `craton-hsm`, and `cargo tree -p craton_hsm` reports "did not match any packages", so this step fails too.
  - `Dockerfile:119-120` and `deploy/helm/craton-hsm/templates/deployment.yaml:75-88`: `grpc_health_probe` and the kubelet gRPC probes call `grpc.health.v1.Health`. The daemon registers no health service (`grep -rn health craton-hsm-daemon` finds only a DRBG message). Kubelet gRPC probes also do not speak TLS, while the chart enables TLS by default (`values.yaml:21`). Pods never become Ready.
  - `templates/configmap.yaml:15` and `:25`: `storage_path` is `"/data/craton-hsm_store"` and `log_path` is `"/data/craton-hsm_audit.jsonl"`. Config validation rejects absolute paths (`src/config/config.rs:292-301`, `:540-549`), and the daemon exits during startup (`craton-hsm-daemon/src/main.rs:69-76`).
  - `templates/secret-security.yaml:9-13`: `security.toml` (`pin_min_length`, `max_failed_logins = 5`) is mounted at `/etc/craton-hsm/security`, but no code loads it. `HsmConfig` reads `[security]` only from the main file (`src/config/config.rs:37-45`). The effective lockout threshold is therefore the default 10 (`config.rs:202-204`), not the configured 5. **The security configuration is silently ignored.**
  - The configmap does not set `persist_objects`, which defaults to `false` (`config.rs:61-62`, `:144`). Keys are lost on restart despite the PVC.
  - `craton-hsm-daemon/src/main.rs:205-208`: `shutdown_signal()` awaits only `ctrl_c()` (SIGINT). Kubernetes and Docker send SIGTERM, so connections are not drained gracefully.
  - `Dockerfile:74-86`: `grpc_health_probe` is verified only against a checksum file from the same origin. That protects against transport corruption, not against a compromised release.
- **Impact:** The delivery-and-operation guidance cannot be followed. Operators who work around the failures (for example, by hand-editing config) get weaker security settings than they configured. Confidence: H, except the SIGTERM point (M).
- **Recommendation:**
  - Commit a sample config and fix the package name.
  - Implement `tonic-health` and use `exec` probes, or a plaintext loopback health port.
  - Merge the security settings into the main config file, or add an include mechanism.
  - Set `persist_objects = true` when persistence is enabled.
  - Handle SIGTERM.
  - Add a CI job that runs `docker build`, `helm lint` and `helm template`, and a kind smoke test.

### A3-10 [Medium] GitHub Actions hardening gaps

- **Location:**
  - No top-level `permissions:` in `ci.yml`, `security-audit.yml` or `release.yml`.
  - `ci.yml:160`: `obi1kenobi/cargo-semver-checks-action@v2`, tag-pinned.
  - `cla.yml:20`: `contributor-assistant/github-action@v2.6.1`, tag-pinned, running under `pull_request_target` (`cla.yml:4-6`) with `actions: write` and `statuses: write` (`cla.yml:8-12`) and `PERSONAL_ACCESS_TOKEN: ${{ secrets.CLA_TOKEN }}` (`cla.yml:23`).
  - `ci.yml:226-232`: the `docs` job requests `pages: write`, `id-token: write` and `environment: github-pages` on every PR run.
  - `ci.yml:268`: Pages deployment is `continue-on-error`.
  - `ci.yml:162-163`: semver check has `package: craton_hsm` (wrong name) and `continue-on-error`, so it can never report.
- **Description:**
  - Jobs without an explicit permissions block get the repository's default token scope, which may be read/write.
  - A mutable tag on a third-party action that receives a PAT in a `pull_request_target` context is a well-known supply-chain vector (compare the tj-actions/changed-files incident of 2025).
  - No script injection was found: no `${{ github.event.* }}` is used in any `run:` step.
- **Impact:** The OpenSSF Scorecard checks Token-Permissions and Pinned-Dependencies would fail. The blast radius of a compromised action includes the CLA signature repository and the PAT's scopes. Confidence: H.
- **Recommendation:**
  - Add `permissions: {contents: read}` at the top of every workflow and grant more per job.
  - SHA-pin all actions (Dependabot already tracks actions).
  - Scope `CLA_TOKEN` to the signature repository only, as a fine-grained PAT.
  - Split docs deployment into a `push`-only job.
  - Correct the semver package name.
  - Add `harden-runner` or an egress policy to the release jobs.

### A3-11 [Medium] No SBOM, non-reproducible artifacts, and release verification docs don't match the workflow

- **Location:**
  - `.github/workflows/release.yml:87-93`: `tar czf` with no `--sort=name --mtime --owner=0 --group=0 --numeric-owner`. The tarball contains binaries only, with no LICENSE, NOTICE or SBOM.
  - `release.yml:98-105`: outputs are `.sig` and `.pem`.
  - `docs/release-signing.md:13`, `:37`, `:59-66`, `:99-115` and `:125-136` describe `--locked`, per-binary `.bundle` files, a `SHA256SUMS` file and a raw `libcraton_hsm.so` download URL. The workflow produces tarballs, `checksums-sha256.txt`, `.sig` and `.pem`.
  - `release-signing.md:131` gives `--certificate-identity <release-identity>` as a placeholder with no concrete workflow identity.
  - `:147-149` claims "signed commits" and "Reproducible builds with `--locked`".
  - `:141` claims the POST KATs detect a corrupted binary.
- **Description:**
  - Users cannot follow the published verification procedure: the files it names do not exist, and there is no identity to pin.
  - KATs verify algorithm correctness, not binary integrity, so the §141 claim is misleading.
  - No SBOM is generated (SPDX or CycloneDX, `cargo auditable`).
  - Builds embed runner paths and are not bit-reproducible.
- **Impact:** Delivery procedures (ALC_DEL.1) are unverifiable. SSDF PS.3.2 and SBOM expectations are unmet. Confidence: H.
- **Recommendation:**
  - Generate a CycloneDX SBOM (`cargo cyclonedx`) and build with `cargo auditable`. Attest the SBOM with `actions/attest-sbom`.
  - Use deterministic `tar`, `--remap-path-prefix` and `SOURCE_DATE_EPOCH`.
  - Switch to `cosign sign-blob --bundle`.
  - Document the exact `--certificate-identity-regexp '^https://github.com/craton-co/craton-hsm-core/.github/workflows/release.yml@refs/tags/v'` and `--certificate-oidc-issuer https://token.actions.githubusercontent.com`, plus `gh attestation verify`.
  - Include LICENSE, NOTICE and THIRD-PARTY-LICENSES in every tarball.

### A3-12 [Medium] Third-party license attribution is incorrect and incomplete; binary distributions ship no notices

- **Location:**
  - `NOTICE:30-32` lists `ed25519-dalek` and `subtle` under "RustCrypto project … Apache-2.0 / MIT". Lockfile metadata: `ed25519-dalek 2.2.0`, `subtle 2.6.1` and `curve25519-dalek 4.1.3` are **BSD-3-Clause** (the dalek-cryptography project).
  - `NOTICE:42` says "tonic, prost (gRPC): MIT". `prost 0.14.3` and `prost-types` are **Apache-2.0**.
  - Not mentioned at all:
    - ISC: `libloading`, `rustls-webpki`, `untrusted`, `ring` (Apache-2.0 AND ISC).
    - `aws-lc-sys` (a multi-license expression including BSD-3-Clause and ISC).
    - Unicode-3.0: `unicode-ident`.
    - Zlib: `foldhash`.
    - `matchit` (MIT AND BSD-3-Clause).
  - `NOTICE:25-26`, `README.md:30`, `:101` and `:116` say the aws-lc-rs backend is available "separately in the craton_hsm-enterprise repository under BSL 1.1". Yet `src/crypto/awslc_backend.rs` and the `awslc-backend` feature (`Cargo.toml:22`, `:92`) are in *this* Apache-2.0 repo. The repository names are also inconsistent (`craton_hsm-enterprise` in Cargo.toml:107-109, `craton-hsm-core-enterprise` in README.md).
  - `deploy/.dockerignore` excludes `LICENSE*` and `*.md`, so the container image carries no license texts.
  - `deny.toml:27-30` has a `ring` exception mentioning the OpenSSL license, which is obsolete for `ring 0.17` (license `Apache-2.0 AND ISC`).
- **Impact:**
  - BSD-3-Clause and ISC require the copyright notice to be reproduced in binary distributions. The current releases (tarballs and image) do not comply.
  - The NOTICE file is inaccurate evidence for a lab.
  - Confidence: H.
- **Recommendation:**
  - Generate `THIRD-PARTY-LICENSES` with `cargo about` or `cargo-bundle-licenses` in CI and ship it in every artifact.
  - Correct NOTICE.
  - Clarify the licensing of `awslc_backend.rs` and the repository naming.

### A3-13 [Medium] Fuzzing infrastructure is non-functional and not run

- **Location:**
  - `fuzz/Cargo.toml:13-14`: `[dependencies.craton_hsm] path = ".."`. Running `cargo tree` in `fuzz/` fails with "no matching package found, searched package name: `craton_hsm`, perhaps you meant: craton-hsm".
  - `fuzz/Cargo.lock` contains no `craton-hsm` entry and pins `redb 2.6.3` against the root's `redb 3.1.1`.
  - No fuzz job exists in CI.
  - Dependabot does not cover `fuzz/`.
  - Several targets log in with `b"1234"` and never call `C_InitToken`/`C_InitPIN`: `fuzz/fuzz_targets/fuzz_keygen.rs:80`, `fuzz_derive_key.rs:61`, `fuzz_multipart_crypto.rs:61`, `fuzz_rsa_ops.rs:52`, `fuzz_set_attribute.rs:62` and `fuzz_wrap_unwrap.rs:60`. The default `pin_min_length` is 8 (`src/config/config.rs:196-198`).
  - Docs claim 5 targets with "1 hour minimum" each (`docs/security-review-checklist.md:23`, `:46-54`, `docs/audit-scope.md:139-147`). There are 12.
- **Description:** The harness cannot compile as committed. Even once fixed, the authenticated key-generation and crypto paths are likely unreachable because the login fails. That second point is confidence M: it depends on the per-mechanism login requirements.
- **Impact:** The ALC_TAT and SSDF PW.8 fuzzing evidence is void. Scorecard's Fuzzing check would pass on file presence alone, which is misleading. Confidence: H for the resolution failure.
- **Recommendation:**
  - Rename the dependency (`craton-hsm = { path = ".." }`) and regenerate `fuzz/Cargo.lock`.
  - Initialise the token with PINs that satisfy the policy.
  - Add a CI smoke-fuzz job (for example 60 s per target) and a nightly long run, or apply for OSS-Fuzz or ClusterFuzzLite.
  - Correct the docs.

### A3-14 [Medium] UB tooling coverage is illusory, and a lint that would flag unsound FFI signatures is suppressed

- **Location:**
  - `.github/workflows/ci.yml:184` and `scripts/*.sh`: `cargo +nightly miri test --lib -- … crypto::zeroize crypto::digest crypto::integrity`.
  - `src/crypto/mod.rs:3-20` contains no `zeroize` module.
  - `src/crypto/digest.rs` has no `#[test]`.
  - Only `src/crypto/integrity.rs` has tests (4, with one skipped under Miri at `:346`).
  - `ci.yml:149` has `-A clippy::not_unsafe_ptr_arg_deref`.
  - The 68 `pub extern "C" fn C_*` in `src/pkcs11_abi/functions.rs` are safe functions that dereference raw pointers (125 `unsafe {}` blocks, 16 `SAFETY` comments).
- **Description:**
  - Miri effectively runs three tests: file SHA-256 hashing and an Ed25519 roundtrip. None of them touch `unsafe` code.
  - The FFI entry points are declared as safe Rust functions while dereferencing caller pointers. Any Rust caller (tests, benches, fuzz targets, the daemon) can therefore trigger UB from safe code. Clippy flags exactly this pattern, and the CI explicitly silences it.
  - No sanitizer (ASan, MSan or TSan) job exists, although the checklist recommends one.
- **Impact:** The claims "Miri (Undefined Behavior Check)" and "Review all 43 unsafe blocks" do not hold. ALC_TAT evidence is overstated. Confidence: H.
- **Recommendation:**
  - Run Miri on real ABI-level unit tests (the `functions.rs` helpers such as `parse_template`, and `digest.rs` zeroization).
  - Mark the exported functions `pub unsafe extern "C" fn`, or keep them safe but wrap the raw access in audited helpers, and remove the `-A`.
  - Add an ASan job for the integration tests.
  - Require a `// SAFETY:` comment on every block, enforced with `clippy::undocumented_unsafe_blocks`.

### A3-15 [Medium] `compute-integrity-hmac.sh` leaks the HMAC key through process arguments, contrary to its own comments

- **Location:**
  - `tools/compute-integrity-hmac.sh:215-219`, `:232-236`: `openssl dgst -sha256 -mac HMAC -macopt "hexkey:${HMAC_KEY_HEX}" "$LIB_PATH"`.
  - `:228` comment: "so we can use -macopt hexkey: (key never in argv)".
  - `:199`: key-file branch condition `[ -n "${1:-}" ] && [ -f "${2:-}" ]`.
- **Description:**
  - `-macopt hexkey:<key>` *is* a command-line argument, visible in `/proc/<pid>/cmdline` and `ps` to other local users.
  - The comments claim the opposite.
  - The HMAC integrity mechanism was removed from the module (integrity.rs:100-107 says "The HMAC-based check has been removed"), yet the scripts (`.sh` and `.ps1`) and the CHANGELOG (lines 113-114) still present it.
- **Impact:** Anyone following the tooling guidance exposes key material on shared build hosts. Dead security tooling also confuses the lab about which mechanism is certified. Confidence: H.
- **Recommendation:** Delete `tools/compute-integrity-hmac.{sh,ps1}`. If an HMAC tool is ever needed, pass the key through `-macopt hexkey:` read from a file descriptor (`openssl mac -macopt hexkey:$(…)` is also argv), or through `openssl mac` with `-in` and an environment variable, and test it with `ps`.

### A3-16 [Medium] "PKCS#11 v3.0" identity claims vs a v2.40 function set; module version reported as 0.1

- **Location:**
  - The 68 exported functions (`src/pkcs11_abi/functions.rs`) are exactly the v2.40 set. None of `C_GetInterfaceList`, `C_GetInterface`, `C_LoginUser`, `C_SessionCancel`, `C_Message*` or `C_*Message*` exist.
  - `functions.rs:5459-5460`: `static FUNCTION_LIST: CK_FUNCTION_LIST = { version: CK_VERSION { major: 3, minor: 0 }, … }`, which is a v2.40-layout struct (`src/pkcs11_abi/types.rs:358-427`).
  - `functions.rs:320`: `cryptoki_version` 3.0.
  - `functions.rs:324`, `:422-423` and `:468-469`: `library_version`, `hardware_version` and `firmware_version` are all `0.1`, while the crate is 0.9.1.
  - Claims in `Cargo.toml:8`, `README.md:13`, `:17`, `docs/faq.md:37`, `docs/PRESENTATION.md:7` and `deploy/Dockerfile:96`.
- **Description:**
  - A consumer that sees `version.major == 3` in the function list may treat it as a `CK_FUNCTION_LIST_3_0` and read past the end of the struct. Confidence M: this depends on the consumer.
  - The module reports version 0.1 through `C_GetInfo` and `C_GetTokenInfo`, so it cannot be identified by version. FIPS 140-3 requires the module to output its name and version.
- **Impact:** Compliance claims are false. Module version identification, which ties the security policy to the binary, is wrong. There is possible interoperability or memory-safety risk in consumers. Confidence: H for the facts.
- **Recommendation:**
  - Report `CK_FUNCTION_LIST.version = 2.40` until the 3.0 interfaces exist, or implement `C_GetInterface` with a proper `CK_FUNCTION_LIST_3_0`.
  - Derive `library_version` from `CARGO_PKG_VERSION_MAJOR/MINOR` at build time.
  - Correct the documentation.

### A3-17 [Low] Configuration-management and versioning inconsistencies

- **Location:**
  - The single unsigned commit `2f76874` with no tags (`git tag` is empty; remote tags were not fetched, confidence M).
  - `CHANGELOG.md:23` and `:113-114`: `.hmac` integrity, where the current code uses `.sig`/Ed25519. No Unreleased section records the migration.
  - `CHANGELOG.md:77` claims `#![forbid(unsafe_code)]` on store. `src/store/mod.rs:7` has `#![deny(unsafe_code)]` with a targeted allow at `src/store/encrypted_store.rs:307`.
  - `CHANGELOG.md:51` says "Version synchronized across all workspace crates (0.9.0 / 0.3.0)". The sub-crates are still at 0.3.0 while the core is at 0.9.1, and CHANGELOG entries do not track the sub-crates separately.
  - `CHANGELOG.md:48` versus `:83`: release 0.9.0, dated 2026-02-24, states facts "as of March 2026".
  - `ROADMAP.md:48` says "v0.9.1 released", with no tag to back it.
  - The Helm `Chart.yaml` and `Dockerfile:97` hard-code 0.9.1.
- **Impact:** ALC_CMC requires unique identification of every configuration item and release. At present, releases cannot be traced to source. Confidence: H.
- **Recommendation:**
  - Publish full history, or at least signed annotated tags per release.
  - Require signed commits.
  - Generate version strings from `Cargo.toml`.
  - Keep an Unreleased section.

### A3-18 [Low] Governance documents and enforcement are misaligned

- **Location:**
  - `GOVERNANCE.md:16`: crypto reviewers own `src/token/token.rs`. `.github/CODEOWNERS:5-7` assigns only `/src/crypto/` and `key_material.rs` to `@craton-co/craton_hsm-crypto`.
  - `GOVERNANCE.md:65` says "Security fixes are backported to all supported versions", while `SECURITY.md:37` lists 0.8.x as supported. There is no branch or tag evidence for 0.8.x.
  - `SECURITY.md` has no fallback contact (email or PGP), no embargo or CVE-assignment policy and no severity model. It puts upstream dependency vulnerabilities out of scope (`:62`), although dependency advisories are the module's problem too (compare A3-05).
  - `GOVERNANCE.md:70-74` lists release gates (audit and deny pass, signed tags) that are not enforced (A3-03).
  - `CODE_OF_CONDUCT.md:39` uses the enforcement contact `dev@craton.com.ar`. There is no security contact in the same domain.
- **Impact:** Weak ALC_FLR.2/3 evidence (flaw-reporting procedure and timely remediation). Confidence: H.
- **Recommendation:**
  - Align CODEOWNERS with GOVERNANCE, adding `src/token/`, `src/pkcs11_abi/` for the crypto team, and `craton-hsm-daemon/` and `deploy/`.
  - Add a `security@` alias with a PGP key and an embargo and CVE policy.
  - Either maintain 0.8.x or drop it from the supported table.

### A3-19 [Low] Library aborts the host process on DRBG failure

- **Location:** `src/crypto/drbg.rs:274-298` (`std::process::abort()`) and `src/crypto/pqc.rs:43-66` (three aborts).
- **Description:** A PKCS#11 shared library runs inside third-party processes such as a JVM, OpenSSL or a web server. On a DRBG health-test failure it kills the whole host process instead of entering the documented error state, where operations return `CKR_GENERAL_ERROR` or `CKR_FUNCTION_FAILED`. The comments cite FIPS §7.3 "enter an error state", which the module-level error state already provides, as `POST_FAILED` does elsewhere.
- **Impact:** A denial of service to the host application. The finite state model documentation (error state) does not match the implementation. Confidence: H.
- **Recommendation:** Latch a global error state and return errors from all services. Use `TryRng` with a real error type for the PQC path instead of `Infallible` plus abort.

### A3-20 [Low] Silently discarded results in security-relevant paths

- **Location:**
  - `src/pkcs11_abi/functions.rs:932`: `let _ = hsm.session_manager.login_all(slot_id, user_type);` after a successful `token.login`.
  - 23 occurrences of `let _ = hsm.audit_log.record(...)` in `functions.rs` (`grep -c`).
- **Description:**
  - If the session-state transition fails and is rolled back (`src/session/manager.rs:166-176`), `C_Login` still returns `CKR_OK` with the token logged in but the sessions not.
  - Audit-log write failures are ignored on the ABI path. The daemon, by contrast, propagates them (`craton-hsm-daemon/src/server.rs:471`).
- **Impact:** Inconsistent authentication state, and loss of audit records without any indication. FIPS 140-3 and CC FAU expectations call for audit failure handling. Confidence: H.
- **Recommendation:** Propagate `login_all` errors (log the token out on failure). Define a policy for audit write failure, either fail-closed or latch an error, and apply it consistently.

### A3-21 [Low] Test and documentation evidence that would not survive lab scrutiny

- **Location and description:**
  - `tests/zeroization.rs:148-230`: after `drop`, the tests read freed heap memory. The comment calls this "UB in strict terms". CI runs them in the parallel group (`ci.yml:71`, `--test-threads=8`), which increases the chance of allocator reuse and flakiness.
  - `tests/fips_approved_mode.rs:277`: `#[ignore = "RSA keygen returns CKR_MECHANISM_PARAM_INVALID — needs investigation"]`. This hides a known defect in approved-mode RSA key generation through the ABI.
  - `tests/interop/java_sunpkcs11.sh:65` and `openssl_pkcs11.sh:68`: the default `USER_PIN=1234` is below the default minimum of 8, so the scripts fail out of the box.
  - `java_sunpkcs11.sh:457`: the temp directory is intentionally left behind.
  - No interop test runs in CI.
- **Impact:** Weak zeroization and interop evidence, plus an untracked functional defect. Confidence: H for the facts. Whether the RSA test still fails is unknown, because the tests were not run.
- **Recommendation:**
  - Replace the post-free reads with a custom zero-checking allocator or instrumentation.
  - Triage the ignored FIPS test into an issue and link it.
  - Fix the interop defaults and run them in a scheduled job.

### A3-22 [Low] Documentation-build tooling is unmaintained and unpinned; generated PDF committed

- **Location:**
  - `package.json`: `html-pdf ^3.0.1`, `markdown-pdf ^11.0.0`, `marked ^17.0.4`.
  - There is no `package-lock.json`, and `.gitignore:23` ignores `bun.lock`.
  - `docs/fips-140-3-certification.pdf` is 246,895 bytes.
- **Description:**
  - `html-pdf` and `markdown-pdf` depend on the abandoned PhantomJS.
  - `html-pdf` is deprecated and has public advisories for local file read or SSRF when rendering untrusted HTML. Confidence M; verify with `npm audit`.
  - Ranges are unpinned with no lockfile.
  - The committed PDF has no recorded generator or source hash, so it may drift from the `.md` source.
- **Impact:** A minor supply-chain risk on documentation builds. The certification document of record lacks provenance. Confidence: M.
- **Recommendation:** Commit a lockfile or move to a maintained renderer (for example pandoc or typst in a pinned container). Generate the PDF in CI and attach its hash to the release.

### A3-23 [Low] Committed local agent settings; crate package ships non-source content

- **Location:**
  - `.claude/settings.local.json`: local tool-permission allow-list.
  - `cargo package --list` includes `.claude/`, `.github/`, `deploy/`, `kreya/`, `docs/*.pdf`, `fuzz/`, `tests/` and similar.
  - `Cargo.toml` has no `include` or `exclude`.
- **Description:** `*.local.json` files are per-developer by convention and should be git-ignored. Everything tracked goes to crates.io, including the A3-01 data.
- **Impact:** Information leakage and larger packages. Confidence: H.
- **Recommendation:** Git-ignore `.claude/*.local.json` and remove the file. Add `package.include`.

### A3-24 [Low] `unsafe` code documentation and soundness nits outside the ABI layer

- **Location:**
  - `src/crypto/digest.rs:150-175`. The `SAFETY` comment item 5 cites "the compile-time size assertion above", but the code uses `debug_assert!`, which runs only at runtime in debug builds and not at all in release.
  - The same code builds `&mut [u8]` over an arbitrary hasher type `D`. If `D` contains padding (uninitialised bytes), creating that reference is UB under current Rust rules. Confidence M: it depends on the concrete types.
  - `src/crypto/awslc_backend.rs:962-964`: `unsafe impl Send/Sync for AwsLcHasher` with the comment "digest::Context is Send+Sync". If that is true, the impl is unnecessary. If false, it is unsound.
  - `src/crypto/integrity.rs:273-277` and `:296-313`: five `unsafe` blocks, none with a `SAFETY` comment.
  - CONTRIBUTING.md:93 and PRESENTATION.md:12, :106 and :374 claim zero `unsafe` in crypto paths, which contradicts these blocks.
- **Impact:** Minor soundness risk, and inaccurate assurance claims. Confidence: H for the facts.
- **Recommendation:**
  - Use `const { assert!(size_of::<D>() <= 512) }`, or zeroize through `write_bytes` on a `MaybeUninit` view.
  - Remove the redundant `unsafe impl`s (the compiler will say whether they are needed).
  - Add `SAFETY` comments.
  - Correct the claims.

### A3-25 [Low] Duplicate and diverging local-CI scripts

- **Location:**
  - `scripts/ci-local.sh` and `scripts/local-ci.sh` both claim to mirror ci.yml.
  - `ci-local.sh:104-112` runs clippy with no `-D` flags and treats it as non-blocking, while `local-ci.sh:97-100` uses the CI flags.
  - `ci-local.sh:170` and `local-ci.sh:109` use different package names (`craton_hsm` vs `craton-hsm`).
  - `local-ci.sh:16` says "Clippy lint with -D warnings", which is false.
  - `ci-local.sh` lacks an SPDX header.
- **Impact:** Developers get inconsistent pre-push results. Confidence: H.
- **Recommendation:** Keep one script, generated from or kept identical to ci.yml.

### A3-26 [Informational] Unused direct dependencies and library-imposed tracing caps

- **Location:**
  - `Cargo.toml:37`: `cipher = "0.5"`. The source uses only `cbc::cipher` (0.4) and aws-lc's `cipher` module.
  - `Cargo.toml:62`: `secrecy = "0.10"`. No `secrecy::` use in `src/`.
  - `Cargo.toml:75`: `tracing` features `max_level_info` and `release_max_level_info` on a library. Cargo feature unification imposes these caps on every consumer and workspace binary.
- **Recommendation:** Remove unused dependencies (add `cargo machete` or `cargo udeps` to CI). Move the tracing level caps to the binaries.

### A3-27 [Informational] Build scripts

- **Location:** `build.rs:3-8` is a no-op apart from `rerun-if-changed`. `craton-hsm-daemon/build.rs:3-6` runs `tonic_prost_build::compile_protos` and requires a host `protoc`.
- **Description:**
  - The build scripts do no network access or code download. This is benign.
  - `protoc` is an unpinned host tool: `arduino/setup-protoc` without a version (ci.yml:51-54) and `apt protobuf-compiler` in the Dockerfile. Generated code can therefore vary across environments.
- **Recommendation:** Pin the `protoc` version in CI and in Docker, or vendor `protoc-bin-vendored`. Consider committing the generated code, reviewed like any other code.

### A3-28 [Informational] Positive observations (for balance)

- Most actions are pinned by full SHA with a version comment.
- The Dockerfile base images are digest-pinned. The Dockerfile uses `cargo fetch --locked` and a distroless non-root runtime.
- The Helm chart sets `runAsNonRoot`, `readOnlyRootFilesystem`, drops all capabilities, uses a seccomp RuntimeDefault profile and `automountServiceAccountToken: false`. It fails to render when TLS or mTLS is disabled without explicit acknowledgement.
- `deny.toml` denies unknown registries and git sources, and `Cargo.lock` contains no git dependencies (`grep 'source = "git'` finds nothing).
- No private keys, certificates, cloud or API tokens were found in tracked files. The patterns checked were `BEGIN … PRIVATE KEY`, `ghp_`, `AKIA`, `xox*`, `AIza` and `api_key` assignments.
- The daemon refuses to start without TLS on non-loopback addresses and fails closed on a missing config.
- The only `unreachable!()` in the codebase (`src/session/manager.rs:164`) is guarded by an early return (`manager.rs:134-136`).

---

## Documentation vs reality discrepancies

| # | Document:line | Claim | Reality (evidence) |
|---|---|---|---|
| 1 | Cargo.toml:8; README.md:13, 17; faq.md:37; PRESENTATION.md:7; Dockerfile:96 | "PKCS#11 v3.0-compliant" | Only the 68 v2.40 functions exist. No `C_GetInterface` or `C_Message*` (A3-16). |
| 2 | Cargo.toml:14; CONTRIBUTING.md:9; install.md:7 | Rust 1.75+ | The lockfile requires ≥1.89 (`redb 3.1.1`) (A3-08). |
| 3 | release-signing.md:13, 99 | Release built with `--locked` | release.yml:42 has no `--locked`. |
| 4 | release-signing.md:37, 106, 125-133 | cosign `.bundle` per binary; download `libcraton_hsm.so` | Tarballs plus `.sig` and `.pem` (release.yml:98-105, :118-122). |
| 5 | release-signing.md:59-66, 136 | `SHA256SUMS` file | `checksums-sha256.txt` (release.yml:92). |
| 6 | release-signing.md:141 | KATs detect a corrupted binary | KATs test algorithms. The integrity test is inert in releases (A3-04). |
| 7 | release-signing.md:147-149 | Signed commits and reproducible builds | Unsigned single commit; non-reproducible build (A3-11, A3-17). |
| 8 | GOVERNANCE.md:70-74 | Release requires audit and deny to pass and a signed tag | Not enforced by release.yml (A3-03). |
| 9 | GOVERNANCE.md:16 | Crypto reviewers own `src/token/token.rs` | Not in CODEOWNERS (CODEOWNERS:5-7). |
| 10 | CONTRIBUTING.md:43, 68, 76; PR template; security-review-checklist.md:15, 221 | `cargo clippy -- -D warnings` | CI uses `-D correctness -D suspicious` plus three `-A` flags (ci.yml:146-149). |
| 11 | ci.yml:120 | "Clippy lint (non-blocking)" | The job is blocking for correctness and suspicious lints (no `continue-on-error`). |
| 12 | CONTRIBUTING.md:93; PRESENTATION.md:12, 106, 374 | No `unsafe` in crypto paths | `integrity.rs` has 5, `digest.rs` 1, `awslc_backend.rs` 2 `unsafe impl` (census below). |
| 13 | CONTRIBUTING.md:92 | All `extern "C"` functions wrap `catch_unwind` | 11 trivial stubs do not (functions.rs 4736-4979, 5437-5452). This is harmless but the claim is inaccurate. |
| 14 | CHANGELOG.md:77; ROADMAP.md:33 | `#![forbid(unsafe_code)]` on store | `#![deny(unsafe_code)]` (store/mod.rs:7) with `#[allow]` at encrypted_store.rs:307. |
| 15 | CHANGELOG.md:23, 113-114; audit-scope.md:85 | HMAC-SHA256 `.hmac` integrity test | Ed25519 `.sig`; HMAC removed (integrity.rs:1-16, 100-107). |
| 16 | security-review-checklist.md:23, 46, 223; audit-scope.md:139-147 | 5 fuzz targets | 12 targets in fuzz/Cargo.toml:20-78, and the harness is broken (A3-13). |
| 17 | security-review-checklist.md:202, 225 | functions.rs ~4000 lines, 43 `unsafe` blocks | 5,622 lines, 128 `unsafe` tokens and 125 `unsafe {` blocks. |
| 18 | security-review-checklist.md:203-211 | File sizes (attributes ~444, encrypt ~250, sign ~200, keygen ~200, token ~200, session ~150, drbg ~150, encrypted_store ~200) | 676, 754, 902, 127, 769, 451, 382 and 483 lines respectively (`wc -l`). |
| 19 | security-review-checklist.md:17, 222 | Miri runs `cargo +nightly miri test --lib` | CI filters to 3 module paths and runs 3 tests (A3-14). |
| 20 | security-review-checklist.md:16 | fmt check runs in the `lint` job | It runs in the `fmt-check` job (ci.yml:15-28). |
| 21 | security-review-checklist.md:125 | `RawKeyMaterial` in `src/store/object.rs` | Defined in `src/store/key_material.rs:18`. |
| 22 | audit-scope.md:23 vs :170 | The gRPC daemon is outside the boundary, yet "Ports and interfaces: PKCS#11 C API, gRPC API" | Self-contradictory boundary definition. |
| 23 | audit-scope.md:32-60 | RustCrypto, Ed25519 and RC PQC crates listed as "Approved Algorithms (FIPS 140-3)" | No CAVP certificates. fips-gap-analysis.md:37 and :94 say Ed25519 is not approved. |
| 24 | audit-scope.md:127; PRESENTATION.md:393 | zeroization tests "ignored by default" | No `#[ignore]` in tests/zeroization.rs. They run in CI (ci.yml:71). |
| 25 | audit-scope.md:129-130 | multipart sign/verify 12 tests; encrypt/decrypt 10 | 1 `#[test]` each (tests/multipart_*.rs). |
| 26 | audit-scope.md:137; install.md:58; PRESENTATION.md:12 | 617+ tests in 33 suites | 717 `#[test]` across 35 integration files plus unit tests (grep count). ROADMAP.md:47 says 717+. |
| 27 | audit-scope.md:171 | ~10,000 lines of Rust in the core | 19,270 lines in `src/` (14,702 non-blank, non-comment). |
| 28 | README.md:26 | POST KATs cover "all approved algorithms" | No KAT for ECDH, AES-KW/KWP, PBKDF2, HKDF, SHA3-384/512, P-384 or SLH-DSA. PQC entries are roundtrips (audit-scope.md:96-99). |
| 29 | README.md:30, 101, 116; NOTICE:25-26 | aws-lc-rs backend lives only in the enterprise repo (BSL) | `src/crypto/awslc_backend.rs` and the `awslc-backend` feature are in this repo (Cargo.toml:22). |
| 30 | NOTICE:30-32, 42 | ed25519-dalek and subtle are Apache/MIT; prost is MIT | BSD-3-Clause and Apache-2.0 respectively (A3-12). |
| 31 | install.md:9 | CMake is required by aws-lc-rs for rustls | The daemon uses `tonic` `tls-ring` (daemon Cargo.toml:16). CMake is needed only for `awslc-backend`. |
| 32 | install.md:127-128; operator-runbook.md:196-197 | Daemon runs "with default config" | A missing config is fatal (daemon config.rs:150-154). The image's `COPY craton_hsm.toml` has no source file. |
| 33 | install.md:146-163; operator-runbook.md:271-292; faq.md:118 | Chart at `deploy/helm/craton_hsm/`; `kubectl create secret tls craton_hsm-tls` | The path is `deploy/helm/craton-hsm/`. Underscores are invalid in Kubernetes resource names. |
| 34 | install.md:163 | `helm test my-hsm` | The chart has no test templates (`templates/` has 10 files, none of them tests). |
| 35 | install.md:171-177 | Defaults: repository `craton_hsm`, `tls.enabled=false`, `tls.secretName=craton_hsm-tls`, `persistence.enabled=false` | values.yaml:2 `craton-hsm`, :21 `true`, :23 `craton-hsm-tls`, :61 `true`. |
| 36 | values.yaml:46-49 (implicit) | PIN and lockout settings take effect | `security.toml` is never loaded (A3-09). |
| 37 | postman-grpc-manual-tests.md:11 | `kreya/Craton HSM-gRPC.krproj` | The file is `kreya/CratonHSM-gRPC.krproj`. |
| 38 | generate-integrity-keypair.sh:42-59 | "Paste this into src/crypto/integrity.rs" as a Rust const | The key is now provided through the build-time environment variable `CRATON_HSM_INTEGRITY_PUBLIC_KEY` (integrity.rs:36-67). |
| 39 | compute-integrity-hmac.sh:228, 232-235 | Key "never in argv" | `-macopt hexkey:<key>` is in argv (A3-15). |
| 40 | daemon main.rs:204 | "Graceful shutdown on SIGTERM/SIGINT" | Only `ctrl_c()`, which is SIGINT (main.rs:206). |
| 41 | CHANGELOG.md:51 | Workspace versions synchronized | Core 0.9.1, sub-crates 0.3.0. `C_GetInfo` reports library 0.1 (functions.rs:324). |
| 42 | SECURITY.md:37; GOVERNANCE.md:65 | 0.8.x supported and backported | No 0.8 branch or tag. Single commit. |
| 43 | security-audit.yml:43 | Ignores reviewed quarterly, last 2026-03-21 | More than 6 months before this audit (2026-09-24). |
| 44 | deny.toml:5-6 | Raw RSA decryption not exposed | `C_Decrypt` with `CKM_RSA_PKCS_OAEP` uses the `rsa` crate (functions.rs:1878-1887). |
| 45 | local-ci.sh:16 | Clippy "with -D warnings" | Same flags as CI (local-ci.sh:97-100). |

---

## Complete stub / TODO / unimplemented inventory

Sweep: every tracked `.rs .sh .ps1 .yml .yaml .md .proto .toml .tpl .json .txt` file (202 files, excluding `docs/audit/`). The patterns searched were:

- `todo!(`, `unimplemented!(`, `unreachable!(` and `panic!(`
- `TODO`, `FIXME`, `XXX` and `HACK`
- "not implemented", "not yet", "stub", "placeholder", "mock" and "dummy"
- `CKR_FUNCTION_NOT_SUPPORTED` and `CKR_FUNCTION_NOT_PARALLEL`
- `#[ignore` and `cfg_attr(…, ignore)`
- `#[allow(dead_code)]`, `#[allow(unused…)]` and `#![allow]`

Results:

- **Zero** `todo!()` or `unimplemented!()` anywhere.
- **Zero** `FIXME` or `HACK`.
- The only `XXX` hit is test data (`tests/security_properties.rs:233`, `"Wrong-Pass456!XXX"`), which is not a marker.
- "not yet" hits in docs refer to FIPS approval status and are not stubs.

| # | file:line | Item | Category | Risk |
|---|---|---|---|---|
| 1 | Cargo.toml:56 | `# TODO: Remove aliases once RustCrypto migrates to rand_core 0.10` (getrandom/rand_core dual versions) | TODO / tech debt | Low. Two RNG stacks (see A3-07). |
| 2 | src/session/manager.rs:164 | `_ => unreachable!()` in `login_all` | unreachable! | Info. Guarded by `manager.rs:134-136` (returns `UserTypeInvalid`). Not reachable. |
| 3 | src/pkcs11_abi/functions.rs:3300-3306 | `fn not_supported() -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }`, under the heading "Stubs for unimplemented functions" | Stub helper | Info |
| 4 | functions.rs:4736 / 4741 | `C_SignRecoverInit` → `not_supported()` | Unimplemented PKCS#11 function | Low. Spec-permitted, but does not check whether the module is initialised first. |
| 5 | functions.rs:4745 / 4752 | `C_SignRecover` → `not_supported()` | Unimplemented | Low |
| 6 | functions.rs:4919 / 4924 | `C_VerifyRecoverInit` → `not_supported()` | Unimplemented | Low |
| 7 | functions.rs:4928 / 4935 | `C_VerifyRecover` → `not_supported()` | Unimplemented | Low |
| 8 | functions.rs:4939 / 4946 | `C_DigestEncryptUpdate` → `not_supported()` | Unimplemented (dual-function) | Low |
| 9 | functions.rs:4950 / 4957 | `C_DecryptDigestUpdate` → `not_supported()` | Unimplemented | Low |
| 10 | functions.rs:4961 / 4968 | `C_SignEncryptUpdate` → `not_supported()` | Unimplemented | Low |
| 11 | functions.rs:4972 / 4979 | `C_DecryptVerifyUpdate` → `not_supported()` | Unimplemented | Low |
| 12 | functions.rs:5447 / 5452 | `C_WaitForSlotEvent` → `not_supported()` | Unimplemented | Low |
| 13 | functions.rs:5437-5438 / 5442-5443 | `C_GetFunctionStatus` / `C_CancelFunction` → `CKR_FUNCTION_NOT_PARALLEL` | Legacy stub (spec-conformant) | Info |
| 14 | functions.rs:3253 | `C_SeedRandom` → `CKR_RANDOM_SEED_NOT_SUPPORTED` | Deliberate non-support | Info (appropriate for a DRBG with prediction resistance) |
| 15 | functions.rs (absent) | `C_GetInterfaceList`, `C_GetInterface`, `C_LoginUser`, `C_SessionCancel`, `C_MessageEncryptInit`, `C_EncryptMessage*`, `C_DecryptMessage*`, `C_MessageSign*`, `C_MessageVerify*` and other v3.0 functions | Not implemented, though v3.0 is claimed | Medium (A3-16) |
| 16 | functions.rs:5459-5460 | `CK_FUNCTION_LIST.version = 3.0` on a v2.40 struct | Mis-declared interface | Medium (A3-16) |
| 17 | functions.rs:324, 422-423, 468-469 | `library_version`, `hardware_version` and `firmware_version` hard-coded to `0.1` | Placeholder version | Medium (A3-16) |
| 18 | functions.rs:5536 | `#[allow(dead_code)] fn is_bool_attribute` | Dead code | Info |
| 19 | craton-hsm-daemon/src/server.rs:328-339 | `#[allow(dead_code)] const FORBIDDEN_TEMPLATE_ATTRS`, "Retained for use when mechanism dispatch is implemented (#20)" | Deferred security control (dead) | **High** (A3-02) |
| 20 | server.rs:684-688 | `generate_key`: only `CKM_AES_KEY_GEN`, otherwise "Unsupported keygen mechanism" | Partial implementation | Low (functional gap; `is_keygen_mechanism` at :656 advertises more) |
| 21 | server.rs:1114, 1209, 1330, 1417, 1449, 1532 | "Unsupported signing / verification / encryption / decryption mechanism" branches | Partial mechanism coverage in the daemon | Low |
| 22 | server.rs:1782-1783 | `FunctionNotSupported` / `RandomSeedNotSupported` → `Status::unimplemented` | Error mapping | Info |
| 23 | src/crypto/digest.rs:11-12 | `#[allow(dead_code)] const HASHER_ZEROIZE_BUF_SIZE = 256` | Dead code from an earlier design | Info |
| 24 | src/crypto/sign.rs:5 | `#[allow(unused_imports)] use sha2::{…}` | Lint suppression | Info |
| 25 | src/crypto/integrity.rs:22-26, 36-38, 66, 70-72, 116-151 | All-zero placeholder integrity public key (`[0u8; 32]`) used when the build-time environment variable is unset | Placeholder security parameter | **High** in releases (A3-04) |
| 26 | src/crypto/integrity.rs:48, 53-56 | `panic!`/`assert!` in a `const` context (invalid key env var) | Compile-time panic | Info (build-time only) |
| 27 | src/crypto/integrity.rs:88-96 | "could not determine module path — skipping" returns `Ok(())` even under `fips` | Fail-open stub path | Medium (A3-04) |
| 28 | src/crypto/drbg.rs:298; src/crypto/pqc.rs:48, 57, 65 | `std::process::abort()` on DRBG failure | Abort in library | Low (A3-19) |
| 29 | src/store/backup.rs:233-238 | "Backup replay protection disabled (consumed_ids=None). This is unsafe for production" (warn only) | Optional security control | Low. The caller decides; verify that the admin CLI always passes `Some`. |
| 30 | src/audit/log.rs:848-853 | Placeholder JSON line emitted when audit serialization fails | Degraded path (by design) | Info |
| 31 | src/crypto/sign.rs:32, 53-63 | Overwrite RSA key with a "minimal dummy key" to scrub memory | Workaround | Info (zeroization best effort) |
| 32 | tools/pkcs11-spy/src/loader.rs:33, 37, 39, 51, 73, 78, 80, 87, 107, 112 | `panic!` on load or validation failure inside a library loaded via `C_GetFunctionList` | panic! in library code | Low (debug tool; a panic across `extern "C"` aborts the host) |
| 33 | benches/pkcs11_abi_bench.rs:118, 149, 157, 218 | `panic!` in benchmark setup | panic! (non-library) | Info |
| 34 | tests/fips_approved_mode.rs:277 | `#[ignore = "RSA keygen returns CKR_MECHANISM_PARAM_INVALID — needs investigation"]` | Ignored test hiding a defect | Medium (A3-21) |
| 35 | src/crypto/integrity.rs:346; src/crypto/mlock.rs:101, 117 | `#[cfg_attr(miri, ignore)]` | Conditional ignore | Info (reduces Miri coverage further; A3-14) |
| 36 | fuzz/Cargo.toml:13-14 | `[dependencies.craton_hsm]` does not resolve | Broken harness | Medium (A3-13) |
| 37 | fuzz/fuzz_targets/fuzz_keygen.rs:80; fuzz_derive_key.rs:61; fuzz_multipart_crypto.rs:61; fuzz_rsa_ops.rs:52; fuzz_set_attribute.rs:62; fuzz_wrap_unwrap.rs:60 | Hard-coded PIN `b"1234"` (below the default min length of 8, with no token init) | Test stub / hard-coded PIN | Medium (A3-13) |
| 38 | fuzz/fuzz_targets/fuzz_init_token.rs:90, 125, 141, 162 | Hard-coded PIN `b"12345678"` | Hard-coded test PIN | Info |
| 39 | tests/fips_approved_mode.rs:51, 80 | Hard-coded SO/User PINs (the same values were reused in kreya) | Hard-coded test PIN | Low (A3-01) |
| 40 | tests/interop/java_sunpkcs11.sh:64-65; openssl_pkcs11.sh:67-68 | Default `SO_PIN=12345678`, `USER_PIN=1234` | Hard-coded default PINs | Low (A3-21) |
| 41 | tests/interop/java_sunpkcs11.sh:457 | `# rm -rf "$TMPDIR_BASE"  # Keep for debugging; uncomment for production` | Debug leftover | Low |
| 42 | kreya/remote.krenv:3-5; kreya/default.krenv:4-5; kreya/…/InitToken-request.json:3; LoginSO-request.json:4 | Committed PINs and a public server URL | Committed credentials | **High** (A3-01) |
| 43 | build.rs:5-6 | "Future: generate PKCS#11 header bindings if needed" | Placeholder build script | Info |
| 44 | Cargo.toml:107-109 | Commented-out `craton_hsm-awslc` path dependency to the enterprise repo | Disabled test dependency | Info (FIPS backend tests never run in CI) |
| 45 | .github/workflows/ci.yml:163, 268, 307 | `continue-on-error: true` (semver, Pages deploy) and `fail_ci_if_error: false` (Codecov) | Non-gating CI steps | Low (A3-10) |
| 46 | ROADMAP.md:46 | "126/130 tasks complete (2 interop tests deferred, 2 Phase 2/3 items deferred)" | Deferred work | Info |
| 47 | tools/compute-integrity-hmac.sh / .ps1 (entire files) | Tooling for a removed mechanism | Dead tooling | Medium (A3-15) |
| 48 | tools/pkcs11-spy/src/lib.rs:10-12; loader.rs:4; benches/pkcs11_abi_bench.rs:24 | `#![allow(non_snake_case / non_camel_case_types / clippy::missing_safety_doc)]` | Lint suppression | Info (`missing_safety_doc` hides unsafe-fn docs) |

---

## unsafe usage census

Counting method: `grep -cE '\bunsafe\b'` (tokens, including comments), `unsafe {` (blocks), `unsafe fn|unsafe impl`, and `// SAFETY|SAFETY:` comments, over all tracked `.rs` files. Files with zero are omitted unless they carry a lint attribute.

| File | `unsafe` tokens | `unsafe {}` blocks | `unsafe fn` / `impl` | `SAFETY` comments | Notes |
|---|---|---|---|---|---|
| src/pkcs11_abi/functions.rs | 128 | 125 | 0 | 16 | The FFI boundary. The 68 `pub extern "C" fn` are declared *safe* while dereferencing raw pointers, and CI suppresses `clippy::not_unsafe_ptr_arg_deref` (ci.yml:149). Only about 13% of blocks carry a `SAFETY` comment. The checklist's claim of "43 unsafe blocks" is stale. |
| src/crypto/integrity.rs | 5 | 5 | 0 | 0 | `dladdr`, `CStr::from_ptr` and `GetModuleHandleExW` / `GetModuleFileNameW` (:273-313). This is a crypto path, contrary to the CONTRIBUTING and PRESENTATION claims. No `SAFETY` comments. |
| src/crypto/mlock.rs | 4 | 4 | 0 | 4 | `mlock`/`munlock` and `VirtualLock`/`VirtualUnlock`. Documented. |
| src/crypto/digest.rs | 1 | 1 | 0 | 1 | `from_raw_parts_mut` over a `ManuallyDrop<D>` hasher (:171). The `SAFETY` comment cites a non-existent compile-time assertion (`debug_assert!`, :153). Possible padding-byte UB (A3-24). |
| src/crypto/awslc_backend.rs | 2 | 0 | 2 (`unsafe impl Send`/`Sync`, :963-964) | 1 | Either redundant or unsound. Feature-gated (`awslc-backend`) and never built in CI. |
| src/store/encrypted_store.rs | 1 | 1 | 0 | 1 | Windows `SetNamedSecurityInfoW` under `#[allow(unsafe_code)]` (:307-320). The store module has `#![deny(unsafe_code)]` (store/mod.rs:7). |
| src/platform_acl.rs | 2 | 1 | 0 | 1 | Windows ACL FFI (:30). One token is in a doc comment. `cfg(windows)` only. |
| src/store/backup.rs | 1 | 0 | 0 | 0 | The word appears in a log message only (:236). No unsafe code. |
| src/store/mod.rs | 1 | 0 | 0 | 0 | `#![deny(unsafe_code)]` plus a comment. |
| src/audit/mod.rs, src/config/mod.rs, src/session/mod.rs, src/store/lockout_store.rs, src/token/mod.rs, src/token/slot.rs, src/token/token.rs | 0 | 0 | 0 | 0 | `#![forbid(unsafe_code)]` present (good). |
| src/lib.rs | 0 | 0 | 0 | 0 | No crate-level `#![deny(unsafe_op_in_unsafe_fn)]` or `clippy::undocumented_unsafe_blocks`. |
| tools/pkcs11-spy/src/lib.rs | 8 | 4 | 4 | 0 | Out of boundary. `#![allow(clippy::missing_safety_doc)]`. Exported functions have no `catch_unwind`. |
| tools/pkcs11-spy/src/loader.rs | 4 | 3 | 1 | 0 | `libloading` and `fstat`/fd loading. Panics on error. |
| craton-hsm-daemon/src/*.rs, tools/craton-hsm-admin/src/**/*.rs | 0 | 0 | 0 | 0 | No `unsafe` (good). No `forbid` attribute either. |
| benches/pkcs11_abi_bench.rs | 8 | 5 | 3 | 4 | Loads SoftHSM and Craton via `libloading`. |
| fuzz/fuzz_targets/fuzz_c_abi.rs | 5 | 5 | 0 | 0 | Test harness (currently unbuildable, A3-13). |
| tests/pkcs11_info_functions.rs | 20 | 20 | 0 | 0 | Test code. |
| tests/pkcs11_conformance.rs | 7 | 7 | 0 | 0 | Test code. |
| tests/random_and_session.rs | 6 | 6 | 0 | 0 | Test code. |
| tests/zeroization.rs | 5 | 4 | 0 | 2 | **Reads freed memory** (:161, :179, :211, :219). Admitted UB (A3-21). |
| tests/pkcs11_compliance.rs | 4 | 4 | 0 | 0 | Test code. |
| tests/pkcs11_error_paths.rs | 3 | 3 | 0 | 0 | Test code. |
| tests/pkcs11_compliance_extended.rs | 2 | 2 | 0 | 0 | Test code. |
| tests/fips_approved_mode.rs | 2 | 1 | 0 | 2 | Test code. |
| **Totals (production `src/`)** | **145** | **137** | **2** | **24** | Of the 137 production `unsafe {}` blocks, 125 (91%) are in `functions.rs`. Miri exercises none of them (A3-14). |

---

*End of A3 report.*
