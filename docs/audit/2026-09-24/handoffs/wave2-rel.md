# Handoff — wave 2, area `rel` (branch `claude/audit-fixes2-rel`, worktree /home/user/hsm-fix2-rel)

Scope: Cargo manifests + lockfiles, deny.toml, .github/** (except the ci.yml
test-file lists and clippy flags), rust-toolchain.toml, .gitignore, NOTICE,
SECURITY/README/CHANGELOG/ROADMAP/CONTRIBUTING, docs/**.

## 1. What this branch did (commits, oldest first)

| Commit | Change |
|---|---|
| e77b3ad | `cargo update -p anyhow -p crossbeam-epoch -p h2 -p rand@0.8.5 -p rustls -p rustls-webpki -p der@0.8.0 -p spin@0.9.8` (clears RUSTSEC-2026-0190/0204/0258/0097/0285/0098/0099/0104 + yanked der/spin); `fuzz/Cargo.lock` = root lock (pruned); `publish = false` + `rust-version = "1.89"` for admin and daemon; unneeded deny skips (cipher, inout) removed |
| c5caeae | A3-26: tracing `max_level_info`/`release_max_level_info` moved from the library to the daemon + admin manifests; stale enterprise awslc comment fixed |
| 08877de | **Packaging bug:** `include = ["/src/**/*.rs", …]` dropped `src/crypto/kat/*` (used by `include_bytes!`) → published crate would not build. Now `/src/**`; verified with `cargo package -p craton-hsm` (builds). `.gitignore`: `craton_hsm.redb`, `*.anchor`, `*.jsonl.lock`, `*.jsonl.[0-9]`, `.craton_hsm_replay_guard.*`, exception `!/src/crypto/kat/*.sig` |
| d4b891a | deny.toml RUSTSEC-2023-0071: honest, time-boxed (blinding, no v1.5 decryption, AWS-LC in fips; bignum not constant time) |
| bc36c8f, 869b94a | ci.yml: `cargo build -p craton-hsm --lib` before the workspace-member tests (spy e2e test); `features` job builds **and tests** `awslc-backend`, `fips`, `--no-default-features --features fips` (lib tests + `fips_approved_mode` + `crypto_vectors`), fips entries embed an ephemeral `CRATON_HSM_INTEGRITY_PUBLIC_KEY` and sign the test executables (`tools/sign-integrity.sh`); new `container` job: `docker build -f deploy/Dockerfile .`, user 65532 check, `helm template` → extract `craton_hsm.toml` → run the daemon in the image with it and require "POST self-tests passed"; `helm lint --strict` |
| 44d1972 | `[profile.dev.package."*"] opt-level = 2` (state handoff: PBKDF2-bound ABI tests) |
| 53b37e1 … b88337d | docs: configuration-reference rewritten (sources, validation, all `[daemon]` keys, persistence setup + key hierarchy, keyed audit), runbook (admin prerequisites, backup/restore, audit, daemon, systemd, k8s), install (protoc, fips build+sign, Docker/Helm), api-reference (`HsmCore::open`, gRPC API incl. InitPin), security-model (keyed audit, Marvin, **pre-release PQC risk**), fips docs, gap analysis, examples (daemon positional arg), migration guide, NOTICE (tonic-health), CHANGELOG Unreleased, ROADMAP/CONTRIBUTING, `docs/audit/2026-09-24/REMEDIATION.md` (all 244 findings) |

## 2. Integrator: MUST-DO after merging abi/core

1. **ci.yml test list (abi owner): `tests/crypto_abi_params.rs` and `tests/state_regressions.rs` are not listed** in either `cargo test` list of the `build-and-test` job → the `fmt-check` job ("Every integration test file is run by CI") fails on the merged tree today. Add them (serial list; both are ABI/global-state tests), plus any new abi test files.
2. **`features` CI job, entry `fips` (`--features fips`, default features on) and the release `-fips` flavour stay red until core sets `crypto_backend = "awslc"` in `HsmConfig::fips_defaults()`** (and `default_crypto_backend()` under `cfg(feature="fips")`). Verified locally: with signed test executables, `--no-default-features --features fips` passes (lib 73/73, fips_approved_mode 11/11, crypto_vectors 19/19); `--features fips` passes lib 78/78 but all 9 `fips_approved_mode` ABI tests fail with `C_Initialize` = CKR_GENERAL_ERROR (POST refuses the RustCrypto backend). `awslc-backend`: lib 79/79, fips_approved_mode 11/11, crypto_vectors 19/19.
3. Lockfile: if abi/core add dependencies, regenerate `Cargo.lock`, re-run `cargo deny --workspace --all-features check` (all four sections pass on this branch) and re-sync: `cp Cargo.lock fuzz/Cargo.lock && (cd fuzz && cargo metadata --format-version 1 >/dev/null)`. New duplicate versions need a deny.toml `skip` with a reason.
4. Update the *Pending wave-2* rows of `docs/audit/2026-09-24/REMEDIATION.md` (and its summary counts; generator logic is simple: one row per `### <ID> [..]` heading) and the matching CHANGELOG "Pending in wave 2" bullet.
5. Re-verify the "docs ahead of code" statements in §3.

## 3. Docs statements that depend on in-flight wave-2 work (verify after merge)

| Statement | Where | Owner / current state |
|---|---|---|
| `C_GetInterfaceList` / `C_GetInterface` exported; `C_GetFunctionList` returns the v2.40 list | README, api-reference, faq, architecture, ROADMAP, fips-140-3-certification §2.2, security-policy | abi — **not exported in the current tree** |
| `C_GetInfo.libraryVersion` = package major.minor | fips-140-3-certification §1.1 (flagged) | abi — still `0.1` (functions.rs ~l.569) |
| Admin CLI commands work against the persistent store (runbook/install/examples: token init, pin, key, backup/restore, audit dump/export) | operator-runbook, install, examples | core — CLI still `HsmCore::try_new` + `CoreMode::Ephemeral` → commands exit 5. Note `try_new` is now an alias of `open`, so switching is mostly `CoreMode::Persistent` + tests |
| `craton-hsm-admin audit verify-chain` verifies the keyed chain (needs key file) | operator-runbook | core/admin — `tools/craton-hsm-admin/src/audit_file.rs` still mirrors the OLD unkeyed SHA-256 chain; the core log is now `HMAC-SHA256(K, …)` → the CLI will report every real log as tampered. Switch to `AuditLog::verify_file(log, key)` (H5-03) |
| Daemon persists token objects (`persist_objects = true` in the chart) | configuration-reference, runbook, install | core — verified locally that the daemon with the rendered chart config logs "persistent token store opened … persistent object store active" (try_new = open); confirm end to end |
| fips builds select AWS-LC | configuration-reference, fips-mode-guide, CHANGELOG | core (§2.2) |
| `unsafe extern "C"` exports; clippy clean on all targets | CHANGELOG (pending), REMEDIATION | abi |
| Remaining authorization checks (C_WrapKey, C_SetOperationState, C_DestroyObject, C_CopyObject, key creation), `CKR_KEY_TYPE_INCONSISTENT` | REMEDIATION, fips-gap-analysis (A1-25/A1-30 rows) | abi |

Verified against the current tree (no action): DRBG serves C_GenerateRandom (backend `generate_random`), reseed 2^16 / 2^19-bit requests, DRBG KAT in POST; CAST ordering; fips fail-closed integrity (missing `.sig`, placeholder key, module path); 39 advertised mechanisms; RSA cache cleared at C_Finalize/C_InitToken; `run_post_with_backend` exists; `HsmCore::init_token` semantics; key use requires `CKU_USER` (`is_logged_in` = user only); CKA_VALUE rule; persistence key hierarchy (encrypted_store.rs doc); `[daemon]` keys/defaults/ranges (config.rs); sign-integrity interface/`.sig` format; slot isolation; PIN policy constants.

## 4. Changes needed outside my paths

| Finding | File / function | Change |
|---|---|---|
| H3-13 (bug) | `src/config/config.rs` `HsmConfig::load()` → `validate_config_path()` → `validate_path_safety()` | `SYSTEM_PATH_PREFIXES` contains `/etc`, so the **system config path `/etc/craton-hsm/craton_hsm.toml` (and any `CRATON_HSM_CONFIG` under /etc) is always rejected** by the library. Apply the system-directory rule only to `storage_path`/`log_path`/`key_path`, not to the config file path (the ownership/permission checks already protect it). Docs describe the intended behaviour. (core) |
| A1-03/H2-05 | `src/config/config.rs` `fips_defaults()` | `crypto_backend = "awslc"` (see §2.2) (core) |
| A1-17 / fips usability | `fips_defaults()` | fips builds are always **ephemeral** (`persist_objects = false`, relative default paths) — no persistent token in the approved-only build. Consider reading non-security settings (storage/audit paths, persist flag) from a root-owned system config in fips builds. Documented in fips-mode-guide. (core) |
| H5-03 | `tools/craton-hsm-admin/src/audit_file.rs`, `commands/audit.rs` | use `AuditLog::verify_file` / keyed chain (see §3) (core) |
| H3-13/H5-11 consistency | `tools/craton-hsm-admin/src/config.rs` `DEFAULT_CONFIG_PATH` | `/etc/craton_hsm/…` (underscore) vs core `SYSTEM_CONFIG_PATH` and container `/etc/craton-hsm/…` (hyphen). Align on `/etc/craton-hsm/craton_hsm.toml`; then update configuration-reference.md "Admin CLI" + runbook intro + examples.md `CFG=` (they document the current underscore default). (core) |
| A3-12 | `.dockerignore` (root) excludes `LICENSE*` and `*.md`; `deploy/Dockerfile` | ship LICENSE + NOTICE (+ THIRD-PARTY-LICENSES) in the image, e.g. `COPY LICENSE NOTICE /usr/share/doc/craton-hsm/` with `!LICENSE`/`!NOTICE` exceptions (deploy owner) |
| A3-16/A3-17 | `deploy/Dockerfile` label "PKCS#11 v3.0 Software HSM", `IMAGE_VERSION=0.3.0`; `Chart.yaml appVersion 0.3.0` | label → "PKCS#11 v2.40 software HSM"; derive versions from Cargo.toml (deploy owner) |
| A3-05/H5-18 | `scripts/audit-ignore.txt` | stale second ignore list (RUSTSEC-2026-0042..0049 are no longer in the graph/needed; 2023-0071 reason outdated). Generate it from deny.toml or make `scripts/local-ci.sh` read deny.toml like security-audit.yml does (scripts owner) |
| H4-27 (nit) | `craton-hsm-daemon/src/main.rs` `init_logging` doc | "the core library caps levels at INFO" → "the daemon binary is compiled with max_level_info" (core) |
| A3-22 | root `package.json` | pin versions + lockfile or drop (unassigned) |
| A3-09/H4-28 | CI | kind end-to-end smoke test and a proto/Kreya consistency check were **not** added (future CI work) |
| A1-11 | — | approved-service indicator: unassigned |

## 5. Verification (this worktree)

- `cargo check --locked --workspace --all-targets`: OK (after all commits).
- `cargo +1.89.0 check --locked --workspace`: OK (MSRV).
- `cargo package -p craton-hsm` (with verification build): OK.
- `cargo deny --workspace --all-features check advisories bans licenses sources` (0.20.2): all ok, no warnings.
- `cargo audit --deny warnings` (0.22.1, db 1269 advisories) on Cargo.lock and fuzz/Cargo.lock with the 2 deny.toml ignores: clean (yanked check could not run: crates.io index 503 via proxy; cargo-deny's yanked check passed).
- All workflows: PyYAML OK, actionlint 1.7.x OK.
- `helm lint --strict` / `helm template` (helm v3.19 built from source): OK; rendered config accepted by the daemon locally (native run).
- Docker build not executed (no Docker daemon in this environment).

## 6. Not fixable in code

See `docs/audit/2026-09-24/REMEDIATION.md` § "Not fixable in code / owner actions" (PIN rotation, public endpoint shutdown, history scrub, secret scanning, `CRATON_HSM_INTEGRITY_PUBLIC_KEY` variable, protected environments, trusted publishing, branch/tag protection, `CLA_TOKEN` scoping, security@ + PGP, ESV, CAVP/ACVP, CST lab, rollback counter, Marvin until `rsa` 0.10).
