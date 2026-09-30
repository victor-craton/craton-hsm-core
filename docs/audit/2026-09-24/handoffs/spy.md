# Handoff — area: spy (tools/pkcs11-spy), branch claude/audit-fixes-spy

All H6-01..H6-17 findings were fixed inside the owned paths (`tools/pkcs11-spy/**`
and the pkcs11-spy section of `docs/install.md`). The items below are outside
those paths and need an owner.

## Changes needed outside owned paths

1. `.github/workflows/ci.yml`, job step "Run workspace member tests" (H6-17, H6-01 item 5)
   - The new integration test `tools/pkcs11-spy/tests/spy_integration.rs::spy_wraps_the_craton_hsm_cdylib`
     loads the spy against the real craton-hsm cdylib. It looks for `libcraton_hsm.so`
     in `target/<profile>/` or `target/<profile>/deps/`, or in `$CRATON_HSM_LIB`, and prints
     `SKIPPED` if it is missing. To make sure CI actually runs it, add
     `cargo build -p craton-hsm --lib` before `cargo test -p pkcs11-spy ...` in that step
     (or set `CRATON_HSM_LIB`). The other spy integration tests compile a mock module
     with `rustc` (taken from `$RUSTC`, else from `PATH`) and need nothing extra.
   - `tools/pkcs11-spy/Cargo.toml` now declares `rust-version = "1.81"` (H6-04: from 1.81 a
     panic that escapes `extern "C"` aborts instead of being UB). The workspace root
     declares `1.75`. If an MSRV job is added later, it must use >= 1.81 for `pkcs11-spy`,
     or the workspace MSRV should be raised (owner of the root `Cargo.toml`).

2. `docs/architecture.md:102` ("PKCS#11 interceptor (cdylib)") and `docs/PRESENTATION.md:302`
   are still accurate. Optional wording: "PKCS#11 v2.40/v3.0 logging interposer".
   No change is required.

## Not fixable in code

- H6-02 (organisational part): the spy is a development tool and must not be configured
  as a provider for privileged or production processes (PAM, polkit, system p11-kit
  config). Only process or policy can enforce that. The code now ignores all
  `PKCS11_SPY_*` variables in secure-execution mode, and `docs/install.md` states the rule.
- H6-07 (residual): on Windows the log file is still created with the inherited ACL and
  then narrowed with `icacls`, so there is a short window before the ACL is applied.
  Removing it would mean `CreateFileW` with an explicit `SECURITY_ATTRIBUTES` DACL, which
  needs a `windows-sys` dependency (a supply-chain decision). `whoami`/`icacls` now run
  by absolute System32 path and fail closed.
- Windows code paths were checked with `cargo clippy --target x86_64-pc-windows-gnu`
  (and `x86_64-apple-darwin` for the `issetugid` path) but never executed. They need a
  test run on a real Windows or macOS host.

## Pre-existing workspace issue (not caused by this branch)

- `cargo check --workspace --all-targets` fails on the untouched initial commit:
  `benches/crypto_bench.rs:347-349` imports `craton_hsm_awslc::AwsLcBackend` with no
  `#[cfg(feature = "awslc-backend")]` guard, and no `craton_hsm_awslc` crate exists
  (E0432). Fix: gate the block with `#[cfg(feature = "awslc-backend")]` and use the
  in-crate backend path. Owner: root crate / benches. `cargo check --workspace --lib
  --bins --tests --examples` passes on this branch.
