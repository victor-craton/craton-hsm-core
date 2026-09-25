# Contributing to Craton HSM

Thank you for your interest in contributing to Craton HSM! This document covers the process for contributing to the project.

## Getting Started

### Prerequisites

- [rustup](https://rustup.rs/). The toolchain is pinned in
  `rust-toolchain.toml` (currently 1.94.1) and installed automatically on
  first use. The minimum supported Rust version (MSRV) is **1.89**
  (`rust-version` in `Cargo.toml`, checked by the `msrv` CI job).
- Git

Optional (for full workspace build):
- protoc (for the gRPC daemon; CI pins the version in `ci.yml`)
- CMake, Clang and Go (for the `awslc-backend` feature)

### Building

```bash
git clone https://github.com/craton-co/craton-hsm-core.git
cd craton-hsm-core

# Build the core library
cargo build --locked

# Build the full workspace (requires protoc: the daemon's build script runs
# tonic-prost-build; set PROTOC=/path/to/protoc if it is not on PATH)
cargo build --locked --workspace
```

### Running Tests

**Important**: Tests must run single-threaded due to global PKCS#11 state.

```bash
# Full test suite
cargo test --locked -- --test-threads=1

# Workspace members (build the cdylib first so the pkcs11-spy end-to-end test
# wraps the real module instead of printing SKIPPED)
cargo build --locked -p craton-hsm --lib
cargo test --locked -p craton-hsm-admin -p pkcs11-spy -p craton-hsm-daemon -- --test-threads=1

# AWS-LC backend (needs cmake, Go, clang): CASTs through AWS-LC and the
# cross-backend differential test
cargo test --locked -p craton-hsm --features awslc-backend --lib -- --test-threads=1
```

`fips` builds fail closed without a signed module, so their tests need an
embedded integrity key and signed test executables — see the `features` job
in `.github/workflows/ci.yml` and
[docs/fips-140-3-certification.md §10.6](docs/fips-140-3-certification.md#106-approved-only-build-procedure).

CI runs every file in `tests/` explicitly (see `.github/workflows/ci.yml`).
When you add a new integration test file, add it to one of the two lists in
the `build-and-test` job — the `fmt-check` job fails otherwise.

### Linting

The same checks CI runs (`correctness` and `suspicious` clippy lints are
errors; other categories are warnings being cleaned up):

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D clippy::correctness -D clippy::suspicious -A deprecated
cargo deny --workspace --all-features check      # needs cargo-deny
```

Please do not add new clippy warnings in the code you touch.

## How to Contribute

### Bug Reports

Open a [GitHub issue](https://github.com/craton-co/craton-hsm-core/issues) with:
- Steps to reproduce
- Expected vs actual behavior
- Rust version (`rustc --version`)
- OS and architecture

**Security bugs**: Please see [SECURITY.md](SECURITY.md) instead.

### Feature Requests

Open an issue describing the use case and proposed solution. For PKCS#11 compliance features, reference the relevant section of the PKCS#11 specification (the module implements the v2.40 function set plus v3.0 interface discovery).

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes
4. Ensure all tests pass: `cargo test --locked -- --test-threads=1`
5. Ensure lints pass (commands in [Linting](#linting))
6. Commit with a clear message
7. Push and open a PR against `main`

### PR Checklist

- [ ] [CLA signed](CLA.md) (the bot will prompt you on your first PR)
- [ ] Tests pass (`cargo test --locked -- --test-threads=1`)
- [ ] Clippy passes with the CI flags and adds no new warnings
- [ ] Code is formatted (`cargo fmt --all`)
- [ ] New functionality has tests
- [ ] Every `unsafe` block has a `// SAFETY:` comment
- [ ] No key material in logs or debug output (use `[REDACTED]`)
- [ ] CHANGELOG.md updated (for user-facing changes)

## Code Guidelines

### Security-Sensitive Code

This is a cryptographic module. Extra care is required:

- **No key bytes in logs**: Use custom `Debug` impls that print `[REDACTED]`
- **Zeroize on drop**: All key material must use `RawKeyMaterial` (which provides mlock + ZeroizeOnDrop)
- **Constant-time comparison**: Use `subtle::ConstantTimeEq` for any secret comparison
- **`catch_unwind`**: every `extern "C"` function that dereferences caller pointers or touches module state must wrap its body in `catch_unwind` (functions that only return a constant need not)
- **Minimise `unsafe`**: `unsafe` code currently exists in the FFI layer (`src/pkcs11_abi/functions.rs`), memory locking (`src/crypto/mlock.rs`), module-path discovery for the integrity test (`src/crypto/integrity.rs`), digest-state zeroization (`src/crypto/digest.rs`) and Windows ACL calls. Do not add more without a strong reason; every block needs a `// SAFETY:` comment, and new `unsafe` in `src/crypto/` needs crypto-reviewer approval
- **Advisory suppressions**: only in `deny.toml`, with a reason and an `expires YYYY-MM-DD` date no more than 120 days ahead (CI enforces this)

### Style

- Follow existing patterns in the codebase
- `cargo fmt` is the formatter — no exceptions
- Prefer explicit error handling over `unwrap()`/`expect()` in library code
- Use `thiserror` for error types that map to `CK_RV` codes

### Testing

- Add tests for new functionality
- Integration tests go in `tests/`
- Test both success and error paths
- For ABI-level tests, use the patterns in existing test files (init token, open session, login, operate, cleanup)

## Architecture Overview

See [docs/architecture.md](docs/architecture.md) for a detailed module diagram. The key entry points:

- `src/core.rs` — `HsmCore` central state
- `src/pkcs11_abi/functions.rs` — C ABI exports (the FFI boundary)
- `src/crypto/` — all cryptographic operations
- `src/store/` — object storage and key material

## Contributor License Agreement (CLA)

All contributors must sign our [Contributor License Agreement](CLA.md) before their pull request can be merged. This is a one-time requirement.

When you open a pull request, the CLA Assistant bot will check whether you have signed. If not, it will post a comment with instructions — simply reply with the specified comment to sign.

The CLA ensures that Craton Software Company has the necessary rights to distribute your contributions under the project's license terms, including the ability to offer enterprise licensing.

## Why is `Cargo.lock` committed?

Craton HSM ships both as a library (`rlib`) and a shared library (`cdylib`). Since the cdylib is a final build artifact loaded by PKCS#11 consumers, we commit `Cargo.lock`, and CI and the release workflow build with `--locked` so that the dependency versions that were audited are the ones that ship. This is consistent with the [Cargo FAQ](https://doc.rust-lang.org/cargo/faq.html#why-have-cargolock-in-version-control) recommendation for binary/artifact projects.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License, Version 2.0](LICENSE), and you confirm that you have signed the [CLA](CLA.md).
