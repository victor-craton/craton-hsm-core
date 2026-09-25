# Tested Platforms

"Tested" on this page means: the complete test suite runs and passes in CI on
that environment. Everything else is marked as *built only* or *not tested*.
For FIPS 140-3 purposes these are the candidate operational environments;
no ACVP testing has been performed on them (see
[fips-140-3-certification.md §5](fips-140-3-certification.md#5-operational-environment)).

## Toolchain

| Property | Value |
|----------|-------|
| Rust toolchain | pinned in `rust-toolchain.toml`: **1.94.1** (used by CI and release builds) |
| MSRV | **1.89** (`rust-version` in `Cargo.toml`; `cargo check` with 1.89.0 in the `msrv` CI job) |
| Edition | 2021 |
| protoc | 36.2 in CI (daemon only) |

## Operational environments

| # | OS (CI runner image) | Architecture | Target triple | Status |
|---|---|---|---|---|
| 1 | Ubuntu 24.04 LTS (`ubuntu-24.04`) | x86_64 | `x86_64-unknown-linux-gnu` | **Tested** on every PR and push (full suite, Miri, fuzz smoke, `fips`/`awslc-backend` builds) |
| 2 | Windows Server 2025 (`windows-2025`) | x86_64 | `x86_64-pc-windows-msvc` | **Tested** on pushes to `main` and for every release |
| 3 | macOS 15 (`macos-15`) | arm64 (Apple Silicon) | `aarch64-apple-darwin` | **Tested** on pushes to `main` and for every release |
| — | macOS (Intel) | x86_64 | `x86_64-apple-darwin` | Built for releases (cross-compiled on arm64); **not tested** |
| — | Linux musl | x86_64 | `x86_64-unknown-linux-musl` | **Not built or tested** in CI |
| — | Windows 11 developer workstations | x86_64 | `x86_64-pc-windows-msvc` | Developer testing only (not recorded) |

The runner images are pinned in `.github/workflows/ci.yml`. Changing them
changes the tested environments and must be reflected here and in the FIPS
documents.

## Feature matrix by platform

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| Core PKCS#11 | ✅ tested | ✅ tested | ✅ tested (arm64) |
| Memory locking (best effort) | `mlock()` / `munlock()` | `VirtualLock()` / `VirtualUnlock()` | `mlock()` / `munlock()` |
| Fork detection | `getpid()` comparison | N/A (no `fork()`) | `getpid()` comparison |
| File locking | `flock()` via fs2 | `LockFileEx()` via fs2 | `flock()` via fs2 |
| Persistent storage (redb, `persist_objects = true`) | ✅ | ✅ | ✅ |
| RustCrypto backend | ✅ tested | ✅ tested | ✅ tested |
| AWS-LC backend (`awslc-backend`) | built in CI (not tested) | not built in CI | not built in CI |
| gRPC daemon | ✅ tested | ✅ tested | ✅ tested |

## Crypto backend requirements

### RustCrypto backend (default)

No additional system dependencies.

```bash
cargo build --release --locked
```

### AWS-LC backend

Requires CMake, a C compiler, Clang/libclang and Go (for `aws-lc-fips-sys`).

```bash
cargo build --release --locked --features awslc-backend
```

On Windows development machines without an assembler toolchain,
`AWS_LC_SYS_NO_ASM=1` makes the build work, but it produces a different
AWS-LC implementation from the validated one; never use it for a build that
is meant to be FIPS-aligned.

## Test execution

```bash
# PKCS#11 ABI tests share a process-wide singleton: run single-threaded
cargo test --locked -- --test-threads=1

# Feature builds checked in CI
cargo build --locked -p craton-hsm --features fips --all-targets
cargo build --locked -p craton-hsm --features awslc-backend --all-targets
cargo build --locked -p craton-hsm --features fips,awslc-backend --all-targets
```

`tests/zeroization.rs` runs as part of the normal suite (serially in CI).
Its checks read memory after `drop`, so they are best-effort evidence.

### Known slow tests

| Test | Approximate duration | Reason |
|------|---------------------|--------|
| RSA 3072 keygen | ~10 s (debug) | Large prime generation |
| SLH-DSA operations | ~60 s (debug) | Hash-based signature scheme |

Use `--release` for faster execution.

## Container

`deploy/Dockerfile` is a multi-stage build with a distroless runtime image
(`gcr.io/distroless/cc-debian12`, digest-pinned). The builder image must
provide a Rust toolchain ≥ the MSRV (1.89) for the locked dependencies to
build; check the `FROM` line in the Dockerfile. The container build is not
exercised by CI yet.

## CI summary

See `.github/workflows/ci.yml`: format check, clippy (correctness and
suspicious lints are errors), test matrix above, doc-tests, feature builds,
MSRV check, Miri, fuzz smoke (60 s per target), Helm lint/template, rustdoc
and coverage. Supply-chain checks are in `.github/workflows/security-audit.yml`.

## Dependency versions

`Cargo.lock` and the CycloneDX SBOM shipped with each release are
authoritative. Notable versions at the time of writing:

| Dependency | Version | Purpose |
|-----------|---------|---------|
| redb | 3.1 | Persistent object storage |
| fs2 | 0.4 | Cross-platform file locking |
| zeroize | 1.8 | Memory zeroization |
| parking_lot | 0.12 | Mutex/RwLock |
| dashmap | 6.1 | Concurrent hash map (sessions) |
| windows-sys | 0.61 | Windows API bindings |
| aws-lc-rs | 1.16 (optional) | AWS-LC backend |
| tonic | 0.14 | gRPC framework (daemon only) |
