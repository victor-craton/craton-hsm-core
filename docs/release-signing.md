# Release Signing & Binary Verification

## Overview

Craton HSM releases are produced only by the GitHub Actions workflow
[`.github/workflows/release.yml`](../.github/workflows/release.yml), triggered by
pushing a `v*` tag. This document describes exactly what that workflow
produces and how to verify it. Nothing here is aspirational: if a file or
check is described below, the workflow creates or performs it.

Two independent integrity mechanisms exist:

1. **Distribution integrity** — every release asset is covered by a
   `SHA256SUMS` file, a Sigstore/cosign keyless signature bundle and a
   GitHub build-provenance attestation. Verify these *before* installing.
2. **Module self-integrity** — the PKCS#11 library verifies an Ed25519
   signature over its own file at every `C_Initialize` (FIPS 140-3 software
   integrity test). The verification public key is embedded at build time and
   the signature ships as a `.sig` sidecar next to the library.

## What the release workflow does

| Stage | Job | What happens |
|---|---|---|
| Gate | `verify-tag` | Tag `vX.Y.Z` must equal `version` in `Cargo.toml` and have a `## [X.Y.Z]` section in `CHANGELOG.md`. |
| Gate | `ci` | The complete CI workflow (`ci.yml`: fmt, clippy, all tests on Linux/Windows/macOS, feature builds, MSRV, Miri, fuzz smoke, Helm lint) runs on the tagged commit. |
| Gate | `audit` | `security-audit.yml`: `cargo deny check` (advisories, bans, licenses, sources), `cargo audit`, advisory-ignore expiry policy. |
| Build | `build` | `cargo build --release --locked` of **all shipped binaries** (`craton-hsm` library, `craton-hsm-admin`, `craton-hsm-daemon`, `pkcs11-spy`) for `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, plus a Linux **FIPS-mode flavour** (`--features craton-hsm/fips,craton-hsm/awslc-backend`). The integrity public key (`CRATON_HSM_INTEGRITY_PUBLIC_KEY`) is embedded; the build fails if it is not configured. Runner paths are remapped (`--remap-path-prefix`). |
| Package | `package` (protected environment `release`) | Signs every PKCS#11 library with the Ed25519 integrity key (`tools/sign-integrity.sh`), independently re-verifies each signature, runs a **load/tamper smoke test** on Linux (the signed library must initialise; a copy with one byte appended must fail `C_Initialize`), generates `THIRD-PARTY-LICENSES.txt` (cargo-about) and CycloneDX SBOMs (cargo-cyclonedx), builds deterministic tarballs (`--sort=name`, fixed mtime = commit time, numeric owner 0, `gzip -n`) and writes `SHA256SUMS`. |
| Publish | `github-release` | cosign keyless signature bundle (`<file>.sigstore.json`) for every asset, GitHub build-provenance attestation for every file listed in `SHA256SUMS`, GitHub Release creation. |
| Publish | `publish-crate` (protected environment `crates-io`) | `cargo publish --locked -p craton-hsm` using crates.io **trusted publishing** (short-lived OIDC token; no long-lived registry token). |

### Release assets

For version `X.Y.Z`:

| Asset | Contents |
|---|---|
| `craton-hsm-X.Y.Z-<target>.tar.gz` | `craton-hsm-X.Y.Z-<target>/` containing the PKCS#11 library (`libcraton_hsm.so` / `craton_hsm.dll` / `libcraton_hsm.dylib`), its integrity sidecar (`libcraton_hsm.sig` / `craton_hsm.sig`), the `pkcs11-spy` library, `craton-hsm-admin[.exe]`, `craton-hsm-daemon[.exe]`, `LICENSE`, `NOTICE`, `README.md`, `THIRD-PARTY-LICENSES.txt` and `sbom/*.cdx.json`. |
| `craton-hsm-X.Y.Z-x86_64-unknown-linux-gnu-fips.tar.gz` | Same layout, library built with the `fips` + `awslc-backend` features. **Not a FIPS 140-3 validated module** — see [fips-mode-guide.md](fips-mode-guide.md). |
| `craton-hsm-X.Y.Z-<crate>.cdx.json` | CycloneDX SBOM per workspace crate (`craton-hsm`, `craton-hsm-admin`, `craton-hsm-daemon`, `pkcs11-spy`). |
| `craton-hsm-X.Y.Z-THIRD-PARTY-LICENSES.txt` | Licence texts of every third-party crate, generated from `Cargo.lock`. |
| `SHA256SUMS` | SHA-256 of every asset above. |
| `<asset>.sigstore.json` | cosign keyless signature bundle for each asset (including `SHA256SUMS`). |

## Verifying a release (users)

```bash
VERSION=0.9.1
TARGET=x86_64-unknown-linux-gnu
BASE=https://github.com/craton-co/craton-hsm-core/releases/download/v${VERSION}
ASSET=craton-hsm-${VERSION}-${TARGET}.tar.gz

curl -fsSLO "${BASE}/${ASSET}"
curl -fsSLO "${BASE}/${ASSET}.sigstore.json"
curl -fsSLO "${BASE}/SHA256SUMS"
curl -fsSLO "${BASE}/SHA256SUMS.sigstore.json"

# 1. The checksum file was signed by this repository's release workflow for a v* tag
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
    --certificate-identity-regexp '^https://github\.com/craton-co/craton-hsm-core/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    SHA256SUMS

# 2. The tarball matches the signed checksum
sha256sum --ignore-missing -c SHA256SUMS

# 3. (Optional) Verify the tarball's own cosign bundle
cosign verify-blob --bundle "${ASSET}.sigstore.json" \
    --certificate-identity-regexp '^https://github\.com/craton-co/craton-hsm-core/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "${ASSET}"

# 4. (Optional) Verify SLSA build provenance with the GitHub CLI
gh attestation verify "${ASSET}" --repo craton-co/craton-hsm-core \
    --signer-workflow craton-co/craton-hsm-core/.github/workflows/release.yml
```

After extracting, install the library **together with its `.sig` sidecar in
the same directory** (see [Module self-integrity signature](#module-self-integrity-signature)).
The module checks the signature at every `C_Initialize`.

## Module self-integrity signature

Independently of the distribution signatures above, the module verifies its
own binary at `C_Initialize` (FIPS 140-3 software integrity test) against an
Ed25519 signature in a `.sig` sidecar file next to the library
(`libcraton_hsm.so` → `libcraton_hsm.sig`, `craton_hsm.dll` → `craton_hsm.sig`).
The public key is embedded at build time.

Scheme (implemented in `src/crypto/integrity.rs`): the sidecar contains the
hex-encoded 64-byte Ed25519 signature over the 32-byte SHA-256 digest of the
library file as installed on disk. The 32-byte public key is compiled in from
the `CRATON_HSM_INTEGRITY_PUBLIC_KEY` build variable (64 hex characters).
There is no HMAC-based integrity check any more; a legacy `.hmac` file is
ignored (a warning is logged).

| Situation | Default build | `fips` build |
|---|---|---|
| `.sig` present and valid | pass | pass |
| `.sig` present, library modified | **fail** → `C_Initialize` returns an error, module in error state | **fail** |
| `.sig` missing | skipped (logged), passes | **fail** |
| public key not embedded (all-zero placeholder) | skipped, passes | **fail** |

Release builds always embed the key and ship the `.sig`, so the test is in
force for released binaries. A self-built library without an embedded key or
without `.sig` does **not** perform the integrity test unless built with the
`fips` feature.

```bash
# One-time: generate the signing key (encrypted PEM by default; the output
# directory must be private and outside any git work tree)
./tools/generate-integrity-keypair.sh            # Linux/macOS
.\tools\generate-integrity-keypair.ps1           # Windows

# Build with the printed public key embedded
CRATON_HSM_INTEGRITY_PUBLIC_KEY=<64 hex chars> cargo build --release --locked --lib

# Sign the built library (writes the .sig sidecar; self-verifies first)
./tools/sign-integrity.sh target/release/libcraton_hsm.so
.\tools\sign-integrity.ps1 -LibPath target\release\craton_hsm.dll
```

- For unattended signing, set `CRATON_HSM_SIGNING_KEY` (key path) and
  `CRATON_HSM_SIGNING_KEY_PASS_FILE` (a file readable only by the build user
  holding the key passphrase). Never pass the key or passphrase as a
  command-line argument.
- Key custody: prefer keeping the signing key in an HSM/KMS. If it is a file,
  keep it encrypted, owner-only (the scripts create it with `umask 077` /
  an owner-only ACL), off shared build hosts and never in version control.
- The former HMAC tooling (`tools/compute-integrity-hmac.sh` / `.ps1`) has
  been removed: the module no longer verifies `.hmac` sidecars, and the old
  script exposed the HMAC key in the process argument list. Rotate any key
  that was used with it and delete stale `.hmac` files.

## Repository configuration required for releases (maintainers)

| Setting | Where | Purpose |
|---|---|---|
| Variable `CRATON_HSM_INTEGRITY_PUBLIC_KEY` | Repository → Settings → Variables | 64-hex-char Ed25519 public key embedded in every build. Public; not a secret. |
| Environment `release` | Repository → Settings → Environments | Required reviewers; deployment tag rule `v*`. Holds secret `CRATON_HSM_INTEGRITY_SIGNING_KEY` (PEM private key) and, if the PEM is encrypted, `CRATON_HSM_INTEGRITY_SIGNING_KEY_PASSPHRASE`. The workflow refuses to sign if the private key does not match the public-key variable. |
| Environment `crates-io` | Repository → Settings → Environments | Required reviewers. On crates.io → crate settings → *Trusted Publishing*: repository `craton-co/craton-hsm-core`, workflow `release.yml`, environment `crates-io`. Delete any old `CARGO_REGISTRY_TOKEN` secret. |
| Tag protection | Repository → Settings → Rules | Only maintainers may create `v*` tags; tags must be signed (GOVERNANCE.md). |
| Branch protection on `main` | Repository → Settings → Rules | Required checks: `CI`, `Security Audit`; required review from CODEOWNERS. |

## What is *not* (yet) provided

Stated explicitly so that operators and evaluators do not assume more:

- **Bit-for-bit reproducibility is not verified.** The build pins the
  toolchain (`rust-toolchain.toml`), uses `--locked`, remaps runner paths and
  produces deterministic tarballs, but no independent rebuild comparison is
  performed. `protoc` is pinned in CI; the host C toolchain is not.
- **No Authenticode / Apple notarisation.** Windows and macOS binaries are
  covered by cosign + SHA256SUMS + provenance only.
- **No GPG signatures.**
- **Signed commits** are required by policy (GOVERNANCE.md), but the history
  imported at open-sourcing (`2f76874`) is a single unsigned commit, and the
  earlier versions listed in CHANGELOG.md have no tags in this repository.
- The POST known-answer tests check **algorithm correctness**, not binary
  integrity. Binary integrity at run time is provided only by the Ed25519
  self-integrity signature described above.

## Supply-chain controls summary

| Layer | Control |
|-------|---------|
| Source | CODEOWNERS review; branch/tag protection (repository settings); secret scanning in CI (trufflehog) |
| Dependencies | `Cargo.lock` committed and enforced with `--locked`; `cargo deny` (advisories, bans, licences, sources) and `cargo audit` on every PR and before every release; advisory suppressions only in `deny.toml` with reason and enforced expiry; Dependabot for Cargo (root and `fuzz/`), Actions, Docker and npm |
| CI | All workflows run with `permissions: contents: read` by default; third-party actions pinned by commit SHA |
| Build | Pinned Rust toolchain; `--locked`; release gated on full CI + audit; protected environments for signing and publishing |
| Artefacts | SHA256SUMS, cosign keyless bundles, SLSA build provenance, CycloneDX SBOMs, third-party licence notices |
| Runtime | Ed25519 software-integrity self-test at every `C_Initialize` (in force for release builds) |
