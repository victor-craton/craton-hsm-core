# Craton HSM Documentation

## Getting Started

- [Installation Guide](install.md) — build, test, deploy, configure
- [Configuration Reference](configuration-reference.md) — all `craton_hsm.toml` fields, defaults, and examples
- [Examples](examples.md) — usage examples for pkcs11-tool, OpenSSL, Python, Java, and configuration
- [FAQ](faq.md) — frequently asked questions

## API

- [API Reference](api-reference.md) — PKCS#11 C ABI functions and Rust library API
- [Migration Guide](migration-guide.md) — version upgrade instructions

## Architecture & Design

- [Architecture Overview](architecture.md) — module diagram, source layout, data flow
- [Security Model](security-model.md) — threat model, key protection, side-channel resistance
- [Fork Safety](fork-safety.md) — multi-process constraints and deployment patterns

## FIPS 140-3

- [FIPS Gap Analysis](fips-gap-analysis.md) — readiness status (not ready) and tracking of open items
- [FIPS Mode Guide](fips-mode-guide.md) — the approved-only (`fips`) build and its limits
- [FIPS 140-3 Certification](fips-140-3-certification.md) — draft security policy (normative boundary, services, SSP table, self-tests)
- [Security Policy](security-policy.md) — operator summary of the draft security policy

## Audit & Testing

- [Audit Scope](audit-scope.md) — boundary, algorithm inventory, self-tests, fuzzing
- [Security Review Checklist](security-review-checklist.md) — pre-audit self-assessment
- [Benchmarks](benchmarks.md) — performance measurements and SoftHSMv2 comparison
- [Tested Platforms](tested-platforms.md) — platform support matrix, CI pipeline

## Operations & Release

- [Operator Runbook](operator-runbook.md) — day-to-day operations
- [Troubleshooting](troubleshooting.md) — common errors, build issues, runtime problems
- [Release Signing](release-signing.md) — release artefacts, cosign/provenance verification, integrity signature
- [Future Work Guide](future-work-guide.md) — PQC upgrades, rand_core unification, FIPS certification, clustering, KMIP

## Presentations & Testing

- [Presentation](PRESENTATION.md) — project overview slide deck (Markdown)
- [Kreya gRPC Manual Tests](postman-grpc-manual-tests.md) — manual gRPC test procedures using Kreya
