# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Craton HSM, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Primary channel: [GitHub private vulnerability reporting](https://github.com/craton-co/craton-hsm-core/security/advisories/new).

Fallback (if you cannot use GitHub): e-mail `dev@craton.com.ar` with the
subject `[SECURITY] Craton HSM`. Do not include exploit details in that first
message; we will reply with an encrypted channel (a GitHub private advisory
invitation, or a PGP key published in this file once available).

### What to include

- Description of the vulnerability
- Steps to reproduce (or a proof-of-concept)
- Affected versions / commit
- Any potential impact assessment

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment and severity rating**: within 1 week
- **Fix or mitigation target** (from assessment): Critical 30 days, High 60 days, Medium/Low next scheduled release

Severity is rated with CVSS v3.1 (base score), adjusted for the deployment
model of a PKCS#11 library loaded into a host process.

### What happens next

1. We confirm receipt and begin investigation
2. We work with you to understand the scope and impact
3. We develop and test a fix, and prepare a release through the normal gated release workflow
4. **Coordinated disclosure:** we agree an embargo date with you (default: publication together with the fixed release, at most 90 days after the report). We publish a GitHub Security Advisory and request a CVE through GitHub (a CNA) for every confirmed vulnerability in a released version.
5. We credit you in the advisory (unless you prefer anonymity)

## Supported Versions

Only the latest release line receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.9.x (latest 0.9.1) | Yes |
| < 0.9   | No (no maintained branches or tags exist for older versions) |

## Security Design

Craton HSM's security architecture is documented in:

- [Security Model](docs/security-model.md) — threat model, key protection, side-channel resistance, known limitations
- [Security Policy (operator summary)](docs/security-policy.md) and the draft [FIPS 140-3 Security Policy](docs/fips-140-3-certification.md) — boundary, services, SSP table
- [Security Review Checklist](docs/security-review-checklist.md) — pre-audit self-assessment
- [Release Signing](docs/release-signing.md) — how to verify release artefacts

Craton HSM is **not** FIPS 140-3 validated.

## Scope

In scope:

- Memory safety issues (FFI boundary and other `unsafe` code)
- Key material leaks (in logs, error messages, debug output, core dumps)
- Authentication or authorization bypass (PIN verification, roles, session state machine, daemon client authorization)
- Cryptographic implementation flaws
- Side-channel vulnerabilities (timing, cache)
- Denial of service via crafted PKCS#11 calls or gRPC requests
- Audit log integrity bypass
- Supply-chain issues in this repository (CI workflows, release pipeline, signing)
- **Vulnerable or malicious third-party dependencies as shipped by Craton HSM.**
  Please also report them upstream; we track them through `cargo deny` /
  `cargo audit` and document any temporary acceptance, with an expiry date,
  in `deny.toml`.

Out of scope:

- Issues requiring physical access to the host machine (Level 1 software module)
- Social engineering attacks
- Findings that only affect the development tools in `tools/pkcs11-spy` when used as documented (debug only), unless they allow code execution

## Known accepted risks

Temporarily accepted advisories are listed, with justification and expiry,
in [`deny.toml`](deny.toml) (`[advisories] ignore`). Notably,
RUSTSEC-2023-0071 (Marvin timing side channel in the `rsa` crate) is **not
mitigated** on the default RustCrypto backend; see
[docs/security-model.md](docs/security-model.md).
