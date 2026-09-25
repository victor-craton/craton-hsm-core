# Installation Guide

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Rust | pinned in `rust-toolchain.toml` (1.94.1); MSRV 1.89 | install [rustup](https://rustup.rs/); the pinned toolchain is installed automatically |
| protoc | 3.x+ (CI pins 36.2) | Required only for building the gRPC daemon |
| CMake, Clang, Go | recent | Required only for the optional `awslc-backend` feature (`aws-lc-fips-sys`). The daemon's TLS stack uses `ring` and does not need them. |
| Git | any | To clone the repository |

### Platform-specific setup

**Linux (Debian/Ubuntu)**
```bash
sudo apt-get install -y protobuf-compiler cmake build-essential
```

**macOS**
```bash
brew install protobuf cmake
```

**Windows**
```powershell
winget install Google.Protobuf Kitware.CMake
# Or: choco install protoc cmake
```

## Build from Source

```bash
# Clone
git clone https://github.com/craton-co/craton-hsm-core.git
cd craton-hsm-core

# Build core PKCS#11 library only
cargo build --release --locked

# Build everything (library + daemon + admin CLI + spy wrapper)
cargo build --release --locked --workspace
```

A self-built library does not embed an integrity-verification key, so the
software-integrity self-test is skipped (logged) unless you build with
`CRATON_HSM_INTEGRITY_PUBLIC_KEY` set and sign the library — see
[release-signing.md](release-signing.md#module-self-integrity-signature).
Prefer the signed release artefacts for production.

```bash
# FIPS-mode (approved-only) build — see fips-mode-guide.md
cargo build --release --locked --features fips,awslc-backend --lib
```

### Build artifacts

| Artifact | Linux | Windows | Description |
|----------|-------|---------|-------------|
| PKCS#11 library | `target/release/libcraton_hsm.so` | `target/release/craton_hsm.dll` | Load via `dlopen`/`LoadLibrary` |
| gRPC daemon | `target/release/craton-hsm-daemon` | `target/release/craton-hsm-daemon.exe` | Standalone network server |
| Admin CLI | `target/release/craton-hsm-admin` | `target/release/craton-hsm-admin.exe` | Token/key/PIN management |
| Spy wrapper | `target/release/libpkcs11_spy.so` | `target/release/pkcs11_spy.dll` | PKCS#11 call interceptor |

## Run Tests

```bash
# Full suite (MUST use a single thread: ABI tests share global PKCS#11 state)
cargo test --locked -- --test-threads=1

# With aws-lc-rs backend
cargo test --features awslc-backend -- --test-threads=1

# Individual suites
cargo test --test crypto_vectors -- --test-threads=1
cargo test --test crypto_vectors_phase2 -- --test-threads=1
cargo test --test pkcs11_compliance -- --test-threads=1
cargo test --test multipart_sign_verify -- --test-threads=1
cargo test --test multipart_encrypt_decrypt -- --test-threads=1
cargo test --test supplementary_functions -- --test-threads=1
cargo test --test drbg_tests -- --test-threads=1
```

## Run Benchmarks

```bash
# Full benchmark suite (criterion, ~5 minutes)
cargo bench

# Specific group
cargo bench -- rsa_sign
cargo bench -- aes_gcm
cargo bench -- ml_dsa

# Reports generated in target/criterion/
```

## Configuration

Craton HSM reads configuration from `craton_hsm.toml` (or the path in `CRATON_HSM_CONFIG`).

```toml
[token]
label = "My HSM Token"
storage_path = "craton_hsm_store"       # redb database directory
max_sessions = 100
max_rw_sessions = 10

[security]
pin_min_length = 8
pin_max_length = 64
max_failed_logins = 10               # lockout threshold
pbkdf2_iterations = 600000           # PIN hashing cost

[algorithms]
allow_weak_rsa = false               # block RSA < 2048
allow_sha1_signing = false           # block SHA-1 in signatures
enable_pqc = true                    # ML-DSA, ML-KEM, SLH-DSA

[audit]
enabled = true
log_path = "craton_hsm_audit.jsonl"
log_level = "all"                    # "all" | "crypto" | "auth" | "admin" | "none"

```

All fields have defaults. The **library** starts with built-in defaults when
no `craton_hsm.toml` exists; an existing but invalid file is an error. Paths
must be relative (absolute paths and `..` are rejected). `fips` builds ignore
the file entirely. See [configuration-reference.md](configuration-reference.md).

The **gRPC daemon** is different: it takes its configuration file path as
its first argument (default `craton_hsm.toml`), the file must exist, and it
must contain a `[daemon]` section in addition to the library sections above.
A missing or invalid daemon configuration is fatal. See the daemon section of
[configuration-reference.md](configuration-reference.md).

## Docker

```bash
# Build the image (from repository root)
docker build -t craton_hsm:latest -f deploy/Dockerfile .

# Run with your configuration and TLS material (the daemon needs a config
# file with a [daemon] section; there is no usable built-in default)
docker run -p 5696:5696 \
  -v /path/to/craton_hsm.toml:/etc/craton_hsm/craton_hsm.toml:ro \
  -v /path/to/tls:/etc/craton_hsm/tls:ro \
  craton_hsm:latest

# Run admin CLI inside the container
docker exec <container> /usr/local/bin/craton-hsm-admin status
```

The image is based on `gcr.io/distroless/cc-debian12:nonroot` — no shell, no package manager, runs as non-root (UID 65534).

## Kubernetes (Helm)

```bash
# TLS with client authentication (mTLS) is required by default: create the
# server certificate secret and a secret holding the client CA first.
kubectl create secret tls craton-hsm-tls \
  --cert=tls.crt --key=tls.key
kubectl create secret generic craton-hsm-client-ca --from-file=ca.crt=client-ca.crt

# Install the Helm chart (the chart directory is deploy/helm/craton-hsm)
helm install my-hsm deploy/helm/craton-hsm/ \
  --set image.repository=your-registry/craton-hsm \
  --set image.tag=0.9.1 \
  --set tls.clientCaSecretName=craton-hsm-client-ca

# Persistence (a PVC) is enabled by default; to change its size add:
#   --set persistence.size=5Gi
# The chart refuses to render if TLS or mTLS is disabled without an explicit
# acknowledgement (tls.acceptInsecure / tls.disableMtls).

# Verify (the chart ships no `helm test` hooks)
kubectl get pods -l app.kubernetes.io/instance=my-hsm
kubectl logs deploy/my-hsm-craton-hsm
```

### Helm values

Defaults from `deploy/helm/craton-hsm/values.yaml` (the file is
authoritative; this table is a summary):

| Parameter | Default | Description |
|-----------|---------|-------------|
| `image.repository` | `craton-hsm` | Container image |
| `image.tag` | `0.9.1` | Image tag |
| `daemon.bind` | `0.0.0.0:5696` | gRPC listen address |
| `daemon.replicas` | `1` | Replica count |
| `tls.enabled` | `true` | TLS for the gRPC endpoint (disabling it requires `tls.acceptInsecure=true`) |
| `tls.secretName` | `craton-hsm-tls` | Kubernetes TLS secret (resource names cannot contain `_`) |
| `tls.clientCaSecretName` | `""` | CA for client certificates (mTLS); disabling mTLS requires `tls.disableMtls=true` |
| `persistence.enabled` | `true` | PVC for the key store |
| `persistence.size` | `1Gi` | PVC size |
| `config.tokenLabel` | `Craton HSM Token` | PKCS#11 token label |
| `config.enablePqc` | `true` | Enable post-quantum mechanisms |

> **Known deployment issues (audit A3-09, owned by the deployment
> maintainers):** verify before production use that the image builds, that
> the configured storage/audit paths are accepted by the configuration
> validator (it rejects absolute paths), that the security settings you set
> in the chart are actually loaded by the daemon, and that the readiness
> probes succeed. See `docs/operator-runbook.md`.

## Using as a PKCS#11 Provider

### Generic

```bash
# Set the module path for any PKCS#11 consumer
export PKCS11_MODULE_PATH=/path/to/libcraton_hsm.so
```

### Java SunPKCS11

Java includes a built-in PKCS#11 provider (SunPKCS11) that works with any compliant module.

**SunPKCS11 config file** (`pkcs11.cfg`):
```
name = Craton HSM
library = /path/to/libcraton_hsm.so
slot = 0
```

**keytool** (JDK command-line key management). keytool prompts for the token
PIN when `-storepass` is omitted; do not put PINs on the command line (they
end up in shell history and `ps` output):
```bash
# List token info
keytool -providerClass sun.security.pkcs11.SunPKCS11 \
        -providerArg pkcs11.cfg \
        -keystore NONE -storetype PKCS11 \
        -list

# Generate RSA key pair
keytool -providerClass sun.security.pkcs11.SunPKCS11 \
        -providerArg pkcs11.cfg \
        -keystore NONE -storetype PKCS11 \
        -genkeypair -alias "my-key" -keyalg RSA -keysize 2048 \
        -sigalg SHA256withRSA -dname "CN=My App"

# Generate EC P-256 key pair
keytool -providerClass sun.security.pkcs11.SunPKCS11 \
        -providerArg pkcs11.cfg \
        -keystore NONE -storetype PKCS11 \
        -genkeypair -alias "ec-key" -keyalg EC -groupname secp256r1 \
        -sigalg SHA256withECDSA -dname "CN=My EC Key"

# Generate CSR (exercises signing through PKCS#11)
keytool -providerClass sun.security.pkcs11.SunPKCS11 \
        -providerArg pkcs11.cfg \
        -keystore NONE -storetype PKCS11 \
        -certreq -alias "my-key" -sigalg SHA256withRSA \
        -file request.csr
```

**Programmatic Java access** (KeyStore + Signature API):
```java
import java.security.*;
import javax.crypto.*;

// Load SunPKCS11 provider
Provider provider = Security.getProvider("SunPKCS11")
    .configure("/path/to/pkcs11.cfg");
Security.addProvider(provider);

// Open KeyStore
KeyStore ks = KeyStore.getInstance("PKCS11", provider);
char[] pin = System.console().readPassword("Token PIN: ");
ks.load(null, pin);
java.util.Arrays.fill(pin, '\0');

// Generate RSA key pair
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
kpg.initialize(2048);
KeyPair kp = kpg.generateKeyPair();

// Sign data
Signature signer = Signature.getInstance("SHA256withRSA", provider);
signer.initSign(kp.getPrivate());
signer.update("data to sign".getBytes());
byte[] sig = signer.sign();

// Verify signature
Signature verifier = Signature.getInstance("SHA256withRSA", provider);
verifier.initVerify(kp.getPublic());
verifier.update("data to sign".getBytes());
boolean valid = verifier.verify(sig);  // true
```

**Supported Java algorithms** via Craton HSM:

| Java Algorithm | PKCS#11 Mechanism |
|---------------|------------------|
| `SHA256withRSA` | `CKM_SHA256_RSA_PKCS` |
| `SHA384withRSA` | `CKM_SHA384_RSA_PKCS` |
| `SHA512withRSA` | `CKM_SHA512_RSA_PKCS` |
| `SHA256withECDSA` | `CKM_ECDSA_SHA256` |
| `SHA384withECDSA` | `CKM_ECDSA_SHA384` |
| `SHA-256` | `CKM_SHA256` |
| `SHA-384` | `CKM_SHA384` |
| `SHA-512` | `CKM_SHA512` |

**Known limitations:**
- Post-quantum algorithms (ML-DSA, ML-KEM, SLH-DSA) are not supported by SunPKCS11
- Token must be initialized with a user PIN before Java can access it
- The `slot` in `pkcs11.cfg` must match a configured slot index (default: `0`; configurable via `slot_count` in `craton_hsm.toml`)

**Troubleshooting:**

| Error | Cause | Fix |
|-------|-------|-----|
| `PKCS11Exception: CKR_TOKEN_NOT_PRESENT` | Token not initialized | Run `pkcs11-tool --module ... --init-token` or `craton-hsm-admin token init` first |
| `PKCS11Exception: CKR_PIN_INCORRECT` | Wrong PIN in `-storepass` | Use the user PIN, not the SO PIN |
| `java.security.ProviderException` | Library path wrong in config | Verify `library` path in `pkcs11.cfg` points to actual `.so`/`.dylib` |
| `CKR_CRYPTOKI_NOT_INITIALIZED` | Fork after init (e.g., Tomcat) | Ensure `C_Initialize` is called in the child process |

**Running interop tests** (Linux/macOS only — these shell scripts are not supported on Windows):
```bash
bash tests/interop/java_sunpkcs11.sh
```

### OpenSSL & pkcs11-tool

Craton HSM is compatible with the most common PKCS#11 CLI tools. The most reliable is `pkcs11-tool` from the OpenSC project.

**Prerequisites:**
```bash
# Debian/Ubuntu
sudo apt-get install opensc gnutls-bin

# macOS
brew install opensc

# Verify
pkcs11-tool --version
```

**pkcs11-tool — Token initialization and key management:**
```bash
MODULE=/path/to/libcraton_hsm.so

# List available slots
pkcs11-tool --module $MODULE --list-slots

# List supported mechanisms
pkcs11-tool --module $MODULE --list-mechanisms

# pkcs11-tool prompts for PINs when --pin / --so-pin are omitted. Never pass
# PINs as arguments. PINs must be 8-64 characters with at least two
# character classes (default policy).

# Initialize token (prompts for the new SO PIN)
pkcs11-tool --module $MODULE --init-token --label "MyToken"

# Set user PIN (log in as SO; prompts for the SO PIN and the new User PIN)
pkcs11-tool --module $MODULE --login --login-type so --init-pin

# Generate RSA-2048 key pair
pkcs11-tool --module $MODULE --keypairgen --key-type RSA:2048 \
    --label "my-rsa-key" --id 01 --login

# Generate EC P-256 key pair
pkcs11-tool --module $MODULE --keypairgen --key-type EC:secp256r1 \
    --label "my-ec-key" --id 02 --login

# List all objects
pkcs11-tool --module $MODULE --list-objects --login
```

**pkcs11-tool — Sign and verify:**
```bash
# Create test data (32 bytes = SHA-256 hash length)
dd if=/dev/urandom of=data.bin bs=32 count=1

# RSA sign (SHA256-RSA-PKCS)
pkcs11-tool --module $MODULE --sign --mechanism SHA256-RSA-PKCS \
    --id 01 --login \
    --input-file data.bin --output-file sig.bin

# RSA verify
pkcs11-tool --module $MODULE --verify --mechanism SHA256-RSA-PKCS \
    --id 01 --login \
    --input-file data.bin --signature-file sig.bin

# ECDSA sign (raw hash, no wrapping)
pkcs11-tool --module $MODULE --sign --mechanism ECDSA \
    --id 02 --login \
    --input-file data.bin --output-file ec_sig.bin

# SHA-256 digest
pkcs11-tool --module $MODULE --hash --mechanism SHA256 \
    --input-file data.bin --output-file digest.bin
```

**p11tool (GnuTLS):**
```bash
# List tokens
p11tool --provider=$MODULE --list-tokens

# List all objects (requires login for private objects)
p11tool --provider=$MODULE --list-all --login   # prompts for the PIN

# List mechanisms
p11tool --provider=$MODULE --list-mechanisms
```

**OpenSSL 3.x pkcs11-provider:**

OpenSSL 3.x supports PKCS#11 tokens via the `pkcs11-provider` module. This requires the provider to be installed separately.

```bash
# Install pkcs11-provider (Debian/Ubuntu)
sudo apt-get install openssl-pkcs11-provider

# Or build from source: https://github.com/latchset/pkcs11-provider
```

Create an OpenSSL config file (`openssl_pkcs11.cnf`):
```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so
pkcs11-module-path = /path/to/libcraton_hsm.so
# PIN read from a file readable only by the service account
pkcs11-module-token-pin = file:/etc/craton_hsm/token.pin
activate = 1
```

```bash
# List objects in token via OpenSSL
OPENSSL_CONF=openssl_pkcs11.cnf openssl storeutl \
    "pkcs11:token=MyToken?pin-source=file:/etc/craton_hsm/token.pin"

# Sign with a key from the token
OPENSSL_CONF=openssl_pkcs11.cnf openssl pkeyutl -sign \
    -provider pkcs11 -inkey "pkcs11:token=MyToken;object=my-rsa-key" \
    -in data.bin -out sig.bin

# List loaded providers
OPENSSL_CONF=openssl_pkcs11.cnf openssl list -providers
```

**OpenSSL 1.1.x engine_pkcs11 (legacy):**
```bash
# Install (Debian/Ubuntu)
sudo apt-get install libengine-pkcs11-openssl

# Sign using the engine
openssl pkeyutl -engine pkcs11 -sign \
    -keyform engine \
    -inkey "pkcs11:token=MyToken;object=my-rsa-key?pin-source=file:/etc/craton_hsm/token.pin" \
    -in data.bin -out sig.bin
```

### SSH Agent

```bash
# Add PKCS#11 module to SSH agent
ssh-add -s /path/to/libcraton_hsm.so
# Enter user PIN when prompted

# List keys from the HSM
ssh-add -L

# Remove PKCS#11 module
ssh-add -e /path/to/libcraton_hsm.so
```

**Known limitations:**
- SSH only uses RSA and ECDSA keys from the token (not Ed25519 via PKCS#11)
- The token must be initialized and contain at least one key pair
- Some SSH clients require the key to have `CKA_SIGN = true`

**OpenSSL / pkcs11-tool troubleshooting:**

| Error | Cause | Fix |
|-------|-------|-----|
| `No slot with a token was found` | Token not initialized | Run `pkcs11-tool --init-token` |
| `CKR_PIN_INCORRECT` | Wrong PIN | Use user PIN for operations, SO PIN for admin |
| `CKR_MECHANISM_INVALID` | Unsupported mechanism | Check `--list-mechanisms` for available mechanisms |
| `error loading pkcs11 module` | Wrong library path | Verify `--module` path; use absolute path |
| `CKR_CRYPTOKI_NOT_INITIALIZED` | Fork or re-exec | Call `C_Initialize` before operations |
| `Database is locked` | Another process has the DB open | Stop other Craton HSM instances or use `craton-hsm-daemon` |

**Running interop tests** (Linux/macOS only — these shell scripts are not supported on Windows):
```bash
bash tests/interop/openssl_pkcs11.sh
```

## Using the Admin CLI

The admin CLI prompts for all PINs and passphrases; it never takes them as
arguments. Run `craton-hsm-admin --help` (and `--help` on each subcommand)
for the authoritative list of subcommands, and see the Admin CLI section of
[examples.md](examples.md). Note that the admin CLI links the library
directly and is outside the module's cryptographic boundary (see
[fips-140-3-certification.md §1.5](fips-140-3-certification.md#15-module-boundary-canonical-definition)).

## Using the Spy Wrapper

The spy wrapper intercepts all PKCS#11 calls for debugging. It works with any PKCS#11 library, not just Craton HSM.

```bash
# Configure the spy
export PKCS11_SPY_TARGET=/path/to/libcraton_hsm.so   # real library
export PKCS11_SPY_LOG=spy.jsonl                     # log file

# Point your application to the spy instead
export PKCS11_MODULE_PATH=/path/to/libpkcs11_spy.so

# All PKCS#11 calls are logged as JSON lines:
# {"timestamp":"2025-01-15T10:30:01Z","function":"C_Sign","args":"mechanism=CKM_ECDSA","rv":"CKR_OK","duration_ms":2}
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `CKR_GENERAL_ERROR` on all calls | a self-test failed (module error state) | Check the log for the failing test; for an integrity failure reinstall the signed release library together with its `.sig`; then `C_Finalize` + `C_Initialize` or restart |
| `CKR_PIN_LOCKED` | Too many failed login attempts | The SO sets a new User PIN with `C_InitPIN` (e.g. `pkcs11-tool --login --login-type so --init-pin`) |
| `CKR_SESSION_COUNT` | Session limit reached | Close unused sessions; increase `max_sessions` |
| `CKR_CRYPTOKI_NOT_INITIALIZED` | `C_Initialize` not called | Call `C_Initialize(NULL)` first |
| `CKR_USER_PIN_NOT_INITIALIZED` / login fails on a new token | Token or User PIN not initialised | `C_InitToken`, then `C_InitPIN` as SO |
| Daemon fails to start | protoc missing at build time | Install protobuf-compiler |
| Daemon TLS error | Invalid cert/key path | Check paths in `[daemon]` config |
