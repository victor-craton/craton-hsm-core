# Examples

## Using Craton HSM as a PKCS#11 Library

### pkcs11-tool (OpenSC)

```bash
# Build the shared library
cargo build --release

# List available slots
pkcs11-tool --module target/release/libcraton_hsm.so --list-slots

# Initialize a token
pkcs11-tool --module target/release/libcraton_hsm.so --init-token --label "MyToken" --so-pin 12345678

# Initialize the User PIN
pkcs11-tool --module target/release/libcraton_hsm.so --init-pin --pin 87654321 --so-pin 12345678

# Generate an RSA key pair
pkcs11-tool --module target/release/libcraton_hsm.so --keypairgen --key-type rsa:2048 --label "mykey" --pin 87654321

# Sign a file
pkcs11-tool --module target/release/libcraton_hsm.so --sign --mechanism SHA256-RSA-PKCS --label "mykey" --pin 87654321 --input-file data.txt --output-file data.sig

# Generate random bytes
pkcs11-tool --module target/release/libcraton_hsm.so --generate-random 32 | xxd
```

### OpenSSL (via pkcs11 engine/provider)

```bash
# Set the module path
export PKCS11_MODULE_PATH=/path/to/libcraton_hsm.so

# List objects via OpenSSL
openssl engine -t pkcs11
```

### Python (PyKCS11)

```python
import PyKCS11

lib = PyKCS11.PyKCS11Lib()
lib.load("/path/to/libcraton_hsm.so")

# Get slot list
slots = lib.getSlotList(tokenPresent=False)
print(f"Available slots: {slots}")

# Open a session
session = lib.openSession(slots[0], PyKCS11.CKF_RW_SESSION | PyKCS11.CKF_SERIAL_SESSION)

# Login
session.login("87654321")

# Generate an AES key
template = [
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
    (PyKCS11.CKA_VALUE_LEN, 32),
    (PyKCS11.CKA_ENCRYPT, True),
    (PyKCS11.CKA_DECRYPT, True),
    (PyKCS11.CKA_LABEL, "my-aes-key"),
]
key = session.generateKey(template, PyKCS11.CKM_AES_KEY_GEN)

# Cleanup
session.logout()
session.closeSession()
```

### Java (SunPKCS11)

```java
// pkcs11.cfg:
// name = Craton HSM
// library = /path/to/libcraton_hsm.so

import java.security.*;
import sun.security.pkcs11.SunPKCS11;

Provider provider = new SunPKCS11("pkcs11.cfg");
Security.addProvider(provider);

KeyStore ks = KeyStore.getInstance("PKCS11", provider);
ks.load(null, "87654321".toCharArray());
```

## Using the gRPC Daemon

```bash
# Start the daemon
cd craton-hsm-daemon
cargo run --release -- --config craton_hsm.toml

# Key generation and other token operations go through PKCS#11
# (C_GenerateKey / C_GenerateKeyPair) or the daemon's gRPC API.
# The admin CLI (below) never takes PINs on the command line.
```

## Using the Admin CLI

`craton-hsm-admin` never accepts PINs or passphrases as arguments or
environment variables: it prompts for them on the terminal without echo, so
they do not end up in shell history or the process list. Run
`craton-hsm-admin --help` (and `<command> --help`) for the authoritative
syntax; exit codes are listed at the end of `--help`.

```bash
cd tools/craton-hsm-admin
ADMIN="cargo run --release --"
CFG=/etc/craton_hsm/craton_hsm.toml   # default; must exist, owned by you or root, not group/world-writable

# Read-only status (shows whether token state was loaded from persistent storage)
$ADMIN --config "$CFG" status
$ADMIN --config "$CFG" token info --json

# Verify the tamper-evident audit log on disk (exit code 6 if the chain is broken)
$ADMIN --config "$CFG" audit verify-chain

# Token initialisation: prompts for the SO PIN (current SO PIN if already
# initialised) and requires typing "initialize" (or --yes for automation)
$ADMIN --config "$CFG" token init --label "MyToken"

# PIN management (prompts for PINs)
$ADMIN --config "$CFG" pin change --user-type user
$ADMIN --config "$CFG" pin reset          # SO resets the User PIN

# Keys: list as User; import a raw 16/24/32-byte AES key; delete with typed confirmation
$ADMIN --config "$CFG" key list --role user
$ADMIN --config "$CFG" key import --file aes256.key --label "my-aes" --type aes
$ADMIN --config "$CFG" key delete --handle 42 --role user

# Backup / restore (SO login + typed confirmation; passphrase is prompted)
$ADMIN --config "$CFG" backup --output token.rhbk
$ADMIN --config "$CFG" restore --input token.rhbk --verify-only   # decrypt/validate only
$ADMIN --config "$CFG" restore --input token.rhbk

# Audit export for SIEM (SO login + typed confirmation)
$ADMIN --config "$CFG" audit export-ndjson > audit.ndjson
```

PINs must be at least 8 characters, contain at least 4 distinct characters
and must not be a sequence, a repeated pattern or a common value.

> **Standalone mode.** Until the CLI can open the persisted token state,
> commands that would otherwise have no lasting effect or need the SO PIN
> (`token init`, `pin *`, `key *`, `backup`, `restore`, `audit dump/export-*`)
> refuse with exit code 5 and make no changes. `status`, `token info`,
> `audit verify-chain` and `restore --verify-only` work in every mode.

## Configuration Examples

### Development Configuration

```toml
[token]
label = "DevToken"
storage_path = "dev_store"
max_sessions = 100
max_rw_sessions = 10

[security]
pbkdf2_iterations = 100000
pin_min_length = 4

[algorithms]
allow_weak_rsa = true
allow_sha1_signing = true

[audit]
enabled = false
```

### Production Configuration

```toml
[token]
label = "ProdToken"
storage_path = "prod_store"
max_sessions = 1000
max_rw_sessions = 100

[security]
pbkdf2_iterations = 600000
pin_min_length = 8
max_failed_logins = 5

[algorithms]
allow_weak_rsa = false
allow_sha1_signing = false

[audit]
enabled = true
log_path = "/var/log/craton_hsm/audit.jsonl"
```

### FIPS Approved Mode

```toml
[token]
label = "FIPSToken"
storage_path = "fips_store"

[security]
pbkdf2_iterations = 600000
pin_min_length = 8

[algorithms]
fips_approved_only = true
allow_weak_rsa = false
allow_sha1_signing = false
enable_pqc = false

[audit]
enabled = true
log_path = "/var/log/craton_hsm/audit.jsonl"
```

Build with the FIPS backend:
```bash
cargo build --release --features awslc-backend --no-default-features
```
