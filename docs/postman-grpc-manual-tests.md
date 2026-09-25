# Craton HSM — Kreya gRPC Manual Tests

> The file name is historical: the collection is for [Kreya](https://kreya.app/), not Postman.

## Security notice — rotate previously published PINs

Earlier revisions of this document and of `kreya/` contained a remote test
server endpoint and the SO / User PINs used against it, plus a Kreya profile
that disabled server-certificate validation. Those values are in the Git
history and **must be treated as compromised**:

- Re-initialise (InitToken) or decommission every HSM instance that ever used
  those PINs, and choose new PINs.
- Do not reuse the old PINs anywhere, including in tests.
- Firewall any remaining test server to known addresses and serve it only
  over TLS with client certificates (mTLS).
- Consider rewriting the repository history if the server was ever
  production-like.

The repository now ships only placeholders. Keep real endpoints and PINs in a
local Kreya environment file that is not committed (`kreya/.gitignore`
ignores every `*.krenv` except the sanitised `default.krenv`).

## Setup

### 1. Install Kreya

Download from [kreya.app](https://kreya.app/) (Windows, macOS, Linux).

### 2. Open the project

Open `kreya/CratonHSM-gRPC.krproj` in Kreya. The proto file is imported from
`craton-hsm-daemon/proto/craton_hsm.proto`.

### 3. TLS and client certificates

The daemon serves TLS 1.3 only and, by default, requires a client
certificate (mTLS). In Kreya's project settings, add:

- the CA that issued the daemon's server certificate (server validation stays
  **enabled**; do not disable it), and
- a client certificate + key issued by the CA configured as
  `[daemon] tls_client_ca`.

Administrator operations (InitToken, SO login, InitPin) additionally require a
client certificate whose SHA-256 fingerprint is listed in
`[daemon] admin_client_cert_sha256`. Compute it with:

```
openssl x509 -in admin.crt -outform DER | sha256sum
```

For purely local development you may run the daemon in plaintext on a
loopback address (`allow_insecure = true`, plus `insecure_loopback_admin = true`
to allow administrator operations); then set `server_url` to
`http://127.0.0.1:5696`. Never do this on a shared host.

### 4. Environment variables

`kreya/default.krenv` contains placeholders only:

| Variable | Meaning |
|----------|---------|
| `server_url` | `https://localhost:5696` by default (daemon default port) |
| `so_pin_b64` | Base64 of **your** SO PIN — set locally |
| `user_pin_b64` | Base64 of **your** User PIN — set locally |
| `session_handle` | Copy from the `02-OpenSession` response |
| `key_handle` | Copy from a key generation response |

Create a local environment (for example `kreya/local.krenv`, git-ignored)
with real values instead of editing `default.krenv`. Encode a PIN with
`printf '%s' "$PIN" | base64`.

---

## Authorization model (what the tests exercise)

- Sessions belong to the client identity (certificate) that opened them;
  other clients get "Session not found".
- Login state is per client and slot; one client's login or logout never
  affects another client. Closing your last session on a slot logs you out.
- The SO role (administrator certificate only) can administer the token but
  cannot use keys. Key operations, Digest and GenerateRandom require login;
  key operations require the **User** role.
- Sessions are closed automatically when the client's connection closes or
  after `session_idle_timeout_secs` of inactivity.
- Keys are ephemeral until the core's persistent store is enabled; until then
  `CKA_TOKEN=true` is rejected.

## Tests — run in order

| Step | Operation | Notes | Expected |
|------|-----------|-------|----------|
| 01 | `InitToken` | Administrator certificate; no session may be open on the slot | `{}` |
| 02 | `OpenSession` | R/W session on slot 0; copy `sessionHandle` into `session_handle` | `{ "sessionHandle": "…" }` |
| 03 | `Login` (SO, `user_type` 0) | Administrator certificate | `{}` |
| 17 | `InitPin` | Re-presents the SO PIN, sets the User PIN | `{}` |
| 14 | `Logout` | Ends the SO login | `{}` |
| 18 | `Login` (User, `user_type` 1) | | `{}` |
| 04 | `GetTokenInfo` | `loginState` is **your** state (`UserLoggedIn`) | label, `initialized: true` |
| 05 | `GenerateRandom` | 32 bytes | `{ "randomData": "…" }` |
| 06 | `Digest` SHA-256 | `592` = CKM_SHA256 | 32-byte digest |
| 07 | `Digest` SHA-512 | `608` = CKM_SHA512 | 64-byte digest |
| 08 | `FindObjects` | | handles visible to you |
| 09 | `GenerateKey` AES | `CKA_VALUE_LEN` (353) is an 8-byte little-endian CK_ULONG (`IAAAAAAAAAA=` = 32) | `{ "keyHandle": "…" }` |
| 10 | `Sign` | `64` = CKM_SHA256_RSA_PKCS; needs an RSA private key in `key_handle` (generate one first) | signature, or an error without a key |

`06-DigestSHA256` / `07-DigestSHA512` hash the bytes of `"Hello RustHSM"`
(`SGVsbG8gUnVzdEhTTQ==`); verify with
`printf 'Hello RustHSM' | sha256sum`.

### Error-case tests

| Step | Operation | Expected |
|------|-----------|----------|
| 11 | `GenerateRandom` with session `999999` | `NOT_FOUND` (session not found) |
| 12 | `Login` with a wrong User PIN | `UNAUTHENTICATED`. **Every failure counts against the token's persistent lockout counter** — never run this against a shared server. After `max_login_attempts` failures from the same client, the daemon imposes a cooldown for that client only. |
| 13 | `GenerateRandom` of 99,999,999 bytes | `INVALID_ARGUMENT` (exceeds `max_random_length`, default 64 KiB) |

### Cleanup

| Step | Operation | Expected |
|------|-----------|----------|
| 14 | `Logout` | `{}` |
| 15 | `CloseSession` | `{}` |
| 16 | `GenerateRandom` on the closed session | `NOT_FOUND` |

---

## Project structure

```
kreya/
  CratonHSM-gRPC.krproj         # Kreya project file (open this)
  directory.krpref              # gRPC endpoint = {{server_url}}; certificate validation ON
  default.krenv                 # Placeholders only
  .gitignore                    # Ignores local *.krenv files
  craton-hsm/HsmService/
    01-InitToken/               # Each test is a directory with:
      InitToken.krop            #   - Operation definition (.krop)
      InitToken-request.json    #   - Request payload (.json)
    02-OpenSession/
    03-LoginSO/
    ...
    16-UseClosedSession/
    17-InitPin/
    18-LoginUser/
```

## Mechanism type reference

| Constant | Hex | Decimal | Algorithm |
|----------|-----|---------|-----------|
| CKM_SHA256_RSA_PKCS | 0x0040 | 64 | RSA PKCS#1 v1.5 with SHA-256 |
| CKM_SHA256 | 0x0250 | 592 | SHA-256 digest |
| CKM_SHA512 | 0x0260 | 608 | SHA-512 digest |
| CKM_AES_KEY_GEN | 0x1080 | 4224 | AES key generation |
| CKM_AES_GCM | 0x1087 | 4231 | AES-GCM encrypt/decrypt (no parameters; IV generated internally) |
| CKM_ECDSA_SHA256 | 0x1044 | 4164 | ECDSA with SHA-256 (P-256 keys) |
| CKM_EDDSA | 0x1057 | 4183 | EdDSA (Ed25519 keys; not FIPS-approved) |

Raw `CKM_RSA_PKCS`, generic `CKM_RSA_PKCS_PSS`, pre-hashed `CKM_ECDSA` and
unpadded `CKM_AES_CBC` are not offered by the gRPC daemon.

See [API Reference](api-reference.md) for the full mechanism list.
