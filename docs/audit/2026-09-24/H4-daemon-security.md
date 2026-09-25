# H4 — craton-hsm-daemon (gRPC) & deployment: defensive security & code review

Date: 2026-09-24 · Track: H4 · Worktree: `/home/user/craton-hsm-audit-wt` · Review type: static, defensive (requested by code owner)

## Scope & method

**In scope**

- `craton-hsm-daemon/`:
  - `Cargo.toml`, `build.rs`
  - `proto/craton_hsm.proto` (218 lines)
  - `src/main.rs` (208), `src/config.rs` (158), `src/tls.rs` (125), `src/server.rs` (1,794)
- Deployment:
  - `deploy/Dockerfile`, `deploy/.dockerignore`
  - `deploy/helm/craton-hsm/**`: `Chart.yaml`, `values.yaml`, `values.schema.json`, and all templates
- Client artefacts:
  - `kreya/**`: the project file, environments, preferences and 16 request/operation pairs
  - `docs/postman-grpc-manual-tests.md`
- Root crate `src/`, read only to confirm how the daemon behaves:
  - `core.rs`
  - `session/{manager,handle}.rs`
  - `token/token.rs`
  - `store/{attributes,object}.rs`
  - `crypto/{keygen,mechanisms,sign,encrypt,digest}.rs`
  - `audit/log.rs`
  - `config/config.rs`
  - `pkcs11_abi/{functions,constants}.rs` (used to compare the daemon with the C ABI behaviour)
- Locked dependency versions, taken from `Cargo.lock`:
  - tonic 0.14.5, tower 0.5.3, hyper 1.8.1, h2 0.4.13, rustls 0.23.37, tokio-rustls 0.26.4, prost 0.14.3
  - I read tonic's `serve_internal` / `MakeSvc` in the local cargo registry. This confirmed where user layers and the per-connection limit are applied: `Server::layer` is applied once, so the `ConcurrencyLimitLayer` semaphore is shared by all connections.

**Method**

- Static review only. I did not build, test, run clippy, run containers, or send network traffic. I did not contact the remote host named in `kreya/remote.krenv`.
- A previous unverified draft was used only as a checklist. Every item below was traced in the source again. Several draft items were corrected, dropped or merged.
- By request, this report is written for defenders. Each issue gives the defect, the impact and the fix. It contains no exploit code, no client command sequences and no step-by-step abuse instructions.

**Confidence levels**

- **Confirmed**: the code path was read end to end in this tree.
- **Likely**: the conclusion also depends on documented behaviour of an external component (Kubernetes, Docker, the Linux kernel, tonic/hyper defaults) that I did not execute.
- **Possible**: plausible, but it depends on the environment or on data I could not observe.

## Attack surface overview (RPCs, auth, network exposure — descriptive)

### Transport and network exposure

| Aspect | Current behaviour | Evidence |
|---|---|---|
| Default bind | `127.0.0.1:5696` in the daemon. The Helm chart sets `0.0.0.0:5696`. | `config.rs:57-59`; `values.yaml:7` |
| TLS requirement | The daemon refuses to start without `tls_cert`/`tls_key` unless `allow_insecure = true`. Insecure mode is accepted only when the bind address parses as a loopback IP. | `main.rs:116-198`; `config.rs:110-126` |
| TLS versions / ALPN | rustls with the `ring` provider, TLS 1.3 only, ALPN `h2` | `main.rs:29-31`; `tls.rs:95-111` |
| Client authentication (mTLS) | **Optional in the daemon.** It is on only when `tls_client_ca` is set; otherwise a warning is logged. The Helm chart requires it unless `tls.disableMtls=true`. | `tls.rs:55-108`; `_helpers.tpl:38-42` |
| Use of client identity | **None.** No handler reads the peer certificate, the remote address or request metadata. A valid client certificate grants the whole API. | `server.rs` (whole file) |
| Revocation | One CRL file, read once at startup, parsed as DER. No reload and no OCSP. | `tls.rs:73-84` |
| Message limits | 4 MiB decode and 16 MiB encode per message | `main.rs:100-102` |
| Concurrency / timeouts | 30 s request timeout. 64 in-flight requests per connection. 256 in-flight requests in total, shared by all connections (the setting is misleadingly named `max_connections`). No limit on connection count, no handshake timeout, no HTTP/2 or TCP keepalive, no idle or max-age limit, no load shedding. | `main.rs:104-113`; tonic `MakeSvc` |
| Health / reflection | Neither `grpc.health.v1` nor reflection is registered. | `Cargo.toml:13-28`; `main.rs:164-190` |
| Kubernetes exposure | ClusterIP only (enforced). NetworkPolicy ingress on 5696 from same-namespace pods labelled `craton-hsm-client: "true"`. Egress limited to kube-dns, plus optional 80/443 to any destination. | `service.yaml:1-3`; `networkpolicy.yaml:14-45` |

### RPC inventory (17 unary RPCs, no streaming — `craton_hsm.proto:5-30`)

| RPC | What the daemon checks before acting | Notes |
|---|---|---|
| OpenSession | Slot exists | Allocates one of the token's session slots (100 / 10 RW by default). Needs no authentication. Sessions are never reaped. |
| CloseSession | Handle exists | Any caller that holds the handle can close it. |
| Login | Handle exists; daemon per-slot throttle | Login state is stored **on the token**, not on the session or the client. |
| Logout | Handle exists | Resets the token to Public, which logs out **every** client. |
| GetTokenInfo | Handle exists on the same slot | Label is always empty. Login state and counts are shown when *anyone* is logged in. |
| InitToken | **No session needed.** Daemon per-slot throttle only. | On an uninitialised token, the first caller sets the SO PIN. |
| GenerateKey / GenerateKeyPair | Handle plus token logged in (User **or SO**) | The caller's template is applied after the defaults, with almost no restrictions. |
| DestroyObject / FindObjects | Handle plus token logged in; object on the same slot | No read-write session check. |
| GetAttributeValue | Handle; login only if the object has `CKA_PRIVATE` | No limit on the length of `attribute_types`. |
| Sign / Verify | Handle plus token logged in; mechanism allow-list and policy | The algorithm is chosen from the **key type**, not the mechanism. |
| Encrypt / Decrypt | Handle plus token logged in; mechanism allow-list and policy | The algorithm is chosen from the mechanism; the key type is not checked. |
| Digest | Handle plus token logged in; size check | No algorithm-policy check and no audit record. |
| GenerateRandom | Handle plus token logged in; length check | Holds the global DRBG mutex for up to 1 MiB of output. |

### Authorization model

1. Authentication has two independent layers, and neither is bound to the other:
   - **Transport:** optional mTLS.
   - **PKCS#11 login:** state that lives on the token.
2. The session handle is the only per-client credential. It is a bearer value. It is not bound to:
   - the TLS peer,
   - the HTTP/2 connection, or
   - the principal that logged in.
3. As soon as any client logs in on slot *N*, every client that can open a session on slot *N* is treated as authenticated. That includes clients with no PIN.
4. The daemon treats SO and User as the same principal for all key operations.
5. There is no InitPIN or SetPIN RPC, and token state is not persisted. As a result the User role can never be set up over gRPC, so in practice every key operation runs as SO.

## Executive summary

| Severity | Count | IDs |
|---|---|---|
| Critical | 1 | H4-01 |
| High | 6 | H4-02 … H4-07 |
| Medium | 10 | H4-08 … H4-17 |
| Low | 8 | H4-18 … H4-25 |
| Informational | 3 | H4-26 … H4-28 |
| **Total** | **28** | |

### Overall assessment

The transport layer is solid:
- TLS 1.3 only, with ALPN `h2`.
- The daemon fails closed when TLS is missing.
- Plaintext is refused on non-loopback addresses.
- `try_into` is used for every protobuf-to-`CK_ULONG` conversion.
- Error messages are sanitised.
- PINs are never logged.

The gaps are in the layers above transport:
- **Authorization model:** the daemon puts the in-process PKCS#11 model (one application, login state per token) on the network without adding any per-client identity or isolation.
- **Lifecycle:** token state and keys are not persisted, and InitToken does not follow PKCS#11 semantics.
- **Resource governance:** handshakes, sessions, attribute sizes and repeated fields are unbounded.
- **Deployment:** the shipped Helm chart and Docker image cannot become healthy.

These problems combine:
1. Health probes fail (H4-13), so the pod restarts in a loop.
2. Every restart wipes all keys (H4-03).
3. Every restart also reopens a window where the first network caller becomes SO (H4-02).

### Top risks

1. **H4-01 (Critical): authentication is token-global.**
   - After any client logs in, every peer that can open a session, including one with no PIN, can sign, decrypt, generate and destroy keys.
   - `Logout` from any client logs out all clients.
   - SO is accepted for all user operations.
   - Evidence: `server.rs:298-321`, `src/session/manager.rs:52-57`, `src/token/token.rs:302-311`.
2. **H4-02 / H4-03 (High): first-caller SO takeover, and no persistence.**
   - The daemon builds a fresh in-memory `ObjectStore` and an uninitialised `Token` on every start (`src/core.rs:133-135`, `src/token/token.rs:169`).
   - `InitToken` needs no session (`server.rs:577-641`).
   - Result: keys are lost on every restart, and the first network caller after a restart sets the SO PIN.
3. **H4-04 (High): the TLS handshake runs inline in the accept loop with no timeout** (`main.rs:139-161`). One idle TCP connection stops all new connections. This needs no credentials.
4. **H4-05 (High): working-looking SO and User PINs, a public test endpoint over plaintext gRPC, and a client profile with certificate validation disabled are committed.**
   - Files: `kreya/*.krenv`, request JSONs, `kreya/directory.krpref:7`.
   - The PINs also appear in plaintext in `docs/postman-grpc-manual-tests.md:32-35`.
5. **H4-06 / H4-07 (High): caller-controlled templates and unbounded repeated fields.**
   - `GenerateKey` / `GenerateKeyPair` templates can replace key material (`CKA_VALUE`), class and key type, and can forge provenance attributes (`server.rs:706-713, 894-907`). The existing `FORBIDDEN_TEMPLATE_ATTRS` list is dead code (`server.rs:332-339`).
   - `GetAttributeValue` builds one response entry per requested type, with no cap and no size check before encoding (`server.rs:1064-1089`). A single request can drive the pod out of memory.

### Recommended remediation order

1. **Bind authorization to the caller:** H4-01 and H4-10.
2. **Fix lifecycle:** persistence (H4-03), gate InitToken (H4-02) and make InitToken wipe the token (H4-09).
3. **Bound resources:** handshake timeout (H4-04), request and attribute limits (H4-07), sessions (H4-10), and `spawn_blocking` for CPU-bound work (H4-12).
4. **Harden templates** (H4-06) and **bind mechanisms to key types** (H4-08).
5. **Fix the deployment:** health service and probes (H4-13), the settings the chart silently drops (H4-14), SIGTERM handling (H4-16), and the Docker build (H4-23).
6. **Revoke the committed credentials and scrub them from history** (H4-05). This should start immediately, in parallel with everything else.

## Findings

### H4-01 [Critical] Login state is token-global and not bound to any client; SO and User are not separated

- **Location:**
  - `craton-hsm-daemon/src/server.rs:283-321` (`require_session`, `require_logged_in`, `require_authenticated_session`)
  - `server.rs:410-488` (`login`), `server.rs:490-517` (`logout`)
  - `src/session/manager.rs:52-57` (a new session inherits the token's login state)
  - `src/token/token.rs:292-311` (`login_state` / `require_login`), `src/token/token.rs:686-694` (`logout`)
- **CWE:** CWE-287 Improper Authentication; CWE-639 Authorization Bypass Through User-Controlled Key; CWE-653 Improper Isolation or Compartmentalization
- **Confidence:** Confirmed
- **Description:**
  - The daemon serves every remote client from one `HsmCore` and one `Token` per slot.
  - `Login` calls `token.login()`. That changes a single `AuthState.login` field shared by the whole token (`token.rs:576-684`).
  - Authorization is `require_logged_in`. It only asks whether the *token* is in the `UserLoggedIn` state. The `UserAnotherAlreadyLoggedIn` arm (`server.rs:306-309`) also accepts `SoLoggedIn`.
  - Nothing ties a session handle to:
    - the TLS peer certificate (tonic exposes it through `Request::peer_certs()`, but the daemon never reads it),
    - the HTTP/2 connection, or
    - the client that entered the PIN.
  - Consequences:
    - Once one client has logged in, sessions opened by any other client pass every `require_authenticated_session` check.
    - `Logout` from any client resets the shared state for everyone.
    - While SO is logged in, read-only sessions cannot be opened at all (`manager.rs:40-45`).
  - SO can use user keys. The daemon lets SO run GenerateKey, Sign, Decrypt and so on. PKCS#11 forbids SO from using private objects. There is no InitPIN RPC, so over gRPC SO is effectively the only usable role; see the Kreya flow `03-LoginSO`.
  - When mTLS is on, the client certificate only gates the TCP connection. There is no per-certificate authorization, tenant mapping or audit attribution.
- **Impact:**
  - Anyone who can reach the port and complete TLS inherits the key-usage rights of whoever logged in last. When mTLS is off, that is anyone who can reach the port at all.
  - Signing and decryption oracles, key creation and key destruction all become available to unauthenticated peers.
  - Audit records attribute actions to session numbers, not identities, so misuse cannot be traced to a client.
- **Recommendation:**
  1. Move authentication state to a daemon-side *client session* object. Bind it to the authenticated transport identity: the mTLS certificate's SPKI hash or SAN.
     - Store the principal (User or SO, plus client identity) on each gRPC session.
     - Check it on every RPC.
     - Keep one PKCS#11 login per client, or perform the PKCS#11 login internally on behalf of daemon-authenticated principals.
  2. Reject any session handle that is presented from a different peer identity than the one that opened it.
  3. Enforce PKCS#11 role separation:
     - SO may only run token and PIN administration.
     - Key-usage RPCs require `UserLoggedIn`. Change `require_logged_in` to require exactly `UserLoggedIn` for key operations.
  4. Make `Logout` affect only the caller's own principal.
  5. Add an explicit authorization policy that maps client identities to allowed RPCs, slots and key labels. At minimum, have a separate "admin" certificate class for InitToken and other SO operations.
  6. Put the client identity in every audit record.

### H4-02 [High] Unauthenticated `InitToken` on a token that is uninitialised at every start: the first caller becomes SO

- **Location:**
  - `craton-hsm-daemon/src/server.rs:577-641`
  - `src/token/token.rs:125-181` (`so_pin_hash: None`, `AuthState::new()` → `initialized: false`, `token.rs:61-66`)
  - `src/token/token.rs:403-449` (`init_token` skips SO PIN verification when the token is not initialised)
  - `src/core.rs:133-135`
- **CWE:** CWE-306 Missing Authentication for Critical Function; CWE-1188 Insecure Default Initialization of Resource
- **Confidence:** Confirmed (code path). The restart frequency in Kubernetes is Likely (see H4-13).
- **Description:**
  - `InitToken` requires no session and no transport-level privilege. Its only limit is the per-slot in-memory throttle.
  - The daemon never loads persisted token state (H4-03), so the token starts uninitialised on every process start.
  - For an uninitialised token, `init_token` sets whatever SO PIN it receives.
  - After a crash, an OOM kill (H4-07), a liveness-probe restart (H4-13) or a deployment, whichever client reaches the daemon first becomes SO.
- **Impact:** Complete control of the HSM:
  - Choosing the SO PIN.
  - Key generation and use as SO, which is enough given H4-01.
  - Denial of service to the legitimate operator, who can no longer initialise the token.
- **Recommendation:**
  1. Do not expose `InitToken` on the general data-plane listener:
     - Remove it from the public service and provide token provisioning through the admin CLI or an out-of-band bootstrap (for example, a sealed initial SO PIN from a Kubernetes Secret or a one-time enrolment token read at startup).
     - Or, at minimum, require a dedicated admin mTLS identity and a pre-shared bootstrap secret.
  2. Persist the "initialised" flag and the PIN hashes (H4-03). Refuse to serve until the token is provisioned, instead of starting in an open state.
  3. Audit and alert on every `InitToken` attempt, including the client identity.

### H4-03 [High] Key material and token state are never persisted by the daemon, despite chart persistence settings

- **Location:**
  - `src/core.rs:133-135` and `171-173`: `ObjectStore::new()`, an in-memory store only.
  - `src/store/attributes.rs:61` (`with_persistence`) and `:114` (`load_from_store`): no caller anywhere in the workspace. A repository-wide search finds only the definitions.
  - `src/token/token.rs:166-180`: PIN hashes start as `None`. Only lockout counters are restored.
  - `deploy/helm/craton-hsm/values.yaml:42,60-63`: persistence enabled; `storage_path` on a PVC.
  - `templates/NOTES.txt:18-22`: implies that key material survives restarts when persistence is enabled.
- **CWE:** CWE-404 Improper Resource Shutdown or Release (loss of critical data); CWE-1188
- **Confidence:** Confirmed
- **Description:**
  - The daemon never wires the encrypted object store into `HsmCore`.
  - Objects generated with `CKA_TOKEN=true` stay in memory only. The token's SO and User PIN hashes and its "initialised" state are not persisted.
  - Only lockout counters are persisted, through `LockoutStore`. This gives a mixed state after a restart: the PIN lock flags survive, but the PINs do not.
- **Impact:**
  - Every restart, crash, OOM kill, rescheduling or upgrade silently destroys all keys.
  - For an HSM this is a loss of availability and integrity. For example, signing keys whose public halves were distributed become unusable.
  - It also enables H4-02.
  - Operators are misled because the chart provisions a PVC and describes persistence.
- **Recommendation:**
  1. Initialise `HsmCore` with `ObjectStore::with_persistence(...)`. Load the store at start, with the key unwrapped from a KEK held outside the pod, such as a KMS or a sealed secret.
  2. Persist token metadata (initialised flag, PIN hashes, label) with integrity protection.
  3. Until persistence is implemented, the daemon should:
     - refuse `CKA_TOKEN=true` objects,
     - log a prominent startup warning, and
     - the chart should state that keys are ephemeral.
  4. Add a start-up self-check that reports how many objects were restored.

### H4-04 [High] TLS handshake runs inside the accept loop with no timeout; no connection cap, idle timeout or keepalive

- **Location:**
  - `craton-hsm-daemon/src/main.rs:139-161` (`async_stream` incoming)
  - `main.rs:104-113` (limits)
  - tonic 0.14.5 `transport/server/mod.rs` `serve_internal`: `Some(Err(_)) => continue`, with no back-off
- **CWE:** CWE-400 Uncontrolled Resource Consumption; CWE-1088 Synchronous Access of Remote Resource without Timeout; CWE-770
- **Confidence:** Confirmed (code). The accept-error spin is Likely (it depends on OS file-descriptor limits).
- **Description:**
  - The incoming stream awaits `listener.accept()` and then awaits `tls_acceptor.accept(tcp)` in the same task, before it yields.
  - While one handshake is waiting on its peer, no other connection is accepted. rustls/tokio-rustls impose no handshake deadline.
  - Completed connections have:
    - no idle timeout,
    - no `http2_keepalive_interval` / `tcp_keepalive`,
    - no `max_connection_age`,
    - no global connection limit.
  - The `max_connections` setting actually limits in-flight *requests*. It is shared by all connections, because tonic applies `Server::layer` once and the cloned `ConcurrencyLimit` shares one semaphore.
  - If file descriptors run out, `accept()` fails immediately. The stream yields `Err`, tonic `continue`s, and the loop spins while logging at error level.
- **Impact:** A peer with no credentials can make the daemon stop accepting new clients:
  - with a single stalled handshake, or
  - by exhausting file descriptors with idle connections.
  The daemon then burns CPU and floods the logs. This is pre-authentication and happens even when mTLS is on.
- **Recommendation:**
  1. Do handshakes concurrently. Spawn each `tls_acceptor.accept` in its own task and wrap it in `tokio::time::timeout` (for example 10 s). Feed completed streams through an `mpsc` channel, or use `futures::StreamExt::buffer_unordered` with a bound.
  2. Add a global connection semaphore, acquired before the handshake and released when the connection closes, plus an optional per-source-IP cap.
  3. Configure `Server::builder()`:
     - `.http2_keepalive_interval(..)`, `.http2_keepalive_timeout(..)`
     - `.tcp_keepalive(..)`
     - `.max_connection_age(..)`
     - `.max_concurrent_streams(..)`
     - `.load_shed(true)`
  4. On `accept()` errors, sleep with exponential back-off (the approach hyper's and tonic's `TcpIncoming` use) instead of yielding immediately. Rate-limit the error log.
  5. Call `set_nodelay(true)` on accepted sockets (see Performance).
  6. Rename `max_connections` to `max_inflight_requests`, or implement a real connection limit.

### H4-05 [High] Committed PINs, a public plaintext test endpoint and disabled certificate validation in client artefacts

- **Location:**
  - `kreya/remote.krenv:3-5`: a routable public IPv4 endpoint over `http://`, with SO and User PINs (base64).
  - `kreya/default.krenv:4-5`: the same PINs.
  - `kreya/craton-hsm/HsmService/01-InitToken/InitToken-request.json:3` and `03-LoginSO/LoginSO-request.json:4`: the SO PIN is hard-coded rather than taken from the environment variable.
  - `kreya/directory.krpref:7`: `disableServerCertificateValidation: true`.
  - `docs/postman-grpc-manual-tests.md:20` (the endpoint) and `:32-35` (a plaintext "PIN Reference" table).
- **CWE:** CWE-798 Use of Hard-coded Credentials; CWE-312 Cleartext Storage of Sensitive Information; CWE-295 Improper Certificate Validation; CWE-319 Cleartext Transmission
- **Confidence:** Confirmed that the credentials are in tracked files (`git ls-files`). Whether they are still valid on the remote host is Possible; it was not checked.
- **Description:**
  - The repository publishes a remote test server address together with the exact SO and User PINs the test flow uses. base64 is encoding, not protection.
  - The server is reached over plaintext gRPC (`http://`). The shipped daemon refuses that on non-loopback addresses, which means the remote host runs a modified configuration or build, or sits behind a plaintext proxy.
  - The Kreya project preference disables server certificate validation for every environment. Anyone who reuses the profile against a TLS endpoint is exposed to MITM.
  - The `12-WrongPIN` test sends a wrong SO PIN. Running the collection repeatedly against a shared server adds to the persistent SO failure counter (H4-11).
- **Impact:**
  - Anyone who reads the repository can authenticate as SO to the listed server, if it still runs with these PINs. PINs and key operations to that host travel in cleartext.
  - The PIN pattern invites reuse in other environments.
- **Recommendation:**
  1. Treat the PINs as compromised:
     - Re-initialise or decommission the remote test server.
     - Firewall it to known addresses.
     - Put it behind TLS and mTLS.
  2. Remove `remote.krenv` from the repository. Replace the PINs with placeholders or with Kreya secret or environment variables stored outside Git. Add `*.krenv` to `.gitignore`, except for a sanitised `example.krenv`. Consider rewriting history if the server was ever production-like.
  3. Remove `disableServerCertificateValidation` and ship a Kreya certificate configuration that references a local test CA.
  4. Delete the plaintext "PIN Reference" table from the documentation.

### H4-06 [High] Caller templates can override security-critical key attributes (key injection, type confusion, forged provenance, unbounded sizes)

- **Location:**
  - `craton-hsm-daemon/src/server.rs:696-713` (GenerateKey: defaults are set, then *every* template attribute except `CKA_VALUE_LEN` is applied)
  - `server.rs:894-907` (GenerateKeyPair: all public-template attributes except two, and *all* private-template attributes, are applied)
  - `server.rs:332-339` (`FORBIDDEN_TEMPLATE_ATTRS` is `#[allow(dead_code)]` and never used)
  - `src/store/attributes.rs:415-541` (`apply_attribute`), in particular:
    - `:421` `CKA_CLASS`, `:424` `CKA_KEY_TYPE`, `:427-432` `CKA_LABEL`/`CKA_ID` (no size limit)
    - `:436` `CKA_PRIVATE`, `:458` `CKA_DESTROYABLE`, `:467` `CKA_SIGN` etc.
    - `:482` `CKA_VALUE`, `:488-499` public components (no size limit)
    - `:528-538` unknown attributes (≤ 8 KiB each, ≤ 64)
- **CWE:** CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes; CWE-843 Access of Resource Using Incompatible Type; CWE-770
- **Confidence:** Confirmed
- **Description:** `apply_attribute` is a creation-time helper that trusts its input. The daemon hands it attacker-controlled templates *after* it has installed generated key material and security defaults. Only the one-way rules for `CKA_SENSITIVE` and `CKA_EXTRACTABLE` are enforced, which is why direct key extraction is still blocked. Everything else can be overridden:
  - **Key material:** `CKA_VALUE` replaces the freshly generated secret or private key with caller-supplied bytes. The object still carries "generated" semantics.
  - **Type:** `CKA_CLASS` and `CKA_KEY_TYPE` can relabel objects. Sign and Verify dispatch on `key_type` (H4-08), so a secret key can be used as if it were an EC private scalar, and vice versa.
  - **Usage flags:** `CKA_SIGN`, `CKA_DECRYPT`, `CKA_WRAP` and `CKA_DERIVE` can be set on any key. This enables cross-algorithm key reuse. `CKA_DESTROYABLE=false` makes an object impossible to delete until restart.
  - **Visibility:** `CKA_PRIVATE=false` lets the object's non-sensitive attributes be read without login.
  - **Provenance:** `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE` and `CKA_TRUSTED` are not handled explicitly. They fall into `extra_attributes`, and `GetAttributeValue` then returns caller-chosen values for them. Relying parties that check these attributes can be misled.
  - **Sizes:** `CKA_LABEL`, `CKA_ID`, `CKA_MODULUS`, `CKA_PUBLIC_EXPONENT`, `CKA_EC_PARAMS` and `CKA_EC_POINT` have no length limit beyond the 4 MiB message size. The object store holds up to 10,000 objects (`attributes.rs:21`), so memory use is unbounded in practice.
- **Impact:**
  - The HSM's core guarantee that keys are generated inside and bound to their algorithm is broken.
  - Injected keys are known to the injector yet presented as HSM-generated.
  - Type confusion undermines algorithm separation and audit accuracy.
  - Large attributes cause memory exhaustion (see H4-07).
- **Recommendation:**
  1. Use an allow-list of caller-settable attributes per mechanism. For example: `CKA_LABEL`, `CKA_ID`, `CKA_TOKEN`, `CKA_PRIVATE` (only toward true), the usage flags consistent with the key type, `CKA_SENSITIVE` (only toward true), `CKA_EXTRACTABLE` (only toward false), `CKA_START_DATE`/`CKA_END_DATE`, and `CKA_VALUE_LEN`/`CKA_MODULUS_BITS`/`CKA_EC_PARAMS` as generation parameters.
  2. Reject `CKA_VALUE`, `CKA_CLASS`, `CKA_KEY_TYPE`, public components and the provenance attributes with `CKR_TEMPLATE_INCONSISTENT`. Wire in `FORBIDDEN_TEMPLATE_ATTRS` and extend it.
  3. Set `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE` server-side.
  4. Validate usage flags against the key type. For example, EC keys cannot have `CKA_DECRYPT`, and AES keys cannot have `CKA_SIGN` unless a MAC is supported.
  5. Cap every variable-length attribute: labels and IDs to about 256 bytes, public components to the maximum for the algorithm. Cap the number of template entries (about 32).
  6. Better still, route daemon key generation through the same core entry point the C ABI uses (`C_GenerateKey` / `C_GenerateKeyPair` logic), so both surfaces share one validated implementation.

### H4-07 [High] Memory amplification: unbounded `attribute_types` and large in-flight messages can OOM the pod

- **Location:**
  - `craton-hsm-daemon/src/server.rs:1064-1089` (one response entry per requested type, with each value cloned)
  - `proto/craton_hsm.proto:144-148` (`repeated uint64 attribute_types`)
  - `main.rs:100-113` (4 MiB decode × 256 global in-flight requests)
  - `deploy/helm/craton-hsm/values.yaml:15-18` (256 Mi memory limit)
- **CWE:** CWE-770 Allocation of Resources Without Limits or Throttling; CWE-789 Memory Allocation with Excessive Size Value; CWE-400
- **Confidence:** Confirmed (code path). Out-of-memory in the pod is Likely (it depends on the allocator and cgroup limits).
- **Description:**
  - **Per-request amplification.** A 4 MiB request can carry about 2 million packed attribute-type varints. For each one, the handler clones the attribute value into a new `Attribute`. With the unbounded attribute sizes in H4-06 (for example a large `CKA_LABEL`), or even a 512-byte RSA modulus, the response vector grows to gigabytes. The 16 MiB encode limit only applies *after* the whole vector has been built.
  - **Aggregate load.** Up to 256 concurrent requests can each hold a 4 MiB decoded body plus the prost copy, roughly 2 GiB in the worst case. The pod limit is 256 Mi. There is no load shedding.
  - **Object requirement.** A login is needed only if the object has `CKA_PRIVATE=true`. That can be switched off through the template (H4-06). And because of H4-01, login is shared anyway.
- **Impact:**
  - One request can crash the daemon (OOM kill or allocation abort).
  - Because of H4-03 a crash also destroys every key, and because of H4-02 it reopens the InitToken window.
- **Recommendation:**
  1. Reject `attribute_types.len()` above a small bound, such as 64. De-duplicate the types.
  2. Keep a running byte budget while building the response and return `RESOURCE_EXHAUSTED` before cloning past the encode limit.
  3. Limit repeated fields in *all* messages (`template`, `public_template`, `private_template`) and each `bytes` field by RPC. For example, Digest, Sign and Encrypt data should be capped to what the mechanism needs.
  4. Lower `max_decoding_message_size` to what the API needs (about 1 MiB). Use a global in-flight *byte* budget, or reduce the global concurrency limit so that the product of concurrency and message size fits in the pod limit with headroom.
  5. Enable `load_shed(true)` so excess requests fail fast instead of queuing.

### H4-08 [Medium] Mechanism not bound to key type; FIPS and algorithm-policy bypass; Digest skips policy and audit

- **Location:**
  - `craton-hsm-daemon/src/server.rs:1113-1177` (Sign), `1207-1300` (Verify), `1359-1420` / `1478-1535` (Encrypt/Decrypt), `1551-1581` (Digest)
  - `src/crypto/mechanisms.rs:236-273` (`validate_mechanism_for_policy` looks only at the mechanism)
  - `src/crypto/sign.rs:465-476` (the P-256 signer always hashes with SHA-256)
  - `src/crypto/digest.rs:19-23` (the comment says the caller must apply the SHA-1 policy)
- **CWE:** CWE-327 Use of a Broken or Risky Cryptographic Algorithm (policy bypass); CWE-693 Protection Mechanism Failure; CWE-778 Insufficient Logging
- **Confidence:** Confirmed
- **Description:**
  - **Sign / Verify.** These validate `mech_type` against the policy, then choose the algorithm from `key.key_type`. Consequences:
    - An Ed25519 key is used for EdDSA even when the request names `CKM_ECDSA`, which is approved in FIPS mode, so non-approved EdDSA runs in `fips_approved_only` mode.
    - An EC key accepts RSA mechanism identifiers.
    - For P-256 and P-384 the hash is fixed by the curve. `CKM_ECDSA_SHA384`/`_SHA512` on P-256 silently use SHA-256.
    - `CKM_ECDSA`, which by PKCS#11 semantics takes a pre-computed digest, is hashed again.
    - The audit record logs the requested mechanism and `fips_approved`, not the algorithm that actually ran.
  - **Encrypt / Decrypt.** These dispatch on the mechanism and never check `key.key_type`. Mismatches mostly fail inside the primitives, but the daemon relies on that by accident rather than by design.
  - **Digest.** It never calls `validate_mechanism_for_policy`, so SHA-1 is served in FIPS mode even though the core documents that the caller must block it. Digest also writes no audit record.
- **Impact:**
  - Silent FIPS non-compliance.
  - Signatures that do not match what the client requested, which causes interoperability failures.
  - Misleading audit trails.
  - Combined with H4-06 (`CKA_KEY_TYPE` override), keys can be used across algorithms.
- **Recommendation:**
  1. Keep a single `(mechanism → allowed key_type(s), hash, params)` table. Reject any mismatch with `KeyTypeInconsistent` before dispatch.
  2. Pass the mechanism's hash explicitly to the EC signers, and support prehashed `CKM_ECDSA`.
  3. Map Ed25519 to `CKM_EDDSA` only.
  4. In Digest, call `validate_mechanism_for_policy` and `self.audit(...)`.
  5. In the audit record, include the key type and algorithm actually used.

### H4-09 [Medium] Daemon `InitToken` does not close sessions, destroy objects or reset counters (key remanence, session-limit bypass)

- **Location:**
  - `craton-hsm-daemon/src/server.rs:577-641`
  - The C ABI does these steps correctly: `src/pkcs11_abi/functions.rs:514-520` (`close_all_sessions`, `object_store.clear()`, `force_reset_all_counters()`)
  - `src/token/token.rs:447-448` (session counters reset to 0 while sessions still exist)
- **CWE:** CWE-226 Sensitive Information in Resource Not Removed Before Reuse; CWE-459 Incomplete Cleanup
- **Confidence:** Confirmed
- **Description:**
  - When an initialised token is re-initialised, the daemon only calls `token.init_token`, which:
    - verifies the SO PIN,
    - resets auth state, and
    - sets the session counters to 0.
  - It does *not*:
    - close existing sessions,
    - clear the object store, or
    - reset the per-key GCM and IV trackers.
  - Existing objects keep `slot_id` and stay visible to the new owner.
  - Sessions opened before the reset remain valid. Because the counters are reset while those sessions still exist, `max_sessions` can be exceeded. Later `CloseSession` calls hit the underflow guard in `decrement_session_count` and return "Internal error".
- **Impact:**
  - Re-initialisation, which operators use to wipe a token, leaves all previous keys usable.
  - Session accounting is corrupted.
- **Recommendation:**
  1. Reuse the C ABI order: close all sessions on the slot, clear the objects for that slot, reset the per-key counters, then `init_token`.
  2. Better, factor this into a single `HsmCore::init_token(slot, pin, label)` that both front-ends call.
  3. Only perform the destructive steps after the SO PIN has been verified.

### H4-10 [Medium] Pre-auth session exhaustion; session handles are unbound bearer tokens and are never reaped

- **Location:**
  - `craton-hsm-daemon/src/server.rs:343-408`
  - `src/session/manager.rs:27-86`
  - `src/token/token.rs:701-725` (`increment_session_count`)
  - `src/session/handle.rs` (4-round Feistel "scrambler" with a non-cryptographic round function)
- **CWE:** CWE-400; CWE-613 Insufficient Session Expiration; CWE-384 Session Fixation (bearer handle not bound); CWE-330
- **Confidence:** Confirmed (exhaustion, no binding, no reaping). Predictability of handles is Possible.
- **Description:**
  - `OpenSession` needs no credentials beyond reaching the port.
  - The token allows 100 sessions and 10 read-write sessions by default.
  - Sessions have:
    - no owner,
    - no idle timeout, and
    - no link to the HTTP/2 connection, so nothing is cleaned up when the client disconnects.
  - Any client that knows or guesses a handle can use it or close it.
  - Handles are obfuscated with a keyed Feistel permutation built on multiply-xorshift round functions. This is not a cryptographic PRP, so handles should not be treated as secret capabilities.
- **Impact:**
  - One client can use up all sessions, and all other clients are then refused until the daemon restarts.
  - A crashed client leaks its sessions permanently.
  - Handle confusion lets one client affect another client's sessions.
- **Recommendation:**
  1. Bind each session to the opening client's transport identity (H4-01) and reject use from any other identity.
  2. Track sessions per connection. When the connection closes (for example, a guard dropped when the connection ends, or tonic connection-info plus a reaper), close them.
  3. Add an idle-session timeout and a per-identity session quota. Keep a reserve for admin identities.
  4. If handles must act as capabilities, generate them from a CSPRNG with at least 128 bits. Otherwise document that they are not secrets and rely on binding.

### H4-11 [Medium] Login throttling and lockout: shared per slot, counts non-PIN errors, racy, and allows anonymous persistent PIN lockout

- **Location:**
  - `craton-hsm-daemon/src/server.rs:98-156` (per-slot throttle)
  - `server.rs:431-487` (`record_login_failure` runs for *every* error)
  - `server.rs:174-231`, `586`, `623` (InitToken throttle)
  - `src/token/token.rs:640-675` (SO lockout persisted after `max_failed_logins`)
  - `token.rs:410-431` (InitToken: back-off only, no lockout, capped at 5 s)
- **CWE:** CWE-307 Improper Restriction of Excessive Authentication Attempts; CWE-645 Overly Restrictive Account Lockout Mechanism; CWE-367 TOCTOU
- **Confidence:** Confirmed
- **Description:**
  - **Scope.** The daemon throttle is keyed only by `slot_id`. All clients share it, so a failure caused by any client locks Login for everyone for `login_cooldown_secs`.
  - **What counts as a failure.** `record_login_failure` also runs for errors that are not PIN failures, such as `UserAlreadyLoggedIn`, `TokenNotInitialized` and `PinRateLimited`. With a shared login state (H4-01), normal clients that call Login while someone else is already logged in trip the cooldown.
  - **Race.** Check and record are separate critical sections (`server.rs:102-123` and `139-155`), so concurrent attempts all pass the check. The token-level back-off, taken under its mutex, is the effective control.
  - **Persistent lockout.** Token-level lockout is permanent: user or SO PIN locked after `max_failed_logins` (10 by default). A caller who holds only an anonymous session can therefore lock the SO or User PIN persistently. The only SO recovery path is `InitToken` with the correct PIN, and through the daemon that does not wipe keys (H4-09).
  - **InitToken guessing.** InitToken guesses on an initialised token are limited only by back-off (at most 5 s) and the daemon cooldown. There is no lockout, and the in-memory throttle resets on restart.
- **Impact:**
  - Easy, unauthenticated, persistent denial of service against the administrator.
  - Legitimate multi-client use triggers spurious lockouts.
  - Slow but unbounded online guessing of the SO PIN through InitToken.
- **Recommendation:**
  1. Count only `PinIncorrect` and `PinLocked` as failures.
  2. Key the throttles by client identity (certificate or IP) *and* by account. Make check-and-record atomic (a single lock scope or an atomic counter).
  3. Require an authenticated admin identity (mTLS) before SO Login or InitToken attempts are accepted at all, so anonymous peers cannot touch the SO lockout counters.
  4. Add a slower, persistent budget for InitToken verification attempts, and alert on it.

### H4-12 [Medium] CPU-bound crypto and PBKDF2 run on async worker threads, some while holding the token mutex; timeouts cannot preempt them

- **Location:**
  - `craton-hsm-daemon/src/server.rs:442` (Login → PBKDF2, 600k iterations by default)
  - `server.rs:599` (InitToken → PBKDF2 hash/verify)
  - `server.rs:685`, `797-799` (AES / RSA-4096 key generation)
  - `server.rs:1147-1177`, `1239-1300` (RSA/EC sign and verify)
  - `server.rs:1577` (digest of up to 4 MiB)
  - `server.rs:1616-1619` (1 MiB from the DRBG under the global mutex)
  - `src/token/token.rs:579-684` (`self.auth.lock()` held across `verify_pin`)
- **CWE:** CWE-400; CWE-833 Deadlock (starvation variant); CWE-1050 Excessive Platform Resource Consumption within a Loop
- **Confidence:** Confirmed (code). The size of the latency impact is Likely.
- **Description:**
  - All handlers are `async fn`s with no `.await` points around heavy work. None use `spawn_blocking` or `block_in_place`.
  - RSA-4096 generation (seconds), PBKDF2 (hundreds of milliseconds at a 500m CPU limit) and large digests occupy a tokio worker for their whole duration.
  - `Token::login` and `init_token` hold the token's `auth` `parking_lot::Mutex` during PBKDF2. Every other RPC's `require_logged_in` needs that mutex, so the whole slot serialises behind one login attempt.
  - `Server::timeout` works by dropping the future at a yield point. Synchronous work never yields, so the 30 s timeout does not bound these operations.
  - Login needs only an anonymous session, so this cost is available before authentication, bounded only by the token back-off.
- **Impact:**
  - Latency spikes and throughput collapse.
  - A few concurrent key generations or logins can stall all workers, including HTTP/2 keepalive and handshake processing.
- **Recommendation:**
  1. Wrap CPU-bound sections in `tokio::task::spawn_blocking`, and bound them with a dedicated semaphore sized to cores.
  2. In the core, compute PBKDF2 *outside* the `auth` mutex: take a snapshot of the stored hash and rate-limit state, verify, then re-lock to commit. Keep the constant-time and lockout ordering guarantees.
  3. Consider a smaller per-request DRBG output cap, or a per-thread DRBG, to avoid serialising on the global mutex.

### H4-13 [Medium] Health checks cannot pass: no health service, and probes speak plaintext to a TLS-only port

- **Location:**
  - `deploy/helm/craton-hsm/templates/deployment.yaml:75-88` (`grpc:` readiness and liveness probes on 5696)
  - `deploy/Dockerfile:119-120` (`grpc_health_probe -addr=:5696` without TLS flags)
  - `craton-hsm-daemon/Cargo.toml:13-28` (no `tonic-health`)
  - `main.rs:164-166` (only `HsmService` is registered)
- **CWE:** CWE-1188; CWE-754 Improper Check for Unusual or Exceptional Conditions
- **Confidence:** Confirmed that no health service exists. Probe behaviour is Likely: Kubernetes gRPC probes do not support TLS, and `grpc_health_probe` without `-tls` sends cleartext HTTP/2.
- **Description:**
  - Both probes call `grpc.health.v1.Health/Check`. The daemon does not implement it, and in the chart it only accepts TLS.
  - Readiness never becomes true, and liveness fails 3 times (about 75 s after start), which restarts the container.
- **Impact:**
  - The chart as shipped yields a pod that is never Ready and restarts in a loop.
  - Each restart destroys all keys (H4-03) and reopens the InitToken takeover window (H4-02).
  - Operators may "fix" this by disabling TLS or probes, which weakens posture.
- **Recommendation:**
  1. Register `tonic_health::server::health_reporter()`. Mark the service `SERVING` only after POST and after the token has been loaded.
  2. Serve health on a *separate* loopback or plaintext port that only the kubelet can reach (for example, `127.0.0.1:5697` with `grpc.port: 5697`). Alternatively use an `exec` probe that runs `grpc_health_probe -tls -tls-ca-cert ... -tls-client-cert ...`.
  3. Update the Docker `HEALTHCHECK` to match.
  4. Use a `startupProbe` for slow POST or persistence load instead of a long `initialDelaySeconds`.

### H4-14 [Medium] Helm security settings are silently ignored (security.toml, CRL, lockout policy)

- **Location:**
  - `deploy/helm/craton-hsm/templates/secret-security.yaml:8-13`
  - `deployment.yaml:56-58, 102-104` (mounted at `/etc/craton-hsm/security`)
  - `configmap.yaml:12-41` (no `[security]` section, no `tls_client_crl`, no `fips_approved_only`)
  - `craton-hsm-daemon/src/main.rs:65-76` (the daemon reads only the single config path)
  - `src/config/config.rs:202-204` (default `max_failed_logins = 10`)
- **CWE:** CWE-1188; CWE-16 Configuration
- **Confidence:** Confirmed. A repository-wide search finds no reader of `security.toml`.
- **Description:**
  - The chart renders `pin_min_length`, `pin_max_length` and `max_failed_logins` into a separate Secret and mounts it. Neither the daemon nor `HsmConfig` ever loads that file.
  - The effective values are the built-in defaults. The chart documents 5 failed logins; the effective limit is 10.
  - `tls.clientCaSecretName` is supported, but there is no value for a client CRL, `fips_approved_only`, the request timeout, concurrency, or the random and digest limits.
  - `enablePqc: true` by default turns on non-FIPS mechanisms without making that visible.
- **Impact:** Operators believe policies are in force when they are not. There is no way to configure revocation or FIPS mode through the chart.
- **Recommendation:**
  1. Render the `[security]` section into the main TOML, or add an `include`/`security_config_path` option that the daemon actually loads and validates.
  2. Fail startup if an expected file is present but unused.
  3. Expose `tls.clientCrlSecretName` → `tls_client_crl`, `algorithms.fipsApprovedOnly`, and the daemon limits in `values.yaml` and the schema.
  4. Default `enablePqc` to `false`, or document it clearly.

### H4-15 [Medium] Object lifecycle and resource leaks: session objects outlive sessions; global object cap; DestroyObject skips GCM/IV tracker cleanup

- **Location:**
  - `craton-hsm-daemon/src/server.rs:381-408` (CloseSession does not destroy session objects)
  - `server.rs:937-974` (DestroyObject does not call `remove_gcm_counter`)
  - `src/store/attributes.rs:21` (`MAX_OBJECTS = 10_000`, global)
  - `src/crypto/encrypt.rs:136-148` (IV tracker: 10,000 keys × 100,000 IVs)
  - The C ABI does the cleanup: `src/pkcs11_abi/functions.rs:1088-1103`
- **CWE:** CWE-772 Missing Release of Resource after Effective Lifetime; CWE-770; CWE-459
- **Confidence:** Confirmed
- **Description:**
  - Objects created with `CKA_TOKEN=false` are not linked to the creating session, so they persist until the process restarts. That violates PKCS#11 session-object semantics.
  - All clients share one 10,000-object cap.
  - The daemon's DestroyObject never removes a key's entry from the AES-GCM counter, nonce-prefix or CBC/CTR IV tracker maps. Once 10,000 distinct keys have been used with CBC or CTR, every CBC/CTR encryption fails globally until restart. The IV sets can grow to about 100,000 entries per key.
- **Impact:**
  - Gradual or deliberate exhaustion leads to a service-wide denial of service.
  - Memory grows without bound.
  - Session-scoped secrets do not expire as clients expect.
- **Recommendation:**
  1. Record the owning session (and client identity) on session objects. Destroy them in CloseSession and in disconnect clean-up (H4-10).
  2. In DestroyObject, mirror the C ABI clean-up (`remove_gcm_counter`).
  3. Add per-identity object quotas.
  4. Share one core implementation between the C ABI and the daemon, as recommended in H4-06 and H4-09.

### H4-16 [Medium] SIGTERM is not handled (and is ignored as PID 1); the audit queue is fire-and-forget, unbounded, and lost on a hard stop

- **Location:**
  - `craton-hsm-daemon/src/main.rs:204-208` (`shutdown_signal` awaits only `ctrl_c`, i.e. SIGINT; its doc comment claims SIGTERM)
  - `deploy/Dockerfile:125` (the daemon is PID 1, with no init)
  - `src/audit/log.rs:514`, `571` (unbounded `std::sync::mpsc::channel`), `728-757` (`record` only enqueues)
  - `server.rs:251-268` (the doc comment claims audit fail-closed)
- **CWE:** CWE-404; CWE-778 Insufficient Logging; CWE-770
- **Confidence:** Confirmed (code). The PID 1 behaviour is Likely: the Linux kernel does not deliver default-action signals to PID 1 unless a handler is installed.
- **Description:**
  - Kubernetes and Docker stop containers with SIGTERM. The daemon installs no SIGTERM handler.
  - As PID 1, SIGTERM is effectively ignored. After the grace period the container receives SIGKILL, so there is no graceful drain.
  - `AuditLog::record` only pushes to an unbounded channel. A background thread does the hash-chaining and fsync.
  - The gRPC response is sent before the event is durable, so the "block the operation if the audit write fails" claim holds only for tamper detection.
  - On SIGKILL, queued events are lost. Under heavy load the queue grows without limit.
- **Impact:**
  - Security events are lost on every rollout or eviction, which weakens FIPS 140-3 / audit-trail guarantees.
  - Termination is slow (a 30 s hang).
- **Recommendation:**
  1. Handle `tokio::signal::unix::signal(SignalKind::terminate())` together with SIGINT.
  2. On shutdown: stop accepting connections, drain in-flight requests, and call `hsm.audit_log().flush()`.
  3. Use a bounded audit channel. On overflow, apply back-pressure or fail the request.
  4. For security-critical operations (Login, InitToken, key generation, destroy), wait for a durability acknowledgement.
  5. Add `tini`/`dumb-init`, or rely on the explicit handler. Set `terminationGracePeriodSeconds` to cover the drain.

### H4-17 [Medium] mTLS is optional by default in the daemon, and misspelled config keys are silently ignored

- **Location:**
  - `craton-hsm-daemon/src/tls.rs:100-107` (no client CA → only a warning)
  - `src/config.rs:9-55` (`#[derive(Deserialize)]` without `deny_unknown_fields`)
  - `main.rs:116-127`
- **CWE:** CWE-306; CWE-1188; CWE-16
- **Confidence:** Confirmed
- **Description:**
  - Outside Helm, a TLS-only configuration accepts any client that can complete a TLS handshake.
  - Because unknown keys are ignored, a typo in `tls_client_ca` (or a key placed in the wrong section) silently disables client authentication. The only sign is a warning log line.
  - Together with H4-01, this means the whole API is available to any network peer.
- **Impact:** It is easy to deploy by mistake with no client authentication on a network-exposed HSM.
- **Recommendation:**
  1. Require `tls_client_ca` whenever the bind address is not loopback. Allow opting out only with an explicit `allow_no_client_auth = true` that logs at error level.
  2. Add `#[serde(deny_unknown_fields)]` to `DaemonConfig`, and validate the whole file (including sections owned by `HsmConfig`) at startup.

### H4-18 [Low] CRL handling: loaded once, expiry not enforced, single DER file, documentation claims PEM

- **Location:** `craton-hsm-daemon/src/tls.rs:73-84`; `src/config.rs:19-21` (the doc says "PEM/DER")
- **CWE:** CWE-299 Improper Check for Certificate Revocation; CWE-672 Operation on a Resource after Expiration or Release
- **Confidence:** Confirmed (code). The expiry policy is Likely: rustls `WebPkiClientVerifierBuilder` ignores CRL `nextUpdate` unless `enforce_revocation_expiration()` is called.
- **Description:**
  - The file's raw bytes are wrapped as a single `CertificateRevocationListDer`. A PEM file fails verifier construction at startup, so the daemon fails closed, but the documentation is wrong.
  - Multiple CRLs (for example, one per intermediate) cannot be supplied.
  - The CRL is never reloaded, so a certificate revoked after start is accepted until restart.
  - An expired CRL is still trusted.
- **Impact:** Revoked client certificates can keep access indefinitely.
- **Recommendation:**
  1. Parse PEM or DER, and accept multiple files.
  2. Call `.enforce_revocation_expiration()`.
  3. Hot-reload the CRL on file change or on a timer, by rebuilding the `ServerConfig` behind an `ArcSwap`.
  4. Consider short-lived client certificates as an alternative.

### H4-19 [Low] PIN zeroization is incomplete

- **Location:** `craton-hsm-daemon/src/server.rs:414-445` (Login), `581-602` (InitToken); `proto/craton_hsm.proto:61-65, 95-99`
- **CWE:** CWE-226; CWE-316 Cleartext Storage of Sensitive Information in Memory
- **Confidence:** Confirmed
- **Description:**
  - `req.pin` / `req.so_pin` are zeroized only on the path that reaches `token.login` / `token.init_token`.
  - Early returns drop the `Vec<u8>` without zeroizing it:
    - Login: invalid `user_type`, invalid session, throttled, `get_token` error.
    - InitToken: throttled, `get_token` error.
  - PIN bytes also stay in the HTTP/2 and tonic decode buffers (`Bytes`/`BytesMut`), which are never scrubbed.
  - The prost-generated message types derive `Debug`, so any future `?req` log statement would print the PIN.
- **Impact:** PIN material stays in process memory longer than necessary and is exposed through core dumps or memory disclosure.
- **Recommendation:**
  1. Move the PIN into `Zeroizing<Vec<u8>>` (`std::mem::take`) as the *first* statement of the handler, so every path scrubs it.
  2. Mark the fields with `#[prost(skip_debug)]` or a custom `Debug` via `tonic_prost_build` `type_attribute`.
  3. Disable core dumps in the container: `ulimit -c 0` or `RLIMIT_CORE=0` at start.
  4. Document that transport buffers cannot be scrubbed.

### H4-20 [Low] Numeric truncation and missing validation of configuration values

- **Location:**
  - `craton-hsm-daemon/src/server.rs:793` (`CKA_MODULUS_BITS` `as u32`)
  - `server.rs:725` (`key_len as u32` in the audit record)
  - `server.rs:1005-1006` (`max_count as usize`)
  - `server.rs:149, 224` (`Instant::now() + login_cooldown` can panic on overflow for huge values)
  - `src/config.rs:24-55`
  - `main.rs:105-113`
- **CWE:** CWE-197 Numeric Truncation Error; CWE-1284 Improper Validation of Specified Quantity in Input; CWE-190
- **Confidence:** Confirmed
- **Description:**
  - `modulus_bits` values above `u32::MAX` wrap. For example, `2^32 + 2048` becomes 2048 and is accepted. It is otherwise harmless because only 2048, 3072 and 4096 are allowed.
  - The daemon configuration is not validated:
    - `request_timeout_secs = 0` makes every request time out.
    - `max_connections = 0` makes every request wait until timeout.
    - A very large `login_cooldown_secs` panics the handler task on the first lockout.
    - `max_digest_length` (16 MiB by default) exceeds the 4 MiB decode limit, so that check is dead.
    - A `max_random_length` above the 16 MiB encode limit produces encode errors.
- **Impact:** Misconfiguration causes denial of service. Some checks are silently ineffective.
- **Recommendation:**
  1. Use `u32::try_from` for `modulus_bits`.
  2. Validate `DaemonConfig` after load: non-zero bounds, cooldown ≤ 1 day, and `max_*_length` ≤ the message limits. Derive the message limits from those values.
  3. Use `checked_add` for `Instant` arithmetic.

### H4-21 [Low] EC key generation silently falls back to P-256 and stores the caller's (mismatching) `CKA_EC_PARAMS`

- **Location:** `craton-hsm-daemon/src/server.rs:826-856`, `1679-1682` (`is_p384_ec_params` substring search)
- **CWE:** CWE-20 Improper Input Validation; CWE-684
- **Confidence:** Confirmed
- **Description:**
  - Any `CKA_EC_PARAMS` that is not recognised as P-384 produces a P-256 key. That includes P-521, brainpool, garbage bytes and an empty value.
  - The object then records the caller's original parameter bytes.
  - P-384 detection accepts any byte string that *contains* the OID.
- **Impact:** Keys on an unexpected curve, and attribute data that is inconsistent with the actual key. That breaks interoperability and makes the security level ambiguous.
- **Recommendation:** Match the DER OID exactly (with an optional named-curve wrapper). Return `CKR_CURVE_NOT_SUPPORTED` / `invalid_argument` for anything else. Store canonical parameters derived from the generated key.

### H4-22 [Low] No read-only session enforcement for object-mutating RPCs

- **Location:** `craton-hsm-daemon/src/server.rs:643-974` (GenerateKey, GenerateKeyPair, DestroyObject). The C ABI enforces it: `src/pkcs11_abi/functions.rs:1077`.
- **CWE:** CWE-285 Improper Authorization
- **Confidence:** Confirmed
- **Description:** A read-only session (`read_write=false`) can create and destroy token objects. PKCS#11 requires a read-write session for this, and the C ABI checks `sess.is_rw()`.
- **Impact:** Clients cannot rely on RO sessions as a least-privilege mode.
- **Recommendation:** Check `session.is_rw()` for GenerateKey, GenerateKeyPair and DestroyObject when `CKA_TOKEN=true` (and for any future create, copy or set-attribute RPC).

### H4-23 [Low] Dockerfile: build is broken as committed; supply-chain and hygiene gaps

- **Location:**
  - `deploy/Dockerfile:16`, `:50-51`, `:59`, `:73-86`, `:97`, `:109`, `:119-120`
  - `deploy/.dockerignore` (placed in `deploy/`)
- **CWE:** CWE-1104 Use of Unmaintained Third-Party Components (toolchain); CWE-494 Download of Code Without Integrity Check (partial); CWE-16
- **Confidence:**
  - Confirmed: the missing file, and the locked dependencies requiring Rust 1.85.
  - Likely: `.dockerignore` placement. Docker reads `.dockerignore` from the context root, or `<Dockerfile>.dockerignore`.
- **Description:**
  - `COPY craton_hsm.toml` (`:59`) references a file that is not tracked in the repository, so a clean build fails.
  - `rust:1.83` (`:16`) cannot build the locked graph with `--locked`. For example, `clap 4.6.0` (used by `craton-hsm-admin`) and the RustCrypto 0.5/0.11 crates are `edition = "2024"` with `rust-version = "1.85"`. The root `Cargo.toml:14` still claims `rust-version = "1.75"`.
  - The build context is the repository root (`:8`), but the ignore file lives in `deploy/`, so it is not applied. `.git`, `target/` and any local `*.pem` / `*.key` files are sent to the builder. The selective `COPY` limits what reaches the image layers.
  - The dependency-priming build hides failures (`|| echo WARN`, `:50-51`).
  - `grpc_health_probe` is checked against a checksum file downloaded from the same origin (`:73-86`). That detects corruption, not a compromised release. Pin the expected SHA-256 in the Dockerfile.
  - The `apt-get` packages are unpinned.
  - `LABEL version="0.9.1"` (`:97`) does not match the daemon crate version `0.3.0`.
  - A default configuration is baked into the image (`:109`). Its contents cannot be reviewed because the file is missing.
  - The `HEALTHCHECK` is ineffective (H4-13).
- **Impact:** Images cannot be reproduced, build contexts may leak, and the supply chain is weaker.
- **Recommendation:**
  1. Commit an example config and copy it under an explicit name, or require a mounted config and drop the `COPY`.
  2. Pin `rust:1.85+` (or read `rust-toolchain.toml`) by digest. Update `rust-version`.
  3. Move the ignore file to the repository root, or rename it to `deploy/Dockerfile.dockerignore`.
  4. Pin the probe binary's SHA-256 inline.
  5. Fail the build on priming errors, or use `cargo chef`.
  6. Align the version labels.

### H4-24 [Low] Helm deployment hygiene: RWO volume with RollingUpdate, mutable image tag, broad optional egress, label-based trust

- **Location:**
  - `deploy/helm/craton-hsm/templates/deployment.yaml:1-12` (no `strategy`)
  - `pvc.yaml:9-10` (ReadWriteOnce)
  - `values.yaml:1-4` (tag, not digest)
  - `networkpolicy.yaml:38-45` (`allowOcsp` opens 80/443 to any destination)
  - `networkpolicy.yaml:15-20`
- **CWE:** CWE-16; CWE-1188
- **Confidence:** Likely
- **Description:**
  - A Deployment with the default RollingUpdate strategy (`maxSurge ≥ 1`) and a ReadWriteOnce PVC has two failure modes:
    - it stalls (a Multi-Attach error when the new pod lands on another node), or
    - when both pods land on the same node, two daemons write the same audit log and lockout file concurrently, which risks corrupting the audit hash chain.
  - The image is referenced by a mutable tag.
  - `allowOcsp` opens egress to the whole internet on 80/443, even though the daemon has no OCSP client.
  - Ingress trust depends on a pod label, which anyone who can create pods in the namespace can set.
- **Impact:** Operational failure or audit-integrity issues. Egress is broader than needed.
- **Recommendation:**
  1. Set `strategy: { type: Recreate }`, or use a StatefulSet.
  2. Support `image.digest`.
  3. Remove `allowOcsp`, or require explicit CIDRs.
  4. Document that mTLS (not the label) is the trust boundary, and optionally add a `namespaceSelector`.
  5. Optionally, the nested secret mounts under the read-only ConfigMap mount at `/etc/craton-hsm` could be moved to sibling paths (`/etc/craton-hsm-tls`, and so on) to avoid mount-ordering surprises.

### H4-25 [Low] GetTokenInfo discloses token-global login state to any session holder

- **Location:** `craton-hsm-daemon/src/server.rs:549-572`
- **CWE:** CWE-200 Exposure of Sensitive Information
- **Confidence:** Confirmed
- **Description:** The "redaction for unauthenticated callers" uses the *token's* login state, not the caller's. Any client with a session learns:
  - whether SO or User is currently logged in (`format!("{:?}", LoginState)`), and
  - the live session counts, whenever anyone is logged in.
- **Impact:** Useful reconnaissance for timing misuse of the shared login state (H4-01). Low on its own.
- **Recommendation:**
  1. Return login state only for the caller's own principal (after H4-01).
  2. Return a stable enum instead of the Rust `Debug` string.
  3. Return the real label, which is currently always empty.

### H4-26 [Informational] Audit coverage gaps

- **Location:** `craton-hsm-daemon/src/server.rs:1551-1581` (Digest: no audit); every crypto handler (only successes are audited); `server.rs:1304-1313` (Verify with `valid=false` is recorded as `Success`)
- **CWE:** CWE-778
- **Confidence:** Confirmed
- **Description / Recommendation:**
  - Audit failed and denied operations as well:
    - authorization failures,
    - policy rejections,
    - "not found" on key handles, which may indicate probing.
  - Audit Digest.
  - Record the verification outcome.
  - Record the client identity (H4-01).
  - Always record `InitToken` with the peer identity.

### H4-27 [Informational] Logging configuration

- **Location:** `craton-hsm-daemon/src/main.rs:34`; `Cargo.toml:24`
- **Confidence:** Confirmed
- **Description / Recommendation:**
  - `tracing_subscriber::fmt()` uses a fixed default level (INFO). The `env-filter` feature is not enabled, so `RUST_LOG` cannot change it.
  - TLS handshake failures and HSM error details are logged at `debug` (`main.rs:146`, `server.rs:1692`), so they are invisible in production.
  - The `json` feature is enabled but unused.
  - Enable `EnvFilter`, emit structured JSON for SIEM ingestion, and log handshake failures at `info` with rate limiting.
  - Positive: PINs, keys and request bodies are never logged, and client-facing errors are sanitised (`server.rs:1684-1794`).

### H4-28 [Informational] Documentation, proto comments and dead code are inconsistent with the implementation

- **Location:**
  - `proto/craton_hsm.proto:63` (says `CKU_SO=3`; the actual value is 0, per `src/pkcs11_abi/constants.rs:240`)
  - `craton-hsm-daemon/src/tls.rs:8-12` (says main.rs uses tonic's `ServerTlsConfig`; it no longer does)
  - `tls.rs:117-125` (unused `make_tls_acceptor`)
  - `server.rs:331-339` (unused `FORBIDDEN_TEMPLATE_ATTRS`)
  - `config.rs:50-51` (`max_connections` actually limits requests)
  - `main.rs:204` (claims SIGTERM)
  - `server.rs:251-253` (claims audit fail-closed)
  - `docs/postman-grpc-manual-tests.md`:
    - its file name says Postman but it describes Kreya;
    - it names `Craton HSM-gRPC.krproj` and `craton_hsm/` (actual: `CratonHSM-gRPC.krproj`, `craton-hsm/`);
    - it uses port 9898 (the daemon defaults to 5696);
    - `10-Sign` uses `CKM_RSA_PKCS`, which the core rejects without a hash.
- **Confidence:** Confirmed
- **Recommendation:** Correct the comments and documentation, remove the dead code or wire it in, and add a CI check that builds the Kreya/proto examples against the daemon.

## Stubs, TODOs and unimplemented items

The daemon source has no `TODO`, `FIXME`, `todo!()` or `unimplemented!()` markers. The items below are functional gaps or stubs found by reading the code.

| # | Item | Location | Status / effect |
|---|---|---|---|
| S1 | Object/token persistence | `src/core.rs:135`; `store/attributes.rs:61,114` never called | Not wired. All keys are ephemeral (H4-03). |
| S2 | InitPIN / SetPIN / SetAttributeValue / CopyObject / Wrap / Unwrap / Derive / multi-part ops / GetMechanismList / GetSlotList RPCs | `proto/craton_hsm.proto:5-30` | Absent. The User PIN cannot be provisioned over gRPC, so SO is the only usable role (H4-01). |
| S3 | gRPC health service | `Cargo.toml`; `main.rs:164-166` | Absent. Probes fail (H4-13). |
| S4 | `FORBIDDEN_TEMPLATE_ATTRS` | `server.rs:331-339` | Dead code, marked "retained for when mechanism dispatch is implemented (#20)" (H4-06). |
| S5 | `make_tls_acceptor` | `tls.rs:117-125` | Dead code. The module doc is stale (`tls.rs:8-12`). |
| S6 | GenerateKey mechanisms | `server.rs:684-688` | Only `CKM_AES_KEY_GEN`. |
| S7 | GenerateKeyPair mechanisms | `server.rs:784-892`; `mechanisms.rs:47-62` | ML-KEM, ML-DSA and SLH-DSA pass `is_keypair_gen_mechanism` but reach the "Unsupported" arm, after two object handles have already been allocated. |
| S8 | PQC and hybrid sign mechanisms | `server.rs:1147-1176` | Accepted by `is_sign_mechanism` but not implemented. The mechanism is ignored and the key type decides (H4-08). |
| S9 | `CKM_RSA_PKCS` (raw) sign | `server.rs:1154-1157` → `sign.rs:232-236` | Always rejected (`MechanismParamInvalid`). This is the documented example in Kreya `10-Sign`. |
| S10 | `CKM_RSA_PKCS_PSS` with parameters | `server.rs:1149-1153` | `mechanism.parameter` is ignored, so the generic PSS mechanism always fails. |
| S11 | AES-GCM parameters (IV, AAD, tag length) | `server.rs:1360-1368`, `1479-1487` | `mechanism.parameter` is ignored. The IV is generated internally, AAD is not supported, and the output format is non-PKCS#11. |
| S12 | `CKM_AES_CBC` vs `CKM_AES_CBC_PAD` | `server.rs:1369-1383` → `encrypt.rs:478-535` | Both use PKCS#7 padding. Unpadded CBC semantics are not implemented. |
| S13 | RSA-OAEP hash/MGF/label | `server.rs:1399-1415`, `1518-1530` | Fixed to SHA-256. Parameters are ignored. |
| S14 | Token label in GetTokenInfo | `server.rs:553` | Always an empty string. |
| S15 | CRL reload, OCSP | `tls.rs:73-84`; `networkpolicy.yaml:38-45` | Not implemented, yet the chart has an OCSP egress toggle (H4-18, H4-24). |
| S16 | `security.toml` loading | `secret-security.yaml`; `deployment.yaml:56-58` | Mounted, never read (H4-14). |
| S17 | SIGTERM handling | `main.rs:204-208` | Only SIGINT is handled (H4-16). |
| S18 | `CKU_CONTEXT_SPECIFIC` login | `server.rs:418-426` | Accepted by the daemon, then always rejected by the core (`UserTypeInvalid`), and counted as a failed attempt. |

## Code review

**Architecture / duplication**
- `server.rs` re-implements the PKCS#11 semantics that already exist, in hardened form, in `pkcs11_abi/functions.rs`. The daemon copy has fallen behind in several places:
  - InitToken wipe (H4-09)
  - DestroyObject GCM clean-up and RW checks (H4-15, H4-22)
  - template validation (H4-06)
- Recommendation: move the operation logic into `HsmCore` methods (`init_token`, `generate_key`, `sign(session, mech, key, data)`, ...) that take already-validated inputs. Make both the C ABI and gRPC thin adapters over them.
- The Sign, Verify, Encrypt and Decrypt handlers repeat the same preamble:
  - session/auth check
  - mechanism allow-list
  - policy check
  - key lookup
  - slot check
  - usage flag check

  Extract it into `fn load_key_for(&self, session, mech, key_handle, Usage) -> Result<(slot, Arc<RwLock<StoredObject>>), Status>`. That removes about 150 duplicated lines and makes it harder to forget a check.
- Two parallel throttle implementations (`login_attempts` / `init_token_attempts`, `server.rs:81-249`) differ only in the map. Use one generic `Throttle` type.

**Correctness**
- The `user_type` validation message and the proto comment disagree (`server.rs:423` vs `proto:63`).
- GenerateKeyPair allocates both handles before it validates the mechanism and templates (`server.rs:769-778`), so handles leak on error. The two `insert_object` calls are not atomic: if the private insert fails (for example, at the object cap) an orphan public key remains (`server.rs:909-918`).
- When the audit write fails *after* a successful state change, the client gets an error but the change is kept. This affects Login, GenerateKey, DestroyObject and InitToken (`server.rs:452-460`, `721-730`, `966-971`, `610-617`). Either write the audit record first (intent), or roll back the change.
- `GetAttributeValue` returns an empty value for both "sensitive" and "absent" (`server.rs:1075-1087`). PKCS#11 requires `CK_UNAVAILABLE_INFORMATION` and `CKR_ATTRIBUTE_SENSITIVE` / `CKR_ATTRIBUTE_TYPE_INVALID`. Clients cannot tell these cases apart.
- `GetAttributeValue` holds the object read lock across `require_logged_in` (which takes the token mutex) and the audit enqueue (`server.rs:1044-1097`). Drop the guard before auditing, as the Sign and Verify handlers already do.
- `find_objects` computes `is_logged_in` from a snapshot (`server.rs:998`), which the core documents as unsafe for authorization. It is harmless today only because `require_authenticated_session` precedes it.
- `GetTokenInfo` treats `session_handle == 0` specially (`server.rs:530-541`). Use `require_session` uniformly; 0 is already `CK_INVALID_HANDLE`.
- `label` in InitToken is truncated at 32 *bytes*, which can split a UTF-8 character (`server.rs:594-596`). Validate or truncate on a character boundary.

**Rust / API hygiene**
- `rustls` is compiled with both `ring` and `aws-lc-rs` (the comment at `main.rs:27-28`). Disable default features on `rustls` and `tokio-rustls` so only the chosen provider is linked. That shrinks the binary and the FIPS boundary.
- `HsmCore::new(...)` panics if DRBG instantiation fails (`core.rs:116`). Prefer `try_new` in `main` and exit with a clear message.
- `FullConfig` and `HsmConfig` parse the same file independently. The daemon's version skips the permission and symlink checks that `HsmConfig::load_from_path` performs, although canonicalisation in `main.rs:42-63` makes the symlink check a no-op anyway. Parse the file once into a combined struct with `deny_unknown_fields`.
- `async-stream` is only used for the incoming stream. It can be replaced with a spawned accept task and a `tokio_stream::wrappers::ReceiverStream`, which is also the fix for H4-04.
- Tests: `craton-hsm-daemon` has no unit or integration tests. Add at least:
  - an in-process tonic test for each RPC's authorization rules (after H4-01),
  - a template allow-list test,
  - message and attribute limit tests,
  - a handshake-timeout test.

**Deployment / docs**
- The chart hard-codes paths (`/etc/craton-hsm/...`, `/data/...`) in several templates. Centralise them in `_helpers.tpl`.
- `values.schema.json` does not constrain `daemon.bind` beyond a regex. It allows `0.0.0.0` without TLS when combined with `acceptInsecure`. The daemon then refuses to start, which is safe but confusing. Add a schema `if/then` rule.
- `NOTES.txt` should warn when `persistence.enabled=true` but the daemon cannot persist objects (H4-03), until that is fixed.

## Performance improvement suggestions

1. **Move CPU-bound work off the reactor** (H4-12). Use `spawn_blocking` for:
   - RSA key generation, sign and decrypt
   - PBKDF2
   - digests larger than a few KiB
   - large random requests

   Size a blocking-pool semaphore to cores so bursts queue instead of spawning hundreds of threads.
2. **Do not hold `Token.auth` during PBKDF2.** Snapshot, verify outside the lock, then commit. This removes slot-wide serialisation of every RPC behind logins.
3. **Parse each RSA private key once.** Every Sign and Decrypt currently re-parses the PKCS#8 DER. `sign.rs` has a key cache (`clear_rsa_key_cache`), so confirm it is keyed safely and used on the daemon path. Otherwise store the parsed key (zeroize-on-drop) in the object.
4. **Set TCP_NODELAY on accepted sockets.** The custom accept loop bypasses tonic's `tcp_nodelay` option, so small unary responses can be delayed by Nagle and delayed-ACK interaction (roughly 40 ms stalls).
5. **Handshake concurrency** (H4-04) also improves throughput under connection churn. Consider enabling rustls session tickets or resumption (the stateful cache is on by default) and HTTP/2 connection reuse guidance for clients.
6. **Remove the global DRBG bottleneck.** `GenerateRandom` holds `hsm.drbg()` for up to 1 MiB of output. Use per-worker DRBG instances (each reseeded from the OS) or chunk the output and release the lock between chunks.
7. **`find_objects_for_slot` scans all objects and takes each object's read lock** (`attributes.rs:371-395`), deliberately in constant time. With 10,000 objects and many clients this is O(N) per call. Keep a per-slot index and do the constant-time filtering only within the slot. Apply `max_count` early to avoid building large vectors.
8. **Avoid unnecessary clones:**
   - `proto_attrs_to_template` clones every value (`server.rs:1646`). Borrow `&[u8]` instead.
   - GenerateKeyPair clones modulus and EC point twice (`server.rs:804-806`, `847-848`).
   - `GetAttributeValue` clones each attribute. Build a response only for de-duplicated types.
9. **Bound the audit channel and batch fsyncs** (H4-16). A bounded `crossbeam` or `tokio::mpsc` channel with group commit (fsync every N events or every T ms) keeps the durability guarantee without one fsync per event.
10. **Right-size limits for the pod.** With 256 Mi and 500m CPU, choose values that fit that budget:
    - global concurrency of about 16–32,
    - a decode limit of about 1 MiB,
    - a small blocking pool.

    Expose them in `values.yaml`.
