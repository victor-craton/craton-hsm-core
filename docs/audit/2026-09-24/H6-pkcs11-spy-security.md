# H6 — pkcs11-spy: defensive security & code review

## Scope & method

| Item | Detail |
|---|---|
| Component | `tools/pkcs11-spy` (crate `pkcs11-spy` 0.3.0, `cdylib`) |
| Files reviewed | `tools/pkcs11-spy/Cargo.toml` (13 lines), `src/lib.rs` (293), `src/loader.rs` (128), `src/logger.rs` (266) |
| Reference material | `src/pkcs11_abi/types.rs`, `src/pkcs11_abi/constants.rs`, `src/pkcs11_abi/functions.rs` (root crate); `docs/install.md`; `.github/workflows/ci.yml`; root `Cargo.toml`; `Cargo.lock` |
| Method | Manual static review only. Nothing was built, tested or linted (no `cargo build/test/clippy`). No tracked files were modified. |
| Review date | 2026-09-24 |
| Standards | PKCS#11 Base Specification v2.40 and v3.0 (function list, interface discovery, return codes); CWE for classification |

Confidence levels: **Confirmed** means the behaviour follows directly from the code as written. **Likely** means it follows from the code together with well-documented platform or toolchain behaviour. **Possible** means it depends on how the target module or host application behaves.

Line numbers refer to each file on its own (`logger.rs` line 1 is its SPDX header).

---

## Executive summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 1 |
| Medium | 4 |
| Low | 7 |
| Informational | 5 |
| **Total** | **17** |

**Overall assessment.** The spy handles FFI data cautiously. It never reads a caller buffer or output pointer (it logs only integer arguments passed by value), and it deliberately leaves PINs, PIN lengths, templates, mechanism parameters and data buffers out of the log. So the usual interposer bugs, such as NULL `pData` on size queries, over-reads on `CKR_BUFFER_TOO_SMALL` and misuse of `CK_UNAVAILABLE_INFORMATION`, are **not present** today. The main problems are elsewhere:

1. **The spy does not log what it says it logs (H6-01, High).** `C_GetFunctionList` passes the call straight to the real module and hands the application the *real* module's function table. Almost every PKCS#11 consumer (p11-kit, OpenSC, OpenSSL providers/engines, NSS, SunPKCS11, the `cryptoki` crate, PyKCS11) makes all later calls through that table, so none of them reach the spy. Operators get a log that looks complete but holds a single line. `docs/install.md:498` says the spy "intercepts all PKCS#11 calls".
2. **Configuration is taken from the environment with no secure-execution guard (H6-02, Medium).** `PKCS11_SPY_TARGET` picks the code to `dlopen`, and `PKCS11_SPY_LOG` picks a file to append to and `chmod`. Neither is ignored when the host runs setuid, setgid or with file capabilities.
3. **The log file is opened unsafely (H6-03, Medium).** The last path component is followed if it is a symlink. An existing file is reused whoever owns it. A new file gets default permissions and only then a path-based `chmod 0600`. FIFOs and devices are accepted.
4. **Panics cross `extern "C"` (H6-04, Medium).** Every configuration error is a `panic!` on the path of every exported function. With current toolchains this aborts the host process. On the declared workspace MSRV (1.75) it is undefined behaviour.
5. **The PKCS#11 v3.0 interface is missing (H6-05, Medium).** There is no `C_GetInterfaceList`/`C_GetInterface` and none of the 22 other v3.0 functions.

The Low findings cover how the target path is chosen, the Windows ACL helper, a documented configuration that silently logs to stderr instead, the reduced-timing mode not working as intended, lock contention and non-atomic log lines, `$ORIGIN` breakage from loading via `/proc/self/fd`, and re-entrancy/self-load hazards.

---

## Findings

### H6-01 [High] `C_GetFunctionList` returns the real module's function table, so the spy is bypassed for nearly all clients

- **Location:** `tools/pkcs11-spy/src/lib.rs:133-135` (together with the generic forwarding at `lib.rs:111-116`); the target's table in the root crate is `src/pkcs11_abi/functions.rs:339-349` and `:5459`.
- **CWE:** CWE-778 (Insufficient Logging); CWE-440 (Expected Behavior Violation)
- **Confidence:** Confirmed

**Description.** `spy_fn_checked!(C_GetFunctionList(...))` resolves the target's `C_GetFunctionList` and forwards the caller's `ppFunctionList` unchanged. The target writes the address of *its own* `CK_FUNCTION_LIST`, for example `&FUNCTION_LIST` in craton-hsm. The spy never builds its own function table: `lib.rs` defines no `CK_FUNCTION_LIST` at all. The PKCS#11 specification makes `C_GetFunctionList` (or `C_GetInterface` in v3.0) the normal entry point, and virtually all consumers call through the returned pointers instead of looking up each `C_*` symbol. After the first call, all traffic goes directly to the target module. The only exception is accidental ELF symbol interposition, when the spy is loaded `RTLD_GLOBAL` and the target's table relocations are not bound locally, and that must not be relied on.

**Impact.** For these applications the spy records one `C_GetFunctionList` call and nothing more. Anyone debugging, or checking which operations and keys an application uses, gets a log that looks valid but is almost empty. Coverage has silently failed. The spy's defensive features (null checks, timing reduction) also never apply.

**Recommendation (fix).**
1. Define a spy-owned `static SPY_FUNCTION_LIST: CK_FUNCTION_LIST` (v2.40 layout, `version = {2, 40}`, or the lower of the target's and the spy's supported versions) whose entries are the spy's own exported `C_*` functions. Use the same `#[cfg_attr(target_os = "windows", repr(C, packed))]` convention as `src/pkcs11_abi/types.rs:61-62`.
2. Have the spy's `C_GetFunctionList` return `&SPY_FUNCTION_LIST` after its own NULL check, and not forward the pointer.
3. When loading, call the target's `C_GetFunctionList` **once**, keep the returned `*const CK_FUNCTION_LIST` in the `OnceLock`, and send every forwarded call through that table instead of per-call `dlsym` (see Performance). This also covers modules that export only `C_GetFunctionList`, which the current `dlsym`-per-function design reports as `CKR_FUNCTION_NOT_SUPPORTED`.
4. Where a target table entry is NULL, return `CKR_FUNCTION_NOT_SUPPORTED`.
5. Add an integration test that loads the spy against the craton-hsm cdylib, calls through the returned table, and checks that each call produces a log record.

---

### H6-02 [Medium] Environment-driven configuration is trusted in secure-execution (setuid/setgid/capability) contexts

- **Location:** `tools/pkcs11-spy/src/loader.rs:28-29` (`PKCS11_SPY_TARGET`), `tools/pkcs11-spy/src/logger.rs:22` (`PKCS11_SPY_LOG`), `logger.rs:130` (`PKCS11_SPY_REDUCED_TIMING`)
- **CWE:** CWE-114 (Process Control); CWE-807 (Reliance on Untrusted Inputs in a Security Decision); CWE-426 (Untrusted Search Path)
- **Confidence:** Confirmed for the code behaviour. Impact depends on the spy being configured as a provider for a privileged program.

**Description.** The spy reads its settings with `std::env::var`, which is plain `getenv`. It does not check whether the process runs in secure-execution mode: on Linux `getauxval(AT_SECURE)` (set for setuid/setgid binaries and file capabilities), on BSD/macOS `issetugid()`. The dynamic loader ignores `LD_PRELOAD`/`LD_LIBRARY_PATH` in that mode for exactly this reason. PKCS#11 modules do get loaded into privileged programs, for example through PAM smart-card modules in `su`/`sudo`/`login`, polkit helpers, or p11-kit, and a debug spy is easy to forget in such a configuration.

**Impact.** If the spy is configured as a module for a privileged program, whoever controls that program's environment decides which shared object runs with elevated privileges (`loader.rs:85-87` / `:110-112`). They also decide which file gets appended to and `chmod 0600`'d with those privileges (`logger.rs:54-68`, and see H6-03). The code does not stop either.

**Recommendation (fix).**
- On Linux, if `libc::getauxval(libc::AT_SECURE) != 0`, or if `getuid() != geteuid()` or `getgid() != getegid()`, ignore all `PKCS11_SPY_*` variables. Refuse to load a target (return `CKR_GENERAL_ERROR` from `C_Initialize`/`C_GetFunctionList`) and turn file logging off. Use `issetugid()` on macOS/BSD. `libc::secure_getenv` is an acceptable shortcut on glibc.
- Optionally support a root-owned configuration file (for example `/etc/pkcs11-spy.conf`, checked for owner and mode as in H6-06) as the only configuration source for privileged hosts.
- Document that the spy is a development tool and must not be configured for privileged or production processes.

---

### H6-03 [Medium] Log file creation follows symlinks, accepts existing or foreign files and non-regular files, and sets permissions by path after creation

- **Location:** `tools/pkcs11-spy/src/logger.rs:30-58` (path handling and open), `logger.rs:61-68` (`set_permissions`)
- **CWE:** CWE-59 (Link Following); CWE-367 (TOCTOU); CWE-276 (Incorrect Default Permissions); CWE-732
- **Confidence:** Confirmed

**Description.** Only the *parent* directory is canonicalized (`logger.rs:31`). The file is then opened with `OpenOptions::new().create(true).append(true)` (`logger.rs:54-58`), which:
1. **follows a symlink in the last component.** No `O_NOFOLLOW` is set, so if the name already exists as a symlink, the open, and any file creation, happens at the symlink's target.
2. **accepts an existing file owned by someone else.** In a shared directory another local user can create the file first and then read everything the spy writes. The later `chmod` (`logger.rs:64-67`) fails for a file the process does not own, and the error is discarded with `let _ =`.
3. **creates the file with the default mode (0666 & ~umask, usually 0644)** and only then calls `set_permissions(…, 0o600)`. Between the two, other users can open the file and keep a readable descriptor.
4. **applies `set_permissions` to the path, not the open descriptor.** It follows symlinks and can change a different inode from the one opened, for example the target of a symlink or a file swapped in after the open. In a privileged context (H6-02) this means an arbitrary file's mode can be changed to 0600.
5. **does not check that the result is a regular file.** A FIFO with no reader blocks the host's first PKCS#11 call indefinitely, inside `OnceLock::get_or_init`, and device nodes are accepted.

**Impact.** The log can be disclosed (it holds handles, operation sequences, return codes and timing). A privileged host can be made to corrupt or change the mode of another file. The host application can hang.

**Recommendation (fix).** Open once, then validate the descriptor:
```rust
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
let f = std::fs::OpenOptions::new()
    .append(true)
    .create(true)                     // or .create_new(true) with a per-process name, e.g. spy.<pid>.jsonl
    .mode(0o600)                      // correct mode at creation; no window
    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK) // no final-component symlink; FIFO cannot block
    .open(&full_path)?;
let m = f.metadata()?;                // fstat on the fd
if !m.file_type().is_file() || m.uid() != unsafe { libc::geteuid() }
    || m.nlink() != 1 || (m.mode() & 0o077) != 0 { /* reject, disable logging */ }
f.set_permissions(std::fs::Permissions::from_mode(0o600))?; // fchmod on the fd, not the path
```
Also reject a parent directory that other users can write to without the sticky bit, or that is not owned by root or the effective UID. Prefer `create_new(true)` so the spy never appends to a file it did not create. On Windows, create the file with an explicit owner-only DACL (see H6-07) and `FILE_FLAG_OPEN_REPARSE_POINT` so reparse points are not followed.

---

### H6-04 [Medium] Configuration errors `panic!` inside `extern "C"` functions and abort the host process (UB on older toolchains)

- **Location:** `tools/pkcs11-spy/src/loader.rs:29, 33, 37, 39, 51-54, 73, 78, 80, 87, 107, 112` (`expect`/`panic!`), reached from every exported function through `loader::resolve` at `lib.rs:74` and `lib.rs:113`
- **CWE:** CWE-248 (Uncaught Exception); CWE-705 (Incorrect Control Flow Scoping); CWE-758 (Reliance on Undefined Behavior)
- **Confidence:** Confirmed

**Description.** `load_library()` treats every failure as a panic: unset variable, unresolvable path, not a regular file, wrong extension, `dlopen` failure (including a missing dependency or wrong architecture). Its callers are `pub unsafe extern "C" fn` items with no `catch_unwind`. From Rust 1.81, a panic unwinding out of an `extern "C"` function aborts the process (`panic in a function that cannot unwind`). Before 1.81 this is undefined behaviour. The workspace declares `rust-version = "1.75"` (`Cargo.toml:14`), and the spy's own `Cargo.toml` sets no MSRV. The root crate wraps every export in `catch_unwind`; the spy does not.

**Impact.** Any misconfiguration, a missing `PKCS11_SPY_TARGET`, or an unloadable target terminates the whole host process on its first PKCS#11 call instead of returning an error code. With p11-kit, which loads every configured module, one stale spy entry can crash every p11-kit consumer on the system.

**Recommendation (fix).**
- Make `load_library()` return `Result<&'static Target, LoadError>`, caching the error as well (for example `OnceLock<Result<Target, String>>`). Log the reason once to the log sink or stderr and return `CKR_GENERAL_ERROR` (or `CKR_FUNCTION_FAILED`) from the exported function.
- Wrap each exported function body in `std::panic::catch_unwind(AssertUnwindSafe(|| …)).unwrap_or(CKR_GENERAL_ERROR)`, as the root crate does.
- Declare `rust-version = "1.81"` (or later) in `tools/pkcs11-spy/Cargo.toml` so abort-rather-than-UB is guaranteed as a backstop.

---

### H6-05 [Medium] The PKCS#11 v3.0 interface is not implemented or forwarded

- **Location:** `tools/pkcs11-spy/src/lib.rs:125-293` (full export list); missing items listed in the Stubs table
- **CWE:** CWE-440 (Expected Behavior Violation); CWE-778
- **Confidence:** Confirmed

**Description.** The spy exports all 68 v2.40 functions, and their signatures match the specification (checked one by one). It exports none of the v3.0 additions: `C_GetInterfaceList`, `C_GetInterface`, `C_LoginUser`, `C_SessionCancel`, or the 20 message-based functions (`C_MessageEncryptInit` … `C_MessageVerifyFinal`). The spy is documented as working "with any PKCS#11 library" (`docs/install.md:498`), and v3.0 targets are common.

**Impact.** A v3.0-aware application that looks up `C_GetInterface` on the spy does not find it. It either fails or falls back to `C_GetFunctionList`, which (H6-01) bypasses the spy entirely. v3.0-only operations (AEAD message APIs, `C_LoginUser`, `C_SessionCancel`) cannot be called or logged through the spy.

**Recommendation (fix).** Implement `C_GetInterfaceList`/`C_GetInterface`. They should return spy-owned `CK_INTERFACE` records (`"PKCS 11"`, v2.40 and v3.0 tables, and optionally pass-through vendor interfaces), with a spy-owned `CK_FUNCTION_LIST_3_0` whose entries wrap the target's `CK_FUNCTION_LIST_3_0` (obtained through the target's `C_GetInterface`). Advertise v3.0 only if the target does. Decide on v3.2 (`C_EncapsulateKey`, `C_DecapsulateKey`, `C_VerifySignature*`, `C_Async*`, `C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated`, `C_GetSessionValidationFlags`) explicitly, and document the decision.

---

### H6-06 [Low] Target library selection: relative paths, no owner/permission checks, heuristic extension test, overstated security comments

- **Location:** `tools/pkcs11-spy/src/loader.rs:15-57` (and comments at `loader.rs:18-25`, `59-67`); Windows loading at `loader.rs:110-112`
- **CWE:** CWE-426 (Untrusted Search Path); CWE-732 (Incorrect Permission Assignment for Critical Resource); CWE-1041
- **Confidence:** Confirmed

**Description.**
- A relative `PKCS11_SPY_TARGET` is accepted and resolved against the host's current working directory (`loader.rs:32`). Which code gets loaded then depends on where the application happens to be started.
- There is no check of the library's owner or mode, or of its ancestor directories. A group- or world-writable `.so`, or a writable directory on its path, lets another local user replace the code. Canonicalization and fd pinning (`loader.rs:72-88`) only guarantee that the file loaded is the file that was validated, and the validation itself says nothing about who controls that file.
- The extension check (`loader.rs:43-57`) is a heuristic, not a control. `name.contains(".so")` also accepts names such as `x.sol` or `a.so.txt`.
- The comments claim the design "mitigates path traversal and symlink-based library injection attacks" (`loader.rs:18-20`). The variable's value is fully trusted, so the real controls are who sets the environment and who can write the file.
- On Windows, `Library::new` calls `LoadLibraryExW(path, 0)`, so the target's *dependencies* are resolved through the standard DLL search order (application directory, `PATH`, and so on).

**Impact.** In multi-user or shared-directory setups the spy may load code that someone other than the operator controls. The comments may lead maintainers to think the loader is hardened when it is not.

**Recommendation (fix).** Require `Path::is_absolute()` on the raw value. After `open`, `fstat` the descriptor and require the owner to be root or the effective UID and `mode & 0o022 == 0`. Walk the ancestor directories with the same rule, allowing sticky world-writable directories only if owned by root. On Windows use `libloading::os::windows::Library::load_with_flags(path, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)`. Keep the extension check only as a usability hint, or drop it, and correct the comments to describe the actual trust model.

---

### H6-07 [Low] Windows log ACL hardening spawns `whoami`/`icacls` by name from inside the host process and ignores failures

- **Location:** `tools/pkcs11-spy/src/logger.rs:69-103`
- **CWE:** CWE-427 (Uncontrolled Search Path Element); CWE-252 (Unchecked Return Value); CWE-367
- **Confidence:** Likely (Rust's Windows `Command` resolves the program name through a search that includes the application directory before the system directories)

**Description.** `Command::new("whoami")` and `Command::new("icacls")` are resolved by name rather than by absolute path, inside whatever application loaded the module. The `icacls` exit status is discarded (`let _ = …status()`, `logger.rs:91-100`), and a failed or empty `whoami` silently skips hardening (`logger.rs:90`). Spawning processes from inside a PKCS#11 module is also bad practice: it adds latency, it can flash console windows in GUI applications, it fails in AppContainer/sandboxed processes, and it applies the ACL only *after* the file already exists (same kind of window as H6-03, item 3).

**Impact.** In a host whose application directory is writable, a planted `whoami.exe`/`icacls.exe` would run inside the host. If `icacls` fails, the log silently keeps the inherited, possibly broad, ACL.

**Recommendation (fix).** Create the file with `CreateFileW` and a `SECURITY_ATTRIBUTES` whose DACL grants only the current token user (take the SID from `GetTokenInformation(TokenUser)`), for example through `windows-sys`. That needs no child processes and leaves no window. If the helper processes are kept, run them by absolute path from `GetSystemDirectoryW`, check the exit status, and fall back to "logging disabled" rather than keeping a file with an unknown ACL.

---

### H6-08 [Low] The documented relative log path silently falls back to stderr; the default sink is stderr

- **Location:** `tools/pkcs11-spy/src/logger.rs:30-31`, `logger.rs:117-126`; `docs/install.md:503`
- **CWE:** CWE-703 (Improper Check or Handling of Exceptional Conditions); CWE-532 (Insertion of Sensitive Information into Log File)
- **Confidence:** Confirmed

**Description.** For a bare filename, `Path::new("spy.jsonl").parent()` returns `Some("")`, not `None`, so the `unwrap_or(".")` fallback is never used. `fs::canonicalize("")` then fails with `ENOENT` and the logger falls back to stderr (`logger.rs:117-123`). The configuration shown in `docs/install.md:503` (`PKCS11_SPY_LOG=spy.jsonl`) therefore never writes a file. More generally, every open failure, and the unset case (`logger.rs:126`), sends the log to stderr. For services, stderr often goes to journald, syslog or container logs that more people can read than a 0600 file.

**Impact.** The documented usage does not work, and the spy fails open, sending its log to a wider audience than the operator asked for.

**Recommendation (fix).** Treat an empty parent as `.` (`parent().filter(|p| !p.as_os_str().is_empty())`), or better, require an absolute path (H6-06) and update the docs. When `PKCS11_SPY_LOG` is set but cannot be opened safely, disable logging, with a single stderr warning, instead of redirecting the data. Make stderr output an explicit opt-in (for example `PKCS11_SPY_LOG=-`).

---

### H6-09 [Low] "Reduced timing" mode leaves microsecond timestamps in place; full precision is the default

- **Location:** `tools/pkcs11-spy/src/logger.rs:173-181` (call records), `logger.rs:190-199` (return records, reduced), `logger.rs:130-132` (default off)
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File); CWE-208 (Observable Timing Discrepancy — recorded, not caused)
- **Confidence:** Confirmed

**Description.** `PKCS11_SPY_REDUCED_TIMING=1` affects only `log_return`. `log_call` always writes `"ts":{:.6}` (µs). Consecutive call timestamps therefore still bound each operation's duration at close to microsecond resolution, which defeats the mode's stated purpose (`logger.rs:14-17`). The mode is also off by default, so `C_Login`/`C_Sign`/`C_Decrypt` durations are logged at µs precision unless the operator opts in.

**Impact.** Fine-grained timing of PIN checks and private-key operations ends up in a durable log. Within this crate's threat model that is low risk, but the documented control does not work.

**Recommendation (fix).** Quantize the base timestamp once, in a shared helper used by both `log_call` and `log_return`. Consider making reduced precision the default, at least for `C_Login`, `C_InitPIN`, `C_SetPIN`, `C_Sign*`, `C_Decrypt*` and `C_Unwrap*`, with full precision as an explicit debugging opt-in.

---

### H6-10 [Low] Logger lock held across blocking, non-atomic multi-syscall writes (stall, interleaving, fork)

- **Location:** `tools/pkcs11-spy/src/logger.rs:149-170` (`with_logger`), `logger.rs:176-180`, `195-198`, `201-205` (`writeln!` on unbuffered `File`/`Stderr`)
- **CWE:** CWE-400 (Uncontrolled Resource Consumption); CWE-362 (Race Condition); CWE-667 (Improper Locking)
- **Confidence:** Confirmed (a and b); Possible (c)

**Description.**
- (a) Every PKCS#11 call takes one global `Mutex` twice and writes to an unbuffered sink while holding it. If stderr is a pipe whose reader has stopped, or the log sits on a slow or hung network file system, every thread in the host blocks inside every PKCS#11 call.
- (b) `io::Write::write_fmt` on an unbuffered `File` does one `write(2)` per literal fragment and per argument (about 9–11 syscalls per record). `O_APPEND` makes each `write` atomic, not each record. When several processes share one log (forked workers, several apps with the same `PKCS11_SPY_LOG`), records interleave mid-line and the JSON-lines output breaks.
- (c) If the host forks while another thread holds the logger lock, the child deadlocks on its first log call.

The poison-recovery path (`logger.rs:156-168`) also re-runs `SpyLogger::new()` while holding the lock, which on Windows spawns processes (H6-07). Poisoning is effectively unreachable today because nothing inside the lock can panic.

**Impact.** Denial of service of the host application under back-pressure. Corrupted logs.

**Recommendation (fix).** Format each record into a `String` (or a reusable thread-local buffer) *outside* the lock, then take the lock for a single `write_all`. Better still, send records to a background writer thread over a bounded channel with a drop-and-count policy when full, so PKCS#11 calls never block on I/O. Record the PID in `SpyLogger` and rebuild the logger when `getpid()` changes (or use `pthread_atfork`).

---

### H6-11 [Low] Loading via `/proc/self/fd/N` breaks `$ORIGIN` dependency resolution and self-location in target modules

- **Location:** `tools/pkcs11-spy/src/loader.rs:84-93`
- **CWE:** CWE-440 (Expected Behavior Violation)
- **Confidence:** Likely

**Description.** The target is `dlopen`ed as `/proc/self/fd/N`, so its link-map name is that string. `$ORIGIN` in the target's `DT_RUNPATH`/`DT_RPATH` expands to `/proc/self/fd`, so vendor modules that ship private dependencies next to themselves (common for HSM client libraries) fail to load. Through H6-04 that becomes a process abort. Modules that find their configuration through `dladdr()`/`dl_iterate_phdr` get `/proc/self/fd/N` instead of their install path. The comment at `loader.rs:90-92` says the descriptor is leaked "to prevent the fd from being closed … before dlopen completes", but `dlopen` has already returned by then. Keeping the fd open does keep the link-map name meaningful, which is the real (undocumented) reason to keep it.

**Impact.** Wrapping some real-world modules fails, or they misbehave, only when loaded through the spy.

**Recommendation (fix).** With H6-06's owner and permission checks in place, the substitution race no longer matters, so load the canonical absolute path. If fd pinning is kept, compare `(st_dev, st_ino)` of the validated descriptor with the mapped object after a path-based `dlopen` (for example via `dlinfo(RTLD_DI_LINKMAP)` plus `stat` of `l_name`) instead of loading via `/proc`. Either way, fix the comment and store the `File` next to the `Library` in the `OnceLock` rather than calling `mem::forget`.

---

### H6-12 [Low] Self-targeting and re-entrant initialization can recurse without bound or deadlock

- **Location:** `tools/pkcs11-spy/src/loader.rs:26-27` (`REAL_LIB.get_or_init`), `loader.rs:122-125`; `lib.rs:74`, `lib.rs:113`
- **CWE:** CWE-674 (Uncontrolled Recursion); CWE-833 (Deadlock)
- **Confidence:** Likely for (a); Possible for (b)

**Description.**
- (a) If `PKCS11_SPY_TARGET` resolves to the spy itself, the loader recognises the already-loaded object by device and inode and returns the spy's own handle. `dlsym` then returns the spy's own `C_*` and each call forwards to itself until the stack overflows.
- (b) If code run during the target's `dlopen` (ELF constructors, or dependencies that call `C_*` through the global symbol scope) re-enters a spy export on the same thread, `OnceLock::get_or_init` is initialized re-entrantly. The standard library documents that this deadlocks or panics.

**Impact.** The host crashes or hangs on a misconfiguration or with an unusual module.

**Recommendation (fix).** After loading, reject the target if its `C_GetFunctionList` address lies inside the spy's own image (compare `dladdr().dli_fbase` with the spy's own base). Add a thread-local "initializing" flag so re-entrant calls return `CKR_GENERAL_ERROR` immediately.

---

### H6-13 [Informational] `ckr_name` is incomplete; unmapped codes are logged as `CKR_UNKNOWN`

- **Location:** `tools/pkcs11-spy/src/logger.rs:211-265`
- **CWE:** CWE-1068 (Inconsistency Between Implementation and Documented Design) — diagnostic quality
- **Confidence:** Confirmed

**Description.** Frequently seen codes are missing, among them `CKR_NO_EVENT` (0x08, the normal result of `C_WaitForSlotEvent` with `CKF_DONT_BLOCK`), `CKR_NEED_TO_CREATE_THREADS` (0x09), `CKR_CANT_LOCK` (0x0A), `CKR_ACTION_PROHIBITED` (0x1B), `CKR_ENCRYPTED_DATA_INVALID`/`_LEN_RANGE` (0x40/0x41), `CKR_KEY_NOT_NEEDED`…`CKR_KEY_UNEXTRACTABLE` (0x64-0x6A), `CKR_OPERATION_ACTIVE`/`_NOT_INITIALIZED` (0x90/0x91), `CKR_PIN_EXPIRED` (0xA3), `CKR_UNWRAPPING_KEY_*` (0xF0-0xF2), `CKR_USER_ANOTHER_ALREADY_LOGGED_IN`/`CKR_USER_TOO_MANY_TYPES` (0x104/0x105), `CKR_WRAPPED_KEY_*`/`CKR_WRAPPING_KEY_*` (0x110-0x115), `CKR_RANDOM_*` (0x120/0x121), `CKR_DOMAIN_PARAMS_INVALID` (0x130), `CKR_CURVE_NOT_SUPPORTED` (0x140), `CKR_SAVED_STATE_INVALID` (0x160), `CKR_INFORMATION_SENSITIVE` (0x170), `CKR_STATE_UNSAVEABLE` (0x180), `CKR_MUTEX_*` (0x1A0/0x1A1), `CKR_NEW_PIN_MODE`…`CKR_PUBLIC_KEY_INVALID` (0x1B0-0x1B9), `CKR_FUNCTION_REJECTED` (0x200), the v3.0 codes 0x201-0x202, and vendor-defined codes (`>= 0x8000_0000`).

**Recommendation.** Generate the table from the root crate's `src/pkcs11_abi/constants.rs` (for example with a small `build.rs` or a shared constants crate). Show vendor codes as `CKR_VENDOR_DEFINED+0x…`, and log `rv_code` as hex so it matches the specification.

---

### H6-14 [Informational] `spy_fn_checked!` changes module behaviour and uses magic numbers

- **Location:** `tools/pkcs11-spy/src/lib.rs:88-123`, `lib.rs:130-135`
- **CWE:** CWE-440
- **Confidence:** Confirmed

**Description.** For `C_GetInfo` and `C_GetFunctionList` a NULL output pointer is answered by the spy (`CKR_ARGUMENTS_BAD`, literal `0x07`) and never reaches the target. A transparent interposer should not change results. For example, a module may correctly return `CKR_CRYPTOKI_NOT_INITIALIZED` for `C_GetInfo` before `C_Initialize`. The rejection is logged with `"duration_us":0` and a free-text `args` string that differs from the normal schema. Once H6-01 is fixed, the `C_GetFunctionList` check does belong to the spy, because it fills in its own table. The `C_GetInfo` check should forward instead.

**Recommendation.** Forward `C_GetInfo` without changes. Use named constants (`CKR_ARGUMENTS_BAD`, `CKR_FUNCTION_NOT_SUPPORTED`) shared with `loader.rs:128`, and emit a distinct `"event":"rejected"` record.

---

### H6-15 [Informational] Caller buffers are never dereferenced (sound today); rules for adding output-side logging

- **Location:** `tools/pkcs11-spy/src/lib.rs:128-293` (all format arguments are by-value integers); relevant constant `src/pkcs11_abi/constants.rs:295` (`CK_UNAVAILABLE_INFORMATION = CK_ULONG::MAX`)
- **CWE:** n/a (positive observation); relevant to CWE-476 / CWE-125 if extended
- **Confidence:** Confirmed

**Description.** The spy logs only integers passed by value (handles, slot IDs, counts, input lengths, flags, mechanism type in `C_GetMechanismInfo`). It never reads `*pulXxxLen`, templates, `CK_MECHANISM`, `CK_C_INITIALIZE_ARGS` or data buffers. So there is currently no NULL dereference on size-query calls (`pData == NULL`), no over-read on `CKR_BUFFER_TOO_SMALL`, and no misuse of `CK_UNAVAILABLE_INFORMATION`. The downside is that output-side diagnostics are missing: returned lengths, new object and session handles, slot and mechanism counts, and mechanism types for `*Init`.

**Recommendation (for future extensions).**
- Read an output pointer only after the call returns, and only if it is non-NULL. For `CK_ULONG_PTR` lengths, log the value when `rv` is `CKR_OK` or `CKR_BUFFER_TOO_SMALL`.
- Never read an output *buffer*. Log lengths only.
- For templates, log `type` and `ulValueLen`, with `CK_UNAVAILABLE_INFORMATION` (`!0`) shown as `"unavailable"`. Never treat `ulValueLen` as a readable size unless `pValue` is non-NULL and `rv == CKR_OK`. Cap how many attributes are iterated, and check `pTemplate != NULL` when `ulCount > 0`.
- For `CK_MECHANISM`, check that `pMechanism` is non-NULL, log `mechanism` only, and never read `pParameter`.
- Wrap all such reads in `catch_unwind` (H6-04) and keep them in one audited helper module with `// SAFETY:` comments.

---

### H6-16 [Informational] Data-minimisation assessment and recommended redaction policy

- **Location:** `tools/pkcs11-spy/src/lib.rs:144-171` (PIN-bearing functions), `lib.rs:193-279` (crypto operations)
- **CWE:** CWE-532 (for the residual items)
- **Confidence:** Confirmed

**Current state (good).** PIN bytes are never logged. PIN lengths are omitted for `C_Login`, `C_InitPIN` and `C_SetPIN` and shown as `"<redacted>"` for `C_InitToken`. Token labels, attribute templates and values, mechanism parameters (IVs, PBKDF passwords, OAEP labels), plaintext, ciphertext, signatures, wrapped keys and random output are never logged.

**Residual or inconsistent.**
- Input lengths (`data_len`, `enc_data_len`, `wrapped_len`) reveal message sizes. That is acceptable for a debugging tool but should be documented.
- Timing (H6-09).
- `C_Login` `userType` is redacted (`lib.rs:161-163`), but whether the user is SO, USER or CONTEXT_SPECIFIC is not secret, is useful for audit, and can often be inferred from later behaviour anyway. Recommend logging it.
- `pin_len` appears as a key only in `C_InitToken`. For a consistent schema, omit it everywhere.

**Recommended policy (document in the crate README and enforce in one helper).**

| Category | Policy |
|---|---|
| PIN / password bytes and lengths (`C_Login`, `C_LoginUser`, `C_InitPIN`, `C_SetPIN`, `C_InitToken`, PBKDF params) | Never log |
| Secret/private attribute values (`CKA_VALUE` of secret/private keys, `CKA_PRIVATE_EXPONENT`, `CKA_PRIME_1/2`, `CKA_EXPONENT_1/2`, `CKA_COEFFICIENT`, `CKA_SEED`, any attribute when `CKA_SENSITIVE`/`!CKA_EXTRACTABLE`) | Never log; type + length only |
| Data buffers (plaintext, ciphertext, signature, digest, wrapped key, random, op-state) | Never log contents; lengths only |
| Mechanism parameters | Log mechanism type only |
| Labels / IDs (`CKA_LABEL`, `CKA_ID`, token label) | Opt-in only (may carry PII), escaped |
| Handles, slot IDs, flags, rv, counts, user type | Log |
| Timing | Millisecond by default; µs opt-in |

Any future string field must be JSON-escaped (CWE-117). Today `args` is safe only because it contains nothing but integers and static names.

---

### H6-17 [Informational] Documentation drift, no tests, undeclared MSRV

- **Location:** `docs/install.md:498-509`; `tools/pkcs11-spy/Cargo.toml:1-13`; `.github/workflows/ci.yml:111-118`
- **CWE:** CWE-1059 (Insufficient Technical Documentation)
- **Confidence:** Confirmed

**Description.**
- `docs/install.md` claims the spy "intercepts all PKCS#11 calls" (false, see H6-01) and shows a record format (`timestamp`, `function`, string `args`, `duration_ms`) that the code does not produce. The real format has separate `call`/`return` records with `ts`, `fn`, `event`, object `args`, `rv`, `rv_code` and `duration_us`.
- The crate has no unit or integration tests (no `#[cfg(test)]`, no `tests/`), yet CI runs `cargo test -p pkcs11-spy`, which passes without testing anything.
- No `rust-version` is declared (see H6-04).

**Recommendation.** Fix the docs, add tests (log-path handling, schema, the H6-01 table test, a misconfiguration returning an error code rather than aborting), and declare the MSRV. (`Cargo.lock` also contains libloading 0.8.9, but only through the build dependency `clang-sys`, so it does not affect the spy.)

---

## Stubs, TODOs and unimplemented items

A search of `tools/pkcs11-spy/` for `TODO|FIXME|XXX|todo!|unimplemented!|unreachable!` found **no** markers. The gaps below are structural.

| # | Item | Location | Status | Related finding |
|---|---|---|---|---|
| 1 | Spy-owned `CK_FUNCTION_LIST` | `lib.rs:133-135` | Not implemented; real table returned | H6-01 |
| 2 | `C_GetInterfaceList`, `C_GetInterface` | n/a | Not exported | H6-05 |
| 3 | `C_LoginUser`, `C_SessionCancel` | n/a | Not exported | H6-05 |
| 4 | `C_MessageEncryptInit`, `C_EncryptMessage`, `C_EncryptMessageBegin`, `C_EncryptMessageNext`, `C_MessageEncryptFinal` | n/a | Not exported | H6-05 |
| 5 | `C_MessageDecryptInit`, `C_DecryptMessage`, `C_DecryptMessageBegin`, `C_DecryptMessageNext`, `C_MessageDecryptFinal` | n/a | Not exported | H6-05 |
| 6 | `C_MessageSignInit`, `C_SignMessage`, `C_SignMessageBegin`, `C_SignMessageNext`, `C_MessageSignFinal` | n/a | Not exported | H6-05 |
| 7 | `C_MessageVerifyInit`, `C_VerifyMessage`, `C_VerifyMessageBegin`, `C_VerifyMessageNext`, `C_MessageVerifyFinal` | n/a | Not exported | H6-05 |
| 8 | v3.2 additions (`C_EncapsulateKey`, `C_DecapsulateKey`, `C_VerifySignature*`, `C_Async*`, `C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated`, `C_GetSessionValidationFlags`) | n/a | Not exported; no documented decision | H6-05 |
| 9 | Output-parameter logging (returned lengths, handles, counts) | `lib.rs:128-293` | Not implemented (by design today) | H6-15 |
| 10 | Mechanism type for `*Init`, `C_GenerateKey*`, `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey` | `lib.rs:194, 204, 214, 222, 228, 236, 242, 264-273` | Not logged (`pMechanism` opaque) | H6-15 |
| 11 | `CK_C_INITIALIZE_ARGS` flags (`CKF_OS_LOCKING_OK`, custom mutex callbacks) | `lib.rs:128` | Logged as `{}` | Code review |
| 12 | `CK_NOTIFY` callback wrapping | `lib.rs:153-154` | Passed through; callbacks not logged | Code review |
| 13 | Missing-symbol diagnostics | `lib.rs:76`, `lib.rs:115` | Silently maps to `CKR_FUNCTION_NOT_SUPPORTED` with no reason | H6-01 |
| 14 | Load-error handling | `loader.rs:26-116` | `panic!` instead of error codes | H6-04 |
| 15 | Return-code name table | `logger.rs:211-265` | Partial | H6-13 |
| 16 | Tests | crate-wide | None | H6-17 |
| 17 | Library/fd lifetime | `loader.rs:93` | fd deliberately leaked; library never unloaded | H6-11 |

---

## Code review

**FFI and unsafe**
- All 68 v2.40 signatures in `lib.rs:128-293` match the specification, including argument order for `C_InitToken`, `C_OpenSession`, `C_UnwrapKey`, `C_GenerateKeyPair`, `C_SetOperationState` and `C_WaitForSlotEvent`. `CK_NOTIFY` as `Option<extern "C" fn …>` is the correct nullable function-pointer representation. `CK_ULONG = c_ulong` correctly gives 32 bits on Win64.
- If H6-01 introduces spy-owned structs, they must follow the Windows 1-byte packing rule already used in `src/pkcs11_abi/types.rs:61-62`.
- The `unsafe { }` blocks inside `unsafe extern "C" fn` (`lib.rs:74-75`, `113-114`) carry no `// SAFETY:` comments. Add `#![deny(unsafe_op_in_unsafe_fn)]` ahead of an edition-2024 migration and document the invariant, which is that the `FnSig` alias matches the C prototype.
- `#![allow(clippy::missing_safety_doc)]` (`lib.rs:12`) hides the missing contract documentation on 68 exported `unsafe` functions. Add one crate-level safety section instead.
- `loader::resolve<T>` (`loader.rs:122-125`) is generic over any `T`. Restrict it to function-pointer types, or remove it with H6-01's cached-table design.

**Structure and duplication**
- `spy_fn!` and `spy_fn_checked!` (`lib.rs:61-123`) duplicate the whole dispatch body. Move it into one `#[inline] fn dispatch(name, args: impl FnOnce() -> String, call: impl FnOnce() -> CK_RV) -> CK_RV`, which also gives a single place for `catch_unwind`.
- The type aliases are defined twice (`lib.rs:25-26` and `loader.rs:10-11`). The comment at `loader.rs:9` says "platform-independent", contradicting `lib.rs:21-24`.
- Magic numbers `0x07` (`lib.rs:102-103`) and `0x54` (`loader.rs:128`) should be named constants. The comment at `loader.rs:127` ("Helper: call a resolved function…") describes a function that does not exist.

**Path handling (`logger.rs`)**
- The checks on `fname_str` at `logger.rs:45-48` are mostly dead code: `file_name()` can never contain `/`. The `..` substring check rejects legitimate names such as `a..jsonl`, and `\` is a legal filename character on Unix. The real protection comes from canonicalizing the parent plus `O_NOFOLLOW` (H6-03).
- `canonical_parent.is_dir()` (`logger.rs:34`) is redundant once `canonicalize` has succeeded and the open is fd-validated.

**Log schema and observability**
- `ts` is seconds since the logger started, not wall-clock time, and records carry no PID or thread ID. In multi-threaded hosts, `call`/`return` pairs cannot be matched. Add `pid`, `tid`, a monotonically increasing `seq`, and an RFC 3339 wall-clock `time` at startup.
- JSON is assembled by hand (`logger.rs:176-205`). It is safe today because only integers and static identifiers are written. Before any string (label, path, error message) is added, switch to `serde_json` or a vetted escaper (CWE-117).
- The poison-recovery record uses `"ts":0` (`logger.rs:165`), which breaks ordering. Use the real timestamp.

**Lifecycle**
- The target is loaded lazily by whichever function is called first, and never unloaded. `C_Finalize` does not reset spy state (fine), and if the host `dlclose`s the spy the target stays mapped (acceptable, but document it).
- `std::mem::forget(file)` (`loader.rs:93`). See H6-11. Store the `File` explicitly instead.

**Cargo**
- Add `rust-version`, `publish = false` (it is an internal tool), and `[lints]` (for example `unsafe_op_in_unsafe_fn = "deny"`, `clippy::undocumented_unsafe_blocks = "warn"`). Consider inheriting the workspace's `version`/`license` via `*.workspace = true`.

---

## Performance improvement suggestions

1. **Resolve once, not per call.** Every call currently goes through `load_library()` (an atomic load) and `Library::get`, which calls `dlsym` (a hash lookup plus `dlerror` bookkeeping). Cache the target's `CK_FUNCTION_LIST` pointer at load time (H6-01) and call through it, so each call costs one indirect call.
2. **One syscall per record.** `writeln!` on an unbuffered `File`/`Stderr` makes roughly 9–11 `write(2)` calls per record, so around 20 per PKCS#11 call (`logger.rs:176-205`). Format into a buffer and `write_all` once, or wrap the sink in a `BufWriter`, flushing per record or on a timer and at `C_Finalize`.
3. **Take I/O out of the critical path.** A background writer thread fed by a bounded MPSC channel (or a lock-free ring buffer) removes the global lock that currently serializes every PKCS#11 call across threads (H6-10) and stops sink back-pressure from blocking crypto operations.
4. **Avoid per-call heap allocation.** `format!` for `args` (`lib.rs:68`, `107`) allocates on every call, as does the `writeln!` machinery. Use a thread-local reusable `String`, or `itoa`-style integer formatting into a stack buffer. Build `args` lazily only when logging is enabled, and add a `PKCS11_SPY_LOG=off` fast path.
5. **One lock, not two.** Each call takes the logger lock twice (call and return). Emit one combined record after the call returns (`args`, `rv`, `duration`), optionally with a separate "call" record only for functions that can block (`C_WaitForSlotEvent`, `C_Login`) so hangs remain visible.
6. **Cheaper timing.** `Instant::now()` is called three times per call (`lib.rs:70`, and inside `log_call` and `log_return` via `elapsed()`). Take one reading before and one after the call and derive `ts` and `duration` from those two.
7. **`ckr_name` lookup.** The large `match` compiles to a jump table or binary search, which is fine. If it is generated from `constants.rs` (H6-13), keep it a `match` or use a sorted static slice with `binary_search`, not a `HashMap`.
