// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! End-to-end tests: load the built spy cdylib in a child process, point it at
//! a mock PKCS#11 module (compiled from `tests/support/mock_pkcs11.rs`) or at
//! the craton-hsm cdylib, call through the function tables the spy hands out,
//! and inspect the JSON-lines log.
//!
//! The spy reads its configuration once per process, so every scenario runs
//! in a fresh child process: the parent test re-executes this test binary with
//! `--ignored --exact child_*` and the scenario's environment.
#![cfg(unix)]
#![allow(non_snake_case)]

use serde_json::Value;
use std::ffi::{c_ulong, c_void, OsString};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

type RV = c_ulong;

const CKR_OK: RV = 0;
const CKR_GENERAL_ERROR: RV = 5;
const CKR_ARGUMENTS_BAD: RV = 7;
const CKR_FUNCTION_NOT_SUPPORTED: RV = 0x54;
const CKR_PIN_INCORRECT: RV = 0xA0;

const SECRET_PIN: &[u8] = b"S3cr3t-PIN-value";
const SECRET_USER: &[u8] = b"alice-user";

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
struct Version {
    major: u8,
    minor: u8,
}

#[repr(C)]
struct List2 {
    version: Version,
    f: [usize; 68],
}

#[repr(C)]
struct List3 {
    version: Version,
    f: [usize; 92],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Interface {
    name: *const u8,
    list: *const c_void,
    flags: c_ulong,
}

// Indices into the function tables (OASIS pkcs11f.h order).
const I_INITIALIZE: usize = 0;
const I_FINALIZE: usize = 1;
const I_GET_INFO: usize = 2;
const I_LOGIN: usize = 18;
const I_ENCRYPT: usize = 30;
const I_GENERATE_RANDOM: usize = 64;
const I_LOGIN_USER: usize = 70;
const I_SESSION_CANCEL: usize = 71;
const I_ENCRYPT_MESSAGE: usize = 73;

type FnPtr = unsafe extern "C" fn(*mut c_void) -> RV;
type FnGetSlotList = unsafe extern "C" fn(u8, *mut c_ulong, *mut c_ulong) -> RV;
type FnLogin = unsafe extern "C" fn(c_ulong, c_ulong, *const u8, c_ulong) -> RV;
type FnLoginUser =
    unsafe extern "C" fn(c_ulong, c_ulong, *const u8, c_ulong, *const u8, c_ulong) -> RV;
type FnGenRandom = unsafe extern "C" fn(c_ulong, *mut u8, c_ulong) -> RV;
type FnEncrypt = unsafe extern "C" fn(c_ulong, *mut u8, c_ulong, *mut u8, *mut c_ulong) -> RV;
type FnSessionCancel = unsafe extern "C" fn(c_ulong, c_ulong) -> RV;
type FnGetFunctionList = unsafe extern "C" fn(*mut *const List2) -> RV;
type FnGetInterfaceList = unsafe extern "C" fn(*mut Interface, *mut c_ulong) -> RV;
type FnGetInterface =
    unsafe extern "C" fn(*const u8, *const Version, *mut *const Interface, c_ulong) -> RV;

unsafe fn entry<T: Copy>(slot: usize) -> T {
    assert_ne!(slot, 0, "NULL function-table entry");
    // SAFETY: the caller names the prototype of this table slot.
    unsafe { std::mem::transmute_copy::<usize, T>(&slot) }
}

// ── Paths and helpers ───────────────────────────────────────────────────────

fn build_dir() -> PathBuf {
    // target/<profile>/deps/<test-binary> → target/<profile>
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().to_path_buf()
}

fn spy_path() -> PathBuf {
    let name = if cfg!(target_os = "macos") {
        "libpkcs11_spy.dylib"
    } else {
        "libpkcs11_spy.so"
    };
    // `cargo test` leaves the cdylib in deps/ (it is uplifted to
    // target/<profile>/ only by `cargo build`).
    let deps = build_dir().join("deps").join(name);
    let p = if deps.exists() {
        deps
    } else {
        build_dir().join(name)
    };
    assert!(p.exists(), "spy cdylib not found at {}", p.display());
    p
}

/// Compile the mock module once per test process.
fn mock_path() -> PathBuf {
    static MOCK: OnceLock<PathBuf> = OnceLock::new();
    MOCK.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("pkcs11-spy-mock");
        std::fs::create_dir_all(&dir).unwrap();
        let ext = if cfg!(target_os = "macos") {
            "dylib"
        } else {
            "so"
        };
        let out = dir.join(format!("libmock_pkcs11_{}.{ext}", std::process::id()));
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/mock_pkcs11.rs");
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let st = Command::new(rustc)
            .args([
                "--edition",
                "2021",
                "--crate-type",
                "cdylib",
                "--crate-name",
                "mock_pkcs11",
            ])
            .args(["-C", "debuginfo=0", "-o"])
            .arg(&out)
            .arg(&src)
            .status()
            .expect("run rustc");
        assert!(st.success(), "compiling the mock PKCS#11 module failed");
        out
    })
    .clone()
}

/// Re-run this binary for one `child_*` scenario with a clean spy environment.
fn run_child(test: &str, envs: &[(&str, OsString)], cwd: Option<&Path>) -> Output {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--ignored",
        "--exact",
        test,
        "--nocapture",
        "--test-threads=1",
    ])
    .env("SPY_CHILD", "1")
    .env("SPY_LIB", spy_path())
    .env_remove("PKCS11_SPY_TARGET")
    .env_remove("PKCS11_SPY_LOG")
    .env_remove("PKCS11_SPY_REDUCED_TIMING")
    .env_remove("MOCK_NO_V3");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    let out = cmd.output().expect("spawn child");
    assert!(
        out.status.success(),
        "child {test} failed ({:?})\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 passed"),
        "child {test} did not run:\n{stdout}"
    );
    out
}

fn is_child() -> bool {
    std::env::var_os("SPY_CHILD").is_some()
}

fn load_spy() -> libloading::Library {
    let p = std::env::var_os("SPY_LIB").unwrap();
    // SAFETY: loading the spy cdylib built by this workspace.
    unsafe { libloading::Library::new(p) }.unwrap()
}

unsafe fn sym<T: Copy>(lib: &libloading::Library, name: &str) -> T {
    // SAFETY: the caller names the symbol's prototype.
    unsafe { *lib.get::<T>(name.as_bytes()).unwrap() }
}

fn read_log(path: &Path) -> (String, Vec<Value>) {
    let text = std::fs::read_to_string(path).unwrap();
    let recs = text
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap_or_else(|e| panic!("bad JSON line {l:?}: {e}"))
        })
        .collect();
    (text, recs)
}

fn records<'a>(recs: &'a [Value], func: &str, event: &str) -> Vec<&'a Value> {
    recs.iter()
        .filter(|r| r["fn"] == func && r["event"] == event)
        .collect()
}

fn one<'a>(recs: &'a [Value], func: &str, event: &str) -> &'a Value {
    let v = records(recs, func, event);
    assert_eq!(v.len(), 1, "expected one {func}/{event} record, got {v:?}");
    v[0]
}

fn assert_no_secrets(text: &str) {
    for s in [SECRET_PIN, SECRET_USER] {
        let s = std::str::from_utf8(s).unwrap();
        assert!(!text.contains(s), "log contains secret {s:?}");
    }
    assert!(!text.contains("pin_len"), "PIN length must never be logged");
}

// ── H6-01: spy-owned CK_FUNCTION_LIST, every call logged ─────────────────────

#[test]
fn function_list_is_spy_owned_and_every_call_is_logged() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("spy.jsonl");
    run_child(
        "child_v2_function_list",
        &[
            ("PKCS11_SPY_TARGET", mock_path().into()),
            ("PKCS11_SPY_LOG", log.clone().into()),
            ("MOCK_NO_V3", "1".into()),
        ],
        None,
    );

    // H6-03: created with mode 0600.
    let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let (text, recs) = read_log(&log);
    assert_no_secrets(&text);
    assert_eq!(recs[0]["event"], "start");
    assert_eq!(recs[0]["timing"], "ms");

    for f in [
        "C_GetFunctionList",
        "C_Initialize",
        "C_GetInfo",
        "C_Login",
        "C_GenerateRandom",
        "C_Encrypt",
        "C_SessionCancel",
        "C_GetInterfaceList",
        "C_Finalize",
    ] {
        one(&recs, f, "call");
        one(&recs, f, "return");
    }
    // H6-14: NULL pInfo is forwarded, the module's own answer is logged
    // (and H6-13: vendor codes are named).
    let r = one(&recs, "C_GetInfo", "return");
    assert_eq!(r["rv"], "CKR_VENDOR_DEFINED+0x1234");
    assert_eq!(r["rv_code"], "0x80001234");
    // H6-16: user type is logged, PIN is not.
    let c = one(&recs, "C_Login", "call");
    assert_eq!(c["args"]["user_type"], 1);
    assert_eq!(c["args"]["session"], 7);
    assert_eq!(one(&recs, "C_Login", "return")["rv"], "CKR_PIN_INCORRECT");
    assert_eq!(
        one(&recs, "C_Encrypt", "return")["rv"],
        "CKR_FUNCTION_NOT_SUPPORTED"
    );
    assert_eq!(
        one(&recs, "C_SessionCancel", "return")["rv"],
        "CKR_FUNCTION_NOT_SUPPORTED"
    );
    assert_eq!(
        one(&recs, "C_GenerateRandom", "call")["args"]["random_len"],
        16
    );
    // H6-09: millisecond timing by default — for call *and* return records.
    for r in &recs {
        let ts = r["ts"].to_string();
        let decimals = ts.split('.').nth(1).map_or(0, str::len);
        assert!(decimals <= 3, "µs timestamp in reduced mode: {ts}");
        if r["event"] == "return" {
            assert!(r.get("duration_ms").is_some() && r.get("duration_us").is_none());
        }
    }
    // H6-10: pairing fields present; seq strictly increasing.
    let seqs: Vec<u64> = recs.iter().map(|r| r["seq"].as_u64().unwrap()).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]));
    assert!(recs.iter().all(|r| r["pid"].is_u64() && r["tid"].is_u64()));
}

#[test]
#[ignore = "subprocess helper for function_list_is_spy_owned_and_every_call_is_logged"]
fn child_v2_function_list() {
    if !is_child() {
        return;
    }
    let spy = load_spy();
    // SAFETY: symbol types match the PKCS#11 prototypes / the mock's layout.
    unsafe {
        let gfl: FnGetFunctionList = sym(&spy, "C_GetFunctionList");
        let mut list: *const List2 = std::ptr::null();
        assert_eq!(gfl(&mut list), CKR_OK);
        assert!(!list.is_null());

        // The table handed out is the spy's, not the mock's.
        let mock =
            libloading::Library::new(std::env::var_os("PKCS11_SPY_TARGET").unwrap()).unwrap();
        let mock_gfl: FnGetFunctionList = sym(&mock, "C_GetFunctionList");
        let mut mock_list: *const List2 = std::ptr::null();
        assert_eq!(mock_gfl(&mut mock_list), CKR_OK);
        assert_ne!(
            list, mock_list,
            "spy returned the target's function list (H6-01)"
        );
        let l = &*list;
        assert_eq!(
            l.version,
            Version {
                major: 2,
                minor: 40
            }
        );
        assert_eq!(
            l.f[3], gfl as *const () as usize,
            "C_GetFunctionList entry is the spy's"
        );

        let init: FnPtr = entry(l.f[I_INITIALIZE]);
        assert_eq!(init(std::ptr::null_mut()), CKR_OK);
        let get_info: FnPtr = entry(l.f[I_GET_INFO]);
        assert_eq!(
            get_info(std::ptr::null_mut()),
            0x8000_1234,
            "NULL pInfo must be forwarded (H6-14)"
        );
        let login: FnLogin = entry(l.f[I_LOGIN]);
        assert_eq!(
            login(7, 1, SECRET_PIN.as_ptr(), SECRET_PIN.len() as c_ulong),
            CKR_PIN_INCORRECT
        );
        let rnd: FnGenRandom = entry(l.f[I_GENERATE_RANDOM]);
        let mut buf = [0u8; 16];
        assert_eq!(rnd(7, buf.as_mut_ptr(), 16), CKR_OK);
        assert_eq!(buf, [0x42; 16], "call reached the target");
        let enc: FnEncrypt = entry(l.f[I_ENCRYPT]);
        let mut n: c_ulong = 0;
        assert_eq!(
            enc(7, buf.as_mut_ptr(), 16, std::ptr::null_mut(), &mut n),
            CKR_FUNCTION_NOT_SUPPORTED,
            "NULL target entry → CKR_FUNCTION_NOT_SUPPORTED"
        );

        // No v3.0 interface on the target: only the 2.40 interface is offered
        // and v3.0 functions are not supported.
        let gil: FnGetInterfaceList = sym(&spy, "C_GetInterfaceList");
        let mut count: c_ulong = 0;
        assert_eq!(gil(std::ptr::null_mut(), &mut count), CKR_OK);
        assert_eq!(count, 1);
        let cancel: FnSessionCancel = sym(&spy, "C_SessionCancel");
        assert_eq!(cancel(7, 0), CKR_FUNCTION_NOT_SUPPORTED);

        let fin: FnPtr = entry(l.f[I_FINALIZE]);
        assert_eq!(fin(std::ptr::null_mut()), CKR_OK);
        // A NULL out-pointer is refused by the spy (it owns this function).
        assert_eq!(gfl(std::ptr::null_mut()), CKR_ARGUMENTS_BAD);
    }
}

// ── H6-05: C_GetInterfaceList / C_GetInterface and v3.0 wrappers ────────────

#[test]
fn v3_interface_wraps_the_target_v3_table() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("spy.jsonl");
    run_child(
        "child_v3_interface",
        &[
            ("PKCS11_SPY_TARGET", mock_path().into()),
            ("PKCS11_SPY_LOG", log.clone().into()),
        ],
        None,
    );
    let (text, recs) = read_log(&log);
    assert_no_secrets(&text);
    let c = one(&recs, "C_LoginUser", "call");
    assert_eq!(c["args"]["user_type"], 1);
    assert_eq!(
        one(&recs, "C_LoginUser", "return")["rv"],
        "CKR_PIN_INCORRECT"
    );
    assert_eq!(one(&recs, "C_SessionCancel", "return")["rv"], "CKR_OK");
    assert_eq!(
        one(&recs, "C_EncryptMessage", "return")["rv"],
        "CKR_FUNCTION_NOT_SUPPORTED"
    );
    assert_eq!(records(&recs, "C_GetInterface", "call").len(), 4);
}

#[test]
#[ignore = "subprocess helper for v3_interface_wraps_the_target_v3_table"]
fn child_v3_interface() {
    if !is_child() {
        return;
    }
    let spy = load_spy();
    // SAFETY: symbol types match the PKCS#11 prototypes / the mock's layout.
    unsafe {
        let gil: FnGetInterfaceList = sym(&spy, "C_GetInterfaceList");
        let gi: FnGetInterface = sym(&spy, "C_GetInterface");

        let mut count: c_ulong = 0;
        assert_eq!(gil(std::ptr::null_mut(), &mut count), CKR_OK);
        assert_eq!(count, 2);
        let mut small: c_ulong = 1;
        let mut ifs = [Interface {
            name: std::ptr::null(),
            list: std::ptr::null(),
            flags: 0,
        }; 2];
        assert_eq!(
            gil(ifs.as_mut_ptr(), &mut small),
            0x150,
            "CKR_BUFFER_TOO_SMALL"
        );
        assert_eq!(small, 2);
        assert_eq!(gil(ifs.as_mut_ptr(), &mut count), CKR_OK);
        for i in &ifs {
            assert_eq!(
                std::ffi::CStr::from_ptr(i.name as *const _).to_bytes(),
                b"PKCS 11"
            );
            assert_eq!(i.flags, 1, "target interface flags are mirrored");
        }
        assert_eq!(
            (*(ifs[0].list as *const List3)).version,
            Version { major: 3, minor: 0 }
        );
        assert_eq!(
            (*(ifs[1].list as *const List2)).version,
            Version {
                major: 2,
                minor: 40
            }
        );

        // Default interface is v3.0; explicit 2.40 works; unknown name fails.
        let mut p: *const Interface = std::ptr::null();
        assert_eq!(gi(std::ptr::null(), std::ptr::null(), &mut p, 0), CKR_OK);
        let v3 = (*p).list as *const List3;
        assert_eq!((*v3).version, Version { major: 3, minor: 0 });
        let v240 = Version {
            major: 2,
            minor: 40,
        };
        assert_eq!(
            gi(c"PKCS 11".as_ptr() as *const u8, &v240, &mut p, 0),
            CKR_OK
        );
        assert_eq!((*((*p).list as *const List2)).version, v240);
        assert_eq!(
            gi(
                c"Vendor \"X\"".as_ptr() as *const u8,
                std::ptr::null(),
                &mut p,
                0
            ),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            gi(std::ptr::null(), std::ptr::null(), &mut p, 0x2),
            CKR_ARGUMENTS_BAD,
            "flags not offered"
        );

        // The v3.0 table is the spy's, wrapping the mock's.
        let mock =
            libloading::Library::new(std::env::var_os("PKCS11_SPY_TARGET").unwrap()).unwrap();
        let mock_v3: unsafe extern "C" fn() -> *const List3 = sym(&mock, "mock_v3_list");
        assert_ne!(v3, mock_v3());
        let l = &*v3;
        let login_user: FnLoginUser = entry(l.f[I_LOGIN_USER]);
        assert_eq!(
            login_user(
                3,
                1,
                SECRET_PIN.as_ptr(),
                SECRET_PIN.len() as c_ulong,
                SECRET_USER.as_ptr(),
                SECRET_USER.len() as c_ulong
            ),
            CKR_PIN_INCORRECT
        );
        let cancel: FnSessionCancel = entry(l.f[I_SESSION_CANCEL]);
        assert_eq!(cancel(3, 0), CKR_OK);
        type FnEncMsg = unsafe extern "C" fn(
            c_ulong,
            *mut c_void,
            c_ulong,
            *mut u8,
            c_ulong,
            *mut u8,
            c_ulong,
            *mut u8,
            *mut c_ulong,
        ) -> RV;
        let enc_msg: FnEncMsg = entry(l.f[I_ENCRYPT_MESSAGE]);
        let mut n: c_ulong = 0;
        let np = std::ptr::null_mut();
        assert_eq!(
            enc_msg(3, np as *mut c_void, 0, np, 0, np, 0, np, &mut n),
            CKR_FUNCTION_NOT_SUPPORTED
        );
    }
}

// ── H6-04 / H6-06 / H6-12: misconfiguration returns an error, never aborts ──

#[test]
fn misconfiguration_returns_ckr_general_error_instead_of_aborting() {
    let dir = tempfile::tempdir().unwrap();
    let world_writable = dir.path().join("libww.so");
    std::fs::copy(mock_path(), &world_writable).unwrap();
    std::fs::set_permissions(&world_writable, std::fs::Permissions::from_mode(0o666)).unwrap();

    let cases: Vec<(Option<OsString>, &str)> = vec![
        (None, "PKCS11_SPY_TARGET is not set"),
        (Some("libmock.so".into()), "must be an absolute path"),
        (
            Some(dir.path().join("missing.so").into()),
            "cannot be resolved",
        ),
        (Some(spy_path().into()), "is the spy itself"),
        (Some(world_writable.into()), "writable by other users"),
    ];
    for (target, reason) in cases {
        let mut envs = vec![("PKCS11_SPY_LOG", OsString::from("off"))];
        if let Some(t) = target {
            envs.push(("PKCS11_SPY_TARGET", t));
        }
        let out = run_child("child_misconfigured", &envs, None);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(reason),
            "expected {reason:?} in stderr:\n{stderr}"
        );
    }
}

#[test]
#[ignore = "subprocess helper for misconfiguration_returns_ckr_general_error_instead_of_aborting"]
fn child_misconfigured() {
    if !is_child() {
        return;
    }
    let spy = load_spy();
    // SAFETY: symbol types match the PKCS#11 prototypes.
    unsafe {
        let gfl: FnGetFunctionList = sym(&spy, "C_GetFunctionList");
        let mut list: *const List2 = std::ptr::null();
        assert_eq!(gfl(&mut list), CKR_GENERAL_ERROR);
        assert!(list.is_null());
        let init: FnPtr = sym(&spy, "C_Initialize");
        assert_eq!(init(std::ptr::null_mut()), CKR_GENERAL_ERROR);
        let gsl: FnGetSlotList = sym(&spy, "C_GetSlotList");
        let mut n: c_ulong = 0;
        assert_eq!(gsl(1, std::ptr::null_mut(), &mut n), CKR_GENERAL_ERROR);
    }
}

// ── H6-08 / H6-03 / H6-09: log path handling and timing precision ───────────

#[test]
fn bare_log_file_name_is_created_in_cwd_with_full_precision_opt_in() {
    let dir = tempfile::tempdir().unwrap();
    run_child(
        "child_minimal_calls",
        &[
            ("PKCS11_SPY_TARGET", mock_path().into()),
            ("PKCS11_SPY_LOG", "spy.jsonl".into()),
            ("PKCS11_SPY_REDUCED_TIMING", "0".into()),
        ],
        Some(dir.path()),
    );
    let log = dir.path().join("spy.jsonl");
    assert_eq!(
        std::fs::metadata(&log).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let (_, recs) = read_log(&log);
    assert_eq!(recs[0]["timing"], "us");
    let r = one(&recs, "C_Initialize", "return");
    assert!(r.get("duration_us").is_some());
    let ts = r["ts"].to_string();
    assert_eq!(ts.split('.').nth(1).map(str::len), Some(6), "{ts}");
}

#[test]
fn symlinked_log_path_is_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    let link = dir.path().join("spy.jsonl");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let out = run_child(
        "child_minimal_calls",
        &[
            ("PKCS11_SPY_TARGET", mock_path().into()),
            ("PKCS11_SPY_LOG", link.into()),
        ],
        None,
    );
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("logging disabled"), "{stderr}");
}

#[test]
fn stderr_sink_is_explicit_opt_in() {
    let out = run_child(
        "child_minimal_calls",
        &[
            ("PKCS11_SPY_TARGET", mock_path().into()),
            ("PKCS11_SPY_LOG", "-".into()),
        ],
        None,
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(r#""fn":"C_Initialize","event":"return""#),
        "{stderr}"
    );

    // Unset: nothing is logged, one warning explains why.
    let out = run_child(
        "child_minimal_calls",
        &[("PKCS11_SPY_TARGET", mock_path().into())],
        None,
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("PKCS11_SPY_LOG is not set"), "{stderr}");
    assert!(!stderr.contains("C_Initialize"), "{stderr}");
}

#[test]
#[ignore = "subprocess helper"]
fn child_minimal_calls() {
    if !is_child() {
        return;
    }
    let spy = load_spy();
    // SAFETY: symbol types match the PKCS#11 prototypes.
    unsafe {
        let init: FnPtr = sym(&spy, "C_Initialize");
        assert_eq!(init(std::ptr::null_mut()), CKR_OK);
        let fin: FnPtr = sym(&spy, "C_Finalize");
        assert_eq!(fin(std::ptr::null_mut()), CKR_OK);
    }
}

// ── Against the real craton-hsm cdylib (when it has been built) ─────────────

fn craton_hsm_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("CRATON_HSM_LIB") {
        return Some(PathBuf::from(p));
    }
    let name = if cfg!(target_os = "macos") {
        "libcraton_hsm.dylib"
    } else {
        "libcraton_hsm.so"
    };
    [build_dir().join(name), build_dir().join("deps").join(name)]
        .into_iter()
        .find(|p| p.exists())
}

#[test]
fn spy_wraps_the_craton_hsm_cdylib() {
    let Some(lib) = craton_hsm_path() else {
        eprintln!(
            "SKIPPED: craton-hsm cdylib not built (run `cargo build -p craton-hsm --lib` \
             or set CRATON_HSM_LIB)"
        );
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("spy.jsonl");
    run_child(
        "child_craton_hsm",
        &[
            ("PKCS11_SPY_TARGET", lib.into()),
            ("PKCS11_SPY_LOG", log.clone().into()),
        ],
        Some(dir.path()),
    );
    let (_, recs) = read_log(&log);
    for f in [
        "C_GetFunctionList",
        "C_Initialize",
        "C_GetSlotList",
        "C_Finalize",
    ] {
        one(&recs, f, "call");
        one(&recs, f, "return");
    }
    assert_eq!(one(&recs, "C_Initialize", "return")["rv"], "CKR_OK");
    assert_eq!(one(&recs, "C_GetSlotList", "return")["rv"], "CKR_OK");
}

#[test]
#[ignore = "subprocess helper for spy_wraps_the_craton_hsm_cdylib"]
fn child_craton_hsm() {
    if !is_child() {
        return;
    }
    let spy = load_spy();
    // SAFETY: symbol types match the PKCS#11 prototypes.
    unsafe {
        let gfl: FnGetFunctionList = sym(&spy, "C_GetFunctionList");
        let mut list: *const List2 = std::ptr::null();
        assert_eq!(gfl(&mut list), CKR_OK);
        let l = &*list;
        let init: FnPtr = entry(l.f[I_INITIALIZE]);
        assert_eq!(init(std::ptr::null_mut()), CKR_OK);
        let gsl: FnGetSlotList = entry(l.f[4]);
        let mut n: c_ulong = 0;
        assert_eq!(gsl(0, std::ptr::null_mut(), &mut n), CKR_OK);
        assert!(n >= 1);
        let fin: FnPtr = entry(l.f[I_FINALIZE]);
        assert_eq!(fin(std::ptr::null_mut()), CKR_OK);
    }
}
