// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Loads the real PKCS#11 module once and caches its function tables.
//!
//! Trust model (H6-06): the spy loads whatever `PKCS11_SPY_TARGET` names, so
//! the real controls are (a) who sets the environment — ignored entirely in
//! secure-execution mode (H6-02, see `config.rs`) — and (b) who can write the
//! module file. The loader therefore requires an absolute path, and on Unix
//! checks that the module and every ancestor directory are owned by root or
//! the effective user and cannot be modified by other users (sticky
//! directories such as `/tmp` excepted). There is no file-extension check: it
//! was a heuristic, not a control.
//!
//! The module is `dlopen`ed by its canonical path (H6-11), not via
//! `/proc/self/fd/N`, so `$ORIGIN` in its `DT_RUNPATH` and `dladdr()`-based
//! self-location keep working. After loading, the path is re-`stat`ed and its
//! `(st_dev, st_ino)` compared with the descriptor that was validated. On
//! Windows the module's dependencies are resolved only from its own directory
//! and System32 (`LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | ..._SYSTEM32`).
//!
//! Errors never panic (H6-04): they are cached, reported once (log + stderr)
//! and every PKCS#11 entry point returns `CKR_GENERAL_ERROR`.
//!
//! Once loaded, the module is never unloaded: if the host `dlclose`s the spy,
//! the target stays mapped for the life of the process.

use crate::ckr::ckr_name;
use crate::config;
use crate::logger;
use crate::types::*;
use libloading::Library;
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::OnceLock;

type GetFunctionListFn = unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;
type GetInterfaceFn =
    unsafe extern "C" fn(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS) -> CK_RV;

/// The loaded target module and its function tables (resolved once — no
/// per-call `dlsym`).
pub struct Target {
    _lib: Library,
    v2: *const CK_FUNCTION_LIST,
    v3: *const CK_FUNCTION_LIST_3_0,
    /// Flags of the target's "PKCS 11" v3.0 interface (0 if none).
    pub iface_flags: CK_FLAGS,
    pub path: PathBuf,
}

// SAFETY: the table pointers refer to immutable data inside the loaded module,
// which is never unloaded; PKCS#11 function lists are shared between threads
// by design.
unsafe impl Send for Target {}
unsafe impl Sync for Target {}

impl Target {
    pub fn v2(&self) -> Option<&CK_FUNCTION_LIST> {
        // SAFETY: non-NULL pointer returned by the target's C_GetFunctionList
        // (or C_GetInterface); valid while the module is loaded (forever).
        unsafe { self.v2.as_ref() }
    }

    pub fn v3(&self) -> Option<&CK_FUNCTION_LIST_3_0> {
        // SAFETY: as above; NULL when the target has no v3.0 interface.
        unsafe { self.v3.as_ref() }
    }

    pub fn has_v3(&self) -> bool {
        !self.v3.is_null()
    }
}

static TARGET: OnceLock<Result<Target, String>> = OnceLock::new();

thread_local! {
    /// Set while this thread is loading the target (H6-12: a re-entrant call
    /// from the target's constructors must not re-enter `OnceLock` init).
    static LOADING: Cell<bool> = const { Cell::new(false) };
}

/// The loaded target, or the error code to return (`CKR_GENERAL_ERROR`).
pub fn target() -> Result<&'static Target, CK_RV> {
    if let Some(r) = TARGET.get() {
        return r.as_ref().map_err(|_| CKR_GENERAL_ERROR);
    }
    if LOADING.try_with(Cell::get).unwrap_or(false) {
        logger::log_event(
            "error",
            "re-entrant call into the spy while the target module is loading; returning CKR_GENERAL_ERROR",
        );
        return Err(CKR_GENERAL_ERROR);
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            let _ = LOADING.try_with(|l| l.set(false));
        }
    }
    let _ = LOADING.try_with(|l| l.set(true));
    let _reset = Reset;

    let r = TARGET.get_or_init(|| {
        let res = load();
        match &res {
            Ok(t) => logger::log_event(
                "info",
                &format!(
                    "loaded target {} (v3.0 interface: {})",
                    t.path.display(),
                    if t.has_v3() { "yes" } else { "no" }
                ),
            ),
            Err(e) => {
                if !logger::is_stderr() {
                    eprintln!("pkcs11-spy: {e}");
                }
                logger::log_event("error", e);
            }
        }
        res
    });
    r.as_ref().map_err(|_| CKR_GENERAL_ERROR)
}

fn load() -> Result<Target, String> {
    let raw = config::get().target.as_ref().map_err(|e| e.to_string())?;
    if !raw.is_absolute() {
        return Err(format!(
            "PKCS11_SPY_TARGET must be an absolute path (got {})",
            raw.display()
        ));
    }
    let canonical = std::fs::canonicalize(raw).map_err(|e| {
        format!(
            "PKCS11_SPY_TARGET {} cannot be resolved: {e}",
            raw.display()
        )
    })?;
    let lib = open_verified(&canonical)?;

    // SAFETY: the symbol types match the PKCS#11 prototypes.
    let gfl: Option<GetFunctionListFn> =
        unsafe { lib.get::<GetFunctionListFn>(b"C_GetFunctionList\0") }
            .ok()
            .map(|s| *s);
    // SAFETY: as above.
    let gi: Option<GetInterfaceFn> = unsafe { lib.get::<GetInterfaceFn>(b"C_GetInterface\0") }
        .ok()
        .map(|s| *s);

    // H6-12: self-targeting — dlopen() of the spy's own file returns the
    // spy's handle, so the resolved entry point is the spy's own.
    let own_gfl: GetFunctionListFn = crate::C_GetFunctionList;
    let own_gi: GetInterfaceFn = crate::C_GetInterface;
    if gfl.map(|f| f as usize) == Some(own_gfl as usize)
        || gi.map(|f| f as usize) == Some(own_gi as usize)
    {
        return Err(format!(
            "PKCS11_SPY_TARGET {} is the spy itself; refusing to recurse",
            canonical.display()
        ));
    }

    let mut v2: CK_FUNCTION_LIST_PTR = ptr::null_mut();
    if let Some(f) = gfl {
        // SAFETY: valid out-pointer; calling the target's documented entry point.
        let rv = unsafe { f(&mut v2) };
        if rv != CKR_OK {
            return Err(format!(
                "target C_GetFunctionList failed: {}",
                ckr_name(crate::ckr::widen(rv))
            ));
        }
    }

    let (mut v3, mut iface_flags): (*const CK_FUNCTION_LIST_3_0, CK_FLAGS) = (ptr::null(), 0);
    if let Some(f) = gi {
        let mut iface: CK_INTERFACE_PTR = ptr::null_mut();
        let mut ver = CK_VERSION { major: 3, minor: 0 };
        // SAFETY: NUL-terminated name, valid version and out-pointer.
        let rv = unsafe { f(c"PKCS 11".as_ptr() as *mut u8, &mut ver, &mut iface, 0) };
        if rv == CKR_OK && !iface.is_null() {
            // SAFETY: the target returned a pointer to its CK_INTERFACE.
            let i = unsafe { ptr::read_unaligned(iface) };
            let l = i.pFunctionList as *const CK_FUNCTION_LIST_3_0;
            // SAFETY: non-NULL table pointer from the target; `version` is a
            // by-value read of a Copy field.
            if !l.is_null() && unsafe { (*l).version }.major == 3 {
                v3 = l;
                iface_flags = i.flags;
            }
        }
    }

    if v2.is_null() && !v3.is_null() {
        // A CK_FUNCTION_LIST_3_0 begins with the complete v2.40 layout.
        v2 = v3 as CK_FUNCTION_LIST_PTR;
    }
    if v2.is_null() {
        return Err(format!(
            "target {} provides neither a usable C_GetFunctionList nor C_GetInterface",
            canonical.display()
        ));
    }

    // H6-12: symbol interposition — if the spy was loaded RTLD_GLOBAL, the
    // target's function-table relocations may have bound to the spy's
    // exported C_* symbols, and forwarding would recurse forever.
    // SAFETY: v2 is non-NULL (checked above) and valid while loaded.
    let t = unsafe { &*v2 };
    let spy = crate::spy_function_list();
    macro_rules! same {
        ($f:ident) => {
            matches!((t.$f, spy.$f), (Some(a), Some(b)) if a as usize == b as usize)
        };
    }
    if ptr::eq(v2, spy)
        || ptr::eq(v3, crate::spy_function_list_3_0())
        || same!(C_Initialize)
        || same!(C_Finalize)
        || same!(C_GetInfo)
        || same!(C_GetFunctionList)
        || same!(C_OpenSession)
    {
        return Err(format!(
            "the function table of {} points back into the spy (self-targeting or \
             symbol interposition); refusing to recurse",
            canonical.display()
        ));
    }

    Ok(Target {
        _lib: lib,
        v2,
        v3,
        iface_flags,
        path: canonical,
    })
}

#[cfg(unix)]
fn open_verified(canonical: &Path) -> Result<Library, String> {
    use std::os::unix::fs::MetadataExt;

    let file = std::fs::File::open(canonical)
        .map_err(|e| format!("cannot open PKCS11_SPY_TARGET {}: {e}", canonical.display()))?;
    let m = file
        .metadata()
        .map_err(|e| format!("cannot fstat {}: {e}", canonical.display()))?;
    crate::fsutil::check_trusted_file(canonical, &m)
        .map_err(|e| format!("untrusted PKCS11_SPY_TARGET: {e}"))?;
    crate::fsutil::check_trusted_ancestors(canonical)
        .map_err(|e| format!("untrusted PKCS11_SPY_TARGET: {e}"))?;

    // SAFETY: loading a module runs its initialisers; the file and its
    // directories were verified above to be controlled by root / the
    // effective user only.
    let lib = unsafe { Library::new(canonical) }
        .map_err(|e| format!("cannot load {}: {e}", canonical.display()))?;

    let now = std::fs::metadata(canonical)
        .map_err(|e| format!("cannot stat {}: {e}", canonical.display()))?;
    if (now.dev(), now.ino()) != (m.dev(), m.ino()) {
        return Err(format!(
            "{} was replaced while it was being loaded",
            canonical.display()
        ));
    }
    Ok(lib)
}

#[cfg(windows)]
fn open_verified(canonical: &Path) -> Result<Library, String> {
    use libloading::os::windows::{
        Library as WinLibrary, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    let m = std::fs::metadata(canonical)
        .map_err(|e| format!("cannot stat PKCS11_SPY_TARGET {}: {e}", canonical.display()))?;
    if !m.is_file() {
        return Err(format!("{} is not a regular file", canonical.display()));
    }
    // SAFETY: loading a module runs its initialisers; dependencies are
    // searched only in the module's directory and System32.
    let lib = unsafe {
        WinLibrary::load_with_flags(
            canonical,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }
    .map_err(|e| format!("cannot load {}: {e}", canonical.display()))?;
    Ok(lib.into())
}
