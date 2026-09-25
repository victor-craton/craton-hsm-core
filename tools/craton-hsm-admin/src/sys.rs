// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! The only module in the admin CLI that is allowed to use `unsafe`: thin,
//! argument-free wrappers around libc process-hardening calls.
#![allow(unsafe_code)]

/// Effective user id of this process.
#[cfg(unix)]
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid() takes no arguments, cannot fail and has no side effects.
    unsafe { libc::geteuid() }
}

/// Best-effort: prevent secrets (PINs, passphrases, key material) held by this
/// process from being written to core dumps or read via ptrace by other
/// processes of the same user (H5-24).
pub fn harden_process() {
    #[cfg(unix)]
    {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid, initialised rlimit that outlives the call.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
        if rc != 0 {
            tracing::warn!("could not disable core dumps (setrlimit RLIMIT_CORE failed)");
        }
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: PR_SET_DUMPABLE takes a single integer argument; the unused
        // variadic arguments are passed as zero as documented in prctl(2).
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc != 0 {
            tracing::warn!("could not mark process non-dumpable (prctl PR_SET_DUMPABLE failed)");
        }
    }
}
