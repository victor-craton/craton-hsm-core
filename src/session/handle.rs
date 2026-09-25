// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Session and object handle allocation.
//!
//! Handles are drawn uniformly at random from the OS CSPRNG over the full
//! non-zero `CK_ULONG` range and checked against the live handle table before
//! use (H3-19). This replaces the earlier keyed Feistel permutation, whose
//! round function was not a secure PRP and whose counter could wrap around
//! onto live handles on 32-bit `CK_ULONG` platforms. Because a handle is only
//! issued if it is not currently in use, and the tables themselves refuse to
//! replace an occupied entry, a live session or object can never be
//! silently replaced.
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::{CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_ULONG};

/// Maximum handle value, bounded by the platform's `CK_ULONG` width.
const MAX_HANDLE: u64 = CK_ULONG::MAX as u64;

/// Upper bound on collision retries before giving up (only reachable if the
/// handle space is almost exhausted, which cannot happen with the object and
/// session caps enforced elsewhere).
const MAX_ATTEMPTS: usize = 1024;

fn random_handle() -> HsmResult<u64> {
    use rand::RngCore;
    let mut buf = [0u8; 8];
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|_| HsmError::GeneralError)?;
    let v = u64::from_ne_bytes(buf);
    Ok(if MAX_HANDLE == u64::MAX {
        v
    } else {
        v % (MAX_HANDLE + 1)
    })
}

fn next_unused_impl(in_use: impl Fn(u64) -> bool) -> HsmResult<u64> {
    for _ in 0..MAX_ATTEMPTS {
        let h = random_handle()?;
        // Skip CK_INVALID_HANDLE (0) and any live handle.
        if h != 0 && !in_use(h) {
            return Ok(h);
        }
    }
    tracing::error!("handle allocation failed: handle space exhausted");
    Err(HsmError::DeviceMemory)
}

/// Generates unique, unpredictable session handles.
#[derive(Default)]
pub struct SessionHandleAllocator;

impl SessionHandleAllocator {
    /// Create an allocator.
    pub fn new() -> Self {
        Self
    }

    /// Return a random non-zero handle for which `in_use` returns false.
    pub fn next_unused(
        &self,
        in_use: impl Fn(CK_SESSION_HANDLE) -> bool,
    ) -> HsmResult<CK_SESSION_HANDLE> {
        next_unused_impl(|h| in_use(h as CK_SESSION_HANDLE)).map(|h| h as CK_SESSION_HANDLE)
    }

    /// Return a random non-zero handle (callers must still insert with a
    /// vacancy check).
    pub fn next(&self) -> HsmResult<CK_SESSION_HANDLE> {
        self.next_unused(|_| false)
    }
}

/// Generates unique, unpredictable object handles.
#[derive(Default)]
pub struct ObjectHandleAllocator;

impl ObjectHandleAllocator {
    /// Create an allocator.
    pub fn new() -> Self {
        Self
    }

    /// Return a random non-zero handle for which `in_use` returns false.
    pub fn next_unused(
        &self,
        in_use: impl Fn(CK_OBJECT_HANDLE) -> bool,
    ) -> HsmResult<CK_OBJECT_HANDLE> {
        next_unused_impl(|h| in_use(h as CK_OBJECT_HANDLE)).map(|h| h as CK_OBJECT_HANDLE)
    }

    /// Return a random non-zero handle (callers must still insert with a
    /// vacancy check).
    pub fn next(&self) -> HsmResult<CK_OBJECT_HANDLE> {
        self.next_unused(|_| false)
    }

    /// Retained for API compatibility. Persisted handles are now protected
    /// by the live-table check in [`next_unused`](Self::next_unused), so no
    /// separate reservation set is needed (P9).
    pub fn ensure_past(&self, _handle: CK_OBJECT_HANDLE) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn handles_are_nonzero_and_unique_against_live_set() {
        let alloc = ObjectHandleAllocator::new();
        let mut live = HashSet::new();
        for _ in 0..10_000 {
            let h = alloc.next_unused(|h| live.contains(&h)).unwrap();
            assert_ne!(h, 0);
            assert!(live.insert(h));
        }
    }

    #[test]
    fn session_handles_not_sequential() {
        let alloc = SessionHandleAllocator::new();
        let a = alloc.next().unwrap();
        let b = alloc.next().unwrap();
        let c = alloc.next().unwrap();
        assert!(!(b == a.wrapping_add(1) && c == b.wrapping_add(1)));
    }

    #[test]
    fn exhausted_space_errors() {
        let alloc = ObjectHandleAllocator::new();
        assert!(alloc.next_unused(|_| true).is_err());
    }
}
