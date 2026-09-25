// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Memory locking utilities for key material protection.
//!
//! On Unix systems, uses mlock(2) (plus `MADV_DONTDUMP` on Linux so locked
//! key pages are excluded from core dumps). On Windows, uses
//! VirtualLock/VirtualUnlock.
//!
//! Page locks do not nest: a single `munlock` unlocks a page no matter how
//! many buffers on it were locked. Because many small key buffers share heap
//! pages, the lock is **reference counted per page** (H2-18): a page is locked
//! when its first key buffer is locked and unlocked only when its last one
//! is released, so dropping one key never makes other live keys swappable.
//!
//! Locking is best effort (it can fail when `RLIMIT_MEMLOCK` is exhausted);
//! failures are counted and exposed via [`mlock_failure_count`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

struct LockTable {
    /// Lock reference count per page start address.
    pages: HashMap<usize, usize>,
    /// Buffers successfully locked, so an unlock of a buffer whose lock
    /// failed (or that was never locked) cannot release other keys' pages.
    buffers: HashMap<(usize, usize), usize>,
}

static LOCKS: parking_lot::Mutex<Option<LockTable>> = parking_lot::Mutex::new(None);
static MLOCK_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Number of page-lock failures since process start.
pub fn mlock_failure_count() -> u64 {
    MLOCK_FAILURES.load(Ordering::Relaxed)
}

fn page_size() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: sysconf has no preconditions.
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if ps > 0 {
            return ps as usize;
        }
        4096
    }
    #[cfg(not(unix))]
    {
        4096
    }
}

fn pages(ptr: *const u8, len: usize) -> impl Iterator<Item = usize> {
    let ps = page_size();
    let start = (ptr as usize) & !(ps - 1);
    let end = (ptr as usize).saturating_add(len - 1) & !(ps - 1);
    (start..=end).step_by(ps)
}

#[cfg(unix)]
fn os_lock_page(page: usize, ps: usize) -> Result<(), std::io::Error> {
    // SAFETY: `page` is the start of a page that overlaps a live allocation
    // owned by the caller; mlock only changes residency, not contents.
    let ret = unsafe { libc::mlock(page as *const libc::c_void, ps) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: as above; MADV_DONTDUMP only affects core dumps.
        unsafe {
            libc::madvise(page as *mut libc::c_void, ps, libc::MADV_DONTDUMP);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn os_unlock_page(page: usize, ps: usize) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: see os_lock_page.
        unsafe {
            libc::madvise(page as *mut libc::c_void, ps, libc::MADV_DODUMP);
        }
    }
    // SAFETY: see os_lock_page.
    unsafe {
        libc::munlock(page as *const libc::c_void, ps);
    }
}

#[cfg(windows)]
fn os_lock_page(page: usize, ps: usize) -> Result<(), std::io::Error> {
    // SAFETY: `page` overlaps a live allocation owned by the caller.
    let ret = unsafe {
        windows_sys::Win32::System::Memory::VirtualLock(page as *mut core::ffi::c_void, ps)
    };
    if ret != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn os_unlock_page(page: usize, ps: usize) {
    // SAFETY: see os_lock_page.
    unsafe {
        windows_sys::Win32::System::Memory::VirtualUnlock(page as *mut core::ffi::c_void, ps);
    }
}

fn release_page(table: &mut LockTable, page: usize, ps: usize) {
    if let Some(c) = table.pages.get_mut(&page) {
        *c -= 1;
        if *c == 0 {
            table.pages.remove(&page);
            os_unlock_page(page, ps);
        }
    }
}

/// Lock a buffer into memory so it cannot be paged to swap.
/// Returns `Ok(())` on success (or when unsupported / under Miri).
pub fn mlock_buffer(ptr: *const u8, len: usize) -> Result<(), std::io::Error> {
    if len == 0 || ptr.is_null() || cfg!(miri) {
        return Ok(());
    }
    let ps = page_size();
    let mut guard = LOCKS.lock();
    let table = guard.get_or_insert_with(|| LockTable {
        pages: HashMap::new(),
        buffers: HashMap::new(),
    });
    let page_list: Vec<usize> = pages(ptr, len).collect();
    for (idx, &page) in page_list.iter().enumerate() {
        let count = table.pages.get(&page).copied().unwrap_or(0);
        if count == 0 {
            if let Err(e) = os_lock_page(page, ps) {
                for &p in &page_list[..idx] {
                    release_page(table, p, ps);
                }
                MLOCK_FAILURES.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        }
        table.pages.insert(page, count + 1);
    }
    *table.buffers.entry((ptr as usize, len)).or_insert(0) += 1;
    Ok(())
}

/// Release a buffer previously locked with [`mlock_buffer`]. A page is only
/// unlocked when no other locked buffer still references it. Buffers that
/// were never (successfully) locked are ignored.
pub fn munlock_buffer(ptr: *const u8, len: usize) -> Result<(), std::io::Error> {
    if len == 0 || ptr.is_null() || cfg!(miri) {
        return Ok(());
    }
    let ps = page_size();
    let mut guard = LOCKS.lock();
    let Some(table) = guard.as_mut() else {
        return Ok(());
    };
    match table.buffers.get_mut(&(ptr as usize, len)) {
        Some(c) if *c > 1 => *c -= 1,
        Some(_) => {
            table.buffers.remove(&(ptr as usize, len));
        }
        None => return Ok(()),
    }
    for page in pages(ptr, len) {
        release_page(table, page, ps);
    }
    Ok(())
}

/// Number of pages currently locked by this module (diagnostics / tests).
pub fn locked_page_count() -> usize {
    LOCKS.lock().as_ref().map_or(0, |t| t.pages.len())
}

#[cfg(test)]
fn page_refcount(page: usize) -> Option<usize> {
    LOCKS
        .lock()
        .as_ref()
        .and_then(|t| t.pages.get(&page).copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlock_empty_buffer() {
        assert!(mlock_buffer(std::ptr::null(), 0).is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_mlock_munlock_roundtrip() {
        let data = vec![0xABu8; 4096];
        if mlock_buffer(data.as_ptr(), data.len()).is_ok() {
            assert!(munlock_buffer(data.as_ptr(), data.len()).is_ok());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_shared_page_stays_locked() {
        // Two small buffers inside one page owned exclusively by this test:
        // releasing one must not unlock the page for the other.
        let ps = page_size();
        let backing = vec![0u8; 3 * ps];
        let base = ((backing.as_ptr() as usize + ps) & !(ps - 1)) as *const u8;
        let a = base;
        let b = unsafe { base.add(32) };
        if mlock_buffer(a, 16).is_err() {
            return; // no mlock privilege in this environment
        }
        mlock_buffer(b, 16).unwrap();
        let page = base as usize;
        assert_eq!(page_refcount(page), Some(2));
        munlock_buffer(a, 16).unwrap();
        assert_eq!(page_refcount(page), Some(1));
        // Unlocking a buffer that is not (or no longer) locked is a no-op.
        munlock_buffer(a, 16).unwrap();
        assert_eq!(page_refcount(page), Some(1));
        munlock_buffer(b, 16).unwrap();
        assert_eq!(page_refcount(page), None);
        drop(backing);
    }
}
