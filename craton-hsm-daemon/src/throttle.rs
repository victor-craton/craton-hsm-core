// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Failed-PIN throttle keyed by (client identity, slot, role) (H4-11).
//!
//! One implementation serves Login, InitToken and InitPin. Only genuine PIN
//! failures are recorded by callers. Callers serialize check → verify →
//! record under the per-slot login lock, so the sequence is atomic.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tonic::Status;

/// Upper bound on tracked keys, to bound memory.
const MAX_ENTRIES: usize = 4096;

struct Entry {
    failures: u32,
    lockout_until: Option<Instant>,
}

pub struct Throttle {
    what: &'static str,
    max_attempts: u32,
    cooldown: Duration,
    map: Mutex<HashMap<String, Entry>>,
}

impl Throttle {
    pub fn new(what: &'static str, max_attempts: u32, cooldown: Duration) -> Self {
        Self {
            what,
            max_attempts,
            cooldown,
            map: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.map.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Reject if `key` is in a cooldown window.
    pub fn check(&self, key: &str) -> Result<(), Status> {
        if self.max_attempts == 0 {
            return Ok(());
        }
        let now = Instant::now();
        let mut map = self.lock();
        if let Some(e) = map.get_mut(key) {
            match e.lockout_until {
                Some(until) if now < until => {
                    let secs = until.duration_since(now).as_secs() + 1;
                    return Err(Status::resource_exhausted(format!(
                        "Too many failed {} attempts. Retry after {} seconds.",
                        self.what, secs
                    )));
                }
                Some(_) => {
                    e.failures = 0;
                    e.lockout_until = None;
                }
                None => {}
            }
        }
        Ok(())
    }

    /// Record one PIN failure for `key`.
    pub fn record_failure(&self, key: &str) {
        if self.max_attempts == 0 {
            return;
        }
        let now = Instant::now();
        let mut map = self.lock();
        if map.len() >= MAX_ENTRIES && !map.contains_key(key) {
            map.retain(|_, e| matches!(e.lockout_until, Some(u) if u > now));
            if map.len() >= MAX_ENTRIES {
                // Still full of active lockouts: drop the entry with the
                // fewest failures rather than growing without bound.
                if let Some(k) = map
                    .iter()
                    .min_by_key(|(_, e)| e.failures)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&k);
                }
            }
        }
        let e = map.entry(key.to_string()).or_insert(Entry {
            failures: 0,
            lockout_until: None,
        });
        e.failures = e.failures.saturating_add(1);
        if e.failures >= self.max_attempts {
            // (H4-20) checked arithmetic — cooldown is bounded by config
            // validation, but never panic on overflow.
            e.lockout_until = now.checked_add(self.cooldown).or(Some(now));
            tracing::warn!(
                what = self.what,
                "throttle engaged after {} failed attempts",
                e.failures
            );
        }
    }

    pub fn clear(&self, key: &str) {
        self.lock().remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_independent_and_lockout_expires() {
        let t = Throttle::new("login", 2, Duration::from_millis(50));
        t.record_failure("a");
        assert!(t.check("a").is_ok());
        t.record_failure("a");
        assert!(t.check("a").is_err());
        assert!(t.check("b").is_ok(), "other clients must not be locked out");
        std::thread::sleep(Duration::from_millis(60));
        assert!(t.check("a").is_ok());
    }

    #[test]
    fn disabled_throttle_never_blocks() {
        let t = Throttle::new("login", 0, Duration::from_secs(60));
        for _ in 0..10 {
            t.record_failure("a");
        }
        assert!(t.check("a").is_ok());
    }
}
