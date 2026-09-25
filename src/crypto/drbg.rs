// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! HMAC_DRBG (SHA-256) per NIST SP 800-90A Rev. 1, plus the module-wide RBG.
//!
//! Structure:
//! - [`entropy`]: entropy input from the operating system (`getrandom` /
//!   `BCryptGenRandom`) passed through SP 800-90B §4.4 style health tests
//!   (Repetition Count Test and Adaptive Proportion Test) with a start-up
//!   test over 1024 samples. A health-test failure latches the module error
//!   state (A1-02, H2-15).
//! - [`HmacDrbg`]: the SP 800-90A mechanism (instantiate / reseed / generate
//!   with optional additional input and prediction resistance), enforcing the
//!   2^19-bit per-request limit and a reseed interval.
//! - [`fill_random`]: a single, process-wide, fork-aware DRBG instance used for
//!   all module randomness and for `C_GenerateRandom` (A1-01). The continuous
//!   test on DRBG output blocks runs on this long-lived instance, so it is
//!   meaningful (the previous per-call instances made it vacuous).
//! - [`drbg_kat`]: the SP 800-90A §11.3 known-answer health test run by POST,
//!   using the NIST CAVP HMAC_DRBG SHA-256 vector.
//!
//! The entropy source itself is **not** ESV-validated; see the handoff notes.
//! In FIPS builds the AWS-LC backend's own validated DRBG serves
//! `C_GenerateRandom` (see `CryptoBackend::generate_random`).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{HsmError, HsmResult};

type HmacSha256 = Hmac<Sha256>;

/// SP 800-90A Table 2: max_number_of_bits_per_request = 2^19 bits.
pub const MAX_BYTES_PER_REQUEST: usize = (1 << 19) / 8;

/// Reseed interval (generate calls). SP 800-90A allows up to 2^48; a much
/// smaller value is used so that fresh entropy is mixed in regularly.
const RESEED_INTERVAL: u64 = 1 << 16;

/// Security strength of HMAC_DRBG(SHA-256) in bytes.
const SECURITY_STRENGTH_BYTES: usize = 32;

/// Returns the current process ID (0 where unavailable). Used for fork
/// detection: a forked child must never continue the parent's DRBG state.
pub(crate) fn current_pid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: getpid has no preconditions.
        (unsafe { libc::getpid() }) as u32
    }
    #[cfg(windows)]
    {
        // SAFETY: GetCurrentProcessId has no preconditions.
        unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() }
    }
    #[cfg(not(any(unix, windows)))]
    {
        0
    }
}

// ============================================================================
// Entropy source + SP 800-90B health tests
// ============================================================================

pub mod entropy {
    //! OS entropy input with continuous health tests.
    //!
    //! Each byte returned by the OS is treated as one 8-bit sample. The cut-off
    //! values assume a conservative claimed min-entropy of H = 4 bits/sample
    //! and a false-positive rate of alpha = 2^-20 (SP 800-90B §4.4.1/§4.4.2):
    //! RCT cut-off C = 1 + ceil(20 / H) = 6, APT window W = 512 with
    //! cut-off 62 (Table 2, H = 4). A failure zeroizes the output, latches the
    //! module error state and returns an error.

    use super::*;
    use rand::RngCore;

    const RCT_CUTOFF: u32 = 6;
    const APT_WINDOW: u32 = 512;
    const APT_CUTOFF: u32 = 62;
    const STARTUP_SAMPLES: usize = 1024;

    struct HealthState {
        rct_last: Option<u8>,
        rct_count: u32,
        apt_first: u8,
        apt_seen: u32,
        apt_matches: u32,
        startup_done: bool,
    }

    static STATE: parking_lot::Mutex<HealthState> = parking_lot::Mutex::new(HealthState {
        rct_last: None,
        rct_count: 0,
        apt_first: 0,
        apt_seen: 0,
        apt_matches: 0,
        startup_done: false,
    });

    impl HealthState {
        /// Feed one sample through RCT and APT. Returns false on failure.
        fn sample(&mut self, b: u8) -> bool {
            // Repetition Count Test (SP 800-90B §4.4.1)
            if self.rct_last == Some(b) {
                self.rct_count += 1;
                if self.rct_count >= RCT_CUTOFF {
                    return false;
                }
            } else {
                self.rct_last = Some(b);
                self.rct_count = 1;
            }
            // Adaptive Proportion Test (SP 800-90B §4.4.2)
            if self.apt_seen == 0 {
                self.apt_first = b;
                self.apt_matches = 1;
                self.apt_seen = 1;
            } else {
                if b == self.apt_first {
                    self.apt_matches += 1;
                    if self.apt_matches >= APT_CUTOFF {
                        return false;
                    }
                }
                self.apt_seen += 1;
                if self.apt_seen >= APT_WINDOW {
                    self.apt_seen = 0;
                }
            }
            true
        }

        fn test_buffer(&mut self, buf: &[u8]) -> bool {
            buf.iter().all(|&b| self.sample(b))
        }
    }

    fn raw(out: &mut [u8]) -> HsmResult<()> {
        rand::rngs::OsRng.try_fill_bytes(out).map_err(|_| {
            tracing::error!("OS entropy source failure");
            HsmError::GeneralError
        })
    }

    fn fail(out: &mut [u8], what: &str) -> HsmError {
        out.zeroize();
        crate::crypto::self_test::enter_error_state(what);
        HsmError::GeneralError
    }

    /// Fill `out` with health-tested entropy input.
    pub fn get_entropy(out: &mut [u8]) -> HsmResult<()> {
        let mut st = STATE.lock();
        if !st.startup_done {
            // SP 800-90B §4.3 (1): start-up tests over 1024 consecutive samples.
            let mut startup = Zeroizing::new(vec![0u8; STARTUP_SAMPLES]);
            if raw(&mut startup).is_err() {
                return Err(fail(out, "entropy source unavailable at start-up"));
            }
            if !st.test_buffer(&startup) {
                return Err(fail(out, "entropy source start-up health test failed"));
            }
            st.startup_done = true;
        }
        if raw(out).is_err() {
            return Err(fail(out, "entropy source read failure"));
        }
        if !st.test_buffer(out) {
            tracing::error!("Entropy source continuous health test (RCT/APT) failed");
            return Err(fail(out, "entropy source continuous health test failed"));
        }
        Ok(())
    }

    /// Run the RCT/APT logic over `samples` on a fresh state (test hook).
    #[doc(hidden)]
    pub fn health_test_samples(samples: &[u8]) -> bool {
        let mut st = HealthState {
            rct_last: None,
            rct_count: 0,
            apt_first: 0,
            apt_seen: 0,
            apt_matches: 0,
            startup_done: true,
        };
        st.test_buffer(samples)
    }
}

// ============================================================================
// HMAC_DRBG
// ============================================================================

/// HMAC_DRBG per SP 800-90A using HMAC-SHA256.
///
/// `K`, `V` and all HMAC outputs are held in [`Zeroizing`] buffers.
pub struct HmacDrbg {
    key: Zeroizing<[u8; 32]>,
    value: Zeroizing<[u8; 32]>,
    reseed_counter: u64,
    /// Last output block, for the continuous output test.
    last_output: Zeroizing<[u8; 32]>,
    has_output: bool,
    /// Reseed from the entropy source before every generate request.
    prediction_resistance: bool,
    /// Instances created by [`HmacDrbg::instantiate`] (KAT only) have no
    /// entropy source and never reseed on their own.
    deterministic: bool,
}

impl std::fmt::Debug for HmacDrbg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacDrbg")
            .field("reseed_counter", &self.reseed_counter)
            .field("prediction_resistance", &self.prediction_resistance)
            .finish()
    }
}

fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length is always valid");
    for p in parts {
        mac.update(p);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    let mut tag = mac.finalize().into_bytes();
    out.copy_from_slice(&tag);
    tag.zeroize();
    out
}

impl HmacDrbg {
    fn blank(prediction_resistance: bool, deterministic: bool) -> Self {
        Self {
            key: Zeroizing::new([0u8; 32]),
            value: Zeroizing::new([0x01u8; 32]),
            reseed_counter: 0,
            last_output: Zeroizing::new([0u8; 32]),
            has_output: false,
            prediction_resistance,
            deterministic,
        }
    }

    /// Instantiate from the health-tested entropy source (no prediction
    /// resistance; reseeds every `RESEED_INTERVAL` requests).
    pub fn new() -> HsmResult<Self> {
        Self::new_with_prediction_resistance(false)
    }

    /// Instantiate from the entropy source, optionally with prediction
    /// resistance (reseed before every request).
    pub fn new_with_prediction_resistance(prediction_resistance: bool) -> HsmResult<Self> {
        let mut drbg = Self::blank(prediction_resistance, false);
        // entropy_input (security_strength) || nonce (security_strength / 2)
        let mut seed =
            Zeroizing::new([0u8; SECURITY_STRENGTH_BYTES + SECURITY_STRENGTH_BYTES / 2]);
        entropy::get_entropy(&mut *seed)?;
        // Personalization string: distinguishes instances across processes.
        let mut pers = [0u8; 20];
        pers[..4].copy_from_slice(&current_pid().to_be_bytes());
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        pers[4..].copy_from_slice(&nanos.to_be_bytes());
        drbg.update(&[&seed[..], b"CratonHSM-HMAC_DRBG-v2", &pers]);
        drbg.reseed_counter = 1;
        Ok(drbg)
    }

    /// SP 800-90A §10.1.2.3 Instantiate with caller-provided inputs.
    ///
    /// **For known-answer testing only.** The resulting instance never reseeds
    /// from the entropy source.
    pub fn instantiate(entropy_input: &[u8], nonce: &[u8], personalization: &[u8]) -> Self {
        let mut drbg = Self::blank(false, true);
        drbg.update(&[entropy_input, nonce, personalization]);
        drbg.reseed_counter = 1;
        drbg
    }

    /// Instantiate with a deterministic seed (for KAT testing only).
    #[cfg(test)]
    pub fn new_deterministic(entropy: &[u8], nonce: &[u8]) -> Self {
        Self::instantiate(entropy, nonce, &[])
    }

    /// SP 800-90A §10.1.2.2 HMAC_DRBG_Update. `provided` is the concatenation
    /// of the given slices (all empty = no provided data).
    fn update(&mut self, provided: &[&[u8]]) {
        let has_data = provided.iter().any(|p| !p.is_empty());
        let v0 = Zeroizing::new(*self.value);
        let mut parts: Vec<&[u8]> = Vec::with_capacity(provided.len() + 2);
        parts.push(&v0[..]);
        parts.push(&[0x00]);
        parts.extend_from_slice(provided);
        self.key = hmac(&self.key, &parts);
        self.value = hmac(&self.key, &[&self.value[..]]);
        if has_data {
            let v1 = Zeroizing::new(*self.value);
            parts[0] = &v1[..];
            parts[1] = &[0x01];
            self.key = hmac(&self.key, &parts);
            self.value = hmac(&self.key, &[&self.value[..]]);
        }
    }

    /// Reseed from the entropy source (SP 800-90A §10.1.2.4).
    pub fn reseed(&mut self) -> HsmResult<()> {
        self.reseed_with_additional_input(&[])
    }

    /// Reseed from the entropy source with additional input (used by
    /// `C_SeedRandom`).
    pub fn reseed_with_additional_input(&mut self, additional_input: &[u8]) -> HsmResult<()> {
        let mut entropy = Zeroizing::new([0u8; SECURITY_STRENGTH_BYTES]);
        entropy::get_entropy(&mut *entropy)?;
        self.reseed_with(&*entropy, additional_input);
        Ok(())
    }

    /// Reseed with caller-provided entropy input (KAT / testing).
    pub fn reseed_with(&mut self, entropy_input: &[u8], additional_input: &[u8]) {
        self.update(&[entropy_input, additional_input]);
        self.reseed_counter = 1;
    }

    /// Reseed with deterministic entropy (for testing).
    #[cfg(test)]
    pub fn reseed_deterministic(&mut self, entropy: &[u8]) {
        self.reseed_with(entropy, &[]);
    }

    /// Generate random bytes (no additional input).
    pub fn generate(&mut self, out: &mut [u8]) -> HsmResult<()> {
        self.generate_with_additional_input(out, &[])
    }

    /// SP 800-90A §10.1.2.5 Generate.
    ///
    /// Requests larger than [`MAX_BYTES_PER_REQUEST`] are rejected; use
    /// [`fill_random`] for arbitrary lengths.
    pub fn generate_with_additional_input(
        &mut self,
        out: &mut [u8],
        additional_input: &[u8],
    ) -> HsmResult<()> {
        if out.len() > MAX_BYTES_PER_REQUEST {
            return Err(HsmError::DataLenRange);
        }
        let mut additional_input = additional_input;
        if !self.deterministic
            && (self.prediction_resistance || self.reseed_counter > RESEED_INTERVAL)
        {
            // SP 800-90A §9.3.1: the reseed consumes the additional input.
            self.reseed_with_additional_input(additional_input)?;
            additional_input = &[];
        } else if self.deterministic && self.reseed_counter > RESEED_INTERVAL {
            return Err(HsmError::GeneralError);
        }
        if !additional_input.is_empty() {
            self.update(&[additional_input]);
        }

        let mut pos = 0;
        while pos < out.len() {
            self.value = hmac(&self.key, &[&self.value[..]]);
            // Continuous test on the output blocks of this long-lived
            // instance: two identical consecutive blocks indicate a stuck
            // generator. The failure is latched module-wide.
            if self.has_output && *self.value == *self.last_output {
                out.zeroize();
                crate::crypto::self_test::enter_error_state("DRBG continuous output test failed");
                return Err(HsmError::GeneralError);
            }
            self.last_output.copy_from_slice(&self.value[..]);
            self.has_output = true;
            let n = (out.len() - pos).min(32);
            out[pos..pos + n].copy_from_slice(&self.value[..n]);
            pos += n;
        }
        self.update(&[additional_input]);
        self.reseed_counter += 1;
        Ok(())
    }
}

// ============================================================================
// Module-wide RBG
// ============================================================================

static GLOBAL_DRBG: parking_lot::Mutex<Option<(u32, HmacDrbg)>> = parking_lot::Mutex::new(None);

fn with_global<R>(f: impl FnOnce(&mut HmacDrbg) -> HsmResult<R>) -> HsmResult<R> {
    if crate::crypto::self_test::is_error_state() {
        return Err(HsmError::GeneralError);
    }
    let mut guard = GLOBAL_DRBG.lock();
    let pid = current_pid();
    let stale = match guard.as_ref() {
        Some((owner, _)) => *owner != pid,
        None => true,
    };
    if stale {
        // First use, or we are a forked child: never continue the parent's
        // state (it would repeat the parent's output stream).
        *guard = Some((pid, HmacDrbg::new()?));
    }
    let (_, drbg) = guard.as_mut().expect("initialized above");
    f(drbg)
}

/// Fill `out` from the module-wide SP 800-90A DRBG, splitting the request
/// into chunks of at most [`MAX_BYTES_PER_REQUEST`].
pub fn fill_random(out: &mut [u8]) -> HsmResult<()> {
    let result = with_global(|drbg| {
        for chunk in out.chunks_mut(MAX_BYTES_PER_REQUEST) {
            drbg.generate(chunk)?;
        }
        Ok(())
    });
    if result.is_err() {
        out.zeroize();
    }
    result
}

/// Mix caller-supplied seed material into the module-wide DRBG
/// (`C_SeedRandom`): reseeds from the entropy source with the seed as
/// additional input. Caller input never replaces the entropy input.
pub fn seed_random(additional_input: &[u8]) -> HsmResult<()> {
    with_global(|drbg| drbg.reseed_with_additional_input(additional_input))
}

/// Drop the module-wide DRBG state (it is re-instantiated on next use).
pub fn reset_global_drbg() {
    *GLOBAL_DRBG.lock() = None;
}

// ============================================================================
// Known-answer health test (SP 800-90A §11.3)
// ============================================================================

/// NIST CAVP HMAC_DRBG, SHA-256, PredictionResistance = False,
/// EntropyInputLen = 256, NonceLen = 128, PersonalizationStringLen = 0,
/// AdditionalInputLen = 0, ReturnedBitsLen = 1024, COUNT = 0.
/// Procedure: instantiate, generate (discarded), generate (returned).
const KAT_ENTROPY: [u8; 32] = [
    0xca, 0x85, 0x19, 0x11, 0x34, 0x93, 0x84, 0xbf, 0xfe, 0x89, 0xde, 0x1c, 0xbd, 0xc4, 0x6e, 0x68,
    0x31, 0xe4, 0x4d, 0x34, 0xa4, 0xfb, 0x93, 0x5e, 0xe2, 0x85, 0xdd, 0x14, 0xb7, 0x1a, 0x74, 0x88,
];
const KAT_NONCE: [u8; 16] = [
    0x65, 0x9b, 0xa9, 0x6c, 0x60, 0x1d, 0xc6, 0x9f, 0xc9, 0x02, 0x94, 0x08, 0x05, 0xec, 0x0c, 0xa8,
];
const KAT_RETURNED: [u8; 128] = [
    0xe5, 0x28, 0xe9, 0xab, 0xf2, 0xde, 0xce, 0x54, 0xd4, 0x7c, 0x7e, 0x75, 0xe5, 0xfe, 0x30, 0x21,
    0x49, 0xf8, 0x17, 0xea, 0x9f, 0xb4, 0xbe, 0xe6, 0xf4, 0x19, 0x96, 0x97, 0xd0, 0x4d, 0x5b, 0x89,
    0xd5, 0x4f, 0xbb, 0x97, 0x8a, 0x15, 0xb5, 0xc4, 0x43, 0xc9, 0xec, 0x21, 0x03, 0x6d, 0x24, 0x60,
    0xb6, 0xf7, 0x3e, 0xba, 0xd0, 0xdc, 0x2a, 0xba, 0x6e, 0x62, 0x4a, 0xbf, 0x07, 0x74, 0x5b, 0xc1,
    0x07, 0x69, 0x4b, 0xb7, 0x54, 0x7b, 0xb0, 0x99, 0x5f, 0x70, 0xde, 0x25, 0xd6, 0xb2, 0x9e, 0x2d,
    0x30, 0x11, 0xbb, 0x19, 0xd2, 0x76, 0x76, 0xc0, 0x71, 0x62, 0xc8, 0xb5, 0xcc, 0xde, 0x06, 0x68,
    0x96, 0x1d, 0xf8, 0x68, 0x03, 0x48, 0x2c, 0xb3, 0x7e, 0xd6, 0xd5, 0xc0, 0xbb, 0x8d, 0x50, 0xcf,
    0x1f, 0x50, 0xd4, 0x76, 0xaa, 0x04, 0x58, 0xbd, 0xab, 0xa8, 0x06, 0xf4, 0x8b, 0xe9, 0xdc, 0xb8,
];

/// Reseed KAT: continues the CAVP instance above with a fixed reseed entropy
/// input and additional input, then generates 32 bytes. Expected value
/// computed with an independent Python implementation of SP 800-90A §10.1.2
/// that reproduces the CAVP vector above.
const KAT_RESEED_ENTROPY: [u8; 32] = [0x5a; 32];
const KAT_RESEED_ADDITIONAL: &[u8] = b"CratonHSM DRBG reseed KAT";
const KAT_AFTER_RESEED: [u8; 32] = [
    0x52, 0xb8, 0x4d, 0xca, 0x67, 0x36, 0xf0, 0xa5, 0xd4, 0x0a, 0x49, 0xa8, 0x79, 0x9a, 0x89, 0x88,
    0x81, 0x47, 0xec, 0xe6, 0xa8, 0xf8, 0x2e, 0x08, 0x67, 0x97, 0xab, 0xac, 0x9e, 0xc7, 0xc2, 0xb9,
];

/// SP 800-90A §11.3 health test: instantiate, generate and reseed functions
/// checked against known answers. Returns `Err` on mismatch.
pub fn drbg_kat() -> HsmResult<()> {
    use subtle::ConstantTimeEq;
    let mut drbg = HmacDrbg::instantiate(&KAT_ENTROPY, &KAT_NONCE, &[]);
    let mut out = Zeroizing::new([0u8; 128]);
    drbg.generate(&mut *out)?;
    drbg.generate(&mut *out)?;
    if !bool::from(out.ct_eq(&KAT_RETURNED)) {
        tracing::error!("DRBG KAT (instantiate/generate) failed");
        return Err(HsmError::GeneralError);
    }
    drbg.reseed_with(&KAT_RESEED_ENTROPY, KAT_RESEED_ADDITIONAL);
    let mut out2 = Zeroizing::new([0u8; 32]);
    drbg.generate(&mut *out2)?;
    if !bool::from(out2.ct_eq(&KAT_AFTER_RESEED)) {
        tracing::error!("DRBG KAT (reseed/generate) failed");
        return Err(HsmError::GeneralError);
    }
    Ok(())
}

// ============================================================================
// rand_core 0.6 adapter
// ============================================================================

/// RNG adapter implementing `rand::CryptoRng + rand::RngCore` over the
/// module-wide DRBG ([`fill_random`]). Cheap to construct.
///
/// All code paths that need randomness MUST use `DrbgRng` (or
/// [`fill_random`]) instead of `OsRng` directly.
pub struct DrbgRng {
    _private: (),
}

impl DrbgRng {
    pub fn new() -> HsmResult<Self> {
        if crate::crypto::self_test::is_error_state() {
            return Err(HsmError::GeneralError);
        }
        Ok(Self { _private: () })
    }
}

impl rand::RngCore for DrbgRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Err(e) = fill_random(dest) {
            // DRBG / entropy failure: the error state is already latched.
            // `fill_bytes` cannot report errors, and continuing with
            // non-random output would silently produce weak keys or
            // signatures, so the process is aborted (a panic could be caught
            // by `catch_unwind`, and unwinding across the FFI boundary is UB).
            dest.fill(0);
            tracing::error!("DRBG catastrophic failure in fill_bytes: {:?} — aborting", e);
            std::process::abort();
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        fill_random(dest).map_err(|_| rand::Error::new("DRBG generate failed"))
    }
}

impl rand::CryptoRng for DrbgRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drbg_basic() {
        let mut drbg = HmacDrbg::new().unwrap();
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        drbg.generate(&mut buf1).unwrap();
        drbg.generate(&mut buf2).unwrap();
        assert_ne!(buf1, buf2, "Consecutive DRBG outputs should differ");
        assert_ne!(buf1, [0u8; 32], "DRBG output should not be all zeros");
    }

    #[test]
    fn test_drbg_various_lengths() {
        let mut drbg = HmacDrbg::new().unwrap();
        for &len in &[1, 16, 32, 48, 64, 100, 256] {
            let mut buf = vec![0u8; len];
            drbg.generate(&mut buf).unwrap();
            assert_ne!(buf, vec![0u8; len]);
        }
    }

    #[test]
    fn test_drbg_reseed() {
        let mut drbg = HmacDrbg::new().unwrap();
        let mut buf1 = [0u8; 32];
        drbg.generate(&mut buf1).unwrap();
        drbg.reseed().unwrap();
        let mut buf2 = [0u8; 32];
        drbg.generate(&mut buf2).unwrap();
        assert_ne!(buf1, buf2, "Output after reseed should differ");
    }

    #[test]
    fn test_drbg_cavp_kat() {
        drbg_kat().expect("SP 800-90A CAVP KAT");
    }

    #[test]
    fn test_drbg_deterministic_matches() {
        let mut a = HmacDrbg::new_deterministic(&[0x42; 32], &[0x13; 16]);
        let mut b = HmacDrbg::new_deterministic(&[0x42; 32], &[0x13; 16]);
        let (mut x, mut y) = ([0u8; 64], [0u8; 64]);
        a.generate(&mut x).unwrap();
        b.generate(&mut y).unwrap();
        assert_eq!(x, y);
        a.reseed_deterministic(&[1u8; 32]);
        a.generate(&mut x).unwrap();
        assert_ne!(x, y);
    }

    #[test]
    fn test_request_limit() {
        let mut drbg = HmacDrbg::new().unwrap();
        let mut big = vec![0u8; MAX_BYTES_PER_REQUEST + 1];
        assert!(drbg.generate(&mut big).is_err());
        // The module-wide RBG chunks large requests.
        fill_random(&mut big).unwrap();
    }

    #[test]
    fn test_entropy_health_tests_detect_stuck_source() {
        assert!(!entropy::health_test_samples(&[0x55; 16]));
        // A source that alternates between two values fails the APT.
        let two: Vec<u8> = (0..512).map(|i| if i % 2 == 0 { 1 } else { 2 }).collect();
        assert!(!entropy::health_test_samples(&two));
        let mut good = vec![0u8; 4096];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut good);
        assert!(entropy::health_test_samples(&good));
    }
}
