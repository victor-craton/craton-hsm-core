// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // (H4-19) Messages carrying PINs get a hand-written, redacting `Debug`
    // implementation (see `src/main.rs`) so that a future `?req` log line can
    // never print PIN material.
    tonic_prost_build::configure()
        .skip_debug([
            "craton_hsm.LoginRequest",
            "craton_hsm.InitTokenRequest",
            "craton_hsm.InitPinRequest",
        ])
        .compile_protos(&["proto/craton_hsm.proto"], &["proto"])?;
    Ok(())
}
