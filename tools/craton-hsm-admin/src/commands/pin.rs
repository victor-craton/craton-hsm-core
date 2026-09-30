// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use super::Ctx;
use crate::admin_core::{open_core, prompt_new_pin, Role};
use crate::error::{CliError, CliResult};
use craton_hsm::config::HsmConfig;
use craton_hsm::token::pin_policy;

/// Absolute minimum PIN length (also the core configuration floor, H5-12).
pub const PIN_MIN_FLOOR: usize = 8;

/// Full policy for a new SO or User PIN — exactly the rules the core applies
/// to C_InitToken / C_InitPIN / C_SetPIN
/// ([`craton_hsm::token::pin_policy`]), checked up front so the operator gets
/// a precise message before any authentication attempt is consumed.
pub fn validate_new_pin(pin: &str, config: &HsmConfig) -> Result<(), String> {
    let min = config.security.pin_min_length.max(PIN_MIN_FLOOR);
    let max = config.security.pin_max_length;
    if pin.len() < min || pin.len() > max {
        return Err(format!(
            "PIN must be at least {min} and at most {max} bytes long."
        ));
    }
    pin_policy::check_complexity(pin.as_bytes()).map_err(|reason| format!("{reason}."))
}

/// Change the User or SO PIN (the role authenticates with its current PIN;
/// `C_SetPIN` through the core, audited with the invoking OS user).
pub fn change(ctx: &Ctx, role: Role) -> CliResult {
    let cfg = ctx.load_config()?;
    let core = open_core(&cfg)?;
    core.require_persistent("pin change")?;
    core.require_audit_intact()?;

    let (session, old_pin) = core.login_with_pin(role)?;
    let new_pin = prompt_new_pin(&cfg, role.name())?;
    core.hsm()
        .set_pin_by(
            session.session(),
            old_pin.as_bytes(),
            new_pin.as_bytes(),
            Some(&core.actor(&format!("pin-change:{}", role.name()))),
        )
        .map_err(|e| CliError::Auth(format!("PIN change failed: {e}")))?;
    drop(session);

    println!("{} PIN changed successfully.", role.name());
    Ok(())
}

/// Reset the User PIN (requires SO authentication; `C_InitPIN`, which also
/// clears a User PIN lockout).
pub fn reset(ctx: &Ctx) -> CliResult {
    let cfg = ctx.load_config()?;
    let core = open_core(&cfg)?;
    core.require_persistent("pin reset")?;
    core.require_audit_intact()?;

    let session = core.login(Role::So)?;
    let new_pin = prompt_new_pin(&cfg, "User")?;
    core.hsm()
        .init_pin_by(
            session.session(),
            new_pin.as_bytes(),
            Some(&core.actor("pin-reset")),
        )
        .map_err(|e| CliError::General(format!("PIN reset failed: {e}")))?;
    drop(session);

    println!("User PIN reset successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_weak_pins() {
        for weak in [
            "aaaaaaaa",
            "12345678",
            "87654321",
            "abcdefgh",
            "12121212",
            "abababab",
            "abcabcabc",
            "11111112",
            "password",
            "Password",
            "MyPassword99",
            "qwertyui",
            "1q2w3e4r",
            "aabbaabb",
        ] {
            assert!(
                validate_new_pin(weak, &HsmConfig::default()).is_err(),
                "{weak} accepted"
            );
        }
    }

    #[test]
    fn accepts_reasonable_pins() {
        for ok in [
            "7391-2846",
            "Tr0ub4dor&3",
            "correct horse battery",
            "59g!Kx2q",
        ] {
            assert!(
                validate_new_pin(ok, &HsmConfig::default()).is_ok(),
                "{ok} rejected"
            );
        }
    }

    #[test]
    fn length_floor_applies_even_if_config_is_lower() {
        let mut cfg = HsmConfig::default();
        cfg.security.pin_min_length = 4;
        assert!(validate_new_pin("7k2!", &cfg).is_err());
        assert!(validate_new_pin("7k2!9x5q", &cfg).is_ok());
        cfg.security.pin_max_length = 8;
        assert!(validate_new_pin("7k2!9x5qz", &cfg).is_err());
    }
}
