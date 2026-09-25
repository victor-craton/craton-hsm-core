// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use super::Ctx;
use crate::admin_core::{open_core, prompt_new_pin, Role};
use crate::error::{CliError, CliResult};
use craton_hsm::audit::log::AuditOperation;
use craton_hsm::config::HsmConfig;

/// Absolute minimum PIN length enforced by the admin CLI, regardless of a
/// lower `pin_min_length` in the config (H5-12).
pub const PIN_MIN_FLOOR: usize = 8;
/// Minimum number of distinct characters in a new PIN.
const MIN_DISTINCT_CHARS: usize = 4;

/// Common PINs/passwords that are rejected outright (compared lowercase).
const DENYLIST: &[&str] = &[
    "00000000",
    "11111111",
    "12341234",
    "12344321",
    "11223344",
    "12121212",
    "123123123",
    "12345678",
    "123456789",
    "1234567890",
    "87654321",
    "98765432",
    "01234567",
    "1q2w3e4r",
    "1qaz2wsx",
    "zaq12wsx",
    "qwertyui",
    "qwertyuiop",
    "qwerty12",
    "qwerty123",
    "asdfghjk",
    "asdfasdf",
    "zxcvbnm1",
    "abcd1234",
    "abc12345",
    "abcdefgh",
    "password",
    "password1",
    "passw0rd",
    "p@ssw0rd",
    "p@ssword",
    "letmein1",
    "iloveyou",
    "admin123",
    "administrator",
    "changeme",
    "changeit",
    "welcome1",
    "trustno1",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "superman",
    "monkey12",
    "security",
    "secret12",
    "default1",
    "test1234",
    "testtest",
    "cratonhsm",
    "hsmadmin",
    "sopin123",
    "userpin1",
    "pkcs11pin",
];

/// Validate the complexity of a new PIN (length is checked separately).
///
/// HANDOFF: this policy belongs in the core (`Token::validate_pin`) so that
/// the PKCS#11 ABI and the daemon enforce the same rules.
pub fn validate_pin_complexity(pin: &str) -> Result<(), &'static str> {
    let chars: Vec<char> = pin.chars().collect();
    let n = chars.len();

    // A short unit repeated, e.g. "aaaaaaaa", "12121212", "abcabcabc".
    if n > 1
        && (1..=n / 2).any(|unit| {
            n.checked_rem(unit) == Some(0) && chars.chunks(unit).all(|c| c == &chars[..unit])
        })
    {
        return Err("PIN must not be a repeated character or pattern (e.g. 12121212).");
    }

    // Strictly ascending / descending sequences, e.g. "12345678", "hgfedcba".
    if n >= 4 {
        let asc = chars
            .windows(2)
            .all(|w| (w[1] as u32) == (w[0] as u32).wrapping_add(1));
        let desc = chars
            .windows(2)
            .all(|w| (w[0] as u32) == (w[1] as u32).wrapping_add(1));
        if asc || desc {
            return Err("PIN must not be a sequential pattern (e.g. 12345678).");
        }
    }

    let mut distinct = chars.clone();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < MIN_DISTINCT_CHARS {
        return Err("PIN must contain at least 4 distinct characters.");
    }

    let lower = pin.to_lowercase();
    if DENYLIST.contains(&lower.as_str()) || lower.contains("password") {
        return Err("PIN is a commonly used value; choose a less guessable PIN.");
    }

    Ok(())
}

/// Full policy for a new SO or User PIN: configured length bounds (with a
/// CLI floor of [`PIN_MIN_FLOOR`]) plus [`validate_pin_complexity`].
pub fn validate_new_pin(pin: &str, config: &HsmConfig) -> Result<(), String> {
    let min = config.security.pin_min_length.max(PIN_MIN_FLOOR);
    let max = config.security.pin_max_length;
    if pin.chars().count() < min || pin.len() > max {
        return Err(format!(
            "PIN must be at least {min} characters and at most {max} bytes long."
        ));
    }
    validate_pin_complexity(pin).map_err(str::to_string)
}

/// Change the User or SO PIN (the role authenticates with its current PIN).
pub fn change(ctx: &Ctx, role: Role) -> CliResult {
    let cfg = ctx.load_config()?;
    let core = open_core(&cfg)?;
    core.require_persistent("pin change")?;
    core.require_audit_intact()?;

    let (session, old_pin) = core.login_with_pin(role)?;
    let new_pin = prompt_new_pin(&cfg, role.name())?;

    let res = session
        .token()
        .set_pin(old_pin.as_bytes(), new_pin.as_bytes());
    core.record(
        AuditOperation::Login {
            user_type: u64::from(role.ck_user()),
        },
        res.as_ref().map(|_| ()),
        &format!("pin-change:{}", role.name()),
    )?;
    res.map_err(|e| CliError::Auth(format!("PIN change failed: {e}")))?;
    drop(session);

    println!("{} PIN changed successfully.", role.name());
    Ok(())
}

/// Reset the User PIN (requires SO authentication).
pub fn reset(ctx: &Ctx) -> CliResult {
    let cfg = ctx.load_config()?;
    let core = open_core(&cfg)?;
    core.require_persistent("pin reset")?;
    core.require_audit_intact()?;

    let session = core.login(Role::So)?;
    let new_pin = prompt_new_pin(&cfg, "User")?;
    let res = session.token().init_pin(new_pin.as_bytes());
    core.record(
        AuditOperation::Login {
            user_type: u64::from(Role::So.ck_user()),
        },
        res.as_ref().map(|_| ()),
        "pin-reset",
    )?;
    res.map_err(|e| CliError::General(format!("PIN reset failed: {e}")))?;
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
            assert!(validate_pin_complexity(weak).is_err(), "{weak} accepted");
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
            assert!(validate_pin_complexity(ok).is_ok(), "{ok} rejected");
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
