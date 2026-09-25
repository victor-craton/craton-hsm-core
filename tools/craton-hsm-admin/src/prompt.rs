// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Interactive prompts: secrets (no echo) and typed confirmations.

use crate::error::{CliError, CliResult};
use std::io::{BufRead, Write};
use zeroize::Zeroizing;

/// Maximum length of a confirmation answer read from stdin.
const MAX_CONFIRM_LEN: u64 = 256;

/// Read a secret from the terminal without echo. Secrets are never accepted
/// from argv or the environment.
pub fn read_secret(prompt: &str) -> CliResult<Zeroizing<String>> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|e| CliError::Io(format!("Cannot read secret from terminal: {e}")))
}

/// Require the operator to type `phrase` to proceed with a destructive or
/// sensitive operation. `--yes` skips the prompt (for automation); the
/// operator must still authenticate.
pub fn confirm_typed(description: &str, phrase: &str, yes: bool) -> CliResult {
    if yes {
        eprintln!("{description}\nConfirmation skipped (--yes).");
        return Ok(());
    }
    eprint!("{description}\nType '{phrase}' to continue: ");
    std::io::stderr().flush().ok();
    let answer = read_line_bounded(&mut std::io::stdin().lock())?;
    check_answer(&answer, phrase)
}

fn check_answer(answer: &str, phrase: &str) -> CliResult {
    if answer.trim_end_matches(['\r', '\n']) == phrase {
        Ok(())
    } else {
        Err(CliError::Aborted)
    }
}

fn read_line_bounded(input: &mut impl BufRead) -> CliResult<String> {
    let mut buf = Vec::new();
    std::io::Read::take(&mut *input, MAX_CONFIRM_LEN)
        .read_until(b'\n', &mut buf)
        .map_err(|e| CliError::Io(format!("Cannot read confirmation: {e}")))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_confirmation_requires_exact_phrase() {
        assert!(check_answer("restore\n", "restore").is_ok());
        assert!(check_answer("restore\r\n", "restore").is_ok());
        assert!(matches!(
            check_answer("y\n", "restore"),
            Err(CliError::Aborted)
        ));
        assert!(matches!(
            check_answer("", "restore"),
            Err(CliError::Aborted)
        ));
        assert!(matches!(
            check_answer("Restore\n", "restore"),
            Err(CliError::Aborted)
        ));
    }

    #[test]
    fn confirmation_read_is_bounded() {
        let long = vec![b'a'; 10_000];
        let mut cur = std::io::Cursor::new(long);
        let s = read_line_bounded(&mut cur).unwrap();
        assert_eq!(s.len() as u64, MAX_CONFIRM_LEN);
    }
}
