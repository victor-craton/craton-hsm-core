// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Output formatting helpers for the admin CLI.

use std::fmt;

/// Print a key-value table to stdout.
pub fn print_table(rows: &[(&str, String)]) {
    let max_key = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (key, value) in rows {
        println!(
            "  {:<width$}  {}",
            key,
            escape_display(value),
            width = max_key
        );
    }
}

/// Neutralise a string for terminal output (H5-15).
///
/// Control characters (including ESC, CR, LF, DEL and C1 controls) and
/// Unicode bidirectional-override / zero-width formatting characters are
/// replaced by visible `\u{..}` escapes so that data taken from objects,
/// backups or the audit log cannot rewrite the terminal or disguise the
/// identity of an object in a confirmation prompt.
pub fn escape_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() || is_invisible_format_char(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

fn is_invisible_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Decode a PKCS#11 label for display: lossy UTF-8, trailing padding
/// removed, and escaped with [`escape_display`].
pub fn display_label(raw: &[u8]) -> String {
    escape_display(String::from_utf8_lossy(raw).trim_end_matches([' ', '\0']))
}

/// Format CK_OBJECT_CLASS as human-readable string.
pub fn object_class_name(class: u64) -> &'static str {
    match class {
        0 => "Data",
        1 => "Certificate",
        2 => "PublicKey",
        3 => "PrivateKey",
        4 => "SecretKey",
        _ => "Unknown",
    }
}

/// Format CK_KEY_TYPE as human-readable string.
pub fn key_type_name(kt: u64) -> &'static str {
    match kt {
        0x00 => "RSA",
        0x03 => "EC",
        0x1F => "AES",
        0x04 => "GENERIC_SECRET",
        0x80000001 => "ED25519",
        0x80000010 => "ML-DSA",
        0x80000011 => "ML-KEM",
        0x80000012 => "SLH-DSA",
        _ => "Unknown",
    }
}

/// Simple columnar table printer for object listings.
pub struct ObjectTable {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl ObjectTable {
    pub fn new(headers: Vec<&str>) -> Self {
        Self {
            headers: headers.into_iter().map(String::from).collect(),
            rows: Vec::new(),
        }
    }

    /// Add a row. Every cell is escaped with [`escape_display`].
    pub fn add_row(&mut self, row: Vec<String>) {
        self.rows
            .push(row.iter().map(|c| escape_display(c)).collect());
    }
}

impl fmt::Display for ObjectTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.rows.is_empty() {
            return writeln!(f, "  (no entries)");
        }

        // Calculate column widths
        let col_count = self.headers.len();
        // Widths are measured in chars, not bytes, so that multi-byte
        // labels do not misalign the table.
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.chars().count()).collect();
        for row in &self.rows {
            for (width, cell) in widths.iter_mut().zip(row.iter()) {
                *width = (*width).max(cell.chars().count());
            }
        }

        // Print header
        for (i, (header, width)) in self.headers.iter().zip(widths.iter()).enumerate() {
            if i > 0 {
                write!(f, "  ")?;
            }
            write!(f, "{:<width$}", header, width = *width)?;
        }
        writeln!(f)?;

        // Print separator
        for (i, w) in widths.iter().enumerate() {
            if i > 0 {
                write!(f, "  ")?;
            }
            write!(f, "{}", "-".repeat(*w))?;
        }
        writeln!(f)?;

        // Print rows
        for row in &self.rows {
            for (i, (cell, width)) in row.iter().zip(widths.iter()).take(col_count).enumerate() {
                if i > 0 {
                    write!(f, "  ")?;
                }
                write!(f, "{:<width$}", cell, width = *width)?;
            }
            writeln!(f)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_display_neutralises_terminal_controls() {
        let s = escape_display("key\x1b[2J\r\nfake\u{202E}txt\x7f");
        assert!(!s.chars().any(|c| c.is_control()));
        assert!(!s.contains('\u{202E}'));
        assert!(s.contains("\\u{1b}"));
        assert_eq!(escape_display("plain label"), "plain label");
        assert_eq!(escape_display("ключ"), "ключ");
    }

    #[test]
    fn table_escapes_cells_and_aligns_by_chars() {
        let mut t = ObjectTable::new(vec!["A", "B"]);
        t.add_row(vec!["ключ".into(), "x\x1b".into()]);
        let out = t.to_string();
        assert!(!out.contains('\x1b'));
        assert!(out.contains("ключ"));
    }

    #[test]
    fn display_label_trims_padding() {
        assert_eq!(display_label(b"abc   "), "abc");
        assert_eq!(display_label(b"a\x1bb"), "a\\u{1b}b");
    }
}
