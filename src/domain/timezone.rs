//! Canonical IANA time-zone identifier validation.

use std::str::FromStr as _;

/// Maximum persisted IANA time-zone identifier length.
pub const MAX_IDENTIFIER_BYTES: usize = 255;

/// Returns whether `value` is an exact identifier in the bundled IANA TZDB.
///
/// Whitespace is significant: accepting a trimmed spelling would make the API
/// response differ from the identifier submitted by the caller.
#[must_use]
pub fn is_valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value == value.trim()
        && chrono_tz::Tz::from_str(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_real_tzdb_identifiers() {
        assert!(is_valid_identifier("UTC"));
        assert!(is_valid_identifier("Asia/Kolkata"));
        assert!(is_valid_identifier("America/New_York"));
    }

    #[test]
    fn rejects_unknown_or_noncanonical_input() {
        assert!(!is_valid_identifier("Europe/Definitely_Not_A_Zone"));
        assert!(!is_valid_identifier(" Asia/Kolkata"));
        assert!(!is_valid_identifier(""));
    }
}
