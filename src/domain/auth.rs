//! Authentication domain types and normalization policy.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Failed OTP verifications permitted before a challenge enters cooldown.
pub const OTP_MAX_FAILED_ATTEMPTS: u16 = 10;

/// Mandatory cooldown after one exhausted OTP verification window.
pub const OTP_COOLDOWN_SECONDS: i64 = 60;

/// Normalized immutable Carbon handle.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct CarbonId(String);

/// Carbon-ID validation failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CarbonIdError {
    /// Identifier has an invalid length.
    #[error("carbon_id must be between 3 and 30 ASCII characters")]
    Length,
    /// Identifier contains an unsupported character.
    #[error("carbon_id may contain only lowercase letters, digits 1-9, hyphens, and underscores")]
    Characters,
}

impl CarbonId {
    /// Returns the normalized handle.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parses an identifier used to look up an already-persisted Carbon.
    ///
    /// Carbon IDs containing `0` were valid before the creation alphabet was
    /// narrowed to `1-9`. They remain immutable and addressable, but this
    /// compatibility parser must never be used to admit a new identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CarbonIdError`] when the value is not a normalized legacy or
    /// current Carbon identifier.
    pub fn from_lookup_str(value: &str) -> Result<Self, CarbonIdError> {
        Self::parse(value, true)
    }

    fn parse(value: &str, allow_legacy_zero: bool) -> Result<Self, CarbonIdError> {
        if value != value.trim() {
            return Err(CarbonIdError::Characters);
        }
        let normalized = value.to_ascii_lowercase();
        if !(3..=30).contains(&normalized.len()) {
            return Err(CarbonIdError::Length);
        }

        if !normalized.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || matches!(byte, b'1'..=b'9' | b'-' | b'_')
                || (allow_legacy_zero && byte == b'0')
        }) {
            return Err(CarbonIdError::Characters);
        }

        Ok(Self(normalized))
    }
}

impl TryFrom<String> for CarbonId {
    type Error = CarbonIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<CarbonId> for String {
    fn from(value: CarbonId) -> Self {
        value.0
    }
}

impl FromStr for CarbonId {
    type Err = CarbonIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value, false)
    }
}

impl fmt::Display for CarbonId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Normalizes an email address for exact identity lookup.
///
/// The domain is lowercased and surrounding whitespace is removed. The local
/// part is lowercased because IAM treats email identities as case-insensitive;
/// the original presentation value is retained encrypted separately.
#[must_use]
pub fn normalize_email(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::{
        CarbonId, CarbonIdError, OTP_COOLDOWN_SECONDS, OTP_MAX_FAILED_ATTEMPTS, normalize_email,
    };

    #[test]
    fn otp_policy_matches_the_public_contract() {
        assert_eq!(OTP_MAX_FAILED_ATTEMPTS, 10);
        assert_eq!(OTP_COOLDOWN_SECONDS, 60);
    }

    #[test]
    fn carbon_id_is_normalized() {
        let carbon_id = CarbonId::from_str("Saket_213");
        assert_eq!(
            carbon_id.map(|value| value.to_string()),
            Ok("saket_213".to_owned())
        );
    }

    #[test]
    fn carbon_id_rejects_zero() {
        assert_eq!(CarbonId::from_str("saket0"), Err(CarbonIdError::Characters));
    }

    #[test]
    fn existing_carbon_id_lookup_accepts_legacy_zero() {
        assert_eq!(
            CarbonId::from_lookup_str("Saket_0").map(|value| value.to_string()),
            Ok("saket_0".to_owned())
        );
    }

    #[test]
    fn carbon_id_rejects_unicode_and_symbols() {
        assert_eq!(CarbonId::from_str("sakét"), Err(CarbonIdError::Characters));
        assert_eq!(CarbonId::from_str("saket!"), Err(CarbonIdError::Characters));
        assert_eq!(CarbonId::from_str(" saket"), Err(CarbonIdError::Characters));
    }

    #[test]
    fn email_lookup_is_case_insensitive() {
        assert_eq!(normalize_email(" User@Example.COM "), "user@example.com");
    }
}
