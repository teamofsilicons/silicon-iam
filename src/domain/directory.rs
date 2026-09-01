//! Validated immutable directory value objects.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Organization's immutable public handle.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct OrganizationId(String);

/// Silicon's organization-local immutable handle.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct SiliconLocalId(String);

/// Application's immutable public OAuth client handle.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ApplicationId(String);

/// Descriptive job role, which never conveys authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct JobRole(String);

/// Directory value validation failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DirectoryValueError {
    /// Value length is outside its database and API bound.
    #[error("directory value has an invalid length")]
    Length,
    /// Value contains a character outside its stable public alphabet.
    #[error("directory value contains an unsupported character")]
    Characters,
    /// Application handles must begin with an ASCII letter.
    #[error("application_id must begin with an ASCII letter")]
    FirstCharacter,
}

macro_rules! impl_handle {
    ($type:ty, $max:expr, $first_letter:expr) => {
        impl $type {
            /// Returns the normalized public handle.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $type {
            type Err = DirectoryValueError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                validate_handle(value, $max, $first_letter).map(Self)
            }
        }

        impl TryFrom<String> for $type {
            type Error = DirectoryValueError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                value.parse()
            }
        }

        impl From<$type> for String {
            fn from(value: $type) -> Self {
                value.0
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

impl_handle!(OrganizationId, 50, false);
impl_handle!(SiliconLocalId, 50, false);
impl_handle!(ApplicationId, 63, true);

impl JobRole {
    /// Maximum number of Unicode scalar values accepted by the directory.
    pub const MAX_CHARACTERS: usize = 5_000;

    /// Returns the descriptive role text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for JobRole {
    type Error = DirectoryValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.chars().count() > Self::MAX_CHARACTERS {
            return Err(DirectoryValueError::Length);
        }
        Ok(Self(value))
    }
}

impl From<JobRole> for String {
    fn from(value: JobRole) -> Self {
        value.0
    }
}

fn validate_handle(
    value: &str,
    max_length: usize,
    first_must_be_letter: bool,
) -> Result<String, DirectoryValueError> {
    if value != value.trim() {
        return Err(DirectoryValueError::Characters);
    }
    let normalized = value.to_ascii_lowercase();
    if !(3..=max_length).contains(&normalized.len()) {
        return Err(DirectoryValueError::Length);
    }
    if first_must_be_letter
        && !normalized
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_lowercase)
    {
        return Err(DirectoryValueError::FirstCharacter);
    }
    if !normalized.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
    }) {
        return Err(DirectoryValueError::Characters);
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::{ApplicationId, DirectoryValueError, OrganizationId};

    #[test]
    fn organization_handles_are_normalized_without_trimming() {
        assert_eq!(
            OrganizationId::from_str("Team_01").map(|value| value.to_string()),
            Ok("team_01".to_owned())
        );
        assert_eq!(
            OrganizationId::from_str(" team"),
            Err(DirectoryValueError::Characters)
        );
    }

    #[test]
    fn application_handle_starts_with_a_letter() {
        assert_eq!(
            ApplicationId::from_str("1app"),
            Err(DirectoryValueError::FirstCharacter)
        );
        assert!(ApplicationId::from_str("iam_app").is_ok());
    }
}
