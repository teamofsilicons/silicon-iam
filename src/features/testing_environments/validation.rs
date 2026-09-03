//! Input validation for the testing-environment control plane.

use serde_json::json;
use uuid::Uuid;

use crate::{error::AppError, infrastructure::crypto::TESTING_ENVIRONMENT_KEY_LENGTH};

use super::model::{EnvironmentCreate, EnvironmentPatch, PageQuery};

const MAX_NAME: usize = 64;
const MAX_DESCRIPTION: usize = 500;
const MAX_PAGE_LIMIT: u16 = 100;
const DEFAULT_PAGE_LIMIT: u16 = 25;

pub(super) fn field(field_name: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        details: json!({ "fields": [{ "field": field_name, "message": message }] }),
    }
}

pub(super) fn create(input: &mut EnvironmentCreate) -> Result<(), AppError> {
    input.name = name("name", &input.name)?;
    input.description = description(input.description.as_deref())?;
    Ok(())
}

pub(super) fn patch(input: &mut EnvironmentPatch) -> Result<(), AppError> {
    if input.name.is_none() && input.description.is_none() {
        return Err(field("name", "at least one field must be supplied"));
    }
    if let Some(value) = input.name.take() {
        input.name = Some(name("name", &value)?);
    }
    if let Some(value) = input.description.take() {
        input.description = Some(description(value.as_deref())?);
    }
    Ok(())
}

/// Validates the page window and the optional lifecycle filter.
///
/// Deleted environments are hidden by default. They remain listable for the
/// recovery window, but an operator scanning their environments should see
/// what is live unless they ask otherwise.
pub(super) fn page(query: &PageQuery) -> Result<(Option<Uuid>, i64, Option<String>), AppError> {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if limit == 0 || limit > MAX_PAGE_LIMIT {
        return Err(field("limit", "must be between 1 and 100"));
    }
    let status = match query.status.as_deref() {
        None | Some("active") => Some("active".to_owned()),
        Some("deleted") => Some("deleted".to_owned()),
        Some("all") => None,
        Some(_) => return Err(field("status", "must be active, deleted, or all")),
    };
    Ok((query.cursor, i64::from(limit), status))
}

/// Parses a presented environment key without revealing why it was rejected.
///
/// The alphabet and length are fixed by the product contract, so a value that
/// does not match cannot identify any environment and is refused before it
/// reaches a digest or the database.
pub(super) fn key_shape(value: &str) -> Option<&str> {
    (value.len() == TESTING_ENVIRONMENT_KEY_LENGTH
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric()))
    .then_some(value)
}

fn name(field_name: &'static str, value: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_NAME {
        return Err(field(field_name, "must contain 1 to 64 characters"));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(field(field_name, "must not contain control characters"));
    }
    Ok(trimmed.to_owned())
}

fn description(value: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > MAX_DESCRIPTION {
        return Err(field("description", "must contain at most 500 characters"));
    }
    if trimmed.chars().any(|character| {
        character.is_control() && character != '\n' && character != '\r' && character != '\t'
    }) {
        return Err(field("description", "must not contain control characters"));
    }
    Ok(Some(trimmed.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{
        super::model::{EnvironmentCreate, EnvironmentPatch, PageQuery},
        create, key_shape, page, patch,
    };

    #[test]
    fn names_are_trimmed_and_bounded() {
        let mut input = EnvironmentCreate {
            name: "  Staging replica  ".to_owned(),
            description: Some("   ".to_owned()),
        };
        assert!(create(&mut input).is_ok());
        assert_eq!(input.name, "Staging replica");
        assert_eq!(input.description, None);

        let mut empty = EnvironmentCreate {
            name: "   ".to_owned(),
            description: None,
        };
        assert!(create(&mut empty).is_err());

        let mut long = EnvironmentCreate {
            name: "n".repeat(65),
            description: None,
        };
        assert!(create(&mut long).is_err());
    }

    #[test]
    fn a_patch_must_change_something() {
        let mut nothing = EnvironmentPatch {
            name: None,
            description: None,
        };
        assert!(patch(&mut nothing).is_err());

        let mut clearing = EnvironmentPatch {
            name: None,
            description: Some(None),
        };
        assert!(patch(&mut clearing).is_ok());
    }

    #[test]
    fn only_the_exact_key_shape_is_admitted() {
        assert!(key_shape(&"a".repeat(32)).is_some());
        assert!(key_shape(&"a".repeat(31)).is_none());
        assert!(key_shape(&"a".repeat(33)).is_none());
        assert!(key_shape(&format!("{}-", "a".repeat(31))).is_none());
        assert!(key_shape("").is_none());
    }

    #[test]
    fn listing_hides_deleted_environments_unless_asked() {
        let Ok((_, limit, status)) = page(&PageQuery::default()) else {
            panic!("the default page window must be valid");
        };
        assert_eq!(limit, 25);
        assert_eq!(status.as_deref(), Some("active"));

        let Ok((_, _, all)) = page(&PageQuery {
            status: Some("all".to_owned()),
            ..PageQuery::default()
        }) else {
            panic!("`all` must be an accepted filter");
        };
        assert_eq!(all, None);

        assert!(
            page(&PageQuery {
                status: Some("archived".to_owned()),
                ..PageQuery::default()
            })
            .is_err()
        );
        assert!(
            page(&PageQuery {
                limit: Some(0),
                ..PageQuery::default()
            })
            .is_err()
        );
    }
}
