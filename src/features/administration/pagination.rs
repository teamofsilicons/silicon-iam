//! Opaque keyset cursor codec shared by administration listings.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AppError;

use super::model::PageInfo;

const DEFAULT_LIMIT: u16 = 50;
const MAX_LIMIT: u16 = 100;
const MAX_CURSOR_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct Cursor {
    pub(super) at: OffsetDateTime,
    pub(super) id: Uuid,
}

pub(super) fn limit(value: Option<u16>) -> Result<i64, AppError> {
    let value = value.unwrap_or(DEFAULT_LIMIT);
    if value == 0 || value > MAX_LIMIT {
        return Err(validation("limit", "must be between 1 and 100"));
    }
    Ok(i64::from(value))
}

pub(super) fn decode(value: Option<&str>) -> Result<Option<Cursor>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() || value.len() > MAX_CURSOR_BYTES {
        return Err(validation("cursor", "is invalid"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| validation("cursor", "is invalid"))?;
    let cursor = serde_json::from_slice::<Cursor>(&decoded)
        .map_err(|_| validation("cursor", "is invalid"))?;
    Ok(Some(cursor))
}

pub(super) fn page<T>(
    items: &mut Vec<T>,
    requested_limit: i64,
    last_key: impl FnOnce(&T) -> Cursor,
) -> Result<PageInfo, AppError> {
    let has_more = i64::try_from(items.len()).unwrap_or(i64::MAX) > requested_limit;
    if has_more {
        items.pop();
    }
    let next_cursor = if has_more {
        items
            .last()
            .map(last_key)
            .map(|cursor| {
                serde_json::to_vec(&cursor)
                    .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
                    .map_err(|_| AppError::Internal {
                        category: "administration_cursor_encode",
                    })
            })
            .transpose()?
    } else {
        None
    };
    Ok(PageInfo {
        next_cursor,
        has_more,
    })
}

fn validation(field: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        details: serde_json::json!({ "field": field, "message": message }),
    }
}
