use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::error::ApiError;

#[derive(Clone, Copy, Deserialize, Serialize)]
pub(super) struct Cursor {
    pub(super) at: OffsetDateTime,
    pub(super) id: Uuid,
}

pub(super) fn decode(value: Option<&str>) -> Result<Option<Cursor>, ApiError> {
    value
        .map(|value| {
            let bytes = URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| ApiError::validation("cursor", "is invalid"))?;
            if bytes.len() > 256 {
                return Err(ApiError::validation("cursor", "is invalid"));
            }
            serde_json::from_slice(&bytes).map_err(|_| ApiError::validation("cursor", "is invalid"))
        })
        .transpose()
}

pub(super) fn encode(at: OffsetDateTime, id: Uuid) -> Result<String, ApiError> {
    let bytes =
        serde_json::to_vec(&Cursor { at, id }).map_err(|_| ApiError::internal("cursor_encode"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) fn limit(value: Option<u16>) -> i64 {
    i64::from(value.unwrap_or(50).clamp(1, 100))
}
