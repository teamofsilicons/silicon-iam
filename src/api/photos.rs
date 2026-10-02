//! Profile photos stored by IAM and served through immutable public URLs.
use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::id::Id,
    error::AppError,
};
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub(super) const MAX_PHOTO_BYTES: usize = 512 * 1024;
pub(super) const UPLOAD_ROUTE: &str = "PUT /api/v1/me/photo";

#[derive(Serialize)]
pub(super) struct PhotoUpload {
    content_type: String,
    sha256: String,
    #[serde(skip)]
    content: Bytes,
}
impl PhotoUpload {
    fn parse(headers: &HeaderMap, content: Bytes) -> Result<Self, AppError> {
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let valid = match content_type.as_str() {
            "image/png" => content.starts_with(b"\x89PNG\r\n\x1a\n"),
            "image/jpeg" => content.starts_with(&[0xff, 0xd8, 0xff]),
            "image/webp" => {
                content.len() >= 12 && content.starts_with(b"RIFF") && &content[8..12] == b"WEBP"
            }
            _ => false,
        };
        if content.len() > MAX_PHOTO_BYTES {
            return Err(AppError::PayloadTooLarge);
        }
        if !valid {
            return Err(AppError::invalid_field(
                "body",
                "must contain a PNG, JPEG or WebP image matching Content-Type",
            ));
        }
        Ok(Self {
            content_type,
            sha256: hex::encode(Sha256::digest(&content)),
            content,
        })
    }
    pub(super) async fn store(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        state: &ApiState,
    ) -> Result<String, AppError> {
        let id = Id::now_v7();
        sqlx::query("SELECT iam_private.store_profile_photo($1,$2,$3,$4)")
            .bind(id)
            .bind(&self.content_type)
            .bind(self.content.as_ref())
            .bind(Sha256::digest(&self.content).as_slice())
            .execute(&mut **transaction)
            .await
            .map_err(|_| AppError::Internal {
                category: "profile_photo_store",
            })?;
        state
            .settings
            .server
            .public_base_url
            .join(&format!("api/v1/profile-photos/{id}"))
            .map(|value| value.to_string())
            .map_err(|_| AppError::Internal {
                category: "profile_photo_url",
            })
    }
}
pub(crate) async fn upload(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let photo = PhotoUpload::parse(&headers, body)?;
    super::me::update_photo(state, authenticated, headers, photo).await
}
pub(crate) async fn get(
    State(state): State<ApiState>,
    Path(id): Path<Id>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let mut transaction = crate::infrastructure::postgres::context::begin_scoped(state.db())
        .await
        .map_err(|_| AppError::Internal {
            category: "profile_photo_read_context",
        })?;
    let (content_type, content, digest) = sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>)>(
        "SELECT content_type,content,content_sha256 FROM iam_private.read_profile_photo($1)",
    )
    .bind(id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "profile_photo_read",
    })?
    .ok_or(AppError::NotFound)?;
    transaction.commit().await.map_err(|_| AppError::Internal {
        category: "profile_photo_read_commit",
    })?;
    let etag = format!("\"{}\"", hex::encode(digest));
    let unchanged = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|tag| tag.trim() == etag));
    Response::builder()
        .status(if unchanged {
            StatusCode::NOT_MODIFIED
        } else {
            StatusCode::OK
        })
        .header(header::CONTENT_TYPE, content_type)
        .header(header::ETAG, etag)
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header("cross-origin-resource-policy", "cross-origin")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; sandbox",
        )
        .body(if unchanged {
            Body::empty()
        } else {
            Body::from(content)
        })
        .map_err(|_| AppError::Internal {
            category: "profile_photo_response",
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uploads_require_matching_raster_types_and_a_bounded_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("image/png"),
        );
        assert!(PhotoUpload::parse(&headers, Bytes::from_static(b"\x89PNG\r\n\x1a\n")).is_ok());
        assert!(PhotoUpload::parse(&headers, Bytes::from_static(b"<svg>script</svg>")).is_err());
        assert!(
            PhotoUpload::parse(&headers, Bytes::from(vec![0_u8; MAX_PHOTO_BYTES + 1])).is_err()
        );
    }
}
