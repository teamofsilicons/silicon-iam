//! Organization logos uploaded to and served by IAM.
//!
//! An upload stores the image bytes in IAM and points the organization's
//! `logo` at a public IAM URL for that exact upload. Each upload has a fresh
//! id, so the URL names immutable bytes and can be cached indefinitely.

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::Response,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::{id::Id, organization::Capability},
    error::AppError,
};

use super::{
    handlers,
    support::{self, Claim, MutationEvent},
    validation,
};

const LOGO_UPLOAD_ROUTE: &str = "PUT /api/v1/organizations/{org_id}/logo";

/// Largest accepted logo. Matches `organization_logos_content_size`.
pub(crate) const MAX_LOGO_BYTES: usize = 512 * 1024;

const ACCEPTED_TYPES: &str = "must be image/png, image/jpeg, image/webp or image/gif";

/// Whether a request is a logo upload, whose body may exceed the default
/// JSON request limit and is not JSON.
pub(crate) fn is_logo_upload(method: &Method, path: &str) -> bool {
    method == Method::PUT
        && path
            .strip_prefix("/api/v1/organizations/")
            .and_then(|rest| rest.strip_suffix("/logo"))
            .is_some_and(|org_id| !org_id.is_empty() && !org_id.contains('/'))
}

/// What idempotency replay and action approvals bind to instead of the raw
/// image: the declared type, the size and the exact content digest.
#[derive(Debug, Serialize)]
pub(super) struct LogoUploadSummary {
    content_type: &'static str,
    byte_size: usize,
    sha256: String,
}

struct LogoUpload {
    content_type: &'static str,
    content: Bytes,
    sha256: [u8; 32],
}

impl LogoUpload {
    fn parse(headers: &HeaderMap, content: Bytes) -> Result<Self, AppError> {
        let declared = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let content_type = accepted_type(&declared)
            .ok_or_else(|| validation::field("content_type", ACCEPTED_TYPES))?;
        if content.is_empty() {
            return Err(validation::field("body", "must contain the logo image"));
        }
        if content.len() > MAX_LOGO_BYTES {
            return Err(AppError::PayloadTooLarge);
        }
        if sniff(&content) != Some(content_type) {
            return Err(validation::field(
                "body",
                "must be an image of the declared content type",
            ));
        }
        Ok(Self {
            content_type,
            sha256: Sha256::digest(&content).into(),
            content,
        })
    }

    fn summary(&self) -> LogoUploadSummary {
        LogoUploadSummary {
            content_type: self.content_type,
            byte_size: self.content.len(),
            sha256: hex::encode(self.sha256),
        }
    }
}

/// The request summary recorded for action approvals, or `None` when the
/// body is not a valid logo (the handler then rejects it).
pub(super) fn upload_summary(headers: &HeaderMap, content: &Bytes) -> Option<LogoUploadSummary> {
    LogoUpload::parse(headers, content.clone())
        .ok()
        .map(|upload| upload.summary())
}

fn accepted_type(value: &str) -> Option<&'static str> {
    match value {
        "image/png" => Some("image/png"),
        "image/jpeg" | "image/jpg" => Some("image/jpeg"),
        "image/webp" => Some("image/webp"),
        "image/gif" => Some("image/gif"),
        _ => None,
    }
}

/// Identifies the image format from its signature. SVG is deliberately not
/// accepted: it is active content when opened directly.
fn sniff(content: &[u8]) -> Option<&'static str> {
    if content.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if content.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if content.starts_with(b"GIF87a") || content.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if content.len() >= 12 && content.starts_with(b"RIFF") && &content[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

pub(super) async fn upload_logo(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let upload = LogoUpload::parse(&headers, body)?;
    support::require_application_scope(&authenticated, "organization.profile.update")?;
    let mut scope = support::begin_directory_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::OrganizationUpdate)?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        LOGO_UPLOAD_ROUTE,
        &upload.summary(),
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    handlers::enforce_actor_rate_limit(&state, &authenticated, "organization_logo_upload").await?;
    let expected_version = validation::expected_version(&headers)?;
    let before =
        handlers::fetch_organization(&mut scope.transaction, scope.access.organization_id).await?;
    if before.version != expected_version {
        return Err(handlers::precondition_failed());
    }

    let logo_id = Id::now_v7();
    let logo_uri = state
        .settings
        .server
        .public_base_url
        .join(&format!("api/v1/organization-logos/{logo_id}"))
        .map_err(|_| AppError::Internal {
            category: "organization_logo_uri",
        })?;
    sqlx::query("SELECT iam_private.store_organization_logo($1, $2, $3, $4, $5)")
        .bind(scope.access.organization_id)
        .bind(logo_id)
        .bind(upload.content_type)
        .bind(upload.content.as_ref())
        .bind(upload.sha256.as_slice())
        .execute(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    let result =
        sqlx::query("UPDATE iam.organizations SET logo_uri = $2 WHERE id = $1 AND version = $3")
            .bind(scope.access.organization_id)
            .bind(logo_uri.as_str())
            .bind(expected_version)
            .execute(&mut *scope.transaction)
            .await
            .map_err(support::database)?;
    if result.rows_affected() != 1 {
        return Err(handlers::precondition_failed());
    }

    let organization =
        handlers::fetch_organization(&mut scope.transaction, scope.access.organization_id).await?;
    support::record_application_mutation(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "organization.updated",
            target_type: "organization",
            target_id: organization.id,
            aggregate_type: "organization",
            aggregate_id: organization.id,
            aggregate_version: organization.version,
            event_type: "organization.updated.v1",
            before_state: handlers::redacted_value(&before)?,
            after_state: handlers::redacted_value(&organization)?,
            metadata: json!({
                "org_id": organization.org_id,
                "logo_id": logo_id,
                "logo_content_type": upload.content_type,
                "logo_byte_size": upload.content.len(),
            }),
        },
    )
    .await?;
    let body = support::finish_mutation(
        &authenticated,
        support::MutationView::Organization,
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &organization,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(organization.version), false)
}

/// Public: browsers and applications load logos without credentials. The id
/// is random per upload, so it reveals nothing that the organization's
/// readers were not already given.
pub(super) async fn get_logo(
    State(state): State<ApiState>,
    Path(logo_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let logo_id = Id::parse_str(&logo_id).map_err(|_| AppError::NotFound)?;
    let (content_type, content, sha256) = sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>)>(
        "SELECT content_type, content, content_sha256 FROM iam_private.read_organization_logo($1)",
    )
    .bind(logo_id)
    .fetch_optional(state.db())
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)?;

    let etag = format!("\"{}\"", hex::encode(sha256));
    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|tag| tag.trim() == etag));
    let (status, body) = if not_modified {
        (StatusCode::NOT_MODIFIED, Body::empty())
    } else {
        (StatusCode::OK, Body::from(content))
    };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::ETAG, etag)
        .header(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        )
        .header(
            "cross-origin-resource-policy",
            HeaderValue::from_static("cross-origin"),
        )
        .header(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; sandbox"),
        )
        .body(body)
        .map_err(|_| AppError::Internal {
            category: "organization_logo_response",
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";

    fn headers(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(content_type).unwrap_or(HeaderValue::from_static("")),
        );
        headers
    }

    #[test]
    fn sniffing_recognises_only_raster_signatures() {
        assert_eq!(sniff(PNG), Some("image/png"));
        assert_eq!(sniff(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(sniff(b"GIF89a...."), Some("image/gif"));
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(sniff(b"RIFF\0\0\0\0WAVE"), None);
        assert_eq!(sniff(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"), None);
        assert_eq!(sniff(b""), None);
    }

    #[test]
    fn uploads_must_match_their_declared_type() {
        let upload = LogoUpload::parse(&headers("image/png; charset=binary"), Bytes::from(PNG));
        assert!(upload.is_ok());
        assert!(LogoUpload::parse(&headers("image/jpeg"), Bytes::from(PNG)).is_err());
        assert!(LogoUpload::parse(&headers("image/svg+xml"), Bytes::from(PNG)).is_err());
        assert!(LogoUpload::parse(&HeaderMap::new(), Bytes::from(PNG)).is_err());
        assert!(LogoUpload::parse(&headers("image/png"), Bytes::new()).is_err());
    }

    #[test]
    fn oversized_uploads_are_rejected() {
        let mut content = PNG.to_vec();
        content.resize(MAX_LOGO_BYTES + 1, 0);
        assert!(matches!(
            LogoUpload::parse(&headers("image/png"), Bytes::from(content)),
            Err(AppError::PayloadTooLarge)
        ));
    }

    #[test]
    fn summaries_bind_the_exact_content() {
        let first = upload_summary(&headers("image/png"), &Bytes::from(PNG));
        let mut other = PNG.to_vec();
        other.push(0);
        let second = upload_summary(&headers("image/png"), &Bytes::from(other));
        let (Some(first), Some(second)) = (first, second) else {
            panic!("valid uploads must summarise");
        };
        assert_eq!(first.byte_size, PNG.len());
        assert_ne!(first.sha256, second.sha256);
    }

    #[test]
    fn upload_paths_are_recognised_exactly() {
        assert!(is_logo_upload(
            &Method::PUT,
            "/api/v1/organizations/acme/logo"
        ));
        assert!(!is_logo_upload(
            &Method::GET,
            "/api/v1/organizations/acme/logo"
        ));
        assert!(!is_logo_upload(&Method::PUT, "/api/v1/organizations//logo"));
        assert!(!is_logo_upload(
            &Method::PUT,
            "/api/v1/organizations/a/b/logo"
        ));
        assert!(!is_logo_upload(&Method::PUT, "/api/v1/organizations/acme"));
    }
}
