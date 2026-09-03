//! Wire types for the testing-environment control plane.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PageQuery {
    pub(super) cursor: Option<Uuid>,
    pub(super) limit: Option<u16>,
    pub(super) status: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct PageInfo {
    pub(super) next_cursor: Option<Uuid>,
    pub(super) has_more: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnvironmentCreate {
    pub(super) name: String,
    pub(super) description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::option_option)]
pub(super) struct EnvironmentPatch {
    pub(super) name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) description: Option<Option<String>>,
}

/// One environment as its owning organization sees it.
///
/// The key is deliberately absent. It is a retrievable credential with its own
/// route and its own audit trail, so it never rides along on a list or a read
/// that a member might reasonably log or cache.
#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub(super) struct EnvironmentResponse {
    pub(super) id: Uuid,
    pub(super) org_id: String,
    pub(super) name: String,
    pub(super) description: Option<String>,
    pub(super) status: String,
    pub(super) created_by_membership_id: Uuid,
    pub(super) key_generation: i32,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(super) key_rotated_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) last_activity_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(super) cleaned_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(super) deleted_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(super) purge_after: Option<OffsetDateTime>,
    pub(super) version: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub(super) struct EnvironmentPage {
    pub(super) items: Vec<EnvironmentResponse>,
    pub(super) page: PageInfo,
}

/// An environment together with its key.
///
/// Returned by creation and rotation, where the caller has just caused the key
/// to exist and cannot be expected to make a second call for it.
#[derive(Debug, Serialize)]
pub(super) struct EnvironmentWithKey {
    #[serde(flatten)]
    pub(super) environment: EnvironmentResponse,
    pub(super) key: String,
}

/// The key on its own, for a later retrieval.
#[derive(Debug, Serialize)]
pub(super) struct EnvironmentKey {
    pub(super) environment_id: Uuid,
    pub(super) key_generation: i32,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(super) key_rotated_at: Option<OffsetDateTime>,
    pub(super) key: String,
}

/// What a key holder can see about the environment it is holding a key to.
///
/// Nothing here identifies the organization's members or its production state;
/// a key is authority inside one environment, not a window into the tenant that
/// owns it.
#[derive(Debug, Serialize)]
pub(super) struct EnvironmentSelfView {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) description: Option<String>,
    pub(super) key_generation: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
}

/// Outcome of erasing an environment's data.
#[derive(Debug, Serialize)]
pub(super) struct CleaningResult {
    pub(super) environment_id: Uuid,
    pub(super) erased_rows: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) cleaned_at: OffsetDateTime,
}
