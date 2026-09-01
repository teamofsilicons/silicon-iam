use std::{num::NonZeroU32, time::Duration};

use axum::{
    Json,
    extract::{Query, State, rejection::QueryRejection},
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    error::AppError,
    infrastructure::postgres::{
        context::{self, DatabaseContext},
        rate_limit::{self, RateLimitPolicy},
    },
};

use super::{sessions, validation};

const DEFAULT_LIMIT: u16 = 10;
const MAX_LIMIT: u16 = 10;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SearchQuery {
    q: String,
    limit: Option<u16>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct CarbonPublicRow {
    principal_id: Uuid,
    carbon_id: String,
    display_name: String,
    description: Option<String>,
    profile_photo_uri: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

#[derive(Serialize)]
pub(super) struct CarbonSearchResponse {
    items: Vec<CarbonPublicResponse>,
}

#[derive(Serialize)]
struct CarbonPublicResponse {
    principal_id: Uuid,
    carbon_id: String,
    display_name: String,
    description: Option<String>,
    profile_photo: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

pub(super) async fn search(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    query: Result<Query<SearchQuery>, QueryRejection>,
) -> Result<Json<CarbonSearchResponse>, AppError> {
    let principal_id = sessions::carbon_context(&authenticated.0)?;
    let Query(query) = query.map_err(|_| validation::validation("query", "is invalid"))?;
    let term = validate_term(&query.q)?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(validation::validation("limit", "must be between 1 and 10"));
    }
    let actor_scope = SecretString::from(principal_id.to_string());
    let query_scope = SecretString::from(format!("{principal_id}:{term}"));
    let maximum = NonZeroU32::new(60).ok_or(AppError::Internal {
        category: "carbon_search_rate_policy",
    })?;
    let window = Duration::from_mins(1);
    let policy = RateLimitPolicy::new(maximum, window, window).map_err(|_| AppError::Internal {
        category: "carbon_search_rate_policy",
    })?;
    rate_limit::enforce(
        &state.pool,
        &state.crypto,
        "carbon_directory_search_actor",
        &actor_scope,
        policy,
    )
    .await?;
    rate_limit::enforce(
        &state.pool,
        &state.crypto,
        "carbon_directory_search_query",
        &query_scope,
        policy,
    )
    .await?;

    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(principal_id))
        .await
        .map_err(|_| AppError::Internal {
            category: "carbon_search_context",
        })?;
    let escaped = escape_like(&term);
    let pattern = format!("%{escaped}%");
    let prefix = format!("{escaped}%");
    let rows = sqlx::query_as::<_, CarbonPublicRow>(
        r"
        SELECT
            carbon.id AS principal_id,
            carbon.carbon_id,
            carbon.display_name,
            carbon.description,
            carbon.profile_photo_uri,
            carbon.created_at
        FROM iam.carbons AS carbon
        JOIN iam.principals AS principal
          ON principal.id = carbon.id
         AND principal.kind = 'carbon'
         AND principal.status = 'active'
        WHERE carbon.deleted_at IS NULL
          AND (
              carbon.carbon_id ILIKE $1 ESCAPE '\'
              OR carbon.display_name ILIKE $1 ESCAPE '\'
          )
        ORDER BY
            (carbon.carbon_id = $2) DESC,
            (carbon.carbon_id ILIKE $3 ESCAPE '\') DESC,
            similarity(carbon.carbon_id, $2) DESC,
            carbon.carbon_id,
            carbon.id
        LIMIT $4
        ",
    )
    .bind(pattern)
    .bind(&term)
    .bind(prefix)
    .bind(i64::from(limit))
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "carbon_search_query",
    })?;
    transaction.commit().await.map_err(|_| AppError::Internal {
        category: "carbon_search_commit",
    })?;

    let items = rows
        .into_iter()
        .map(|row| public_response(&state, row))
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(Json(CarbonSearchResponse { items }))
}

fn validate_term(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 100 || value.chars().any(char::is_control) {
        return Err(validation::validation(
            "q",
            "must contain 1 to 100 non-control characters",
        ));
    }
    Ok(value.to_lowercase())
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn public_response(
    state: &ApiState,
    row: CarbonPublicRow,
) -> Result<CarbonPublicResponse, AppError> {
    let profile_photo = if let Some(value) = row.profile_photo_uri {
        value
    } else {
        let mut url = state
            .settings
            .providers
            .iris_base_url
            .join("pfp/carbon")
            .map_err(|_| AppError::Internal {
                category: "carbon_search_profile_photo",
            })?;
        url.query_pairs_mut().append_pair("id", &row.carbon_id);
        url.to_string()
    };
    Ok(CarbonPublicResponse {
        principal_id: row.principal_id,
        carbon_id: row.carbon_id,
        display_name: row.display_name,
        description: row.description,
        profile_photo,
        created_at: row.created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::{escape_like, validate_term};

    #[test]
    fn search_terms_are_bounded_and_wildcards_are_literal() {
        assert_eq!(validate_term("  Carbon  ").ok().as_deref(), Some("carbon"));
        assert!(validate_term("\n").is_err());
        assert_eq!(escape_like(r"a%b_c\d"), r"a\%b\_c\\d");
    }
}
