use std::{num::NonZeroU32, time::Duration};

use axum::{
    Json,
    extract::{Query, State, rejection::JsonRejection, rejection::QueryRejection},
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::{
    api::{ApiState, authentication::Authenticated},
    error::AppError,
    infrastructure::postgres::{
        context::{self, DatabaseContext},
        rate_limit::{self, RateLimitPolicy},
    },
};

use super::{
    contacts,
    model::{EmailInput, PhoneInput, ValidatedContact},
    sessions, validation,
};

const DEFAULT_LIMIT: u16 = 10;
const MAX_LIMIT: u16 = 10;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SearchQuery {
    q: String,
    limit: Option<u16>,
}

#[derive(Clone, Debug, Serialize)]
struct CarbonSuggestion {
    carbon_id: String,
}

#[derive(Serialize)]
pub(super) struct CarbonSearchResponse {
    items: Vec<CarbonSuggestion>,
}

#[derive(Serialize)]
pub(super) struct CarbonResolutionResponse {
    carbon_id: String,
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
    let carbon_ids = sqlx::query_scalar::<_, String>(
        r"
        SELECT
            carbon.carbon_id
        FROM iam.carbons AS carbon
        JOIN iam.principals AS principal
          ON principal.id = carbon.id
         AND principal.kind = 'carbon'
         AND principal.status = 'active'
        WHERE carbon.deleted_at IS NULL
          AND (
              carbon.carbon_id ILIKE $1 ESCAPE '\'
              OR carbon.carbon_id OPERATOR(public.%) $2
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

    let items = carbon_ids
        .into_iter()
        .map(|carbon_id| CarbonSuggestion { carbon_id })
        .collect();
    Ok(Json(CarbonSearchResponse { items }))
}

pub(super) async fn resolve_email(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    payload: Result<Json<EmailInput>, JsonRejection>,
) -> Result<Json<CarbonResolutionResponse>, AppError> {
    let Json(input) = payload.map_err(|_| validation::validation("body", "is invalid"))?;
    let contact = validation::email(input.email)?;
    resolve_contact(&state, &authenticated, contact).await
}

pub(super) async fn resolve_phone(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    payload: Result<Json<PhoneInput>, JsonRejection>,
) -> Result<Json<CarbonResolutionResponse>, AppError> {
    let Json(input) = payload.map_err(|_| validation::validation("body", "is invalid"))?;
    let contact = validation::phone(input.phone_number)?;
    resolve_contact(&state, &authenticated, contact).await
}

async fn resolve_contact(
    state: &ApiState,
    authenticated: &Authenticated,
    contact: ValidatedContact,
) -> Result<Json<CarbonResolutionResponse>, AppError> {
    let principal_id = sessions::carbon_context(&authenticated.0)?;
    enforce_resolution_rate_limits(state, principal_id, &contact).await?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(principal_id))
        .await
        .map_err(|_| AppError::Internal {
            category: "carbon_resolution_context",
        })?;
    let carbon_id =
        contacts::resolve_carbon_id_by_contact(&mut transaction, &state.crypto, &contact)
            .await?
            .ok_or(AppError::NotFound)?;
    transaction.commit().await.map_err(|_| AppError::Internal {
        category: "carbon_resolution_commit",
    })?;
    Ok(Json(CarbonResolutionResponse { carbon_id }))
}

async fn enforce_resolution_rate_limits(
    state: &ApiState,
    principal_id: uuid::Uuid,
    contact: &ValidatedContact,
) -> Result<(), AppError> {
    let maximum = NonZeroU32::new(60).ok_or(AppError::Internal {
        category: "carbon_resolution_rate_policy",
    })?;
    let window = Duration::from_mins(1);
    let policy = RateLimitPolicy::new(maximum, window, window).map_err(|_| AppError::Internal {
        category: "carbon_resolution_rate_policy",
    })?;
    let actor_scope = SecretString::from(principal_id.to_string());
    let contact_scope = SecretString::from(format!(
        "{}:{}",
        contact.channel.database_value(),
        contact.normalized,
    ));
    rate_limit::enforce(
        &state.pool,
        &state.crypto,
        "carbon_resolution_actor",
        &actor_scope,
        policy,
    )
    .await?;
    rate_limit::enforce(
        &state.pool,
        &state.crypto,
        "carbon_resolution_contact",
        &contact_scope,
        policy,
    )
    .await
    .map(|_| ())
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        CarbonResolutionResponse, CarbonSearchResponse, CarbonSuggestion, escape_like,
        validate_term,
    };

    #[test]
    fn search_terms_are_bounded_and_wildcards_are_literal() {
        assert_eq!(validate_term("  Carbon  ").ok().as_deref(), Some("carbon"));
        assert!(validate_term("\n").is_err());
        assert_eq!(escape_like(r"a%b_c\d"), r"a\%b\_c\\d");
    }

    #[test]
    fn public_search_and_resolution_expose_only_carbon_ids() {
        let search = CarbonSearchResponse {
            items: vec![CarbonSuggestion {
                carbon_id: "saket".to_owned(),
            }],
        };
        assert_eq!(
            serde_json::to_value(search).ok(),
            Some(json!({ "items": [{ "carbon_id": "saket" }] }))
        );

        let resolution = CarbonResolutionResponse {
            carbon_id: "saket".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(resolution).ok(),
            Some(json!({ "carbon_id": "saket" }))
        );
    }
}
