//! One explicit approval, with isolated per-application consent and single-use SLTs.

use super::{
    error::ApiError,
    idempotency::{self, Claim},
    model::{
        BatchLoginChoicesQuery, BatchLoginRequest, BatchLoginResponse, BatchLoginToken,
        ShortLivedTokenRequest,
    },
    oauth,
    security::Bearer,
    validation,
};
use crate::{
    api::ApiState,
    infrastructure::postgres::context::{self, DatabaseContext},
};
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};
use serde_json::json;

pub(super) async fn organizations(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Query(query): Query<BatchLoginChoicesQuery>,
) -> Result<Response, ApiError> {
    oauth::require_direct_login(&access)?;
    validation::batch_app_ids(query.app_ids.split(','))?;
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(access.subject.id))
        .await
        .map_err(|_| ApiError::internal("batch_login_choices_context"))?;
    let mut items = Vec::new();
    for app_id in query.app_ids.split(',') {
        items.push(oauth::login_choices(&mut transaction, &access, app_id).await?);
    }
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("batch_login_choices_commit"))?;
    Ok(Json(json!({"items": items})).into_response())
}

pub(super) fn validate(input: &BatchLoginRequest) -> Result<(), ApiError> {
    validation::batch_app_ids(input.applications.iter().map(|app| app.app_id.as_str()))?;
    if let Some(uri) = &input.redirect_uri {
        validation::redirect_uri(uri)?;
    }
    for app in &input.applications {
        if app.org_ids.is_empty() || app.org_ids.len() > 1000 {
            return Err(ApiError::validation(
                "org_ids",
                "select between 1 and 1000 organizations per application",
            ));
        }
        let mut unique = std::collections::BTreeSet::new();
        for org in &app.org_ids {
            validation::org_id(org)?;
            if !unique.insert(org) {
                return Err(ApiError::validation(
                    "org_ids",
                    "must not contain duplicates",
                ));
            }
        }
    }
    Ok(())
}

pub(super) async fn issue(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    headers: HeaderMap,
    Json(input): Json<BatchLoginRequest>,
) -> Result<Response, ApiError> {
    oauth::require_direct_login(&access)?;
    validate(&input)?;
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(access.subject.id))
        .await
        .map_err(|_| ApiError::internal("batch_login_context"))?;
    let caller = format!(
        "batch-login:{}:{}",
        access.subject.id, access.authentication_session_id
    );
    let (status, response) = issue_in_transaction(
        &mut transaction,
        &state,
        &access,
        &headers,
        &input,
        &caller,
        "POST /api/v1/app-auth/batch/short-lived-tokens",
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("batch_login_commit"))?;
    Ok((status, Json(response)).into_response())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn issue_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    state: &ApiState,
    access: &crate::infrastructure::postgres::tokens::AccessContext,
    headers: &HeaderMap,
    input: &BatchLoginRequest,
    caller: &str,
    route: &'static str,
) -> Result<(StatusCode, BatchLoginResponse), ApiError> {
    let canonical =
        serde_json::to_vec(input).map_err(|_| ApiError::internal("batch_login_canonical"))?;
    let claim = idempotency::claim::<BatchLoginResponse>(
        transaction,
        &state.crypto,
        headers,
        caller,
        route,
        &canonical,
        true,
    )
    .await?;
    if let Claim::Replay { status, response } = claim {
        return Ok((
            StatusCode::from_u16(status).map_err(|_| ApiError::internal("batch_login_status"))?,
            response,
        ));
    }
    let Claim::Acquired(id) = claim else {
        return Err(ApiError::internal("batch_login_idempotency"));
    };
    // Stable lock ordering across overlapping batches avoids reversed-app deadlocks.
    let mut applications = input.applications.iter().collect::<Vec<_>>();
    applications.sort_by(|a, b| a.app_id.cmp(&b.app_id));
    let ttl = i64::try_from(state.settings.security.authorization_code_ttl.as_secs())
        .map_err(|_| ApiError::internal("batch_login_ttl"))?;
    let expires_at = sqlx::query_scalar::<_, time::OffsetDateTime>(
        "SELECT transaction_timestamp() + ($1::bigint * interval '1 second')",
    )
    .bind(ttl)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("batch_login_expiry"))?;
    let mut items = Vec::with_capacity(applications.len());
    for app in applications {
        let token = oauth::issue_for_selection(
            transaction,
            state,
            access,
            &ShortLivedTokenRequest {
                app_id: app.app_id.clone(),
                scope_version: app.scope_version,
                approved_scopes: app.approved_scopes.clone(),
                org_ids: app.org_ids.clone(),
                org_id: None,
                redirect_uri: input.redirect_uri.clone(),
            },
        )
        .await?;
        items.push(BatchLoginToken {
            app_id: app.app_id.clone(),
            expires_at,
            token,
        });
    }
    // Retain caller order in the response; it is also part of the replay identity.
    items.sort_by_key(|item| {
        input
            .applications
            .iter()
            .position(|app| app.app_id == item.app_id)
    });
    let response = BatchLoginResponse { items };
    idempotency::complete(transaction, &state.crypto, id, 201, &response, true).await?;
    Ok((StatusCode::CREATED, response))
}

#[cfg(test)]
mod tests {
    use super::super::model::BatchLoginSelection;
    use super::*;
    fn batch(count: usize) -> BatchLoginRequest {
        BatchLoginRequest {
            applications: (0..count)
                .map(|i| BatchLoginSelection {
                    app_id: format!("tos>app-{i}"),
                    org_ids: vec!["tos".to_owned()],
                    scope_version: 1,
                    approved_scopes: vec!["self.identity.read".to_owned()],
                })
                .collect(),
            redirect_uri: None,
        }
    }
    #[test]
    fn bounds_and_duplicate_targets_are_enforced() {
        assert!(validate(&batch(0)).is_err());
        assert!(validate(&batch(1)).is_ok());
        assert!(validate(&batch(100)).is_ok());
        assert!(validate(&batch(101)).is_err());
        let mut request = batch(2);
        request.applications[1].app_id = request.applications[0].app_id.clone();
        assert!(validate(&request).is_err());
    }
    #[test]
    fn every_app_requires_an_explicit_valid_selection() {
        let mut request = batch(2);
        request.applications[1].org_ids.clear();
        assert!(validate(&request).is_err());
        request.applications[1].org_ids = vec!["tos".to_owned(), "tos".to_owned()];
        assert!(validate(&request).is_err());
        request.applications[1].org_ids = vec!["tos".to_owned()];
        request.redirect_uri = Some("javascript:alert(1)".to_owned());
        assert!(validate(&request).is_err());
    }
}
