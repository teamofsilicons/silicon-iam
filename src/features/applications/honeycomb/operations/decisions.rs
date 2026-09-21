//! Provider and webhook decisions keep authority separate from publication.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeDecision {
    operation_id: Id,
    expected_iam_revision: i64,
    environment_id: Option<Id>,
    target_app_id: Option<String>,
    scopes: Vec<String>,
    decision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WebhookApproval {
    operation_id: Id,
    expected_iam_revision: i64,
    environment_id: Option<Id>,
    pending_endpoint_id: Id,
}

pub(super) fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/honeycomb/applications/{app_id}/scope-decisions",
            post(scope_decision),
        )
        .route(
            "/api/v1/honeycomb/applications/{app_id}/webhook-approvals",
            post(webhook_approval),
        )
}

async fn scope_decision(
    State(state): State<ApiState>,
    service: Service,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    validation::app_id(&path)?;
    let input: ScopeDecision = decode(&body)?;
    if input.environment_id.is_some() {
        return Err(ApiError::forbidden("use_testing_lifecycle_integration"));
    }
    if !matches!(input.decision.as_str(), "approve" | "revoke")
        || input.scopes.is_empty()
        || input.scopes.len() > 100
    {
        return Err(ApiError::validation(
            "scope_decision",
            "select approve or revoke and 1-100 scopes",
        ));
    }
    if let Some(provider) = &input.target_app_id {
        validation::app_id(provider)?;
    }
    let actor = service.actor(&state, &headers).await?;
    let mut tx = begin(&state, &actor).await?;
    // Reviewer authority is checked before replay, and again under the mutation locks.
    if let Some(provider) = &input.target_app_id {
        let org = provider
            .split_once('>')
            .map(|(org, _)| org)
            .ok_or_else(ApiError::not_found)?;
        manager(&mut tx, &actor, org).await?;
    } else {
        security::require_platform_capability(&mut tx, actor.subject.id, "applications.review")
            .await?;
    }
    if let Some(response) = claim(
        &mut tx,
        &state,
        &service,
        &actor.subject,
        &headers,
        input.operation_id,
        "scope-decision",
        &path,
        &body,
    )
    .await?
    {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("honeycomb_decision_replay"))?;
        return Ok(management_response(response, true));
    }
    let revision = sqlx::query_scalar::<_, i64>(
        "SELECT iam_private.honeycomb_scope_decision($1,$2,$3,$4,$5,$6)",
    )
    .bind(&path)
    .bind(actor.subject.id)
    .bind(input.expected_iam_revision)
    .bind(&input.target_app_id)
    .bind(&input.scopes)
    .bind(&input.decision)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| scopes::database_error(&error))?;
    let response = json!({"operation_id":input.operation_id,"state":"accepted","iam_revision":revision,"app_id":path,"decision":input.decision,"scopes":input.scopes});
    complete(
        &mut tx,
        &state,
        &service,
        input.operation_id,
        &path,
        revision,
        &response,
        false,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("honeycomb_decision_commit"))?;
    Ok(management_response(response, false))
}

async fn webhook_approval(
    State(state): State<ApiState>,
    service: Service,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    validation::app_id(&path)?;
    let input: WebhookApproval = decode(&body)?;
    if input.environment_id.is_some() {
        return Err(ApiError::forbidden("use_testing_lifecycle_integration"));
    }
    let actor = service.actor(&state, &headers).await?;
    let mut tx = begin(&state, &actor).await?;
    security::lock_step_up_actor(&mut tx, actor.subject.id).await?;
    let reviewer = sqlx::query_scalar::<_, bool>(
        "SELECT iam_private.has_platform_capability($1,'applications.review')",
    )
    .bind(actor.subject.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| ApiError::internal("honeycomb_webhook_reviewer"))?;
    if !reviewer {
        manager(
            &mut tx,
            &actor,
            path.split_once('>')
                .map(|(org, _)| org)
                .ok_or_else(ApiError::not_found)?,
        )
        .await?;
    }
    if let Some(response) = claim(
        &mut tx,
        &state,
        &service,
        &actor.subject,
        &headers,
        input.operation_id,
        "webhook-approval",
        &path,
        &body,
    )
    .await?
    {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("honeycomb_webhook_replay"))?;
        return Ok(management_response(response, true));
    }
    let app =
        applications::resolve_webhook_review_app(&mut tx, actor.subject.id, &path, true).await?;
    if app.version != input.expected_iam_revision {
        return Err(ApiError::conflict("iam_revision_conflict"));
    }
    let pending=sqlx::query_scalar::<_,Id>("SELECT id FROM iam.application_webhook_endpoints WHERE application_id=$1 AND id=$2 AND status='pending_review' FOR UPDATE")
        .bind(app.id).bind(input.pending_endpoint_id).fetch_optional(&mut *tx).await.map_err(|_|ApiError::internal("honeycomb_pending_webhook"))?.ok_or_else(ApiError::not_found)?;
    security::require_step_up(
        &mut tx,
        &state.crypto,
        &headers,
        &actor,
        "application.webhook.approve",
        app.id,
        crate::infrastructure::postgres::step_up::RequiredAssurance::VerifiedChannel,
    )
    .await?;
    sqlx::query("UPDATE iam.application_webhook_endpoints SET status='retired',retired_at=transaction_timestamp() WHERE application_id=$1 AND status IN ('active','pending_review') AND id<>$2")
        .bind(app.id).bind(pending).execute(&mut *tx).await.map_err(|_|ApiError::internal("honeycomb_webhook_retire"))?;
    sqlx::query("UPDATE iam.application_webhook_endpoints SET status='active',activated_at=transaction_timestamp() WHERE id=$1")
        .bind(pending).execute(&mut *tx).await.map_err(|_|ApiError::internal("honeycomb_webhook_activate"))?;
    let revision = applications::bump_application(&mut tx, app.id).await?;
    let response = json!({"operation_id":input.operation_id,"state":"accepted","iam_revision":revision,"app_id":path,"webhook_endpoint_id":pending});
    complete(
        &mut tx,
        &state,
        &service,
        input.operation_id,
        &path,
        revision,
        &response,
        false,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("honeycomb_webhook_commit"))?;
    Ok(management_response(response, false))
}
