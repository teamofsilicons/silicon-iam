use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::actor::ActorRef,
    error::AppError,
    features::webhook_replay::{self, DeadLetterRecord},
    infrastructure::postgres::events::{self, AggregateVersion, AuditRecord},
};

use super::{
    super::{
        model::{
            PageInfo, PageQuery, WebhookDeadLetterPage, WebhookDeadLetterResponse,
            WebhookReplayRequest, WebhookReplayResponse,
        },
        silicons,
        support::{self, Claim},
        validation,
    },
    shared,
};

const REPLAY_ROUTE: &str =
    "POST /api/v1/organizations/{org_id}/silicons/{silicon_id}/webhook/dead-letters/replays";

pub(in crate::features::organizations) async fn list_dead_letters(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
    Query(query): Query<PageQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    silicons::validate_global_silicon_id(&silicon_id, &org_id)?;
    let (cursor_id, limit) = validation::page(&query)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let target = shared::load_target(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    shared::authorize(&authenticated, &scope.access, &target)?;
    let cursor_at = if let Some(cursor_id) = cursor_id {
        Some(
            load_cursor_timestamp(
                &mut scope.transaction,
                scope.access.organization_id,
                target.principal_id,
                cursor_id,
            )
            .await?,
        )
    } else {
        None
    };
    let mut rows = webhook_replay::list_silicon_dead_letters(
        &mut scope.transaction,
        scope.access.organization_id,
        target.principal_id,
        cursor_at,
        cursor_id,
        limit + 1,
    )
    .await
    .map_err(support::database)?;
    let has_more = i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit;
    if has_more {
        rows.pop();
    }
    let next_cursor = if has_more {
        rows.last()
            .map(|delivery| validation::encode_cursor(delivery.delivery_id))
    } else {
        None
    };
    let response = WebhookDeadLetterPage {
        items: rows.iter().map(dead_letter_response).collect(),
        page: PageInfo {
            next_cursor,
            has_more,
        },
    };
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &response, None)
}

#[allow(
    clippy::too_many_lines,
    reason = "the idempotency claim, ordered delivery locks, subscription rechecks, replay resets, and audit records form one atomic transaction"
)]
pub(in crate::features::organizations) async fn replay_dead_letters(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<WebhookReplayRequest>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    silicons::validate_global_silicon_id(&silicon_id, &org_id)?;
    validation::delivery_ids(&input.delivery_ids)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let target = shared::load_target(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    shared::authorize_identity(&authenticated, &scope.access, &target)?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        REPLAY_ROUTE,
        &silicon_id,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let target = shared::load_target_for_update(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    shared::authorize(&authenticated, &scope.access, &target)?;
    let deliveries = webhook_replay::lock_silicon_dead_letters(
        &mut scope.transaction,
        scope.access.organization_id,
        target.principal_id,
        &input.delivery_ids,
    )
    .await
    .map_err(support::database)?;
    if deliveries.len() != input.delivery_ids.len() {
        return Err(AppError::Conflict {
            code: "dead_letter_not_replayable".into(),
        });
    }

    // One batch-specific ordering lane serializes the selected historical
    // events without reducing concurrency for unrelated webhook work.
    let replay_batch_id = Uuid::now_v7();
    let mut replayed = Vec::with_capacity(deliveries.len());
    let mut locked_endpoint_id = None;
    for delivery in deliveries {
        let replay_target = sqlx::query_as::<_, (Uuid, Uuid)>(
            r"
            SELECT endpoint_id, signing_key_id
            FROM iam_private.resolve_silicon_webhook_replay_target($1, $2, $3)
            ",
        )
        .bind(delivery.event_id)
        .bind(scope.access.organization_id)
        .bind(target.principal_id)
        .fetch_optional(&mut *scope.transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::Forbidden)?;
        if locked_endpoint_id != Some(replay_target.0) {
            shared::lock_delivery_scope(&mut scope.transaction, replay_target.0).await?;
            locked_endpoint_id = Some(replay_target.0);
        }
        let reset = webhook_replay::replay_silicon_delivery(
            &mut scope.transaction,
            &delivery,
            replay_target.0,
            replay_target.1,
            replay_batch_id,
        )
        .await
        .map_err(support::database)?;
        record_replay_audit(
            &mut scope.transaction,
            &authenticated,
            scope.access.organization_id,
            &reset,
        )
        .await?;
        replayed.push(dead_letter_response(&reset));
    }
    let response = WebhookReplayResponse {
        replayed_count: replayed.len(),
        deliveries: replayed,
    };
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::ACCEPTED,
        &response,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::ACCEPTED, body, None, false)
}

async fn load_cursor_timestamp(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    silicon_id: Uuid,
    delivery_id: Uuid,
) -> Result<OffsetDateTime, AppError> {
    sqlx::query_scalar::<_, OffsetDateTime>(
        r"
        SELECT delivery.dead_lettered_at
        FROM iam.webhook_deliveries AS delivery
        JOIN iam.outbox_event_recipients AS recipient
          ON recipient.id = delivery.recipient_id
         AND recipient.outbox_event_id = delivery.outbox_event_id
         AND recipient.recipient_kind = 'silicon_webhook'
        JOIN iam.silicon_webhook_endpoints AS endpoint
          ON endpoint.id = recipient.silicon_webhook_endpoint_id
        WHERE delivery.id = $1 AND delivery.status = 'dead_letter'
          AND endpoint.organization_id = $2 AND endpoint.silicon_id = $3
        ",
    )
    .bind(delivery_id)
    .bind(organization_id)
    .bind(silicon_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or_else(|| validation::field("cursor", "does not identify a visible dead letter"))
}

async fn record_replay_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    authenticated: &Authenticated,
    organization_id: Uuid,
    delivery: &DeadLetterRecord,
) -> Result<(), AppError> {
    events::record_audit(
        transaction,
        AuditRecord {
            actor: Some(ActorRef {
                actor_type: authenticated.0.subject.actor_type,
                id: authenticated.0.subject.id,
            }),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            organization_id: Some(organization_id),
            application_id: None,
            action: "webhook.dead_letter.replay",
            target_type: "webhook_delivery",
            target_id: Some(delivery.delivery_id),
            authentication_method: None,
            aggregate: Some(AggregateVersion {
                aggregate_type: "webhook_delivery",
                aggregate_id: delivery.delivery_id,
                version: delivery.version,
            }),
            before_state: Some(json!({ "status": "dead_letter" })),
            after_state: Some(json!({
                "status": delivery.status,
                "cycle_attempt_count": delivery.cycle_attempt_count,
                "manual_replay_count": delivery.manual_replay_count,
            })),
            metadata: json!({
                "event_id": delivery.event_id,
                "event_type": delivery.event_type,
            }),
        },
    )
    .await
    .map_err(support::database)?;
    Ok(())
}

fn dead_letter_response(delivery: &DeadLetterRecord) -> WebhookDeadLetterResponse {
    WebhookDeadLetterResponse {
        delivery_id: delivery.delivery_id,
        event_id: delivery.event_id,
        event_type: delivery.event_type.clone(),
        occurred_at: delivery.occurred_at,
        aggregate_type: delivery.aggregate_type.clone(),
        aggregate_id: delivery.aggregate_id,
        aggregate_version: delivery.aggregate_version,
        status: delivery.status.clone(),
        attempt_count: delivery.attempt_count,
        cycle_attempt_count: delivery.cycle_attempt_count,
        manual_replay_count: delivery.manual_replay_count,
        last_http_status: delivery.last_http_status,
        last_error_code: delivery.last_error_code.clone(),
        dead_lettered_at: delivery.dead_lettered_at,
        version: delivery.version,
    }
}

#[cfg(test)]
mod tests {
    use super::REPLAY_ROUTE;

    #[test]
    fn replay_route_is_method_qualified_and_resource_scoped() {
        assert_eq!(
            REPLAY_ROUTE,
            "POST /api/v1/organizations/{org_id}/silicons/{silicon_id}/webhook/dead-letters/replays"
        );
    }
}
