use std::collections::BTreeSet;

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse as _, Response},
};
use secrecy::SecretString;
use serde::Serialize;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::{
        actor::{ActorRef, ActorType},
        organization::Capability,
    },
    error::AppError,
    features::application_webhook_projections::{self, OrganizationProjectionEvent},
    infrastructure::postgres::{
        authorization::{self, AuthorizationError, OrganizationAccess},
        context::{self, DatabaseContext},
        events::{
            self, AggregateVersion, AuditRecord, OutboxRecord, SiliconWebhookRouting,
            SiliconWebhookTopic,
        },
        idempotency::{self, IdempotencyClaim, IdempotencyKey, IdempotencyLease},
        step_up::{self, RequiredAssurance, StepUpExpectation, StepUpToken},
    },
};

pub(super) struct OrganizationTransaction<'a> {
    pub(super) transaction: Transaction<'a, Postgres>,
    pub(super) access: OrganizationAccess,
}

pub(super) struct MutationEvent<'a> {
    pub(super) action: &'static str,
    pub(super) target_type: &'static str,
    pub(super) target_id: Uuid,
    pub(super) aggregate_type: &'a str,
    pub(super) aggregate_id: Uuid,
    pub(super) aggregate_version: i64,
    pub(super) event_type: &'a str,
    pub(super) before_state: Option<serde_json::Value>,
    pub(super) after_state: Option<serde_json::Value>,
    pub(super) metadata: serde_json::Value,
}

pub(super) enum Claim {
    Acquired(IdempotencyLease),
    Replay(Response),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectIamBinding {
    Carbon,
    Silicon {
        organization_id: Uuid,
        membership_id: Uuid,
    },
}

pub(super) async fn begin_organization<'a>(
    state: &'a ApiState,
    authenticated: &Authenticated,
    organization_handle: &str,
) -> Result<OrganizationTransaction<'a>, AppError> {
    let credential_binding = direct_iam_binding(authenticated)?;
    let principal_id = authenticated.0.subject.id;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(principal_id))
        .await
        .map_err(database)?;
    let access = authorization::resolve_organization_access(
        &mut transaction,
        principal_id,
        organization_handle,
    )
    .await
    .map_err(map_authorization)?
    .ok_or(AppError::NotFound)?;
    context::select_organization(&mut transaction, access.organization_id)
        .await
        .map_err(database)?;
    if let DirectIamBinding::Silicon {
        organization_id,
        membership_id,
    } = credential_binding
        && (organization_id != access.organization_id || membership_id != access.membership_id)
    {
        return Err(AppError::Forbidden);
    }
    Ok(OrganizationTransaction {
        transaction,
        access,
    })
}

pub(super) fn require_carbon(authenticated: &Authenticated) -> Result<Uuid, AppError> {
    if authenticated.0.subject.actor_type != ActorType::Carbon
        || direct_iam_binding(authenticated)? != DirectIamBinding::Carbon
    {
        return Err(AppError::Forbidden);
    }
    Ok(authenticated.0.subject.id)
}

fn direct_iam_binding(authenticated: &Authenticated) -> Result<DirectIamBinding, AppError> {
    let access = &authenticated.0;
    if access.audience != "silicon-iam"
        || access.client_application_id.is_some()
        || !access.scopes.iter().any(|scope| scope == "iam.self")
    {
        return Err(AppError::Forbidden);
    }

    match (
        access.subject.actor_type,
        access.organization_id,
        access.membership_id,
    ) {
        (ActorType::Carbon, None, None) => Ok(DirectIamBinding::Carbon),
        (ActorType::Silicon, Some(organization_id), Some(membership_id)) => {
            Ok(DirectIamBinding::Silicon {
                organization_id,
                membership_id,
            })
        }
        _ => Err(AppError::Forbidden),
    }
}

pub(super) fn require_capability(
    access: &OrganizationAccess,
    capability: Capability,
) -> Result<(), AppError> {
    if access.authority.allows(capability) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub(super) async fn claim<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    route: &'static str,
    request: &T,
    contains_one_time_secret: bool,
) -> Result<Claim, AppError> {
    claim_scoped(
        transaction,
        state,
        authenticated,
        headers,
        route,
        None,
        request,
        contains_one_time_secret,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "the tenant/resource-bound idempotency inputs remain explicit at each mutation"
)]
pub(super) async fn claim_resource<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    route: &'static str,
    resource_scope: &str,
    request: &T,
    contains_one_time_secret: bool,
) -> Result<Claim, AppError> {
    claim_scoped(
        transaction,
        state,
        authenticated,
        headers,
        route,
        Some(resource_scope),
        request,
        contains_one_time_secret,
    )
    .await
}

/// Checks for a completed resource-bound replay without reserving the key.
/// The caller must commit this short transaction before external I/O and make
/// a full [`claim_resource`] in the later mutation transaction.
#[allow(
    clippy::too_many_arguments,
    reason = "the replay preflight must use the exact same explicit claim inputs"
)]
pub(super) async fn replay_resource_if_present<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    route: &'static str,
    resource_scope: &str,
    request: &T,
    contains_one_time_secret: bool,
) -> Result<Option<Response>, AppError> {
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            crate::features::organizations::validation::field("idempotency_key", "is required")
        })?;
    let key = IdempotencyKey::parse(key).map_err(|_| {
        crate::features::organizations::validation::field(
            "idempotency_key",
            "must contain 16 to 255 visible ASCII characters",
        )
    })?;
    let organization_id =
        sqlx::query_scalar::<_, Option<Uuid>>("SELECT iam_private.current_organization_id()")
            .fetch_one(&mut **transaction)
            .await
            .map_err(database)?;
    let caller_scope = SecretString::from(idempotency_caller_scope(
        authenticated.0.subject.actor_type.as_str(),
        authenticated.0.subject.id,
        organization_id,
        Some(resource_scope),
    ));
    let request_payload =
        SecretString::from(
            serde_json::to_string(request).map_err(|_| AppError::Internal {
                category: "organization_request_serialize",
            })?,
        );
    idempotency::replay_if_present(
        transaction,
        &state.crypto,
        idempotency::IdempotencyRequest {
            route,
            caller_scope: &caller_scope,
            key: &key,
            request_payload: &request_payload,
            contains_one_time_secret,
        },
    )
    .await?
    .map(|replay| replay_response(replay, contains_one_time_secret))
    .transpose()
}

#[allow(
    clippy::too_many_arguments,
    reason = "the organization and concrete resource are explicit idempotency security inputs"
)]
async fn claim_scoped<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    route: &'static str,
    resource_scope: Option<&str>,
    request: &T,
    contains_one_time_secret: bool,
) -> Result<Claim, AppError> {
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            crate::features::organizations::validation::field("idempotency_key", "is required")
        })?;
    let key = IdempotencyKey::parse(key).map_err(|_| {
        crate::features::organizations::validation::field(
            "idempotency_key",
            "must contain 16 to 255 visible ASCII characters",
        )
    })?;
    let organization_id =
        sqlx::query_scalar::<_, Option<Uuid>>("SELECT iam_private.current_organization_id()")
            .fetch_one(&mut **transaction)
            .await
            .map_err(database)?;
    let caller_scope = SecretString::from(idempotency_caller_scope(
        authenticated.0.subject.actor_type.as_str(),
        authenticated.0.subject.id,
        organization_id,
        resource_scope,
    ));
    let request_payload =
        SecretString::from(
            serde_json::to_string(request).map_err(|_| AppError::Internal {
                category: "organization_request_serialize",
            })?,
        );
    match idempotency::claim(
        transaction,
        &state.crypto,
        idempotency::IdempotencyRequest {
            route,
            caller_scope: &caller_scope,
            key: &key,
            request_payload: &request_payload,
            contains_one_time_secret,
        },
    )
    .await?
    {
        IdempotencyClaim::Acquired(lease) => Ok(Claim::Acquired(lease)),
        IdempotencyClaim::Replay(replay) => Ok(Claim::Replay(replay_response(
            replay,
            contains_one_time_secret,
        )?)),
    }
}

fn idempotency_caller_scope(
    actor_type: &str,
    actor_id: Uuid,
    organization_id: Option<Uuid>,
    resource_scope: Option<&str>,
) -> String {
    format!(
        "{actor_type}:{actor_id}:{}:{}",
        organization_id.map_or_else(|| "global".to_owned(), |id| id.to_string()),
        resource_scope.unwrap_or("collection")
    )
}

pub(super) async fn consume_step_up(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    action: &'static str,
    resource_id: Option<Uuid>,
    assurance: RequiredAssurance,
) -> Result<Uuid, AppError> {
    let carbon_id = require_carbon(authenticated)?;
    let token = headers
        .get("x-step-up-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::PreconditionRequired {
            code: "step_up_required".into(),
        })?;
    let token = StepUpToken::parse(token).map_err(|_| AppError::PreconditionFailed {
        code: "step_up_invalid".into(),
    })?;
    step_up::consume(
        transaction,
        &state.crypto,
        &token,
        StepUpExpectation {
            carbon_id,
            authentication_session_id: authenticated.0.authentication_session_id,
            action,
            resource_id,
            required_assurance: assurance,
        },
    )
    .await
}

pub(super) async fn record_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated: &Authenticated,
    organization_id: Uuid,
    event: MutationEvent<'_>,
) -> Result<(), AppError> {
    persist_mutation(transaction, authenticated, organization_id, event)
        .await
        .map(|_| ())
}

/// Records an explicitly allowlisted organization-member event and freezes
/// every per-Application projection before the domain transaction commits.
pub(super) async fn record_application_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    organization_id: Uuid,
    event: MutationEvent<'_>,
) -> Result<(), AppError> {
    let event_type = event.event_type;
    let aggregate_type = event.aggregate_type;
    let aggregate_id = event.aggregate_id;
    let aggregate_version = event.aggregate_version;
    let before_state = event.before_state.clone();
    let after_state = event.after_state.clone();
    let metadata = event.metadata.clone();
    let outbox_event_id =
        persist_mutation(transaction, authenticated, organization_id, event).await?;
    application_webhook_projections::capture_organization_application_projections(
        transaction,
        state,
        OrganizationProjectionEvent {
            outbox_event_id,
            organization_id,
            aggregate_type,
            aggregate_id,
            aggregate_version,
            event_type,
            before_state: before_state.as_ref(),
            after_state: after_state.as_ref(),
            metadata: &metadata,
        },
    )
    .await
}

async fn persist_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated: &Authenticated,
    organization_id: Uuid,
    event: MutationEvent<'_>,
) -> Result<Uuid, AppError> {
    let aggregate = AggregateVersion {
        aggregate_type: event.aggregate_type,
        aggregate_id: event.aggregate_id,
        version: event.aggregate_version,
    };
    let silicon_webhook_routing =
        silicon_webhook_routing(transaction, organization_id, &event).await?;
    let webhook_payload = webhook_payload(&event);
    events::record_audit(
        transaction,
        AuditRecord {
            actor: Some(ActorRef {
                actor_type: authenticated.0.subject.actor_type,
                id: authenticated.0.subject.id,
            }),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            organization_id: Some(organization_id),
            application_id: authenticated.0.client_application_id,
            action: event.action,
            target_type: event.target_type,
            target_id: Some(event.target_id),
            authentication_method: None,
            aggregate: Some(aggregate),
            before_state: event.before_state,
            after_state: event.after_state,
            metadata: event.metadata.clone(),
        },
    )
    .await
    .map_err(database)?;
    events::enqueue_outbox(
        transaction,
        OutboxRecord {
            organization_id: Some(organization_id),
            aggregate,
            event_ordinal: 1,
            event_type: event.event_type,
            schema_version: 1,
            payload: webhook_payload,
            silicon_webhook_routing,
        },
    )
    .await
    .map_err(database)
}

pub(super) async fn lock_membership_removal_event_scope(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
    reassign_reports_to: Option<Uuid>,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar::<_, Vec<Uuid>>(
        "SELECT iam_private.lock_membership_removal_event_scope($1, $2, $3)",
    )
    .bind(organization_id)
    .bind(membership_id)
    .bind(reassign_reports_to)
    .fetch_one(&mut **transaction)
    .await
    .map_err(transition_database)
}

async fn silicon_webhook_routing(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    event: &MutationEvent<'_>,
) -> Result<Option<SiliconWebhookRouting>, AppError> {
    let primary_membership_id = if event.target_type == "organization_membership" {
        Some(event.target_id)
    } else {
        value_uuid(&event.metadata, "membership_id")
            .or_else(|| value_uuid(&event.metadata, "target_membership_id"))
    };
    let primary_membership_id = primary_membership_id.or_else(|| {
        event
            .after_state
            .as_ref()
            .and_then(|value| value_uuid(value, "membership_id"))
            .or_else(|| {
                event
                    .before_state
                    .as_ref()
                    .and_then(|value| value_uuid(value, "membership_id"))
            })
    });
    let mut affected_membership_ids = BTreeSet::new();
    affected_membership_ids.extend(primary_membership_id);
    collect_membership_ids(&event.metadata, &mut affected_membership_ids);
    if let Some(before) = event.before_state.as_ref() {
        collect_membership_ids(before, &mut affected_membership_ids);
    }
    if let Some(after) = event.after_state.as_ref() {
        collect_membership_ids(after, &mut affected_membership_ids);
    }
    let Some(topics) = silicon_webhook_topics(event, &affected_membership_ids) else {
        return Ok(None);
    };

    let mut tag_ids = BTreeSet::new();
    collect_tag_ids(&event.metadata, &mut tag_ids);
    if let Some(before) = event.before_state.as_ref() {
        collect_tag_ids(before, &mut tag_ids);
    }
    if let Some(after) = event.after_state.as_ref() {
        collect_tag_ids(after, &mut tag_ids);
    }
    let mut before_tag_membership_ids = BTreeSet::new();
    collect_uuid_array(
        &event.metadata,
        "before_tag_membership_ids",
        &mut before_tag_membership_ids,
    );
    if let (Some(primary_membership_id), Some(before)) =
        (primary_membership_id, event.before_state.as_ref())
    {
        let mut before_tag_ids = BTreeSet::new();
        collect_tag_ids(before, &mut before_tag_ids);
        if !before_tag_ids.is_empty() {
            before_tag_membership_ids.insert(primary_membership_id);
        }
    }
    if event.target_type == "organization_tag" {
        tag_ids.insert(event.target_id);
    }
    if !affected_membership_ids.is_empty() {
        let current_tag_ids = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT tag_id
            FROM iam.membership_tags
            WHERE organization_id = $1 AND membership_id = ANY($2)
            ORDER BY tag_id
            ",
        )
        .bind(organization_id)
        .bind(affected_membership_ids.iter().copied().collect::<Vec<_>>())
        .fetch_all(&mut **transaction)
        .await
        .map_err(database)?;
        tag_ids.extend(current_tag_ids);
    }
    let affected_membership_id = if affected_membership_ids.len() == 1 {
        affected_membership_ids.first().copied()
    } else {
        None
    };
    let affected_tag_ids = tag_ids.into_iter().collect::<Vec<_>>();
    let organization_wide = affected_membership_ids.is_empty() && affected_tag_ids.is_empty();
    Ok(Some(SiliconWebhookRouting {
        topics,
        affected_membership_id,
        affected_tag_ids,
        before_tag_membership_ids: before_tag_membership_ids.into_iter().collect(),
        organization_wide,
    }))
}

fn silicon_webhook_topics(
    event: &MutationEvent<'_>,
    affected_membership_ids: &BTreeSet<Uuid>,
) -> Option<Vec<SiliconWebhookTopic>> {
    let mut topics = match event.event_type {
        "organization.membership.created.v1"
        | "organization.membership.reactivated.v1"
        | "organization.silicon.created.v1" => {
            vec![SiliconWebhookTopic::MembershipLifecycle]
        }
        "organization.membership.removed.v1" | "organization.silicon.removed.v1" => {
            let mut topics = vec![SiliconWebhookTopic::MembershipLifecycle];
            let removed_membership_id = if event.target_type == "organization_membership" {
                Some(event.target_id)
            } else {
                value_uuid(&event.metadata, "membership_id")
            };
            if affected_membership_ids
                .iter()
                .any(|membership_id| Some(*membership_id) != removed_membership_id)
            {
                topics.push(SiliconWebhookTopic::MemberUpdates);
            }
            topics
        }
        "organization.trust.default_updated.v1"
        | "organization.trust.rule_created.v1"
        | "organization.trust.rule_updated.v1"
        | "organization.trust.rule_archived.v1" => {
            vec![SiliconWebhookTopic::TrustUpdates]
        }
        "organization.membership.updated.v1" => membership_update_topics(event),
        "organization.ownership_transferred.v1"
        | "organization.membership.profile_updated.v1"
        | "organization.membership.authorization_updated.v1"
        | "organization.admin.promoted.v1"
        | "organization.admin.demoted.v1"
        | "organization.silicon.updated.v1" => vec![SiliconWebhookTopic::MemberUpdates],
        "organization.tag_updated.v1" => {
            if metadata_has_uuid_array_value(&event.metadata, "tag_assignment_membership_ids") {
                vec![SiliconWebhookTopic::MemberUpdates]
            } else {
                Vec::new()
            }
        }
        "organization.created.v1"
        | "organization.updated.v1"
        | "organization.tag_created.v1"
        | "organization.invitation.created.v1"
        | "organization.invitation.accepted.v1"
        | "organization.invitation.revoked.v1"
        | "organization.role_change.requested.v1"
        | "organization.tag_change.requested.v1"
        | "organization.approval.decided.v1"
        | "organization.silicon.rotation_requested.v1"
        | "organization.silicon.credential_rotated.v1"
        | "organization.silicon.webhook.configured.v1"
        | "organization.silicon.webhook.deleted.v1"
        | "organization.silicon.webhook_subscription.updated.v1"
        | "organization.silicon.webhook_subscription.deleted.v1" => Vec::new(),
        _ => return None,
    };
    topics.sort_unstable();
    topics.dedup();
    Some(topics)
}

fn membership_update_topics(event: &MutationEvent<'_>) -> Vec<SiliconWebhookTopic> {
    let Some(before) = event
        .before_state
        .as_ref()
        .and_then(serde_json::Value::as_object)
    else {
        return vec![SiliconWebhookTopic::MemberUpdates];
    };
    let Some(after) = event
        .after_state
        .as_ref()
        .and_then(serde_json::Value::as_object)
    else {
        return vec![SiliconWebhookTopic::MemberUpdates];
    };
    let trust_changed = before.get("default_trust") != after.get("default_trust");
    if !trust_changed {
        return vec![SiliconWebhookTopic::MemberUpdates];
    }

    let mut before_member = before.clone();
    let mut after_member = after.clone();
    for field in ["default_trust", "version", "updated_at"] {
        before_member.remove(field);
        after_member.remove(field);
    }
    let mut topics = vec![SiliconWebhookTopic::TrustUpdates];
    if before_member != after_member {
        topics.push(SiliconWebhookTopic::MemberUpdates);
    }
    topics
}

fn metadata_has_uuid_array_value(value: &serde_json::Value, key: &str) -> bool {
    let mut ids = BTreeSet::new();
    collect_uuid_array(value, key, &mut ids);
    !ids.is_empty()
}

fn webhook_payload(event: &MutationEvent<'_>) -> serde_json::Value {
    let mut payload = event.metadata.as_object().cloned().unwrap_or_default();
    payload.insert("change".to_owned(), serde_json::json!(event.action));
    payload.insert(
        "target".to_owned(),
        serde_json::json!({ "type": event.target_type, "id": event.target_id }),
    );
    payload.insert(
        "before".to_owned(),
        event
            .before_state
            .clone()
            .unwrap_or(serde_json::Value::Null),
    );
    payload.insert(
        "after".to_owned(),
        event.after_state.clone().unwrap_or(serde_json::Value::Null),
    );
    serde_json::Value::Object(payload)
}

fn value_uuid(value: &serde_json::Value, key: &str) -> Option<Uuid> {
    match value {
        serde_json::Value::Object(object) => object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .or_else(|| object.values().find_map(|value| value_uuid(value, key))),
        serde_json::Value::Array(values) => values.iter().find_map(|value| value_uuid(value, key)),
        _ => None,
    }
}

fn collect_membership_ids(value: &serde_json::Value, membership_ids: &mut BTreeSet<Uuid>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if key == "membership_id"
                    && let Some(membership_id) =
                        value.as_str().and_then(|value| Uuid::parse_str(value).ok())
                {
                    membership_ids.insert(membership_id);
                }
                if matches!(
                    key.as_str(),
                    "membership_ids"
                        | "affected_membership_ids"
                        | "before_tag_membership_ids"
                        | "tag_assignment_membership_ids"
                ) {
                    collect_direct_uuids(value, membership_ids);
                }
                collect_membership_ids(value, membership_ids);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_membership_ids(value, membership_ids);
            }
        }
        _ => {}
    }
}

fn collect_direct_uuids(value: &serde_json::Value, ids: &mut BTreeSet<Uuid>) {
    let Some(values) = value.as_array() else {
        return;
    };
    for value in values {
        if let Some(id) = value.as_str().and_then(|value| Uuid::parse_str(value).ok()) {
            ids.insert(id);
        }
    }
}

fn collect_uuid_array(value: &serde_json::Value, key: &str, ids: &mut BTreeSet<Uuid>) {
    match value {
        serde_json::Value::Object(object) => {
            for (candidate, value) in object {
                if candidate == key {
                    collect_direct_uuids(value, ids);
                }
                collect_uuid_array(value, key, ids);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_uuid_array(value, key, ids);
            }
        }
        _ => {}
    }
}

fn collect_tag_ids(value: &serde_json::Value, tag_ids: &mut BTreeSet<Uuid>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if key == "tag_id"
                    && let Some(tag_id) =
                        value.as_str().and_then(|value| Uuid::parse_str(value).ok())
                {
                    tag_ids.insert(tag_id);
                }
                if key == "tag_ids" || key == "tags" {
                    collect_direct_tag_ids(value, tag_ids);
                }
                collect_tag_ids(value, tag_ids);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_tag_ids(value, tag_ids);
            }
        }
        _ => {}
    }
}

fn collect_direct_tag_ids(value: &serde_json::Value, tag_ids: &mut BTreeSet<Uuid>) {
    let Some(values) = value.as_array() else {
        return;
    };
    for value in values {
        let candidate = value
            .as_str()
            .or_else(|| value.get("id").and_then(serde_json::Value::as_str));
        if let Some(tag_id) = candidate.and_then(|value| Uuid::parse_str(value).ok()) {
            tag_ids.insert(tag_id);
        }
    }
}

pub(super) async fn finish_json<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    lease: IdempotencyLease,
    status: StatusCode,
    value: &T,
) -> Result<Vec<u8>, AppError> {
    let bytes = serde_json::to_vec(value).map_err(|_| AppError::Internal {
        category: "organization_response_serialize",
    })?;
    idempotency::complete(transaction, &state.crypto, lease, status.as_u16(), &bytes).await?;
    Ok(bytes)
}

pub(super) async fn finish_empty(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    lease: IdempotencyLease,
    status: StatusCode,
) -> Result<(), AppError> {
    idempotency::complete(transaction, &state.crypto, lease, status.as_u16(), &[]).await
}

pub(super) fn json_response(
    status: StatusCode,
    body: Vec<u8>,
    version: Option<i64>,
    contains_secret: bool,
) -> Result<Response, AppError> {
    let mut response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|_| AppError::Internal {
            category: "organization_response_build",
        })?;
    if let Some(version) = version {
        let etag =
            HeaderValue::from_str(&format!("\"{version}\"")).map_err(|_| AppError::Internal {
                category: "organization_etag",
            })?;
        response.headers_mut().insert(http::header::ETAG, etag);
    }
    if contains_secret {
        response.headers_mut().insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        response
            .headers_mut()
            .insert(http::header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    Ok(response)
}

pub(super) fn json<T: Serialize>(
    status: StatusCode,
    value: &T,
    version: Option<i64>,
) -> Result<Response, AppError> {
    let body = serde_json::to_vec(value).map_err(|_| AppError::Internal {
        category: "organization_response_serialize",
    })?;
    json_response(status, body, version, false)
}

pub(super) fn empty(status: StatusCode) -> Response {
    status.into_response()
}

pub(super) fn database(_error: sqlx::Error) -> AppError {
    AppError::Internal {
        category: "organization_database",
    }
}

pub(super) fn conflict_from_database(error: sqlx::Error, code: &'static str) -> AppError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|database_code| matches!(database_code.as_ref(), "23505" | "23514" | "23P01"))
    {
        AppError::Conflict { code: code.into() }
    } else {
        database(error)
    }
}

pub(super) fn transition_database(error: sqlx::Error) -> AppError {
    let message = error
        .as_database_error()
        .map(sqlx::error::DatabaseError::message);

    match message {
        Some(
            "membership_version_mismatch" | "silicon_version_mismatch" | "tag_version_mismatch",
        ) => AppError::PreconditionFailed {
            code: "etag_mismatch".into(),
        },
        Some("owner_cannot_be_removed") => AppError::Conflict {
            code: "owner_cannot_be_removed".into(),
        },
        Some("reassign_reports_to_required") => AppError::Conflict {
            code: "reassign_reports_to_required".into(),
        },
        Some("invalid_reporting_hierarchy") => AppError::Conflict {
            code: "invalid_reporting_hierarchy".into(),
        },
        Some("membership_role_transition_invalid") => AppError::Conflict {
            code: "membership_role_transition_invalid".into(),
        },
        Some("membership_removal_forbidden" | "admin_role_transition_forbidden") => {
            AppError::Forbidden
        }
        _ => database(error),
    }
}

fn replay_response(
    replay: idempotency::ReplayResponse,
    contains_one_time_secret: bool,
) -> Result<Response, AppError> {
    let status = StatusCode::from_u16(replay.status).map_err(|_| AppError::Internal {
        category: "organization_replay_status",
    })?;
    let version = replay_etag_version(&replay.body);
    let mut response = json_response(status, replay.body, version, contains_one_time_secret)?;
    response.headers_mut().insert(
        HeaderNameExt::idempotency_replayed(),
        HeaderValue::from_static("true"),
    );
    Ok(response)
}

fn replay_etag_version(body: &[u8]) -> Option<i64> {
    let value = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    [
        value.get("version"),
        value.get("webhook_version"),
        value
            .get("webhook")
            .and_then(|webhook| webhook.get("version")),
    ]
    .into_iter()
    .flatten()
    .find_map(serde_json::Value::as_i64)
    .filter(|version| *version > 0)
}

fn map_authorization(error: AuthorizationError) -> AppError {
    match error {
        AuthorizationError::Database(error) => database(error),
        AuthorizationError::InvalidStoredValue => AppError::Internal {
            category: "organization_authorization_value",
        },
    }
}

struct HeaderNameExt;

impl HeaderNameExt {
    fn idempotency_replayed() -> http::HeaderName {
        http::HeaderName::from_static("idempotency-replayed")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::{
        api::authentication::Authenticated,
        domain::actor::{ActorRef, ActorType},
        infrastructure::postgres::{events::SiliconWebhookTopic, tokens::AccessContext},
    };
    use serde_json::json;

    use super::{
        DirectIamBinding, MutationEvent, collect_membership_ids, collect_tag_ids,
        direct_iam_binding, idempotency_caller_scope, replay_etag_version, require_carbon,
        silicon_webhook_topics, webhook_payload,
    };
    use uuid::Uuid;

    fn event_topics(
        event_type: &'static str,
        target_type: &'static str,
        target_id: Uuid,
        before_state: Option<serde_json::Value>,
        after_state: Option<serde_json::Value>,
        metadata: serde_json::Value,
        affected_membership_ids: impl IntoIterator<Item = Uuid>,
    ) -> Option<Vec<SiliconWebhookTopic>> {
        let event = MutationEvent {
            action: "test.change",
            target_type,
            target_id,
            aggregate_type: "test",
            aggregate_id: target_id,
            aggregate_version: 2,
            event_type,
            before_state,
            after_state,
            metadata,
        };
        silicon_webhook_topics(&event, &affected_membership_ids.into_iter().collect())
    }

    fn direct_carbon() -> Authenticated {
        Authenticated(AccessContext {
            token_id: Uuid::from_u128(1),
            authentication_session_id: Uuid::from_u128(2),
            subject: ActorRef {
                actor_type: ActorType::Carbon,
                id: Uuid::from_u128(3),
            },
            client_application_id: None,
            audience_application_id: None,
            audience: "silicon-iam".to_owned(),
            organization_id: None,
            membership_id: None,
            scopes: vec!["iam.self".to_owned()],
            assurance_level: 2,
        })
    }

    #[test]
    fn organization_access_rejects_delegated_carbon_oauth_tokens() {
        let direct = direct_carbon();
        assert!(matches!(
            direct_iam_binding(&direct),
            Ok(DirectIamBinding::Carbon)
        ));
        assert!(require_carbon(&direct).is_ok());

        let mut delegated = direct;
        delegated.0.client_application_id = Some(Uuid::from_u128(4));
        delegated.0.audience = "third-party-app".to_owned();
        assert!(direct_iam_binding(&delegated).is_err());
        assert!(require_carbon(&delegated).is_err());
    }

    #[test]
    fn silicon_iam_tokens_require_exact_tenant_binding() {
        let organization_id = Uuid::from_u128(5);
        let membership_id = Uuid::from_u128(6);
        let mut authenticated = direct_carbon();
        authenticated.0.subject.actor_type = ActorType::Silicon;
        authenticated.0.organization_id = Some(organization_id);
        authenticated.0.membership_id = Some(membership_id);

        assert!(matches!(
            direct_iam_binding(&authenticated),
            Ok(DirectIamBinding::Silicon {
                organization_id: bound_organization_id,
                membership_id: bound_membership_id,
            }) if bound_organization_id == organization_id && bound_membership_id == membership_id
        ));

        authenticated.0.membership_id = None;
        assert!(direct_iam_binding(&authenticated).is_err());
    }

    #[test]
    fn idempotency_scope_binds_tenant_and_concrete_resource() {
        let actor_id = Uuid::from_u128(1);
        let first_org = Uuid::from_u128(2);
        let second_org = Uuid::from_u128(3);

        let first =
            idempotency_caller_scope("carbon", actor_id, Some(first_org), Some("membership-a"));
        assert_ne!(
            first,
            idempotency_caller_scope("carbon", actor_id, Some(second_org), Some("membership-a"))
        );
        assert_ne!(
            first,
            idempotency_caller_scope("carbon", actor_id, Some(first_org), Some("membership-b"))
        );
        assert_ne!(
            first,
            idempotency_caller_scope("carbon", actor_id, Some(first_org), None)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the table-driven event vocabulary is most reviewable as one exhaustive contract test"
    )]
    fn webhook_topic_catalog_keeps_trust_separate_and_fails_closed() {
        let target_id = Uuid::from_u128(31);
        assert_eq!(
            event_topics(
                "organization.membership.created.v1",
                "organization_membership",
                target_id,
                None,
                None,
                json!({}),
                [target_id],
            ),
            Some(vec![SiliconWebhookTopic::MembershipLifecycle])
        );
        assert_eq!(
            event_topics(
                "organization.membership.updated.v1",
                "organization_membership",
                target_id,
                Some(json!({ "job_role": "Engineer", "version": 1 })),
                Some(json!({ "job_role": "Staff Engineer", "version": 2 })),
                json!({}),
                [target_id],
            ),
            Some(vec![SiliconWebhookTopic::MemberUpdates])
        );
        assert_eq!(
            event_topics(
                "organization.membership.profile_updated.v1",
                "organization_membership",
                target_id,
                None,
                None,
                json!({}),
                [target_id],
            ),
            Some(vec![SiliconWebhookTopic::MemberUpdates])
        );
        assert_eq!(
            event_topics(
                "organization.trust.rule_updated.v1",
                "trust_rule",
                target_id,
                None,
                None,
                json!({}),
                [],
            ),
            Some(vec![SiliconWebhookTopic::TrustUpdates])
        );
        let other_membership_id = Uuid::from_u128(32);
        assert_eq!(
            event_topics(
                "organization.silicon.removed.v1",
                "silicon",
                Uuid::from_u128(33),
                None,
                None,
                json!({ "membership_id": target_id }),
                [target_id, other_membership_id],
            ),
            Some(vec![
                SiliconWebhookTopic::MembershipLifecycle,
                SiliconWebhookTopic::MemberUpdates,
            ])
        );
        assert_eq!(
            event_topics(
                "organization.silicon.removed.v1",
                "silicon",
                Uuid::from_u128(33),
                None,
                None,
                json!({ "membership_id": target_id }),
                [target_id],
            ),
            Some(vec![SiliconWebhookTopic::MembershipLifecycle])
        );
        assert_eq!(
            event_topics(
                "organization.updated.v1",
                "organization",
                target_id,
                None,
                None,
                json!({}),
                [],
            ),
            Some(Vec::new())
        );
        assert_eq!(
            event_topics(
                "organization.invitation.created.v1",
                "invitation",
                target_id,
                None,
                None,
                json!({}),
                [],
            ),
            Some(Vec::new())
        );
        assert_eq!(
            event_topics(
                "organization.silicon.webhook.configured.v1",
                "silicon_webhook",
                target_id,
                None,
                None,
                json!({}),
                [],
            ),
            Some(Vec::new())
        );
        assert_eq!(
            event_topics(
                "organization.silicon.webhook_subscription.updated.v1",
                "silicon_webhook_subscription",
                target_id,
                None,
                None,
                json!({}),
                [],
            ),
            Some(Vec::new())
        );
        assert_eq!(
            event_topics(
                "authentication.session.revoked.v1",
                "authentication_session",
                target_id,
                None,
                None,
                json!({}),
                [],
            ),
            None
        );
    }

    #[test]
    fn every_organization_event_in_the_full_catalog_has_explicit_routing() {
        let target_id = Uuid::from_u128(35);
        for event_type in crate::domain::events::SILICON_FULL_EVENT_TYPES
            .iter()
            .filter(|event_type| event_type.starts_with("organization."))
        {
            assert!(
                event_topics(
                    event_type,
                    "organization_membership",
                    target_id,
                    None,
                    None,
                    json!({}),
                    [],
                )
                .is_some(),
                "missing explicit Silicon Full routing for {event_type}"
            );
        }
    }

    #[test]
    fn membership_update_topics_split_trust_only_mixed_and_directory_changes() {
        let target_id = Uuid::from_u128(34);
        let before_trust = json!({ "boundary": "internal", "level": "trusted" });
        let after_trust = json!({ "boundary": "external", "level": "not_trusted" });
        let topics = |before, after| {
            event_topics(
                "organization.membership.updated.v1",
                "organization_membership",
                target_id,
                Some(before),
                Some(after),
                json!({ "membership_id": target_id }),
                [target_id],
            )
        };

        assert_eq!(
            topics(
                json!({ "job_role": "Engineer", "default_trust": before_trust, "version": 1 }),
                json!({ "job_role": "Engineer", "default_trust": after_trust, "version": 2 }),
            ),
            Some(vec![SiliconWebhookTopic::TrustUpdates])
        );
        assert_eq!(
            topics(
                json!({ "job_role": "Engineer", "default_trust": before_trust, "version": 1 }),
                json!({ "job_role": "Lead", "default_trust": after_trust, "version": 2 }),
            ),
            Some(vec![
                SiliconWebhookTopic::MemberUpdates,
                SiliconWebhookTopic::TrustUpdates,
            ])
        );
    }

    #[test]
    fn tag_topics_reflect_exact_member_and_trust_rule_effects() {
        let tag_id = Uuid::from_u128(35);
        let membership_id = Uuid::from_u128(36);
        assert_eq!(
            event_topics(
                "organization.tag_updated.v1",
                "tag",
                tag_id,
                None,
                None,
                json!({
                    "tag_id": tag_id,
                    "tag_assignment_membership_ids": [membership_id],
                }),
                [membership_id],
            ),
            Some(vec![SiliconWebhookTopic::MemberUpdates])
        );
        assert_eq!(
            event_topics(
                "organization.tag_updated.v1",
                "tag",
                tag_id,
                None,
                None,
                json!({ "tag_id": tag_id }),
                [],
            ),
            Some(Vec::new())
        );
    }

    #[test]
    fn routing_tag_extraction_keeps_before_and_after_audiences() {
        let before = Uuid::from_u128(11);
        let after = Uuid::from_u128(12);
        let selector = Uuid::from_u128(13);
        let mut tag_ids = BTreeSet::new();

        collect_tag_ids(
            &json!({
                "before": { "tags": [{ "id": before }] },
                "after": { "tag_ids": [after] },
                "selector": { "tag_id": selector }
            }),
            &mut tag_ids,
        );

        assert_eq!(tag_ids, BTreeSet::from([before, after, selector]));
    }

    #[test]
    fn trust_routing_collects_every_membership_selector() {
        let subject = Uuid::from_u128(14);
        let target = Uuid::from_u128(15);
        let mut membership_ids = BTreeSet::new();

        collect_membership_ids(
            &json!({
                "subject": { "kind": "membership", "membership_id": subject },
                "target": { "kind": "membership", "membership_id": target }
            }),
            &mut membership_ids,
        );

        assert_eq!(membership_ids, BTreeSet::from([subject, target]));
    }

    #[test]
    fn webhook_payload_keeps_routing_private_and_exposes_redacted_change_state() {
        let target_id = Uuid::from_u128(21);
        let event = MutationEvent {
            action: "membership.updated",
            target_type: "organization_membership",
            target_id,
            aggregate_type: "organization_membership",
            aggregate_id: target_id,
            aggregate_version: 2,
            event_type: "organization.membership.updated.v1",
            before_state: Some(json!({ "job_role": "Engineer" })),
            after_state: Some(json!({ "job_role": "Staff Engineer" })),
            metadata: json!({ "membership_id": target_id }),
        };

        let payload = webhook_payload(&event);

        assert_eq!(payload["membership_id"], json!(target_id));
        assert_eq!(payload["change"], "membership.updated");
        assert_eq!(payload["target"]["id"], json!(target_id));
        assert_eq!(payload["before"]["job_role"], "Engineer");
        assert_eq!(payload["after"]["job_role"], "Staff Engineer");
        assert!(payload.get("topics").is_none());
        assert!(payload.get("affected_tag_ids").is_none());
    }

    #[test]
    fn idempotent_json_replays_recover_the_original_resource_version() {
        assert_eq!(replay_etag_version(br#"{"version":7}"#), Some(7));
        assert_eq!(
            replay_etag_version(br#"{"webhook":{"version":8}}"#),
            Some(8)
        );
        assert_eq!(
            replay_etag_version(br#"{"webhook_version":9,"secret_version":2}"#),
            Some(9)
        );
        assert_eq!(replay_etag_version(br#"{"version":0}"#), None);
    }
}
