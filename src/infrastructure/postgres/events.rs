//! Transactional audit and outbox persistence primitives.

use std::collections::BTreeSet;

use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{domain::actor::ActorRef, request_context};

/// Events whose Application recipients and wire data must come exclusively
/// from immutable per-recipient projections captured by the domain mutation.
///
/// Keep this vocabulary closed: protocol/configuration events continue to use
/// their deliberately minimal direct-subject routing, and Carbon profile
/// membership notifications remain Silicon-only to avoid duplicate
/// Application delivery alongside `carbon.updated.v1`.
#[must_use]
pub fn uses_captured_application_webhook_projection(event_type: &str) -> bool {
    matches!(
        event_type,
        "carbon.updated.v1"
            | "organization.updated.v1"
            | "organization.ownership_transferred.v1"
            | "organization.tag_updated.v1"
            | "organization.tag_archived.v1"
            | "organization.trust.default_updated.v1"
            | "organization.trust.rule_created.v1"
            | "organization.trust.rule_updated.v1"
            | "organization.trust.rule_archived.v1"
            | "organization.membership.created.v1"
            | "organization.membership.reactivated.v1"
            | "organization.membership.removed.v1"
            | "organization.membership.updated.v1"
            | "organization.membership.authorization_updated.v1"
            | "organization.admin.promoted.v1"
            | "organization.admin.demoted.v1"
            | "organization.silicon.created.v1"
            | "organization.silicon.updated.v1"
            | "organization.silicon.removed.v1"
            | "organization.silicon.credential_rotated.v1"
    )
}

/// Redacted security audit record committed with a domain mutation.
pub struct AuditRecord<'a> {
    /// Actor responsible for the mutation; absent only for system maintenance.
    pub actor: Option<ActorRef>,
    /// Parent authentication session when the actor is interactive.
    pub authentication_session_id: Option<Uuid>,
    /// Organization boundary, when applicable.
    pub organization_id: Option<Uuid>,
    /// Application boundary, when applicable.
    pub application_id: Option<Uuid>,
    /// Stable dotted action vocabulary.
    pub action: &'static str,
    /// Stable target type.
    pub target_type: &'static str,
    /// Target UUID, when the target already exists.
    pub target_id: Option<Uuid>,
    /// Authentication method used for the request.
    pub authentication_method: Option<&'static str>,
    /// Aggregate identity and new exact version.
    pub aggregate: Option<AggregateVersion<'a>>,
    /// Redacted externally visible prior state.
    pub before_state: Option<Value>,
    /// Redacted externally visible new state.
    pub after_state: Option<Value>,
    /// Redacted supplemental metadata.
    pub metadata: Value,
}

/// Aggregate identity captured by audit and outbox ordering.
#[derive(Clone, Copy)]
pub struct AggregateVersion<'a> {
    /// Stable aggregate type.
    pub aggregate_type: &'a str,
    /// Aggregate UUID.
    pub aggregate_id: Uuid,
    /// Exact version after the mutation.
    pub version: i64,
}

/// Minimal versioned integration event committed with a domain mutation.
pub struct OutboxRecord<'a> {
    /// Optional organization boundary.
    pub organization_id: Option<Uuid>,
    /// Aggregate ordering identity.
    pub aggregate: AggregateVersion<'a>,
    /// Ordinal when one mutation emits multiple events at one version.
    pub event_ordinal: i16,
    /// Stable dotted event name.
    pub event_type: &'a str,
    /// Event schema version.
    pub schema_version: i16,
    /// Minimal secret-free object payload.
    pub payload: Value,
    /// Optional, private routing metadata for configurable Silicon webhooks.
    pub silicon_webhook_routing: Option<SiliconWebhookRouting>,
}

/// Closed Silicon webhook topic vocabulary persisted separately from wire data.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SiliconWebhookTopic {
    /// Carbon or Silicon organization membership lifecycle changes.
    MembershipLifecycle,
    /// Existing organization member directory and authorization changes.
    MemberUpdates,
    /// Organization default or rule-level trust changes.
    TrustUpdates,
}

impl SiliconWebhookTopic {
    const fn as_str(self) -> &'static str {
        match self {
            Self::MembershipLifecycle => "membership_lifecycle",
            Self::MemberUpdates => "member_updates",
            Self::TrustUpdates => "trust_updates",
        }
    }
}

/// Private subscription-routing context captured in the domain transaction.
///
/// This data is intentionally normalized outside the outbox payload so internal
/// routing decisions never become part of the public webhook contract.
#[derive(Debug)]
pub struct SiliconWebhookRouting {
    /// One or more closed subscription topics.
    pub topics: Vec<SiliconWebhookTopic>,
    /// Organization membership affected by the event, when applicable.
    pub affected_membership_id: Option<Uuid>,
    /// Union of affected tags before and after the mutation.
    pub affected_tag_ids: Vec<Uuid>,
    /// Memberships whose pre-mutation tags must participate in own-tag routing.
    ///
    /// Enqueueing combines these IDs with the post-mutation tag intersection
    /// while the domain transaction is still open, producing one immutable
    /// event-time audience. Delivery never hydrates later tag membership.
    pub before_tag_membership_ids: Vec<Uuid>,
    /// Whether the event concerns the organization rather than a taggable member.
    pub organization_wide: bool,
}

/// Inserts an append-only audit event in the caller's transaction.
///
/// # Errors
///
/// Returns an error if PostgreSQL rejects the redacted event or any reference.
pub async fn record_audit(
    transaction: &mut Transaction<'_, Postgres>,
    record: AuditRecord<'_>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    let request_id = request_context::current_request_uuid().unwrap_or_else(Uuid::now_v7);
    let (actor_id, actor_kind) = record.actor.map_or((None, None), |actor| {
        (Some(actor.id), Some(actor.actor_type.as_str()))
    });
    let (aggregate_type, aggregate_id, aggregate_version) =
        record.aggregate.map_or((None, None, None), |aggregate| {
            (
                Some(aggregate.aggregate_type),
                Some(aggregate.aggregate_id),
                Some(aggregate.version),
            )
        });

    sqlx::query(
        r"
        INSERT INTO iam.audit_events (
            occurred_at, id, request_id, actor_principal_id, actor_kind,
            actor_authentication_session_id, organization_id, application_id,
            action, target_type, target_id, authentication_method,
            aggregate_type, aggregate_id, aggregate_version,
            before_state, after_state, metadata
        ) VALUES (
            transaction_timestamp(), $1, $2, $3, $4::iam.principal_kind,
            $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
        )
        ",
    )
    .bind(id)
    .bind(request_id)
    .bind(actor_id)
    .bind(actor_kind)
    .bind(record.authentication_session_id)
    .bind(record.organization_id)
    .bind(record.application_id)
    .bind(record.action)
    .bind(record.target_type)
    .bind(record.target_id)
    .bind(record.authentication_method)
    .bind(aggregate_type)
    .bind(aggregate_id)
    .bind(aggregate_version)
    .bind(record.before_state)
    .bind(record.after_state)
    .bind(record.metadata)
    .execute(&mut **transaction)
    .await?;
    Ok(id)
}

/// Inserts one durable integration event in the caller's transaction.
///
/// # Errors
///
/// Returns an error if PostgreSQL rejects the event shape, ordering identity,
/// or organization reference.
pub async fn enqueue_outbox(
    transaction: &mut Transaction<'_, Postgres>,
    record: OutboxRecord<'_>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    let silicon_webhook_routable =
        is_silicon_webhook_routable(record.silicon_webhook_routing.as_ref());
    let own_tag_membership_ids = capture_own_tag_membership_ids(
        transaction,
        record.organization_id,
        record.silicon_webhook_routing.as_ref(),
    )
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.outbox_events (
            id, organization_id, aggregate_type, aggregate_id,
            aggregate_version, event_ordinal, event_type, schema_version,
            payload, affected_membership_id, organization_wide,
            silicon_webhook_routable
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ",
    )
    .bind(id)
    .bind(record.organization_id)
    .bind(record.aggregate.aggregate_type)
    .bind(record.aggregate.aggregate_id)
    .bind(record.aggregate.version)
    .bind(record.event_ordinal)
    .bind(record.event_type)
    .bind(record.schema_version)
    .bind(record.payload)
    .bind(
        record
            .silicon_webhook_routing
            .as_ref()
            .and_then(|routing| routing.affected_membership_id),
    )
    .bind(
        record
            .silicon_webhook_routing
            .as_ref()
            .is_some_and(|routing| routing.organization_wide),
    )
    .bind(silicon_webhook_routable)
    .execute(&mut **transaction)
    .await?;

    if let Some(routing) = record.silicon_webhook_routing {
        for topic in routing.topics {
            sqlx::query(
                r"
                INSERT INTO iam.outbox_event_topics (outbox_event_id, topic)
                VALUES ($1, $2)
                ON CONFLICT (outbox_event_id, topic) DO NOTHING
                ",
            )
            .bind(id)
            .bind(topic.as_str())
            .execute(&mut **transaction)
            .await?;
        }
        for tag_id in routing.affected_tag_ids {
            sqlx::query(
                r"
                INSERT INTO iam.outbox_event_affected_tags (outbox_event_id, tag_id)
                VALUES ($1, $2)
                ON CONFLICT (outbox_event_id, tag_id) DO NOTHING
                ",
            )
            .bind(id)
            .bind(tag_id)
            .execute(&mut **transaction)
            .await?;
        }
    }
    for membership_id in own_tag_membership_ids {
        sqlx::query(
            r"
            INSERT INTO iam.outbox_event_own_tag_memberships (
                outbox_event_id, membership_id
            ) VALUES ($1, $2)
            ON CONFLICT (outbox_event_id, membership_id) DO NOTHING
            ",
        )
        .bind(id)
        .bind(membership_id)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(id)
}

async fn capture_own_tag_membership_ids(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Option<Uuid>,
    routing: Option<&SiliconWebhookRouting>,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let (Some(organization_id), Some(routing)) = (organization_id, routing) else {
        return Ok(Vec::new());
    };
    if routing.affected_tag_ids.is_empty() {
        return Ok(Vec::new());
    }
    let before_membership_ids = routing
        .before_tag_membership_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let affected_tag_ids = routing
        .affected_tag_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT membership_id
        FROM iam_private.lock_silicon_webhook_own_tag_audience($1, $2, $3)
        ",
    )
    .bind(organization_id)
    .bind(affected_tag_ids)
    .bind(before_membership_ids)
    .fetch_all(&mut **transaction)
    .await
}

const fn is_silicon_webhook_routable(routing: Option<&SiliconWebhookRouting>) -> bool {
    routing.is_some()
}

#[cfg(test)]
mod tests {
    use super::{
        SiliconWebhookRouting, is_silicon_webhook_routable,
        uses_captured_application_webhook_projection,
    };

    #[test]
    fn captured_application_event_vocabulary_excludes_silicon_only_profile_fanout() {
        assert!(uses_captured_application_webhook_projection(
            "carbon.updated.v1"
        ));
        assert!(uses_captured_application_webhook_projection(
            "organization.membership.authorization_updated.v1"
        ));
        assert!(uses_captured_application_webhook_projection(
            "organization.silicon.credential_rotated.v1"
        ));
        assert!(!uses_captured_application_webhook_projection(
            "organization.membership.profile_updated.v1"
        ));
        assert!(!uses_captured_application_webhook_projection(
            "organization.silicon.rotation_requested.v1"
        ));
        assert!(!uses_captured_application_webhook_projection(
            "organization.silicon.webhook.configured.v1"
        ));
    }

    #[test]
    fn an_empty_topic_set_is_full_only_not_unrouted() {
        let full_only = SiliconWebhookRouting {
            topics: Vec::new(),
            affected_membership_id: None,
            affected_tag_ids: Vec::new(),
            before_tag_membership_ids: Vec::new(),
            organization_wide: true,
        };

        assert!(is_silicon_webhook_routable(Some(&full_only)));
        assert!(!is_silicon_webhook_routable(None));
    }
}
