//! Transactional Silicon-webhook projections for Carbon profile changes.

use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    error::AppError,
    infrastructure::postgres::events::{
        self, AggregateVersion, OutboxRecord, SiliconWebhookRouting, SiliconWebhookTopic,
    },
};

use super::{directory, support};

const EVENT_TYPE: &str = "organization.membership.profile_updated.v1";

#[derive(Debug, sqlx::FromRow)]
struct ActiveCarbonMembership {
    organization_id: Uuid,
    membership_id: Uuid,
}

/// Same-transaction organization and tag scope for one Carbon membership.
///
/// Capturing this before the profile mutation serializes membership removal and
/// tag changes behind the profile event. The serialized membership projection
/// is the same complete state that an active same-organization principal can
/// read through the membership API.
#[derive(Debug)]
pub(crate) struct CarbonProfileSiliconRoute {
    organization_id: Uuid,
    membership_id: Uuid,
    affected_tag_ids: Vec<Uuid>,
    membership: Value,
}

/// Locks and snapshots every active organization membership for a Carbon.
pub(crate) async fn capture_carbon_profile_silicon_routes(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
) -> Result<Vec<CarbonProfileSiliconRoute>, AppError> {
    let memberships = sqlx::query_as::<_, ActiveCarbonMembership>(
        r"
        SELECT
            membership.organization_id,
            membership.id AS membership_id
        FROM iam.organization_memberships AS membership
        JOIN iam.organizations AS organization
          ON organization.id = membership.organization_id
         AND organization.status = 'active'
        WHERE membership.principal_id = $1
          AND membership.principal_kind = 'carbon'
          AND membership.status = 'active'
        ORDER BY membership.organization_id, membership.id
        FOR SHARE OF membership, organization
        ",
    )
    .bind(carbon_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(support::database)?;

    let mut routes = Vec::with_capacity(memberships.len());
    for membership in memberships {
        let affected_tag_ids = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT assignment.tag_id
            FROM iam.membership_tags AS assignment
            JOIN iam.organization_tags AS tag
              ON tag.organization_id = assignment.organization_id
             AND tag.id = assignment.tag_id
             AND tag.status = 'active'
            WHERE assignment.organization_id = $1
              AND assignment.membership_id = $2
            ORDER BY assignment.tag_id
            FOR SHARE OF assignment, tag
            ",
        )
        .bind(membership.organization_id)
        .bind(membership.membership_id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(support::database)?;
        let current = directory::fetch_member(
            transaction,
            membership.organization_id,
            membership.membership_id,
        )
        .await?;
        let current = serde_json::to_value(current).map_err(|_| AppError::Internal {
            category: "carbon_profile_membership_projection",
        })?;
        routes.push(CarbonProfileSiliconRoute {
            organization_id: membership.organization_id,
            membership_id: membership.membership_id,
            affected_tag_ids,
            membership: current,
        });
    }
    Ok(routes)
}

/// Persists one immutable, organization-bound Silicon event per captured route.
///
/// The caller has already written the single global audit record and
/// Application event. These rows are delivery projections of that same Carbon
/// mutation, not additional mutations or audit actions.
pub(crate) async fn enqueue_carbon_profile_silicon_events(
    transaction: &mut Transaction<'_, Postgres>,
    profile_version: i64,
    changed_fields: &[&str],
    before_profile: &Value,
    after_profile: &Value,
    routes: &[CarbonProfileSiliconRoute],
) -> Result<(), AppError> {
    let before_profile = authorized_profile_state(before_profile)?;
    let after_profile = authorized_profile_state(after_profile)?;
    for route in routes {
        let payload = silicon_event_payload(route, changed_fields, &before_profile, &after_profile);
        events::enqueue_outbox(
            transaction,
            OutboxRecord {
                organization_id: Some(route.organization_id),
                aggregate: AggregateVersion {
                    aggregate_type: "organization_membership_profile",
                    aggregate_id: route.membership_id,
                    version: profile_version,
                },
                event_ordinal: 1,
                event_type: EVENT_TYPE,
                schema_version: 1,
                payload,
                silicon_webhook_routing: Some(SiliconWebhookRouting {
                    topics: vec![SiliconWebhookTopic::MemberUpdates],
                    affected_membership_id: Some(route.membership_id),
                    affected_tag_ids: route.affected_tag_ids.clone(),
                    before_tag_membership_ids: Vec::new(),
                    organization_wide: false,
                }),
            },
        )
        .await
        .map_err(support::database)?;
    }
    Ok(())
}

fn authorized_profile_state(profile: &Value) -> Result<Value, AppError> {
    let source = profile.as_object().ok_or(AppError::Internal {
        category: "carbon_profile_silicon_projection",
    })?;
    let mut projected = serde_json::Map::new();
    for field in [
        "principal_id",
        "carbon_id",
        "display_name",
        "timezone",
        "description",
        "profile_photo",
        "status",
        "version",
        "created_at",
        "updated_at",
    ] {
        let value = source.get(field).ok_or(AppError::Internal {
            category: "carbon_profile_silicon_projection",
        })?;
        projected.insert(field.to_owned(), value.clone());
    }
    Ok(Value::Object(projected))
}

fn silicon_event_payload(
    route: &CarbonProfileSiliconRoute,
    changed_fields: &[&str],
    before_profile: &Value,
    after_profile: &Value,
) -> Value {
    let before = json!({
        "profile": before_profile,
        "membership": route.membership,
    });
    let current = json!({
        "profile": after_profile,
        "membership": route.membership,
    });
    json!({
        "change": "carbon.profile_update",
        "target": {
            "type": "organization_membership",
            "id": route.membership_id,
        },
        "membership_id": route.membership_id,
        "changed_fields": changed_fields,
        "affected_tags": {
            "before": route.affected_tag_ids,
            "after": route.affected_tag_ids,
        },
        "before": before,
        "after": current,
        "current": current,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use super::{CarbonProfileSiliconRoute, authorized_profile_state, silicon_event_payload};

    fn profile(display_name: &str) -> serde_json::Value {
        json!({
            "principal_id": Uuid::from_u128(1),
            "carbon_id": "carbon-one",
            "display_name": display_name,
            "timezone": "UTC",
            "description": "Engineer",
            "profile_photo": "https://iris.example/pfp/carbon?id=carbon-one",
            "email": "private@example.test",
            "phone_number": "+15555550100",
            "status": "active",
            "version": 2,
            "created_at": "2026-09-01T00:00:00Z",
            "updated_at": "2026-09-01T00:01:00Z",
            "future_secret": "must-not-be-forwarded",
        })
    }

    #[test]
    fn profile_projection_is_allowlisted_and_contact_free() {
        let Ok(projected) = authorized_profile_state(&profile("After")) else {
            panic!("valid Carbon profile must project");
        };
        assert_eq!(projected["display_name"], "After");
        for forbidden in ["email", "phone_number", "future_secret"] {
            assert!(projected.get(forbidden).is_none());
        }
    }

    #[test]
    fn silicon_payload_keeps_exact_state_and_both_tag_audiences() {
        let membership_id = Uuid::from_u128(2);
        let first_tag = Uuid::from_u128(3);
        let second_tag = Uuid::from_u128(4);
        let route = CarbonProfileSiliconRoute {
            organization_id: Uuid::from_u128(5),
            membership_id,
            affected_tag_ids: vec![first_tag, second_tag],
            membership: json!({
                "id": membership_id,
                "job_role": "Engineer",
                "tags": [{ "id": first_tag }, { "id": second_tag }],
                "version": 7,
            }),
        };
        let Ok(before) = authorized_profile_state(&profile("Before")) else {
            panic!("valid before profile must project");
        };
        let Ok(after) = authorized_profile_state(&profile("Captured")) else {
            panic!("valid after profile must project");
        };
        let payload = silicon_event_payload(&route, &["display_name"], &before, &after);

        assert_eq!(payload["changed_fields"], json!(["display_name"]));
        assert_eq!(payload["before"]["profile"]["display_name"], "Before");
        assert_eq!(payload["current"]["profile"]["display_name"], "Captured");
        assert_eq!(payload["current"]["membership"]["job_role"], "Engineer");
        assert_eq!(
            payload["affected_tags"]["before"],
            json!([first_tag, second_tag])
        );
        assert_eq!(
            payload["affected_tags"]["after"],
            json!([first_tag, second_tag])
        );
    }
}
