#![allow(clippy::too_many_lines)]

use std::borrow::Cow;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Serialize;
use serde_json::json;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    error::AppError,
};

use super::{
    super::{
        model::{
            SiliconWebhookSubscriptionMode, SiliconWebhookSubscriptionReplace,
            SiliconWebhookSubscriptionResponse, SiliconWebhookTagFilter, SiliconWebhookTopic,
        },
        silicons,
        support::{self, Claim, MutationEvent},
        validation,
    },
    shared::{self, TargetSilicon},
};

const SUBSCRIPTION_REPLACE_ROUTE: &str =
    "PUT /api/v1/organizations/{org_id}/silicons/{silicon_id}/webhook/subscription";
const SUBSCRIPTION_DELETE_ROUTE: &str =
    "DELETE /api/v1/organizations/{org_id}/silicons/{silicon_id}/webhook/subscription";

#[derive(Clone, Debug, Serialize)]
struct CanonicalSubscription {
    mode: SiliconWebhookSubscriptionMode,
    topics: Vec<SiliconWebhookTopic>,
    tag_filter: Option<SiliconWebhookTagFilter>,
}

#[derive(Debug, FromRow)]
struct SubscriptionRow {
    silicon_id: String,
    mode: String,
    topics: Vec<String>,
    tag_filter_enabled: bool,
    additional_tag_ids: Vec<Uuid>,
    version: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, FromRow)]
struct SubscriptionIdentity {
    id: Uuid,
    version: i64,
}

pub(in crate::features::organizations) async fn get_subscription(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    silicons::validate_global_silicon_id(&silicon_id, &org_id)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let target = shared::load_target(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    shared::authorize(&authenticated, &scope.access, &target)?;
    let response = load_subscription(
        &mut scope.transaction,
        scope.access.organization_id,
        &target,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &response, Some(response.version))
}

pub(in crate::features::organizations) async fn replace_subscription(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<SiliconWebhookSubscriptionReplace>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    silicons::validate_global_silicon_id(&silicon_id, &org_id)?;
    let canonical = canonicalize(input)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let target = shared::load_target(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    shared::authorize_identity(&authenticated, &scope.access, &target)?;
    let claim_request = replace_claim_request(
        scope.access.organization_id,
        target.principal_id,
        &canonical,
    );
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        SUBSCRIPTION_REPLACE_ROUTE,
        &silicon_id,
        &claim_request,
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
    shared::consume_carbon_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        "organization.silicon_webhook.redirect",
        &target,
    )
    .await?;
    let endpoint_id = lock_active_endpoint(
        &mut scope.transaction,
        scope.access.organization_id,
        target.principal_id,
    )
    .await?
    .ok_or(AppError::Conflict {
        code: Cow::Borrowed("silicon_webhook_endpoint_required"),
    })?;
    shared::lock_delivery_scope(&mut scope.transaction, endpoint_id).await?;
    shared::cancel_deliveries(
        &mut scope.transaction,
        scope.access.organization_id,
        endpoint_id,
        "subscription_replaced",
    )
    .await?;
    let existing = sqlx::query_as::<_, SubscriptionIdentity>(
        r"
        SELECT id, version
        FROM iam.silicon_webhook_subscriptions
        WHERE organization_id = $1 AND silicon_id = $2
        FOR UPDATE
        ",
    )
    .bind(scope.access.organization_id)
    .bind(target.principal_id)
    .fetch_optional(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    enforce_existing_version(&headers, existing.map(|subscription| subscription.version))?;
    let subscription_id = existing.map_or_else(Uuid::now_v7, |subscription| subscription.id);
    let version = if existing.is_some() {
        sqlx::query_scalar::<_, i64>(
            r"
            UPDATE iam.silicon_webhook_subscriptions
            SET endpoint_id = $3, mode = $4, tag_filter_enabled = $5,
                updated_at = transaction_timestamp()
            WHERE organization_id = $1 AND silicon_id = $2
            RETURNING version
            ",
        )
        .bind(scope.access.organization_id)
        .bind(target.principal_id)
        .bind(endpoint_id)
        .bind(canonical.mode.as_str())
        .bind(canonical.tag_filter.is_some())
        .fetch_one(&mut *scope.transaction)
        .await
        .map_err(support::database)?
    } else {
        sqlx::query_scalar::<_, i64>(
            r"
            INSERT INTO iam.silicon_webhook_subscriptions (
                id, organization_id, silicon_id, endpoint_id, mode, tag_filter_enabled
            ) VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING version
            ",
        )
        .bind(subscription_id)
        .bind(scope.access.organization_id)
        .bind(target.principal_id)
        .bind(endpoint_id)
        .bind(canonical.mode.as_str())
        .bind(canonical.tag_filter.is_some())
        .fetch_one(&mut *scope.transaction)
        .await
        .map_err(support::database)?
    };
    sqlx::query("DELETE FROM iam.silicon_webhook_subscription_topics WHERE subscription_id = $1")
        .bind(subscription_id)
        .execute(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    if canonical.mode == SiliconWebhookSubscriptionMode::Selected {
        for topic in &canonical.topics {
            sqlx::query(
                r"
                INSERT INTO iam.silicon_webhook_subscription_topics (subscription_id, topic)
                VALUES ($1, $2)
                ",
            )
            .bind(subscription_id)
            .bind(topic.as_str())
            .execute(&mut *scope.transaction)
            .await
            .map_err(support::database)?;
        }
    }
    sqlx::query(
        "DELETE FROM iam.silicon_webhook_subscription_extra_tags WHERE subscription_id = $1",
    )
    .bind(subscription_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if let Some(tag_filter) = &canonical.tag_filter {
        validate_active_filter_tags(
            &mut scope.transaction,
            scope.access.organization_id,
            &tag_filter.additional_tag_ids,
        )
        .await?;
        for tag_id in &tag_filter.additional_tag_ids {
            sqlx::query(
                r"
                INSERT INTO iam.silicon_webhook_subscription_extra_tags (
                    organization_id, subscription_id, tag_id
                ) VALUES ($1, $2, $3)
                ",
            )
            .bind(scope.access.organization_id)
            .bind(subscription_id)
            .bind(tag_id)
            .execute(&mut *scope.transaction)
            .await
            .map_err(support::database)?;
        }
    }
    let response = load_subscription(
        &mut scope.transaction,
        scope.access.organization_id,
        &target,
    )
    .await?;
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "silicon.webhook_subscription.replace",
            target_type: "silicon_webhook_subscription",
            target_id: subscription_id,
            aggregate_type: "silicon_webhook_subscription",
            aggregate_id: subscription_id,
            aggregate_version: version,
            event_type: "organization.silicon.webhook_subscription.updated.v1",
            before_state: existing.map(|subscription| {
                json!({
                    "subscription_id": subscription.id,
                    "version": subscription.version,
                })
            }),
            after_state: Some(json!({
                "mode": canonical.mode,
                "topics": canonical.topics,
                "tag_filter": canonical.tag_filter,
            })),
            metadata: json!({
                "silicon_id": target.principal_id,
                "membership_id": target.membership_id,
                "endpoint_id": endpoint_id,
                "subscription_id": subscription_id,
            }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &response,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(version), false)
}

pub(in crate::features::organizations) async fn delete_subscription(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    silicons::validate_global_silicon_id(&silicon_id, &org_id)?;
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
        SUBSCRIPTION_DELETE_ROUTE,
        &silicon_id,
        &json!({ "operation": "delete" }),
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
    shared::consume_carbon_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        "organization.silicon_webhook.redirect",
        &target,
    )
    .await?;
    let endpoint_id = lock_active_endpoint(
        &mut scope.transaction,
        scope.access.organization_id,
        target.principal_id,
    )
    .await?
    .ok_or(AppError::NotFound)?;
    shared::lock_delivery_scope(&mut scope.transaction, endpoint_id).await?;
    let before = load_subscription(
        &mut scope.transaction,
        scope.access.organization_id,
        &target,
    )
    .await?;
    enforce_existing_version(&headers, Some(before.version))?;
    shared::cancel_deliveries(
        &mut scope.transaction,
        scope.access.organization_id,
        endpoint_id,
        "subscription_deleted",
    )
    .await?;
    sqlx::query(
        r"
        DELETE FROM iam.silicon_webhook_subscription_topics AS topic
        USING iam.silicon_webhook_subscriptions AS subscription
        WHERE topic.subscription_id = subscription.id
          AND subscription.organization_id = $1
          AND subscription.silicon_id = $2
        ",
    )
    .bind(scope.access.organization_id)
    .bind(target.principal_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    let deleted_id = sqlx::query_scalar::<_, Uuid>(
        r"
        DELETE FROM iam.silicon_webhook_subscriptions
        WHERE organization_id = $1 AND silicon_id = $2
        RETURNING id
        ",
    )
    .bind(scope.access.organization_id)
    .bind(target.principal_id)
    .fetch_optional(&mut *scope.transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)?;
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "silicon.webhook_subscription.delete",
            target_type: "silicon_webhook_subscription",
            target_id: deleted_id,
            aggregate_type: "silicon_webhook_subscription",
            aggregate_id: deleted_id,
            aggregate_version: before.version + 1,
            event_type: "organization.silicon.webhook_subscription.deleted.v1",
            before_state: serde_json::to_value(&before).ok(),
            after_state: None,
            metadata: json!({
                "silicon_id": target.principal_id,
                "membership_id": target.membership_id,
                "subscription_id": deleted_id,
            }),
        },
    )
    .await?;
    support::finish_empty(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::NO_CONTENT,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    Ok(support::empty(StatusCode::NO_CONTENT))
}

fn canonicalize(
    input: SiliconWebhookSubscriptionReplace,
) -> Result<CanonicalSubscription, AppError> {
    let mut topics = input.topics;
    topics.sort_unstable();
    topics.dedup();
    match input.mode {
        SiliconWebhookSubscriptionMode::All => {
            topics = SiliconWebhookTopic::ALL.to_vec();
        }
        SiliconWebhookSubscriptionMode::Selected if topics.is_empty() => {
            return Err(validation::field(
                "topics",
                "must contain at least one topic when mode is selected",
            ));
        }
        SiliconWebhookSubscriptionMode::Selected => {}
    }
    let tag_filter = input
        .tag_filter
        .map(|mut tag_filter| {
            if tag_filter.additional_tag_ids.len() > 100 {
                return Err(validation::field(
                    "tag_filter.additional_tag_ids",
                    "must contain at most 100 tags",
                ));
            }
            tag_filter.additional_tag_ids.sort_unstable();
            if tag_filter
                .additional_tag_ids
                .windows(2)
                .any(|pair| pair[0] == pair[1])
            {
                return Err(validation::field(
                    "tag_filter.additional_tag_ids",
                    "must contain unique values",
                ));
            }
            Ok(tag_filter)
        })
        .transpose()?;
    Ok(CanonicalSubscription {
        mode: input.mode,
        topics,
        tag_filter,
    })
}

fn replace_claim_request(
    organization_id: Uuid,
    silicon_id: Uuid,
    input: &CanonicalSubscription,
) -> serde_json::Value {
    json!({
        "organization_id": organization_id,
        "silicon_id": silicon_id,
        "request": input,
    })
}

fn enforce_existing_version(
    headers: &HeaderMap,
    existing_version: Option<i64>,
) -> Result<(), AppError> {
    let Some(existing_version) = existing_version else {
        return Ok(());
    };
    if validation::expected_version(headers)? != existing_version {
        return Err(AppError::PreconditionFailed {
            code: "etag_mismatch".into(),
        });
    }
    Ok(())
}

async fn lock_active_endpoint(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM iam.silicon_webhook_endpoints
        WHERE organization_id = $1 AND silicon_id = $2 AND status = 'active'
        FOR UPDATE
        ",
    )
    .bind(organization_id)
    .bind(silicon_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)
}

async fn load_subscription(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    target: &TargetSilicon,
) -> Result<SiliconWebhookSubscriptionResponse, AppError> {
    let row = sqlx::query_as::<_, SubscriptionRow>(
        r"
        SELECT silicon.global_silicon_id AS silicon_id,
               subscription.mode,
               ARRAY(
                   SELECT topic.topic
                   FROM iam.silicon_webhook_subscription_topics AS topic
                   WHERE topic.subscription_id = subscription.id
                   ORDER BY topic.topic
               ) AS topics,
               subscription.tag_filter_enabled,
               ARRAY(
                   SELECT extra_tag.tag_id
                   FROM iam.silicon_webhook_subscription_extra_tags AS extra_tag
                   WHERE extra_tag.subscription_id = subscription.id
                   ORDER BY extra_tag.tag_id
               ) AS additional_tag_ids,
               subscription.version,
               subscription.created_at,
               subscription.updated_at
        FROM iam.silicon_webhook_subscriptions AS subscription
        JOIN iam.silicons AS silicon
          ON silicon.organization_id = subscription.organization_id
         AND silicon.id = subscription.silicon_id
        JOIN iam.silicon_webhook_endpoints AS endpoint
          ON endpoint.organization_id = subscription.organization_id
         AND endpoint.silicon_id = subscription.silicon_id
         AND endpoint.id = subscription.endpoint_id
         AND endpoint.status = 'active'
        WHERE subscription.organization_id = $1
          AND subscription.silicon_id = $2
        LIMIT 1
        ",
    )
    .bind(organization_id)
    .bind(target.principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)?;
    let mode = parse_mode(&row.mode)?;
    let topics = if mode == SiliconWebhookSubscriptionMode::All {
        SiliconWebhookTopic::ALL.to_vec()
    } else {
        row.topics
            .iter()
            .map(|topic| parse_topic(topic))
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(SiliconWebhookSubscriptionResponse {
        silicon_id: row.silicon_id,
        mode,
        topics,
        tag_filter: row.tag_filter_enabled.then_some(SiliconWebhookTagFilter {
            additional_tag_ids: row.additional_tag_ids,
        }),
        version: row.version,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

async fn validate_active_filter_tags(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    tag_ids: &[Uuid],
) -> Result<(), AppError> {
    let count = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*)
        FROM iam.organization_tags
        WHERE organization_id = $1 AND id = ANY($2) AND status = 'active'
        ",
    )
    .bind(organization_id)
    .bind(tag_ids)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if usize::try_from(count).ok() != Some(tag_ids.len()) {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("directory_reference_inactive"),
        });
    }
    Ok(())
}

fn parse_mode(value: &str) -> Result<SiliconWebhookSubscriptionMode, AppError> {
    match value {
        "all" => Ok(SiliconWebhookSubscriptionMode::All),
        "selected" => Ok(SiliconWebhookSubscriptionMode::Selected),
        _ => Err(AppError::Internal {
            category: "silicon_webhook_subscription_mode",
        }),
    }
}

fn parse_topic(value: &str) -> Result<SiliconWebhookTopic, AppError> {
    match value {
        "membership_lifecycle" => Ok(SiliconWebhookTopic::MembershipLifecycle),
        "member_updates" => Ok(SiliconWebhookTopic::MemberUpdates),
        "trust_updates" => Ok(SiliconWebhookTopic::TrustUpdates),
        _ => Err(AppError::Internal {
            category: "silicon_webhook_subscription_topic",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_mode_canonicalizes_to_every_topic() {
        let Ok(canonical) = canonicalize(SiliconWebhookSubscriptionReplace {
            mode: SiliconWebhookSubscriptionMode::All,
            topics: vec![SiliconWebhookTopic::TrustUpdates],
            tag_filter: Some(SiliconWebhookTagFilter {
                additional_tag_ids: vec![Uuid::from_u128(2), Uuid::from_u128(1)],
            }),
        }) else {
            panic!("all mode must be valid");
        };
        assert_eq!(canonical.topics, SiliconWebhookTopic::ALL);
        assert_eq!(
            canonical.tag_filter.map(|filter| filter.additional_tag_ids),
            Some(vec![Uuid::from_u128(1), Uuid::from_u128(2)])
        );
    }

    #[test]
    fn selected_mode_sorts_and_deduplicates_topics() {
        let Ok(canonical) = canonicalize(SiliconWebhookSubscriptionReplace {
            mode: SiliconWebhookSubscriptionMode::Selected,
            topics: vec![
                SiliconWebhookTopic::TrustUpdates,
                SiliconWebhookTopic::MembershipLifecycle,
                SiliconWebhookTopic::TrustUpdates,
            ],
            tag_filter: None,
        }) else {
            panic!("selected mode with topics must be valid");
        };
        assert_eq!(
            canonical.topics,
            vec![
                SiliconWebhookTopic::MembershipLifecycle,
                SiliconWebhookTopic::TrustUpdates,
            ]
        );
    }

    #[test]
    fn selected_mode_rejects_an_empty_topic_set() {
        assert!(
            canonicalize(SiliconWebhookSubscriptionReplace {
                mode: SiliconWebhookSubscriptionMode::Selected,
                topics: Vec::new(),
                tag_filter: None,
            })
            .is_err()
        );
    }

    #[test]
    fn replacement_idempotency_is_bound_to_the_target_silicon() {
        let organization_id = Uuid::now_v7();
        let input = CanonicalSubscription {
            mode: SiliconWebhookSubscriptionMode::All,
            topics: SiliconWebhookTopic::ALL.to_vec(),
            tag_filter: None,
        };
        let first = replace_claim_request(organization_id, Uuid::now_v7(), &input);
        let second = replace_claim_request(organization_id, Uuid::now_v7(), &input);
        assert_ne!(first, second);
    }

    #[tokio::test]
    #[ignore = "requires a local Docker daemon"]
    async fn archived_additional_tag_no_longer_authorizes_delivery() -> anyhow::Result<()> {
        use anyhow::ensure;
        use sqlx::postgres::PgPoolOptions;
        use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
        use testcontainers_modules::postgres::Postgres as TestPostgres;

        let container = TestPostgres::default()
            .with_tag("16-alpine")
            .start()
            .await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&format!(
                "postgres://postgres:postgres@{host}:{port}/postgres"
            ))
            .await?;
        crate::infrastructure::postgres::migrate(&pool).await?;

        let organization_id = Uuid::from_u128(0x41_01);
        let creator_id = Uuid::from_u128(0x41_02);
        let silicon_id = Uuid::from_u128(0x41_03);
        let membership_id = Uuid::from_u128(0x41_04);
        let endpoint_id = Uuid::from_u128(0x41_05);
        let signing_key_id = Uuid::from_u128(0x41_06);
        let subscription_id = Uuid::from_u128(0x41_07);
        let tag_id = Uuid::from_u128(0x41_08);
        let event_id = Uuid::from_u128(0x41_09);

        let mut transaction = pool.begin().await?;
        // This focused resolver test deliberately bypasses unrelated foreign-key
        // fixtures while retaining all CHECK constraints and the routing query.
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            r"
            INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name)
            VALUES ($1, 'tag-filter-test', $2, 'Tag filter test')
            ",
        )
        .bind(organization_id)
        .bind(creator_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.principals (id, kind, status, activated_at)
            VALUES ($1, 'silicon', 'active', transaction_timestamp())
            ",
        )
        .bind(silicon_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.organization_memberships (
                id, organization_id, principal_id, principal_kind, org_role
            ) VALUES ($1, $2, $3, 'silicon', 'member')
            ",
        )
        .bind(membership_id)
        .bind(organization_id)
        .bind(silicon_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.silicons (
                id, organization_id, membership_id, organization_handle,
                silicon_handle, display_name, provisioning_status
            ) VALUES (
                $1, $2, $3, 'tag-filter-test', 'subscriber',
                'Subscriber', 'active'
            )
            ",
        )
        .bind(silicon_id)
        .bind(organization_id)
        .bind(membership_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.silicon_webhook_endpoints (
                id, organization_id, silicon_id, url_ciphertext, url_nonce,
                encryption_key_version, url_digest
            ) VALUES ($1, $2, $3, decode(repeat('41', 17), 'hex'),
                      decode(repeat('41', 12), 'hex'), 1,
                      decode(repeat('41', 32), 'hex'))
            ",
        )
        .bind(endpoint_id)
        .bind(organization_id)
        .bind(silicon_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.silicon_webhook_signing_keys (
                id, organization_id, silicon_id, endpoint_id, secret_version,
                key_prefix, secret_ciphertext, secret_nonce,
                encryption_key_version
            ) VALUES ($1, $2, $3, $4, 1, 'swhs_1234567',
                      decode(repeat('41', 17), 'hex'),
                      decode(repeat('41', 12), 'hex'), 1)
            ",
        )
        .bind(signing_key_id)
        .bind(organization_id)
        .bind(silicon_id)
        .bind(endpoint_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.silicon_webhook_subscriptions (
                id, organization_id, silicon_id, endpoint_id, mode,
                tag_filter_enabled
            ) VALUES ($1, $2, $3, $4, 'all', true)
            ",
        )
        .bind(subscription_id)
        .bind(organization_id)
        .bind(silicon_id)
        .bind(endpoint_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.organization_tags (
                id, organization_id, name, normalized_name,
                created_by_membership_id
            ) VALUES ($1, $2, 'Subscribed tag', 'subscribed-tag', $3)
            ",
        )
        .bind(tag_id)
        .bind(organization_id)
        .bind(membership_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.silicon_webhook_subscription_extra_tags (
                organization_id, subscription_id, tag_id
            ) VALUES ($1, $2, $3)
            ",
        )
        .bind(organization_id)
        .bind(subscription_id)
        .bind(tag_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.outbox_events (
                id, organization_id, aggregate_type, aggregate_id,
                aggregate_version, event_type, payload,
                silicon_webhook_routable
            ) VALUES ($1, $2, 'organization_membership', $3, 1,
                      'organization.membership.updated.v1', '{}'::jsonb, true)
            ",
        )
        .bind(event_id)
        .bind(organization_id)
        .bind(membership_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO iam.outbox_event_affected_tags (outbox_event_id, tag_id) VALUES ($1, $2)",
        )
        .bind(event_id)
        .bind(tag_id)
        .execute(&mut *transaction)
        .await?;

        let active_recipients = sqlx::query_scalar::<_, Uuid>(
            "SELECT silicon_id FROM iam_private.list_worker_silicon_webhook_recipients($1)",
        )
        .bind(event_id)
        .fetch_all(&mut *transaction)
        .await?;
        ensure!(
            active_recipients == vec![silicon_id],
            "an active additional tag did not authorize its subscriber"
        );

        sqlx::query(
            r"
            UPDATE iam.organization_tags
            SET status = 'archived', archived_at = transaction_timestamp()
            WHERE id = $1
            ",
        )
        .bind(tag_id)
        .execute(&mut *transaction)
        .await?;
        let archived_recipients = sqlx::query_scalar::<_, Uuid>(
            "SELECT silicon_id FROM iam_private.list_worker_silicon_webhook_recipients($1)",
        )
        .bind(event_id)
        .fetch_all(&mut *transaction)
        .await?;
        ensure!(
            archived_recipients.is_empty(),
            "an archived additional tag still authorized webhook delivery"
        );
        transaction.rollback().await?;
        Ok(())
    }
}
