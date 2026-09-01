//! Transaction-bound, per-Application organization member webhook snapshots.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};
use sqlx::{FromRow, Postgres, Transaction, types::Json};
use uuid::Uuid;

use crate::{
    api::ApiState,
    error::AppError,
    infrastructure::{
        crypto::{CryptoService, EncryptedValue, EncryptionContext, ProtectedField},
        postgres::events::uses_captured_application_webhook_projection,
    },
};

const MAX_PROJECTION_PLAINTEXT_BYTES: usize = 1_048_576;

pub(crate) struct OrganizationProjectionEvent<'a> {
    pub(crate) outbox_event_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) aggregate_type: &'a str,
    pub(crate) aggregate_id: Uuid,
    pub(crate) aggregate_version: i64,
    pub(crate) event_type: &'a str,
    pub(crate) before_state: Option<&'a Value>,
    pub(crate) after_state: Option<&'a Value>,
    pub(crate) metadata: &'a Value,
}

#[derive(Debug, FromRow)]
struct AuthorizationRow {
    application_id: Uuid,
    membership_id: Uuid,
    scope: String,
    authorized_after: bool,
}

#[derive(Debug, Default)]
struct MemberAuthorization {
    authorized_after: bool,
    union_scopes: BTreeSet<String>,
    effective_scopes: BTreeSet<String>,
}

#[derive(Debug, FromRow)]
struct ProjectionSource {
    membership_id: Uuid,
    principal_id: Uuid,
    principal_kind: String,
    current_state: Json<Value>,
    email_contact_id: Option<Uuid>,
    email_ciphertext: Option<Vec<u8>>,
    email_nonce: Option<Vec<u8>>,
    email_encryption_key_version: Option<i16>,
    phone_contact_id: Option<Uuid>,
    phone_ciphertext: Option<Vec<u8>>,
    phone_nonce: Option<Vec<u8>>,
    phone_encryption_key_version: Option<i16>,
}

/// Captures the exact authorized projection for one explicit organization
/// member event. Events outside the closed vocabulary remain untouched.
pub(crate) async fn capture_organization_application_projections(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    event: OrganizationProjectionEvent<'_>,
) -> Result<(), AppError> {
    capture_with_dependencies(
        transaction,
        &state.crypto,
        &state.settings.providers.iris_base_url,
        event,
    )
    .await
}

async fn capture_with_dependencies(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    iris_base_url: &url::Url,
    event: OrganizationProjectionEvent<'_>,
) -> Result<(), AppError> {
    if !uses_captured_application_webhook_projection(event.event_type)
        || event.event_type == "carbon.updated.v1"
    {
        return Ok(());
    }

    let membership_ids = affected_membership_ids(transaction, &event).await?;
    if membership_ids.is_empty() {
        return Ok(());
    }
    let membership_ids = membership_ids.into_iter().collect::<Vec<_>>();
    let authorizations =
        load_authorizations(transaction, event.organization_id, &membership_ids).await?;
    if authorizations.is_empty() {
        return Ok(());
    }

    let source_ids = authorizations
        .values()
        .flat_map(BTreeMap::keys)
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let sources = load_sources(transaction, event.organization_id, &source_ids).await?;
    let changed_fields = changed_fields(&event);

    if event.event_type == "organization.updated.v1" {
        return capture_organization_update(
            transaction,
            crypto,
            event.outbox_event_id,
            authorizations,
            &sources,
            &changed_fields,
        )
        .await;
    }

    for (application_id, members) in authorizations {
        let aggregate_authorization = AggregateAuthorization {
            authorized_after: members.values().any(|authorization| {
                authorization.authorized_after
                    && authorization.effective_scopes.contains("memberships.read")
            }),
            authorized_before_or_after: members
                .values()
                .any(|authorization| authorization.union_scopes.contains("memberships.read")),
        };
        let mut application_changed_fields = BTreeSet::new();
        let mut projected_members = Vec::with_capacity(members.len());
        for (membership_id, authorization) in members {
            let source = sources
                .get(&membership_id)
                .ok_or_else(|| internal("organization_application_webhook_projection_source"))?;
            let current = project_member(crypto, iris_base_url, source, &authorization)?;
            let disclosure_scopes = if authorization.authorized_after {
                &authorization.effective_scopes
            } else {
                &authorization.union_scopes
            };
            application_changed_fields.extend(
                changed_fields
                    .iter()
                    .filter(|field| field_is_authorized(field, disclosure_scopes))
                    .cloned(),
            );
            projected_members.push(current);
        }

        let current = match project_event_resource(&event, aggregate_authorization)? {
            Some(resource) => json!({
                "resource": resource,
                "members": projected_members,
            }),
            None => member_current(&projected_members),
        };
        let payload = json!({
            "changed_fields": application_changed_fields,
            "current": current,
        });
        persist_projection(
            transaction,
            crypto,
            event.outbox_event_id,
            application_id,
            &payload,
        )
        .await?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct AggregateAuthorization {
    authorized_after: bool,
    authorized_before_or_after: bool,
}

fn project_event_resource(
    event: &OrganizationProjectionEvent<'_>,
    authorization: AggregateAuthorization,
) -> Result<Option<Value>, AppError> {
    let (resource_type, expected_aggregate_type, archived) = match event.event_type {
        "organization.tag_updated.v1" => ("organization_tag", "organization_tag", false),
        "organization.tag_archived.v1" => ("organization_tag", "organization_tag", true),
        "organization.trust.default_updated.v1" => {
            ("organization_trust_default", "organization", false)
        }
        "organization.trust.rule_created.v1" | "organization.trust.rule_updated.v1" => {
            ("organization_trust_rule", "trust_rule", false)
        }
        "organization.trust.rule_archived.v1" => ("organization_trust_rule", "trust_rule", true),
        _ => return Ok(None),
    };
    if event.aggregate_type != expected_aggregate_type {
        return Err(internal("organization_application_webhook_aggregate_type"));
    }
    if !authorization.authorized_before_or_after {
        return Ok(Some(Value::Null));
    }
    if !authorization.authorized_after {
        return Ok(Some(json!({
            "type": resource_type,
            "id": event.aggregate_id,
            "version": event.aggregate_version,
            "authorization": "removed",
        })));
    }
    if archived {
        return Ok(Some(json!({
            "type": resource_type,
            "id": event.aggregate_id,
            "version": event.aggregate_version,
            "status": "archived",
        })));
    }

    let mut resource = event
        .after_state
        .or(event.before_state)
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| internal("organization_application_webhook_aggregate_state"))?;
    resource.insert("type".to_owned(), Value::String(resource_type.to_owned()));
    resource.insert("id".to_owned(), json!(event.aggregate_id));
    resource.insert("version".to_owned(), json!(event.aggregate_version));
    Ok(Some(Value::Object(resource)))
}

async fn load_authorizations(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_ids: &[Uuid],
) -> Result<BTreeMap<Uuid, BTreeMap<Uuid, MemberAuthorization>>, AppError> {
    let rows = sqlx::query_as::<_, AuthorizationRow>(
        r"
        SELECT application_id, membership_id, scope, authorized_after
        FROM iam_private.list_organization_member_webhook_authorizations(
            $1, $2, transaction_timestamp()
        )
        ",
    )
    .bind(organization_id)
    .bind(membership_ids)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| internal("organization_application_webhook_authorizations"))?;

    let mut applications = BTreeMap::<Uuid, BTreeMap<Uuid, MemberAuthorization>>::new();
    for row in rows {
        let authorization = applications
            .entry(row.application_id)
            .or_default()
            .entry(row.membership_id)
            .or_default();
        authorization.authorized_after |= row.authorized_after;
        authorization.union_scopes.insert(row.scope.clone());
        if row.authorized_after {
            authorization.effective_scopes.insert(row.scope);
        }
    }
    Ok(applications)
}

async fn load_sources(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_ids: &[Uuid],
) -> Result<BTreeMap<Uuid, ProjectionSource>, AppError> {
    let rows = sqlx::query_as::<_, ProjectionSource>(
        r"
        SELECT
            membership_id, principal_id, principal_kind, current_state,
            email_contact_id, email_ciphertext, email_nonce,
            email_encryption_key_version, phone_contact_id, phone_ciphertext,
            phone_nonce, phone_encryption_key_version
        FROM iam_private.list_organization_member_webhook_projection_sources($1, $2)
        ",
    )
    .bind(organization_id)
    .bind(membership_ids)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| internal("organization_application_webhook_sources"))?;
    Ok(rows
        .into_iter()
        .map(|source| (source.membership_id, source))
        .collect())
}

fn project_member(
    crypto: &CryptoService,
    iris_base_url: &url::Url,
    source: &ProjectionSource,
    authorization: &MemberAuthorization,
) -> Result<Value, AppError> {
    let source_object = source
        .current_state
        .0
        .as_object()
        .ok_or_else(|| internal("organization_application_webhook_source_shape"))?;
    let resource = source_object
        .get("resource")
        .cloned()
        .ok_or_else(|| internal("organization_application_webhook_resource_shape"))?;
    if resource
        .get("principal_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        != Some(source.principal_id)
    {
        return Err(internal(
            "organization_application_webhook_resource_principal",
        ));
    }
    let mut projected = Map::from_iter([("resource".to_owned(), resource)]);
    if !authorization.authorized_after {
        projected.insert(
            "authorization".to_owned(),
            Value::String("removed".to_owned()),
        );
        return Ok(Value::Object(projected));
    }

    if authorization.effective_scopes.contains("profile") {
        let mut principal = source_object
            .get("principal")
            .and_then(Value::as_object)
            .cloned()
            .ok_or_else(|| internal("organization_application_webhook_principal_shape"))?;
        fill_default_profile_photo(iris_base_url, source, &mut principal)?;
        projected.insert("principal".to_owned(), Value::Object(principal));
    }
    if authorization
        .effective_scopes
        .contains("organizations.read")
        && let Some(value) = source_object.get("organization")
    {
        projected.insert("organization".to_owned(), value.clone());
    }
    if authorization.effective_scopes.contains("memberships.read")
        && let Some(value) = source_object.get("membership")
    {
        projected.insert("membership".to_owned(), value.clone());
    }
    if authorization.effective_scopes.contains("roles.read")
        && let Some(value) = source_object.get("roles")
    {
        projected.insert("roles".to_owned(), value.clone());
    }

    let mut contacts = Map::new();
    if source.principal_kind == "carbon" && authorization.effective_scopes.contains("email") {
        contacts.insert(
            "email".to_owned(),
            Value::String(decrypt_contact(crypto, source, "email")?),
        );
    }
    if source.principal_kind == "carbon" && authorization.effective_scopes.contains("phone") {
        contacts.insert(
            "phone_number".to_owned(),
            Value::String(decrypt_contact(crypto, source, "phone")?),
        );
    }
    if !contacts.is_empty() {
        projected.insert("contacts".to_owned(), Value::Object(contacts));
    }
    Ok(Value::Object(projected))
}

async fn capture_organization_update(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    outbox_event_id: Uuid,
    authorizations: BTreeMap<Uuid, BTreeMap<Uuid, MemberAuthorization>>,
    sources: &BTreeMap<Uuid, ProjectionSource>,
    changed_fields: &BTreeSet<String>,
) -> Result<(), AppError> {
    for (application_id, members) in authorizations {
        let eligible = members
            .iter()
            .filter(|(_, authorization)| organization_scope_authorizes(authorization))
            .collect::<Vec<_>>();
        if eligible.is_empty() {
            continue;
        }
        let authorized_after = eligible.iter().any(|(_, authorization)| {
            authorization.authorized_after
                && authorization
                    .effective_scopes
                    .contains("organizations.read")
        });
        let (membership_id, _) = eligible
            .iter()
            .find(|(_, authorization)| {
                authorization.authorized_after
                    && authorization
                        .effective_scopes
                        .contains("organizations.read")
            })
            .copied()
            .unwrap_or(eligible[0]);
        let source = sources
            .get(membership_id)
            .ok_or_else(|| internal("organization_application_webhook_projection_source"))?;
        let organization = source
            .current_state
            .0
            .get("organization")
            .cloned()
            .ok_or_else(|| internal("organization_application_webhook_organization_shape"))?;
        let current = if authorized_after {
            json!({ "organization": organization })
        } else {
            json!({
                "organization": {
                    "id": organization.get("id"),
                    "version": organization.get("version"),
                    "authorization": "removed",
                }
            })
        };
        let payload = json!({
            "changed_fields": changed_fields,
            "current": current,
        });
        persist_projection(
            transaction,
            crypto,
            outbox_event_id,
            application_id,
            &payload,
        )
        .await?;
    }
    Ok(())
}

fn organization_scope_authorizes(authorization: &MemberAuthorization) -> bool {
    authorization.union_scopes.contains("organizations.read")
}

fn member_current(members: &[Value]) -> Value {
    json!({ "members": members })
}

fn fill_default_profile_photo(
    iris_base_url: &url::Url,
    source: &ProjectionSource,
    principal: &mut Map<String, Value>,
) -> Result<(), AppError> {
    if !principal.get("profile_photo").is_none_or(Value::is_null) {
        return Ok(());
    }
    let public_id = principal
        .get("public_id")
        .and_then(Value::as_str)
        .ok_or_else(|| internal("organization_application_webhook_public_id"))?;
    let value = if source.principal_kind == "silicon" {
        let level = source
            .current_state
            .0
            .pointer("/membership/hierarchy_level")
            .and_then(Value::as_i64)
            .ok_or_else(|| internal("organization_application_webhook_hierarchy_level"))?;
        silicon_profile_photo(iris_base_url, public_id, level)?
    } else {
        let mut url = iris_base_url
            .join("pfp/carbon")
            .map_err(|_| internal("organization_application_webhook_profile_photo"))?;
        url.query_pairs_mut().append_pair("id", public_id);
        url.to_string()
    };
    principal.insert("profile_photo".to_owned(), Value::String(value));
    Ok(())
}

fn silicon_profile_photo(
    iris_base_url: &url::Url,
    public_id: &str,
    hierarchy_level: i64,
) -> Result<String, AppError> {
    let base = iris_base_url
        .join("pfp/silicon")
        .map_err(|_| internal("organization_application_webhook_profile_photo"))?;
    // Silicon global ids are already restricted to the canonical
    // `{handle}:{org}` alphabet. Public reads deliberately preserve that
    // colon, so do not form this URL through query-pair percent encoding.
    Ok(format!("{base}?id={public_id}&level={hierarchy_level}"))
}

fn decrypt_contact(
    crypto: &CryptoService,
    source: &ProjectionSource,
    kind: &str,
) -> Result<String, AppError> {
    let (id, ciphertext, nonce, key_version, field) = match kind {
        "email" => (
            source.email_contact_id,
            source.email_ciphertext.as_deref(),
            source.email_nonce.as_deref(),
            source.email_encryption_key_version,
            ProtectedField::CarbonEmail,
        ),
        "phone" => (
            source.phone_contact_id,
            source.phone_ciphertext.as_deref(),
            source.phone_nonce.as_deref(),
            source.phone_encryption_key_version,
            ProtectedField::CarbonPhone,
        ),
        _ => return Err(internal("organization_application_webhook_contact_kind")),
    };
    let id = id.ok_or_else(|| internal("organization_application_webhook_contact_missing"))?;
    let nonce: [u8; 12] = nonce
        .ok_or_else(|| internal("organization_application_webhook_contact_missing"))?
        .try_into()
        .map_err(|_| internal("organization_application_webhook_contact_nonce"))?;
    let encrypted = EncryptedValue {
        key_version: key_version
            .ok_or_else(|| internal("organization_application_webhook_contact_missing"))?,
        nonce,
        ciphertext: ciphertext
            .ok_or_else(|| internal("organization_application_webhook_contact_missing"))?
            .to_vec(),
    };
    let plaintext = crypto
        .decrypt(EncryptionContext::global(field, id), &encrypted)
        .map_err(|_| internal("organization_application_webhook_contact_decrypt"))?;
    String::from_utf8(plaintext.to_vec())
        .map_err(|_| internal("organization_application_webhook_contact_plaintext"))
}

async fn persist_projection(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    outbox_event_id: Uuid,
    application_id: Uuid,
    payload: &Value,
) -> Result<(), AppError> {
    let plaintext = serde_json::to_vec(payload)
        .map_err(|_| internal("organization_application_webhook_encode"))?;
    if plaintext.len() > MAX_PROJECTION_PLAINTEXT_BYTES {
        return Err(internal("organization_application_webhook_projection_size"));
    }
    let projection_id = Uuid::now_v7();
    let encrypted = crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookEventPayload,
                application_id,
                projection_id,
            ),
            &plaintext,
        )
        .map_err(|_| internal("organization_application_webhook_encrypt"))?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_event_projections (
            id, outbox_event_id, application_id,
            payload_ciphertext, payload_nonce, encryption_key_version
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(projection_id)
    .bind(outbox_event_id)
    .bind(application_id)
    .bind(encrypted.ciphertext)
    .bind(encrypted.nonce.as_slice())
    .bind(encrypted.key_version)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("organization_application_webhook_insert"))?;
    Ok(())
}

async fn affected_membership_ids(
    transaction: &mut Transaction<'_, Postgres>,
    event: &OrganizationProjectionEvent<'_>,
) -> Result<BTreeSet<Uuid>, AppError> {
    if matches!(
        event.event_type,
        "organization.updated.v1" | "organization.trust.default_updated.v1"
    ) {
        return active_memberships(transaction, event.organization_id).await;
    }

    if let Some(membership_ids) = captured_trust_rule_membership_ids(event) {
        return Ok(membership_ids);
    }

    let mut membership_ids = BTreeSet::new();
    collect_named_membership_ids(event.metadata, &mut membership_ids);
    if let Some(before) = event.before_state {
        collect_named_membership_ids(before, &mut membership_ids);
    }
    if let Some(after) = event.after_state {
        collect_named_membership_ids(after, &mut membership_ids);
    }

    if matches!(
        event.event_type,
        "organization.tag_updated.v1" | "organization.tag_archived.v1"
    ) && membership_ids.is_empty()
        && let Some(tag_id) = value_uuid(event.metadata, "tag_id")
    {
        membership_ids
            .extend(tag_memberships(transaction, event.organization_id, tag_id, false).await?);
    }

    Ok(membership_ids)
}

fn captured_trust_rule_membership_ids(
    event: &OrganizationProjectionEvent<'_>,
) -> Option<BTreeSet<Uuid>> {
    if !matches!(
        event.event_type,
        "organization.trust.rule_created.v1"
            | "organization.trust.rule_updated.v1"
            | "organization.trust.rule_archived.v1"
    ) {
        return None;
    }
    let mut membership_ids = BTreeSet::new();
    collect_named_membership_ids(event.metadata, &mut membership_ids);
    Some(membership_ids)
}

async fn active_memberships(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
) -> Result<BTreeSet<Uuid>, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM iam.organization_memberships
        WHERE organization_id = $1 AND status = 'active'
        ORDER BY id
        ",
    )
    .bind(organization_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|ids| ids.into_iter().collect())
    .map_err(|_| internal("organization_application_webhook_active_members"))
}

async fn tag_memberships(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    tag_id: Uuid,
    silicon_only: bool,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT membership.id
        FROM iam.membership_tags AS assignment
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = assignment.organization_id
         AND membership.id = assignment.membership_id
         AND membership.status = 'active'
        WHERE assignment.organization_id = $1
          AND assignment.tag_id = $2
          AND (NOT $3 OR membership.principal_kind = 'silicon')
        ORDER BY membership.id
        ",
    )
    .bind(organization_id)
    .bind(tag_id)
    .bind(silicon_only)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| internal("organization_application_webhook_tag_members"))
}

fn collect_named_membership_ids(value: &Value, membership_ids: &mut BTreeSet<Uuid>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if matches!(
                    key.as_str(),
                    "affected_memberships" | "affected_membership_ids"
                ) && let Some(values) = child.as_array()
                {
                    for value in values {
                        if let Some(value) = value.as_str()
                            && let Ok(id) = Uuid::parse_str(value)
                        {
                            membership_ids.insert(id);
                        }
                    }
                }
                if matches!(
                    key.as_str(),
                    "membership_id"
                        | "target_membership_id"
                        | "previous_owner_membership_id"
                        | "new_owner_membership_id"
                ) && let Some(value) = child.as_str()
                    && let Ok(id) = Uuid::parse_str(value)
                {
                    membership_ids.insert(id);
                }
                collect_named_membership_ids(child, membership_ids);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_named_membership_ids(child, membership_ids);
            }
        }
        _ => {}
    }
}

fn changed_fields(event: &OrganizationProjectionEvent<'_>) -> BTreeSet<String> {
    let fixed = match event.event_type {
        "organization.ownership_transferred.v1" => [
            "roles.org_role",
            "roles.capabilities",
            "membership.authorization_epoch",
        ]
        .as_slice(),
        "organization.tag_updated.v1" => ["resource.name", "membership.tags"].as_slice(),
        "organization.trust.default_updated.v1" => {
            ["resource.trust", "membership.trust"].as_slice()
        }
        "organization.trust.rule_created.v1" => [
            "resource.subject",
            "resource.target",
            "resource.trust",
            "resource.status",
            "membership.trust",
        ]
        .as_slice(),
        "organization.trust.rule_updated.v1" => ["membership.trust"].as_slice(),
        "organization.trust.rule_archived.v1" => ["resource.status", "membership.trust"].as_slice(),
        "organization.membership.created.v1"
        | "organization.membership.reactivated.v1"
        | "organization.silicon.created.v1" => {
            ["principal", "organization", "membership", "roles"].as_slice()
        }
        "organization.membership.removed.v1" | "organization.silicon.removed.v1" => [
            "membership.status",
            "membership.tags",
            "membership.hierarchy",
            "membership.authorization_epoch",
            "membership.access",
            "roles.org_role",
            "roles.capabilities",
        ]
        .as_slice(),
        "organization.silicon.credential_rotated.v1" => {
            ["membership.authorization_epoch", "membership.access"].as_slice()
        }
        _ => [].as_slice(),
    };
    let mut fields = fixed
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<String>>();
    if event.event_type == "organization.tag_archived.v1" {
        let has_exact_metadata = event
            .metadata
            .get("tag_assignment_membership_ids")
            .is_some()
            || event.metadata.get("archived_trust_rule_ids").is_some();
        if non_empty_array(event.metadata, "tag_assignment_membership_ids") {
            fields.insert("membership.tags".to_owned());
        }
        if non_empty_array(event.metadata, "archived_trust_rule_ids") {
            fields.insert("membership.trust".to_owned());
        }
        if !has_exact_metadata {
            // Compatibility for an in-flight deployment during the 0031/0032
            // rollout. New writes always carry the exact disjoint sets.
            fields.insert("membership.tags".to_owned());
            if event
                .metadata
                .get("cascade")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                fields.insert("membership.trust".to_owned());
            }
        }
        fields.insert("resource.status".to_owned());
    }
    collect_explicit_changed_fields(event.event_type, event.metadata, &mut fields);
    if let (Some(before), Some(after)) = (event.before_state, event.after_state) {
        collect_state_diff(event.event_type, before, after, &mut fields);
    }
    fields
}

fn non_empty_array(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty())
}

fn collect_explicit_changed_fields(
    event_type: &str,
    metadata: &Value,
    fields: &mut BTreeSet<String>,
) {
    let Some(values) = metadata.get("changed_fields").and_then(Value::as_array) else {
        return;
    };
    for field in values.iter().filter_map(Value::as_str) {
        if let Some(canonical) = canonical_field(event_type, field) {
            fields.insert(canonical.to_owned());
        }
    }
}

fn collect_state_diff(
    event_type: &str,
    before: &Value,
    after: &Value,
    fields: &mut BTreeSet<String>,
) {
    let (Some(before), Some(after)) = (before.as_object(), after.as_object()) else {
        return;
    };
    for key in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
        if before.get(key) == after.get(key) {
            continue;
        }
        if key == "principal"
            && let (Some(before), Some(after)) = (before.get(key), after.get(key))
        {
            collect_state_diff(event_type, before, after, fields);
        } else if let Some(canonical) = canonical_field(event_type, key) {
            fields.insert(canonical.to_owned());
        }
    }
}

fn canonical_field(event_type: &str, field: &str) -> Option<&'static str> {
    if event_type == "organization.updated.v1" {
        return match field {
            "name" => Some("organization.name"),
            "logo" | "logo_uri" => Some("organization.logo"),
            "description" => Some("organization.description"),
            "join_method" => Some("organization.join_method"),
            "status" => Some("organization.status"),
            _ => None,
        };
    }
    if event_type == "organization.tag_updated.v1" {
        return match field {
            "name" => Some("resource.name"),
            "status" => Some("resource.status"),
            _ => None,
        };
    }
    if matches!(
        event_type,
        "organization.trust.rule_created.v1"
            | "organization.trust.rule_updated.v1"
            | "organization.trust.rule_archived.v1"
    ) {
        return match field {
            "subject" => Some("resource.subject"),
            "target" => Some("resource.target"),
            "trust" => Some("resource.trust"),
            "status" => Some("resource.status"),
            _ => None,
        };
    }
    match field {
        "display_name" => Some("principal.display_name"),
        "timezone" => Some("principal.timezone"),
        "description" => Some("principal.description"),
        "profile_photo" => Some("principal.profile_photo"),
        "status" => Some("membership.status"),
        "tags" | "tag_ids" => Some("membership.tags"),
        "first_silicon_membership_id" => Some("membership.first_silicon_membership_id"),
        "extra_silicons" | "extra_silicon_membership_ids" => {
            Some("membership.extra_silicon_membership_ids")
        }
        "default_trust" | "trust" => Some("membership.trust"),
        "reports_to_membership_id" => Some("membership.reports_to_membership_id"),
        "hierarchy_level" => Some("membership.hierarchy_level"),
        "authorization_epoch" => Some("membership.authorization_epoch"),
        "credential_version" => Some("membership.access"),
        "org_role" => Some("roles.org_role"),
        "job_role" => Some("roles.job_role"),
        "capabilities" => Some("roles.capabilities"),
        _ => None,
    }
}

fn field_is_authorized(field: &str, scopes: &BTreeSet<String>) -> bool {
    (field.starts_with("principal") && scopes.contains("profile"))
        || (field.starts_with("organization") && scopes.contains("organizations.read"))
        || (field.starts_with("membership") && scopes.contains("memberships.read"))
        || (field.starts_with("roles") && scopes.contains("roles.read"))
        || (field.starts_with("resource") && scopes.contains("memberships.read"))
        || (field == "contacts.email" && scopes.contains("email"))
        || (field == "contacts.phone_number" && scopes.contains("phone"))
}

fn value_uuid(value: &Value, key: &str) -> Option<Uuid> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
}

const fn internal(category: &'static str) -> AppError {
    AppError::Internal { category }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use anyhow::ensure;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use secrecy::SecretString;
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;
    use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
    use testcontainers_modules::postgres::Postgres as TestPostgres;

    use super::{
        AggregateAuthorization, MemberAuthorization, OrganizationProjectionEvent,
        capture_with_dependencies, captured_trust_rule_membership_ids, changed_fields,
        collect_named_membership_ids, field_is_authorized, member_current,
        organization_scope_authorizes, project_event_resource, silicon_profile_photo,
    };
    use crate::{
        config::{KeyringSettings, SecuritySettings},
        infrastructure::{
            crypto::{CryptoService, EncryptedValue, EncryptionContext, ProtectedField},
            postgres,
        },
    };

    fn projection_crypto() -> Result<CryptoService, crate::infrastructure::crypto::CryptoError> {
        let key = URL_SAFE_NO_PAD.encode([47_u8; 32]);
        let keyring = || KeyringSettings {
            current_version: 1,
            keys: BTreeMap::from([(1, SecretString::from(key.clone()))]),
        };
        CryptoService::from_settings(&SecuritySettings {
            token_peppers: keyring(),
            blind_index_keys: keyring(),
            encryption_keys: keyring(),
            cookie_key: SecretString::from(key),
            access_token_ttl: std::time::Duration::from_mins(30),
            refresh_family_ttl: std::time::Duration::from_hours(21_600),
            authorization_code_ttl: std::time::Duration::from_mins(2),
            otp_ttl: std::time::Duration::from_mins(10),
            otp_max_attempts: 10,
        })
    }

    #[test]
    fn affected_membership_collection_finds_exact_multi_subject_metadata() {
        let first = uuid::Uuid::from_u128(1);
        let second = uuid::Uuid::from_u128(2);
        let metadata = json!({
            "previous_owner_membership_id": first,
            "new_owner_membership_id": second,
            "unrelated_id": uuid::Uuid::from_u128(3),
        });
        let mut ids = BTreeSet::new();
        collect_named_membership_ids(&metadata, &mut ids);
        assert_eq!(ids, BTreeSet::from([first, second]));
    }

    #[test]
    fn affected_membership_collection_keeps_bare_uuid_cascade_arrays() {
        let removed = uuid::Uuid::from_u128(1);
        let reassigned = uuid::Uuid::from_u128(2);
        let access_changed = uuid::Uuid::from_u128(3);
        let metadata = json!({
            "membership_id": removed,
            "affected_memberships": [removed, reassigned],
            "affected_membership_ids": [access_changed],
        });
        let mut ids = BTreeSet::new();
        collect_named_membership_ids(&metadata, &mut ids);
        assert_eq!(ids, BTreeSet::from([removed, reassigned, access_changed]));
    }

    #[test]
    fn trust_recipient_collection_uses_only_captured_metadata() {
        let captured = uuid::Uuid::from_u128(1);
        let stale_selector_member = uuid::Uuid::from_u128(2);
        let metadata = json!({ "affected_membership_ids": [captured] });
        let before = json!({
            "subject": { "kind": "membership", "membership_id": stale_selector_member },
            "target": { "kind": "tag", "tag_id": uuid::Uuid::from_u128(3) },
        });
        let event = OrganizationProjectionEvent {
            outbox_event_id: uuid::Uuid::from_u128(4),
            organization_id: uuid::Uuid::from_u128(5),
            aggregate_type: "trust_rule",
            aggregate_id: uuid::Uuid::from_u128(6),
            aggregate_version: 2,
            event_type: "organization.trust.rule_updated.v1",
            before_state: Some(&before),
            after_state: None,
            metadata: &metadata,
        };
        assert_eq!(
            captured_trust_rule_membership_ids(&event),
            Some(BTreeSet::from([captured]))
        );
    }

    #[test]
    fn projection_shapes_do_not_depend_on_member_count() {
        assert_eq!(
            member_current(&[json!({ "resource": { "id": "one" } })]),
            json!({ "members": [{ "resource": { "id": "one" } }] })
        );
        assert_eq!(
            member_current(&[
                json!({ "resource": { "id": "one" } }),
                json!({ "resource": { "id": "two" } }),
            ]),
            json!({
                "members": [
                    { "resource": { "id": "one" } },
                    { "resource": { "id": "two" } },
                ]
            })
        );
    }

    #[test]
    fn profile_only_authorization_does_not_receive_organization_updates() {
        let profile_only = MemberAuthorization {
            authorized_after: true,
            union_scopes: BTreeSet::from(["profile".to_owned()]),
            effective_scopes: BTreeSet::from(["profile".to_owned()]),
        };
        assert!(!organization_scope_authorizes(&profile_only));
    }

    #[test]
    fn versioned_trust_resource_is_complete_or_an_authorization_tombstone() {
        let rule_id = uuid::Uuid::from_u128(7);
        let organization_id = uuid::Uuid::from_u128(8);
        let after = json!({
            "subject": { "kind": "membership", "membership_id": uuid::Uuid::from_u128(9) },
            "target": { "kind": "tag", "tag_id": uuid::Uuid::from_u128(10) },
            "trust": { "boundary": "internal", "level": "trusted" },
            "specificity": 1,
        });
        let metadata = json!({});
        let event = OrganizationProjectionEvent {
            outbox_event_id: uuid::Uuid::from_u128(6),
            organization_id,
            aggregate_type: "trust_rule",
            aggregate_id: rule_id,
            aggregate_version: 3,
            event_type: "organization.trust.rule_updated.v1",
            before_state: None,
            after_state: Some(&after),
            metadata: &metadata,
        };
        let Ok(Some(complete)) = project_event_resource(
            &event,
            AggregateAuthorization {
                authorized_after: true,
                authorized_before_or_after: true,
            },
        ) else {
            panic!("authorized trust resource must project");
        };
        assert_eq!(complete["type"], "organization_trust_rule");
        assert_eq!(complete["id"], json!(rule_id));
        assert_eq!(complete["version"], 3);
        assert_eq!(complete["trust"]["level"], "trusted");

        let Ok(Some(tombstone)) = project_event_resource(
            &event,
            AggregateAuthorization {
                authorized_after: false,
                authorized_before_or_after: true,
            },
        ) else {
            panic!("before-only trust authority must project a tombstone");
        };
        assert_eq!(
            tombstone,
            json!({
                "type": "organization_trust_rule",
                "id": rule_id,
                "version": 3,
                "authorization": "removed",
            })
        );
    }

    #[test]
    fn silicon_default_photo_matches_public_read_contract_without_escaping_colon() {
        let Ok(base) = url::Url::parse("https://iris.teamofsilicons.com") else {
            panic!("valid test Iris URL must parse");
        };
        let Ok(photo) = silicon_profile_photo(&base, "helper:acme", 3) else {
            panic!("valid Silicon profile URL must render");
        };
        assert_eq!(
            photo,
            "https://iris.teamofsilicons.com/pfp/silicon?id=helper:acme&level=3"
        );
    }

    #[test]
    fn changed_fields_are_canonical_and_scope_filtered() {
        let before = json!({ "job_role": "Old", "tag_ids": [uuid::Uuid::from_u128(1)] });
        let after = json!({ "job_role": "New", "tag_ids": [uuid::Uuid::from_u128(2)] });
        let metadata = json!({ "membership_id": uuid::Uuid::from_u128(3) });
        let fields = changed_fields(&OrganizationProjectionEvent {
            outbox_event_id: uuid::Uuid::from_u128(4),
            organization_id: uuid::Uuid::from_u128(5),
            aggregate_type: "organization_membership",
            aggregate_id: uuid::Uuid::from_u128(3),
            aggregate_version: 2,
            event_type: "organization.membership.updated.v1",
            before_state: Some(&before),
            after_state: Some(&after),
            metadata: &metadata,
        });
        assert!(fields.contains("roles.job_role"));
        assert!(fields.contains("membership.tags"));
        assert!(field_is_authorized(
            "roles.job_role",
            &BTreeSet::from(["roles.read".to_owned()])
        ));
        assert!(!field_is_authorized(
            "membership.tags",
            &BTreeSet::from(["roles.read".to_owned()])
        ));
    }

    #[test]
    fn organization_description_diff_uses_the_exact_organization_path() {
        let before = json!({ "description": "Before", "name": "Same", "version": 1 });
        let after = json!({ "description": "After", "name": "Same", "version": 2 });
        let metadata = json!({});
        let fields = changed_fields(&OrganizationProjectionEvent {
            outbox_event_id: uuid::Uuid::from_u128(4),
            organization_id: uuid::Uuid::from_u128(5),
            aggregate_type: "organization",
            aggregate_id: uuid::Uuid::from_u128(5),
            aggregate_version: 2,
            event_type: "organization.updated.v1",
            before_state: Some(&before),
            after_state: Some(&after),
            metadata: &metadata,
        });
        assert_eq!(
            fields,
            BTreeSet::from(["organization.description".to_owned()])
        );
        assert!(!fields.contains("principal.description"));
    }

    #[test]
    fn before_only_authority_never_reuses_prior_scopes() {
        assert!(!field_is_authorized(
            "principal.display_name",
            &BTreeSet::new()
        ));
        assert!(!field_is_authorized("membership.status", &BTreeSet::new()));
    }

    #[tokio::test]
    #[ignore = "requires a local Docker daemon"]
    #[allow(
        clippy::too_many_lines,
        reason = "the fresh database, authorization union, encrypted rows, and immutable payload assertions form one end-to-end contract test"
    )]
    async fn live_organization_member_projections_are_scoped_frozen_and_exact() -> anyhow::Result<()>
    {
        let container = TestPostgres::default()
            .with_tag("16-alpine")
            .start()
            .await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&format!(
                "postgres://postgres:postgres@{host}:{port}/postgres"
            ))
            .await?;
        postgres::migrate(&pool).await?;

        let actor_id = uuid::Uuid::from_u128(0xa01);
        let silicon_id = uuid::Uuid::from_u128(0xa02);
        let full_application_id = uuid::Uuid::from_u128(0xa03);
        let profile_application_id = uuid::Uuid::from_u128(0xa04);
        let actor_membership_id = uuid::Uuid::from_u128(0xa05);
        let silicon_membership_id = uuid::Uuid::from_u128(0xa06);
        let organization_id = uuid::Uuid::from_u128(0xa07);
        let silicon_session_id = uuid::Uuid::from_u128(0xa08);
        let full_consent_id = uuid::Uuid::from_u128(0xa09);
        let profile_consent_id = uuid::Uuid::from_u128(0xa0a);
        let full_endpoint_id = uuid::Uuid::from_u128(0xa0b);
        let profile_endpoint_id = uuid::Uuid::from_u128(0xa0c);
        let full_signing_key_id = uuid::Uuid::from_u128(0xa0d);
        let profile_signing_key_id = uuid::Uuid::from_u128(0xa0e);
        let removed_silicon_id = uuid::Uuid::from_u128(0xa20);
        let removed_membership_id = uuid::Uuid::from_u128(0xa21);
        let child_silicon_id = uuid::Uuid::from_u128(0xa22);
        let child_membership_id = uuid::Uuid::from_u128(0xa23);
        let grandchild_silicon_id = uuid::Uuid::from_u128(0xa24);
        let grandchild_membership_id = uuid::Uuid::from_u128(0xa25);
        let removed_session_id = uuid::Uuid::from_u128(0xa26);
        let seed = format!(
            r"
            BEGIN;
            INSERT INTO iam.cryptographic_key_versions (purpose, key_version, status)
            VALUES ('contact_aead', 1, 'active');
            INSERT INTO iam.principals (id, kind, status, activated_at) VALUES
              ('{actor_id}', 'carbon', 'active', transaction_timestamp()),
              ('{silicon_id}', 'silicon', 'active', transaction_timestamp()),
              ('{full_application_id}', 'application', 'active', transaction_timestamp()),
              ('{profile_application_id}', 'application', 'active', transaction_timestamp());
            INSERT INTO iam.carbons (id, carbon_id, display_name)
            VALUES ('{actor_id}', 'projection-owner', 'Projection owner');
            INSERT INTO iam.carbon_contacts (
                id, carbon_id, kind, ciphertext, nonce, encryption_key_version, verified_at
            ) VALUES
              ('00000000-0000-0000-0000-000000000a11', '{actor_id}', 'email',
               decode(repeat('51', 17), 'hex'), decode(repeat('52', 12), 'hex'), 1,
               transaction_timestamp()),
              ('00000000-0000-0000-0000-000000000a12', '{actor_id}', 'phone',
               decode(repeat('53', 17), 'hex'), decode(repeat('54', 12), 'hex'), 1,
               transaction_timestamp());
            INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name, description)
            VALUES ('{organization_id}', 'projection-org', '{actor_id}', 'Projection Org', 'Before');
            INSERT INTO iam.organization_memberships (
                id, organization_id, principal_id, principal_kind, org_role, job_role
            ) VALUES
              ('{actor_membership_id}', '{organization_id}', '{actor_id}', 'carbon', 'owner', 'Owner'),
              ('{silicon_membership_id}', '{organization_id}', '{silicon_id}', 'silicon', 'member', 'Helper');
            INSERT INTO iam.carbon_membership_settings (organization_id, membership_id, carbon_id)
            VALUES ('{organization_id}', '{actor_membership_id}', '{actor_id}');
            INSERT INTO iam.silicons (
                id, organization_id, membership_id, organization_handle,
                silicon_handle, display_name, description, provisioning_status
            ) VALUES (
                '{silicon_id}', '{organization_id}', '{silicon_membership_id}',
                'projection-org', 'helper', 'Before', 'Before', 'active'
            );
            INSERT INTO iam.authentication_sessions (
                id, subject_principal_id, subject_kind, authentication_method,
                subject_auth_epoch, idle_expires_at, absolute_expires_at
            ) VALUES (
                '{silicon_session_id}', '{silicon_id}', 'silicon', 'silicon_credential', 1,
                transaction_timestamp() + interval '1 day',
                transaction_timestamp() + interval '2 days'
            );
            INSERT INTO iam.applications (id, app_id, owner_carbon_id, review_status) VALUES
              ('{full_application_id}', 'projection-full', '{actor_id}', 'verified'),
              ('{profile_application_id}', 'projection-profile', '{actor_id}', 'verified');
            INSERT INTO iam.application_requested_scopes (application_id, scope) VALUES
              ('{full_application_id}', 'profile'),
              ('{full_application_id}', 'organizations.read'),
              ('{full_application_id}', 'memberships.read'),
              ('{full_application_id}', 'roles.read'),
              ('{profile_application_id}', 'profile');
            INSERT INTO iam.application_approved_scopes (
                application_id, scope, approved_by_carbon_id
            ) VALUES
              ('{full_application_id}', 'profile', '{actor_id}'),
              ('{full_application_id}', 'organizations.read', '{actor_id}'),
              ('{full_application_id}', 'memberships.read', '{actor_id}'),
              ('{full_application_id}', 'roles.read', '{actor_id}'),
              ('{profile_application_id}', 'profile', '{actor_id}');
            INSERT INTO iam.oauth_consent_grants (
                id, application_id, subject_principal_id, subject_kind,
                organization_id, membership_id, parent_authentication_session_id
            ) VALUES
              ('{full_consent_id}', '{full_application_id}', '{silicon_id}', 'silicon',
               '{organization_id}', '{silicon_membership_id}', '{silicon_session_id}'),
              ('{profile_consent_id}', '{profile_application_id}', '{silicon_id}', 'silicon',
               '{organization_id}', '{silicon_membership_id}', '{silicon_session_id}');
            INSERT INTO iam.oauth_consent_grant_scopes (consent_grant_id, scope) VALUES
              ('{full_consent_id}', 'profile'),
              ('{full_consent_id}', 'organizations.read'),
              ('{full_consent_id}', 'memberships.read'),
              ('{full_consent_id}', 'roles.read'),
              ('{profile_consent_id}', 'profile');
            INSERT INTO iam.application_webhook_endpoints (
                id, application_id, url_ciphertext, url_nonce,
                encryption_key_version, url_digest, status, activated_at
            ) VALUES
              ('{full_endpoint_id}', '{full_application_id}', decode(repeat('11', 17), 'hex'),
               decode(repeat('12', 12), 'hex'), 1, decode(repeat('13', 32), 'hex'),
               'active', transaction_timestamp()),
              ('{profile_endpoint_id}', '{profile_application_id}', decode(repeat('21', 17), 'hex'),
               decode(repeat('22', 12), 'hex'), 1, decode(repeat('23', 32), 'hex'),
               'active', transaction_timestamp());
            INSERT INTO iam.application_webhook_signing_keys (
                id, application_id, endpoint_id, secret_version, key_prefix,
                secret_ciphertext, secret_nonce, encryption_key_version
            ) VALUES
              ('{full_signing_key_id}', '{full_application_id}', '{full_endpoint_id}', 1,
               'whs_full0001', decode(repeat('31', 17), 'hex'), decode(repeat('32', 12), 'hex'), 1),
              ('{profile_signing_key_id}', '{profile_application_id}', '{profile_endpoint_id}', 1,
               'whs_prof0001', decode(repeat('41', 17), 'hex'), decode(repeat('42', 12), 'hex'), 1);
            COMMIT;
            "
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(seed))
            .execute(&pool)
            .await?;

        let crypto = projection_crypto()?;
        let iris_base_url = url::Url::parse("https://iris.teamofsilicons.com")?;
        let member_event_id = uuid::Uuid::now_v7();
        let organization_event_id = uuid::Uuid::now_v7();
        let organization_before_only_event_id = uuid::Uuid::now_v7();
        let before_only_event_id = uuid::Uuid::now_v7();
        let mut transaction = pool.begin().await?;
        sqlx::query("SELECT set_config('iam.principal_id', $1, true)")
            .bind(actor_id.to_string())
            .execute(&mut *transaction)
            .await?;
        let silicon_version = sqlx::query_scalar::<_, i64>(
            "UPDATE iam.silicons SET display_name = 'Captured', description = 'Captured' WHERE id = $1 RETURNING version",
        )
        .bind(silicon_id)
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.outbox_events (
                id, organization_id, aggregate_type, aggregate_id, aggregate_version,
                event_ordinal, event_type, schema_version, payload
            ) VALUES ($1, $2, 'silicon', $3, $4, 1, 'organization.silicon.updated.v1', 1, '{}')
            ",
        )
        .bind(member_event_id)
        .bind(organization_id)
        .bind(silicon_id)
        .bind(silicon_version)
        .execute(&mut *transaction)
        .await?;
        let member_before = json!({ "display_name": "Before" });
        let member_after = json!({ "display_name": "Captured" });
        let member_metadata = json!({ "membership_id": silicon_membership_id });
        capture_with_dependencies(
            &mut transaction,
            &crypto,
            &iris_base_url,
            OrganizationProjectionEvent {
                outbox_event_id: member_event_id,
                organization_id,
                aggregate_type: "silicon",
                aggregate_id: silicon_id,
                aggregate_version: silicon_version,
                event_type: "organization.silicon.updated.v1",
                before_state: Some(&member_before),
                after_state: Some(&member_after),
                metadata: &member_metadata,
            },
        )
        .await?;

        let organization_version = sqlx::query_scalar::<_, i64>(
            "UPDATE iam.organizations SET description = 'After' WHERE id = $1 RETURNING version",
        )
        .bind(organization_id)
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.outbox_events (
                id, organization_id, aggregate_type, aggregate_id, aggregate_version,
                event_ordinal, event_type, schema_version, payload
            ) VALUES ($1, $2, 'organization', $2, $3, 1, 'organization.updated.v1', 1, '{}')
            ",
        )
        .bind(organization_event_id)
        .bind(organization_id)
        .bind(organization_version)
        .execute(&mut *transaction)
        .await?;
        let organization_before = json!({ "description": "Before", "version": 1 });
        let organization_after = json!({ "description": "After", "version": organization_version });
        let organization_metadata = json!({});
        capture_with_dependencies(
            &mut transaction,
            &crypto,
            &iris_base_url,
            OrganizationProjectionEvent {
                outbox_event_id: organization_event_id,
                organization_id,
                aggregate_type: "organization",
                aggregate_id: organization_id,
                aggregate_version: organization_version,
                event_type: "organization.updated.v1",
                before_state: Some(&organization_before),
                after_state: Some(&organization_after),
                metadata: &organization_metadata,
            },
        )
        .await?;

        sqlx::query(
            "UPDATE iam.oauth_consent_grants SET status = 'revoked', revoked_at = transaction_timestamp() WHERE id = $1",
        )
        .bind(full_consent_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.outbox_events (
                id, organization_id, aggregate_type, aggregate_id, aggregate_version,
                event_ordinal, event_type, schema_version, payload
            ) VALUES ($1, $2, 'organization', $2, $3, 2, 'organization.updated.v1', 1, '{}')
            ",
        )
        .bind(organization_before_only_event_id)
        .bind(organization_id)
        .bind(organization_version)
        .execute(&mut *transaction)
        .await?;
        capture_with_dependencies(
            &mut transaction,
            &crypto,
            &iris_base_url,
            OrganizationProjectionEvent {
                outbox_event_id: organization_before_only_event_id,
                organization_id,
                aggregate_type: "organization",
                aggregate_id: organization_id,
                aggregate_version: organization_version,
                event_type: "organization.updated.v1",
                before_state: Some(&organization_before),
                after_state: Some(&organization_after),
                metadata: &organization_metadata,
            },
        )
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.outbox_events (
                id, organization_id, aggregate_type, aggregate_id, aggregate_version,
                event_ordinal, event_type, schema_version, payload
            ) VALUES ($1, $2, 'organization_membership', $3, 1, 1, 'organization.membership.removed.v1', 1, '{}')
            ",
        )
        .bind(before_only_event_id)
        .bind(organization_id)
        .bind(silicon_membership_id)
        .execute(&mut *transaction)
        .await?;
        let removal_before = json!({ "status": "active", "version": 1 });
        let removal_after = json!({ "status": "removed", "version": 1 });
        let removal_metadata = json!({ "membership_id": silicon_membership_id });
        capture_with_dependencies(
            &mut transaction,
            &crypto,
            &iris_base_url,
            OrganizationProjectionEvent {
                outbox_event_id: before_only_event_id,
                organization_id,
                aggregate_type: "organization_membership",
                aggregate_id: silicon_membership_id,
                aggregate_version: 1,
                event_type: "organization.membership.removed.v1",
                before_state: Some(&removal_before),
                after_state: Some(&removal_after),
                metadata: &removal_metadata,
            },
        )
        .await?;
        transaction.commit().await?;

        sqlx::query("UPDATE iam.silicons SET display_name = 'Later' WHERE id = $1")
            .bind(silicon_id)
            .execute(&pool)
            .await?;
        let rows =
            sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid, uuid::Uuid, Vec<u8>, Vec<u8>, i16)>(
                r"
            SELECT outbox_event_id, id, application_id, payload_ciphertext,
                   payload_nonce, encryption_key_version
            FROM iam.application_webhook_event_projections
            WHERE outbox_event_id = ANY($1)
            ORDER BY outbox_event_id, application_id
            ",
            )
            .bind(vec![
                member_event_id,
                organization_event_id,
                organization_before_only_event_id,
                before_only_event_id,
            ])
            .fetch_all(&pool)
            .await?;
        let mut payloads = BTreeMap::new();
        for (event_id, projection_id, application_id, ciphertext, nonce, key_version) in rows {
            let nonce: [u8; 12] = nonce
                .try_into()
                .map_err(|_| anyhow::anyhow!("projection nonce length changed"))?;
            let plaintext = crypto.decrypt(
                EncryptionContext::tenant(
                    ProtectedField::ApplicationWebhookEventPayload,
                    application_id,
                    projection_id,
                ),
                &EncryptedValue {
                    key_version,
                    nonce,
                    ciphertext,
                },
            )?;
            payloads.insert(
                (event_id, application_id),
                serde_json::from_slice::<serde_json::Value>(&plaintext)?,
            );
        }

        let full_member = &payloads[&(member_event_id, full_application_id)];
        ensure!(
            full_member["current"]["members"]
                .as_array()
                .is_some_and(|v| v.len() == 1)
        );
        ensure!(full_member["current"]["members"][0]["principal"]["display_name"] == "Captured");
        ensure!(
            full_member["current"]["members"][0]["principal"]["profile_photo"]
                == "https://iris.teamofsilicons.com/pfp/silicon?id=helper:projection-org&level=1"
        );
        ensure!(
            full_member["current"]["members"][0]
                .get("organization")
                .is_some()
        );
        ensure!(
            full_member["current"]["members"][0]
                .get("membership")
                .is_some()
        );
        ensure!(full_member["current"]["members"][0].get("roles").is_some());
        ensure!(full_member["changed_fields"] == json!(["principal.display_name"]));

        let profile_member = &payloads[&(member_event_id, profile_application_id)];
        ensure!(
            profile_member["current"]["members"][0]
                .get("principal")
                .is_some()
        );
        ensure!(
            profile_member["current"]["members"][0]
                .get("organization")
                .is_none()
        );
        ensure!(
            profile_member["current"]["members"][0]
                .get("membership")
                .is_none()
        );
        ensure!(
            profile_member["current"]["members"][0]
                .get("roles")
                .is_none()
        );

        let organization = &payloads[&(organization_event_id, full_application_id)];
        ensure!(organization["current"]["organization"]["description"] == "After");
        ensure!(organization["current"].get("members").is_none());
        ensure!(organization["changed_fields"] == json!(["organization.description"]));
        ensure!(!payloads.contains_key(&(organization_event_id, profile_application_id)));

        let before_only = &payloads[&(before_only_event_id, full_application_id)];
        ensure!(
            before_only["changed_fields"]
                .as_array()
                .is_some_and(|fields| fields.iter().any(|field| field == "membership.status"))
        );
        ensure!(
            before_only["current"]["members"][0]
                == json!({
                    "resource": {
                        "type": "organization_membership",
                        "id": silicon_membership_id,
                        "principal_id": silicon_id,
                        "principal_type": "silicon",
                        "version": 1,
                        "status": "active",
                    },
                    "authorization": "removed",
                })
        );

        let organization_before_only =
            &payloads[&(organization_before_only_event_id, full_application_id)];
        ensure!(organization_before_only["changed_fields"] == json!(["organization.description"]));
        ensure!(
            organization_before_only["current"]["organization"]
                == json!({
                    "id": organization_id,
                    "version": organization_version,
                    "authorization": "removed",
                })
        );

        let recipients = sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid)>(
            r"
            SELECT endpoint_id, signing_key_id
            FROM iam_private.list_worker_captured_application_webhook_recipients($1)
            ",
        )
        .bind(organization_event_id)
        .fetch_all(&pool)
        .await?;
        ensure!(recipients == vec![(full_endpoint_id, full_signing_key_id)]);

        // Exercise 0034 on the same fresh schema. The removed Silicon sits one
        // level below the existing root, so reparenting its child to that root
        // changes both the child's parent and the grandchild's derived depth.
        // The owner also loses first-Silicon and explicit-access state, but is
        // still versioned exactly once.
        let removal_seed = format!(
            r"
            INSERT INTO iam.principals (id, kind, status, activated_at) VALUES
              ('{removed_silicon_id}', 'silicon', 'active', transaction_timestamp()),
              ('{child_silicon_id}', 'silicon', 'active', transaction_timestamp()),
              ('{grandchild_silicon_id}', 'silicon', 'active', transaction_timestamp());
            INSERT INTO iam.organization_memberships (
                id, organization_id, principal_id, principal_kind, org_role, job_role
            ) VALUES
              ('{removed_membership_id}', '{organization_id}', '{removed_silicon_id}', 'silicon', 'member', 'Removed'),
              ('{child_membership_id}', '{organization_id}', '{child_silicon_id}', 'silicon', 'member', 'Child'),
              ('{grandchild_membership_id}', '{organization_id}', '{grandchild_silicon_id}', 'silicon', 'member', 'Grandchild');
            INSERT INTO iam.silicons (
                id, organization_id, membership_id, organization_handle,
                silicon_handle, display_name, provisioning_status,
                reports_to_membership_id
            ) VALUES
              ('{removed_silicon_id}', '{organization_id}', '{removed_membership_id}',
               'projection-org', 'removed', 'Removed', 'active', '{silicon_membership_id}'),
              ('{child_silicon_id}', '{organization_id}', '{child_membership_id}',
               'projection-org', 'child', 'Child', 'active', '{removed_membership_id}'),
              ('{grandchild_silicon_id}', '{organization_id}', '{grandchild_membership_id}',
               'projection-org', 'grandchild', 'Grandchild', 'active', '{child_membership_id}');
            UPDATE iam.carbon_membership_settings
            SET first_silicon_membership_id = '{removed_membership_id}'
            WHERE organization_id = '{organization_id}'
              AND membership_id = '{actor_membership_id}';
            INSERT INTO iam.extra_silicon_access_grants (
                organization_id, carbon_membership_id, silicon_membership_id,
                granted_by_membership_id
            ) VALUES (
                '{organization_id}', '{actor_membership_id}',
                '{removed_membership_id}', '{actor_membership_id}'
            );
            INSERT INTO iam.authentication_sessions (
                id, subject_principal_id, subject_kind, authentication_method,
                subject_auth_epoch, idle_expires_at, absolute_expires_at
            ) VALUES (
                '{removed_session_id}', '{removed_silicon_id}', 'silicon',
                'silicon_credential', 1,
                transaction_timestamp() + interval '1 day',
                transaction_timestamp() + interval '2 days'
            );
            "
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(removal_seed))
            .execute(&pool)
            .await?;

        let replacement_versions_before = sqlx::query_as::<_, (i64, i64)>(
            r"
            SELECT membership.version, silicon.version
            FROM iam.organization_memberships AS membership
            JOIN iam.silicons AS silicon
              ON silicon.organization_id = membership.organization_id
             AND silicon.membership_id = membership.id
            WHERE membership.organization_id = $1 AND membership.id = $2
            ",
        )
        .bind(organization_id)
        .bind(silicon_membership_id)
        .fetch_one(&pool)
        .await?;

        let mut removal = pool.begin().await?;
        sqlx::query("SELECT set_config('iam.principal_id', $1, true)")
            .bind(actor_id.to_string())
            .execute(&mut *removal)
            .await?;
        sqlx::query("SELECT set_config('iam.organization_id', $1, true)")
            .bind(organization_id.to_string())
            .execute(&mut *removal)
            .await?;
        let affected = sqlx::query_scalar::<_, Vec<uuid::Uuid>>(
            "SELECT iam_private.lock_membership_removal_event_scope($1, $2, $3)",
        )
        .bind(organization_id)
        .bind(removed_membership_id)
        .bind(silicon_membership_id)
        .fetch_one(&mut *removal)
        .await?;
        ensure!(
            affected.into_iter().collect::<BTreeSet<_>>()
                == BTreeSet::from([
                    actor_membership_id,
                    removed_membership_id,
                    child_membership_id,
                    grandchild_membership_id,
                ])
        );
        let removed_versions = sqlx::query_as::<_, (i64, Option<i64>)>(
            r"
            SELECT membership_version, silicon_version
            FROM iam_private.remove_organization_membership($1, $2, 1, 1, $3)
            ",
        )
        .bind(organization_id)
        .bind(removed_membership_id)
        .bind(silicon_membership_id)
        .fetch_one(&mut *removal)
        .await?;
        ensure!(removed_versions == (2, Some(2)));
        removal.commit().await?;

        let membership_versions = sqlx::query_as::<_, (uuid::Uuid, String, i64, i64)>(
            r"
            SELECT id, status, version, authz_epoch
            FROM iam.organization_memberships
            WHERE organization_id = $1 AND id = ANY($2)
            ORDER BY id
            ",
        )
        .bind(organization_id)
        .bind(vec![
            actor_membership_id,
            removed_membership_id,
            child_membership_id,
            grandchild_membership_id,
        ])
        .fetch_all(&pool)
        .await?
        .into_iter()
        .collect::<Vec<_>>();
        let membership_versions = membership_versions
            .into_iter()
            .map(|(id, status, version, epoch)| (id, (status, version, epoch)))
            .collect::<BTreeMap<_, _>>();
        ensure!(membership_versions[&removed_membership_id] == ("removed".to_owned(), 2, 2));
        ensure!(membership_versions[&actor_membership_id] == ("active".to_owned(), 2, 2));
        ensure!(membership_versions[&child_membership_id] == ("active".to_owned(), 2, 1));
        ensure!(membership_versions[&grandchild_membership_id] == ("active".to_owned(), 2, 1));

        let child_state = sqlx::query_as::<_, (Option<uuid::Uuid>, i64)>(
            "SELECT reports_to_membership_id, version FROM iam.silicons WHERE organization_id = $1 AND membership_id = $2",
        )
        .bind(organization_id)
        .bind(child_membership_id)
        .fetch_one(&pool)
        .await?;
        ensure!(child_state == (Some(silicon_membership_id), 2));
        let grandchild_version = sqlx::query_scalar::<_, i64>(
            "SELECT version FROM iam.silicons WHERE organization_id = $1 AND membership_id = $2",
        )
        .bind(organization_id)
        .bind(grandchild_membership_id)
        .fetch_one(&pool)
        .await?;
        ensure!(grandchild_version == 2);
        let replacement_versions_after = sqlx::query_as::<_, (i64, i64)>(
            r"
            SELECT membership.version, silicon.version
            FROM iam.organization_memberships AS membership
            JOIN iam.silicons AS silicon
              ON silicon.organization_id = membership.organization_id
             AND silicon.membership_id = membership.id
            WHERE membership.organization_id = $1 AND membership.id = $2
            ",
        )
        .bind(organization_id)
        .bind(silicon_membership_id)
        .fetch_one(&pool)
        .await?;
        ensure!(replacement_versions_after == replacement_versions_before);
        let removed_session = sqlx::query_as::<_, (String, i64)>(
            "SELECT status, version FROM iam.authentication_sessions WHERE id = $1",
        )
        .bind(removed_session_id)
        .fetch_one(&pool)
        .await?;
        ensure!(removed_session == ("revoked".to_owned(), 2));
        Ok(())
    }
}
