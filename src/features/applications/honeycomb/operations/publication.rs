//! Exact desired-revision publication with immutable plans and live authority.
use super::*;
use axum::{extract::Query, routing::get};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanRequest {
    request_id: Id,
    app_id: String,
    configuration_revision: i64,
    configuration: Value,
    visibility: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionRequest {
    operation_id: Id,
    request_id: Id,
    plan_id: Id,
    app_id: String,
    configuration_revision: i64,
    provider: String,
    scopes: Vec<String>,
    decision: String,
    reason: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationRequest {
    operation_id: Id,
    request_id: Id,
    plan_id: Id,
    app_id: String,
    configuration_revision: i64,
    expected_iam_revision: i64,
    configuration: Value,
    visibility: String,
    decision_ids: Vec<Id>,
    #[serde(default)]
    configuration_operations: Vec<Id>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderQuery {
    provider: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipientQuery {
    provider: String,
    after: Option<Id>,
    #[serde(default = "recipient_limit")]
    limit: i32,
}
const fn recipient_limit() -> i32 {
    100
}

pub(super) fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/honeycomb/organizations/{org_id}/notification-recipients",
            get(organization_recipients),
        )
        .route(
            "/api/v1/honeycomb/applications/{app_id}/publication-plans",
            post(plan),
        )
        .route(
            "/api/v1/honeycomb/applications/{app_id}/publication-decisions",
            post(decide),
        )
        .route(
            "/api/v1/honeycomb/applications/{app_id}/publication-activations",
            post(activate),
        )
        .route("/api/v1/honeycomb/publication-plans/{plan_id}", get(read))
        .route(
            "/api/v1/honeycomb/publication-plans/{plan_id}/reviewer-eligibility",
            get(eligibility),
        )
        .route(
            "/api/v1/honeycomb/publication-plans/{plan_id}/notification-recipients",
            get(recipients),
        )
}

/// The digest covers semantic configuration, including the secret if supplied,
/// but never an operation/revision precondition. No raw configuration is stored.
pub(super) fn configuration_digest(input: &AcceptedConfiguration) -> Result<Vec<u8>, ApiError> {
    let mut value = serde_json::to_value(input)
        .map_err(|_| ApiError::internal("publication_configuration_encode"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| ApiError::internal("publication_configuration_shape"))?;
    for field in [
        "operation_id",
        "expected_iam_revision",
        "publication_approved",
    ] {
        object.remove(field);
    }
    let bytes = serde_json::to_vec(&value)
        .map_err(|_| ApiError::internal("publication_configuration_encode"))?;
    Ok(Sha256::digest(bytes).to_vec())
}

fn configuration(
    path: &str,
    revision: i64,
    operation: Id,
    expected: i64,
    visibility: &str,
    value: &Value,
) -> Result<AcceptedConfiguration, ApiError> {
    if visibility != "public" {
        return Err(ApiError::validation(
            "visibility",
            "publication requires public visibility",
        ));
    }
    let mut value = value.clone();
    let object = value
        .as_object_mut()
        .ok_or_else(|| ApiError::validation("configuration", "expected an object"))?;
    // Required envelope identities may be repeated, but never contradicted.
    for (key, expected_value) in [
        ("app_id", json!(path)),
        ("configuration_revision", json!(revision)),
        ("visibility", json!("public")),
    ] {
        if object
            .get(key)
            .is_some_and(|current| current != &expected_value)
        {
            return Err(ApiError::conflict("publication_configuration_mismatch"));
        }
        object.insert(key.into(), expected_value);
    }
    object.insert("operation_id".into(), json!(operation));
    object.insert("expected_iam_revision".into(), json!(expected));
    object.insert("publication_approved".into(), json!(true));
    let input: AcceptedConfiguration = serde_json::from_value(value)
        .map_err(|_| ApiError::validation("configuration", "invalid accepted configuration"))?;
    validate_configuration(path, &input)?;
    if input.availability != "active" {
        return Err(ApiError::validation(
            "availability",
            "publication requires active availability",
        ));
    }
    Ok(input)
}

async fn plan(
    State(state): State<ApiState>,
    service: Service,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let input: PlanRequest = decode(&body)?;
    if path != input.app_id {
        return Err(ApiError::conflict("application_identity_immutable"));
    }
    let desired = configuration(
        &path,
        input.configuration_revision,
        input.request_id,
        0,
        &input.visibility,
        &input.configuration,
    )?;
    let actor = service.actor(&state, &headers).await?;
    let mut tx = begin(&state, &actor).await?;
    manager(&mut tx, &actor, &desired.org_id).await?;
    if let Some(response) = claim(
        &mut tx,
        &state,
        &service,
        &actor.subject,
        &headers,
        input.request_id,
        "publication-plan",
        &path,
        &body,
    )
    .await?
    {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("publication_replay"))?;
        return Ok(management_response(response, true));
    }
    validate_current_revision(&mut tx, &state, &service, &desired).await?;
    let response = sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "SELECT iam_private.honeycomb_publication_plan($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(service.application_id)
    .bind(actor.subject.id)
    .bind(input.request_id)
    .bind(&path)
    .bind(input.configuration_revision)
    .bind(configuration_digest(&desired)?)
    .bind(sqlx::types::Json(&desired.app_scope))
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| database_error(&error))?
    .0;
    let revision = application_revision(&mut tx, &service, &path).await?;
    complete(
        &mut tx,
        &state,
        &service,
        input.request_id,
        &path,
        revision,
        &response,
        false,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("publication_plan_commit"))?;
    Ok(management_response(response, false))
}

async fn reviewer(
    tx: &mut Transaction<'_, Postgres>,
    actor: &AccessContext,
    provider: &str,
) -> Result<(), ApiError> {
    match provider {
        "iam" => {
            security::require_platform_capability(tx, actor.subject.id, "applications.review")
                .await?;
        }
        "honeycomb" => {
            security::require_platform_capability(
                tx,
                actor.subject.id,
                "honeycomb.applications.review",
            )
            .await?;
        }
        other => {
            validation::app_id(other)?;
            let (org, _) = other.split_once('>').ok_or_else(ApiError::not_found)?;
            manager(tx, actor, org).await?;
        }
    }
    Ok(())
}
async fn decide(
    State(state): State<ApiState>,
    service: Service,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let input: DecisionRequest = decode(&body)?;
    validation::app_id(&path)?;
    if path != input.app_id {
        return Err(ApiError::conflict("application_identity_immutable"));
    }
    validation::optional_text("reason", input.reason.as_deref(), 1, 2000)?;
    if input.scopes.len() > 100 || !matches!(input.decision.as_str(), "approve" | "deny") {
        return Err(ApiError::validation(
            "decision",
            "expected approve or deny and at most 100 exact scopes",
        ));
    }
    let actor = service.actor(&state, &headers).await?;
    let mut tx = begin(&state, &actor).await?;
    reviewer(&mut tx, &actor, &input.provider).await?;
    if let Some(response) = claim(
        &mut tx,
        &state,
        &service,
        &actor.subject,
        &headers,
        input.operation_id,
        "publication-decision",
        &path,
        &body,
    )
    .await?
    {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("publication_replay"))?;
        return Ok(management_response(response, true));
    }
    let response = sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "SELECT iam_private.honeycomb_publication_decide($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(service.application_id)
    .bind(actor.subject.id)
    .bind(input.operation_id)
    .bind(input.request_id)
    .bind(input.plan_id)
    .bind(&path)
    .bind(input.configuration_revision)
    .bind(&input.provider)
    .bind(&input.scopes)
    .bind(&input.decision)
    .bind(&input.reason)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| database_error(&error))?
    .0;
    let revision = application_revision(&mut tx, &service, &path).await?;
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
        .map_err(|_| ApiError::internal("publication_decision_commit"))?;
    Ok(management_response(response, false))
}
async fn application_revision(
    tx: &mut Transaction<'_, Postgres>,
    service: &Service,
    path: &str,
) -> Result<i64, ApiError> {
    let value = sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "SELECT iam_private.honeycomb_application_record($1,$2)",
    )
    .bind(service.application_id)
    .bind(path)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::internal("publication_application_record"))?;
    value.0["iam_revision"]
        .as_i64()
        .ok_or_else(|| ApiError::internal("publication_application_revision"))
}
async fn activate(
    State(state): State<ApiState>,
    service: Service,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let input: ActivationRequest = decode(&body)?;
    if path != input.app_id {
        return Err(ApiError::conflict("application_identity_immutable"));
    }
    if input.decision_ids.len() > 101 || input.configuration_operations.len() > 100 {
        return Err(ApiError::validation(
            "operations",
            "too many review decisions or pending operations",
        ));
    }
    let desired = configuration(
        &path,
        input.configuration_revision,
        input.operation_id,
        input.expected_iam_revision,
        &input.visibility,
        &input.configuration,
    )?;
    let actor = service.actor(&state, &headers).await?;
    let mut tx = begin(&state, &actor).await?;
    let organization = manager(&mut tx, &actor, &desired.org_id).await?;
    if let Some(response) = claim(
        &mut tx,
        &state,
        &service,
        &actor.subject,
        &headers,
        input.operation_id,
        "publication-activation",
        &path,
        &body,
    )
    .await?
    {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("publication_replay"))?;
        return Ok(management_response(response, true));
    }
    validate_current_revision(&mut tx, &state, &service, &desired).await?;
    let app = sqlx::query_scalar::<_, Id>(
        "SELECT iam_private.honeycomb_publication_accept($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(service.application_id)
    .bind(actor.subject.id)
    .bind(input.request_id)
    .bind(input.plan_id)
    .bind(&path)
    .bind(input.configuration_revision)
    .bind(input.expected_iam_revision)
    .bind(configuration_digest(&desired)?)
    .bind(&input.decision_ids)
    .bind(&input.configuration_operations)
    .bind(sqlx::types::Json(&desired.app_scope))
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| database_error(&error))?;
    let current = sqlx::query_as::<_, (Id, i64, String)>(
        "SELECT id,version,visibility FROM iam.applications WHERE id=$1 FOR UPDATE",
    )
    .bind(app)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| ApiError::internal("publication_configuration_read"))?;
    apply_configuration(
        &mut tx,
        &state,
        &actor,
        organization,
        &desired,
        Some(current),
    )
    .await?;
    let effective = sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "SELECT iam_private.honeycomb_application_record($1,$2)",
    )
    .bind(service.application_id)
    .bind(&path)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| ApiError::internal("publication_effective_record"))?
    .0;
    let revision = effective["iam_revision"]
        .as_i64()
        .ok_or_else(|| ApiError::internal("publication_effective_revision"))?;
    if revision <= input.expected_iam_revision
        || effective["visibility"] != "public"
        || effective["availability"] != "verified"
    {
        return Err(ApiError::conflict("publication_activation_incomplete"));
    }
    let response = json!({"operation_id":input.operation_id,"request_id":input.request_id,"publication_request_id":input.request_id,"plan_id":input.plan_id,
        "app_id":path,"configuration_revision":input.configuration_revision,"state":"accepted","visibility":"public","iam_revision":revision,"effective_configuration":effective});
    sqlx::query("SELECT iam_private.honeycomb_publication_complete_pending($1,$2,$3)")
        .bind(service.application_id)
        .bind(&input.configuration_operations)
        .bind(sqlx::types::Json(&response))
        .execute(&mut *tx)
        .await
        .map_err(|error| database_error(&error))?;
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
        .map_err(|_| ApiError::internal("publication_activation_commit"))?;
    Ok(management_response(response, false))
}
async fn read_plan(state: &ApiState, service: &Service, plan: Id) -> Result<Value, ApiError> {
    sqlx::query_scalar::<_, Option<sqlx::types::Json<Value>>>(
        "SELECT iam_private.honeycomb_publication_read($1,$2)",
    )
    .bind(service.application_id)
    .bind(plan)
    .fetch_one(&state.pool)
    .await
    .map_err(|_| ApiError::internal("publication_plan_read"))?
    .map(|value| value.0)
    .ok_or_else(ApiError::not_found)
}
async fn read(
    State(state): State<ApiState>,
    service: Service,
    Path(plan): Path<Id>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(read_plan(&state, &service, plan).await?))
}
fn require_provider(plan: &Value, provider: &str, owners: bool) -> Result<(), ApiError> {
    if (owners && provider == "owners")
        || plan["gates"]
            .as_array()
            .is_some_and(|gates| gates.iter().any(|gate| gate["provider"] == provider))
    {
        Ok(())
    } else {
        Err(ApiError::validation(
            "provider",
            "provider is not a gate on this plan",
        ))
    }
}
async fn eligibility(
    State(state): State<ApiState>,
    service: Service,
    Path(plan): Path<Id>,
    Query(query): Query<ProviderQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let receipt = read_plan(&state, &service, plan).await?;
    require_provider(&receipt, &query.provider, false)?;
    let actor = service.actor(&state, &headers).await?;
    let mut tx = begin(&state, &actor).await?;
    let eligible = if reviewer(&mut tx, &actor, &query.provider).await.is_ok() {
        sqlx::query_scalar::<_, bool>("SELECT iam_private.honeycomb_reviewer_eligible($1,$2)")
            .bind(actor.subject.id)
            .bind(&query.provider)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ApiError::internal("publication_reviewer_eligibility"))?
    } else {
        false
    };
    tx.rollback()
        .await
        .map_err(|_| ApiError::internal("publication_eligibility_rollback"))?;
    Ok(Json(
        json!({"plan_id":plan,"provider":query.provider,"actor_id":actor.subject.id,"eligible":eligible}),
    ))
}
#[derive(sqlx::FromRow)]
struct Recipient {
    principal_id: Id,
    contact_id: Id,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    encryption_key_version: i16,
}
async fn recipients(
    State(state): State<ApiState>,
    service: Service,
    Path(plan): Path<Id>,
    Query(query): Query<RecipientQuery>,
) -> Result<Json<Value>, ApiError> {
    if !(1..=1000).contains(&query.limit) {
        return Err(ApiError::validation("limit", "must be between 1 and 1000"));
    }
    let receipt = read_plan(&state, &service, plan).await?;
    require_provider(&receipt, &query.provider, true)?;
    let rows = sqlx::query_as::<_, Recipient>(
        "SELECT * FROM iam_private.honeycomb_publication_recipients($1,$2,$3,$4,$5)",
    )
    .bind(service.application_id)
    .bind(plan)
    .bind(&query.provider)
    .bind(query.after.map(|id| id.to_string()))
    .bind(query.limit)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| ApiError::internal("publication_recipients"))?;
    let (recipients, next_cursor) = recipient_page(&state, rows, query.limit)?;
    Ok(Json(
        json!({"plan_id":plan,"provider":query.provider,"recipients":recipients,"next_cursor":next_cursor}),
    ))
}

fn recipient_page(
    state: &ApiState,
    mut rows: Vec<Recipient>,
    requested_limit: i32,
) -> Result<(Vec<Value>, Option<Id>), ApiError> {
    let limit = usize::try_from(requested_limit)
        .map_err(|_| ApiError::internal("publication_recipient_limit"))?;
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = if has_more {
        rows.last().map(|row| row.principal_id)
    } else {
        None
    };
    let mut recipients = Vec::with_capacity(rows.len());
    for row in rows {
        let nonce = row
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| ApiError::internal("publication_recipient_nonce"))?;
        let plaintext = state
            .crypto
            .decrypt(
                EncryptionContext::global(ProtectedField::CarbonEmail, row.contact_id),
                &EncryptedValue {
                    key_version: row.encryption_key_version,
                    nonce,
                    ciphertext: row.ciphertext,
                },
            )
            .map_err(|_| ApiError::internal("publication_recipient_decrypt"))?;
        let email = String::from_utf8(plaintext.to_vec())
            .map_err(|_| ApiError::internal("publication_recipient_encoding"))?;
        recipients.push(json!({"carbon_id":row.principal_id,"email":email}));
    }
    Ok((recipients, next_cursor))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrganizationRecipientQuery {
    after: Option<Id>,
    #[serde(default = "recipient_limit")]
    limit: i32,
}
async fn organization_recipients(
    State(state): State<ApiState>,
    service: Service,
    Path(org_id): Path<String>,
    Query(query): Query<OrganizationRecipientQuery>,
) -> Result<Json<Value>, ApiError> {
    validation::org_id(&org_id)?;
    if !(1..=1000).contains(&query.limit) {
        return Err(ApiError::validation("limit", "must be between 1 and 1000"));
    }
    let rows = sqlx::query_as::<_, Recipient>(
        "SELECT * FROM iam_private.honeycomb_organization_recipients($1,$2,$3,$4)",
    )
    .bind(service.application_id)
    .bind(&org_id)
    .bind(query.after.map(|id| id.to_string()))
    .bind(query.limit)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| ApiError::internal("honeycomb_organization_recipients"))?;
    let (recipients, next_cursor) = recipient_page(&state, rows, query.limit)?;
    Ok(Json(
        json!({"org_id":org_id,"recipients":recipients,"next_cursor":next_cursor}),
    ))
}

fn database_error(error: &sqlx::Error) -> ApiError {
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .as_deref()
    {
        Some("42501") => ApiError::forbidden("publication_authority_required"),
        Some("40001" | "23505") => ApiError::conflict("publication_revision_or_plan_conflict"),
        Some("22023" | "23514") => ApiError::validation(
            "publication",
            "request does not match the immutable review plan",
        ),
        Some("P0002") => ApiError::not_found(),
        _ => ApiError::internal("publication_database"),
    }
}

/// Publishing a saved private revision changes visibility only. A higher desired
/// revision may carry reviewed edits; equality must match the current accepted
/// configuration under the same application lock used by activation.
async fn validate_current_revision(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    service: &Service,
    desired: &AcceptedConfiguration,
) -> Result<(), ApiError> {
    let (app, revision, visibility): (Id, i64, String) = sqlx::query_as(
        "SELECT id,honeycomb_configuration_revision,visibility FROM iam.applications WHERE app_id=$1 AND deleted_at IS NULL FOR UPDATE")
        .bind(&desired.app_id).fetch_optional(&mut **tx).await
        .map_err(|_| ApiError::internal("publication_current_configuration"))?.ok_or_else(ApiError::not_found)?;
    if revision != desired.configuration_revision {
        return Ok(());
    }
    if visibility != "private" {
        return Err(ApiError::conflict(
            "publication_configuration_revision_conflict",
        ));
    }
    let current = sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "SELECT iam_private.honeycomb_application_record($1,$2)",
    )
    .bind(service.application_id)
    .bind(&desired.app_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::internal("publication_current_configuration"))?
    .0;
    let mut endpoints = serde_json::to_value(&desired.obo_endpoints)
        .map_err(|_| ApiError::internal("publication_endpoint_encode"))?;
    if let Some(endpoints) = endpoints.as_array_mut() {
        endpoints.sort_by(|left, right| {
            left["endpoint_id"]
                .as_str()
                .cmp(&right["endpoint_id"].as_str())
        });
    }
    let expected = json!({"app_id":desired.app_id,"org_id":desired.org_id,"app_name":desired.name,
        "app_logo":desired.logo_url,"base_url":desired.base_url,"availability":"verified",
        "app_scope":desired.app_scope,"webhook_scope":desired.webhook.scope,"obo_endpoints":endpoints,
        "obo_review_message":desired.obo_review_message,"testing_idle_days":desired.testing_idle_days});
    if expected.as_object().is_none_or(|fields| {
        fields
            .iter()
            .any(|(key, value)| current.get(key) != Some(value))
    }) {
        return Err(ApiError::conflict("publication_configuration_mismatch"));
    }
    let destination: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT url_digest FROM iam.application_webhook_endpoints WHERE application_id=$1 AND status IN ('active','pending_review') ORDER BY (status='pending_review') DESC,created_at DESC LIMIT 1")
        .bind(app).fetch_optional(&mut **tx).await.map_err(|_|ApiError::internal("publication_current_webhook"))?;
    if destination.as_deref() != Some(Sha256::digest(desired.webhook.url.as_bytes()).as_slice()) {
        return Err(ApiError::conflict("publication_configuration_mismatch"));
    }
    // The matching destination exists, so this branch only verifies a supplied
    // signing secret and cannot create or rotate webhook material.
    configure_webhook(tx, state, app, &desired.webhook).await
}
