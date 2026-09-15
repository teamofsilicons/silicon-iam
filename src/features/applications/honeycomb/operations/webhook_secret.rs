//! Stepped-up rotation of webhook signing credentials through Honeycomb.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    operation_id: Uuid,
    expected_iam_revision: i64,
    environment_id: Option<Uuid>,
    webhook_secret: String,
}
pub(super) fn router() -> Router<ApiState> {
    Router::new().route(
        "/api/v1/honeycomb/applications/{app_id}/webhook-secret-rotations",
        post(rotate),
    )
}
async fn rotate(
    State(state): State<ApiState>,
    service: Service,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    validation::app_id(&path)?;
    let input: Input = decode(&body)?;
    validation::webhook_secret(&input.webhook_secret)?;
    if input.environment_id.is_some() {
        return Err(ApiError::forbidden("use_testing_lifecycle_integration"));
    }
    let actor = service.actor(&state, &headers).await?;
    let mut tx = begin(&state, &actor).await?;
    security::lock_step_up_actor(&mut tx, actor.subject.id).await?;
    manager(
        &mut tx,
        &actor,
        path.split_once('>').map_or("", |(org, _)| org),
    )
    .await?;
    if let Some(response) = claim(
        &mut tx,
        &state,
        &service,
        &actor.subject,
        &headers,
        input.operation_id,
        "rotate-webhook-secret",
        &path,
        &body,
    )
    .await?
    {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("webhook_rotation_replay"))?;
        return Ok(management_response(response, true));
    }
    let app = applications::resolve_technical_app(&mut tx, actor.subject.id, &path, true).await?;
    if app.version != input.expected_iam_revision {
        return Err(ApiError::conflict("iam_revision_conflict"));
    }
    security::require_step_up(
        &mut tx,
        &state.crypto,
        &headers,
        &actor,
        "application.webhook_secret.rotate",
        app.id,
        crate::infrastructure::postgres::step_up::RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let endpoints:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM iam.application_webhook_endpoints WHERE application_id=$1 AND status IN ('active','pending_review') ORDER BY id FOR UPDATE").bind(app.id).fetch_all(&mut *tx).await.map_err(|_|ApiError::internal("webhook_rotation_endpoints"))?;
    if endpoints.is_empty() {
        return Err(ApiError::conflict("application_webhook_not_configured"));
    }
    let mut version:i64=sqlx::query_scalar("SELECT COALESCE(max(secret_version),0) FROM iam.application_webhook_signing_keys WHERE application_id=$1").bind(app.id).fetch_one(&mut *tx).await.map_err(|_|ApiError::internal("webhook_rotation_version"))?;
    sqlx::query("UPDATE iam.application_webhook_signing_keys SET status='retiring',retires_at=transaction_timestamp()+interval '10 minutes' WHERE application_id=$1 AND status='active'").bind(app.id).execute(&mut *tx).await.map_err(|_|ApiError::internal("webhook_rotation_retire"))?;
    for endpoint in endpoints {
        let id = Uuid::now_v7();
        version += 1;
        let encrypted = state
            .crypto
            .encrypt(
                EncryptionContext::tenant(
                    ProtectedField::ApplicationWebhookSigningSecret,
                    app.id,
                    id,
                ),
                input.webhook_secret.as_bytes(),
            )
            .map_err(|_| ApiError::internal("webhook_rotation_encrypt"))?;
        sqlx::query("INSERT INTO iam.application_webhook_signing_keys(id,application_id,endpoint_id,secret_version,key_prefix,secret_ciphertext,secret_nonce,encryption_key_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(id).bind(app.id).bind(endpoint).bind(version).bind(applications::webhook_secret_fingerprint(&input.webhook_secret)).bind(encrypted.ciphertext).bind(encrypted.nonce.as_slice()).bind(encrypted.key_version).execute(&mut *tx).await.map_err(|_|ApiError::internal("webhook_rotation_write"))?;
    }
    let revision = applications::bump_application(&mut tx, app.id).await?;
    let response = json!({"operation_id":input.operation_id,"state":"accepted","iam_revision":revision,"app_id":path,"webhook_secret_version":version});
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
        .map_err(|_| ApiError::internal("webhook_rotation_commit"))?;
    Ok(management_response(response, false))
}
