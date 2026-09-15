//! Accepted bundle membership supplied by Honeycomb.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedConfiguration {
    operation_id: Uuid,
    expected_iam_revision: i64,
    configuration_revision: i64,
    environment_id: Option<Uuid>,
    app_name: Option<String>,
    app_logo: Option<String>,
    app_ids: Vec<String>,
    #[serde(default)]
    deleted: bool,
}
pub(super) fn router() -> Router<ApiState> {
    Router::new().route(
        "/api/v1/honeycomb/bundles/{bundle_id}/configuration",
        put(configure),
    )
}
async fn configure(
    State(state): State<ApiState>,
    service: Service,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    validation::app_id(&path)?;
    let input: AcceptedConfiguration = decode(&body)?;
    if input.environment_id.is_some() {
        return Err(ApiError::forbidden("use_testing_lifecycle_integration"));
    }
    if input.expected_iam_revision < 0 || input.configuration_revision <= 0 {
        return Err(ApiError::validation("revision", "invalid revision"));
    }
    validation::optional_text("app_name", input.app_name.as_deref(), 1, 200)?;
    validation::optional_https_uri("app_logo", input.app_logo.as_deref(), 2048)?;
    for app in &input.app_ids {
        validation::app_id(app)?;
    }
    let (org, slug) = path.split_once('>').ok_or_else(ApiError::not_found)?;
    let actor = service.actor(&state, &headers).await?;
    let mut tx = begin(&state, &actor).await?;
    manager(&mut tx, &actor, org).await?;
    if let Some(response) = claim(
        &mut tx,
        &state,
        &service,
        &actor.subject,
        &headers,
        input.operation_id,
        "bundle-configure",
        &path,
        &body,
    )
    .await?
    {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("honeycomb_bundle_replay"))?;
        return Ok(management_response(response, true));
    }
    let existing: Option<(i64, i64)> =
        sqlx::query_as("SELECT * FROM iam_private.honeycomb_bundle_revision($1,NULL)")
            .bind(&path)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| ApiError::internal("honeycomb_bundle_read"))?;
    if existing.map_or(0, |value| value.0) != input.expected_iam_revision {
        return Err(ApiError::conflict("iam_revision_conflict"));
    }
    if existing.is_some_and(|value| value.1 >= input.configuration_revision) {
        return Err(ApiError::conflict("configuration_revision_conflict"));
    }
    let action = if input.deleted {
        "delete"
    } else if existing.is_some() {
        "update"
    } else {
        "create"
    };
    let accepted = json!({"org_id":org,"app_id":slug,"app_name":input.app_name,"app_logo":input.app_logo,"app_ids":input.app_ids});
    let (_, value): (Uuid, sqlx::types::Json<Value>) =
        sqlx::query_as("SELECT * FROM iam_private.mutate_application_bundle($1,$2,$3,$4,$5)")
            .bind(&path)
            .bind(actor.subject.id)
            .bind(input.expected_iam_revision)
            .bind(action)
            .bind(sqlx::types::Json(accepted))
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| super::super::super::bundles::database_error(&error))?;
    let revision: i64 =
        sqlx::query_scalar("SELECT version FROM iam_private.honeycomb_bundle_revision($1,$2)")
            .bind(&path)
            .bind(input.configuration_revision)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ApiError::internal("honeycomb_bundle_revision"))?;
    let mut value = value.0;
    value["version"] = json!(revision);
    value["configuration_revision"] = json!(input.configuration_revision);
    let response = json!({"operation_id":input.operation_id,"state":"accepted","iam_revision":revision,"effective_configuration":value});
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
        .map_err(|_| ApiError::internal("honeycomb_bundle_commit"))?;
    Ok(management_response(response, false))
}
