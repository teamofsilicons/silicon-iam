//! Reviewed, actor-bound application delegation credentials managed by Honeycomb.
use super::super::super::ata_catalog::{self, Dependency};
use super::*;

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    operation_id: Option<Id>,
    #[serde(default)]
    app_ids: Vec<String>,
    endpoints: Vec<Dependency>,
    expires_after: Option<i64>,
    #[serde(default = "default_access_ttl")]
    access_token_validity: i32,
    graph_version: Option<String>,
}
const fn default_access_ttl() -> i32 {
    1800
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeInput {
    operation_id: Id,
}

pub(super) fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/honeycomb/applications/{app_id}/ata-verifications",
            axum::routing::get(list).post(create),
        )
        .route(
            "/api/v1/honeycomb/applications/{app_id}/ata-verifications/preview",
            post(preview),
        )
        .route(
            "/api/v1/honeycomb/applications/{app_id}/ata-verifications/{id}/revoke",
            post(revoke),
        )
}

fn validate(input: &Input) -> Result<(), ApiError> {
    if !(60..=86400).contains(&input.access_token_validity) {
        return Err(ApiError::validation(
            "access_token_validity",
            "must be between 60 and 86400 seconds",
        ));
    }
    if input.expires_after.is_some_and(|v| {
        v < 3600
            || OffsetDateTime::now_utc()
                .checked_add(Duration::seconds(v))
                .is_none()
    }) {
        return Err(ApiError::validation(
            "expires_after",
            "must be at least one hour; use null for never",
        ));
    }
    if !(1..=64).contains(&input.endpoints.len()) || input.app_ids.len() > 64 {
        return Err(ApiError::validation("endpoints", "select 1–64 endpoints"));
    }
    let mut keys = std::collections::BTreeSet::new();
    for endpoint in &input.endpoints {
        validation::app_id(&endpoint.audience)?;
        if !ata_catalog::valid_local_id(&endpoint.endpoint_id)
            || !keys.insert((&endpoint.audience, &endpoint.endpoint_id))
        {
            return Err(ApiError::validation(
                "endpoints",
                "select distinct application and ATA endpoint pairs",
            ));
        }
    }
    let mut apps = std::collections::BTreeSet::new();
    for app in &input.app_ids {
        validation::app_id(app)?;
        if !apps.insert(app) {
            return Err(ApiError::validation(
                "app_ids",
                "select distinct recipient applications",
            ));
        }
    }
    Ok(())
}

async fn graph(
    tx: &mut Transaction<'_, Postgres>,
    app: Id,
    input: &Input,
) -> Result<Value, ApiError> {
    let value = sqlx::query_scalar::<_, Option<sqlx::types::Json<Value>>>(
        "SELECT iam_private.application_ata_graph($1,$2)",
    )
    .bind(app)
    .bind(sqlx::types::Json(&input.endpoints))
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::internal("ata_graph_review"))?
    .ok_or_else(|| {
        ApiError::validation(
            "endpoints",
            "the endpoint chain is unavailable, cyclic or exceeds its limits",
        )
    })?;
    Ok(value.0)
}
fn review(app: &str, input: &Input, graph: &Value) -> Result<Value, ApiError> {
    let entries = graph
        .as_array()
        .ok_or_else(|| ApiError::internal("ata_graph_shape"))?;
    let apps: std::collections::BTreeSet<_> = entries
        .iter()
        .filter_map(|v| v["app_id"].as_str())
        .collect();
    let endpoints: Vec<_> = entries
        .iter()
        .map(|v| json!({"audience":v["app_id"],"endpoint_id":v["endpoint_id"]}))
        .collect();
    let selected_apps: std::collections::BTreeSet<_> =
        input.app_ids.iter().map(String::as_str).collect();
    let selected_endpoints: std::collections::BTreeSet<_> = input
        .endpoints
        .iter()
        .map(|v| (v.audience.as_str(), v.endpoint_id.as_str()))
        .collect();
    let expanded_endpoints: std::collections::BTreeSet<_> = entries
        .iter()
        .filter_map(|v| Some((v["app_id"].as_str()?, v["endpoint_id"].as_str()?)))
        .collect();
    Ok(
        json!({"app_id":app,"app_ids":apps,"endpoints":endpoints,"graph":graph,
        "graph_version":hex::encode(Sha256::digest(graph.to_string().as_bytes())),
        "requires_expansion":selected_apps!=apps || selected_endpoints!=expanded_endpoints}),
    )
}
async fn authorize<'a>(
    state: &'a ApiState,
    service: &Service,
    headers: &HeaderMap,
    app: &str,
) -> Result<(Transaction<'a, Postgres>, AccessContext, Id, i64), ApiError> {
    validation::app_id(app)?;
    let actor = service.actor(state, headers).await?;
    let mut tx = begin(state, &actor).await?;
    let org = application_org(&mut tx, app).await?;
    manager(&mut tx, &actor, &org).await?;
    let application =
        applications::resolve_technical_app(&mut tx, actor.subject.id, app, true).await?;
    Ok((tx, actor, application.id, application.version))
}

async fn preview(
    State(state): State<ApiState>,
    service: Service,
    Path(app): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Input>,
) -> Result<Response, ApiError> {
    validate(&input)?;
    let (mut tx, _, id, _) = authorize(&state, &service, &headers, &app).await?;
    let graph = graph(&mut tx, id, &input).await?;
    let response = review(&app, &input, &graph)?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("ata_preview_commit"))?;
    Ok(Json(response).into_response())
}

async fn create(
    State(state): State<ApiState>,
    service: Service,
    Path(app): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let input: Input = decode(&body)?;
    validate(&input)?;
    let operation = input
        .operation_id
        .ok_or_else(|| ApiError::validation("operation_id", "is required"))?;
    let (mut tx, actor, id, revision) = authorize(&state, &service, &headers, &app).await?;
    if let Some(response) = claim(
        &mut tx,
        &state,
        &service,
        &actor.subject,
        &headers,
        operation,
        "ata-create",
        &app,
        &body,
    )
    .await?
    {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("ata_create_replay"))?;
        return Ok(management_response(response, true));
    }
    let graph = graph(&mut tx, id, &input).await?;
    let preview = review(&app, &input, &graph)?;
    if preview["requires_expansion"] == true {
        return Err(ApiError::validation(
            "app_ids",
            "review and include every dependency application and endpoint before creating the verification",
        ));
    }
    if input.graph_version.as_deref() != preview["graph_version"].as_str() {
        return Err(ApiError::conflict("ata_graph_changed"));
    }
    let token = state
        .crypto
        .generate_secret(SecretKind::AtaRefreshToken)
        .map_err(|_| ApiError::internal("ata_refresh_generate"))?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::AtaRefreshToken, &token)
        .map_err(|_| ApiError::internal("ata_refresh_digest"))?;
    let credential = json!({"id":Id::now_v7(),"digest":hex::encode(digest.as_bytes()),"key_version":digest.key_version()});
    let sqlx::types::Json(mut response): sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT iam_private.ata_verification_create($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(id)
            .bind(operation)
            .bind(sqlx::types::Json(&input.endpoints))
            .bind(sqlx::types::Json(&graph))
            .bind(&input.app_ids)
            .bind(input.expires_after)
            .bind(input.access_token_validity)
            .bind(sqlx::types::Json(credential))
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| {
                ApiError::validation("verification", "could not create the reviewed verification")
            })?;
    response["refresh_token"] = json!(token.expose_secret());
    complete(
        &mut tx, &state, &service, operation, &app, revision, &response, true,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("ata_create_commit"))?;
    Ok(management_response(response, false))
}

async fn list(
    State(state): State<ApiState>,
    service: Service,
    Path(app): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (mut tx, _, id, _) = authorize(&state, &service, &headers, &app).await?;
    let sqlx::types::Json(response) = sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "SELECT iam_private.ata_verifications_list($1)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| ApiError::internal("ata_list"))?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("ata_list_commit"))?;
    Ok(Json(response))
}

async fn revoke(
    State(state): State<ApiState>,
    service: Service,
    Path((app, verification)): Path<(String, Id)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let input: RevokeInput = decode(&body)?;
    let (mut tx, actor, id, revision) = authorize(&state, &service, &headers, &app).await?;
    let resource = format!("{app}/{verification}");
    if let Some(response) = claim(
        &mut tx,
        &state,
        &service,
        &actor.subject,
        &headers,
        input.operation_id,
        "ata-revoke",
        &resource,
        &body,
    )
    .await?
    {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("ata_revoke_replay"))?;
        return Ok(management_response(response, true));
    }
    let sqlx::types::Json(response) = sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "SELECT iam_private.ata_verification_revoke($1,$2)",
    )
    .bind(id)
    .bind(verification)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| ApiError::not_found())?;
    complete(
        &mut tx,
        &state,
        &service,
        input.operation_id,
        &app,
        revision,
        &response,
        false,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("ata_revoke_commit"))?;
    Ok(management_response(response, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dependency_expansion_requires_explicit_review() {
        let input:Input=serde_json::from_value(json!({"endpoints":[{"audience":"waveform","endpoint_id":"speak"}],"app_ids":["waveform"]})).unwrap_or_else(|e|panic!("{e}"));
        let graph = json!([{"app_id":"briefcase","endpoint_id":"store"},{"app_id":"waveform","endpoint_id":"speak"}]);
        let preview = review("ting", &input, &graph).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(preview["requires_expansion"], true);
        assert_eq!(preview["app_ids"], json!(["briefcase", "waveform"]));
        let expanded: Input = serde_json::from_value(
            json!({"endpoints":preview["endpoints"],"app_ids":preview["app_ids"]}),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            review("ting", &expanded, &graph).unwrap_or_else(|e| panic!("{e:?}"))["requires_expansion"],
            false
        );
    }
}
