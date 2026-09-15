//! Reconciliation history and explicit notification replay.
use super::*;
use axum::{extract::Query, routing::post};
use serde_json::json;
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    after: Option<Uuid>,
}
pub(super) fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/honeycomb/events", get(list))
        .route("/api/v1/honeycomb/events/{event_id}/replay", post(replay))
}
async fn list(
    State(state): State<ApiState>,
    service: Service,
    Query(page): Query<Page>,
) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "SELECT * FROM iam_private.honeycomb_management_events($1,$2)",
    )
    .bind(service.application_id)
    .bind(page.after)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| ApiError::internal("honeycomb_events"))?;
    let items: Vec<Value> = rows.into_iter().map(|row| row.0).collect();
    Ok(Json(json!({"items":items})))
}
async fn replay(
    State(state): State<ApiState>,
    service: Service,
    Path(event): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let queued: bool =
        sqlx::query_scalar("SELECT iam_private.replay_honeycomb_management_event($1,$2)")
            .bind(service.application_id)
            .bind(event)
            .fetch_one(&state.pool)
            .await
            .map_err(|_| ApiError::internal("honeycomb_event_replay"))?;
    if !queued {
        return Err(ApiError::not_found());
    }
    Ok(Json(json!({"event_id":event,"queued":true})))
}
