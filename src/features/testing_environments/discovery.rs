//! Application-scoped plane selection. The selector is never root authority.
use super::{graph, support};
use crate::domain::id::Id;
use crate::{
    api::{ApiState, authentication::Authenticated},
    error::AppError,
    features::applications::security::ApplicationClient,
    infrastructure::{
        postgres::context::{self, DatabaseContext},
        testing_plane::{self, SelectedEnvironment},
    },
};
use axum::response::IntoResponse as _;
use axum::{
    extract::{FromRequestParts, Request},
    http::{HeaderMap, HeaderValue, header},
    middleware::Next,
    response::Response,
};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};
use tower::ServiceExt as _;

pub(crate) const APPLICATION_HEADER: &str = "x-testing-application";

/// A Basic application credential, carried separately so OAuth bearers can coexist.
pub(super) fn presented(headers: &HeaderMap) -> Result<Option<HeaderValue>, AppError> {
    let mut values = headers.get_all(APPLICATION_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() || headers.contains_key(super::key::ENVIRONMENT_KEY_HEADER) {
        return Err(AppError::Unauthenticated);
    }
    Ok(Some(value.clone()))
}

pub(crate) async fn register(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Id,
    secret: &SecretString,
) -> Result<(), AppError> {
    if !testing_plane::is_active() {
        return Ok(());
    }
    sqlx::query("SELECT iam_private.register_test_application_selector($1,$2)")
        .bind(application_id)
        .bind(Sha256::digest(secret.expose_secret().as_bytes()).as_slice())
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    Ok(())
}

/// Prepares routing entries for existing imported secrets without exposing root keys.
pub(crate) async fn backfill(state: &ApiState) -> Result<(), AppError> {
    if state.testing.is_none() {
        return Ok(());
    }
    let environments = sqlx::query_as::<_, (Id, Id)>(
        "SELECT * FROM iam_private.test_application_backfill_environments()",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(support::database)?;
    for (id, organization_id) in environments {
        testing_plane::scope(
            SelectedEnvironment {
                id,
                organization_id,
            },
            async {
                let mut tx = context::begin(state.db(), DatabaseContext::anonymous())
                    .await
                    .map_err(support::database)?;
                let rows = sqlx::query_as::<_, (Id, Vec<u8>, Vec<u8>, i16)>(
                    "SELECT * FROM iam_private.test_application_selector_backfill()",
                )
                .fetch_all(&mut *tx)
                .await
                .map_err(support::database)?;
                for (app, cipher, nonce, version) in rows {
                    let bytes = state
                        .crypto
                        .decrypt(
                            graph::secret_context(id, app),
                            &graph::encrypted(version, &nonce, cipher)?,
                        )
                        .map_err(|_| AppError::Internal {
                            category: "testing_selector_backfill_decrypt",
                        })?;
                    let secret =
                        SecretString::from(String::from_utf8(bytes.to_vec()).map_err(|_| {
                            AppError::Internal {
                                category: "testing_selector_backfill_encoding",
                            }
                        })?);
                    register(&mut tx, app, &secret).await?;
                }
                tx.commit().await.map_err(support::database)
            },
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn select(
    state: ApiState,
    request: Request,
    next: Next,
    credential: HeaderValue,
) -> Result<Response, AppError> {
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, credential.clone());
    let (_, secret) = crate::features::applications::security::basic_credentials(&headers)
        .map_err(|_| AppError::Unauthenticated)?;
    let plane = support::plane(&state)?;
    let (id, expected_app) = sqlx::query_as::<_, (Id, Id)>(
        "SELECT * FROM iam_private.resolve_test_application_selector($1)",
    )
    .bind(Sha256::digest(secret.expose_secret().as_bytes()).as_slice())
    .fetch_optional(&plane.pool)
    .await
    .map_err(support::database)?
    .ok_or(AppError::Unauthenticated)?;
    let organization_id = sqlx::query_scalar::<_, Id>(
        "SELECT organization_id FROM iam_private.test_application_environment($1)",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(support::database)?
    .ok_or(AppError::Unauthenticated)?;
    let (generation, key_version): (Option<i64>, i32) =
        sqlx::query_as("SELECT * FROM iam_private.testing_runtime_version($1)")
            .bind(id)
            .fetch_optional(&state.pool)
            .await
            .map_err(support::database)?
            .ok_or(AppError::Unauthenticated)?;
    Box::pin(testing_plane::scope_runtime(
        SelectedEnvironment {
            id,
            organization_id,
        },
        generation.map(|generation| (generation, key_version)),
        async {
            super::scope_policy::revalidate(&state).await?;
            let (mut parts, body) = request.into_parts();
            let original = parts
                .headers
                .get(header::AUTHORIZATION)
                .cloned()
                .ok_or(AppError::Unauthenticated)?;
            parts
                .headers
                .insert(header::AUTHORIZATION, credential.clone());
            let client = match ApplicationClient::from_request_parts(&mut parts, &state).await {
                Ok(client) => client,
                Err(error) => return Ok(error.into_response()),
            };
            if client.application_id != expected_app {
                return Err(AppError::Unauthenticated);
            }
            parts
                .headers
                .insert(header::AUTHORIZATION, original.clone());
            if original == credential {
                if !application_route(parts.method.as_str(), parts.uri.path()) {
                    return Err(AppError::Forbidden);
                }
            } else {
                // Never let an app selector turn fixed-OTP signup or a direct IAM session
                // into administrative authority. Only this application's OAuth users pass.
                let auth = Authenticated::from_request_parts(&mut parts, &state).await?;
                if auth.0.audience_application_id != Some(expected_app)
                    || auth.0.client_application_id != Some(expected_app)
                {
                    return Err(AppError::Forbidden);
                }
                // The outer router already captured path parameters. A second
                // route match appends them, making Path<T> fail on duplicate
                // parameters. Preserve the verified actor, but rebuild routing
                // extensions for the scoped router. Request IDs stay in headers.
                parts.extensions.clear();
                parts.extensions.insert(auth);
                support::touch(&state.pool, id).await;
                // Reuse the application's existing scope-governed router. Anonymous OTP,
                // account creation, direct IAM consent and administrative routes do not exist here.
                return match crate::api::scoped::router(state.clone())
                    .layer(axum::middleware::from_fn_with_state(
                        state.clone(),
                        crate::api::membership_ids::transport,
                    ))
                    .with_state(state.clone())
                    .oneshot(Request::from_parts(parts, body))
                    .await
                {
                    Ok(response) => Ok(response),
                    Err(never) => match never {},
                };
            }
            support::touch(&state.pool, id).await;
            Ok(next.run(Request::from_parts(parts, body)).await)
        },
    ))
    .await
}

fn application_route(method: &str, path: &str) -> bool {
    match method {
        "POST" => matches!(
            path,
            "/api/v1/app-auth/tokens"
                | "/api/v1/oauth/introspect"
                | "/api/v1/oauth/revoke"
                | "/api/v1/obo-access/exchanges"
                | "/api/v1/obo-access/verify"
        ),
        "GET" => {
            path == "/api/v1/application/testing-context"
                || path.starts_with("/api/v1/application-directory/")
                || (path.starts_with("/api/v1/obo-access/applications/")
                    && path.ends_with("/endpoints"))
        }
        _ => false,
    }
}

/// Application selectors may never be ignored by production control routes.
pub(crate) async fn reject_application_selector(request: Request, next: Next) -> Response {
    if request.headers().contains_key(APPLICATION_HEADER) {
        return AppError::Forbidden.into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selectors_never_authorize_root_routes() {
        for route in [
            "/api/v1/signup",
            "/api/v1/testing-environment/cleanings",
            "/api/v1/app-auth/short-lived-tokens",
            "/api/v1/applications",
        ] {
            assert!(!application_route("POST", route));
        }
    }
    #[test]
    fn ambiguous_selectors_fail() {
        let mut h = HeaderMap::new();
        h.insert(APPLICATION_HEADER, HeaderValue::from_static("Basic x"));
        h.insert(
            super::super::key::ENVIRONMENT_KEY_HEADER,
            HeaderValue::from_static("root"),
        );
        assert!(presented(&h).is_err());
    }
}
