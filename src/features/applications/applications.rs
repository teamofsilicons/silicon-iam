#![allow(clippy::too_many_lines)]

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use secrecy::ExposeSecret as _;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::ApiState,
    domain::actor::ActorType,
    infrastructure::{
        crypto::{DigestPurpose, EncryptionContext, ProtectedField, SecretKind},
        postgres::{
            context::{self, DatabaseContext},
            step_up::RequiredAssurance,
        },
    },
};

use super::{
    cursor,
    error::ApiError,
    events::{self, Mutation},
    idempotency::{self, Claim},
    model::{
        AppPath, ApplicationAdminDecision, ApplicationCreate, ApplicationCreated,
        ApplicationDetail, ApplicationPage, ApplicationPatch, ApplicationSecretRotated,
        ApplicationView, Availability, AvailabilityPath, CollaboratorCreate, CollaboratorPage,
        CollaboratorPath, CollaboratorView, PageInfo, PageQuery, PublicActor,
        SecretRotationRequest,
    },
    security::{
        Bearer, expected_version, require_carbon, require_platform_capability, require_step_up,
    },
    validation,
};

pub(super) const REVOKE_ACCESS_TOKENS_FOR_REMOVED_SCOPES_QUERY: &str = r"
    UPDATE iam.access_tokens AS token
    SET revoked_at = transaction_timestamp(),
        revocation_reason = 'application_scope_revoked'
    WHERE token.client_application_id = $1
      AND token.token_class = 'application_access'
      AND token.revoked_at IS NULL
      AND token.expires_at > transaction_timestamp()
      AND EXISTS (
          SELECT 1
          FROM iam.access_token_scopes AS token_scope
          WHERE token_scope.access_token_id = token.id
            AND token_scope.scope = ANY($2::text[])
      )
    ";

pub(super) async fn availability(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AvailabilityPath>,
) -> Result<Json<Availability>, ApiError> {
    require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let unavailable = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM iam.applications WHERE app_id = $1)",
    )
    .bind(path.app_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|_| ApiError::internal("application_availability"))?;
    Ok(Json(Availability {
        available: !unavailable,
    }))
}

pub(super) async fn list(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Query(query): Query<PageQuery>,
) -> Result<Json<ApplicationPage>, ApiError> {
    let carbon_id = require_carbon(&access)?;
    let cursor = cursor::decode(query.cursor.as_deref())?;
    let limit = cursor::limit(query.limit);
    if query.status.as_deref().is_some_and(|status| {
        !matches!(
            status,
            "under_review" | "verified" | "rejected" | "suspended" | "deleted"
        )
    }) {
        return Err(ApiError::validation("status", "contains an invalid status"));
    }
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("application_list_context"))?;
    let (cursor_at, cursor_id) =
        cursor.map_or((None, None), |cursor| (Some(cursor.at), Some(cursor.id)));
    let mut rows = sqlx::query_as::<_, ApplicationView>(
        r"
        SELECT
            application.id, application.app_id, application.owner_carbon_id,
            application.app_name, application.app_logo_uri,
            application.review_status, application.version,
            application.created_at, application.updated_at
        FROM iam.applications AS application
        WHERE application.deleted_at IS NULL
          AND iam_private.can_read_application(application.id, $1)
          AND ($2::text IS NULL OR application.review_status = $2)
          AND (
              $3::timestamptz IS NULL
              OR (application.created_at, application.id) < ($3, $4)
          )
        ORDER BY application.created_at DESC, application.id DESC
        LIMIT $5
        ",
    )
    .bind(carbon_id)
    .bind(query.status)
    .bind(cursor_at)
    .bind(cursor_id)
    .bind(limit + 1)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_list"))?;
    let next_cursor = if i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit {
        rows.pop();
        rows.last()
            .map(|item| cursor::encode(item.created_at, item.id))
            .transpose()?
    } else {
        None
    };
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(load_detail(&mut transaction, &state, row.id).await?);
    }
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("application_list_commit"))?;
    Ok(Json(ApplicationPage {
        items,
        page: PageInfo::from_next_cursor(next_cursor),
    }))
}

pub(super) async fn create(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    headers: HeaderMap,
    Json(input): Json<ApplicationCreate>,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::application_create(&input)?;
    let canonical = serde_json::to_vec(&json!({
        "app_id": input.app_id,
        "app_name": input.app_name,
        "app_logo_uri": input.app_logo_uri,
        "redirect_uris": input.redirect_uris,
        "webhook_url": input.webhook_url,
        "requested_scopes": input.requested_scopes,
    }))
    .map_err(|_| ApiError::internal("application_create_canonical"))?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("application_create_context"))?;
    let caller_scope = format!("carbon:{carbon_id}");
    let claim = idempotency::claim::<ApplicationCreated>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/applications",
        &canonical,
        true,
    )
    .await?;
    if let Claim::Replay { response, .. } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("application_replay_commit"))?;
        return Ok(created_secret_response(response, true));
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("application_idempotency_state"));
    };

    let application_id = Uuid::now_v7();
    let webhook_endpoint_id = Uuid::now_v7();
    let webhook_key_id = Uuid::now_v7();
    let client_secret_id = Uuid::now_v7();
    let client_secret = state
        .crypto
        .generate_secret(SecretKind::ApplicationSecret)
        .map_err(|_| ApiError::internal("application_secret_generate"))?;
    let webhook_secret = state
        .crypto
        .generate_secret(SecretKind::WebhookSigningSecret)
        .map_err(|_| ApiError::internal("webhook_secret_generate"))?;
    let client_digest = state
        .crypto
        .digest_secret(DigestPurpose::ApplicationSecret, &client_secret)
        .map_err(|_| ApiError::internal("application_secret_digest"))?;
    let encrypted_webhook = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookUrl,
                application_id,
                webhook_endpoint_id,
            ),
            input.webhook_url.as_bytes(),
        )
        .map_err(|_| ApiError::internal("webhook_url_encrypt"))?;
    let encrypted_webhook_secret = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookSigningSecret,
                application_id,
                webhook_key_id,
            ),
            webhook_secret.expose_secret().as_bytes(),
        )
        .map_err(|_| ApiError::internal("webhook_secret_encrypt"))?;
    let webhook_digest = Sha256::digest(input.webhook_url.as_bytes());

    sqlx::query(
        r"
        INSERT INTO iam.principals (id, kind, status, activated_at)
        VALUES ($1, 'application', 'active', transaction_timestamp())
        ",
    )
    .bind(application_id)
    .execute(&mut *transaction)
    .await
    .map_err(map_application_write)?;
    sqlx::query(
        r"
        INSERT INTO iam.applications (
            id, app_id, owner_carbon_id, app_name, app_logo_uri
        ) VALUES ($1, $2, $3, $4, $5)
        ",
    )
    .bind(application_id)
    .bind(&input.app_id)
    .bind(carbon_id)
    .bind(&input.app_name)
    .bind(&input.app_logo_uri)
    .execute(&mut *transaction)
    .await
    .map_err(map_application_write)?;
    for scope in &input.requested_scopes {
        let result = sqlx::query(
            r"
            INSERT INTO iam.application_requested_scopes (application_id, scope)
            SELECT $1, catalog.scope
            FROM iam.oauth_scope_catalog AS catalog
            WHERE catalog.scope = $2
            ",
        )
        .bind(application_id)
        .bind(scope)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("application_scope_insert"))?;
        if result.rows_affected() != 1 {
            return Err(ApiError::validation(
                "requested_scopes",
                format!("unknown scope: {scope}"),
            ));
        }
    }
    for redirect_uri in &input.redirect_uris {
        sqlx::query(
            r"
            INSERT INTO iam.application_redirect_uris (
                id, application_id, redirect_uri, uri_digest
            ) VALUES ($1, $2, $3, $4)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(application_id)
        .bind(redirect_uri)
        .bind(Sha256::digest(redirect_uri.as_bytes()).as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(map_application_write)?;
    }
    sqlx::query(
        r"
        INSERT INTO iam.application_secrets (
            id, application_id, secret_version, secret_prefix, secret_digest,
            pepper_key_version, created_by_carbon_id
        ) VALUES ($1, $2, 1, $3, $4, $5, $6)
        ",
    )
    .bind(client_secret_id)
    .bind(application_id)
    .bind(secret_prefix(client_secret.expose_secret()))
    .bind(client_digest.as_bytes().as_slice())
    .bind(client_digest.key_version())
    .bind(carbon_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_secret_insert"))?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_endpoints (
            id, application_id, url_ciphertext, url_nonce,
            encryption_key_version, url_digest
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(webhook_endpoint_id)
    .bind(application_id)
    .bind(encrypted_webhook.ciphertext)
    .bind(encrypted_webhook.nonce.as_slice())
    .bind(encrypted_webhook.key_version)
    .bind(webhook_digest.as_slice())
    .execute(&mut *transaction)
    .await
    .map_err(map_application_write)?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_signing_keys (
            id, application_id, endpoint_id, secret_version, key_prefix,
            secret_ciphertext, secret_nonce, encryption_key_version
        ) VALUES ($1, $2, $3, 1, $4, $5, $6, $7)
        ",
    )
    .bind(webhook_key_id)
    .bind(application_id)
    .bind(webhook_endpoint_id)
    .bind(secret_prefix(webhook_secret.expose_secret()))
    .bind(encrypted_webhook_secret.ciphertext)
    .bind(encrypted_webhook_secret.nonce.as_slice())
    .bind(encrypted_webhook_secret.key_version)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("webhook_secret_insert"))?;

    let detail = load_detail(&mut transaction, &state, application_id).await?;
    let secret_replay_expires_at = sqlx::query_scalar::<_, OffsetDateTime>(
        "SELECT transaction_timestamp() + interval '10 minutes'",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_secret_replay_expiry"))?;
    let response = ApplicationCreated {
        application: detail,
        app_secret: client_secret.expose_secret().to_owned(),
        app_secret_version: 1,
        webhook_signing_secret: webhook_secret.expose_secret().to_owned(),
        webhook_secret_version: 1,
        secret_replay_expires_at,
    };
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            application_id,
            action: "application.create",
            target_type: "application",
            target_id: Some(application_id),
            aggregate_type: "application",
            aggregate_id: application_id,
            aggregate_version: 1,
            before: None,
            after: Some(json!({
                "app_id": input.app_id,
                "review_status": "under_review",
            })),
            metadata: json!({
                "application_id": application_id,
                "requested_scope_count": input.requested_scopes.len(),
                "redirect_uri_count": input.redirect_uris.len(),
            }),
            event_type: "application.created",
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        201,
        &response,
        true,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("application_create_commit"))?;
    Ok(created_secret_response(response, false))
}

pub(super) async fn get(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("application_get_context"))?;
    let application =
        resolve_readable_app(&mut transaction, carbon_id, &path.app_id, false).await?;
    let detail = load_detail(&mut transaction, &state, application.id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("application_get_commit"))?;
    json_with_etag(StatusCode::OK, &detail, detail.version)
}

pub(super) async fn patch(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    headers: HeaderMap,
    Json(input): Json<ApplicationPatch>,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    validation::application_patch(&input)?;
    let version = expected_version(&headers)?;
    let canonical = serde_json::to_vec(&input_as_json(&input))
        .map_err(|_| ApiError::internal("application_patch_canonical"))?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("application_patch_context"))?;
    let caller_scope = format!("carbon:{carbon_id}:application:{}", path.app_id);
    let claim = idempotency::claim::<ApplicationDetail>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "PATCH /api/v1/applications/{app_id}",
        &canonical,
        false,
    )
    .await?;
    if let Claim::Replay { response, .. } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("application_patch_replay_commit"))?;
        return json_with_etag(StatusCode::OK, &response, response.version);
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("application_patch_idempotency"));
    };
    let before = resolve_technical_app(&mut transaction, carbon_id, &path.app_id, true).await?;
    if before.version != version {
        return Err(ApiError::precondition_failed());
    }
    if input.app_name.is_some() || input.app_logo_uri.is_some() {
        sqlx::query(
            r"
            UPDATE iam.applications
            SET app_name = CASE WHEN $2 THEN $3 ELSE app_name END,
                app_logo_uri = CASE WHEN $4 THEN $5 ELSE app_logo_uri END
            WHERE id = $1 AND version = $6
            ",
        )
        .bind(before.id)
        .bind(input.app_name.is_some())
        .bind(input.app_name.clone().flatten())
        .bind(input.app_logo_uri.is_some())
        .bind(input.app_logo_uri.clone().flatten())
        .bind(version)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("application_patch_metadata"))?;
    }
    if let Some(scopes) = &input.requested_scopes {
        for scope in scopes {
            let result = sqlx::query(
                r"
                INSERT INTO iam.application_requested_scopes (application_id, scope)
                SELECT $1, scope FROM iam.oauth_scope_catalog WHERE scope = $2
                ON CONFLICT DO NOTHING
                ",
            )
            .bind(before.id)
            .bind(scope)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("application_scope_patch"))?;
            if result.rows_affected() == 0 {
                let exists = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS (SELECT 1 FROM iam.oauth_scope_catalog WHERE scope = $1)",
                )
                .bind(scope)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| ApiError::internal("application_scope_validate"))?;
                if !exists {
                    return Err(ApiError::validation(
                        "requested_scopes",
                        format!("unknown scope: {scope}"),
                    ));
                }
            }
        }
        sqlx::query(
            r"
            DELETE FROM iam.application_requested_scopes AS requested
            WHERE requested.application_id = $1
              AND NOT (requested.scope = ANY($2::text[]))
              AND NOT EXISTS (
                  SELECT 1 FROM iam.application_approved_scopes AS approved
                  WHERE approved.application_id = requested.application_id
                    AND approved.scope = requested.scope
                    AND approved.revoked_at IS NULL
              )
            ",
        )
        .bind(before.id)
        .bind(scopes)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("application_scope_remove"))?;
    }
    if let Some(redirect_uris) = &input.redirect_uris {
        for redirect_uri in redirect_uris {
            sqlx::query(
                r"
                INSERT INTO iam.application_redirect_uris (
                    id, application_id, redirect_uri, uri_digest
                ) VALUES ($1, $2, $3, $4)
                ON CONFLICT (application_id, uri_digest) DO NOTHING
                ",
            )
            .bind(Uuid::now_v7())
            .bind(before.id)
            .bind(redirect_uri)
            .bind(Sha256::digest(redirect_uri.as_bytes()).as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("application_redirect_patch"))?;
        }
    }
    let updated_version = if input.app_name.is_some() || input.app_logo_uri.is_some() {
        version + 1
    } else {
        bump_application(&mut transaction, before.id).await?
    };
    let response = load_detail(&mut transaction, &state, before.id).await?;
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            application_id: before.id,
            action: "application.update",
            target_type: "application",
            target_id: Some(before.id),
            aggregate_type: "application",
            aggregate_id: before.id,
            aggregate_version: updated_version,
            before: Some(json!({
                "app_name": before.app_name,
                "app_logo_uri": before.app_logo_uri,
                "review_status": before.review_status,
            })),
            after: Some(json!({
                "app_name": response.app_name,
                "app_logo_uri": response.app_logo,
                "review_status": response.status,
            })),
            metadata: json!({ "pending_configuration_review": true }),
            event_type: "application.updated",
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        200,
        &response,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("application_patch_commit"))?;
    json_with_etag(StatusCode::OK, &response, response.version)
}

pub(super) async fn delete(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let version = expected_version(&headers)?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("application_delete_context"))?;
    let owner_managed = sqlx::query_scalar::<_, bool>(
        r"
        SELECT COALESCE((
            SELECT iam_private.can_manage_application(id, $2)
            FROM iam.applications
            WHERE app_id = $1 AND deleted_at IS NULL
        ), FALSE)
        ",
    )
    .bind(&path.app_id)
    .bind(carbon_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_delete_authority"))?;
    let (app, required_assurance) = if owner_managed {
        (
            resolve_managed_app(&mut transaction, carbon_id, &path.app_id, true).await?,
            RequiredAssurance::VerifiedChannel,
        )
    } else {
        for capability in [
            "applications.review",
            "applications.suspend",
            "applications.policy",
        ] {
            require_platform_capability(&mut transaction, carbon_id, capability).await?;
        }
        (
            resolve_admin_app(&mut transaction, &path.app_id, true).await?,
            RequiredAssurance::PhishingResistant,
        )
    };
    if app.version != version {
        return Err(ApiError::precondition_failed());
    }
    require_step_up(
        &mut transaction,
        &state.crypto,
        &headers,
        &access,
        "application.delete",
        app.id,
        required_assurance,
    )
    .await?;
    let canonical = version.to_be_bytes();
    let caller_scope = format!("carbon:{carbon_id}:application:{}", app.id);
    let claim = idempotency::claim::<serde_json::Value>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "DELETE /api/v1/applications/{app_id}",
        &canonical,
        false,
    )
    .await?;
    if matches!(claim, Claim::Replay { .. }) {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("application_delete_replay"))?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("application_delete_idempotency"));
    };
    sqlx::query(
        r"
        UPDATE iam.applications
        SET review_status = 'deleted', deleted_at = transaction_timestamp()
        WHERE id = $1 AND version = $2 AND deleted_at IS NULL
        ",
    )
    .bind(app.id)
    .bind(version)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_delete"))?;
    sqlx::query(
        r"
        UPDATE iam.principals
        SET status = 'deleted', deleted_at = transaction_timestamp(), auth_epoch = auth_epoch + 1
        WHERE id = $1 AND kind = 'application' AND status <> 'deleted'
        ",
    )
    .bind(app.id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_principal_delete"))?;
    revoke_application_authority(&mut transaction, app.id, "application_deleted").await?;
    let updated_version = version + 1;
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            application_id: app.id,
            action: "application.delete",
            target_type: "application",
            target_id: Some(app.id),
            aggregate_type: "application",
            aggregate_id: app.id,
            aggregate_version: updated_version,
            before: Some(json!({ "review_status": app.review_status })),
            after: Some(json!({ "review_status": "deleted" })),
            metadata: json!({ "authority_revoked": true }),
            event_type: "application.deleted",
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        204,
        &serde_json::Value::Null,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("application_delete_commit"))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(super) async fn list_collaborators(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    Query(query): Query<PageQuery>,
) -> Result<Json<CollaboratorPage>, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let cursor = cursor::decode(query.cursor.as_deref())?;
    let limit = cursor::limit(query.limit);
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("collaborator_list_context"))?;
    let app = resolve_readable_app(&mut transaction, carbon_id, &path.app_id, false).await?;
    let (at, id) = cursor.map_or((None, None), |cursor| (Some(cursor.at), Some(cursor.id)));
    let mut rows = sqlx::query_as::<_, (Uuid, String, String, OffsetDateTime)>(
        r"
        SELECT collaborator.carbon_id, carbon.carbon_id AS public_id,
               collaborator.collaborator_role, collaborator.added_at
        FROM iam.application_collaborators AS collaborator
        JOIN iam.carbons AS carbon ON carbon.id = collaborator.carbon_id
        WHERE collaborator.application_id = $1 AND collaborator.revoked_at IS NULL
          AND ($2::timestamptz IS NULL
               OR (collaborator.added_at, collaborator.carbon_id) < ($2, $3))
        ORDER BY collaborator.added_at DESC, collaborator.carbon_id DESC
        LIMIT $4
        ",
    )
    .bind(app.id)
    .bind(at)
    .bind(id)
    .bind(limit + 1)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("collaborator_list"))?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("collaborator_list_commit"))?;
    let next_cursor = if i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit {
        rows.pop();
        rows.last()
            .map(|item| cursor::encode(item.3, item.0))
            .transpose()?
    } else {
        None
    };
    let items = rows
        .into_iter()
        .map(
            |(principal_id, public_id, role, created_at)| CollaboratorView {
                principal: PublicActor {
                    principal_id,
                    actor_type: ActorType::Carbon.as_str().to_owned(),
                    public_id,
                },
                role,
                created_at,
            },
        )
        .collect();
    Ok(Json(CollaboratorPage {
        items,
        page: PageInfo::from_next_cursor(next_cursor),
    }))
}

pub(super) async fn add_collaborator(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    headers: HeaderMap,
    Json(input): Json<CollaboratorCreate>,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    validation::collaborator_role(&input.role)?;
    let canonical = serde_json::to_vec(&json!({
        "carbon_id": input.carbon_id.as_str(),
        "role": input.role,
    }))
    .map_err(|_| ApiError::internal("collaborator_canonical"))?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("collaborator_add_context"))?;
    let app = resolve_managed_app(&mut transaction, carbon_id, &path.app_id, true).await?;
    require_step_up(
        &mut transaction,
        &state.crypto,
        &headers,
        &access,
        "application.manage_collaborators",
        app.id,
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let caller_scope = format!("carbon:{carbon_id}:application:{}", app.id);
    let claim = idempotency::claim::<CollaboratorView>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/applications/{app_id}/collaborators",
        &canonical,
        false,
    )
    .await?;
    if let Claim::Replay { response, .. } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("collaborator_replay_commit"))?;
        return Ok((StatusCode::CREATED, Json(response)).into_response());
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("collaborator_idempotency"));
    };
    let target_carbon_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT principal_id
        FROM iam_private.resolve_active_carbon_by_handle($1)
        ",
    )
    .bind(input.carbon_id.as_str())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("collaborator_target_read"))?
    .ok_or_else(ApiError::not_found)?;
    if target_carbon_id == app.owner_carbon_id {
        return Err(ApiError::conflict("owner_cannot_be_collaborator"));
    }
    let (principal_id, role, created_at) = sqlx::query_as::<_, (Uuid, String, OffsetDateTime)>(
        r"
        INSERT INTO iam.application_collaborators (
            application_id, carbon_id, collaborator_role, added_by_carbon_id
        ) VALUES ($1, $2, $3, $4)
        RETURNING carbon_id, collaborator_role, added_at
        ",
    )
    .bind(app.id)
    .bind(target_carbon_id)
    .bind(&input.role)
    .bind(carbon_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_application_write)?;
    let response = CollaboratorView {
        principal: PublicActor {
            principal_id,
            actor_type: ActorType::Carbon.as_str().to_owned(),
            public_id: input.carbon_id.as_str().to_owned(),
        },
        role,
        created_at,
    };
    let version = bump_application(&mut transaction, app.id).await?;
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            application_id: app.id,
            action: "application.collaborator.add",
            target_type: "carbon",
            target_id: Some(target_carbon_id),
            aggregate_type: "application",
            aggregate_id: app.id,
            aggregate_version: version,
            before: None,
            after: Some(json!({ "role": input.role })),
            metadata: json!({ "collaborator_id": target_carbon_id }),
            event_type: "application.collaborator_added",
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        201,
        &response,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("collaborator_add_commit"))?;
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

pub(super) async fn remove_collaborator(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<CollaboratorPath>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("collaborator_remove_context"))?;
    let app = resolve_managed_app(&mut transaction, carbon_id, &path.app_id, true).await?;
    require_step_up(
        &mut transaction,
        &state.crypto,
        &headers,
        &access,
        "application.manage_collaborators",
        app.id,
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let caller_scope = format!("carbon:{carbon_id}:application:{}", app.id);
    let claim = idempotency::claim::<serde_json::Value>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "DELETE /api/v1/applications/{app_id}/collaborators/{principal_id}",
        path.principal_id.as_bytes(),
        false,
    )
    .await?;
    if matches!(claim, Claim::Replay { .. }) {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("collaborator_remove_replay"))?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("collaborator_remove_idempotency"));
    };
    let result = sqlx::query(
        r"
        UPDATE iam.application_collaborators
        SET revoked_by_carbon_id = $3, revoked_at = transaction_timestamp()
        WHERE application_id = $1 AND carbon_id = $2 AND revoked_at IS NULL
        ",
    )
    .bind(app.id)
    .bind(path.principal_id)
    .bind(carbon_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("collaborator_remove"))?;
    if result.rows_affected() != 1 {
        return Err(ApiError::not_found());
    }
    let version = bump_application(&mut transaction, app.id).await?;
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            application_id: app.id,
            action: "application.collaborator.remove",
            target_type: "carbon",
            target_id: Some(path.principal_id),
            aggregate_type: "application",
            aggregate_id: app.id,
            aggregate_version: version,
            before: Some(json!({ "active": true })),
            after: Some(json!({ "active": false })),
            metadata: json!({ "collaborator_id": path.principal_id }),
            event_type: "application.collaborator_removed",
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        204,
        &serde_json::Value::Null,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("collaborator_remove_commit"))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(super) async fn rotate_secret(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    headers: HeaderMap,
    input: Option<Json<SecretRotationRequest>>,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let input = input.map_or_else(SecretRotationRequest::default, |Json(value)| value);
    validation::overlap(input.overlap_seconds)?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("secret_rotate_context"))?;
    let app = resolve_technical_app(&mut transaction, carbon_id, &path.app_id, true).await?;
    require_step_up(
        &mut transaction,
        &state.crypto,
        &headers,
        &access,
        "application.rotate_secret",
        app.id,
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let caller_scope = format!("carbon:{carbon_id}:application:{}", app.id);
    let claim = idempotency::claim::<ApplicationSecretRotated>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/applications/{app_id}/secret-rotations",
        &input.overlap_seconds.to_be_bytes(),
        true,
    )
    .await?;
    if let Claim::Replay { response, .. } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("secret_rotate_replay"))?;
        return Ok(secret_rotation_response(response, true));
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("secret_rotate_idempotency"));
    };
    let raw = state
        .crypto
        .generate_secret(SecretKind::ApplicationSecret)
        .map_err(|_| ApiError::internal("secret_rotate_generate"))?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::ApplicationSecret, &raw)
        .map_err(|_| ApiError::internal("secret_rotate_digest"))?;
    let previous_valid_until = sqlx::query_scalar::<_, OffsetDateTime>(
        "SELECT transaction_timestamp() + ($1::bigint * interval '1 second')",
    )
    .bind(i64::from(input.overlap_seconds))
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("secret_rotate_validity"))?;
    if input.overlap_seconds == 0 {
        sqlx::query(
            r"
            UPDATE iam.application_secrets
            SET status = 'retired', retired_at = transaction_timestamp(), retires_at = NULL
            WHERE application_id = $1 AND status IN ('active', 'retiring')
            ",
        )
        .bind(app.id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("secret_rotate_retire"))?;
    } else {
        sqlx::query(
            r"
            UPDATE iam.application_secrets
            SET status = 'retiring', retires_at = $2
            WHERE application_id = $1 AND status = 'active'
            ",
        )
        .bind(app.id)
        .bind(previous_valid_until)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("secret_rotate_overlap"))?;
    }
    let secret_id = Uuid::now_v7();
    let secret_version = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(MAX(secret_version), 0) + 1 FROM iam.application_secrets WHERE application_id = $1",
    )
    .bind(app.id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("secret_rotate_version"))?;
    sqlx::query(
        r"
        INSERT INTO iam.application_secrets (
            id, application_id, secret_version, secret_prefix, secret_digest,
            pepper_key_version, created_by_carbon_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ",
    )
    .bind(secret_id)
    .bind(app.id)
    .bind(secret_version)
    .bind(secret_prefix(raw.expose_secret()))
    .bind(digest.as_bytes().as_slice())
    .bind(digest.key_version())
    .bind(carbon_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("secret_rotate_insert"))?;
    let version = bump_application(&mut transaction, app.id).await?;
    let secret_replay_expires_at = sqlx::query_scalar::<_, OffsetDateTime>(
        "SELECT transaction_timestamp() + interval '10 minutes'",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("secret_rotate_replay_expiry"))?;
    let response = ApplicationSecretRotated {
        app_id: app.app_id.clone(),
        app_secret: raw.expose_secret().to_owned(),
        secret_version,
        previous_valid_until,
        secret_replay_expires_at,
    };
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            application_id: app.id,
            action: "application.secret.rotate",
            target_type: "application_secret",
            target_id: Some(secret_id),
            aggregate_type: "application",
            aggregate_id: app.id,
            aggregate_version: version,
            before: None,
            after: Some(json!({
                "secret_id": secret_id,
                "prefix": secret_prefix(raw.expose_secret()),
                "secret_version": secret_version,
            })),
            metadata: json!({ "overlap_seconds": input.overlap_seconds }),
            event_type: "application.secret_rotated",
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        201,
        &response,
        true,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("secret_rotate_commit"))?;
    Ok(secret_rotation_response(response, false))
}

pub(super) async fn admin_list(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Query(query): Query<PageQuery>,
) -> Result<Json<ApplicationPage>, ApiError> {
    let carbon_id = require_carbon(&access)?;
    let cursor = cursor::decode(query.cursor.as_deref())?;
    let limit = cursor::limit(query.limit);
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("admin_application_list_context"))?;
    require_platform_capability(&mut transaction, carbon_id, "applications.review").await?;
    let (at, id) = cursor.map_or((None, None), |cursor| (Some(cursor.at), Some(cursor.id)));
    let mut rows = sqlx::query_as::<_, ApplicationView>(
        r"
        SELECT id, app_id, owner_carbon_id, app_name, app_logo_uri,
               review_status, version, created_at, updated_at
        FROM iam.applications
        WHERE ($1::text IS NULL OR review_status = $1)
          AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3))
        ORDER BY created_at DESC, id DESC
        LIMIT $4
        ",
    )
    .bind(query.status)
    .bind(at)
    .bind(id)
    .bind(limit + 1)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("admin_application_list"))?;
    let next_cursor = if i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit {
        rows.pop();
        rows.last()
            .map(|item| cursor::encode(item.created_at, item.id))
            .transpose()?
    } else {
        None
    };
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(load_detail(&mut transaction, &state, row.id).await?);
    }
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("admin_application_list_commit"))?;
    Ok(Json(ApplicationPage {
        items,
        page: PageInfo::from_next_cursor(next_cursor),
    }))
}

pub(super) async fn admin_decide(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    headers: HeaderMap,
    Json(input): Json<ApplicationAdminDecision>,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    validate_admin_decision(&input)?;
    let expected = expected_version(&headers)?;
    let canonical = serde_json::to_vec(&json!({
        "decision": input.decision,
        "reason": input.reason,
        "approved_scopes": input.approved_scopes,
        "notify_users": input.notify_users,
    }))
    .map_err(|_| ApiError::internal("admin_decision_canonical"))?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("admin_decision_context"))?;
    let capability = match input.decision.as_str() {
        "suspend" | "reactivate" => "applications.suspend",
        _ => "applications.review",
    };
    require_platform_capability(&mut transaction, carbon_id, capability).await?;
    if input.notify_users.is_some() {
        require_platform_capability(&mut transaction, carbon_id, "applications.policy").await?;
    }
    let app = resolve_admin_app(&mut transaction, &path.app_id, true).await?;
    validate_admin_transition(&input, &app.review_status)?;
    if app.version != expected {
        return Err(ApiError::precondition_failed());
    }
    require_step_up(
        &mut transaction,
        &state.crypto,
        &headers,
        &access,
        "platform_admin.application_review",
        app.id,
        RequiredAssurance::PhishingResistant,
    )
    .await?;
    let caller_scope = format!("platform-admin:{carbon_id}:application:{}", app.id);
    let claim = idempotency::claim::<ApplicationDetail>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/admin/applications/{app_id}/decisions",
        &canonical,
        false,
    )
    .await?;
    if let Claim::Replay { response, .. } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("admin_decision_replay"))?;
        return json_with_etag(StatusCode::OK, &response, response.version);
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("admin_decision_idempotency"));
    };
    apply_admin_decision(&mut transaction, carbon_id, app.id, &input).await?;
    let next_status = match input.decision.as_str() {
        "approve" | "reactivate" => Some("verified"),
        "reject" => Some("rejected"),
        "suspend" => Some("suspended"),
        _ => None,
    };
    sqlx::query(
        r"
        UPDATE iam.applications
        SET review_status = COALESCE($2, review_status),
            notify_users = COALESCE($3, notify_users)
        WHERE id = $1 AND version = $4
        ",
    )
    .bind(app.id)
    .bind(next_status)
    .bind(input.notify_users)
    .bind(expected)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("admin_decision_application"))?;
    if let Some(status) = next_status {
        if status == "suspended" {
            sqlx::query(
                r"
                UPDATE iam.principals
                SET status = 'suspended', suspended_at = transaction_timestamp(),
                    auth_epoch = auth_epoch + 1
                WHERE id = $1 AND kind = 'application'
                ",
            )
            .bind(app.id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("admin_suspend_principal"))?;
            revoke_application_authority(&mut transaction, app.id, "application_suspended").await?;
        } else if status == "verified" {
            sqlx::query(
                r"
                UPDATE iam.principals
                SET status = 'active', activated_at = COALESCE(activated_at, transaction_timestamp()),
                    suspended_at = NULL
                WHERE id = $1 AND kind = 'application' AND status <> 'deleted'
                ",
            )
            .bind(app.id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("admin_restore_principal"))?;
        }
    }
    let version =
        sqlx::query_scalar::<_, i64>("SELECT version FROM iam.applications WHERE id = $1")
            .bind(app.id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("admin_decision_version"))?;
    sqlx::query(
        r"
        INSERT INTO iam.application_reviews (
            id, application_id, reviewer_carbon_id, decision, reason, application_version
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(app.id)
    .bind(carbon_id)
    .bind(review_decision_name(&input.decision))
    .bind(&input.reason)
    .bind(version)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_review_insert"))?;
    let response = load_detail(&mut transaction, &state, app.id).await?;
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            application_id: app.id,
            action: "application.review.decide",
            target_type: "application",
            target_id: Some(app.id),
            aggregate_type: "application",
            aggregate_id: app.id,
            aggregate_version: version,
            before: Some(json!({ "review_status": app.review_status })),
            after: Some(json!({ "review_status": response.status })),
            metadata: json!({
                "decision": input.decision,
                "reason_present": input.reason.is_some(),
            }),
            event_type: "application.review_decided",
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        200,
        &response,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("admin_decision_commit"))?;
    json_with_etag(StatusCode::OK, &response, response.version)
}

pub(super) async fn resolve_managed_app(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    app_id: &str,
    for_update: bool,
) -> Result<ApplicationView, ApiError> {
    resolve_app(transaction, Some(carbon_id), app_id, "manage", for_update).await
}

pub(super) async fn resolve_technical_app(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    app_id: &str,
    for_update: bool,
) -> Result<ApplicationView, ApiError> {
    resolve_app(
        transaction,
        Some(carbon_id),
        app_id,
        "technical",
        for_update,
    )
    .await
}

pub(super) async fn resolve_readable_app(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    app_id: &str,
    for_update: bool,
) -> Result<ApplicationView, ApiError> {
    resolve_app(transaction, Some(carbon_id), app_id, "read", for_update).await
}

async fn resolve_admin_app(
    transaction: &mut Transaction<'_, Postgres>,
    app_id: &str,
    for_update: bool,
) -> Result<ApplicationView, ApiError> {
    resolve_app(transaction, None, app_id, "admin", for_update).await
}

async fn resolve_app(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Option<Uuid>,
    app_id: &str,
    access: &'static str,
    for_update: bool,
) -> Result<ApplicationView, ApiError> {
    let app = if for_update {
        sqlx::query_as::<_, ApplicationView>(
            r"
            SELECT id, app_id, owner_carbon_id, app_name, app_logo_uri,
                   review_status, version, created_at, updated_at
            FROM iam.applications
            WHERE app_id = $1 AND deleted_at IS NULL
              AND CASE $3::text
                    WHEN 'read' THEN iam_private.can_read_application(id, $2)
                    WHEN 'technical' THEN iam_private.can_manage_application_technical(id, $2)
                    WHEN 'manage' THEN iam_private.can_manage_application(id, $2)
                    WHEN 'admin' THEN TRUE
                    ELSE FALSE
                  END
            FOR UPDATE
            ",
        )
        .bind(app_id)
        .bind(carbon_id)
        .bind(access)
        .fetch_optional(&mut **transaction)
        .await
    } else {
        sqlx::query_as::<_, ApplicationView>(
            r"
            SELECT id, app_id, owner_carbon_id, app_name, app_logo_uri,
                   review_status, version, created_at, updated_at
            FROM iam.applications
            WHERE app_id = $1 AND deleted_at IS NULL
              AND CASE $3::text
                    WHEN 'read' THEN iam_private.can_read_application(id, $2)
                    WHEN 'technical' THEN iam_private.can_manage_application_technical(id, $2)
                    WHEN 'manage' THEN iam_private.can_manage_application(id, $2)
                    WHEN 'admin' THEN TRUE
                    ELSE FALSE
                  END
            ",
        )
        .bind(app_id)
        .bind(carbon_id)
        .bind(access)
        .fetch_optional(&mut **transaction)
        .await
    }
    .map_err(|_| ApiError::internal("application_resolve"))?
    .ok_or_else(ApiError::not_found)?;
    sqlx::query("SELECT set_config('iam.application_id', $1, true)")
        .bind(app.id.to_string())
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("application_context_select"))?;
    Ok(app)
}

pub(super) async fn load_detail(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    application_id: Uuid,
) -> Result<ApplicationDetail, ApiError> {
    let application = sqlx::query_as::<_, ApplicationView>(
        r"
        SELECT id, app_id, owner_carbon_id, app_name, app_logo_uri,
               review_status, version, created_at, updated_at
        FROM iam.applications WHERE id = $1
        ",
    )
    .bind(application_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_detail"))?;
    let notify_users =
        sqlx::query_scalar::<_, bool>("SELECT notify_users FROM iam.applications WHERE id = $1")
            .bind(application_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| ApiError::internal("application_notify_users"))?;
    let owner_public_id =
        sqlx::query_scalar::<_, String>("SELECT carbon_id FROM iam.carbons WHERE id = $1")
            .bind(application.owner_carbon_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| ApiError::internal("application_owner_public_id"))?;
    let requested_scopes = sqlx::query_scalar::<_, String>(
        r"
        SELECT scope FROM iam.application_requested_scopes
        WHERE application_id = $1 ORDER BY scope
        ",
    )
    .bind(application_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_requested_scopes"))?;
    let approved_scopes = sqlx::query_scalar::<_, String>(
        r"
        SELECT scope FROM iam.application_approved_scopes
        WHERE application_id = $1 AND revoked_at IS NULL ORDER BY scope
        ",
    )
    .bind(application_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_approved_scopes"))?;
    let redirect_uris = sqlx::query_scalar::<_, String>(
        r"
        SELECT redirect_uri
        FROM iam.application_redirect_uris
        WHERE application_id = $1 AND status <> 'retired'
        ORDER BY created_at, id
        ",
    )
    .bind(application_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_redirect_uris"))?;
    let has_pending_changes = sqlx::query_scalar::<_, bool>(
        r"
        SELECT
            EXISTS (
                SELECT 1 FROM iam.application_redirect_uris
                WHERE application_id = $1 AND status = 'pending_review'
            )
            OR EXISTS (
                SELECT 1 FROM iam.application_webhook_endpoints
                WHERE application_id = $1 AND status = 'pending_review'
            )
            OR EXISTS (
                SELECT 1
                FROM iam.application_requested_scopes AS requested
                WHERE requested.application_id = $1
                  AND NOT EXISTS (
                      SELECT 1 FROM iam.application_approved_scopes AS approved
                      WHERE approved.application_id = requested.application_id
                        AND approved.scope = requested.scope
                        AND approved.revoked_at IS NULL
                  )
            )
        ",
    )
    .bind(application_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_pending_changes"))?;
    let webhook = super::webhooks::load_webhook(transaction, state, application_id).await?;
    Ok(ApplicationDetail {
        id: application.id,
        app_id: application.app_id,
        owner: PublicActor {
            principal_id: application.owner_carbon_id,
            actor_type: ActorType::Carbon.as_str().to_owned(),
            public_id: owner_public_id,
        },
        app_name: application.app_name,
        app_logo: application.app_logo_uri,
        redirect_uris,
        requested_scopes,
        approved_scopes,
        status: application.review_status,
        notify_users,
        webhook,
        has_pending_changes,
        version: application.version,
        created_at: application.created_at,
        updated_at: application.updated_at,
    })
}

pub(super) async fn bump_application(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
) -> Result<i64, ApiError> {
    sqlx::query_scalar::<_, i64>(
        r"
        UPDATE iam.applications
        SET updated_at = transaction_timestamp()
        WHERE id = $1
        RETURNING version
        ",
    )
    .bind(application_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_version_bump"))
}

async fn revoke_application_authority(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    reason: &'static str,
) -> Result<(), ApiError> {
    sqlx::query(
        r"
        UPDATE iam.application_secrets
        SET status = 'compromised', retired_at = transaction_timestamp(), retires_at = NULL
        WHERE application_id = $1 AND status IN ('active', 'retiring')
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_secret_revoke_all"))?;
    sqlx::query(
        r"
        UPDATE iam.refresh_token_families
        SET status = 'revoked', revoked_at = transaction_timestamp(), revocation_reason = $2
        WHERE client_application_id = $1 AND status = 'active'
        ",
    )
    .bind(application_id)
    .bind(reason)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_refresh_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.access_tokens
        SET revoked_at = transaction_timestamp(), revocation_reason = $2
        WHERE (client_application_id = $1 OR audience_application_id = $1)
          AND revoked_at IS NULL
        ",
    )
    .bind(application_id)
    .bind(reason)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_access_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.oauth_consent_grants
        SET status = 'revoked', revoked_at = transaction_timestamp()
        WHERE application_id = $1 AND status = 'active'
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_consent_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.obo_proofs
        SET revoked_at = transaction_timestamp()
        WHERE (issuer_application_id = $1 OR audience_application_id = $1)
          AND consumed_at IS NULL AND revoked_at IS NULL
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_obo_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.webhook_deliveries AS delivery
        SET status = 'cancelled', lease_owner = NULL, lease_expires_at = NULL
        FROM iam.outbox_event_recipients AS recipient
        JOIN iam.application_webhook_endpoints AS endpoint
          ON endpoint.id = recipient.application_webhook_endpoint_id
        WHERE delivery.recipient_id = recipient.id
          AND endpoint.application_id = $1
          AND delivery.status IN ('pending', 'processing')
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_delivery_cancel"))?;
    Ok(())
}

async fn apply_admin_decision(
    transaction: &mut Transaction<'_, Postgres>,
    reviewer: Uuid,
    application_id: Uuid,
    input: &ApplicationAdminDecision,
) -> Result<(), ApiError> {
    let effective_scopes = if let Some(scopes) = &input.approved_scopes {
        Some(scopes.clone())
    } else if matches!(
        input.decision.as_str(),
        "approve" | "approve_pending_changes"
    ) {
        Some(
            sqlx::query_scalar::<_, String>(
                r"
                SELECT scope FROM iam.application_requested_scopes
                WHERE application_id = $1 ORDER BY scope
                ",
            )
            .bind(application_id)
            .fetch_all(&mut **transaction)
            .await
            .map_err(|_| ApiError::internal("requested_scope_review"))?,
        )
    } else {
        None
    };
    if let Some(scopes) = &effective_scopes {
        let removed_scopes = sqlx::query_scalar::<_, String>(
            r"
            UPDATE iam.application_approved_scopes
            SET revoked_by_carbon_id = $2, revoked_at = transaction_timestamp()
            WHERE application_id = $1 AND revoked_at IS NULL
              AND NOT (scope = ANY($3::text[]))
            RETURNING scope
            ",
        )
        .bind(application_id)
        .bind(reviewer)
        .bind(scopes)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("approved_scope_revoke"))?;
        if !removed_scopes.is_empty() {
            sqlx::query(REVOKE_ACCESS_TOKENS_FOR_REMOVED_SCOPES_QUERY)
                .bind(application_id)
                .bind(&removed_scopes)
                .execute(&mut **transaction)
                .await
                .map_err(|_| ApiError::internal("approved_scope_access_revoke"))?;
        }
        for scope in scopes {
            let inserted = sqlx::query(
                r"
                INSERT INTO iam.application_approved_scopes (
                    application_id, scope, approved_by_carbon_id
                )
                SELECT requested.application_id, requested.scope, $3
                FROM iam.application_requested_scopes AS requested
                WHERE requested.application_id = $1 AND requested.scope = $2
                  AND NOT EXISTS (
                      SELECT 1 FROM iam.application_approved_scopes AS approved
                      WHERE approved.application_id = requested.application_id
                        AND approved.scope = requested.scope AND approved.revoked_at IS NULL
                  )
                ",
            )
            .bind(application_id)
            .bind(scope)
            .bind(reviewer)
            .execute(&mut **transaction)
            .await
            .map_err(|_| ApiError::internal("approved_scope_insert"))?;
            if inserted.rows_affected() == 0 {
                let active = sqlx::query_scalar::<_, bool>(
                    r"
                    SELECT EXISTS (
                        SELECT 1 FROM iam.application_approved_scopes
                        WHERE application_id = $1 AND scope = $2 AND revoked_at IS NULL
                    )
                    ",
                )
                .bind(application_id)
                .bind(scope)
                .fetch_one(&mut **transaction)
                .await
                .map_err(|_| ApiError::internal("approved_scope_check"))?;
                if !active {
                    return Err(ApiError::validation(
                        "approved_scopes",
                        format!("scope was not requested: {scope}"),
                    ));
                }
            }
        }
    }
    if matches!(
        input.decision.as_str(),
        "approve" | "approve_pending_changes"
    ) {
        sqlx::query(
            r"
            UPDATE iam.application_redirect_uris
            SET status = 'active', approved_at = transaction_timestamp()
            WHERE application_id = $1 AND status = 'pending_review'
            ",
        )
        .bind(application_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("redirect_approve_all"))?;
    }
    let endpoint_id = if matches!(
        input.decision.as_str(),
        "approve" | "approve_pending_changes"
    ) {
        sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT id FROM iam.application_webhook_endpoints
            WHERE application_id = $1 AND status = 'pending_review'
            ORDER BY created_at DESC, id DESC LIMIT 1
            ",
        )
        .bind(application_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("webhook_pending_review"))?
    } else {
        None
    };
    if let Some(endpoint_id) = endpoint_id {
        sqlx::query(
            r"
            UPDATE iam.application_webhook_endpoints
            SET status = 'retired', retired_at = transaction_timestamp()
            WHERE application_id = $1 AND status = 'active' AND id <> $2
            ",
        )
        .bind(application_id)
        .bind(endpoint_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("webhook_previous_retire"))?;
        let result = sqlx::query(
            r"
            UPDATE iam.application_webhook_endpoints
            SET status = 'active', activated_at = transaction_timestamp()
            WHERE application_id = $1 AND id = $2 AND status = 'pending_review'
            ",
        )
        .bind(application_id)
        .bind(endpoint_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("webhook_activate"))?;
        if result.rows_affected() != 1 {
            return Err(ApiError::validation(
                "webhook_endpoint_id",
                "must identify a pending endpoint",
            ));
        }
        sqlx::query(
            r"
            UPDATE iam.application_webhook_endpoints
            SET status = 'retired', retired_at = transaction_timestamp()
            WHERE application_id = $1 AND status = 'pending_review' AND id <> $2
            ",
        )
        .bind(application_id)
        .bind(endpoint_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("webhook_pending_retire"))?;
    }
    if input.decision == "reject_pending_changes" {
        sqlx::query(
            r"
            UPDATE iam.application_redirect_uris
            SET status = 'retired', retired_at = transaction_timestamp()
            WHERE application_id = $1 AND status = 'pending_review'
            ",
        )
        .bind(application_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("redirect_reject_pending"))?;
        sqlx::query(
            r"
            UPDATE iam.application_webhook_endpoints
            SET status = 'retired', retired_at = transaction_timestamp()
            WHERE application_id = $1 AND status = 'pending_review'
            ",
        )
        .bind(application_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("webhook_reject_pending"))?;
        sqlx::query(
            r"
            DELETE FROM iam.application_requested_scopes AS requested
            WHERE requested.application_id = $1
              AND NOT EXISTS (
                  SELECT 1 FROM iam.application_approved_scopes AS approved
                  WHERE approved.application_id = requested.application_id
                    AND approved.scope = requested.scope
                    AND approved.revoked_at IS NULL
              )
            ",
        )
        .bind(application_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("scope_reject_pending"))?;
    }
    Ok(())
}

fn validate_admin_decision(input: &ApplicationAdminDecision) -> Result<(), ApiError> {
    if !matches!(
        input.decision.as_str(),
        "approve"
            | "reject"
            | "suspend"
            | "reactivate"
            | "approve_pending_changes"
            | "reject_pending_changes"
    ) {
        return Err(ApiError::validation(
            "decision",
            "contains an invalid decision",
        ));
    }
    if input
        .reason
        .as_deref()
        .is_some_and(|reason| reason.is_empty() || reason.chars().count() > 2_000)
    {
        return Err(ApiError::validation(
            "reason",
            "must contain 1 to 2000 characters",
        ));
    }
    if let Some(scopes) = &input.approved_scopes {
        validation::scopes(scopes)?;
    }
    let approves_changes = matches!(
        input.decision.as_str(),
        "approve" | "approve_pending_changes"
    );
    if !approves_changes && input.approved_scopes.is_some() {
        return Err(ApiError::validation(
            "decision",
            "review approvals are only valid with an approving decision",
        ));
    }
    Ok(())
}

fn validate_admin_transition(
    input: &ApplicationAdminDecision,
    current_status: &str,
) -> Result<(), ApiError> {
    let allowed = match input.decision.as_str() {
        "approve" | "reject" => current_status == "under_review",
        "suspend" | "approve_pending_changes" | "reject_pending_changes" => {
            current_status == "verified"
        }
        "reactivate" => current_status == "suspended",
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(ApiError::conflict("application_review_state_conflict"))
    }
}

fn review_decision_name(decision: &str) -> &'static str {
    match decision {
        "approve" | "approve_pending_changes" => "approve",
        "suspend" => "suspend",
        "reactivate" => "restore",
        _ => "reject",
    }
}

fn input_as_json(input: &ApplicationPatch) -> serde_json::Value {
    json!({
        "app_name": input.app_name,
        "app_logo_uri": input.app_logo_uri,
        "redirect_uris": input.redirect_uris,
        "requested_scopes": input.requested_scopes,
    })
}

fn secret_prefix(secret: &str) -> String {
    secret.chars().take(12).collect()
}

fn created_secret_response(response: ApplicationCreated, replayed: bool) -> Response {
    let mut response = (StatusCode::CREATED, Json(response)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if replayed {
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
    response
}

fn secret_rotation_response(response: ApplicationSecretRotated, replayed: bool) -> Response {
    let mut response = (StatusCode::CREATED, Json(response)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if replayed {
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
    response
}

pub(super) fn json_with_etag<T: serde::Serialize>(
    status: StatusCode,
    body: &T,
    version: i64,
) -> Result<Response, ApiError> {
    let mut response = (status, Json(body)).into_response();
    let etag = HeaderValue::from_str(&format!("\"{version}\""))
        .map_err(|_| ApiError::internal("etag_encode"))?;
    response.headers_mut().insert(header::ETAG, etag);
    Ok(response)
}

#[allow(clippy::needless_pass_by_value)]
fn map_application_write(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(database) = &error
        && database.is_unique_violation()
    {
        return ApiError::conflict("application_conflict");
    }
    ApiError::internal("application_write")
}

#[cfg(test)]
mod tests {
    use super::REVOKE_ACCESS_TOKENS_FOR_REMOVED_SCOPES_QUERY;

    #[test]
    fn removed_scopes_revoke_only_intersecting_active_client_access_tokens() {
        for required_fragment in [
            "token.client_application_id = $1",
            "token.token_class = 'application_access'",
            "token.revoked_at IS NULL",
            "token.expires_at > transaction_timestamp()",
            "FROM iam.access_token_scopes AS token_scope",
            "token_scope.access_token_id = token.id",
            "token_scope.scope = ANY($2::text[])",
            "revocation_reason = 'application_scope_revoked'",
        ] {
            assert!(
                REVOKE_ACCESS_TOKENS_FOR_REMOVED_SCOPES_QUERY.contains(required_fragment),
                "scope-removal containment is missing `{required_fragment}`"
            );
        }
        assert!(!REVOKE_ACCESS_TOKENS_FOR_REMOVED_SCOPES_QUERY.contains("refresh_tokens"));
        assert!(!REVOKE_ACCESS_TOKENS_FOR_REMOVED_SCOPES_QUERY.contains("authentication_sessions"));
    }
}
