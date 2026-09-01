#![allow(clippy::too_many_lines)]

use std::{borrow::Cow, str::FromStr as _};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use garde::rules::email::parse_email;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    application::ports::EmailOtp,
    domain::{auth::CarbonId, organization::Capability},
    error::AppError,
    infrastructure::{
        crypto::{
            BlindIndexPurpose, DigestPurpose, EncryptedValue, EncryptionContext, ProtectedField,
            SecretDigest,
        },
        postgres::context::{self, DatabaseContext},
    },
};

use super::{
    directory,
    model::{
        ActorResponse, CarbonInviteCreate, CarbonPublicResponse, InvitationAcceptance,
        InvitationPage, InvitationResponse, PageInfo, StatusPageQuery, TrustValue,
    },
    support::{self, Claim, MutationEvent},
    validation,
};

const INVITATION_CREATE_ROUTE: &str = "/api/v1/organizations/{org_id}/carbon-invites";
const INVITATION_ROUTE: &str = "/api/v1/organizations/{org_id}/carbon-invites/{invite_id}";
const INVITATION_CODE_ROUTE: &str =
    "/api/v1/organizations/{org_id}/carbon-invites/{invite_id}/verification-code";
const INVITATION_JOIN_ROUTE: &str = "/api/v1/organizations/{org_id}/join";

#[derive(Clone, Debug, sqlx::FromRow)]
struct ContactMaterial {
    contact_id: Uuid,
    contact_kind: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    encryption_key_version: i16,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct ContactResolution {
    principal_id: Uuid,
    contact_id: Uuid,
    contact_ciphertext: Vec<u8>,
    contact_nonce: Vec<u8>,
    contact_encryption_key_version: i16,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct InvitationRow {
    id: Uuid,
    org_id: String,
    target_principal_id: Uuid,
    target_carbon_id: String,
    target_display_name: String,
    target_description: Option<String>,
    target_profile_photo: String,
    target_created_at: OffsetDateTime,
    job_role: String,
    tag_ids: Vec<Uuid>,
    first_silicon_membership_id: Option<Uuid>,
    extra_silicon_membership_ids: Vec<Uuid>,
    default_trust_boundary: String,
    default_trust_level: String,
    inviter_principal_id: Uuid,
    inviter_type: String,
    inviter_public_id: String,
    status: String,
    expires_at: OffsetDateTime,
    version: i64,
    created_at: OffsetDateTime,
    accepted_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct ChallengeRow {
    organization_id: Uuid,
    target_carbon_id: Uuid,
    invitation_status: String,
    invitation_expires_at: OffsetDateTime,
    challenge_id: Uuid,
    code_digest: Vec<u8>,
    digest_key_version: i16,
    failed_attempts: i16,
    max_attempts: i16,
    cooldown_until: Option<OffsetDateTime>,
    challenge_expires_at: OffsetDateTime,
    consumed_at: Option<OffsetDateTime>,
    superseded_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct CompletedInvitation {
    organization_id: Uuid,
    membership_id: Uuid,
    membership_version: i64,
}

pub(super) async fn list_invitations(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    Query(query): Query<StatusPageQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_status(query.status.as_deref())?;
    let (cursor, limit) = validation::page_parts(query.cursor.as_deref(), query.limit)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::MembersInvite)?;
    let rows = sqlx::query_as::<_, InvitationRow>(INVITATION_LIST_SQL)
        .bind(scope.access.organization_id)
        .bind(cursor)
        .bind(limit + 1)
        .bind(query.status.as_deref())
        .fetch_all(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    let mut items = materialize_invitations(&mut scope.transaction, &state, rows).await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    let page = take_page(&mut items, limit)?;
    support::json(StatusCode::OK, &InvitationPage { items, page }, None)
}

pub(super) async fn create_invitation(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<CarbonInviteCreate>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_invitation(&mut input)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::MembersInvite)?;
    if !input.tag_ids.is_empty() {
        support::require_capability(&scope.access, Capability::TagsManage)?;
    }
    let target = resolve_target(&mut scope.transaction, &state, &input).await?;
    validate_invitation_references(&mut scope.transaction, scope.access.organization_id, &input)
        .await?;
    let already_active = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM iam.organization_memberships WHERE organization_id = $1 AND principal_id = $2 AND status = 'active')",
    )
    .bind(scope.access.organization_id)
    .bind(target.principal_id)
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if already_active {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("carbon_already_member"),
        });
    }
    let redirect_application_id = if let Some(app_id) = input.redirect_app_id.as_deref() {
        Some(sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM iam.applications WHERE app_id = $1 AND review_status = 'verified' LIMIT 1",
        )
        .bind(app_id)
        .fetch_optional(&mut *scope.transaction)
        .await
        .map_err(support::database)?
        .ok_or_else(|| validation::field("redirect_app_id", "does not identify a verified application"))?)
    } else {
        None
    };
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        INVITATION_CREATE_ROUTE,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let invitation_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.organization_invitations (
            id, organization_id, target_carbon_id, invited_by_membership_id,
            job_role, first_silicon_membership_id, default_trust_boundary,
            default_trust_level, redirect_application_principal_id,
            expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6,
            $7::iam.trust_boundary, $8::iam.trust_level, $9,
            transaction_timestamp() + interval '48 hours'
        )
        ",
    )
    .bind(invitation_id)
    .bind(scope.access.organization_id)
    .bind(target.principal_id)
    .bind(scope.access.membership_id)
    .bind(&input.job_role)
    .bind(input.first_silicon_membership_id)
    .bind(input.default_trust.boundary.as_str())
    .bind(input.default_trust.level.as_str())
    .bind(redirect_application_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "invitation_already_pending"))?;
    for tag_id in &input.tag_ids {
        sqlx::query(
            "INSERT INTO iam.organization_invitation_tags (organization_id, invitation_id, tag_id) VALUES ($1, $2, $3)",
        )
        .bind(scope.access.organization_id)
        .bind(invitation_id)
        .bind(tag_id)
        .execute(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    }
    for silicon_membership_id in &input.extra_silicon_membership_ids {
        sqlx::query(
            "INSERT INTO iam.organization_invitation_extra_silicons (organization_id, invitation_id, silicon_membership_id) VALUES ($1, $2, $3)",
        )
        .bind(scope.access.organization_id)
        .bind(invitation_id)
        .bind(silicon_membership_id)
        .execute(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    }
    sqlx::query(
        r"
        INSERT INTO iam.notification_jobs (
            id, notification_kind, provider, recipient_contact_id,
            recipient_contact_kind, template_id, context_type, context_id
        ) VALUES (
            $1, 'invitation', 'postmark', $2, 'email',
            'invitation.created', 'organization_invitation', $3
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(target.contact.contact_id)
    .bind(invitation_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    let invitation = fetch_invitation(
        &mut scope.transaction,
        &state,
        scope.access.organization_id,
        invitation_id,
        &org_id,
    )
    .await?;
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "invitation.created",
            target_type: "organization_invitation",
            target_id: invitation.id,
            aggregate_type: "organization_invitation",
            aggregate_id: invitation.id,
            aggregate_version: invitation.version,
            event_type: "organization.invitation.created.v1",
            before_state: None,
            after_state: redacted_invitation(&invitation)?,
            metadata: json!({ "invitation_id": invitation.id, "target_carbon_id": target.principal_id }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::CREATED,
        &invitation,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::CREATED, body, Some(invitation.version), false)
}

pub(super) async fn get_invitation(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, invite_id)): Path<(String, Uuid)>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let (mut transaction, organization_id) =
        begin_invitation(&state, &authenticated, &org_id, invite_id).await?;
    let invitation = fetch_invitation(
        &mut transaction,
        &state,
        organization_id,
        invite_id,
        &org_id,
    )
    .await?;
    transaction.commit().await.map_err(support::database)?;
    support::json(StatusCode::OK, &invitation, Some(invitation.version))
}

pub(super) async fn revoke_invitation(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, invite_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let expected_version = validation::expected_version(&headers)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::MembersInvite)?;
    let before = fetch_invitation(
        &mut scope.transaction,
        &state,
        scope.access.organization_id,
        invite_id,
        &org_id,
    )
    .await?;
    if before.version != expected_version || before.status != "pending" {
        return Err(precondition_failed());
    }
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        INVITATION_ROUTE,
        &json!({ "invite_id": invite_id }),
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let result = sqlx::query(
        r"
        UPDATE iam.organization_invitations
        SET status = 'revoked', revoked_at = transaction_timestamp()
        WHERE organization_id = $1 AND id = $2 AND version = $3 AND status = 'pending'
        ",
    )
    .bind(scope.access.organization_id)
    .bind(invite_id)
    .bind(expected_version)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if result.rows_affected() != 1 {
        return Err(precondition_failed());
    }
    sqlx::query(
        "UPDATE iam.invitation_verification_challenges SET superseded_at = transaction_timestamp() WHERE organization_id = $1 AND invitation_id = $2 AND consumed_at IS NULL AND superseded_at IS NULL",
    )
    .bind(scope.access.organization_id)
    .bind(invite_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        "UPDATE iam.notification_jobs SET status = 'cancelled' WHERE context_type = 'organization_invitation' AND context_id = $1 AND status IN ('pending', 'processing')",
    )
    .bind(invite_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "invitation.revoked",
            target_type: "organization_invitation",
            target_id: invite_id,
            aggregate_type: "organization_invitation",
            aggregate_id: invite_id,
            aggregate_version: expected_version + 1,
            event_type: "organization.invitation.revoked.v1",
            before_state: redacted_invitation(&before)?,
            after_state: Some(json!({ "status": "revoked", "version": expected_version + 1 })),
            metadata: json!({ "invitation_id": invite_id }),
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

pub(super) async fn send_invitation_code(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, invite_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let (mut transaction, organization_id) =
        begin_invitation(&state, &authenticated, &org_id, invite_id).await?;
    let (target_carbon_id, status, expires_at) = sqlx::query_as::<_, (Uuid, String, OffsetDateTime)>(
        "SELECT target_carbon_id, status, expires_at FROM iam.organization_invitations WHERE organization_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(invite_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)?;
    if status != "pending" || expires_at <= OffsetDateTime::now_utc() {
        return Err(AppError::Gone {
            code: Cow::Borrowed("invitation_expired"),
        });
    }
    let lease = match support::claim(
        &mut transaction,
        &state,
        &authenticated,
        &headers,
        INVITATION_CODE_ROUTE,
        &json!({ "invite_id": invite_id }),
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let contact = primary_email(&mut transaction, target_carbon_id).await?;
    let recipient = decrypt_email(&state, &contact)?;
    let code = state
        .crypto
        .generate_otp()
        .map_err(|_| AppError::Internal {
            category: "invitation_code_generate",
        })?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::InvitationOtp, &code)
        .map_err(|_| AppError::Internal {
            category: "invitation_code_digest",
        })?;
    sqlx::query(
        "UPDATE iam.invitation_verification_challenges SET superseded_at = transaction_timestamp() WHERE invitation_id = $1 AND consumed_at IS NULL AND superseded_at IS NULL",
    )
    .bind(invite_id)
    .execute(&mut *transaction)
    .await
    .map_err(support::database)?;
    let ttl_seconds = i64::try_from(state.settings.security.otp_ttl.as_secs()).map_err(|_| {
        AppError::Internal {
            category: "invitation_code_ttl",
        }
    })?;
    sqlx::query(
        r"
        INSERT INTO iam.invitation_verification_challenges (
            id, organization_id, invitation_id, target_carbon_id,
            destination_contact_id, code_digest, digest_key_version,
            max_attempts, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8,
            transaction_timestamp() + ($9::bigint * interval '1 second')
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(invite_id)
    .bind(target_carbon_id)
    .bind(contact.contact_id)
    .bind(digest.as_bytes().as_slice())
    .bind(digest.key_version())
    .bind(
        i16::try_from(state.settings.security.otp_max_attempts).map_err(|_| {
            AppError::Internal {
                category: "invitation_code_attempts",
            }
        })?,
    )
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await
    .map_err(support::database)?;
    let response = json!({ "accepted": true });
    let body = support::finish_json(
        &mut transaction,
        &state,
        lease,
        StatusCode::ACCEPTED,
        &response,
    )
    .await?;
    transaction.commit().await.map_err(support::database)?;

    let minutes =
        u16::try_from(state.settings.security.otp_ttl.as_secs().div_ceil(60)).unwrap_or(u16::MAX);
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        state.notifications.email.send_otp(EmailOtp {
            recipient: &recipient,
            code: &code,
            purpose: "organization invitation",
            expires_in_minutes: minutes,
        }),
    )
    .await;
    support::json_response(StatusCode::ACCEPTED, body, None, false)
}

pub(super) async fn join_organization(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<InvitationAcceptance>,
) -> Result<Response, AppError> {
    let carbon_id = support::require_carbon(&authenticated)?;
    let org_id = validation::organization_id(&org_id)?.to_string();
    let code = validate_code(&input.verification_code)?;
    let (mut transaction, organization_id) =
        begin_invitation(&state, &authenticated, &org_id, input.invite_id).await?;
    let challenge = fetch_challenge(&mut transaction, input.invite_id, carbon_id).await?;
    if challenge.organization_id != organization_id || challenge.target_carbon_id != carbon_id {
        return Err(AppError::NotFound);
    }
    let stored = SecretDigest::from_parts(challenge.digest_key_version, &challenge.code_digest)
        .ok_or(AppError::Internal {
            category: "invitation_digest_shape",
        })?;
    let valid = state
        .crypto
        .verify_secret(DigestPurpose::InvitationOtp, &code, stored)
        .map_err(|_| AppError::Internal {
            category: "invitation_code_verify",
        })?;
    if !valid {
        register_failed_attempt(&mut transaction, &challenge).await?;
        transaction.commit().await.map_err(support::database)?;
        return Err(validation::field(
            "verification_code",
            "is invalid or expired",
        ));
    }
    let lease = match support::claim(
        &mut transaction,
        &state,
        &authenticated,
        &headers,
        INVITATION_JOIN_ROUTE,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    if challenge.invitation_status != "pending"
        || challenge.invitation_expires_at <= OffsetDateTime::now_utc()
        || challenge.challenge_expires_at <= OffsetDateTime::now_utc()
        || challenge.consumed_at.is_some()
        || challenge.superseded_at.is_some()
        || challenge.failed_attempts >= challenge.max_attempts
        || challenge
            .cooldown_until
            .is_some_and(|cooldown| cooldown > OffsetDateTime::now_utc())
    {
        return Err(AppError::Gone {
            code: Cow::Borrowed("invitation_expired"),
        });
    }
    let completed = sqlx::query_as::<_, CompletedInvitation>(
        r"
        SELECT organization_id, membership_id, membership_version
        FROM iam_private.complete_verified_organization_invitation($1, $2, $3, $4, $5)
        ",
    )
    .bind(&org_id)
    .bind(input.invite_id)
    .bind(Uuid::now_v7())
    .bind(challenge.digest_key_version)
    .bind(&challenge.code_digest)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "invitation_cannot_be_completed"))?
    .ok_or(AppError::Conflict {
        code: Cow::Borrowed("invitation_cannot_be_completed"),
    })?;
    if completed.organization_id != organization_id {
        return Err(AppError::Internal {
            category: "invitation_tenant_mismatch",
        });
    }
    let member =
        directory::fetch_member(&mut transaction, organization_id, completed.membership_id).await?;
    if member.version != completed.membership_version {
        return Err(AppError::Internal {
            category: "invitation_membership_version",
        });
    }
    support::record_mutation(
        &mut transaction,
        &authenticated,
        organization_id,
        MutationEvent {
            action: "membership.joined",
            target_type: "organization_membership",
            target_id: member.id,
            aggregate_type: "organization_membership",
            aggregate_id: member.id,
            aggregate_version: member.version,
            event_type: "organization.membership.created.v1",
            before_state: None,
            after_state: serde_json::to_value(&member).ok(),
            metadata: json!({ "membership_id": member.id, "invitation_id": input.invite_id }),
        },
    )
    .await?;
    let body =
        support::finish_json(&mut transaction, &state, lease, StatusCode::OK, &member).await?;
    transaction.commit().await.map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(member.version), false)
}

struct ResolvedTarget {
    principal_id: Uuid,
    contact: ContactMaterial,
}

async fn resolve_target(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    input: &CarbonInviteCreate,
) -> Result<ResolvedTarget, AppError> {
    if let Some(carbon_id) = input.carbon_id.as_deref() {
        let principal_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT principal_id FROM iam_private.resolve_active_carbon_by_handle($1)",
        )
        .bind(carbon_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::NotFound)?;
        let contact = primary_email(transaction, principal_id).await?;
        return Ok(ResolvedTarget {
            principal_id,
            contact,
        });
    }
    let email = input.email.as_deref().ok_or(AppError::NotFound)?;
    let normalized = crate::domain::auth::normalize_email(email);
    for digest in state
        .crypto
        .blind_indexes(BlindIndexPurpose::CarbonEmail, &normalized)
        .map_err(|_| AppError::Internal {
            category: "invitation_email_index",
        })?
    {
        if let Some(resolved) = sqlx::query_as::<_, ContactResolution>(
            r"
            SELECT principal_id, contact_id, contact_ciphertext,
                   contact_nonce, contact_encryption_key_version
            FROM iam_private.resolve_active_carbon_by_contact_digest('email', $1, $2)
            ",
        )
        .bind(digest.key_version())
        .bind(digest.as_bytes().as_slice())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?
        {
            return Ok(ResolvedTarget {
                principal_id: resolved.principal_id,
                contact: ContactMaterial {
                    contact_id: resolved.contact_id,
                    contact_kind: "email".to_owned(),
                    ciphertext: resolved.contact_ciphertext,
                    nonce: resolved.contact_nonce,
                    encryption_key_version: resolved.contact_encryption_key_version,
                },
            });
        }
    }
    Err(AppError::NotFound)
}

async fn primary_email(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
) -> Result<ContactMaterial, AppError> {
    sqlx::query_as::<_, ContactMaterial>(
        r"
        SELECT contact_id, contact_kind::text AS contact_kind,
               contact_ciphertext AS ciphertext, contact_nonce AS nonce,
               contact_encryption_key_version AS encryption_key_version
        FROM iam_private.list_active_carbon_login_contacts($1)
        WHERE contact_kind = 'email'
        LIMIT 1
        ",
    )
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::Conflict {
        code: Cow::Borrowed("target_has_no_active_email"),
    })
}

fn decrypt_email(state: &ApiState, contact: &ContactMaterial) -> Result<SecretString, AppError> {
    if contact.contact_kind != "email" {
        return Err(AppError::Internal {
            category: "invitation_contact_kind",
        });
    }
    let nonce = <[u8; 12]>::try_from(contact.nonce.as_slice()).map_err(|_| AppError::Internal {
        category: "invitation_contact_shape",
    })?;
    let plaintext = state
        .crypto
        .decrypt(
            EncryptionContext::global(ProtectedField::CarbonEmail, contact.contact_id),
            &EncryptedValue {
                key_version: contact.encryption_key_version,
                nonce,
                ciphertext: contact.ciphertext.clone(),
            },
        )
        .map_err(|_| AppError::Internal {
            category: "invitation_contact_decrypt",
        })?;
    String::from_utf8(plaintext.to_vec())
        .map(SecretString::from)
        .map_err(|_| AppError::Internal {
            category: "invitation_contact_encoding",
        })
}

async fn begin_invitation<'a>(
    state: &'a ApiState,
    authenticated: &Authenticated,
    org_id: &str,
    invite_id: Uuid,
) -> Result<(Transaction<'a, Postgres>, Uuid), AppError> {
    support::require_carbon(authenticated)?;
    let mut transaction = context::begin(
        &state.pool,
        DatabaseContext::principal(authenticated.0.subject.id),
    )
    .await
    .map_err(support::database)?;
    let organization_id = sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT iam_private.resolve_organization_invitation_tenant($1, $2)",
    )
    .bind(org_id)
    .bind(invite_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)?;
    context::select_organization(&mut transaction, organization_id)
        .await
        .map_err(support::database)?;
    Ok((transaction, organization_id))
}

async fn fetch_invitation(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    organization_id: Uuid,
    invite_id: Uuid,
    organization_handle: &str,
) -> Result<InvitationResponse, AppError> {
    let row = sqlx::query_as::<_, InvitationRow>(INVITATION_BY_ID_SQL)
        .bind(organization_id)
        .bind(invite_id)
        .bind(organization_handle)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::NotFound)?;
    materialize_invitation(transaction, state, row).await
}

async fn materialize_invitations(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    rows: Vec<InvitationRow>,
) -> Result<Vec<InvitationResponse>, AppError> {
    let mut output = Vec::with_capacity(rows.len());
    for row in rows {
        output.push(materialize_invitation(transaction, state, row).await?);
    }
    Ok(output)
}

async fn materialize_invitation(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    row: InvitationRow,
) -> Result<InvitationResponse, AppError> {
    let contact = primary_email(transaction, row.target_principal_id).await?;
    let email = decrypt_email(state, &contact)?;
    Ok(InvitationResponse {
        id: row.id,
        org_id: row.org_id,
        target_carbon: CarbonPublicResponse {
            principal_id: row.target_principal_id,
            carbon_id: row.target_carbon_id,
            display_name: row.target_display_name,
            description: row.target_description,
            profile_photo: row.target_profile_photo,
            created_at: row.target_created_at,
        },
        masked_delivery_address: Some(mask_email(email.expose_secret())),
        org_role: "member".to_owned(),
        job_role: row.job_role,
        tag_ids: row.tag_ids,
        first_silicon_membership_id: row.first_silicon_membership_id,
        extra_silicon_membership_ids: row.extra_silicon_membership_ids,
        default_trust: TrustValue {
            boundary: parse_boundary(&row.default_trust_boundary)?,
            level: parse_level(&row.default_trust_level)?,
        },
        invited_by: ActorResponse {
            principal_id: row.inviter_principal_id,
            actor_type: row.inviter_type,
            public_id: row.inviter_public_id,
        },
        status: row.status,
        expires_at: row.expires_at,
        version: row.version,
        created_at: row.created_at,
        accepted_at: row.accepted_at,
    })
}

async fn fetch_challenge(
    transaction: &mut Transaction<'_, Postgres>,
    invite_id: Uuid,
    carbon_id: Uuid,
) -> Result<ChallengeRow, AppError> {
    sqlx::query_as::<_, ChallengeRow>(
        r"
        SELECT invitation.organization_id, invitation.target_carbon_id,
               invitation.status AS invitation_status,
               invitation.expires_at AS invitation_expires_at,
               challenge.id AS challenge_id, challenge.code_digest,
               challenge.digest_key_version, challenge.failed_attempts,
               challenge.max_attempts, challenge.cooldown_until,
               challenge.expires_at AS challenge_expires_at,
               challenge.consumed_at, challenge.superseded_at
        FROM iam.organization_invitations AS invitation
        JOIN iam.invitation_verification_challenges AS challenge
          ON challenge.organization_id = invitation.organization_id
         AND challenge.invitation_id = invitation.id
         AND challenge.target_carbon_id = invitation.target_carbon_id
        WHERE invitation.id = $1 AND invitation.target_carbon_id = $2
        ORDER BY challenge.created_at DESC
        LIMIT 1
        FOR UPDATE OF invitation, challenge
        ",
    )
    .bind(invite_id)
    .bind(carbon_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

async fn register_failed_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    challenge: &ChallengeRow,
) -> Result<(), AppError> {
    if challenge.consumed_at.is_none()
        && challenge.superseded_at.is_none()
        && challenge.challenge_expires_at > OffsetDateTime::now_utc()
        && challenge.failed_attempts < challenge.max_attempts
    {
        sqlx::query(
            r"
            UPDATE iam.invitation_verification_challenges
            SET failed_attempts = failed_attempts + 1,
                cooldown_until = transaction_timestamp() + interval '30 seconds'
            WHERE id = $1 AND consumed_at IS NULL AND superseded_at IS NULL
              AND failed_attempts < max_attempts
            ",
        )
        .bind(challenge.challenge_id)
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    }
    Ok(())
}

async fn validate_invitation_references(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    input: &CarbonInviteCreate,
) -> Result<(), AppError> {
    let tag_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM iam.organization_tags WHERE organization_id = $1 AND id = ANY($2) AND status = 'active'",
    )
    .bind(organization_id)
    .bind(&input.tag_ids)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if usize::try_from(tag_count).ok() != Some(input.tag_ids.len()) {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("invitation_default_inactive"),
        });
    }
    let mut silicons = input.extra_silicon_membership_ids.clone();
    if let Some(first) = input.first_silicon_membership_id {
        silicons.push(first);
        silicons.sort_unstable();
        silicons.dedup();
    }
    let silicon_count = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*)
        FROM iam.silicons AS silicon
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = silicon.organization_id
         AND membership.id = silicon.membership_id
        WHERE silicon.organization_id = $1 AND silicon.membership_id = ANY($2)
          AND silicon.provisioning_status <> 'deleted' AND membership.status = 'active'
        ",
    )
    .bind(organization_id)
    .bind(&silicons)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if usize::try_from(silicon_count).ok() != Some(silicons.len()) {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("invitation_default_inactive"),
        });
    }
    Ok(())
}

fn validate_invitation(input: &mut CarbonInviteCreate) -> Result<(), AppError> {
    match (input.carbon_id.as_mut(), input.email.as_mut()) {
        (Some(carbon_id), None) => {
            *carbon_id = CarbonId::from_str(carbon_id)
                .map_err(|_| validation::field("carbon_id", "has an invalid format"))?
                .to_string();
        }
        (None, Some(email)) => {
            if *email != email.trim() || email.len() > 320 || parse_email(email).is_err() {
                return Err(validation::field("email", "must be a valid email address"));
            }
        }
        _ => {
            return Err(validation::field(
                "target",
                "exactly one of carbon_id or email is required",
            ));
        }
    }
    input.job_role = validation::job_role(std::mem::take(&mut input.job_role))?;
    unique_ids("tag_ids", &mut input.tag_ids, 100)?;
    unique_ids(
        "extra_silicon_membership_ids",
        &mut input.extra_silicon_membership_ids,
        500,
    )?;
    if let Some(app_id) = input.redirect_app_id.as_deref()
        && (app_id.len() > 63
            || app_id.len() < 3
            || !app_id.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_lowercase()
                } else {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'-')
                }
            }))
    {
        return Err(validation::field(
            "redirect_app_id",
            "has an invalid format",
        ));
    }
    Ok(())
}

fn unique_ids(name: &'static str, values: &mut [Uuid], maximum: usize) -> Result<(), AppError> {
    values.sort_unstable();
    if values.len() > maximum || values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(validation::field(
            name,
            "must contain unique values within the item limit",
        ));
    }
    Ok(())
}

fn validate_code(value: &str) -> Result<SecretString, AppError> {
    if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(validation::field(
            "verification_code",
            "must contain exactly six digits",
        ));
    }
    Ok(SecretString::from(value.to_owned()))
}

fn validate_status(status: Option<&str>) -> Result<(), AppError> {
    if status.is_some_and(|value| !matches!(value, "pending" | "accepted" | "revoked" | "expired"))
    {
        return Err(validation::field("status", "has an unsupported value"));
    }
    Ok(())
}

fn mask_email(value: &str) -> String {
    let Some((local, domain)) = value.split_once('@') else {
        return "***".to_owned();
    };
    let visible = local.chars().next().unwrap_or('*');
    format!("{visible}***@{domain}")
}

fn parse_boundary(value: &str) -> Result<super::model::TrustBoundary, AppError> {
    match value {
        "internal" => Ok(super::model::TrustBoundary::Internal),
        "external" => Ok(super::model::TrustBoundary::External),
        _ => Err(AppError::Internal {
            category: "invitation_trust_boundary",
        }),
    }
}

fn parse_level(value: &str) -> Result<super::model::TrustLevel, AppError> {
    match value {
        "not_trusted" => Ok(super::model::TrustLevel::NotTrusted),
        "needs_approval" => Ok(super::model::TrustLevel::NeedsApproval),
        "trusted" => Ok(super::model::TrustLevel::Trusted),
        _ => Err(AppError::Internal {
            category: "invitation_trust_level",
        }),
    }
}

fn redacted_invitation(value: &InvitationResponse) -> Result<Option<serde_json::Value>, AppError> {
    serde_json::to_value(value)
        .map(|mut value| {
            if let Some(object) = value.as_object_mut() {
                object.remove("masked_delivery_address");
            }
            Some(value)
        })
        .map_err(|_| AppError::Internal {
            category: "invitation_audit_serialize",
        })
}

fn take_page(items: &mut Vec<InvitationResponse>, limit: i64) -> Result<PageInfo, AppError> {
    let limit = usize::try_from(limit).map_err(|_| AppError::Internal {
        category: "invitation_page_limit",
    })?;
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    let next_cursor = if has_more {
        items.last().map(|item| validation::encode_cursor(item.id))
    } else {
        None
    };
    Ok(PageInfo {
        next_cursor,
        has_more,
    })
}

fn precondition_failed() -> AppError {
    AppError::PreconditionFailed {
        code: Cow::Borrowed("etag_mismatch"),
    }
}

const INVITATION_LIST_SQL: &str = r"
    SELECT invitation.id, organization.org_id,
           target.id AS target_principal_id, target.carbon_id AS target_carbon_id,
           target.display_name AS target_display_name, target.description AS target_description,
           COALESCE(target.profile_photo_uri, '') AS target_profile_photo,
           target.created_at AS target_created_at, invitation.job_role,
           ARRAY(SELECT x.tag_id FROM iam.organization_invitation_tags x WHERE x.organization_id = invitation.organization_id AND x.invitation_id = invitation.id ORDER BY x.tag_id) AS tag_ids,
           invitation.first_silicon_membership_id,
           ARRAY(SELECT x.silicon_membership_id FROM iam.organization_invitation_extra_silicons x WHERE x.organization_id = invitation.organization_id AND x.invitation_id = invitation.id ORDER BY x.silicon_membership_id) AS extra_silicon_membership_ids,
           invitation.default_trust_boundary::text AS default_trust_boundary,
           invitation.default_trust_level::text AS default_trust_level,
           inviter_membership.principal_id AS inviter_principal_id,
           inviter_membership.principal_kind::text AS inviter_type,
           CASE WHEN inviter_membership.principal_kind = 'carbon' THEN inviter_carbon.carbon_id ELSE inviter_silicon.global_silicon_id END AS inviter_public_id,
           CASE WHEN invitation.status = 'pending' AND invitation.expires_at <= transaction_timestamp() THEN 'expired' ELSE invitation.status END AS status,
           invitation.expires_at, invitation.version, invitation.created_at, invitation.accepted_at
    FROM iam.organization_invitations invitation
    JOIN iam.organizations organization ON organization.id = invitation.organization_id
    JOIN iam.carbons target ON target.id = invitation.target_carbon_id
    JOIN iam.organization_memberships inviter_membership ON inviter_membership.organization_id = invitation.organization_id AND inviter_membership.id = invitation.invited_by_membership_id
    LEFT JOIN iam.carbons inviter_carbon ON inviter_carbon.id = inviter_membership.principal_id AND inviter_membership.principal_kind = 'carbon'
    LEFT JOIN iam.silicons inviter_silicon ON inviter_silicon.id = inviter_membership.principal_id AND inviter_membership.principal_kind = 'silicon'
    WHERE invitation.organization_id = $1 AND ($2::uuid IS NULL OR invitation.id > $2)
      AND ($4::text IS NULL OR CASE WHEN invitation.status = 'pending' AND invitation.expires_at <= transaction_timestamp() THEN 'expired' ELSE invitation.status END = $4)
    ORDER BY invitation.id LIMIT $3
";

const INVITATION_BY_ID_SQL: &str = r"
    SELECT invitation.id, $3::text AS org_id,
           target.id AS target_principal_id, target.carbon_id AS target_carbon_id,
           target.display_name AS target_display_name, target.description AS target_description,
           COALESCE(target.profile_photo_uri, '') AS target_profile_photo,
           target.created_at AS target_created_at, invitation.job_role,
           ARRAY(SELECT x.tag_id FROM iam.organization_invitation_tags x WHERE x.organization_id = invitation.organization_id AND x.invitation_id = invitation.id ORDER BY x.tag_id) AS tag_ids,
           invitation.first_silicon_membership_id,
           ARRAY(SELECT x.silicon_membership_id FROM iam.organization_invitation_extra_silicons x WHERE x.organization_id = invitation.organization_id AND x.invitation_id = invitation.id ORDER BY x.silicon_membership_id) AS extra_silicon_membership_ids,
           invitation.default_trust_boundary::text AS default_trust_boundary,
           invitation.default_trust_level::text AS default_trust_level,
           inviter_membership.principal_id AS inviter_principal_id,
           inviter_membership.principal_kind::text AS inviter_type,
           CASE WHEN inviter_membership.principal_kind = 'carbon' THEN inviter_carbon.carbon_id ELSE inviter_silicon.global_silicon_id END AS inviter_public_id,
           CASE WHEN invitation.status = 'pending' AND invitation.expires_at <= transaction_timestamp() THEN 'expired' ELSE invitation.status END AS status,
           invitation.expires_at, invitation.version, invitation.created_at, invitation.accepted_at
    FROM iam.organization_invitations invitation
    JOIN iam.carbons target ON target.id = invitation.target_carbon_id
    JOIN iam.organization_memberships inviter_membership ON inviter_membership.organization_id = invitation.organization_id AND inviter_membership.id = invitation.invited_by_membership_id
    LEFT JOIN iam.carbons inviter_carbon ON inviter_carbon.id = inviter_membership.principal_id AND inviter_membership.principal_kind = 'carbon'
    LEFT JOIN iam.silicons inviter_silicon ON inviter_silicon.id = inviter_membership.principal_id AND inviter_membership.principal_kind = 'silicon'
    WHERE invitation.organization_id = $1 AND invitation.id = $2 LIMIT 1
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masked_email_never_contains_the_local_part() {
        assert_eq!(mask_email("alice@example.com"), "a***@example.com");
        assert_eq!(mask_email("malformed"), "***");
    }

    #[test]
    fn invitation_codes_have_an_exact_shape() {
        assert!(validate_code("000042").is_ok());
        assert!(validate_code("42").is_err());
        assert!(validate_code("abcdef").is_err());
    }
}
