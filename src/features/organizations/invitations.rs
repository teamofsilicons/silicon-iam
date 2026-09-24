#![allow(clippy::too_many_lines)]

use super::application_reads::ReadScopes;

use std::{borrow::Cow, num::NonZeroU32, time::Duration};

use crate::domain::id::Id;
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

use crate::{
    api::{ApiState, authentication::Authenticated},
    application::ports::{DeliveryError, EmailOtp},
    domain::{
        auth::{CarbonId, OTP_COOLDOWN_SECONDS},
        directory::ApplicationId,
        organization::Capability,
    },
    error::AppError,
    infrastructure::{
        crypto::{
            BlindIndexPurpose, DigestPurpose, EncryptedValue, EncryptionContext, ProtectedField,
            SecretDigest,
        },
        postgres::{
            context::{self, DatabaseContext},
            idempotency::{self, IdempotencyLease},
            rate_limit::{self, RateLimitPolicy},
        },
    },
};

use super::{
    directory,
    model::{
        ActorResponse, CarbonInviteCreate, CarbonPublicResponse, InvitationAcceptance,
        InvitationEmailCodeRequest, InvitationEmailCodeResponse, InvitationPage,
        InvitationResponse, InvitationSiliconTrustOverride, InvitationTagTrustOverride, PageInfo,
        StatusPageQuery, TrustValue,
    },
    support::{self, Claim, MutationEvent},
    validation,
};

const INVITATION_CREATE_ROUTE: &str = "POST /api/v1/organizations/{org_id}/carbon-invites";
const INVITATION_ROUTE: &str = "DELETE /api/v1/organizations/{org_id}/carbon-invites/{invite_id}";
const INVITATION_EMAIL_CODE_ROUTE: &str =
    "POST /api/v1/organizations/{org_id}/join/email-verification-code";
const INVITATION_JOIN_ROUTE: &str = "POST /api/v1/organizations/{org_id}/join";
const INVITATION_CODE_SEND_LIMIT: u32 = 10;
const INVITATION_CODE_SEND_WINDOW: Duration = Duration::from_secs(60);
const INVITATION_OTP_PROVIDER_TIMEOUT: Duration = Duration::from_secs(5);
/// Locks the invitation and its latest verification challenge for the invitee.
///
/// Routed through an owner-rights function. The lock is the point — the attempt
/// counter and the acceptance must not race — but PostgreSQL applies a table's
/// UPDATE policies to a locking read, and the only policy governing UPDATE on
/// `iam.organization_invitations` requires an organization context the invitee
/// does not have: they are not a member yet, which is what holding an
/// invitation means. Run inline, the row row security explicitly lets the
/// target read could never be locked, and every acceptance reported the
/// challenge missing.
const INVITATION_CHALLENGE_LOCK_QUERY: &str = r"
    SELECT *
    FROM iam_private.lock_invitation_verification_challenge($1, $2)
";

#[derive(Clone, Debug, sqlx::FromRow)]
struct ContactMaterial {
    contact_id: Id,
    contact_kind: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    encryption_key_version: i16,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct ContactResolution {
    principal_id: Id,
    contact_id: Id,
    contact_ciphertext: Vec<u8>,
    contact_nonce: Vec<u8>,
    contact_encryption_key_version: i16,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct EmailJoinResolution {
    organization_id: Id,
    invitation_id: Id,
    invitation_expires_at: OffsetDateTime,
    contact_id: Id,
    contact_kind: String,
    contact_ciphertext: Vec<u8>,
    contact_nonce: Vec<u8>,
    contact_encryption_key_version: i16,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct InvitationRow {
    id: Id,
    org_id: String,
    target_principal_id: Option<Id>,
    target_carbon_id: Option<String>,
    target_display_name: Option<String>,
    email_ciphertext: Option<Vec<u8>>,
    email_nonce: Option<Vec<u8>>,
    email_key_version: Option<i16>,
    target_profile_photo: String,
    target_created_at: Option<OffsetDateTime>,
    destination_contact_id: Option<Id>,
    destination_contact_kind: Option<String>,
    destination_contact_ciphertext: Option<Vec<u8>>,
    destination_contact_nonce: Option<Vec<u8>>,
    destination_contact_encryption_key_version: Option<i16>,
    job_role: String,
    tag_ids: Vec<Id>,
    first_silicon_membership_id: Option<Id>,
    extra_silicon_membership_ids: Vec<Id>,
    default_trust_boundary: String,
    default_trust_level: String,
    tag_trust_overrides: sqlx::types::Json<Vec<InvitationTagTrustOverride>>,
    silicon_trust_overrides: sqlx::types::Json<Vec<InvitationSiliconTrustOverride>>,
    inviter_principal_id: Id,
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
    organization_id: Id,
    target_carbon_id: Id,
    invitation_status: String,
    invitation_expires_at: OffsetDateTime,
    challenge_id: Id,
    code_digest: Vec<u8>,
    digest_key_version: i16,
    failed_attempts: i16,
    max_attempts: i16,
    delivery_status: String,
    cooldown_retry_after_seconds: i64,
    challenge_expires_at: OffsetDateTime,
    consumed_at: Option<OffsetDateTime>,
    superseded_at: Option<OffsetDateTime>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvitationOtpDeliveryError {
    Definitive,
    OutcomeUnknown,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct CompletedInvitation {
    organization_id: Id,
    membership_id: Id,
    membership_version: i64,
}

pub(super) async fn list_invitations(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    Query(query): Query<StatusPageQuery>,
) -> Result<Response, AppError> {
    let scopes = ReadScopes::for_actor(&authenticated);
    scopes.require("organization.invitations.read")?;
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_status(query.status.as_deref())?;
    let (cursor, limit) = validation::page_parts(query.cursor.as_deref(), query.limit)?;
    let mut scope = support::begin_directory_organization(&state, &authenticated, &org_id).await?;
    if !scopes.is_application() {
        support::require_capability(&scope.access, Capability::MembersInvite)?;
    }
    let rows = sqlx::query_as::<_, InvitationRow>(INVITATION_LIST_SQL)
        .bind(scope.access.organization_id)
        .bind(cursor)
        .bind(limit + 1)
        .bind(query.status.as_deref())
        .fetch_all(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    let mut items = materialize_invitations(&state, rows)?;
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
    let mut scope = support::begin_scoped_organization(
        &state,
        &authenticated,
        &org_id,
        "organization.invitations.create",
    )
    .await?;
    support::require_capability(&scope.access, Capability::MembersInvite)?;
    if !input.tag_ids.is_empty() {
        support::require_capability(&scope.access, Capability::TagsManage)?;
    }
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
    // Serialize creation with email binding, before resolving a signup race.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 7319))")
        .bind(scope.access.organization_id.to_string())
        .execute(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    let target = resolve_target(&mut scope.transaction, &state, &input).await?;
    let email = if let Some(contact) = &target.contact {
        decrypt_email(&state, contact)?
    } else {
        SecretString::from(input.email.clone().ok_or(AppError::NotFound)?)
    };
    let normalized = crate::domain::auth::normalize_email(email.expose_secret());
    let email_indexes = state
        .crypto
        .blind_indexes(BlindIndexPurpose::CarbonEmail, &normalized)
        .map_err(|_| AppError::Internal {
            category: "invitation_email_index",
        })?
        .iter()
        .map(|digest| {
            format!(
                "{}:{}",
                digest.key_version(),
                hex::encode(digest.as_bytes())
            )
        })
        .collect::<Vec<_>>();
    sqlx::query("UPDATE iam.organization_invitations SET status = 'expired' WHERE organization_id = $1 AND status = 'pending' AND expires_at <= transaction_timestamp()")
        .bind(scope.access.organization_id).execute(&mut *scope.transaction).await.map_err(support::database)?;
    let duplicate = sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM iam.organization_invitations WHERE organization_id = $1 AND status = 'pending' AND email_blind_indexes && $2::text[])")
        .bind(scope.access.organization_id).bind(&email_indexes)
        .fetch_one(&mut *scope.transaction).await.map_err(support::database)?;
    if duplicate {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("invitation_already_pending"),
        });
    }
    validate_invitation_references(&mut scope.transaction, scope.access.organization_id, &input)
        .await?;
    let already_active = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM iam.organization_memberships WHERE organization_id = $1 AND principal_id = $2 AND status = 'active')",
    )
    .bind(scope.access.organization_id)
    .bind(target.principal_id.map(|id| id.to_string()))
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if already_active {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("carbon_already_member"),
        });
    }
    let redirect_application_id = if let Some(app_id) = input.redirect_app_id.as_deref() {
        Some(sqlx::query_scalar::<_, Id>(
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
    let invitation_id = Id::now_v7();
    let encrypted_email = state
        .crypto
        .encrypt(
            EncryptionContext::global(ProtectedField::InvitationEmail, invitation_id),
            normalized.as_bytes(),
        )
        .map_err(|_| AppError::Internal {
            category: "invitation_email_encrypt",
        })?;
    sqlx::query(
        r"
        INSERT INTO iam.organization_invitations (
            id, organization_id, target_carbon_id, invited_by_membership_id,
            job_role, first_silicon_membership_id, default_trust_boundary,
            default_trust_level, destination_contact_id,
            redirect_application_principal_id, expires_at,
            email_ciphertext, email_nonce, email_key_version, email_blind_indexes
        ) VALUES (
            $1, $2, $3, $4, $5, $6,
            $7::iam.trust_boundary, $8::iam.trust_level, $9, $10,
            transaction_timestamp() + interval '48 hours', $11, $12, $13, $14
        )
        ",
    )
    .bind(invitation_id)
    .bind(scope.access.organization_id)
    .bind(target.principal_id.map(|id| id.to_string()))
    .bind(scope.access.membership_id)
    .bind(&input.job_role)
    .bind(input.first_silicon_membership_id)
    .bind(input.default_trust.boundary.as_str())
    .bind(input.default_trust.level.as_str())
    .bind(target.contact.as_ref().map(|contact| contact.contact_id))
    .bind(redirect_application_id.map(|id| id.to_string()))
    .bind(&encrypted_email.ciphertext)
    .bind(encrypted_email.nonce.as_slice())
    .bind(encrypted_email.key_version)
    .bind(&email_indexes)
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
    insert_invitation_trust_overrides(
        &mut scope.transaction,
        scope.access.organization_id,
        invitation_id,
        &input,
    )
    .await?;
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
    .bind(Id::now_v7())
    .bind(target.contact.as_ref().map(|contact| contact.contact_id))
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
    let body = support::finish_mutation(
        &authenticated,
        support::MutationView::Invitation,
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
    Path((org_id, invite_id)): Path<(String, Id)>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let scopes = ReadScopes::for_actor(&authenticated);
    let (mut transaction, organization_id) = if scopes.is_application() {
        scopes.require("organization.invitations.read")?;
        let scope = support::begin_directory_organization(&state, &authenticated, &org_id).await?;
        (scope.transaction, scope.access.organization_id)
    } else {
        begin_invitation(&state, &authenticated, &org_id, invite_id).await?
    };
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
    Path((org_id, invite_id)): Path<(String, Id)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_scoped_organization(
        &state,
        &authenticated,
        &org_id,
        "organization.invitations.revoke",
    )
    .await?;
    support::require_capability(&scope.access, Capability::MembersInvite)?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        INVITATION_ROUTE,
        &invite_id.to_string(),
        &json!({ "operation": "revoke" }),
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
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

pub(super) async fn send_invitation_email_code(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<InvitationEmailCodeRequest>,
) -> Result<Response, AppError> {
    let carbon_id = support::require_scoped_carbon(&authenticated, "organizations.join")?;
    let org_id = validation::organization_id(&org_id)?.to_string();
    input.email = validate_invitation_email(&input.email)?;
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
        .await
        .map_err(support::database)?;
    let lease = match support::claim_resource(
        &mut transaction,
        &state,
        &authenticated,
        &headers,
        INVITATION_EMAIL_CODE_ROUTE,
        &org_id,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    enforce_invitation_code_send_limit(&state, carbon_id, &org_id).await?;
    let resolved = resolve_pending_email_join(&mut transaction, &state, &org_id, &input.email)
        .await?
        .ok_or(AppError::NotInvited)?;
    context::select_organization(&mut transaction, resolved.organization_id)
        .await
        .map_err(support::database)?;
    let contact = ContactMaterial {
        contact_id: resolved.contact_id,
        contact_kind: resolved.contact_kind,
        ciphertext: resolved.contact_ciphertext,
        nonce: resolved.contact_nonce,
        encryption_key_version: resolved.contact_encryption_key_version,
    };
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
    let attempt_state = sqlx::query_as::<_, (i16, Option<OffsetDateTime>)>(
        r"
        UPDATE iam.invitation_verification_challenges
        SET superseded_at = transaction_timestamp()
        WHERE organization_id = $1
          AND invitation_id = $2
          AND target_carbon_id = $3
          AND consumed_at IS NULL
          AND superseded_at IS NULL
        RETURNING
            failed_attempts,
            CASE
                WHEN cooldown_until > transaction_timestamp() THEN cooldown_until
                ELSE NULL
            END AS cooldown_until
        ",
    )
    .bind(resolved.organization_id)
    .bind(resolved.invitation_id)
    .bind(carbon_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(support::database)?;
    let (failed_attempts, cooldown_until) = attempt_state.unwrap_or((0, None));
    let ttl_seconds = i64::try_from(state.settings.security.otp_ttl.as_secs()).map_err(|_| {
        AppError::Internal {
            category: "invitation_code_ttl",
        }
    })?;
    let challenge_id = Id::now_v7();
    let challenge_expires_at = sqlx::query_scalar::<_, OffsetDateTime>(
        r"
        INSERT INTO iam.invitation_verification_challenges (
            id, organization_id, invitation_id, target_carbon_id,
            destination_contact_id, code_digest, digest_key_version,
            failed_attempts, max_attempts, cooldown_until, expires_at,
            delivery_status, delivered_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            LEAST(
                $11,
                transaction_timestamp() + ($12::bigint * interval '1 second')
            ),
            'pending', NULL
        )
        RETURNING expires_at
        ",
    )
    .bind(challenge_id)
    .bind(resolved.organization_id)
    .bind(resolved.invitation_id)
    .bind(carbon_id)
    .bind(contact.contact_id)
    .bind(digest.as_bytes().as_slice())
    .bind(digest.key_version())
    .bind(failed_attempts)
    .bind(
        i16::try_from(state.settings.security.otp_max_attempts).map_err(|_| {
            AppError::Internal {
                category: "invitation_code_attempts",
            }
        })?,
    )
    .bind(cooldown_until)
    .bind(resolved.invitation_expires_at)
    .bind(ttl_seconds)
    .fetch_one(&mut *transaction)
    .await
    .map_err(support::database)?;
    let expires_in = u64::try_from(
        (challenge_expires_at - OffsetDateTime::now_utc())
            .whole_seconds()
            .max(1),
    )
    .map_err(|_| AppError::Internal {
        category: "invitation_code_expiry",
    })?;
    let response = InvitationEmailCodeResponse {
        accepted: true,
        invite_id: resolved.invitation_id,
        expires_in,
    };

    // Phase A commits only a digest-backed pending challenge and the exclusive
    // idempotency reservation. Provider I/O happens with no database locks,
    // and pending challenges are rejected by both Rust and PostgreSQL.
    transaction.commit().await.map_err(support::database)?;

    let minutes = u16::try_from(expires_in.div_ceil(60).max(1)).unwrap_or(u16::MAX);
    let delivery = tokio::time::timeout(
        INVITATION_OTP_PROVIDER_TIMEOUT,
        state.notifications.email.send_otp(EmailOtp {
            recipient: &recipient,
            code: &code,
            purpose: "organization invitation",
            expires_in_minutes: minutes,
        }),
    )
    .await;
    match classify_invitation_otp_delivery(delivery) {
        Ok(()) => {
            let body = confirm_invitation_otp_delivery(
                &state,
                lease,
                carbon_id,
                resolved.organization_id,
                resolved.invitation_id,
                challenge_id,
                contact.contact_id,
                &response,
            )
            .await?;
            support::json_response(StatusCode::ACCEPTED, body, None, false)
        }
        Err(InvitationOtpDeliveryError::Definitive) => {
            fail_invitation_otp_delivery(
                &state,
                lease,
                carbon_id,
                resolved.organization_id,
                resolved.invitation_id,
                challenge_id,
            )
            .await?;
            Err(AppError::ProviderUnavailable)
        }
        Err(InvitationOtpDeliveryError::OutcomeUnknown) => {
            // The pending digest and processing reservation deliberately stay
            // durable. Retrying the same key cannot duplicate an uncertain
            // provider side effect; a fresh key supersedes this unusable code.
            Err(AppError::ProviderUnavailable)
        }
    }
}

fn classify_invitation_otp_delivery(
    result: Result<
        Result<crate::application::ports::DeliveryReceipt, DeliveryError>,
        tokio::time::error::Elapsed,
    >,
) -> Result<(), InvitationOtpDeliveryError> {
    match result {
        Ok(Ok(_receipt)) => Ok(()),
        Ok(Err(DeliveryError::Rejected)) => {
            tracing::warn!(
                provider_error = "rejected",
                purpose = "organization_invitation",
                "required invitation OTP delivery failed"
            );
            Err(InvitationOtpDeliveryError::Definitive)
        }
        Ok(Err(DeliveryError::Unavailable)) => {
            tracing::warn!(
                provider_error = "unavailable",
                purpose = "organization_invitation",
                "required invitation OTP delivery outcome is unknown"
            );
            Err(InvitationOtpDeliveryError::OutcomeUnknown)
        }
        Err(_) => {
            tracing::warn!(
                provider_error = "timeout",
                purpose = "organization_invitation",
                "required invitation OTP delivery outcome is unknown"
            );
            Err(InvitationOtpDeliveryError::OutcomeUnknown)
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the exact invitation challenge authority is required for atomic activation"
)]
async fn confirm_invitation_otp_delivery(
    state: &ApiState,
    lease: IdempotencyLease,
    carbon_id: Id,
    organization_id: Id,
    invitation_id: Id,
    challenge_id: Id,
    destination_contact_id: Id,
    response: &InvitationEmailCodeResponse,
) -> Result<Vec<u8>, AppError> {
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
        .await
        .map_err(support::database)?;
    context::select_organization(&mut transaction, organization_id)
        .await
        .map_err(support::database)?;
    let activated = sqlx::query(
        r"
        UPDATE iam.invitation_verification_challenges AS challenge
        SET delivery_status = 'delivered',
            delivered_at = transaction_timestamp()
        FROM iam.organization_invitations AS invitation,
             iam.carbon_contacts AS contact
        WHERE challenge.id = $1
          AND challenge.organization_id = $2
          AND challenge.invitation_id = $3
          AND challenge.target_carbon_id = $4
          AND challenge.destination_contact_id = $5
          AND challenge.delivery_status = 'pending'
          AND challenge.delivered_at IS NULL
          AND challenge.delivery_failed_at IS NULL
          AND challenge.consumed_at IS NULL
          AND challenge.superseded_at IS NULL
          AND challenge.expires_at > transaction_timestamp()
          AND challenge.failed_attempts < challenge.max_attempts
          AND invitation.organization_id = challenge.organization_id
          AND invitation.id = challenge.invitation_id
          AND invitation.target_carbon_id = challenge.target_carbon_id
          AND invitation.status = 'pending'
          AND invitation.expires_at > transaction_timestamp()
          AND contact.carbon_id = challenge.target_carbon_id
          AND contact.id = challenge.destination_contact_id
          AND contact.kind = 'email'
          AND contact.status = 'active'
          AND contact.verified_at IS NOT NULL
        ",
    )
    .bind(challenge_id)
    .bind(organization_id)
    .bind(invitation_id)
    .bind(carbon_id)
    .bind(destination_contact_id)
    .execute(&mut *transaction)
    .await
    .map_err(support::database)?;
    if activated.rows_affected() != 1 {
        idempotency::cancel_for_retry(&mut transaction, lease).await?;
        transaction.commit().await.map_err(support::database)?;
        return Err(AppError::Conflict {
            code: Cow::Borrowed("otp_delivery_superseded"),
        });
    }

    let body = support::finish_json(
        &mut transaction,
        state,
        lease,
        StatusCode::ACCEPTED,
        response,
    )
    .await?;
    transaction.commit().await.map_err(support::database)?;
    Ok(body)
}

async fn fail_invitation_otp_delivery(
    state: &ApiState,
    lease: IdempotencyLease,
    carbon_id: Id,
    organization_id: Id,
    invitation_id: Id,
    challenge_id: Id,
) -> Result<(), AppError> {
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
        .await
        .map_err(support::database)?;
    context::select_organization(&mut transaction, organization_id)
        .await
        .map_err(support::database)?;
    sqlx::query(
        r"
        UPDATE iam.invitation_verification_challenges
        SET delivery_status = 'failed',
            delivered_at = NULL,
            delivery_failed_at = transaction_timestamp(),
            superseded_at = COALESCE(superseded_at, transaction_timestamp())
        WHERE id = $1
          AND organization_id = $2
          AND invitation_id = $3
          AND target_carbon_id = $4
          AND delivery_status = 'pending'
        ",
    )
    .bind(challenge_id)
    .bind(organization_id)
    .bind(invitation_id)
    .bind(carbon_id)
    .execute(&mut *transaction)
    .await
    .map_err(support::database)?;
    idempotency::cancel_for_retry(&mut transaction, lease).await?;
    transaction.commit().await.map_err(support::database)
}

pub(super) async fn join_organization(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<InvitationAcceptance>,
) -> Result<Response, AppError> {
    let carbon_id = support::require_scoped_carbon(&authenticated, "organizations.join")?;
    let org_id = validation::organization_id(&org_id)?.to_string();
    let code = validate_code(&input.verification_code)?;
    let (mut transaction, organization_id) =
        begin_invitation(&state, &authenticated, &org_id, input.invite_id).await?;
    let lease = match support::claim_resource(
        &mut transaction,
        &state,
        &authenticated,
        &headers,
        INVITATION_JOIN_ROUTE,
        &input.invite_id.to_string(),
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let challenge = fetch_challenge(&mut transaction, input.invite_id, carbon_id).await?;
    if challenge.organization_id != organization_id || challenge.target_carbon_id != carbon_id {
        return Err(AppError::NotFound);
    }
    if challenge.invitation_status != "pending"
        || challenge.invitation_expires_at <= OffsetDateTime::now_utc()
        || challenge.delivery_status != "delivered"
        || challenge.challenge_expires_at <= OffsetDateTime::now_utc()
        || challenge.consumed_at.is_some()
        || challenge.superseded_at.is_some()
        || challenge.failed_attempts >= challenge.max_attempts
    {
        return Err(AppError::Gone {
            code: Cow::Borrowed("invitation_expired"),
        });
    }
    if challenge.cooldown_retry_after_seconds > 0 {
        let retry_after_seconds =
            u64::try_from(challenge.cooldown_retry_after_seconds).unwrap_or(u64::MAX);
        return Err(AppError::RateLimited {
            limit: u64::try_from(challenge.max_attempts.max(1)).unwrap_or(1),
            remaining: 0,
            reset_after_seconds: retry_after_seconds,
            retry_after_seconds,
        });
    }
    let stored = SecretDigest::from_parts(challenge.digest_key_version, &challenge.code_digest)
        .ok_or(AppError::Internal {
            category: "invitation_digest_shape",
        })?;
    // Inside a testing environment the fixed code stands in for a delivered
    // one: nothing was ever sent, so there is nothing to compare against.
    let valid = crate::infrastructure::testing_plane::accepts_verification_code(&code)
        || state
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
    let prior_membership = sqlx::query_as::<_, (String, i64)>(
        r"
        SELECT status, version
        FROM iam.organization_memberships
        WHERE organization_id = $1 AND principal_id = $2 AND principal_kind = 'carbon'
        FOR SHARE
        ",
    )
    .bind(organization_id)
    .bind(carbon_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(support::database)?;
    let completed = sqlx::query_as::<_, CompletedInvitation>(
        r"
        SELECT organization_id, membership_id, membership_version
        FROM iam_private.complete_verified_organization_invitation($1, $2, $3, $4, $5)
        ",
    )
    .bind(&org_id)
    .bind(input.invite_id)
    .bind(Id::now_v7())
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
    let reactivated = prior_membership.is_some();
    support::record_application_mutation(
        &mut transaction,
        &state,
        &authenticated,
        organization_id,
        MutationEvent {
            action: if reactivated {
                "membership.reactivated"
            } else {
                "membership.joined"
            },
            target_type: "organization_membership",
            target_id: member.id,
            aggregate_type: "organization_membership",
            aggregate_id: member.id,
            aggregate_version: member.version,
            event_type: if reactivated {
                "organization.membership.reactivated.v1"
            } else {
                "organization.membership.created.v1"
            },
            before_state: prior_membership
                .as_ref()
                .map(|(status, version)| json!({ "status": status, "version": version })),
            after_state: serde_json::to_value(&member).ok(),
            metadata: json!({ "membership_id": member.id, "invitation_id": input.invite_id }),
        },
    )
    .await?;
    let invitation_version = sqlx::query_scalar::<_, i64>(
        "SELECT version FROM iam.organization_invitations WHERE organization_id = $1 AND id = $2 AND status = 'accepted'",
    )
    .bind(organization_id)
    .bind(input.invite_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(support::database)?;
    support::record_mutation(
        &mut transaction,
        &authenticated,
        organization_id,
        MutationEvent {
            action: "invitation.accepted",
            target_type: "organization_invitation",
            target_id: input.invite_id,
            aggregate_type: "organization_invitation",
            aggregate_id: input.invite_id,
            aggregate_version: invitation_version,
            event_type: "organization.invitation.accepted.v1",
            before_state: Some(json!({
                "status": "pending",
                "version": invitation_version.saturating_sub(1),
            })),
            after_state: Some(json!({
                "status": "accepted",
                "version": invitation_version,
            })),
            metadata: json!({
                "invitation_id": input.invite_id,
                "membership_id": member.id,
            }),
        },
    )
    .await?;
    let body = support::finish_mutation(
        &authenticated,
        support::MutationView::Member,
        &mut transaction,
        &state,
        lease,
        StatusCode::OK,
        &member,
    )
    .await?;
    transaction.commit().await.map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(member.version), false)
}

struct ResolvedTarget {
    principal_id: Option<Id>,
    contact: Option<ContactMaterial>,
}

async fn resolve_pending_email_join(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    organization_handle: &str,
    normalized_email: &str,
) -> Result<Option<EmailJoinResolution>, AppError> {
    for digest in state
        .crypto
        .blind_indexes(BlindIndexPurpose::CarbonEmail, normalized_email)
        .map_err(|_| AppError::Internal {
            category: "invitation_email_index",
        })?
    {
        let resolved = sqlx::query_as::<_, EmailJoinResolution>(
            r"
            SELECT organization_id, invitation_id, invitation_expires_at,
                   contact_id, contact_kind, contact_ciphertext,
                   contact_nonce, contact_encryption_key_version
            FROM iam_private.resolve_pending_email_join_invitation($1, $2, $3)
            ",
        )
        .bind(organization_handle)
        .bind(digest.key_version())
        .bind(digest.as_bytes().as_slice())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?;
        if resolved.is_some() {
            return Ok(resolved);
        }
    }
    Ok(None)
}

async fn resolve_target(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    input: &CarbonInviteCreate,
) -> Result<ResolvedTarget, AppError> {
    if let Some(carbon_id) = input.carbon_id.as_deref() {
        let principal_id = sqlx::query_scalar::<_, Id>(
            "SELECT principal_id FROM iam_private.resolve_active_carbon_by_handle($1)",
        )
        .bind(carbon_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::NotFound)?;
        let contact = primary_email(transaction, principal_id).await?;
        return Ok(ResolvedTarget {
            principal_id: Some(principal_id),
            contact: Some(contact),
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
                principal_id: Some(resolved.principal_id),
                contact: Some(ContactMaterial {
                    contact_id: resolved.contact_id,
                    contact_kind: "email".to_owned(),
                    ciphertext: resolved.contact_ciphertext,
                    nonce: resolved.contact_nonce,
                    encryption_key_version: resolved.contact_encryption_key_version,
                }),
            });
        }
    }
    Ok(ResolvedTarget {
        principal_id: None,
        contact: None,
    })
}

async fn insert_invitation_trust_overrides(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Id,
    invitation_id: Id,
    input: &CarbonInviteCreate,
) -> Result<(), AppError> {
    if !input.tag_trust_overrides.is_empty() {
        let rule_ids = input
            .tag_trust_overrides
            .iter()
            .map(|_| Id::now_v7())
            .collect::<Vec<_>>();
        let tag_ids = input
            .tag_trust_overrides
            .iter()
            .map(|override_value| override_value.tag_id)
            .collect::<Vec<_>>();
        let boundaries = input
            .tag_trust_overrides
            .iter()
            .map(|override_value| override_value.trust.boundary.as_str())
            .collect::<Vec<_>>();
        let levels = input
            .tag_trust_overrides
            .iter()
            .map(|override_value| override_value.trust.level.as_str())
            .collect::<Vec<_>>();
        sqlx::query(
            r"
            INSERT INTO iam.organization_invitation_tag_trust_overrides (
                id, organization_id, invitation_id, tag_id,
                trust_boundary, trust_level
            )
            SELECT
                candidate.id,
                $1,
                $2,
                candidate.tag_id,
                candidate.trust_boundary::iam.trust_boundary,
                candidate.trust_level::iam.trust_level
            FROM unnest($3::uuid[], $4::uuid[], $5::text[], $6::text[])
                AS candidate(id, tag_id, trust_boundary, trust_level)
            ",
        )
        .bind(organization_id)
        .bind(invitation_id)
        .bind(&rule_ids)
        .bind(&tag_ids)
        .bind(&boundaries)
        .bind(&levels)
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    }

    if !input.silicon_trust_overrides.is_empty() {
        let rule_ids = input
            .silicon_trust_overrides
            .iter()
            .map(|_| Id::now_v7())
            .collect::<Vec<_>>();
        let silicon_membership_ids = input
            .silicon_trust_overrides
            .iter()
            .map(|override_value| override_value.silicon_membership_id)
            .collect::<Vec<_>>();
        let boundaries = input
            .silicon_trust_overrides
            .iter()
            .map(|override_value| override_value.trust.boundary.as_str())
            .collect::<Vec<_>>();
        let levels = input
            .silicon_trust_overrides
            .iter()
            .map(|override_value| override_value.trust.level.as_str())
            .collect::<Vec<_>>();
        sqlx::query(
            r"
            INSERT INTO iam.organization_invitation_silicon_trust_overrides (
                id, organization_id, invitation_id, silicon_membership_id,
                trust_boundary, trust_level
            )
            SELECT
                candidate.id,
                $1,
                $2,
                candidate.silicon_membership_id,
                candidate.trust_boundary::iam.trust_boundary,
                candidate.trust_level::iam.trust_level
            FROM unnest($3::uuid[], $4::uuid[], $5::text[], $6::text[])
                AS candidate(id, silicon_membership_id, trust_boundary, trust_level)
            ",
        )
        .bind(organization_id)
        .bind(invitation_id)
        .bind(&rule_ids)
        .bind(&silicon_membership_ids)
        .bind(&boundaries)
        .bind(&levels)
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    }

    Ok(())
}

async fn enforce_invitation_code_send_limit(
    state: &ApiState,
    carbon_id: Id,
    organization_handle: &str,
) -> Result<(), AppError> {
    let policy = RateLimitPolicy::new(
        NonZeroU32::new(INVITATION_CODE_SEND_LIMIT).ok_or(AppError::Internal {
            category: "invitation_code_send_rate_limit_policy",
        })?,
        INVITATION_CODE_SEND_WINDOW,
        INVITATION_CODE_SEND_WINDOW,
    )
    .map_err(|_| AppError::Internal {
        category: "invitation_code_send_rate_limit_policy",
    })?;
    let scope = SecretString::from(invitation_code_send_scope(carbon_id, organization_handle));
    rate_limit::enforce_burst_cooldown(
        state.db(),
        &state.crypto,
        "organization_invitation_email_join_send",
        &scope,
        policy,
    )
    .await?;
    Ok(())
}

fn invitation_code_send_scope(carbon_id: Id, organization_handle: &str) -> String {
    format!("carbon={carbon_id}:organization={organization_handle}")
}

async fn primary_email(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Id,
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
    invite_id: Id,
) -> Result<(Transaction<'a, Postgres>, Id), AppError> {
    support::require_scoped_carbon(authenticated, "organizations.join")?;
    let mut transaction = context::begin(
        state.db(),
        DatabaseContext::principal(authenticated.0.subject.id),
    )
    .await
    .map_err(support::database)?;
    let organization_id = sqlx::query_scalar::<_, Option<Id>>(
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
    organization_id: Id,
    invite_id: Id,
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
    materialize_invitation(state, row)
}

fn materialize_invitations(
    state: &ApiState,
    rows: Vec<InvitationRow>,
) -> Result<Vec<InvitationResponse>, AppError> {
    rows.into_iter()
        .map(|row| materialize_invitation(state, row))
        .collect()
}

fn materialize_invitation(
    state: &ApiState,
    row: InvitationRow,
) -> Result<InvitationResponse, AppError> {
    let mut masked_delivery_address = match (
        row.destination_contact_id,
        row.destination_contact_kind,
        row.destination_contact_ciphertext,
        row.destination_contact_nonce,
        row.destination_contact_encryption_key_version,
    ) {
        (
            Some(contact_id),
            Some(contact_kind),
            Some(ciphertext),
            Some(nonce),
            Some(key_version),
        ) => {
            let contact = ContactMaterial {
                contact_id,
                contact_kind,
                ciphertext,
                nonce,
                encryption_key_version: key_version,
            };
            let email = decrypt_email(state, &contact)?;
            Some(mask_email(email.expose_secret()))
        }
        (None, None, None, None, None) => None,
        _ => {
            return Err(AppError::Internal {
                category: "invitation_destination_shape",
            });
        }
    };
    if let (Some(ciphertext), Some(nonce), Some(key_version)) =
        (row.email_ciphertext, row.email_nonce, row.email_key_version)
    {
        let plaintext = state
            .crypto
            .decrypt(
                EncryptionContext::global(ProtectedField::InvitationEmail, row.id),
                &EncryptedValue {
                    ciphertext,
                    nonce: nonce.try_into().map_err(|_| AppError::Internal {
                        category: "invitation_email_shape",
                    })?,
                    key_version,
                },
            )
            .map_err(|_| AppError::Internal {
                category: "invitation_email_decrypt",
            })?;
        let email = std::str::from_utf8(&plaintext).map_err(|_| AppError::Internal {
            category: "invitation_email_encoding",
        })?;
        masked_delivery_address = Some(mask_email(email));
    }
    let target_carbon = match (
        row.target_principal_id,
        row.target_carbon_id,
        row.target_display_name,
        row.target_created_at,
    ) {
        (Some(principal_id), Some(carbon_id), Some(display_name), Some(created_at)) => {
            Some(CarbonPublicResponse {
                principal_id,
                carbon_id,
                display_name,
                created_at,
                profile_photo: row.target_profile_photo,
            })
        }
        (None, None, None, None) => None,
        _ => {
            return Err(AppError::Internal {
                category: "invitation_target_shape",
            });
        }
    };
    Ok(InvitationResponse {
        id: row.id,
        org_id: row.org_id,
        target_carbon,
        masked_delivery_address,
        org_role: "member".to_owned(),
        job_role: row.job_role,
        tag_ids: row.tag_ids,
        first_silicon_membership_id: row.first_silicon_membership_id,
        extra_silicon_membership_ids: row.extra_silicon_membership_ids,
        default_trust: TrustValue {
            boundary: parse_boundary(&row.default_trust_boundary)?,
            level: parse_level(&row.default_trust_level)?,
        },
        tag_trust_overrides: row.tag_trust_overrides.0,
        silicon_trust_overrides: row.silicon_trust_overrides.0,
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
    invite_id: Id,
    carbon_id: Id,
) -> Result<ChallengeRow, AppError> {
    sqlx::query_as::<_, ChallengeRow>(INVITATION_CHALLENGE_LOCK_QUERY)
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
        && challenge.cooldown_retry_after_seconds == 0
        && challenge.failed_attempts < challenge.max_attempts
    {
        sqlx::query(
            r"
            UPDATE iam.invitation_verification_challenges
            SET failed_attempts = CASE
                    WHEN failed_attempts + 1 >= max_attempts THEN 0
                    ELSE failed_attempts + 1
                END,
                cooldown_until = CASE
                    WHEN failed_attempts + 1 >= max_attempts
                        THEN transaction_timestamp() + ($2::bigint * interval '1 second')
                    ELSE NULL
                END
            WHERE id = $1
              AND consumed_at IS NULL
              AND superseded_at IS NULL
              AND expires_at > transaction_timestamp()
              AND (cooldown_until IS NULL OR cooldown_until <= transaction_timestamp())
            ",
        )
        .bind(challenge.challenge_id)
        .bind(OTP_COOLDOWN_SECONDS)
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    }
    Ok(())
}

async fn validate_invitation_references(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Id,
    input: &CarbonInviteCreate,
) -> Result<(), AppError> {
    let mut tags = input.tag_ids.clone();
    tags.extend(
        input
            .tag_trust_overrides
            .iter()
            .map(|override_value| override_value.tag_id),
    );
    tags.sort_unstable();
    tags.dedup();
    let tag_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM iam.organization_tags WHERE organization_id = $1 AND id = ANY($2) AND status = 'active'",
    )
    .bind(organization_id)
    .bind(&tags)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if usize::try_from(tag_count).ok() != Some(tags.len()) {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("invitation_default_inactive"),
        });
    }
    let mut silicons = input.extra_silicon_membership_ids.clone();
    if let Some(first) = input.first_silicon_membership_id {
        silicons.push(first);
    }
    silicons.extend(
        input
            .silicon_trust_overrides
            .iter()
            .map(|override_value| override_value.silicon_membership_id),
    );
    silicons.sort_unstable();
    silicons.dedup();
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
            *carbon_id = CarbonId::existing(carbon_id)
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
    unique_override_targets(
        "tag_trust_overrides",
        &mut input.tag_trust_overrides,
        100,
        |override_value| override_value.tag_id,
    )?;
    unique_override_targets(
        "silicon_trust_overrides",
        &mut input.silicon_trust_overrides,
        500,
        |override_value| override_value.silicon_membership_id,
    )?;
    if let Some(app_id) = input.redirect_app_id.as_mut() {
        *app_id = app_id
            .parse::<ApplicationId>()
            .map_err(|_| validation::field("redirect_app_id", "has an invalid format"))?
            .to_string();
    }
    Ok(())
}

fn validate_invitation_email(email: &str) -> Result<String, AppError> {
    if email != email.trim() || email.len() > 320 || parse_email(email).is_err() {
        return Err(validation::field("email", "must be a valid email address"));
    }
    Ok(crate::domain::auth::normalize_email(email))
}

fn unique_ids(name: &'static str, values: &mut [Id], maximum: usize) -> Result<(), AppError> {
    values.sort_unstable();
    if values.len() > maximum || values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(validation::field(
            name,
            "must contain unique values within the item limit",
        ));
    }
    Ok(())
}

fn unique_override_targets<T>(
    name: &'static str,
    values: &mut [T],
    maximum: usize,
    target_id: impl Copy + Fn(&T) -> Id,
) -> Result<(), AppError> {
    values.sort_unstable_by_key(target_id);
    if values.len() > maximum
        || values
            .windows(2)
            .any(|pair| target_id(&pair[0]) == target_id(&pair[1]))
    {
        return Err(validation::field(
            name,
            "must contain unique targets within the item limit",
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
           target.display_name AS target_display_name,
           COALESCE(target.profile_photo_uri, '') AS target_profile_photo,
           target.created_at AS target_created_at,
           invitation.email_ciphertext, invitation.email_nonce, invitation.email_key_version,
           destination_contact.contact_id AS destination_contact_id,
           destination_contact.contact_kind::text AS destination_contact_kind,
           destination_contact.contact_ciphertext AS destination_contact_ciphertext,
           destination_contact.contact_nonce AS destination_contact_nonce,
           destination_contact.contact_encryption_key_version AS destination_contact_encryption_key_version,
           invitation.job_role,
           ARRAY(SELECT x.tag_id FROM iam.organization_invitation_tags x WHERE x.organization_id = invitation.organization_id AND x.invitation_id = invitation.id ORDER BY x.tag_id) AS tag_ids,
           invitation.first_silicon_membership_id,
           ARRAY(SELECT x.silicon_membership_id FROM iam.organization_invitation_extra_silicons x WHERE x.organization_id = invitation.organization_id AND x.invitation_id = invitation.id ORDER BY x.silicon_membership_id) AS extra_silicon_membership_ids,
           invitation.default_trust_boundary::text AS default_trust_boundary,
           invitation.default_trust_level::text AS default_trust_level,
           COALESCE((
               SELECT jsonb_agg(
                   jsonb_build_object(
                       'tag_id', trust_override.tag_id,
                       'trust', jsonb_build_object(
                           'boundary', trust_override.trust_boundary::text,
                           'level', trust_override.trust_level::text
                       )
                   )
                   ORDER BY trust_override.tag_id
               )
               FROM iam.organization_invitation_tag_trust_overrides AS trust_override
               WHERE trust_override.organization_id = invitation.organization_id
                 AND trust_override.invitation_id = invitation.id
           ), '[]'::jsonb) AS tag_trust_overrides,
           COALESCE((
               SELECT jsonb_agg(
                   jsonb_build_object(
                       'silicon_membership_id', trust_override.silicon_membership_id,
                       'trust', jsonb_build_object(
                           'boundary', trust_override.trust_boundary::text,
                           'level', trust_override.trust_level::text
                       )
                   )
                   ORDER BY trust_override.silicon_membership_id
               )
               FROM iam.organization_invitation_silicon_trust_overrides AS trust_override
               WHERE trust_override.organization_id = invitation.organization_id
                 AND trust_override.invitation_id = invitation.id
           ), '[]'::jsonb) AS silicon_trust_overrides,
           inviter_membership.principal_id AS inviter_principal_id,
           inviter_membership.principal_kind::text AS inviter_type,
           CASE WHEN inviter_membership.principal_kind = 'carbon' THEN inviter_carbon.carbon_id ELSE inviter_silicon.global_silicon_id END AS inviter_public_id,
           CASE WHEN invitation.status = 'pending' AND invitation.expires_at <= transaction_timestamp() THEN 'expired' ELSE invitation.status END AS status,
           invitation.expires_at, invitation.version, invitation.created_at, invitation.accepted_at
    FROM iam.organization_invitations invitation
    JOIN iam.organizations organization ON organization.id = invitation.organization_id
    LEFT JOIN iam.carbons target ON target.id = invitation.target_carbon_id
    LEFT JOIN LATERAL iam_private.get_organization_invitation_destination(
        invitation.organization_id,
        invitation.id
    )
      AS destination_contact
      ON true
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
           target.display_name AS target_display_name,
           COALESCE(target.profile_photo_uri, '') AS target_profile_photo,
           target.created_at AS target_created_at,
           invitation.email_ciphertext, invitation.email_nonce, invitation.email_key_version,
           destination_contact.contact_id AS destination_contact_id,
           destination_contact.contact_kind::text AS destination_contact_kind,
           destination_contact.contact_ciphertext AS destination_contact_ciphertext,
           destination_contact.contact_nonce AS destination_contact_nonce,
           destination_contact.contact_encryption_key_version AS destination_contact_encryption_key_version,
           invitation.job_role,
           ARRAY(SELECT x.tag_id FROM iam.organization_invitation_tags x WHERE x.organization_id = invitation.organization_id AND x.invitation_id = invitation.id ORDER BY x.tag_id) AS tag_ids,
           invitation.first_silicon_membership_id,
           ARRAY(SELECT x.silicon_membership_id FROM iam.organization_invitation_extra_silicons x WHERE x.organization_id = invitation.organization_id AND x.invitation_id = invitation.id ORDER BY x.silicon_membership_id) AS extra_silicon_membership_ids,
           invitation.default_trust_boundary::text AS default_trust_boundary,
           invitation.default_trust_level::text AS default_trust_level,
           COALESCE((
               SELECT jsonb_agg(
                   jsonb_build_object(
                       'tag_id', trust_override.tag_id,
                       'trust', jsonb_build_object(
                           'boundary', trust_override.trust_boundary::text,
                           'level', trust_override.trust_level::text
                       )
                   )
                   ORDER BY trust_override.tag_id
               )
               FROM iam.organization_invitation_tag_trust_overrides AS trust_override
               WHERE trust_override.organization_id = invitation.organization_id
                 AND trust_override.invitation_id = invitation.id
           ), '[]'::jsonb) AS tag_trust_overrides,
           COALESCE((
               SELECT jsonb_agg(
                   jsonb_build_object(
                       'silicon_membership_id', trust_override.silicon_membership_id,
                       'trust', jsonb_build_object(
                           'boundary', trust_override.trust_boundary::text,
                           'level', trust_override.trust_level::text
                       )
                   )
                   ORDER BY trust_override.silicon_membership_id
               )
               FROM iam.organization_invitation_silicon_trust_overrides AS trust_override
               WHERE trust_override.organization_id = invitation.organization_id
                 AND trust_override.invitation_id = invitation.id
           ), '[]'::jsonb) AS silicon_trust_overrides,
           inviter_membership.principal_id AS inviter_principal_id,
           inviter_membership.principal_kind::text AS inviter_type,
           CASE WHEN inviter_membership.principal_kind = 'carbon' THEN inviter_carbon.carbon_id ELSE inviter_silicon.global_silicon_id END AS inviter_public_id,
           CASE WHEN invitation.status = 'pending' AND invitation.expires_at <= transaction_timestamp() THEN 'expired' ELSE invitation.status END AS status,
           invitation.expires_at, invitation.version, invitation.created_at, invitation.accepted_at
    FROM iam.organization_invitations invitation
    LEFT JOIN iam.carbons target ON target.id = invitation.target_carbon_id
    LEFT JOIN LATERAL iam_private.get_organization_invitation_destination(
        invitation.organization_id,
        invitation.id
    )
      AS destination_contact
      ON true
    JOIN iam.organization_memberships inviter_membership ON inviter_membership.organization_id = invitation.organization_id AND inviter_membership.id = invitation.invited_by_membership_id
    LEFT JOIN iam.carbons inviter_carbon ON inviter_carbon.id = inviter_membership.principal_id AND inviter_membership.principal_kind = 'carbon'
    LEFT JOIN iam.silicons inviter_silicon ON inviter_silicon.id = inviter_membership.principal_id AND inviter_membership.principal_kind = 'silicon'
    WHERE invitation.organization_id = $1 AND invitation.id = $2 LIMIT 1
";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::ports::DeliveryReceipt;

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

    #[test]
    fn invitation_override_targets_must_be_unique() {
        let tag_id = Id::now_v7();
        let mut overrides = vec![
            InvitationTagTrustOverride {
                tag_id,
                trust: TrustValue {
                    boundary: super::super::model::TrustBoundary::Internal,
                    level: super::super::model::TrustLevel::Trusted,
                },
            },
            InvitationTagTrustOverride {
                tag_id,
                trust: TrustValue {
                    boundary: super::super::model::TrustBoundary::External,
                    level: super::super::model::TrustLevel::NeedsApproval,
                },
            },
        ];

        assert!(
            unique_override_targets("tag_trust_overrides", &mut overrides, 100, |value| value
                .tag_id)
            .is_err()
        );
    }

    #[test]
    fn invitation_code_send_scope_is_stable_and_tenant_qualified() {
        let carbon_id = Id::fixture("c:invitee");

        let scope = invitation_code_send_scope(carbon_id, "acme");

        assert_eq!(scope, invitation_code_send_scope(carbon_id, "acme"));
        assert_ne!(
            scope,
            invitation_code_send_scope(Id::fixture("c:other-invitee"), "acme")
        );
        assert_ne!(scope, invitation_code_send_scope(carbon_id, "other-org"));
    }

    #[test]
    fn invitation_join_email_is_validated_and_canonicalized() {
        let Ok(email) = validate_invitation_email("Invitee@Example.COM") else {
            panic!("a valid invitation email must be accepted");
        };
        assert_eq!(email, "invitee@example.com");
        assert!(validate_invitation_email(" invitee@example.com").is_err());
        assert!(validate_invitation_email("not-an-email").is_err());
    }

    #[test]
    fn invitation_redirects_use_bare_application_ids() {
        assert_eq!(
            "Billing_App"
                .parse::<ApplicationId>()
                .map(|app_id| app_id.to_string()),
            Ok("billing_app".to_owned())
        );
        assert!("team>billing_app".parse::<ApplicationId>().is_err());
        assert!("team>1billing".parse::<ApplicationId>().is_err());
    }

    #[test]
    fn invitation_otp_delivery_requires_an_unambiguous_provider_success() {
        assert_eq!(
            classify_invitation_otp_delivery(Ok(Ok(DeliveryReceipt {
                provider_message_id: "provider-message-id".to_owned(),
            }))),
            Ok(())
        );
        assert_eq!(
            classify_invitation_otp_delivery(Ok(Err(DeliveryError::Rejected))),
            Err(InvitationOtpDeliveryError::Definitive)
        );
        assert_eq!(
            classify_invitation_otp_delivery(Ok(Err(DeliveryError::Unavailable))),
            Err(InvitationOtpDeliveryError::OutcomeUnknown)
        );
    }

    #[test]
    fn invitation_join_locks_delivery_state_with_the_challenge() {
        // The lock now lives in `iam_private.lock_invitation_verification_challenge`,
        // because an invitee holds no organization context and so could not
        // lock the invitation row row security lets them read.
        assert!(
            INVITATION_CHALLENGE_LOCK_QUERY
                .contains("iam_private.lock_invitation_verification_challenge")
        );
    }

    #[test]
    fn invitation_delivery_migration_fails_legacy_and_future_challenges_closed() {
        let migration = include_str!("../../../migrations/0036_invitation_otp_delivery_state.sql");

        assert!(migration.contains("ALTER COLUMN delivery_status SET DEFAULT 'pending'"));
        assert!(migration.contains("consumed_at IS NULL OR delivery_status = 'delivered'"));
        assert!(migration.contains("DELETE FROM iam.idempotency_records"));
        assert!(migration.contains(
            "WHEN consumed_at IS NULL THEN COALESCE(superseded_at, transaction_timestamp())"
        ));
    }

    #[tokio::test]
    #[ignore = "requires isolated PostgreSQL via IAM_TEST_DATABASE_ADMIN_URL or Docker"]
    async fn live_pending_invitation_otp_cannot_be_consumed() -> anyhow::Result<()> {
        use anyhow::ensure;

        let database = crate::test_database::TestDatabase::start().await?;
        let pool = database.pool.clone();
        crate::infrastructure::postgres::migrate(&pool).await?;

        let challenge_id = Id::from_u128(0x36_01);
        let mut transaction = pool.begin().await?;
        // Foreign keys are irrelevant to this focused constraint test. Check
        // constraints remain active while replication-trigger FKs are skipped.
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            r"
            INSERT INTO iam.invitation_verification_challenges (
                id, organization_id, invitation_id, target_carbon_id,
                destination_contact_id, code_digest, digest_key_version,
                failed_attempts, max_attempts, expires_at,
                delivery_status, delivered_at, delivery_failed_at
            ) VALUES (
                $1, $2, $3, $4, $5, decode(repeat('36', 32), 'hex'), 1,
                0, 10, transaction_timestamp() + interval '10 minutes',
                'pending', NULL, NULL
            )
            ",
        )
        .bind(challenge_id)
        .bind(Id::from_u128(0x36_02))
        .bind(Id::from_u128(0x36_03))
        .bind(Id::fixture("c:recipient"))
        .bind(Id::from_u128(0x36_05))
        .execute(&mut *transaction)
        .await?;

        let result = sqlx::query(
            "UPDATE iam.invitation_verification_challenges SET consumed_at = transaction_timestamp() WHERE id = $1",
        )
        .bind(challenge_id)
        .execute(&mut *transaction)
        .await;
        let Err(error) = result else {
            anyhow::bail!("a pending invitation OTP was consumable");
        };
        let sqlx::Error::Database(database_error) = error else {
            anyhow::bail!("pending consumption returned a non-database error");
        };
        ensure!(
            database_error.code().as_deref() == Some("23514"),
            "pending consumption must violate a check constraint"
        );
        Ok(())
    }

    /// An invitee locks their own invitation, as the restricted API role.
    ///
    /// Accepting an invitation always answered 404. Submitting the code locks
    /// the invitation and its challenge, PostgreSQL applies a table's UPDATE
    /// policies to a locking read, and the only policy governing UPDATE on
    /// `iam.organization_invitations` requires an organization context the
    /// invitee does not have — they are not a member yet, which is what
    /// holding an invitation means. The row row security explicitly lets the
    /// target read could therefore never be locked.
    ///
    /// Every other Docker-backed test connects as the schema owner, where row
    /// security does not apply and the fault is invisible.
    #[tokio::test]
    #[ignore = "requires isolated PostgreSQL via IAM_TEST_DATABASE_ADMIN_URL or Docker"]
    #[allow(
        clippy::too_many_lines,
        reason = "one fixture spans the organization, the inviter, the invitee and the challenge"
    )]
    async fn an_invitee_can_lock_their_own_invitation() -> anyhow::Result<()> {
        use anyhow::ensure;

        const RUNTIME_ROLES: &str = "
            DO $$ DECLARE role_name text; BEGIN
                FOREACH role_name IN ARRAY ARRAY['silicon_iam_api','silicon_iam_worker','silicon_iam_key_operator','silicon_iam_api_runtime'] LOOP
                    IF to_regrole(role_name) IS NULL THEN
                        EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS',role_name);
                    END IF;
                END LOOP;
            END $$;
            GRANT silicon_iam_api TO silicon_iam_api_runtime;
        ";
        let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
            .lines()
            .filter(|line| !line.trim_start().starts_with('\\'))
            .collect::<Vec<_>>()
            .join("\n");

        let database = crate::test_database::TestDatabase::start().await?;
        let pool = database.pool.clone();
        crate::infrastructure::postgres::migrate(&pool).await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(RUNTIME_ROLES))
            .execute(&pool)
            .await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
            .execute(&pool)
            .await?;

        let admin = Id::fixture("c:admin");
        let recipient = Id::fixture("c:recipient");
        let organization = Id::from_u128(0x52_03);
        let admin_membership = Id::from_u128(0x52_04);
        let invitation = Id::from_u128(0x52_05);
        let challenge = Id::from_u128(0x52_06);
        let invitee_email_contact = Id::from_u128(0x52_07);

        let mut fixture = pool.begin().await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(
            "INSERT INTO iam.cryptographic_key_versions (purpose, key_version)
             VALUES ('contact_aead', 1), ('token_hmac', 1)",
        ))
        .execute(&mut *fixture)
        .await?;

        for (principal, handle, email_contact, phone_contact) in [
            (
                admin,
                "admin",
                Id::from_u128(0x52_11),
                Id::from_u128(0x52_12),
            ),
            (
                recipient,
                "recipient",
                invitee_email_contact,
                Id::from_u128(0x52_13),
            ),
        ] {
            sqlx::query(
                r"
                INSERT INTO iam.principals (id, kind, status, activated_at)
                VALUES ($1, 'carbon', 'active', transaction_timestamp())
                ",
            )
            .bind(principal)
            .execute(&mut *fixture)
            .await?;
            sqlx::query(
                "INSERT INTO iam.carbons (id, carbon_id, display_name) VALUES ($1, $1, $2)",
            )
            .bind(principal)
            .bind(handle)
            .execute(&mut *fixture)
            .await?;
            sqlx::query(
                r"
                INSERT INTO iam.carbon_contacts (
                    id, carbon_id, kind, ciphertext, nonce, encryption_key_version, verified_at
                ) VALUES
                    ($1, $3, 'email', decode(repeat('11', 17), 'hex'),
                        decode(repeat('12', 12), 'hex'), 1, transaction_timestamp()),
                    ($2, $3, 'phone', decode(repeat('21', 17), 'hex'),
                        decode(repeat('22', 12), 'hex'), 1, transaction_timestamp())
                ",
            )
            .bind(email_contact)
            .bind(phone_contact)
            .bind(principal)
            .execute(&mut *fixture)
            .await?;
        }

        sqlx::query(
            r"
            INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name)
            VALUES ($1, 'tos', $2, 'Team of Silicons')
            ",
        )
        .bind(organization)
        .bind(admin)
        .execute(&mut *fixture)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.organization_memberships (
                id, organization_id, principal_id, principal_kind, org_role
            ) VALUES ($1, $2, $3, 'carbon', 'owner')
            ",
        )
        .bind(admin_membership)
        .bind(organization)
        .bind(admin)
        .execute(&mut *fixture)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.organization_invitations (
                id, organization_id, target_carbon_id, invited_by_membership_id,
                destination_contact_id, job_role, default_trust_boundary,
                default_trust_level, expires_at
            ) VALUES (
                $1, $2, $3, $4, $5, 'Engineer', 'internal', 'not_trusted',
                transaction_timestamp() + interval '7 days'
            )
            ",
        )
        .bind(invitation)
        .bind(organization)
        .bind(recipient)
        .bind(admin_membership)
        .bind(invitee_email_contact)
        .execute(&mut *fixture)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.invitation_verification_challenges (
                id, organization_id, invitation_id, target_carbon_id,
                destination_contact_id, code_digest, digest_key_version,
                max_attempts, expires_at, delivery_status, delivered_at
            ) VALUES (
                $1, $2, $3, $4, $5, decode(repeat('33', 32), 'hex'), 1,
                10, transaction_timestamp() + interval '10 minutes',
                'delivered', transaction_timestamp()
            )
            ",
        )
        .bind(challenge)
        .bind(organization)
        .bind(invitation)
        .bind(recipient)
        .bind(invitee_email_contact)
        .execute(&mut *fixture)
        .await?;
        fixture.commit().await?;

        // Exactly the recipient's context: their principal is known, and they
        // belong to no organization.
        let mut accepting = pool.begin().await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(
            "SET LOCAL ROLE silicon_iam_api_runtime",
        ))
        .execute(&mut *accepting)
        .await?;
        sqlx::query("SELECT set_config('iam.principal_id', $1::text, true)")
            .bind(recipient)
            .execute(&mut *accepting)
            .await?;

        let row = super::fetch_challenge(&mut accepting, invitation, recipient)
            .await
            .map_err(|_| anyhow::anyhow!("the recipient could not lock their own invitation"))?;

        ensure!(row.challenge_id == challenge, "locked the wrong challenge");
        ensure!(row.invitation_status == "pending", "unexpected status");
        ensure!(row.max_attempts == 10, "unexpected attempt ceiling");

        // Somebody else's invitation must still be refused.
        ensure!(
            super::fetch_challenge(&mut accepting, invitation, admin)
                .await
                .is_err(),
            "an invitation addressed to another Carbon must not resolve"
        );

        Ok(())
    }
    #[tokio::test]
    #[ignore = "requires isolated PostgreSQL via IAM_TEST_DATABASE_ADMIN_URL or Docker"]
    #[allow(
        clippy::too_many_lines,
        reason = "full invitation, registration, worker and restricted-role acceptance lifecycle"
    )]
    async fn an_email_invitation_can_precede_signup_and_be_accepted() -> anyhow::Result<()> {
        use anyhow::ensure;

        const RUNTIME_ROLES: &str = "
            DO $$ DECLARE role_name text; BEGIN
                FOREACH role_name IN ARRAY ARRAY['silicon_iam_api','silicon_iam_worker','silicon_iam_key_operator','silicon_iam_api_runtime'] LOOP
                    IF to_regrole(role_name) IS NULL THEN
                        EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS',role_name);
                    END IF;
                END LOOP;
            END $$;
            GRANT silicon_iam_api TO silicon_iam_api_runtime;
        ";
        let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
            .lines()
            .filter(|line| !line.trim_start().starts_with('\\'))
            .collect::<Vec<_>>()
            .join("\n");

        let database = crate::test_database::TestDatabase::start().await?;
        let pool = database.pool.clone();
        crate::infrastructure::postgres::migrate(&pool).await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(RUNTIME_ROLES))
            .execute(&pool)
            .await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
            .execute(&pool)
            .await?;

        let admin = Id::fixture("c:admin");
        let recipient = Id::fixture("c:recipient");
        let organization = Id::from_u128(0x52_03);
        let admin_membership = Id::from_u128(0x52_04);
        let invitation = Id::from_u128(0x52_05);
        let challenge = Id::from_u128(0x52_06);
        let invitee_email_contact = Id::from_u128(0x52_07);

        let mut fixture = pool.begin().await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(
            "INSERT INTO iam.cryptographic_key_versions (purpose, key_version)
             VALUES ('contact_aead', 1), ('token_hmac', 1), ('contact_lookup_hmac', 1)",
        ))
        .execute(&mut *fixture)
        .await?;

        for (principal, handle, email_contact, phone_contact) in [
            (
                admin,
                "admin",
                Id::from_u128(0x52_11),
                Id::from_u128(0x52_12),
            ),
            (
                recipient,
                "recipient",
                invitee_email_contact,
                Id::from_u128(0x52_13),
            ),
        ]
        .into_iter()
        .take(1)
        {
            sqlx::query(
                r"
                INSERT INTO iam.principals (id, kind, status, activated_at)
                VALUES ($1, 'carbon', 'active', transaction_timestamp())
                ",
            )
            .bind(principal)
            .execute(&mut *fixture)
            .await?;
            sqlx::query(
                "INSERT INTO iam.carbons (id, carbon_id, display_name) VALUES ($1, $1, $2)",
            )
            .bind(principal)
            .bind(handle)
            .execute(&mut *fixture)
            .await?;
            sqlx::query(
                r"
                INSERT INTO iam.carbon_contacts (
                    id, carbon_id, kind, ciphertext, nonce, encryption_key_version, verified_at
                ) VALUES
                    ($1, $3, 'email', decode(repeat('11', 17), 'hex'),
                        decode(repeat('12', 12), 'hex'), 1, transaction_timestamp()),
                    ($2, $3, 'phone', decode(repeat('21', 17), 'hex'),
                        decode(repeat('22', 12), 'hex'), 1, transaction_timestamp())
                ",
            )
            .bind(email_contact)
            .bind(phone_contact)
            .bind(principal)
            .execute(&mut *fixture)
            .await?;
        }

        sqlx::query(
            r"
            INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name)
            VALUES ($1, 'tos', $2, 'Team of Silicons')
            ",
        )
        .bind(organization)
        .bind(admin)
        .execute(&mut *fixture)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.organization_memberships (
                id, organization_id, principal_id, principal_kind, org_role
            ) VALUES ($1, $2, $3, 'carbon', 'owner')
            ",
        )
        .bind(admin_membership)
        .bind(organization)
        .bind(admin)
        .execute(&mut *fixture)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.organization_invitations (
                id, organization_id, target_carbon_id, invited_by_membership_id,
                destination_contact_id, job_role, default_trust_boundary,
                default_trust_level, expires_at, email_ciphertext, email_nonce, email_key_version, email_blind_indexes
            ) VALUES (
                $1, $2, NULL, $3, NULL, 'Engineer', 'internal', 'not_trusted',
                transaction_timestamp() + interval '48 hours',
                decode(repeat('11',17),'hex'), decode(repeat('12',12),'hex'), 1,
                ARRAY['1:' || repeat('44',32)]
            )
            ",
        ).bind(invitation).bind(organization).bind(admin_membership)
        .execute(&mut *fixture).await?;
        fixture.commit().await?;

        // Read and deliver the invitation before the recipient account exists.
        let mut managing = pool.begin().await?;
        sqlx::query("SET LOCAL ROLE silicon_iam_api_runtime")
            .execute(&mut *managing)
            .await?;
        sqlx::query("SELECT set_config('iam.principal_id', $1::text, true), set_config('iam.organization_id', $2::text, true)")
            .bind(admin).bind(organization).execute(&mut *managing).await?;
        let pending = sqlx::query_as::<_, InvitationRow>(INVITATION_BY_ID_SQL)
            .bind(organization)
            .bind(invitation)
            .bind("tos")
            .fetch_one(&mut *managing)
            .await?;
        ensure!(pending.target_principal_id.is_none());
        ensure!(pending.email_ciphertext.is_some());
        let unresolved = sqlx::query("SELECT * FROM iam_private.resolve_pending_email_join_invitation('tos', 1::smallint, decode(repeat('44',32),'hex'))")
            .fetch_optional(&mut *managing).await?;
        ensure!(
            unresolved.is_none(),
            "an inviter must not claim the recipient's email"
        );
        let job = Id::now_v7();
        sqlx::query("INSERT INTO iam.notification_jobs (id, notification_kind, provider, recipient_contact_kind, template_id, context_type, context_id, status, lease_owner, lease_expires_at) VALUES ($1, 'invitation', 'postmark', 'email', 'invitation.created', 'organization_invitation', $2, 'processing', 'email-test', transaction_timestamp() + interval '1 minute')")
            .bind(job).bind(invitation).execute(&mut *managing).await?;
        managing.commit().await?;
        let mut delivery = pool.begin().await?;
        sqlx::query("SET LOCAL ROLE silicon_iam_worker")
            .execute(&mut *delivery)
            .await?;
        let delivered =
            sqlx::query("SELECT * FROM iam_private.get_worker_email_invitation($1, 'email-test')")
                .bind(job)
                .fetch_optional(&mut *delivery)
                .await?;
        ensure!(
            delivered.is_some(),
            "worker must resolve an unregistered recipient"
        );
        let unleased = sqlx::query(
            "SELECT * FROM iam_private.get_worker_email_invitation($1, 'other-worker')",
        )
        .bind(job)
        .fetch_optional(&mut *delivery)
        .await?;
        ensure!(unleased.is_none(), "worker must own the notification lease");
        delivery.rollback().await?;

        // Registration occurs only after the invitation has been stored/delivered.
        let mut fixture = pool.begin().await?;
        for (principal, handle, email_contact, phone_contact) in [
            (
                admin,
                "admin",
                Id::from_u128(0x52_11),
                Id::from_u128(0x52_12),
            ),
            (
                recipient,
                "recipient",
                invitee_email_contact,
                Id::from_u128(0x52_13),
            ),
        ]
        .into_iter()
        .skip(1)
        {
            sqlx::query(
                r"
                INSERT INTO iam.principals (id, kind, status, activated_at)
                VALUES ($1, 'carbon', 'active', transaction_timestamp())
                ",
            )
            .bind(principal)
            .execute(&mut *fixture)
            .await?;
            sqlx::query(
                "INSERT INTO iam.carbons (id, carbon_id, display_name) VALUES ($1, $1, $2)",
            )
            .bind(principal)
            .bind(handle)
            .execute(&mut *fixture)
            .await?;
            sqlx::query(
                r"
                INSERT INTO iam.carbon_contacts (
                    id, carbon_id, kind, ciphertext, nonce, encryption_key_version, verified_at
                ) VALUES
                    ($1, $3, 'email', decode(repeat('11', 17), 'hex'),
                        decode(repeat('12', 12), 'hex'), 1, transaction_timestamp()),
                    ($2, $3, 'phone', decode(repeat('21', 17), 'hex'),
                        decode(repeat('22', 12), 'hex'), 1, transaction_timestamp())
                ",
            )
            .bind(email_contact)
            .bind(phone_contact)
            .bind(principal)
            .execute(&mut *fixture)
            .await?;
        }

        sqlx::query("INSERT INTO iam.contact_blind_indexes (contact_id, contact_kind, hmac_key_version, digest) VALUES ($1, 'email', 1, decode(repeat('44',32),'hex'))")
            .bind(invitee_email_contact).execute(&mut *fixture).await?;
        fixture.commit().await?;
        let mut binding = pool.begin().await?;
        sqlx::query("SET LOCAL ROLE silicon_iam_api_runtime")
            .execute(&mut *binding)
            .await?;
        sqlx::query("SELECT set_config('iam.principal_id', $1::text, true)")
            .bind(recipient)
            .execute(&mut *binding)
            .await?;
        for (org, digest) in [("tos", vec![0x55_u8; 32]), ("other", vec![0x44_u8; 32])] {
            let wrong = sqlx::query("SELECT * FROM iam_private.resolve_pending_email_join_invitation($1, 1::smallint, $2)")
                .bind(org).bind(digest).fetch_optional(&mut *binding).await?;
            ensure!(
                wrong.is_none(),
                "wrong email or organization must not resolve"
            );
        }
        let bound = sqlx::query_as::<_, EmailJoinResolution>("SELECT * FROM iam_private.resolve_pending_email_join_invitation('tos', 1::smallint, decode(repeat('44',32),'hex'))")
            .fetch_one(&mut *binding).await?;
        ensure!(bound.invitation_id == invitation && bound.contact_id == invitee_email_contact);
        binding.commit().await?;
        let mut fixture = pool.begin().await?;
        sqlx::query(
            r"
            INSERT INTO iam.invitation_verification_challenges (
                id, organization_id, invitation_id, target_carbon_id,
                destination_contact_id, code_digest, digest_key_version,
                max_attempts, expires_at, delivery_status, delivered_at
            ) VALUES (
                $1, $2, $3, $4, $5, decode(repeat('33', 32), 'hex'), 1,
                10, transaction_timestamp() + interval '10 minutes',
                'delivered', transaction_timestamp()
            )
            ",
        )
        .bind(challenge)
        .bind(organization)
        .bind(invitation)
        .bind(recipient)
        .bind(invitee_email_contact)
        .execute(&mut *fixture)
        .await?;
        fixture.commit().await?;

        // Exactly the recipient's context: their principal is known, and they
        // belong to no organization.
        let mut accepting = pool.begin().await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(
            "SET LOCAL ROLE silicon_iam_api_runtime",
        ))
        .execute(&mut *accepting)
        .await?;
        sqlx::query("SELECT set_config('iam.principal_id', $1::text, true)")
            .bind(recipient)
            .execute(&mut *accepting)
            .await?;

        let row = super::fetch_challenge(&mut accepting, invitation, recipient)
            .await
            .map_err(|_| anyhow::anyhow!("the recipient could not lock their own invitation"))?;

        ensure!(row.challenge_id == challenge, "locked the wrong challenge");
        ensure!(row.invitation_status == "pending", "unexpected status");
        ensure!(row.max_attempts == 10, "unexpected attempt ceiling");

        // Somebody else's invitation must still be refused.
        ensure!(
            super::fetch_challenge(&mut accepting, invitation, admin)
                .await
                .is_err(),
            "an invitation addressed to another Carbon must not resolve"
        );

        accepting.rollback().await?;
        let mut joining = pool.begin().await?;
        sqlx::query("SET LOCAL ROLE silicon_iam_api_runtime")
            .execute(&mut *joining)
            .await?;
        sqlx::query("SELECT set_config('iam.principal_id', $1::text, true), set_config('iam.organization_id', $2::text, true)")
            .bind(recipient).bind(organization).execute(&mut *joining).await?;
        let joined = sqlx::query_as::<_, CompletedInvitation>("SELECT * FROM iam_private.complete_verified_organization_invitation('tos', $1, $2, 1::smallint, decode(repeat('33',32),'hex'))")
            .bind(invitation).bind(Id::now_v7()).fetch_one(&mut *joining).await?;
        ensure!(joined.organization_id == organization);
        joining.commit().await?;
        let state = sqlx::query_scalar::<_, String>(
            "SELECT status FROM iam.organization_invitations WHERE id=$1",
        )
        .bind(invitation)
        .fetch_one(&pool)
        .await?;
        ensure!(state == "accepted");
        Ok(())
    }
}
