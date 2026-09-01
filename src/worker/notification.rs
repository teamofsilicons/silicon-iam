//! Durable invitation and secret-free security notification delivery.

use futures::{StreamExt as _, stream};
use secrecy::SecretString;
use uuid::Uuid;

use crate::{
    application::ports::{
        DeliveryError, DeliveryReceipt, InvitationEmail, InvitationSms, SecurityNotice,
    },
    error::AppError,
    infrastructure::crypto::{EncryptedValue, EncryptionContext, ProtectedField},
};

use super::{WorkerContext, delivery_claim_limit, retry_delay_seconds};

#[derive(sqlx::FromRow)]
struct ClaimedNotification {
    id: Uuid,
    notification_kind: String,
    provider: String,
    recipient_contact_id: Uuid,
    recipient_contact_kind: String,
    template_id: String,
    context_type: String,
    context_id: Uuid,
    attempt_count: i32,
}

#[derive(sqlx::FromRow)]
struct ContactMaterial {
    carbon_id: Uuid,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    encryption_key_version: i16,
}

#[derive(sqlx::FromRow)]
struct InvitationContext {
    organization_name: String,
}

pub(super) async fn process_batch(context: &WorkerContext) -> Result<(), AppError> {
    let _outbound_stage = context.outbound_stage_lock.lock().await;
    let claim_limit = delivery_claim_limit(context)?;
    let lease_seconds =
        i64::try_from(context.settings.worker.lease_duration.as_secs()).map_err(|_| {
            AppError::Internal {
                category: "worker_lease_duration",
            }
        })?;
    let jobs = sqlx::query_as::<_, ClaimedNotification>(
        r"
        WITH candidates AS (
            SELECT notification.id
            FROM iam.notification_jobs AS notification
            WHERE (
                    notification.status = 'pending'
                    AND notification.available_at <= transaction_timestamp()
                ) OR (
                    notification.status = 'processing'
                    AND notification.lease_expires_at <= transaction_timestamp()
                )
            ORDER BY notification.available_at, notification.created_at, notification.id
            FOR UPDATE SKIP LOCKED
            LIMIT $1
        )
        UPDATE iam.notification_jobs AS notification
        SET status = 'processing',
            lease_owner = $2,
            lease_expires_at = transaction_timestamp()
                + ($3::bigint * interval '1 second'),
            attempt_count = notification.attempt_count + 1,
            last_error_code = NULL
        FROM candidates
        WHERE notification.id = candidates.id
        RETURNING
            notification.id,
            notification.notification_kind,
            notification.provider,
            notification.recipient_contact_id,
            notification.recipient_contact_kind::text AS recipient_contact_kind,
            notification.template_id,
            notification.context_type,
            notification.context_id,
            notification.attempt_count
        ",
    )
    .bind(claim_limit)
    .bind(&context.instance_id)
    .bind(lease_seconds)
    .fetch_all(&context.pool)
    .await?;

    let results = stream::iter(jobs)
        .map(|job| async move { process_job(context, &job).await })
        .buffer_unordered(context.settings.worker.delivery_concurrency.get())
        .collect::<Vec<_>>()
        .await;
    for result in results {
        result?;
    }
    Ok(())
}

async fn process_job(context: &WorkerContext, job: &ClaimedNotification) -> Result<(), AppError> {
    let result = deliver(context, job).await;
    match result {
        Ok(receipt) => record_success(context, job, receipt).await?,
        Err(error) => record_failure(context, job, error).await?,
    }
    Ok(())
}

async fn renew_lease(context: &WorkerContext, job_id: Uuid) -> Result<bool, AppError> {
    let lease_seconds =
        i64::try_from(context.settings.worker.lease_duration.as_secs()).map_err(|_| {
            AppError::Internal {
                category: "worker_lease_duration",
            }
        })?;
    let result = sqlx::query(
        r"
        UPDATE iam.notification_jobs
        SET lease_expires_at = transaction_timestamp()
            + ($3::bigint * interval '1 second')
        WHERE id = $1
          AND status = 'processing'
          AND lease_owner = $2
          AND lease_expires_at > transaction_timestamp()
        ",
    )
    .bind(job_id)
    .bind(&context.instance_id)
    .bind(lease_seconds)
    .execute(&context.pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

async fn deliver(
    context: &WorkerContext,
    job: &ClaimedNotification,
) -> Result<DeliveryReceipt, DeliveryError> {
    let contact = if job.notification_kind == "security_notice" {
        sqlx::query_as::<_, ContactMaterial>(
            "SELECT * FROM iam_private.get_worker_security_notice_contact($1, $2)",
        )
        .bind(job.id)
        .bind(&context.instance_id)
        .fetch_optional(&context.pool)
        .await
        .map_err(|_| DeliveryError::Unavailable)?
    } else {
        sqlx::query_as::<_, ContactMaterial>(
            r"
            SELECT *
            FROM iam_private.get_worker_notification_contact(
                $1, $2::iam.contact_kind
            )
            ",
        )
        .bind(job.recipient_contact_id)
        .bind(&job.recipient_contact_kind)
        .fetch_optional(&context.pool)
        .await
        .map_err(|_| DeliveryError::Unavailable)?
    }
    .ok_or(DeliveryError::Rejected)?;
    let field = match job.recipient_contact_kind.as_str() {
        "email" => ProtectedField::CarbonEmail,
        "phone" => ProtectedField::CarbonPhone,
        _ => return Err(DeliveryError::Rejected),
    };
    let contact_carbon_id = contact.carbon_id;
    let nonce = contact
        .nonce
        .try_into()
        .map_err(|_| DeliveryError::Rejected)?;
    let plaintext = context
        .encryption
        .decrypt(
            EncryptionContext::global(field, job.recipient_contact_id),
            &EncryptedValue {
                key_version: contact.encryption_key_version,
                nonce,
                ciphertext: contact.ciphertext,
            },
        )
        .map_err(|_| DeliveryError::Unavailable)?;
    let destination = std::str::from_utf8(&plaintext).map_err(|_| DeliveryError::Rejected)?;
    let destination = SecretString::from(destination.to_owned());

    match job.notification_kind.as_str() {
        "invitation" => deliver_invitation(context, job, contact_carbon_id, &destination).await,
        "security_notice" => deliver_security_notice(context, job, &destination).await,
        _ => Err(DeliveryError::Rejected),
    }
}

async fn deliver_invitation(
    context: &WorkerContext,
    job: &ClaimedNotification,
    contact_carbon_id: Uuid,
    destination: &SecretString,
) -> Result<DeliveryReceipt, DeliveryError> {
    if job.context_type != "organization_invitation" || job.template_id != "invitation.created" {
        return Err(DeliveryError::Rejected);
    }
    let invitation = sqlx::query_as::<_, InvitationContext>(
        r"
        SELECT *
        FROM iam_private.get_worker_invitation_context($1, $2)
        ",
    )
    .bind(job.context_id)
    .bind(contact_carbon_id)
    .fetch_optional(&context.pool)
    .await
    .map_err(|_| DeliveryError::Unavailable)?
    .ok_or(DeliveryError::Rejected)?;
    let mut join_url = context.settings.auth_base_url.clone();
    join_url.set_path(&format!("/invitations/{}", job.context_id));
    join_url.set_query(None);
    join_url.set_fragment(None);
    ensure_current_lease(context, job.id).await?;
    match job.provider.as_str() {
        "postmark" => {
            context
                .notifications
                .email
                .send_invitation(InvitationEmail {
                    recipient: destination,
                    organization_name: &invitation.organization_name,
                    join_url: &join_url,
                })
                .await
        }
        "twilio_messaging" => {
            context
                .notifications
                .sms
                .send_invitation(InvitationSms {
                    recipient: destination,
                    organization_name: &invitation.organization_name,
                    join_url: &join_url,
                })
                .await
        }
        _ => Err(DeliveryError::Rejected),
    }
}

async fn deliver_security_notice(
    context: &WorkerContext,
    job: &ClaimedNotification,
    destination: &SecretString,
) -> Result<DeliveryReceipt, DeliveryError> {
    let (subject, body) = security_notice(&job.template_id).ok_or(DeliveryError::Rejected)?;
    let command = SecurityNotice {
        recipient: destination,
        subject,
        body,
    };
    ensure_current_lease(context, job.id).await?;
    match job.provider.as_str() {
        "postmark" => {
            context
                .notifications
                .email
                .send_security_notice(command)
                .await
        }
        "twilio_messaging" => {
            context
                .notifications
                .sms
                .send_security_notice(command)
                .await
        }
        _ => Err(DeliveryError::Rejected),
    }
}

async fn ensure_current_lease(context: &WorkerContext, job_id: Uuid) -> Result<(), DeliveryError> {
    if renew_lease(context, job_id)
        .await
        .map_err(|_| DeliveryError::Unavailable)?
    {
        Ok(())
    } else {
        Err(DeliveryError::Unavailable)
    }
}

fn security_notice(template_id: &str) -> Option<(&'static str, &'static str)> {
    match template_id {
        "security.session_revoked" => Some((
            "A Silicon IAM session was revoked",
            "A session on your Silicon IAM account was revoked. Review your login history if this was unexpected.",
        )),
        "security.refresh_reuse" => Some((
            "Silicon IAM blocked a reused credential",
            "Silicon IAM detected a reused refresh credential and revoked its session family. Review your login history.",
        )),
        "security.credential_rotated" => Some((
            "A Silicon IAM credential was rotated",
            "A credential associated with your Silicon IAM account was rotated. Review recent security activity if this was unexpected.",
        )),
        "security.contact_changed" => Some((
            "Your Silicon IAM contact changed",
            "A verified contact on your Silicon IAM account changed. Review recent security activity and contact support if this was not you.",
        )),
        _ => None,
    }
}

async fn record_success(
    context: &WorkerContext,
    job: &ClaimedNotification,
    receipt: DeliveryReceipt,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        UPDATE iam.notification_jobs
        SET status = 'sent',
            lease_owner = NULL,
            lease_expires_at = NULL,
            provider_message_id = $3,
            last_error_code = NULL,
            sent_at = transaction_timestamp()
        WHERE id = $1
          AND status = 'processing'
          AND lease_owner = $2
        ",
    )
    .bind(job.id)
    .bind(&context.instance_id)
    .bind(receipt.provider_message_id)
    .execute(&context.pool)
    .await?;
    Ok(())
}

async fn record_failure(
    context: &WorkerContext,
    job: &ClaimedNotification,
    error: DeliveryError,
) -> Result<(), AppError> {
    let retryable = matches!(error, DeliveryError::Unavailable)
        && job.attempt_count < i32::from(context.settings.worker.max_attempts);
    let delay = retry_delay_seconds(
        u32::try_from(job.attempt_count).unwrap_or(u32::MAX),
        context.settings.worker.max_retry_delay,
        job.id,
    );
    let error_code = match error {
        DeliveryError::Unavailable => "provider_unavailable",
        DeliveryError::Rejected => "notification_rejected",
    };
    sqlx::query(
        r"
        UPDATE iam.notification_jobs
        SET status = CASE WHEN $3 THEN 'pending' ELSE 'failed' END,
            lease_owner = NULL,
            lease_expires_at = NULL,
            available_at = CASE
                WHEN $3 THEN transaction_timestamp() + ($4::bigint * interval '1 second')
                ELSE available_at
            END,
            last_error_code = $5,
            failed_at = CASE WHEN $3 THEN NULL ELSE transaction_timestamp() END
        WHERE id = $1
          AND status = 'processing'
          AND lease_owner = $2
        ",
    )
    .bind(job.id)
    .bind(&context.instance_id)
    .bind(retryable)
    .bind(delay)
    .bind(error_code)
    .execute(&context.pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_templates_are_closed_and_secret_free() {
        assert!(security_notice("security.session_revoked").is_some());
        assert!(security_notice("security.contact_changed").is_some());
        assert!(security_notice("caller.supplied.template").is_none());
    }
}
