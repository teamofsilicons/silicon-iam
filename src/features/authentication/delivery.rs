//! Required synchronous OTP delivery for authentication initiations.

use futures::future;

use crate::{
    api::ApiState,
    application::ports::{DeliveryError, DeliveryReceipt, EmailOtp, PhoneOtp, SmsOtp},
    error::AppError,
};

use super::model::{ContactChannel, Delivery};

/// Failure classification used by the durable challenge delivery state
/// machine. Only a definitive rejection is safe to cancel and retry under the
/// same idempotency key; every ambiguous or partially successful batch remains
/// reserved to prevent duplicate messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RequiredDeliveryError {
    Definitive,
    OutcomeUnknown,
}

#[derive(Debug)]
pub(super) struct RequiredDeliveryReceipt {
    pub(super) channel: ContactChannel,
    pub(super) provider_message_id: String,
}

/// Redacts definitive and ambiguous provider outcomes to one public shape. In
/// particular, login must not reveal recipient/provider classification.
pub(super) const fn public_error() -> AppError {
    AppError::ProviderUnavailable
}

/// Sends every required OTP after the pending challenge and idempotency
/// reservation have committed. The caller activates the challenge only when
/// every provider confirms delivery.
pub(super) async fn send_all_required(
    state: &ApiState,
    deliveries: &[Delivery],
) -> Result<Vec<RequiredDeliveryReceipt>, RequiredDeliveryError> {
    let results = future::join_all(
        deliveries
            .iter()
            .map(|delivery| send_required(state, delivery)),
    )
    .await;
    classify_batch(&results)?;
    Ok(deliveries
        .iter()
        .zip(results)
        .filter_map(|(delivery, result)| {
            result.ok().map(|receipt| RequiredDeliveryReceipt {
                channel: delivery.channel,
                provider_message_id: receipt.provider_message_id,
            })
        })
        .collect())
}

/// Sends one required OTP without exposing the provider's recipient-specific
/// rejection classification to the caller.
pub(super) async fn send_required(
    state: &ApiState,
    delivery: &Delivery,
) -> Result<DeliveryReceipt, RequiredDeliveryError> {
    // A testing environment sends nothing. Its contacts are invented, and a
    // real message to an invented address is at best noise and at worst a way
    // to have this service mail a stranger on request. The flow still needs a
    // successful delivery to activate the challenge, so it gets one.
    if crate::infrastructure::testing_plane::is_active() {
        return Ok(DeliveryReceipt {
            provider_message_id: "testing-environment".to_owned(),
        });
    }

    let minutes = state.settings.security.otp_ttl.as_secs().div_ceil(60);
    let expires_in_minutes = u16::try_from(minutes).unwrap_or(u16::MAX);
    let result = match delivery.channel {
        ContactChannel::Email => {
            state
                .notifications
                .email
                .send_otp(EmailOtp {
                    recipient: &delivery.recipient,
                    code: &delivery.code,
                    purpose: delivery.purpose,
                    expires_in_minutes,
                })
                .await
        }
        ContactChannel::Phone => {
            if let Some(provider) = &state.notifications.phone_otp {
                provider
                    .start(PhoneOtp {
                        recipient: &delivery.recipient,
                    })
                    .await
            } else {
                state
                    .notifications
                    .sms
                    .send_otp(SmsOtp {
                        recipient: &delivery.recipient,
                        code: &delivery.code,
                        expires_in_minutes,
                    })
                    .await
            }
        }
    };
    result.map_err(|error| {
        tracing::warn!(
            channel = delivery.channel.database_value(),
            purpose = delivery.purpose,
            provider_error = provider_error_code(error),
            "required OTP delivery failed"
        );
        classify_provider_error(error)
    })
}

/// Reports whether the provider generates and validates the code for this
/// channel.
///
/// IAM holds no code in that case, so persisting a digest would leave a secret
/// at rest that is never delivered to anyone.
pub(super) fn provider_manages_otp(state: &ApiState, channel: ContactChannel) -> bool {
    !crate::infrastructure::testing_plane::is_active()
        && matches!(channel, ContactChannel::Phone)
        && state.notifications.phone_otp.is_some()
}

pub(super) async fn verify_managed_phone_otp(
    state: &ApiState,
    provider_verification_id: Option<&str>,
    code: &secrecy::SecretString,
) -> Result<Option<bool>, AppError> {
    // A testing environment never registered a verification with the provider,
    // so there is nothing to check against. Verification falls through to the
    // fixed environment code handled by the caller.
    if crate::infrastructure::testing_plane::is_active() {
        return Ok(None);
    }
    let Some(provider) = &state.notifications.phone_otp else {
        return Ok(None);
    };
    let provider_verification_id = provider_verification_id.ok_or(AppError::Internal {
        category: "phone_otp_provider_reference_missing",
    })?;
    match provider.check(provider_verification_id, code).await {
        Ok(approved) => Ok(Some(approved)),
        Err(DeliveryError::Rejected) => Ok(Some(false)),
        Err(DeliveryError::Unavailable) => Err(AppError::ProviderUnavailable),
    }
}

fn classify_batch(
    results: &[Result<DeliveryReceipt, RequiredDeliveryError>],
) -> Result<(), RequiredDeliveryError> {
    if results.is_empty() {
        return Err(RequiredDeliveryError::OutcomeUnknown);
    }
    if results.iter().all(Result::is_ok) {
        return Ok(());
    }
    if results.iter().any(Result::is_ok) {
        // At least one message may already be usable. Retrying the same batch
        // could duplicate that code, so retain the processing reservation.
        return Err(RequiredDeliveryError::OutcomeUnknown);
    }
    if results
        .iter()
        .all(|result| matches!(result, Err(RequiredDeliveryError::Definitive)))
    {
        Err(RequiredDeliveryError::Definitive)
    } else {
        Err(RequiredDeliveryError::OutcomeUnknown)
    }
}

const fn classify_provider_error(error: DeliveryError) -> RequiredDeliveryError {
    match error {
        DeliveryError::Rejected => RequiredDeliveryError::Definitive,
        DeliveryError::Unavailable => RequiredDeliveryError::OutcomeUnknown,
    }
}

const fn provider_error_code(error: DeliveryError) -> &'static str {
    match error {
        DeliveryError::Unavailable => "unavailable",
        DeliveryError::Rejected => "rejected",
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        application::ports::{DeliveryError, DeliveryReceipt},
        error::AppError,
    };

    use super::{
        RequiredDeliveryError, classify_batch, classify_provider_error, provider_error_code,
    };

    fn receipt() -> DeliveryReceipt {
        DeliveryReceipt {
            provider_message_id: "provider-id".to_owned(),
        }
    }

    #[test]
    fn provider_failure_classification_is_redacted_from_the_public_error() {
        assert_eq!(
            provider_error_code(DeliveryError::Unavailable),
            "unavailable"
        );
        assert_eq!(provider_error_code(DeliveryError::Rejected), "rejected");
        assert!(matches!(
            super::public_error(),
            AppError::ProviderUnavailable
        ));
        assert!(matches!(
            super::public_error(),
            AppError::ProviderUnavailable
        ));
        assert_eq!(
            classify_provider_error(DeliveryError::Rejected),
            RequiredDeliveryError::Definitive
        );
        assert_eq!(
            classify_provider_error(DeliveryError::Unavailable),
            RequiredDeliveryError::OutcomeUnknown
        );
    }

    #[test]
    fn partial_or_ambiguous_delivery_is_never_safe_to_retry_in_place() {
        assert_eq!(classify_batch(&[Ok(receipt()), Ok(receipt())]), Ok(()));
        assert_eq!(
            classify_batch(&[Ok(receipt()), Err(RequiredDeliveryError::Definitive),]),
            Err(RequiredDeliveryError::OutcomeUnknown)
        );
        assert_eq!(
            classify_batch(&[Err(RequiredDeliveryError::OutcomeUnknown)]),
            Err(RequiredDeliveryError::OutcomeUnknown)
        );
        assert_eq!(
            classify_batch(&[
                Err(RequiredDeliveryError::Definitive),
                Err(RequiredDeliveryError::Definitive),
            ]),
            Err(RequiredDeliveryError::Definitive)
        );
    }

    #[test]
    fn forward_migration_backfills_legacy_rows_then_defaults_fail_closed() {
        let migration = include_str!("../../../migrations/0028_align_refresh_session_lifetime.sql");
        assert_eq!(
            migration
                .matches("ADD COLUMN delivery_status text NOT NULL DEFAULT 'delivered'")
                .count(),
            3
        );
        assert_eq!(
            migration
                .matches("ALTER COLUMN delivery_status SET DEFAULT 'pending'")
                .count(),
            3
        );
        assert_eq!(
            migration
                .matches("ALTER COLUMN delivered_at DROP DEFAULT")
                .count(),
            3
        );
        assert_eq!(
            migration
                .matches("CHECK (delivery_status IN ('pending', 'delivered', 'failed'))")
                .count(),
            3
        );
    }
}
