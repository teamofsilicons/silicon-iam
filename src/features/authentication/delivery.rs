//! Required synchronous OTP delivery for authentication initiations.

use futures::future;

use crate::{
    api::ApiState,
    application::ports::{DeliveryError, EmailOtp, SmsOtp},
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
) -> Result<(), RequiredDeliveryError> {
    let results = future::join_all(
        deliveries
            .iter()
            .map(|delivery| send_required(state, delivery)),
    )
    .await;
    classify_batch(&results)
}

/// Sends one required OTP without exposing the provider's recipient-specific
/// rejection classification to the caller.
pub(super) async fn send_required(
    state: &ApiState,
    delivery: &Delivery,
) -> Result<(), RequiredDeliveryError> {
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
    };
    result.map(|_| ()).map_err(|error| {
        tracing::warn!(
            channel = delivery.channel.database_value(),
            purpose = delivery.purpose,
            provider_error = provider_error_code(error),
            "required OTP delivery failed"
        );
        classify_provider_error(error)
    })
}

fn classify_batch(
    results: &[Result<(), RequiredDeliveryError>],
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
    use crate::{application::ports::DeliveryError, error::AppError};

    use super::{
        RequiredDeliveryError, classify_batch, classify_provider_error, provider_error_code,
    };

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
        assert_eq!(classify_batch(&[Ok(()), Ok(())]), Ok(()));
        assert_eq!(
            classify_batch(&[Ok(()), Err(RequiredDeliveryError::Definitive),]),
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
