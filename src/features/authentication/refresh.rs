use secrecy::{ExposeSecret as _, SecretString};

use crate::{api::ApiState, error::AppError, infrastructure::crypto::DigestPurpose};

use super::{
    database::{database_conflict, serializable},
    idempotency::{self, Claim, IdempotencyKey},
    model::RefreshMutationOutcome,
    tokens::{self, RefreshResult},
};

const REFRESH_ROUTE: &str = "/api/v1/auth/tokens/refresh";

pub(super) async fn rotate(
    state: &ApiState,
    key: &IdempotencyKey,
    supplied: SecretString,
) -> Result<RefreshMutationOutcome, AppError> {
    let request_key = state
        .crypto
        .digest_secret(DigestPurpose::RefreshToken, &supplied)
        .map_err(|_| AppError::Internal {
            category: "refresh_request_digest",
        })?;
    let request_version = request_key.key_version().to_be_bytes();
    let request_digest = idempotency::digest_parts(
        b"refresh-token-rotate",
        &[&request_version, request_key.as_bytes()],
    );
    let caller_scope = idempotency::digest_parts(
        b"refresh-token-caller",
        &[supplied.expose_secret().as_bytes()],
    );
    let mut transaction = serializable(&state.pool, "refresh_transaction").await?;
    let record_id = match idempotency::begin::<RefreshMutationOutcome>(
        &mut transaction,
        &state.crypto,
        key,
        &caller_scope,
        REFRESH_ROUTE,
        request_digest,
        true,
    )
    .await?
    {
        Claim::Replay { response } => {
            transaction
                .commit()
                .await
                .map_err(|error| database_conflict(&error, "refresh_serialization_conflict"))?;
            return Ok(response);
        }
        Claim::Acquired { record_id } => record_id,
    };

    let outcome = match tokens::rotate_refresh_token(
        &mut transaction,
        &state.crypto,
        &state.settings.security,
        &supplied,
    )
    .await?
    {
        RefreshResult::Rotated(tokens) => RefreshMutationOutcome::Success(tokens),
        RefreshResult::ReplayRevoked => RefreshMutationOutcome::ReplayRevoked,
    };
    let status = match outcome {
        RefreshMutationOutcome::Success(_) => 200,
        RefreshMutationOutcome::ReplayRevoked => 401,
    };
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        status,
        &outcome,
        true,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "refresh_serialization_conflict"))?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::REFRESH_ROUTE;

    #[test]
    fn refresh_idempotency_route_is_template_stable() {
        assert_eq!(REFRESH_ROUTE, "/api/v1/auth/tokens/refresh");
    }
}
