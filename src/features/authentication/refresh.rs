use secrecy::{ExposeSecret as _, SecretString};

use crate::{api::ApiState, error::AppError};

use super::{
    database::{database_conflict, serializable},
    idempotency::{self, Claim, IdempotencyKey, Outcome},
    model::RefreshMutationOutcome,
    tokens::{self, RefreshResult},
};

const REFRESH_ROUTE: &str = "POST /api/v1/auth/tokens/refresh";

pub(super) async fn rotate(
    state: &ApiState,
    key: &IdempotencyKey,
    supplied: SecretString,
) -> Result<Outcome<RefreshMutationOutcome>, AppError> {
    let request_digest = refresh_request_digest(&supplied);
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
        Claim::Replay { status, response } => {
            transaction
                .commit()
                .await
                .map_err(|error| database_conflict(&error, "refresh_serialization_conflict"))?;
            return Ok(Outcome::replay(status, response));
        }
        Claim::Acquired { record_id } => record_id,
    };

    super::http::enforce_limit(
        state,
        "refresh_token_rotate",
        &supplied,
        30,
        std::time::Duration::from_secs(60),
    )
    .await?;

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
    Ok(Outcome::fresh(status, outcome))
}

fn refresh_request_digest(supplied: &SecretString) -> [u8; 32] {
    idempotency::digest_parts(
        b"refresh-token-rotate",
        &[supplied.expose_secret().as_bytes()],
    )
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::{REFRESH_ROUTE, refresh_request_digest};

    #[test]
    fn refresh_idempotency_route_is_template_stable() {
        assert_eq!(REFRESH_ROUTE, "POST /api/v1/auth/tokens/refresh");
    }

    #[test]
    fn refresh_idempotency_material_is_pepper_version_independent() {
        let token = SecretString::from(format!("rft_{}", "a".repeat(43)));
        let digest = refresh_request_digest(&token);
        assert_eq!(digest, refresh_request_digest(&token));
        assert_ne!(
            digest,
            refresh_request_digest(&SecretString::from(format!("rft_{}", "b".repeat(43))))
        );
    }
}
