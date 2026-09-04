//! Request-local selection of the testing data plane.
//!
//! A testing environment is not a separate service. It is the same API,
//! executing against a different database, with every row scoped to one
//! environment. Which environment that is arrives as a request header and has
//! to reach two places far below the handler: the pool a transaction opens
//! against, and the transaction-local setting the row-security policies read.
//!
//! Threading it through several hundred call sites would be noise, and putting
//! it in `ApiState` would not work -- that value is
//! shared by every concurrent request. It lives here as request-scoped state
//! instead, alongside the request correlation identifier, which is the same
//! shape of problem.
//!
//! Nothing in this module grants authority. The selection is established once,
//! by the middleware that has already verified an environment key.

use std::future::Future;

use secrecy::{ExposeSecret as _, SecretString};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

/// The verification code every testing environment accepts.
///
/// A testing environment delivers nothing -- no email, no SMS, no provider
/// call -- because the addresses in it are invented and the point of the
/// environment is to exercise a flow without involving anyone real. The
/// verification step still has to be passable, so this fixed code stands in for
/// a delivered one.
pub const UNIVERSAL_VERIFICATION_CODE: &str = "000000";

/// The testing environment one request is executing inside.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedEnvironment {
    /// Control-plane identity of the environment.
    pub id: Uuid,
    /// Organization that owns the environment.
    pub organization_id: Uuid,
}

tokio::task_local! {
    static SELECTED: SelectedEnvironment;
}

/// Runs a request future inside one testing environment.
pub async fn scope<T>(selected: SelectedEnvironment, future: impl Future<Output = T>) -> T {
    SELECTED.scope(selected, future).await
}

/// Returns the testing environment selected by the current request.
#[must_use]
pub fn current() -> Option<SelectedEnvironment> {
    SELECTED.try_with(|selected| *selected).ok()
}

/// Returns only the selected environment's identity.
#[must_use]
pub fn current_id() -> Option<Uuid> {
    current().map(|selected| selected.id)
}

/// Reports whether the current request is executing against a testing
/// environment rather than the production plane.
#[must_use]
pub fn is_active() -> bool {
    current().is_some()
}

/// Reports whether a presented one-time code is the environment's fixed code.
///
/// Answers false everywhere except inside a testing environment, so production
/// verification is untouched: the constant has no standing there at all.
#[must_use]
pub fn accepts_verification_code(supplied: &SecretString) -> bool {
    is_active()
        && bool::from(
            supplied
                .expose_secret()
                .as_bytes()
                .ct_eq(UNIVERSAL_VERIFICATION_CODE.as_bytes()),
        )
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use uuid::Uuid;

    use super::{
        SelectedEnvironment, UNIVERSAL_VERIFICATION_CODE, accepts_verification_code, current,
        current_id, is_active, scope,
    };

    fn selected() -> SelectedEnvironment {
        SelectedEnvironment {
            id: Uuid::from_u128(1),
            organization_id: Uuid::from_u128(2),
        }
    }

    #[tokio::test]
    async fn production_requests_have_no_environment_and_no_fixed_code() {
        assert!(!is_active());
        assert_eq!(current(), None);
        assert_eq!(current_id(), None);
        // The safety-critical half: the fixed code must never verify anything
        // outside a testing environment.
        assert!(!accepts_verification_code(&SecretString::from(
            UNIVERSAL_VERIFICATION_CODE.to_owned()
        )));
    }

    #[tokio::test]
    async fn a_scoped_request_carries_its_environment_and_accepts_the_fixed_code() {
        scope(selected(), async {
            assert!(is_active());
            assert_eq!(current(), Some(selected()));
            assert_eq!(current_id(), Some(Uuid::from_u128(1)));
            assert!(accepts_verification_code(&SecretString::from(
                UNIVERSAL_VERIFICATION_CODE.to_owned()
            )));
            assert!(!accepts_verification_code(&SecretString::from(
                "000001".to_owned()
            )));
            assert!(!accepts_verification_code(&SecretString::from(
                String::new()
            )));
        })
        .await;
    }

    #[tokio::test]
    async fn the_selection_does_not_outlive_its_request() {
        scope(selected(), async { assert!(is_active()) }).await;
        assert!(!is_active());
    }
}
