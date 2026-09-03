//! Request-local selection of the testing data plane.
//!
//! A testing environment is not a separate service. It is the same API,
//! executing against a different database, with every row scoped to one
//! environment. Which environment that is arrives as a request header and has
//! to reach two places far below the handler: the pool a transaction opens
//! against, and the transaction-local setting the row-security policies read.
//!
//! Threading it through several hundred call sites would be noise, and putting
//! it in [`ApiState`](crate::api::ApiState) would not work -- that value is
//! shared by every concurrent request. It lives here as request-scoped state
//! instead, alongside the request correlation identifier, which is the same
//! shape of problem.
//!
//! Nothing in this module grants authority. The selection is established once,
//! by the middleware that has already verified an environment key.

use std::future::Future;

use uuid::Uuid;

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
