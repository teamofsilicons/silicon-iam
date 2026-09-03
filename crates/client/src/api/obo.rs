//! Delegated access between applications in one organization.
//!
//! One application asks Silicon IAM for a single-use proof that it may call
//! another, then the callee verifies that proof. Both ends authenticate with
//! their own application credential.

use crate::{Client, Mutation, Result, models};

/// On-behalf-of access.
pub struct Obo<'a>(pub(super) &'a Client);

impl Obo<'_> {
    /// The endpoints an application publishes for delegated access.
    ///
    /// # Errors
    ///
    /// Returns an error when the application is outside the caller's
    /// organization, which is answered as not-found.
    pub async fn endpoints(&self, app_id: &str) -> Result<models::OboEndpointCatalog> {
        self.0
            .get(&["obo-access", "applications", app_id, "endpoints"])
            .await
    }

    /// Exchanges a signed request for a single-use capability proof.
    ///
    /// The proof is bound to the exact method, endpoint and body digest given
    /// here, so it cannot be replayed against a different call. `timestamp`
    /// and `signature` are the request signature the contract specifies.
    ///
    /// # Errors
    ///
    /// Returns an error when the signature does not verify, the timestamp is
    /// outside tolerance, or the callee does not grant the caller access.
    pub async fn exchange(
        &self,
        request: &models::OboExchangeRequest,
        timestamp: &str,
        signature: &str,
        mutation: &Mutation,
    ) -> Result<models::OboProofResponse> {
        let built = mutation
            .apply(
                self.0
                    .route(reqwest::Method::POST, &["obo-access", "exchanges"])?,
            )
            .header("x-obo-timestamp", timestamp)
            .header("x-obo-signature", signature)
            .json(request);
        self.0.send_json(built).await
    }

    /// Consumes a proof, confirming what the caller may do.
    ///
    /// Single use: a second verification of the same proof fails, which is
    /// what stops a captured proof from being replayed.
    ///
    /// # Errors
    ///
    /// Returns an error when the proof is unknown, expired, already consumed,
    /// or does not match the request it is presented against.
    pub async fn verify(
        &self,
        request: &models::OboVerifyRequest,
    ) -> Result<models::OboAccessResult> {
        let built = self
            .0
            .route(reqwest::Method::POST, &["obo-access", "verify"])?
            .json(request);
        self.0.send_json(built).await
    }
}
