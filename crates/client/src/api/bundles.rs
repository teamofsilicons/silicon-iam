//! Application bundles retain independent applications and credentials.

use crate::{Client, Mutation, Result, models};

/// Organization-administered application bundle configuration.
pub struct Bundles<'a>(pub(super) &'a Client);

impl Bundles<'_> {
    /// Lists bundles the signed-in Carbon may administer.
    ///
    /// # Errors
    /// Fails when the caller is not authenticated.
    pub async fn list(&self) -> Result<models::ApplicationBundleList> {
        self.0.get(&["application-bundles"]).await
    }

    /// Creates a bundle whose members belong to the same organization.
    ///
    /// # Errors
    /// Fails if bundle creation is unavailable, the handle is taken, or a member is invalid.
    pub async fn create(
        &self,
        input: &models::ApplicationBundleCreate,
        mutation: &Mutation,
    ) -> Result<models::ApplicationBundle> {
        self.0.post(&["application-bundles"], input, mutation).await
    }

    /// Reads a bundle using its canonical organization-qualified identifier.
    ///
    /// # Errors
    /// Fails when the bundle is unavailable to this caller.
    pub async fn get(&self, bundle_id: &str) -> Result<models::ApplicationBundle> {
        self.0.get(&["application-bundles", bundle_id]).await
    }

    /// Updates display details or the complete member list.
    ///
    /// # Errors
    /// Fails if the version is stale or the caller cannot administer the bundle.
    pub async fn update(
        &self,
        bundle_id: &str,
        version: i64,
        input: &models::ApplicationBundlePatch,
        mutation: &Mutation,
    ) -> Result<models::ApplicationBundle> {
        self.0
            .patch(
                &["application-bundles", bundle_id],
                version,
                input,
                mutation,
            )
            .await
    }

    /// Deletes a bundle while leaving every member application intact.
    ///
    /// # Errors
    /// Fails if the version is stale or the caller cannot administer the bundle.
    pub async fn delete(&self, bundle_id: &str, version: i64, mutation: &Mutation) -> Result<()> {
        self.0
            .delete(&["application-bundles", bundle_id], Some(version), mutation)
            .await
    }
}
