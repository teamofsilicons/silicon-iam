//! Organization membership and capability resolution.

use std::{collections::HashSet, str::FromStr as _};

use sqlx::{FromRow, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::domain::organization::{Capability, OrgRole, OrganizationAuthority};

/// Active organization context for one authenticated principal.
#[derive(Clone, Debug)]
pub struct OrganizationAccess {
    /// Internal organization identity.
    pub organization_id: Uuid,
    /// Durable membership identity.
    pub membership_id: Uuid,
    /// Resolved authorization tier and explicit grants.
    pub authority: OrganizationAuthority,
}

/// Failure to resolve stored organization authority.
#[derive(Debug, Error)]
pub enum AuthorizationError {
    /// PostgreSQL lookup failed.
    #[error("organization authorization lookup failed")]
    Database(#[from] sqlx::Error),
    /// Stored role or capability is outside the compiled vocabulary.
    #[error("stored organization authorization value is invalid")]
    InvalidStoredValue,
}

#[derive(FromRow)]
struct OrganizationAccessRow {
    organization_id: Uuid,
    membership_id: Uuid,
    org_role: String,
    capabilities: Vec<String>,
}

/// Resolves an active membership by immutable public organization handle.
///
/// The caller must begin the transaction with the authenticated principal set,
/// allowing RLS to hide organizations outside that principal's directory.
///
/// # Errors
///
/// Returns an error for database failures or an invalid stored authorization
/// value. A non-member or unknown handle returns `Ok(None)`.
pub async fn resolve_organization_access(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
    organization_handle: &str,
) -> Result<Option<OrganizationAccess>, AuthorizationError> {
    let row = sqlx::query_as::<_, OrganizationAccessRow>(
        r"
        SELECT
            organization.id AS organization_id,
            membership.id AS membership_id,
            membership.org_role::text AS org_role,
            ARRAY(
                SELECT capability_grant.capability
                FROM iam.organization_capability_grants AS capability_grant
                WHERE capability_grant.organization_id = organization.id
                  AND capability_grant.grantee_membership_id = membership.id
                  AND capability_grant.revoked_at IS NULL
                  AND capability_grant.capability <> 'audit.read'
                ORDER BY capability_grant.capability
            ) AS capabilities
        FROM iam.organizations AS organization
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.principal_id = $1
         AND membership.status = 'active'
        WHERE organization.org_id = $2
          AND organization.status = 'active'
        LIMIT 1
        ",
    )
    .bind(principal_id)
    .bind(organization_handle)
    .fetch_optional(&mut **transaction)
    .await?;

    row.map(OrganizationAccess::try_from).transpose()
}

impl TryFrom<OrganizationAccessRow> for OrganizationAccess {
    type Error = AuthorizationError;

    fn try_from(row: OrganizationAccessRow) -> Result<Self, Self::Error> {
        let org_role = match row.org_role.as_str() {
            "owner" => OrgRole::Owner,
            "admin" => OrgRole::Admin,
            "member" => OrgRole::Member,
            _ => return Err(AuthorizationError::InvalidStoredValue),
        };
        let capabilities = row
            .capabilities
            .into_iter()
            .map(|capability| {
                Capability::from_str(&capability)
                    .map_err(|_| AuthorizationError::InvalidStoredValue)
            })
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(Self {
            organization_id: row.organization_id,
            membership_id: row.membership_id,
            authority: OrganizationAuthority {
                org_role,
                capabilities,
            },
        })
    }
}
