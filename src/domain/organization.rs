//! Organization authorization and directory types.

use serde::{Deserialize, Serialize};
use std::{collections::HashSet, str::FromStr};
use thiserror::Error;

/// Coarse authorization tier on a Carbon organization membership.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgRole {
    /// Sole organization owner.
    Owner,
    /// Administrator with explicitly granted capabilities.
    Admin,
    /// Regular member.
    Member,
}

/// Fine-grained organization control-plane capability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Update organization metadata and join method.
    OrganizationUpdate,
    /// Create and revoke Carbon invitations.
    MembersInvite,
    /// Remove organization members.
    MembersRemove,
    /// Update membership directory metadata.
    MembersUpdateDirectory,
    /// Create Silicon identities.
    SiliconsCreate,
    /// Update Silicon directory configuration.
    SiliconsUpdateDirectory,
    /// Change the acyclic Silicon reporting hierarchy.
    SiliconsManageHierarchy,
    /// Remove Silicon identities.
    SiliconsRemove,
    /// Request or approve Silicon secret rotation.
    SiliconsRotateToken,
    /// Request job-role changes.
    RolesRequest,
    /// Approve job-role changes.
    RolesApprove,
    /// Promote a member with a delegable capability subset.
    AdminsCreate,
    /// Change admin grants or demote an administrator.
    AdminsManage,
    /// Manage organization tags.
    TagsManage,
    /// Manage advisory trust metadata.
    TrustManage,
    /// Configure SSO.
    SsoManage,
    /// Read privileged security audit records.
    AuditRead,
}

/// Invalid organization capability persisted or supplied at an API boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("unknown organization capability")]
pub struct CapabilityError;

/// Current organization authority for one active membership.
#[derive(Clone, Debug)]
pub struct OrganizationAuthority {
    /// Coarse organization tier.
    pub org_role: OrgRole,
    /// Active explicit capability grants.
    pub capabilities: HashSet<Capability>,
}

impl OrganizationAuthority {
    /// Evaluates one capability using the deny-by-default policy.
    #[must_use]
    pub fn allows(&self, capability: Capability) -> bool {
        self.org_role == OrgRole::Owner || self.capabilities.contains(&capability)
    }
}

impl Capability {
    /// Stable database and API vocabulary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrganizationUpdate => "organization.update",
            Self::MembersInvite => "members.invite",
            Self::MembersUpdateDirectory => "members.update_directory",
            Self::MembersRemove => "members.remove",
            Self::SiliconsCreate => "silicons.create",
            Self::SiliconsUpdateDirectory => "silicons.update_directory",
            Self::SiliconsManageHierarchy => "silicons.manage_hierarchy",
            Self::SiliconsRemove => "silicons.remove",
            Self::SiliconsRotateToken => "silicons.rotate_token",
            Self::TagsManage => "tags.manage",
            Self::TrustManage => "trust.manage",
            Self::RolesRequest => "roles.request",
            Self::RolesApprove => "roles.approve",
            Self::AdminsCreate => "admins.create",
            Self::AdminsManage => "admins.manage",
            Self::SsoManage => "sso.manage",
            Self::AuditRead => "audit.read",
        }
    }
}

impl FromStr for Capability {
    type Err = CapabilityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "organization.update" => Ok(Self::OrganizationUpdate),
            "members.invite" => Ok(Self::MembersInvite),
            "members.update_directory" => Ok(Self::MembersUpdateDirectory),
            "members.remove" => Ok(Self::MembersRemove),
            "silicons.create" => Ok(Self::SiliconsCreate),
            "silicons.update_directory" => Ok(Self::SiliconsUpdateDirectory),
            "silicons.manage_hierarchy" => Ok(Self::SiliconsManageHierarchy),
            "silicons.remove" => Ok(Self::SiliconsRemove),
            "silicons.rotate_token" => Ok(Self::SiliconsRotateToken),
            "tags.manage" => Ok(Self::TagsManage),
            "trust.manage" => Ok(Self::TrustManage),
            "roles.request" => Ok(Self::RolesRequest),
            "roles.approve" => Ok(Self::RolesApprove),
            "admins.create" => Ok(Self::AdminsCreate),
            "admins.manage" => Ok(Self::AdminsManage),
            "sso.manage" => Ok(Self::SsoManage),
            "audit.read" => Ok(Self::AuditRead),
            _ => Err(CapabilityError),
        }
    }
}

/// Advisory trust boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustBoundary {
    /// Principal belongs to the internal trust boundary.
    Internal,
    /// Principal belongs to an external trust boundary.
    External,
}

/// Advisory trust level.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Actions should not be trusted.
    NotTrusted,
    /// Actions should require human approval.
    NeedsApproval,
    /// Actions may be trusted by consumers.
    Trusted,
}
