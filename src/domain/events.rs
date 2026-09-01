//! Closed public event vocabularies.

/// Complete event vocabulary delivered to Silicon subscriptions in `all` mode.
///
/// This list is a public compatibility boundary. Additive changes require a
/// new reviewed API contract and must update the exact routing regression
/// tests and `OpenAPI` enum in the same milestone.
pub const SILICON_FULL_EVENT_TYPES: [&str; 38] = [
    "organization.membership.created.v1",
    "organization.membership.reactivated.v1",
    "organization.membership.removed.v1",
    "organization.silicon.created.v1",
    "organization.silicon.removed.v1",
    "organization.membership.updated.v1",
    "organization.membership.profile_updated.v1",
    "organization.membership.authorization_updated.v1",
    "organization.ownership_transferred.v1",
    "organization.admin.promoted.v1",
    "organization.admin.demoted.v1",
    "organization.silicon.updated.v1",
    "organization.tag_updated.v1",
    "organization.trust.default_updated.v1",
    "organization.trust.rule_created.v1",
    "organization.trust.rule_updated.v1",
    "organization.trust.rule_archived.v1",
    "organization.created.v1",
    "organization.updated.v1",
    "organization.tag_created.v1",
    "organization.invitation.created.v1",
    "organization.invitation.accepted.v1",
    "organization.invitation.revoked.v1",
    "organization.role_change.requested.v1",
    "organization.tag_change.requested.v1",
    "organization.approval.decided.v1",
    "organization.silicon.rotation_requested.v1",
    "organization.silicon.credential_rotated.v1",
    "organization.silicon.webhook.configured.v1",
    "organization.silicon.webhook.deleted.v1",
    "organization.silicon.webhook_subscription.updated.v1",
    "organization.silicon.webhook_subscription.deleted.v1",
    "sso.setup_link.created.v1",
    "sso.configuration.disabled.v1",
    "sso.entitlement.replaced.v1",
    "sso.connection.activated.v1",
    "sso.connection.deactivated.v1",
    "sso.connection.deleted.v1",
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::SILICON_FULL_EVENT_TYPES;

    #[test]
    fn silicon_full_event_vocabulary_is_an_exact_unique_set_of_38() {
        assert_eq!(SILICON_FULL_EVENT_TYPES.len(), 38);
        assert_eq!(
            SILICON_FULL_EVENT_TYPES
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            38
        );
        assert_eq!(
            SILICON_FULL_EVENT_TYPES
                .iter()
                .filter(|event_type| event_type.starts_with("organization."))
                .count(),
            32
        );
        assert_eq!(
            SILICON_FULL_EVENT_TYPES
                .iter()
                .filter(|event_type| event_type.starts_with("sso."))
                .count(),
            6
        );
    }
}
