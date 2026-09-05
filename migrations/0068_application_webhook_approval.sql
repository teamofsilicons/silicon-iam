-- Approving a pending webhook destination is a separate, resource-bound
-- verified-channel action. Retain the existing closed action catalog and
-- historical rows; older retired purposes remain covered by NOT VALID.
ALTER TABLE iam.step_up_challenges
    DROP CONSTRAINT step_up_challenges_supported_purpose,
    ADD CONSTRAINT step_up_challenges_supported_purpose CHECK (
        purpose IN (
            'account.session_revoke',
            'account.sessions_revoke_all',
            'application.client_secret.rotate',
            'application.webhook_secret.rotate',
            'application.webhook.approve',
            'organization.transfer_ownership',
            'organization.authorization_change',
            'organization.sso_change',
            'organization.silicon_webhook.redirect',
            'silicon.rotate_token',
            'platform_admin.sso_entitlement',
            'platform_admin.application_review'
        )
    ) NOT VALID;

ALTER TABLE iam.step_up_assertions
    DROP CONSTRAINT step_up_assertions_supported_purpose,
    ADD CONSTRAINT step_up_assertions_supported_purpose CHECK (
        purpose IN (
            'account.session_revoke',
            'account.sessions_revoke_all',
            'application.client_secret.rotate',
            'application.webhook_secret.rotate',
            'application.webhook.approve',
            'organization.transfer_ownership',
            'organization.authorization_change',
            'organization.sso_change',
            'organization.silicon_webhook.redirect',
            'silicon.rotate_token',
            'platform_admin.sso_entitlement',
            'platform_admin.application_review'
        )
    ) NOT VALID;

COMMENT ON CONSTRAINT step_up_challenges_supported_purpose ON iam.step_up_challenges IS
    'Closed action catalog including resource-bound Application webhook destination approval.';
COMMENT ON CONSTRAINT step_up_assertions_supported_purpose ON iam.step_up_assertions IS
    'Closed action catalog including resource-bound Application webhook destination approval.';

-- Runtime roles may not mutate platform grants or read their capability
-- catalog directly. This narrow helper only locks the current Carbon's live
-- reviewer authority until the calling transaction commits; it cannot grant
-- authority or substitute a different Carbon. A grant revocation or capability
-- removal therefore cannot race a successful webhook approval.
CREATE FUNCTION iam_private.lock_application_webhook_reviewer(p_carbon_id uuid)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF p_carbon_id IS NULL
       OR p_carbon_id IS DISTINCT FROM iam_private.current_principal_id() THEN
        RETURN false;
    END IF;

    PERFORM role_grant.id
    FROM iam.principals AS principal
    JOIN iam.platform_role_grants AS role_grant
      ON role_grant.carbon_id = principal.id
     AND role_grant.revoked_at IS NULL
    JOIN iam.platform_role_capabilities AS role_capability
      ON role_capability.role = role_grant.role
     AND role_capability.capability = 'applications.review'
    WHERE principal.id = p_carbon_id
      AND principal.kind = 'carbon'
      AND principal.status = 'active'
    ORDER BY role_grant.id
    LIMIT 1
    FOR SHARE OF principal, role_grant, role_capability;

    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.lock_application_webhook_reviewer(uuid) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.lock_application_webhook_reviewer(uuid) IS
    'Lock and verify only the current active Carbon platform reviewer; testing migrations reconcile this helper to the RLS-constrained definer owner.';
