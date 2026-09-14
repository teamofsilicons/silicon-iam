-- Explicit, non-critical delegation for isolated test-world creation. This
-- definition does not grant any app or user additional authority by itself.
INSERT INTO iam.oauth_scope_catalog(scope, description, sensitive) VALUES (
    'organization.testing_environments.create',
    'Create an isolated IAM test environment for your selected organization and receive its root key to bootstrap test identities, import applications and manage test data. Does not authorize production identity or access changes.',
    false
);

CREATE OR REPLACE FUNCTION iam_private.iam_scope_catalog()
RETURNS TABLE(scope text, description text, critical boolean, app_id text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam AS $$
    SELECT catalog.scope, catalog.description, catalog.sensitive, NULL::text
    FROM iam.oauth_scope_catalog AS catalog
    WHERE catalog.scope = ANY(ARRAY[
        'self.identity.read',
        'self.profile.read',
        'self.email.read',
        'self.phone.read',
        'self.organizations.read',
        'self.membership.read',
        'self.capabilities.read',
        'self.job_role.read',
        'self.tags.read',
        'self.silicon_access.read',
        'self.hierarchy.read',
        'self.trust.read',
        'directory.carbons.read',
        'directory.silicons.read',
        'directory.profiles.read',
        'directory.memberships.read',
        'directory.capabilities.read',
        'directory.job_roles.read',
        'directory.tags.read',
        'directory.silicon_access.read',
        'directory.hierarchy.read',
        'organization.tags.read',
        'organization.trust.read',
        'organization.invitations.read',
        'organization.governance.read',
        'organizations.create',
        'organization.profile.update',
        'organization.invitations.create',
        'organization.invitations.revoke',
        'organization.silicons.create',
        'organization.testing_environments.create',
        'organization.silicons.update',
        'organization.carbons.remove',
        'organization.silicons.remove',
        'organization.tags.create',
        'organization.tags.update',
        'organization.tags.delete',
        'organization.member_tags.update',
        'organization.job_roles.update',
        'organization.silicon_access.update',
        'organization.trust.update',
        'organization.admins.promote',
        'organization.admins.demote',
        'organization.capabilities.update',
        'organization.change_requests.read',
        'organization.job_role_changes.request',
        'organization.tag_changes.request',
        'organization.change_requests.decide',
        'organization.job_role_history.read',
        'organization.tag_history.read',
        'organizations.join',
        'organization.sso.read',
        'organization.sso.manage',
        'organization.silicons.credentials.rotate'
    ]::text[])
$$;
REVOKE ALL ON FUNCTION iam_private.iam_scope_catalog() FROM PUBLIC;

COMMENT ON FUNCTION iam_private.iam_scope_catalog() IS
    'Public IAM permission definitions only; excludes external application scope history and testing-environment data.';

-- Locks the exact authenticated Carbon/session/application/membership chain.
-- The API installs subject, organization and application from verified context;
-- there is no arbitrary scope or delegated target parameter.
CREATE FUNCTION iam_private.authorize_scoped_testing_environment_creation(p_token uuid, p_membership uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE
    app uuid := iam_private.current_application_id();
    subject uuid := iam_private.current_principal_id();
    organization uuid := iam_private.current_organization_id();
    app_epoch bigint;
    snapshot jsonb;
BEGIN
    IF app IS NULL OR subject IS NULL OR organization IS NULL OR p_membership IS NULL
       OR NULLIF(current_setting('iam.testing_environment_id', true), '') IS NOT NULL THEN
        RETURN false;
    END IF;
    SELECT token.client_auth_epoch INTO app_epoch FROM iam.access_tokens token
    WHERE token.id = p_token AND token.subject_principal_id = subject
      AND token.subject_kind = 'carbon' AND token.token_class = 'application_access'
      AND token.client_application_id = app AND token.audience_application_id = app;
    IF NOT FOUND THEN RETURN false; END IF;
    snapshot := iam_private.get_current_application_authorization(
        p_token, subject, organization, p_membership, app, app_epoch, NULL);
    RETURN COALESCE(snapshot->'scopes' ? 'organization.testing_environments.create', false);
END $$;
REVOKE ALL ON FUNCTION iam_private.authorize_scoped_testing_environment_creation(uuid,uuid) FROM PUBLIC;
DO $$ BEGIN
    IF to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION iam_private.authorize_scoped_testing_environment_creation(uuid,uuid) TO silicon_iam_api;
    END IF;
END $$;
