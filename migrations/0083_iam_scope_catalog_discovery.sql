-- The default picker reads only the shared IAM permission definitions. Keep
-- historical external scope keys inaccessible through the shared table and
-- avoid scanning every application's published endpoints for this fixed list.
CREATE FUNCTION iam_private.iam_scope_catalog()
RETURNS TABLE(scope text, description text, critical boolean, app_id text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam AS $$
    SELECT catalog.scope, catalog.description, catalog.sensitive, NULL::text
    FROM iam.oauth_scope_catalog AS catalog
    WHERE catalog.scope = ANY(ARRAY[
        'self.identity.read', 'self.profile.read', 'self.email.read',
        'self.phone.read', 'self.organizations.read', 'self.membership.read',
        'self.capabilities.read', 'self.job_role.read', 'self.tags.read',
        'self.silicon_access.read', 'self.hierarchy.read', 'self.trust.read',
        'directory.carbons.read', 'directory.silicons.read',
        'directory.profiles.read', 'directory.memberships.read',
        'directory.capabilities.read', 'directory.job_roles.read',
        'directory.tags.read', 'directory.silicon_access.read',
        'directory.hierarchy.read', 'organization.tags.read',
        'organization.trust.read', 'organization.invitations.read',
        'organization.governance.read'
    ]::text[])
$$;
REVOKE ALL ON FUNCTION iam_private.iam_scope_catalog() FROM PUBLIC;

COMMENT ON FUNCTION iam_private.iam_scope_catalog() IS
    'Public IAM permission definitions only; excludes external application scope history and testing-environment data.';
