-- Let a Carbon list organizations whose membership was removed without
-- weakening the ordinary active-member row-security policies.
--
-- The function takes no principal identifier: it is bound to the transaction's
-- authenticated principal and verifies that principal is an active Carbon.
-- The only rows it can return are organizations joined through that Carbon's
-- own removed memberships. In the shared testing database, FORCE ROW LEVEL
-- SECURITY keeps the restrictive testing-environment policy in force even for
-- this owner-rights function.

CREATE FUNCTION iam_private.list_removed_organizations_for_current_carbon(
    p_after_organization_id uuid,
    p_limit integer
)
RETURNS TABLE (
    id uuid,
    org_id text,
    name text,
    logo text,
    description text,
    owner_membership_id uuid,
    join_method text,
    sso_status text,
    status text,
    version bigint,
    created_at timestamptz,
    updated_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT
        organization.id,
        organization.org_id,
        organization.name,
        organization.logo_uri AS logo,
        organization.description,
        owner.id AS owner_membership_id,
        organization.join_method,
        COALESCE(sso.status, 'disabled') AS sso_status,
        CASE
            WHEN organization.status = 'active' THEN 'active'
            ELSE 'disabled'
        END AS status,
        organization.version,
        organization.created_at,
        organization.updated_at
    FROM iam.principals AS caller
    JOIN iam.carbons AS carbon
      ON carbon.id = caller.id
     AND carbon.deleted_at IS NULL
    JOIN iam.organization_memberships AS caller_membership
      ON caller_membership.principal_id = caller.id
     AND caller_membership.principal_kind = 'carbon'
     AND caller_membership.status = 'removed'
    JOIN iam.organizations AS organization
      ON organization.id = caller_membership.organization_id
    JOIN iam.organization_memberships AS owner
      ON owner.organization_id = organization.id
     AND owner.org_role = 'owner'
     AND owner.status = 'active'
    LEFT JOIN iam.organization_sso_configs AS sso
      ON sso.organization_id = organization.id
    WHERE caller.id = iam_private.current_principal_id()
      AND caller.kind = 'carbon'
      AND caller.status = 'active'
      AND (
          p_after_organization_id IS NULL
          OR organization.id > p_after_organization_id
      )
      AND p_limit BETWEEN 1 AND 101
    ORDER BY organization.id
    LIMIT LEAST(p_limit, 101)
$$;

COMMENT ON FUNCTION iam_private.list_removed_organizations_for_current_carbon(uuid, integer) IS
    'Pages organizations reached only through the current active Carbon principal''s own removed memberships.';

REVOKE ALL ON FUNCTION iam_private.list_removed_organizations_for_current_carbon(uuid, integer)
    FROM PUBLIC;

DO $grant_runtime_api$
BEGIN
    IF pg_catalog.to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION
            iam_private.list_removed_organizations_for_current_carbon(uuid, integer)
            TO silicon_iam_api;
    END IF;
END;
$grant_runtime_api$;
