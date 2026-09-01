-- Project an Application's organization identity without weakening the
-- organization table's row-level tenant boundary. Application management,
-- platform review, and same-organization OBO discovery have distinct forms of
-- authority, so callers must pass through this narrow projection instead of
-- joining iam.organizations directly.

CREATE FUNCTION iam_private.resolve_authorized_application_organization(
    p_application_id uuid
)
RETURNS TABLE (
    organization_id uuid,
    org_id text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT application.organization_id, organization.org_id
    FROM iam.applications AS application
    JOIN iam.organizations AS organization
      ON organization.id = application.organization_id
    WHERE application.id = p_application_id
      AND (
          iam_private.can_read_application(
              application.id,
              iam_private.current_principal_id()
          )
          OR iam_private.can_administer_application(
              application.id,
              iam_private.current_principal_id()
          )
          OR (
              application.review_status = 'verified'
              AND application.deleted_at IS NULL
              AND organization.status = 'active'
              AND iam_private.current_principal_id()
                  = iam_private.current_application_id()
              AND EXISTS (
                  SELECT 1
                  FROM iam.applications AS caller
                  JOIN iam.principals AS caller_principal
                    ON caller_principal.id = caller.id
                   AND caller_principal.kind = 'application'
                   AND caller_principal.status = 'active'
                  JOIN iam.principals AS target_principal
                    ON target_principal.id = application.id
                   AND target_principal.kind = 'application'
                   AND target_principal.status = 'active'
                  WHERE caller.id = iam_private.current_application_id()
                    AND caller.organization_id = application.organization_id
                    AND caller.review_status = 'verified'
                    AND caller.deleted_at IS NULL
              )
          )
      )
$$;

COMMENT ON FUNCTION iam_private.resolve_authorized_application_organization(uuid) IS
    'Returns one Application organization identity only to its current tenant managers, authorized platform reviewers, or verified same-organization Application callers.';

REVOKE ALL ON FUNCTION iam_private.resolve_authorized_application_organization(uuid)
    FROM PUBLIC;
