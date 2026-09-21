-- The IAM-owned scoped service authenticates only its registered tos>iam
-- application using the trusted API database connection. There is no caller-
-- supplied app selector and no application-secret material in this projection.
-- Public main IAM token endpoints still authenticate ApplicationClient secrets.
BEGIN;

DROP FUNCTION IF EXISTS iam_private.resolve_scoped_iam_application();
CREATE FUNCTION iam_private.resolve_scoped_iam_application()
RETURNS TABLE (application_id text, app_id text, organization_id uuid, auth_epoch bigint)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT application.id, application.app_id, application.organization_id, principal.auth_epoch
    FROM iam.applications AS application
    JOIN iam.principals AS principal
      ON principal.id = application.id
     AND principal.kind = 'application'
     AND principal.status = 'active'
    JOIN iam.organizations AS organization
      ON organization.id = application.organization_id
     AND organization.org_id = 'tos'
     AND organization.status = 'active'
    WHERE application.app_id = 'tos>iam'
      AND application.review_status = 'verified'
      AND application.deleted_at IS NULL
      AND NULLIF(current_setting('iam.testing_environment_id', true), '') IS NULL
$$;
REVOKE ALL ON FUNCTION iam_private.resolve_scoped_iam_application() FROM PUBLIC;
DO $$ BEGIN
    IF to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION iam_private.resolve_scoped_iam_application() TO silicon_iam_api;
    END IF;
END $$;

COMMIT;
