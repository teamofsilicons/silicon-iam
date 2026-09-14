-- Only a verified root-selected world can resolve its imported scoped app.
-- The production resolver remains separate and cannot be used as a fallback.
CREATE FUNCTION iam_private.resolve_testing_scoped_iam_application()
RETURNS TABLE(application_id uuid, app_id text, organization_id uuid, auth_epoch bigint)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT app.id, app.app_id, app.organization_id, principal.auth_epoch
    FROM iam.applications app
    JOIN iam.principals principal ON principal.id = app.id
      AND principal.kind = 'application' AND principal.status = 'active'
    JOIN iam.organizations organization ON organization.id = app.organization_id
      AND organization.org_id = 'tos' AND organization.status = 'active'
    JOIN iam.testing_application_imports imported ON imported.application_id = app.id
      AND imported.testing_environment_id = iam_private.current_testing_environment_id()
      AND imported.retired_at IS NULL
    WHERE iam_private.current_testing_environment_id() IS NOT NULL
      AND app.app_id = 'tos>iam' AND app.review_status = 'verified'
      AND app.deleted_at IS NULL AND app.test_imported_from_production
$$;
REVOKE ALL ON FUNCTION iam_private.resolve_testing_scoped_iam_application() FROM PUBLIC;
DO $$ BEGIN
    IF to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION iam_private.resolve_testing_scoped_iam_application() TO silicon_iam_api;
    END IF;
END $$;
SELECT iam_private.reconcile_testing_environment_security();
