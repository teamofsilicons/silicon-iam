-- An Application login is available to every active Carbon and Silicon, not
-- only to principals who administer the Application.  The ordinary RLS policy
-- on application_approved_scopes is intentionally administrative, so expose
-- only the active scope snapshot needed while minting a short-lived token.

CREATE FUNCTION iam_private.list_application_login_approved_scopes(
    p_application_id uuid
)
RETURNS TABLE (
    scope text,
    approved_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT approved.scope, approved.approved_at
    FROM iam.applications AS application
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
     AND application_principal.status = 'active'
    JOIN iam.application_approved_scopes AS approved
      ON approved.application_id = application.id
     AND approved.revoked_at IS NULL
    WHERE application.id = p_application_id
      AND application.review_status = 'verified'
      AND application.deleted_at IS NULL
      AND EXISTS (
          SELECT 1
          FROM iam.principals AS caller
          WHERE caller.id = iam_private.current_principal_id()
            AND caller.kind IN ('carbon', 'silicon')
            AND caller.status = 'active'
      )
    ORDER BY approved.scope
$$;

COMMENT ON FUNCTION iam_private.list_application_login_approved_scopes(uuid) IS
    'Returns only the active scope/approval snapshot required to mint an Application SLT for the current active Carbon or Silicon.';

REVOKE ALL ON FUNCTION iam_private.list_application_login_approved_scopes(uuid)
    FROM PUBLIC;

DO $grant_runtime_api$
BEGIN
    IF pg_catalog.to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION
            iam_private.list_application_login_approved_scopes(uuid)
            TO silicon_iam_api;
    END IF;
END;
$grant_runtime_api$;
