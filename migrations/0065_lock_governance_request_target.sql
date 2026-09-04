-- A Silicon may request role and tag changes without holding direct member
-- update authority. PostgreSQL applies UPDATE row policies to SELECT ... FOR
-- UPDATE, so the ordinary API-role query hid every target from those callers
-- and both request routes answered 404.
--
-- Keep the serialization lock behind a narrow owner-rights function. It is
-- bound to the transaction's selected organization and authenticated active
-- Silicon membership, and can return only the exact target membership in that
-- organization.

CREATE FUNCTION iam_private.lock_governance_request_target(
    p_organization_id uuid,
    p_membership_id uuid
)
RETURNS TABLE (
    id uuid,
    principal_kind text,
    job_role text,
    status text
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT
        target.id,
        target.principal_kind::text,
        target.job_role,
        target.status
    FROM iam.organization_memberships AS target
    WHERE target.organization_id = p_organization_id
      AND target.id = p_membership_id
      AND p_organization_id = iam_private.current_organization_id()
      AND EXISTS (
          SELECT 1
          FROM iam.organization_memberships AS requester
          JOIN iam.principals AS requester_principal
            ON requester_principal.id = requester.principal_id
           AND requester_principal.kind = 'silicon'
           AND requester_principal.status = 'active'
          WHERE requester.organization_id = p_organization_id
            AND requester.principal_id = iam_private.current_principal_id()
            AND requester.principal_kind = 'silicon'
            AND requester.status = 'active'
      )
    LIMIT 1
    FOR UPDATE OF target
$$;

COMMENT ON FUNCTION iam_private.lock_governance_request_target(uuid, uuid) IS
    'Locks one role/tag request target for the current active Silicon in the selected organization.';

REVOKE ALL ON FUNCTION iam_private.lock_governance_request_target(uuid, uuid)
    FROM PUBLIC;

DO $grant_runtime_api$
BEGIN
    IF pg_catalog.to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION
            iam_private.lock_governance_request_target(uuid, uuid)
            TO silicon_iam_api;
    END IF;
END;
$grant_runtime_api$;
