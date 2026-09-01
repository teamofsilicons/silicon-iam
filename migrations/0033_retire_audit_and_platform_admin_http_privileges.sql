-- Retire database authority that existed only for the removed generic audit
-- browsers and dynamic platform-administrator HTTP mutations. Historical audit
-- and role-grant rows remain intact, and the API keeps SELECT on role grants for
-- the deferred last-active-administrator invariant on principal mutations.

DO $retire_administration_http_privileges$
BEGIN
    IF pg_catalog.to_regrole('silicon_iam_api') IS NOT NULL THEN
        EXECUTE 'REVOKE INSERT, UPDATE ON TABLE iam.platform_role_grants FROM silicon_iam_api';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION iam_private.get_audit_public_identifiers(uuid, iam.principal_kind, uuid, uuid) FROM silicon_iam_api';
    END IF;
END;
$retire_administration_http_privileges$;

