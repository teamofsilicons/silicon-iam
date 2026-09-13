-- Production has no actor-ID authentication. The testing overlay replaces
-- this inert helper only in the separate, row-scoped testing database.
CREATE FUNCTION iam_private.create_testing_actor_login(
    p_application_id uuid, p_application_epoch bigint, p_public_id text,
    p_session_id uuid, p_consent_id uuid, p_lifetime_seconds bigint
)
RETURNS TABLE (
    principal_id uuid, subject_kind text, subject_auth_epoch bigint,
    subject_public_id text, scopes text[]
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT NULL::uuid, NULL::text, NULL::bigint, NULL::text, NULL::text[] WHERE false
$$;
REVOKE ALL ON FUNCTION iam_private.create_testing_actor_login(uuid, bigint, text, uuid, uuid, bigint) FROM PUBLIC;
