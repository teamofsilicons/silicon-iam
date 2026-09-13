-- Test-only login: an authenticated test Application may select an existing
-- actor in its verified test world. No implementation exists in production.
ALTER TABLE iam.authentication_sessions DROP CONSTRAINT authentication_sessions_method;
ALTER TABLE iam.authentication_sessions ADD CONSTRAINT authentication_sessions_method
CHECK (authentication_method IN (
    'email_otp', 'phone_otp', 'silicon_credential',
    'workos_sso', 'refresh_token', 'testing_actor_id'
)) NOT VALID;

CREATE OR REPLACE FUNCTION iam_private.create_testing_actor_login(
    p_application_id uuid, p_application_epoch bigint, p_public_id text,
    p_session_id uuid, p_consent_id uuid, p_lifetime_seconds bigint
)
RETURNS TABLE (
    principal_id uuid, subject_kind text, subject_auth_epoch bigint,
    subject_public_id text, scopes text[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    actor record;
    selected_memberships uuid[];
    approved_scopes text[];
BEGIN
    IF iam_private.current_testing_environment_id() IS NULL
       OR iam_private.current_application_id() IS DISTINCT FROM p_application_id
       OR iam_private.current_principal_id() IS DISTINCT FROM p_application_id
       OR p_lifetime_seconds IS NULL OR p_lifetime_seconds NOT BETWEEN 1 AND 77760000
       OR p_public_id IS NULL OR NOT (
          p_public_id ~ '^[a-z1-9_-]{3,30}$'
          OR p_public_id ~ '^[a-z0-9_-]{3,50}:[a-z0-9_-]{3,50}$'
       ) THEN
        RETURN;
    END IF;
    IF iam_private.lock_current_application_client(p_application_id, p_application_epoch) IS NULL THEN
        RETURN;
    END IF;
    SELECT p.id, p.kind::text AS kind, p.auth_epoch,
           COALESCE(c.carbon_id, s.global_silicon_id) AS public_id
    INTO actor
    FROM iam.principals p
    LEFT JOIN iam.carbons c ON c.id = p.id AND p.kind = 'carbon'
    LEFT JOIN iam.silicons s ON s.id = p.id AND p.kind = 'silicon'
    WHERE p.status = 'active'
      AND ((p.kind = 'carbon' AND c.carbon_id = p_public_id)
        OR (p.kind = 'silicon' AND s.global_silicon_id = p_public_id
            AND s.provisioning_status = 'active' AND EXISTS (
                SELECT 1 FROM iam.organization_memberships m
                JOIN iam.organizations o ON o.id = m.organization_id AND o.status = 'active'
                WHERE m.id = s.membership_id AND m.principal_id = p.id AND m.status = 'active'
            )))
    FOR SHARE OF p;
    IF NOT FOUND THEN RETURN; END IF;

    -- Test ID login selects current active organizations only. New memberships
    -- do not silently extend a session; introspection rechecks each selection.
    SELECT COALESCE(array_agg(m.id ORDER BY m.id), '{}'::uuid[])
    INTO selected_memberships
    FROM iam.organization_memberships m
    JOIN iam.organizations o ON o.id = m.organization_id AND o.status = 'active'
    WHERE m.principal_id = actor.id AND m.status = 'active';
    SELECT COALESCE(array_agg(approved.scope ORDER BY approved.scope), '{}'::text[])
    INTO approved_scopes FROM iam_private.locked_application_approved_scopes(p_application_id) approved;

    INSERT INTO iam.authentication_sessions (
        id, subject_principal_id, subject_kind, authentication_method,
        assurance_level, subject_auth_epoch, idle_expires_at, absolute_expires_at
    ) VALUES (p_session_id, actor.id, actor.kind::iam.principal_kind,
        'testing_actor_id', 1, actor.auth_epoch,
        transaction_timestamp() + p_lifetime_seconds * interval '1 second',
        transaction_timestamp() + p_lifetime_seconds * interval '1 second');
    INSERT INTO iam.oauth_consent_grants (
        id, application_id, subject_principal_id, subject_kind,
        parent_authentication_session_id, selected_membership_ids
    ) VALUES (p_consent_id, p_application_id, actor.id, actor.kind::iam.principal_kind,
        p_session_id, selected_memberships);
    INSERT INTO iam.oauth_consent_grant_scopes (consent_grant_id, scope)
        SELECT p_consent_id, scope FROM unnest(approved_scopes) scope;
    RETURN QUERY SELECT actor.id, actor.kind, actor.auth_epoch, actor.public_id, approved_scopes;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.create_testing_actor_login(uuid, bigint, text, uuid, uuid, bigint) FROM PUBLIC;
SELECT iam_private.reconcile_testing_environment_security();
