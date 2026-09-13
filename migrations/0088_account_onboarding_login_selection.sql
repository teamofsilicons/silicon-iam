-- Account-level organization creation/joining is available before membership.
-- Preserve the original nonempty selector and require a verified app's current
-- onboarding approval plus a live direct Carbon session for an empty selection.
-- User consent is validated against this application's exact policy/version by
-- the single, batch, and bundle issuance handlers before this function runs.
CREATE FUNCTION iam_private.lock_account_login_organization_selection(
    p_subject_id uuid, p_session_id uuid, p_org_ids text[], p_application_id uuid
)
RETURNS uuid[]
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF p_subject_id IS NULL OR p_session_id IS NULL OR p_org_ids IS NULL
       OR p_application_id IS NULL
       OR p_subject_id IS DISTINCT FROM iam_private.current_principal_id()
       OR iam_private.current_application_id() IS NOT NULL
       OR cardinality(p_org_ids) NOT BETWEEN 0 AND 1000 THEN
        RAISE EXCEPTION 'login_selection_forbidden' USING ERRCODE = '42501';
    END IF;
    IF cardinality(p_org_ids) > 0 THEN
        RETURN iam_private.lock_login_organization_selection(
            p_subject_id, p_session_id, p_org_ids
        );
    END IF;

    -- Match application administration's lock order before locking the subject.
    PERFORM application.id
    FROM iam.applications application
    JOIN iam.principals client ON client.id = application.id
      AND client.kind = 'application' AND client.status = 'active'
    WHERE application.id = p_application_id AND application.review_status = 'verified'
      AND application.deleted_at IS NULL
    FOR SHARE OF application, client;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'login_selection_forbidden' USING ERRCODE = '42501';
    END IF;
    PERFORM approved.scope FROM iam.application_approved_scopes approved
    WHERE approved.application_id = p_application_id AND approved.revoked_at IS NULL
      AND approved.scope IN ('organizations.create', 'organizations.join')
    ORDER BY approved.scope FOR SHARE OF approved;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'login_selection_forbidden' USING ERRCODE = '42501';
    END IF;
    PERFORM session.id FROM iam.authentication_sessions session
    JOIN iam.principals subject ON subject.id = session.subject_principal_id
      AND subject.kind = 'carbon' AND subject.status = 'active'
      AND subject.auth_epoch = session.subject_auth_epoch
    JOIN iam.carbons carbon ON carbon.id = subject.id AND carbon.deleted_at IS NULL
    WHERE session.id = p_session_id AND session.subject_principal_id = p_subject_id
      AND session.subject_kind = 'carbon' AND session.status = 'active'
      AND session.idle_expires_at > clock_timestamp()
      AND session.absolute_expires_at > clock_timestamp()
    FOR SHARE OF session, subject, carbon;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'login_selection_forbidden' USING ERRCODE = '42501';
    END IF;
    RETURN '{}'::uuid[];
END;
$$;
REVOKE ALL ON FUNCTION iam_private.lock_account_login_organization_selection(uuid, uuid, text[], uuid) FROM PUBLIC;

DO $grant_runtime_api$
BEGIN
    IF pg_catalog.to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION iam_private.lock_account_login_organization_selection(uuid, uuid, text[], uuid)
            TO silicon_iam_api;
    END IF;
END;
$grant_runtime_api$;
