-- Finish consent-bound self disclosure for unscoped introspection.
CREATE OR REPLACE FUNCTION iam_private.list_current_application_authorizations(
    p_access_token_id uuid,
    p_subject_principal_id uuid,
    p_audience_application_id uuid,
    p_audience_auth_epoch bigint
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    authorizations jsonb;
BEGIN
    IF p_access_token_id IS NULL OR p_subject_principal_id IS NULL
       OR p_audience_application_id IS NULL OR p_audience_auth_epoch IS NULL
       OR p_subject_principal_id IS DISTINCT FROM iam_private.current_principal_id()
       OR p_audience_application_id IS DISTINCT FROM iam_private.current_application_id()
       OR iam_private.current_organization_id() IS NOT NULL THEN
        RAISE EXCEPTION 'application_authorization_context_forbidden'
            USING ERRCODE = '42501';
    END IF;

    -- Administration locks applications before scopes and revocations. The
    -- issuer and the audience are the same application on a bearer listing.
    PERFORM application.id
    FROM iam.applications AS application
    JOIN iam.principals AS principal ON principal.id = application.id
    WHERE application.id = p_audience_application_id
    FOR SHARE OF application, principal;

    -- The bearer chain, minus any organization. Locked and rechecked here so a
    -- dead token is reported as inactive rather than as a member of nothing.
    PERFORM token.id
    FROM iam.access_tokens AS token
    JOIN iam.principals AS subject
      ON subject.id = token.subject_principal_id AND subject.kind = token.subject_kind
     AND subject.status = 'active' AND subject.auth_epoch = token.subject_auth_epoch
    JOIN iam.authentication_sessions AS session
      ON session.id = token.authentication_session_id
     AND session.subject_principal_id = subject.id AND session.subject_kind = subject.kind
     AND session.subject_auth_epoch = subject.auth_epoch AND session.status = 'active'
     AND session.idle_expires_at > clock_timestamp()
     AND session.absolute_expires_at > clock_timestamp()
    JOIN iam.applications AS audience
      ON audience.id = p_audience_application_id
     AND audience.id = token.client_application_id
     AND audience.id = token.audience_application_id
     AND audience.app_id = token.audience
     AND audience.review_status = 'verified' AND audience.deleted_at IS NULL
    JOIN iam.principals AS audience_principal
      ON audience_principal.id = audience.id AND audience_principal.kind = 'application'
     AND audience_principal.status = 'active'
     AND audience_principal.auth_epoch = p_audience_auth_epoch
     AND audience_principal.auth_epoch = token.client_auth_epoch
    WHERE token.id = p_access_token_id
      AND token.subject_principal_id = p_subject_principal_id
      AND token.token_class = 'application_access'
      AND token.organization_id IS NULL AND token.membership_id IS NULL
      AND token.revoked_at IS NULL
      AND token.expires_at > clock_timestamp()
    FOR SHARE OF token, subject, session, audience, audience_principal;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    WITH approved AS MATERIALIZED (
        SELECT scope
        FROM iam_private.locked_application_approved_scopes(p_audience_application_id)
    ),
    consented AS MATERIALIZED (
        SELECT granted.scope
        FROM iam.access_tokens AS token
        JOIN iam.oauth_consent_grants AS consent
          ON consent.application_id = token.client_application_id
         AND consent.subject_principal_id = token.subject_principal_id
         AND consent.subject_kind = token.subject_kind
         AND consent.parent_authentication_session_id = token.authentication_session_id
         AND consent.organization_id IS NOT DISTINCT FROM token.organization_id
         AND consent.membership_id IS NOT DISTINCT FROM token.membership_id
         AND consent.status = 'active'
        JOIN iam.oauth_consent_grant_scopes AS granted
          ON granted.consent_grant_id = consent.id
        WHERE token.id = p_access_token_id
        FOR SHARE OF consent, granted
    ),
    effective AS MATERIALIZED (
        SELECT ARRAY(
            SELECT token_scope.scope FROM iam.access_token_scopes AS token_scope
            JOIN approved ON approved.scope = token_scope.scope
            JOIN consented ON consented.scope = token_scope.scope
            WHERE token_scope.access_token_id = p_access_token_id
            ORDER BY token_scope.scope
        ) AS scopes
    ),
    reachable AS (
        SELECT organization.id AS organization_id, organization.org_id,
               membership.id AS membership_id, membership.version,
               membership.authz_epoch, membership.org_role,
               subject.id AS subject_id, subject.kind AS subject_kind,
               COALESCE(carbon.carbon_id, silicon.global_silicon_id) AS public_id,
               audience.app_id AS audience_app_id, effective.scopes
        FROM effective
        CROSS JOIN iam.principals AS subject
        JOIN iam.organization_memberships AS membership
          ON membership.principal_id = subject.id
         AND membership.principal_kind = subject.kind
         AND membership.status = 'active'
        JOIN iam.organizations AS organization
          ON organization.id = membership.organization_id AND organization.status = 'active'
        JOIN iam.applications AS audience
          ON audience.id = p_audience_application_id
        LEFT JOIN iam.carbons AS carbon
          ON carbon.id = subject.id AND subject.kind = 'carbon' AND carbon.deleted_at IS NULL
        LEFT JOIN iam.silicons AS silicon
          ON silicon.id = subject.id AND subject.kind = 'silicon'
         AND silicon.organization_id = organization.id AND silicon.membership_id = membership.id
         AND silicon.provisioning_status = 'active' AND silicon.deleted_at IS NULL
        WHERE subject.id = p_subject_principal_id
          AND iam_private.application_token_allows_membership(p_access_token_id, membership.id)
          AND (carbon.id IS NOT NULL OR silicon.id IS NOT NULL)
        ORDER BY organization.org_id
        FOR SHARE OF membership, organization
    )
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'principal_id', reachable.subject_id,
        'actor_type', reachable.subject_kind::text,
        'public_id', reachable.public_id,
        'organization_id', reachable.organization_id,
        'org_id', reachable.org_id,
        'membership_id', reachable.membership_id,
        'membership_version', reachable.version,
        'authorization_epoch', reachable.authz_epoch,
        'audience', reachable.audience_app_id,
        'testing_environment_id', NULLIF(current_setting('iam.testing_environment_id', true), ''),
        'scopes', to_jsonb(reachable.scopes),
        'org_role', CASE WHEN 'self.membership.read' = ANY(reachable.scopes)
            THEN reachable.org_role::text ELSE NULL END,
        'tags', CASE WHEN 'self.tags.read' = ANY(reachable.scopes) THEN (
            SELECT COALESCE(jsonb_agg(jsonb_build_object('id', tag.id, 'name', tag.name)
                ORDER BY tag.id), '[]'::jsonb)
            FROM iam.membership_tags AS assignment
            JOIN iam.organization_tags AS tag
              ON tag.organization_id = assignment.organization_id
             AND tag.id = assignment.tag_id AND tag.status = 'active'
            WHERE assignment.organization_id = reachable.organization_id
              AND assignment.membership_id = reachable.membership_id
        ) ELSE NULL END
    ) ORDER BY reachable.org_id), '[]'::jsonb)
    INTO authorizations
    FROM reachable;

    RETURN authorizations;
END;
$$;

-- Protected service reads expose accepted destination URLs, never signing keys.
CREATE FUNCTION iam_private.honeycomb_webhook_destinations(p_service uuid,p_app text)
RETURNS TABLE(id uuid,application_id uuid,status text,url_ciphertext bytea,url_nonce bytea,encryption_key_version smallint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 SELECT endpoint.id,endpoint.application_id,endpoint.status::text,endpoint.url_ciphertext,endpoint.url_nonce,endpoint.encryption_key_version
 FROM iam.application_webhook_endpoints endpoint JOIN iam.applications app ON app.id=endpoint.application_id
 WHERE app.app_id=p_app AND app.deleted_at IS NULL AND endpoint.status IN ('active','pending_review')
 AND EXISTS(SELECT 1 FROM iam.applications WHERE id=p_service)
 ORDER BY endpoint.created_at,endpoint.id;
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_webhook_destinations(uuid,text) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_webhook_destinations(uuid,text) TO silicon_iam_api;
END IF; END $$;
