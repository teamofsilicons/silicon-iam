-- Organization authority is explicit and additive within one parent IAM login.
-- Membership IDs are a fixed allowlist, not a wildcard for future memberships.
-- Existing single-org consent preserves its scope. Old all-org consent has no
-- evidence of user selection: it gets no organization access until reauthorized.
ALTER TABLE iam.oauth_consent_grants
    ADD COLUMN selected_membership_ids uuid[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT oauth_selected_memberships_no_nulls
        CHECK (array_position(selected_membership_ids, NULL) IS NULL);

UPDATE iam.oauth_consent_grants
SET selected_membership_ids = ARRAY[membership_id]
WHERE membership_id IS NOT NULL;

-- Ordinary members must be able to consent without membership UPDATE rights.
-- Lock under a narrow definer; the testing overlay keeps its tenant isolation.
CREATE FUNCTION iam_private.lock_login_organization_selection(
    p_subject_id uuid, p_session_id uuid, p_org_ids text[]
)
RETURNS uuid[]
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE selected uuid[];
BEGIN
    IF p_subject_id IS DISTINCT FROM iam_private.current_principal_id()
       OR iam_private.current_application_id() IS NOT NULL
       OR cardinality(p_org_ids) NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION 'login_selection_forbidden' USING ERRCODE = '42501';
    END IF;
    PERFORM session.id FROM iam.authentication_sessions session
    JOIN iam.principals subject ON subject.id = session.subject_principal_id
      AND subject.auth_epoch = session.subject_auth_epoch AND subject.status = 'active'
    WHERE session.id = p_session_id AND session.subject_principal_id = p_subject_id
      AND session.status = 'active' AND session.idle_expires_at > clock_timestamp()
      AND session.absolute_expires_at > clock_timestamp()
    FOR SHARE OF session, subject;
    IF NOT FOUND THEN RETURN '{}'::uuid[]; END IF;
    SELECT COALESCE(array_agg(id ORDER BY id), '{}'::uuid[]) INTO selected FROM (
        SELECT member.id FROM iam.organization_memberships member
        JOIN iam.organizations organization ON organization.id = member.organization_id
          AND organization.status = 'active'
        WHERE member.principal_id = p_subject_id AND member.status = 'active'
          AND organization.org_id = ANY(p_org_ids)
        ORDER BY member.id FOR SHARE OF member, organization
    ) locked;
    RETURN selected;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.lock_login_organization_selection(uuid, uuid, text[]) FROM PUBLIC;

CREATE FUNCTION iam_private.application_token_allows_membership(
    p_access_token_id uuid, p_membership_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT EXISTS (
        SELECT 1 FROM iam.access_tokens token
        JOIN iam.oauth_consent_grants consent
          ON consent.application_id = token.client_application_id
         AND consent.subject_principal_id = token.subject_principal_id
         AND consent.subject_kind = token.subject_kind
         AND consent.parent_authentication_session_id = token.authentication_session_id
         AND consent.organization_id IS NOT DISTINCT FROM token.organization_id
         AND consent.membership_id IS NOT DISTINCT FROM token.membership_id
         AND consent.status = 'active'
        JOIN iam.organization_memberships membership
          ON membership.id = p_membership_id
         AND membership.id = ANY(consent.selected_membership_ids)
         AND membership.principal_id = token.subject_principal_id
         AND membership.principal_kind = token.subject_kind
         AND membership.status = 'active'
        JOIN iam.organizations organization
          ON organization.id = membership.organization_id AND organization.status = 'active'
        JOIN iam.principals subject
          ON subject.id = token.subject_principal_id AND subject.status = 'active'
         AND subject.auth_epoch = token.subject_auth_epoch
        JOIN iam.authentication_sessions session
          ON session.id = token.authentication_session_id AND session.status = 'active'
         AND session.subject_principal_id = subject.id
         AND session.subject_auth_epoch = subject.auth_epoch
         AND session.idle_expires_at > statement_timestamp()
         AND session.absolute_expires_at > statement_timestamp()
        JOIN iam.applications application
          ON application.id = token.client_application_id
         AND application.id = token.audience_application_id
         AND application.app_id = token.audience
         AND application.review_status = 'verified' AND application.deleted_at IS NULL
        JOIN iam.principals client
          ON client.id = application.id AND client.status = 'active'
         AND client.auth_epoch = token.client_auth_epoch
        WHERE token.id = p_access_token_id AND token.token_class = 'application_access'
          AND token.revoked_at IS NULL AND token.expires_at > statement_timestamp()
          AND (iam_private.current_principal_id() = subject.id
               OR (iam_private.current_principal_id() = application.id
                   AND iam_private.current_application_id() = application.id))
          AND (token.organization_id IS NULL OR (
              token.organization_id = membership.organization_id
              AND token.membership_id = membership.id
              AND token.membership_authz_epoch = membership.authz_epoch))
    );
$$;
REVOKE ALL ON FUNCTION iam_private.application_token_allows_membership(uuid, uuid) FROM PUBLIC;

DO $grant_runtime_api$
BEGIN
    IF pg_catalog.to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION iam_private.application_token_allows_membership(uuid, uuid)
            TO silicon_iam_api;
        GRANT EXECUTE ON FUNCTION iam_private.lock_login_organization_selection(uuid, uuid, text[])
            TO silicon_iam_api;
    END IF;
END;
$grant_runtime_api$;

CREATE OR REPLACE FUNCTION iam_private.get_current_application_authorization(
    p_access_token_id uuid,
    p_subject_principal_id uuid,
    p_organization_id uuid,
    p_membership_id uuid,
    p_audience_application_id uuid,
    p_audience_auth_epoch bigint,
    p_proof_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    v_issuer_application_id uuid;
    subject_epoch bigint;
    issuer_epoch bigint;
    membership_epoch bigint;
    proof_consumed_at timestamptz;
    authorization_snapshot jsonb;
BEGIN
    IF p_access_token_id IS NULL OR p_subject_principal_id IS NULL
       OR p_organization_id IS NULL OR p_membership_id IS NULL
       OR p_audience_application_id IS NULL OR p_audience_auth_epoch IS NULL
       OR p_subject_principal_id IS DISTINCT FROM iam_private.current_principal_id()
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id()
       OR p_audience_application_id IS DISTINCT FROM iam_private.current_application_id() THEN
        RAISE EXCEPTION 'application_authorization_context_forbidden'
            USING ERRCODE = '42501';
    END IF;

    -- Resolve only the exact supplied chain. A bound token must name this
    -- organization; an unscoped token reaches every organization it can prove
    -- an active membership in, and the locking read below rechecks that
    -- membership before returning any authority.
    SELECT token.client_application_id INTO v_issuer_application_id
    FROM iam.access_tokens AS token
    WHERE token.id = p_access_token_id
      AND token.subject_principal_id = p_subject_principal_id
      AND (
          (token.organization_id = p_organization_id
           AND token.membership_id = p_membership_id)
          OR (token.organization_id IS NULL AND token.membership_id IS NULL)
      )
      AND iam_private.application_token_allows_membership(token.id, p_membership_id)
      AND token.token_class = 'application_access'
      AND (p_proof_id IS NOT NULL OR token.client_application_id = p_audience_application_id);
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    -- Administration locks applications before scopes and revocations.
    -- Follow that order, sorting the two applications in a delegated request.
    PERFORM application.id
    FROM iam.applications AS application
    JOIN iam.principals AS principal ON principal.id = application.id
    WHERE application.id = ANY(ARRAY[v_issuer_application_id, p_audience_application_id])
    ORDER BY application.id
    FOR SHARE OF application, principal;

    WITH approved AS MATERIALIZED (
        SELECT scope
        FROM iam_private.locked_application_approved_scopes(p_audience_application_id)
    )
    SELECT jsonb_build_object(
        'principal_id', subject.id,
        'actor_type', subject.kind::text,
        'public_id', COALESCE(carbon.carbon_id, silicon.global_silicon_id),
        'organization_id', organization.id,
        'org_id', organization.org_id,
        'membership_id', membership.id,
        'membership_version', membership.version,
        'authorization_epoch', membership.authz_epoch,
        'audience', audience.app_id,
        'testing_environment_id', NULLIF(current_setting('iam.testing_environment_id', true), ''),
        'scopes', to_jsonb(effective.scopes),
        'org_role', CASE WHEN 'roles.read' = ANY(effective.scopes)
            THEN membership.org_role::text ELSE NULL END,
        'tags', CASE WHEN 'memberships.read' = ANY(effective.scopes) THEN (
            SELECT COALESCE(jsonb_agg(jsonb_build_object('id', tag.id, 'name', tag.name)
                ORDER BY tag.id), '[]'::jsonb)
            FROM iam.membership_tags AS assignment
            JOIN iam.organization_tags AS tag
              ON tag.organization_id = assignment.organization_id
             AND tag.id = assignment.tag_id AND tag.status = 'active'
            WHERE assignment.organization_id = membership.organization_id
              AND assignment.membership_id = membership.id
        ) ELSE NULL END
    ), subject.auth_epoch, issuer_principal.auth_epoch, membership.authz_epoch
    INTO authorization_snapshot, subject_epoch, issuer_epoch, membership_epoch
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
    JOIN iam.organization_memberships AS membership
      ON membership.id = p_membership_id AND membership.organization_id = p_organization_id
     AND membership.principal_id = subject.id AND membership.principal_kind = subject.kind
     AND membership.status = 'active'
     AND (
         token.organization_id IS NULL
         OR (membership.id = token.membership_id
             AND membership.organization_id = token.organization_id
             AND membership.authz_epoch = token.membership_authz_epoch)
     )
    JOIN iam.organizations AS organization
      ON organization.id = membership.organization_id AND organization.status = 'active'
    JOIN iam.applications AS issuer
      ON issuer.id = token.client_application_id AND issuer.id = token.audience_application_id
     AND issuer.id = v_issuer_application_id AND issuer.app_id = token.audience
     AND issuer.review_status = 'verified' AND issuer.deleted_at IS NULL
    JOIN iam.principals AS issuer_principal
      ON issuer_principal.id = issuer.id AND issuer_principal.kind = 'application'
     AND issuer_principal.status = 'active' AND issuer_principal.auth_epoch = token.client_auth_epoch
    JOIN iam.applications AS audience
      ON audience.id = p_audience_application_id
     AND audience.review_status = 'verified' AND audience.deleted_at IS NULL
    JOIN iam.principals AS audience_principal
      ON audience_principal.id = audience.id AND audience_principal.kind = 'application'
     AND audience_principal.status = 'active' AND audience_principal.auth_epoch = p_audience_auth_epoch
    LEFT JOIN iam.carbons AS carbon
      ON carbon.id = subject.id AND subject.kind = 'carbon' AND carbon.deleted_at IS NULL
    LEFT JOIN iam.silicons AS silicon
      ON silicon.id = subject.id AND subject.kind = 'silicon'
     AND silicon.organization_id = organization.id AND silicon.membership_id = membership.id
     AND silicon.provisioning_status = 'active' AND silicon.deleted_at IS NULL
    CROSS JOIN LATERAL (
        SELECT ARRAY(
            SELECT token_scope.scope FROM iam.access_token_scopes AS token_scope
            JOIN approved ON approved.scope = token_scope.scope
            WHERE token_scope.access_token_id = token.id ORDER BY token_scope.scope
        ) AS scopes
    ) AS effective
    WHERE token.id = p_access_token_id AND subject.id = p_subject_principal_id
      AND organization.id = p_organization_id AND membership.id = p_membership_id
      AND token.token_class = 'application_access' AND token.revoked_at IS NULL
      AND token.expires_at > clock_timestamp()
      AND (carbon.id IS NOT NULL OR silicon.id IS NOT NULL)
      AND (
          (p_proof_id IS NULL AND issuer.id = audience.id)
          OR (p_proof_id IS NOT NULL
              AND issuer.organization_id = organization.id
              AND audience.organization_id = organization.id
              AND EXISTS (SELECT 1 FROM iam.access_token_scopes AS delegated
                  WHERE delegated.access_token_id = token.id AND delegated.scope = 'obo.issue'))
      )
    FOR SHARE OF token, subject, session, membership, organization,
                 issuer, issuer_principal, audience, audience_principal;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    IF p_proof_id IS NOT NULL THEN
        -- Another application's parent token alone is never sufficient.
        -- Require this audience's exact persisted proof, lock it after its
        -- parent, and lock the endpoint until the caller consumes the proof.
        SELECT proof.consumed_at INTO proof_consumed_at
        FROM iam.obo_proofs AS proof
        JOIN iam.application_obo_endpoints AS endpoint
          ON endpoint.organization_id = proof.organization_id
         AND endpoint.application_id = proof.audience_application_id
         AND endpoint.endpoint_id = proof.endpoint_id
         AND endpoint.path = proof.request_path
         AND endpoint.version = proof.endpoint_version
         AND endpoint.status = 'active'
        WHERE proof.id = p_proof_id
          AND proof.parent_access_token_id = p_access_token_id
          AND proof.subject_principal_id = p_subject_principal_id
          AND proof.subject_kind::text = authorization_snapshot->>'actor_type'
          AND proof.organization_id = p_organization_id
          AND proof.membership_id = p_membership_id
          AND proof.issuer_application_id = v_issuer_application_id
          AND proof.audience_application_id = p_audience_application_id
          AND proof.subject_auth_epoch = subject_epoch
          AND proof.issuer_auth_epoch = issuer_epoch
          AND proof.membership_authz_epoch = membership_epoch
          AND proof.audience_auth_epoch = p_audience_auth_epoch
          AND proof.revoked_at IS NULL
          AND proof.expires_at > clock_timestamp()
        FOR UPDATE OF proof FOR SHARE OF endpoint;
        IF NOT FOUND THEN
            RETURN NULL;
        END IF;
        IF proof_consumed_at IS NOT NULL THEN
            RAISE EXCEPTION 'obo_proof_consumed' USING ERRCODE = 'P0001';
        END IF;
    END IF;

    RETURN authorization_snapshot;
END;
$$;

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
    effective AS MATERIALIZED (
        SELECT ARRAY(
            SELECT token_scope.scope FROM iam.access_token_scopes AS token_scope
            JOIN approved ON approved.scope = token_scope.scope
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
        'org_role', CASE WHEN 'roles.read' = ANY(reachable.scopes)
            THEN reachable.org_role::text ELSE NULL END,
        'tags', CASE WHEN 'memberships.read' = ANY(reachable.scopes) THEN (
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

CREATE OR REPLACE FUNCTION iam_private.lock_current_application_obo_exchange_authority(
    p_issuer_application_id uuid,
    p_issuer_auth_epoch bigint,
    p_parent_access_token_id uuid,
    p_subject_principal_id uuid,
    p_subject_kind iam.principal_kind,
    p_organization_id uuid,
    p_membership_id uuid,
    p_audience_app_id text,
    p_endpoint_id text
)
RETURNS TABLE (
    audience_application_id uuid,
    endpoint_path text,
    metadata_definition jsonb,
    endpoint_version bigint,
    audience_auth_epoch bigint,
    subject_auth_epoch bigint,
    membership_authz_epoch bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF p_issuer_application_id IS NULL
       OR p_issuer_application_id IS DISTINCT FROM iam_private.current_application_id()
       OR p_issuer_application_id IS DISTINCT FROM iam_private.current_principal_id()
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id() THEN
        RAISE EXCEPTION 'application_obo_exchange_authority_forbidden'
            USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    WITH wall_clock AS MATERIALIZED (
        SELECT clock_timestamp() AS value
    )
    SELECT audience.id,
           endpoint.path,
           endpoint.metadata_definition,
           endpoint.version,
           audience_principal.auth_epoch,
           subject_principal.auth_epoch,
           membership.authz_epoch
    FROM wall_clock
    JOIN iam.organizations AS organization
      ON organization.id = p_organization_id
     AND organization.status = 'active'
    JOIN iam.applications AS issuer
      ON issuer.id = p_issuer_application_id
     AND issuer.organization_id = organization.id
     AND issuer.review_status = 'verified'
     AND issuer.deleted_at IS NULL
    JOIN iam.principals AS issuer_principal
      ON issuer_principal.id = issuer.id
     AND issuer_principal.kind = 'application'
     AND issuer_principal.status = 'active'
     AND issuer_principal.auth_epoch = p_issuer_auth_epoch
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = organization.id
     AND membership.id = p_membership_id
     AND membership.principal_id = p_subject_principal_id
     AND membership.principal_kind = p_subject_kind
     AND membership.status = 'active'
    JOIN iam.principals AS subject_principal
      ON subject_principal.id = membership.principal_id
     AND subject_principal.kind = membership.principal_kind
     AND subject_principal.status = 'active'
    JOIN iam.access_tokens AS parent
      ON parent.id = p_parent_access_token_id
     AND parent.token_class = 'application_access'
     AND iam_private.application_token_allows_membership(parent.id, membership.id)
     AND parent.client_application_id = issuer.id
     AND parent.audience_application_id = issuer.id
     AND parent.audience = issuer.app_id
     AND parent.subject_principal_id = subject_principal.id
     AND parent.subject_kind = subject_principal.kind
     AND (
         (parent.organization_id = organization.id
          AND parent.membership_id = membership.id
          AND parent.membership_authz_epoch = membership.authz_epoch)
         OR (parent.organization_id IS NULL
             AND parent.membership_id IS NULL
             AND parent.membership_authz_epoch IS NULL)
     )
     AND parent.subject_auth_epoch = subject_principal.auth_epoch
     AND parent.client_auth_epoch = issuer_principal.auth_epoch
     AND parent.revoked_at IS NULL
     AND parent.expires_at > wall_clock.value
    JOIN iam.authentication_sessions AS authentication_session
      ON authentication_session.id = parent.authentication_session_id
     AND authentication_session.subject_principal_id = subject_principal.id
     AND authentication_session.subject_kind = subject_principal.kind
     AND authentication_session.subject_auth_epoch = subject_principal.auth_epoch
     AND authentication_session.status = 'active'
     AND authentication_session.idle_expires_at > wall_clock.value
     AND authentication_session.absolute_expires_at > wall_clock.value
    JOIN iam.access_token_scopes AS parent_scope
      ON parent_scope.access_token_id = parent.id
     AND parent_scope.scope = 'obo.issue'
    JOIN iam.applications AS audience
      ON audience.app_id = p_audience_app_id
     AND audience.organization_id = organization.id
     AND audience.review_status = 'verified'
     AND audience.deleted_at IS NULL
    JOIN iam.principals AS audience_principal
      ON audience_principal.id = audience.id
     AND audience_principal.kind = 'application'
     AND audience_principal.status = 'active'
    JOIN iam.application_obo_endpoints AS endpoint
      ON endpoint.organization_id = organization.id
     AND endpoint.application_id = audience.id
     AND endpoint.endpoint_id = p_endpoint_id
     AND endpoint.status = 'active'
    FOR SHARE OF organization, issuer, issuer_principal, membership,
                 subject_principal, parent, authentication_session, parent_scope,
                 audience, audience_principal, endpoint;
END;
$$;

CREATE OR REPLACE FUNCTION iam_private.list_organization_member_webhook_authorizations(
    p_organization_id uuid,
    p_membership_ids uuid[],
    p_event_occurred_at timestamptz
)
RETURNS TABLE (
    application_id uuid,
    membership_id uuid,
    scope text,
    authorized_after boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF p_organization_id IS NULL
       OR p_membership_ids IS NULL
       OR cardinality(p_membership_ids) NOT BETWEEN 1 AND 100000
       OR p_event_occurred_at IS NULL
       OR iam_private.current_principal_id() IS NULL
       OR NOT EXISTS (
            SELECT 1
            FROM iam.organization_memberships AS actor_membership
            JOIN iam.principals AS actor_principal
              ON actor_principal.id = actor_membership.principal_id
             AND actor_principal.kind = actor_membership.principal_kind
             AND actor_principal.status = 'active'
            WHERE actor_membership.organization_id = p_organization_id
              AND actor_membership.principal_id = iam_private.current_principal_id()
              AND actor_membership.status = 'active'
       ) THEN
        RAISE EXCEPTION 'organization member webhook authorization scope is invalid'
            USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT
        consent.application_id,
        membership.id,
        consent_scope.scope,
        (
            consent.status = 'active'
            AND approved_scope.revoked_at IS NULL
            AND membership.status = 'active'
            AND subject_principal.status = 'active'
        ) AS authorized_after
    FROM iam.organization_memberships AS membership
    JOIN iam.principals AS subject_principal
      ON subject_principal.id = membership.principal_id
     AND subject_principal.kind = membership.principal_kind
    JOIN iam.oauth_consent_grants AS consent
      ON consent.subject_principal_id = membership.principal_id
     AND consent.subject_kind = membership.principal_kind
     AND membership.id = ANY(consent.selected_membership_ids)
    JOIN iam.oauth_consent_grant_scopes AS consent_scope
      ON consent_scope.consent_grant_id = consent.id
    JOIN iam.application_approved_scopes AS approved_scope
      ON approved_scope.application_id = consent.application_id
     AND approved_scope.scope = consent_scope.scope
    JOIN iam.applications AS application
      ON application.id = consent.application_id
     AND application.review_status = 'verified'
     AND application.deleted_at IS NULL
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
     AND application_principal.status = 'active'
    WHERE membership.organization_id = p_organization_id
      AND membership.id = ANY(p_membership_ids)
      AND (
          consent.status = 'active'
          OR consent.revoked_at >= p_event_occurred_at
      )
      AND (
          approved_scope.revoked_at IS NULL
          OR approved_scope.revoked_at >= p_event_occurred_at
      )
      AND (
          membership.status = 'active'
          OR membership.removed_at >= p_event_occurred_at
          OR membership.suspended_at >= p_event_occurred_at
      )
      AND (
          subject_principal.status = 'active'
          OR subject_principal.deleted_at >= p_event_occurred_at
          OR subject_principal.suspended_at >= p_event_occurred_at
      )
    ORDER BY consent.application_id, membership.id, consent_scope.scope
    FOR SHARE OF membership, subject_principal, consent, consent_scope,
                 approved_scope, application, application_principal;
END;
$$;

CREATE OR REPLACE FUNCTION iam_private.list_worker_application_webhook_recipients(
    p_organization_id uuid,
    p_subject_principal_id uuid,
    p_application_id uuid,
    p_event_occurred_at timestamptz
)
RETURNS TABLE (
    endpoint_id uuid,
    signing_key_id uuid
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT endpoint.id, signing_key.id
    FROM iam.application_webhook_endpoints AS endpoint
    JOIN iam.applications AS application ON application.id = endpoint.application_id
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
    JOIN iam.application_webhook_signing_keys AS signing_key
      ON signing_key.endpoint_id = endpoint.id
     AND signing_key.application_id = application.id
    WHERE endpoint.status = 'active'
      AND (p_organization_id IS NULL
           OR (p_application_id = application.id AND p_organization_id = application.organization_id)
           OR EXISTS (
          SELECT 1 FROM iam.oauth_consent_grants selected
          JOIN iam.organization_memberships granted
            ON granted.id = ANY(selected.selected_membership_ids)
           AND granted.principal_id = selected.subject_principal_id
           AND granted.organization_id = p_organization_id
          WHERE selected.application_id = application.id
            AND (p_subject_principal_id IS NULL OR selected.subject_principal_id = p_subject_principal_id)
            AND (selected.status = 'active' OR selected.revoked_at >= p_event_occurred_at)
            AND (granted.status = 'active' OR granted.removed_at >= p_event_occurred_at
                 OR granted.suspended_at >= p_event_occurred_at)
      ))
      AND signing_key.status IN ('active', 'retiring')
      AND (signing_key.retires_at IS NULL OR signing_key.retires_at > transaction_timestamp())
      AND application.review_status = 'verified'
      AND application_principal.status = 'active'
      AND (
          application.id = p_application_id
          OR EXISTS (
              SELECT 1
              FROM iam.access_tokens AS token
              JOIN iam.principals AS subject_principal
                ON subject_principal.id = token.subject_principal_id
               AND subject_principal.kind = token.subject_kind
               AND (
                   subject_principal.auth_epoch = token.subject_auth_epoch
                   OR subject_principal.suspended_at >= p_event_occurred_at
                   OR subject_principal.deleted_at >= p_event_occurred_at
               )
              LEFT JOIN iam.organization_memberships AS membership
                ON membership.organization_id = token.organization_id
               AND membership.id = token.membership_id
               AND membership.principal_id = token.subject_principal_id
               AND membership.principal_kind = token.subject_kind
              WHERE token.client_application_id = application.id
                AND token.token_class = 'application_access'
                AND token.client_auth_epoch = application_principal.auth_epoch
                AND (token.revoked_at IS NULL OR token.revoked_at >= p_event_occurred_at)
                AND token.created_at <= p_event_occurred_at
                AND token.expires_at > p_event_occurred_at
                AND (p_subject_principal_id IS NULL
                    OR token.subject_principal_id = p_subject_principal_id)
                AND (p_organization_id IS NULL
                    OR token.organization_id = p_organization_id OR token.organization_id IS NULL)
                AND (
                    token.organization_id IS NULL
                    OR (
                        (
                            membership.status = 'active'
                            OR membership.suspended_at >= p_event_occurred_at
                            OR membership.removed_at >= p_event_occurred_at
                        )
                        AND (
                            membership.authz_epoch = token.membership_authz_epoch
                            OR membership.updated_at >= p_event_occurred_at
                        )
                    )
                )
          )
          OR EXISTS (
              -- Refresh families intentionally carry no membership-epoch
              -- snapshot: every rotation revalidates the membership and uses
              -- its then-current epoch. Event-boundary status, not an expired
              -- access-token snapshot, therefore defines refresh authority.
              SELECT 1
              FROM iam.refresh_token_families AS family
              JOIN iam.authentication_sessions AS session
                ON session.id = family.authentication_session_id
               AND session.subject_principal_id = family.subject_principal_id
              JOIN iam.principals AS subject_principal
                ON subject_principal.id = family.subject_principal_id
               AND subject_principal.kind = session.subject_kind
               AND (
                   subject_principal.auth_epoch = session.subject_auth_epoch
                   OR subject_principal.suspended_at >= p_event_occurred_at
                   OR subject_principal.deleted_at >= p_event_occurred_at
               )
              JOIN iam.oauth_consent_grants AS consent
                ON consent.id = family.oauth_consent_grant_id
               AND consent.application_id = family.client_application_id
               AND consent.subject_principal_id = family.subject_principal_id
               AND consent.subject_kind = session.subject_kind
               AND consent.parent_authentication_session_id = family.authentication_session_id
              LEFT JOIN iam.organizations AS organization
                ON organization.id = consent.organization_id
              LEFT JOIN iam.organization_memberships AS membership
                ON membership.organization_id = consent.organization_id
               AND membership.id = consent.membership_id
               AND membership.principal_id = consent.subject_principal_id
               AND membership.principal_kind = consent.subject_kind
              WHERE family.client_application_id = application.id
                AND family.created_at <= p_event_occurred_at
                AND family.absolute_expires_at > p_event_occurred_at
                AND (
                    family.status = 'active'
                    OR family.revoked_at >= p_event_occurred_at
                )
                AND session.created_at <= p_event_occurred_at
                AND session.idle_expires_at > p_event_occurred_at
                AND session.absolute_expires_at > p_event_occurred_at
                AND (
                    session.status = 'active'
                    OR session.revoked_at >= p_event_occurred_at
                )
                AND consent.granted_at <= p_event_occurred_at
                AND (
                    consent.status = 'active'
                    OR consent.revoked_at >= p_event_occurred_at
                )
                AND (p_subject_principal_id IS NULL
                    OR family.subject_principal_id = p_subject_principal_id)
                AND (p_organization_id IS NULL
                    OR EXISTS (SELECT 1 FROM iam.organization_memberships selected_member
                        WHERE selected_member.id = ANY(consent.selected_membership_ids)
                          AND selected_member.organization_id = p_organization_id))
                AND (
                    consent.organization_id IS NULL
                    OR (
                        (
                            organization.status = 'active'
                            OR organization.updated_at >= p_event_occurred_at
                        )
                        AND (
                            membership.status = 'active'
                            OR membership.suspended_at >= p_event_occurred_at
                            OR membership.removed_at >= p_event_occurred_at
                        )
                    )
                )
                AND EXISTS (
                    SELECT 1
                    FROM iam.refresh_tokens AS refresh
                    WHERE refresh.family_id = family.id
                      AND refresh.created_at <= p_event_occurred_at
                      AND refresh.expires_at > p_event_occurred_at
                      AND (refresh.revoked_at IS NULL
                          OR refresh.revoked_at >= p_event_occurred_at)
                      AND (refresh.consumed_at IS NULL
                          OR refresh.consumed_at >= p_event_occurred_at)
                )
          )
      )
$$;

-- Recheck queued/captured deliveries as well as newly generated projections.
CREATE OR REPLACE FUNCTION iam_private.list_worker_captured_application_webhook_recipients(
    p_outbox_event_id uuid
)
RETURNS TABLE (
    endpoint_id uuid,
    signing_key_id uuid
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT endpoint.id, signing_key.id
    FROM iam.application_webhook_event_projections AS projection
    JOIN iam.outbox_events AS event
      ON event.id = projection.outbox_event_id
     AND event.event_type IN (
        'carbon.updated.v1',
        'organization.updated.v1',
        'organization.ownership_transferred.v1',
        'organization.tag_updated.v1',
        'organization.tag_archived.v1',
        'organization.trust.default_updated.v1',
        'organization.trust.rule_created.v1',
        'organization.trust.rule_updated.v1',
        'organization.trust.rule_archived.v1',
        'organization.membership.created.v1',
        'organization.membership.reactivated.v1',
        'organization.membership.removed.v1',
        'organization.membership.updated.v1',
        'organization.membership.authorization_updated.v1',
        'organization.admin.promoted.v1',
        'organization.admin.demoted.v1',
        'organization.silicon.created.v1',
        'organization.silicon.updated.v1',
        'organization.silicon.removed.v1',
        'organization.silicon.credential_rotated.v1'
     )
    JOIN iam.applications AS application
      ON application.id = projection.application_id
     AND application.review_status = 'verified'
     AND application.deleted_at IS NULL
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
     AND application_principal.status = 'active'
    JOIN iam.application_webhook_endpoints AS endpoint
      ON endpoint.application_id = application.id
     AND endpoint.status = 'active'
    JOIN LATERAL (
        SELECT candidate.id
        FROM iam.application_webhook_signing_keys AS candidate
        WHERE candidate.application_id = application.id
          AND candidate.endpoint_id = endpoint.id
          AND candidate.status IN ('active', 'retiring')
          AND (
              candidate.retires_at IS NULL
              OR candidate.retires_at > transaction_timestamp()
          )
        ORDER BY (candidate.status = 'active') DESC, candidate.secret_version DESC
        LIMIT 1
    ) AS signing_key ON true
    WHERE projection.outbox_event_id = p_outbox_event_id
      AND (event.organization_id IS NULL OR EXISTS (
          SELECT 1 FROM iam.oauth_consent_grants consent
          JOIN iam.organization_memberships membership
            ON membership.id = ANY(consent.selected_membership_ids)
           AND membership.principal_id = consent.subject_principal_id
           AND membership.organization_id = event.organization_id
          WHERE consent.application_id = projection.application_id
            AND (consent.status = 'active' OR consent.revoked_at >= event.created_at)
            AND (membership.status = 'active' OR membership.removed_at >= event.created_at
                 OR membership.suspended_at >= event.created_at)
      ))
    ORDER BY endpoint.id
$$;

CREATE OR REPLACE FUNCTION iam_private.get_worker_application_webhook_event_projection(
    p_outbox_event_id uuid,
    p_application_id uuid
)
RETURNS TABLE (
    projection_id uuid,
    payload_ciphertext bytea,
    payload_nonce bytea,
    encryption_key_version smallint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        projection.id,
        projection.payload_ciphertext,
        projection.payload_nonce,
        projection.encryption_key_version
    FROM iam.application_webhook_event_projections AS projection
    JOIN iam.outbox_events AS event
      ON event.id = projection.outbox_event_id
     AND event.event_type IN (
        'carbon.updated.v1',
        'organization.updated.v1',
        'organization.ownership_transferred.v1',
        'organization.tag_updated.v1',
        'organization.tag_archived.v1',
        'organization.trust.default_updated.v1',
        'organization.trust.rule_created.v1',
        'organization.trust.rule_updated.v1',
        'organization.trust.rule_archived.v1',
        'organization.membership.created.v1',
        'organization.membership.reactivated.v1',
        'organization.membership.removed.v1',
        'organization.membership.updated.v1',
        'organization.membership.authorization_updated.v1',
        'organization.admin.promoted.v1',
        'organization.admin.demoted.v1',
        'organization.silicon.created.v1',
        'organization.silicon.updated.v1',
        'organization.silicon.removed.v1',
        'organization.silicon.credential_rotated.v1'
     )
    WHERE projection.outbox_event_id = p_outbox_event_id
      AND (event.organization_id IS NULL OR EXISTS (
          SELECT 1 FROM iam.oauth_consent_grants consent
          JOIN iam.organization_memberships membership
            ON membership.id = ANY(consent.selected_membership_ids)
           AND membership.principal_id = consent.subject_principal_id
           AND membership.organization_id = event.organization_id
          WHERE consent.application_id = projection.application_id
            AND (consent.status = 'active' OR consent.revoked_at >= event.created_at)
            AND (membership.status = 'active' OR membership.removed_at >= event.created_at
                 OR membership.suspended_at >= event.created_at)
      ))
      AND projection.application_id = p_application_id
$$;
