-- An unscoped Application login authorizes every organization in which the
-- subject holds an active membership, resolved live at request time. A login
-- that named an organization stays bound to exactly that one.
--
-- Before this migration an unscoped bearer carried no organization authority at
-- all: introspection disclosed no snapshot and OBO refused the exchange. The
-- authority for an unscoped bearer is now the membership row itself rather than
-- a pinned token column, so joining, leaving, or being suspended from an
-- organization takes effect on the next request without reissuing the token.
-- Every other predicate -- subject epoch, session liveness, issuer and audience
-- application epochs, approved scopes, row locks -- is unchanged.

-- Accepts an unscoped parent bearer. A bound bearer must still match the exact
-- organization, membership, and authorization epoch it was issued against.
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

COMMENT ON FUNCTION iam_private.get_current_application_authorization(
    uuid, uuid, uuid, uuid, uuid, bigint, uuid
) IS
    'Current caller-bound bearer or persisted OBO authorization for one organization; a bound bearer must match its pinned membership epoch, an unscoped bearer proves an active membership live.';

-- Every organization an unscoped bearer currently reaches, as one snapshot per
-- active membership. Introspection uses this when the Application asked for no
-- particular organization; naming one goes through the single-organization
-- function above instead. Returns NULL when the bearer chain itself is dead and
-- an empty array when the chain is live but the subject holds no membership.
CREATE FUNCTION iam_private.list_current_application_authorizations(
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

REVOKE ALL ON FUNCTION iam_private.list_current_application_authorizations(
    uuid, uuid, uuid, bigint
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.list_current_application_authorizations(
    uuid, uuid, uuid, bigint
) IS
    'Every organization an unscoped Application bearer currently reaches, one locked snapshot per active membership.';

DO $grant_runtime_api$
BEGIN
    IF pg_catalog.to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION iam_private.list_current_application_authorizations(
            uuid, uuid, uuid, bigint
        ) TO silicon_iam_api;
    END IF;
END;
$grant_runtime_api$;

-- Accepts an unscoped parent bearer for a same-organization OBO exchange. The
-- organization is still the issuer Application's own, so OBO never leaves it;
-- what changes is that a subject who logged in without naming an organization
-- can now prove the membership live instead of being refused outright.
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

COMMENT ON FUNCTION iam_private.lock_current_application_obo_exchange_authority(
    uuid, bigint, uuid, uuid, iam.principal_kind, uuid, uuid, text, text
) IS
    'Locks one exact same-organization OBO exchange authority chain only for its currently authenticated issuer Application; the parent bearer is either bound to that organization or unscoped.';

-- Which organizations an unscoped bearer reaches has to be answered while the
-- authenticated Application is the RLS principal, and an Application is never a
-- member of anything, so member-select policies would hide every row. These two
-- resolvers answer exactly that question and nothing else: an identifier, no
-- role, no tags, no version, no authority. They are callable only from an
-- authenticated Application context, and every caller still has to obtain the
-- real authority from the locking snapshot functions above.
CREATE FUNCTION iam_private.current_subject_membership(
    p_organization_id uuid,
    p_subject_principal_id uuid,
    p_subject_kind iam.principal_kind
)
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    resolved uuid;
BEGIN
    IF iam_private.current_application_id() IS NULL THEN
        RAISE EXCEPTION 'subject_membership_context_forbidden' USING ERRCODE = '42501';
    END IF;

    SELECT membership.id INTO resolved
    FROM iam.organization_memberships AS membership
    JOIN iam.organizations AS organization
      ON organization.id = membership.organization_id
     AND organization.status = 'active'
    JOIN iam.principals AS subject
      ON subject.id = membership.principal_id
     AND subject.kind = membership.principal_kind
     AND subject.status = 'active'
    WHERE membership.organization_id = p_organization_id
      AND membership.principal_id = p_subject_principal_id
      AND membership.principal_kind = p_subject_kind
      AND membership.status = 'active';

    RETURN resolved;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.current_subject_membership(
    uuid, uuid, iam.principal_kind
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.current_subject_membership(
    uuid, uuid, iam.principal_kind
) IS
    'Resolves one active membership identifier for an authenticated Application; discloses nothing else and confers no authority.';

-- The same question asked by organization handle, for introspection selecting
-- one organization out of the many an unscoped bearer reaches.
CREATE FUNCTION iam_private.current_subject_organization(
    p_org_id text,
    p_subject_principal_id uuid,
    p_subject_kind iam.principal_kind
)
RETURNS TABLE (organization_id uuid, membership_id uuid)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF iam_private.current_application_id() IS NULL THEN
        RAISE EXCEPTION 'subject_membership_context_forbidden' USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT organization.id, membership.id
    FROM iam.organizations AS organization
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = organization.id
     AND membership.principal_id = p_subject_principal_id
     AND membership.principal_kind = p_subject_kind
     AND membership.status = 'active'
    JOIN iam.principals AS subject
      ON subject.id = membership.principal_id
     AND subject.kind = membership.principal_kind
     AND subject.status = 'active'
    WHERE organization.org_id = p_org_id
      AND organization.status = 'active';
END;
$$;

REVOKE ALL ON FUNCTION iam_private.current_subject_organization(
    text, uuid, iam.principal_kind
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.current_subject_organization(
    text, uuid, iam.principal_kind
) IS
    'Resolves one active membership by organization handle for an authenticated Application; discloses nothing else and confers no authority.';

DO $grant_runtime_api_membership$
BEGIN
    IF pg_catalog.to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION iam_private.current_subject_membership(
            uuid, uuid, iam.principal_kind
        ) TO silicon_iam_api;
        GRANT EXECUTE ON FUNCTION iam_private.current_subject_organization(
            text, uuid, iam.principal_kind
        ) TO silicon_iam_api;
    END IF;
END;
$grant_runtime_api_membership$;
