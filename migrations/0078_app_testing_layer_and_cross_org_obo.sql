-- Cross-organization delegation remains bound to a caller-issued subject
-- token, an exact consented external endpoint, and a selected membership.
ALTER TABLE iam.obo_proofs
    DROP CONSTRAINT obo_proofs_issuer_tenant_fk,
    DROP CONSTRAINT obo_proofs_audience_tenant_fk,
    DROP CONSTRAINT obo_proofs_endpoint_tenant_fk,
    DROP CONSTRAINT obo_proofs_consumer_tenant_fk,
    ADD CONSTRAINT obo_proofs_issuer_fk FOREIGN KEY (issuer_application_id)
        REFERENCES iam.applications(id) ON DELETE RESTRICT,
    ADD CONSTRAINT obo_proofs_audience_fk FOREIGN KEY (audience_application_id)
        REFERENCES iam.applications(id) ON DELETE RESTRICT,
    ADD CONSTRAINT obo_proofs_consumer_fk FOREIGN KEY (consumed_by_application_id)
        REFERENCES iam.applications(id) ON DELETE RESTRICT;
ALTER TABLE iam.application_obo_endpoints
    ADD CONSTRAINT application_obo_endpoints_request_identity_key
        UNIQUE(application_id, endpoint_id, path);
ALTER TABLE iam.obo_proofs
    ADD CONSTRAINT obo_proofs_endpoint_fk
        FOREIGN KEY (audience_application_id, endpoint_id, request_path)
        REFERENCES iam.application_obo_endpoints(application_id, endpoint_id, path)
        ON DELETE RESTRICT;
COMMENT ON TABLE iam.obo_proofs IS
    'Single-use request-bound delegation between applications, authorized by the caller-issued token, current consent and selected subject organization.';

CREATE FUNCTION iam_private.discover_application_obo_endpoints(p_app_id text)
RETURNS SETOF jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT jsonb_build_object(
        'application', jsonb_build_object('app_id', app.app_id, 'org_id', org.org_id),
        'endpoints', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'endpoint_id', endpoint.endpoint_id, 'path', endpoint.path,
            'metadata', endpoint.metadata_definition, 'critical', endpoint.critical
        ) ORDER BY endpoint.endpoint_id)
        FROM iam.application_obo_endpoints endpoint
        WHERE endpoint.application_id = app.id AND endpoint.status = 'active'), '[]'::jsonb)
    )
    FROM iam.applications app
    JOIN iam.principals principal ON principal.id = app.id AND principal.status = 'active'
    JOIN iam.organizations org ON org.id = app.organization_id AND org.status = 'active'
    WHERE app.app_id = p_app_id AND app.review_status = 'verified' AND app.deleted_at IS NULL
      AND iam_private.current_application_id() = iam_private.current_principal_id()
      AND EXISTS (SELECT 1 FROM iam.applications caller
        JOIN iam.principals identity ON identity.id = caller.id AND identity.status = 'active'
        WHERE caller.id = iam_private.current_application_id()
          AND caller.review_status = 'verified' AND caller.deleted_at IS NULL);
$$;

CREATE FUNCTION iam_private.resolve_application_obo_memberships(
    p_token_id uuid, p_subject_id uuid, p_org_id text
) RETURNS TABLE(organization_id uuid, membership_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT organization.id, membership.id
    FROM iam.access_tokens token
    JOIN iam.organization_memberships membership ON membership.principal_id = token.subject_principal_id
      AND membership.principal_kind = token.subject_kind AND membership.status = 'active'
    JOIN iam.organizations organization ON organization.id = membership.organization_id
      AND organization.status = 'active'
    WHERE token.id = p_token_id AND token.subject_principal_id = p_subject_id
      AND token.client_application_id = iam_private.current_application_id()
      AND iam_private.current_principal_id() = iam_private.current_application_id()
      AND (p_org_id IS NULL OR organization.org_id = p_org_id)
      AND iam_private.application_token_allows_membership(token.id, membership.id)
    ORDER BY membership.id LIMIT 2;
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
    JOIN iam.applications AS audience
      ON audience.app_id = p_audience_app_id
     AND audience.review_status = 'verified'
     AND audience.deleted_at IS NULL
    JOIN iam.principals AS audience_principal
      ON audience_principal.id = audience.id
     AND audience_principal.kind = 'application'
     AND audience_principal.status = 'active'
    JOIN iam.application_obo_endpoints AS endpoint
      ON endpoint.application_id = audience.id
     AND endpoint.endpoint_id = p_endpoint_id
     AND endpoint.status = 'active'
    WHERE iam_private.application_token_allows_external_scope(parent.id, audience.id, endpoint.endpoint_id)
    FOR SHARE OF organization, issuer, issuer_principal, membership,
                 subject_principal, parent, authentication_session,
                 audience, audience_principal, endpoint;
END;
$$;

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
        'org_role', CASE WHEN p_proof_id IS NULL AND 'self.membership.read' = ANY(effective.scopes)
            THEN membership.org_role::text ELSE NULL END,
        'tags', CASE WHEN p_proof_id IS NULL AND 'self.tags.read' = ANY(effective.scopes) THEN (
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
          OR (p_proof_id IS NOT NULL)
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
          ON endpoint.application_id = proof.audience_application_id
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
          AND iam_private.application_token_allows_external_scope(p_access_token_id, p_audience_application_id, proof.endpoint_id)
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

    IF p_proof_id IS NOT NULL THEN
        SELECT authorization_snapshot || jsonb_build_object('scopes', jsonb_build_array(
            'obo:' || audience.app_id || ':' || proof.endpoint_id))
        INTO authorization_snapshot FROM iam.obo_proofs proof
        JOIN iam.applications audience ON audience.id = proof.audience_application_id
        WHERE proof.id = p_proof_id;
    END IF;
    IF p_proof_id IS NULL AND NOT (authorization_snapshot->'scopes' ? 'self.identity.read') THEN
        authorization_snapshot := authorization_snapshot - ARRAY['actor_type','public_id'];
    END IF;
    RETURN authorization_snapshot;
END;
$$;

CREATE FUNCTION iam_private.lookup_application_obo_proof(smallint[], bytea[], uuid)
RETURNS TABLE(id uuid, proof_digest bytea, digest_key_version smallint,
 issuer_application_id uuid, issuer_app_id text, subject_principal_id uuid,
 subject_kind text, organization_id uuid, membership_id uuid,
 parent_access_token_id uuid, endpoint_id text, request_method text,
 request_path text, request_body_sha256 bytea, endpoint_version bigint,
 request_metadata jsonb, subject_auth_epoch bigint, membership_authz_epoch bigint,
 issuer_auth_epoch bigint, audience_auth_epoch bigint, expires_at timestamptz,
 checked_at timestamptz, consumed_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
        WITH supplied_digest (key_version, digest) AS (
            SELECT * FROM unnest($1::smallint[], $2::bytea[])
        )
        SELECT proof.id, proof.proof_digest, proof.digest_key_version,
               proof.issuer_application_id, issuer.app_id AS issuer_app_id,
               proof.subject_principal_id,
               proof.subject_kind::text AS subject_kind,
               proof.organization_id,
               proof.membership_id, proof.parent_access_token_id, proof.endpoint_id,
               proof.request_method, proof.request_path, proof.request_body_sha256,
               proof.endpoint_version, proof.request_metadata,
               proof.subject_auth_epoch, proof.membership_authz_epoch,
               proof.issuer_auth_epoch, proof.audience_auth_epoch,
               proof.expires_at, clock_timestamp() AS checked_at,
               proof.consumed_at, proof.revoked_at
        FROM supplied_digest
        JOIN iam.obo_proofs AS proof
          ON proof.digest_key_version = supplied_digest.key_version
         AND proof.proof_digest = supplied_digest.digest
        JOIN iam.applications AS issuer
          ON issuer.id = proof.issuer_application_id
        JOIN iam.application_obo_endpoints AS endpoint
          ON endpoint.application_id = proof.audience_application_id
         AND endpoint.endpoint_id = proof.endpoint_id
         AND endpoint.path = proof.request_path
        WHERE proof.audience_application_id = $3
          AND $3 = iam_private.current_application_id()
          AND $3 = iam_private.current_principal_id();
$$;

CREATE FUNCTION iam_private.application_obo_exchange_replay_is_live(uuid, uuid, uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
        WITH wall_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS value
        )
        SELECT EXISTS (
            SELECT 1
            FROM wall_clock
            JOIN iam.obo_proofs AS proof ON TRUE
            JOIN iam.applications AS issuer_application
              ON issuer_application.id = proof.issuer_application_id
             AND issuer_application.review_status = 'verified'
             AND issuer_application.deleted_at IS NULL
            JOIN iam.principals AS issuer
              ON issuer.id = issuer_application.id
             AND issuer.kind = 'application'
             AND issuer.status = 'active'
             AND issuer.auth_epoch = proof.issuer_auth_epoch
            JOIN iam.applications AS audience_application
              ON audience_application.id = proof.audience_application_id
             AND audience_application.review_status = 'verified'
             AND audience_application.deleted_at IS NULL
            JOIN iam.principals AS audience
              ON audience.id = audience_application.id
             AND audience.kind = 'application'
             AND audience.status = 'active'
             AND audience.auth_epoch = proof.audience_auth_epoch
            JOIN iam.principals AS subject
              ON subject.id = proof.subject_principal_id
             AND subject.kind = proof.subject_kind
             AND subject.status = 'active'
             AND subject.auth_epoch = proof.subject_auth_epoch
            JOIN iam.organization_memberships AS membership
              ON membership.organization_id = proof.organization_id
             AND membership.id = proof.membership_id
             AND membership.principal_id = proof.subject_principal_id
             AND membership.principal_kind = proof.subject_kind
             AND membership.status = 'active'
             AND membership.authz_epoch = proof.membership_authz_epoch
            JOIN iam.access_tokens AS parent
              ON parent.id = proof.parent_access_token_id
             AND parent.client_application_id = proof.issuer_application_id
             AND parent.subject_auth_epoch = subject.auth_epoch
             AND (
                 (parent.organization_id = proof.organization_id
                  AND parent.membership_id = proof.membership_id
                  AND parent.membership_authz_epoch = membership.authz_epoch)
                 OR (parent.organization_id IS NULL
                     AND parent.membership_id IS NULL
                     AND parent.membership_authz_epoch IS NULL)
             )
             AND iam_private.application_token_allows_membership(parent.id, membership.id)
             AND parent.client_auth_epoch = issuer.auth_epoch
             AND parent.revoked_at IS NULL
             AND parent.expires_at > wall_clock.value
            JOIN iam.authentication_sessions AS session
             ON session.id = parent.authentication_session_id
             AND session.status = 'active'
             AND session.idle_expires_at > wall_clock.value
             AND session.absolute_expires_at > wall_clock.value
            JOIN iam.application_obo_endpoints AS endpoint
              ON endpoint.application_id = proof.audience_application_id
             AND endpoint.endpoint_id = proof.endpoint_id
             AND endpoint.path = proof.request_path
             AND endpoint.version = proof.endpoint_version
             AND endpoint.status = 'active'
            WHERE proof.id = $1
              AND proof.issuer_application_id = $2
              AND proof.organization_id = $3
              AND proof.consumed_at IS NULL
              AND proof.revoked_at IS NULL
              AND proof.expires_at > wall_clock.value
              AND iam_private.application_token_allows_external_scope(parent.id, audience.id, endpoint.endpoint_id)
              AND proof.issuer_application_id = iam_private.current_application_id()
        );
$$;

CREATE FUNCTION iam_private.application_obo_load_current_context(uuid, uuid, uuid, uuid, uuid, uuid, text, bigint, text, text)
RETURNS TABLE(org_id text, subject_public_id text, subject_auth_epoch bigint, membership_authz_epoch bigint, issuer_auth_epoch bigint, audience_auth_epoch bigint, parent_active boolean, endpoint_active boolean) LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
        WITH wall_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS value
        )
        SELECT organization.org_id,
               COALESCE(carbon.carbon_id, silicon.global_silicon_id) AS subject_public_id,
               subject.auth_epoch AS subject_auth_epoch,
               membership.authz_epoch AS membership_authz_epoch,
               issuer.auth_epoch AS issuer_auth_epoch,
               audience.auth_epoch AS audience_auth_epoch,
               EXISTS (
                   SELECT 1
                   FROM iam.access_tokens AS parent
                   JOIN iam.authentication_sessions AS session
                     ON session.id = parent.authentication_session_id
                    AND session.status = 'active'
                    AND session.idle_expires_at > wall_clock.value
                    AND session.absolute_expires_at > wall_clock.value
                   WHERE parent.id = $6
                     AND parent.client_application_id = $4
                     AND parent.subject_principal_id = $1
                     AND parent.subject_auth_epoch = subject.auth_epoch
                     AND (
                         (parent.organization_id = $2
                          AND parent.membership_id = $3
                          AND parent.membership_authz_epoch = membership.authz_epoch)
                         OR (parent.organization_id IS NULL
                             AND parent.membership_id IS NULL
                             AND parent.membership_authz_epoch IS NULL)
                     )
                     AND parent.client_auth_epoch = issuer.auth_epoch
                     AND parent.revoked_at IS NULL
                     AND parent.expires_at > wall_clock.value
                     AND iam_private.application_token_allows_membership(parent.id, $3)
                     AND iam_private.application_token_allows_external_scope(parent.id, $5, $7)
               ) AS parent_active,
               (endpoint.path = $10 AND endpoint.version = $8
                AND endpoint.status = 'active') AS endpoint_active
        FROM wall_clock
        JOIN iam.organizations AS organization ON TRUE
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.id = $3
         AND membership.principal_id = $1
         AND membership.principal_kind = $9::iam.principal_kind
         AND membership.status = 'active'
        JOIN iam.principals AS subject
          ON subject.id = membership.principal_id
         AND subject.kind = membership.principal_kind
         AND subject.status = 'active'
        LEFT JOIN iam.carbons AS carbon
          ON carbon.id = subject.id
         AND subject.kind = 'carbon'
         AND carbon.deleted_at IS NULL
        LEFT JOIN iam.silicons AS silicon
          ON silicon.id = subject.id
         AND subject.kind = 'silicon'
         AND silicon.organization_id = organization.id
         AND silicon.membership_id = membership.id
         AND silicon.provisioning_status = 'active'
         AND silicon.deleted_at IS NULL
        JOIN iam.applications AS issuer_application
          ON issuer_application.id = $4
         AND issuer_application.review_status = 'verified'
         AND issuer_application.deleted_at IS NULL
        JOIN iam.principals AS issuer
          ON issuer.id = issuer_application.id
         AND issuer.kind = 'application'
         AND issuer.status = 'active'
        JOIN iam.applications AS audience_application
          ON audience_application.id = $5
         AND audience_application.review_status = 'verified'
         AND audience_application.deleted_at IS NULL
        JOIN iam.principals AS audience
          ON audience.id = audience_application.id
         AND audience.kind = 'application'
         AND audience.status = 'active'
        JOIN iam.application_obo_endpoints AS endpoint
          ON endpoint.application_id = audience_application.id
         AND endpoint.endpoint_id = $7
        WHERE $5 = iam_private.current_application_id() AND $1 = iam_private.current_principal_id()
          AND organization.id = $2
          AND organization.status = 'active'
          AND (
              (subject.kind = 'carbon' AND carbon.id IS NOT NULL)
              OR (subject.kind = 'silicon' AND silicon.id IS NOT NULL)
          );
$$;

CREATE FUNCTION iam_private.get_testing_application_import_v1(p_app_ids text[])
RETURNS TABLE (
    source_application_id uuid,
    source_webhook_endpoint_id uuid,
    source_webhook_signing_key_id uuid,
    app_id text,
    org_id text,
    organization_name text,
    organization_logo_uri text,
    organization_description text,
    app_name text,
    app_logo_uri text,
    base_url text,
    webhook_url_ciphertext bytea,
    webhook_url_nonce bytea,
    webhook_url_encryption_key_version smallint,
    webhook_secret_ciphertext bytea,
    webhook_secret_nonce bytea,
    webhook_secret_encryption_key_version smallint,
    webhook_secret_version bigint,
    obo_endpoints jsonb,
    app_scope jsonb, webhook_scope text[], testing_idle_days integer
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        application.id,
        endpoint.id,
        signing_key.id,
        application.app_id,
        organization.org_id,
        organization.name,
        organization.logo_uri,
        organization.description,
        application.app_name,
        application.app_logo_uri,
        application.base_url,
        endpoint.url_ciphertext,
        endpoint.url_nonce,
        endpoint.encryption_key_version,
        signing_key.secret_ciphertext,
        signing_key.secret_nonce,
        signing_key.encryption_key_version,
        signing_key.secret_version,
        (
            SELECT COALESCE(
                jsonb_agg(
                    jsonb_build_object(
                        'endpoint_id', obo.endpoint_id,
                        'path', obo.path,
                        'metadata', obo.metadata_definition, 'critical', obo.critical
                    ) ORDER BY obo.endpoint_id
                ),
                '[]'::jsonb
            )
            FROM iam.application_obo_endpoints AS obo
            WHERE obo.application_id = application.id
              AND obo.organization_id = application.organization_id
              AND obo.status = 'active'
        ), application.app_scope, application.webhook_scope, application.testing_idle_days
    FROM iam.applications AS application
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
     AND application_principal.status = 'active'
    JOIN iam.organizations AS organization
      ON organization.id = application.organization_id
     AND organization.status = 'active'
    JOIN LATERAL (
        SELECT candidate.*
        FROM iam.application_webhook_endpoints AS candidate
        WHERE candidate.application_id = application.id
          AND candidate.status IN ('active', 'pending_review')
        ORDER BY
            (candidate.status = 'active') DESC,
            candidate.activated_at DESC NULLS LAST,
            candidate.created_at DESC,
            candidate.id DESC
        LIMIT 1
    ) AS endpoint ON true
    JOIN LATERAL (
        SELECT candidate.*
        FROM iam.application_webhook_signing_keys AS candidate
        WHERE candidate.application_id = application.id
          AND candidate.endpoint_id = endpoint.id
          AND candidate.status = 'active'
        ORDER BY candidate.secret_version DESC, candidate.id DESC
        LIMIT 1
    ) AS signing_key ON true
    WHERE application.app_id = ANY(p_app_ids)
      AND application.review_status = 'verified'
      AND application.deleted_at IS NULL
$$;

-- Production control-plane links never contain reusable test credentials.
CREATE TABLE iam.application_testing_environments (
    environment_id uuid NOT NULL REFERENCES iam.testing_environments(id) ON DELETE CASCADE,
    source_application_id uuid NOT NULL REFERENCES iam.applications(id) ON DELETE RESTRICT,
    target_application_id uuid NOT NULL,
    last_activity_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    retired_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK(version > 0),
    PRIMARY KEY(environment_id, source_application_id)
);
CREATE INDEX application_testing_environments_application_idx
    ON iam.application_testing_environments(source_application_id, environment_id) WHERE retired_at IS NULL;
CREATE UNIQUE INDEX application_testing_environments_target_idx
    ON iam.application_testing_environments(environment_id,target_application_id);
ALTER TABLE iam.application_testing_environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.testing_environments ADD COLUMN created_by_application_id uuid REFERENCES iam.applications(id);

-- Exists only as useful state in the testing data plane. The testing schema
-- overlay enforces environment isolation even inside SECURITY DEFINER helpers.
CREATE TABLE iam.testing_application_imports (
    application_id uuid PRIMARY KEY REFERENCES iam.applications(id) ON DELETE RESTRICT,
    source_application_id uuid NOT NULL,
    secret_ciphertext bytea NOT NULL,
    secret_nonce bytea NOT NULL CHECK(octet_length(secret_nonce) = 12),
    secret_key_version smallint NOT NULL CHECK(secret_key_version > 0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);
ALTER TABLE iam.testing_application_imports ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION iam_private.get_testing_application_secret(p_app_id text)
RETURNS TABLE(application_id uuid, secret_ciphertext bytea, secret_nonce bytea, secret_key_version smallint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT imported.application_id, imported.secret_ciphertext, imported.secret_nonce, imported.secret_key_version
    FROM iam.testing_application_imports imported JOIN iam.applications app ON app.id = imported.application_id
    WHERE app.app_id = p_app_id AND app.deleted_at IS NULL AND app.review_status IN ('verified','suspended')
      AND NULLIF(current_setting('iam.testing_environment_id', true), '') IS NOT NULL;
$$;

CREATE FUNCTION iam_private.import_testing_application_configuration(p jsonb)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE environment_id uuid := NULLIF(current_setting('iam.testing_environment_id', true), '')::uuid;
    owner_id uuid; org_id uuid; app_id uuid := (p->>'application_id')::uuid;
    endpoint_id uuid := (p->>'endpoint_id')::uuid; item jsonb;
BEGIN
    IF environment_id IS NULL THEN RAISE EXCEPTION 'testing_environment_required' USING ERRCODE = '42501'; END IF;
    -- An uncredentialed, suspended fixture is audit attribution, never a
    -- production identity or a login-capable organization administrator.
    owner_id := iam_private.current_principal_id();
    IF owner_id IS NULL OR NOT EXISTS (SELECT 1 FROM iam.carbons c JOIN iam.principals identity ON identity.id=c.id
        WHERE c.id=owner_id AND identity.status='active') THEN owner_id := environment_id; END IF;
    IF NOT EXISTS (SELECT 1 FROM iam.carbons WHERE id = owner_id) THEN
        INSERT INTO iam.principals(id,kind,status,suspended_at) VALUES(owner_id,'carbon','suspended',clock_timestamp());
        INSERT INTO iam.carbons(id,carbon_id,display_name)
        VALUES(owner_id, 'test_' || translate(left(replace(environment_id::text,'-',''),24),'0','g'), 'Testing environment fixture');
    END IF;
    SELECT organization.id INTO org_id FROM iam.organizations organization
    WHERE organization.org_id = p->>'org_id' AND organization.status = 'active';
    IF org_id IS NOT NULL AND owner_id <> environment_id
       AND NOT iam_private.is_active_organization_owner_or_admin(org_id,owner_id) THEN
        RAISE EXCEPTION 'testing_import_organization_not_managed' USING ERRCODE='42501';
    END IF;
    IF org_id IS NULL THEN
        org_id := gen_random_uuid();
        INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name,logo_uri,description)
        VALUES(org_id,p->>'org_id',owner_id,p->>'organization_name',p->>'organization_logo',p->>'organization_description');
        INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role)
        VALUES(gen_random_uuid(),org_id,owner_id,'carbon','owner');
        INSERT INTO iam.carbon_membership_settings(organization_id,membership_id,carbon_id)
        SELECT org_id,membership.id,owner_id FROM iam.organization_memberships membership
        WHERE membership.organization_id = org_id AND membership.principal_id = owner_id;
    END IF;
    INSERT INTO iam.principals(id,kind,status,activated_at) VALUES(app_id,'application','active',transaction_timestamp());
    INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,app_name,app_logo_uri,base_url,
        review_status,test_imported_from_production,app_scope,webhook_scope,testing_idle_days)
    VALUES(app_id,p->>'app_id',org_id,owner_id,p->>'app_name',p->>'app_logo',p->>'base_url','verified',true,
        p->'app_scope',ARRAY(SELECT jsonb_array_elements_text(p->'webhook_scope')),(p->>'testing_idle_days')::integer);
    FOR item IN SELECT * FROM jsonb_array_elements(p->'obo_endpoints') LOOP
        INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical)
        VALUES(org_id,app_id,item->>'endpoint_id',item->>'path',item->'metadata',(item->>'critical')::boolean);
    END LOOP;
    INSERT INTO iam.application_secrets(id,application_id,secret_version,secret_prefix,secret_digest,pepper_key_version,created_by_carbon_id)
    VALUES((p->>'secret_id')::uuid,app_id,1,p->>'secret_prefix',decode(p->>'secret_digest','hex'),(p->>'secret_digest_version')::smallint,owner_id);
    INSERT INTO iam.application_webhook_endpoints(id,application_id,url_ciphertext,url_nonce,encryption_key_version,url_digest,status,activated_at)
    VALUES(endpoint_id,app_id,decode(p->>'url_ciphertext','hex'),decode(p->>'url_nonce','hex'),(p->>'url_key_version')::smallint,
        decode(p->>'url_digest','hex'),'active',transaction_timestamp());
    INSERT INTO iam.application_webhook_signing_keys(id,application_id,endpoint_id,secret_version,key_prefix,secret_ciphertext,secret_nonce,encryption_key_version,test_inherited_from_production)
    VALUES((p->>'signing_key_id')::uuid,app_id,endpoint_id,(p->>'webhook_secret_version')::bigint,p->>'webhook_fingerprint',
        decode(p->>'signing_ciphertext','hex'),decode(p->>'signing_nonce','hex'),(p->>'signing_key_version')::smallint,true);
    INSERT INTO iam.testing_application_imports(application_id,source_application_id,secret_ciphertext,secret_nonce,secret_key_version)
    VALUES(app_id,(p->>'source_application_id')::uuid,decode(p->>'secret_ciphertext','hex'),decode(p->>'secret_nonce','hex'),(p->>'secret_key_version')::smallint);
    RETURN app_id;
END;
$$;

CREATE FUNCTION iam_private.activate_testing_application_scopes(p_app_ids uuid[])
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE app record;
BEGIN
    IF NULLIF(current_setting('iam.testing_environment_id', true), '') IS NULL THEN
        RAISE EXCEPTION 'testing_environment_required' USING ERRCODE='42501'; END IF;
    UPDATE iam.principals principal SET status='active',suspended_at=NULL FROM iam.testing_application_imports imported
    WHERE imported.application_id=principal.id AND imported.retired_at IS NOT NULL AND principal.id=ANY(p_app_ids);
    UPDATE iam.applications application SET review_status='verified' FROM iam.testing_application_imports imported
    WHERE imported.application_id=application.id AND imported.retired_at IS NOT NULL AND application.id=ANY(p_app_ids);
    UPDATE iam.testing_application_imports SET retired_at=NULL,last_activity_at=clock_timestamp()
    WHERE application_id=ANY(p_app_ids);
    FOR app IN SELECT application.id,application.app_scope,application.created_by_carbon_id
        FROM iam.applications application JOIN iam.testing_application_imports imported ON imported.application_id=application.id
        WHERE application.id = ANY(p_app_ids) LOOP
        INSERT INTO iam.oauth_scope_catalog(scope,description,sensitive)
        SELECT scope,description,critical FROM iam_private.application_scope_catalog(NULL)
        WHERE scope=ANY(iam_private.application_scope_names(app.app_scope)) ON CONFLICT(scope) DO NOTHING;
        INSERT INTO iam.application_requested_scopes(application_id,scope)
        SELECT app.id,unnest(iam_private.application_scope_names(app.app_scope)) ON CONFLICT DO NOTHING;
        INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id)
        SELECT app.id,desired.scope,app.created_by_carbon_id FROM unnest(iam_private.application_scope_names(app.app_scope)) AS desired(scope)
        WHERE NOT EXISTS (SELECT 1 FROM iam.application_approved_scopes approved
            WHERE approved.application_id=app.id AND approved.scope=desired.scope AND approved.revoked_at IS NULL);
    END LOOP;
END;
$$;

-- Caller application identity is installed only after Basic authentication.
CREATE FUNCTION iam_private.create_application_testing_environment(
    p_id uuid,p_name text,p_description text,p_digest bytea,p_digest_version smallint,
    p_ciphertext bytea,p_nonce bytea,p_key_version smallint,p_max integer
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE app iam.applications%ROWTYPE; creator uuid; organization_handle text;
BEGIN
    SELECT application.* INTO app FROM iam.applications application
    JOIN iam.principals principal ON principal.id=application.id AND principal.status='active'
    WHERE application.id=iam_private.current_application_id() AND application.id=iam_private.current_principal_id()
      AND application.review_status='verified' AND application.deleted_at IS NULL FOR SHARE OF application;
    IF NOT FOUND THEN RAISE EXCEPTION 'application_required' USING ERRCODE='42501'; END IF;
    SELECT org.org_id INTO organization_handle FROM iam.organizations org
    WHERE org.id=app.organization_id AND org.status='active' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'organization_inactive' USING ERRCODE='42501'; END IF;
    SELECT member.id INTO STRICT creator FROM iam.organization_memberships member
    WHERE member.organization_id=app.organization_id AND member.org_role='owner' AND member.status='active';
    IF (SELECT count(*) FROM iam.testing_environments env WHERE env.organization_id=app.organization_id AND env.status='active') >= p_max
    THEN RAISE EXCEPTION 'testing_environment_limit_reached' USING ERRCODE='23514'; END IF;
    INSERT INTO iam.testing_environments(id,organization_id,created_by_membership_id,created_by_application_id,name,description,
        key_digest,key_digest_key_version,key_ciphertext,key_nonce,key_encryption_key_version)
    VALUES(p_id,app.organization_id,creator,app.id,p_name,p_description,p_digest,p_digest_version,p_ciphertext,p_nonce,p_key_version);
    RETURN organization_handle;
END;
$$;

CREATE FUNCTION iam_private.link_application_testing_environment(p_environment_id uuid,p_source_id uuid,p_target_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM iam.testing_environments env
        JOIN iam.applications caller ON caller.organization_id=env.organization_id
        WHERE env.id=p_environment_id AND env.status='active' AND caller.id=iam_private.current_application_id()
          AND caller.id=iam_private.current_principal_id() AND caller.deleted_at IS NULL AND caller.review_status='verified')
    THEN RAISE EXCEPTION 'testing_environment_organization_mismatch' USING ERRCODE='42501'; END IF;
    INSERT INTO iam.application_testing_environments(environment_id,source_application_id,target_application_id)
    VALUES(p_environment_id,p_source_id,p_target_id)
    ON CONFLICT ON CONSTRAINT application_testing_environments_pkey DO UPDATE
    SET target_application_id=EXCLUDED.target_application_id,last_activity_at=clock_timestamp(),retired_at=NULL,
        version=iam.application_testing_environments.version+1;
END;
$$;

CREATE FUNCTION iam_private.list_application_testing_environments(p_cursor uuid,p_limit integer)
RETURNS TABLE(environment_id uuid,org_id text,name text,description text,last_activity_at timestamptz,retention_days integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT env.id,org.org_id,env.name,env.description,link.last_activity_at,app.testing_idle_days
    FROM iam.application_testing_environments link
    JOIN iam.applications app ON app.id=link.source_application_id
    JOIN iam.testing_environments env ON env.id=link.environment_id AND env.status='active'
    JOIN iam.organizations org ON org.id=env.organization_id AND org.status='active'
    WHERE app.id=iam_private.current_application_id() AND app.id=iam_private.current_principal_id()
      AND app.organization_id=env.organization_id AND app.deleted_at IS NULL AND app.review_status='verified'
      AND link.retired_at IS NULL AND (p_cursor IS NULL OR env.id>p_cursor)
    ORDER BY env.id LIMIT LEAST(GREATEST(p_limit,1),101);
$$;

CREATE FUNCTION iam_private.touch_application_testing_environment(p_environment_id uuid,p_target_id uuid)
RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
    UPDATE iam.application_testing_environments SET last_activity_at=clock_timestamp()
    WHERE environment_id=p_environment_id AND target_application_id=p_target_id AND retired_at IS NULL
      AND last_activity_at < clock_timestamp()-interval '1 minute';
$$;

CREATE FUNCTION iam_private.lock_application_testing_environment(p_environment_id uuid)
RETURNS TABLE(org_id text,name text,description text,version bigint)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT org.org_id,env.name,env.description,env.version FROM iam.testing_environments env
    JOIN iam.organizations org ON org.id=env.organization_id AND org.status='active'
    JOIN iam.applications app ON app.organization_id=env.organization_id
    WHERE env.id=p_environment_id AND env.status='active' AND app.id=iam_private.current_application_id()
      AND app.id=iam_private.current_principal_id() AND app.deleted_at IS NULL AND app.review_status='verified'
    FOR SHARE OF env,org,app;
$$;

ALTER TABLE iam.testing_application_imports
    ADD COLUMN last_activity_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    ADD COLUMN retired_at timestamptz;

CREATE FUNCTION iam_private.touch_testing_application(p_application_id uuid)
RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
    UPDATE iam.testing_application_imports imported SET last_activity_at=clock_timestamp()
    WHERE imported.application_id=p_application_id AND imported.retired_at IS NULL
      AND NULLIF(current_setting('iam.testing_environment_id',true),'') IS NOT NULL
      AND imported.last_activity_at < clock_timestamp()-interval '1 minute';
$$;

CREATE FUNCTION iam_private.list_idle_application_testing_candidates(p_limit integer)
RETURNS TABLE(environment_id uuid,organization_id uuid,target_application_id uuid,idle_days integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
    SELECT link.environment_id,environment.organization_id,link.target_application_id,app.testing_idle_days
    FROM iam.application_testing_environments link
    JOIN iam.testing_environments environment ON environment.id=link.environment_id AND environment.status='active'
    JOIN iam.applications app ON app.id=link.source_application_id
    WHERE link.retired_at IS NULL
      AND link.last_activity_at <= clock_timestamp()-make_interval(days=>app.testing_idle_days)
    ORDER BY link.last_activity_at,link.environment_id,link.source_application_id LIMIT LEAST(GREATEST(p_limit,1),100);
$$;

CREATE FUNCTION iam_private.retire_idle_testing_application(p_application_id uuid,p_idle_days integer)
RETURNS TABLE(last_activity_at timestamptz,retired boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE imported iam.testing_application_imports%ROWTYPE;
BEGIN
    IF NULLIF(current_setting('iam.testing_environment_id',true),'') IS NULL OR p_idle_days NOT BETWEEN 1 AND 36500
    THEN RAISE EXCEPTION 'testing_environment_required' USING ERRCODE='42501'; END IF;
    SELECT entry.* INTO imported FROM iam.testing_application_imports entry
    WHERE entry.application_id=p_application_id FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    IF imported.retired_at IS NOT NULL THEN RETURN QUERY SELECT imported.last_activity_at,true; RETURN; END IF;
    IF imported.last_activity_at > clock_timestamp()-make_interval(days=>p_idle_days) THEN
        RETURN QUERY SELECT imported.last_activity_at,false; RETURN;
    END IF;
    -- Logical deletion keeps historical authentication/audit references valid
    -- and invalidates all previously issued credentials through the epoch.
    UPDATE iam.principals SET status='suspended',suspended_at=clock_timestamp(),auth_epoch=auth_epoch+1 WHERE id=p_application_id;
    UPDATE iam.applications SET review_status='suspended' WHERE id=p_application_id;
    UPDATE iam.testing_application_imports SET retired_at=clock_timestamp() WHERE application_id=p_application_id;
    RETURN QUERY SELECT imported.last_activity_at,true;
END;
$$;

CREATE FUNCTION iam_private.record_application_testing_maintenance(p_environment_id uuid,p_application_id uuid,p_activity timestamptz,p_retired boolean)
RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
    UPDATE iam.application_testing_environments SET last_activity_at=GREATEST(last_activity_at,p_activity),
      retired_at=CASE WHEN p_retired THEN clock_timestamp() ELSE NULL END,version=version+1
    WHERE environment_id=p_environment_id AND target_application_id=p_application_id;
$$;

CREATE OR REPLACE FUNCTION iam_private.expire_idle_testing_environments(
    p_idle_days integer,
    p_recovery_days integer,
    p_limit integer
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    expired_count bigint;
BEGIN
    IF p_idle_days < 1 OR p_idle_days > 3650
       OR p_recovery_days < 1 OR p_recovery_days > 3650
       OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'testing environment maintenance arguments are out of range'
            USING ERRCODE = '22023';
    END IF;

    WITH idle AS MATERIALIZED (
        SELECT environment.id
        FROM iam.testing_environments AS environment
        WHERE environment.status = 'active'
          AND environment.last_activity_at
              <= transaction_timestamp() - make_interval(days => p_idle_days)
          AND NOT EXISTS (SELECT 1 FROM iam.application_testing_environments linked
              JOIN iam.applications app ON app.id=linked.source_application_id
              WHERE linked.environment_id=environment.id AND linked.retired_at IS NULL
                AND linked.last_activity_at > transaction_timestamp()-make_interval(days=>app.testing_idle_days))
        ORDER BY environment.last_activity_at, environment.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    )
    UPDATE iam.testing_environments AS environment
    SET status = 'deleted',
        deleted_at = transaction_timestamp(),
        purge_after = transaction_timestamp() + make_interval(days => p_recovery_days)
    FROM idle
    WHERE environment.id = idle.id;
    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$$;

CREATE FUNCTION iam_private.update_testing_application_secret(p_id uuid,p_ciphertext bytea,p_nonce bytea,p_key_version smallint)
RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
    UPDATE iam.testing_application_imports SET secret_ciphertext=p_ciphertext,secret_nonce=p_nonce,secret_key_version=p_key_version
    WHERE application_id=p_id AND NULLIF(current_setting('iam.testing_environment_id',true),'') IS NOT NULL
      AND iam_private.can_manage_application(p_id,iam_private.current_principal_id());
$$;

CREATE FUNCTION iam_private.get_testing_environment_obo_key(p_environment_id uuid)
RETURNS TABLE(organization_id uuid,key_ciphertext bytea,key_nonce bytea,key_encryption_key_version smallint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
    SELECT * FROM iam_private.get_worker_testing_environment_webhook_key(p_environment_id);
$$;

DO $new_function_privileges$
DECLARE procedure record;
BEGIN
 FOR procedure IN SELECT p.oid::regprocedure AS identity,p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='iam_private' AND p.proname = ANY(ARRAY['discover_application_obo_endpoints','resolve_application_obo_memberships','lookup_application_obo_proof','application_obo_exchange_replay_is_live','application_obo_load_current_context','get_testing_application_secret','import_testing_application_configuration','activate_testing_application_scopes','create_application_testing_environment','link_application_testing_environment','list_application_testing_environments','touch_application_testing_environment','lock_application_testing_environment','touch_testing_application','list_idle_application_testing_candidates','retire_idle_testing_application','record_application_testing_maintenance','update_testing_application_secret','get_testing_environment_obo_key']) LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',procedure.identity);
  IF procedure.proname = ANY(ARRAY['discover_application_obo_endpoints','resolve_application_obo_memberships','lookup_application_obo_proof','application_obo_exchange_replay_is_live','application_obo_load_current_context','get_testing_application_secret','import_testing_application_configuration','activate_testing_application_scopes','create_application_testing_environment','link_application_testing_environment','list_application_testing_environments','touch_application_testing_environment','lock_application_testing_environment','touch_testing_application','update_testing_application_secret','get_testing_environment_obo_key']) AND to_regrole('silicon_iam_api') IS NOT NULL THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO silicon_iam_api',procedure.identity);
  END IF;
  IF procedure.proname = ANY(ARRAY['list_idle_application_testing_candidates','retire_idle_testing_application','record_application_testing_maintenance']) AND to_regrole('silicon_iam_worker') IS NOT NULL THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO silicon_iam_worker',procedure.identity);
  END IF;
 END LOOP;
END;
$new_function_privileges$;

-- Static privilege declarations also support automated migration auditing.
REVOKE ALL ON FUNCTION iam_private.discover_application_obo_endpoints(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.resolve_application_obo_memberships(uuid, uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.lookup_application_obo_proof(smallint[], bytea[], uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.application_obo_exchange_replay_is_live(uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.application_obo_load_current_context(uuid, uuid, uuid, uuid, uuid, uuid, text, bigint, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.get_testing_application_secret(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.import_testing_application_configuration(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.activate_testing_application_scopes(uuid[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.create_application_testing_environment(uuid, text, text, bytea, smallint, bytea, bytea, smallint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.link_application_testing_environment(uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.list_application_testing_environments(uuid, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.touch_application_testing_environment(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.lock_application_testing_environment(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.touch_testing_application(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.list_idle_application_testing_candidates(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.retire_idle_testing_application(uuid, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.record_application_testing_maintenance(uuid, uuid, timestamptz, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.update_testing_application_secret(uuid, bytea, bytea, smallint) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.get_testing_environment_obo_key(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.get_testing_application_import_v1(text[]) FROM PUBLIC;
DO $$ BEGIN
 IF to_regrole('silicon_iam_api') IS NOT NULL THEN
  GRANT EXECUTE ON FUNCTION iam_private.get_testing_application_import_v1(text[]) TO silicon_iam_api;
 END IF;
END $$;

-- A process can stop between the test commit and control commit. Age-gated,
-- rotating candidate checks let the worker reclaim those unreachable rows.
ALTER TABLE iam.testing_application_imports ADD COLUMN last_control_check_at timestamptz NOT NULL DEFAULT transaction_timestamp();
CREATE INDEX testing_application_imports_control_check_idx ON iam.testing_application_imports(last_control_check_at);
CREATE FUNCTION iam_private.list_testing_application_orphan_candidates(p_limit integer)
RETURNS TABLE(environment_id uuid) LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.testing_application_imports'::regclass
        AND attname='testing_environment_id' AND NOT attisdropped) THEN RETURN; END IF;
    RETURN QUERY WITH candidates AS MATERIALIZED (
        SELECT imported.testing_environment_id FROM iam.testing_application_imports imported
        WHERE imported.created_at < clock_timestamp()-interval '1 day'
          AND imported.last_control_check_at < clock_timestamp()-interval '1 hour'
        GROUP BY imported.testing_environment_id
        ORDER BY min(imported.last_control_check_at),imported.testing_environment_id
        LIMIT LEAST(GREATEST(p_limit,1),100)
    ), touched AS (
        UPDATE iam.testing_application_imports imported SET last_control_check_at=clock_timestamp()
        FROM candidates WHERE imported.testing_environment_id=candidates.testing_environment_id
        RETURNING imported.testing_environment_id
    ) SELECT DISTINCT touched.testing_environment_id FROM touched;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.list_testing_application_orphan_candidates(integer) FROM PUBLIC;

CREATE FUNCTION iam_private.testing_environment_record_exists(p_environment_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
    SELECT EXISTS(SELECT 1 FROM iam.testing_environments WHERE id=p_environment_id);
$$;
REVOKE ALL ON FUNCTION iam_private.testing_environment_record_exists(uuid) FROM PUBLIC;
DO $$ BEGIN
 IF to_regrole('silicon_iam_worker') IS NOT NULL THEN
  GRANT EXECUTE ON FUNCTION iam_private.list_testing_application_orphan_candidates(integer),
    iam_private.testing_environment_record_exists(uuid) TO silicon_iam_worker;
 END IF;
END $$;
