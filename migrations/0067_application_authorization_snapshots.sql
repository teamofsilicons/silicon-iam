-- Exact-chain, row-locking authorization without granting runtime UPDATE RLS.
CREATE FUNCTION iam_private.get_current_application_authorization(
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

    -- Resolve only the exact supplied chain. The locking read below rechecks
    -- every mutable predicate before returning any authority.
    SELECT token.client_application_id INTO v_issuer_application_id
    FROM iam.access_tokens AS token
    WHERE token.id = p_access_token_id
      AND token.subject_principal_id = p_subject_principal_id
      AND token.organization_id = p_organization_id
      AND token.membership_id = p_membership_id
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
      ON membership.id = token.membership_id AND membership.organization_id = token.organization_id
     AND membership.principal_id = subject.id AND membership.principal_kind = subject.kind
     AND membership.status = 'active' AND membership.authz_epoch = token.membership_authz_epoch
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

REVOKE ALL ON FUNCTION iam_private.get_current_application_authorization(
    uuid, uuid, uuid, uuid, uuid, bigint, uuid
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.get_current_application_authorization(
    uuid, uuid, uuid, uuid, uuid, bigint, uuid
) IS
    'Current caller-bound bearer or persisted OBO authorization; locks exact authority, proof and endpoint without granting runtime organization-write privileges.';

DO $grant_runtime_api$
BEGIN
    IF pg_catalog.to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION iam_private.get_current_application_authorization(
            uuid, uuid, uuid, uuid, uuid, bigint, uuid
        ) TO silicon_iam_api;
    END IF;
END;
$grant_runtime_api$;
