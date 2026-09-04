-- Application-authenticated OAuth and OBO requests must lock authority that
-- belongs to their human or Silicon subject.  The Application principal is not
-- itself an organization member, so ordinary locking reads are intentionally
-- hidden by the organization RLS policies.  These projections expose only an
-- exact, caller-bound authority chain and keep every production/testing RLS
-- boundary in force.

CREATE OR REPLACE FUNCTION iam_private.lock_current_application_client(
    p_application_id uuid,
    p_auth_epoch bigint
)
RETURNS uuid
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT application.id
    FROM iam.applications AS application
    JOIN iam.principals AS principal
      ON principal.id = application.id
     AND principal.kind = 'application'
     AND principal.status = 'active'
     AND principal.auth_epoch = p_auth_epoch
    WHERE p_application_id IS NOT DISTINCT FROM iam_private.current_application_id()
      AND p_application_id IS NOT DISTINCT FROM iam_private.current_principal_id()
      AND application.id = p_application_id
      AND application.review_status = 'verified'
      AND application.deleted_at IS NULL
    FOR SHARE OF application, principal
$$;

REVOKE ALL ON FUNCTION iam_private.lock_current_application_client(uuid, bigint)
    FROM PUBLIC;

CREATE FUNCTION iam_private.lock_current_application_oauth_subject_authority(
    p_application_id uuid,
    p_consent_grant_id uuid,
    p_authentication_session_id uuid,
    p_subject_principal_id uuid,
    p_subject_kind iam.principal_kind,
    p_organization_id uuid,
    p_membership_id uuid
)
RETURNS TABLE (
    subject_auth_epoch bigint,
    membership_authz_epoch bigint,
    org_id text,
    subject_public_id text,
    session_idle_expires_at timestamptz,
    session_absolute_expires_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF p_application_id IS NULL
       OR p_application_id IS DISTINCT FROM iam_private.current_application_id()
       OR p_application_id IS DISTINCT FROM iam_private.current_principal_id() THEN
        RAISE EXCEPTION 'application_oauth_subject_authority_forbidden'
            USING ERRCODE = '42501';
    END IF;

    IF (p_organization_id IS NULL) IS DISTINCT FROM (p_membership_id IS NULL)
       OR p_subject_kind NOT IN ('carbon', 'silicon')
       OR (p_subject_kind = 'silicon' AND p_organization_id IS NULL) THEN
        RETURN;
    END IF;

    IF p_organization_id IS NULL THEN
        RETURN QUERY
        SELECT principal.auth_epoch,
               NULL::bigint,
               NULL::text,
               carbon.carbon_id,
               authentication_session.idle_expires_at,
               authentication_session.absolute_expires_at
        FROM iam.principals AS principal
        JOIN iam.carbons AS carbon
          ON carbon.id = principal.id
         AND principal.kind = 'carbon'
         AND carbon.deleted_at IS NULL
        JOIN iam.authentication_sessions AS authentication_session
          ON authentication_session.id = p_authentication_session_id
         AND authentication_session.subject_principal_id = principal.id
         AND authentication_session.subject_kind = principal.kind
         AND authentication_session.subject_auth_epoch = principal.auth_epoch
         AND authentication_session.status = 'active'
         AND authentication_session.idle_expires_at > transaction_timestamp()
         AND authentication_session.absolute_expires_at > transaction_timestamp()
        JOIN iam.oauth_consent_grants AS consent
          ON consent.id = p_consent_grant_id
         AND consent.application_id = p_application_id
         AND consent.subject_principal_id = principal.id
         AND consent.subject_kind = principal.kind
         AND consent.organization_id IS NULL
         AND consent.membership_id IS NULL
         AND consent.parent_authentication_session_id = authentication_session.id
         AND consent.status = 'active'
        WHERE principal.id = p_subject_principal_id
          AND principal.kind = p_subject_kind
          AND principal.status = 'active'
        FOR SHARE OF principal, carbon, authentication_session, consent;
    ELSIF p_subject_kind = 'carbon' THEN
        RETURN QUERY
        SELECT principal.auth_epoch,
               membership.authz_epoch,
               organization.org_id,
               carbon.carbon_id,
               authentication_session.idle_expires_at,
               authentication_session.absolute_expires_at
        FROM iam.principals AS principal
        JOIN iam.carbons AS carbon
          ON carbon.id = principal.id
         AND principal.kind = 'carbon'
         AND carbon.deleted_at IS NULL
        JOIN iam.authentication_sessions AS authentication_session
          ON authentication_session.id = p_authentication_session_id
         AND authentication_session.subject_principal_id = principal.id
         AND authentication_session.subject_kind = principal.kind
         AND authentication_session.subject_auth_epoch = principal.auth_epoch
         AND authentication_session.status = 'active'
         AND authentication_session.idle_expires_at > transaction_timestamp()
         AND authentication_session.absolute_expires_at > transaction_timestamp()
        JOIN iam.organizations AS organization
          ON organization.id = p_organization_id
         AND organization.status = 'active'
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.id = p_membership_id
         AND membership.principal_id = principal.id
         AND membership.principal_kind = principal.kind
         AND membership.status = 'active'
        JOIN iam.oauth_consent_grants AS consent
          ON consent.id = p_consent_grant_id
         AND consent.application_id = p_application_id
         AND consent.subject_principal_id = principal.id
         AND consent.subject_kind = principal.kind
         AND consent.organization_id = organization.id
         AND consent.membership_id = membership.id
         AND consent.parent_authentication_session_id = authentication_session.id
         AND consent.status = 'active'
        WHERE principal.id = p_subject_principal_id
          AND principal.kind = p_subject_kind
          AND principal.status = 'active'
        FOR SHARE OF principal, carbon, authentication_session, organization,
                     membership, consent;
    ELSE
        RETURN QUERY
        SELECT principal.auth_epoch,
               membership.authz_epoch,
               organization.org_id,
               silicon.global_silicon_id,
               authentication_session.idle_expires_at,
               authentication_session.absolute_expires_at
        FROM iam.principals AS principal
        JOIN iam.silicons AS silicon
          ON silicon.id = principal.id
         AND principal.kind = 'silicon'
         AND silicon.organization_id = p_organization_id
         AND silicon.membership_id = p_membership_id
         AND silicon.provisioning_status = 'active'
         AND silicon.deleted_at IS NULL
        JOIN iam.authentication_sessions AS authentication_session
          ON authentication_session.id = p_authentication_session_id
         AND authentication_session.subject_principal_id = principal.id
         AND authentication_session.subject_kind = principal.kind
         AND authentication_session.subject_auth_epoch = principal.auth_epoch
         AND authentication_session.status = 'active'
         AND authentication_session.idle_expires_at > transaction_timestamp()
         AND authentication_session.absolute_expires_at > transaction_timestamp()
        JOIN iam.organizations AS organization
          ON organization.id = p_organization_id
         AND organization.status = 'active'
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.id = p_membership_id
         AND membership.principal_id = principal.id
         AND membership.principal_kind = principal.kind
         AND membership.status = 'active'
        JOIN iam.oauth_consent_grants AS consent
          ON consent.id = p_consent_grant_id
         AND consent.application_id = p_application_id
         AND consent.subject_principal_id = principal.id
         AND consent.subject_kind = principal.kind
         AND consent.organization_id = organization.id
         AND consent.membership_id = membership.id
         AND consent.parent_authentication_session_id = authentication_session.id
         AND consent.status = 'active'
        WHERE principal.id = p_subject_principal_id
          AND principal.kind = p_subject_kind
          AND principal.status = 'active'
        FOR SHARE OF principal, silicon, authentication_session, organization,
                     membership, consent;
    END IF;
END;
$$;

COMMENT ON FUNCTION iam_private.lock_current_application_oauth_subject_authority(
    uuid, uuid, uuid, uuid, iam.principal_kind, uuid, uuid
) IS
    'Locks and projects one exact live OAuth subject/session/consent chain only for the currently authenticated Application.';

REVOKE ALL ON FUNCTION iam_private.lock_current_application_oauth_subject_authority(
    uuid, uuid, uuid, uuid, iam.principal_kind, uuid, uuid
) FROM PUBLIC;

CREATE FUNCTION iam_private.lock_current_application_obo_exchange_authority(
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
     AND parent.organization_id = organization.id
     AND parent.membership_id = membership.id
     AND parent.subject_auth_epoch = subject_principal.auth_epoch
     AND parent.membership_authz_epoch = membership.authz_epoch
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
    'Locks one exact same-organization OBO exchange authority chain only for its currently authenticated issuer Application.';

REVOKE ALL ON FUNCTION iam_private.lock_current_application_obo_exchange_authority(
    uuid, bigint, uuid, uuid, iam.principal_kind, uuid, uuid, text, text
) FROM PUBLIC;
