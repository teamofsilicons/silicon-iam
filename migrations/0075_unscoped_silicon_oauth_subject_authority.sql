-- Selected-organization logins are deliberately unscoped for both Carbon and
-- Silicon subjects. Keep the Silicon's own live organization and membership
-- locked without converting that login into a legacy organization-bound token.

CREATE OR REPLACE FUNCTION iam_private.lock_current_application_oauth_subject_authority(
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
       OR p_subject_kind NOT IN ('carbon', 'silicon') THEN
        RETURN;
    END IF;

    IF p_organization_id IS NULL AND p_subject_kind = 'carbon' THEN
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
               CASE WHEN p_membership_id IS NULL THEN NULL ELSE membership.authz_epoch END,
               CASE WHEN p_organization_id IS NULL THEN NULL ELSE organization.org_id END,
               silicon.global_silicon_id,
               authentication_session.idle_expires_at,
               authentication_session.absolute_expires_at
        FROM iam.principals AS principal
        JOIN iam.silicons AS silicon
          ON silicon.id = principal.id
         AND principal.kind = 'silicon'
         AND (p_organization_id IS NULL OR silicon.organization_id = p_organization_id)
         AND (p_membership_id IS NULL OR silicon.membership_id = p_membership_id)
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
          ON organization.id = silicon.organization_id
         AND organization.status = 'active'
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.id = silicon.membership_id
         AND membership.principal_id = principal.id
         AND membership.principal_kind = principal.kind
         AND membership.status = 'active'
        JOIN iam.oauth_consent_grants AS consent
          ON consent.id = p_consent_grant_id
         AND consent.application_id = p_application_id
         AND consent.subject_principal_id = principal.id
         AND consent.subject_kind = principal.kind
         AND consent.organization_id IS NOT DISTINCT FROM p_organization_id
         AND consent.membership_id IS NOT DISTINCT FROM p_membership_id
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

