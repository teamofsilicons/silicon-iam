-- An Application remains authorized while it holds a usable OAuth refresh
-- family even when its most recent 30-minute access token has expired. Keep
-- event-boundary webhook routing aligned with that authority so global logout
-- reaches every Application that could act for the Carbon immediately before
-- IAM atomically revoked the parent session.

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
                    OR token.organization_id = p_organization_id)
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
                    OR consent.organization_id = p_organization_id)
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

REVOKE ALL ON FUNCTION iam_private.list_worker_application_webhook_recipients(
    uuid, uuid, uuid, timestamptz
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.list_worker_application_webhook_recipients(
    uuid, uuid, uuid, timestamptz
) IS
    'Returns current webhook material for an explicitly targeted Application or one holding access/refresh authority at the exact event boundary.';
