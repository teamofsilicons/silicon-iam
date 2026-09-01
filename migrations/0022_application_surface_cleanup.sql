-- Remove application product surfaces that are not part of the published contract.
--
-- Application access is owner-only. OAuth remains authorization-code + PKCE with
-- opaque tokens, so OIDC signing material and OIDC nonce storage are retired.

DROP FUNCTION iam_private.replace_carbon_status(text, bigint, text, text);
DROP FUNCTION iam_private.get_platform_carbon(text);

DROP POLICY silicon_webhook_endpoints_platform_delivery_select
    ON iam.silicon_webhook_endpoints;
DROP POLICY silicon_hooks_platform_delivery_select ON iam.silicon_hooks;
DROP POLICY application_webhook_endpoints_platform_delivery_select
    ON iam.application_webhook_endpoints;
DROP POLICY silicon_hooks_member_select ON iam.silicon_hooks;
DROP POLICY silicon_hooks_create ON iam.silicon_hooks;
DROP POLICY silicon_hooks_manage ON iam.silicon_hooks;

DELETE FROM iam.platform_role_capabilities
WHERE capability IN ('carbons.status_manage', 'deliveries.manage');

DELETE FROM iam.platform_capability_catalog
WHERE capability IN ('carbons.status_manage', 'deliveries.manage');

CREATE OR REPLACE FUNCTION iam_private.can_read_application(
    p_application_id uuid,
    p_carbon_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.applications AS application
        JOIN iam.principals AS principal
          ON principal.id = p_carbon_id
         AND principal.kind = 'carbon'
         AND principal.status = 'active'
        WHERE application.id = p_application_id
          AND application.owner_carbon_id = p_carbon_id
          AND application.deleted_at IS NULL
    )
$$;

CREATE OR REPLACE FUNCTION iam_private.can_manage_application(
    p_application_id uuid,
    p_carbon_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT iam_private.can_read_application(p_application_id, p_carbon_id)
$$;

CREATE OR REPLACE FUNCTION iam_private.can_manage_application_technical(
    p_application_id uuid,
    p_carbon_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT iam_private.can_read_application(p_application_id, p_carbon_id)
$$;

REVOKE ALL ON FUNCTION iam_private.can_read_application(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.can_manage_application(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.can_manage_application_technical(uuid, uuid) FROM PUBLIC;

ALTER POLICY applications_owner_or_collaborator_select
    ON iam.applications
    RENAME TO applications_owner_admin_or_verified_select;

DROP TABLE iam.application_collaborators;
DROP TABLE iam.oidc_signing_keys;

ALTER TABLE iam.oauth_authorization_requests
    DROP CONSTRAINT oauth_authorization_requests_ciphertext_lengths,
    DROP CONSTRAINT oauth_authorization_requests_nonce_lengths,
    DROP CONSTRAINT oauth_authorization_requests_oidc_nonce_pair,
    DROP COLUMN oidc_nonce_ciphertext,
    DROP COLUMN oidc_nonce_encryption_nonce,
    ADD CONSTRAINT oauth_authorization_requests_state_ciphertext_length
        CHECK (octet_length(state_ciphertext) BETWEEN 17 AND 8192),
    ADD CONSTRAINT oauth_authorization_requests_state_nonce_length
        CHECK (octet_length(state_encryption_nonce) BETWEEN 12 AND 32);

COMMENT ON TABLE iam.oauth_authorization_requests IS
    'Short-lived OAuth authorization-code interactions bound to exact redirect, session, organization, state, and PKCE-S256.';

-- Application deletion is a backend-admin review decision. It remains soft so
-- audit history and immutable authorization evidence retain their references.
ALTER TABLE iam.application_reviews
    DROP CONSTRAINT application_reviews_decision,
    ADD CONSTRAINT application_reviews_decision
        CHECK (decision IN ('approve', 'reject', 'suspend', 'restore', 'delete'));

-- Bring tombstones created by earlier application-delete behavior up to the
-- same fail-closed credential and endpoint state as the admin decision path.
UPDATE iam.application_secrets AS secret
SET status = 'compromised', retired_at = transaction_timestamp(), retires_at = NULL
FROM iam.applications AS application
WHERE secret.application_id = application.id
  AND application.deleted_at IS NOT NULL
  AND secret.status IN ('active', 'retiring');

UPDATE iam.application_webhook_signing_keys AS signing
SET status = 'compromised', retired_at = transaction_timestamp(), retires_at = NULL
FROM iam.applications AS application
WHERE signing.application_id = application.id
  AND application.deleted_at IS NOT NULL
  AND signing.status IN ('active', 'retiring');

UPDATE iam.application_webhook_endpoints AS endpoint
SET status = 'disabled'
FROM iam.applications AS application
WHERE endpoint.application_id = application.id
  AND application.deleted_at IS NOT NULL
  AND endpoint.status IN ('active', 'pending_review');

UPDATE iam.application_redirect_uris AS redirect
SET status = 'retired', retired_at = transaction_timestamp()
FROM iam.applications AS application
WHERE redirect.application_id = application.id
  AND application.deleted_at IS NOT NULL
  AND redirect.status <> 'retired';

UPDATE iam.application_obo_endpoints AS endpoint
SET status = 'retired', retired_at = transaction_timestamp()
FROM iam.applications AS application
WHERE endpoint.application_id = application.id
  AND application.deleted_at IS NOT NULL
  AND endpoint.status = 'active';

-- Retire challenge purposes whose public mutation surfaces were removed.
UPDATE iam.step_up_assertions
SET consumed_at = transaction_timestamp()
WHERE purpose IN (
        'application.delete',
        'application.rotate_secret',
        'organization.silicon_webhook.rotate_secret'
    )
  AND consumed_at IS NULL;

UPDATE iam.step_up_challenges
SET status = 'cancelled'
WHERE purpose IN (
        'application.delete',
        'application.rotate_secret',
        'organization.silicon_webhook.rotate_secret'
    )
  AND status = 'pending';

-- OIDC is no longer exposed. Fail closed for every live artifact carrying the
-- retired scope before removing its immutable issuance snapshots and catalog row.
UPDATE iam.oauth_authorization_codes AS code
SET consumed_at = transaction_timestamp()
WHERE code.consumed_at IS NULL
  AND EXISTS (
      SELECT 1
      FROM iam.oauth_authorization_request_scopes AS request_scope
      WHERE request_scope.authorization_request_id = code.authorization_request_id
        AND request_scope.scope = 'openid'
  );

UPDATE iam.oauth_authorization_requests AS request
SET status = 'denied',
    decided_at = COALESCE(request.decided_at, transaction_timestamp())
WHERE request.status IN ('pending', 'approved')
  AND EXISTS (
      SELECT 1
      FROM iam.oauth_authorization_request_scopes AS request_scope
      WHERE request_scope.authorization_request_id = request.id
        AND request_scope.scope = 'openid'
  );

UPDATE iam.oauth_consent_grants AS consent
SET status = 'revoked', revoked_at = transaction_timestamp()
WHERE consent.status = 'active'
  AND EXISTS (
      SELECT 1
      FROM iam.oauth_consent_grant_scopes AS consent_scope
      WHERE consent_scope.consent_grant_id = consent.id
        AND consent_scope.scope = 'openid'
  );

UPDATE iam.refresh_token_families AS family
SET status = 'revoked',
    revoked_at = transaction_timestamp(),
    revocation_reason = 'openid_scope_retired'
WHERE family.status = 'active'
  AND EXISTS (
      SELECT 1
      FROM iam.oauth_refresh_family_scopes AS family_scope
      WHERE family_scope.family_id = family.id
        AND family_scope.scope = 'openid'
  );

UPDATE iam.refresh_tokens AS token
SET revoked_at = transaction_timestamp()
WHERE token.revoked_at IS NULL
  AND EXISTS (
      SELECT 1
      FROM iam.oauth_refresh_family_scopes AS family_scope
      WHERE family_scope.family_id = token.family_id
        AND family_scope.scope = 'openid'
  );

UPDATE iam.access_tokens AS token
SET revoked_at = transaction_timestamp(),
    revocation_reason = 'openid_scope_retired'
WHERE token.revoked_at IS NULL
  AND EXISTS (
      SELECT 1
      FROM iam.access_token_scopes AS token_scope
      WHERE token_scope.access_token_id = token.id
        AND token_scope.scope = 'openid'
  );

DELETE FROM iam.oauth_authorization_request_scopes WHERE scope = 'openid';
DELETE FROM iam.access_token_scopes WHERE scope = 'openid';

DROP TRIGGER oauth_refresh_family_scopes_immutable
    ON iam.oauth_refresh_family_scopes;
DELETE FROM iam.oauth_refresh_family_scopes WHERE scope = 'openid';
CREATE TRIGGER oauth_refresh_family_scopes_immutable
BEFORE UPDATE OR DELETE ON iam.oauth_refresh_family_scopes
FOR EACH ROW EXECUTE FUNCTION iam_private.prevent_oauth_refresh_family_scope_mutation();

DELETE FROM iam.oauth_consent_grant_scopes WHERE scope = 'openid';
DELETE FROM iam.application_approved_scopes WHERE scope = 'openid';
DELETE FROM iam.application_requested_scopes WHERE scope = 'openid';
DELETE FROM iam.oauth_scope_catalog WHERE scope = 'openid';
