-- Qualified Application identities, discoverable backend locations, and the
-- dedicated step-up authority needed to rotate a webhook signing secret.

-- Preserve the audience carried by already-issued application access tokens
-- while the public Application identifier changes. The UUID binding remains
-- authoritative; the text is updated only when it still names that binding.
UPDATE iam.access_tokens AS token
SET audience = organization.org_id || '>' || application.app_id
FROM iam.applications AS application
JOIN iam.organizations AS organization
  ON organization.id = application.organization_id
WHERE token.audience_application_id = application.id
  AND token.audience = application.app_id;

ALTER TABLE iam.applications
    ADD COLUMN base_url text,
    DROP CONSTRAINT applications_app_id_format;

-- Existing installations have no backend URL to migrate. Give every legacy
-- row an explicitly non-routable IANA-reserved location instead of guessing
-- from encrypted webhook configuration. Organization administrators can
-- replace it through the ordinary versioned Application update.
ALTER TABLE iam.applications DISABLE TRIGGER applications_immutable_identity;

UPDATE iam.applications AS application
SET app_id = organization.org_id || '>' || application.app_id,
    base_url = 'https://unconfigured.invalid/' || application.id::text
FROM iam.organizations AS organization
WHERE organization.id = application.organization_id;

ALTER TABLE iam.applications ENABLE TRIGGER applications_immutable_identity;

ALTER TABLE iam.applications
    ALTER COLUMN base_url SET NOT NULL,
    ALTER COLUMN review_status SET DEFAULT 'verified',
    ADD CONSTRAINT applications_app_id_format CHECK (
        app_id ~ '^[a-z0-9_-]{3,50}>[a-z][a-z0-9_-]{2,79}$'
    ),
    ADD CONSTRAINT applications_base_url_length
        CHECK (char_length(base_url) BETWEEN 8 AND 2048),
    ADD CONSTRAINT applications_base_url_shape CHECK (
        base_url ~ '^https?://[^[:space:]]+$'
        AND base_url !~ '[?#]'
        AND base_url !~ '^https?://[^/]*@'
        AND (
            base_url ~ '^https://'
            OR base_url ~ '^http://(localhost|127[.]0[.]0[.]1|\[::1\])([:/]|$)'
        )
    );

-- Completed responses written by the preceding schema version can contain an
-- unqualified Application ID and ApplicationDetail values without base_url.
-- Leaving them replayable would either disclose stale identity or make the
-- new decoder fail with a 500 until their normal TTL elapsed. Expire only the
-- affected route families; unrelated idempotent work retains its guarantee.
DELETE FROM iam.idempotency_records
WHERE route IN (
    'POST /api/v1/applications',
    'PATCH /api/v1/applications/{app_id}',
    'POST /api/v1/admin/applications/{app_id}/decisions',
    'POST /api/v1/applications/{app_id}/client-secret-rotations'
);

-- A webhook-secret rotation applies one logical version to every currently
-- configured destination (the active URL and, when present, its pending
-- replacement). The original application-wide uniqueness rule forced those
-- copies of the same secret to carry different wire versions, making the
-- rotation response ambiguous. Keep versions unique per endpoint instead.
ALTER TABLE iam.application_webhook_signing_keys
    DROP CONSTRAINT application_webhook_signing_k_application_id_secret_version_key,
    ADD CONSTRAINT application_webhook_endpoint_secret_version_unique
        UNIQUE (endpoint_id, secret_version);

COMMENT ON COLUMN iam.applications.app_id IS
    'Globally unique immutable identifier formed as organization>application.';
COMMENT ON COLUMN iam.applications.base_url IS
    'Versioned Application backend base URL disclosed only to an authenticated Application client.';

-- Webhook-secret rotation returns new secret material and therefore gets the
-- same resource-bound, verified-channel treatment as client-secret rotation,
-- without making either credential interchangeable with the other.
ALTER TABLE iam.step_up_challenges
    DROP CONSTRAINT step_up_challenges_supported_purpose,
    ADD CONSTRAINT step_up_challenges_supported_purpose CHECK (
        purpose IN (
            'account.session_revoke',
            'account.sessions_revoke_all',
            'application.client_secret.rotate',
            'application.webhook_secret.rotate',
            'organization.transfer_ownership',
            'organization.authorization_change',
            'organization.sso_change',
            'organization.silicon_webhook.redirect',
            'silicon.rotate_token',
            'platform_admin.sso_entitlement',
            'platform_admin.application_review'
        )
    ) NOT VALID;

ALTER TABLE iam.step_up_assertions
    DROP CONSTRAINT step_up_assertions_supported_purpose,
    ADD CONSTRAINT step_up_assertions_supported_purpose CHECK (
        purpose IN (
            'account.session_revoke',
            'account.sessions_revoke_all',
            'application.client_secret.rotate',
            'application.webhook_secret.rotate',
            'organization.transfer_ownership',
            'organization.authorization_change',
            'organization.sso_change',
            'organization.silicon_webhook.redirect',
            'silicon.rotate_token',
            'platform_admin.sso_entitlement',
            'platform_admin.application_review'
        )
    ) NOT VALID;

COMMENT ON CONSTRAINT step_up_challenges_supported_purpose ON iam.step_up_challenges IS
    'Closed action catalog including resource-bound Application client- and webhook-secret rotation.';
COMMENT ON CONSTRAINT step_up_assertions_supported_purpose ON iam.step_up_assertions IS
    'Closed action catalog including resource-bound Application client- and webhook-secret rotation.';

-- A rotated key remains usable briefly for deliveries that were already
-- claimed with it. New events must bind only the successor, otherwise the
-- pre-existing recipient function would return both the active and retiring
-- keys and enqueue a duplicate delivery. Retain its exact event-boundary
-- authorization logic under a private legacy name and narrow its result to
-- the one active key per endpoint.
ALTER FUNCTION iam_private.list_worker_application_webhook_recipients(
    uuid, uuid, uuid, timestamptz
) RENAME TO list_worker_application_webhook_recipients_legacy;

REVOKE ALL ON FUNCTION iam_private.list_worker_application_webhook_recipients_legacy(
    uuid, uuid, uuid, timestamptz
) FROM PUBLIC;

CREATE FUNCTION iam_private.list_worker_application_webhook_recipients(
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
    SELECT DISTINCT authorized.endpoint_id, current_key.id
    FROM iam_private.list_worker_application_webhook_recipients_legacy(
        p_organization_id,
        p_subject_principal_id,
        p_application_id,
        p_event_occurred_at
    ) AS authorized
    JOIN LATERAL (
        SELECT signing_key.id
        FROM iam.application_webhook_signing_keys AS signing_key
        WHERE signing_key.endpoint_id = authorized.endpoint_id
          AND signing_key.status = 'active'
        ORDER BY signing_key.secret_version DESC
        LIMIT 1
    ) AS current_key ON true
$$;

REVOKE ALL ON FUNCTION iam_private.list_worker_application_webhook_recipients(
    uuid, uuid, uuid, timestamptz
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.list_worker_application_webhook_recipients_legacy(
    uuid, uuid, uuid, timestamptz
) IS
    'Internal event-boundary authorization candidates; may include a retiring key for an already-bound delivery.';
COMMENT ON FUNCTION iam_private.list_worker_application_webhook_recipients(
    uuid, uuid, uuid, timestamptz
) IS
    'Returns each currently authorized Application webhook endpoint exactly once with its active signing key.';
