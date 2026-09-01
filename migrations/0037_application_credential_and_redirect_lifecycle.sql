-- Explicit Application client-secret and redirect-URI lifecycle controls.

-- Client-secret rotation discloses a new credential and therefore has its own
-- narrow, Application-resource-bound verified-channel step-up action.
ALTER TABLE iam.step_up_challenges
    DROP CONSTRAINT step_up_challenges_supported_purpose,
    ADD CONSTRAINT step_up_challenges_supported_purpose CHECK (
        purpose IN (
            'account.session_revoke',
            'account.sessions_revoke_all',
            'application.client_secret.rotate',
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
    'Closed action catalog including resource-bound Application client-secret rotation.';
COMMENT ON CONSTRAINT step_up_assertions_supported_purpose ON iam.step_up_assertions IS
    'Closed action catalog including resource-bound Application client-secret rotation.';

ALTER TABLE iam.application_redirect_uris
    DROP CONSTRAINT IF EXISTS application_redirect_uris_application_id_uri_digest_key,
    ADD COLUMN version bigint NOT NULL DEFAULT 1,
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    ADD CONSTRAINT application_redirect_uris_positive_version CHECK (version > 0);

-- Earlier API revisions allowed more than one simultaneously current redirect URI.
-- Preserve the newest value as the sole current record before installing the
-- lifecycle constraints; older values remain available as immutable history.
WITH ranked_current_uris AS (
    SELECT
        id,
        row_number() OVER (
            PARTITION BY application_id
            ORDER BY created_at DESC, id DESC
        ) AS current_rank
    FROM iam.application_redirect_uris
    WHERE status IN ('active', 'pending_review')
)
UPDATE iam.application_redirect_uris AS redirect_uri
SET
    status = 'retired',
    retired_at = COALESCE(redirect_uri.retired_at, transaction_timestamp())
FROM ranked_current_uris AS ranked
WHERE redirect_uri.id = ranked.id
  AND ranked.current_rank > 1;

CREATE UNIQUE INDEX application_redirect_uris_one_current_value_idx
    ON iam.application_redirect_uris (application_id, uri_digest)
    WHERE status <> 'retired';

CREATE UNIQUE INDEX application_redirect_uris_one_active_idx
    ON iam.application_redirect_uris (application_id)
    WHERE status = 'active';

CREATE INDEX application_redirect_uris_history_idx
    ON iam.application_redirect_uris (application_id, created_at DESC, id DESC);

CREATE TRIGGER application_redirect_uris_bump_version
BEFORE UPDATE ON iam.application_redirect_uris
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE UNIQUE INDEX application_secrets_one_active_idx
    ON iam.application_secrets (application_id)
    WHERE status = 'active';

COMMENT ON COLUMN iam.application_redirect_uris.version IS
    'Monotonic URI-record version advanced whenever its lifecycle status changes.';
COMMENT ON INDEX iam.application_secrets_one_active_idx IS
    'An Application has exactly one usable primary client secret after an atomic rotation.';
