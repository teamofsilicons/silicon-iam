-- Retire the undeclared service-principal credential plane while preserving
-- immutable principal and audit history. Service principals may remain as
-- inert historical actors, but no new service session or bearer token can be
-- created or authenticated after this transition.

UPDATE iam.principals AS principal
SET status = 'suspended',
    auth_epoch = principal.auth_epoch + 1,
    suspended_at = COALESCE(principal.suspended_at, transaction_timestamp())
WHERE principal.kind = 'service'
  AND principal.status IN ('provisioning', 'active');

UPDATE iam.authentication_sessions AS authentication_session
SET status = 'revoked',
    revoked_at = COALESCE(authentication_session.revoked_at, transaction_timestamp()),
    revocation_reason = COALESCE(
        authentication_session.revocation_reason,
        'service credential authentication retired'
    )
WHERE authentication_session.subject_kind = 'service'
  AND authentication_session.status <> 'revoked';

UPDATE iam.refresh_token_families AS family
SET status = 'revoked',
    revoked_at = COALESCE(family.revoked_at, transaction_timestamp()),
    revocation_reason = COALESCE(
        family.revocation_reason,
        'service credential authentication retired'
    )
WHERE family.subject_principal_id IN (
    SELECT principal.id
    FROM iam.principals AS principal
    WHERE principal.kind = 'service'
)
  AND family.status <> 'revoked';

UPDATE iam.refresh_tokens AS refresh_token
SET revoked_at = COALESCE(refresh_token.revoked_at, transaction_timestamp())
WHERE refresh_token.family_id IN (
    SELECT family.id
    FROM iam.refresh_token_families AS family
    JOIN iam.principals AS principal
      ON principal.id = family.subject_principal_id
     AND principal.kind = 'service'
);

-- Service access tokens were never valid OBO parents in the public contract,
-- but purge any impossible legacy proof defensively before removing the token.
DELETE FROM iam.obo_proofs AS proof
WHERE proof.parent_access_token_id IN (
    SELECT access_token.id
    FROM iam.access_tokens AS access_token
    WHERE access_token.token_class = 'service_access'
);

DELETE FROM iam.access_token_scopes AS token_scope
WHERE token_scope.access_token_id IN (
    SELECT access_token.id
    FROM iam.access_tokens AS access_token
    WHERE access_token.token_class = 'service_access'
);

DELETE FROM iam.access_tokens AS access_token
WHERE access_token.token_class = 'service_access';

DROP TABLE IF EXISTS iam.service_credentials;

ALTER TABLE iam.access_tokens
    DROP CONSTRAINT access_tokens_class,
    DROP CONSTRAINT access_tokens_prefix_format,
    DROP CONSTRAINT access_tokens_class_prefix_and_subject,
    ADD CONSTRAINT access_tokens_class
        CHECK (token_class IN ('carbon_access', 'silicon_access', 'application_access')),
    ADD CONSTRAINT access_tokens_prefix_format
        CHECK (token_prefix ~ '^(cat|sat|oat)_[A-Za-z0-9_-]{8}$'),
    ADD CONSTRAINT access_tokens_class_prefix_and_subject CHECK (
        (token_class = 'carbon_access'
            AND subject_kind = 'carbon'
            AND left(token_prefix, 4) = 'cat_')
        OR (token_class = 'silicon_access'
            AND subject_kind = 'silicon'
            AND left(token_prefix, 4) = 'sat_')
        OR (token_class = 'application_access'
            AND subject_kind IN ('carbon', 'silicon')
            AND left(token_prefix, 4) = 'oat_')
    );

-- NOT VALID preserves any revoked historical service session while enforcing
-- the reduced method vocabulary for every newly inserted or updated row.
ALTER TABLE iam.authentication_sessions
    DROP CONSTRAINT authentication_sessions_method,
    ADD CONSTRAINT authentication_sessions_method
        CHECK (authentication_method IN (
            'email_otp', 'phone_otp', 'silicon_credential', 'workos_sso', 'refresh_token'
        )) NOT VALID;

DO $validate_authentication_session_methods$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM iam.authentication_sessions AS authentication_session
        WHERE authentication_session.authentication_method NOT IN (
            'email_otp', 'phone_otp', 'silicon_credential', 'workos_sso', 'refresh_token'
        )
    ) THEN
        ALTER TABLE iam.authentication_sessions
            VALIDATE CONSTRAINT authentication_sessions_method;
    END IF;
END;
$validate_authentication_session_methods$;

COMMENT ON TABLE iam.authentication_sessions IS
    'Revocable parent sessions. Carbon and Silicon absolute lifetime may be at most 900 days by service policy.';

COMMENT ON TABLE iam.rate_limit_buckets IS
    'Authoritative PostgreSQL state for distributed abuse controls.';
