-- Refresh validity is governed by one absolute family/session deadline. The
-- former rolling 30-day idle deadline was not part of the public IAM contract
-- and could make an otherwise active 900-day refresh family unusable.

UPDATE iam.authentication_sessions AS authentication_session
SET idle_expires_at = authentication_session.absolute_expires_at
WHERE authentication_session.status = 'active'
  AND authentication_session.idle_expires_at
        IS DISTINCT FROM authentication_session.absolute_expires_at;

-- OAuth refresh credentials used the same undocumented 30-day deadline on
-- each rotating token. Align currently usable credentials with their existing
-- immutable family deadline; explicit revocation, rotation consumption,
-- principal/client epochs, consent, and parent-session checks remain intact.
UPDATE iam.refresh_tokens AS refresh_token
SET expires_at = family.absolute_expires_at
FROM iam.refresh_token_families AS family
WHERE family.id = refresh_token.family_id
  AND family.client_application_id IS NOT NULL
  AND family.status = 'active'
  AND family.absolute_expires_at > transaction_timestamp()
  AND refresh_token.consumed_at IS NULL
  AND refresh_token.revoked_at IS NULL
  AND refresh_token.expires_at IS DISTINCT FROM family.absolute_expires_at;

COMMENT ON COLUMN iam.authentication_sessions.idle_expires_at IS
    'Compatibility deadline kept equal to absolute_expires_at; IAM sessions have no separate idle expiry.';

COMMENT ON COLUMN iam.refresh_tokens.expires_at IS
    'Credential deadline equal to its refresh family absolute expiry; rotation, revocation, replay, and authority checks remain independent.';

-- Authentication challenges are prepared durably before provider I/O. Legacy
-- rows predate this state machine and were only committed after synchronous
-- delivery, so they are backfilled as delivered.
ALTER TABLE iam.signup_otp_challenges
    ADD COLUMN delivery_status text NOT NULL DEFAULT 'delivered',
    ADD COLUMN delivered_at timestamptz DEFAULT transaction_timestamp(),
    ADD COLUMN delivery_failed_at timestamptz,
    ADD CONSTRAINT signup_otp_challenges_delivery_status
        CHECK (delivery_status IN ('pending', 'delivered', 'failed')),
    ADD CONSTRAINT signup_otp_challenges_delivery_consistency CHECK (
        (delivery_status = 'pending'
            AND delivered_at IS NULL
            AND delivery_failed_at IS NULL)
        OR (delivery_status = 'delivered'
            AND delivered_at IS NOT NULL
            AND delivery_failed_at IS NULL)
        OR (delivery_status = 'failed'
            AND delivered_at IS NULL
            AND delivery_failed_at IS NOT NULL)
    );

ALTER TABLE iam.login_challenges
    ADD COLUMN delivery_status text NOT NULL DEFAULT 'delivered',
    ADD COLUMN delivered_at timestamptz DEFAULT transaction_timestamp(),
    ADD COLUMN delivery_failed_at timestamptz,
    ADD CONSTRAINT login_challenges_delivery_status
        CHECK (delivery_status IN ('pending', 'delivered', 'failed')),
    ADD CONSTRAINT login_challenges_delivery_consistency CHECK (
        (delivery_status = 'pending'
            AND delivered_at IS NULL
            AND delivery_failed_at IS NULL)
        OR (delivery_status = 'delivered'
            AND delivered_at IS NOT NULL
            AND delivery_failed_at IS NULL)
        OR (delivery_status = 'failed'
            AND delivered_at IS NULL
            AND delivery_failed_at IS NOT NULL)
    );

ALTER TABLE iam.step_up_challenges
    ADD COLUMN delivery_status text NOT NULL DEFAULT 'delivered',
    ADD COLUMN delivered_at timestamptz DEFAULT transaction_timestamp(),
    ADD COLUMN delivery_failed_at timestamptz,
    ADD CONSTRAINT step_up_challenges_delivery_status
        CHECK (delivery_status IN ('pending', 'delivered', 'failed')),
    ADD CONSTRAINT step_up_challenges_delivery_consistency CHECK (
        (delivery_status = 'pending'
            AND delivered_at IS NULL
            AND delivery_failed_at IS NULL)
        OR (delivery_status = 'delivered'
            AND delivered_at IS NOT NULL
            AND delivery_failed_at IS NULL)
        OR (delivery_status = 'failed'
            AND delivered_at IS NULL
            AND delivery_failed_at IS NOT NULL)
    );

-- The temporary delivered defaults above exist only to classify legacy rows.
-- All future writers fail closed when they omit delivery state.
ALTER TABLE iam.signup_otp_challenges
    ALTER COLUMN delivery_status SET DEFAULT 'pending',
    ALTER COLUMN delivered_at DROP DEFAULT;
ALTER TABLE iam.login_challenges
    ALTER COLUMN delivery_status SET DEFAULT 'pending',
    ALTER COLUMN delivered_at DROP DEFAULT;
ALTER TABLE iam.step_up_challenges
    ALTER COLUMN delivery_status SET DEFAULT 'pending',
    ALTER COLUMN delivered_at DROP DEFAULT;

COMMENT ON COLUMN iam.signup_otp_challenges.delivery_status IS
    'Fail-closed delivery state: pending challenges cannot verify; delivered is activated only after provider confirmation.';
COMMENT ON COLUMN iam.login_challenges.delivery_status IS
    'Fail-closed delivery state: pending challenges cannot verify; delivered is activated only after every required provider confirms.';
COMMENT ON COLUMN iam.step_up_challenges.delivery_status IS
    'Fail-closed delivery state: pending challenges cannot verify; delivered is activated only after provider confirmation.';

COMMENT ON TABLE iam.login_challenge_channels IS
    'One or more IAM-digested email/phone verifiers; plaintext OTPs are never persisted, and their parent challenge activates only after every required delivery is confirmed.';
