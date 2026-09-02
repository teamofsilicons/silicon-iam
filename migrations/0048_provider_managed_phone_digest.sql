-- A provider-managed phone OTP is generated and validated by Twilio Verify, so
-- IAM never holds a code for it. The digest columns previously demanded one
-- anyway, which left an undeliverable secret at rest on every phone challenge.
-- They now admit its absence, and a new constraint keeps every channel that
-- still carries a local code from losing its digest.

ALTER TABLE iam.signup_otp_challenges
    ALTER COLUMN code_digest DROP NOT NULL,
    ALTER COLUMN digest_key_version DROP NOT NULL,
    ADD CONSTRAINT signup_otp_challenges_local_digest CHECK (
        (code_digest IS NULL) = (digest_key_version IS NULL)
        AND (code_digest IS NOT NULL OR contact_kind = 'phone')
    );

ALTER TABLE iam.login_challenge_channels
    ALTER COLUMN code_digest DROP NOT NULL,
    ALTER COLUMN digest_key_version DROP NOT NULL,
    ADD CONSTRAINT login_challenge_channels_local_digest CHECK (
        (code_digest IS NULL) = (digest_key_version IS NULL)
        AND (code_digest IS NOT NULL OR contact_kind = 'phone')
    );

ALTER TABLE iam.step_up_challenges
    ALTER COLUMN challenge_digest DROP NOT NULL,
    ALTER COLUMN digest_key_version DROP NOT NULL,
    ADD CONSTRAINT step_up_challenges_local_digest CHECK (
        (challenge_digest IS NULL) = (digest_key_version IS NULL)
        AND (challenge_digest IS NOT NULL OR channel = 'phone')
    );

COMMENT ON COLUMN iam.signup_otp_challenges.code_digest IS
    'Keyed digest of the locally generated code; NULL when a provider generates and validates the phone code instead.';
COMMENT ON COLUMN iam.login_challenge_channels.code_digest IS
    'Keyed digest of the locally generated code; NULL when a provider generates and validates the phone code instead.';
COMMENT ON COLUMN iam.step_up_challenges.challenge_digest IS
    'Keyed digest of the locally generated code; NULL when a provider generates and validates the phone code instead.';
