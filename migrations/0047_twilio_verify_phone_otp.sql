ALTER TABLE iam.signup_otp_challenges
    ADD COLUMN provider_verification_sid text,
    ADD CONSTRAINT signup_otp_challenges_provider_verification_sid CHECK (
        provider_verification_sid IS NULL
        OR (
            contact_kind = 'phone'
            AND provider_verification_sid ~ '^VE[0-9A-Fa-f]{32}$'
        )
    );

ALTER TABLE iam.login_challenge_channels
    ADD COLUMN provider_verification_sid text,
    ADD CONSTRAINT login_challenge_channels_provider_verification_sid CHECK (
        provider_verification_sid IS NULL
        OR (
            contact_kind = 'phone'
            AND provider_verification_sid ~ '^VE[0-9A-Fa-f]{32}$'
        )
    );

ALTER TABLE iam.step_up_challenges
    ADD COLUMN provider_verification_sid text,
    ADD CONSTRAINT step_up_challenges_provider_verification_sid CHECK (
        provider_verification_sid IS NULL
        OR (
            channel = 'phone'
            AND provider_verification_sid ~ '^VE[0-9A-Fa-f]{32}$'
        )
    );

COMMENT ON COLUMN iam.signup_otp_challenges.provider_verification_sid IS
    'Twilio Verify attempt identifier for provider-generated phone OTPs; contains no recipient PII.';
COMMENT ON COLUMN iam.login_challenge_channels.provider_verification_sid IS
    'Twilio Verify attempt identifier for provider-generated phone OTPs; contains no recipient PII.';
COMMENT ON COLUMN iam.step_up_challenges.provider_verification_sid IS
    'Twilio Verify attempt identifier for provider-generated phone OTPs; contains no recipient PII.';
