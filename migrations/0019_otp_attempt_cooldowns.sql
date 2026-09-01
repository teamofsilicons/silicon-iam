-- Align every IAM-managed verification challenge with the ten-attempt,
-- one-minute cooldown policy. Challenges remain reusable after cooldown while
-- their original ten-minute expiry remains authoritative.

ALTER TABLE iam.signup_otp_challenges
    DROP CONSTRAINT signup_otp_challenges_attempts;
ALTER TABLE iam.login_challenge_channels
    DROP CONSTRAINT login_challenge_channels_attempts;
ALTER TABLE iam.invitation_verification_challenges
    DROP CONSTRAINT invitation_verification_attempts;
ALTER TABLE iam.step_up_challenges
    DROP CONSTRAINT step_up_challenges_attempts;

ALTER TABLE iam.step_up_challenges
    ADD COLUMN cooldown_until timestamptz;

ALTER TABLE iam.signup_otp_challenges
    ALTER COLUMN max_attempts SET DEFAULT 10;
ALTER TABLE iam.login_challenge_channels
    ALTER COLUMN max_attempts SET DEFAULT 10;
ALTER TABLE iam.invitation_verification_challenges
    ALTER COLUMN max_attempts SET DEFAULT 10;
ALTER TABLE iam.step_up_challenges
    ALTER COLUMN max_attempts SET DEFAULT 10;

-- Adopt the new policy for still-usable challenges. Historical terminal rows
-- retain the policy under which they were attempted.
UPDATE iam.signup_otp_challenges
SET max_attempts = 10
WHERE consumed_at IS NULL
  AND superseded_at IS NULL
  AND expires_at > transaction_timestamp();

UPDATE iam.login_challenge_channels
SET max_attempts = 10
WHERE consumed_at IS NULL
  AND superseded_at IS NULL
  AND expires_at > transaction_timestamp();

UPDATE iam.invitation_verification_challenges
SET max_attempts = 10,
    cooldown_until = NULL
WHERE consumed_at IS NULL
  AND superseded_at IS NULL
  AND expires_at > transaction_timestamp();

UPDATE iam.step_up_challenges
SET max_attempts = 10
WHERE status = 'pending'
  AND expires_at > transaction_timestamp();

ALTER TABLE iam.signup_otp_challenges
    ADD CONSTRAINT signup_otp_challenges_attempts
        CHECK (max_attempts BETWEEN 1 AND 10 AND failed_attempts BETWEEN 0 AND max_attempts);
ALTER TABLE iam.login_challenge_channels
    ADD CONSTRAINT login_challenge_channels_attempts
        CHECK (max_attempts BETWEEN 1 AND 10 AND failed_attempts BETWEEN 0 AND max_attempts);
ALTER TABLE iam.invitation_verification_challenges
    ADD CONSTRAINT invitation_verification_attempts
        CHECK (max_attempts BETWEEN 1 AND 10 AND failed_attempts BETWEEN 0 AND max_attempts);
ALTER TABLE iam.step_up_challenges
    ADD CONSTRAINT step_up_challenges_attempts
        CHECK (max_attempts BETWEEN 1 AND 10 AND attempt_count BETWEEN 0 AND max_attempts);

COMMENT ON COLUMN iam.signup_otp_challenges.cooldown_until IS
    'Verification is denied until this instant after an exhausted ten-attempt window; the same unexpired challenge is reusable afterward.';
COMMENT ON COLUMN iam.login_challenge_channels.cooldown_until IS
    'Verification is denied until this instant after an exhausted ten-attempt window; the same unexpired challenge is reusable afterward.';
COMMENT ON COLUMN iam.invitation_verification_challenges.cooldown_until IS
    'Verification is denied until this instant after an exhausted ten-attempt window; the same unexpired challenge is reusable afterward.';
COMMENT ON COLUMN iam.step_up_challenges.cooldown_until IS
    'Verification is denied until this instant after an exhausted ten-attempt window; the same unexpired challenge is reusable afterward.';
