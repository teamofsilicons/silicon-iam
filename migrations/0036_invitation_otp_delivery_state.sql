-- Organization invitation OTPs must not become usable until Postmark confirms
-- the send. Historical unconsumed challenges cannot be proven delivered
-- because the former handler discarded the provider outcome, so retire them
-- fail closed and require callers to request a fresh code.

ALTER TABLE iam.invitation_verification_challenges
    ADD COLUMN delivery_status text,
    ADD COLUMN delivered_at timestamptz,
    ADD COLUMN delivery_failed_at timestamptz;

UPDATE iam.invitation_verification_challenges
SET delivery_status = CASE
        WHEN consumed_at IS NOT NULL THEN 'delivered'
        ELSE 'failed'
    END,
    delivered_at = CASE
        WHEN consumed_at IS NOT NULL THEN created_at
        ELSE NULL
    END,
    delivery_failed_at = CASE
        WHEN consumed_at IS NULL THEN transaction_timestamp()
        ELSE NULL
    END,
    superseded_at = CASE
        WHEN consumed_at IS NULL THEN COALESCE(superseded_at, transaction_timestamp())
        ELSE superseded_at
    END;

ALTER TABLE iam.invitation_verification_challenges
    ALTER COLUMN delivery_status SET NOT NULL,
    ALTER COLUMN delivery_status SET DEFAULT 'pending',
    ADD CONSTRAINT invitation_verification_delivery_status CHECK (
        delivery_status IN ('pending', 'delivered', 'failed')
    ),
    ADD CONSTRAINT invitation_verification_delivery_consistency CHECK (
        (delivery_status = 'pending'
            AND delivered_at IS NULL
            AND delivery_failed_at IS NULL)
        OR (delivery_status = 'delivered'
            AND delivered_at IS NOT NULL
            AND delivery_failed_at IS NULL)
        OR (delivery_status = 'failed'
            AND delivered_at IS NULL
            AND delivery_failed_at IS NOT NULL)
    ),
    ADD CONSTRAINT invitation_verification_consumed_after_delivery CHECK (
        consumed_at IS NULL OR delivery_status = 'delivered'
    );

COMMENT ON COLUMN iam.invitation_verification_challenges.delivery_status IS
    'Fail-closed delivery state: pending and failed invitation OTPs cannot be consumed; delivered is activated only after provider confirmation.';
COMMENT ON COLUMN iam.invitation_verification_challenges.delivered_at IS
    'Time IAM durably confirmed the provider-accepted invitation OTP delivery.';
COMMENT ON COLUMN iam.invitation_verification_challenges.delivery_failed_at IS
    'Time a definitive provider rejection retired the invitation OTP; null for ambiguous pending outcomes.';

