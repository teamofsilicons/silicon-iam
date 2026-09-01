-- Harden the public authentication contract without rewriting historical
-- migrations. Runtime challenge creation carries failed-attempt state across
-- replacement codes; these indexes keep the locked scope lookups bounded.

CREATE INDEX signup_otp_challenges_attempt_scope_idx
    ON iam.signup_otp_challenges (
        signup_session_id,
        contact_kind,
        created_at DESC,
        id DESC
    );

CREATE INDEX login_challenge_channels_attempt_scope_idx
    ON iam.login_challenge_channels (carbon_id, created_at DESC, id DESC)
    WHERE consumed_at IS NULL AND superseded_at IS NULL;

CREATE INDEX step_up_challenges_attempt_scope_idx
    ON iam.step_up_challenges (
        authentication_session_id,
        carbon_id,
        purpose,
        resource_id,
        created_at DESC,
        id DESC
    )
    WHERE status = 'pending';

-- Signup must suppress delivery when an active verified contact belongs to a
-- non-deleted Carbon even while that Carbon is suspended. Login intentionally
-- retains its stricter active-principal resolver.
CREATE FUNCTION iam_private.non_deleted_carbon_contact_exists(
    p_contact_kind iam.contact_kind,
    p_hmac_key_version smallint,
    p_digest bytea
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.contact_blind_indexes AS blind_index
        JOIN iam.carbon_contacts AS contact
          ON contact.id = blind_index.contact_id
         AND contact.kind = blind_index.contact_kind
        JOIN iam.carbons AS carbon ON carbon.id = contact.carbon_id
        JOIN iam.principals AS principal
          ON principal.id = carbon.id
         AND principal.kind = 'carbon'
        WHERE blind_index.contact_kind = p_contact_kind
          AND blind_index.hmac_key_version = p_hmac_key_version
          AND blind_index.digest = p_digest
          AND octet_length(p_digest) = 32
          AND contact.status = 'active'
          AND contact.is_primary
          AND contact.verified_at IS NOT NULL
          AND carbon.deleted_at IS NULL
          AND principal.deleted_at IS NULL
          AND principal.status IN ('active', 'suspended')
    )
$$;

REVOKE ALL ON FUNCTION iam_private.non_deleted_carbon_contact_exists(
    iam.contact_kind, smallint, bytea
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.non_deleted_carbon_contact_exists(
    iam.contact_kind, smallint, bytea
) IS
    'Signup-only blind-index association check covering active and suspended non-deleted Carbons without exposing contact material.';

-- The generic platform-admin action granted authority wider than its only
-- supported consumer. Retire outstanding generic artifacts and admit only the
-- narrowly scoped SSO-entitlement action for new challenges and assertions.
UPDATE iam.step_up_assertions
SET consumed_at = transaction_timestamp()
WHERE purpose = 'platform_admin.manage'
  AND consumed_at IS NULL;

UPDATE iam.step_up_challenges
SET status = 'cancelled'
WHERE purpose = 'platform_admin.manage'
  AND status = 'pending';

ALTER TABLE iam.step_up_challenges
    ADD CONSTRAINT step_up_challenges_supported_purpose CHECK (
        purpose IN (
            'account.session_revoke',
            'account.sessions_revoke_all',
            'organization.transfer_ownership',
            'organization.authorization_change',
            'organization.sso_change',
            'organization.silicon_webhook.redirect',
            'silicon.rotate_token',
            'platform_admin.sso_entitlement',
            'platform_admin.application_review'
        )
    ) NOT VALID,
    ADD CONSTRAINT step_up_challenges_resource_required
        CHECK (resource_id IS NOT NULL) NOT VALID;

ALTER TABLE iam.step_up_assertions
    ADD CONSTRAINT step_up_assertions_supported_purpose CHECK (
        purpose IN (
            'account.session_revoke',
            'account.sessions_revoke_all',
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
    'Closed action catalog for every challenge created after this migration; NOT VALID preserves immutable historical retired actions.';
COMMENT ON CONSTRAINT step_up_challenges_resource_required ON iam.step_up_challenges IS
    'Requires every challenge created after this migration to bind one exact resource UUID; historical terminal rows remain untouched.';
COMMENT ON CONSTRAINT step_up_assertions_supported_purpose ON iam.step_up_assertions IS
    'Closed action catalog for every assertion created after this migration; NOT VALID preserves immutable historical retired actions.';

-- All newly inserted reusable OTP challenges use the exact ten-failure
-- contract even if a future code path omits an explicit max_attempts value.
ALTER TABLE iam.signup_otp_challenges
    ADD CONSTRAINT signup_otp_challenges_contract_attempts
        CHECK (max_attempts = 10) NOT VALID;
ALTER TABLE iam.login_challenge_channels
    ADD CONSTRAINT login_challenge_channels_contract_attempts
        CHECK (max_attempts = 10) NOT VALID;
ALTER TABLE iam.invitation_verification_challenges
    ADD CONSTRAINT invitation_verification_contract_attempts
        CHECK (max_attempts = 10) NOT VALID;
ALTER TABLE iam.step_up_challenges
    ADD CONSTRAINT step_up_challenges_contract_attempts
        CHECK (max_attempts = 10) NOT VALID;
