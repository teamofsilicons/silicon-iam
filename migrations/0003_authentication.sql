-- Passwordless enrollment, authentication sessions, opaque access tokens, and rotating refresh tokens.

CREATE TABLE iam.signup_sessions (
    id uuid PRIMARY KEY,
    status text NOT NULL DEFAULT 'pending',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    completed_carbon_id uuid,
    completed_at timestamptz,
    CONSTRAINT signup_sessions_completed_carbon_fk
        FOREIGN KEY (completed_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT signup_sessions_status CHECK (status IN ('pending', 'completed', 'expired', 'cancelled')),
    CONSTRAINT signup_sessions_expiry CHECK (expires_at > created_at),
    CONSTRAINT signup_sessions_completion_consistency CHECK (
        (status = 'completed') = (completed_carbon_id IS NOT NULL AND completed_at IS NOT NULL)
    ),
    CONSTRAINT signup_sessions_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.signup_sessions IS
    'Forty-eight-hour Carbon signup aggregates binding verified email and phone candidates.';

CREATE TRIGGER signup_sessions_bump_version
BEFORE UPDATE ON iam.signup_sessions
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE INDEX signup_sessions_expiry_idx
    ON iam.signup_sessions (status, expires_at) WHERE status = 'pending';

CREATE TABLE iam.signup_contact_candidates (
    id uuid PRIMARY KEY,
    signup_session_id uuid NOT NULL,
    kind iam.contact_kind NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    encryption_key_version smallint NOT NULL,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    verified_at timestamptz,
    superseded_at timestamptz,
    UNIQUE (id, kind),
    UNIQUE (id, signup_session_id, kind),
    CONSTRAINT signup_contact_candidates_session_fk
        FOREIGN KEY (signup_session_id) REFERENCES iam.signup_sessions (id) ON DELETE RESTRICT,
    CONSTRAINT signup_contact_candidates_encryption_key_fk
        FOREIGN KEY (encryption_purpose, encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT signup_contact_candidates_ciphertext_length
        CHECK (octet_length(ciphertext) BETWEEN 17 AND 8192),
    CONSTRAINT signup_contact_candidates_nonce_length
        CHECK (octet_length(nonce) BETWEEN 12 AND 32),
    CONSTRAINT signup_contact_candidates_verification_consistency
        CHECK (verified_at IS NULL OR superseded_at IS NULL)
);

CREATE UNIQUE INDEX signup_contact_candidates_one_current_kind_idx
    ON iam.signup_contact_candidates (signup_session_id, kind)
    WHERE superseded_at IS NULL;

CREATE TABLE iam.signup_candidate_blind_indexes (
    candidate_id uuid NOT NULL,
    contact_kind iam.contact_kind NOT NULL,
    hmac_key_version smallint NOT NULL,
    hmac_purpose text
        GENERATED ALWAYS AS ('contact_lookup_hmac'::text) STORED,
    digest bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (candidate_id, hmac_key_version),
    CONSTRAINT signup_candidate_blind_indexes_candidate_fk
        FOREIGN KEY (candidate_id, contact_kind)
        REFERENCES iam.signup_contact_candidates (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT signup_candidate_blind_indexes_key_fk
        FOREIGN KEY (hmac_purpose, hmac_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT signup_candidate_blind_indexes_digest_length CHECK (octet_length(digest) = 32)
);

CREATE INDEX signup_candidate_blind_indexes_lookup_idx
    ON iam.signup_candidate_blind_indexes (contact_kind, hmac_key_version, digest);

CREATE TABLE iam.signup_otp_challenges (
    id uuid PRIMARY KEY,
    signup_session_id uuid NOT NULL,
    candidate_id uuid NOT NULL,
    contact_kind iam.contact_kind NOT NULL,
    code_digest bytea NOT NULL,
    digest_key_version smallint NOT NULL,
    digest_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    failed_attempts smallint NOT NULL DEFAULT 0,
    max_attempts smallint NOT NULL DEFAULT 5,
    cooldown_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    superseded_at timestamptz,
    CONSTRAINT signup_otp_challenges_session_fk
        FOREIGN KEY (signup_session_id) REFERENCES iam.signup_sessions (id) ON DELETE RESTRICT,
    CONSTRAINT signup_otp_challenges_candidate_fk
        FOREIGN KEY (candidate_id, signup_session_id, contact_kind)
        REFERENCES iam.signup_contact_candidates (id, signup_session_id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT signup_otp_challenges_digest_key_fk
        FOREIGN KEY (digest_purpose, digest_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT signup_otp_challenges_digest_length CHECK (octet_length(code_digest) = 32),
    CONSTRAINT signup_otp_challenges_attempts
        CHECK (max_attempts BETWEEN 1 AND 5 AND failed_attempts BETWEEN 0 AND max_attempts),
    CONSTRAINT signup_otp_challenges_expiry CHECK (expires_at > created_at),
    CONSTRAINT signup_otp_challenges_terminal_exclusivity
        CHECK (consumed_at IS NULL OR superseded_at IS NULL)
);

CREATE UNIQUE INDEX signup_otp_challenges_one_current_idx
    ON iam.signup_otp_challenges (candidate_id)
    WHERE consumed_at IS NULL AND superseded_at IS NULL;
CREATE INDEX signup_otp_challenges_expiry_idx
    ON iam.signup_otp_challenges (expires_at)
    WHERE consumed_at IS NULL AND superseded_at IS NULL;

COMMENT ON TABLE iam.signup_otp_challenges IS
    'IAM-generated signup OTP digests; plaintext is delivered synchronously after commit and never retained.';

CREATE TABLE iam.login_challenges (
    id uuid PRIMARY KEY,
    carbon_id uuid NOT NULL,
    requested_identifier_kind text NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    cancelled_at timestamptz,
    UNIQUE (id, carbon_id),
    CONSTRAINT login_challenges_carbon_fk
        FOREIGN KEY (carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT login_challenges_identifier_kind
        CHECK (requested_identifier_kind IN ('email', 'phone', 'carbon_id')),
    CONSTRAINT login_challenges_status
        CHECK (status IN ('pending', 'completed', 'expired', 'cancelled')),
    CONSTRAINT login_challenges_expiry CHECK (expires_at > created_at),
    CONSTRAINT login_challenges_terminal_consistency CHECK (
        (status <> 'completed' OR consumed_at IS NOT NULL)
        AND (status <> 'cancelled' OR cancelled_at IS NOT NULL)
    )
);

CREATE INDEX login_challenges_carbon_idx
    ON iam.login_challenges (carbon_id, created_at DESC);
CREATE INDEX login_challenges_expiry_idx
    ON iam.login_challenges (status, expires_at) WHERE status = 'pending';

CREATE TABLE iam.login_challenge_channels (
    id uuid PRIMARY KEY,
    login_challenge_id uuid NOT NULL,
    carbon_id uuid NOT NULL,
    contact_id uuid NOT NULL,
    contact_kind iam.contact_kind NOT NULL,
    code_digest bytea NOT NULL,
    digest_key_version smallint NOT NULL,
    digest_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    failed_attempts smallint NOT NULL DEFAULT 0,
    max_attempts smallint NOT NULL DEFAULT 5,
    cooldown_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    superseded_at timestamptz,
    CONSTRAINT login_challenge_channels_challenge_fk
        FOREIGN KEY (login_challenge_id, carbon_id)
        REFERENCES iam.login_challenges (id, carbon_id)
        ON DELETE RESTRICT,
    CONSTRAINT login_challenge_channels_contact_fk
        FOREIGN KEY (carbon_id, contact_id)
        REFERENCES iam.carbon_contacts (carbon_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT login_challenge_channels_contact_kind_fk
        FOREIGN KEY (contact_id, contact_kind)
        REFERENCES iam.carbon_contacts (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT login_challenge_channels_digest_key_fk
        FOREIGN KEY (digest_purpose, digest_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT login_challenge_channels_digest_length CHECK (octet_length(code_digest) = 32),
    CONSTRAINT login_challenge_channels_attempts
        CHECK (max_attempts BETWEEN 1 AND 5 AND failed_attempts BETWEEN 0 AND max_attempts),
    CONSTRAINT login_challenge_channels_expiry CHECK (expires_at > created_at),
    CONSTRAINT login_challenge_channels_terminal_exclusivity
        CHECK (consumed_at IS NULL OR superseded_at IS NULL)
);

COMMENT ON TABLE iam.login_challenge_channels IS
    'One or more IAM-digested email/phone verifiers; Carbon-ID login may synchronously deliver both after commit.';

CREATE UNIQUE INDEX login_challenge_channels_one_current_contact_idx
    ON iam.login_challenge_channels (login_challenge_id, contact_id)
    WHERE consumed_at IS NULL AND superseded_at IS NULL;
CREATE INDEX login_challenge_channels_expiry_idx
    ON iam.login_challenge_channels (expires_at)
    WHERE consumed_at IS NULL AND superseded_at IS NULL;

CREATE TABLE iam.authentication_sessions (
    id uuid PRIMARY KEY,
    subject_principal_id uuid NOT NULL,
    subject_kind iam.principal_kind NOT NULL,
    parent_session_id uuid,
    authentication_method text NOT NULL,
    assurance_level smallint NOT NULL DEFAULT 1,
    subject_auth_epoch bigint NOT NULL,
    status text NOT NULL DEFAULT 'active',
    authenticated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    last_seen_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_reason text,
    ip_fingerprint bytea,
    user_agent_fingerprint bytea,
    version bigint NOT NULL DEFAULT 1,
    UNIQUE (id, subject_principal_id),
    CONSTRAINT authentication_sessions_subject_fk
        FOREIGN KEY (subject_principal_id, subject_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT authentication_sessions_parent_fk
        FOREIGN KEY (parent_session_id, subject_principal_id)
        REFERENCES iam.authentication_sessions (id, subject_principal_id)
        ON DELETE RESTRICT,
    CONSTRAINT authentication_sessions_method
        CHECK (authentication_method IN (
            'email_otp', 'phone_otp', 'silicon_credential', 'service_credential',
            'workos_sso', 'refresh_token'
        )),
    CONSTRAINT authentication_sessions_assurance CHECK (assurance_level BETWEEN 1 AND 3),
    CONSTRAINT authentication_sessions_positive_epoch CHECK (subject_auth_epoch > 0),
    CONSTRAINT authentication_sessions_status
        CHECK (status IN ('active', 'revoked', 'expired')),
    CONSTRAINT authentication_sessions_expiry_order CHECK (
        idle_expires_at > created_at
        AND absolute_expires_at > created_at
        AND idle_expires_at <= absolute_expires_at
    ),
    CONSTRAINT authentication_sessions_revocation_consistency
        CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CONSTRAINT authentication_sessions_revocation_reason_length
        CHECK (revocation_reason IS NULL OR char_length(revocation_reason) <= 500),
    CONSTRAINT authentication_sessions_fingerprint_lengths CHECK (
        (ip_fingerprint IS NULL OR octet_length(ip_fingerprint) = 32)
        AND (user_agent_fingerprint IS NULL OR octet_length(user_agent_fingerprint) = 32)
    ),
    CONSTRAINT authentication_sessions_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.authentication_sessions IS
    'Revocable parent sessions. Carbon absolute lifetime may be at most 365 days by service policy.';

CREATE INDEX authentication_sessions_subject_idx
    ON iam.authentication_sessions (subject_principal_id, status, created_at DESC);
CREATE INDEX authentication_sessions_expiry_idx
    ON iam.authentication_sessions (status, absolute_expires_at)
    WHERE status = 'active';

CREATE TABLE iam.refresh_token_families (
    id uuid PRIMARY KEY,
    authentication_session_id uuid NOT NULL,
    subject_principal_id uuid NOT NULL,
    client_application_id uuid,
    client_kind iam.principal_kind
        GENERATED ALWAYS AS ('application'::iam.principal_kind) STORED,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    compromised_at timestamptz,
    revocation_reason text,
    CONSTRAINT refresh_token_families_session_fk
        FOREIGN KEY (authentication_session_id, subject_principal_id)
        REFERENCES iam.authentication_sessions (id, subject_principal_id)
        ON DELETE RESTRICT,
    CONSTRAINT refresh_token_families_client_fk
        FOREIGN KEY (client_application_id, client_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT refresh_token_families_status
        CHECK (status IN ('active', 'revoked', 'compromised', 'expired')),
    CONSTRAINT refresh_token_families_expiry CHECK (absolute_expires_at > created_at),
    CONSTRAINT refresh_token_families_terminal_consistency CHECK (
        (status <> 'revoked' OR revoked_at IS NOT NULL)
        AND (status <> 'compromised' OR compromised_at IS NOT NULL)
    ),
    CONSTRAINT refresh_token_families_revocation_reason_length
        CHECK (revocation_reason IS NULL OR char_length(revocation_reason) <= 500)
);

CREATE INDEX refresh_token_families_session_idx
    ON iam.refresh_token_families (authentication_session_id, status);

CREATE TABLE iam.refresh_tokens (
    id uuid PRIMARY KEY,
    family_id uuid NOT NULL,
    parent_token_id uuid,
    replacement_token_id uuid,
    token_digest bytea NOT NULL,
    digest_key_version smallint NOT NULL,
    digest_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    token_prefix text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    UNIQUE (token_digest),
    UNIQUE (family_id, id),
    UNIQUE (parent_token_id),
    UNIQUE (replacement_token_id),
    CONSTRAINT refresh_tokens_family_fk
        FOREIGN KEY (family_id) REFERENCES iam.refresh_token_families (id) ON DELETE RESTRICT,
    CONSTRAINT refresh_tokens_parent_fk
        FOREIGN KEY (parent_token_id) REFERENCES iam.refresh_tokens (id) ON DELETE RESTRICT,
    CONSTRAINT refresh_tokens_replacement_fk
        FOREIGN KEY (replacement_token_id) REFERENCES iam.refresh_tokens (id) ON DELETE RESTRICT,
    CONSTRAINT refresh_tokens_digest_key_fk
        FOREIGN KEY (digest_purpose, digest_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT refresh_tokens_digest_length CHECK (octet_length(token_digest) = 32),
    CONSTRAINT refresh_tokens_prefix_format CHECK (token_prefix ~ '^(rft|ort)_[A-Za-z0-9_-]{8}$'),
    CONSTRAINT refresh_tokens_expiry CHECK (expires_at > created_at),
    CONSTRAINT refresh_tokens_rotation_consistency CHECK (
        (consumed_at IS NULL AND replacement_token_id IS NULL)
        OR (consumed_at IS NOT NULL AND replacement_token_id IS NOT NULL)
    )
);

COMMENT ON TABLE iam.refresh_tokens IS
    'One-time rotating refresh tokens. Replay detection revokes the complete family.';

CREATE INDEX refresh_tokens_family_idx
    ON iam.refresh_tokens (family_id, created_at DESC);
CREATE INDEX refresh_tokens_expiry_idx
    ON iam.refresh_tokens (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE iam.access_tokens (
    id uuid PRIMARY KEY,
    token_class text NOT NULL,
    token_digest bytea NOT NULL,
    digest_key_version smallint NOT NULL,
    digest_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    token_prefix text NOT NULL,
    authentication_session_id uuid NOT NULL,
    subject_principal_id uuid NOT NULL,
    subject_kind iam.principal_kind NOT NULL,
    client_application_id uuid,
    client_kind iam.principal_kind
        GENERATED ALWAYS AS ('application'::iam.principal_kind) STORED,
    audience text NOT NULL,
    audience_application_id uuid,
    audience_kind iam.principal_kind
        GENERATED ALWAYS AS ('application'::iam.principal_kind) STORED,
    organization_id uuid,
    membership_id uuid,
    subject_auth_epoch bigint NOT NULL,
    membership_authz_epoch bigint,
    client_auth_epoch bigint,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    revocation_reason text,
    UNIQUE (token_digest),
    UNIQUE (id, subject_principal_id),
    CONSTRAINT access_tokens_digest_key_fk
        FOREIGN KEY (digest_purpose, digest_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT access_tokens_session_fk
        FOREIGN KEY (authentication_session_id, subject_principal_id)
        REFERENCES iam.authentication_sessions (id, subject_principal_id)
        ON DELETE RESTRICT,
    CONSTRAINT access_tokens_subject_fk
        FOREIGN KEY (subject_principal_id, subject_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT access_tokens_client_fk
        FOREIGN KEY (client_application_id, client_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT access_tokens_audience_app_fk
        FOREIGN KEY (audience_application_id, audience_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT access_tokens_membership_fk
        FOREIGN KEY (organization_id, membership_id, subject_principal_id, subject_kind)
        REFERENCES iam.organization_memberships
            (organization_id, id, principal_id, principal_kind)
        ON DELETE RESTRICT,
    CONSTRAINT access_tokens_class
        CHECK (token_class IN ('carbon_access', 'silicon_access', 'application_access', 'service_access')),
    CONSTRAINT access_tokens_digest_length CHECK (octet_length(token_digest) = 32),
    CONSTRAINT access_tokens_prefix_format
        CHECK (token_prefix ~ '^(cat|sat|oat|svt)_[A-Za-z0-9_-]{8}$'),
    CONSTRAINT access_tokens_class_prefix_and_subject CHECK (
        (token_class = 'carbon_access' AND subject_kind = 'carbon' AND left(token_prefix, 4) = 'cat_')
        OR (token_class = 'silicon_access' AND subject_kind = 'silicon' AND left(token_prefix, 4) = 'sat_')
        OR (token_class = 'application_access'
            AND subject_kind IN ('carbon', 'silicon') AND left(token_prefix, 4) = 'oat_')
        OR (token_class = 'service_access' AND subject_kind = 'service' AND left(token_prefix, 4) = 'svt_')
    ),
    CONSTRAINT access_tokens_audience_length CHECK (char_length(audience) BETWEEN 1 AND 255),
    CONSTRAINT access_tokens_positive_epochs CHECK (
        subject_auth_epoch > 0
        AND (membership_authz_epoch IS NULL OR membership_authz_epoch > 0)
        AND (client_auth_epoch IS NULL OR client_auth_epoch > 0)
    ),
    CONSTRAINT access_tokens_org_binding CHECK (
        (organization_id IS NULL AND membership_id IS NULL AND membership_authz_epoch IS NULL)
        OR (organization_id IS NOT NULL AND membership_id IS NOT NULL AND membership_authz_epoch IS NOT NULL)
    ),
    CONSTRAINT access_tokens_application_binding CHECK (
        (token_class = 'application_access'
            AND client_application_id IS NOT NULL
            AND audience_application_id IS NOT NULL
            AND client_auth_epoch IS NOT NULL)
        OR (token_class <> 'application_access'
            AND client_application_id IS NULL
            AND client_auth_epoch IS NULL)
    ),
    CONSTRAINT access_tokens_expiry CHECK (expires_at > created_at),
    CONSTRAINT access_tokens_revocation_reason_length
        CHECK (revocation_reason IS NULL OR char_length(revocation_reason) <= 500)
);

COMMENT ON TABLE iam.access_tokens IS
    'Opaque 256-bit bearer-token records. Introspection joins current principal, session, membership, and app epochs.';

CREATE INDEX access_tokens_session_idx
    ON iam.access_tokens (authentication_session_id, revoked_at, expires_at);
CREATE INDEX access_tokens_subject_idx
    ON iam.access_tokens (subject_principal_id, created_at DESC);
CREATE INDEX access_tokens_client_idx
    ON iam.access_tokens (client_application_id, revoked_at, expires_at)
    WHERE client_application_id IS NOT NULL;
CREATE INDEX access_tokens_membership_idx
    ON iam.access_tokens (organization_id, membership_id, revoked_at)
    WHERE organization_id IS NOT NULL;
CREATE INDEX access_tokens_expiry_idx
    ON iam.access_tokens (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE iam.access_token_scopes (
    access_token_id uuid NOT NULL,
    scope text NOT NULL,
    PRIMARY KEY (access_token_id, scope),
    CONSTRAINT access_token_scopes_token_fk
        FOREIGN KEY (access_token_id) REFERENCES iam.access_tokens (id) ON DELETE RESTRICT,
    CONSTRAINT access_token_scopes_scope_format
        CHECK (scope ~ '^[a-z][a-z0-9_.:-]{0,127}$')
);

CREATE TABLE iam.service_credentials (
    id uuid PRIMARY KEY,
    service_principal_id uuid NOT NULL,
    credential_prefix text NOT NULL,
    secret_digest bytea NOT NULL,
    pepper_key_version smallint NOT NULL,
    pepper_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    last_used_at timestamptz,
    retired_at timestamptz,
    UNIQUE (service_principal_id, id),
    CONSTRAINT service_credentials_service_fk
        FOREIGN KEY (service_principal_id)
        REFERENCES iam.service_principals (id)
        ON DELETE RESTRICT,
    CONSTRAINT service_credentials_pepper_key_fk
        FOREIGN KEY (pepper_purpose, pepper_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT service_credentials_prefix_format
        CHECK (credential_prefix ~ '^svc_[A-Za-z0-9_-]{8}$'),
    CONSTRAINT service_credentials_digest_length
        CHECK (octet_length(secret_digest) = 32),
    CONSTRAINT service_credentials_status
        CHECK (status IN ('active', 'retired', 'compromised')),
    CONSTRAINT service_credentials_retirement_consistency
        CHECK ((status = 'active') = (retired_at IS NULL))
);

COMMENT ON TABLE iam.service_credentials IS
    'Versioned purpose-separated keyed digests for explicit internal service credentials.';

CREATE UNIQUE INDEX service_credentials_one_active_idx
    ON iam.service_credentials (service_principal_id)
    WHERE status = 'active';
