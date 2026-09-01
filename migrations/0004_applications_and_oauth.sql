-- Carbon-owned applications, reviewable scopes, webhook endpoints, and OAuth/OIDC authorization code flow.

CREATE TABLE iam.applications (
    id uuid PRIMARY KEY,
    principal_kind iam.principal_kind
        GENERATED ALWAYS AS ('application'::iam.principal_kind) STORED,
    app_id text NOT NULL,
    owner_carbon_id uuid NOT NULL,
    app_name text,
    app_logo_uri text,
    review_status text NOT NULL DEFAULT 'under_review',
    notify_users boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    deleted_at timestamptz,
    UNIQUE (app_id),
    UNIQUE (id, principal_kind),
    CONSTRAINT applications_principal_fk
        FOREIGN KEY (id, principal_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT applications_owner_fk
        FOREIGN KEY (owner_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT applications_app_id_format
        CHECK (app_id ~ '^[a-z][a-z0-9_-]{2,79}$'),
    CONSTRAINT applications_name_length
        CHECK (app_name IS NULL OR char_length(app_name) BETWEEN 1 AND 200),
    CONSTRAINT applications_logo_uri_length
        CHECK (app_logo_uri IS NULL OR char_length(app_logo_uri) <= 2048),
    CONSTRAINT applications_review_status CHECK (
        review_status IN ('under_review', 'verified', 'rejected', 'suspended', 'deleted')
    ),
    CONSTRAINT applications_deletion_consistency
        CHECK ((review_status = 'deleted') = (deleted_at IS NOT NULL)),
    CONSTRAINT applications_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.applications IS
    'Carbon-owned OAuth clients and OBO participants. Application secrets are stored separately.';
COMMENT ON COLUMN iam.applications.notify_users IS
    'Backend-only consent policy. It is intentionally excluded from owner-facing mutation APIs.';

CREATE FUNCTION iam_private.prevent_application_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.app_id <> OLD.app_id THEN
        RAISE EXCEPTION 'application internal id and app_id are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER applications_immutable_identity
BEFORE UPDATE ON iam.applications
FOR EACH ROW EXECUTE FUNCTION iam_private.prevent_application_identity_change();

CREATE TRIGGER applications_bump_version
BEFORE UPDATE ON iam.applications
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE INDEX applications_owner_idx
    ON iam.applications (owner_carbon_id, review_status, created_at DESC);
CREATE INDEX applications_review_queue_idx
    ON iam.applications (review_status, created_at, id);

CREATE TABLE iam.application_collaborators (
    application_id uuid NOT NULL,
    carbon_id uuid NOT NULL,
    collaborator_role text NOT NULL,
    added_by_carbon_id uuid NOT NULL,
    added_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    revoked_by_carbon_id uuid,
    revoked_at timestamptz,
    PRIMARY KEY (application_id, carbon_id, added_at),
    CONSTRAINT application_collaborators_application_fk
        FOREIGN KEY (application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT application_collaborators_carbon_fk
        FOREIGN KEY (carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT application_collaborators_adder_fk
        FOREIGN KEY (added_by_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT application_collaborators_revoker_fk
        FOREIGN KEY (revoked_by_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT application_collaborators_role
        CHECK (collaborator_role IN ('owner_delegate', 'developer', 'viewer')),
    CONSTRAINT application_collaborators_revocation_consistency
        CHECK ((revoked_at IS NULL) = (revoked_by_carbon_id IS NULL))
);

CREATE UNIQUE INDEX application_collaborators_one_active_idx
    ON iam.application_collaborators (application_id, carbon_id)
    WHERE revoked_at IS NULL;

CREATE TABLE iam.oauth_scope_catalog (
    scope text PRIMARY KEY,
    description text NOT NULL,
    sensitive boolean NOT NULL DEFAULT false,
    CONSTRAINT oauth_scope_catalog_format CHECK (scope ~ '^[a-z][a-z0-9_.:-]{0,127}$'),
    CONSTRAINT oauth_scope_catalog_description_length
        CHECK (char_length(description) BETWEEN 1 AND 500)
);

INSERT INTO iam.oauth_scope_catalog (scope, description, sensitive)
VALUES
    ('openid', 'Authenticate the represented principal with OIDC.', false),
    ('profile', 'Read public Carbon or Silicon profile claims.', false),
    ('email', 'Read the represented Carbon primary verified email.', true),
    ('phone', 'Read the represented Carbon primary verified phone.', true),
    ('organizations.read', 'Read organizations visible to the represented principal.', false),
    ('memberships.read', 'Read represented organization membership claims.', false),
    ('roles.read', 'Read descriptive job-role claims.', false),
    ('offline_access', 'Receive a rotating application refresh-token family.', true),
    ('obo.issue', 'Exchange an actor-bound application token for an OBO proof.', true);

CREATE TABLE iam.application_requested_scopes (
    application_id uuid NOT NULL,
    scope text NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (application_id, scope),
    CONSTRAINT application_requested_scopes_application_fk
        FOREIGN KEY (application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT application_requested_scopes_scope_fk
        FOREIGN KEY (scope) REFERENCES iam.oauth_scope_catalog (scope) ON DELETE RESTRICT
);

CREATE TABLE iam.application_approved_scopes (
    application_id uuid NOT NULL,
    scope text NOT NULL,
    approved_by_carbon_id uuid NOT NULL,
    approved_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    revoked_by_carbon_id uuid,
    revoked_at timestamptz,
    PRIMARY KEY (application_id, scope, approved_at),
    CONSTRAINT application_approved_scopes_application_fk
        FOREIGN KEY (application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT application_approved_scopes_requested_fk
        FOREIGN KEY (application_id, scope)
        REFERENCES iam.application_requested_scopes (application_id, scope)
        ON DELETE RESTRICT,
    CONSTRAINT application_approved_scopes_approver_fk
        FOREIGN KEY (approved_by_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT application_approved_scopes_revoker_fk
        FOREIGN KEY (revoked_by_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT application_approved_scopes_revocation_consistency
        CHECK ((revoked_at IS NULL) = (revoked_by_carbon_id IS NULL))
);

CREATE UNIQUE INDEX application_approved_scopes_one_active_idx
    ON iam.application_approved_scopes (application_id, scope)
    WHERE revoked_at IS NULL;

CREATE TABLE iam.application_redirect_uris (
    id uuid PRIMARY KEY,
    application_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    uri_digest bytea NOT NULL,
    status text NOT NULL DEFAULT 'pending_review',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    approved_at timestamptz,
    retired_at timestamptz,
    UNIQUE (application_id, id),
    UNIQUE (application_id, uri_digest),
    CONSTRAINT application_redirect_uris_application_fk
        FOREIGN KEY (application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT application_redirect_uris_length
        CHECK (char_length(redirect_uri) BETWEEN 1 AND 2048),
    CONSTRAINT application_redirect_uris_digest_length CHECK (octet_length(uri_digest) = 32),
    CONSTRAINT application_redirect_uris_status
        CHECK (status IN ('pending_review', 'active', 'retired')),
    CONSTRAINT application_redirect_uris_status_timestamps CHECK (
        (status <> 'active' OR approved_at IS NOT NULL)
        AND (status <> 'retired' OR retired_at IS NOT NULL)
    )
);

COMMENT ON TABLE iam.application_redirect_uris IS
    'Exact registered redirect URIs. Lookup digest must be followed by full-string comparison.';

CREATE INDEX application_redirect_uris_active_idx
    ON iam.application_redirect_uris (application_id, status)
    WHERE status = 'active';

CREATE TABLE iam.application_secrets (
    id uuid PRIMARY KEY,
    application_id uuid NOT NULL,
    secret_version bigint NOT NULL,
    secret_prefix text NOT NULL,
    secret_digest bytea NOT NULL,
    pepper_key_version smallint NOT NULL,
    pepper_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    status text NOT NULL DEFAULT 'active',
    created_by_carbon_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    last_used_at timestamptz,
    retires_at timestamptz,
    retired_at timestamptz,
    UNIQUE (application_id, id),
    UNIQUE (application_id, secret_version),
    CONSTRAINT application_secrets_application_fk
        FOREIGN KEY (application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT application_secrets_creator_fk
        FOREIGN KEY (created_by_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT application_secrets_pepper_key_fk
        FOREIGN KEY (pepper_purpose, pepper_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT application_secrets_prefix_format
        CHECK (secret_prefix ~ '^ask_[A-Za-z0-9_-]{8}$'),
    CONSTRAINT application_secrets_digest_length
        CHECK (octet_length(secret_digest) = 32),
    CONSTRAINT application_secrets_positive_version CHECK (secret_version > 0),
    CONSTRAINT application_secrets_status
        CHECK (status IN ('active', 'retiring', 'retired', 'compromised')),
    CONSTRAINT application_secrets_retirement_consistency CHECK (
        (status IN ('retired', 'compromised')) = (retired_at IS NOT NULL)
        AND (status <> 'retiring' OR retires_at IS NOT NULL)
    )
);

COMMENT ON TABLE iam.application_secrets IS
    'Versioned purpose-separated keyed client-secret digests; plaintext is returned only through bounded reveal handling.';

CREATE INDEX application_secrets_active_idx
    ON iam.application_secrets (application_id, status, created_at DESC)
    WHERE status IN ('active', 'retiring');

CREATE TABLE iam.application_reviews (
    id uuid PRIMARY KEY,
    application_id uuid NOT NULL,
    reviewer_carbon_id uuid NOT NULL,
    decision text NOT NULL,
    reason text,
    application_version bigint NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT application_reviews_application_fk
        FOREIGN KEY (application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT application_reviews_reviewer_fk
        FOREIGN KEY (reviewer_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT application_reviews_decision
        CHECK (decision IN ('approve', 'reject', 'suspend', 'restore')),
    CONSTRAINT application_reviews_reason_length
        CHECK (reason IS NULL OR char_length(reason) <= 2000),
    CONSTRAINT application_reviews_positive_version CHECK (application_version > 0)
);

CREATE INDEX application_reviews_history_idx
    ON iam.application_reviews (application_id, decided_at DESC, id);

CREATE TABLE iam.application_webhook_endpoints (
    id uuid PRIMARY KEY,
    application_id uuid NOT NULL,
    url_ciphertext bytea NOT NULL,
    url_nonce bytea NOT NULL,
    encryption_key_version smallint NOT NULL,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    url_digest bytea NOT NULL,
    status text NOT NULL DEFAULT 'pending_review',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    activated_at timestamptz,
    retired_at timestamptz,
    UNIQUE (application_id, id),
    UNIQUE (application_id, url_digest),
    CONSTRAINT application_webhook_endpoints_application_fk
        FOREIGN KEY (application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT application_webhook_endpoints_encryption_key_fk
        FOREIGN KEY (encryption_purpose, encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT application_webhook_endpoints_ciphertext_length
        CHECK (octet_length(url_ciphertext) BETWEEN 17 AND 8192),
    CONSTRAINT application_webhook_endpoints_nonce_length
        CHECK (octet_length(url_nonce) BETWEEN 12 AND 32),
    CONSTRAINT application_webhook_endpoints_digest_length CHECK (octet_length(url_digest) = 32),
    CONSTRAINT application_webhook_endpoints_status
        CHECK (status IN ('pending_review', 'active', 'disabled', 'retired')),
    CONSTRAINT application_webhook_endpoints_status_timestamps CHECK (
        (status <> 'active' OR activated_at IS NOT NULL)
        AND (status <> 'retired' OR retired_at IS NOT NULL)
    ),
    CONSTRAINT application_webhook_endpoints_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.application_webhook_endpoints IS
    'Versioned encrypted webhook URL history. v1 permits exactly one active endpoint per app.';

CREATE UNIQUE INDEX application_webhook_endpoints_one_active_idx
    ON iam.application_webhook_endpoints (application_id)
    WHERE status = 'active';

CREATE TRIGGER application_webhook_endpoints_bump_version
BEFORE UPDATE ON iam.application_webhook_endpoints
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE TABLE iam.application_webhook_signing_keys (
    id uuid PRIMARY KEY,
    application_id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    secret_version bigint NOT NULL,
    key_prefix text NOT NULL,
    secret_ciphertext bytea NOT NULL,
    secret_nonce bytea NOT NULL,
    encryption_key_version smallint NOT NULL,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    retires_at timestamptz,
    retired_at timestamptz,
    UNIQUE (endpoint_id, id),
    UNIQUE (application_id, secret_version),
    CONSTRAINT application_webhook_signing_keys_endpoint_fk
        FOREIGN KEY (application_id, endpoint_id)
        REFERENCES iam.application_webhook_endpoints (application_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT application_webhook_signing_keys_encryption_key_fk
        FOREIGN KEY (encryption_purpose, encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT application_webhook_signing_keys_prefix_format
        CHECK (key_prefix ~ '^whs_[A-Za-z0-9_-]{8}$'),
    CONSTRAINT application_webhook_signing_keys_ciphertext_length
        CHECK (octet_length(secret_ciphertext) BETWEEN 17 AND 8192),
    CONSTRAINT application_webhook_signing_keys_nonce_length
        CHECK (octet_length(secret_nonce) BETWEEN 12 AND 32),
    CONSTRAINT application_webhook_signing_keys_positive_version CHECK (secret_version > 0),
    CONSTRAINT application_webhook_signing_keys_status
        CHECK (status IN ('active', 'retiring', 'retired', 'compromised')),
    CONSTRAINT application_webhook_signing_keys_retirement_consistency CHECK (
        (status IN ('retired', 'compromised')) = (retired_at IS NOT NULL)
        AND (status <> 'retiring' OR retires_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX application_webhook_signing_keys_one_active_idx
    ON iam.application_webhook_signing_keys (endpoint_id)
    WHERE status = 'active';

CREATE TABLE iam.oauth_authorization_requests (
    id uuid PRIMARY KEY,
    application_id uuid NOT NULL,
    redirect_uri_id uuid NOT NULL,
    authentication_session_id uuid NOT NULL,
    subject_principal_id uuid NOT NULL,
    subject_kind iam.principal_kind NOT NULL,
    organization_id uuid,
    membership_id uuid,
    state_digest bytea NOT NULL,
    state_ciphertext bytea NOT NULL,
    state_encryption_nonce bytea NOT NULL,
    oidc_nonce_ciphertext bytea,
    oidc_nonce_encryption_nonce bytea,
    encryption_key_version smallint NOT NULL,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    pkce_code_challenge text NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    decided_at timestamptz,
    UNIQUE (id, application_id),
    CONSTRAINT oauth_authorization_requests_application_fk
        FOREIGN KEY (application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_requests_redirect_fk
        FOREIGN KEY (application_id, redirect_uri_id)
        REFERENCES iam.application_redirect_uris (application_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_requests_session_fk
        FOREIGN KEY (authentication_session_id, subject_principal_id)
        REFERENCES iam.authentication_sessions (id, subject_principal_id)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_requests_subject_fk
        FOREIGN KEY (subject_principal_id, subject_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_requests_membership_fk
        FOREIGN KEY (organization_id, membership_id, subject_principal_id, subject_kind)
        REFERENCES iam.organization_memberships
            (organization_id, id, principal_id, principal_kind)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_requests_encryption_key_fk
        FOREIGN KEY (encryption_purpose, encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_requests_state_digest_length
        CHECK (octet_length(state_digest) = 32),
    CONSTRAINT oauth_authorization_requests_ciphertext_lengths CHECK (
        octet_length(state_ciphertext) BETWEEN 17 AND 8192
        AND (oidc_nonce_ciphertext IS NULL OR octet_length(oidc_nonce_ciphertext) BETWEEN 17 AND 8192)
    ),
    CONSTRAINT oauth_authorization_requests_nonce_lengths CHECK (
        octet_length(state_encryption_nonce) BETWEEN 12 AND 32
        AND (oidc_nonce_encryption_nonce IS NULL OR octet_length(oidc_nonce_encryption_nonce) BETWEEN 12 AND 32)
    ),
    CONSTRAINT oauth_authorization_requests_oidc_nonce_pair CHECK (
        (oidc_nonce_ciphertext IS NULL) = (oidc_nonce_encryption_nonce IS NULL)
    ),
    CONSTRAINT oauth_authorization_requests_pkce_s256 CHECK (
        char_length(pkce_code_challenge) BETWEEN 43 AND 128
        AND pkce_code_challenge ~ '^[A-Za-z0-9_-]+$'
    ),
    CONSTRAINT oauth_authorization_requests_status
        CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'consumed')),
    CONSTRAINT oauth_authorization_requests_expiry CHECK (expires_at > created_at),
    CONSTRAINT oauth_authorization_requests_org_binding CHECK (
        (organization_id IS NULL AND membership_id IS NULL)
        OR (organization_id IS NOT NULL AND membership_id IS NOT NULL)
    ),
    CONSTRAINT oauth_authorization_requests_decision_consistency
        CHECK ((status = 'pending') = (decided_at IS NULL))
);

COMMENT ON TABLE iam.oauth_authorization_requests IS
    'Short-lived browser interactions bound to exact redirect, session, organization, state, nonce, and PKCE-S256.';

CREATE INDEX oauth_authorization_requests_expiry_idx
    ON iam.oauth_authorization_requests (status, expires_at)
    WHERE status = 'pending';
CREATE INDEX oauth_authorization_requests_session_idx
    ON iam.oauth_authorization_requests (authentication_session_id, created_at DESC);

CREATE TABLE iam.oauth_authorization_request_scopes (
    authorization_request_id uuid NOT NULL,
    application_id uuid NOT NULL,
    scope text NOT NULL,
    approved_at timestamptz NOT NULL,
    PRIMARY KEY (authorization_request_id, scope),
    CONSTRAINT oauth_authorization_request_scopes_request_fk
        FOREIGN KEY (authorization_request_id, application_id)
        REFERENCES iam.oauth_authorization_requests (id, application_id)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_request_scopes_approved_fk
        FOREIGN KEY (application_id, scope, approved_at)
        REFERENCES iam.application_approved_scopes (application_id, scope, approved_at)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY IMMEDIATE
);

CREATE TABLE iam.oauth_authorization_codes (
    id uuid PRIMARY KEY,
    authorization_request_id uuid NOT NULL UNIQUE,
    application_id uuid NOT NULL,
    code_digest bytea NOT NULL,
    digest_key_version smallint NOT NULL,
    digest_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    code_prefix text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT oauth_authorization_codes_request_fk
        FOREIGN KEY (authorization_request_id, application_id)
        REFERENCES iam.oauth_authorization_requests (id, application_id)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_codes_application_fk
        FOREIGN KEY (application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_codes_digest_key_fk
        FOREIGN KEY (digest_purpose, digest_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_codes_digest_length CHECK (octet_length(code_digest) = 32),
    CONSTRAINT oauth_authorization_codes_prefix_format
        CHECK (code_prefix ~ '^oac_[A-Za-z0-9_-]{8}$'),
    CONSTRAINT oauth_authorization_codes_expiry CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX oauth_authorization_codes_digest_idx
    ON iam.oauth_authorization_codes (code_digest);
CREATE INDEX oauth_authorization_codes_expiry_idx
    ON iam.oauth_authorization_codes (expires_at) WHERE consumed_at IS NULL;

CREATE TABLE iam.oauth_consent_grants (
    id uuid PRIMARY KEY,
    application_id uuid NOT NULL,
    subject_principal_id uuid NOT NULL,
    subject_kind iam.principal_kind NOT NULL,
    organization_id uuid,
    membership_id uuid,
    parent_authentication_session_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'active',
    version bigint NOT NULL DEFAULT 1,
    granted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    revoked_at timestamptz,
    UNIQUE NULLS NOT DISTINCT (application_id, subject_principal_id, organization_id),
    CONSTRAINT oauth_consent_grants_application_fk
        FOREIGN KEY (application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT oauth_consent_grants_subject_fk
        FOREIGN KEY (subject_principal_id, subject_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_consent_grants_session_fk
        FOREIGN KEY (parent_authentication_session_id, subject_principal_id)
        REFERENCES iam.authentication_sessions (id, subject_principal_id)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_consent_grants_membership_fk
        FOREIGN KEY (organization_id, membership_id, subject_principal_id, subject_kind)
        REFERENCES iam.organization_memberships
            (organization_id, id, principal_id, principal_kind)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_consent_grants_status CHECK (status IN ('active', 'revoked')),
    CONSTRAINT oauth_consent_grants_org_binding CHECK (
        (organization_id IS NULL AND membership_id IS NULL)
        OR (organization_id IS NOT NULL AND membership_id IS NOT NULL)
    ),
    CONSTRAINT oauth_consent_grants_revocation_consistency
        CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CONSTRAINT oauth_consent_grants_positive_version CHECK (version > 0)
);

CREATE TRIGGER oauth_consent_grants_bump_version
BEFORE UPDATE ON iam.oauth_consent_grants
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE TABLE iam.oauth_consent_grant_scopes (
    consent_grant_id uuid NOT NULL,
    scope text NOT NULL,
    PRIMARY KEY (consent_grant_id, scope),
    CONSTRAINT oauth_consent_grant_scopes_grant_fk
        FOREIGN KEY (consent_grant_id) REFERENCES iam.oauth_consent_grants (id) ON DELETE RESTRICT,
    CONSTRAINT oauth_consent_grant_scopes_scope_fk
        FOREIGN KEY (scope) REFERENCES iam.oauth_scope_catalog (scope) ON DELETE RESTRICT
);

ALTER TABLE iam.refresh_token_families
    ADD COLUMN oauth_consent_grant_id uuid,
    ADD CONSTRAINT refresh_token_families_consent_fk
        FOREIGN KEY (oauth_consent_grant_id)
        REFERENCES iam.oauth_consent_grants (id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT refresh_token_families_application_consent_binding CHECK (
        (client_application_id IS NULL AND oauth_consent_grant_id IS NULL)
        OR (client_application_id IS NOT NULL AND oauth_consent_grant_id IS NOT NULL)
    ),
    ADD UNIQUE (id, oauth_consent_grant_id);

CREATE FUNCTION iam_private.enforce_refresh_token_family_prefix()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    family_client_application_id uuid;
BEGIN
    SELECT client_application_id
    INTO family_client_application_id
    FROM iam.refresh_token_families
    WHERE id = NEW.family_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'refresh-token family does not exist'
            USING ERRCODE = '23503';
    END IF;
    IF family_client_application_id IS NULL AND left(NEW.token_prefix, 4) <> 'rft_' THEN
        RAISE EXCEPTION 'Carbon refresh-token families require the rft_ prefix'
            USING ERRCODE = '23514';
    END IF;
    IF family_client_application_id IS NOT NULL AND left(NEW.token_prefix, 4) <> 'ort_' THEN
        RAISE EXCEPTION 'OAuth refresh-token families require the ort_ prefix'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER refresh_tokens_enforce_family_prefix
BEFORE INSERT OR UPDATE OF family_id, token_prefix ON iam.refresh_tokens
FOR EACH ROW EXECUTE FUNCTION iam_private.enforce_refresh_token_family_prefix();

CREATE TABLE iam.oauth_refresh_family_scopes (
    family_id uuid NOT NULL,
    consent_grant_id uuid NOT NULL,
    scope text NOT NULL,
    PRIMARY KEY (family_id, scope),
    CONSTRAINT oauth_refresh_family_scopes_family_consent_fk
        FOREIGN KEY (family_id, consent_grant_id)
        REFERENCES iam.refresh_token_families (id, oauth_consent_grant_id)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_refresh_family_scopes_consent_fk
        FOREIGN KEY (consent_grant_id)
        REFERENCES iam.oauth_consent_grants (id)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_refresh_family_scopes_scope_fk
        FOREIGN KEY (scope) REFERENCES iam.oauth_scope_catalog (scope) ON DELETE RESTRICT
);

COMMENT ON TABLE iam.oauth_refresh_family_scopes IS
    'Immutable issuance-time scope ceiling for one OAuth refresh-token family and exact consent grant.';

CREATE FUNCTION iam_private.prevent_oauth_refresh_family_scope_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'OAuth refresh-family scope snapshots are immutable'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER oauth_refresh_family_scopes_immutable
BEFORE UPDATE OR DELETE ON iam.oauth_refresh_family_scopes
FOR EACH ROW EXECUTE FUNCTION iam_private.prevent_oauth_refresh_family_scope_mutation();

CREATE TABLE iam.oidc_signing_keys (
    id uuid PRIMARY KEY,
    key_id text NOT NULL UNIQUE,
    algorithm text NOT NULL,
    public_jwk jsonb NOT NULL,
    private_key_ciphertext bytea NOT NULL,
    private_key_nonce bytea NOT NULL,
    encryption_key_version smallint NOT NULL,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    status text NOT NULL DEFAULT 'pending',
    not_before timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    retires_at timestamptz,
    retired_at timestamptz,
    CONSTRAINT oidc_signing_keys_encryption_key_fk
        FOREIGN KEY (encryption_purpose, encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT oidc_signing_keys_key_id_format
        CHECK (key_id ~ '^[A-Za-z0-9_-]{8,128}$'),
    CONSTRAINT oidc_signing_keys_algorithm CHECK (algorithm IN ('EdDSA', 'ES256', 'RS256')),
    CONSTRAINT oidc_signing_keys_public_jwk_object
        CHECK (jsonb_typeof(public_jwk) = 'object'),
    CONSTRAINT oidc_signing_keys_ciphertext_length
        CHECK (octet_length(private_key_ciphertext) BETWEEN 17 AND 16384),
    CONSTRAINT oidc_signing_keys_nonce_length
        CHECK (octet_length(private_key_nonce) BETWEEN 12 AND 32),
    CONSTRAINT oidc_signing_keys_status
        CHECK (status IN ('pending', 'active', 'retiring', 'retired', 'compromised')),
    CONSTRAINT oidc_signing_keys_retirement_consistency CHECK (
        (status IN ('retired', 'compromised')) = (retired_at IS NOT NULL)
        AND (status <> 'retiring' OR retires_at IS NOT NULL)
    )
);

COMMENT ON TABLE iam.oidc_signing_keys IS
    'Versioned asymmetric OIDC signing keys; only public JWK data is stored in plaintext.';

CREATE UNIQUE INDEX oidc_signing_keys_one_active_idx
    ON iam.oidc_signing_keys (algorithm)
    WHERE status = 'active';
