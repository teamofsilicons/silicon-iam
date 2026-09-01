-- Platform administration, step-up authentication, governance approvals, trust, SSO, and OBO proofs.

CREATE TABLE iam.platform_capability_catalog (
    capability text PRIMARY KEY,
    description text NOT NULL,
    CONSTRAINT platform_capability_catalog_format
        CHECK (capability ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    CONSTRAINT platform_capability_catalog_description_length
        CHECK (char_length(description) BETWEEN 1 AND 500)
);

INSERT INTO iam.platform_capability_catalog (capability, description)
VALUES
    ('applications.review', 'Approve or reject application registrations and scope changes.'),
    ('applications.suspend', 'Suspend and restore registered applications.'),
    ('applications.policy', 'Manage backend-only application consent and security policy.'),
    ('organizations.sso_feature', 'Enable or disable the platform SSO feature gate.'),
    ('carbons.status_manage', 'Suspend or reactivate Carbon principals and revoke delegated authority.'),
    ('deliveries.manage', 'Inspect and replay failed outbound webhook deliveries.'),
    ('audit.read_global', 'Read the redacted global security audit stream.'),
    ('platform.admins_manage', 'Grant or revoke platform roles.');

CREATE TABLE iam.platform_role_catalog (
    role text PRIMARY KEY,
    description text NOT NULL,
    CONSTRAINT platform_role_catalog_format CHECK (role ~ '^[a-z][a-z0-9_]{2,63}$'),
    CONSTRAINT platform_role_catalog_description_length
        CHECK (char_length(description) BETWEEN 1 AND 500)
);

INSERT INTO iam.platform_role_catalog (role, description)
VALUES
    ('platform_administrator', 'Full platform administration after phishing-resistant step-up.'),
    ('application_reviewer', 'Application-review authority without unrelated platform administration.'),
    ('security_auditor', 'Read-only access to redacted global security audit history.');

CREATE TABLE iam.platform_role_capabilities (
    role text NOT NULL,
    capability text NOT NULL,
    PRIMARY KEY (role, capability),
    CONSTRAINT platform_role_capabilities_role_fk
        FOREIGN KEY (role) REFERENCES iam.platform_role_catalog (role) ON DELETE RESTRICT,
    CONSTRAINT platform_role_capabilities_capability_fk
        FOREIGN KEY (capability)
        REFERENCES iam.platform_capability_catalog (capability)
        ON DELETE RESTRICT
);

INSERT INTO iam.platform_role_capabilities (role, capability)
SELECT 'platform_administrator', capability FROM iam.platform_capability_catalog;

INSERT INTO iam.platform_role_capabilities (role, capability)
VALUES
    ('application_reviewer', 'applications.review'),
    ('security_auditor', 'audit.read_global');

CREATE TABLE iam.platform_role_grants (
    id uuid PRIMARY KEY,
    carbon_id uuid NOT NULL,
    role text NOT NULL,
    grant_source text NOT NULL,
    granted_by_carbon_id uuid,
    granted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    revoked_by_carbon_id uuid,
    revoked_at timestamptz,
    reason text,
    version bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT platform_role_grants_carbon_fk
        FOREIGN KEY (carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT platform_role_grants_role_fk
        FOREIGN KEY (role) REFERENCES iam.platform_role_catalog (role) ON DELETE RESTRICT,
    CONSTRAINT platform_role_grants_grantor_fk
        FOREIGN KEY (granted_by_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT platform_role_grants_revoker_fk
        FOREIGN KEY (revoked_by_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT platform_role_grants_source CHECK (grant_source IN ('bootstrap', 'administrator')),
    CONSTRAINT platform_role_grants_bootstrap_grantor CHECK (
        (grant_source = 'bootstrap' AND granted_by_carbon_id IS NULL)
        OR (grant_source = 'administrator' AND granted_by_carbon_id IS NOT NULL)
    ),
    CONSTRAINT platform_role_grants_revocation_consistency
        CHECK ((revoked_at IS NULL) = (revoked_by_carbon_id IS NULL)),
    CONSTRAINT platform_role_grants_reason_length
        CHECK (reason IS NULL OR char_length(reason) <= 2000),
    CONSTRAINT platform_role_grants_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.platform_role_grants IS
    'Privileged roles attached to normal Carbon identities; bootstrap never creates a password identity.';

CREATE UNIQUE INDEX platform_role_grants_one_active_idx
    ON iam.platform_role_grants (carbon_id, role)
    WHERE revoked_at IS NULL;

CREATE TRIGGER platform_role_grants_bump_version
BEFORE UPDATE ON iam.platform_role_grants
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE TABLE iam.webauthn_credentials (
    id uuid PRIMARY KEY,
    carbon_id uuid NOT NULL,
    credential_id bytea NOT NULL UNIQUE,
    public_key bytea NOT NULL,
    sign_count bigint NOT NULL DEFAULT 0,
    aaguid uuid,
    transports text[] NOT NULL DEFAULT '{}',
    backup_eligible boolean NOT NULL DEFAULT false,
    backup_state boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    last_used_at timestamptz,
    revoked_at timestamptz,
    CONSTRAINT webauthn_credentials_carbon_fk
        FOREIGN KEY (carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT webauthn_credentials_credential_id_length
        CHECK (octet_length(credential_id) BETWEEN 16 AND 1024),
    CONSTRAINT webauthn_credentials_public_key_length
        CHECK (octet_length(public_key) BETWEEN 32 AND 4096),
    CONSTRAINT webauthn_credentials_nonnegative_sign_count CHECK (sign_count >= 0),
    CONSTRAINT webauthn_credentials_status CHECK (status IN ('active', 'revoked')),
    CONSTRAINT webauthn_credentials_revocation_consistency
        CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CONSTRAINT webauthn_credentials_transports CHECK (
        transports <@ ARRAY['usb', 'nfc', 'ble', 'internal', 'hybrid']::text[]
    )
);

CREATE INDEX webauthn_credentials_carbon_idx
    ON iam.webauthn_credentials (carbon_id, status);

CREATE TABLE iam.step_up_challenges (
    id uuid PRIMARY KEY,
    authentication_session_id uuid NOT NULL,
    carbon_id uuid NOT NULL,
    purpose text NOT NULL,
    resource_id uuid,
    channel iam.contact_kind NOT NULL,
    challenge_digest bytea NOT NULL,
    digest_key_version smallint NOT NULL,
    digest_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    status text NOT NULL DEFAULT 'pending',
    attempt_count smallint NOT NULL DEFAULT 0,
    max_attempts smallint NOT NULL DEFAULT 5,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    UNIQUE (id, authentication_session_id, carbon_id, purpose),
    CONSTRAINT step_up_challenges_session_fk
        FOREIGN KEY (authentication_session_id, carbon_id)
        REFERENCES iam.authentication_sessions (id, subject_principal_id)
        ON DELETE RESTRICT,
    CONSTRAINT step_up_challenges_carbon_fk
        FOREIGN KEY (carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT step_up_challenges_digest_key_fk
        FOREIGN KEY (digest_purpose, digest_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT step_up_challenges_purpose_format
        CHECK (purpose ~ '^[a-z][a-z0-9_.:-]{2,127}$'),
    CONSTRAINT step_up_challenges_digest_length CHECK (octet_length(challenge_digest) = 32),
    CONSTRAINT step_up_challenges_status
        CHECK (status IN ('pending', 'completed', 'expired', 'cancelled')),
    CONSTRAINT step_up_challenges_attempts
        CHECK (
            max_attempts BETWEEN 1 AND 5
            AND attempt_count BETWEEN 0 AND max_attempts
        ),
    CONSTRAINT step_up_challenges_expiry CHECK (expires_at > created_at),
    CONSTRAINT step_up_challenges_completion_consistency
        CHECK ((status = 'completed') = (consumed_at IS NOT NULL))
);

CREATE INDEX step_up_challenges_expiry_idx
    ON iam.step_up_challenges (status, expires_at) WHERE status = 'pending';

CREATE TABLE iam.step_up_assertions (
    id uuid PRIMARY KEY,
    step_up_challenge_id uuid NOT NULL UNIQUE,
    authentication_session_id uuid NOT NULL,
    carbon_id uuid NOT NULL,
    purpose text NOT NULL,
    token_prefix text NOT NULL,
    token_digest bytea NOT NULL,
    digest_key_version smallint NOT NULL,
    digest_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    assurance_level smallint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    UNIQUE (digest_key_version, token_digest),
    CONSTRAINT step_up_assertions_challenge_fk
        FOREIGN KEY (step_up_challenge_id, authentication_session_id, carbon_id, purpose)
        REFERENCES iam.step_up_challenges (id, authentication_session_id, carbon_id, purpose)
        ON DELETE RESTRICT,
    CONSTRAINT step_up_assertions_session_fk
        FOREIGN KEY (authentication_session_id, carbon_id)
        REFERENCES iam.authentication_sessions (id, subject_principal_id)
        ON DELETE RESTRICT,
    CONSTRAINT step_up_assertions_carbon_fk
        FOREIGN KEY (carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT step_up_assertions_digest_key_fk
        FOREIGN KEY (digest_purpose, digest_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT step_up_assertions_purpose_format
        CHECK (purpose ~ '^[a-z][a-z0-9_.:-]{2,127}$'),
    CONSTRAINT step_up_assertions_token_prefix_format
        CHECK (token_prefix ~ '^sup_[A-Za-z0-9_-]{8}$'),
    CONSTRAINT step_up_assertions_token_digest_length CHECK (octet_length(token_digest) = 32),
    CONSTRAINT step_up_assertions_assurance CHECK (assurance_level IN (2, 3)),
    CONSTRAINT step_up_assertions_expiry CHECK (expires_at > created_at)
);

CREATE INDEX step_up_assertions_expiry_idx
    ON iam.step_up_assertions (expires_at) WHERE consumed_at IS NULL;
CREATE INDEX step_up_assertions_session_idx
    ON iam.step_up_assertions (authentication_session_id, expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE iam.approval_requests (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    request_kind text NOT NULL,
    requested_by_membership_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    minimum_distinct_approvers smallint NOT NULL DEFAULT 1,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    rejected_at timestamptz,
    approved_at timestamptz,
    applied_at timestamptz,
    cancelled_at timestamptz,
    UNIQUE (organization_id, id),
    CONSTRAINT approval_requests_organization_fk
        FOREIGN KEY (organization_id) REFERENCES iam.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT approval_requests_requester_fk
        FOREIGN KEY (organization_id, requested_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT approval_requests_kind CHECK (request_kind IN (
        'carbon_job_role_change', 'silicon_job_role_change',
        'silicon_token_rotation', 'ownership_transfer'
    )),
    CONSTRAINT approval_requests_status CHECK (
        status IN ('pending', 'approved', 'rejected', 'applied', 'expired', 'cancelled', 'failed')
    ),
    CONSTRAINT approval_requests_approver_count
        CHECK (minimum_distinct_approvers BETWEEN 1 AND 10),
    CONSTRAINT approval_requests_expiry CHECK (expires_at > created_at),
    CONSTRAINT approval_requests_terminal_timestamps CHECK (
        (status <> 'rejected' OR rejected_at IS NOT NULL)
        AND (status NOT IN ('approved', 'applied') OR approved_at IS NOT NULL)
        AND (status <> 'applied' OR applied_at IS NOT NULL)
        AND (status <> 'cancelled' OR cancelled_at IS NOT NULL)
    ),
    CONSTRAINT approval_requests_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.approval_requests IS
    'Common approval state machine. Kind-specific payloads are stored in immutable subtype tables.';

CREATE TRIGGER approval_requests_bump_version
BEFORE UPDATE ON iam.approval_requests
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE INDEX approval_requests_pending_idx
    ON iam.approval_requests (organization_id, status, expires_at, id)
    WHERE status = 'pending';
CREATE INDEX approval_requests_requester_idx
    ON iam.approval_requests (requested_by_membership_id, created_at DESC);

CREATE TABLE iam.approval_requirements (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    approval_request_id uuid NOT NULL,
    requirement_kind text NOT NULL,
    specific_membership_id uuid,
    required_capability text,
    quorum smallint NOT NULL DEFAULT 1,
    UNIQUE (approval_request_id, id),
    CONSTRAINT approval_requirements_request_fk
        FOREIGN KEY (organization_id, approval_request_id)
        REFERENCES iam.approval_requests (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT approval_requirements_specific_member_fk
        FOREIGN KEY (organization_id, specific_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT approval_requirements_capability_fk
        FOREIGN KEY (required_capability)
        REFERENCES iam.organization_capability_catalog (capability)
        ON DELETE RESTRICT,
    CONSTRAINT approval_requirements_kind CHECK (
        requirement_kind IN ('specific_membership', 'current_owner', 'current_owner_or_admin')
    ),
    CONSTRAINT approval_requirements_shape CHECK (
        (requirement_kind = 'specific_membership'
            AND specific_membership_id IS NOT NULL AND required_capability IS NULL)
        OR (requirement_kind = 'current_owner'
            AND specific_membership_id IS NULL AND required_capability IS NULL)
        OR (requirement_kind = 'current_owner_or_admin'
            AND specific_membership_id IS NULL AND required_capability IS NOT NULL)
    ),
    CONSTRAINT approval_requirements_quorum CHECK (quorum BETWEEN 1 AND 10)
);

CREATE TABLE iam.approval_decisions (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    approval_request_id uuid NOT NULL,
    approval_requirement_id uuid NOT NULL,
    decided_by_membership_id uuid NOT NULL,
    decision text NOT NULL,
    eligibility_snapshot jsonb NOT NULL,
    step_up_assertion_id uuid,
    decided_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (approval_request_id, decided_by_membership_id),
    CONSTRAINT approval_decisions_request_fk
        FOREIGN KEY (organization_id, approval_request_id)
        REFERENCES iam.approval_requests (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT approval_decisions_requirement_fk
        FOREIGN KEY (approval_request_id, approval_requirement_id)
        REFERENCES iam.approval_requirements (approval_request_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT approval_decisions_decider_fk
        FOREIGN KEY (organization_id, decided_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT approval_decisions_step_up_fk
        FOREIGN KEY (step_up_assertion_id) REFERENCES iam.step_up_assertions (id) ON DELETE RESTRICT,
    CONSTRAINT approval_decisions_decision CHECK (decision IN ('approve', 'reject')),
    CONSTRAINT approval_decisions_snapshot_object
        CHECK (jsonb_typeof(eligibility_snapshot) = 'object')
);

CREATE INDEX approval_decisions_request_idx
    ON iam.approval_decisions (approval_request_id, decided_at, id);

CREATE TABLE iam.job_role_change_requests (
    approval_request_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    target_membership_id uuid NOT NULL,
    target_principal_kind iam.principal_kind NOT NULL,
    previous_job_role text NOT NULL,
    proposed_job_role text NOT NULL,
    CONSTRAINT job_role_change_requests_request_fk
        FOREIGN KEY (organization_id, approval_request_id)
        REFERENCES iam.approval_requests (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT job_role_change_requests_target_fk
        FOREIGN KEY (organization_id, target_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT job_role_change_requests_target_kind
        CHECK (target_principal_kind IN ('carbon', 'silicon')),
    CONSTRAINT job_role_change_requests_previous_length
        CHECK (char_length(previous_job_role) <= 5000),
    CONSTRAINT job_role_change_requests_proposed_length
        CHECK (char_length(proposed_job_role) <= 5000),
    CONSTRAINT job_role_change_requests_changes_value
        CHECK (proposed_job_role <> previous_job_role)
);

CREATE TABLE iam.silicon_token_rotation_requests (
    approval_request_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    silicon_id uuid NOT NULL,
    previous_credential_id uuid NOT NULL,
    replacement_credential_id uuid,
    fulfillment_status text NOT NULL DEFAULT 'awaiting_approval',
    fulfilled_at timestamptz,
    CONSTRAINT silicon_token_rotation_requests_request_fk
        FOREIGN KEY (organization_id, approval_request_id)
        REFERENCES iam.approval_requests (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_token_rotation_requests_silicon_fk
        FOREIGN KEY (organization_id, silicon_id)
        REFERENCES iam.silicons (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_token_rotation_requests_previous_fk
        FOREIGN KEY (silicon_id, previous_credential_id)
        REFERENCES iam.silicon_credentials (silicon_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_token_rotation_requests_replacement_fk
        FOREIGN KEY (silicon_id, replacement_credential_id)
        REFERENCES iam.silicon_credentials (silicon_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_token_rotation_requests_status CHECK (
        fulfillment_status IN ('awaiting_approval', 'ready', 'completed', 'failed')
    ),
    CONSTRAINT silicon_token_rotation_requests_fulfillment_consistency CHECK (
        (fulfillment_status = 'completed')
            = (replacement_credential_id IS NOT NULL AND fulfilled_at IS NOT NULL)
    ),
    CONSTRAINT silicon_token_rotation_requests_distinct_credentials
        CHECK (replacement_credential_id IS NULL OR replacement_credential_id <> previous_credential_id)
);

CREATE TABLE iam.ownership_transfer_requests (
    approval_request_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    current_owner_membership_id uuid NOT NULL,
    proposed_owner_membership_id uuid NOT NULL,
    previous_owner_resulting_role iam.organization_role NOT NULL,
    CONSTRAINT ownership_transfer_requests_request_fk
        FOREIGN KEY (organization_id, approval_request_id)
        REFERENCES iam.approval_requests (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT ownership_transfer_requests_current_owner_fk
        FOREIGN KEY (organization_id, current_owner_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT ownership_transfer_requests_proposed_owner_fk
        FOREIGN KEY (organization_id, proposed_owner_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT ownership_transfer_requests_distinct_members
        CHECK (current_owner_membership_id <> proposed_owner_membership_id),
    CONSTRAINT ownership_transfer_requests_resulting_role
        CHECK (previous_owner_resulting_role IN ('admin', 'member'))
);

CREATE FUNCTION iam_private.reject_approval_payload_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'approval request payloads are immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER job_role_change_requests_immutable
BEFORE UPDATE OR DELETE ON iam.job_role_change_requests
FOR EACH ROW EXECUTE FUNCTION iam_private.reject_approval_payload_change();

CREATE TRIGGER ownership_transfer_requests_immutable
BEFORE UPDATE OR DELETE ON iam.ownership_transfer_requests
FOR EACH ROW EXECUTE FUNCTION iam_private.reject_approval_payload_change();

CREATE FUNCTION iam_private.prevent_rotation_target_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.approval_request_id <> OLD.approval_request_id
       OR NEW.organization_id <> OLD.organization_id
       OR NEW.silicon_id <> OLD.silicon_id
       OR NEW.previous_credential_id <> OLD.previous_credential_id THEN
        RAISE EXCEPTION 'Silicon rotation target payload is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER silicon_token_rotation_requests_immutable_target
BEFORE UPDATE ON iam.silicon_token_rotation_requests
FOR EACH ROW EXECUTE FUNCTION iam_private.prevent_rotation_target_change();

CREATE TABLE iam.job_role_history (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    approval_request_id uuid NOT NULL,
    previous_job_role text NOT NULL,
    applied_job_role text NOT NULL,
    membership_version bigint NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (approval_request_id),
    CONSTRAINT job_role_history_membership_fk
        FOREIGN KEY (organization_id, membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT job_role_history_request_fk
        FOREIGN KEY (organization_id, approval_request_id)
        REFERENCES iam.approval_requests (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT job_role_history_role_lengths CHECK (
        char_length(previous_job_role) <= 5000 AND char_length(applied_job_role) <= 5000
    ),
    CONSTRAINT job_role_history_positive_version CHECK (membership_version > 0)
);

CREATE INDEX job_role_history_member_idx
    ON iam.job_role_history (organization_id, membership_id, applied_at DESC, id);

CREATE TABLE iam.silicon_credential_history (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    silicon_id uuid NOT NULL,
    approval_request_id uuid NOT NULL,
    previous_credential_id uuid NOT NULL,
    replacement_credential_id uuid NOT NULL,
    rotated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (approval_request_id),
    CONSTRAINT silicon_credential_history_silicon_fk
        FOREIGN KEY (organization_id, silicon_id)
        REFERENCES iam.silicons (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_credential_history_request_fk
        FOREIGN KEY (organization_id, approval_request_id)
        REFERENCES iam.approval_requests (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_credential_history_previous_fk
        FOREIGN KEY (silicon_id, previous_credential_id)
        REFERENCES iam.silicon_credentials (silicon_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_credential_history_replacement_fk
        FOREIGN KEY (silicon_id, replacement_credential_id)
        REFERENCES iam.silicon_credentials (silicon_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_credential_history_distinct_credentials
        CHECK (previous_credential_id <> replacement_credential_id)
);

CREATE TABLE iam.trust_rules (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    subject_kind text NOT NULL,
    subject_membership_id uuid,
    subject_tag_id uuid,
    target_kind text NOT NULL,
    target_silicon_membership_id uuid,
    target_tag_id uuid,
    trust_boundary iam.trust_boundary NOT NULL,
    trust_level iam.trust_level NOT NULL,
    created_by_membership_id uuid NOT NULL,
    updated_by_membership_id uuid NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    archived_at timestamptz,
    UNIQUE (organization_id, id),
    CONSTRAINT trust_rules_organization_fk
        FOREIGN KEY (organization_id) REFERENCES iam.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT trust_rules_subject_member_fk
        FOREIGN KEY (organization_id, subject_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT trust_rules_subject_tag_fk
        FOREIGN KEY (organization_id, subject_tag_id)
        REFERENCES iam.organization_tags (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT trust_rules_target_silicon_fk
        FOREIGN KEY (organization_id, target_silicon_membership_id)
        REFERENCES iam.silicons (organization_id, membership_id)
        ON DELETE RESTRICT,
    CONSTRAINT trust_rules_target_tag_fk
        FOREIGN KEY (organization_id, target_tag_id)
        REFERENCES iam.organization_tags (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT trust_rules_creator_fk
        FOREIGN KEY (organization_id, created_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT trust_rules_updater_fk
        FOREIGN KEY (organization_id, updated_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT trust_rules_subject_shape CHECK (
        (subject_kind = 'membership' AND subject_membership_id IS NOT NULL AND subject_tag_id IS NULL)
        OR (subject_kind = 'tag' AND subject_membership_id IS NULL AND subject_tag_id IS NOT NULL)
    ),
    CONSTRAINT trust_rules_target_shape CHECK (
        (target_kind = 'silicon' AND target_silicon_membership_id IS NOT NULL AND target_tag_id IS NULL)
        OR (target_kind = 'tag' AND target_silicon_membership_id IS NULL AND target_tag_id IS NOT NULL)
    ),
    CONSTRAINT trust_rules_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.trust_rules IS
    'Typed, tenant-safe advisory trust metadata. Trust rules never grant authorization.';

CREATE UNIQUE INDEX trust_rules_member_to_silicon_active_idx
    ON iam.trust_rules (organization_id, subject_membership_id, target_silicon_membership_id)
    WHERE subject_kind = 'membership' AND target_kind = 'silicon' AND archived_at IS NULL;
CREATE UNIQUE INDEX trust_rules_member_to_tag_active_idx
    ON iam.trust_rules (organization_id, subject_membership_id, target_tag_id)
    WHERE subject_kind = 'membership' AND target_kind = 'tag' AND archived_at IS NULL;
CREATE UNIQUE INDEX trust_rules_tag_to_silicon_active_idx
    ON iam.trust_rules (organization_id, subject_tag_id, target_silicon_membership_id)
    WHERE subject_kind = 'tag' AND target_kind = 'silicon' AND archived_at IS NULL;
CREATE UNIQUE INDEX trust_rules_tag_to_tag_active_idx
    ON iam.trust_rules (organization_id, subject_tag_id, target_tag_id)
    WHERE subject_kind = 'tag' AND target_kind = 'tag' AND archived_at IS NULL;

CREATE TRIGGER trust_rules_bump_version
BEFORE UPDATE ON iam.trust_rules
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE TABLE iam.organization_sso_configs (
    organization_id uuid PRIMARY KEY,
    platform_enabled boolean NOT NULL DEFAULT false,
    provider text NOT NULL DEFAULT 'workos',
    provider_organization_id text UNIQUE,
    status text NOT NULL DEFAULT 'disabled',
    last_error_code text,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT organization_sso_configs_organization_fk
        FOREIGN KEY (organization_id) REFERENCES iam.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT organization_sso_configs_provider CHECK (provider = 'workos'),
    CONSTRAINT organization_sso_configs_status
        CHECK (status IN ('disabled', 'pending', 'active', 'error')),
    CONSTRAINT organization_sso_configs_provider_org_length
        CHECK (provider_organization_id IS NULL OR char_length(provider_organization_id) <= 255),
    CONSTRAINT organization_sso_configs_active_requirements CHECK (
        status <> 'active' OR (platform_enabled AND provider_organization_id IS NOT NULL)
    ),
    CONSTRAINT organization_sso_configs_positive_version CHECK (version > 0)
);

CREATE TRIGGER organization_sso_configs_bump_version
BEFORE UPDATE ON iam.organization_sso_configs
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE TABLE iam.sso_connections (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    provider_connection_id text NOT NULL UNIQUE,
    connection_type text,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    activated_at timestamptz,
    disabled_at timestamptz,
    UNIQUE (organization_id, id),
    CONSTRAINT sso_connections_config_fk
        FOREIGN KEY (organization_id)
        REFERENCES iam.organization_sso_configs (organization_id)
        ON DELETE RESTRICT,
    CONSTRAINT sso_connections_provider_id_length
        CHECK (char_length(provider_connection_id) BETWEEN 1 AND 255),
    CONSTRAINT sso_connections_type_length
        CHECK (connection_type IS NULL OR char_length(connection_type) <= 100),
    CONSTRAINT sso_connections_status
        CHECK (status IN ('pending', 'active', 'disabled', 'error')),
    CONSTRAINT sso_connections_status_timestamps CHECK (
        (status <> 'active' OR activated_at IS NOT NULL)
        AND (status <> 'disabled' OR disabled_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX sso_connections_one_active_idx
    ON iam.sso_connections (organization_id) WHERE status = 'active';

CREATE TABLE iam.sso_membership_policies (
    organization_id uuid PRIMARY KEY,
    allow_policy_admission boolean NOT NULL DEFAULT false,
    default_job_role text NOT NULL DEFAULT '',
    first_silicon_membership_id uuid,
    default_trust_boundary iam.trust_boundary NOT NULL DEFAULT 'internal',
    default_trust_level iam.trust_level NOT NULL DEFAULT 'not_trusted',
    allowed_domains text[] NOT NULL DEFAULT '{}',
    allowed_groups text[] NOT NULL DEFAULT '{}',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT sso_membership_policies_sso_config_fk
        FOREIGN KEY (organization_id)
        REFERENCES iam.organization_sso_configs (organization_id)
        ON DELETE RESTRICT,
    CONSTRAINT sso_membership_policies_first_silicon_fk
        FOREIGN KEY (organization_id, first_silicon_membership_id)
        REFERENCES iam.silicons (organization_id, membership_id)
        ON DELETE RESTRICT,
    CONSTRAINT sso_membership_policies_job_role_length
        CHECK (char_length(default_job_role) <= 5000),
    CONSTRAINT sso_membership_policies_domain_count
        CHECK (cardinality(allowed_domains) <= 100),
    CONSTRAINT sso_membership_policies_group_count
        CHECK (cardinality(allowed_groups) <= 500),
    CONSTRAINT sso_membership_policies_admission_constraints CHECK (
        NOT allow_policy_admission
        OR cardinality(allowed_domains) > 0
        OR cardinality(allowed_groups) > 0
    ),
    CONSTRAINT sso_membership_policies_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.sso_membership_policies IS
    'Explicit existing-Carbon admission policy. Without an enabled matching policy, SSO requires an invitation.';

CREATE TRIGGER sso_membership_policies_bump_version
BEFORE UPDATE ON iam.sso_membership_policies
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE TABLE iam.sso_membership_policy_tags (
    organization_id uuid NOT NULL,
    tag_id uuid NOT NULL,
    PRIMARY KEY (organization_id, tag_id),
    CONSTRAINT sso_membership_policy_tags_policy_fk
        FOREIGN KEY (organization_id)
        REFERENCES iam.sso_membership_policies (organization_id)
        ON DELETE RESTRICT,
    CONSTRAINT sso_membership_policy_tags_tag_fk
        FOREIGN KEY (organization_id, tag_id)
        REFERENCES iam.organization_tags (organization_id, id)
        ON DELETE RESTRICT
);

CREATE TABLE iam.sso_identities (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    provider_subject text NOT NULL,
    carbon_id uuid NOT NULL,
    verified_contact_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    last_authenticated_at timestamptz,
    revoked_at timestamptz,
    UNIQUE (connection_id, provider_subject),
    UNIQUE (connection_id, carbon_id),
    CONSTRAINT sso_identities_connection_fk
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES iam.sso_connections (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT sso_identities_contact_fk
        FOREIGN KEY (carbon_id, verified_contact_id)
        REFERENCES iam.carbon_contacts (carbon_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT sso_identities_provider_subject_length
        CHECK (char_length(provider_subject) BETWEEN 1 AND 512)
);

CREATE INDEX sso_identities_carbon_idx
    ON iam.sso_identities (carbon_id, revoked_at);

CREATE TABLE iam.sso_authorization_transactions (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    carbon_id uuid NOT NULL,
    authentication_session_id uuid NOT NULL,
    state_digest bytea NOT NULL UNIQUE,
    nonce_digest bytea NOT NULL,
    digest_key_version smallint NOT NULL,
    digest_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    return_uri_ciphertext bytea NOT NULL,
    return_uri_nonce bytea NOT NULL,
    encryption_key_version smallint NOT NULL,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT sso_authorization_transactions_connection_fk
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES iam.sso_connections (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT sso_authorization_transactions_session_fk
        FOREIGN KEY (authentication_session_id, carbon_id)
        REFERENCES iam.authentication_sessions (id, subject_principal_id)
        ON DELETE RESTRICT,
    CONSTRAINT sso_authorization_transactions_carbon_fk
        FOREIGN KEY (carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT sso_authorization_transactions_digest_key_fk
        FOREIGN KEY (digest_purpose, digest_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT sso_authorization_transactions_encryption_key_fk
        FOREIGN KEY (encryption_purpose, encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT sso_authorization_transactions_digest_lengths CHECK (
        octet_length(state_digest) = 32 AND octet_length(nonce_digest) = 32
    ),
    CONSTRAINT sso_authorization_transactions_ciphertext_length
        CHECK (octet_length(return_uri_ciphertext) BETWEEN 17 AND 8192),
    CONSTRAINT sso_authorization_transactions_nonce_length
        CHECK (octet_length(return_uri_nonce) BETWEEN 12 AND 32),
    CONSTRAINT sso_authorization_transactions_status
        CHECK (status IN ('pending', 'completed', 'expired', 'cancelled')),
    CONSTRAINT sso_authorization_transactions_expiry CHECK (expires_at > created_at),
    CONSTRAINT sso_authorization_transactions_completion_consistency
        CHECK ((status = 'completed') = (consumed_at IS NOT NULL))
);

CREATE INDEX sso_authorization_transactions_expiry_idx
    ON iam.sso_authorization_transactions (status, expires_at) WHERE status = 'pending';

CREATE TABLE iam.sso_setup_sessions (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    requested_by_membership_id uuid NOT NULL,
    provider_intent_id text,
    status text NOT NULL DEFAULT 'created',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT sso_setup_sessions_config_fk
        FOREIGN KEY (organization_id)
        REFERENCES iam.organization_sso_configs (organization_id)
        ON DELETE RESTRICT,
    CONSTRAINT sso_setup_sessions_requester_fk
        FOREIGN KEY (organization_id, requested_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT sso_setup_sessions_intent_length
        CHECK (provider_intent_id IS NULL OR char_length(provider_intent_id) <= 255),
    CONSTRAINT sso_setup_sessions_status
        CHECK (status IN ('created', 'opened', 'completed', 'expired', 'cancelled')),
    CONSTRAINT sso_setup_sessions_expiry CHECK (expires_at > created_at),
    CONSTRAINT sso_setup_sessions_completion_consistency
        CHECK ((status = 'completed') = (consumed_at IS NOT NULL))
);

CREATE TABLE iam.external_webhook_receipts (
    id uuid PRIMARY KEY,
    provider text NOT NULL,
    provider_event_id text NOT NULL,
    payload_digest bytea NOT NULL,
    signature_verified_at timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'received',
    received_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    processed_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0,
    last_error_code text,
    UNIQUE (provider, provider_event_id),
    CONSTRAINT external_webhook_receipts_provider CHECK (provider IN ('workos', 'postmark', 'twilio', 'silicon_hook')),
    CONSTRAINT external_webhook_receipts_event_id_length
        CHECK (char_length(provider_event_id) BETWEEN 1 AND 512),
    CONSTRAINT external_webhook_receipts_digest_length CHECK (octet_length(payload_digest) = 32),
    CONSTRAINT external_webhook_receipts_status
        CHECK (status IN ('received', 'processing', 'processed', 'ignored', 'failed')),
    CONSTRAINT external_webhook_receipts_attempts CHECK (attempt_count >= 0),
    CONSTRAINT external_webhook_receipts_processing_consistency
        CHECK (status <> 'processed' OR processed_at IS NOT NULL)
);

CREATE INDEX external_webhook_receipts_processing_idx
    ON iam.external_webhook_receipts (status, received_at)
    WHERE status IN ('received', 'failed');

CREATE TABLE iam.obo_action_catalog (
    audience_application_id uuid NOT NULL,
    action text NOT NULL,
    description text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    PRIMARY KEY (audience_application_id, action),
    CONSTRAINT obo_action_catalog_audience_fk
        FOREIGN KEY (audience_application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT obo_action_catalog_action_format
        CHECK (action ~ '^[a-z][a-z0-9_.:-]{2,127}$'),
    CONSTRAINT obo_action_catalog_description_length
        CHECK (char_length(description) BETWEEN 1 AND 500),
    CONSTRAINT obo_action_catalog_status CHECK (status IN ('active', 'retired'))
);

CREATE TABLE iam.obo_application_grants (
    id uuid PRIMARY KEY,
    issuer_application_id uuid NOT NULL,
    audience_application_id uuid NOT NULL,
    action text NOT NULL,
    approved_by_carbon_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'active',
    approved_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    revoked_by_carbon_id uuid,
    revoked_at timestamptz,
    UNIQUE (issuer_application_id, audience_application_id, action, approved_at),
    CONSTRAINT obo_application_grants_issuer_fk
        FOREIGN KEY (issuer_application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT obo_application_grants_action_fk
        FOREIGN KEY (audience_application_id, action)
        REFERENCES iam.obo_action_catalog (audience_application_id, action)
        ON DELETE RESTRICT,
    CONSTRAINT obo_application_grants_approver_fk
        FOREIGN KEY (approved_by_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT obo_application_grants_revoker_fk
        FOREIGN KEY (revoked_by_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT obo_application_grants_distinct_apps
        CHECK (issuer_application_id <> audience_application_id),
    CONSTRAINT obo_application_grants_status CHECK (status IN ('active', 'revoked')),
    CONSTRAINT obo_application_grants_revocation_consistency
        CHECK ((status = 'revoked') = (revoked_at IS NOT NULL AND revoked_by_carbon_id IS NOT NULL))
);

CREATE UNIQUE INDEX obo_application_grants_one_active_idx
    ON iam.obo_application_grants (issuer_application_id, audience_application_id, action)
    WHERE status = 'active';

ALTER TABLE iam.access_tokens
    ADD CONSTRAINT access_tokens_obo_parent_unique
    UNIQUE (id, subject_principal_id, client_application_id, organization_id, membership_id);

CREATE TABLE iam.obo_proofs (
    id uuid PRIMARY KEY,
    proof_digest bytea NOT NULL UNIQUE,
    digest_key_version smallint NOT NULL,
    digest_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    proof_prefix text NOT NULL,
    issuer_application_id uuid NOT NULL,
    audience_application_id uuid NOT NULL,
    subject_principal_id uuid NOT NULL,
    subject_kind iam.principal_kind NOT NULL,
    organization_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    parent_access_token_id uuid NOT NULL,
    action text NOT NULL,
    resource_digest bytea,
    resource_digest_key_version smallint,
    resource_digest_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    subject_auth_epoch bigint NOT NULL,
    membership_authz_epoch bigint NOT NULL,
    issuer_auth_epoch bigint NOT NULL,
    audience_auth_epoch bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    consumed_by_application_id uuid,
    revoked_at timestamptz,
    CONSTRAINT obo_proofs_digest_key_fk
        FOREIGN KEY (digest_purpose, digest_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT obo_proofs_resource_digest_key_fk
        FOREIGN KEY (resource_digest_purpose, resource_digest_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT obo_proofs_issuer_fk
        FOREIGN KEY (issuer_application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT obo_proofs_action_fk
        FOREIGN KEY (audience_application_id, action)
        REFERENCES iam.obo_action_catalog (audience_application_id, action)
        ON DELETE RESTRICT,
    CONSTRAINT obo_proofs_subject_fk
        FOREIGN KEY (subject_principal_id, subject_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT obo_proofs_membership_fk
        FOREIGN KEY (organization_id, membership_id, subject_principal_id, subject_kind)
        REFERENCES iam.organization_memberships
            (organization_id, id, principal_id, principal_kind)
        ON DELETE RESTRICT,
    CONSTRAINT obo_proofs_parent_token_fk
        FOREIGN KEY (
            parent_access_token_id, subject_principal_id, issuer_application_id,
            organization_id, membership_id
        )
        REFERENCES iam.access_tokens (
            id, subject_principal_id, client_application_id, organization_id, membership_id
        )
        ON DELETE RESTRICT,
    CONSTRAINT obo_proofs_consumer_fk
        FOREIGN KEY (consumed_by_application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT obo_proofs_digest_length CHECK (octet_length(proof_digest) = 32),
    CONSTRAINT obo_proofs_prefix_format
        CHECK (proof_prefix ~ '^obo_[A-Za-z0-9_-]{8}$'),
    CONSTRAINT obo_proofs_resource_binding CHECK (
        (resource_digest IS NULL AND resource_digest_key_version IS NULL)
        OR (resource_digest IS NOT NULL AND octet_length(resource_digest) = 32
            AND resource_digest_key_version IS NOT NULL)
    ),
    CONSTRAINT obo_proofs_positive_epochs CHECK (
        subject_auth_epoch > 0 AND membership_authz_epoch > 0
        AND issuer_auth_epoch > 0 AND audience_auth_epoch > 0
    ),
    CONSTRAINT obo_proofs_lifetime CHECK (
        expires_at > created_at AND expires_at <= created_at + interval '60 seconds'
    ),
    CONSTRAINT obo_proofs_consumption_consistency CHECK (
        (consumed_at IS NULL AND consumed_by_application_id IS NULL)
        OR (consumed_at IS NOT NULL AND consumed_by_application_id = audience_application_id)
    )
);

COMMENT ON TABLE iam.obo_proofs IS
    'Random one-time OBO capabilities bound to issuer, audience, actor, organization, action, resource, and current epochs.';

CREATE INDEX obo_proofs_audience_idx
    ON iam.obo_proofs (audience_application_id, expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;
CREATE INDEX obo_proofs_subject_history_idx
    ON iam.obo_proofs (subject_principal_id, created_at DESC, id);
