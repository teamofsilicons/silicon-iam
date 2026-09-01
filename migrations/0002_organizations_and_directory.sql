-- Organization tenancy, directory, invitations, tags, Silicon identities, and capabilities.

CREATE TYPE iam.organization_role AS ENUM ('owner', 'admin', 'member');

CREATE TABLE iam.organizations (
    id uuid PRIMARY KEY,
    org_id text NOT NULL,
    created_by_carbon_id uuid NOT NULL,
    name text NOT NULL,
    logo_uri text,
    description text,
    join_method text NOT NULL DEFAULT 'email',
    status text NOT NULL DEFAULT 'active',
    default_trust_boundary iam.trust_boundary NOT NULL DEFAULT 'internal',
    default_trust_level iam.trust_level NOT NULL DEFAULT 'not_trusted',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    deleted_at timestamptz,
    UNIQUE (org_id),
    UNIQUE (id, org_id),
    CONSTRAINT organizations_creator_fk
        FOREIGN KEY (created_by_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT organizations_org_id_format CHECK (org_id ~ '^[a-z0-9_-]{3,50}$'),
    CONSTRAINT organizations_name_length CHECK (char_length(name) BETWEEN 1 AND 200),
    CONSTRAINT organizations_logo_uri_length
        CHECK (logo_uri IS NULL OR char_length(logo_uri) <= 2048),
    CONSTRAINT organizations_description_length
        CHECK (description IS NULL OR char_length(description) <= 5000),
    CONSTRAINT organizations_join_method CHECK (join_method IN ('email', 'sso')),
    CONSTRAINT organizations_status CHECK (status IN ('active', 'suspended', 'deleted')),
    CONSTRAINT organizations_positive_version CHECK (version > 0),
    CONSTRAINT organizations_deletion_consistency
        CHECK ((status = 'deleted') = (deleted_at IS NOT NULL))
);

COMMENT ON TABLE iam.organizations IS
    'Top-level tenant and directory security boundary. org_id is immutable after creation.';

CREATE FUNCTION iam_private.prevent_organization_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.org_id <> OLD.org_id THEN
        RAISE EXCEPTION 'organization internal id and org_id are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER organizations_immutable_identity
BEFORE UPDATE ON iam.organizations
FOR EACH ROW EXECUTE FUNCTION iam_private.prevent_organization_identity_change();

CREATE TRIGGER organizations_bump_version
BEFORE UPDATE ON iam.organizations
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE INDEX organizations_creator_idx
    ON iam.organizations (created_by_carbon_id, status, created_at);
CREATE INDEX organizations_status_idx ON iam.organizations (status, created_at, id);

CREATE TABLE iam.organization_memberships (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    principal_kind iam.principal_kind NOT NULL,
    org_role iam.organization_role NOT NULL DEFAULT 'member',
    job_role text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'active',
    role_granted_by_membership_id uuid,
    authz_epoch bigint NOT NULL DEFAULT 1,
    version bigint NOT NULL DEFAULT 1,
    joined_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    suspended_at timestamptz,
    removed_at timestamptz,
    UNIQUE (organization_id, principal_id),
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, id, principal_id, principal_kind),
    CONSTRAINT organization_memberships_organization_fk
        FOREIGN KEY (organization_id) REFERENCES iam.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT organization_memberships_principal_fk
        FOREIGN KEY (principal_id, principal_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT organization_memberships_grantor_fk
        FOREIGN KEY (organization_id, role_granted_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT organization_memberships_job_role_length CHECK (char_length(job_role) <= 5000),
    CONSTRAINT organization_memberships_status
        CHECK (status IN ('active', 'suspended', 'removed')),
    CONSTRAINT organization_memberships_positive_authz_epoch CHECK (authz_epoch > 0),
    CONSTRAINT organization_memberships_positive_version CHECK (version > 0),
    CONSTRAINT organization_memberships_supported_principal_kind
        CHECK (principal_kind IN ('carbon', 'silicon')),
    CONSTRAINT organization_memberships_human_admin_roles CHECK (
        org_role = 'member' OR principal_kind = 'carbon'
    ),
    CONSTRAINT organization_memberships_admin_grantor CHECK (
        org_role <> 'admin' OR role_granted_by_membership_id IS NOT NULL
    ),
    CONSTRAINT organization_memberships_status_timestamps CHECK (
        (status <> 'suspended' OR suspended_at IS NOT NULL)
        AND (status <> 'removed' OR removed_at IS NOT NULL)
    )
);

COMMENT ON TABLE iam.organization_memberships IS
    'One durable membership identity per principal and organization, including removed history.';
COMMENT ON COLUMN iam.organization_memberships.org_role IS
    'Authorization tier. Silicons are always members; their authority comes from explicit machine capabilities.';
COMMENT ON COLUMN iam.organization_memberships.job_role IS
    'Descriptive directory text only and never an authorization input.';
COMMENT ON COLUMN iam.organization_memberships.authz_epoch IS
    'Incremented for any membership authority or visibility change to invalidate token snapshots.';

CREATE FUNCTION iam_private.prevent_membership_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id <> OLD.id
       OR NEW.organization_id <> OLD.organization_id
       OR NEW.principal_id <> OLD.principal_id
       OR NEW.principal_kind <> OLD.principal_kind THEN
        RAISE EXCEPTION 'membership identity and tenant are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER organization_memberships_immutable_identity
BEFORE UPDATE ON iam.organization_memberships
FOR EACH ROW EXECUTE FUNCTION iam_private.prevent_membership_identity_change();

CREATE TRIGGER organization_memberships_bump_version
BEFORE UPDATE ON iam.organization_memberships
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE UNIQUE INDEX organization_memberships_one_active_owner_idx
    ON iam.organization_memberships (organization_id)
    WHERE status = 'active' AND org_role = 'owner';
CREATE INDEX organization_memberships_principal_idx
    ON iam.organization_memberships (principal_id, status, organization_id);
CREATE INDEX organization_memberships_directory_idx
    ON iam.organization_memberships (organization_id, status, principal_kind, id);
CREATE INDEX organization_memberships_authority_idx
    ON iam.organization_memberships (organization_id, org_role, status);

CREATE FUNCTION iam_private.assert_exactly_one_organization_owner(p_organization_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    owner_count integer;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM iam.organizations AS organization
        WHERE organization.id = p_organization_id
          AND organization.status = 'active'
    ) THEN
        RETURN;
    END IF;

    SELECT count(*)
    INTO owner_count
    FROM iam.organization_memberships AS membership
    WHERE membership.organization_id = p_organization_id
      AND membership.status = 'active'
      AND membership.org_role = 'owner';

    IF owner_count <> 1 THEN
        RAISE EXCEPTION 'active organization % must have exactly one active owner', p_organization_id
            USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE FUNCTION iam_private.check_owner_after_membership_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    affected_organization_id uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        affected_organization_id := OLD.organization_id;
    ELSE
        affected_organization_id := NEW.organization_id;
    END IF;
    PERFORM iam_private.assert_exactly_one_organization_owner(affected_organization_id);
    RETURN NULL;
END;
$$;

CREATE FUNCTION iam_private.check_owner_after_organization_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    affected_organization_id uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        affected_organization_id := OLD.id;
    ELSE
        affected_organization_id := NEW.id;
    END IF;
    PERFORM iam_private.assert_exactly_one_organization_owner(affected_organization_id);
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER organization_memberships_exactly_one_owner
AFTER INSERT OR UPDATE OR DELETE ON iam.organization_memberships
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_owner_after_membership_change();

CREATE CONSTRAINT TRIGGER organizations_exactly_one_owner
AFTER INSERT OR UPDATE OR DELETE ON iam.organizations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_owner_after_organization_change();

CREATE TABLE iam.organization_capability_catalog (
    capability text PRIMARY KEY,
    description text NOT NULL,
    delegable boolean NOT NULL DEFAULT false,
    allowed_for_carbon boolean NOT NULL DEFAULT true,
    allowed_for_silicon boolean NOT NULL DEFAULT false,
    CONSTRAINT organization_capability_catalog_format
        CHECK (capability ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    CONSTRAINT organization_capability_catalog_description_length
        CHECK (char_length(description) BETWEEN 1 AND 500)
);

COMMENT ON TABLE iam.organization_capability_catalog IS
    'Deny-by-default fixed vocabulary of organization authority; owners receive all capabilities implicitly.';

INSERT INTO iam.organization_capability_catalog
    (capability, description, delegable, allowed_for_carbon, allowed_for_silicon)
VALUES
    ('organization.update', 'Update non-immutable organization settings.', false, true, false),
    ('members.invite', 'Invite existing Carbons into the organization.', true, true, false),
    ('members.update_directory', 'Update member directory configuration.', true, true, true),
    ('members.remove', 'Remove non-owner members.', false, true, false),
    ('silicons.create', 'Create Silicon identities.', true, true, false),
    ('silicons.update_directory', 'Update Silicon directory configuration.', true, true, true),
    ('silicons.manage_hierarchy', 'Update Silicon reporting relationships.', true, true, true),
    ('silicons.remove', 'Remove Silicon identities.', false, true, false),
    ('silicons.rotate_token', 'Request Silicon credential rotation.', false, true, false),
    ('tags.manage', 'Create, rename, archive, and assign organization tags.', true, true, false),
    ('trust.manage', 'Manage advisory trust rules.', true, true, true),
    ('roles.request', 'Request a descriptive job-role change.', true, true, true),
    ('roles.approve', 'Approve an eligible job-role change.', false, true, false),
    ('admins.create', 'Promote a member using a delegable capability subset.', false, true, false),
    ('admins.manage', 'Change admin grants or demote an administrator.', false, true, false),
    ('sso.manage', 'Configure the organization SSO integration.', false, true, false),
    ('audit.read', 'Read organization audit history.', false, true, false);

CREATE TABLE iam.organization_capability_grants (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    grantee_membership_id uuid NOT NULL,
    capability text NOT NULL,
    granted_by_membership_id uuid NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    revoked_by_membership_id uuid,
    revoked_by_platform_carbon_id uuid,
    revoked_at timestamptz,
    reason text,
    CONSTRAINT organization_capability_grants_grantee_fk
        FOREIGN KEY (organization_id, grantee_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT organization_capability_grants_grantor_fk
        FOREIGN KEY (organization_id, granted_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT organization_capability_grants_revoker_fk
        FOREIGN KEY (organization_id, revoked_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT organization_capability_grants_platform_revoker_fk
        FOREIGN KEY (revoked_by_platform_carbon_id)
        REFERENCES iam.carbons (id)
        ON DELETE RESTRICT,
    CONSTRAINT organization_capability_grants_capability_fk
        FOREIGN KEY (capability)
        REFERENCES iam.organization_capability_catalog (capability)
        ON DELETE RESTRICT,
    CONSTRAINT organization_capability_grants_reason_length
        CHECK (reason IS NULL OR char_length(reason) <= 1000),
    CONSTRAINT organization_capability_grants_revocation_consistency CHECK (
        (revoked_at IS NULL) = (
            revoked_by_membership_id IS NULL
            AND revoked_by_platform_carbon_id IS NULL
        )
        AND NOT (
            revoked_by_membership_id IS NOT NULL
            AND revoked_by_platform_carbon_id IS NOT NULL
        )
    )
);

CREATE UNIQUE INDEX organization_capability_grants_one_active_idx
    ON iam.organization_capability_grants
        (organization_id, grantee_membership_id, capability)
    WHERE revoked_at IS NULL;
CREATE INDEX organization_capability_grants_grantee_idx
    ON iam.organization_capability_grants
        (organization_id, grantee_membership_id, revoked_at);

CREATE TABLE iam.organization_tags (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    name text NOT NULL,
    normalized_name text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    created_by_membership_id uuid NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    archived_at timestamptz,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, normalized_name),
    CONSTRAINT organization_tags_creator_fk
        FOREIGN KEY (organization_id, created_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT organization_tags_organization_fk
        FOREIGN KEY (organization_id) REFERENCES iam.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT organization_tags_name_length CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT organization_tags_normalized_name_format
        CHECK (normalized_name ~ '^[a-z0-9][a-z0-9_-]{0,99}$'),
    CONSTRAINT organization_tags_status CHECK (status IN ('active', 'archived')),
    CONSTRAINT organization_tags_archive_consistency
        CHECK ((status = 'archived') = (archived_at IS NOT NULL)),
    CONSTRAINT organization_tags_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.organization_tags IS
    'Immutable-identity tenant-scoped tags. Referenced tags are restricted from deletion.';

CREATE TRIGGER organization_tags_bump_version
BEFORE UPDATE ON iam.organization_tags
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE TABLE iam.silicons (
    id uuid PRIMARY KEY,
    principal_kind iam.principal_kind
        GENERATED ALWAYS AS ('silicon'::iam.principal_kind) STORED,
    organization_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    organization_handle text NOT NULL,
    local_silicon_id text NOT NULL,
    global_silicon_id text
        GENERATED ALWAYS AS (local_silicon_id || ':' || organization_handle) STORED,
    profile_photo_override_uri text,
    reports_to_membership_id uuid,
    provisioning_status text NOT NULL DEFAULT 'pending_hook',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    deleted_at timestamptz,
    UNIQUE (global_silicon_id),
    UNIQUE (organization_id, local_silicon_id),
    UNIQUE (organization_id, membership_id),
    UNIQUE (organization_id, id),
    CONSTRAINT silicons_principal_fk
        FOREIGN KEY (id, principal_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT silicons_organization_handle_fk
        FOREIGN KEY (organization_id, organization_handle)
        REFERENCES iam.organizations (id, org_id)
        ON DELETE RESTRICT,
    CONSTRAINT silicons_membership_fk
        FOREIGN KEY (organization_id, membership_id, id, principal_kind)
        REFERENCES iam.organization_memberships
            (organization_id, id, principal_id, principal_kind)
        ON DELETE RESTRICT,
    CONSTRAINT silicons_reports_to_fk
        FOREIGN KEY (organization_id, reports_to_membership_id)
        REFERENCES iam.silicons (organization_id, membership_id)
        ON DELETE RESTRICT,
    CONSTRAINT silicons_local_id_format
        CHECK (local_silicon_id ~ '^[a-z0-9_-]{3,50}$'),
    CONSTRAINT silicons_global_id_length CHECK (char_length(global_silicon_id) <= 101),
    CONSTRAINT silicons_profile_photo_uri_length
        CHECK (profile_photo_override_uri IS NULL OR char_length(profile_photo_override_uri) <= 2048),
    CONSTRAINT silicons_not_self_reporting
        CHECK (reports_to_membership_id IS NULL OR reports_to_membership_id <> membership_id),
    CONSTRAINT silicons_provisioning_status
        CHECK (provisioning_status IN ('pending_hook', 'active', 'hook_error', 'deleted')),
    CONSTRAINT silicons_positive_version CHECK (version > 0),
    CONSTRAINT silicons_deletion_consistency
        CHECK ((provisioning_status = 'deleted') = (deleted_at IS NOT NULL))
);

COMMENT ON TABLE iam.silicons IS
    'Organization-bound AI-agent identities. Effective Iris profile URLs are derived at read time.';

CREATE FUNCTION iam_private.prevent_silicon_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id <> OLD.id
       OR NEW.organization_id <> OLD.organization_id
       OR NEW.membership_id <> OLD.membership_id
       OR NEW.organization_handle <> OLD.organization_handle
       OR NEW.local_silicon_id <> OLD.local_silicon_id THEN
        RAISE EXCEPTION 'Silicon identity, tenant, and handles are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER silicons_immutable_identity
BEFORE UPDATE ON iam.silicons
FOR EACH ROW EXECUTE FUNCTION iam_private.prevent_silicon_identity_change();

CREATE FUNCTION iam_private.prevent_silicon_reporting_cycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    creates_cycle boolean;
BEGIN
    IF NEW.reports_to_membership_id IS NULL THEN
        RETURN NEW;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.organization_id::text, 734921));

    IF NOT EXISTS (
        SELECT 1
        FROM iam.organization_memberships AS parent_membership
        WHERE parent_membership.organization_id = NEW.organization_id
          AND parent_membership.id = NEW.reports_to_membership_id
          AND parent_membership.principal_kind = 'silicon'
          AND parent_membership.status = 'active'
    ) THEN
        RAISE EXCEPTION 'reports_to must reference an active Silicon in the same organization'
            USING ERRCODE = '23514';
    END IF;

    WITH RECURSIVE ancestors AS (
        SELECT silicon.membership_id, silicon.reports_to_membership_id
        FROM iam.silicons AS silicon
        WHERE silicon.organization_id = NEW.organization_id
          AND silicon.membership_id = NEW.reports_to_membership_id

        UNION

        SELECT silicon.membership_id, silicon.reports_to_membership_id
        FROM iam.silicons AS silicon
        JOIN ancestors
          ON ancestors.reports_to_membership_id = silicon.membership_id
        WHERE silicon.organization_id = NEW.organization_id
    )
    SELECT EXISTS (
        SELECT 1 FROM ancestors WHERE membership_id = NEW.membership_id
    )
    INTO creates_cycle;

    IF creates_cycle THEN
        RAISE EXCEPTION 'reports_to would create a Silicon reporting cycle'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER silicons_prevent_reporting_cycle
BEFORE INSERT OR UPDATE OF reports_to_membership_id ON iam.silicons
FOR EACH ROW EXECUTE FUNCTION iam_private.prevent_silicon_reporting_cycle();

CREATE TRIGGER silicons_bump_version
BEFORE UPDATE ON iam.silicons
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE INDEX silicons_reports_to_idx
    ON iam.silicons (organization_id, reports_to_membership_id)
    WHERE reports_to_membership_id IS NOT NULL;
CREATE INDEX silicons_directory_idx
    ON iam.silicons (organization_id, provisioning_status, local_silicon_id);

CREATE TABLE iam.carbon_membership_settings (
    organization_id uuid NOT NULL,
    membership_id uuid PRIMARY KEY,
    carbon_id uuid NOT NULL,
    principal_kind iam.principal_kind
        GENERATED ALWAYS AS ('carbon'::iam.principal_kind) STORED,
    first_silicon_membership_id uuid,
    default_trust_boundary iam.trust_boundary NOT NULL DEFAULT 'internal',
    default_trust_level iam.trust_level NOT NULL DEFAULT 'not_trusted',
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (organization_id, membership_id),
    CONSTRAINT carbon_membership_settings_membership_fk
        FOREIGN KEY (organization_id, membership_id, carbon_id, principal_kind)
        REFERENCES iam.organization_memberships
            (organization_id, id, principal_id, principal_kind)
        ON DELETE RESTRICT,
    CONSTRAINT carbon_membership_settings_first_silicon_fk
        FOREIGN KEY (organization_id, first_silicon_membership_id)
        REFERENCES iam.silicons (organization_id, membership_id)
        ON DELETE RESTRICT
);

COMMENT ON TABLE iam.carbon_membership_settings IS
    'Carbon-only organization directory settings kept separate from authorization role data.';

CREATE TRIGGER carbon_membership_settings_updated_at
BEFORE UPDATE ON iam.carbon_membership_settings
FOR EACH ROW EXECUTE FUNCTION iam_private.set_updated_at();

CREATE TABLE iam.membership_tags (
    organization_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    tag_id uuid NOT NULL,
    assigned_by_membership_id uuid NOT NULL,
    assigned_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, membership_id, tag_id),
    CONSTRAINT membership_tags_membership_fk
        FOREIGN KEY (organization_id, membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT membership_tags_tag_fk
        FOREIGN KEY (organization_id, tag_id)
        REFERENCES iam.organization_tags (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT membership_tags_assigner_fk
        FOREIGN KEY (organization_id, assigned_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT
);

CREATE INDEX membership_tags_tag_idx
    ON iam.membership_tags (organization_id, tag_id, membership_id);

CREATE TABLE iam.extra_silicon_access_grants (
    organization_id uuid NOT NULL,
    carbon_membership_id uuid NOT NULL,
    silicon_membership_id uuid NOT NULL,
    granted_by_membership_id uuid NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    revoked_by_membership_id uuid,
    revoked_by_platform_carbon_id uuid,
    revoked_at timestamptz,
    PRIMARY KEY (organization_id, carbon_membership_id, silicon_membership_id, granted_at),
    CONSTRAINT extra_silicon_access_carbon_fk
        FOREIGN KEY (organization_id, carbon_membership_id)
        REFERENCES iam.carbon_membership_settings (organization_id, membership_id)
        ON DELETE RESTRICT,
    CONSTRAINT extra_silicon_access_silicon_fk
        FOREIGN KEY (organization_id, silicon_membership_id)
        REFERENCES iam.silicons (organization_id, membership_id)
        ON DELETE RESTRICT,
    CONSTRAINT extra_silicon_access_grantor_fk
        FOREIGN KEY (organization_id, granted_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT extra_silicon_access_revoker_fk
        FOREIGN KEY (organization_id, revoked_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT extra_silicon_access_platform_revoker_fk
        FOREIGN KEY (revoked_by_platform_carbon_id)
        REFERENCES iam.carbons (id)
        ON DELETE RESTRICT,
    CONSTRAINT extra_silicon_access_revocation_consistency CHECK (
        (revoked_at IS NULL) = (
            revoked_by_membership_id IS NULL
            AND revoked_by_platform_carbon_id IS NULL
        )
        AND NOT (
            revoked_by_membership_id IS NOT NULL
            AND revoked_by_platform_carbon_id IS NOT NULL
        )
    )
);

CREATE UNIQUE INDEX extra_silicon_access_one_active_idx
    ON iam.extra_silicon_access_grants
        (organization_id, carbon_membership_id, silicon_membership_id)
    WHERE revoked_at IS NULL;
CREATE INDEX extra_silicon_access_reverse_idx
    ON iam.extra_silicon_access_grants
        (organization_id, silicon_membership_id, revoked_at);

CREATE TABLE iam.silicon_credentials (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    silicon_id uuid NOT NULL,
    credential_prefix text NOT NULL,
    secret_digest bytea NOT NULL,
    pepper_key_version smallint NOT NULL,
    pepper_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    status text NOT NULL DEFAULT 'active',
    created_by_membership_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    last_used_at timestamptz,
    retired_at timestamptz,
    UNIQUE (silicon_id, id),
    CONSTRAINT silicon_credentials_silicon_fk
        FOREIGN KEY (organization_id, silicon_id)
        REFERENCES iam.silicons (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_credentials_creator_fk
        FOREIGN KEY (organization_id, created_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_credentials_pepper_key_fk
        FOREIGN KEY (pepper_purpose, pepper_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_credentials_prefix_format
        CHECK (credential_prefix ~ '^stk-[a-f0-9]{8}$'),
    CONSTRAINT silicon_credentials_digest_length
        CHECK (octet_length(secret_digest) = 32),
    CONSTRAINT silicon_credentials_status CHECK (status IN ('active', 'retired', 'compromised')),
    CONSTRAINT silicon_credentials_retirement_consistency
        CHECK ((status = 'active') = (retired_at IS NULL))
);

COMMENT ON TABLE iam.silicon_credentials IS
    'Purpose-separated keyed Silicon credential digests. Raw STKs are never persisted.';

CREATE UNIQUE INDEX silicon_credentials_one_active_idx
    ON iam.silicon_credentials (silicon_id)
    WHERE status = 'active';

CREATE TABLE iam.silicon_hooks (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    silicon_id uuid NOT NULL,
    provider_hook_id text,
    url_ciphertext bytea,
    url_nonce bytea,
    encryption_key_version smallint,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    status text NOT NULL DEFAULT 'pending',
    last_error_code text,
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz,
    lease_owner text,
    lease_expires_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    activated_at timestamptz,
    UNIQUE (organization_id, silicon_id),
    UNIQUE (provider_hook_id),
    CONSTRAINT silicon_hooks_silicon_fk
        FOREIGN KEY (organization_id, silicon_id)
        REFERENCES iam.silicons (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_hooks_encryption_key_fk
        FOREIGN KEY (encryption_purpose, encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_hooks_status
        CHECK (status IN ('pending', 'provisioning', 'active', 'failed', 'disabled')),
    CONSTRAINT silicon_hooks_nonnegative_attempts CHECK (attempt_count >= 0),
    CONSTRAINT silicon_hooks_lease_consistency CHECK (
        (lease_owner IS NULL AND lease_expires_at IS NULL)
        OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
    ),
    CONSTRAINT silicon_hooks_url_encryption_consistency CHECK (
        (url_ciphertext IS NULL AND url_nonce IS NULL AND encryption_key_version IS NULL)
        OR (url_ciphertext IS NOT NULL AND url_nonce IS NOT NULL AND encryption_key_version IS NOT NULL)
    ),
    CONSTRAINT silicon_hooks_url_nonce_length
        CHECK (url_nonce IS NULL OR octet_length(url_nonce) BETWEEN 12 AND 32),
    CONSTRAINT silicon_hooks_positive_version CHECK (version > 0)
);

CREATE TRIGGER silicon_hooks_bump_version
BEFORE UPDATE ON iam.silicon_hooks
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE TABLE iam.organization_invitations (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    target_carbon_id uuid NOT NULL,
    invited_by_membership_id uuid NOT NULL,
    job_role text NOT NULL,
    first_silicon_membership_id uuid,
    default_trust_boundary iam.trust_boundary NOT NULL,
    default_trust_level iam.trust_level NOT NULL,
    redirect_application_principal_id uuid,
    redirect_application_kind iam.principal_kind
        GENERATED ALWAYS AS ('application'::iam.principal_kind) STORED,
    status text NOT NULL DEFAULT 'pending',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    revoked_at timestamptz,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, id, target_carbon_id),
    CONSTRAINT organization_invitations_organization_fk
        FOREIGN KEY (organization_id) REFERENCES iam.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT organization_invitations_target_fk
        FOREIGN KEY (target_carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT organization_invitations_inviter_fk
        FOREIGN KEY (organization_id, invited_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT organization_invitations_first_silicon_fk
        FOREIGN KEY (organization_id, first_silicon_membership_id)
        REFERENCES iam.silicons (organization_id, membership_id)
        ON DELETE RESTRICT,
    CONSTRAINT organization_invitations_redirect_app_fk
        FOREIGN KEY (redirect_application_principal_id, redirect_application_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT organization_invitations_job_role_length CHECK (char_length(job_role) <= 5000),
    CONSTRAINT organization_invitations_status
        CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    CONSTRAINT organization_invitations_expiry CHECK (expires_at > created_at),
    CONSTRAINT organization_invitations_terminal_timestamps CHECK (
        (status <> 'accepted' OR accepted_at IS NOT NULL)
        AND (status <> 'revoked' OR revoked_at IS NOT NULL)
    ),
    CONSTRAINT organization_invitations_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.organization_invitations IS
    'Auditable 48-hour invitations addressed only to already-registered Carbons.';

CREATE UNIQUE INDEX organization_invitations_one_pending_idx
    ON iam.organization_invitations (organization_id, target_carbon_id)
    WHERE status = 'pending';
CREATE INDEX organization_invitations_org_status_expiry_idx
    ON iam.organization_invitations (organization_id, status, expires_at, id);
CREATE INDEX organization_invitations_target_idx
    ON iam.organization_invitations (target_carbon_id, status, expires_at);

CREATE TRIGGER organization_invitations_bump_version
BEFORE UPDATE ON iam.organization_invitations
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE TABLE iam.organization_invitation_tags (
    organization_id uuid NOT NULL,
    invitation_id uuid NOT NULL,
    tag_id uuid NOT NULL,
    PRIMARY KEY (organization_id, invitation_id, tag_id),
    CONSTRAINT organization_invitation_tags_invitation_fk
        FOREIGN KEY (organization_id, invitation_id)
        REFERENCES iam.organization_invitations (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT organization_invitation_tags_tag_fk
        FOREIGN KEY (organization_id, tag_id)
        REFERENCES iam.organization_tags (organization_id, id)
        ON DELETE RESTRICT
);

CREATE TABLE iam.organization_invitation_extra_silicons (
    organization_id uuid NOT NULL,
    invitation_id uuid NOT NULL,
    silicon_membership_id uuid NOT NULL,
    PRIMARY KEY (organization_id, invitation_id, silicon_membership_id),
    CONSTRAINT organization_invitation_extra_invitation_fk
        FOREIGN KEY (organization_id, invitation_id)
        REFERENCES iam.organization_invitations (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT organization_invitation_extra_silicon_fk
        FOREIGN KEY (organization_id, silicon_membership_id)
        REFERENCES iam.silicons (organization_id, membership_id)
        ON DELETE RESTRICT
);

CREATE TABLE iam.invitation_verification_challenges (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    invitation_id uuid NOT NULL,
    target_carbon_id uuid NOT NULL,
    destination_contact_id uuid NOT NULL,
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
    CONSTRAINT invitation_verification_invitation_fk
        FOREIGN KEY (organization_id, invitation_id, target_carbon_id)
        REFERENCES iam.organization_invitations (organization_id, id, target_carbon_id)
        ON DELETE RESTRICT,
    CONSTRAINT invitation_verification_contact_fk
        FOREIGN KEY (target_carbon_id, destination_contact_id)
        REFERENCES iam.carbon_contacts (carbon_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT invitation_verification_digest_key_fk
        FOREIGN KEY (digest_purpose, digest_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT invitation_verification_digest_length CHECK (octet_length(code_digest) = 32),
    CONSTRAINT invitation_verification_attempts
        CHECK (max_attempts BETWEEN 1 AND 5 AND failed_attempts BETWEEN 0 AND max_attempts),
    CONSTRAINT invitation_verification_expiry CHECK (expires_at > created_at),
    CONSTRAINT invitation_verification_terminal_exclusivity
        CHECK (consumed_at IS NULL OR superseded_at IS NULL)
);

COMMENT ON TABLE iam.invitation_verification_challenges IS
    'Single-purpose, target-bound organization join challenges retaining only an IAM-generated code digest; delivery is synchronous after commit.';

CREATE UNIQUE INDEX invitation_verification_one_current_idx
    ON iam.invitation_verification_challenges (invitation_id)
    WHERE consumed_at IS NULL AND superseded_at IS NULL;
CREATE INDEX invitation_verification_expiry_idx
    ON iam.invitation_verification_challenges (expires_at)
    WHERE consumed_at IS NULL AND superseded_at IS NULL;
