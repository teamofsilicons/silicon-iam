-- Silicon IAM foundational identity schema.
-- PostgreSQL 16 compatible. Runtime cryptographic key material never belongs in this schema.

CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS iam_private;

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

CREATE TYPE iam.principal_kind AS ENUM ('carbon', 'silicon', 'application', 'service');
CREATE TYPE iam.contact_kind AS ENUM ('email', 'phone');
CREATE TYPE iam.trust_boundary AS ENUM ('internal', 'external');
CREATE TYPE iam.trust_level AS ENUM ('not_trusted', 'needs_approval', 'trusted');

CREATE FUNCTION iam_private.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := transaction_timestamp();
    RETURN NEW;
END;
$$;

CREATE FUNCTION iam_private.bump_aggregate_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.version := OLD.version + 1;
    NEW.updated_at := transaction_timestamp();
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION iam_private.bump_aggregate_version() IS
    'Advances an externally visible aggregate by exactly one version per row mutation.';

CREATE TABLE iam.cryptographic_key_versions (
    purpose text NOT NULL,
    key_version smallint NOT NULL,
    status text NOT NULL DEFAULT 'active',
    provider_key_reference text,
    activated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    retired_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (purpose, key_version),
    CONSTRAINT cryptographic_key_versions_purpose_format
        CHECK (purpose ~ '^[a-z][a-z0-9_]{2,63}$'),
    CONSTRAINT cryptographic_key_versions_positive_version CHECK (key_version > 0),
    CONSTRAINT cryptographic_key_versions_status
        CHECK (status IN ('pending', 'active', 'decrypt_only', 'retired')),
    CONSTRAINT cryptographic_key_versions_retirement_consistency
        CHECK ((status = 'retired') = (retired_at IS NOT NULL))
);

COMMENT ON TABLE iam.cryptographic_key_versions IS
    'Non-secret metadata for application-managed encryption, HMAC, and pepper key rotations.';
COMMENT ON COLUMN iam.cryptographic_key_versions.provider_key_reference IS
    'Opaque secret-provider key identifier; never key material.';

CREATE TABLE iam.principals (
    id uuid PRIMARY KEY,
    kind iam.principal_kind NOT NULL,
    status text NOT NULL DEFAULT 'provisioning',
    auth_epoch bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    activated_at timestamptz,
    suspended_at timestamptz,
    deleted_at timestamptz,
    UNIQUE (id, kind),
    CONSTRAINT principals_non_nil_id CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT principals_status
        CHECK (status IN ('provisioning', 'active', 'suspended', 'deleted')),
    CONSTRAINT principals_positive_auth_epoch CHECK (auth_epoch > 0),
    CONSTRAINT principals_status_timestamps CHECK (
        (status <> 'active' OR activated_at IS NOT NULL)
        AND (status <> 'suspended' OR suspended_at IS NOT NULL)
        AND (status <> 'deleted' OR deleted_at IS NOT NULL)
    )
);

COMMENT ON TABLE iam.principals IS
    'Internal security-principal supertype. Public handles live only on typed subtype tables.';
COMMENT ON COLUMN iam.principals.auth_epoch IS
    'Incremented to invalidate every credential and token snapshot for this principal.';

CREATE FUNCTION iam_private.prevent_principal_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.kind <> OLD.kind THEN
        RAISE EXCEPTION 'principal id and kind are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER principals_immutable_identity
BEFORE UPDATE ON iam.principals
FOR EACH ROW EXECUTE FUNCTION iam_private.prevent_principal_identity_change();

CREATE INDEX principals_status_idx ON iam.principals (status, kind);

CREATE TABLE iam.carbons (
    id uuid PRIMARY KEY,
    principal_kind iam.principal_kind
        GENERATED ALWAYS AS ('carbon'::iam.principal_kind) STORED,
    carbon_id text NOT NULL,
    display_name text NOT NULL,
    description text,
    profile_photo_uri text,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    deleted_at timestamptz,
    UNIQUE (carbon_id),
    UNIQUE (id, principal_kind),
    CONSTRAINT carbons_principal_fk
        FOREIGN KEY (id, principal_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT carbons_carbon_id_format CHECK (carbon_id ~ '^[a-z0-9_-]{3,30}$'),
    CONSTRAINT carbons_display_name_length
        CHECK (char_length(display_name) BETWEEN 1 AND 200),
    CONSTRAINT carbons_description_length
        CHECK (description IS NULL OR char_length(description) <= 5000),
    CONSTRAINT carbons_profile_photo_uri_length
        CHECK (profile_photo_uri IS NULL OR char_length(profile_photo_uri) <= 2048),
    CONSTRAINT carbons_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.carbons IS
    'Human IAM accounts. Contact identities are isolated in encrypted contact tables.';
COMMENT ON COLUMN iam.carbons.carbon_id IS
    'Immutable case-normalized public handle; retained permanently and never reused.';

CREATE FUNCTION iam_private.prevent_carbon_handle_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.carbon_id <> OLD.carbon_id THEN
        RAISE EXCEPTION 'Carbon internal id and carbon_id are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER carbons_immutable_handle
BEFORE UPDATE ON iam.carbons
FOR EACH ROW EXECUTE FUNCTION iam_private.prevent_carbon_handle_change();

CREATE TRIGGER carbons_bump_version
BEFORE UPDATE ON iam.carbons
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE INDEX carbons_carbon_id_trgm_idx
    ON iam.carbons USING gin (carbon_id public.gin_trgm_ops);
CREATE INDEX carbons_created_at_idx ON iam.carbons (created_at, id);

CREATE TABLE iam.carbon_contacts (
    id uuid PRIMARY KEY,
    carbon_id uuid NOT NULL,
    kind iam.contact_kind NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    encryption_key_version smallint NOT NULL,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    is_primary boolean NOT NULL DEFAULT true,
    status text NOT NULL DEFAULT 'active',
    verified_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    retired_at timestamptz,
    UNIQUE (id, kind),
    UNIQUE (carbon_id, id),
    CONSTRAINT carbon_contacts_carbon_fk
        FOREIGN KEY (carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT carbon_contacts_encryption_key_fk
        FOREIGN KEY (encryption_purpose, encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT carbon_contacts_ciphertext_length
        CHECK (octet_length(ciphertext) BETWEEN 17 AND 8192),
    CONSTRAINT carbon_contacts_nonce_length CHECK (octet_length(nonce) BETWEEN 12 AND 32),
    CONSTRAINT carbon_contacts_status CHECK (status IN ('active', 'retired')),
    CONSTRAINT carbon_contacts_retirement_consistency
        CHECK ((status = 'retired') = (retired_at IS NOT NULL))
);

COMMENT ON TABLE iam.carbon_contacts IS
    'AEAD-encrypted verified email addresses and E.164 phone numbers.';
COMMENT ON COLUMN iam.carbon_contacts.ciphertext IS
    'Authenticated ciphertext only. Decryption keys are supplied by the runtime secret provider.';

CREATE UNIQUE INDEX carbon_contacts_one_active_primary_per_kind_idx
    ON iam.carbon_contacts (carbon_id, kind)
    WHERE status = 'active' AND is_primary;
CREATE INDEX carbon_contacts_carbon_status_idx
    ON iam.carbon_contacts (carbon_id, status, kind);

CREATE TABLE iam.contact_blind_indexes (
    contact_id uuid NOT NULL,
    contact_kind iam.contact_kind NOT NULL,
    hmac_key_version smallint NOT NULL,
    hmac_purpose text
        GENERATED ALWAYS AS ('contact_lookup_hmac'::text) STORED,
    digest bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (contact_id, hmac_key_version),
    CONSTRAINT contact_blind_indexes_contact_fk
        FOREIGN KEY (contact_id, contact_kind)
        REFERENCES iam.carbon_contacts (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT contact_blind_indexes_hmac_key_fk
        FOREIGN KEY (hmac_purpose, hmac_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT contact_blind_indexes_digest_length CHECK (octet_length(digest) = 32),
    UNIQUE (contact_kind, hmac_key_version, digest)
);

COMMENT ON TABLE iam.contact_blind_indexes IS
    'Versioned HMAC blind indexes used for exact contact lookup and uniqueness without plaintext PII.';

CREATE VIEW iam.carbon_public_profiles
WITH (security_barrier = true)
AS
SELECT id, carbon_id, display_name, profile_photo_uri, version
FROM iam.carbons
WHERE deleted_at IS NULL;

COMMENT ON VIEW iam.carbon_public_profiles IS
    'Contact-free global Carbon directory projection for authenticated fuzzy search.';

CREATE TABLE iam.service_principals (
    id uuid PRIMARY KEY,
    principal_kind iam.principal_kind
        GENERATED ALWAYS AS ('service'::iam.principal_kind) STORED,
    service_id text NOT NULL,
    display_name text NOT NULL,
    description text,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    deleted_at timestamptz,
    UNIQUE (service_id),
    UNIQUE (id, principal_kind),
    CONSTRAINT service_principals_principal_fk
        FOREIGN KEY (id, principal_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT service_principals_service_id_format
        CHECK (service_id ~ '^[a-z][a-z0-9_-]{2,62}$'),
    CONSTRAINT service_principals_display_name_length
        CHECK (char_length(display_name) BETWEEN 1 AND 200),
    CONSTRAINT service_principals_description_length
        CHECK (description IS NULL OR char_length(description) <= 2000),
    CONSTRAINT service_principals_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.service_principals IS
    'Explicit internal platform-service principals; services never become organization members.';

CREATE FUNCTION iam_private.prevent_service_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.service_id <> OLD.service_id THEN
        RAISE EXCEPTION 'service principal identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER service_principals_immutable_identity
BEFORE UPDATE ON iam.service_principals
FOR EACH ROW EXECUTE FUNCTION iam_private.prevent_service_identity_change();

CREATE TRIGGER service_principals_bump_version
BEFORE UPDATE ON iam.service_principals
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();
