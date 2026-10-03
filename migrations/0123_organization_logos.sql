-- Organization logos uploaded to and served by IAM itself.
--
-- An upload stores the image bytes here and points organizations.logo_uri at
-- the public IAM URL for that exact upload. Every upload gets a fresh random
-- id, so a published URL always names immutable bytes and can be cached
-- forever. Only the organization's current upload is kept: replacing or
-- clearing logo_uri deletes the stored image it no longer references.
CREATE TABLE iam.organization_logos (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES iam.organizations (id) ON DELETE CASCADE,
    content_type text NOT NULL,
    content bytea NOT NULL,
    content_sha256 bytea NOT NULL,
    uploaded_by_principal_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT organization_logos_content_type
        CHECK (content_type IN ('image/png', 'image/jpeg', 'image/webp', 'image/gif')),
    CONSTRAINT organization_logos_content_size
        CHECK (octet_length(content) BETWEEN 1 AND 524288),
    CONSTRAINT organization_logos_content_sha256
        CHECK (octet_length(content_sha256) = 32)
);
CREATE INDEX organization_logos_organization ON iam.organization_logos (organization_id);
ALTER TABLE iam.organization_logos ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON iam.organization_logos FROM PUBLIC;

COMMENT ON TABLE iam.organization_logos IS
    'Uploaded organization logo bytes. Reached only through the fixed-path iam_private logo functions.';

-- Stores an upload for the selected organization. The caller then points
-- logo_uri at it through the ordinary RLS-checked organization UPDATE, whose
-- trigger below removes the previous upload.
CREATE FUNCTION iam_private.store_organization_logo(
    p_organization_id uuid,
    p_logo_id uuid,
    p_content_type text,
    p_content bytea,
    p_content_sha256 bytea
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF p_organization_id IS NULL
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id()
       OR NOT iam_private.has_organization_capability(
           p_organization_id, iam_private.current_principal_id(), 'organization.update'
       ) THEN
        RAISE EXCEPTION 'organization_logo_forbidden' USING ERRCODE = '42501';
    END IF;
    INSERT INTO iam.organization_logos (
        id, organization_id, content_type, content, content_sha256, uploaded_by_principal_id
    ) VALUES (
        p_logo_id, p_organization_id, p_content_type, p_content, p_content_sha256,
        iam_private.current_principal_id()
    );
END;
$$;
REVOKE ALL ON FUNCTION iam_private.store_organization_logo(uuid, uuid, text, bytea, bytea) FROM PUBLIC;

-- Public read by unguessable upload id. Logos of organizations that are no
-- longer active are not served.
CREATE FUNCTION iam_private.read_organization_logo(p_logo_id uuid)
RETURNS TABLE (content_type text, content bytea, content_sha256 bytea)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT logo.content_type, logo.content, logo.content_sha256
    FROM iam.organization_logos AS logo
    JOIN iam.organizations AS organization ON organization.id = logo.organization_id
    WHERE logo.id = p_logo_id
      AND organization.status = 'active';
$$;
REVOKE ALL ON FUNCTION iam_private.read_organization_logo(uuid) FROM PUBLIC;

-- Keeps only the upload that logo_uri still names, whichever route changed it.
CREATE FUNCTION iam_private.prune_organization_logos()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    DELETE FROM iam.organization_logos AS logo
    WHERE logo.organization_id = NEW.id
      AND (
          NEW.logo_uri IS NULL
          OR pg_catalog.strpos(NEW.logo_uri, '/organization-logos/' || logo.id::text) = 0
      );
    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.prune_organization_logos() FROM PUBLIC;

CREATE TRIGGER organizations_prune_logos
AFTER UPDATE OF logo_uri ON iam.organizations
FOR EACH ROW
WHEN (NEW.logo_uri IS DISTINCT FROM OLD.logo_uri)
EXECUTE FUNCTION iam_private.prune_organization_logos();

DO $$ BEGIN
    IF to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION
            iam_private.store_organization_logo(uuid, uuid, text, bytea, bytea),
            iam_private.read_organization_logo(uuid)
            TO silicon_iam_api;
    END IF;
END $$;
