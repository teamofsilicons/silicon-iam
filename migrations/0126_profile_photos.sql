-- Self-service profile photo storage; mutations participate in profile concurrency and audit.
CREATE TABLE iam.profile_photos (
    id uuid PRIMARY KEY,
    principal_id text NOT NULL,
    content_type text NOT NULL,
    content bytea NOT NULL,
    content_sha256 bytea NOT NULL,
    uploaded_by_principal_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT profile_photos_content_type
        CHECK (content_type IN ('image/png', 'image/jpeg', 'image/webp')),
    CONSTRAINT profile_photos_content_size
        CHECK (octet_length(content) BETWEEN 1 AND 524288),
    CONSTRAINT profile_photos_content_sha256
        CHECK (octet_length(content_sha256) = 32)
);
CREATE INDEX profile_photos_principal ON iam.profile_photos (principal_id);
ALTER TABLE iam.profile_photos ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON iam.profile_photos FROM PUBLIC;

COMMENT ON TABLE iam.profile_photos IS
    'Uploaded profile photos. Accessed only through fixed-path, actor-checked functions.';

CREATE FUNCTION iam_private.store_profile_photo(
    p_photo_id uuid,
    p_content_type text,
    p_content bytea,
    p_content_sha256 bytea
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM iam.principals WHERE id = iam_private.current_principal_id()
                   AND kind IN ('carbon','silicon') AND status = 'active') THEN
        RAISE EXCEPTION 'profile_photo_forbidden' USING ERRCODE = '42501';
    END IF;
    INSERT INTO iam.profile_photos (
        id, principal_id, content_type, content, content_sha256, uploaded_by_principal_id
    ) VALUES (
        p_photo_id, iam_private.current_principal_id(), p_content_type, p_content, p_content_sha256,
        iam_private.current_principal_id()
    );
END;
$$;
REVOKE ALL ON FUNCTION iam_private.store_profile_photo(uuid, text, bytea, bytea) FROM PUBLIC;

CREATE FUNCTION iam_private.read_profile_photo(p_photo_id uuid)
RETURNS TABLE (content_type text, content bytea, content_sha256 bytea)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT logo.content_type, logo.content, logo.content_sha256
    FROM iam.profile_photos AS logo
    JOIN iam.principals AS principal ON principal.id = logo.principal_id
    WHERE logo.id = p_photo_id
      AND principal.status = 'active';
$$;
REVOKE ALL ON FUNCTION iam_private.read_profile_photo(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.prune_profile_photos()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    DELETE FROM iam.profile_photos AS logo
    WHERE logo.principal_id = NEW.id
      AND (
          NEW.profile_photo_uri IS NULL
          OR pg_catalog.strpos(NEW.profile_photo_uri, '/profile-photos/' || logo.id::text) = 0
      );
    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.prune_profile_photos() FROM PUBLIC;

CREATE TRIGGER carbons_prune_photos
AFTER UPDATE OF profile_photo_uri ON iam.carbons
FOR EACH ROW
WHEN (NEW.profile_photo_uri IS DISTINCT FROM OLD.profile_photo_uri)
EXECUTE FUNCTION iam_private.prune_profile_photos();

DO $$ BEGIN
    IF to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION
            iam_private.store_profile_photo(uuid, text, bytea, bytea),
            iam_private.read_profile_photo(uuid)
            TO silicon_iam_api;
    END IF;
END $$;
