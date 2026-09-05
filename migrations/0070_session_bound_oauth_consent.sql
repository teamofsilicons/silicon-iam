-- A consent's parent login is part of its authority. Reusing one row across
-- devices invalidates older refresh families when the parent is overwritten.
-- Keep existing rows and credentials as they are; this migration does not
-- revive any previously invalidated or revoked authority.
DO $migration$
DECLARE
    old_constraint text;
BEGIN
    SELECT constraint_row.conname INTO STRICT old_constraint
    FROM pg_catalog.pg_constraint AS constraint_row
    WHERE constraint_row.conrelid = 'iam.oauth_consent_grants'::regclass
      AND constraint_row.contype = 'u'
      AND (
          SELECT array_agg(attribute.attname::text ORDER BY key.ordinality)
          FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key(attnum, ordinality)
          JOIN pg_catalog.pg_attribute AS attribute
            ON attribute.attrelid = constraint_row.conrelid
           AND attribute.attnum = key.attnum
      ) = ARRAY['application_id', 'subject_principal_id', 'organization_id'];

    EXECUTE format('ALTER TABLE iam.oauth_consent_grants DROP CONSTRAINT %I', old_constraint);
END;
$migration$;

ALTER TABLE iam.oauth_consent_grants
    ADD CONSTRAINT oauth_consent_grants_application_subject_org_session_key
    UNIQUE NULLS NOT DISTINCT (
        application_id, subject_principal_id, organization_id,
        parent_authentication_session_id
    );

CREATE FUNCTION iam_private.preserve_oauth_consent_parent()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF NEW.parent_authentication_session_id IS DISTINCT FROM OLD.parent_authentication_session_id THEN
        RAISE EXCEPTION 'OAuth consent parent session is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.preserve_oauth_consent_parent() FROM PUBLIC;

CREATE TRIGGER oauth_consent_grants_preserve_parent
BEFORE UPDATE OF parent_authentication_session_id ON iam.oauth_consent_grants
FOR EACH ROW EXECUTE FUNCTION iam_private.preserve_oauth_consent_parent();
