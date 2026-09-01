-- IANA time zones and mutable Silicon profile data.

ALTER TABLE iam.carbons
    ADD COLUMN timezone_id text NOT NULL DEFAULT 'UTC',
    ADD CONSTRAINT carbons_timezone_id_shape CHECK (
        char_length(timezone_id) BETWEEN 1 AND 255
        AND timezone_id ~ '^[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*$'
    );

ALTER TABLE iam.silicons
    ADD COLUMN display_name text,
    ADD COLUMN description text,
    ADD COLUMN timezone_id text NOT NULL DEFAULT 'UTC';

-- The immutable local handle is the least surprising safe display fallback for
-- profiles created before display names were part of the contract. This
-- intentional profile mutation also advances the Silicon aggregate version.
UPDATE iam.silicons
SET display_name = local_silicon_id,
    updated_at = transaction_timestamp()
WHERE display_name IS NULL;

ALTER TABLE iam.silicons
    ALTER COLUMN display_name SET NOT NULL,
    ADD CONSTRAINT silicons_display_name_length
        CHECK (char_length(display_name) BETWEEN 1 AND 200),
    ADD CONSTRAINT silicons_description_length
        CHECK (description IS NULL OR char_length(description) <= 5000),
    ADD CONSTRAINT silicons_timezone_id_shape CHECK (
        char_length(timezone_id) BETWEEN 1 AND 255
        AND timezone_id ~ '^[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*$'
    );

COMMENT ON COLUMN iam.carbons.timezone_id IS
    'Exact IANA TZDB identifier validated by both the API and database catalog.';
COMMENT ON COLUMN iam.silicons.display_name IS
    'Mutable presentation name; the local and global Silicon handles remain immutable.';
COMMENT ON COLUMN iam.silicons.description IS
    'Optional mutable Silicon profile description, never an authorization input.';
COMMENT ON COLUMN iam.silicons.timezone_id IS
    'Exact IANA TZDB identifier validated by both the API and database catalog.';

CREATE FUNCTION iam_private.reject_unknown_profile_timezone()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, iam
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_timezone_names AS timezone
        WHERE timezone.name = NEW.timezone_id
    ) THEN
        RAISE EXCEPTION 'unknown IANA time-zone identifier'
            USING ERRCODE = '22023';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER carbons_validate_timezone
BEFORE INSERT OR UPDATE OF timezone_id ON iam.carbons
FOR EACH ROW EXECUTE FUNCTION iam_private.reject_unknown_profile_timezone();

CREATE TRIGGER silicons_validate_timezone
BEFORE INSERT OR UPDATE OF timezone_id ON iam.silicons
FOR EACH ROW EXECUTE FUNCTION iam_private.reject_unknown_profile_timezone();

REVOKE ALL ON FUNCTION iam_private.reject_unknown_profile_timezone() FROM PUBLIC;

-- Forward-replace the signup entry point so new accounts cannot omit their
-- validated timezone. The prior migration remains immutable.
DROP FUNCTION iam_private.complete_verified_signup(
    uuid, uuid, text, text, text, text, uuid, uuid
);

CREATE FUNCTION iam_private.complete_verified_signup(
    p_signup_session_id uuid,
    p_principal_id uuid,
    p_carbon_handle text,
    p_display_name text,
    p_description text,
    p_profile_photo_uri text,
    p_timezone_id text,
    p_email_contact_id uuid,
    p_phone_contact_id uuid
)
RETURNS TABLE (
    principal_id uuid,
    carbon_handle text,
    aggregate_version bigint,
    created_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    current_candidate_count integer;
    indexed_candidate_kind_count integer;
BEGIN
    IF p_principal_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_email_contact_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_phone_contact_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_email_contact_id = p_phone_contact_id THEN
        RAISE EXCEPTION 'signup cannot be completed' USING ERRCODE = '22023';
    END IF;

    PERFORM 1
    FROM iam.signup_sessions AS signup_session
    WHERE signup_session.id = p_signup_session_id
      AND signup_session.status = 'pending'
      AND signup_session.expires_at > statement_timestamp()
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'signup cannot be completed' USING ERRCODE = '23514';
    END IF;

    SELECT count(*), count(DISTINCT candidate.kind)
    INTO current_candidate_count, indexed_candidate_kind_count
    FROM iam.signup_contact_candidates AS candidate
    WHERE candidate.signup_session_id = p_signup_session_id
      AND candidate.verified_at IS NOT NULL
      AND candidate.superseded_at IS NULL;

    IF current_candidate_count <> 2 OR indexed_candidate_kind_count <> 2 THEN
        RAISE EXCEPTION 'signup cannot be completed' USING ERRCODE = '23514';
    END IF;

    SELECT count(DISTINCT candidate.kind)
    INTO indexed_candidate_kind_count
    FROM iam.signup_contact_candidates AS candidate
    JOIN iam.signup_candidate_blind_indexes AS candidate_index
      ON candidate_index.candidate_id = candidate.id
     AND candidate_index.contact_kind = candidate.kind
    WHERE candidate.signup_session_id = p_signup_session_id
      AND candidate.verified_at IS NOT NULL
      AND candidate.superseded_at IS NULL;

    IF indexed_candidate_kind_count <> 2 THEN
        RAISE EXCEPTION 'signup cannot be completed' USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM iam.signup_contact_candidates AS candidate
        JOIN iam.signup_candidate_blind_indexes AS candidate_index
          ON candidate_index.candidate_id = candidate.id
         AND candidate_index.contact_kind = candidate.kind
        JOIN iam.contact_blind_indexes AS existing_index
          ON existing_index.contact_kind = candidate_index.contact_kind
         AND existing_index.hmac_key_version = candidate_index.hmac_key_version
         AND existing_index.digest = candidate_index.digest
        JOIN iam.carbon_contacts AS existing_contact
          ON existing_contact.id = existing_index.contact_id
         AND existing_contact.kind = existing_index.contact_kind
        WHERE candidate.signup_session_id = p_signup_session_id
          AND candidate.verified_at IS NOT NULL
          AND candidate.superseded_at IS NULL
          AND existing_contact.status = 'active'
    ) THEN
        RAISE EXCEPTION 'signup cannot be completed' USING ERRCODE = '23505';
    END IF;

    INSERT INTO iam.principals (id, kind, status)
    VALUES (p_principal_id, 'carbon', 'provisioning');

    INSERT INTO iam.carbons (
        id,
        carbon_id,
        display_name,
        description,
        profile_photo_uri,
        timezone_id
    )
    VALUES (
        p_principal_id,
        p_carbon_handle,
        p_display_name,
        p_description,
        p_profile_photo_uri,
        p_timezone_id
    );

    INSERT INTO iam.carbon_contacts (
        id,
        carbon_id,
        kind,
        ciphertext,
        nonce,
        encryption_key_version,
        verified_at
    )
    SELECT
        CASE candidate.kind
            WHEN 'email' THEN p_email_contact_id
            WHEN 'phone' THEN p_phone_contact_id
        END,
        p_principal_id,
        candidate.kind,
        candidate.ciphertext,
        candidate.nonce,
        candidate.encryption_key_version,
        candidate.verified_at
    FROM iam.signup_contact_candidates AS candidate
    WHERE candidate.signup_session_id = p_signup_session_id
      AND candidate.verified_at IS NOT NULL
      AND candidate.superseded_at IS NULL;

    INSERT INTO iam.contact_blind_indexes (
        contact_id,
        contact_kind,
        hmac_key_version,
        digest
    )
    SELECT
        CASE candidate.kind
            WHEN 'email' THEN p_email_contact_id
            WHEN 'phone' THEN p_phone_contact_id
        END,
        candidate.kind,
        candidate_index.hmac_key_version,
        candidate_index.digest
    FROM iam.signup_contact_candidates AS candidate
    JOIN iam.signup_candidate_blind_indexes AS candidate_index
      ON candidate_index.candidate_id = candidate.id
     AND candidate_index.contact_kind = candidate.kind
    WHERE candidate.signup_session_id = p_signup_session_id
      AND candidate.verified_at IS NOT NULL
      AND candidate.superseded_at IS NULL;

    UPDATE iam.principals
    SET status = 'active', activated_at = transaction_timestamp()
    WHERE id = p_principal_id;

    UPDATE iam.signup_sessions
    SET status = 'completed',
        completed_carbon_id = p_principal_id,
        completed_at = transaction_timestamp()
    WHERE id = p_signup_session_id;

    RETURN QUERY
    SELECT carbon.id, carbon.carbon_id, carbon.version, carbon.created_at
    FROM iam.carbons AS carbon
    WHERE carbon.id = p_principal_id;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.complete_verified_signup(
    uuid, uuid, text, text, text, text, text, uuid, uuid
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.complete_verified_signup(
    uuid, uuid, text, text, text, text, text, uuid, uuid
) IS
    'Atomically consumes verified signup state and creates one Carbon with an exact IANA TZDB profile identifier.';
