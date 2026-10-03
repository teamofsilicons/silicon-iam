-- Carbon signup requires a verified email and permits an absent phone.
-- A supplied phone still has to be verified, or explicitly skipped, before completion.
-- Preserve the function signatures and owners used by both runtime planes.
CREATE OR REPLACE FUNCTION iam_private.assert_active_carbon_contacts(p_carbon_id text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM iam.principals WHERE id = p_carbon_id AND kind = 'carbon' AND status = 'active')
       AND NOT EXISTS (
           SELECT 1 FROM iam.carbon_contacts
           WHERE carbon_id = p_carbon_id AND kind = 'email' AND status = 'active'
             AND is_primary AND verified_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'active Carbon % must have a verified primary email', p_carbon_id
            USING ERRCODE = '23514';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.assert_active_carbon_contacts(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.complete_verified_signup(
    p_signup_session_id uuid,
    p_principal_id text,
    p_carbon_handle text,
    p_display_name text,
    p_description text,
    p_profile_photo_uri text,
    p_timezone_id text,
    p_email_contact_id uuid,
    p_phone_contact_id uuid
)
RETURNS TABLE (
    principal_id text,
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
    expected_contact_count integer := CASE WHEN p_phone_contact_id IS NULL THEN 1 ELSE 2 END;
BEGIN
    IF p_principal_id IS NULL OR p_email_contact_id IS NULL
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

    IF current_candidate_count <> expected_contact_count
       OR indexed_candidate_kind_count <> expected_contact_count
       OR NOT EXISTS (
           SELECT 1 FROM iam.signup_contact_candidates
           WHERE signup_session_id = p_signup_session_id AND kind = 'email'
             AND verified_at IS NOT NULL AND superseded_at IS NULL
       )
       OR EXISTS (
           SELECT 1 FROM iam.signup_contact_candidates
           WHERE signup_session_id = p_signup_session_id
             AND superseded_at IS NULL AND verified_at IS NULL
       ) THEN
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

    IF indexed_candidate_kind_count <> expected_contact_count THEN
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
        profile_photo_uri,
        timezone_id
    )
    VALUES (
        p_principal_id,
        p_carbon_handle,
        p_display_name,
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
