-- Independent app logins can share the same parent IAM session and consent.
-- Access-token revocation must follow the issuing refresh family, not that parent.
ALTER TABLE iam.refresh_token_families
    ADD CONSTRAINT refresh_token_families_access_identity_key
    UNIQUE (id, authentication_session_id, subject_principal_id, client_application_id);

ALTER TABLE iam.access_tokens
    ADD COLUMN oauth_refresh_family_id uuid,
    ADD CONSTRAINT access_tokens_oauth_refresh_family_class CHECK (
        oauth_refresh_family_id IS NULL OR token_class = 'application_access'
    ),
    ADD CONSTRAINT access_tokens_oauth_refresh_family_fk
    FOREIGN KEY (oauth_refresh_family_id, authentication_session_id,
                 subject_principal_id, client_application_id)
    REFERENCES iam.refresh_token_families
        (id, authentication_session_id, subject_principal_id, client_application_id)
    ON DELETE SET NULL (oauth_refresh_family_id);

CREATE INDEX access_tokens_oauth_refresh_family_idx
    ON iam.access_tokens (oauth_refresh_family_id)
    WHERE oauth_refresh_family_id IS NOT NULL;

-- Historical issuance inserts each access/refresh pair in the same transaction;
-- both created_at defaults are transaction_timestamp(). Backfill only an exact,
-- unique family match. Expired or already revoked access tokens need no link.
WITH candidates AS (
    SELECT access.id AS access_id, (array_agg(DISTINCT refresh.family_id))[1] AS family_id
    FROM iam.access_tokens access
    JOIN iam.refresh_token_families family
      ON family.authentication_session_id = access.authentication_session_id
     AND family.subject_principal_id = access.subject_principal_id
     AND family.client_application_id = access.client_application_id
    JOIN iam.refresh_tokens refresh
      ON refresh.family_id = family.id AND refresh.created_at = access.created_at
    WHERE access.token_class = 'application_access'
      AND access.revoked_at IS NULL AND access.expires_at > transaction_timestamp()
    GROUP BY access.id
    HAVING count(DISTINCT refresh.family_id) = 1
)
UPDATE iam.access_tokens access
SET oauth_refresh_family_id = candidates.family_id
FROM candidates WHERE access.id = candidates.access_id;

DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM iam.access_tokens
        WHERE token_class = 'application_access' AND revoked_at IS NULL
          AND expires_at > transaction_timestamp() AND oauth_refresh_family_id IS NULL
    ) THEN
        RAISE EXCEPTION 'active OAuth access tokens lack an unambiguous refresh family; inspect before retrying migration'
            USING ERRCODE = '23514';
    END IF;
END $$;
