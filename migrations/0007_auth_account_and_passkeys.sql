-- Carbon self-service lifecycle, contact replacement, and WebAuthn ceremony persistence.

ALTER TABLE iam.principals
    DROP CONSTRAINT principals_status,
    ADD CONSTRAINT principals_status
        CHECK (status IN ('provisioning', 'active', 'suspended', 'deletion_pending', 'deleted'));

ALTER TABLE iam.carbon_contacts
    ALTER COLUMN ciphertext DROP NOT NULL,
    ALTER COLUMN nonce DROP NOT NULL,
    ALTER COLUMN encryption_key_version DROP NOT NULL,
    ADD COLUMN purged_at timestamptz,
    ADD CONSTRAINT carbon_contacts_protected_value_lifecycle CHECK (
        (
            ciphertext IS NOT NULL
            AND nonce IS NOT NULL
            AND encryption_key_version IS NOT NULL
            AND purged_at IS NULL
        )
        OR (
            ciphertext IS NULL
            AND nonce IS NULL
            AND encryption_key_version IS NULL
            AND purged_at IS NOT NULL
            AND status = 'retired'
            AND NOT is_primary
        )
    );

COMMENT ON COLUMN iam.carbon_contacts.purged_at IS
    'Terminal cryptographic erasure marker; purged contacts retain only referential history.';

CREATE TABLE iam.account_deletion_requests (
    id uuid PRIMARY KEY,
    carbon_id uuid NOT NULL UNIQUE,
    requested_from_session_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    requested_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    scheduled_for timestamptz NOT NULL,
    completed_at timestamptz,
    cancelled_at timestamptz,
    CONSTRAINT account_deletion_requests_carbon_fk
        FOREIGN KEY (carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT account_deletion_requests_session_fk
        FOREIGN KEY (requested_from_session_id, carbon_id)
        REFERENCES iam.authentication_sessions (id, subject_principal_id)
        ON DELETE RESTRICT,
    CONSTRAINT account_deletion_requests_status
        CHECK (status IN ('pending', 'completed', 'cancelled')),
    CONSTRAINT account_deletion_requests_schedule
        CHECK (scheduled_for > requested_at),
    CONSTRAINT account_deletion_requests_terminal_consistency CHECK (
        (status = 'completed') = (completed_at IS NOT NULL)
        AND (status = 'cancelled') = (cancelled_at IS NOT NULL)
    )
);

COMMENT ON TABLE iam.account_deletion_requests IS
    'Grace-period account-deletion workflow; authority is disabled immediately and a bounded worker performs the terminal soft deletion when due.';

CREATE TABLE iam.contact_change_sessions (
    id uuid PRIMARY KEY,
    carbon_id uuid NOT NULL,
    authentication_session_id uuid NOT NULL,
    kind iam.contact_kind NOT NULL,
    candidate_contact_id uuid NOT NULL UNIQUE,
    previous_contact_id uuid,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    encryption_key_version smallint NOT NULL,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    code_digest bytea NOT NULL,
    digest_key_version smallint NOT NULL,
    digest_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    status text NOT NULL DEFAULT 'pending',
    failed_attempts smallint NOT NULL DEFAULT 0,
    max_attempts smallint NOT NULL DEFAULT 5,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    verified_at timestamptz,
    superseded_at timestamptz,
    UNIQUE (id, carbon_id, kind),
    CONSTRAINT contact_change_sessions_carbon_fk
        FOREIGN KEY (carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT contact_change_sessions_previous_contact_fk
        FOREIGN KEY (carbon_id, previous_contact_id)
        REFERENCES iam.carbon_contacts (carbon_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT contact_change_sessions_session_fk
        FOREIGN KEY (authentication_session_id, carbon_id)
        REFERENCES iam.authentication_sessions (id, subject_principal_id)
        ON DELETE RESTRICT,
    CONSTRAINT contact_change_sessions_encryption_key_fk
        FOREIGN KEY (encryption_purpose, encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT contact_change_sessions_digest_key_fk
        FOREIGN KEY (digest_purpose, digest_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT contact_change_sessions_ciphertext_length
        CHECK (octet_length(ciphertext) BETWEEN 17 AND 8192),
    CONSTRAINT contact_change_sessions_nonce_length CHECK (octet_length(nonce) = 12),
    CONSTRAINT contact_change_sessions_digest_length CHECK (octet_length(code_digest) = 32),
    CONSTRAINT contact_change_sessions_status
        CHECK (status IN ('pending', 'verified', 'cancelled')),
    CONSTRAINT contact_change_sessions_attempts CHECK (
        max_attempts BETWEEN 1 AND 5
        AND failed_attempts BETWEEN 0 AND max_attempts
    ),
    CONSTRAINT contact_change_sessions_expiry CHECK (expires_at > created_at),
    CONSTRAINT contact_change_sessions_terminal_consistency CHECK (
        (status = 'verified') = (verified_at IS NOT NULL)
        AND (status = 'verified') = (previous_contact_id IS NOT NULL)
        AND (status = 'cancelled') = (superseded_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX contact_change_sessions_one_pending_kind_idx
    ON iam.contact_change_sessions (carbon_id, kind)
    WHERE status = 'pending' AND superseded_at IS NULL;
CREATE INDEX contact_change_sessions_expiry_idx
    ON iam.contact_change_sessions (expires_at)
    WHERE status = 'pending';

CREATE TABLE iam.contact_change_blind_indexes (
    contact_change_session_id uuid NOT NULL,
    carbon_id uuid NOT NULL,
    contact_kind iam.contact_kind NOT NULL,
    hmac_key_version smallint NOT NULL,
    hmac_purpose text
        GENERATED ALWAYS AS ('contact_lookup_hmac'::text) STORED,
    digest bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (contact_change_session_id, hmac_key_version),
    CONSTRAINT contact_change_blind_indexes_session_fk
        FOREIGN KEY (contact_change_session_id, carbon_id, contact_kind)
        REFERENCES iam.contact_change_sessions (id, carbon_id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT contact_change_blind_indexes_key_fk
        FOREIGN KEY (hmac_purpose, hmac_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT contact_change_blind_indexes_digest_length CHECK (octet_length(digest) = 32)
);

ALTER TABLE iam.webauthn_credentials
    RENAME COLUMN public_key TO credential_state;
ALTER TABLE iam.webauthn_credentials
    RENAME CONSTRAINT webauthn_credentials_public_key_length
    TO webauthn_credentials_state_length;
ALTER TABLE iam.webauthn_credentials
    DROP CONSTRAINT webauthn_credentials_state_length,
    ADD CONSTRAINT webauthn_credentials_state_length
        CHECK (octet_length(credential_state) BETWEEN 32 AND 16384),
    ADD COLUMN name text NOT NULL DEFAULT 'Passkey',
    ADD COLUMN version bigint NOT NULL DEFAULT 1,
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    ADD CONSTRAINT webauthn_credentials_name_length
        CHECK (char_length(name) BETWEEN 1 AND 200),
    ADD CONSTRAINT webauthn_credentials_positive_version CHECK (version > 0);
ALTER TABLE iam.webauthn_credentials ALTER COLUMN name DROP DEFAULT;

CREATE TRIGGER webauthn_credentials_bump_version
BEFORE UPDATE ON iam.webauthn_credentials
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE TABLE iam.webauthn_ceremonies (
    id uuid PRIMARY KEY,
    carbon_id uuid NOT NULL,
    authentication_session_id uuid NOT NULL,
    ceremony_kind text NOT NULL,
    action text,
    resource_id uuid,
    rp_id text NOT NULL,
    origin text NOT NULL,
    state_ciphertext bytea NOT NULL,
    state_nonce bytea NOT NULL,
    state_encryption_key_version smallint NOT NULL,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    UNIQUE (id, authentication_session_id, carbon_id),
    CONSTRAINT webauthn_ceremonies_carbon_fk
        FOREIGN KEY (carbon_id) REFERENCES iam.carbons (id) ON DELETE RESTRICT,
    CONSTRAINT webauthn_ceremonies_session_fk
        FOREIGN KEY (authentication_session_id, carbon_id)
        REFERENCES iam.authentication_sessions (id, subject_principal_id)
        ON DELETE RESTRICT,
    CONSTRAINT webauthn_ceremonies_encryption_key_fk
        FOREIGN KEY (encryption_purpose, state_encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT webauthn_ceremonies_kind
        CHECK (ceremony_kind IN ('registration', 'step_up')),
    CONSTRAINT webauthn_ceremonies_action_binding CHECK (
        (ceremony_kind = 'registration' AND action IS NULL AND resource_id IS NULL)
        OR (ceremony_kind = 'step_up' AND action IS NOT NULL)
    ),
    CONSTRAINT webauthn_ceremonies_action_format
        CHECK (action IS NULL OR action ~ '^[a-z][a-z0-9_.:-]{2,127}$'),
    CONSTRAINT webauthn_ceremonies_rp_id_length CHECK (char_length(rp_id) BETWEEN 1 AND 253),
    CONSTRAINT webauthn_ceremonies_origin_length CHECK (char_length(origin) BETWEEN 1 AND 2048),
    CONSTRAINT webauthn_ceremonies_state_length
        CHECK (octet_length(state_ciphertext) BETWEEN 17 AND 65536),
    CONSTRAINT webauthn_ceremonies_nonce_length CHECK (octet_length(state_nonce) = 12),
    CONSTRAINT webauthn_ceremonies_status
        CHECK (status IN ('pending', 'completed', 'cancelled')),
    CONSTRAINT webauthn_ceremonies_expiry CHECK (expires_at > created_at),
    CONSTRAINT webauthn_ceremonies_completion_consistency
        CHECK ((status = 'completed') = (consumed_at IS NOT NULL))
);

CREATE INDEX webauthn_ceremonies_expiry_idx
    ON iam.webauthn_ceremonies (expires_at)
    WHERE status = 'pending';

ALTER TABLE iam.step_up_assertions
    ALTER COLUMN step_up_challenge_id DROP NOT NULL,
    ADD COLUMN webauthn_ceremony_id uuid UNIQUE,
    ADD CONSTRAINT step_up_assertions_webauthn_ceremony_fk
        FOREIGN KEY (webauthn_ceremony_id, authentication_session_id, carbon_id)
        REFERENCES iam.webauthn_ceremonies (id, authentication_session_id, carbon_id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT step_up_assertions_exactly_one_source
        CHECK (num_nonnulls(step_up_challenge_id, webauthn_ceremony_id) = 1);

ALTER TABLE iam.account_deletion_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.contact_change_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.contact_change_blind_indexes ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.webauthn_ceremonies ENABLE ROW LEVEL SECURITY;

CREATE POLICY account_deletion_requests_self_access
ON iam.account_deletion_requests
USING (carbon_id = iam_private.current_principal_id())
WITH CHECK (carbon_id = iam_private.current_principal_id());

CREATE POLICY contact_change_sessions_self_access
ON iam.contact_change_sessions
USING (carbon_id = iam_private.current_principal_id())
WITH CHECK (carbon_id = iam_private.current_principal_id());

CREATE POLICY contact_change_blind_indexes_self_access
ON iam.contact_change_blind_indexes
USING (carbon_id = iam_private.current_principal_id())
WITH CHECK (carbon_id = iam_private.current_principal_id());

CREATE POLICY webauthn_credentials_self_access
ON iam.webauthn_credentials
USING (carbon_id = iam_private.current_principal_id())
WITH CHECK (carbon_id = iam_private.current_principal_id());

CREATE POLICY webauthn_ceremonies_self_access
ON iam.webauthn_ceremonies
USING (carbon_id = iam_private.current_principal_id())
WITH CHECK (carbon_id = iam_private.current_principal_id());

COMMENT ON TABLE iam.contact_change_sessions IS
    'Encrypted replacement contact plus keyed OTP; plaintext and decryptable OTP values never persist.';
COMMENT ON TABLE iam.webauthn_credentials IS
    'Library-verified serialized passkeys. Public-key material is never accepted outside WebAuthn verification.';
COMMENT ON TABLE iam.webauthn_ceremonies IS
    'AEAD-protected server-side WebAuthn ceremony state bound to one Carbon, session, RP ID, origin, and action.';

CREATE FUNCTION iam_private.resolve_active_silicon_credential(
    p_global_silicon_id text,
    p_key_versions smallint[],
    p_digests bytea[]
)
RETURNS TABLE (
    principal_id uuid,
    credential_id uuid,
    secret_digest bytea,
    pepper_key_version smallint,
    organization_id uuid,
    membership_id uuid,
    membership_authz_epoch bigint,
    principal_auth_epoch bigint,
    global_silicon_id text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
BEGIN
    IF p_global_silicon_id IS NULL
       OR p_global_silicon_id !~ '^[a-z0-9_-]{3,50}:[a-z0-9_-]{3,50}$'
       OR cardinality(p_key_versions) = 0
       OR cardinality(p_key_versions) <> cardinality(p_digests)
       OR array_position(p_key_versions, NULL) IS NOT NULL
       OR array_position(p_digests, NULL) IS NOT NULL
       OR EXISTS (
           SELECT 1
           FROM unnest(p_digests) AS supplied(digest)
           WHERE octet_length(supplied.digest) <> 32
       )
       OR cardinality(ARRAY(
              SELECT DISTINCT supplied.key_version
              FROM unnest(p_key_versions) AS supplied(key_version)
          ))
          <> cardinality(p_key_versions) THEN
        RAISE EXCEPTION 'invalid Silicon credential lookup input' USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    WITH supplied_digest (key_version, digest) AS (
        SELECT * FROM unnest(p_key_versions, p_digests)
    )
    SELECT
        silicon.id,
        credential.id,
        credential.secret_digest,
        credential.pepper_key_version,
        silicon.organization_id,
        silicon.membership_id,
        membership.authz_epoch,
        principal.auth_epoch,
        silicon.global_silicon_id
    FROM supplied_digest
    JOIN iam.silicon_credentials AS credential
      ON credential.pepper_key_version = supplied_digest.key_version
     AND credential.secret_digest = supplied_digest.digest
     AND credential.status = 'active'
    JOIN iam.silicons AS silicon
      ON silicon.id = credential.silicon_id
     AND silicon.organization_id = credential.organization_id
     AND silicon.global_silicon_id = p_global_silicon_id
     AND silicon.provisioning_status = 'active'
     AND silicon.deleted_at IS NULL
    JOIN iam.principals AS principal
      ON principal.id = silicon.id
     AND principal.kind = 'silicon'
     AND principal.status = 'active'
    JOIN iam.organizations AS organization
      ON organization.id = silicon.organization_id
     AND organization.status = 'active'
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = silicon.organization_id
     AND membership.id = silicon.membership_id
     AND membership.principal_id = silicon.id
     AND membership.principal_kind = 'silicon'
     AND membership.status = 'active'
    LIMIT 1
    FOR UPDATE OF credential, silicon, principal, organization, membership;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.resolve_active_silicon_credential(
    text, smallint[], bytea[]
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.resolve_active_silicon_credential(
    text, smallint[], bytea[]
) IS
    'Exact pre-auth Silicon credential resolver that reveals no row until SID, keyed digest, principal, tenant, and membership are all active.';

CREATE FUNCTION iam_private.run_worker_account_deletion_finalization(
    p_batch_size integer,
    p_request_ids uuid[],
    p_audit_event_ids uuid[],
    p_outbox_event_ids uuid[]
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    deletion_record record;
    item_index integer := 0;
    aggregate_version bigint;
BEGIN
    IF p_batch_size IS NULL OR p_batch_size NOT BETWEEN 1 AND 1000
       OR p_request_ids IS NULL
       OR p_audit_event_ids IS NULL
       OR p_outbox_event_ids IS NULL
       OR cardinality(p_request_ids) <> p_batch_size
       OR cardinality(p_audit_event_ids) <> p_batch_size
       OR cardinality(p_outbox_event_ids) <> p_batch_size
       OR array_position(p_request_ids, NULL) IS NOT NULL
       OR array_position(p_audit_event_ids, NULL) IS NOT NULL
       OR array_position(p_outbox_event_ids, NULL) IS NOT NULL
       OR cardinality(ARRAY(SELECT DISTINCT id FROM unnest(p_request_ids) AS supplied(id)))
          <> cardinality(p_request_ids)
       OR cardinality(ARRAY(SELECT DISTINCT id FROM unnest(p_audit_event_ids) AS supplied(id)))
          <> cardinality(p_audit_event_ids)
       OR cardinality(ARRAY(SELECT DISTINCT id FROM unnest(p_outbox_event_ids) AS supplied(id)))
          <> cardinality(p_outbox_event_ids)
       OR EXISTS (
           SELECT 1
           FROM unnest(p_request_ids || p_audit_event_ids || p_outbox_event_ids) AS supplied(id)
           WHERE supplied.id = '00000000-0000-0000-0000-000000000000'::uuid
       ) THEN
        RAISE EXCEPTION 'invalid account deletion finalization batch' USING ERRCODE = '22023';
    END IF;

    FOR deletion_record IN
        SELECT deletion_request.id, deletion_request.carbon_id
        FROM iam.account_deletion_requests AS deletion_request
        JOIN iam.principals AS principal
          ON principal.id = deletion_request.carbon_id
         AND principal.kind = 'carbon'
         AND principal.status = 'deletion_pending'
        JOIN iam.carbons AS carbon
          ON carbon.id = deletion_request.carbon_id
         AND carbon.deleted_at IS NULL
        WHERE deletion_request.status = 'pending'
          AND deletion_request.scheduled_for <= transaction_timestamp()
        ORDER BY deletion_request.scheduled_for, deletion_request.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_batch_size
    LOOP
        item_index := item_index + 1;
        aggregate_version := NULL;

        UPDATE iam.authentication_sessions
        SET status = 'revoked',
            revoked_at = COALESCE(revoked_at, transaction_timestamp()),
            revocation_reason = COALESCE(revocation_reason, 'account_deleted'),
            version = version + 1
        WHERE subject_principal_id = deletion_record.carbon_id
          AND status = 'active';

        UPDATE iam.refresh_token_families
        SET status = 'revoked',
            revoked_at = COALESCE(revoked_at, transaction_timestamp()),
            revocation_reason = COALESCE(revocation_reason, 'account_deleted')
        WHERE subject_principal_id = deletion_record.carbon_id
          AND status = 'active';

        UPDATE iam.refresh_tokens AS refresh
        SET revoked_at = COALESCE(refresh.revoked_at, transaction_timestamp())
        FROM iam.refresh_token_families AS family
        WHERE refresh.family_id = family.id
          AND family.subject_principal_id = deletion_record.carbon_id;

        UPDATE iam.access_tokens
        SET revoked_at = COALESCE(revoked_at, transaction_timestamp()),
            revocation_reason = COALESCE(revocation_reason, 'account_deleted')
        WHERE subject_principal_id = deletion_record.carbon_id
          AND revoked_at IS NULL;

        UPDATE iam.organization_memberships
        SET status = 'removed',
            authz_epoch = authz_epoch + 1,
            removed_at = COALESCE(removed_at, transaction_timestamp()),
            suspended_at = NULL
        WHERE principal_id = deletion_record.carbon_id
          AND principal_kind = 'carbon'
          AND status <> 'removed';

        UPDATE iam.oauth_consent_grants
        SET status = 'revoked',
            revoked_at = COALESCE(revoked_at, transaction_timestamp())
        WHERE subject_principal_id = deletion_record.carbon_id
          AND status = 'active';

        UPDATE iam.sso_identities
        SET revoked_at = COALESCE(revoked_at, transaction_timestamp())
        WHERE carbon_id = deletion_record.carbon_id
          AND revoked_at IS NULL;

        UPDATE iam.webauthn_credentials
        SET status = 'revoked',
            revoked_at = COALESCE(revoked_at, transaction_timestamp())
        WHERE carbon_id = deletion_record.carbon_id
          AND status = 'active';

        UPDATE iam.step_up_challenges
        SET status = 'cancelled'
        WHERE carbon_id = deletion_record.carbon_id
          AND status = 'pending';

        UPDATE iam.webauthn_ceremonies
        SET status = 'cancelled'
        WHERE carbon_id = deletion_record.carbon_id
          AND status = 'pending';

        DELETE FROM iam.contact_change_blind_indexes
        WHERE carbon_id = deletion_record.carbon_id;

        DELETE FROM iam.contact_change_sessions
        WHERE carbon_id = deletion_record.carbon_id;

        UPDATE iam.principals
        SET status = 'deleted',
            auth_epoch = auth_epoch + 1,
            deleted_at = COALESCE(deleted_at, transaction_timestamp())
        WHERE id = deletion_record.carbon_id
          AND kind = 'carbon'
          AND status = 'deletion_pending';

        DELETE FROM iam.contact_blind_indexes AS blind_index
        USING iam.carbon_contacts AS contact
        WHERE blind_index.contact_id = contact.id
          AND contact.carbon_id = deletion_record.carbon_id;

        UPDATE iam.carbon_contacts
        SET status = 'retired',
            is_primary = false,
            ciphertext = NULL,
            nonce = NULL,
            encryption_key_version = NULL,
            purged_at = transaction_timestamp(),
            retired_at = COALESCE(retired_at, transaction_timestamp())
        WHERE carbon_id = deletion_record.carbon_id
          AND purged_at IS NULL;

        UPDATE iam.carbons
        SET display_name = 'Deleted Carbon',
            description = NULL,
            profile_photo_uri = NULL,
            deleted_at = COALESCE(deleted_at, transaction_timestamp()),
            updated_at = transaction_timestamp()
        WHERE id = deletion_record.carbon_id
        RETURNING version INTO aggregate_version;

        IF aggregate_version IS NULL THEN
            RAISE EXCEPTION 'account deletion target is missing' USING ERRCODE = '23503';
        END IF;

        UPDATE iam.account_deletion_requests
        SET status = 'completed', completed_at = transaction_timestamp()
        WHERE id = deletion_record.id AND status = 'pending';

        INSERT INTO iam.audit_events (
            occurred_at, id, request_id, action, target_type, target_id,
            result, aggregate_type, aggregate_id, aggregate_version,
            before_state, after_state, metadata
        ) VALUES (
            transaction_timestamp(), p_audit_event_ids[item_index],
            p_request_ids[item_index], 'carbon.deletion_finalize', 'carbon',
            deletion_record.carbon_id, 'success', 'carbon',
            deletion_record.carbon_id, aggregate_version,
            '{"status":"deletion_pending"}'::jsonb,
            '{"status":"deleted"}'::jsonb,
            pg_catalog.jsonb_build_object('deletion_request_id', deletion_record.id)
        );

        INSERT INTO iam.outbox_events (
            id, aggregate_type, aggregate_id, aggregate_version, event_type, payload
        ) VALUES (
            p_outbox_event_ids[item_index], 'carbon', deletion_record.carbon_id,
            aggregate_version, 'carbon.deleted',
            pg_catalog.jsonb_build_object('deletion_request_id', deletion_record.id)
        );
    END LOOP;

    -- Run every deferred cross-table invariant while the narrow definer still
    -- owns the transition. The worker role never receives the unrelated table
    -- reads or helper execution needed by those invariant triggers at commit.
    SET CONSTRAINTS ALL IMMEDIATE;

    RETURN item_index;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.run_worker_account_deletion_finalization(
    integer, uuid[], uuid[], uuid[]
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.run_worker_account_deletion_finalization(
    integer, uuid[], uuid[], uuid[]
) IS
    'Bounded SKIP LOCKED finalization for due Carbon deletion requests, including terminal authority cleanup and transactional audit/outbox records.';

CREATE FUNCTION iam_private.get_worker_security_notice_contact(
    p_notification_job_id uuid,
    p_lease_owner text
)
RETURNS TABLE (
    carbon_id uuid,
    ciphertext bytea,
    nonce bytea,
    encryption_key_version smallint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        contact.carbon_id,
        contact.ciphertext,
        contact.nonce,
        contact.encryption_key_version
    FROM iam.notification_jobs AS notification
    JOIN iam.carbon_contacts AS contact
      ON contact.id = notification.recipient_contact_id
     AND contact.kind = notification.recipient_contact_kind
    JOIN iam.contact_change_sessions AS contact_change
      ON contact_change.id = notification.context_id
     AND contact_change.carbon_id = contact.carbon_id
     AND contact_change.kind = contact.kind
     AND contact_change.status = 'verified'
     AND contact.id IN (
         contact_change.previous_contact_id,
         contact_change.candidate_contact_id
     )
    JOIN iam.carbons AS carbon ON carbon.id = contact.carbon_id
    JOIN iam.principals AS principal
      ON principal.id = carbon.id
     AND principal.kind = 'carbon'
    WHERE notification.id = p_notification_job_id
      AND notification.notification_kind = 'security_notice'
      AND notification.template_id = 'security.contact_changed'
      AND notification.context_type = 'contact_change'
      AND notification.status = 'processing'
      AND notification.lease_owner = p_lease_owner
      AND notification.lease_expires_at > transaction_timestamp()
      AND contact.status IN ('active', 'retired')
      AND principal.status = 'active'
      AND carbon.deleted_at IS NULL
$$;

REVOKE ALL ON FUNCTION iam_private.get_worker_security_notice_contact(uuid, text) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.get_worker_security_notice_contact(uuid, text) IS
    'Worker-only lease-bound resolver for durable security notices, including the just-retired destination of a verified contact change.';
