-- Configurable, bounded retention with a worker-only append-history deletion guard.

CREATE TABLE iam_private.worker_retention_guards (
    backend_pid integer NOT NULL,
    transaction_id xid8 NOT NULL,
    invoker name NOT NULL,
    PRIMARY KEY (backend_pid, transaction_id),
    CONSTRAINT worker_retention_guards_positive_pid CHECK (backend_pid > 0)
);

REVOKE ALL ON TABLE iam_private.worker_retention_guards FROM PUBLIC;

COMMENT ON TABLE iam_private.worker_retention_guards IS
    'Transaction-scoped capability installed only by the worker retention definer; never a runtime-visible queue.';

CREATE OR REPLACE FUNCTION iam_private.reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam_private
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND EXISTS (
        SELECT 1
        FROM iam_private.worker_retention_guards AS guard
        WHERE guard.backend_pid = pg_catalog.pg_backend_pid()
          AND guard.transaction_id = pg_catalog.pg_current_xact_id()
          AND guard.invoker = session_user
    ) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = '55000';
END;
$$;

REVOKE ALL ON FUNCTION iam_private.reject_audit_mutation() FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.reject_immutable_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam_private
AS $$
BEGIN
    IF TG_NARGS = 1 AND TG_ARGV[0] = 'worker_retention_purge' THEN
        IF TG_OP = 'UPDATE' AND EXISTS (
            SELECT 1
            FROM iam_private.worker_retention_guards AS guard
            WHERE guard.backend_pid = pg_catalog.pg_backend_pid()
              AND guard.transaction_id = pg_catalog.pg_current_xact_id()
              AND guard.invoker = session_user
        ) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION '% retention erasure requires the worker transition',
            TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME
            USING ERRCODE = '42501';
    END IF;

    IF TG_OP = 'DELETE' AND EXISTS (
        SELECT 1
        FROM iam_private.worker_retention_guards AS guard
        WHERE guard.backend_pid = pg_catalog.pg_backend_pid()
          AND guard.transaction_id = pg_catalog.pg_current_xact_id()
          AND guard.invoker = session_user
    ) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

REVOKE ALL ON FUNCTION iam_private.reject_immutable_history_mutation() FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.prevent_oauth_refresh_family_scope_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam_private
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND EXISTS (
        SELECT 1
        FROM iam_private.worker_retention_guards AS guard
        WHERE guard.backend_pid = pg_catalog.pg_backend_pid()
          AND guard.transaction_id = pg_catalog.pg_current_xact_id()
          AND guard.invoker = session_user
    ) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'OAuth refresh-family scope snapshots are immutable'
        USING ERRCODE = '23514';
END;
$$;

REVOKE ALL ON FUNCTION iam_private.prevent_oauth_refresh_family_scope_mutation() FROM PUBLIC;

ALTER TABLE iam.step_up_challenges
    ALTER COLUMN challenge_digest DROP NOT NULL,
    ALTER COLUMN digest_key_version DROP NOT NULL,
    ADD COLUMN secret_purged_at timestamptz,
    ADD CONSTRAINT step_up_challenges_retention_purge_consistency CHECK (
        (secret_purged_at IS NULL
            AND challenge_digest IS NOT NULL
            AND digest_key_version IS NOT NULL)
        OR (secret_purged_at IS NOT NULL
            AND challenge_digest IS NULL
            AND digest_key_version IS NULL)
    );

ALTER TABLE iam.step_up_assertions
    ALTER COLUMN token_prefix DROP NOT NULL,
    ALTER COLUMN token_digest DROP NOT NULL,
    ALTER COLUMN digest_key_version DROP NOT NULL,
    ADD COLUMN secret_purged_at timestamptz,
    ADD CONSTRAINT step_up_assertions_retention_purge_consistency CHECK (
        (secret_purged_at IS NULL
            AND token_prefix IS NOT NULL
            AND token_digest IS NOT NULL
            AND digest_key_version IS NOT NULL)
        OR (secret_purged_at IS NOT NULL
            AND token_prefix IS NULL
            AND token_digest IS NULL
            AND digest_key_version IS NULL)
    );

ALTER TABLE iam.webauthn_ceremonies
    ALTER COLUMN state_ciphertext DROP NOT NULL,
    ALTER COLUMN state_nonce DROP NOT NULL,
    ALTER COLUMN state_encryption_key_version DROP NOT NULL,
    ADD COLUMN state_purged_at timestamptz,
    ADD CONSTRAINT webauthn_ceremonies_retention_purge_consistency CHECK (
        (state_purged_at IS NULL
            AND state_ciphertext IS NOT NULL
            AND state_nonce IS NOT NULL
            AND state_encryption_key_version IS NOT NULL)
        OR (state_purged_at IS NOT NULL
            AND state_ciphertext IS NULL
            AND state_nonce IS NULL
            AND state_encryption_key_version IS NULL)
    );

ALTER TABLE iam.authentication_sessions
    ADD COLUMN retention_purged_at timestamptz,
    ADD CONSTRAINT authentication_sessions_retention_purge_consistency CHECK (
        retention_purged_at IS NULL
        OR (ip_fingerprint IS NULL
            AND user_agent_fingerprint IS NULL
            AND revocation_reason IS NULL)
    );

COMMENT ON COLUMN iam.step_up_challenges.secret_purged_at IS
    'Set after the retention cutoff when an approval decision requires the challenge skeleton to remain.';
COMMENT ON COLUMN iam.step_up_assertions.secret_purged_at IS
    'Set after token digest erasure when governance history still references the assertion.';
COMMENT ON COLUMN iam.webauthn_ceremonies.state_purged_at IS
    'Set after encrypted WebAuthn ceremony state is erased while a governance assertion retains the source ID.';
COMMENT ON COLUMN iam.authentication_sessions.retention_purged_at IS
    'Set when a retained FK skeleton has had optional fingerprint and revocation-detail fields erased.';

-- These markers are the only valid transition into the nullable retained-skeleton
-- shapes above. Reusing the fixed-path history guard avoids trusting a caller-set
-- GUC and prevents the broadly privileged API role from erasing retained state.
CREATE TRIGGER step_up_challenges_worker_retention_purge
BEFORE UPDATE OF secret_purged_at ON iam.step_up_challenges
FOR EACH ROW
WHEN (NEW.secret_purged_at IS DISTINCT FROM OLD.secret_purged_at)
EXECUTE FUNCTION iam_private.reject_immutable_history_mutation('worker_retention_purge');

CREATE TRIGGER step_up_assertions_worker_retention_purge
BEFORE UPDATE OF secret_purged_at ON iam.step_up_assertions
FOR EACH ROW
WHEN (NEW.secret_purged_at IS DISTINCT FROM OLD.secret_purged_at)
EXECUTE FUNCTION iam_private.reject_immutable_history_mutation('worker_retention_purge');

CREATE TRIGGER webauthn_ceremonies_worker_retention_purge
BEFORE UPDATE OF state_purged_at ON iam.webauthn_ceremonies
FOR EACH ROW
WHEN (NEW.state_purged_at IS DISTINCT FROM OLD.state_purged_at)
EXECUTE FUNCTION iam_private.reject_immutable_history_mutation('worker_retention_purge');

CREATE TRIGGER authentication_sessions_worker_retention_purge
BEFORE UPDATE OF retention_purged_at ON iam.authentication_sessions
FOR EACH ROW
WHEN (NEW.retention_purged_at IS DISTINCT FROM OLD.retention_purged_at)
EXECUTE FUNCTION iam_private.reject_immutable_history_mutation('worker_retention_purge');

CREATE INDEX authentication_events_retention_idx
    ON iam.authentication_events (occurred_at, id);
CREATE INDEX signup_sessions_retention_idx
    ON iam.signup_sessions (expires_at, id);
CREATE INDEX login_challenges_retention_idx
    ON iam.login_challenges (expires_at, id);
CREATE INDEX invitation_verification_retention_idx
    ON iam.invitation_verification_challenges (expires_at, id);
CREATE INDEX contact_change_sessions_retention_idx
    ON iam.contact_change_sessions (expires_at, id);
CREATE INDEX oauth_authorization_requests_retention_idx
    ON iam.oauth_authorization_requests (expires_at, id);
CREATE INDEX sso_authorization_transactions_retention_idx
    ON iam.sso_authorization_transactions (expires_at, id);
CREATE INDEX sso_setup_sessions_retention_idx
    ON iam.sso_setup_sessions (expires_at, id);
CREATE INDEX step_up_challenges_retention_idx
    ON iam.step_up_challenges (expires_at, id);
CREATE INDEX step_up_assertions_retention_idx
    ON iam.step_up_assertions (expires_at, id);
CREATE INDEX webauthn_ceremonies_retention_idx
    ON iam.webauthn_ceremonies (expires_at, id);
CREATE INDEX obo_proofs_retention_idx
    ON iam.obo_proofs ((COALESCE(revoked_at, consumed_at, expires_at)), id);
CREATE INDEX access_tokens_retention_idx
    ON iam.access_tokens ((COALESCE(revoked_at, expires_at)), id);
CREATE INDEX refresh_token_families_retention_idx
    ON iam.refresh_token_families ((COALESCE(revoked_at, absolute_expires_at)), id)
    WHERE status <> 'compromised';
CREATE INDEX refresh_token_families_compromised_retention_idx
    ON iam.refresh_token_families (compromised_at, id)
    WHERE status = 'compromised';
CREATE INDEX webhook_delivery_attempts_retention_idx
    ON iam.webhook_delivery_attempts (started_at, id);
CREATE INDEX authentication_sessions_retention_idx
    ON iam.authentication_sessions ((COALESCE(revoked_at, absolute_expires_at)), id);

CREATE FUNCTION iam_private.run_worker_retention_maintenance(
    p_phase text,
    p_login_history_days integer,
    p_ephemeral_security_days integer,
    p_token_metadata_days integer,
    p_compromised_refresh_days integer,
    p_webhook_attempt_days integer,
    p_audit_event_days integer,
    p_limit integer
)
RETURNS TABLE (
    completed_phase text,
    affected_rows bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    worker_role regrole;
    guard_transaction_id xid8;
    selected_ids uuid[];
    retention_now timestamptz;
    login_cutoff timestamptz;
    ephemeral_cutoff timestamptz;
    token_cutoff timestamptz;
    compromised_refresh_cutoff timestamptz;
    webhook_attempt_cutoff timestamptz;
    audit_cutoff timestamptz;
BEGIN
    worker_role := pg_catalog.to_regrole('silicon_iam_worker');
    IF worker_role IS NULL OR NOT COALESCE(
        pg_catalog.pg_has_role(session_user, worker_role, 'member'), false
    ) THEN
        RAISE EXCEPTION 'retention maintenance requires the silicon_iam_worker role'
            USING ERRCODE = '42501';
    END IF;

    IF p_phase IS NULL OR p_phase NOT IN (
        'authentication_events',
        'signup_sessions',
        'login_challenges',
        'invitation_challenges',
        'contact_change_sessions',
        'oauth_authorization_requests',
        'sso_authorization_transactions',
        'sso_setup_sessions',
        'governance_step_up_challenges_purge',
        'governance_step_up_assertions_purge',
        'governance_webauthn_ceremonies_purge',
        'step_up_assertions_delete',
        'step_up_challenges_delete',
        'webauthn_ceremonies_delete',
        'obo_proofs',
        'access_tokens',
        'refresh_token_families',
        'webhook_delivery_attempts',
        'audit_events',
        'authentication_sessions_delete',
        'authentication_sessions_purge'
    ) THEN
        RAISE EXCEPTION 'unsupported retention maintenance phase'
            USING ERRCODE = '22023';
    END IF;

    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'retention batch limit must be between 1 and 1000'
            USING ERRCODE = '22023';
    END IF;
    IF p_login_history_days IS NULL
       OR p_ephemeral_security_days IS NULL
       OR p_token_metadata_days IS NULL
       OR p_compromised_refresh_days IS NULL
       OR p_webhook_attempt_days IS NULL
       OR p_audit_event_days IS NULL
       OR p_login_history_days NOT BETWEEN 1 AND 36500
       OR p_ephemeral_security_days NOT BETWEEN 1 AND 36500
       OR p_token_metadata_days NOT BETWEEN 1 AND 36500
       OR p_compromised_refresh_days NOT BETWEEN 1 AND 36500
       OR p_webhook_attempt_days NOT BETWEEN 1 AND 36500
       OR p_audit_event_days NOT BETWEEN 1 AND 36500 THEN
        RAISE EXCEPTION 'retention days must be between 1 and 36500'
            USING ERRCODE = '22023';
    END IF;
    IF p_compromised_refresh_days < p_token_metadata_days THEN
        RAISE EXCEPTION 'compromised refresh retention cannot be shorter than token retention'
            USING ERRCODE = '22023';
    END IF;

    retention_now := transaction_timestamp();
    login_cutoff := retention_now - pg_catalog.make_interval(days => p_login_history_days);
    ephemeral_cutoff := retention_now
        - pg_catalog.make_interval(days => p_ephemeral_security_days);
    token_cutoff := retention_now - pg_catalog.make_interval(days => p_token_metadata_days);
    compromised_refresh_cutoff := retention_now
        - pg_catalog.make_interval(days => p_compromised_refresh_days);
    webhook_attempt_cutoff := retention_now
        - pg_catalog.make_interval(days => p_webhook_attempt_days);
    audit_cutoff := retention_now - pg_catalog.make_interval(days => p_audit_event_days);

    guard_transaction_id := pg_catalog.pg_current_xact_id();
    INSERT INTO iam_private.worker_retention_guards (
        backend_pid, transaction_id, invoker
    )
    VALUES (pg_catalog.pg_backend_pid(), guard_transaction_id, session_user);

    IF p_phase = 'authentication_events' THEN
    WITH expired AS MATERIALIZED (
        SELECT event.id
        FROM iam.authentication_events AS event
        WHERE event.occurred_at < login_cutoff
        ORDER BY event.occurred_at, event.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    )
    DELETE FROM iam.authentication_events AS event
    USING expired
    WHERE event.id = expired.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'signup_sessions' THEN
    SELECT COALESCE(pg_catalog.array_agg(candidate.id), ARRAY[]::uuid[])
    INTO selected_ids
    FROM (
        SELECT signup.id
        FROM iam.signup_sessions AS signup
        WHERE signup.expires_at < ephemeral_cutoff
        ORDER BY signup.expires_at, signup.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    ) AS candidate;
    DELETE FROM iam.signup_otp_challenges AS challenge
    WHERE challenge.signup_session_id = ANY(selected_ids);
    DELETE FROM iam.signup_candidate_blind_indexes AS blind_index
    USING iam.signup_contact_candidates AS candidate
    WHERE blind_index.candidate_id = candidate.id
      AND candidate.signup_session_id = ANY(selected_ids);
    DELETE FROM iam.signup_contact_candidates AS candidate
    WHERE candidate.signup_session_id = ANY(selected_ids);
    DELETE FROM iam.signup_sessions AS signup
    WHERE signup.id = ANY(selected_ids);
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'login_challenges' THEN
    SELECT COALESCE(pg_catalog.array_agg(candidate.id), ARRAY[]::uuid[])
    INTO selected_ids
    FROM (
        SELECT challenge.id
        FROM iam.login_challenges AS challenge
        WHERE challenge.expires_at < ephemeral_cutoff
        ORDER BY challenge.expires_at, challenge.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    ) AS candidate;
    DELETE FROM iam.login_challenge_channels AS channel
    WHERE channel.login_challenge_id = ANY(selected_ids);
    DELETE FROM iam.login_challenges AS challenge
    WHERE challenge.id = ANY(selected_ids);
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'invitation_challenges' THEN
    WITH expired AS MATERIALIZED (
        SELECT challenge.id
        FROM iam.invitation_verification_challenges AS challenge
        WHERE challenge.expires_at < ephemeral_cutoff
        ORDER BY challenge.expires_at, challenge.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    )
    DELETE FROM iam.invitation_verification_challenges AS challenge
    USING expired
    WHERE challenge.id = expired.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'contact_change_sessions' THEN
    SELECT COALESCE(pg_catalog.array_agg(candidate.id), ARRAY[]::uuid[])
    INTO selected_ids
    FROM (
        SELECT contact_change.id
        FROM iam.contact_change_sessions AS contact_change
        WHERE contact_change.expires_at < ephemeral_cutoff
        ORDER BY contact_change.expires_at, contact_change.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    ) AS candidate;
    DELETE FROM iam.contact_change_blind_indexes AS blind_index
    WHERE blind_index.contact_change_session_id = ANY(selected_ids);
    DELETE FROM iam.contact_change_sessions AS contact_change
    WHERE contact_change.id = ANY(selected_ids);
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'oauth_authorization_requests' THEN
    SELECT COALESCE(pg_catalog.array_agg(candidate.id), ARRAY[]::uuid[])
    INTO selected_ids
    FROM (
        SELECT authorization_request.id
        FROM iam.oauth_authorization_requests AS authorization_request
        WHERE authorization_request.expires_at < ephemeral_cutoff
        ORDER BY authorization_request.expires_at, authorization_request.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    ) AS candidate;
    DELETE FROM iam.oauth_authorization_codes AS authorization_code
    WHERE authorization_code.authorization_request_id = ANY(selected_ids);
    DELETE FROM iam.oauth_authorization_request_scopes AS request_scope
    WHERE request_scope.authorization_request_id = ANY(selected_ids);
    DELETE FROM iam.oauth_authorization_requests AS authorization_request
    WHERE authorization_request.id = ANY(selected_ids);
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'sso_authorization_transactions' THEN
    WITH expired AS MATERIALIZED (
        SELECT authorization_transaction.id
        FROM iam.sso_authorization_transactions AS authorization_transaction
        WHERE authorization_transaction.expires_at < ephemeral_cutoff
        ORDER BY authorization_transaction.expires_at, authorization_transaction.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    )
    DELETE FROM iam.sso_authorization_transactions AS authorization_transaction
    USING expired
    WHERE authorization_transaction.id = expired.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'sso_setup_sessions' THEN
    WITH expired AS MATERIALIZED (
        SELECT setup_session.id
        FROM iam.sso_setup_sessions AS setup_session
        WHERE setup_session.expires_at < ephemeral_cutoff
        ORDER BY setup_session.expires_at, setup_session.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    )
    DELETE FROM iam.sso_setup_sessions AS setup_session
    USING expired
    WHERE setup_session.id = expired.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'governance_step_up_challenges_purge' THEN
    WITH retained AS MATERIALIZED (
        SELECT challenge.id
        FROM iam.step_up_challenges AS challenge
        WHERE challenge.expires_at < ephemeral_cutoff
          AND challenge.secret_purged_at IS NULL
          AND EXISTS (
              SELECT 1
              FROM iam.step_up_assertions AS assertion
              JOIN iam.approval_decisions AS decision
                ON decision.step_up_assertion_id = assertion.id
              WHERE assertion.step_up_challenge_id = challenge.id
          )
        ORDER BY challenge.expires_at, challenge.id
        FOR UPDATE OF challenge SKIP LOCKED
        LIMIT p_limit
    )
    UPDATE iam.step_up_challenges AS challenge
    SET challenge_digest = NULL,
        digest_key_version = NULL,
        secret_purged_at = retention_now
    FROM retained
    WHERE challenge.id = retained.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'governance_step_up_assertions_purge' THEN
    WITH retained AS MATERIALIZED (
        SELECT assertion.id
        FROM iam.step_up_assertions AS assertion
        WHERE assertion.expires_at < ephemeral_cutoff
          AND assertion.secret_purged_at IS NULL
          AND EXISTS (
              SELECT 1
              FROM iam.approval_decisions AS decision
              WHERE decision.step_up_assertion_id = assertion.id
          )
        ORDER BY assertion.expires_at, assertion.id
        FOR UPDATE OF assertion SKIP LOCKED
        LIMIT p_limit
    )
    UPDATE iam.step_up_assertions AS assertion
    SET token_prefix = NULL,
        token_digest = NULL,
        digest_key_version = NULL,
        secret_purged_at = retention_now
    FROM retained
    WHERE assertion.id = retained.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'governance_webauthn_ceremonies_purge' THEN
    WITH retained AS MATERIALIZED (
        SELECT ceremony.id
        FROM iam.webauthn_ceremonies AS ceremony
        WHERE ceremony.expires_at < ephemeral_cutoff
          AND ceremony.state_purged_at IS NULL
          AND EXISTS (
              SELECT 1
              FROM iam.step_up_assertions AS assertion
              JOIN iam.approval_decisions AS decision
                ON decision.step_up_assertion_id = assertion.id
              WHERE assertion.webauthn_ceremony_id = ceremony.id
          )
        ORDER BY ceremony.expires_at, ceremony.id
        FOR UPDATE OF ceremony SKIP LOCKED
        LIMIT p_limit
    )
    UPDATE iam.webauthn_ceremonies AS ceremony
    SET state_ciphertext = NULL,
        state_nonce = NULL,
        state_encryption_key_version = NULL,
        state_purged_at = retention_now
    FROM retained
    WHERE ceremony.id = retained.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'step_up_assertions_delete' THEN
    WITH expired AS MATERIALIZED (
        SELECT assertion.id
        FROM iam.step_up_assertions AS assertion
        WHERE assertion.expires_at < ephemeral_cutoff
          AND NOT EXISTS (
              SELECT 1
              FROM iam.approval_decisions AS decision
              WHERE decision.step_up_assertion_id = assertion.id
          )
        ORDER BY assertion.expires_at, assertion.id
        FOR UPDATE OF assertion SKIP LOCKED
        LIMIT p_limit
    )
    DELETE FROM iam.step_up_assertions AS assertion
    USING expired
    WHERE assertion.id = expired.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'step_up_challenges_delete' THEN
    WITH expired AS MATERIALIZED (
        SELECT challenge.id
        FROM iam.step_up_challenges AS challenge
        WHERE challenge.expires_at < ephemeral_cutoff
          AND NOT EXISTS (
              SELECT 1
              FROM iam.step_up_assertions AS assertion
              WHERE assertion.step_up_challenge_id = challenge.id
          )
        ORDER BY challenge.expires_at, challenge.id
        FOR UPDATE OF challenge SKIP LOCKED
        LIMIT p_limit
    )
    DELETE FROM iam.step_up_challenges AS challenge
    USING expired
    WHERE challenge.id = expired.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'webauthn_ceremonies_delete' THEN
    WITH expired AS MATERIALIZED (
        SELECT ceremony.id
        FROM iam.webauthn_ceremonies AS ceremony
        WHERE ceremony.expires_at < ephemeral_cutoff
          AND NOT EXISTS (
              SELECT 1
              FROM iam.step_up_assertions AS assertion
              WHERE assertion.webauthn_ceremony_id = ceremony.id
          )
        ORDER BY ceremony.expires_at, ceremony.id
        FOR UPDATE OF ceremony SKIP LOCKED
        LIMIT p_limit
    )
    DELETE FROM iam.webauthn_ceremonies AS ceremony
    USING expired
    WHERE ceremony.id = expired.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'obo_proofs' THEN
    WITH expired AS MATERIALIZED (
        SELECT proof.id
        FROM iam.obo_proofs AS proof
        WHERE COALESCE(proof.revoked_at, proof.consumed_at, proof.expires_at) < token_cutoff
        ORDER BY COALESCE(proof.revoked_at, proof.consumed_at, proof.expires_at), proof.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    )
    DELETE FROM iam.obo_proofs AS proof
    USING expired
    WHERE proof.id = expired.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'access_tokens' THEN
    SELECT COALESCE(pg_catalog.array_agg(candidate.id), ARRAY[]::uuid[])
    INTO selected_ids
    FROM (
        SELECT access_token.id
        FROM iam.access_tokens AS access_token
        WHERE COALESCE(access_token.revoked_at, access_token.expires_at) < token_cutoff
          AND NOT EXISTS (
              SELECT 1
              FROM iam.obo_proofs AS proof
              WHERE proof.parent_access_token_id = access_token.id
          )
        ORDER BY COALESCE(access_token.revoked_at, access_token.expires_at), access_token.id
        FOR UPDATE OF access_token SKIP LOCKED
        LIMIT p_limit
    ) AS candidate;
    DELETE FROM iam.access_token_scopes AS token_scope
    WHERE token_scope.access_token_id = ANY(selected_ids);
    DELETE FROM iam.access_tokens AS access_token
    WHERE access_token.id = ANY(selected_ids);
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'refresh_token_families' THEN
    SELECT COALESCE(pg_catalog.array_agg(candidate.id), ARRAY[]::uuid[])
    INTO selected_ids
    FROM (
        SELECT family.id
        FROM iam.refresh_token_families AS family
        WHERE (
                family.status = 'compromised'
                AND family.compromised_at < compromised_refresh_cutoff
            )
           OR (
                family.status <> 'compromised'
                AND COALESCE(family.revoked_at, family.absolute_expires_at) < token_cutoff
            )
        ORDER BY
            CASE
                WHEN family.status = 'compromised' THEN family.compromised_at
                ELSE COALESCE(family.revoked_at, family.absolute_expires_at)
            END,
            family.id
        FOR UPDATE OF family SKIP LOCKED
        LIMIT p_limit
    ) AS candidate;
    DELETE FROM iam.oauth_refresh_family_scopes AS family_scope
    WHERE family_scope.family_id = ANY(selected_ids);
    DELETE FROM iam.refresh_tokens AS refresh_token
    WHERE refresh_token.family_id = ANY(selected_ids);
    DELETE FROM iam.refresh_token_families AS family
    WHERE family.id = ANY(selected_ids);
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'webhook_delivery_attempts' THEN
    WITH expired AS MATERIALIZED (
        SELECT attempt.id
        FROM iam.webhook_delivery_attempts AS attempt
        WHERE attempt.started_at < webhook_attempt_cutoff
        ORDER BY attempt.started_at, attempt.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    )
    DELETE FROM iam.webhook_delivery_attempts AS attempt
    USING expired
    WHERE attempt.id = expired.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'audit_events' THEN
    WITH expired AS MATERIALIZED (
        SELECT audit.occurred_at, audit.id
        FROM iam.audit_events AS audit
        WHERE audit.occurred_at < audit_cutoff
        ORDER BY audit.occurred_at, audit.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    )
    DELETE FROM iam.audit_events AS audit
    USING expired
    WHERE audit.occurred_at = expired.occurred_at
      AND audit.id = expired.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'authentication_sessions_delete' THEN
    WITH expired AS MATERIALIZED (
        SELECT authentication_session.id
        FROM iam.authentication_sessions AS authentication_session
        WHERE COALESCE(
                authentication_session.revoked_at,
                authentication_session.absolute_expires_at
              ) < login_cutoff
          AND NOT EXISTS (
              SELECT 1 FROM iam.authentication_sessions AS child
              WHERE child.parent_session_id = authentication_session.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM iam.refresh_token_families AS family
              WHERE family.authentication_session_id = authentication_session.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM iam.access_tokens AS access_token
              WHERE access_token.authentication_session_id = authentication_session.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM iam.account_deletion_requests AS deletion_request
              WHERE deletion_request.requested_from_session_id = authentication_session.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM iam.contact_change_sessions AS contact_change
              WHERE contact_change.authentication_session_id = authentication_session.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM iam.webauthn_ceremonies AS ceremony
              WHERE ceremony.authentication_session_id = authentication_session.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM iam.step_up_challenges AS challenge
              WHERE challenge.authentication_session_id = authentication_session.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM iam.step_up_assertions AS assertion
              WHERE assertion.authentication_session_id = authentication_session.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM iam.oauth_authorization_requests AS authorization_request
              WHERE authorization_request.authentication_session_id = authentication_session.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM iam.oauth_consent_grants AS consent
              WHERE consent.parent_authentication_session_id = authentication_session.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM iam.sso_authorization_transactions AS authorization_transaction
              WHERE authorization_transaction.authentication_session_id = authentication_session.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM iam.authentication_events AS event
              WHERE event.authentication_session_id = authentication_session.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM iam.audit_events AS audit
              WHERE audit.actor_authentication_session_id = authentication_session.id
          )
        ORDER BY
            COALESCE(authentication_session.revoked_at, authentication_session.absolute_expires_at),
            authentication_session.id
        FOR UPDATE OF authentication_session SKIP LOCKED
        LIMIT p_limit
    )
    DELETE FROM iam.authentication_sessions AS authentication_session
    USING expired
    WHERE authentication_session.id = expired.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    ELSIF p_phase = 'authentication_sessions_purge' THEN
    WITH retained AS MATERIALIZED (
        SELECT authentication_session.id
        FROM iam.authentication_sessions AS authentication_session
        WHERE COALESCE(
                authentication_session.revoked_at,
                authentication_session.absolute_expires_at
              ) < login_cutoff
          AND authentication_session.retention_purged_at IS NULL
        ORDER BY
            COALESCE(authentication_session.revoked_at, authentication_session.absolute_expires_at),
            authentication_session.id
        FOR UPDATE OF authentication_session SKIP LOCKED
        LIMIT p_limit
    )
    UPDATE iam.authentication_sessions AS authentication_session
    SET ip_fingerprint = NULL,
        user_agent_fingerprint = NULL,
        revocation_reason = NULL,
        retention_purged_at = retention_now
    FROM retained
    WHERE authentication_session.id = retained.id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    END IF;

    DELETE FROM iam_private.worker_retention_guards AS guard
    WHERE guard.backend_pid = pg_catalog.pg_backend_pid()
      AND guard.transaction_id = guard_transaction_id
      AND guard.invoker = session_user;

    RETURN QUERY SELECT p_phase, affected_rows;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.run_worker_retention_maintenance(
    text, integer, integer, integer, integer, integer, integer, integer
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.run_worker_retention_maintenance(
    text, integer, integer, integer, integer, integer, integer, integer
) IS
    'Worker-role-only single-phase retention transition; deletes expired metadata or cryptographically erases FK-retained skeletons in one bounded transaction.';
