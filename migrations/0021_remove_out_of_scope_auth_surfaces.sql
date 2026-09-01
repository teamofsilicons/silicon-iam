-- Retire authentication surfaces that are not part of the product contract.
-- Historical migrations stay immutable; this transition removes their live
-- database capabilities without discarding governance evidence.

-- Contact-change notices cannot be delivered after their resolver is retired.
-- Cancel in-flight work first so a leased worker cannot send stale material.
UPDATE iam.notification_jobs
SET status = 'cancelled',
    lease_owner = NULL,
    lease_expires_at = NULL
WHERE notification_kind = 'security_notice'
  AND template_id = 'security.contact_changed'
  AND status IN ('pending', 'processing');

DROP FUNCTION iam_private.run_worker_account_deletion_finalization(
    integer, uuid[], uuid[], uuid[]
);

-- Account-deletion requests disabled authority immediately. Restore those
-- principals to a login-capable state, but advance auth_epoch so no credential
-- issued before the request can regain authority.
UPDATE iam.principals AS principal
SET status = 'active',
    auth_epoch = principal.auth_epoch + 1,
    activated_at = COALESCE(principal.activated_at, transaction_timestamp())
WHERE principal.kind = 'carbon'
  AND principal.status = 'deletion_pending';

-- Discharge the deferred active-Carbon contact invariant before changing the
-- table definition; PostgreSQL rejects DDL while those trigger events remain
-- queued in the transaction.
SET CONSTRAINTS ALL IMMEDIATE;

ALTER TABLE iam.principals
    DROP CONSTRAINT principals_status,
    ADD CONSTRAINT principals_status
        CHECK (status IN ('provisioning', 'active', 'suspended', 'deleted'));

-- No new request can be produced by the API. Mark any already-issued request
-- challenges terminal so their codes cannot be exchanged while retention
-- removes them normally.
UPDATE iam.step_up_challenges
SET status = 'cancelled'
WHERE purpose IN ('account.contact_change', 'account.delete')
  AND status = 'pending';

-- Most WebAuthn assertions are ephemeral and can be removed. Assertions cited
-- by immutable approval decisions remain only as non-secret evidence skeletons.
DROP TRIGGER step_up_assertions_worker_retention_purge
    ON iam.step_up_assertions;

DELETE FROM iam.step_up_assertions AS assertion
WHERE assertion.webauthn_ceremony_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM iam.approval_decisions AS decision
      WHERE decision.step_up_assertion_id = assertion.id
  );

UPDATE iam.step_up_assertions AS assertion
SET token_prefix = NULL,
    token_digest = NULL,
    digest_key_version = NULL,
    assurance_level = 2,
    consumed_at = COALESCE(assertion.consumed_at, assertion.created_at),
    secret_purged_at = COALESCE(assertion.secret_purged_at, transaction_timestamp())
WHERE assertion.webauthn_ceremony_id IS NOT NULL;

ALTER TABLE iam.step_up_assertions
    DROP CONSTRAINT step_up_assertions_exactly_one_source,
    DROP CONSTRAINT step_up_assertions_webauthn_ceremony_fk,
    DROP COLUMN webauthn_ceremony_id,
    DROP CONSTRAINT step_up_assertions_assurance,
    ADD CONSTRAINT step_up_assertions_assurance
        CHECK (assurance_level = 2),
    ADD CONSTRAINT step_up_assertions_supported_source CHECK (
        step_up_challenge_id IS NOT NULL
        OR (
            secret_purged_at IS NOT NULL
            AND consumed_at IS NOT NULL
            AND token_prefix IS NULL
            AND token_digest IS NULL
            AND digest_key_version IS NULL
        )
    );

CREATE FUNCTION iam_private.enforce_step_up_assertion_source()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.step_up_challenge_id IS NULL
       AND (TG_OP = 'INSERT' OR OLD.step_up_challenge_id IS NOT NULL) THEN
        RAISE EXCEPTION 'new step-up assertions require an OTP challenge source'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.enforce_step_up_assertion_source() FROM PUBLIC;

CREATE TRIGGER step_up_assertions_supported_source
BEFORE INSERT OR UPDATE OF step_up_challenge_id ON iam.step_up_assertions
FOR EACH ROW
EXECUTE FUNCTION iam_private.enforce_step_up_assertion_source();

CREATE TRIGGER step_up_assertions_worker_retention_purge
BEFORE UPDATE OF secret_purged_at ON iam.step_up_assertions
FOR EACH ROW
WHEN (NEW.secret_purged_at IS DISTINCT FROM OLD.secret_purged_at)
EXECUTE FUNCTION iam_private.reject_immutable_history_mutation('worker_retention_purge');

-- Security notices now resolve only to the recipient's current verified
-- contact. The resolver remains lease-bound and accepts a closed template set.
CREATE OR REPLACE FUNCTION iam_private.get_worker_security_notice_contact(
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
    JOIN iam.carbons AS carbon ON carbon.id = contact.carbon_id
    JOIN iam.principals AS principal
      ON principal.id = carbon.id
     AND principal.kind = 'carbon'
    WHERE notification.id = p_notification_job_id
      AND notification.notification_kind = 'security_notice'
      AND notification.template_id IN (
          'security.session_revoked',
          'security.refresh_reuse',
          'security.credential_rotated'
      )
      AND notification.status = 'processing'
      AND notification.lease_owner = p_lease_owner
      AND notification.lease_expires_at > transaction_timestamp()
      AND contact.status = 'active'
      AND contact.is_primary
      AND contact.verified_at IS NOT NULL
      AND contact.ciphertext IS NOT NULL
      AND contact.nonce IS NOT NULL
      AND contact.encryption_key_version IS NOT NULL
      AND principal.status = 'active'
      AND carbon.deleted_at IS NULL
$$;

REVOKE ALL ON FUNCTION iam_private.get_worker_security_notice_contact(uuid, text) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.get_worker_security_notice_contact(uuid, text) IS
    'Worker-only lease-bound resolver for closed-set security notices sent to a current verified Carbon contact.';

-- Preserve the proven per-phase implementations for the supported phases, but
-- make the old entry point inaccessible and place a strict 18-phase facade in
-- front of it. Session deletion is implemented locally because the historical
-- implementation referenced the tables removed below.
ALTER FUNCTION iam_private.run_worker_retention_maintenance(
    text, integer, integer, integer, integer, integer, integer, integer
) RENAME TO run_worker_retention_maintenance_core;

ALTER FUNCTION iam_private.run_worker_retention_maintenance_core(
    text, integer, integer, integer, integer, integer, integer, integer
) SECURITY INVOKER;

REVOKE ALL ON FUNCTION iam_private.run_worker_retention_maintenance_core(
    text, integer, integer, integer, integer, integer, integer, integer
) FROM PUBLIC;

DO $revoke_retention_core$
BEGIN
    IF pg_catalog.to_regrole('silicon_iam_worker') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON FUNCTION iam_private.run_worker_retention_maintenance_core(text, integer, integer, integer, integer, integer, integer, integer) FROM silicon_iam_worker';
    END IF;
END;
$revoke_retention_core$;

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
    login_cutoff timestamptz;
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
        'oauth_authorization_requests',
        'sso_authorization_transactions',
        'sso_setup_sessions',
        'governance_step_up_challenges_purge',
        'governance_step_up_assertions_purge',
        'step_up_assertions_delete',
        'step_up_challenges_delete',
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

    IF p_phase <> 'authentication_sessions_delete' THEN
        RETURN QUERY
        SELECT result.completed_phase, result.affected_rows
        FROM iam_private.run_worker_retention_maintenance_core(
            p_phase,
            p_login_history_days,
            p_ephemeral_security_days,
            p_token_metadata_days,
            p_compromised_refresh_days,
            p_webhook_attempt_days,
            p_audit_event_days,
            p_limit
        ) AS result;
        RETURN;
    END IF;

    login_cutoff := transaction_timestamp()
        - pg_catalog.make_interval(days => p_login_history_days);
    guard_transaction_id := pg_catalog.pg_current_xact_id();
    INSERT INTO iam_private.worker_retention_guards (
        backend_pid, transaction_id, invoker
    )
    VALUES (pg_catalog.pg_backend_pid(), guard_transaction_id, session_user);

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
    'Worker-role-only single-phase retention transition over the active 18-phase vocabulary.';

DROP TABLE iam.contact_change_blind_indexes;
DROP TABLE iam.contact_change_sessions;
DROP TABLE iam.account_deletion_requests;
DROP TABLE iam.webauthn_ceremonies;
DROP TABLE iam.webauthn_credentials;
