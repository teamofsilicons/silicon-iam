-- Version-correct, scope-filtered Carbon profile webhook projections.

CREATE TABLE iam.application_webhook_event_projections (
    id uuid PRIMARY KEY,
    outbox_event_id uuid NOT NULL,
    application_id uuid NOT NULL,
    payload_ciphertext bytea NOT NULL,
    payload_nonce bytea NOT NULL,
    encryption_key_version smallint NOT NULL,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (outbox_event_id, application_id),
    CONSTRAINT application_webhook_event_projections_event_fk
        FOREIGN KEY (outbox_event_id) REFERENCES iam.outbox_events (id) ON DELETE RESTRICT,
    CONSTRAINT application_webhook_event_projections_application_fk
        FOREIGN KEY (application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT application_webhook_event_projections_encryption_key_fk
        FOREIGN KEY (encryption_purpose, encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT application_webhook_event_projections_ciphertext_length
        CHECK (octet_length(payload_ciphertext) BETWEEN 17 AND 1048592),
    CONSTRAINT application_webhook_event_projections_nonce_length
        CHECK (octet_length(payload_nonce) = 12)
);

CREATE INDEX application_webhook_event_projections_retention_idx
    ON iam.application_webhook_event_projections (created_at, id);

COMMENT ON TABLE iam.application_webhook_event_projections IS
    'Row-bound encrypted, immutable per-Application payloads and the union of authorization recipients effective immediately before or after a Carbon profile event.';

REVOKE ALL ON TABLE iam.application_webhook_event_projections FROM PUBLIC;

CREATE FUNCTION iam_private.list_profile_webhook_authorization_scopes(
    p_carbon_id uuid
)
RETURNS TABLE (
    application_id uuid,
    scope text
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT consent.application_id, consent_scope.scope
    FROM iam.oauth_consent_grants AS consent
    JOIN iam.oauth_consent_grant_scopes AS consent_scope
      ON consent_scope.consent_grant_id = consent.id
    JOIN iam.application_approved_scopes AS approved_scope
      ON approved_scope.application_id = consent.application_id
     AND approved_scope.scope = consent_scope.scope
     AND approved_scope.revoked_at IS NULL
    JOIN iam.applications AS application
      ON application.id = consent.application_id
     AND application.review_status = 'verified'
     AND application.deleted_at IS NULL
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
     AND application_principal.status = 'active'
    JOIN iam.principals AS subject_principal
      ON subject_principal.id = consent.subject_principal_id
     AND subject_principal.kind = 'carbon'
     AND subject_principal.status = 'active'
    WHERE iam_private.current_principal_id() = p_carbon_id
      AND consent.subject_principal_id = p_carbon_id
      AND consent.subject_kind = 'carbon'
      AND consent.status = 'active'
    ORDER BY consent.application_id, consent_scope.scope
    FOR SHARE OF consent, consent_scope, approved_scope, application, application_principal
$$;

REVOKE ALL ON FUNCTION iam_private.list_profile_webhook_authorization_scopes(uuid)
    FROM PUBLIC;

CREATE FUNCTION iam_private.list_worker_captured_application_webhook_recipients(
    p_outbox_event_id uuid
)
RETURNS TABLE (
    endpoint_id uuid,
    signing_key_id uuid
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT endpoint.id, signing_key.id
    FROM iam.application_webhook_event_projections AS projection
    JOIN iam.outbox_events AS event
      ON event.id = projection.outbox_event_id
     AND event.aggregate_type = 'carbon'
     AND event.event_type = 'carbon.updated.v1'
    JOIN iam.applications AS application
      ON application.id = projection.application_id
     AND application.review_status = 'verified'
     AND application.deleted_at IS NULL
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
     AND application_principal.status = 'active'
    JOIN iam.application_webhook_endpoints AS endpoint
      ON endpoint.application_id = application.id
     AND endpoint.status = 'active'
    JOIN LATERAL (
        SELECT candidate.id
        FROM iam.application_webhook_signing_keys AS candidate
        WHERE candidate.application_id = application.id
          AND candidate.endpoint_id = endpoint.id
          AND candidate.status IN ('active', 'retiring')
          AND (
              candidate.retires_at IS NULL
              OR candidate.retires_at > transaction_timestamp()
          )
        ORDER BY (candidate.status = 'active') DESC, candidate.secret_version DESC
        LIMIT 1
    ) AS signing_key ON true
    WHERE projection.outbox_event_id = p_outbox_event_id
    ORDER BY endpoint.id
$$;

CREATE FUNCTION iam_private.get_worker_application_webhook_event_projection(
    p_outbox_event_id uuid,
    p_application_id uuid
)
RETURNS TABLE (
    projection_id uuid,
    payload_ciphertext bytea,
    payload_nonce bytea,
    encryption_key_version smallint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        projection.id,
        projection.payload_ciphertext,
        projection.payload_nonce,
        projection.encryption_key_version
    FROM iam.application_webhook_event_projections AS projection
    JOIN iam.outbox_events AS event
      ON event.id = projection.outbox_event_id
     AND event.aggregate_type = 'carbon'
     AND event.event_type = 'carbon.updated.v1'
    WHERE projection.outbox_event_id = p_outbox_event_id
      AND projection.application_id = p_application_id
$$;

REVOKE ALL ON FUNCTION iam_private.list_worker_captured_application_webhook_recipients(uuid)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.get_worker_application_webhook_event_projection(uuid, uuid)
    FROM PUBLIC;

-- Keep projection retention inside the existing bounded webhook-attempt phase.
-- The previous wrapper becomes an ungranted invoker-rights implementation so
-- the replacement can reuse all existing phase validation and cleanup logic.
ALTER FUNCTION iam_private.run_worker_retention_maintenance(
    text, integer, integer, integer, integer, integer, integer, integer
) RENAME TO run_worker_retention_maintenance_before_profile_projection;

ALTER FUNCTION iam_private.run_worker_retention_maintenance_before_profile_projection(
    text, integer, integer, integer, integer, integer, integer, integer
) SECURITY INVOKER;

REVOKE ALL ON FUNCTION iam_private.run_worker_retention_maintenance_before_profile_projection(
    text, integer, integer, integer, integer, integer, integer, integer
) FROM PUBLIC;

DO $revoke_old_retention_wrapper$
BEGIN
    IF pg_catalog.to_regrole('silicon_iam_worker') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON FUNCTION iam_private.run_worker_retention_maintenance_before_profile_projection(text, integer, integer, integer, integer, integer, integer, integer) FROM silicon_iam_worker';
    END IF;
END;
$revoke_old_retention_wrapper$;

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
    delegated_affected_rows bigint;
    projection_affected_rows bigint := 0;
    projection_limit integer;
    webhook_projection_cutoff timestamptz;
BEGIN
    SELECT result.affected_rows
    INTO STRICT delegated_affected_rows
    FROM iam_private.run_worker_retention_maintenance_before_profile_projection(
        p_phase,
        p_login_history_days,
        p_ephemeral_security_days,
        p_token_metadata_days,
        p_compromised_refresh_days,
        p_webhook_attempt_days,
        p_audit_event_days,
        p_limit
    ) AS result;

    IF p_phase = 'webhook_delivery_attempts' THEN
        projection_limit := p_limit - LEAST(p_limit::bigint, delegated_affected_rows)::integer;
        webhook_projection_cutoff := transaction_timestamp()
            - pg_catalog.make_interval(days => p_webhook_attempt_days);

        IF projection_limit > 0 THEN
            WITH expired AS MATERIALIZED (
                SELECT projection.id
                FROM iam.application_webhook_event_projections AS projection
                JOIN iam.outbox_events AS event ON event.id = projection.outbox_event_id
                WHERE projection.created_at < webhook_projection_cutoff
                  AND event.status IN ('completed', 'dead_letter')
                  AND NOT EXISTS (
                      SELECT 1
                      FROM iam.webhook_deliveries AS delivery
                      WHERE delivery.outbox_event_id = projection.outbox_event_id
                        AND delivery.status IN ('pending', 'processing')
                  )
                ORDER BY projection.created_at, projection.id
                FOR UPDATE OF projection SKIP LOCKED
                LIMIT projection_limit
            )
            DELETE FROM iam.application_webhook_event_projections AS projection
            USING expired
            WHERE projection.id = expired.id;
            GET DIAGNOSTICS projection_affected_rows = ROW_COUNT;
        END IF;
    END IF;

    RETURN QUERY
    SELECT p_phase, delegated_affected_rows + projection_affected_rows;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.run_worker_retention_maintenance(
    text, integer, integer, integer, integer, integer, integer, integer
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.run_worker_retention_maintenance(
    text, integer, integer, integer, integer, integer, integer, integer
) IS
    'Worker-role-only bounded retention transition, including encrypted Application webhook projections in the webhook-attempt phase.';
