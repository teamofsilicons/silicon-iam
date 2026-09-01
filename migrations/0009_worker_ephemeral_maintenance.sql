-- Bounded, least-privilege cleanup of expired ephemeral security state.

CREATE INDEX idempotency_secret_response_expiry_idx
    ON iam.idempotency_records (response_expires_at, id)
    WHERE contains_one_time_secret AND response_ciphertext IS NOT NULL;

CREATE FUNCTION iam_private.run_worker_ephemeral_maintenance(p_limit integer)
RETURNS TABLE (
    erased_secret_responses bigint,
    deleted_idempotency_records bigint,
    deleted_rate_limit_buckets bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
BEGIN
    IF p_limit < 1 OR p_limit > 10000 THEN
        RAISE EXCEPTION 'maintenance batch limit must be between 1 and 10000'
            USING ERRCODE = '22023';
    END IF;

    WITH expired AS MATERIALIZED (
        SELECT record.id
        FROM iam.idempotency_records AS record
        WHERE record.contains_one_time_secret
          AND record.response_expires_at <= transaction_timestamp()
          AND record.response_ciphertext IS NOT NULL
        ORDER BY record.response_expires_at, record.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    )
    UPDATE iam.idempotency_records AS record
    SET status = 'expired',
        lease_owner = NULL,
        lease_expires_at = NULL,
        response_status = NULL,
        response_ciphertext = NULL,
        response_nonce = NULL,
        encryption_key_version = NULL,
        response_expires_at = NULL
    FROM expired
    WHERE record.id = expired.id;
    GET DIAGNOSTICS erased_secret_responses = ROW_COUNT;

    WITH expired AS MATERIALIZED (
        SELECT record.id
        FROM iam.idempotency_records AS record
        WHERE record.expires_at <= transaction_timestamp()
        ORDER BY record.expires_at, record.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    )
    DELETE FROM iam.idempotency_records AS record
    USING expired
    WHERE record.id = expired.id;
    GET DIAGNOSTICS deleted_idempotency_records = ROW_COUNT;

    WITH expired AS MATERIALIZED (
        SELECT
            bucket.scope_digest,
            bucket.limit_name,
            bucket.window_started_at
        FROM iam.rate_limit_buckets AS bucket
        WHERE bucket.expires_at <= transaction_timestamp()
        ORDER BY
            bucket.expires_at,
            bucket.scope_digest,
            bucket.limit_name,
            bucket.window_started_at
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    )
    DELETE FROM iam.rate_limit_buckets AS bucket
    USING expired
    WHERE bucket.scope_digest = expired.scope_digest
      AND bucket.limit_name = expired.limit_name
      AND bucket.window_started_at = expired.window_started_at;
    GET DIAGNOSTICS deleted_rate_limit_buckets = ROW_COUNT;

    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.run_worker_ephemeral_maintenance(integer) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.run_worker_ephemeral_maintenance(integer) IS
    'Worker-only bounded cleanup that hides replayable idempotency ciphertext from the worker role.';
