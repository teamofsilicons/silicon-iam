-- A WorkOS activation can atomically disable the previously-active connection.
-- Return every connection transition performed by the security-definer boundary
-- so the API can emit one outbox event per actual state change without widening
-- its direct access to webhook receipts or bypassing tenant RLS.

ALTER TABLE iam.sso_connections
    ADD COLUMN version bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT sso_connections_positive_version CHECK (version > 0);

CREATE TRIGGER sso_connections_bump_aggregate_version
BEFORE UPDATE ON iam.sso_connections
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

DROP FUNCTION iam_private.apply_workos_connection_event(
    uuid, text, text, text, uuid, text, text, bytea, timestamptz
);

CREATE FUNCTION iam_private.apply_workos_connection_event(
    p_receipt_id uuid,
    p_provider_event_id text,
    p_event_type text,
    p_provider_organization_id text,
    p_connection_id uuid,
    p_provider_connection_id text,
    p_connection_type text,
    p_payload_digest bytea,
    p_signature_timestamp timestamptz
)
RETURNS TABLE (
    organization_id uuid,
    connection_id uuid,
    connection_version bigint,
    changed boolean,
    status text
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    resolved_organization_id uuid;
    resolved_connection_id uuid;
    resolved_connection_version bigint;
    resolved_status text;
    duplicate_receipt iam.external_webhook_receipts%ROWTYPE;
    inserted_receipt boolean;
    affected_rows bigint;
    target_connection_changed boolean := false;
    deactivated_connection_ids uuid[] := ARRAY[]::uuid[];
    deactivated_connection_id uuid;
BEGIN
    IF p_receipt_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_connection_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR char_length(p_provider_event_id) NOT BETWEEN 1 AND 512
       OR p_event_type NOT IN (
            'connection.activated', 'connection.deactivated', 'connection.deleted'
       )
       OR char_length(p_provider_organization_id) NOT BETWEEN 1 AND 255
       OR char_length(p_provider_connection_id) NOT BETWEEN 1 AND 255
       OR (p_connection_type IS NOT NULL AND char_length(p_connection_type) > 100)
       OR octet_length(p_payload_digest) <> 32
       OR p_signature_timestamp < transaction_timestamp() - interval '5 minutes'
       OR p_signature_timestamp > transaction_timestamp() + interval '1 minute' THEN
        RAISE EXCEPTION 'invalid WorkOS connection event' USING ERRCODE = '22023';
    END IF;

    INSERT INTO iam.external_webhook_receipts (
        id, provider, provider_event_id, payload_digest,
        signature_verified_at, status
    ) VALUES (
        p_receipt_id, 'workos', p_provider_event_id, p_payload_digest,
        p_signature_timestamp, 'processing'
    )
    ON CONFLICT (provider, provider_event_id) DO NOTHING;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    inserted_receipt := affected_rows = 1;

    IF NOT inserted_receipt THEN
        SELECT receipt.*
        INTO duplicate_receipt
        FROM iam.external_webhook_receipts AS receipt
        WHERE receipt.provider = 'workos'
          AND receipt.provider_event_id = p_provider_event_id;

        IF NOT FOUND OR duplicate_receipt.payload_digest <> p_payload_digest THEN
            RAISE EXCEPTION 'WorkOS event identity was reused with different content'
                USING ERRCODE = '23514';
        END IF;

        RETURN QUERY
        SELECT
            config.organization_id,
            connection.id,
            connection.version,
            false,
            COALESCE(connection.status,
                CASE WHEN p_event_type = 'connection.activated'
                    THEN 'active'
                    ELSE 'disabled'
                END)
        FROM iam.organization_sso_configs AS config
        LEFT JOIN iam.sso_connections AS connection
          ON connection.organization_id = config.organization_id
         AND connection.provider_connection_id = p_provider_connection_id
        WHERE config.provider = 'workos'
          AND config.provider_organization_id = p_provider_organization_id;
        RETURN;
    END IF;

    SELECT config.organization_id
    INTO resolved_organization_id
    FROM iam.organization_sso_configs AS config
    JOIN iam.organizations AS organization
      ON organization.id = config.organization_id
     AND organization.status = 'active'
    WHERE config.provider = 'workos'
      AND config.provider_organization_id = p_provider_organization_id
    FOR UPDATE OF config;

    IF NOT FOUND THEN
        UPDATE iam.external_webhook_receipts AS receipt
        SET status = 'ignored', processed_at = transaction_timestamp(),
            attempt_count = receipt.attempt_count + 1
        WHERE receipt.id = p_receipt_id;
        RETURN;
    END IF;

    IF p_event_type = 'connection.activated' THEN
        SELECT COALESCE(
            pg_catalog.array_agg(locked_connection.id ORDER BY locked_connection.id),
            ARRAY[]::uuid[]
        )
        INTO deactivated_connection_ids
        FROM (
            SELECT other_connection.id
            FROM iam.sso_connections AS other_connection
            WHERE other_connection.organization_id = resolved_organization_id
              AND other_connection.provider_connection_id <> p_provider_connection_id
              AND other_connection.status = 'active'
            ORDER BY other_connection.id
            FOR UPDATE OF other_connection
        ) AS locked_connection;

        UPDATE iam.sso_connections AS other_connection
        SET status = 'disabled',
            disabled_at = transaction_timestamp(),
            activated_at = NULL,
            updated_at = transaction_timestamp()
        WHERE other_connection.organization_id = resolved_organization_id
          AND other_connection.id = ANY(deactivated_connection_ids)
          AND other_connection.status = 'active';

        SELECT connection.id
        INTO resolved_connection_id
        FROM iam.sso_connections AS connection
        WHERE connection.provider_connection_id = p_provider_connection_id
        FOR UPDATE OF connection;

        IF FOUND THEN
            IF EXISTS (
                SELECT 1
                FROM iam.sso_connections AS connection
                WHERE connection.id = resolved_connection_id
                  AND connection.organization_id <> resolved_organization_id
            ) THEN
                RAISE EXCEPTION 'WorkOS connection belongs to another organization'
                    USING ERRCODE = '23505';
            END IF;
            UPDATE iam.sso_connections AS connection
            SET connection_type = p_connection_type,
                status = 'active',
                activated_at = COALESCE(connection.activated_at, transaction_timestamp()),
                disabled_at = NULL,
                updated_at = transaction_timestamp()
            WHERE connection.id = resolved_connection_id
              AND (
                  connection.connection_type IS DISTINCT FROM p_connection_type
                  OR connection.status <> 'active'
              );
            target_connection_changed := FOUND;
        ELSE
            INSERT INTO iam.sso_connections (
                id, organization_id, provider_connection_id,
                connection_type, status, activated_at
            ) VALUES (
                p_connection_id,
                resolved_organization_id,
                p_provider_connection_id,
                p_connection_type,
                'active',
                transaction_timestamp()
            )
            RETURNING id INTO resolved_connection_id;
            target_connection_changed := true;
        END IF;

        UPDATE iam.organization_sso_configs AS config
        SET status = CASE WHEN config.platform_enabled THEN 'active' ELSE 'disabled' END,
            last_error_code = NULL
        WHERE config.organization_id = resolved_organization_id
          AND (
              config.status IS DISTINCT FROM
                  CASE WHEN config.platform_enabled THEN 'active' ELSE 'disabled' END
              OR config.last_error_code IS NOT NULL
          );
        resolved_status := 'active';
    ELSE
        SELECT connection.id
        INTO resolved_connection_id
        FROM iam.sso_connections AS connection
        WHERE connection.organization_id = resolved_organization_id
          AND connection.provider_connection_id = p_provider_connection_id
        FOR UPDATE OF connection;

        IF FOUND THEN
            UPDATE iam.sso_connections AS connection
            SET connection_type = COALESCE(p_connection_type, connection.connection_type),
                status = 'disabled',
                activated_at = NULL,
                disabled_at = COALESCE(connection.disabled_at, transaction_timestamp()),
                updated_at = transaction_timestamp()
            WHERE connection.id = resolved_connection_id
              AND (
                  p_event_type = 'connection.deleted'
                  OR connection.status <> 'disabled'
                  OR (
                      p_connection_type IS NOT NULL
                      AND connection.connection_type IS DISTINCT FROM p_connection_type
                  )
              );
            target_connection_changed := FOUND;
        END IF;

        UPDATE iam.organization_sso_configs AS config
        SET status = CASE WHEN config.platform_enabled THEN 'pending' ELSE 'disabled' END,
            last_error_code = NULL
        WHERE config.organization_id = resolved_organization_id
          AND (
              config.status IS DISTINCT FROM
                  CASE WHEN config.platform_enabled THEN 'pending' ELSE 'disabled' END
              OR config.last_error_code IS NOT NULL
          );
        resolved_status := 'disabled';
    END IF;

    UPDATE iam.external_webhook_receipts AS receipt
    SET status = 'processed', processed_at = transaction_timestamp(),
        attempt_count = receipt.attempt_count + 1
    WHERE receipt.id = p_receipt_id;

    organization_id := resolved_organization_id;

    IF p_event_type = 'connection.activated' THEN
        IF target_connection_changed THEN
            SELECT connection.version
            INTO resolved_connection_version
            FROM iam.sso_connections AS connection
            WHERE connection.id = resolved_connection_id;
            connection_id := resolved_connection_id;
            connection_version := resolved_connection_version;
            changed := true;
            status := 'active';
            RETURN NEXT;
        END IF;

        FOREACH deactivated_connection_id IN ARRAY deactivated_connection_ids
        LOOP
            SELECT connection.version
            INTO resolved_connection_version
            FROM iam.sso_connections AS connection
            WHERE connection.id = deactivated_connection_id;
            connection_id := deactivated_connection_id;
            connection_version := resolved_connection_version;
            changed := true;
            status := 'disabled';
            RETURN NEXT;
        END LOOP;

        IF NOT target_connection_changed
           AND pg_catalog.cardinality(deactivated_connection_ids) = 0 THEN
            SELECT connection.version
            INTO resolved_connection_version
            FROM iam.sso_connections AS connection
            WHERE connection.id = resolved_connection_id;
            connection_id := resolved_connection_id;
            connection_version := resolved_connection_version;
            changed := false;
            status := resolved_status;
            RETURN NEXT;
        END IF;
    ELSE
        SELECT connection.version
        INTO resolved_connection_version
        FROM iam.sso_connections AS connection
        WHERE connection.id = resolved_connection_id;
        connection_id := resolved_connection_id;
        connection_version := resolved_connection_version;
        changed := target_connection_changed;
        status := resolved_status;
        RETURN NEXT;
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.apply_workos_connection_event(
    uuid, text, text, text, uuid, text, text, bytea, timestamptz
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.apply_workos_connection_event(
    uuid, text, text, text, uuid, text, text, bytea, timestamptz
) IS
    'Applies one idempotent WorkOS connection event and returns the target transition first, followed by each implicitly deactivated connection in deterministic UUID order.';
