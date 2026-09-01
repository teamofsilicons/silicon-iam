-- Versioned, recipient-safe manual replay of dead-letter webhook deliveries.

ALTER TABLE iam.webhook_deliveries
    ADD COLUMN version bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT webhook_deliveries_positive_version CHECK (version > 0);

CREATE TRIGGER webhook_deliveries_bump_version
BEFORE UPDATE ON iam.webhook_deliveries
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE INDEX webhook_deliveries_dead_letter_idx
    ON iam.webhook_deliveries (dead_lettered_at DESC, id DESC)
    WHERE status = 'dead_letter';

CREATE FUNCTION iam_private.resolve_silicon_webhook_replay_target(
    p_outbox_event_id uuid,
    p_organization_id uuid,
    p_silicon_id uuid
)
RETURNS TABLE (
    endpoint_id uuid,
    signing_key_id uuid
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF iam_private.current_principal_id() IS NULL
       OR NOT (
           iam_private.current_principal_id() = p_silicon_id
           OR iam_private.has_organization_capability(
               p_organization_id,
               iam_private.current_principal_id(),
               'silicons.update_directory'
           )
       ) THEN
        RAISE EXCEPTION 'silicon webhook replay target access denied'
            USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT recipient.endpoint_id, recipient.signing_key_id
    FROM iam_private.list_worker_silicon_webhook_recipients(p_outbox_event_id) AS recipient
    JOIN iam.silicon_webhook_endpoints AS endpoint
      ON endpoint.id = recipient.endpoint_id
     AND endpoint.organization_id = p_organization_id
     AND endpoint.silicon_id = p_silicon_id
    WHERE recipient.silicon_id = p_silicon_id
    ORDER BY recipient.endpoint_id
    LIMIT 1;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.resolve_silicon_webhook_replay_target(
    uuid, uuid, uuid
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.resolve_silicon_webhook_replay_target(uuid, uuid, uuid) IS
    'API-only resolver that rechecks the current Silicon subscription and returns only its current active endpoint and signing-key identifiers for an existing event.';
