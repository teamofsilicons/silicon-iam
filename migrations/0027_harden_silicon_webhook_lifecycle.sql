-- Harden configurable Silicon webhook lifecycle operations without rewriting
-- the already-applied base migration.

ALTER TABLE iam.silicon_webhook_subscription_topics
    DROP CONSTRAINT silicon_webhook_subscription_topics_subscription_fk,
    ADD CONSTRAINT silicon_webhook_subscription_topics_subscription_fk
        FOREIGN KEY (subscription_id)
        REFERENCES iam.silicon_webhook_subscriptions (id)
        ON DELETE CASCADE;

CREATE FUNCTION iam_private.lock_silicon_webhook_target(
    p_organization_id uuid,
    p_global_silicon_id text
)
RETURNS TABLE (
    principal_id uuid,
    membership_id uuid,
    silicon_id text,
    status text
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT
        silicon.id,
        silicon.membership_id,
        silicon.global_silicon_id,
        CASE
            WHEN silicon.provisioning_status <> 'deleted'
             AND membership.status = 'active'
            THEN 'active'
            ELSE 'removed'
        END
    FROM iam.silicons AS silicon
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = silicon.organization_id
     AND membership.id = silicon.membership_id
    WHERE p_organization_id IS NOT DISTINCT FROM iam_private.current_organization_id()
      AND silicon.organization_id = p_organization_id
      AND silicon.global_silicon_id = p_global_silicon_id
      AND (
          silicon.id = iam_private.current_principal_id()
          OR iam_private.has_organization_capability(
              p_organization_id,
              iam_private.current_principal_id(),
              'silicons.update_directory'
          )
      )
    LIMIT 1
    FOR UPDATE OF silicon, membership
$$;

COMMENT ON FUNCTION iam_private.lock_silicon_webhook_target(uuid, text) IS
    'Attests self-or-directory-manager authority, locks one Silicon and membership in the shared webhook/removal order, and returns its current lifecycle projection.';

CREATE FUNCTION iam_private.lock_silicon_webhook_delivery_scope(
    p_endpoint_id uuid
)
RETURNS void
LANGUAGE sql
VOLATILE
SET search_path = pg_catalog
AS $$
    SELECT pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'iam:silicon-webhook-delivery:' || p_endpoint_id::text,
            0
        )
    )
$$;

COMMENT ON FUNCTION iam_private.lock_silicon_webhook_delivery_scope(uuid) IS
    'Serializes recipient expansion with endpoint/subscription removal or replacement for one stable endpoint ID; callers must hold it through insert or cancellation commit.';

CREATE FUNCTION iam_private.cancel_silicon_webhook_deliveries(
    p_organization_id uuid,
    p_endpoint_id uuid,
    p_reason text
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    endpoint_silicon_id uuid;
    cancelled_count bigint;
BEGIN
    IF p_organization_id IS DISTINCT FROM iam_private.current_organization_id()
       OR p_reason IS NULL
       OR p_reason !~ '^[a-z][a-z0-9_]{2,63}$' THEN
        RAISE EXCEPTION 'Silicon webhook delivery cancellation is not authorized'
            USING ERRCODE = '42501';
    END IF;

    SELECT endpoint.silicon_id
    INTO endpoint_silicon_id
    FROM iam.silicon_webhook_endpoints AS endpoint
    WHERE endpoint.organization_id = p_organization_id
      AND endpoint.id = p_endpoint_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Silicon webhook endpoint is unavailable'
            USING ERRCODE = 'P0002';
    END IF;

    IF endpoint_silicon_id IS DISTINCT FROM iam_private.current_principal_id()
       AND NOT iam_private.has_organization_capability(
           p_organization_id,
           iam_private.current_principal_id(),
           'silicons.update_directory'
       ) THEN
        RAISE EXCEPTION 'Silicon webhook delivery cancellation is not authorized'
            USING ERRCODE = '42501';
    END IF;

    UPDATE iam.webhook_deliveries AS delivery
    SET status = 'cancelled',
        lease_owner = NULL,
        lease_expires_at = NULL,
        last_error_code = p_reason
    FROM iam.outbox_event_recipients AS recipient
    WHERE recipient.outbox_event_id = delivery.outbox_event_id
      AND recipient.id = delivery.recipient_id
      AND recipient.recipient_kind = 'silicon_webhook'
      AND recipient.silicon_webhook_endpoint_id = p_endpoint_id
      AND delivery.status IN ('pending', 'processing');

    GET DIAGNOSTICS cancelled_count = ROW_COUNT;
    RETURN cancelled_count;
END;
$$;

COMMENT ON FUNCTION iam_private.cancel_silicon_webhook_deliveries(uuid, uuid, text) IS
    'Cancels queued deliveries for one endpoint after attesting tenant context and self-or-directory-manager authority.';

CREATE FUNCTION iam_private.deactivate_silicon_webhook_for_removal(
    p_organization_id uuid,
    p_silicon_id uuid
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    resolved_endpoint_id uuid;
    cancelled_count bigint := 0;
BEGIN
    IF p_organization_id IS DISTINCT FROM iam_private.current_organization_id()
       OR NOT iam_private.has_organization_capability(
           p_organization_id,
           iam_private.current_principal_id(),
           'silicons.remove'
       ) THEN
        RAISE EXCEPTION 'Silicon webhook removal deactivation is not authorized'
            USING ERRCODE = '42501';
    END IF;

    -- Webhook mutations take this same target lock before they inspect or create
    -- endpoint state. Holding it through membership removal prevents a concurrent
    -- configuration transaction from reviving a webhook for a removed Silicon.
    PERFORM silicon.id
    FROM iam.silicons AS silicon
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = silicon.organization_id
     AND membership.id = silicon.membership_id
    WHERE silicon.organization_id = p_organization_id
      AND silicon.id = p_silicon_id
    FOR UPDATE OF silicon, membership;

    IF NOT FOUND THEN
        RETURN 0;
    END IF;

    SELECT endpoint.id
    INTO resolved_endpoint_id
    FROM iam.silicon_webhook_endpoints AS endpoint
    WHERE endpoint.organization_id = p_organization_id
      AND endpoint.silicon_id = p_silicon_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN 0;
    END IF;

    PERFORM iam_private.lock_silicon_webhook_delivery_scope(resolved_endpoint_id);

    DELETE FROM iam.silicon_webhook_subscriptions AS subscription
    WHERE subscription.organization_id = p_organization_id
      AND subscription.silicon_id = p_silicon_id;

    UPDATE iam.webhook_deliveries AS delivery
    SET status = 'cancelled',
        lease_owner = NULL,
        lease_expires_at = NULL,
        last_error_code = 'silicon_removed'
    FROM iam.outbox_event_recipients AS recipient
    WHERE recipient.outbox_event_id = delivery.outbox_event_id
      AND recipient.id = delivery.recipient_id
      AND recipient.recipient_kind = 'silicon_webhook'
      AND recipient.silicon_webhook_endpoint_id = resolved_endpoint_id
      AND delivery.status IN ('pending', 'processing');

    GET DIAGNOSTICS cancelled_count = ROW_COUNT;

    UPDATE iam.silicon_webhook_signing_keys AS signing_key
    SET status = 'retired',
        retires_at = NULL,
        retired_at = transaction_timestamp()
    WHERE signing_key.organization_id = p_organization_id
      AND signing_key.silicon_id = p_silicon_id
      AND signing_key.status IN ('active', 'retiring');

    UPDATE iam.silicon_webhook_endpoints AS endpoint
    SET status = 'disabled',
        disabled_at = transaction_timestamp()
    WHERE endpoint.organization_id = p_organization_id
      AND endpoint.id = resolved_endpoint_id
      AND endpoint.status = 'active';

    RETURN cancelled_count;
END;
$$;

COMMENT ON FUNCTION iam_private.deactivate_silicon_webhook_for_removal(uuid, uuid) IS
    'Atomically removes a Silicon subscription, cancels queued deliveries, retires keys, and disables its endpoint after attesting silicons.remove authority.';

REVOKE ALL ON FUNCTION iam_private.cancel_silicon_webhook_deliveries(uuid, uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.deactivate_silicon_webhook_for_removal(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.lock_silicon_webhook_target(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.lock_silicon_webhook_delivery_scope(uuid) FROM PUBLIC;

