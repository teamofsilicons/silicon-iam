-- Make Full Silicon subscriptions distinct from the three selected topics.
-- Empty topics mean an explicitly routed Full-only organization event; they
-- must never be confused with an outbox event that has no Silicon audience.

ALTER TABLE iam.outbox_events
    ADD COLUMN silicon_webhook_routable boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT outbox_events_silicon_webhook_routable_tenant
        CHECK (NOT silicon_webhook_routable OR organization_id IS NOT NULL);

UPDATE iam.outbox_events AS event
SET silicon_webhook_routable = true
WHERE event.organization_id IS NOT NULL
  AND (
      event.affected_membership_id IS NOT NULL
      OR event.organization_wide
      OR EXISTS (
          SELECT 1
          FROM iam.outbox_event_topics AS event_topic
          WHERE event_topic.outbox_event_id = event.id
      )
  );

COMMENT ON COLUMN iam.outbox_events.silicon_webhook_routable IS
    'Explicit domain-transaction decision that an organization event belongs to the Silicon webhook audience. Full subscriptions consume every marked event; selected subscriptions still require an exact normalized topic.';

CREATE TABLE iam.outbox_event_own_tag_memberships (
    outbox_event_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (outbox_event_id, membership_id),
    CONSTRAINT outbox_event_own_tag_memberships_event_fk
        FOREIGN KEY (outbox_event_id) REFERENCES iam.outbox_events (id)
        ON DELETE CASCADE,
    CONSTRAINT outbox_event_own_tag_memberships_membership_fk
        FOREIGN KEY (membership_id) REFERENCES iam.organization_memberships (id)
        ON DELETE RESTRICT
);

COMMENT ON TABLE iam.outbox_event_own_tag_memberships IS
    'Immutable event-time Silicon memberships whose own tags intersected the affected member tags immediately before or after the mutation. Delivery revalidates the subscriber but never hydrates later tag assignments.';

CREATE INDEX outbox_event_own_tag_memberships_membership_idx
    ON iam.outbox_event_own_tag_memberships (membership_id, outbox_event_id);

CREATE FUNCTION iam_private.assert_outbox_event_own_tag_membership_tenant()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, iam
AS $$
DECLARE
    event_organization_id uuid;
    membership_organization_id uuid;
BEGIN
    SELECT event.organization_id
    INTO event_organization_id
    FROM iam.outbox_events AS event
    WHERE event.id = NEW.outbox_event_id;

    SELECT membership.organization_id
    INTO membership_organization_id
    FROM iam.organization_memberships AS membership
    WHERE membership.id = NEW.membership_id;

    IF event_organization_id IS NULL
       OR membership_organization_id IS NULL
       OR event_organization_id <> membership_organization_id THEN
        RAISE EXCEPTION 'outbox own-tag membership must belong to the event organization'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.assert_outbox_event_own_tag_membership_tenant()
    FROM PUBLIC;

CREATE CONSTRAINT TRIGGER outbox_event_own_tag_memberships_tenant
AFTER INSERT OR UPDATE ON iam.outbox_event_own_tag_memberships
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.assert_outbox_event_own_tag_membership_tenant();

-- Existing undelivered rows cannot recover a deleted pre-mutation assignment,
-- but their current intersection can be preserved during a rolling deploy.
INSERT INTO iam.outbox_event_own_tag_memberships (outbox_event_id, membership_id)
SELECT DISTINCT event.id, membership.id
FROM iam.outbox_events AS event
JOIN iam.outbox_event_affected_tags AS affected_tag
  ON affected_tag.outbox_event_id = event.id
JOIN iam.membership_tags AS assignment
  ON assignment.tag_id = affected_tag.tag_id
 AND assignment.organization_id = event.organization_id
JOIN iam.organization_memberships AS membership
  ON membership.organization_id = assignment.organization_id
 AND membership.id = assignment.membership_id
 AND membership.principal_kind = 'silicon'
 AND membership.status = 'active'
JOIN iam.silicons AS silicon
  ON silicon.organization_id = membership.organization_id
 AND silicon.membership_id = membership.id
 AND silicon.id = membership.principal_id
 AND silicon.provisioning_status = 'active'
JOIN iam.principals AS principal
  ON principal.id = silicon.id
 AND principal.kind = 'silicon'
 AND principal.status = 'active'
WHERE event.silicon_webhook_routable
  AND NOT event.organization_wide
ON CONFLICT (outbox_event_id, membership_id) DO NOTHING;

CREATE FUNCTION iam_private.lock_silicon_webhook_own_tag_audience(
    p_organization_id uuid,
    p_affected_tag_ids uuid[],
    p_before_membership_ids uuid[]
)
RETURNS TABLE (membership_id uuid)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_actor_id uuid := iam_private.current_principal_id();
BEGIN
    IF p_organization_id IS NULL
       OR p_affected_tag_ids IS NULL
       OR p_before_membership_ids IS NULL
       OR current_actor_id IS NULL
       OR EXISTS (
            SELECT 1 FROM pg_catalog.unnest(p_affected_tag_ids) AS tag_id
            WHERE tag_id IS NULL
       )
       OR EXISTS (
            SELECT 1 FROM pg_catalog.unnest(p_before_membership_ids) AS member_id
            WHERE member_id IS NULL
       )
       OR NOT iam_private.is_active_organization_member(
            p_organization_id, current_actor_id
       ) THEN
        RAISE EXCEPTION 'silicon webhook own-tag audience forbidden'
            USING ERRCODE = '42501';
    END IF;

    -- Serialize the event-time tag snapshot against subscription changes and
    -- governed tag changes, which take an update lock on the target membership.
    PERFORM membership.id
    FROM iam.silicon_webhook_subscriptions AS subscription
    JOIN iam.silicon_webhook_endpoints AS endpoint
      ON endpoint.organization_id = subscription.organization_id
     AND endpoint.silicon_id = subscription.silicon_id
     AND endpoint.id = subscription.endpoint_id
     AND endpoint.status = 'active'
    JOIN iam.silicons AS silicon
      ON silicon.organization_id = endpoint.organization_id
     AND silicon.id = endpoint.silicon_id
     AND silicon.provisioning_status = 'active'
    JOIN iam.principals AS principal
      ON principal.id = silicon.id
     AND principal.kind = 'silicon'
     AND principal.status = 'active'
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = silicon.organization_id
     AND membership.id = silicon.membership_id
     AND membership.principal_id = silicon.id
     AND membership.principal_kind = 'silicon'
     AND membership.status = 'active'
    WHERE subscription.organization_id = p_organization_id
    ORDER BY membership.id
    FOR SHARE OF subscription, endpoint, silicon, principal, membership;

    RETURN QUERY
    SELECT membership.id
    FROM iam.silicon_webhook_subscriptions AS subscription
    JOIN iam.silicon_webhook_endpoints AS endpoint
      ON endpoint.organization_id = subscription.organization_id
     AND endpoint.silicon_id = subscription.silicon_id
     AND endpoint.id = subscription.endpoint_id
     AND endpoint.status = 'active'
    JOIN iam.silicons AS silicon
      ON silicon.organization_id = endpoint.organization_id
     AND silicon.id = endpoint.silicon_id
     AND silicon.provisioning_status = 'active'
    JOIN iam.principals AS principal
      ON principal.id = silicon.id
     AND principal.kind = 'silicon'
     AND principal.status = 'active'
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = silicon.organization_id
     AND membership.id = silicon.membership_id
     AND membership.principal_id = silicon.id
     AND membership.principal_kind = 'silicon'
     AND membership.status = 'active'
    WHERE subscription.organization_id = p_organization_id
      AND (
          membership.id = ANY(p_before_membership_ids)
          OR EXISTS (
              SELECT 1
              FROM iam.membership_tags AS assignment
              JOIN iam.organization_tags AS tag
                ON tag.organization_id = assignment.organization_id
               AND tag.id = assignment.tag_id
               AND tag.status = 'active'
              WHERE assignment.organization_id = membership.organization_id
                AND assignment.membership_id = membership.id
                AND assignment.tag_id = ANY(p_affected_tag_ids)
          )
      )
    ORDER BY membership.id;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.lock_silicon_webhook_own_tag_audience(
    uuid, uuid[], uuid[]
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.lock_silicon_webhook_own_tag_audience(
    uuid, uuid[], uuid[]
) IS
    'Attests an active organization actor, locks active Silicon webhook subscribers in deterministic order, and returns the exact before-or-after own-tag membership audience for immutable outbox capture.';

CREATE OR REPLACE FUNCTION iam_private.list_worker_silicon_webhook_recipients(
    p_outbox_event_id uuid
)
RETURNS TABLE (
    endpoint_id uuid,
    signing_key_id uuid,
    silicon_id uuid
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT endpoint.id, signing_key.id, silicon.id
    FROM iam.outbox_events AS event
    JOIN iam.organizations AS organization
      ON organization.id = event.organization_id
     AND organization.status = 'active'
    JOIN iam.silicon_webhook_endpoints AS endpoint
      ON endpoint.organization_id = event.organization_id
     AND endpoint.status = 'active'
    JOIN iam.silicons AS silicon
      ON silicon.organization_id = endpoint.organization_id
     AND silicon.id = endpoint.silicon_id
     AND silicon.provisioning_status = 'active'
    JOIN iam.principals AS principal
      ON principal.id = silicon.id
     AND principal.kind = 'silicon'
     AND principal.status = 'active'
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = silicon.organization_id
     AND membership.id = silicon.membership_id
     AND membership.principal_id = silicon.id
     AND membership.principal_kind = 'silicon'
     AND membership.status = 'active'
    JOIN iam.silicon_webhook_signing_keys AS signing_key
      ON signing_key.organization_id = endpoint.organization_id
     AND signing_key.silicon_id = endpoint.silicon_id
     AND signing_key.endpoint_id = endpoint.id
     AND signing_key.status = 'active'
    JOIN iam.silicon_webhook_subscriptions AS subscription
      ON subscription.organization_id = endpoint.organization_id
     AND subscription.silicon_id = endpoint.silicon_id
     AND subscription.endpoint_id = endpoint.id
    WHERE event.id = p_outbox_event_id
      AND event.silicon_webhook_routable
      AND (
          subscription.mode = 'all'
          OR (
              subscription.mode = 'selected'
              AND EXISTS (
                  SELECT 1
                  FROM iam.outbox_event_topics AS event_topic
                  JOIN iam.silicon_webhook_subscription_topics AS selected_topic
                    ON selected_topic.subscription_id = subscription.id
                   AND selected_topic.topic = event_topic.topic
                  WHERE event_topic.outbox_event_id = event.id
              )
          )
      )
      AND (
          NOT subscription.own_tags_only
          OR (
              NOT event.organization_wide
              AND EXISTS (
                  SELECT 1
                  FROM iam.outbox_event_own_tag_memberships AS own_tag_audience
                  WHERE own_tag_audience.outbox_event_id = event.id
                    AND own_tag_audience.membership_id = silicon.membership_id
              )
          )
      )
    ORDER BY endpoint.id
$$;

REVOKE ALL ON FUNCTION iam_private.list_worker_silicon_webhook_recipients(uuid)
    FROM PUBLIC;

COMMENT ON FUNCTION iam_private.list_worker_silicon_webhook_recipients(uuid) IS
    'Returns recipients only for explicitly Silicon-routed events. Full mode accepts routed events without a selected topic; selected mode requires an exact topic, and own_tags_only uses only the immutable event-time before/after tag audience while revalidating the subscriber.';
