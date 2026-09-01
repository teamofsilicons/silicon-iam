-- An optional Silicon webhook tag filter always includes the subscriber's own
-- event-time tags and can add an explicit, tenant-scoped set of extra tags.

ALTER TABLE iam.silicon_webhook_subscriptions
    RENAME COLUMN own_tags_only TO tag_filter_enabled;

ALTER TABLE iam.silicon_webhook_subscriptions
    ADD CONSTRAINT silicon_webhook_subscriptions_organization_id_id_key
        UNIQUE (organization_id, id);

CREATE TABLE iam.silicon_webhook_subscription_extra_tags (
    organization_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    tag_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (subscription_id, tag_id),
    CONSTRAINT silicon_webhook_subscription_extra_tags_subscription_fk
        FOREIGN KEY (organization_id, subscription_id)
        REFERENCES iam.silicon_webhook_subscriptions (organization_id, id)
        ON DELETE CASCADE,
    CONSTRAINT silicon_webhook_subscription_extra_tags_tag_fk
        FOREIGN KEY (organization_id, tag_id)
        REFERENCES iam.organization_tags (organization_id, id)
        ON DELETE RESTRICT
);

COMMENT ON COLUMN iam.silicon_webhook_subscriptions.tag_filter_enabled IS
    'When true, member-scoped events must match the Silicon own-tag snapshot or an explicit additional subscription tag.';
COMMENT ON TABLE iam.silicon_webhook_subscription_extra_tags IS
    'Additional active organization tags included alongside a Silicon subscriber own tags.';

ALTER TABLE iam.silicon_webhook_subscription_extra_tags ENABLE ROW LEVEL SECURITY;

CREATE POLICY silicon_webhook_subscription_extra_tags_manage
ON iam.silicon_webhook_subscription_extra_tags
USING (
    organization_id = iam_private.current_organization_id()
    AND EXISTS (
        SELECT 1
        FROM iam.silicon_webhook_subscriptions AS subscription
        WHERE subscription.organization_id = silicon_webhook_subscription_extra_tags.organization_id
          AND subscription.id = silicon_webhook_subscription_extra_tags.subscription_id
          AND (
              subscription.silicon_id = iam_private.current_principal_id()
              OR iam_private.has_organization_capability(
                  subscription.organization_id,
                  iam_private.current_principal_id(),
                  'silicons.update_directory'
              )
          )
    )
)
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND EXISTS (
        SELECT 1
        FROM iam.silicon_webhook_subscriptions AS subscription
        WHERE subscription.organization_id = silicon_webhook_subscription_extra_tags.organization_id
          AND subscription.id = silicon_webhook_subscription_extra_tags.subscription_id
          AND (
              subscription.silicon_id = iam_private.current_principal_id()
              OR iam_private.has_organization_capability(
                  subscription.organization_id,
                  iam_private.current_principal_id(),
                  'silicons.update_directory'
              )
          )
    )
);

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
          NOT subscription.tag_filter_enabled
          OR (
              NOT event.organization_wide
              AND (
                  EXISTS (
                      SELECT 1
                      FROM iam.outbox_event_own_tag_memberships AS own_tag_audience
                      WHERE own_tag_audience.outbox_event_id = event.id
                        AND own_tag_audience.membership_id = silicon.membership_id
                  )
                  OR EXISTS (
                      SELECT 1
                      FROM iam.outbox_event_affected_tags AS affected_tag
                      JOIN iam.silicon_webhook_subscription_extra_tags AS extra_tag
                        ON extra_tag.subscription_id = subscription.id
                       AND extra_tag.organization_id = subscription.organization_id
                       AND extra_tag.tag_id = affected_tag.tag_id
                      JOIN iam.organization_tags AS configured_tag
                        ON configured_tag.organization_id = extra_tag.organization_id
                       AND configured_tag.id = extra_tag.tag_id
                       AND configured_tag.status = 'active'
                      WHERE affected_tag.outbox_event_id = event.id
                  )
              )
          )
      )
    ORDER BY endpoint.id
$$;

REVOKE ALL ON FUNCTION iam_private.list_worker_silicon_webhook_recipients(uuid)
    FROM PUBLIC;

COMMENT ON FUNCTION iam_private.list_worker_silicon_webhook_recipients(uuid) IS
    'Returns currently authorized recipients for explicitly routed events; optional tag filtering matches immutable own-tag audience or current additional subscription tags.';
