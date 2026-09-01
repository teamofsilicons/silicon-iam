-- Subscriber-managed Silicon webhooks and normalized, private outbox routing metadata.

ALTER TABLE iam.outbox_events
    ADD COLUMN affected_membership_id uuid,
    ADD COLUMN organization_wide boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT outbox_events_affected_membership_fk
        FOREIGN KEY (organization_id, affected_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT outbox_events_affected_membership_tenant
        CHECK (affected_membership_id IS NULL OR organization_id IS NOT NULL),
    ADD CONSTRAINT outbox_events_organization_wide_tenant
        CHECK (NOT organization_wide OR organization_id IS NOT NULL);

COMMENT ON COLUMN iam.outbox_events.affected_membership_id IS
    'Private routing metadata identifying the membership affected by an organization event; never serialized into a webhook payload.';
COMMENT ON COLUMN iam.outbox_events.organization_wide IS
    'Private routing metadata marking an event as organization-wide and therefore unattributable to a membership tag; never serialized into a webhook payload.';

CREATE TABLE iam.outbox_event_topics (
    outbox_event_id uuid NOT NULL,
    topic text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (outbox_event_id, topic),
    CONSTRAINT outbox_event_topics_event_fk
        FOREIGN KEY (outbox_event_id) REFERENCES iam.outbox_events (id) ON DELETE RESTRICT,
    CONSTRAINT outbox_event_topics_topic CHECK (
        topic IN ('membership_lifecycle', 'member_updates', 'trust_updates')
    )
);

COMMENT ON TABLE iam.outbox_event_topics IS
    'Private normalized Silicon-subscription topics for an outbox event. Rows control routing only and are never serialized into webhook payloads.';

CREATE INDEX outbox_event_topics_topic_idx
    ON iam.outbox_event_topics (topic, outbox_event_id);

CREATE TABLE iam.outbox_event_affected_tags (
    outbox_event_id uuid NOT NULL,
    tag_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (outbox_event_id, tag_id),
    CONSTRAINT outbox_event_affected_tags_event_fk
        FOREIGN KEY (outbox_event_id) REFERENCES iam.outbox_events (id) ON DELETE RESTRICT,
    CONSTRAINT outbox_event_affected_tags_tag_fk
        FOREIGN KEY (tag_id) REFERENCES iam.organization_tags (id) ON DELETE RESTRICT
);

COMMENT ON TABLE iam.outbox_event_affected_tags IS
    'Private before/after tag union used only to route own-tags-only Silicon subscriptions. These identifiers never enter webhook payloads.';

CREATE INDEX outbox_event_affected_tags_tag_idx
    ON iam.outbox_event_affected_tags (tag_id, outbox_event_id);

CREATE FUNCTION iam_private.assert_outbox_event_affected_tag_tenant()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    event_organization_id uuid;
    tag_organization_id uuid;
BEGIN
    SELECT event.organization_id
    INTO event_organization_id
    FROM iam.outbox_events AS event
    WHERE event.id = NEW.outbox_event_id;

    SELECT tag.organization_id
    INTO tag_organization_id
    FROM iam.organization_tags AS tag
    WHERE tag.id = NEW.tag_id;

    IF event_organization_id IS NULL
       OR tag_organization_id IS NULL
       OR event_organization_id <> tag_organization_id THEN
        RAISE EXCEPTION 'outbox affected tag must belong to the event organization'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER outbox_event_affected_tags_tenant
AFTER INSERT OR UPDATE ON iam.outbox_event_affected_tags
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.assert_outbox_event_affected_tag_tenant();

CREATE TABLE iam.silicon_webhook_endpoints (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    silicon_id uuid NOT NULL,
    url_ciphertext bytea NOT NULL,
    url_nonce bytea NOT NULL,
    encryption_key_version smallint NOT NULL,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    url_digest bytea NOT NULL,
    status text NOT NULL DEFAULT 'active',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    disabled_at timestamptz,
    UNIQUE (organization_id, silicon_id),
    UNIQUE (organization_id, silicon_id, id),
    CONSTRAINT silicon_webhook_endpoints_silicon_fk
        FOREIGN KEY (organization_id, silicon_id)
        REFERENCES iam.silicons (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_webhook_endpoints_encryption_key_fk
        FOREIGN KEY (encryption_purpose, encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_webhook_endpoints_url_ciphertext_length
        CHECK (octet_length(url_ciphertext) BETWEEN 17 AND 8192),
    CONSTRAINT silicon_webhook_endpoints_url_nonce_length
        CHECK (octet_length(url_nonce) BETWEEN 12 AND 32),
    CONSTRAINT silicon_webhook_endpoints_url_digest_length
        CHECK (octet_length(url_digest) = 32),
    CONSTRAINT silicon_webhook_endpoints_status
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT silicon_webhook_endpoints_status_consistency
        CHECK ((status = 'disabled') = (disabled_at IS NOT NULL)),
    CONSTRAINT silicon_webhook_endpoints_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.silicon_webhook_endpoints IS
    'One subscriber-managed, encrypted webhook endpoint per Silicon. Disabled rows retain non-secret routing identity and encrypted URL history.';

CREATE TRIGGER silicon_webhook_endpoints_bump_version
BEFORE UPDATE ON iam.silicon_webhook_endpoints
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE TABLE iam.silicon_webhook_signing_keys (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    silicon_id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    secret_version bigint NOT NULL,
    key_prefix text NOT NULL,
    secret_ciphertext bytea NOT NULL,
    secret_nonce bytea NOT NULL,
    encryption_key_version smallint NOT NULL,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    retires_at timestamptz,
    retired_at timestamptz,
    UNIQUE (endpoint_id, id),
    UNIQUE (silicon_id, secret_version),
    CONSTRAINT silicon_webhook_signing_keys_endpoint_fk
        FOREIGN KEY (organization_id, silicon_id, endpoint_id)
        REFERENCES iam.silicon_webhook_endpoints (organization_id, silicon_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_webhook_signing_keys_encryption_key_fk
        FOREIGN KEY (encryption_purpose, encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_webhook_signing_keys_prefix_format
        CHECK (key_prefix ~ '^swhs_[A-Za-z0-9_-]{7}$'),
    CONSTRAINT silicon_webhook_signing_keys_ciphertext_length
        CHECK (octet_length(secret_ciphertext) BETWEEN 17 AND 8192),
    CONSTRAINT silicon_webhook_signing_keys_nonce_length
        CHECK (octet_length(secret_nonce) BETWEEN 12 AND 32),
    CONSTRAINT silicon_webhook_signing_keys_positive_version CHECK (secret_version > 0),
    CONSTRAINT silicon_webhook_signing_keys_status
        CHECK (status IN ('active', 'retiring', 'retired', 'compromised')),
    CONSTRAINT silicon_webhook_signing_keys_retirement_consistency CHECK (
        (status IN ('retired', 'compromised')) = (retired_at IS NOT NULL)
        AND (status <> 'retiring' OR retires_at IS NOT NULL)
    )
);

COMMENT ON TABLE iam.silicon_webhook_signing_keys IS
    'Versioned encrypted HMAC signing secrets for subscriber-managed Silicon webhook deliveries. The one-time secret prefix uses swhs_.';

CREATE UNIQUE INDEX silicon_webhook_signing_keys_one_active_idx
    ON iam.silicon_webhook_signing_keys (silicon_id)
    WHERE status = 'active';

CREATE TABLE iam.silicon_webhook_subscriptions (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    silicon_id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    mode text NOT NULL,
    own_tags_only boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (organization_id, silicon_id),
    UNIQUE (endpoint_id),
    UNIQUE (organization_id, silicon_id, id),
    CONSTRAINT silicon_webhook_subscriptions_endpoint_fk
        FOREIGN KEY (organization_id, silicon_id, endpoint_id)
        REFERENCES iam.silicon_webhook_endpoints (organization_id, silicon_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_webhook_subscriptions_mode CHECK (mode IN ('all', 'selected')),
    CONSTRAINT silicon_webhook_subscriptions_positive_version CHECK (version > 0)
);

COMMENT ON TABLE iam.silicon_webhook_subscriptions IS
    'At most one subscription per Silicon. all selects every closed topic; selected requires explicit topic rows. own_tags_only is an orthogonal, fail-closed routing filter.';

CREATE TRIGGER silicon_webhook_subscriptions_bump_version
BEFORE UPDATE ON iam.silicon_webhook_subscriptions
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE TABLE iam.silicon_webhook_subscription_topics (
    subscription_id uuid NOT NULL,
    topic text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (subscription_id, topic),
    CONSTRAINT silicon_webhook_subscription_topics_subscription_fk
        FOREIGN KEY (subscription_id)
        REFERENCES iam.silicon_webhook_subscriptions (id)
        ON DELETE RESTRICT,
    CONSTRAINT silicon_webhook_subscription_topics_topic CHECK (
        topic IN ('membership_lifecycle', 'member_updates', 'trust_updates')
    )
);

COMMENT ON TABLE iam.silicon_webhook_subscription_topics IS
    'Closed, normalized topic selection for Silicon webhook subscriptions in selected mode.';

CREATE INDEX silicon_webhook_subscription_topics_topic_idx
    ON iam.silicon_webhook_subscription_topics (topic, subscription_id);

CREATE FUNCTION iam_private.assert_silicon_webhook_subscription_topics()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    resolved_subscription_id uuid;
    resolved_mode text;
    topic_count integer;
BEGIN
    IF TG_TABLE_NAME = 'silicon_webhook_subscriptions' THEN
        resolved_subscription_id := COALESCE(NEW.id, OLD.id);
    ELSE
        resolved_subscription_id := COALESCE(NEW.subscription_id, OLD.subscription_id);
    END IF;

    SELECT subscription.mode
    INTO resolved_mode
    FROM iam.silicon_webhook_subscriptions AS subscription
    WHERE subscription.id = resolved_subscription_id;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT pg_catalog.count(*)
    INTO topic_count
    FROM iam.silicon_webhook_subscription_topics AS topic
    WHERE topic.subscription_id = resolved_subscription_id;

    IF (resolved_mode = 'all' AND topic_count <> 0)
       OR (resolved_mode = 'selected' AND topic_count = 0) THEN
        RAISE EXCEPTION 'Silicon webhook subscription topics do not match mode %', resolved_mode
            USING ERRCODE = '23514';
    END IF;

    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER silicon_webhook_subscriptions_topic_shape
AFTER INSERT OR UPDATE OF mode ON iam.silicon_webhook_subscriptions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.assert_silicon_webhook_subscription_topics();

CREATE CONSTRAINT TRIGGER silicon_webhook_subscription_topics_shape
AFTER INSERT OR UPDATE OR DELETE ON iam.silicon_webhook_subscription_topics
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.assert_silicon_webhook_subscription_topics();

ALTER TABLE iam.outbox_event_recipients
    ADD COLUMN silicon_webhook_endpoint_id uuid,
    DROP CONSTRAINT outbox_event_recipients_shape,
    ADD CONSTRAINT outbox_event_recipients_silicon_webhook_endpoint_fk
        FOREIGN KEY (silicon_webhook_endpoint_id)
        REFERENCES iam.silicon_webhook_endpoints (id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT outbox_event_recipients_shape CHECK (
        (recipient_kind = 'application'
            AND application_webhook_endpoint_id IS NOT NULL
            AND silicon_hook_id IS NULL
            AND silicon_webhook_endpoint_id IS NULL)
        OR (recipient_kind = 'silicon_hook'
            AND application_webhook_endpoint_id IS NULL
            AND silicon_hook_id IS NOT NULL
            AND silicon_webhook_endpoint_id IS NULL)
        OR (recipient_kind = 'silicon_webhook'
            AND application_webhook_endpoint_id IS NULL
            AND silicon_hook_id IS NULL
            AND silicon_webhook_endpoint_id IS NOT NULL)
    );

CREATE UNIQUE INDEX outbox_event_recipients_silicon_webhook_unique_idx
    ON iam.outbox_event_recipients (outbox_event_id, silicon_webhook_endpoint_id)
    WHERE recipient_kind = 'silicon_webhook';

ALTER TABLE iam.webhook_deliveries
    ADD COLUMN silicon_webhook_signing_key_id uuid,
    ADD CONSTRAINT webhook_deliveries_silicon_webhook_signing_key_fk
        FOREIGN KEY (silicon_webhook_signing_key_id)
        REFERENCES iam.silicon_webhook_signing_keys (id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT webhook_deliveries_signing_key_shape
        CHECK (signing_key_id IS NULL OR silicon_webhook_signing_key_id IS NULL);

CREATE FUNCTION iam_private.list_worker_silicon_webhook_recipients(
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
      AND EXISTS (
          SELECT 1
          FROM iam.outbox_event_topics AS event_topic
          WHERE event_topic.outbox_event_id = event.id
            AND (
                subscription.mode = 'all'
                OR EXISTS (
                    SELECT 1
                    FROM iam.silicon_webhook_subscription_topics AS selected_topic
                    WHERE selected_topic.subscription_id = subscription.id
                      AND selected_topic.topic = event_topic.topic
                )
            )
      )
      AND (
          NOT subscription.own_tags_only
          OR (
              NOT event.organization_wide
              AND EXISTS (
                  SELECT 1
                  FROM iam.outbox_event_affected_tags AS affected_tag
                  JOIN iam.membership_tags AS silicon_tag
                    ON silicon_tag.organization_id = event.organization_id
                   AND silicon_tag.membership_id = silicon.membership_id
                   AND silicon_tag.tag_id = affected_tag.tag_id
                  JOIN iam.organization_tags AS active_tag
                    ON active_tag.organization_id = silicon_tag.organization_id
                   AND active_tag.id = silicon_tag.tag_id
                   AND active_tag.status = 'active'
                  WHERE affected_tag.outbox_event_id = event.id
              )
          )
      )
    ORDER BY endpoint.id
$$;

COMMENT ON FUNCTION iam_private.list_worker_silicon_webhook_recipients(uuid) IS
    'Returns active Silicon webhook recipients for normalized event topics. own_tags_only fails closed for organization-wide, unattributed, or tag-disjoint events.';

CREATE FUNCTION iam_private.get_worker_silicon_webhook_material(
    p_endpoint_id uuid,
    p_signing_key_id uuid
)
RETURNS TABLE (
    organization_id uuid,
    silicon_id uuid,
    url_ciphertext bytea,
    url_nonce bytea,
    url_encryption_key_version smallint,
    secret_ciphertext bytea,
    secret_nonce bytea,
    secret_encryption_key_version smallint,
    secret_version bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        endpoint.organization_id,
        endpoint.silicon_id,
        endpoint.url_ciphertext,
        endpoint.url_nonce,
        endpoint.encryption_key_version,
        signing_key.secret_ciphertext,
        signing_key.secret_nonce,
        signing_key.encryption_key_version,
        signing_key.secret_version
    FROM iam.silicon_webhook_endpoints AS endpoint
    JOIN iam.organizations AS organization
      ON organization.id = endpoint.organization_id
     AND organization.status = 'active'
    JOIN iam.silicon_webhook_signing_keys AS signing_key
      ON signing_key.id = p_signing_key_id
     AND signing_key.organization_id = endpoint.organization_id
     AND signing_key.silicon_id = endpoint.silicon_id
     AND signing_key.endpoint_id = endpoint.id
    JOIN iam.silicons AS silicon
      ON silicon.organization_id = endpoint.organization_id
     AND silicon.id = endpoint.silicon_id
    JOIN iam.principals AS principal
      ON principal.id = silicon.id
     AND principal.kind = 'silicon'
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = silicon.organization_id
     AND membership.id = silicon.membership_id
     AND membership.principal_id = silicon.id
     AND membership.principal_kind = 'silicon'
    WHERE endpoint.id = p_endpoint_id
      AND endpoint.status = 'active'
      AND signing_key.status IN ('active', 'retiring')
      AND (signing_key.retires_at IS NULL
          OR signing_key.retires_at > transaction_timestamp())
      AND silicon.provisioning_status = 'active'
      AND principal.status = 'active'
      AND membership.status = 'active'
$$;

COMMENT ON FUNCTION iam_private.get_worker_silicon_webhook_material(uuid, uuid) IS
    'Narrow worker-only reader for encrypted Silicon webhook URL and signing material.';

REVOKE ALL ON FUNCTION iam_private.list_worker_silicon_webhook_recipients(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.get_worker_silicon_webhook_material(uuid, uuid) FROM PUBLIC;

ALTER TABLE iam.silicon_webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.silicon_webhook_signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.silicon_webhook_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.silicon_webhook_subscription_topics ENABLE ROW LEVEL SECURITY;

ALTER TABLE iam.silicons
    ALTER COLUMN provisioning_status SET DEFAULT 'active';

CREATE POLICY silicon_webhook_endpoints_manage
ON iam.silicon_webhook_endpoints
USING (
    organization_id = iam_private.current_organization_id()
    AND (
        silicon_id = iam_private.current_principal_id()
        OR iam_private.has_organization_capability(
            organization_id,
            iam_private.current_principal_id(),
            'silicons.update_directory'
        )
    )
)
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND (
        silicon_id = iam_private.current_principal_id()
        OR iam_private.has_organization_capability(
            organization_id,
            iam_private.current_principal_id(),
            'silicons.update_directory'
        )
    )
);

CREATE POLICY silicon_webhook_endpoints_platform_delivery_select
ON iam.silicon_webhook_endpoints FOR SELECT
USING (
    iam_private.has_platform_capability(
        iam_private.current_principal_id(),
        'deliveries.manage'
    )
);

CREATE POLICY silicon_hooks_platform_delivery_select
ON iam.silicon_hooks FOR SELECT
USING (
    iam_private.has_platform_capability(
        iam_private.current_principal_id(),
        'deliveries.manage'
    )
);

CREATE POLICY application_webhook_endpoints_platform_delivery_select
ON iam.application_webhook_endpoints FOR SELECT
USING (
    iam_private.has_platform_capability(
        iam_private.current_principal_id(),
        'deliveries.manage'
    )
);

CREATE POLICY silicon_webhook_signing_keys_manage
ON iam.silicon_webhook_signing_keys
USING (
    organization_id = iam_private.current_organization_id()
    AND (
        silicon_id = iam_private.current_principal_id()
        OR iam_private.has_organization_capability(
            organization_id,
            iam_private.current_principal_id(),
            'silicons.update_directory'
        )
    )
)
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND (
        silicon_id = iam_private.current_principal_id()
        OR iam_private.has_organization_capability(
            organization_id,
            iam_private.current_principal_id(),
            'silicons.update_directory'
        )
    )
);

CREATE POLICY silicon_webhook_subscriptions_manage
ON iam.silicon_webhook_subscriptions
USING (
    organization_id = iam_private.current_organization_id()
    AND (
        silicon_id = iam_private.current_principal_id()
        OR iam_private.has_organization_capability(
            organization_id,
            iam_private.current_principal_id(),
            'silicons.update_directory'
        )
    )
)
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND (
        silicon_id = iam_private.current_principal_id()
        OR iam_private.has_organization_capability(
            organization_id,
            iam_private.current_principal_id(),
            'silicons.update_directory'
        )
    )
);

CREATE POLICY silicon_webhook_subscription_topics_manage
ON iam.silicon_webhook_subscription_topics
USING (
    EXISTS (
        SELECT 1
        FROM iam.silicon_webhook_subscriptions AS subscription
        WHERE subscription.id = silicon_webhook_subscription_topics.subscription_id
          AND subscription.organization_id = iam_private.current_organization_id()
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
    EXISTS (
        SELECT 1
        FROM iam.silicon_webhook_subscriptions AS subscription
        WHERE subscription.id = silicon_webhook_subscription_topics.subscription_id
          AND subscription.organization_id = iam_private.current_organization_id()
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

-- Provider-managed Silicon Hooks are retained only so existing foreign keys and
-- immutable delivery history remain valid. New Silicon identities no longer wait
-- for provider provisioning, and all in-flight legacy delivery work is cancelled.
UPDATE iam.principals AS principal
SET status = 'active',
    activated_at = COALESCE(principal.activated_at, transaction_timestamp())
FROM iam.silicons AS silicon
WHERE silicon.id = principal.id
  AND principal.kind = 'silicon'
  AND principal.status = 'provisioning'
  AND silicon.provisioning_status IN ('pending_hook', 'hook_error');

UPDATE iam.silicons AS silicon
SET provisioning_status = 'active'
WHERE silicon.provisioning_status IN ('pending_hook', 'hook_error');

UPDATE iam.silicon_hooks AS hook
SET status = 'disabled',
    last_error_code = NULL,
    next_attempt_at = NULL,
    lease_owner = NULL,
    lease_expires_at = NULL
WHERE hook.status <> 'disabled';

UPDATE iam.webhook_deliveries AS delivery
SET status = 'cancelled',
    lease_owner = NULL,
    lease_expires_at = NULL,
    last_error_code = 'legacy_silicon_hook_disabled'
FROM iam.outbox_event_recipients AS recipient
WHERE recipient.outbox_event_id = delivery.outbox_event_id
  AND recipient.id = delivery.recipient_id
  AND recipient.recipient_kind = 'silicon_hook'
  AND delivery.status IN ('pending', 'processing');
