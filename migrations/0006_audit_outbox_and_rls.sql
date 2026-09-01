-- Append-only security history, transactional outbox, delivery state, idempotency, and RLS backstops.

CREATE TABLE iam.authentication_events (
    id uuid PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    event_type text NOT NULL,
    outcome text NOT NULL,
    subject_principal_id uuid,
    subject_kind iam.principal_kind,
    authentication_session_id uuid,
    application_id uuid,
    organization_id uuid,
    request_id uuid NOT NULL,
    ip_fingerprint bytea,
    user_agent_fingerprint bytea,
    failure_code text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT authentication_events_subject_fk
        FOREIGN KEY (subject_principal_id, subject_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT authentication_events_session_fk
        FOREIGN KEY (authentication_session_id) REFERENCES iam.authentication_sessions (id) ON DELETE RESTRICT,
    CONSTRAINT authentication_events_application_fk
        FOREIGN KEY (application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT authentication_events_organization_fk
        FOREIGN KEY (organization_id) REFERENCES iam.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT authentication_events_type_format
        CHECK (event_type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    CONSTRAINT authentication_events_outcome CHECK (outcome IN ('success', 'failure', 'denied')),
    CONSTRAINT authentication_events_fingerprint_lengths CHECK (
        (ip_fingerprint IS NULL OR octet_length(ip_fingerprint) = 32)
        AND (user_agent_fingerprint IS NULL OR octet_length(user_agent_fingerprint) = 32)
    ),
    CONSTRAINT authentication_events_failure_code_length
        CHECK (failure_code IS NULL OR char_length(failure_code) <= 128),
    CONSTRAINT authentication_events_metadata_object CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT authentication_events_metadata_size
        CHECK (octet_length(metadata::text) <= 16384)
);

COMMENT ON TABLE iam.authentication_events IS
    'Redacted login, token, SSO, and security-event history. Raw identifiers and protocol secrets are prohibited.';

CREATE INDEX authentication_events_subject_idx
    ON iam.authentication_events (subject_principal_id, occurred_at DESC, id);
CREATE INDEX authentication_events_application_idx
    ON iam.authentication_events (application_id, occurred_at DESC, id)
    WHERE application_id IS NOT NULL;
CREATE INDEX authentication_events_organization_idx
    ON iam.authentication_events (organization_id, occurred_at DESC, id)
    WHERE organization_id IS NOT NULL;
CREATE INDEX authentication_events_occurred_brin_idx
    ON iam.authentication_events USING brin (occurred_at);

CREATE TABLE iam.audit_events (
    occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    id uuid NOT NULL,
    global_sequence bigint GENERATED ALWAYS AS IDENTITY,
    request_id uuid NOT NULL,
    correlation_id uuid,
    actor_principal_id uuid,
    actor_kind iam.principal_kind,
    actor_authentication_session_id uuid,
    organization_id uuid,
    application_id uuid,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id uuid,
    result text NOT NULL DEFAULT 'success',
    authentication_method text,
    aggregate_type text,
    aggregate_id uuid,
    aggregate_version bigint,
    before_state jsonb,
    after_state jsonb,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip_fingerprint bytea,
    user_agent_fingerprint bytea,
    PRIMARY KEY (occurred_at, id),
    CONSTRAINT audit_events_actor_fk
        FOREIGN KEY (actor_principal_id, actor_kind)
        REFERENCES iam.principals (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT audit_events_session_fk
        FOREIGN KEY (actor_authentication_session_id)
        REFERENCES iam.authentication_sessions (id)
        ON DELETE RESTRICT,
    CONSTRAINT audit_events_organization_fk
        FOREIGN KEY (organization_id) REFERENCES iam.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT audit_events_application_fk
        FOREIGN KEY (application_id) REFERENCES iam.applications (id) ON DELETE RESTRICT,
    CONSTRAINT audit_events_action_format
        CHECK (action ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    CONSTRAINT audit_events_target_type_format
        CHECK (target_type ~ '^[a-z][a-z0-9_]{1,63}$'),
    CONSTRAINT audit_events_result CHECK (result IN ('success', 'failure', 'denied')),
    CONSTRAINT audit_events_aggregate_binding CHECK (
        (aggregate_type IS NULL AND aggregate_id IS NULL AND aggregate_version IS NULL)
        OR (aggregate_type IS NOT NULL AND aggregate_id IS NOT NULL AND aggregate_version IS NOT NULL)
    ),
    CONSTRAINT audit_events_positive_aggregate_version
        CHECK (aggregate_version IS NULL OR aggregate_version > 0),
    CONSTRAINT audit_events_state_objects CHECK (
        (before_state IS NULL OR jsonb_typeof(before_state) = 'object')
        AND (after_state IS NULL OR jsonb_typeof(after_state) = 'object')
        AND jsonb_typeof(metadata) = 'object'
    ),
    CONSTRAINT audit_events_bounded_payloads CHECK (
        (before_state IS NULL OR octet_length(before_state::text) <= 262144)
        AND (after_state IS NULL OR octet_length(after_state::text) <= 262144)
        AND octet_length(metadata::text) <= 65536
    ),
    CONSTRAINT audit_events_fingerprint_lengths CHECK (
        (ip_fingerprint IS NULL OR octet_length(ip_fingerprint) = 32)
        AND (user_agent_fingerprint IS NULL OR octet_length(user_agent_fingerprint) = 32)
    )
) PARTITION BY RANGE (occurred_at);

CREATE TABLE iam.audit_events_default
    PARTITION OF iam.audit_events DEFAULT;

COMMENT ON TABLE iam.audit_events IS
    'Append-only, redacted security audit history partitioned by occurrence time.';
COMMENT ON COLUMN iam.audit_events.before_state IS
    'Redacted externally meaningful state only; never credentials, OTPs, raw contacts, or provider payloads.';

CREATE INDEX audit_events_org_time_idx
    ON iam.audit_events (organization_id, occurred_at DESC, id);
CREATE INDEX audit_events_actor_time_idx
    ON iam.audit_events (actor_principal_id, occurred_at DESC, id);
CREATE INDEX audit_events_target_time_idx
    ON iam.audit_events (target_type, target_id, occurred_at DESC, id);
CREATE INDEX audit_events_request_idx ON iam.audit_events (request_id);
CREATE INDEX audit_events_occurred_brin_idx ON iam.audit_events USING brin (occurred_at);

CREATE FUNCTION iam_private.reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON iam.audit_events
FOR EACH ROW EXECUTE FUNCTION iam_private.reject_audit_mutation();

CREATE TABLE iam.outbox_events (
    id uuid PRIMARY KEY,
    global_sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    organization_id uuid,
    aggregate_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL,
    event_ordinal smallint NOT NULL DEFAULT 1,
    event_type text NOT NULL,
    schema_version smallint NOT NULL DEFAULT 1,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    lease_owner text,
    lease_expires_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0,
    last_error_code text,
    completed_at timestamptz,
    dead_lettered_at timestamptz,
    UNIQUE (aggregate_type, aggregate_id, aggregate_version, event_ordinal),
    CONSTRAINT outbox_events_organization_fk
        FOREIGN KEY (organization_id) REFERENCES iam.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT outbox_events_aggregate_type_format
        CHECK (aggregate_type ~ '^[a-z][a-z0-9_]{1,63}$'),
    CONSTRAINT outbox_events_positive_aggregate_version CHECK (aggregate_version > 0),
    CONSTRAINT outbox_events_positive_ordinal CHECK (event_ordinal > 0),
    CONSTRAINT outbox_events_event_type_format
        CHECK (event_type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    CONSTRAINT outbox_events_positive_schema_version CHECK (schema_version > 0),
    CONSTRAINT outbox_events_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT outbox_events_payload_size CHECK (octet_length(payload::text) <= 1048576),
    CONSTRAINT outbox_events_status
        CHECK (status IN ('pending', 'processing', 'completed', 'dead_letter')),
    CONSTRAINT outbox_events_nonnegative_attempts CHECK (attempt_count >= 0),
    CONSTRAINT outbox_events_lease_consistency CHECK (
        (lease_owner IS NULL AND lease_expires_at IS NULL)
        OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
    ),
    CONSTRAINT outbox_events_terminal_consistency CHECK (
        (status <> 'completed' OR completed_at IS NOT NULL)
        AND (status <> 'dead_letter' OR dead_lettered_at IS NOT NULL)
    )
);

COMMENT ON TABLE iam.outbox_events IS
    'Transactional minimal event payloads claimed with bounded leases and FOR UPDATE SKIP LOCKED.';

CREATE INDEX outbox_events_claim_idx
    ON iam.outbox_events (available_at, created_at, id)
    WHERE status IN ('pending', 'processing');
CREATE INDEX outbox_events_aggregate_idx
    ON iam.outbox_events (aggregate_type, aggregate_id, aggregate_version, event_ordinal);
CREATE INDEX outbox_events_org_idx
    ON iam.outbox_events (organization_id, created_at, id)
    WHERE organization_id IS NOT NULL;

CREATE TABLE iam.outbox_event_recipients (
    id uuid PRIMARY KEY,
    outbox_event_id uuid NOT NULL,
    recipient_kind text NOT NULL,
    application_webhook_endpoint_id uuid,
    silicon_hook_id uuid,
    ordering_key text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (outbox_event_id, id),
    CONSTRAINT outbox_event_recipients_event_fk
        FOREIGN KEY (outbox_event_id) REFERENCES iam.outbox_events (id) ON DELETE RESTRICT,
    CONSTRAINT outbox_event_recipients_application_endpoint_fk
        FOREIGN KEY (application_webhook_endpoint_id)
        REFERENCES iam.application_webhook_endpoints (id)
        ON DELETE RESTRICT,
    CONSTRAINT outbox_event_recipients_silicon_hook_fk
        FOREIGN KEY (silicon_hook_id) REFERENCES iam.silicon_hooks (id) ON DELETE RESTRICT,
    CONSTRAINT outbox_event_recipients_shape CHECK (
        (recipient_kind = 'application'
            AND application_webhook_endpoint_id IS NOT NULL AND silicon_hook_id IS NULL)
        OR (recipient_kind = 'silicon_hook'
            AND application_webhook_endpoint_id IS NULL AND silicon_hook_id IS NOT NULL)
    ),
    CONSTRAINT outbox_event_recipients_ordering_key_length
        CHECK (char_length(ordering_key) BETWEEN 1 AND 255)
);

CREATE UNIQUE INDEX outbox_event_recipients_app_unique_idx
    ON iam.outbox_event_recipients (outbox_event_id, application_webhook_endpoint_id)
    WHERE recipient_kind = 'application';
CREATE UNIQUE INDEX outbox_event_recipients_hook_unique_idx
    ON iam.outbox_event_recipients (outbox_event_id, silicon_hook_id)
    WHERE recipient_kind = 'silicon_hook';

CREATE TABLE iam.webhook_deliveries (
    id uuid PRIMARY KEY,
    outbox_event_id uuid NOT NULL,
    recipient_id uuid NOT NULL,
    signing_key_id uuid,
    status text NOT NULL DEFAULT 'pending',
    attempt_count integer NOT NULL DEFAULT 0,
    cycle_attempt_count integer NOT NULL DEFAULT 0,
    manual_replay_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    lease_owner text,
    lease_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    delivered_at timestamptz,
    dead_lettered_at timestamptz,
    last_http_status smallint,
    last_error_code text,
    UNIQUE (outbox_event_id, recipient_id),
    CONSTRAINT webhook_deliveries_recipient_fk
        FOREIGN KEY (outbox_event_id, recipient_id)
        REFERENCES iam.outbox_event_recipients (outbox_event_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT webhook_deliveries_signing_key_fk
        FOREIGN KEY (signing_key_id)
        REFERENCES iam.application_webhook_signing_keys (id)
        ON DELETE RESTRICT,
    CONSTRAINT webhook_deliveries_status
        CHECK (status IN ('pending', 'processing', 'delivered', 'dead_letter', 'cancelled')),
    CONSTRAINT webhook_deliveries_attempts CHECK (
        attempt_count >= 0
        AND cycle_attempt_count >= 0
        AND manual_replay_count >= 0
        AND cycle_attempt_count <= attempt_count
    ),
    CONSTRAINT webhook_deliveries_lease_consistency CHECK (
        (lease_owner IS NULL AND lease_expires_at IS NULL)
        OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
    ),
    CONSTRAINT webhook_deliveries_terminal_consistency CHECK (
        (status <> 'delivered' OR delivered_at IS NOT NULL)
        AND (status <> 'dead_letter' OR dead_lettered_at IS NOT NULL)
    ),
    CONSTRAINT webhook_deliveries_http_status
        CHECK (last_http_status IS NULL OR last_http_status BETWEEN 100 AND 599)
);

CREATE INDEX webhook_deliveries_claim_idx
    ON iam.webhook_deliveries (next_attempt_at, created_at, id)
    WHERE status IN ('pending', 'processing');

CREATE TRIGGER webhook_deliveries_set_updated_at
BEFORE UPDATE ON iam.webhook_deliveries
FOR EACH ROW EXECUTE FUNCTION iam_private.set_updated_at();

CREATE TABLE iam.webhook_delivery_attempts (
    id uuid PRIMARY KEY,
    delivery_id uuid NOT NULL,
    attempt_number integer NOT NULL,
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    finished_at timestamptz,
    http_status smallint,
    duration_ms integer,
    error_code text,
    response_digest bytea,
    UNIQUE (delivery_id, attempt_number),
    CONSTRAINT webhook_delivery_attempts_delivery_fk
        FOREIGN KEY (delivery_id) REFERENCES iam.webhook_deliveries (id) ON DELETE RESTRICT,
    CONSTRAINT webhook_delivery_attempts_positive_attempt CHECK (attempt_number > 0),
    CONSTRAINT webhook_delivery_attempts_http_status
        CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
    CONSTRAINT webhook_delivery_attempts_duration
        CHECK (duration_ms IS NULL OR duration_ms >= 0),
    CONSTRAINT webhook_delivery_attempts_response_digest
        CHECK (response_digest IS NULL OR octet_length(response_digest) = 32),
    CONSTRAINT webhook_delivery_attempts_finish_order
        CHECK (finished_at IS NULL OR finished_at >= started_at)
);

COMMENT ON TABLE iam.webhook_delivery_attempts IS
    'Bounded delivery telemetry. Response bodies are never stored; only an optional digest is retained.';

CREATE INDEX webhook_delivery_attempts_delivery_idx
    ON iam.webhook_delivery_attempts (delivery_id, attempt_number DESC);
CREATE INDEX webhook_delivery_attempts_started_brin_idx
    ON iam.webhook_delivery_attempts USING brin (started_at);

CREATE TABLE iam.idempotency_records (
    id uuid PRIMARY KEY,
    digest_key_version smallint NOT NULL,
    digest_purpose text
        GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    caller_scope_digest bytea NOT NULL,
    route text NOT NULL,
    idempotency_key_digest bytea NOT NULL,
    request_digest bytea NOT NULL,
    status text NOT NULL DEFAULT 'processing',
    lease_owner text,
    lease_expires_at timestamptz,
    response_status smallint,
    response_ciphertext bytea,
    response_nonce bytea,
    encryption_key_version smallint,
    encryption_purpose text
        GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    contains_one_time_secret boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    response_expires_at timestamptz,
    expires_at timestamptz NOT NULL,
    UNIQUE (digest_key_version, caller_scope_digest, route, idempotency_key_digest),
    CONSTRAINT idempotency_records_digest_key_fk
        FOREIGN KEY (digest_purpose, digest_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT idempotency_records_encryption_key_fk
        FOREIGN KEY (encryption_purpose, encryption_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version)
        ON DELETE RESTRICT,
    CONSTRAINT idempotency_records_digest_lengths CHECK (
        octet_length(caller_scope_digest) = 32
        AND octet_length(idempotency_key_digest) = 32
        AND octet_length(request_digest) = 32
    ),
    CONSTRAINT idempotency_records_route_length CHECK (char_length(route) BETWEEN 1 AND 255),
    CONSTRAINT idempotency_records_status
        CHECK (status IN ('processing', 'completed', 'failed', 'expired')),
    CONSTRAINT idempotency_records_lease_consistency CHECK (
        (lease_owner IS NULL AND lease_expires_at IS NULL)
        OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
    ),
    CONSTRAINT idempotency_records_response_encryption_consistency CHECK (
        (response_ciphertext IS NULL AND response_nonce IS NULL AND encryption_key_version IS NULL)
        OR (response_ciphertext IS NOT NULL AND response_nonce IS NOT NULL AND encryption_key_version IS NOT NULL)
    ),
    CONSTRAINT idempotency_records_response_nonce_length
        CHECK (response_nonce IS NULL OR octet_length(response_nonce) BETWEEN 12 AND 32),
    CONSTRAINT idempotency_records_response_status
        CHECK (response_status IS NULL OR response_status BETWEEN 100 AND 599),
    CONSTRAINT idempotency_records_completion_consistency CHECK (
        status <> 'completed'
        OR (response_status IS NOT NULL AND response_ciphertext IS NOT NULL AND response_expires_at IS NOT NULL)
    ),
    CONSTRAINT idempotency_records_expiry CHECK (expires_at > created_at),
    CONSTRAINT idempotency_records_secret_replay_window CHECK (
        NOT contains_one_time_secret
        OR status <> 'completed'
        OR (response_expires_at IS NOT NULL
            AND response_expires_at <= created_at + interval '10 minutes')
    )
);

COMMENT ON TABLE iam.idempotency_records IS
    'Request-digest-bound idempotency state. Responses are encrypted; one-time secret envelopes expire within ten minutes.';
COMMENT ON COLUMN iam.idempotency_records.digest_key_version IS
    'Token-HMAC key version shared by the caller-scope, idempotency-key, and request digests.';

CREATE INDEX idempotency_records_expiry_idx ON iam.idempotency_records (expires_at);
CREATE INDEX idempotency_records_processing_idx
    ON iam.idempotency_records (lease_expires_at, created_at)
    WHERE status = 'processing';

CREATE TRIGGER idempotency_records_updated_at
BEFORE UPDATE ON iam.idempotency_records
FOR EACH ROW EXECUTE FUNCTION iam_private.set_updated_at();

CREATE TABLE iam.notification_jobs (
    id uuid PRIMARY KEY,
    notification_kind text NOT NULL,
    provider text NOT NULL,
    recipient_contact_id uuid NOT NULL,
    recipient_contact_kind iam.contact_kind NOT NULL,
    template_id text NOT NULL,
    context_type text NOT NULL,
    context_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    attempt_count integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    lease_owner text,
    lease_expires_at timestamptz,
    provider_message_id text,
    last_error_code text,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    sent_at timestamptz,
    failed_at timestamptz,
    UNIQUE (notification_kind, context_type, context_id, recipient_contact_id),
    CONSTRAINT notification_jobs_contact_fk
        FOREIGN KEY (recipient_contact_id, recipient_contact_kind)
        REFERENCES iam.carbon_contacts (id, kind)
        ON DELETE RESTRICT,
    CONSTRAINT notification_jobs_kind CHECK (
        notification_kind IN ('invitation', 'security_notice')
    ),
    CONSTRAINT notification_jobs_provider CHECK (provider IN ('postmark', 'twilio_messaging')),
    CONSTRAINT notification_jobs_provider_channel CHECK (
        (provider = 'postmark' AND recipient_contact_kind = 'email')
        OR (provider = 'twilio_messaging' AND recipient_contact_kind = 'phone')
    ),
    CONSTRAINT notification_jobs_template_format
        CHECK (template_id ~ '^[a-z][a-z0-9_.:-]{2,127}$'),
    CONSTRAINT notification_jobs_context_format
        CHECK (context_type ~ '^[a-z][a-z0-9_]{2,63}$'),
    CONSTRAINT notification_jobs_status
        CHECK (status IN ('pending', 'processing', 'sent', 'failed', 'cancelled')),
    CONSTRAINT notification_jobs_attempts CHECK (attempt_count >= 0),
    CONSTRAINT notification_jobs_lease_consistency CHECK (
        (lease_owner IS NULL AND lease_expires_at IS NULL)
        OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
    ),
    CONSTRAINT notification_jobs_terminal_consistency CHECK (
        (status <> 'sent' OR sent_at IS NOT NULL)
        AND (status <> 'failed' OR failed_at IS NOT NULL)
    )
);

COMMENT ON TABLE iam.notification_jobs IS
    'Transactional invitation and security-notice delivery work; OTP delivery is synchronous and never queued.';
COMMENT ON COLUMN iam.notification_jobs.provider IS
    'Postmark Email API or Twilio Messages API selected consistently with the bound contact kind.';

CREATE INDEX notification_jobs_claim_idx
    ON iam.notification_jobs (available_at, created_at, id)
    WHERE status IN ('pending', 'processing');

CREATE TABLE iam.rate_limit_buckets (
    scope_digest bytea NOT NULL,
    limit_name text NOT NULL,
    window_started_at timestamptz NOT NULL,
    request_count integer NOT NULL DEFAULT 0,
    blocked_until timestamptz,
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (scope_digest, limit_name, window_started_at),
    CONSTRAINT rate_limit_buckets_scope_digest_length CHECK (octet_length(scope_digest) = 32),
    CONSTRAINT rate_limit_buckets_limit_name_format
        CHECK (limit_name ~ '^[a-z][a-z0-9_.:-]{2,127}$'),
    CONSTRAINT rate_limit_buckets_nonnegative_count CHECK (request_count >= 0),
    CONSTRAINT rate_limit_buckets_expiry CHECK (expires_at > window_started_at)
);

COMMENT ON TABLE iam.rate_limit_buckets IS
    'PostgreSQL fallback for distributed abuse controls when a Redis-compatible accelerator is absent.';

CREATE INDEX rate_limit_buckets_expiry_idx ON iam.rate_limit_buckets (expires_at);

CREATE FUNCTION iam_private.reject_immutable_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER authentication_events_append_only
BEFORE UPDATE OR DELETE ON iam.authentication_events
FOR EACH ROW EXECUTE FUNCTION iam_private.reject_immutable_history_mutation();

CREATE TRIGGER approval_requirements_immutable
BEFORE UPDATE OR DELETE ON iam.approval_requirements
FOR EACH ROW EXECUTE FUNCTION iam_private.reject_immutable_history_mutation();

CREATE TRIGGER approval_decisions_immutable
BEFORE UPDATE OR DELETE ON iam.approval_decisions
FOR EACH ROW EXECUTE FUNCTION iam_private.reject_immutable_history_mutation();

CREATE TRIGGER job_role_history_append_only
BEFORE UPDATE OR DELETE ON iam.job_role_history
FOR EACH ROW EXECUTE FUNCTION iam_private.reject_immutable_history_mutation();

CREATE TRIGGER silicon_credential_history_append_only
BEFORE UPDATE OR DELETE ON iam.silicon_credential_history
FOR EACH ROW EXECUTE FUNCTION iam_private.reject_immutable_history_mutation();

CREATE FUNCTION iam_private.guard_platform_role_grant_history()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'platform role grants are retained as revocation history'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.id <> OLD.id
       OR NEW.carbon_id <> OLD.carbon_id
       OR NEW.role <> OLD.role
       OR NEW.grant_source <> OLD.grant_source
       OR NEW.granted_by_carbon_id IS DISTINCT FROM OLD.granted_by_carbon_id
       OR NEW.granted_at <> OLD.granted_at
       OR (OLD.revoked_at IS NOT NULL AND (
           NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
           OR NEW.revoked_by_carbon_id IS DISTINCT FROM OLD.revoked_by_carbon_id
       )) THEN
        RAISE EXCEPTION 'platform role grant identity and completed revocation are immutable'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER platform_role_grants_preserve_history
BEFORE UPDATE OR DELETE ON iam.platform_role_grants
FOR EACH ROW EXECUTE FUNCTION iam_private.guard_platform_role_grant_history();

CREATE FUNCTION iam_private.assert_platform_administrator_present()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM iam.platform_role_grants
        WHERE role = 'platform_administrator'
    ) AND NOT EXISTS (
        SELECT 1
        FROM iam.platform_role_grants AS role_grant
        JOIN iam.principals AS principal
          ON principal.id = role_grant.carbon_id
         AND principal.kind = 'carbon'
         AND principal.status = 'active'
        WHERE role_grant.role = 'platform_administrator'
          AND role_grant.revoked_at IS NULL
    ) THEN
        RAISE EXCEPTION 'the final active platform administrator cannot be revoked'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE FUNCTION iam_private.check_platform_administrator_after_grant_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM iam_private.assert_platform_administrator_present();
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER platform_role_grants_require_administrator
AFTER INSERT OR UPDATE OR DELETE ON iam.platform_role_grants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_platform_administrator_after_grant_change();

CREATE CONSTRAINT TRIGGER active_platform_administrator_principal_required
AFTER INSERT OR UPDATE OR DELETE ON iam.principals
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_platform_administrator_after_grant_change();

CREATE FUNCTION iam_private.assert_active_principal_subtype(p_principal_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    principal_kind iam.principal_kind;
    principal_status text;
    subtype_exists boolean;
BEGIN
    SELECT principal.kind, principal.status
    INTO principal_kind, principal_status
    FROM iam.principals AS principal
    WHERE principal.id = p_principal_id;

    IF NOT FOUND OR principal_status <> 'active' THEN
        RETURN;
    END IF;

    subtype_exists := CASE principal_kind
        WHEN 'carbon' THEN EXISTS (SELECT 1 FROM iam.carbons WHERE id = p_principal_id)
        WHEN 'silicon' THEN EXISTS (SELECT 1 FROM iam.silicons WHERE id = p_principal_id)
        WHEN 'application' THEN EXISTS (SELECT 1 FROM iam.applications WHERE id = p_principal_id)
        WHEN 'service' THEN EXISTS (SELECT 1 FROM iam.service_principals WHERE id = p_principal_id)
    END;

    IF NOT subtype_exists THEN
        RAISE EXCEPTION 'active principal % has no matching % subtype', p_principal_id, principal_kind
            USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE FUNCTION iam_private.check_principal_subtype_from_principal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM iam_private.assert_active_principal_subtype(OLD.id);
    ELSE
        PERFORM iam_private.assert_active_principal_subtype(NEW.id);
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION iam_private.check_principal_subtype_from_subtype()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM iam_private.assert_active_principal_subtype(OLD.id);
    ELSE
        IF TG_OP = 'UPDATE' AND OLD.id IS DISTINCT FROM NEW.id THEN
            PERFORM iam_private.assert_active_principal_subtype(OLD.id);
        END IF;
        PERFORM iam_private.assert_active_principal_subtype(NEW.id);
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER principals_require_active_subtype
AFTER INSERT OR UPDATE OR DELETE ON iam.principals
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_principal_subtype_from_principal();

CREATE CONSTRAINT TRIGGER carbons_satisfy_principal_subtype
AFTER INSERT OR UPDATE OR DELETE ON iam.carbons
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_principal_subtype_from_subtype();

CREATE CONSTRAINT TRIGGER silicons_satisfy_principal_subtype
AFTER INSERT OR UPDATE OR DELETE ON iam.silicons
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_principal_subtype_from_subtype();

CREATE CONSTRAINT TRIGGER applications_satisfy_principal_subtype
AFTER INSERT OR UPDATE OR DELETE ON iam.applications
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_principal_subtype_from_subtype();

CREATE CONSTRAINT TRIGGER services_satisfy_principal_subtype
AFTER INSERT OR UPDATE OR DELETE ON iam.service_principals
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_principal_subtype_from_subtype();

CREATE FUNCTION iam_private.assert_active_carbon_contacts(p_carbon_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    active_principal boolean;
    verified_contact_kinds integer;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM iam.principals AS principal
        WHERE principal.id = p_carbon_id
          AND principal.kind = 'carbon'
          AND principal.status = 'active'
    ) INTO active_principal;

    IF NOT active_principal THEN
        RETURN;
    END IF;

    SELECT count(DISTINCT contact.kind)
    INTO verified_contact_kinds
    FROM iam.carbon_contacts AS contact
    WHERE contact.carbon_id = p_carbon_id
      AND contact.status = 'active'
      AND contact.is_primary
      AND contact.verified_at IS NOT NULL;

    IF verified_contact_kinds <> 2 THEN
        RAISE EXCEPTION 'active Carbon % must have one verified primary email and phone', p_carbon_id
            USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE FUNCTION iam_private.check_carbon_contacts_from_contact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM iam_private.assert_active_carbon_contacts(OLD.carbon_id);
    ELSE
        IF TG_OP = 'UPDATE' AND OLD.carbon_id IS DISTINCT FROM NEW.carbon_id THEN
            PERFORM iam_private.assert_active_carbon_contacts(OLD.carbon_id);
        END IF;
        PERFORM iam_private.assert_active_carbon_contacts(NEW.carbon_id);
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION iam_private.check_carbon_contacts_from_principal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'DELETE' AND NEW.kind = 'carbon' THEN
        PERFORM iam_private.assert_active_carbon_contacts(NEW.id);
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER carbon_contacts_required_for_active_carbon
AFTER INSERT OR UPDATE OR DELETE ON iam.carbon_contacts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_carbon_contacts_from_contact();

CREATE CONSTRAINT TRIGGER active_carbon_requires_contacts
AFTER INSERT OR UPDATE ON iam.principals
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_carbon_contacts_from_principal();

CREATE FUNCTION iam_private.assert_approval_request_shape(p_approval_request_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    request_kind text;
    minimum_approvers smallint;
    subtype_count integer;
    role_target_kind iam.principal_kind;
    role_target_membership_id uuid;
    requirement_count integer;
    requirements_valid boolean;
BEGIN
    SELECT request.request_kind, request.minimum_distinct_approvers
    INTO request_kind, minimum_approvers
    FROM iam.approval_requests AS request
    WHERE request.id = p_approval_request_id;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT
        (SELECT count(*) FROM iam.job_role_change_requests WHERE approval_request_id = p_approval_request_id)
        + (SELECT count(*) FROM iam.silicon_token_rotation_requests WHERE approval_request_id = p_approval_request_id)
        + (SELECT count(*) FROM iam.ownership_transfer_requests WHERE approval_request_id = p_approval_request_id)
    INTO subtype_count;

    IF subtype_count <> 1 THEN
        RAISE EXCEPTION 'approval request % must have exactly one payload subtype', p_approval_request_id
            USING ERRCODE = '23514';
    END IF;

    SELECT target_principal_kind, target_membership_id
    INTO role_target_kind, role_target_membership_id
    FROM iam.job_role_change_requests
    WHERE approval_request_id = p_approval_request_id;

    SELECT count(*)
    INTO requirement_count
    FROM iam.approval_requirements
    WHERE approval_request_id = p_approval_request_id;

    requirements_valid := CASE request_kind
        WHEN 'carbon_job_role_change' THEN
            role_target_kind = 'carbon'
            AND minimum_approvers = 2
            AND requirement_count = 2
            AND EXISTS (
                SELECT 1 FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'specific_membership'
                  AND specific_membership_id = role_target_membership_id
                  AND quorum = 1
            )
            AND EXISTS (
                SELECT 1 FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'current_owner_or_admin'
                  AND required_capability = 'roles.approve'
                  AND quorum = 1
            )
        WHEN 'silicon_job_role_change' THEN
            role_target_kind = 'silicon'
            AND minimum_approvers = 1
            AND requirement_count = 1
            AND EXISTS (
                SELECT 1 FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'current_owner_or_admin'
                  AND required_capability = 'roles.approve'
                  AND quorum = 1
            )
        WHEN 'silicon_token_rotation' THEN
            EXISTS (
                SELECT 1 FROM iam.silicon_token_rotation_requests
                WHERE approval_request_id = p_approval_request_id
            )
            AND minimum_approvers = 1
            AND requirement_count = 1
            AND EXISTS (
                SELECT 1 FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'current_owner'
                  AND quorum = 1
            )
        WHEN 'ownership_transfer' THEN
            EXISTS (
                SELECT 1 FROM iam.ownership_transfer_requests
                WHERE approval_request_id = p_approval_request_id
            )
            AND minimum_approvers = 1
            AND requirement_count = 1
            AND EXISTS (
                SELECT 1 FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'current_owner'
                  AND quorum = 1
            )
        ELSE false
    END;

    IF NOT requirements_valid THEN
        RAISE EXCEPTION 'approval request % has an invalid payload or approver requirement set',
            p_approval_request_id USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE FUNCTION iam_private.check_approval_shape_from_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM iam_private.assert_approval_request_shape(OLD.id);
    ELSE
        IF TG_OP = 'UPDATE' AND OLD.id IS DISTINCT FROM NEW.id THEN
            PERFORM iam_private.assert_approval_request_shape(OLD.id);
        END IF;
        PERFORM iam_private.assert_approval_request_shape(NEW.id);
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION iam_private.check_approval_shape_from_payload()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM iam_private.assert_approval_request_shape(OLD.approval_request_id);
    ELSE
        IF TG_OP = 'UPDATE'
           AND OLD.approval_request_id IS DISTINCT FROM NEW.approval_request_id THEN
            PERFORM iam_private.assert_approval_request_shape(OLD.approval_request_id);
        END IF;
        PERFORM iam_private.assert_approval_request_shape(NEW.approval_request_id);
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER approval_requests_require_valid_shape
AFTER INSERT OR UPDATE OR DELETE ON iam.approval_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_approval_shape_from_request();

CREATE CONSTRAINT TRIGGER approval_requirements_preserve_shape
AFTER INSERT OR UPDATE OR DELETE ON iam.approval_requirements
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_approval_shape_from_payload();

CREATE CONSTRAINT TRIGGER job_role_payload_preserves_shape
AFTER INSERT OR UPDATE OR DELETE ON iam.job_role_change_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_approval_shape_from_payload();

CREATE CONSTRAINT TRIGGER silicon_rotation_payload_preserves_shape
AFTER INSERT OR UPDATE OR DELETE ON iam.silicon_token_rotation_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_approval_shape_from_payload();

CREATE CONSTRAINT TRIGGER ownership_transfer_payload_preserves_shape
AFTER INSERT OR UPDATE OR DELETE ON iam.ownership_transfer_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_approval_shape_from_payload();

CREATE FUNCTION iam_private.current_principal_id()
RETURNS uuid
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT NULLIF(current_setting('iam.principal_id', true), '')::uuid
$$;

CREATE FUNCTION iam_private.current_organization_id()
RETURNS uuid
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT NULLIF(current_setting('iam.organization_id', true), '')::uuid
$$;

CREATE FUNCTION iam_private.current_application_id()
RETURNS uuid
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT NULLIF(current_setting('iam.application_id', true), '')::uuid
$$;

CREATE FUNCTION iam_private.register_runtime_key_version(
    p_purpose text,
    p_key_version smallint,
    p_is_current boolean
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    existing_status text;
BEGIN
    IF p_purpose NOT IN ('token_hmac', 'contact_lookup_hmac', 'contact_aead')
       OR p_key_version <= 0 THEN
        RAISE EXCEPTION 'unsupported runtime key metadata'
            USING ERRCODE = '22023';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('silicon-iam:keyring:' || p_purpose, 0)
    );

    SELECT key_metadata.status
    INTO existing_status
    FROM iam.cryptographic_key_versions AS key_metadata
    WHERE key_metadata.purpose = p_purpose
      AND key_metadata.key_version = p_key_version
    FOR UPDATE;

    IF existing_status = 'retired' THEN
        RAISE EXCEPTION 'retired runtime key metadata cannot be reactivated'
            USING ERRCODE = '55000';
    END IF;

    IF p_is_current THEN
        UPDATE iam.cryptographic_key_versions
        SET status = 'decrypt_only', retired_at = NULL
        WHERE purpose = p_purpose
          AND key_version <> p_key_version
          AND status = 'active';

        INSERT INTO iam.cryptographic_key_versions (
            purpose,
            key_version,
            status,
            activated_at
        )
        VALUES (p_purpose, p_key_version, 'active', transaction_timestamp())
        ON CONFLICT (purpose, key_version) DO UPDATE
        SET status = 'active',
            activated_at = EXCLUDED.activated_at,
            retired_at = NULL;
    ELSE
        INSERT INTO iam.cryptographic_key_versions (purpose, key_version, status)
        VALUES (p_purpose, p_key_version, 'decrypt_only')
        ON CONFLICT (purpose, key_version) DO UPDATE
        SET status = CASE
                WHEN iam.cryptographic_key_versions.status = 'active' THEN 'active'
                ELSE 'decrypt_only'
            END,
            retired_at = NULL;
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.register_runtime_key_version(
    text, smallint, boolean
) FROM PUBLIC;

CREATE FUNCTION iam_private.list_worker_application_webhook_recipients(
    p_organization_id uuid,
    p_subject_principal_id uuid,
    p_application_id uuid,
    p_event_occurred_at timestamptz
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
    FROM iam.application_webhook_endpoints AS endpoint
    JOIN iam.applications AS application ON application.id = endpoint.application_id
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
    JOIN iam.application_webhook_signing_keys AS signing_key
      ON signing_key.endpoint_id = endpoint.id
     AND signing_key.application_id = application.id
    WHERE endpoint.status = 'active'
      AND signing_key.status IN ('active', 'retiring')
      AND (signing_key.retires_at IS NULL OR signing_key.retires_at > transaction_timestamp())
      AND application.review_status = 'verified'
      AND application_principal.status = 'active'
      AND (
          application.id = p_application_id
          OR EXISTS (
              SELECT 1
              FROM iam.access_tokens AS token
              JOIN iam.principals AS subject_principal
                ON subject_principal.id = token.subject_principal_id
               AND subject_principal.kind = token.subject_kind
               AND (
                   subject_principal.auth_epoch = token.subject_auth_epoch
                   OR subject_principal.suspended_at >= p_event_occurred_at
                   OR subject_principal.deleted_at >= p_event_occurred_at
               )
              LEFT JOIN iam.organization_memberships AS membership
                ON membership.organization_id = token.organization_id
               AND membership.id = token.membership_id
               AND membership.principal_id = token.subject_principal_id
               AND membership.principal_kind = token.subject_kind
              WHERE token.client_application_id = application.id
                AND token.token_class = 'application_access'
                AND token.client_auth_epoch = application_principal.auth_epoch
                AND (token.revoked_at IS NULL OR token.revoked_at >= p_event_occurred_at)
                AND token.created_at <= p_event_occurred_at
                AND token.expires_at > p_event_occurred_at
                AND (p_subject_principal_id IS NULL
                    OR token.subject_principal_id = p_subject_principal_id)
                AND (p_organization_id IS NULL
                    OR token.organization_id = p_organization_id)
                AND (
                    token.organization_id IS NULL
                    OR (
                        (
                            membership.status = 'active'
                            OR membership.suspended_at >= p_event_occurred_at
                            OR membership.removed_at >= p_event_occurred_at
                        )
                        AND (
                            membership.authz_epoch = token.membership_authz_epoch
                            OR membership.updated_at >= p_event_occurred_at
                        )
                    )
                )
          )
      )
$$;

CREATE FUNCTION iam_private.get_worker_application_webhook_material(
    p_endpoint_id uuid,
    p_signing_key_id uuid
)
RETURNS TABLE (
    application_id uuid,
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
        endpoint.application_id,
        endpoint.url_ciphertext,
        endpoint.url_nonce,
        endpoint.encryption_key_version,
        signing_key.secret_ciphertext,
        signing_key.secret_nonce,
        signing_key.encryption_key_version,
        signing_key.secret_version
    FROM iam.application_webhook_endpoints AS endpoint
    JOIN iam.application_webhook_signing_keys AS signing_key
      ON signing_key.id = p_signing_key_id
     AND signing_key.endpoint_id = endpoint.id
     AND signing_key.application_id = endpoint.application_id
    JOIN iam.applications AS application ON application.id = endpoint.application_id
    JOIN iam.principals AS principal
      ON principal.id = application.id
     AND principal.kind = 'application'
    WHERE endpoint.id = p_endpoint_id
      AND endpoint.status = 'active'
      AND signing_key.status IN ('active', 'retiring')
      AND (signing_key.retires_at IS NULL OR signing_key.retires_at > transaction_timestamp())
      AND application.review_status = 'verified'
      AND principal.status = 'active'
$$;

CREATE FUNCTION iam_private.get_worker_notification_contact(
    p_contact_id uuid,
    p_contact_kind iam.contact_kind
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
    FROM iam.carbon_contacts AS contact
    JOIN iam.carbons AS carbon ON carbon.id = contact.carbon_id
    JOIN iam.principals AS principal
      ON principal.id = carbon.id
     AND principal.kind = 'carbon'
    WHERE contact.id = p_contact_id
      AND contact.kind = p_contact_kind
      AND contact.status = 'active'
      AND principal.status = 'active'
      AND carbon.deleted_at IS NULL
$$;

CREATE FUNCTION iam_private.get_worker_invitation_context(
    p_invitation_id uuid,
    p_target_carbon_id uuid
)
RETURNS TABLE (
    organization_name text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT organization.name
    FROM iam.organization_invitations AS invitation
    JOIN iam.organizations AS organization ON organization.id = invitation.organization_id
    WHERE invitation.id = p_invitation_id
      AND invitation.target_carbon_id = p_target_carbon_id
      AND invitation.status = 'pending'
      AND invitation.expires_at > transaction_timestamp()
      AND organization.status = 'active'
$$;

CREATE FUNCTION iam_private.get_worker_silicon_hook_identity(
    p_hook_id uuid,
    p_lease_owner text
)
RETURNS TABLE (
    organization_id uuid,
    silicon_id uuid,
    global_silicon_id text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT silicon.organization_id, silicon.id, silicon.global_silicon_id
    FROM iam.silicon_hooks AS hook
    JOIN iam.silicons AS silicon
      ON silicon.organization_id = hook.organization_id
     AND silicon.id = hook.silicon_id
    JOIN iam.principals AS principal
      ON principal.id = silicon.id
     AND principal.kind = 'silicon'
    WHERE hook.id = p_hook_id
      AND hook.status = 'provisioning'
      AND hook.lease_owner = p_lease_owner
      AND hook.lease_expires_at > transaction_timestamp()
      AND silicon.provisioning_status IN ('pending_hook', 'hook_error')
      AND principal.status = 'provisioning'
$$;

CREATE FUNCTION iam_private.complete_worker_silicon_hook(
    p_hook_id uuid,
    p_lease_owner text,
    p_provider_hook_id text,
    p_url_ciphertext bytea,
    p_url_nonce bytea,
    p_encryption_key_version smallint,
    p_audit_id uuid,
    p_request_id uuid,
    p_outbox_event_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    resolved_organization_id uuid;
    resolved_silicon_id uuid;
    resolved_global_silicon_id text;
    resolved_silicon_version bigint;
    resolved_organization_handle text;
    resolved_organization_name text;
    resolved_organization_version bigint;
    resolved_job_role text;
BEGIN
    UPDATE iam.silicon_hooks AS hook
    SET provider_hook_id = p_provider_hook_id,
        url_ciphertext = p_url_ciphertext,
        url_nonce = p_url_nonce,
        encryption_key_version = p_encryption_key_version,
        status = 'active',
        last_error_code = NULL,
        next_attempt_at = NULL,
        lease_owner = NULL,
        lease_expires_at = NULL,
        activated_at = transaction_timestamp()
    WHERE hook.id = p_hook_id
      AND hook.status = 'provisioning'
      AND hook.lease_owner = p_lease_owner
      AND hook.lease_expires_at > transaction_timestamp()
    RETURNING hook.organization_id, hook.silicon_id
    INTO resolved_organization_id, resolved_silicon_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Silicon Hook lease is unavailable' USING ERRCODE = '55000';
    END IF;

    UPDATE iam.silicons AS silicon
    SET provisioning_status = 'active'
    WHERE silicon.organization_id = resolved_organization_id
      AND silicon.id = resolved_silicon_id
      AND silicon.provisioning_status IN ('pending_hook', 'hook_error')
    RETURNING silicon.global_silicon_id, silicon.version
    INTO resolved_global_silicon_id, resolved_silicon_version;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Silicon is unavailable for Hook activation' USING ERRCODE = '55000';
    END IF;

    UPDATE iam.principals AS principal
    SET status = 'active', activated_at = transaction_timestamp()
    WHERE principal.id = resolved_silicon_id
      AND principal.kind = 'silicon'
      AND principal.status = 'provisioning';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Silicon principal is unavailable for activation' USING ERRCODE = '55000';
    END IF;

    SELECT organization.org_id, organization.name, organization.version, membership.job_role
    INTO resolved_organization_handle, resolved_organization_name,
         resolved_organization_version, resolved_job_role
    FROM iam.organizations AS organization
    JOIN iam.silicons AS silicon
      ON silicon.organization_id = organization.id
     AND silicon.id = resolved_silicon_id
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = silicon.organization_id
     AND membership.id = silicon.membership_id
    WHERE organization.id = resolved_organization_id;

    INSERT INTO iam.audit_events (
        occurred_at, id, request_id, organization_id,
        action, target_type, target_id,
        aggregate_type, aggregate_id, aggregate_version,
        after_state, metadata
    ) VALUES (
        transaction_timestamp(), p_audit_id, p_request_id, resolved_organization_id,
        'silicon.hook_activated', 'silicon', resolved_silicon_id,
        'silicon', resolved_silicon_id, resolved_silicon_version,
        pg_catalog.jsonb_build_object(
            'provisioning_status', 'active',
            'global_silicon_id', resolved_global_silicon_id
        ),
        pg_catalog.jsonb_build_object('system', 'iam-worker')
    );

    INSERT INTO iam.outbox_events (
        id, organization_id, aggregate_type, aggregate_id,
        aggregate_version, event_ordinal, event_type, schema_version, payload
    ) VALUES (
        p_outbox_event_id, resolved_organization_id, 'silicon', resolved_silicon_id,
        resolved_silicon_version, 1, 'iam.silicon.initialized.v1', 1,
        pg_catalog.jsonb_build_object(
            'silicon_id', resolved_silicon_id,
            'global_silicon_id', resolved_global_silicon_id,
            'job_role', resolved_job_role,
            'organization', pg_catalog.jsonb_build_object(
                'id', resolved_organization_id,
                'org_id', resolved_organization_handle,
                'name', resolved_organization_name,
                'version', resolved_organization_version
            )
        )
    );
END;
$$;

CREATE FUNCTION iam_private.fail_worker_silicon_hook(
    p_hook_id uuid,
    p_lease_owner text,
    p_error_code text,
    p_retry_delay_seconds bigint,
    p_retryable boolean
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    resolved_organization_id uuid;
    resolved_silicon_id uuid;
BEGIN
    UPDATE iam.silicon_hooks AS hook
    SET status = 'failed',
        last_error_code = p_error_code,
        next_attempt_at = CASE
            WHEN p_retryable THEN transaction_timestamp()
                + (p_retry_delay_seconds * interval '1 second')
            ELSE NULL
        END,
        lease_owner = NULL,
        lease_expires_at = NULL
    WHERE hook.id = p_hook_id
      AND hook.status = 'provisioning'
      AND hook.lease_owner = p_lease_owner
    RETURNING hook.organization_id, hook.silicon_id
    INTO resolved_organization_id, resolved_silicon_id;

    IF FOUND THEN
        UPDATE iam.silicons AS silicon
        SET provisioning_status = 'hook_error'
        WHERE silicon.organization_id = resolved_organization_id
          AND silicon.id = resolved_silicon_id
          AND silicon.provisioning_status = 'pending_hook';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.list_worker_application_webhook_recipients(
    uuid, uuid, uuid, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.get_worker_application_webhook_material(
    uuid, uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.get_worker_notification_contact(
    uuid, iam.contact_kind
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.get_worker_invitation_context(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.get_worker_silicon_hook_identity(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.complete_worker_silicon_hook(
    uuid, text, text, bytea, bytea, smallint, uuid, uuid, uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.fail_worker_silicon_hook(
    uuid, text, text, bigint, boolean
) FROM PUBLIC;

CREATE FUNCTION iam_private.organization_handle_is_available(p_organization_handle text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT NOT EXISTS (
        SELECT 1
        FROM iam.organizations AS organization
        WHERE organization.org_id = p_organization_handle
    )
$$;

REVOKE ALL ON FUNCTION iam_private.organization_handle_is_available(text) FROM PUBLIC;

CREATE FUNCTION iam_private.carbon_handle_is_available(p_carbon_handle text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT NOT EXISTS (
        SELECT 1
        FROM iam.carbons AS carbon
        WHERE carbon.carbon_id = p_carbon_handle
    )
$$;

CREATE FUNCTION iam_private.resolve_active_carbon_by_handle(p_carbon_handle text)
RETURNS TABLE (principal_id uuid, auth_epoch bigint)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT principal.id, principal.auth_epoch
    FROM iam.carbons AS carbon
    JOIN iam.principals AS principal
      ON principal.id = carbon.id
     AND principal.kind = 'carbon'
    WHERE carbon.carbon_id = p_carbon_handle
      AND carbon.deleted_at IS NULL
      AND principal.status = 'active'
$$;

CREATE FUNCTION iam_private.resolve_active_carbon_by_contact_digest(
    p_contact_kind iam.contact_kind,
    p_hmac_key_version smallint,
    p_digest bytea
)
RETURNS TABLE (
    principal_id uuid,
    contact_id uuid,
    contact_ciphertext bytea,
    contact_nonce bytea,
    contact_encryption_key_version smallint,
    auth_epoch bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        principal.id,
        contact.id,
        contact.ciphertext,
        contact.nonce,
        contact.encryption_key_version,
        principal.auth_epoch
    FROM iam.contact_blind_indexes AS blind_index
    JOIN iam.carbon_contacts AS contact
      ON contact.id = blind_index.contact_id
     AND contact.kind = blind_index.contact_kind
    JOIN iam.carbons AS carbon ON carbon.id = contact.carbon_id
    JOIN iam.principals AS principal
      ON principal.id = carbon.id
     AND principal.kind = 'carbon'
    WHERE blind_index.contact_kind = p_contact_kind
      AND blind_index.hmac_key_version = p_hmac_key_version
      AND blind_index.digest = p_digest
      AND octet_length(p_digest) = 32
      AND contact.status = 'active'
      AND contact.is_primary
      AND carbon.deleted_at IS NULL
      AND principal.status = 'active'
$$;

CREATE FUNCTION iam_private.list_active_carbon_login_contacts(p_principal_id uuid)
RETURNS TABLE (
    contact_id uuid,
    contact_kind iam.contact_kind,
    contact_ciphertext bytea,
    contact_nonce bytea,
    contact_encryption_key_version smallint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        contact.id,
        contact.kind,
        contact.ciphertext,
        contact.nonce,
        contact.encryption_key_version
    FROM iam.carbon_contacts AS contact
    JOIN iam.carbons AS carbon ON carbon.id = contact.carbon_id
    JOIN iam.principals AS principal
      ON principal.id = carbon.id
     AND principal.kind = 'carbon'
    WHERE principal.id = p_principal_id
      AND principal.status = 'active'
      AND carbon.deleted_at IS NULL
      AND contact.status = 'active'
      AND contact.is_primary
    ORDER BY contact.kind, contact.id
$$;

CREATE FUNCTION iam_private.complete_verified_signup(
    p_signup_session_id uuid,
    p_principal_id uuid,
    p_carbon_handle text,
    p_display_name text,
    p_description text,
    p_profile_photo_uri text,
    p_email_contact_id uuid,
    p_phone_contact_id uuid
)
RETURNS TABLE (
    principal_id uuid,
    carbon_handle text,
    aggregate_version bigint,
    created_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    current_candidate_count integer;
    indexed_candidate_kind_count integer;
BEGIN
    IF p_principal_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_email_contact_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_phone_contact_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_email_contact_id = p_phone_contact_id THEN
        RAISE EXCEPTION 'signup cannot be completed' USING ERRCODE = '22023';
    END IF;

    PERFORM 1
    FROM iam.signup_sessions AS signup_session
    WHERE signup_session.id = p_signup_session_id
      AND signup_session.status = 'pending'
      AND signup_session.expires_at > statement_timestamp()
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'signup cannot be completed' USING ERRCODE = '23514';
    END IF;

    SELECT count(*), count(DISTINCT candidate.kind)
    INTO current_candidate_count, indexed_candidate_kind_count
    FROM iam.signup_contact_candidates AS candidate
    WHERE candidate.signup_session_id = p_signup_session_id
      AND candidate.verified_at IS NOT NULL
      AND candidate.superseded_at IS NULL;

    IF current_candidate_count <> 2 OR indexed_candidate_kind_count <> 2 THEN
        RAISE EXCEPTION 'signup cannot be completed' USING ERRCODE = '23514';
    END IF;

    SELECT count(DISTINCT candidate.kind)
    INTO indexed_candidate_kind_count
    FROM iam.signup_contact_candidates AS candidate
    JOIN iam.signup_candidate_blind_indexes AS candidate_index
      ON candidate_index.candidate_id = candidate.id
     AND candidate_index.contact_kind = candidate.kind
    WHERE candidate.signup_session_id = p_signup_session_id
      AND candidate.verified_at IS NOT NULL
      AND candidate.superseded_at IS NULL;

    IF indexed_candidate_kind_count <> 2 THEN
        RAISE EXCEPTION 'signup cannot be completed' USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM iam.signup_contact_candidates AS candidate
        JOIN iam.signup_candidate_blind_indexes AS candidate_index
          ON candidate_index.candidate_id = candidate.id
         AND candidate_index.contact_kind = candidate.kind
        JOIN iam.contact_blind_indexes AS existing_index
          ON existing_index.contact_kind = candidate_index.contact_kind
         AND existing_index.hmac_key_version = candidate_index.hmac_key_version
         AND existing_index.digest = candidate_index.digest
        JOIN iam.carbon_contacts AS existing_contact
          ON existing_contact.id = existing_index.contact_id
         AND existing_contact.kind = existing_index.contact_kind
        WHERE candidate.signup_session_id = p_signup_session_id
          AND candidate.verified_at IS NOT NULL
          AND candidate.superseded_at IS NULL
          AND existing_contact.status = 'active'
    ) THEN
        RAISE EXCEPTION 'signup cannot be completed' USING ERRCODE = '23505';
    END IF;

    INSERT INTO iam.principals (id, kind, status)
    VALUES (p_principal_id, 'carbon', 'provisioning');

    INSERT INTO iam.carbons (
        id,
        carbon_id,
        display_name,
        description,
        profile_photo_uri
    )
    VALUES (
        p_principal_id,
        p_carbon_handle,
        p_display_name,
        p_description,
        p_profile_photo_uri
    );

    INSERT INTO iam.carbon_contacts (
        id,
        carbon_id,
        kind,
        ciphertext,
        nonce,
        encryption_key_version,
        verified_at
    )
    SELECT
        CASE candidate.kind
            WHEN 'email' THEN p_email_contact_id
            WHEN 'phone' THEN p_phone_contact_id
        END,
        p_principal_id,
        candidate.kind,
        candidate.ciphertext,
        candidate.nonce,
        candidate.encryption_key_version,
        candidate.verified_at
    FROM iam.signup_contact_candidates AS candidate
    WHERE candidate.signup_session_id = p_signup_session_id
      AND candidate.verified_at IS NOT NULL
      AND candidate.superseded_at IS NULL;

    INSERT INTO iam.contact_blind_indexes (
        contact_id,
        contact_kind,
        hmac_key_version,
        digest
    )
    SELECT
        CASE candidate.kind
            WHEN 'email' THEN p_email_contact_id
            WHEN 'phone' THEN p_phone_contact_id
        END,
        candidate.kind,
        candidate_index.hmac_key_version,
        candidate_index.digest
    FROM iam.signup_contact_candidates AS candidate
    JOIN iam.signup_candidate_blind_indexes AS candidate_index
      ON candidate_index.candidate_id = candidate.id
     AND candidate_index.contact_kind = candidate.kind
    WHERE candidate.signup_session_id = p_signup_session_id
      AND candidate.verified_at IS NOT NULL
      AND candidate.superseded_at IS NULL;

    UPDATE iam.principals
    SET status = 'active', activated_at = transaction_timestamp()
    WHERE id = p_principal_id;

    UPDATE iam.signup_sessions
    SET status = 'completed',
        completed_carbon_id = p_principal_id,
        completed_at = transaction_timestamp()
    WHERE id = p_signup_session_id;

    RETURN QUERY
    SELECT carbon.id, carbon.carbon_id, carbon.version, carbon.created_at
    FROM iam.carbons AS carbon
    WHERE carbon.id = p_principal_id;
END;
$$;

CREATE FUNCTION iam_private.complete_verified_organization_invitation(
    p_organization_handle text,
    p_invitation_id uuid,
    p_new_membership_id uuid,
    p_digest_key_version smallint,
    p_code_digest bytea
)
RETURNS TABLE (
    organization_id uuid,
    membership_id uuid,
    membership_version bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    current_carbon_id uuid := iam_private.current_principal_id();
    invitation_record iam.organization_invitations%ROWTYPE;
    resolved_membership_id uuid;
    resolved_membership_version bigint;
    expected_tag_count integer;
    active_tag_count integer;
    expected_extra_count integer;
    active_extra_count integer;
BEGIN
    IF current_carbon_id IS NULL
       OR p_new_membership_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_digest_key_version <= 0
       OR octet_length(p_code_digest) <> 32 THEN
        RAISE EXCEPTION 'organization invitation cannot be completed' USING ERRCODE = '22023';
    END IF;

    SELECT invitation.*
    INTO invitation_record
    FROM iam.organization_invitations AS invitation
    JOIN iam.organizations AS organization
      ON organization.id = invitation.organization_id
     AND organization.org_id = p_organization_handle
     AND organization.status = 'active'
    JOIN iam.principals AS principal
      ON principal.id = invitation.target_carbon_id
     AND principal.kind = 'carbon'
     AND principal.status = 'active'
    WHERE invitation.id = p_invitation_id
      AND invitation.target_carbon_id = current_carbon_id
      AND invitation.status = 'pending'
      AND invitation.expires_at > transaction_timestamp()
    FOR UPDATE OF invitation;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization invitation cannot be completed' USING ERRCODE = '23514';
    END IF;

    PERFORM 1
    FROM iam.invitation_verification_challenges AS challenge
    JOIN iam.carbon_contacts AS contact
      ON contact.carbon_id = challenge.target_carbon_id
     AND contact.id = challenge.destination_contact_id
     AND contact.status = 'active'
     AND contact.verified_at IS NOT NULL
    WHERE challenge.organization_id = invitation_record.organization_id
      AND challenge.invitation_id = invitation_record.id
      AND challenge.target_carbon_id = current_carbon_id
      AND challenge.digest_key_version = p_digest_key_version
      AND challenge.code_digest = p_code_digest
      AND challenge.failed_attempts < challenge.max_attempts
      AND challenge.consumed_at IS NULL
      AND challenge.superseded_at IS NULL
      AND challenge.expires_at > transaction_timestamp()
      AND (challenge.cooldown_until IS NULL OR challenge.cooldown_until <= transaction_timestamp())
    FOR UPDATE OF challenge;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization invitation cannot be completed' USING ERRCODE = '23514';
    END IF;

    SELECT count(*) INTO expected_tag_count
    FROM iam.organization_invitation_tags AS tag_assignment
    WHERE tag_assignment.organization_id = invitation_record.organization_id
      AND tag_assignment.invitation_id = invitation_record.id;
    SELECT count(*) INTO active_tag_count
    FROM iam.organization_invitation_tags AS assignment
    JOIN iam.organization_tags AS tag
      ON tag.organization_id = assignment.organization_id
     AND tag.id = assignment.tag_id
     AND tag.status = 'active'
    WHERE assignment.organization_id = invitation_record.organization_id
      AND assignment.invitation_id = invitation_record.id;

    SELECT count(*) INTO expected_extra_count
    FROM iam.organization_invitation_extra_silicons AS extra_assignment
    WHERE extra_assignment.organization_id = invitation_record.organization_id
      AND extra_assignment.invitation_id = invitation_record.id;
    SELECT count(*) INTO active_extra_count
    FROM iam.organization_invitation_extra_silicons AS assignment
    JOIN iam.silicons AS silicon
      ON silicon.organization_id = assignment.organization_id
     AND silicon.membership_id = assignment.silicon_membership_id
     AND silicon.provisioning_status <> 'deleted'
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = silicon.organization_id
     AND membership.id = silicon.membership_id
     AND membership.status = 'active'
    WHERE assignment.organization_id = invitation_record.organization_id
      AND assignment.invitation_id = invitation_record.id;

    IF expected_tag_count <> active_tag_count
       OR expected_extra_count <> active_extra_count
       OR (
            invitation_record.first_silicon_membership_id IS NOT NULL
            AND NOT EXISTS (
                SELECT 1
                FROM iam.silicons AS silicon
                JOIN iam.organization_memberships AS membership
                  ON membership.organization_id = silicon.organization_id
                 AND membership.id = silicon.membership_id
                 AND membership.status = 'active'
                WHERE silicon.organization_id = invitation_record.organization_id
                  AND silicon.membership_id = invitation_record.first_silicon_membership_id
                  AND silicon.provisioning_status <> 'deleted'
            )
       ) THEN
        RAISE EXCEPTION 'organization invitation defaults are no longer active'
            USING ERRCODE = '23514';
    END IF;

    INSERT INTO iam.organization_memberships (
        id, organization_id, principal_id, principal_kind, org_role, job_role
    ) VALUES (
        p_new_membership_id,
        invitation_record.organization_id,
        current_carbon_id,
        'carbon',
        'member',
        invitation_record.job_role
    )
    ON CONFLICT (organization_id, principal_id) DO UPDATE
    SET status = 'active',
        suspended_at = NULL,
        removed_at = NULL,
        org_role = 'member',
        job_role = EXCLUDED.job_role,
        role_granted_by_membership_id = NULL,
        authz_epoch = iam.organization_memberships.authz_epoch + 1
    WHERE iam.organization_memberships.principal_kind = 'carbon'
      AND iam.organization_memberships.status <> 'active'
    RETURNING id, version
    INTO resolved_membership_id, resolved_membership_version;

    IF resolved_membership_id IS NULL THEN
        RAISE EXCEPTION 'organization membership is already active' USING ERRCODE = '23505';
    END IF;

    UPDATE iam.organization_capability_grants AS capability_grant
    SET revoked_by_membership_id = resolved_membership_id,
        revoked_at = transaction_timestamp(),
        reason = 'membership reactivated from a new invitation'
    WHERE capability_grant.organization_id = invitation_record.organization_id
      AND capability_grant.grantee_membership_id = resolved_membership_id
      AND capability_grant.revoked_at IS NULL;

    INSERT INTO iam.carbon_membership_settings (
        organization_id,
        membership_id,
        carbon_id,
        first_silicon_membership_id,
        default_trust_boundary,
        default_trust_level
    ) VALUES (
        invitation_record.organization_id,
        resolved_membership_id,
        current_carbon_id,
        invitation_record.first_silicon_membership_id,
        invitation_record.default_trust_boundary,
        invitation_record.default_trust_level
    )
    ON CONFLICT (membership_id) DO UPDATE
    SET first_silicon_membership_id = EXCLUDED.first_silicon_membership_id,
        default_trust_boundary = EXCLUDED.default_trust_boundary,
        default_trust_level = EXCLUDED.default_trust_level;

    DELETE FROM iam.membership_tags AS membership_tag
    WHERE membership_tag.organization_id = invitation_record.organization_id
      AND membership_tag.membership_id = resolved_membership_id;
    INSERT INTO iam.membership_tags (
        organization_id, membership_id, tag_id, assigned_by_membership_id
    )
    SELECT
        assignment.organization_id,
        resolved_membership_id,
        assignment.tag_id,
        invitation_record.invited_by_membership_id
    FROM iam.organization_invitation_tags AS assignment
    WHERE assignment.organization_id = invitation_record.organization_id
      AND assignment.invitation_id = invitation_record.id;

    UPDATE iam.extra_silicon_access_grants AS access_grant
    SET revoked_by_membership_id = resolved_membership_id,
        revoked_at = transaction_timestamp()
    WHERE access_grant.organization_id = invitation_record.organization_id
      AND access_grant.carbon_membership_id = resolved_membership_id
      AND access_grant.revoked_at IS NULL;
    INSERT INTO iam.extra_silicon_access_grants (
        organization_id,
        carbon_membership_id,
        silicon_membership_id,
        granted_by_membership_id
    )
    SELECT
        assignment.organization_id,
        resolved_membership_id,
        assignment.silicon_membership_id,
        invitation_record.invited_by_membership_id
    FROM iam.organization_invitation_extra_silicons AS assignment
    WHERE assignment.organization_id = invitation_record.organization_id
      AND assignment.invitation_id = invitation_record.id;

    UPDATE iam.invitation_verification_challenges AS challenge
    SET consumed_at = transaction_timestamp()
    WHERE challenge.organization_id = invitation_record.organization_id
      AND challenge.invitation_id = invitation_record.id
      AND challenge.target_carbon_id = current_carbon_id
      AND challenge.digest_key_version = p_digest_key_version
      AND challenge.code_digest = p_code_digest
      AND challenge.consumed_at IS NULL
      AND challenge.superseded_at IS NULL;
    UPDATE iam.organization_invitations AS invitation
    SET status = 'accepted', accepted_at = transaction_timestamp()
    WHERE invitation.organization_id = invitation_record.organization_id
      AND invitation.id = invitation_record.id
      AND invitation.status = 'pending';

    organization_id := invitation_record.organization_id;
    membership_id := resolved_membership_id;
    membership_version := resolved_membership_version;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.complete_verified_organization_invitation(
    text, uuid, uuid, smallint, bytea
) FROM PUBLIC;

CREATE FUNCTION iam_private.resolve_organization_invitation_tenant(
    p_organization_handle text,
    p_invitation_id uuid
)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT invitation.organization_id
    FROM iam.organization_invitations AS invitation
    JOIN iam.organizations AS organization
      ON organization.id = invitation.organization_id
     AND organization.org_id = p_organization_handle
     AND organization.status = 'active'
    WHERE invitation.id = p_invitation_id
      AND (
          invitation.target_carbon_id = iam_private.current_principal_id()
          OR EXISTS (
              SELECT 1
              FROM iam.organization_memberships AS membership
              WHERE membership.organization_id = invitation.organization_id
                AND membership.principal_id = iam_private.current_principal_id()
                AND membership.principal_kind = 'carbon'
                AND membership.status = 'active'
                AND (
                    membership.org_role = 'owner'
                    OR EXISTS (
                        SELECT 1
                        FROM iam.organization_capability_grants AS capability_grant
                        WHERE capability_grant.organization_id = membership.organization_id
                          AND capability_grant.grantee_membership_id = membership.id
                          AND capability_grant.capability = 'members.invite'
                          AND capability_grant.revoked_at IS NULL
                    )
                )
          )
      )
$$;

REVOKE ALL ON FUNCTION iam_private.resolve_organization_invitation_tenant(text, uuid) FROM PUBLIC;

REVOKE ALL ON FUNCTION iam_private.carbon_handle_is_available(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.resolve_active_carbon_by_handle(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.resolve_active_carbon_by_contact_digest(
    iam.contact_kind, smallint, bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.list_active_carbon_login_contacts(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.complete_verified_signup(
    uuid, uuid, text, text, text, text, uuid, uuid
) FROM PUBLIC;

CREATE FUNCTION iam_private.is_organization_creator(
    p_organization_id uuid,
    p_carbon_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.organizations AS organization
        WHERE organization.id = p_organization_id
          AND organization.created_by_carbon_id = p_carbon_id
    )
$$;

CREATE FUNCTION iam_private.is_active_organization_member(
    p_organization_id uuid,
    p_principal_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.organization_memberships AS membership
        JOIN iam.organizations AS organization
          ON organization.id = membership.organization_id
         AND organization.status = 'active'
        JOIN iam.principals AS principal
          ON principal.id = membership.principal_id
         AND principal.kind = membership.principal_kind
         AND principal.status = 'active'
        WHERE membership.organization_id = p_organization_id
          AND membership.principal_id = p_principal_id
          AND membership.status = 'active'
    )
$$;

CREATE FUNCTION iam_private.has_organization_capability(
    p_organization_id uuid,
    p_principal_id uuid,
    p_capability text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.organization_memberships AS membership
        JOIN iam.organizations AS organization
          ON organization.id = membership.organization_id
         AND organization.status = 'active'
        JOIN iam.principals AS principal
          ON principal.id = membership.principal_id
         AND principal.kind = membership.principal_kind
         AND principal.status = 'active'
        WHERE membership.organization_id = p_organization_id
          AND membership.principal_id = p_principal_id
          AND membership.status = 'active'
          AND (
              membership.org_role = 'owner'
              OR EXISTS (
                  SELECT 1
                  FROM iam.organization_capability_grants AS capability_grant
                  JOIN iam.organization_capability_catalog AS catalog
                    ON catalog.capability = capability_grant.capability
                  WHERE capability_grant.organization_id = membership.organization_id
                    AND capability_grant.grantee_membership_id = membership.id
                    AND capability_grant.capability = p_capability
                    AND capability_grant.revoked_at IS NULL
                    AND (
                        (membership.principal_kind = 'carbon' AND catalog.allowed_for_carbon)
                        OR (membership.principal_kind = 'silicon' AND catalog.allowed_for_silicon)
                    )
              )
          )
    )
$$;

CREATE FUNCTION iam_private.has_platform_capability(
    p_carbon_id uuid,
    p_capability text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.platform_role_grants AS role_grant
        JOIN iam.platform_role_capabilities AS role_capability
          ON role_capability.role = role_grant.role
        JOIN iam.principals AS principal
          ON principal.id = role_grant.carbon_id
         AND principal.kind = 'carbon'
         AND principal.status = 'active'
        WHERE role_grant.carbon_id = p_carbon_id
          AND role_grant.revoked_at IS NULL
          AND role_capability.capability = p_capability
    )
$$;

CREATE FUNCTION iam_private.replace_carbon_status(
    p_target_carbon_id text,
    p_expected_version bigint,
    p_status text,
    p_reason text
)
RETURNS TABLE (
    principal_id uuid,
    carbon_id text,
    status text,
    version bigint,
    updated_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    actor_id uuid := iam_private.current_principal_id();
    target_id uuid;
    target_status text;
    target_version bigint;
BEGIN
    IF actor_id IS NULL
       OR NOT iam_private.has_platform_capability(actor_id, 'carbons.status_manage') THEN
        RAISE EXCEPTION 'platform Carbon status authority is required'
            USING ERRCODE = '42501';
    END IF;
    IF p_target_carbon_id IS NULL
       OR p_expected_version IS NULL
       OR p_status IS NULL
       OR p_reason IS NULL
       OR p_status NOT IN ('active', 'suspended')
       OR char_length(p_reason) NOT BETWEEN 1 AND 2000 THEN
        RAISE EXCEPTION 'invalid Carbon status transition input'
            USING ERRCODE = '22023';
    END IF;

    SELECT carbon.id, principal.status, carbon.version
    INTO target_id, target_status, target_version
    FROM iam.carbons AS carbon
    JOIN iam.principals AS principal
      ON principal.id = carbon.id
     AND principal.kind = 'carbon'
    WHERE carbon.carbon_id = p_target_carbon_id
      AND carbon.deleted_at IS NULL
    FOR UPDATE OF carbon, principal;

    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF target_version <> p_expected_version THEN
        RAISE EXCEPTION 'carbon_version_mismatch' USING ERRCODE = 'P0001';
    END IF;
    IF target_status NOT IN ('active', 'suspended') THEN
        RAISE EXCEPTION 'carbon_status_transition_forbidden' USING ERRCODE = 'P0001';
    END IF;
    IF target_status = p_status THEN
        RAISE EXCEPTION 'carbon_status_unchanged' USING ERRCODE = 'P0001';
    END IF;

    IF p_status = 'suspended' THEN
        IF EXISTS (
            SELECT 1
            FROM iam.organization_memberships AS membership
            JOIN iam.organizations AS organization
              ON organization.id = membership.organization_id
             AND organization.status = 'active'
            WHERE membership.principal_id = target_id
              AND membership.principal_kind = 'carbon'
              AND membership.status = 'active'
              AND membership.org_role = 'owner'
        ) THEN
            RAISE EXCEPTION 'carbon_owns_active_organization' USING ERRCODE = 'P0001';
        END IF;

        UPDATE iam.login_challenge_channels AS channel
        SET superseded_at = transaction_timestamp()
        FROM iam.login_challenges AS challenge
        WHERE challenge.id = channel.login_challenge_id
          AND challenge.carbon_id = target_id
          AND challenge.status = 'pending'
          AND channel.consumed_at IS NULL
          AND channel.superseded_at IS NULL;
        UPDATE iam.login_challenges AS login_challenge
        SET status = 'cancelled', cancelled_at = transaction_timestamp()
        WHERE login_challenge.carbon_id = target_id
          AND login_challenge.status = 'pending';
        UPDATE iam.step_up_assertions AS assertion
        SET consumed_at = transaction_timestamp()
        WHERE assertion.carbon_id = target_id
          AND assertion.consumed_at IS NULL;
        UPDATE iam.step_up_challenges AS step_up_challenge
        SET status = 'cancelled'
        WHERE step_up_challenge.carbon_id = target_id
          AND step_up_challenge.status = 'pending';
        UPDATE iam.sso_authorization_transactions AS sso_transaction
        SET status = 'cancelled'
        WHERE sso_transaction.carbon_id = target_id
          AND sso_transaction.status = 'pending';
        UPDATE iam.oauth_authorization_requests AS authorization_request
        SET status = 'denied', decided_at = transaction_timestamp()
        WHERE authorization_request.subject_principal_id = target_id
          AND authorization_request.subject_kind = 'carbon'
          AND authorization_request.status = 'pending';

        UPDATE iam.authentication_sessions AS authentication_session
        SET status = 'revoked',
            revoked_at = transaction_timestamp(),
            revocation_reason = 'Carbon suspended by platform administration',
            version = authentication_session.version + 1
        WHERE authentication_session.subject_principal_id = target_id
          AND authentication_session.status = 'active';
        UPDATE iam.refresh_token_families AS refresh_family
        SET status = 'revoked',
            revoked_at = transaction_timestamp(),
            revocation_reason = 'Carbon suspended by platform administration'
        WHERE refresh_family.subject_principal_id = target_id
          AND refresh_family.status = 'active';
        UPDATE iam.refresh_tokens AS token
        SET revoked_at = transaction_timestamp()
        FROM iam.refresh_token_families AS family
        WHERE family.id = token.family_id
          AND family.subject_principal_id = target_id
          AND token.revoked_at IS NULL;
        UPDATE iam.access_tokens AS access_token
        SET revoked_at = transaction_timestamp(),
            revocation_reason = 'Carbon suspended by platform administration'
        WHERE access_token.subject_principal_id = target_id
          AND access_token.revoked_at IS NULL;
        UPDATE iam.obo_proofs AS obo_proof
        SET revoked_at = transaction_timestamp()
        WHERE obo_proof.subject_principal_id = target_id
          AND obo_proof.revoked_at IS NULL;
        UPDATE iam.oauth_consent_grants AS consent_grant
        SET status = 'revoked', revoked_at = transaction_timestamp()
        WHERE consent_grant.subject_principal_id = target_id
          AND consent_grant.subject_kind = 'carbon'
          AND consent_grant.status = 'active';

        UPDATE iam.application_collaborators AS collaborator
        SET revoked_by_carbon_id = actor_id, revoked_at = transaction_timestamp()
        WHERE collaborator.carbon_id = target_id
          AND collaborator.revoked_at IS NULL;
        UPDATE iam.platform_role_grants AS role_grant
        SET revoked_by_carbon_id = actor_id,
            revoked_at = transaction_timestamp(),
            reason = p_reason
        WHERE role_grant.carbon_id = target_id
          AND role_grant.revoked_at IS NULL;
        UPDATE iam.organization_capability_grants AS capability_grant
        SET revoked_by_platform_carbon_id = actor_id,
            revoked_at = transaction_timestamp(),
            reason = left(p_reason, 1000)
        FROM iam.organization_memberships AS membership
        WHERE membership.id = capability_grant.grantee_membership_id
          AND membership.organization_id = capability_grant.organization_id
          AND membership.principal_id = target_id
          AND membership.principal_kind = 'carbon'
          AND capability_grant.revoked_at IS NULL;
        UPDATE iam.extra_silicon_access_grants AS access_grant
        SET revoked_by_platform_carbon_id = actor_id,
            revoked_at = transaction_timestamp()
        FROM iam.organization_memberships AS membership
        WHERE membership.id = access_grant.carbon_membership_id
          AND membership.organization_id = access_grant.organization_id
          AND membership.principal_id = target_id
          AND membership.principal_kind = 'carbon'
          AND access_grant.revoked_at IS NULL;
        UPDATE iam.organization_memberships AS membership
        SET status = 'suspended',
            suspended_at = transaction_timestamp(),
            authz_epoch = membership.authz_epoch + 1,
            org_role = 'member',
            role_granted_by_membership_id = NULL
        WHERE membership.principal_id = target_id
          AND membership.principal_kind = 'carbon'
          AND membership.status = 'active'
          AND membership.org_role <> 'owner';

        UPDATE iam.principals AS principal
        SET status = 'suspended',
            auth_epoch = principal.auth_epoch + 1,
            suspended_at = transaction_timestamp()
        WHERE principal.id = target_id
          AND principal.kind = 'carbon'
          AND principal.status = 'active';
    ELSE
        UPDATE iam.principals AS principal
        SET status = 'active',
            auth_epoch = principal.auth_epoch + 1,
            activated_at = transaction_timestamp(),
            suspended_at = NULL
        WHERE principal.id = target_id
          AND principal.kind = 'carbon'
          AND principal.status = 'suspended';
    END IF;

    UPDATE iam.carbons AS carbon
    SET updated_at = transaction_timestamp()
    WHERE carbon.id = target_id AND carbon.version = p_expected_version;

    RETURN QUERY
    SELECT carbon.id, carbon.carbon_id, principal.status, carbon.version, carbon.updated_at
    FROM iam.carbons AS carbon
    JOIN iam.principals AS principal ON principal.id = carbon.id
    WHERE carbon.id = target_id;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.replace_carbon_status(text, bigint, text, text)
FROM PUBLIC;

CREATE FUNCTION iam_private.get_platform_carbon(p_target_carbon_id text)
RETURNS TABLE (principal_id uuid, status text, version bigint)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT carbon.id, principal.status, carbon.version
    FROM iam.carbons AS carbon
    JOIN iam.principals AS principal
      ON principal.id = carbon.id
     AND principal.kind = 'carbon'
    WHERE carbon.carbon_id = p_target_carbon_id
      AND carbon.deleted_at IS NULL
      AND principal.status IN ('active', 'suspended')
      AND iam_private.has_platform_capability(
          iam_private.current_principal_id(),
          'carbons.status_manage'
      )
$$;

REVOKE ALL ON FUNCTION iam_private.get_platform_carbon(text) FROM PUBLIC;

CREATE FUNCTION iam_private.get_audit_public_identifiers(
    p_actor_principal_id uuid,
    p_actor_kind iam.principal_kind,
    p_organization_id uuid,
    p_application_id uuid
)
RETURNS TABLE (
    actor_public_id text,
    organization_public_id text,
    application_public_id text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_id uuid := iam_private.current_principal_id();
BEGIN
    IF NOT iam_private.has_platform_capability(current_id, 'audit.read_global')
       AND (
           p_organization_id IS NULL
           OR NOT iam_private.has_organization_capability(
               p_organization_id,
               current_id,
               'audit.read'
           )
       ) THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        CASE p_actor_kind
            WHEN 'carbon' THEN (
                SELECT carbon.carbon_id FROM iam.carbons AS carbon
                WHERE carbon.id = p_actor_principal_id
            )
            WHEN 'silicon' THEN (
                SELECT silicon.global_silicon_id FROM iam.silicons AS silicon
                WHERE silicon.id = p_actor_principal_id
            )
            WHEN 'application' THEN (
                SELECT application.app_id FROM iam.applications AS application
                WHERE application.id = p_actor_principal_id
            )
            WHEN 'service' THEN (
                SELECT service.service_id FROM iam.service_principals AS service
                WHERE service.id = p_actor_principal_id
            )
        END,
        (
            SELECT organization.org_id FROM iam.organizations AS organization
            WHERE organization.id = p_organization_id
        ),
        (
            SELECT application.app_id FROM iam.applications AS application
            WHERE application.id = p_application_id
        );
END;
$$;

REVOKE ALL ON FUNCTION iam_private.get_audit_public_identifiers(
    uuid, iam.principal_kind, uuid, uuid
) FROM PUBLIC;

CREATE FUNCTION iam_private.can_read_application(
    p_application_id uuid,
    p_carbon_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.applications AS application
        JOIN iam.principals AS principal
          ON principal.id = p_carbon_id
         AND principal.kind = 'carbon'
         AND principal.status = 'active'
        WHERE application.id = p_application_id
          AND (
              application.owner_carbon_id = p_carbon_id
              OR EXISTS (
                  SELECT 1
                  FROM iam.application_collaborators AS collaborator
                  WHERE collaborator.application_id = application.id
                    AND collaborator.carbon_id = p_carbon_id
                    AND collaborator.revoked_at IS NULL
              )
          )
    )
$$;

CREATE FUNCTION iam_private.can_manage_application(
    p_application_id uuid,
    p_carbon_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.applications AS application
        JOIN iam.principals AS principal
          ON principal.id = p_carbon_id
         AND principal.kind = 'carbon'
         AND principal.status = 'active'
        WHERE application.id = p_application_id
          AND (
              application.owner_carbon_id = p_carbon_id
              OR EXISTS (
                  SELECT 1
                  FROM iam.application_collaborators AS collaborator
                  WHERE collaborator.application_id = application.id
                    AND collaborator.carbon_id = p_carbon_id
                    AND collaborator.collaborator_role = 'owner_delegate'
                    AND collaborator.revoked_at IS NULL
              )
          )
    )
$$;

CREATE FUNCTION iam_private.can_manage_application_technical(
    p_application_id uuid,
    p_carbon_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.applications AS application
        JOIN iam.principals AS principal
          ON principal.id = p_carbon_id
         AND principal.kind = 'carbon'
         AND principal.status = 'active'
        WHERE application.id = p_application_id
          AND (
              application.owner_carbon_id = p_carbon_id
              OR EXISTS (
                  SELECT 1
                  FROM iam.application_collaborators AS collaborator
                  WHERE collaborator.application_id = application.id
                    AND collaborator.carbon_id = p_carbon_id
                    AND collaborator.collaborator_role IN ('owner_delegate', 'developer')
                    AND collaborator.revoked_at IS NULL
              )
          )
    )
$$;

CREATE FUNCTION iam_private.can_administer_application(
    p_application_id uuid,
    p_carbon_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.applications AS application
        WHERE application.id = p_application_id
          AND (
              iam_private.has_platform_capability(p_carbon_id, 'applications.review')
              OR iam_private.has_platform_capability(p_carbon_id, 'applications.suspend')
              OR iam_private.has_platform_capability(p_carbon_id, 'applications.policy')
          )
    )
$$;

CREATE FUNCTION iam_private.resolve_platform_sso_organization(
    p_organization_handle text
)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT organization.id
    FROM iam.organizations AS organization
    WHERE organization.org_id = p_organization_handle
      AND organization.status = 'active'
      AND iam_private.has_platform_capability(
          iam_private.current_principal_id(),
          'organizations.sso_feature'
      )
$$;

REVOKE ALL ON FUNCTION iam_private.resolve_platform_sso_organization(text) FROM PUBLIC;

CREATE FUNCTION iam_private.replace_organization_sso_entitlement(
    p_organization_handle text,
    p_expected_version bigint,
    p_enabled boolean,
    p_reason text
)
RETURNS TABLE (
    organization_id uuid,
    org_id text,
    enabled boolean,
    status text,
    version bigint,
    updated_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    resolved_organization_id uuid;
    current_config iam.organization_sso_configs%ROWTYPE;
    next_status text;
BEGIN
    IF NOT iam_private.has_platform_capability(
        iam_private.current_principal_id(),
        'organizations.sso_feature'
    ) THEN
        RAISE EXCEPTION 'platform SSO entitlement authority is required'
            USING ERRCODE = '42501';
    END IF;
    IF p_expected_version <= 0
       OR (p_reason IS NOT NULL AND (
            p_reason = ''
            OR p_reason <> btrim(p_reason)
            OR char_length(p_reason) > 2000
       )) THEN
        RAISE EXCEPTION 'invalid SSO entitlement input' USING ERRCODE = '22023';
    END IF;

    SELECT organization.id
    INTO resolved_organization_id
    FROM iam.organizations AS organization
    WHERE organization.org_id = p_organization_handle
      AND organization.status = 'active'
    FOR UPDATE OF organization;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT config.*
    INTO current_config
    FROM iam.organization_sso_configs AS config
    WHERE config.organization_id = resolved_organization_id
    FOR UPDATE OF config;

    IF NOT FOUND THEN
        IF p_expected_version <> 1 THEN
            RAISE EXCEPTION 'sso_config_version_mismatch' USING ERRCODE = 'P0001';
        END IF;
        INSERT INTO iam.organization_sso_configs (
            organization_id, platform_enabled, status
        ) VALUES (
            resolved_organization_id,
            p_enabled,
            CASE WHEN p_enabled THEN 'pending' ELSE 'disabled' END
        );
    ELSE
        IF current_config.version <> p_expected_version THEN
            RAISE EXCEPTION 'sso_config_version_mismatch' USING ERRCODE = 'P0001';
        END IF;
        next_status := CASE
            WHEN NOT p_enabled THEN 'disabled'
            WHEN current_config.provider_organization_id IS NOT NULL
                 AND EXISTS (
                    SELECT 1
                    FROM iam.sso_connections AS connection
                    WHERE connection.organization_id = resolved_organization_id
                      AND connection.status = 'active'
                 ) THEN 'active'
            ELSE 'pending'
        END;
        UPDATE iam.organization_sso_configs AS config
        SET platform_enabled = p_enabled,
            status = next_status,
            last_error_code = NULL
        WHERE config.organization_id = resolved_organization_id;
    END IF;

    RETURN QUERY
    SELECT
        organization.id,
        organization.org_id,
        config.platform_enabled,
        config.status,
        config.version,
        config.updated_at
    FROM iam.organizations AS organization
    JOIN iam.organization_sso_configs AS config
      ON config.organization_id = organization.id
    WHERE organization.id = resolved_organization_id;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.replace_organization_sso_entitlement(
    text, bigint, boolean, text
) FROM PUBLIC;

CREATE FUNCTION iam_private.begin_sso_authorization(
    p_organization_handle text,
    p_authentication_session_id uuid,
    p_transaction_id uuid,
    p_state_digest bytea,
    p_nonce_digest bytea,
    p_digest_key_version smallint,
    p_return_ciphertext bytea,
    p_return_nonce bytea,
    p_encryption_key_version smallint,
    p_expires_at timestamptz
)
RETURNS TABLE (
    organization_id uuid,
    connection_id uuid,
    provider_organization_id text,
    provider_connection_id text
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_carbon_id uuid := iam_private.current_principal_id();
    resolved_organization_id uuid;
    resolved_connection_id uuid;
    resolved_provider_organization_id text;
    resolved_provider_connection_id text;
BEGIN
    IF current_carbon_id IS NULL
       OR p_transaction_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_digest_key_version <= 0
       OR p_encryption_key_version <= 0
       OR octet_length(p_state_digest) <> 32
       OR octet_length(p_nonce_digest) <> 32
       OR octet_length(p_return_ciphertext) NOT BETWEEN 17 AND 8192
       OR octet_length(p_return_nonce) NOT BETWEEN 12 AND 32
       OR p_expires_at <= transaction_timestamp()
       OR p_expires_at > transaction_timestamp() + interval '10 minutes' THEN
        RAISE EXCEPTION 'invalid SSO authorization input' USING ERRCODE = '22023';
    END IF;

    SELECT
        organization.id,
        connection.id,
        config.provider_organization_id,
        connection.provider_connection_id
    INTO
        resolved_organization_id,
        resolved_connection_id,
        resolved_provider_organization_id,
        resolved_provider_connection_id
    FROM iam.organizations AS organization
    JOIN iam.organization_sso_configs AS config
      ON config.organization_id = organization.id
     AND config.platform_enabled
     AND config.status = 'active'
     AND config.provider_organization_id IS NOT NULL
    JOIN iam.sso_connections AS connection
      ON connection.organization_id = organization.id
     AND connection.status = 'active'
    JOIN iam.principals AS principal
      ON principal.id = current_carbon_id
     AND principal.kind = 'carbon'
     AND principal.status = 'active'
    JOIN iam.authentication_sessions AS authentication_session
      ON authentication_session.id = p_authentication_session_id
     AND authentication_session.subject_principal_id = current_carbon_id
     AND authentication_session.subject_kind = 'carbon'
     AND authentication_session.status = 'active'
     AND authentication_session.idle_expires_at > transaction_timestamp()
     AND authentication_session.absolute_expires_at > transaction_timestamp()
     AND authentication_session.subject_auth_epoch = principal.auth_epoch
    WHERE organization.org_id = p_organization_handle
      AND organization.status = 'active'
      AND organization.join_method = 'sso'
    FOR SHARE OF organization, config, connection, principal, authentication_session;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'SSO authorization is unavailable' USING ERRCODE = '42501';
    END IF;

    UPDATE iam.sso_authorization_transactions AS authorization_transaction
    SET status = 'cancelled'
    WHERE authorization_transaction.organization_id = resolved_organization_id
      AND authorization_transaction.carbon_id = current_carbon_id
      AND authorization_transaction.authentication_session_id = p_authentication_session_id
      AND authorization_transaction.status = 'pending';

    INSERT INTO iam.sso_authorization_transactions (
        id, organization_id, connection_id, carbon_id,
        authentication_session_id, state_digest, nonce_digest,
        digest_key_version, return_uri_ciphertext, return_uri_nonce,
        encryption_key_version, expires_at
    ) VALUES (
        p_transaction_id, resolved_organization_id, resolved_connection_id,
        current_carbon_id, p_authentication_session_id, p_state_digest,
        p_nonce_digest, p_digest_key_version, p_return_ciphertext,
        p_return_nonce, p_encryption_key_version, p_expires_at
    );

    organization_id := resolved_organization_id;
    connection_id := resolved_connection_id;
    provider_organization_id := resolved_provider_organization_id;
    provider_connection_id := resolved_provider_connection_id;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.begin_sso_authorization(
    text, uuid, uuid, bytea, bytea, smallint, bytea, bytea, smallint, timestamptz
) FROM PUBLIC;

CREATE FUNCTION iam_private.complete_sso_authorization(
    p_authentication_session_id uuid,
    p_state_digest_key_versions smallint[],
    p_state_digests bytea[],
    p_nonce_digests bytea[],
    p_provider_organization_id text,
    p_provider_connection_id text,
    p_provider_subject text,
    p_normalized_email text,
    p_contact_digest_key_versions smallint[],
    p_contact_digests bytea[],
    p_provider_groups text[],
    p_new_membership_id uuid,
    p_sso_identity_id uuid
)
RETURNS TABLE (
    organization_id uuid,
    membership_id uuid,
    sso_identity_id uuid,
    membership_created boolean,
    config_version bigint,
    authorization_transaction_id uuid,
    return_uri_ciphertext bytea,
    return_uri_nonce bytea,
    return_uri_encryption_key_version smallint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_carbon_id uuid := iam_private.current_principal_id();
    authorization_record iam.sso_authorization_transactions%ROWTYPE;
    invitation_record iam.organization_invitations%ROWTYPE;
    policy_record iam.sso_membership_policies%ROWTYPE;
    membership_record iam.organization_memberships%ROWTYPE;
    resolved_contact_id uuid;
    resolved_identity_id uuid;
    resolved_config_version bigint;
    assignment_membership_id uuid;
    selected_job_role text;
    selected_first_silicon_id uuid;
    selected_trust_boundary iam.trust_boundary;
    selected_trust_level iam.trust_level;
    email_domain text;
    admitted_by_invitation boolean := false;
    admitted_by_policy boolean := false;
    was_membership_created boolean := false;
    expected_count integer;
    active_count integer;
BEGIN
    IF current_carbon_id IS NULL
       OR p_new_membership_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_sso_identity_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_state_digest_key_versions IS NULL
       OR p_state_digests IS NULL
       OR p_nonce_digests IS NULL
       OR cardinality(p_state_digest_key_versions) NOT BETWEEN 1 AND 16
       OR cardinality(p_state_digest_key_versions) <> cardinality(p_state_digests)
       OR cardinality(p_state_digest_key_versions) <> cardinality(p_nonce_digests)
       OR array_position(p_state_digest_key_versions, NULL) IS NOT NULL
       OR array_position(p_state_digests, NULL) IS NOT NULL
       OR array_position(p_nonce_digests, NULL) IS NOT NULL
       OR EXISTS (
            SELECT 1 FROM unnest(p_state_digest_key_versions) AS key_version
            WHERE key_version <= 0
       )
       OR EXISTS (
            SELECT 1 FROM unnest(p_state_digests) AS digest
            WHERE octet_length(digest) <> 32
       )
       OR EXISTS (
            SELECT 1 FROM unnest(p_nonce_digests) AS digest
            WHERE octet_length(digest) <> 32
       )
       OR (
            SELECT count(DISTINCT key_version)
            FROM unnest(p_state_digest_key_versions) AS key_version
       ) <> cardinality(p_state_digest_key_versions)
       OR p_contact_digest_key_versions IS NULL
       OR p_contact_digests IS NULL
       OR cardinality(p_contact_digest_key_versions) NOT BETWEEN 1 AND 16
       OR cardinality(p_contact_digest_key_versions) <> cardinality(p_contact_digests)
       OR array_position(p_contact_digest_key_versions, NULL) IS NOT NULL
       OR array_position(p_contact_digests, NULL) IS NOT NULL
       OR EXISTS (
            SELECT 1 FROM unnest(p_contact_digest_key_versions) AS key_version
            WHERE key_version <= 0
       )
       OR EXISTS (
            SELECT 1 FROM unnest(p_contact_digests) AS digest
            WHERE octet_length(digest) <> 32
       )
       OR (
            SELECT count(DISTINCT key_version)
            FROM unnest(p_contact_digest_key_versions) AS key_version
       ) <> cardinality(p_contact_digest_key_versions)
       OR p_provider_groups IS NULL
       OR cardinality(p_provider_groups) > 500
       OR array_position(p_provider_groups, NULL) IS NOT NULL
       OR EXISTS (
            SELECT 1 FROM unnest(p_provider_groups) AS provider_group
            WHERE char_length(provider_group) NOT BETWEEN 1 AND 512
       )
       OR p_provider_organization_id = ''
       OR char_length(p_provider_organization_id) > 255
       OR p_provider_connection_id = ''
       OR char_length(p_provider_connection_id) > 255
       OR char_length(p_provider_subject) NOT BETWEEN 1 AND 512
       OR char_length(p_normalized_email) > 320
       OR p_normalized_email <> lower(p_normalized_email)
       OR p_normalized_email !~ '^[^@]+@[^@]+$' THEN
        RAISE EXCEPTION 'invalid SSO callback input' USING ERRCODE = '22023';
    END IF;

    UPDATE iam.sso_authorization_transactions AS stale_transaction
    SET status = 'expired'
    WHERE stale_transaction.carbon_id = current_carbon_id
      AND stale_transaction.authentication_session_id = p_authentication_session_id
      AND stale_transaction.status = 'pending'
      AND stale_transaction.expires_at <= transaction_timestamp();

    SELECT authorization_transaction
    INTO authorization_record
    FROM iam.sso_authorization_transactions AS authorization_transaction
    JOIN iam.organization_sso_configs AS config
      ON config.organization_id = authorization_transaction.organization_id
     AND config.platform_enabled
     AND config.status = 'active'
     AND config.provider_organization_id = p_provider_organization_id
    JOIN iam.sso_connections AS connection
      ON connection.organization_id = authorization_transaction.organization_id
     AND connection.id = authorization_transaction.connection_id
     AND connection.provider_connection_id = p_provider_connection_id
     AND connection.status = 'active'
    JOIN iam.principals AS principal
      ON principal.id = authorization_transaction.carbon_id
     AND principal.kind = 'carbon'
     AND principal.status = 'active'
    JOIN iam.authentication_sessions AS authentication_session
      ON authentication_session.id = authorization_transaction.authentication_session_id
     AND authentication_session.subject_principal_id = authorization_transaction.carbon_id
     AND authentication_session.subject_kind = 'carbon'
     AND authentication_session.status = 'active'
     AND authentication_session.idle_expires_at > transaction_timestamp()
     AND authentication_session.absolute_expires_at > transaction_timestamp()
     AND authentication_session.subject_auth_epoch = principal.auth_epoch
    WHERE authorization_transaction.carbon_id = current_carbon_id
      AND authorization_transaction.authentication_session_id = p_authentication_session_id
      AND authorization_transaction.status = 'pending'
      AND authorization_transaction.expires_at > transaction_timestamp()
      AND EXISTS (
          SELECT 1
          FROM generate_subscripts(p_state_digest_key_versions, 1) AS candidate(index)
          WHERE p_state_digest_key_versions[candidate.index] =
                    authorization_transaction.digest_key_version
            AND p_state_digests[candidate.index] = authorization_transaction.state_digest
            AND p_nonce_digests[candidate.index] = authorization_transaction.nonce_digest
      )
    FOR UPDATE OF authorization_transaction, config, connection;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'SSO callback correlation is invalid' USING ERRCODE = '23514';
    END IF;

    SELECT config.version
    INTO resolved_config_version
    FROM iam.organization_sso_configs AS config
    WHERE config.organization_id = authorization_record.organization_id;

    SELECT contact.id
    INTO resolved_contact_id
    FROM iam.carbon_contacts AS contact
    JOIN iam.contact_blind_indexes AS blind_index
      ON blind_index.contact_id = contact.id
     AND blind_index.contact_kind = contact.kind
    WHERE contact.carbon_id = current_carbon_id
      AND contact.kind = 'email'
      AND contact.status = 'active'
      AND contact.verified_at IS NOT NULL
      AND EXISTS (
          SELECT 1
          FROM generate_subscripts(p_contact_digest_key_versions, 1) AS candidate(index)
          WHERE p_contact_digest_key_versions[candidate.index] = blind_index.hmac_key_version
            AND p_contact_digests[candidate.index] = blind_index.digest
      )
    ORDER BY contact.is_primary DESC, contact.created_at, contact.id
    LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'SSO profile does not match the active Carbon contact'
            USING ERRCODE = '23514';
    END IF;

    SELECT membership.*
    INTO membership_record
    FROM iam.organization_memberships AS membership
    WHERE membership.organization_id = authorization_record.organization_id
      AND membership.principal_id = current_carbon_id
      AND membership.principal_kind = 'carbon'
    FOR UPDATE OF membership;

    IF NOT FOUND OR membership_record.status <> 'active' THEN
        SELECT invitation.*
        INTO invitation_record
        FROM iam.organization_invitations AS invitation
        WHERE invitation.organization_id = authorization_record.organization_id
          AND invitation.target_carbon_id = current_carbon_id
          AND invitation.status = 'pending'
          AND invitation.expires_at > transaction_timestamp()
        ORDER BY invitation.created_at, invitation.id
        LIMIT 1
        FOR UPDATE OF invitation;

        admitted_by_invitation := FOUND;
        IF admitted_by_invitation THEN
            selected_job_role := invitation_record.job_role;
            selected_first_silicon_id := invitation_record.first_silicon_membership_id;
            selected_trust_boundary := invitation_record.default_trust_boundary;
            selected_trust_level := invitation_record.default_trust_level;
            assignment_membership_id := invitation_record.invited_by_membership_id;
        ELSE
            SELECT policy.*
            INTO policy_record
            FROM iam.sso_membership_policies AS policy
            WHERE policy.organization_id = authorization_record.organization_id
            FOR SHARE OF policy;

            email_domain := substring(
                p_normalized_email FROM position('@' IN p_normalized_email) + 1
            );
            admitted_by_policy := FOUND
                AND policy_record.allow_policy_admission
                AND (
                    email_domain = ANY(policy_record.allowed_domains)
                    OR policy_record.allowed_groups && p_provider_groups
                );
            IF NOT admitted_by_policy THEN
                RAISE EXCEPTION 'SSO admission policy did not match' USING ERRCODE = '42501';
            END IF;
            selected_job_role := policy_record.default_job_role;
            selected_first_silicon_id := policy_record.first_silicon_membership_id;
            selected_trust_boundary := policy_record.default_trust_boundary;
            selected_trust_level := policy_record.default_trust_level;
            SELECT owner.id
            INTO assignment_membership_id
            FROM iam.organization_memberships AS owner
            WHERE owner.organization_id = authorization_record.organization_id
              AND owner.status = 'active'
              AND owner.principal_kind = 'carbon'
              AND owner.org_role = 'owner';
        END IF;

        IF selected_first_silicon_id IS NOT NULL AND NOT EXISTS (
            SELECT 1
            FROM iam.silicons AS silicon
            JOIN iam.organization_memberships AS silicon_membership
              ON silicon_membership.organization_id = silicon.organization_id
             AND silicon_membership.id = silicon.membership_id
             AND silicon_membership.status = 'active'
            WHERE silicon.organization_id = authorization_record.organization_id
              AND silicon.membership_id = selected_first_silicon_id
              AND silicon.provisioning_status <> 'deleted'
        ) THEN
            RAISE EXCEPTION 'SSO admission defaults are no longer active'
                USING ERRCODE = '23514';
        END IF;

        IF admitted_by_invitation THEN
            SELECT count(*) INTO expected_count
            FROM iam.organization_invitation_tags AS assignment
            WHERE assignment.organization_id = authorization_record.organization_id
              AND assignment.invitation_id = invitation_record.id;
            SELECT count(*) INTO active_count
            FROM iam.organization_invitation_tags AS assignment
            JOIN iam.organization_tags AS tag
              ON tag.organization_id = assignment.organization_id
             AND tag.id = assignment.tag_id
             AND tag.status = 'active'
            WHERE assignment.organization_id = authorization_record.organization_id
              AND assignment.invitation_id = invitation_record.id;
        ELSE
            SELECT count(*) INTO expected_count
            FROM iam.sso_membership_policy_tags AS assignment
            WHERE assignment.organization_id = authorization_record.organization_id;
            SELECT count(*) INTO active_count
            FROM iam.sso_membership_policy_tags AS assignment
            JOIN iam.organization_tags AS tag
              ON tag.organization_id = assignment.organization_id
             AND tag.id = assignment.tag_id
             AND tag.status = 'active'
            WHERE assignment.organization_id = authorization_record.organization_id;
        END IF;
        IF expected_count <> active_count THEN
            RAISE EXCEPTION 'SSO admission tags are no longer active' USING ERRCODE = '23514';
        END IF;

        IF membership_record.id IS NULL THEN
            INSERT INTO iam.organization_memberships (
                id, organization_id, principal_id, principal_kind,
                org_role, job_role
            ) VALUES (
                p_new_membership_id,
                authorization_record.organization_id,
                current_carbon_id,
                'carbon',
                'member',
                selected_job_role
            )
            RETURNING * INTO membership_record;
            was_membership_created := true;
        ELSE
            UPDATE iam.organization_memberships AS membership
            SET status = 'active',
                suspended_at = NULL,
                removed_at = NULL,
                org_role = 'member',
                role_granted_by_membership_id = NULL,
                job_role = selected_job_role,
                authz_epoch = membership.authz_epoch + 1
            WHERE membership.organization_id = authorization_record.organization_id
              AND membership.id = membership_record.id
              AND membership.status <> 'active'
            RETURNING membership.* INTO membership_record;
        END IF;

        UPDATE iam.organization_capability_grants AS capability_grant
        SET revoked_by_membership_id = membership_record.id,
            revoked_at = transaction_timestamp(),
            reason = 'membership admitted or reactivated by SSO'
        WHERE capability_grant.organization_id = authorization_record.organization_id
          AND capability_grant.grantee_membership_id = membership_record.id
          AND capability_grant.revoked_at IS NULL;

        INSERT INTO iam.carbon_membership_settings (
            organization_id, membership_id, carbon_id,
            first_silicon_membership_id, default_trust_boundary,
            default_trust_level
        ) VALUES (
            authorization_record.organization_id,
            membership_record.id,
            current_carbon_id,
            selected_first_silicon_id,
            selected_trust_boundary,
            selected_trust_level
        )
        ON CONFLICT (membership_id) DO UPDATE
        SET first_silicon_membership_id = EXCLUDED.first_silicon_membership_id,
            default_trust_boundary = EXCLUDED.default_trust_boundary,
            default_trust_level = EXCLUDED.default_trust_level;

        DELETE FROM iam.membership_tags AS membership_tag
        WHERE membership_tag.organization_id = authorization_record.organization_id
          AND membership_tag.membership_id = membership_record.id;
        IF admitted_by_invitation THEN
            INSERT INTO iam.membership_tags (
                organization_id, membership_id, tag_id, assigned_by_membership_id
            )
            SELECT
                assignment.organization_id,
                membership_record.id,
                assignment.tag_id,
                assignment_membership_id
            FROM iam.organization_invitation_tags AS assignment
            WHERE assignment.organization_id = authorization_record.organization_id
              AND assignment.invitation_id = invitation_record.id;
        ELSE
            INSERT INTO iam.membership_tags (
                organization_id, membership_id, tag_id, assigned_by_membership_id
            )
            SELECT
                assignment.organization_id,
                membership_record.id,
                assignment.tag_id,
                assignment_membership_id
            FROM iam.sso_membership_policy_tags AS assignment
            WHERE assignment.organization_id = authorization_record.organization_id;
        END IF;

        UPDATE iam.extra_silicon_access_grants AS access_grant
        SET revoked_by_membership_id = membership_record.id,
            revoked_at = transaction_timestamp()
        WHERE access_grant.organization_id = authorization_record.organization_id
          AND access_grant.carbon_membership_id = membership_record.id
          AND access_grant.revoked_at IS NULL;
        IF admitted_by_invitation THEN
            INSERT INTO iam.extra_silicon_access_grants (
                organization_id, carbon_membership_id,
                silicon_membership_id, granted_by_membership_id
            )
            SELECT
                assignment.organization_id,
                membership_record.id,
                assignment.silicon_membership_id,
                assignment_membership_id
            FROM iam.organization_invitation_extra_silicons AS assignment
            JOIN iam.silicons AS silicon
              ON silicon.organization_id = assignment.organization_id
             AND silicon.membership_id = assignment.silicon_membership_id
             AND silicon.provisioning_status <> 'deleted'
            JOIN iam.organization_memberships AS silicon_membership
              ON silicon_membership.organization_id = silicon.organization_id
             AND silicon_membership.id = silicon.membership_id
             AND silicon_membership.status = 'active'
            WHERE assignment.organization_id = authorization_record.organization_id
              AND assignment.invitation_id = invitation_record.id;

            GET DIAGNOSTICS active_count = ROW_COUNT;
            SELECT count(*) INTO expected_count
            FROM iam.organization_invitation_extra_silicons AS assignment
            WHERE assignment.organization_id = authorization_record.organization_id
              AND assignment.invitation_id = invitation_record.id;
            IF active_count <> expected_count THEN
                RAISE EXCEPTION 'SSO invitation defaults are no longer active'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;

    SELECT identity.id
    INTO resolved_identity_id
    FROM iam.sso_identities AS identity
    WHERE identity.connection_id = authorization_record.connection_id
      AND identity.provider_subject = p_provider_subject
    FOR UPDATE OF identity;

    IF FOUND THEN
        IF EXISTS (
            SELECT 1
            FROM iam.sso_identities AS identity
            WHERE identity.id = resolved_identity_id
              AND identity.carbon_id <> current_carbon_id
        ) THEN
            RAISE EXCEPTION 'SSO subject is already bound to another Carbon'
                USING ERRCODE = '23505';
        END IF;
        UPDATE iam.sso_identities AS identity
        SET verified_contact_id = resolved_contact_id,
            last_authenticated_at = transaction_timestamp(),
            revoked_at = NULL
        WHERE identity.id = resolved_identity_id;
    ELSE
        IF EXISTS (
            SELECT 1
            FROM iam.sso_identities AS identity
            WHERE identity.connection_id = authorization_record.connection_id
              AND identity.carbon_id = current_carbon_id
        ) THEN
            RAISE EXCEPTION 'Carbon is already bound to another SSO subject'
                USING ERRCODE = '23505';
        END IF;
        INSERT INTO iam.sso_identities (
            id, organization_id, connection_id, provider_subject,
            carbon_id, verified_contact_id, last_authenticated_at
        ) VALUES (
            p_sso_identity_id,
            authorization_record.organization_id,
            authorization_record.connection_id,
            p_provider_subject,
            current_carbon_id,
            resolved_contact_id,
            transaction_timestamp()
        )
        RETURNING id INTO resolved_identity_id;
    END IF;

    IF admitted_by_invitation THEN
        UPDATE iam.organization_invitations AS invitation
        SET status = 'accepted', accepted_at = transaction_timestamp()
        WHERE invitation.organization_id = authorization_record.organization_id
          AND invitation.id = invitation_record.id
          AND invitation.status = 'pending';
    END IF;

    UPDATE iam.sso_authorization_transactions AS authorization_transaction
    SET status = 'completed', consumed_at = transaction_timestamp()
    WHERE authorization_transaction.id = authorization_record.id
      AND authorization_transaction.status = 'pending';

    organization_id := authorization_record.organization_id;
    membership_id := membership_record.id;
    sso_identity_id := resolved_identity_id;
    membership_created := was_membership_created;
    config_version := resolved_config_version;
    authorization_transaction_id := authorization_record.id;
    return_uri_ciphertext := authorization_record.return_uri_ciphertext;
    return_uri_nonce := authorization_record.return_uri_nonce;
    return_uri_encryption_key_version := authorization_record.encryption_key_version;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.complete_sso_authorization(
    uuid, smallint[], bytea[], bytea[], text, text, text, text,
    smallint[], bytea[], text[], uuid, uuid
) FROM PUBLIC;

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
    config_version bigint,
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
    resolved_config_version bigint;
    resolved_status text;
    duplicate_receipt iam.external_webhook_receipts%ROWTYPE;
    inserted_receipt boolean;
    affected_rows bigint;
    connection_changed boolean := false;
    config_changed boolean := false;
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
            config.version,
            false,
            connection.status
        FROM iam.organization_sso_configs AS config
        JOIN iam.sso_connections AS connection
          ON connection.organization_id = config.organization_id
         AND connection.provider_connection_id = p_provider_connection_id
        WHERE config.provider_organization_id = p_provider_organization_id;
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
        UPDATE iam.sso_connections AS other_connection
        SET status = 'disabled',
            disabled_at = transaction_timestamp(),
            activated_at = NULL
        WHERE other_connection.organization_id = resolved_organization_id
          AND other_connection.provider_connection_id <> p_provider_connection_id
          AND other_connection.status = 'active';
        IF FOUND THEN
            connection_changed := true;
        END IF;

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
            IF FOUND THEN
                connection_changed := true;
            END IF;
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
            connection_changed := true;
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
        IF FOUND THEN
            config_changed := true;
        END IF;
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
                  connection.status <> 'disabled'
                  OR (
                      p_connection_type IS NOT NULL
                      AND connection.connection_type IS DISTINCT FROM p_connection_type
                  )
              );
            IF FOUND THEN
                connection_changed := true;
            END IF;
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
        IF FOUND THEN
            config_changed := true;
        END IF;
        resolved_status := 'disabled';
    END IF;

    UPDATE iam.external_webhook_receipts AS receipt
    SET status = 'processed', processed_at = transaction_timestamp(),
        attempt_count = receipt.attempt_count + 1
    WHERE receipt.id = p_receipt_id;

    SELECT config.version
    INTO resolved_config_version
    FROM iam.organization_sso_configs AS config
    WHERE config.organization_id = resolved_organization_id;

    organization_id := resolved_organization_id;
    connection_id := resolved_connection_id;
    config_version := resolved_config_version;
    changed := connection_changed OR config_changed;
    status := resolved_status;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.apply_workos_connection_event(
    uuid, text, text, text, uuid, text, text, bytea, timestamptz
) FROM PUBLIC;

CREATE FUNCTION iam_private.remove_organization_membership(
    p_organization_id uuid,
    p_membership_id uuid,
    p_expected_membership_version bigint,
    p_expected_silicon_version bigint,
    p_reassign_reports_to uuid
)
RETURNS TABLE (
    principal_id uuid,
    principal_kind iam.principal_kind,
    membership_version bigint,
    silicon_version bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_actor_id uuid := iam_private.current_principal_id();
    actor_membership_id uuid;
    target_membership iam.organization_memberships%ROWTYPE;
    target_silicon iam.silicons%ROWTYPE;
    resulting_membership_version bigint;
    resulting_silicon_version bigint;
    direct_report_count bigint;
BEGIN
    IF p_organization_id IS NULL
       OR p_membership_id IS NULL
       OR p_expected_membership_version IS NULL
       OR p_expected_membership_version <= 0
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id() THEN
        RAISE EXCEPTION 'membership_removal_invalid' USING ERRCODE = '22023';
    END IF;

    SELECT membership.id
    INTO actor_membership_id
    FROM iam.organization_memberships AS membership
    JOIN iam.principals AS principal
      ON principal.id = membership.principal_id
     AND principal.kind = membership.principal_kind
     AND principal.status = 'active'
    WHERE membership.organization_id = p_organization_id
      AND membership.principal_id = current_actor_id
      AND membership.status = 'active';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'membership_removal_forbidden' USING ERRCODE = '42501';
    END IF;

    SELECT membership.*
    INTO target_membership
    FROM iam.organization_memberships AS membership
    WHERE membership.organization_id = p_organization_id
      AND membership.id = p_membership_id
    FOR UPDATE OF membership;

    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF target_membership.status <> 'active'
       OR target_membership.version <> p_expected_membership_version THEN
        RAISE EXCEPTION 'membership_version_mismatch' USING ERRCODE = 'P0001';
    END IF;
    IF target_membership.org_role = 'owner' THEN
        RAISE EXCEPTION 'owner_cannot_be_removed' USING ERRCODE = 'P0001';
    END IF;
    IF NOT iam_private.has_organization_capability(
        p_organization_id,
        current_actor_id,
        CASE target_membership.principal_kind
            WHEN 'carbon' THEN 'members.remove'
            WHEN 'silicon' THEN 'silicons.remove'
            ELSE '__unsupported__'
        END
    ) THEN
        RAISE EXCEPTION 'membership_removal_forbidden' USING ERRCODE = '42501';
    END IF;

    IF target_membership.principal_kind = 'silicon' THEN
        IF p_expected_silicon_version IS NULL OR p_expected_silicon_version <= 0 THEN
            RAISE EXCEPTION 'silicon_version_mismatch' USING ERRCODE = 'P0001';
        END IF;
        SELECT silicon.*
        INTO target_silicon
        FROM iam.silicons AS silicon
        WHERE silicon.organization_id = p_organization_id
          AND silicon.id = target_membership.principal_id
          AND silicon.membership_id = target_membership.id
        FOR UPDATE OF silicon;

        IF NOT FOUND
           OR target_silicon.provisioning_status = 'deleted'
           OR target_silicon.version <> p_expected_silicon_version THEN
            RAISE EXCEPTION 'silicon_version_mismatch' USING ERRCODE = 'P0001';
        END IF;

        -- Reporting mutations use the same tenant-scoped advisory lock in the
        -- hierarchy trigger. This prevents a concurrent child assignment from
        -- appearing after the direct-report check but before retirement.
        PERFORM pg_advisory_xact_lock(hashtextextended(p_organization_id::text, 734921));

        SELECT count(*)
        INTO direct_report_count
        FROM iam.silicons AS report
        WHERE report.organization_id = p_organization_id
          AND report.reports_to_membership_id = target_membership.id
          AND report.provisioning_status <> 'deleted';

        IF direct_report_count > 0 AND p_reassign_reports_to IS NULL THEN
            RAISE EXCEPTION 'reassign_reports_to_required' USING ERRCODE = 'P0001';
        END IF;
        IF p_reassign_reports_to = target_membership.id
           OR (
                p_reassign_reports_to IS NOT NULL
                AND NOT EXISTS (
                    SELECT 1
                    FROM iam.silicons AS replacement
                    JOIN iam.organization_memberships AS replacement_membership
                      ON replacement_membership.organization_id = replacement.organization_id
                     AND replacement_membership.id = replacement.membership_id
                     AND replacement_membership.status = 'active'
                    JOIN iam.principals AS replacement_principal
                      ON replacement_principal.id = replacement.id
                     AND replacement_principal.kind = 'silicon'
                     AND replacement_principal.status = 'active'
                    WHERE replacement.organization_id = p_organization_id
                      AND replacement.membership_id = p_reassign_reports_to
                      AND replacement.provisioning_status <> 'deleted'
                )
           ) THEN
            RAISE EXCEPTION 'invalid_reporting_hierarchy' USING ERRCODE = 'P0001';
        END IF;

        UPDATE iam.silicons AS report
        SET reports_to_membership_id = p_reassign_reports_to
        WHERE report.organization_id = p_organization_id
          AND report.reports_to_membership_id = target_membership.id
          AND report.provisioning_status <> 'deleted';

        UPDATE iam.carbon_membership_settings AS settings
        SET first_silicon_membership_id = NULL
        WHERE settings.organization_id = p_organization_id
          AND settings.first_silicon_membership_id = target_membership.id;

        UPDATE iam.silicon_hooks AS hook
        SET status = 'disabled',
            last_error_code = NULL,
            next_attempt_at = NULL,
            lease_owner = NULL,
            lease_expires_at = NULL
        WHERE hook.organization_id = p_organization_id
          AND hook.silicon_id = target_membership.principal_id
          AND hook.status <> 'disabled';

        UPDATE iam.silicon_credentials AS credential
        SET status = 'retired', retired_at = transaction_timestamp()
        WHERE credential.organization_id = p_organization_id
          AND credential.silicon_id = target_membership.principal_id
          AND credential.status = 'active';

        UPDATE iam.refresh_token_families AS family
        SET status = 'revoked',
            revoked_at = transaction_timestamp(),
            revocation_reason = 'Silicon removed'
        WHERE family.subject_principal_id = target_membership.principal_id
          AND family.status = 'active';

        UPDATE iam.authentication_sessions AS authentication_session
        SET status = 'revoked',
            revoked_at = transaction_timestamp(),
            revocation_reason = 'Silicon removed'
        WHERE authentication_session.subject_principal_id = target_membership.principal_id
          AND authentication_session.status = 'active';

        UPDATE iam.access_tokens AS access_token
        SET revoked_at = transaction_timestamp(),
            revocation_reason = 'Silicon removed'
        WHERE access_token.subject_principal_id = target_membership.principal_id
          AND access_token.revoked_at IS NULL;

        UPDATE iam.silicons AS silicon
        SET provisioning_status = 'deleted', deleted_at = transaction_timestamp()
        WHERE silicon.organization_id = p_organization_id
          AND silicon.id = target_membership.principal_id
          AND silicon.version = p_expected_silicon_version
          AND silicon.provisioning_status <> 'deleted'
        RETURNING silicon.version INTO resulting_silicon_version;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'silicon_version_mismatch' USING ERRCODE = 'P0001';
        END IF;

        UPDATE iam.principals AS principal
        SET status = 'deleted',
            auth_epoch = principal.auth_epoch + 1,
            deleted_at = transaction_timestamp()
        WHERE principal.id = target_membership.principal_id
          AND principal.kind = 'silicon'
          AND principal.status <> 'deleted';
    ELSE
        IF p_expected_silicon_version IS NOT NULL OR p_reassign_reports_to IS NOT NULL THEN
            RAISE EXCEPTION 'membership_removal_invalid' USING ERRCODE = '22023';
        END IF;
    END IF;

    UPDATE iam.organization_capability_grants AS capability_grant
    SET revoked_by_membership_id = actor_membership_id,
        revoked_at = transaction_timestamp(),
        reason = 'membership removed'
    WHERE capability_grant.organization_id = p_organization_id
      AND capability_grant.grantee_membership_id = target_membership.id
      AND capability_grant.revoked_at IS NULL;

    DELETE FROM iam.membership_tags AS membership_tag
    WHERE membership_tag.organization_id = p_organization_id
      AND membership_tag.membership_id = target_membership.id;

    UPDATE iam.extra_silicon_access_grants AS access_grant
    SET revoked_by_membership_id = actor_membership_id,
        revoked_at = transaction_timestamp()
    WHERE access_grant.organization_id = p_organization_id
      AND (
          access_grant.carbon_membership_id = target_membership.id
          OR access_grant.silicon_membership_id = target_membership.id
      )
      AND access_grant.revoked_at IS NULL;

    UPDATE iam.organization_memberships AS membership
    SET status = 'removed',
        removed_at = transaction_timestamp(),
        suspended_at = NULL,
        org_role = 'member',
        role_granted_by_membership_id = NULL,
        authz_epoch = membership.authz_epoch + 1
    WHERE membership.organization_id = p_organization_id
      AND membership.id = target_membership.id
      AND membership.version = p_expected_membership_version
      AND membership.status = 'active'
    RETURNING membership.version INTO resulting_membership_version;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'membership_version_mismatch' USING ERRCODE = 'P0001';
    END IF;

    UPDATE iam.access_tokens AS access_token
    SET revoked_at = transaction_timestamp(),
        revocation_reason = 'organization membership removed'
    WHERE access_token.organization_id = p_organization_id
      AND access_token.membership_id = target_membership.id
      AND access_token.revoked_at IS NULL;

    principal_id := target_membership.principal_id;
    principal_kind := target_membership.principal_kind;
    membership_version := resulting_membership_version;
    silicon_version := resulting_silicon_version;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.remove_organization_membership(
    uuid, uuid, bigint, bigint, uuid
) FROM PUBLIC;

CREATE FUNCTION iam_private.set_organization_admin_role(
    p_organization_id uuid,
    p_membership_id uuid,
    p_expected_version bigint,
    p_promote boolean
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_actor_id uuid := iam_private.current_principal_id();
    actor_membership_id uuid;
    target_membership iam.organization_memberships%ROWTYPE;
    resulting_version bigint;
BEGIN
    IF p_organization_id IS NULL
       OR p_membership_id IS NULL
       OR p_expected_version IS NULL
       OR p_expected_version <= 0
       OR p_promote IS NULL
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id() THEN
        RAISE EXCEPTION 'admin_role_transition_invalid' USING ERRCODE = '22023';
    END IF;

    SELECT membership.id
    INTO actor_membership_id
    FROM iam.organization_memberships AS membership
    WHERE membership.organization_id = p_organization_id
      AND membership.principal_id = current_actor_id
      AND membership.principal_kind = 'carbon'
      AND membership.status = 'active';

    IF NOT FOUND OR NOT iam_private.has_organization_capability(
        p_organization_id,
        current_actor_id,
        CASE WHEN p_promote THEN 'admins.create' ELSE 'admins.manage' END
    ) THEN
        RAISE EXCEPTION 'admin_role_transition_forbidden' USING ERRCODE = '42501';
    END IF;

    SELECT membership.*
    INTO target_membership
    FROM iam.organization_memberships AS membership
    WHERE membership.organization_id = p_organization_id
      AND membership.id = p_membership_id
    FOR UPDATE OF membership;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF target_membership.status <> 'active'
       OR target_membership.version <> p_expected_version THEN
        RAISE EXCEPTION 'membership_version_mismatch' USING ERRCODE = 'P0001';
    END IF;
    IF target_membership.principal_kind <> 'carbon'
       OR (p_promote AND target_membership.org_role <> 'member')
       OR (NOT p_promote AND target_membership.org_role <> 'admin') THEN
        RAISE EXCEPTION 'membership_role_transition_invalid' USING ERRCODE = 'P0001';
    END IF;

    IF NOT p_promote THEN
        UPDATE iam.organization_capability_grants AS capability_grant
        SET revoked_by_membership_id = actor_membership_id,
            revoked_at = transaction_timestamp(),
            reason = 'administrator demoted'
        WHERE capability_grant.organization_id = p_organization_id
          AND capability_grant.grantee_membership_id = target_membership.id
          AND capability_grant.revoked_at IS NULL;
    END IF;

    UPDATE iam.organization_memberships AS membership
    SET org_role = CASE
            WHEN p_promote THEN 'admin'::iam.organization_role
            ELSE 'member'::iam.organization_role
        END,
        role_granted_by_membership_id = CASE
            WHEN p_promote THEN actor_membership_id
            ELSE NULL
        END,
        authz_epoch = membership.authz_epoch + 1
    WHERE membership.organization_id = p_organization_id
      AND membership.id = target_membership.id
      AND membership.version = p_expected_version
      AND membership.status = 'active'
    RETURNING membership.version INTO resulting_version;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'membership_version_mismatch' USING ERRCODE = 'P0001';
    END IF;
    RETURN resulting_version;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.set_organization_admin_role(
    uuid, uuid, bigint, boolean
) FROM PUBLIC;

CREATE FUNCTION iam_private.archive_organization_tag(
    p_organization_id uuid,
    p_tag_id uuid,
    p_expected_version bigint,
    p_cascade boolean
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_actor_id uuid := iam_private.current_principal_id();
    resulting_version bigint;
    is_referenced boolean;
BEGIN
    IF p_organization_id IS NULL
       OR p_tag_id IS NULL
       OR p_expected_version IS NULL
       OR p_expected_version <= 0
       OR p_cascade IS NULL
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id() THEN
        RAISE EXCEPTION 'tag_archive_invalid' USING ERRCODE = '22023';
    END IF;
    IF NOT iam_private.has_organization_capability(
        p_organization_id, current_actor_id, 'tags.manage'
    ) THEN
        RAISE EXCEPTION 'tag_archive_forbidden' USING ERRCODE = '42501';
    END IF;

    PERFORM 1
    FROM iam.organization_tags AS tag
    WHERE tag.organization_id = p_organization_id
      AND tag.id = p_tag_id
      AND tag.status = 'active'
      AND tag.version = p_expected_version
    FOR UPDATE OF tag;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'tag_version_mismatch' USING ERRCODE = 'P0001';
    END IF;

    SELECT
        EXISTS (
            SELECT 1 FROM iam.membership_tags AS membership_tag
            WHERE membership_tag.organization_id = p_organization_id
              AND membership_tag.tag_id = p_tag_id
        )
        OR EXISTS (
            SELECT 1 FROM iam.organization_invitation_tags AS invitation_tag
            WHERE invitation_tag.organization_id = p_organization_id
              AND invitation_tag.tag_id = p_tag_id
        )
        OR EXISTS (
            SELECT 1 FROM iam.sso_membership_policy_tags AS policy_tag
            WHERE policy_tag.organization_id = p_organization_id
              AND policy_tag.tag_id = p_tag_id
        )
        OR EXISTS (
            SELECT 1 FROM iam.trust_rules AS trust_rule
            WHERE trust_rule.organization_id = p_organization_id
              AND trust_rule.archived_at IS NULL
              AND (
                  trust_rule.subject_tag_id = p_tag_id
                  OR trust_rule.target_tag_id = p_tag_id
              )
        )
    INTO is_referenced;

    IF is_referenced AND NOT p_cascade THEN
        RAISE EXCEPTION 'tag_in_use' USING ERRCODE = 'P0001';
    END IF;

    IF p_cascade THEN
        DELETE FROM iam.membership_tags AS membership_tag
        WHERE membership_tag.organization_id = p_organization_id
          AND membership_tag.tag_id = p_tag_id;

        DELETE FROM iam.organization_invitation_tags AS invitation_tag
        WHERE invitation_tag.organization_id = p_organization_id
          AND invitation_tag.tag_id = p_tag_id;

        DELETE FROM iam.sso_membership_policy_tags AS policy_tag
        WHERE policy_tag.organization_id = p_organization_id
          AND policy_tag.tag_id = p_tag_id;

        UPDATE iam.trust_rules AS trust_rule
        SET archived_at = transaction_timestamp()
        WHERE trust_rule.organization_id = p_organization_id
          AND trust_rule.archived_at IS NULL
          AND (
              trust_rule.subject_tag_id = p_tag_id
              OR trust_rule.target_tag_id = p_tag_id
          );
    END IF;

    UPDATE iam.organization_tags AS tag
    SET status = 'archived', archived_at = transaction_timestamp()
    WHERE tag.organization_id = p_organization_id
      AND tag.id = p_tag_id
      AND tag.version = p_expected_version
      AND tag.status = 'active'
    RETURNING tag.version INTO resulting_version;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'tag_version_mismatch' USING ERRCODE = 'P0001';
    END IF;
    RETURN resulting_version;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.archive_organization_tag(
    uuid, uuid, bigint, boolean
) FROM PUBLIC;

CREATE FUNCTION iam_private.record_ignored_workos_event(
    p_receipt_id uuid,
    p_provider_event_id text,
    p_payload_digest bytea,
    p_signature_timestamp timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    existing_receipt iam.external_webhook_receipts%ROWTYPE;
    affected_rows bigint;
BEGIN
    IF p_receipt_id IS NULL
       OR p_receipt_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_provider_event_id IS NULL
       OR char_length(p_provider_event_id) NOT BETWEEN 1 AND 512
       OR p_payload_digest IS NULL
       OR octet_length(p_payload_digest) <> 32
       OR p_signature_timestamp IS NULL
       OR p_signature_timestamp < transaction_timestamp() - interval '5 minutes'
       OR p_signature_timestamp > transaction_timestamp() + interval '1 minute' THEN
        RAISE EXCEPTION 'workos_event_invalid' USING ERRCODE = '22023';
    END IF;

    INSERT INTO iam.external_webhook_receipts (
        id, provider, provider_event_id, payload_digest,
        signature_verified_at, status, processed_at, attempt_count
    ) VALUES (
        p_receipt_id, 'workos', p_provider_event_id, p_payload_digest,
        p_signature_timestamp, 'ignored', transaction_timestamp(), 1
    )
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows = 1 THEN
        RETURN true;
    END IF;

    SELECT receipt.*
    INTO existing_receipt
    FROM iam.external_webhook_receipts AS receipt
    WHERE receipt.provider = 'workos'
      AND receipt.provider_event_id = p_provider_event_id
    FOR UPDATE OF receipt;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'workos_event_metadata_conflict' USING ERRCODE = '23514';
    END IF;
    IF existing_receipt.payload_digest <> p_payload_digest THEN
        RAISE EXCEPTION 'workos_event_payload_conflict' USING ERRCODE = '23514';
    END IF;
    IF existing_receipt.signature_verified_at IS DISTINCT FROM p_signature_timestamp THEN
        RAISE EXCEPTION 'workos_event_metadata_conflict' USING ERRCODE = '23514';
    END IF;
    RETURN false;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.record_ignored_workos_event(
    uuid, text, bytea, timestamptz
) FROM PUBLIC;

REVOKE ALL ON FUNCTION iam_private.is_organization_creator(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.is_active_organization_member(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.has_organization_capability(uuid, uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.has_platform_capability(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.can_read_application(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.can_manage_application(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.can_manage_application_technical(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.can_administer_application(uuid, uuid) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.remove_organization_membership(
    uuid, uuid, bigint, bigint, uuid
) IS
    'Atomically removes a non-owner Carbon or Silicon membership and revokes all tenant-derived authority; Silicon removal also retires credentials and authentication state.';
COMMENT ON FUNCTION iam_private.set_organization_admin_role(
    uuid, uuid, bigint, boolean
) IS
    'Performs the exact Carbon member/admin transition, requiring admins.create for promotion and admins.manage for demotion.';
COMMENT ON FUNCTION iam_private.archive_organization_tag(
    uuid, uuid, bigint, boolean
) IS
    'Archives one tenant tag and, only when explicitly requested, removes all tag joins and archives active trust-rule references atomically.';
COMMENT ON FUNCTION iam_private.record_ignored_workos_event(
    uuid, text, bytea, timestamptz
) IS
    'Records a signature-verified unsupported WorkOS event without exposing the pre-tenant webhook receipt table; exact replays are idempotent and metadata conflicts fail closed.';

COMMENT ON FUNCTION iam_private.current_principal_id() IS
    'Reads request principal from a transaction-local setting; a missing setting returns NULL and policies deny.';
COMMENT ON FUNCTION iam_private.register_runtime_key_version(text, smallint, boolean) IS
    'Registers only configured IAM keyring metadata; current promotion serializes per purpose and keeps prior active versions usable for verification/decryption.';
COMMENT ON FUNCTION iam_private.organization_handle_is_available(text) IS
    'Pre-auth exact organization-handle availability check; deleted handles remain unavailable.';
COMMENT ON FUNCTION iam_private.carbon_handle_is_available(text) IS
    'Pre-auth exact handle availability check; tombstoned Carbon handles remain unavailable.';
COMMENT ON FUNCTION iam_private.resolve_active_carbon_by_handle(text) IS
    'Pre-auth exact handle resolver returning only active principal identity and epoch.';
COMMENT ON FUNCTION iam_private.resolve_active_carbon_by_contact_digest(
    iam.contact_kind, smallint, bytea
) IS
    'Pre-auth versioned blind-index resolver returning only encrypted active contact material.';
COMMENT ON FUNCTION iam_private.list_active_carbon_login_contacts(uuid) IS
    'Pre-auth resolver for encrypted primary login destinations after an exact handle match.';
COMMENT ON FUNCTION iam_private.complete_verified_signup(
    uuid, uuid, text, text, text, text, uuid, uuid
) IS
    'Atomically locks and consumes a verified signup, copies encrypted contacts and blind indexes, and activates exactly one Carbon.';
COMMENT ON FUNCTION iam_private.is_active_organization_member(uuid, uuid) IS
    'RLS helper owned by the migration role. Runtime roles must not own RLS-protected tables.';

ALTER TABLE iam.carbons ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.carbon_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.organization_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.organization_capability_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.organization_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.silicons ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.silicon_hooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.carbon_membership_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.membership_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.extra_silicon_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.organization_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.organization_invitation_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.organization_invitation_extra_silicons ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.trust_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.approval_requirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.approval_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.organization_sso_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.sso_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.sso_membership_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.sso_membership_policy_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.sso_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.sso_authorization_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.sso_setup_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.application_collaborators ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.application_redirect_uris ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.application_requested_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.application_approved_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.application_webhook_endpoints ENABLE ROW LEVEL SECURITY;

CREATE POLICY carbons_authenticated_directory_select
ON iam.carbons FOR SELECT
USING (iam_private.current_principal_id() IS NOT NULL);

CREATE POLICY carbons_self_update
ON iam.carbons FOR UPDATE
USING (id = iam_private.current_principal_id())
WITH CHECK (id = iam_private.current_principal_id());

CREATE POLICY carbon_contacts_self_access
ON iam.carbon_contacts
USING (carbon_id = iam_private.current_principal_id())
WITH CHECK (carbon_id = iam_private.current_principal_id());

CREATE POLICY organizations_member_select
ON iam.organizations FOR SELECT
USING (
    iam_private.is_active_organization_member(id, iam_private.current_principal_id())
    OR iam_private.has_platform_capability(iam_private.current_principal_id(), 'audit.read_global')
);

CREATE POLICY organizations_creator_insert
ON iam.organizations FOR INSERT
WITH CHECK (created_by_carbon_id = iam_private.current_principal_id());

CREATE POLICY organizations_authorized_update
ON iam.organizations FOR UPDATE
USING (
    id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        id, iam_private.current_principal_id(), 'organization.update'
    )
)
WITH CHECK (id = iam_private.current_organization_id());

CREATE POLICY organization_memberships_member_select
ON iam.organization_memberships FOR SELECT
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()));

CREATE POLICY organization_memberships_invitee_select
ON iam.organization_memberships FOR SELECT
USING (
    EXISTS (
        SELECT 1
        FROM iam.organization_invitations AS invitation
        WHERE invitation.organization_id = organization_memberships.organization_id
          AND invitation.invited_by_membership_id = organization_memberships.id
          AND invitation.target_carbon_id = iam_private.current_principal_id()
          AND invitation.status = 'pending'
          AND invitation.expires_at > transaction_timestamp()
    )
);

CREATE POLICY organization_memberships_authorized_insert
ON iam.organization_memberships FOR INSERT
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND (
        (
            principal_kind = 'carbon'
            AND iam_private.has_organization_capability(
                organization_id, iam_private.current_principal_id(), 'members.invite'
            )
        )
        OR (
            principal_kind = 'silicon'
            AND iam_private.has_organization_capability(
                organization_id, iam_private.current_principal_id(), 'silicons.create'
            )
        )
        OR (
            principal_id = iam_private.current_principal_id()
            AND principal_kind = 'carbon'
            AND org_role = 'owner'
            AND iam_private.is_organization_creator(
                organization_id, iam_private.current_principal_id()
            )
        )
    )
);

CREATE POLICY organization_memberships_authorized_update
ON iam.organization_memberships FOR UPDATE
USING (
    organization_id = iam_private.current_organization_id()
    AND (
        iam_private.has_organization_capability(
            organization_id, iam_private.current_principal_id(), 'members.update_directory'
        )
        OR iam_private.has_organization_capability(
            organization_id, iam_private.current_principal_id(), 'members.remove'
        )
        OR iam_private.has_organization_capability(
            organization_id, iam_private.current_principal_id(), 'admins.manage'
        )
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

CREATE POLICY organization_capability_grants_member_select
ON iam.organization_capability_grants FOR SELECT
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()));

CREATE POLICY organization_capability_grants_manage
ON iam.organization_capability_grants
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'admins.manage'
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

CREATE POLICY organization_tags_member_select
ON iam.organization_tags FOR SELECT
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()));

CREATE POLICY organization_tags_manage
ON iam.organization_tags
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'tags.manage'
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

CREATE POLICY silicons_member_select
ON iam.silicons FOR SELECT
USING (
    iam_private.is_active_organization_member(
        organization_id, iam_private.current_principal_id()
    )
);

CREATE POLICY silicons_create
ON iam.silicons FOR INSERT
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'silicons.create'
    )
);

CREATE POLICY silicons_update
ON iam.silicons FOR UPDATE
USING (
    organization_id = iam_private.current_organization_id()
    AND (
        iam_private.has_organization_capability(
            organization_id, iam_private.current_principal_id(), 'silicons.update_directory'
        )
        OR iam_private.has_organization_capability(
            organization_id, iam_private.current_principal_id(), 'silicons.manage_hierarchy'
        )
    )
)
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND (
        iam_private.has_organization_capability(
            organization_id, iam_private.current_principal_id(), 'silicons.update_directory'
        )
        OR iam_private.has_organization_capability(
            organization_id, iam_private.current_principal_id(), 'silicons.manage_hierarchy'
        )
    )
);

CREATE POLICY silicons_remove
ON iam.silicons FOR DELETE
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'silicons.remove'
    )
);

CREATE POLICY silicon_hooks_member_select
ON iam.silicon_hooks FOR SELECT
USING (
    iam_private.is_active_organization_member(
        organization_id, iam_private.current_principal_id()
    )
);

CREATE POLICY silicon_hooks_create
ON iam.silicon_hooks FOR INSERT
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'silicons.create'
    )
);

CREATE POLICY silicon_hooks_manage
ON iam.silicon_hooks FOR UPDATE
USING (
    organization_id = iam_private.current_organization_id()
    AND (
        iam_private.has_organization_capability(
            organization_id,
            iam_private.current_principal_id(),
            'silicons.update_directory'
        )
        OR iam_private.has_organization_capability(
            organization_id,
            iam_private.current_principal_id(),
            'silicons.remove'
        )
    )
)
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND (
        iam_private.has_organization_capability(
            organization_id,
            iam_private.current_principal_id(),
            'silicons.update_directory'
        )
        OR iam_private.has_organization_capability(
            organization_id,
            iam_private.current_principal_id(),
            'silicons.remove'
        )
    )
);

CREATE POLICY carbon_membership_settings_member_select
ON iam.carbon_membership_settings FOR SELECT
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()));

CREATE POLICY carbon_membership_settings_manage
ON iam.carbon_membership_settings
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'members.update_directory'
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

CREATE POLICY membership_tags_member_select
ON iam.membership_tags FOR SELECT
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()));

CREATE POLICY membership_tags_manage
ON iam.membership_tags
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'tags.manage'
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

CREATE POLICY extra_silicon_access_member_select
ON iam.extra_silicon_access_grants FOR SELECT
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()));

CREATE POLICY extra_silicon_access_manage
ON iam.extra_silicon_access_grants
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'members.update_directory'
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

CREATE POLICY organization_invitations_authorized_select
ON iam.organization_invitations FOR SELECT
USING (
    target_carbon_id = iam_private.current_principal_id()
    OR iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'members.invite'
    )
);

CREATE POLICY organization_invitations_manage
ON iam.organization_invitations
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'members.invite'
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

CREATE POLICY organization_invitation_tags_access
ON iam.organization_invitation_tags
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()))
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'members.invite'
    )
);

CREATE POLICY organization_invitation_tags_invitee_select
ON iam.organization_invitation_tags FOR SELECT
USING (
    EXISTS (
        SELECT 1
        FROM iam.organization_invitations AS invitation
        WHERE invitation.organization_id = organization_invitation_tags.organization_id
          AND invitation.id = organization_invitation_tags.invitation_id
          AND invitation.target_carbon_id = iam_private.current_principal_id()
          AND invitation.status = 'pending'
          AND invitation.expires_at > transaction_timestamp()
    )
);

CREATE POLICY organization_invitation_extra_access
ON iam.organization_invitation_extra_silicons
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()))
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'members.invite'
    )
);

CREATE POLICY organization_invitation_extra_invitee_select
ON iam.organization_invitation_extra_silicons FOR SELECT
USING (
    EXISTS (
        SELECT 1
        FROM iam.organization_invitations AS invitation
        WHERE invitation.organization_id = organization_invitation_extra_silicons.organization_id
          AND invitation.id = organization_invitation_extra_silicons.invitation_id
          AND invitation.target_carbon_id = iam_private.current_principal_id()
          AND invitation.status = 'pending'
          AND invitation.expires_at > transaction_timestamp()
    )
);

CREATE POLICY trust_rules_member_select
ON iam.trust_rules FOR SELECT
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()));

CREATE POLICY trust_rules_manage
ON iam.trust_rules
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'trust.manage'
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

CREATE POLICY approval_requests_member_select
ON iam.approval_requests FOR SELECT
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()));

CREATE POLICY approval_requests_create
ON iam.approval_requests FOR INSERT
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND EXISTS (
        SELECT 1
        FROM iam.organization_memberships AS requester
        WHERE requester.organization_id = approval_requests.organization_id
          AND requester.id = approval_requests.requested_by_membership_id
          AND requester.principal_id = iam_private.current_principal_id()
          AND requester.status = 'active'
          AND (
              (
                  approval_requests.request_kind IN (
                      'carbon_job_role_change', 'silicon_job_role_change'
                  )
                  AND iam_private.has_organization_capability(
                      approval_requests.organization_id,
                      iam_private.current_principal_id(),
                      'roles.request'
                  )
              )
              OR (
                  approval_requests.request_kind = 'silicon_token_rotation'
                  AND iam_private.has_organization_capability(
                      approval_requests.organization_id,
                      iam_private.current_principal_id(),
                      'silicons.rotate_token'
                  )
              )
              OR (
                  approval_requests.request_kind = 'ownership_transfer'
                  AND requester.principal_kind = 'carbon'
                  AND requester.org_role = 'owner'
              )
          )
    )
);

CREATE POLICY approval_requests_decide
ON iam.approval_requests FOR UPDATE
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.is_active_organization_member(
        organization_id, iam_private.current_principal_id()
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

CREATE POLICY approval_requirements_member_select
ON iam.approval_requirements FOR SELECT
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()));

CREATE POLICY approval_requirements_create
ON iam.approval_requirements FOR INSERT
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND EXISTS (
        SELECT 1
        FROM iam.approval_requests AS request
        JOIN iam.organization_memberships AS requester
          ON requester.organization_id = request.organization_id
         AND requester.id = request.requested_by_membership_id
         AND requester.principal_id = iam_private.current_principal_id()
         AND requester.status = 'active'
        LEFT JOIN iam.job_role_change_requests AS role_change
          ON role_change.organization_id = request.organization_id
         AND role_change.approval_request_id = request.id
        WHERE request.organization_id = approval_requirements.organization_id
          AND request.id = approval_requirements.approval_request_id
          AND (
              (
                  request.request_kind = 'carbon_job_role_change'
                  AND iam_private.has_organization_capability(
                      request.organization_id,
                      iam_private.current_principal_id(),
                      'roles.request'
                  )
                  AND (
                      (
                          approval_requirements.requirement_kind = 'specific_membership'
                          AND approval_requirements.specific_membership_id =
                              role_change.target_membership_id
                          AND approval_requirements.required_capability IS NULL
                          AND approval_requirements.quorum = 1
                      )
                      OR (
                          approval_requirements.requirement_kind = 'current_owner_or_admin'
                          AND approval_requirements.specific_membership_id IS NULL
                          AND approval_requirements.required_capability = 'roles.approve'
                          AND approval_requirements.quorum = 1
                      )
                  )
              )
              OR (
                  request.request_kind = 'silicon_job_role_change'
                  AND iam_private.has_organization_capability(
                      request.organization_id,
                      iam_private.current_principal_id(),
                      'roles.request'
                  )
                  AND approval_requirements.requirement_kind = 'current_owner_or_admin'
                  AND approval_requirements.specific_membership_id IS NULL
                  AND approval_requirements.required_capability = 'roles.approve'
                  AND approval_requirements.quorum = 1
              )
              OR (
                  request.request_kind = 'silicon_token_rotation'
                  AND iam_private.has_organization_capability(
                      request.organization_id,
                      iam_private.current_principal_id(),
                      'silicons.rotate_token'
                  )
                  AND approval_requirements.requirement_kind = 'current_owner'
                  AND approval_requirements.specific_membership_id IS NULL
                  AND approval_requirements.required_capability IS NULL
                  AND approval_requirements.quorum = 1
              )
              OR (
                  request.request_kind = 'ownership_transfer'
                  AND requester.principal_kind = 'carbon'
                  AND requester.org_role = 'owner'
                  AND approval_requirements.requirement_kind = 'current_owner'
                  AND approval_requirements.specific_membership_id IS NULL
                  AND approval_requirements.required_capability IS NULL
                  AND approval_requirements.quorum = 1
              )
          )
    )
);

CREATE POLICY approval_decisions_member_select
ON iam.approval_decisions FOR SELECT
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()));

CREATE POLICY approval_decisions_create
ON iam.approval_decisions FOR INSERT
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND decided_by_membership_id = (
        SELECT membership.id
        FROM iam.organization_memberships AS membership
        WHERE membership.organization_id = organization_id
          AND membership.principal_id = iam_private.current_principal_id()
          AND membership.status = 'active'
    )
);

CREATE POLICY organization_sso_configs_member_select
ON iam.organization_sso_configs FOR SELECT
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()));

CREATE POLICY organization_sso_configs_manage
ON iam.organization_sso_configs
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'sso.manage'
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

CREATE POLICY sso_connections_member_select
ON iam.sso_connections FOR SELECT
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()));

CREATE POLICY sso_connections_manage
ON iam.sso_connections
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'sso.manage'
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

CREATE POLICY sso_membership_policies_member_select
ON iam.sso_membership_policies FOR SELECT
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()));

CREATE POLICY sso_membership_policies_manage
ON iam.sso_membership_policies
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'sso.manage'
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

CREATE POLICY sso_membership_policy_tags_access
ON iam.sso_membership_policy_tags
USING (iam_private.is_active_organization_member(organization_id, iam_private.current_principal_id()))
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'sso.manage'
    )
);

CREATE POLICY sso_identities_self_or_manager_select
ON iam.sso_identities FOR SELECT
USING (
    carbon_id = iam_private.current_principal_id()
    OR iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'sso.manage'
    )
);

CREATE POLICY sso_authorization_transactions_manage
ON iam.sso_authorization_transactions FOR UPDATE
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'sso.manage'
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

CREATE POLICY sso_setup_sessions_member_select
ON iam.sso_setup_sessions FOR SELECT
USING (
    iam_private.is_active_organization_member(
        organization_id, iam_private.current_principal_id()
    )
);

CREATE POLICY sso_setup_sessions_manage
ON iam.sso_setup_sessions
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'sso.manage'
    )
)
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND iam_private.has_organization_capability(
        organization_id, iam_private.current_principal_id(), 'sso.manage'
    )
);

CREATE POLICY applications_owner_or_collaborator_select
ON iam.applications FOR SELECT
USING (
    owner_carbon_id = iam_private.current_principal_id()
    OR iam_private.can_read_application(id, iam_private.current_principal_id())
    OR iam_private.can_administer_application(id, iam_private.current_principal_id())
    OR (iam_private.current_principal_id() IS NOT NULL AND review_status = 'verified')
);

CREATE POLICY applications_carbon_insert
ON iam.applications FOR INSERT
WITH CHECK (owner_carbon_id = iam_private.current_principal_id());

CREATE POLICY applications_manager_update
ON iam.applications FOR UPDATE
USING (
    iam_private.can_manage_application_technical(id, iam_private.current_principal_id())
    OR iam_private.can_administer_application(id, iam_private.current_principal_id())
)
WITH CHECK (
    iam_private.can_manage_application_technical(id, iam_private.current_principal_id())
    OR iam_private.can_administer_application(id, iam_private.current_principal_id())
);

CREATE POLICY application_collaborators_manager_access
ON iam.application_collaborators
USING (iam_private.can_manage_application(application_id, iam_private.current_principal_id()))
WITH CHECK (iam_private.can_manage_application(application_id, iam_private.current_principal_id()));

CREATE POLICY application_redirect_uris_manager_access
ON iam.application_redirect_uris
USING (
    iam_private.can_manage_application_technical(application_id, iam_private.current_principal_id())
    OR iam_private.can_administer_application(application_id, iam_private.current_principal_id())
)
WITH CHECK (
    iam_private.can_manage_application_technical(application_id, iam_private.current_principal_id())
    OR iam_private.can_administer_application(application_id, iam_private.current_principal_id())
);

CREATE POLICY application_requested_scopes_manager_access
ON iam.application_requested_scopes
USING (
    iam_private.can_manage_application_technical(application_id, iam_private.current_principal_id())
    OR iam_private.can_administer_application(application_id, iam_private.current_principal_id())
)
WITH CHECK (
    iam_private.can_manage_application_technical(application_id, iam_private.current_principal_id())
    OR iam_private.can_administer_application(application_id, iam_private.current_principal_id())
);

CREATE POLICY application_approved_scopes_manager_select
ON iam.application_approved_scopes FOR SELECT
USING (
    application_id = iam_private.current_application_id()
    OR iam_private.can_read_application(application_id, iam_private.current_principal_id())
    OR iam_private.can_administer_application(application_id, iam_private.current_principal_id())
);

CREATE POLICY application_approved_scopes_admin_manage
ON iam.application_approved_scopes
USING (iam_private.can_administer_application(application_id, iam_private.current_principal_id()))
WITH CHECK (iam_private.can_administer_application(application_id, iam_private.current_principal_id()));

CREATE POLICY application_webhook_endpoints_manager_access
ON iam.application_webhook_endpoints
USING (
    iam_private.can_manage_application_technical(application_id, iam_private.current_principal_id())
    OR iam_private.can_administer_application(application_id, iam_private.current_principal_id())
)
WITH CHECK (
    iam_private.can_manage_application_technical(application_id, iam_private.current_principal_id())
    OR iam_private.can_administer_application(application_id, iam_private.current_principal_id())
);

COMMENT ON SCHEMA iam_private IS
    'Internal invariant and RLS helpers. SECURITY DEFINER functions use a fixed search path.';
COMMENT ON SCHEMA iam IS
    'Silicon IAM authoritative relational schema. Runtime roles must differ from the migration owner.';

-- Keep every relation discoverable from PostgreSQL catalogs. These comments are
-- intentionally colocated so schema-review tooling can require complete coverage.
COMMENT ON TABLE iam.access_token_scopes IS
    'Normalized OAuth scopes carried by an issued access token.';
COMMENT ON TABLE iam.application_approved_scopes IS
    'Application scopes approved by platform review and available for issuance.';
COMMENT ON TABLE iam.application_collaborators IS
    'Carbon principals delegated an application management role by its owner.';
COMMENT ON TABLE iam.application_requested_scopes IS
    'OAuth scopes requested by an application for a subsequent platform review.';
COMMENT ON TABLE iam.application_reviews IS
    'Immutable platform review attempts and outcomes for applications.';
COMMENT ON TABLE iam.application_webhook_signing_keys IS
    'Versioned HMAC signing-key material for application webhook deliveries.';
COMMENT ON TABLE iam.approval_decisions IS
    'One actor decision per approval requirement, with the evaluated authorization context.';
COMMENT ON TABLE iam.approval_requirements IS
    'Ordered authorization requirements that must be satisfied for an approval request.';
COMMENT ON TABLE iam.audit_events_default IS
    'Default audit-events partition used until time-bounded partitions are provisioned.';
COMMENT ON TABLE iam.external_webhook_receipts IS
    'Deduplicated inbound provider webhook receipts and their processing outcome.';
COMMENT ON TABLE iam.extra_silicon_access_grants IS
    'Explicit Carbon-to-Silicon access grants outside the normal organization hierarchy.';
COMMENT ON TABLE iam.job_role_change_requests IS
    'Typed payload for a governed membership job-role change.';
COMMENT ON TABLE iam.job_role_history IS
    'Append-only history of effective membership job-role changes.';
COMMENT ON TABLE iam.login_challenges IS
    'Short-lived login transactions binding a Carbon, requested assurance, and completion state.';
COMMENT ON TABLE iam.membership_tags IS
    'Many-to-many assignment of organization-owned tags to memberships.';
COMMENT ON TABLE iam.oauth_authorization_codes IS
    'Single-use, digest-only OAuth authorization codes bound to an authorization request.';
COMMENT ON TABLE iam.oauth_authorization_request_scopes IS
    'Requested scopes and user decisions for an OAuth authorization transaction.';
COMMENT ON TABLE iam.oauth_consent_grant_scopes IS
    'Normalized scopes covered by a Carbon application consent grant.';
COMMENT ON TABLE iam.oauth_consent_grants IS
    'Revocable Carbon consent grants issued to OAuth applications.';
COMMENT ON TABLE iam.oauth_scope_catalog IS
    'Canonical OAuth scope definitions and consent classifications.';
COMMENT ON TABLE iam.obo_action_catalog IS
    'Audience-defined actions that may be delegated through on-behalf-of proofs.';
COMMENT ON TABLE iam.obo_application_grants IS
    'Platform-approved issuer-to-audience permissions for on-behalf-of actions.';
COMMENT ON TABLE iam.organization_capability_grants IS
    'Organization-role to capability mapping used by tenant authorization checks.';
COMMENT ON TABLE iam.organization_invitation_extra_silicons IS
    'Extra Silicon access grants staged on an organization invitation.';
COMMENT ON TABLE iam.organization_invitation_tags IS
    'Membership tags staged on an organization invitation.';
COMMENT ON TABLE iam.organization_sso_configs IS
    'Organization-wide SSO enforcement and routing configuration.';
COMMENT ON TABLE iam.outbox_event_recipients IS
    'Normalized recipient list for a transactional outbox event.';
COMMENT ON TABLE iam.ownership_transfer_requests IS
    'Typed payload for a governed organization ownership transfer.';
COMMENT ON TABLE iam.platform_capability_catalog IS
    'Canonical platform-administration capabilities recognized by authorization code.';
COMMENT ON TABLE iam.platform_role_capabilities IS
    'Platform-role to capability assignments.';
COMMENT ON TABLE iam.platform_role_catalog IS
    'Canonical platform-administration roles.';
COMMENT ON TABLE iam.refresh_token_families IS
    'Refresh-token rotation families used for replay detection and family-wide revocation.';
COMMENT ON TABLE iam.signup_candidate_blind_indexes IS
    'Blind indexes for duplicate detection across encrypted signup contact candidates.';
COMMENT ON TABLE iam.signup_contact_candidates IS
    'Encrypted email and phone candidates collected before Carbon creation.';
COMMENT ON TABLE iam.silicon_credential_history IS
    'Append-only history of Silicon credential rotations and revocations.';
COMMENT ON TABLE iam.silicon_hooks IS
    'Organization-owned callback registrations associated with a Silicon identity.';
COMMENT ON TABLE iam.silicon_token_rotation_requests IS
    'Typed payload and encrypted result envelope for governed Silicon credential rotation.';
COMMENT ON TABLE iam.sso_authorization_transactions IS
    'Short-lived SSO authorization state binding organization, provider, PKCE, and relay context.';
COMMENT ON TABLE iam.sso_connections IS
    'Organization identity-provider connections and encrypted provider configuration.';
COMMENT ON TABLE iam.sso_identities IS
    'Stable external subject mappings from an SSO connection to an existing Carbon.';
COMMENT ON TABLE iam.sso_membership_policy_tags IS
    'Tags applied when an SSO membership policy matches.';
COMMENT ON TABLE iam.sso_setup_sessions IS
    'Short-lived proof-of-control sessions used while configuring an SSO connection.';
COMMENT ON TABLE iam.step_up_assertions IS
    'Single-use assurance assertions produced by a successfully completed step-up challenge.';
COMMENT ON TABLE iam.step_up_challenges IS
    'Short-lived challenges for elevating an authenticated session assurance level.';
COMMENT ON TABLE iam.webauthn_credentials IS
    'Carbon WebAuthn credential public keys, counters, transports, and lifecycle state.';
COMMENT ON TABLE iam.webhook_deliveries IS
    'Durable per-endpoint webhook delivery state derived from an outbox event.';
