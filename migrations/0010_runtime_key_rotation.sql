-- Fail-closed, monotonic runtime-key metadata reconciliation and activation.

CREATE UNIQUE INDEX cryptographic_key_versions_one_active_per_purpose
    ON iam.cryptographic_key_versions (purpose)
    WHERE status = 'active';

CREATE TABLE iam.runtime_key_activations (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    purpose text NOT NULL,
    previous_key_version smallint NOT NULL,
    activated_key_version smallint NOT NULL,
    activated_by text NOT NULL,
    activated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT runtime_key_activations_previous_key_fk
        FOREIGN KEY (purpose, previous_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version),
    CONSTRAINT runtime_key_activations_activated_key_fk
        FOREIGN KEY (purpose, activated_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version),
    CONSTRAINT runtime_key_activations_monotonic
        CHECK (activated_key_version > previous_key_version),
    UNIQUE (purpose, activated_key_version)
);

COMMENT ON TABLE iam.runtime_key_activations IS
    'Append-only operator history for monotonic runtime-key activations; contains metadata only.';

CREATE FUNCTION iam_private.reconcile_runtime_keyring(
    p_purpose text,
    p_current_version smallint,
    p_local_versions smallint[]
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    metadata_count bigint;
    active_count bigint;
    database_active_version smallint;
    missing_local_versions smallint[];
BEGIN
    IF p_purpose NOT IN ('token_hmac', 'contact_lookup_hmac', 'contact_aead')
       OR p_current_version <= 0
       OR p_local_versions IS NULL
       OR pg_catalog.cardinality(p_local_versions) = 0 THEN
        RAISE EXCEPTION 'unsupported runtime keyring metadata'
            USING ERRCODE = '22023';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.unnest(p_local_versions) AS local_version(version)
        WHERE local_version.version IS NULL OR local_version.version <= 0
    ) OR (
        SELECT pg_catalog.count(*) <> pg_catalog.count(DISTINCT local_version.version)
        FROM pg_catalog.unnest(p_local_versions) AS local_version(version)
    ) OR NOT p_current_version = ANY (p_local_versions) THEN
        RAISE EXCEPTION 'runtime keyring versions must be unique positive values containing current'
            USING ERRCODE = '22023';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('silicon-iam:keyring:' || p_purpose, 0)
    );
    PERFORM 1
    FROM iam.cryptographic_key_versions AS key_metadata
    WHERE key_metadata.purpose = p_purpose
    FOR UPDATE;

    SELECT
        pg_catalog.count(*),
        pg_catalog.count(*) FILTER (WHERE key_metadata.status = 'active'),
        pg_catalog.max(key_metadata.key_version)
            FILTER (WHERE key_metadata.status = 'active')
    INTO metadata_count, active_count, database_active_version
    FROM iam.cryptographic_key_versions AS key_metadata
    WHERE key_metadata.purpose = p_purpose;

    IF metadata_count = 0 THEN
        INSERT INTO iam.cryptographic_key_versions (
            purpose,
            key_version,
            status,
            activated_at
        )
        SELECT
            p_purpose,
            local_version.version,
            CASE
                WHEN local_version.version = p_current_version THEN 'active'
                ELSE 'decrypt_only'
            END,
            transaction_timestamp()
        FROM pg_catalog.unnest(p_local_versions) AS local_version(version);
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM iam.cryptographic_key_versions AS key_metadata
        WHERE key_metadata.purpose = p_purpose
          AND key_metadata.status = 'pending'
    ) THEN
        RAISE EXCEPTION 'runtime keyring % has unresolved pending metadata', p_purpose
            USING ERRCODE = '55000';
    END IF;

    IF active_count <> 1 THEN
        RAISE EXCEPTION 'runtime keyring % must have exactly one database-active version', p_purpose
            USING ERRCODE = '55000';
    END IF;

    IF database_active_version <> p_current_version THEN
        RAISE EXCEPTION
            'runtime keyring % database-active version % differs from configured current version %',
            p_purpose,
            database_active_version,
            p_current_version
            USING ERRCODE = '55000';
    END IF;

    SELECT pg_catalog.array_agg(key_metadata.key_version ORDER BY key_metadata.key_version)
    INTO missing_local_versions
    FROM iam.cryptographic_key_versions AS key_metadata
    WHERE key_metadata.purpose = p_purpose
      AND key_metadata.status IN ('active', 'decrypt_only')
      AND NOT key_metadata.key_version = ANY (p_local_versions);

    IF missing_local_versions IS NOT NULL THEN
        RAISE EXCEPTION
            'runtime keyring % is missing locally required database versions %',
            p_purpose,
            missing_local_versions
            USING ERRCODE = '55000';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM iam.cryptographic_key_versions AS key_metadata
        WHERE key_metadata.purpose = p_purpose
          AND key_metadata.status = 'retired'
          AND key_metadata.key_version = ANY (p_local_versions)
    ) THEN
        RAISE EXCEPTION 'runtime keyring % still contains a database-retired local version', p_purpose
            USING ERRCODE = '55000';
    END IF;

    INSERT INTO iam.cryptographic_key_versions (
        purpose,
        key_version,
        status,
        activated_at
    )
    SELECT
        p_purpose,
        local_version.version,
        'decrypt_only',
        transaction_timestamp()
    FROM pg_catalog.unnest(p_local_versions) AS local_version(version)
    WHERE local_version.version > database_active_version
    ON CONFLICT (purpose, key_version) DO NOTHING;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.reconcile_runtime_keyring(
    text, smallint, smallint[]
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.reconcile_runtime_keyring(
    text, smallint, smallint[]
) IS
    'Initializes an empty runtime keyring or fail-closed verifies its configured active and retained versions, staging only future versions as decrypt-only.';

CREATE FUNCTION iam_private.reconcile_worker_contact_aead_keyring(
    p_current_version smallint,
    p_local_versions smallint[]
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam_private
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS worker_role
          ON worker_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles AS login_role
          ON login_role.oid = membership.member
        WHERE worker_role.rolname = 'silicon_iam_worker'
          AND login_role.rolname = session_user
          AND login_role.rolcanlogin
          AND NOT login_role.rolsuper
          AND NOT login_role.rolcreatedb
          AND NOT login_role.rolcreaterole
          AND NOT login_role.rolreplication
          AND NOT login_role.rolbypassrls
    ) THEN
        RAISE EXCEPTION 'contact-AEAD reconciliation requires the silicon_iam_worker role'
            USING ERRCODE = '42501';
    END IF;

    PERFORM iam_private.reconcile_runtime_keyring(
        'contact_aead',
        p_current_version,
        p_local_versions
    );
END;
$$;

REVOKE ALL ON FUNCTION iam_private.reconcile_worker_contact_aead_keyring(
    smallint, smallint[]
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.reconcile_worker_contact_aead_keyring(
    smallint, smallint[]
) IS
    'Worker-role-attested reconciliation wrapper fixed to contact_aead; the worker never receives generic key-purpose metadata authority.';

CREATE FUNCTION iam_private.activate_runtime_key_version(
    p_purpose text,
    p_expected_current_version smallint,
    p_new_version smallint
)
RETURNS TABLE (
    activation_id bigint,
    previous_version smallint,
    active_version smallint,
    activated_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    active_count bigint;
    database_active_version smallint;
    target_status text;
    activation_timestamp timestamptz := transaction_timestamp();
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS operator_role
          ON operator_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles AS login_role
          ON login_role.oid = membership.member
        WHERE operator_role.rolname = 'silicon_iam_key_operator'
          AND login_role.rolname = session_user
          AND login_role.rolcanlogin
          AND NOT login_role.rolsuper
          AND NOT login_role.rolcreatedb
          AND NOT login_role.rolcreaterole
          AND NOT login_role.rolreplication
          AND NOT login_role.rolbypassrls
    ) OR pg_catalog.has_schema_privilege(session_user, 'iam', 'USAGE')
      OR pg_catalog.has_schema_privilege(session_user, 'iam', 'CREATE')
      OR pg_catalog.has_table_privilege(
          session_user, 'iam.cryptographic_key_versions', 'INSERT'
      )
      OR pg_catalog.has_table_privilege(
          session_user, 'iam.cryptographic_key_versions', 'UPDATE'
      )
      OR pg_catalog.has_table_privilege(
          session_user, 'iam.cryptographic_key_versions', 'DELETE'
      ) THEN
        RAISE EXCEPTION 'runtime key activation requires the dedicated key-operator role'
            USING ERRCODE = '42501';
    END IF;

    IF p_purpose NOT IN ('token_hmac', 'contact_lookup_hmac', 'contact_aead')
       OR p_expected_current_version <= 0
       OR p_new_version <= p_expected_current_version THEN
        RAISE EXCEPTION 'runtime key activation must name a supported purpose and increasing versions'
            USING ERRCODE = '22023';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('silicon-iam:keyring:' || p_purpose, 0)
    );
    PERFORM 1
    FROM iam.cryptographic_key_versions AS key_metadata
    WHERE key_metadata.purpose = p_purpose
    FOR UPDATE;

    SELECT
        pg_catalog.count(*) FILTER (WHERE key_metadata.status = 'active'),
        pg_catalog.max(key_metadata.key_version)
            FILTER (WHERE key_metadata.status = 'active')
    INTO active_count, database_active_version
    FROM iam.cryptographic_key_versions AS key_metadata
    WHERE key_metadata.purpose = p_purpose;

    IF active_count <> 1 OR database_active_version <> p_expected_current_version THEN
        RAISE EXCEPTION
            'runtime keyring % active version does not equal the expected version %',
            p_purpose,
            p_expected_current_version
            USING ERRCODE = '55000';
    END IF;

    IF p_new_version <= database_active_version THEN
        RAISE EXCEPTION 'runtime key activation must be strictly monotonic'
            USING ERRCODE = '55000';
    END IF;

    SELECT key_metadata.status
    INTO target_status
    FROM iam.cryptographic_key_versions AS key_metadata
    WHERE key_metadata.purpose = p_purpose
      AND key_metadata.key_version = p_new_version;

    IF NOT FOUND OR target_status <> 'decrypt_only' THEN
        RAISE EXCEPTION
            'runtime keyring % version % is not preloaded as decrypt-only',
            p_purpose,
            p_new_version
            USING ERRCODE = '55000';
    END IF;

    UPDATE iam.cryptographic_key_versions
    SET status = 'decrypt_only',
        retired_at = NULL
    WHERE purpose = p_purpose
      AND key_version = database_active_version
      AND status = 'active';

    UPDATE iam.cryptographic_key_versions
    SET status = 'active',
        activated_at = activation_timestamp,
        retired_at = NULL
    WHERE purpose = p_purpose
      AND key_version = p_new_version
      AND status = 'decrypt_only';

    INSERT INTO iam.runtime_key_activations (
        purpose,
        previous_key_version,
        activated_key_version,
        activated_by,
        activated_at
    )
    VALUES (
        p_purpose,
        database_active_version,
        p_new_version,
        session_user,
        activation_timestamp
    )
    RETURNING id INTO activation_id;

    previous_version := database_active_version;
    active_version := p_new_version;
    activated_at := activation_timestamp;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.activate_runtime_key_version(
    text, smallint, smallint
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.activate_runtime_key_version(
    text, smallint, smallint
) IS
    'Role-attested operator-only compare-and-swap activation of a preloaded runtime key version; transitions are strictly increasing and append-only audited.';

DROP FUNCTION iam_private.register_runtime_key_version(text, smallint, boolean);
