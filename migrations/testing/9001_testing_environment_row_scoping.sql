-- Per-environment row scoping for the shared testing database.
--
-- The testing database runs the identical Silicon IAM schema: every table,
-- constraint, trigger and function that production has. This overlay is
-- applied on top of it, and only there. It is what makes one physical database
-- safe to share between many testing environments.
--
-- The mechanism is deliberately uniform rather than hand-written per table.
-- Every tenant table gains a testing_environment_id that defaults from a
-- transaction-local setting, so the ~250 INSERT statements in the application
-- need no change at all -- a row lands in whichever environment the request
-- selected. A RESTRICTIVE policy then ANDs an environment predicate onto
-- whatever policies that table already has, without editing a single existing
-- policy.
--
-- Three properties are worth being explicit about.
--
-- FORCE ROW LEVEL SECURITY is not optional here. Silicon IAM resolves handles,
-- contacts and credentials through SECURITY DEFINER functions that run as the
-- table owner, and the owner is exempt from row security unless forced. Without
-- FORCE, iam_private.resolve_active_carbon_by_contact_digest would happily
-- return another environment's Carbon. Forcing it means the owner is also
-- subject to the permissive policies those functions were written to bypass,
-- so each scoped table also gets a permissive owner policy that restores
-- exactly that bypass -- and nothing else, because the environment predicate is
-- restrictive and therefore still applies.
--
-- The environment predicate is written twice on purpose. The general one is
-- inert while no environment is selected, so migrations, maintenance and
-- ordinary DBA work keep functioning. The API role gets a second, strict one
-- with no such escape: a request that somehow reached the database without
-- selecting an environment sees nothing rather than everything.
--
-- Only unique indexes that can actually collide across environments are
-- rewritten, and two kinds of column already rule that out. Every surrogate key
-- here is a generated UUID, so an index carrying a NOT NULL uuid is unique
-- across environments by construction. Every NOT NULL bytea here is a keyed
-- digest or blind index, and those are separated by the selected environment
-- inside the application's digest derivation -- which is deliberate, because
-- widening those indexes instead would break the `ON CONFLICT` inference the
-- idempotency and token upserts depend on. What remains is the set of genuine
-- natural keys -- handles, provider identifiers -- which two environments
-- really can mint identically.

CREATE FUNCTION iam_private.current_testing_environment_id()
RETURNS uuid
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT NULLIF(current_setting('iam.testing_environment_id', true), '')::uuid
$$;

COMMENT ON FUNCTION iam_private.current_testing_environment_id() IS
    'Transaction-local testing environment selected by the request, or NULL.';

DO $scope_tables$
DECLARE
    -- Platform-level reference data. These rows describe the deployment, not
    -- any one environment: the capability and role catalogs are seeded by
    -- migrations, and the key-version metadata is the target of foreign keys
    -- from nearly every scoped table, so it has to be shared for those
    -- references to resolve at all.
    shared_table_names text[] := ARRAY[
        'cryptographic_key_versions',
        'oauth_scope_catalog',
        'organization_capability_catalog',
        'platform_capability_catalog',
        'platform_role_capabilities',
        'platform_role_catalog',
        'runtime_key_activations'
    ];
    table_record record;
    owner_name text;
    scoped_count integer := 0;
BEGIN
    FOR table_record IN
        SELECT
            entry.oid,
            entry.relname,
            entry.relispartition,
            entry.relrowsecurity,
            pg_catalog.pg_get_userbyid(entry.relowner) AS owner_name
        FROM pg_catalog.pg_class AS entry
        JOIN pg_catalog.pg_namespace AS schema_entry
          ON schema_entry.oid = entry.relnamespace
        WHERE schema_entry.nspname = 'iam'
          AND entry.relkind IN ('r', 'p')
          AND entry.relname <> ALL (shared_table_names)
        ORDER BY entry.relname
    LOOP
        owner_name := table_record.owner_name;

        -- Partitions inherit the column from their parent; adding it again
        -- would fail. Everything else in this loop still applies to them,
        -- because a partition can be addressed directly.
        IF NOT table_record.relispartition THEN
            EXECUTE pg_catalog.format(
                'ALTER TABLE %s ADD COLUMN testing_environment_id uuid NOT NULL'
                || ' DEFAULT iam_private.current_testing_environment_id()',
                table_record.oid::pg_catalog.regclass
            );
            -- Unnamed on purpose: several table names are long enough that an
            -- explicit suffix would be silently truncated to 63 bytes, and two
            -- of them truncate to within a character of each other. Letting
            -- PostgreSQL derive the name keeps it both legible and unique.
            EXECUTE pg_catalog.format(
                'CREATE INDEX ON %s (testing_environment_id)',
                table_record.oid::pg_catalog.regclass
            );
            scoped_count := scoped_count + 1;
        END IF;

        -- A table that did not have row security before must keep behaving as
        -- though it has none, or enabling it here would silently deny the API
        -- everything. The baseline policy grants what the absence of row
        -- security used to grant; the restrictive policies below still apply.
        IF NOT table_record.relrowsecurity THEN
            EXECUTE pg_catalog.format(
                'CREATE POLICY testing_environment_baseline ON %s'
                || ' USING (true) WITH CHECK (true)',
                table_record.oid::pg_catalog.regclass
            );
        END IF;

        EXECUTE pg_catalog.format(
            'CREATE POLICY testing_environment_owner ON %s TO %I'
            || ' USING (true) WITH CHECK (true)',
            table_record.oid::pg_catalog.regclass,
            owner_name
        );

        EXECUTE pg_catalog.format(
            'CREATE POLICY testing_environment_isolation ON %s AS RESTRICTIVE'
            || ' USING ('
            || '     iam_private.current_testing_environment_id() IS NULL'
            || '     OR testing_environment_id = iam_private.current_testing_environment_id()'
            || ' ) WITH CHECK ('
            || '     iam_private.current_testing_environment_id() IS NULL'
            || '     OR testing_environment_id = iam_private.current_testing_environment_id()'
            || ' )',
            table_record.oid::pg_catalog.regclass
        );

        EXECUTE pg_catalog.format(
            'ALTER TABLE %s ENABLE ROW LEVEL SECURITY',
            table_record.oid::pg_catalog.regclass
        );
        EXECUTE pg_catalog.format(
            'ALTER TABLE %s FORCE ROW LEVEL SECURITY',
            table_record.oid::pg_catalog.regclass
        );
    END LOOP;

    RAISE NOTICE 'scoped % tables to testing environments', scoped_count;
END;
$scope_tables$;

-- The strict predicate for the request path. Split from the general one above
-- because it must not have the "no environment selected" escape: the API role
-- reaches this database only through a resolved environment key, so a query
-- arriving without one is a bug, and it should return nothing.
--
-- Bound to the role after the fact, like the other deployment-time policy role
-- bindings, so a schema bootstrap stays portable when the runtime roles have
-- not been provisioned yet.
DO $api_isolation$
DECLARE
    table_record record;
BEGIN
    IF pg_catalog.to_regrole('silicon_iam_api') IS NULL THEN
        RAISE NOTICE 'silicon_iam_api does not exist; strict API isolation not bound';
        RETURN;
    END IF;

    FOR table_record IN
        SELECT entry.oid
        FROM pg_catalog.pg_class AS entry
        JOIN pg_catalog.pg_namespace AS schema_entry
          ON schema_entry.oid = entry.relnamespace
        JOIN pg_catalog.pg_attribute AS scope_column
          ON scope_column.attrelid = entry.oid
         AND scope_column.attname = 'testing_environment_id'
         AND scope_column.attnum > 0
         AND NOT scope_column.attisdropped
        WHERE schema_entry.nspname = 'iam'
          AND entry.relkind IN ('r', 'p')
        ORDER BY entry.relname
    LOOP
        EXECUTE pg_catalog.format(
            'CREATE POLICY testing_environment_required ON %s AS RESTRICTIVE'
            || ' TO silicon_iam_api'
            || ' USING (testing_environment_id = iam_private.current_testing_environment_id())'
            || ' WITH CHECK ('
            || '     testing_environment_id = iam_private.current_testing_environment_id()'
            || ' )',
            table_record.oid::pg_catalog.regclass
        );
    END LOOP;
END;
$api_isolation$;

-- Re-scope the natural keys.
--
-- A unique index containing a NOT NULL uuid column cannot collide across
-- environments, because every uuid in this schema is a generated surrogate.
-- The rest are real natural keys -- a Carbon handle, an organization handle, a
-- contact blind index -- and two environments are expected to mint them
-- identically, so they become unique per environment instead of globally.
--
-- Indexes that back a unique constraint are replaced by a plain unique index:
-- that loses nothing here, since none of the affected keys is the target of a
-- foreign key, and it keeps the rewrite mechanical.
DO $rescope_unique_indexes$
DECLARE
    index_record record;
    rewritten_definition text;
    rewritten_count integer := 0;
BEGIN
    FOR index_record IN
        SELECT
            index_entry.indexrelid,
            index_class.relname AS index_name,
            index_entry.indrelid,
            pg_catalog.pg_get_indexdef(index_entry.indexrelid) AS definition,
            constraint_entry.conname AS constraint_name
        FROM pg_catalog.pg_index AS index_entry
        JOIN pg_catalog.pg_class AS index_class
          ON index_class.oid = index_entry.indexrelid
        JOIN pg_catalog.pg_class AS table_class
          ON table_class.oid = index_entry.indrelid
        JOIN pg_catalog.pg_namespace AS schema_entry
          ON schema_entry.oid = table_class.relnamespace
        JOIN pg_catalog.pg_attribute AS scope_column
          ON scope_column.attrelid = index_entry.indrelid
         AND scope_column.attname = 'testing_environment_id'
         AND scope_column.attnum > 0
         AND NOT scope_column.attisdropped
        LEFT JOIN pg_catalog.pg_constraint AS constraint_entry
          ON constraint_entry.conindid = index_entry.indexrelid
         AND constraint_entry.contype = 'u'
        WHERE schema_entry.nspname = 'iam'
          AND index_entry.indisunique
          AND NOT index_entry.indisprimary
          AND NOT EXISTS (
              SELECT 1
              FROM pg_catalog.unnest(index_entry.indkey::pg_catalog.int2[]) AS key_attnum
              JOIN pg_catalog.pg_attribute AS key_column
                ON key_column.attrelid = index_entry.indrelid
               AND key_column.attnum = key_attnum
              WHERE key_column.attnotnull
                AND key_column.atttypid IN (
                    'pg_catalog.uuid'::pg_catalog.regtype,
                    'pg_catalog.bytea'::pg_catalog.regtype
                )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM pg_catalog.pg_constraint AS referencing
              WHERE referencing.conindid = index_entry.indexrelid
                AND referencing.contype = 'f'
          )
        ORDER BY index_class.relname
    LOOP
        rewritten_definition := pg_catalog.replace(
            index_record.definition,
            ' USING btree (',
            ' USING btree (testing_environment_id, '
        );
        IF rewritten_definition = index_record.definition THEN
            RAISE EXCEPTION
                'cannot re-scope unique index %: unrecognized definition %',
                index_record.index_name,
                index_record.definition;
        END IF;

        IF index_record.constraint_name IS NULL THEN
            EXECUTE pg_catalog.format('DROP INDEX iam.%I', index_record.index_name);
        ELSE
            EXECUTE pg_catalog.format(
                'ALTER TABLE %s DROP CONSTRAINT %I',
                index_record.indrelid::pg_catalog.regclass,
                index_record.constraint_name
            );
        END IF;
        EXECUTE rewritten_definition;
        rewritten_count := rewritten_count + 1;
    END LOOP;

    RAISE NOTICE 're-scoped % unique keys to testing environments', rewritten_count;
END;
$rescope_unique_indexes$;

-- Erases every row belonging to one environment.
--
-- Backs both "clean the environment" and the final stage of "delete the
-- environment", which are the same operation seen from different ends of the
-- lifecycle. It runs as the owner because it has to reach past the policies
-- that make ordinary access tenant-shaped.
--
-- The delete order is discovered rather than declared. Foreign keys in this
-- schema form a wide graph with cascades and self-references, and a hand-
-- written order would rot the first time a migration adds a table. Instead
-- each pass deletes what it can and defers what it cannot, which converges in
-- as many passes as the deepest dependency chain; a pass that makes no
-- progress at all means a genuine cycle and is raised rather than retried.
CREATE FUNCTION iam_private.erase_testing_environment(
    p_testing_environment_id uuid
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    pending regclass[];
    deferred regclass[];
    target regclass;
    deleted_total bigint := 0;
    deleted_rows bigint;
    pass_count integer := 0;
    guard_transaction_id xid8;
BEGIN
    IF p_testing_environment_id IS NULL THEN
        RAISE EXCEPTION 'a testing environment must be identified'
            USING ERRCODE = '22023';
    END IF;

    -- Audit events and the governance histories are append-only, guarded by
    -- triggers that make exactly one exception: a transaction holding the
    -- schema's erasure capability. Retention already uses it to discharge the
    -- same invariant, and reusing it is far safer than replacing two
    -- security-critical trigger functions with testing-only variants. The row
    -- is keyed to this backend, this transaction and this login, so it grants
    -- nothing beyond the statements below and disappears with them.
    guard_transaction_id := pg_current_xact_id();
    INSERT INTO iam_private.worker_retention_guards (
        backend_pid, transaction_id, invoker
    )
    VALUES (pg_backend_pid(), guard_transaction_id, session_user);

    SELECT array_agg(entry.oid::regclass ORDER BY entry.relname)
    INTO pending
    FROM pg_class AS entry
    JOIN pg_namespace AS schema_entry ON schema_entry.oid = entry.relnamespace
    JOIN pg_attribute AS scope_column
      ON scope_column.attrelid = entry.oid
     AND scope_column.attname = 'testing_environment_id'
     AND scope_column.attnum > 0
     AND NOT scope_column.attisdropped
    WHERE schema_entry.nspname = 'iam'
      AND entry.relkind IN ('r', 'p')
      AND NOT entry.relispartition;

    WHILE pending IS NOT NULL AND cardinality(pending) > 0 LOOP
        pass_count := pass_count + 1;
        IF pass_count > 64 THEN
            RAISE EXCEPTION 'testing environment erase did not converge'
                USING ERRCODE = '55000';
        END IF;

        deferred := ARRAY[]::regclass[];
        FOREACH target IN ARRAY pending LOOP
            BEGIN
                EXECUTE format(
                    'DELETE FROM %s WHERE testing_environment_id = $1',
                    target
                ) USING p_testing_environment_id;
                GET DIAGNOSTICS deleted_rows = ROW_COUNT;
                deleted_total := deleted_total + deleted_rows;
            EXCEPTION
                WHEN foreign_key_violation THEN
                    deferred := deferred || target;
            END;
        END LOOP;

        IF cardinality(deferred) = cardinality(pending) THEN
            RAISE EXCEPTION
                'testing environment erase stalled on % dependent tables',
                cardinality(deferred)
                USING ERRCODE = '55000';
        END IF;
        pending := deferred;
    END LOOP;

    DELETE FROM iam_private.worker_retention_guards AS guard
    WHERE guard.backend_pid = pg_backend_pid()
      AND guard.transaction_id = guard_transaction_id
      AND guard.invoker = session_user;

    RETURN deleted_total;
END;
$$;

COMMENT ON FUNCTION iam_private.erase_testing_environment(uuid) IS
    'Deletes every row belonging to one testing environment, in discovered dependency order.';

REVOKE ALL ON FUNCTION iam_private.erase_testing_environment(uuid) FROM PUBLIC;
