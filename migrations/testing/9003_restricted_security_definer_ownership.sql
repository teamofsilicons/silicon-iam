-- FORCE ROW LEVEL SECURITY does not constrain an elevated migration login.
-- Give testing helpers a non-login, row-security-constrained owner instead.
-- Production ownership is deliberately unchanged: this is a testing overlay.

CREATE FUNCTION iam_private.testing_environment_definer_scope_is_allowed(
    p_testing_environment_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, iam_private
AS $$
    SELECT p_testing_environment_id = iam_private.current_testing_environment_id()
        OR (
            iam_private.current_testing_environment_id() IS NULL
            AND (
                COALESCE(pg_catalog.pg_has_role(
                    session_user,
                    pg_catalog.to_regrole('silicon_iam_worker'),
                    'member'
                ), false)
                OR COALESCE(pg_catalog.pg_has_role(
                    session_user,
                    pg_catalog.to_regrole('silicon_iam_testing_definer'),
                    'member'
                ), false)
            )
        )
$$;

REVOKE ALL ON FUNCTION iam_private.testing_environment_definer_scope_is_allowed(uuid)
    FROM PUBLIC;

-- This is intentionally SECURITY INVOKER, unavailable to runtime roles.
-- The migrator reruns it after every base migration, including replacements
-- and newly introduced helpers. Running only the overlay once would allow a
-- later CREATE FUNCTION to reintroduce elevated ownership.
CREATE FUNCTION iam_private.reconcile_testing_environment_security()
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    definer_role oid;
    runtime_role text;
    table_record record;
    function_record record;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(706946, 9003);

    IF pg_catalog.to_regrole('silicon_iam_testing_definer') IS NULL THEN
        CREATE ROLE silicon_iam_testing_definer
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;

    SELECT oid INTO STRICT definer_role
    FROM pg_catalog.pg_roles
    WHERE rolname = 'silicon_iam_testing_definer'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
      AND NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication
      AND NOT rolbypassrls;

    -- Never repair an unsafe runtime membership silently. A runtime login
    -- that could SET ROLE to this owner would defeat the helper boundary.
    FOREACH runtime_role IN ARRAY ARRAY[
        'silicon_iam_api', 'silicon_iam_worker', 'silicon_iam_key_operator'
    ] LOOP
        IF pg_catalog.to_regrole(runtime_role) IS NOT NULL
           AND pg_catalog.pg_has_role(
               pg_catalog.to_regrole(runtime_role), definer_role, 'member'
           ) THEN
            RAISE EXCEPTION '% must not be a testing definer member', runtime_role;
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles AS login
        WHERE login.rolcanlogin AND NOT login.rolsuper
          AND pg_catalog.pg_has_role(login.oid, definer_role, 'member')
          AND (
              COALESCE(pg_catalog.pg_has_role(login.oid,
                  pg_catalog.to_regrole('silicon_iam_api'), 'member'), false)
              OR COALESCE(pg_catalog.pg_has_role(login.oid,
                  pg_catalog.to_regrole('silicon_iam_worker'), 'member'), false)
              OR COALESCE(pg_catalog.pg_has_role(login.oid,
                  pg_catalog.to_regrole('silicon_iam_key_operator'), 'member'), false)
          )
    ) THEN
        RAISE EXCEPTION 'runtime logins must not be testing definer members';
    END IF;

    -- Migrators must retain ownership rights for subsequent forward
    -- replacements. This role is never granted to API or worker logins.
    EXECUTE pg_catalog.format(
        'GRANT silicon_iam_testing_definer TO %I', current_user
    );
    GRANT USAGE ON SCHEMA iam, iam_private TO silicon_iam_testing_definer;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA iam, iam_private
        TO silicon_iam_testing_definer;
    GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA iam, iam_private
        TO silicon_iam_testing_definer;
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA iam_private
        TO silicon_iam_testing_definer;

    FOR table_record IN
        SELECT entry.oid
        FROM pg_catalog.pg_class AS entry
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = entry.relnamespace
        JOIN pg_catalog.pg_attribute AS scope_column
          ON scope_column.attrelid = entry.oid
         AND scope_column.attname = 'testing_environment_id'
         AND scope_column.attnum > 0 AND NOT scope_column.attisdropped
        WHERE namespace.nspname = 'iam' AND entry.relkind IN ('r', 'p')
    LOOP
        EXECUTE pg_catalog.format(
            'DROP POLICY IF EXISTS testing_environment_definer ON %s',
            table_record.oid::regclass
        );
        EXECUTE pg_catalog.format(
            'CREATE POLICY testing_environment_definer ON %s'
            || ' TO silicon_iam_testing_definer USING (true) WITH CHECK (true)',
            table_record.oid::regclass
        );
        EXECUTE pg_catalog.format(
            'DROP POLICY IF EXISTS testing_environment_definer_required ON %s',
            table_record.oid::regclass
        );
        EXECUTE pg_catalog.format(
            'CREATE POLICY testing_environment_definer_required ON %s AS RESTRICTIVE'
            || ' TO silicon_iam_testing_definer'
            || ' USING (iam_private.testing_environment_definer_scope_is_allowed(testing_environment_id))'
            || ' WITH CHECK (iam_private.testing_environment_definer_scope_is_allowed(testing_environment_id))',
            table_record.oid::regclass
        );
        EXECUTE pg_catalog.format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',
            table_record.oid::regclass);
        EXECUTE pg_catalog.format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',
            table_record.oid::regclass);
    END LOOP;

    -- PostgreSQL requires schema CREATE while transferring function ownership;
    -- the function owner has no need for it once the transfer is complete.
    GRANT CREATE ON SCHEMA iam_private TO silicon_iam_testing_definer;
    FOR function_record IN
        SELECT procedure.oid::regprocedure AS signature
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'iam_private' AND procedure.prosecdef
    LOOP
        EXECUTE pg_catalog.format('ALTER FUNCTION %s OWNER TO silicon_iam_testing_definer',
            function_record.signature);
    END LOOP;
    REVOKE CREATE ON SCHEMA iam_private FROM silicon_iam_testing_definer;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.reconcile_testing_environment_security() FROM PUBLIC;

SELECT iam_private.reconcile_testing_environment_security();
