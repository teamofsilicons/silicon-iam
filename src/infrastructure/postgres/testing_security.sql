-- Read-only readiness audit; callable by the ordinary runtime role without
-- granting it the privileged migration-time reconciliation entry point.
WITH definer AS (
    SELECT oid FROM pg_catalog.pg_roles
    WHERE rolname = 'silicon_iam_testing_definer'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
      AND NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication
      AND NOT rolbypassrls
), scoped_tables AS (
    SELECT entry.oid, entry.relrowsecurity, entry.relforcerowsecurity
    FROM pg_catalog.pg_class AS entry
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = entry.relnamespace
    WHERE namespace.nspname = 'iam' AND entry.relkind IN ('r', 'p')
      AND entry.relname <> ALL (ARRAY[
          'cryptographic_key_versions', 'oauth_scope_catalog',
          'organization_capability_catalog', 'platform_capability_catalog',
          'platform_role_capabilities', 'platform_role_catalog',
          'runtime_key_activations'
      ])
)
SELECT EXISTS (SELECT 1 FROM definer)
    AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'iam_private' AND procedure.prosecdef
          AND procedure.proowner <> (SELECT oid FROM definer)
    )
    AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles AS role
        WHERE (role.rolname IN ('silicon_iam_api', 'silicon_iam_worker', 'silicon_iam_key_operator')
            OR (role.rolcanlogin AND NOT role.rolsuper AND (
                COALESCE(pg_catalog.pg_has_role(role.oid,
                    pg_catalog.to_regrole('silicon_iam_api'), 'member'), false)
                OR COALESCE(pg_catalog.pg_has_role(role.oid,
                    pg_catalog.to_regrole('silicon_iam_worker'), 'member'), false)
                OR COALESCE(pg_catalog.pg_has_role(role.oid,
                    pg_catalog.to_regrole('silicon_iam_key_operator'), 'member'), false)
            )))
          AND pg_catalog.pg_has_role(role.oid, (SELECT oid FROM definer), 'member')
    )
    AND NOT EXISTS (
        SELECT 1 FROM scoped_tables AS scoped
        WHERE NOT scoped.relrowsecurity OR NOT scoped.relforcerowsecurity
           OR NOT EXISTS (
               SELECT 1 FROM pg_catalog.pg_attribute AS column_entry
               WHERE column_entry.attrelid = scoped.oid
                 AND column_entry.attname = 'testing_environment_id'
                 AND column_entry.attnum > 0 AND NOT column_entry.attisdropped
                 AND column_entry.attnotnull
           )
           OR NOT EXISTS (
               SELECT 1 FROM pg_catalog.pg_policy AS policy
               WHERE policy.polrelid = scoped.oid
                 AND policy.polname = 'testing_environment_definer'
                 AND policy.polpermissive AND policy.polcmd = '*'
                 AND policy.polroles = ARRAY[(SELECT oid FROM definer)]
                 AND pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) = 'true'
                 AND pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid) = 'true'
           )
           OR NOT EXISTS (
               SELECT 1 FROM pg_catalog.pg_policy AS policy
               WHERE policy.polrelid = scoped.oid
                 AND policy.polname = 'testing_environment_definer_required'
                 AND NOT policy.polpermissive AND policy.polcmd = '*'
                 AND policy.polroles = ARRAY[(SELECT oid FROM definer)]
                 AND pg_catalog.pg_get_expr(policy.polqual, policy.polrelid)
                     = 'iam_private.testing_environment_definer_scope_is_allowed(testing_environment_id)'
                 AND pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid)
                     = 'iam_private.testing_environment_definer_scope_is_allowed(testing_environment_id)'
           )
    )
