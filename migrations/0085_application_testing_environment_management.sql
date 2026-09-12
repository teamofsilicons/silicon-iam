-- A production application owns lifecycle authority only for environments it
-- created. Dependency imports and possession of another app's test secret do
-- not confer production control-plane authority.
CREATE FUNCTION iam_private.is_application_testing_environment_administrator(p_environment_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT EXISTS (
        SELECT 1 FROM iam.testing_environments env
        JOIN iam.applications app ON app.id = env.created_by_application_id
        JOIN iam.principals principal ON principal.id = app.id AND principal.status = 'active'
        JOIN iam.organizations org ON org.id = env.organization_id AND org.status = 'active'
        WHERE env.id = p_environment_id
          AND app.id = iam_private.current_application_id()
          AND app.id = iam_private.current_principal_id()
          AND app.organization_id = env.organization_id
          AND env.organization_id = iam_private.current_organization_id()
          AND app.review_status = 'verified' AND app.deleted_at IS NULL
    );
$$;
REVOKE ALL ON FUNCTION iam_private.is_application_testing_environment_administrator(uuid) FROM PUBLIC;

CREATE POLICY testing_environments_application_select ON iam.testing_environments FOR SELECT
USING (iam_private.is_application_testing_environment_administrator(id));
CREATE POLICY testing_environments_application_update ON iam.testing_environments FOR UPDATE
USING (iam_private.is_application_testing_environment_administrator(id))
WITH CHECK (iam_private.is_application_testing_environment_administrator(id));

-- Return only the owning handle, without widening application access to the
-- production organization directory or its private fields.
CREATE FUNCTION iam_private.testing_environment_organization_handle(p_organization_id uuid)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT org.org_id FROM iam.organizations org WHERE org.id = p_organization_id
    AND (iam_private.is_active_organization_member(org.id, iam_private.current_principal_id())
        OR EXISTS (SELECT 1 FROM iam.applications app
            JOIN iam.principals principal ON principal.id = app.id AND principal.status = 'active'
            WHERE app.id = iam_private.current_application_id()
              AND app.id = iam_private.current_principal_id()
              AND app.organization_id = org.id AND org.status = 'active'
              AND app.review_status = 'verified' AND app.deleted_at IS NULL));
$$;
REVOKE ALL ON FUNCTION iam_private.testing_environment_organization_handle(uuid) FROM PUBLIC;

-- Include deleted environments so owners can discover and restore them.
-- Keep linked environments visible, but make lifecycle authority explicit.
DROP FUNCTION iam_private.list_application_testing_environments(uuid, integer);
CREATE FUNCTION iam_private.list_application_testing_environments(p_cursor uuid, p_limit integer, p_status text)
RETURNS TABLE(environment_id uuid, org_id text, name text, description text,
    last_activity_at timestamptz, retention_days integer, status text,
    purge_after timestamptz, version bigint, can_manage boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT env.id, org.org_id, env.name, env.description,
        COALESCE(link.last_activity_at, env.last_activity_at), app.testing_idle_days,
        env.status, env.purge_after, env.version, COALESCE(env.created_by_application_id = app.id, false)
    FROM iam.applications app
    JOIN iam.principals principal ON principal.id = app.id AND principal.status = 'active'
    JOIN iam.testing_environments env ON env.organization_id = app.organization_id
    JOIN iam.organizations org ON org.id = env.organization_id AND org.status = 'active'
    LEFT JOIN iam.application_testing_environments link
        ON link.environment_id = env.id AND link.source_application_id = app.id
    WHERE app.id = iam_private.current_application_id() AND app.id = iam_private.current_principal_id()
      AND app.deleted_at IS NULL AND app.review_status = 'verified'
      AND (env.created_by_application_id = app.id OR (link.environment_id IS NOT NULL AND link.retired_at IS NULL))
      AND (p_status IS NULL OR env.status = p_status) AND (p_cursor IS NULL OR env.id > p_cursor)
    ORDER BY env.id LIMIT LEAST(GREATEST(p_limit, 1), 101);
$$;
REVOKE ALL ON FUNCTION iam_private.list_application_testing_environments(uuid, integer, text) FROM PUBLIC;

DO $$ BEGIN
    IF to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION
            iam_private.is_application_testing_environment_administrator(uuid),
            iam_private.testing_environment_organization_handle(uuid),
            iam_private.list_application_testing_environments(uuid, integer, text)
        TO silicon_iam_api;
    END IF;
END $$;
