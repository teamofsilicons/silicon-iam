-- Imported applications retain a configuration snapshot, while their owning
-- production organization's IAM scope policy is rechecked before test traffic.
-- Policy values are read by the server, never accepted from an HTTP caller.
CREATE FUNCTION iam_private.get_testing_source_iam_scope_policies(p_sources uuid[])
RETURNS TABLE(source_application_id uuid, org_id text, trusted_org boolean, allowed_scopes text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam AS $$
 SELECT app.id, org.org_id, org.status = 'active' AND org.trusted_org,
        CASE WHEN org.status = 'active' THEN org.allowed_restricted_iam_scopes ELSE '{}'::text[] END
 FROM iam.applications app JOIN iam.organizations org ON org.id = app.organization_id
 -- Imported applications have their own lifecycle. A retained source row is
 -- provenance for its owning-org policy even after that source is retired.
 WHERE app.id = ANY(p_sources)
$$;
REVOKE ALL ON FUNCTION iam_private.get_testing_source_iam_scope_policies(uuid[]) FROM PUBLIC;

CREATE FUNCTION iam_private.list_testing_import_iam_scope_sources()
RETURNS TABLE(application_id uuid, source_application_id uuid, org_id text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
BEGIN
 -- A forged setting cannot turn the production database into a test world.
 IF NULLIF(current_setting('iam.testing_environment_id', true), '') IS NULL
    OR to_regprocedure('iam_private.current_testing_environment_id()') IS NULL THEN
   RAISE EXCEPTION 'testing_environment_required' USING ERRCODE='42501';
 END IF;
 RETURN QUERY SELECT app.id, imported.source_application_id, org.org_id
 FROM iam.testing_application_imports imported
 JOIN iam.applications app ON app.id = imported.application_id
 JOIN iam.organizations org ON org.id = app.organization_id;
END $$;
REVOKE ALL ON FUNCTION iam_private.list_testing_import_iam_scope_sources() FROM PUBLIC;

CREATE FUNCTION iam_private.apply_testing_import_iam_scope_policies(p_policies jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE policy record;
BEGIN
 IF NULLIF(current_setting('iam.testing_environment_id', true), '') IS NULL
    OR to_regprocedure('iam_private.current_testing_environment_id()') IS NULL THEN
   RAISE EXCEPTION 'testing_environment_required' USING ERRCODE='42501';
 END IF;
 IF p_policies IS NULL OR jsonb_typeof(p_policies) <> 'array' THEN
   RAISE EXCEPTION 'testing_import_policy_invalid' USING ERRCODE='42501';
 END IF;
 -- The batch must identify existing imported applications by BOTH local and
 -- production UUID, and the owning organization handle returned by production.
 -- It can never select an arbitrary local organization for trust elevation.
 IF EXISTS (
   SELECT 1 FROM jsonb_to_recordset(p_policies) AS input(
     application_id uuid, source_application_id uuid, org_id text, trusted_org boolean, allowed_scopes text[])
   LEFT JOIN iam.testing_application_imports imported
     ON imported.application_id=input.application_id AND imported.source_application_id=input.source_application_id
   LEFT JOIN iam.applications app ON app.id=imported.application_id AND app.test_imported_from_production
   LEFT JOIN iam.organizations org ON org.id=app.organization_id AND org.org_id=input.org_id
   WHERE org.id IS NULL OR input.trusted_org IS NULL OR input.allowed_scopes IS NULL
 ) OR EXISTS (
   SELECT 1 FROM jsonb_to_recordset(p_policies) AS input(
     application_id uuid, source_application_id uuid, org_id text, trusted_org boolean, allowed_scopes text[])
   GROUP BY input.org_id HAVING count(DISTINCT (input.trusted_org,input.allowed_scopes)) > 1
 ) THEN
   RAISE EXCEPTION 'testing_import_policy_invalid' USING ERRCODE='42501';
 END IF;
 -- A matching snapshot is a read-only operation. Changed policies take locks
 -- in deterministic organization order; the 0087 trigger revokes unavailable
 -- approvals and access tokens. Restoring policy does not restore approvals.
 FOR policy IN
   SELECT DISTINCT org.id, input.trusted_org, input.allowed_scopes
   FROM jsonb_to_recordset(p_policies) AS input(
     application_id uuid, source_application_id uuid, org_id text, trusted_org boolean, allowed_scopes text[])
   JOIN iam.testing_application_imports imported ON imported.application_id=input.application_id
   JOIN iam.applications app ON app.id=imported.application_id
   JOIN iam.organizations org ON org.id=app.organization_id
   WHERE org.trusted_org IS DISTINCT FROM input.trusted_org
      OR org.allowed_restricted_iam_scopes IS DISTINCT FROM input.allowed_scopes
   ORDER BY org.id
 LOOP
   UPDATE iam.organizations SET trusted_org=policy.trusted_org,
       allowed_restricted_iam_scopes=policy.allowed_scopes
   WHERE id=policy.id AND (trusted_org IS DISTINCT FROM policy.trusted_org
       OR allowed_restricted_iam_scopes IS DISTINCT FROM policy.allowed_scopes);
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION iam_private.apply_testing_import_iam_scope_policies(jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.activate_testing_application_scopes(p_app_ids uuid[])
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE app record;
BEGIN
 IF NULLIF(current_setting('iam.testing_environment_id', true), '') IS NULL THEN
   RAISE EXCEPTION 'testing_environment_required' USING ERRCODE='42501';
 END IF;
 UPDATE iam.principals principal SET status='active',suspended_at=NULL FROM iam.testing_application_imports imported
 WHERE imported.application_id=principal.id AND imported.retired_at IS NOT NULL AND principal.id=ANY(p_app_ids);
 UPDATE iam.applications application SET review_status='verified' FROM iam.testing_application_imports imported
 WHERE imported.application_id=application.id AND imported.retired_at IS NOT NULL AND application.id=ANY(p_app_ids);
 UPDATE iam.testing_application_imports SET retired_at=NULL,last_activity_at=clock_timestamp() WHERE application_id=ANY(p_app_ids);
 FOR app IN SELECT application.id,application.app_scope,application.created_by_carbon_id
   FROM iam.applications application JOIN iam.testing_application_imports imported ON imported.application_id=application.id
   WHERE application.id=ANY(p_app_ids) LOOP
   INSERT INTO iam.oauth_scope_catalog(scope,description,sensitive)
   SELECT scope,description,critical FROM iam_private.application_scope_catalog(NULL)
   WHERE scope=ANY(iam_private.application_scope_names(app.app_scope)) ON CONFLICT(scope) DO NOTHING;
   INSERT INTO iam.application_requested_scopes(application_id,scope)
   SELECT app.id,desired.scope FROM unnest(iam_private.application_scope_names(app.app_scope)) desired(scope)
   WHERE iam_private.application_iam_scope_allowed(app.id,desired.scope) ON CONFLICT DO NOTHING;
   INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id)
   SELECT app.id,desired.scope,app.created_by_carbon_id FROM unnest(iam_private.application_scope_names(app.app_scope)) desired(scope)
   WHERE iam_private.application_iam_scope_allowed(app.id,desired.scope)
     AND NOT EXISTS (SELECT 1 FROM iam.application_approved_scopes approved
       WHERE approved.application_id=app.id AND approved.scope=desired.scope AND approved.revoked_at IS NULL);
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION iam_private.activate_testing_application_scopes(uuid[]) FROM PUBLIC;

DO $$ BEGIN
 IF to_regrole('silicon_iam_api') IS NOT NULL THEN
   GRANT EXECUTE ON FUNCTION iam_private.get_testing_source_iam_scope_policies(uuid[]),
     iam_private.list_testing_import_iam_scope_sources(),
     iam_private.apply_testing_import_iam_scope_policies(jsonb) TO silicon_iam_api;
 END IF;
END $$;
