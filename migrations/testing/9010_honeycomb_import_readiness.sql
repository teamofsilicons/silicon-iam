-- An active shared environment may contain apps awaiting coordinator readiness.
CREATE TABLE iam_private.honeycomb_testing_pending_apps (
 environment_id uuid NOT NULL,
 application_id uuid PRIMARY KEY REFERENCES iam.applications(id) ON DELETE CASCADE
);
CREATE TABLE iam_private.honeycomb_testing_source_snapshots (
 environment_id uuid NOT NULL,
 application_id uuid PRIMARY KEY REFERENCES iam.applications(id) ON DELETE CASCADE,
 source_revision bigint NOT NULL,
 snapshot jsonb NOT NULL
);
REVOKE ALL ON iam_private.honeycomb_testing_pending_apps,iam_private.honeycomb_testing_source_snapshots FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE,DELETE ON iam_private.honeycomb_testing_pending_apps,iam_private.honeycomb_testing_source_snapshots TO silicon_iam_testing_definer;

CREATE FUNCTION iam_private.honeycomb_testing_app_readiness(p_apps uuid[],p_ready boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE env uuid:=iam_private.current_testing_environment_id();
BEGIN
 IF env IS NULL OR EXISTS(SELECT 1 FROM unnest(p_apps) wanted(id) LEFT JOIN iam.applications app ON app.id=wanted.id WHERE app.id IS NULL) THEN
  RAISE EXCEPTION 'testing_application_required' USING ERRCODE='42501'; END IF;
 IF p_ready THEN
  IF EXISTS(SELECT 1 FROM unnest(p_apps) wanted(id) WHERE NOT EXISTS(SELECT 1 FROM iam_private.honeycomb_testing_pending_apps WHERE application_id=wanted.id AND environment_id=env)) THEN
   RAISE EXCEPTION 'pending_testing_application_required' USING ERRCODE='40001'; END IF;
  UPDATE iam.principals SET status='active',suspended_at=NULL WHERE id=ANY(p_apps);
  DELETE FROM iam_private.honeycomb_testing_pending_apps WHERE environment_id=env AND application_id=ANY(p_apps);
 ELSE
  UPDATE iam.principals SET status='suspended',suspended_at=clock_timestamp(),auth_epoch=auth_epoch+1
  WHERE id=ANY(p_apps) AND status='active';
  INSERT INTO iam_private.honeycomb_testing_pending_apps SELECT env,unnest(p_apps) ON CONFLICT DO NOTHING;
 END IF;
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_app_readiness(uuid[],boolean) FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_testing_activate_apps(p_apps text[])
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE ids uuid[]; env uuid:=iam_private.current_testing_environment_id();
BEGIN
 IF env IS NULL THEN RAISE EXCEPTION 'environment_required' USING ERRCODE='42501'; END IF;
 SELECT COALESCE(array_agg(app.id),'{}'::uuid[]) INTO ids FROM iam.applications app
 JOIN iam_private.honeycomb_testing_pending_apps pending ON pending.application_id=app.id AND pending.environment_id=env
 WHERE p_apps IS NULL OR app.app_id=ANY(p_apps);
 -- A test commit can succeed before its production receipt. Exact retries may
 -- therefore name already-active imports; they must not reactivate retired apps.
 IF p_apps IS NOT NULL AND (
  cardinality(p_apps)<>(SELECT count(DISTINCT value) FROM unnest(p_apps) value)
  OR EXISTS(SELECT 1 FROM unnest(p_apps) wanted(app_id)
   LEFT JOIN iam.applications app ON app.app_id=wanted.app_id
   LEFT JOIN iam.principals principal ON principal.id=app.id
   LEFT JOIN iam.testing_application_imports imported ON imported.application_id=app.id
   WHERE app.id IS NULL OR (app.test_imported_from_production AND (imported.application_id IS NULL OR imported.retired_at IS NOT NULL))
    OR (principal.status<>'active' AND NOT EXISTS(SELECT 1 FROM iam_private.honeycomb_testing_pending_apps pending WHERE pending.environment_id=env AND pending.application_id=app.id)))
 ) THEN RAISE EXCEPTION 'exact_pending_apps_required' USING ERRCODE='40001'; END IF;
 PERFORM iam_private.honeycomb_testing_app_readiness(ids,true);
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_activate_apps(text[]) FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_testing_store_snapshot(p_app uuid,p_revision bigint,p_snapshot jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE env uuid:=iam_private.current_testing_environment_id();
BEGIN
 IF env IS NULL OR NOT EXISTS(SELECT 1 FROM iam.testing_application_imports WHERE application_id=p_app AND source_revision=p_revision) THEN
  RAISE EXCEPTION 'testing_import_required' USING ERRCODE='42501'; END IF;
 INSERT INTO iam_private.honeycomb_testing_source_snapshots VALUES(env,p_app,p_revision,p_snapshot)
 ON CONFLICT(application_id) DO UPDATE SET source_revision=EXCLUDED.source_revision,snapshot=EXCLUDED.snapshot;
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_store_snapshot(uuid,bigint,jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_testing_source_snapshots()
RETURNS SETOF jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE env uuid:=iam_private.current_testing_environment_id(); missing text[];
BEGIN
 IF env IS NULL THEN RAISE EXCEPTION 'environment_required' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT cache.snapshot FROM iam_private.honeycomb_testing_source_snapshots cache
 JOIN iam.testing_application_imports imported ON imported.application_id=cache.application_id AND imported.source_revision=cache.source_revision
 WHERE cache.environment_id=env;
 SELECT array_agg(app.app_id) INTO missing FROM iam.applications app
 JOIN iam.testing_application_imports imported ON imported.application_id=app.id
 WHERE NOT EXISTS(SELECT 1 FROM iam_private.honeycomb_testing_source_snapshots cache WHERE cache.application_id=app.id AND cache.source_revision=imported.source_revision);
 -- Adopt an existing pin from its accepted test record, not today's production config.
 RETURN QUERY SELECT to_jsonb(source)||jsonb_build_object('encryption_application_id',source.source_application_id,
  'source_application_id',imported.source_application_id,'source_revision',imported.source_revision)
 FROM iam_private.get_testing_application_import_v2(missing) source
 JOIN iam.testing_application_imports imported ON imported.application_id=source.source_application_id;
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_source_snapshots() FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_testing_import_records()
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE result jsonb; env uuid:=iam_private.current_testing_environment_id();
BEGIN
 IF env IS NULL THEN RAISE EXCEPTION 'environment_required' USING ERRCODE='42501'; END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('app_id',app.app_id,'application_id',app.id,
 'source_application_id',imported.source_application_id,'source_revision',imported.source_revision,
 'configuration_revision',app.honeycomb_configuration_revision,'iam_revision',app.version,
 'ready',principal.status='active' AND imported.retired_at IS NULL AND NOT EXISTS(SELECT 1 FROM iam_private.honeycomb_testing_pending_apps WHERE environment_id=env AND application_id=app.id),
 'effective_configuration',jsonb_build_object('app_id',app.app_id,'org_id',org.org_id,'app_name',app.app_name,
 'app_logo',app.app_logo_uri,'base_url',app.base_url,'visibility',app.visibility,'app_scope',app.app_scope,'webhook_scope',app.webhook_scope)
 ) ORDER BY app.app_id),'[]'::jsonb) INTO result
 FROM iam.testing_application_imports imported JOIN iam.applications app ON app.id=imported.application_id
 JOIN iam.principals principal ON principal.id=app.id JOIN iam.organizations org ON org.id=app.organization_id;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_import_records() FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
GRANT EXECUTE ON FUNCTION iam_private.honeycomb_testing_app_readiness(uuid[],boolean),iam_private.honeycomb_testing_activate_apps(text[]),
 iam_private.honeycomb_testing_store_snapshot(uuid,bigint,jsonb),iam_private.honeycomb_testing_source_snapshots(),iam_private.honeycomb_testing_import_records() TO silicon_iam_api;
END IF; END $$;
SELECT iam_private.reconcile_testing_environment_security();
