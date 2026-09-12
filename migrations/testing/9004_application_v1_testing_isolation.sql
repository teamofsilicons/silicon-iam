-- Extend an already-created testing database when the official application tables arrive.
-- A fresh database was scoped by 9001; this loop only handles missing columns.
DO $new_application_tables$
DECLARE entry record;
BEGIN
 FOR entry IN SELECT relation.oid,pg_catalog.pg_get_userbyid(relation.relowner) owner_name
 FROM pg_catalog.pg_class relation JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
 WHERE namespace.nspname='iam' AND relation.relkind='r'
 AND relation.relname=ANY(ARRAY['application_scope_requests','application_scope_messages','application_bundles','application_bundle_members','application_testing_environments','testing_application_imports'])
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute column_entry WHERE column_entry.attrelid=relation.oid AND column_entry.attname='testing_environment_id' AND NOT column_entry.attisdropped)
 LOOP
 EXECUTE format('ALTER TABLE %s ADD COLUMN testing_environment_id uuid NOT NULL DEFAULT iam_private.current_testing_environment_id()',entry.oid::regclass);
 EXECUTE format('CREATE INDEX ON %s(testing_environment_id)',entry.oid::regclass);
 EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',entry.oid::regclass);
 EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',entry.oid::regclass);
 EXECUTE format('CREATE POLICY testing_environment_owner ON %s TO %I USING(true) WITH CHECK(true)',entry.oid::regclass,entry.owner_name);
 EXECUTE format('CREATE POLICY testing_environment_isolation ON %s AS RESTRICTIVE USING(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id()) WITH CHECK(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id())',entry.oid::regclass);
 IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 EXECUTE format('CREATE POLICY testing_environment_api ON %s AS RESTRICTIVE TO silicon_iam_api USING(testing_environment_id=iam_private.current_testing_environment_id()) WITH CHECK(testing_environment_id=iam_private.current_testing_environment_id())',entry.oid::regclass);
 END IF;
 END LOOP;
END $new_application_tables$;
-- This includes the shared iam_private.contract_versions catalogue. Reconcile
-- grants as well as helper ownership on both fresh and already-scoped databases.
SELECT iam_private.reconcile_testing_environment_security();
