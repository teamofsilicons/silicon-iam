DO $$
DECLARE table_name text;
BEGIN
 FOREACH table_name IN ARRAY ARRAY['silicon_signup_requests','silicon_password_credentials','silicon_custodians'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=format('iam.%I',table_name)::regclass AND attname='testing_environment_id' AND NOT attisdropped) THEN
   EXECUTE format('ALTER TABLE iam.%I ADD COLUMN testing_environment_id uuid NOT NULL DEFAULT iam_private.current_testing_environment_id()',table_name);
   EXECUTE format('CREATE INDEX ON iam.%I(testing_environment_id)',table_name);
   EXECUTE format('CREATE POLICY testing_environment_isolation ON iam.%I AS RESTRICTIVE USING(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id()) WITH CHECK(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id())',table_name);
   EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',table_name);
  END IF;
 END LOOP;
END $$;
SELECT iam_private.reconcile_testing_environment_security();
