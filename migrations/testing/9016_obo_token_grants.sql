-- Existing testing installations need the same forced tenant boundary that
-- fresh databases receive from 9001, on every new OBO relation.
DO $$
DECLARE relation_name text;
BEGIN
 FOREACH relation_name IN ARRAY ARRAY['obo_authorization_requests','obo_grants','obo_authorization_codes','obo_token_families','obo_access_tokens','obo_refresh_tokens'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=('iam.'||relation_name)::regclass
    AND attname='testing_environment_id' AND NOT attisdropped) THEN
   EXECUTE format('ALTER TABLE iam.%I ADD COLUMN testing_environment_id uuid NOT NULL DEFAULT iam_private.current_testing_environment_id()',relation_name);
   EXECUTE format('CREATE INDEX ON iam.%I(testing_environment_id)',relation_name);
   EXECUTE format('CREATE POLICY testing_environment_isolation ON iam.%I AS RESTRICTIVE USING(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id()) WITH CHECK(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id())',relation_name);
   EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',relation_name);
  END IF;
 END LOOP;
END $$;
SELECT iam_private.reconcile_testing_environment_security();
