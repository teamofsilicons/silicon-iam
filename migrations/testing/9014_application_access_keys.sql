-- Fresh testing databases gain this column in 9001. Existing installations
-- need the same forced scope when the new production table is introduced.
DO $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.application_access_keys'::regclass
               AND attname='testing_environment_id' AND NOT attisdropped) THEN
  ALTER TABLE iam.application_access_keys ADD COLUMN testing_environment_id uuid NOT NULL
    DEFAULT iam_private.current_testing_environment_id();
  CREATE INDEX ON iam.application_access_keys(testing_environment_id);
  CREATE POLICY testing_environment_isolation ON iam.application_access_keys AS RESTRICTIVE
    USING(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id())
    WITH CHECK(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id());
  ALTER TABLE iam.application_access_keys FORCE ROW LEVEL SECURITY;
 END IF;
END $$;
SELECT iam_private.reconcile_testing_environment_security();
