-- Scope uploaded profile photos to their testing environment, like every
-- other IAM table in the testing database.
DO $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.silicon_step_up_assertions'::regclass
               AND attname='testing_environment_id' AND NOT attisdropped) THEN
  ALTER TABLE iam.silicon_step_up_assertions ADD COLUMN testing_environment_id uuid NOT NULL
    DEFAULT iam_private.current_testing_environment_id();
  CREATE INDEX ON iam.silicon_step_up_assertions(testing_environment_id);
  CREATE POLICY testing_environment_isolation ON iam.silicon_step_up_assertions AS RESTRICTIVE
    USING(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id())
    WITH CHECK(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id());
  ALTER TABLE iam.silicon_step_up_assertions FORCE ROW LEVEL SECURITY;
 END IF;
END $$;
SELECT iam_private.reconcile_testing_environment_security();
