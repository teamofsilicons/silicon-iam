-- Scope uploaded organization logos to their testing environment, like every
-- other IAM table in the testing database.
DO $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.organization_logos'::regclass
               AND attname='testing_environment_id' AND NOT attisdropped) THEN
  ALTER TABLE iam.organization_logos ADD COLUMN testing_environment_id uuid NOT NULL
    DEFAULT iam_private.current_testing_environment_id();
  CREATE INDEX ON iam.organization_logos(testing_environment_id);
  CREATE POLICY testing_environment_isolation ON iam.organization_logos AS RESTRICTIVE
    USING(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id())
    WITH CHECK(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id());
  ALTER TABLE iam.organization_logos FORCE ROW LEVEL SECURITY;
 END IF;
END $$;
SELECT iam_private.reconcile_testing_environment_security();
