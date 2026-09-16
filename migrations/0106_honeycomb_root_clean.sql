-- Environment root holders may clean their own shared environment. Exact replay
-- also works after generation advances and while target-plane cleanup is pending.
ALTER TABLE iam_private.honeycomb_testing_root_operations
 DROP CONSTRAINT honeycomb_testing_root_operations_operation_kind_check;
ALTER TABLE iam_private.honeycomb_testing_root_operations
 ADD CONSTRAINT honeycomb_testing_root_operations_operation_kind_check
 CHECK(operation_kind IN ('import','rotate-key','clean'));

CREATE OR REPLACE FUNCTION iam_private.honeycomb_testing_root_authority(p_service uuid,p_environment uuid,p_operation uuid,p_kind text,p_generation bigint,p_expected bigint,p_key_version integer,p_digests bytea[])
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE env iam.testing_environments%ROWTYPE; proof iam_private.honeycomb_testing_root_operations%ROWTYPE;
BEGIN
 IF p_service IS DISTINCT FROM iam_private.current_principal_id()
  OR iam_private.current_application_id() IS NOT NULL OR p_kind NOT IN ('import','rotate-key','clean')
  OR p_generation IS NULL OR p_expected IS NULL OR p_key_version IS NULL OR COALESCE(cardinality(p_digests),0)=0 THEN RETURN false; END IF;
 IF NOT EXISTS(SELECT 1 FROM iam.applications app JOIN iam.principals principal ON principal.id=app.id AND principal.status='active'
  WHERE app.id=p_service AND app.deleted_at IS NULL) THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('testing-runtime:'||p_environment::text,0));
 SELECT * INTO env FROM iam.testing_environments WHERE id=p_environment FOR UPDATE;
 IF env.id IS NULL OR env.honeycomb_service_id IS DISTINCT FROM p_service
  OR env.managed_state IN ('legacy','disabled','purging','purged')
  OR (env.managed_state='cleaning' AND p_kind<>'clean') THEN RETURN false; END IF;
 SELECT * INTO proof FROM iam_private.honeycomb_testing_root_operations WHERE operation_id=p_operation;
 IF proof.operation_id IS NOT NULL THEN
  IF proof.service_application_id<>p_service OR proof.environment_id<>p_environment OR proof.operation_kind<>p_kind
   OR proof.generation<>p_generation OR proof.expected_revision<>p_expected OR proof.expected_key_version<>p_key_version
   OR NOT proof.key_digest=ANY(p_digests) OR env.lifecycle_operation_id IS DISTINCT FROM p_operation
   OR NOT EXISTS(SELECT 1 FROM iam.honeycomb_operations operation WHERE operation.operation_id=p_operation
    AND operation.service_application_id=p_service AND operation.actor_principal_id=p_service
    AND operation.resource_id=p_environment::text AND operation.operation_kind='testing-'||p_kind) THEN RETURN false; END IF;
 ELSE
  IF env.managed_state NOT IN ('prepared','cleaned','active') OR env.cleaning_generation<>p_generation
   OR env.version<>p_expected OR env.key_generation<>p_key_version OR NOT env.key_digest=ANY(p_digests) THEN RETURN false; END IF;
  INSERT INTO iam_private.honeycomb_testing_root_operations(operation_id,service_application_id,environment_id,operation_kind,generation,expected_revision,expected_key_version,key_digest)
  VALUES(p_operation,p_service,p_environment,p_kind,p_generation,p_expected,p_key_version,env.key_digest);
 END IF;
 PERFORM set_config('iam.honeycomb_root_authority',p_environment::text||':'||p_operation::text,true);
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_root_authority(uuid,uuid,uuid,text,bigint,bigint,integer,bytea[]) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_testing_root_authority(uuid,uuid,uuid,text,bigint,bigint,integer,bytea[]) TO silicon_iam_api;
END IF; END $$;

