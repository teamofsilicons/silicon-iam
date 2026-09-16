-- Root authority is limited to this managed isolated environment, never a user
-- identity or permission to alter a production application.
CREATE FUNCTION iam_private.honeycomb_testing_root_app_authority(p_service uuid,p_environment uuid,p_generation bigint,p_key_version integer,p_digests bytea[])
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT p_service=iam_private.current_principal_id()
 AND iam_private.current_application_id() IS NULL
 AND EXISTS(SELECT 1 FROM iam.testing_environments env
 JOIN iam.applications app ON app.id=p_service AND app.deleted_at IS NULL
 JOIN iam.principals principal ON principal.id=app.id AND principal.status='active'
 WHERE env.id=p_environment AND env.honeycomb_service_id=p_service
 AND env.managed_state IN ('active','prepared','cleaned')
 AND env.cleaning_generation=p_generation AND env.key_generation=p_key_version
 AND env.key_digest=ANY(p_digests));
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_root_app_authority(uuid,uuid,bigint,integer,bytea[]) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_testing_root_app_authority(uuid,uuid,bigint,integer,bytea[]) TO silicon_iam_api;
END IF; END $$;
