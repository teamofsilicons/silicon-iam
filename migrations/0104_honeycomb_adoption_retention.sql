-- Protected transfer and exact application-retention control. Neither changes
-- root credentials, ownership, accepted configuration, or the writer cutover.
CREATE FUNCTION iam_private.honeycomb_adoption_export(p_service uuid,p_environment uuid,p_expected bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private
AS $$
DECLARE env iam.testing_environments%ROWTYPE; result jsonb;
BEGIN
 IF iam_private.current_principal_id() IS DISTINCT FROM p_service OR NOT EXISTS(SELECT 1 FROM iam.applications WHERE id=p_service AND deleted_at IS NULL) THEN
 RAISE EXCEPTION 'service_required' USING ERRCODE='42501'; END IF;
 SELECT * INTO env FROM iam.testing_environments WHERE id=p_environment FOR SHARE;
 IF env.id IS NULL THEN RAISE EXCEPTION 'environment_not_found' USING ERRCODE='P0002'; END IF;
 IF env.honeycomb_service_id IS NOT NULL AND env.honeycomb_service_id<>p_service THEN RAISE EXCEPTION 'environment_service_mismatch' USING ERRCODE='42501'; END IF;
 IF env.version<>p_expected OR env.managed_state IN ('cleaning','purging','purged','importing') THEN RAISE EXCEPTION 'environment_revision_conflict' USING ERRCODE='40001'; END IF;
 SELECT jsonb_build_object('environment_id',env.id,'org_id',org.org_id,'organization_id',env.organization_id,
 'name',env.name,'description',env.description,'status',env.status,'state',env.managed_state,'iam_revision',env.version,
 'generation',env.cleaning_generation,'key_version',env.key_generation,'created_by_membership_id',env.created_by_membership_id,
 'created_by_application_id',env.created_by_application_id,'last_activity_at',env.last_activity_at,'deleted_at',env.deleted_at,'purge_after',env.purge_after,
 'applications',COALESCE((SELECT jsonb_agg(jsonb_build_object('app_id',app.app_id,'source_application_id',link.source_application_id,
 'target_application_id',link.target_application_id,'iam_revision',app.version,'configuration_revision',app.honeycomb_configuration_revision,
 'retention_days',app.testing_idle_days,'link_revision',link.version,'last_activity_at',link.last_activity_at,'retired_at',link.retired_at) ORDER BY app.app_id)
 FROM iam.application_testing_environments link JOIN iam.applications app ON app.id=link.source_application_id WHERE link.environment_id=env.id),'[]'::jsonb))
 INTO result FROM iam.organizations org WHERE org.id=env.organization_id;
 RETURN result;
END $$;
CREATE FUNCTION iam_private.honeycomb_adoption_key(p_service uuid,p_environment uuid)
RETURNS TABLE(organization_id uuid,key_digest bytea,key_digest_key_version smallint,key_ciphertext bytea,key_nonce bytea,key_encryption_key_version smallint)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private
AS $$
 SELECT organization_id,key_digest,key_digest_key_version,key_ciphertext,key_nonce,key_encryption_key_version
 FROM iam.testing_environments WHERE id=p_environment AND managed_state<>'purged'
 AND (honeycomb_service_id IS NULL OR honeycomb_service_id=p_service)
 AND iam_private.current_principal_id()=p_service AND EXISTS(SELECT 1 FROM iam.applications WHERE id=p_service AND deleted_at IS NULL);
$$;

CREATE FUNCTION iam_private.honeycomb_retention_start(p_service uuid,p_environment uuid,p_operation uuid,p_expected bigint,p_generation bigint,p_key integer,p_apps text[],p_test_apps text[] DEFAULT ARRAY[]::text[])
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private
AS $$
DECLARE env iam.testing_environments%ROWTYPE;
BEGIN
 IF iam_private.current_principal_id() IS DISTINCT FROM p_service THEN RAISE EXCEPTION 'service_required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('testing-runtime:'||p_environment::text,0));
 SELECT * INTO env FROM iam.testing_environments WHERE id=p_environment FOR UPDATE;
 IF env.id IS NULL THEN RAISE EXCEPTION 'environment_not_found' USING ERRCODE='P0002'; END IF;
 IF env.honeycomb_service_id IS DISTINCT FROM p_service THEN RAISE EXCEPTION 'environment_service_mismatch' USING ERRCODE='42501'; END IF;
 IF (env.version<>p_expected AND env.lifecycle_operation_id IS DISTINCT FROM p_operation) OR env.cleaning_generation<>p_generation OR env.key_generation<>p_key OR env.managed_state NOT IN ('active','prepared','cleaned','disabled')
 OR EXISTS(SELECT 1 FROM iam.honeycomb_operations WHERE operation_id=env.lifecycle_operation_id AND NOT completed AND operation_id<>p_operation)
 THEN RAISE EXCEPTION 'environment_revision_conflict' USING ERRCODE='40001'; END IF;
 -- A durable reservation has already verified this immutable request. Its
 -- test-only applications may have been erased before a lost production commit.
 IF env.lifecycle_operation_id=p_operation THEN RETURN iam_private.honeycomb_testing_record(p_service,p_environment); END IF;
 IF cardinality(p_apps) IS NULL OR cardinality(p_apps) NOT BETWEEN 1 AND 100 OR EXISTS(SELECT 1 FROM unnest(p_apps) app GROUP BY app HAVING count(*)>1)
 OR EXISTS(SELECT 1 FROM unnest(p_apps) wanted(app_id) WHERE NOT (wanted.app_id=ANY(p_test_apps) OR EXISTS(SELECT 1 FROM iam.application_testing_environments link JOIN iam.applications app ON app.id=link.source_application_id WHERE link.environment_id=p_environment AND app.app_id=wanted.app_id)))
 THEN RAISE EXCEPTION 'exact_linked_applications_required' USING ERRCODE='22023'; END IF;
 IF env.lifecycle_operation_id IS DISTINCT FROM p_operation THEN
 UPDATE iam.testing_environments SET lifecycle_operation_id=p_operation WHERE id=p_environment;
 END IF;
 RETURN iam_private.honeycomb_testing_record(p_service,p_environment);
END $$;
CREATE FUNCTION iam_private.honeycomb_retention_finish(p_service uuid,p_environment uuid,p_operation uuid,p_apps text[])
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private
AS $$
BEGIN
 IF iam_private.current_principal_id() IS DISTINCT FROM p_service OR NOT EXISTS(SELECT 1 FROM iam.testing_environments WHERE id=p_environment AND honeycomb_service_id=p_service AND lifecycle_operation_id=p_operation) THEN
 RAISE EXCEPTION 'service_required' USING ERRCODE='42501'; END IF;
 UPDATE iam.application_testing_environments link SET retired_at=COALESCE(link.retired_at,transaction_timestamp()),version=link.version+CASE WHEN link.retired_at IS NULL THEN 1 ELSE 0 END
 FROM iam.applications app WHERE app.id=link.source_application_id AND link.environment_id=p_environment AND app.app_id=ANY(p_apps);
 RETURN iam_private.honeycomb_testing_record(p_service,p_environment);
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_adoption_export(uuid,uuid,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.honeycomb_adoption_key(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.honeycomb_retention_start(uuid,uuid,uuid,bigint,bigint,integer,text[],text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.honeycomb_retention_finish(uuid,uuid,uuid,text[]) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_adoption_export(uuid,uuid,bigint),iam_private.honeycomb_adoption_key(uuid,uuid),
 iam_private.honeycomb_retention_start(uuid,uuid,uuid,bigint,bigint,integer,text[],text[]),iam_private.honeycomb_retention_finish(uuid,uuid,uuid,text[]) TO silicon_iam_api;
END IF; END $$;

-- Imports are committed in the isolated plane first. Record their unchanged
-- source/target identities while the matching durable lifecycle operation
-- still holds this environment's production reservation.
CREATE FUNCTION iam_private.honeycomb_testing_link_imports(p_service uuid,p_environment uuid,p_operation uuid,p_mappings jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private
AS $$
DECLARE item jsonb; source uuid; target uuid;
BEGIN
 IF jsonb_typeof(p_mappings)<>'array' OR jsonb_array_length(p_mappings)>1000 THEN RAISE EXCEPTION 'invalid_import_links' USING ERRCODE='22023'; END IF;
 IF NOT EXISTS(SELECT 1 FROM iam.testing_environments env JOIN iam.honeycomb_operations operation ON operation.operation_id=env.lifecycle_operation_id
 WHERE env.id=p_environment AND env.honeycomb_service_id=p_service AND operation.operation_id=p_operation
 AND operation.service_application_id=p_service AND operation.actor_principal_id=iam_private.current_principal_id() AND NOT operation.completed
 AND operation.operation_kind IN ('testing-import','testing-prepare')) THEN RAISE EXCEPTION 'import_operation_required' USING ERRCODE='42501'; END IF;
 FOR item IN SELECT * FROM jsonb_array_elements(p_mappings) LOOP
 source:=(item->>'source_application_id')::uuid;target:=(item->>'target_application_id')::uuid;
 IF source IS NULL OR target IS NULL OR NOT EXISTS(SELECT 1 FROM iam.applications WHERE id=source AND deleted_at IS NULL) THEN RAISE EXCEPTION 'invalid_import_link' USING ERRCODE='22023'; END IF;
 INSERT INTO iam.application_testing_environments(environment_id,source_application_id,target_application_id)
 VALUES(p_environment,source,target)
 ON CONFLICT(environment_id,source_application_id) DO UPDATE SET target_application_id=EXCLUDED.target_application_id,retired_at=NULL,
 last_activity_at=transaction_timestamp(),version=application_testing_environments.version+1;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_link_imports(uuid,uuid,uuid,jsonb) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.honeycomb_testing_link_imports(uuid,uuid,uuid,jsonb) TO silicon_iam_api; END IF; END $$;

-- Seed non-reuse history when an unchanged legacy root is transferred. Only a
-- pending operation that has already authenticated this actor can remember it.
CREATE FUNCTION iam_private.honeycomb_remember_testing_key(p_service uuid,p_environment uuid,p_operation uuid,p_fingerprint bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE env iam.testing_environments%ROWTYPE;
BEGIN
 SELECT * INTO env FROM iam.testing_environments WHERE id=p_environment FOR SHARE;
 IF env.id IS NULL OR env.managed_state='purged' OR (env.honeycomb_service_id IS NOT NULL AND env.honeycomb_service_id<>p_service)
 OR octet_length(p_fingerprint)<>32 OR p_fingerprint IS NULL OR NOT EXISTS(
  SELECT 1 FROM iam.honeycomb_operations operation WHERE operation.operation_id=p_operation AND operation.service_application_id=p_service
   AND operation.actor_principal_id=iam_private.current_principal_id() AND operation.resource_id=p_environment::text AND NOT operation.completed
   AND ((operation.operation_kind IN('testing-prepare','testing-rotate-key') AND env.honeycomb_service_id=p_service AND env.lifecycle_operation_id=p_operation)
    OR (operation.operation_kind='testing-adoption-export' AND iam_private.current_principal_id()=p_service))) THEN
  RAISE EXCEPTION 'testing_key_transfer_required' USING ERRCODE='42501';
 END IF;
 INSERT INTO iam_private.honeycomb_testing_key_history(environment_id,fingerprint) VALUES(p_environment,p_fingerprint) ON CONFLICT DO NOTHING;
 IF EXISTS(SELECT 1 FROM iam_private.honeycomb_testing_key_history WHERE fingerprint=p_fingerprint AND environment_id<>p_environment) THEN
  RAISE EXCEPTION 'testing_key_reuse_forbidden' USING ERRCODE='40001';
 END IF;
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_remember_testing_key(uuid,uuid,uuid,bytea) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_remember_testing_key(uuid,uuid,uuid,bytea) TO silicon_iam_api;
END IF; END $$;
