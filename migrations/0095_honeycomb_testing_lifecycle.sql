-- IAM-local lifecycle state. Legacy records retain identifiers and credentials.
ALTER TABLE iam.testing_environments
 ADD COLUMN honeycomb_service_id uuid REFERENCES iam.applications(id),
 ADD COLUMN managed_state text NOT NULL DEFAULT 'legacy' CHECK(managed_state IN ('legacy','prepared','active','disabled','cleaning','cleaned','purging','purged','importing')),
 ADD COLUMN cleaning_generation bigint NOT NULL DEFAULT 1 CHECK(cleaning_generation>0),
 ADD COLUMN lifecycle_operation_id uuid,
 ALTER COLUMN key_digest DROP NOT NULL, ALTER COLUMN key_digest_key_version DROP NOT NULL,
 ALTER COLUMN key_ciphertext DROP NOT NULL, ALTER COLUMN key_nonce DROP NOT NULL, ALTER COLUMN key_encryption_key_version DROP NOT NULL,
 ADD CONSTRAINT testing_environment_purged_keys CHECK((managed_state='purged' AND key_digest IS NULL AND key_ciphertext IS NULL AND key_nonce IS NULL AND key_digest_key_version IS NULL AND key_encryption_key_version IS NULL)
 OR (managed_state<>'purged' AND key_digest IS NOT NULL AND key_ciphertext IS NOT NULL AND key_nonce IS NOT NULL AND key_digest_key_version IS NOT NULL AND key_encryption_key_version IS NOT NULL));

CREATE FUNCTION iam_private.honeycomb_testing_record(p_service uuid,p_environment uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 SELECT jsonb_build_object('environment_id',env.id,'org_id',org.org_id,'state',env.managed_state,'iam_revision',env.version,
 'generation',env.cleaning_generation,'key_version',env.key_generation,'last_activity_at',env.last_activity_at,'operation_id',env.lifecycle_operation_id)
 FROM iam.testing_environments env JOIN iam.organizations org ON org.id=env.organization_id
 WHERE env.id=p_environment AND (env.honeycomb_service_id=p_service OR
 (env.honeycomb_service_id IS NULL AND EXISTS(SELECT 1 FROM iam.applications WHERE id=p_service)));
$$;

CREATE FUNCTION iam_private.honeycomb_testing_start(p_environment uuid,p_service uuid,p_actor uuid,p_token uuid,p_operation uuid,p_kind text,p_expected bigint,p_generation bigint,p_input jsonb,p_key jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE env iam.testing_environments%ROWTYPE; org iam.organizations%ROWTYPE; member iam.organization_memberships%ROWTYPE;
BEGIN
 IF iam_private.current_principal_id() IS DISTINCT FROM p_actor THEN RAISE EXCEPTION 'actor_required' USING ERRCODE='42501'; END IF;
 -- Same lock used by runtime request leases; commit the blocked state before erasure.
 PERFORM pg_advisory_xact_lock(hashtextextended('testing-runtime:'||p_environment::text,0));
 SELECT * INTO env FROM iam.testing_environments WHERE id=p_environment FOR UPDATE;
 IF env.id IS NULL THEN
  IF p_kind<>'prepare' OR p_expected<>0 OR p_generation<>1 OR p_actor=p_service THEN RAISE EXCEPTION 'environment_not_found' USING ERRCODE='P0002'; END IF;
  SELECT * INTO org FROM iam.organizations WHERE org_id=p_input->>'org_id' AND status='active' FOR SHARE;
 ELSE
  SELECT * INTO org FROM iam.organizations WHERE id=env.organization_id AND status='active' FOR SHARE;
 END IF;
 IF org.id IS NULL THEN RAISE EXCEPTION 'environment_organization_unavailable' USING ERRCODE='42501'; END IF;
 IF p_actor<>p_service THEN
  SELECT m.* INTO member FROM iam.organization_memberships m JOIN iam.principals principal ON principal.id=m.principal_id AND principal.status='active'
  WHERE m.organization_id=org.id AND m.principal_id=p_actor AND m.principal_kind='carbon' AND m.status='active'
  AND iam_private.application_token_allows_membership(p_token,m.id) FOR SHARE OF m,principal;
  IF member.id IS NULL OR (env.id IS NOT NULL AND member.id<>env.created_by_membership_id AND member.org_role NOT IN ('owner','admin')) THEN
   RAISE EXCEPTION 'environment_manager_required' USING ERRCODE='42501'; END IF;
 ELSE
  IF p_kind NOT IN ('clean','disable','restore','purge','activate') OR env.honeycomb_service_id IS DISTINCT FROM p_service THEN
   RAISE EXCEPTION 'scheduled_operation_forbidden' USING ERRCODE='42501'; END IF;
 END IF;
 IF env.id IS NULL THEN
  INSERT INTO iam.testing_environments(id,organization_id,created_by_membership_id,name,description,honeycomb_service_id,managed_state,lifecycle_operation_id,
   status,deleted_at,purge_after,key_digest,key_digest_key_version,key_ciphertext,key_nonce,key_encryption_key_version)
  VALUES(p_environment,org.id,member.id,p_input->>'name',p_input->>'description',p_service,'prepared',p_operation,
   'deleted',transaction_timestamp(),'infinity',decode(p_key->>'digest','hex'),(p_key->>'digest_version')::smallint,
   decode(p_key->>'ciphertext','hex'),decode(p_key->>'nonce','hex'),(p_key->>'encryption_version')::smallint);
 ELSE
  IF env.honeycomb_service_id IS NOT NULL AND env.honeycomb_service_id<>p_service THEN RAISE EXCEPTION 'environment_service_mismatch' USING ERRCODE='42501'; END IF;
  IF env.lifecycle_operation_id=p_operation THEN RETURN iam_private.honeycomb_testing_record(p_service,p_environment); END IF;
  IF EXISTS(SELECT 1 FROM iam.honeycomb_operations WHERE operation_id=env.lifecycle_operation_id AND NOT completed) THEN RAISE EXCEPTION 'environment_operation_in_progress' USING ERRCODE='40001'; END IF;
  IF env.version<>p_expected OR env.cleaning_generation<>p_generation THEN RAISE EXCEPTION 'iam_revision_conflict' USING ERRCODE='40001'; END IF;
  IF env.managed_state IN ('cleaning','purging','importing','purged') THEN RAISE EXCEPTION 'environment_operation_in_progress' USING ERRCODE='40001'; END IF;
  IF p_kind='prepare' THEN
   IF env.managed_state<>'legacy' THEN RAISE EXCEPTION 'already_prepared' USING ERRCODE='40001'; END IF;
   UPDATE iam.testing_environments SET honeycomb_service_id=p_service,managed_state=CASE WHEN status='active' THEN 'active' ELSE 'disabled' END,lifecycle_operation_id=p_operation WHERE id=p_environment;
  ELSIF p_kind='rotate-key' THEN
   UPDATE iam.testing_environments SET key_digest=decode(p_key->>'digest','hex'),key_digest_key_version=(p_key->>'digest_version')::smallint,
    key_ciphertext=decode(p_key->>'ciphertext','hex'),key_nonce=decode(p_key->>'nonce','hex'),key_encryption_key_version=(p_key->>'encryption_version')::smallint,
    key_generation=key_generation+1,key_rotated_at=transaction_timestamp(),lifecycle_operation_id=p_operation WHERE id=p_environment;
  ELSIF p_kind='disable' THEN
   UPDATE iam.testing_environments SET status='deleted',deleted_at=COALESCE(deleted_at,transaction_timestamp()),purge_after='infinity',managed_state='disabled',lifecycle_operation_id=p_operation WHERE id=p_environment;
  ELSIF p_kind='restore' THEN
   IF env.managed_state<>'disabled' THEN RAISE EXCEPTION 'retained_state_required' USING ERRCODE='40001'; END IF;
   UPDATE iam.testing_environments SET managed_state='prepared',lifecycle_operation_id=p_operation WHERE id=p_environment;
  ELSIF p_kind='activate' THEN
   IF env.managed_state NOT IN ('prepared','cleaned') THEN RAISE EXCEPTION 'prepared_state_required' USING ERRCODE='40001'; END IF;
   UPDATE iam.testing_environments SET status='active',deleted_at=NULL,purge_after=NULL,managed_state='active',lifecycle_operation_id=p_operation WHERE id=p_environment;
  ELSIF p_kind IN ('clean','purge','import') THEN
   IF p_kind='purge' AND env.status<>'deleted' THEN RAISE EXCEPTION 'disable_before_purge' USING ERRCODE='40001'; END IF;
   IF p_kind='import' AND env.managed_state NOT IN ('prepared','cleaned') THEN RAISE EXCEPTION 'prepare_before_import' USING ERRCODE='40001'; END IF;
   UPDATE iam.testing_environments SET status='deleted',deleted_at=COALESCE(deleted_at,transaction_timestamp()),purge_after='infinity',
    managed_state=CASE p_kind WHEN 'clean' THEN 'cleaning' WHEN 'purge' THEN 'purging' ELSE 'importing' END,
    cleaning_generation=cleaning_generation+CASE WHEN p_kind='clean' THEN 1 ELSE 0 END,lifecycle_operation_id=p_operation WHERE id=p_environment;
  ELSE RAISE EXCEPTION 'invalid_lifecycle_operation' USING ERRCODE='22023'; END IF;
 END IF;
 RETURN iam_private.honeycomb_testing_record(p_service,p_environment);
END $$;

CREATE FUNCTION iam_private.honeycomb_testing_finish(p_service uuid,p_environment uuid,p_operation uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 UPDATE iam.testing_environments SET
 managed_state=CASE managed_state WHEN 'cleaning' THEN 'cleaned' WHEN 'importing' THEN 'prepared' WHEN 'purging' THEN 'purged' ELSE managed_state END,
 cleaned_at=CASE WHEN managed_state='cleaning' THEN transaction_timestamp() ELSE cleaned_at END,
 name=CASE WHEN managed_state='purging' THEN id::text ELSE name END,description=CASE WHEN managed_state='purging' THEN NULL ELSE description END,
 key_digest=CASE WHEN managed_state='purging' THEN NULL ELSE key_digest END,key_ciphertext=CASE WHEN managed_state='purging' THEN NULL ELSE key_ciphertext END,
 key_nonce=CASE WHEN managed_state='purging' THEN NULL ELSE key_nonce END,key_digest_key_version=CASE WHEN managed_state='purging' THEN NULL ELSE key_digest_key_version END,
 key_encryption_key_version=CASE WHEN managed_state='purging' THEN NULL ELSE key_encryption_key_version END
 WHERE id=p_environment AND honeycomb_service_id=p_service AND lifecycle_operation_id=p_operation;
 IF NOT FOUND THEN RAISE EXCEPTION 'environment_operation_mismatch' USING ERRCODE='40001'; END IF;
 RETURN iam_private.honeycomb_testing_record(p_service,p_environment);
END $$;

CREATE FUNCTION iam_private.honeycomb_testing_key(p_service uuid,p_environment uuid)
RETURNS TABLE(organization_id uuid,key_digest bytea,key_digest_key_version smallint,key_ciphertext bytea,key_nonce bytea,key_encryption_key_version smallint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 SELECT organization_id,key_digest,key_digest_key_version,key_ciphertext,key_nonce,key_encryption_key_version
 FROM iam.testing_environments WHERE id=p_environment AND honeycomb_service_id=p_service AND managed_state<>'purged';
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_record(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_start(uuid,uuid,uuid,uuid,uuid,text,bigint,bigint,jsonb,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_finish(uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_key(uuid,uuid) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_testing_record(uuid,uuid),iam_private.honeycomb_testing_start(uuid,uuid,uuid,uuid,uuid,text,bigint,bigint,jsonb,jsonb),
 iam_private.honeycomb_testing_finish(uuid,uuid,uuid),iam_private.honeycomb_testing_key(uuid,uuid) TO silicon_iam_api;
END IF; END $$;

CREATE FUNCTION iam_private.honeycomb_testing_actor(p_env uuid,p_actor uuid,p_token uuid,p_org text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT EXISTS(SELECT 1 FROM iam.organization_memberships member JOIN iam.organizations org ON org.id=member.organization_id AND org.status='active'
 JOIN iam.principals actor ON actor.id=member.principal_id AND actor.status='active' AND actor.kind='carbon'
 LEFT JOIN iam.testing_environments env ON env.id=p_env
 WHERE member.principal_id=p_actor AND member.status='active'
 AND org.id=COALESCE(env.organization_id,(SELECT id FROM iam.organizations WHERE org_id=p_org))
 AND (env.id IS NULL OR env.created_by_membership_id=member.id OR member.org_role IN ('owner','admin'))
 AND iam_private.application_token_allows_membership(p_token,member.id));
$$;
CREATE FUNCTION iam_private.honeycomb_testing_organization(p_env uuid,p_org text)
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 SELECT COALESCE((SELECT organization_id FROM iam.testing_environments WHERE id=p_env),(SELECT id FROM iam.organizations WHERE org_id=p_org));
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_actor(uuid,uuid,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_organization(uuid,text) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_testing_actor(uuid,uuid,uuid,text),iam_private.honeycomb_testing_organization(uuid,text) TO silicon_iam_api;
END IF; END $$;

CREATE FUNCTION iam_private.resolve_testing_environment_v2(p_digests bytea[])
RETURNS TABLE(environment_id uuid,organization_id uuid,key_digest_key_version smallint,generation bigint,key_version integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 SELECT env.id,env.organization_id,env.key_digest_key_version,CASE WHEN env.managed_state<>'legacy' THEN env.cleaning_generation END,env.key_generation
 FROM iam.testing_environments env JOIN iam.organizations org ON org.id=env.organization_id AND org.status='active'
 WHERE env.status='active' AND env.key_digest=ANY(p_digests);
$$;
CREATE FUNCTION iam_private.testing_runtime_version(p_env uuid)
RETURNS TABLE(generation bigint,key_version integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 SELECT CASE WHEN env.managed_state<>'legacy' THEN env.cleaning_generation END,env.key_generation
 FROM iam.testing_environments env JOIN iam.organizations org ON org.id=env.organization_id AND org.status='active'
 WHERE env.id=p_env AND env.status='active';
$$;
REVOKE ALL ON FUNCTION iam_private.resolve_testing_environment_v2(bytea[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.testing_runtime_version(uuid) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.resolve_testing_environment_v2(bytea[]),iam_private.testing_runtime_version(uuid) TO silicon_iam_api;
END IF; END $$;

CREATE FUNCTION iam_private.honeycomb_testing_purge_receipts(p_service uuid,p_environment uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM iam.testing_environments WHERE id=p_environment AND honeycomb_service_id=p_service AND managed_state='purging') THEN
 RAISE EXCEPTION 'purging_environment_required' USING ERRCODE='42501'; END IF;
 DELETE FROM iam.application_testing_environments WHERE environment_id=p_environment;
 UPDATE iam.honeycomb_operations SET response_ciphertext=NULL,response_nonce=NULL,response_key_version=NULL,
 response_expires_at=CASE WHEN response_expires_at IS NOT NULL THEN transaction_timestamp() END,
 result=jsonb_build_object('operation_id',operation_id,'state',state,'environment_id',environment_id,'iam_revision',iam_revision,'purged',true)
 WHERE environment_id=p_environment AND service_application_id=p_service;
 UPDATE iam.honeycomb_management_events SET payload=jsonb_build_object('operation_id',operation_id,'environment_id',environment_id,'iam_revision',revision,'purged',true)
 WHERE environment_id=p_environment AND service_application_id=p_service;
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_purge_receipts(uuid,uuid) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_testing_purge_receipts(uuid,uuid) TO silicon_iam_api;
END IF; END $$;

ALTER TABLE iam.outbox_events ADD COLUMN testing_generation bigint NOT NULL DEFAULT 1 CHECK(testing_generation>0);
CREATE FUNCTION iam_private.get_worker_testing_environment_webhook_key_v2(p_environment uuid,p_generation bigint)
RETURNS TABLE(organization_id uuid,key_ciphertext bytea,key_nonce bytea,key_encryption_key_version smallint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 SELECT env.organization_id,env.key_ciphertext,env.key_nonce,env.key_encryption_key_version
 FROM iam.testing_environments env JOIN iam.organizations org ON org.id=env.organization_id AND org.status='active'
 WHERE env.id=p_environment AND env.status='active' AND env.cleaning_generation=p_generation;
$$;
REVOKE ALL ON FUNCTION iam_private.get_worker_testing_environment_webhook_key_v2(uuid,bigint) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_worker') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.get_worker_testing_environment_webhook_key_v2(uuid,bigint) TO silicon_iam_worker;
END IF; END $$;

-- Secret-free inventory supports adopting existing identities without recreating them.
CREATE FUNCTION iam_private.honeycomb_inventory(p_service uuid,p_kind text,p_after uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 WITH records AS (
 SELECT id,app_id AS resource_id,version AS iam_revision FROM iam.applications WHERE p_kind='applications'
 UNION ALL SELECT id,bundle_id,version FROM iam.application_bundles WHERE p_kind='bundles'
 UNION ALL SELECT id,id::text,version FROM iam.testing_environments WHERE p_kind='testing-environments'
 ), page AS (SELECT * FROM records WHERE (p_after IS NULL OR id>p_after)
 AND EXISTS(SELECT 1 FROM iam.applications WHERE id=p_service) ORDER BY id LIMIT 100)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(to_jsonb(page) ORDER BY id),'[]'::jsonb),
 'next_after',CASE WHEN count(*)=100 THEN (SELECT id FROM page ORDER BY id DESC LIMIT 1) END) FROM page;
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_inventory(uuid,text,uuid) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.honeycomb_inventory(uuid,text,uuid) TO silicon_iam_api; END IF; END $$;
