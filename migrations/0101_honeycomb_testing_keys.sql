ALTER TABLE iam.testing_environments DROP CONSTRAINT testing_environments_managed_state_check;
ALTER TABLE iam.testing_environments ADD CONSTRAINT testing_environments_managed_state_check
 CHECK(managed_state IN ('legacy','prepared','active','disabled','cleaning','cleaned','purging','purged','importing','importing-active'));
-- Fingerprints only: plaintext shared root keys remain envelope-encrypted.
-- Retained across clean and purge so retired keys cannot be reinstalled.
CREATE TABLE iam_private.honeycomb_testing_key_history (
 environment_id uuid NOT NULL REFERENCES iam.testing_environments(id),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 PRIMARY KEY(environment_id,fingerprint),
 UNIQUE(fingerprint)
);
REVOKE ALL ON iam_private.honeycomb_testing_key_history FROM PUBLIC;

-- An old root can resume only the operation it authorized before rotation.
-- This private proof stores a keyed digest, never recoverable key material.
CREATE TABLE iam_private.honeycomb_testing_root_operations (
 operation_id uuid PRIMARY KEY,
 service_application_id uuid NOT NULL REFERENCES iam.applications(id),
 environment_id uuid NOT NULL REFERENCES iam.testing_environments(id),
 operation_kind text NOT NULL CHECK(operation_kind IN ('import','rotate-key')),
 generation bigint NOT NULL,
 expected_revision bigint NOT NULL,
 expected_key_version integer NOT NULL,
 key_digest bytea NOT NULL CHECK(octet_length(key_digest)=32)
);
REVOKE ALL ON iam_private.honeycomb_testing_root_operations FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_testing_root_authority(p_service uuid,p_environment uuid,p_operation uuid,p_kind text,p_generation bigint,p_expected bigint,p_key_version integer,p_digests bytea[])
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE env iam.testing_environments%ROWTYPE; proof iam_private.honeycomb_testing_root_operations%ROWTYPE;
BEGIN
 IF p_service IS DISTINCT FROM iam_private.current_principal_id()
  OR iam_private.current_application_id() IS NOT NULL OR p_kind NOT IN ('import','rotate-key')
  OR p_generation IS NULL OR p_expected IS NULL OR p_key_version IS NULL OR COALESCE(cardinality(p_digests),0)=0 THEN RETURN false; END IF;
 IF NOT EXISTS(SELECT 1 FROM iam.applications app JOIN iam.principals principal ON principal.id=app.id AND principal.status='active'
  WHERE app.id=p_service AND app.deleted_at IS NULL) THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('testing-runtime:'||p_environment::text,0));
 SELECT * INTO env FROM iam.testing_environments WHERE id=p_environment FOR UPDATE;
 IF env.id IS NULL OR env.honeycomb_service_id IS DISTINCT FROM p_service
  OR env.managed_state IN ('legacy','disabled','cleaning','purging','purged') THEN RETURN false; END IF;
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

CREATE OR REPLACE FUNCTION iam_private.honeycomb_testing_start(p_environment uuid,p_service uuid,p_actor uuid,p_token uuid,p_operation uuid,p_kind text,p_expected bigint,p_generation bigint,p_input jsonb,p_key jsonb)
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
  IF env.honeycomb_service_id IS DISTINCT FROM p_service THEN
   RAISE EXCEPTION 'environment_service_mismatch' USING ERRCODE='42501'; END IF;
  IF p_kind IN ('import','rotate-key') THEN
   IF current_setting('iam.honeycomb_root_authority',true) IS DISTINCT FROM p_environment::text||':'||p_operation::text
    OR NOT EXISTS(SELECT 1 FROM iam_private.honeycomb_testing_root_operations proof WHERE proof.operation_id=p_operation
     AND proof.environment_id=p_environment AND proof.service_application_id=p_service AND proof.operation_kind=p_kind
     AND proof.generation=p_generation AND proof.expected_revision=p_expected
     AND proof.expected_key_version=(p_input->>'expected_key_version')::integer) THEN
    RAISE EXCEPTION 'testing_root_authority_required' USING ERRCODE='42501'; END IF;
  ELSIF p_kind NOT IN ('clean','disable','restore','purge','activate','activate-apps') THEN
   RAISE EXCEPTION 'scheduled_operation_forbidden' USING ERRCODE='42501'; END IF;
 END IF;
 IF env.id IS NULL AND p_input->>'key_version' IS NOT NULL AND (p_input->>'key_version')::integer<>1 THEN
  RAISE EXCEPTION 'initial_key_version_required' USING ERRCODE='40001'; END IF;
 IF env.id IS NULL AND p_input->>'expected_key_version' IS NOT NULL THEN
  RAISE EXCEPTION 'new_environment_has_no_key_version' USING ERRCODE='40001'; END IF;
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
  IF p_input->>'expected_key_version' IS NOT NULL AND env.key_generation<>(p_input->>'expected_key_version')::integer THEN
   RAISE EXCEPTION 'testing_key_version_conflict' USING ERRCODE='40001'; END IF;
  IF p_kind='rotate-key' AND p_input->>'key_version' IS NOT NULL AND (p_input->>'key_version')::integer<>env.key_generation+1 THEN
   RAISE EXCEPTION 'testing_key_version_conflict' USING ERRCODE='40001'; END IF;
  IF env.version<>p_expected OR env.cleaning_generation<>p_generation THEN RAISE EXCEPTION 'iam_revision_conflict' USING ERRCODE='40001'; END IF;
  IF env.managed_state IN ('cleaning','purging','importing','importing-active','purged') THEN RAISE EXCEPTION 'environment_operation_in_progress' USING ERRCODE='40001'; END IF;
  IF p_kind='prepare' THEN
   IF env.managed_state<>'legacy' THEN RAISE EXCEPTION 'already_prepared' USING ERRCODE='40001'; END IF;
   UPDATE iam.testing_environments SET honeycomb_service_id=p_service,managed_state=CASE WHEN status='active' THEN 'active' ELSE 'disabled' END,lifecycle_operation_id=p_operation WHERE id=p_environment;
  ELSIF p_kind='rotate-key' THEN
   IF p_key->>'previous_fingerprint' IS NULL OR p_key->>'fingerprint' IS NULL THEN
    RAISE EXCEPTION 'testing_key_material_required' USING ERRCODE='22023'; END IF;
   INSERT INTO iam_private.honeycomb_testing_key_history(environment_id,fingerprint)
   VALUES(p_environment,decode(p_key->>'previous_fingerprint','hex')) ON CONFLICT DO NOTHING;
   IF EXISTS(SELECT 1 FROM iam_private.honeycomb_testing_key_history WHERE environment_id=p_environment AND fingerprint=decode(p_key->>'fingerprint','hex')) THEN
    RAISE EXCEPTION 'testing_key_reuse_forbidden' USING ERRCODE='40001'; END IF;
   UPDATE iam.testing_environments SET key_digest=decode(p_key->>'digest','hex'),key_digest_key_version=(p_key->>'digest_version')::smallint,
    key_ciphertext=decode(p_key->>'ciphertext','hex'),key_nonce=decode(p_key->>'nonce','hex'),key_encryption_key_version=(p_key->>'encryption_version')::smallint,
    key_generation=key_generation+1,key_rotated_at=transaction_timestamp(),status='deleted',
    deleted_at=COALESCE(deleted_at,transaction_timestamp()),
    purge_after=CASE WHEN env.managed_state='disabled' THEN env.purge_after ELSE 'infinity'::timestamptz END,
    managed_state=CASE WHEN env.managed_state='disabled' THEN 'disabled' ELSE 'prepared' END,
    lifecycle_operation_id=p_operation WHERE id=p_environment;
  ELSIF p_kind='disable' THEN
   UPDATE iam.testing_environments SET status='deleted',deleted_at=COALESCE(deleted_at,transaction_timestamp()),purge_after='infinity',managed_state='disabled',lifecycle_operation_id=p_operation WHERE id=p_environment;
  ELSIF p_kind='restore' THEN
   IF env.managed_state<>'disabled' THEN RAISE EXCEPTION 'retained_state_required' USING ERRCODE='40001'; END IF;
   UPDATE iam.testing_environments SET managed_state='prepared',lifecycle_operation_id=p_operation WHERE id=p_environment;
  ELSIF p_kind='activate-apps' THEN
   IF env.managed_state<>'active' THEN RAISE EXCEPTION 'active_environment_required' USING ERRCODE='40001'; END IF;
   UPDATE iam.testing_environments SET lifecycle_operation_id=p_operation WHERE id=p_environment;
  ELSIF p_kind='activate' THEN
   IF env.managed_state NOT IN ('prepared','cleaned') THEN RAISE EXCEPTION 'prepared_state_required' USING ERRCODE='40001'; END IF;
   UPDATE iam.testing_environments SET status='active',deleted_at=NULL,purge_after=NULL,managed_state='active',lifecycle_operation_id=p_operation WHERE id=p_environment;
  ELSIF p_kind IN ('clean','purge','import') THEN
   IF p_kind='purge' AND env.status<>'deleted' THEN RAISE EXCEPTION 'disable_before_purge' USING ERRCODE='40001'; END IF;
   IF p_kind='import' AND env.managed_state NOT IN ('prepared','cleaned','active') THEN RAISE EXCEPTION 'prepare_before_import' USING ERRCODE='40001'; END IF;
   UPDATE iam.testing_environments SET
    status=CASE WHEN p_kind='import' AND env.managed_state='active' THEN 'active' ELSE 'deleted' END,
    deleted_at=CASE WHEN p_kind='import' AND env.managed_state='active' THEN NULL ELSE COALESCE(deleted_at,transaction_timestamp()) END,
    purge_after=CASE WHEN p_kind='import' AND env.managed_state='active' THEN NULL ELSE 'infinity'::timestamptz END,
    managed_state=CASE WHEN p_kind='clean' THEN 'cleaning' WHEN p_kind='purge' THEN 'purging' WHEN env.managed_state='active' THEN 'importing-active' ELSE 'importing' END,
    cleaning_generation=cleaning_generation+CASE WHEN p_kind='clean' THEN 1 ELSE 0 END,lifecycle_operation_id=p_operation WHERE id=p_environment;
  ELSE RAISE EXCEPTION 'invalid_lifecycle_operation' USING ERRCODE='22023'; END IF;
 END IF;
 IF p_key->>'fingerprint' IS NOT NULL THEN
  INSERT INTO iam_private.honeycomb_testing_key_history(environment_id,fingerprint)
  VALUES(p_environment,decode(p_key->>'fingerprint','hex')) ON CONFLICT DO NOTHING;
  IF EXISTS(SELECT 1 FROM iam_private.honeycomb_testing_key_history WHERE fingerprint=decode(p_key->>'fingerprint','hex') AND environment_id<>p_environment) THEN
   RAISE EXCEPTION 'testing_key_reuse_forbidden' USING ERRCODE='40001';
  END IF;
 END IF;
 RETURN iam_private.honeycomb_testing_record(p_service,p_environment);
END $$;


CREATE OR REPLACE FUNCTION iam_private.honeycomb_testing_finish(p_service uuid,p_environment uuid,p_operation uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 UPDATE iam.testing_environments SET
 managed_state=CASE managed_state WHEN 'cleaning' THEN 'cleaned' WHEN 'importing' THEN 'prepared' WHEN 'importing-active' THEN 'active' WHEN 'purging' THEN 'purged' ELSE managed_state END,
 cleaned_at=CASE WHEN managed_state='cleaning' THEN transaction_timestamp() ELSE cleaned_at END,
 name=CASE WHEN managed_state='purging' THEN id::text ELSE name END,description=CASE WHEN managed_state='purging' THEN NULL ELSE description END,
 key_digest=CASE WHEN managed_state='purging' THEN NULL ELSE key_digest END,key_ciphertext=CASE WHEN managed_state='purging' THEN NULL ELSE key_ciphertext END,
 key_nonce=CASE WHEN managed_state='purging' THEN NULL ELSE key_nonce END,key_digest_key_version=CASE WHEN managed_state='purging' THEN NULL ELSE key_digest_key_version END,
 key_encryption_key_version=CASE WHEN managed_state='purging' THEN NULL ELSE key_encryption_key_version END
 WHERE id=p_environment AND honeycomb_service_id=p_service AND lifecycle_operation_id=p_operation;
 IF NOT FOUND THEN RAISE EXCEPTION 'environment_operation_mismatch' USING ERRCODE='40001'; END IF;
 RETURN iam_private.honeycomb_testing_record(p_service,p_environment);
END $$;

