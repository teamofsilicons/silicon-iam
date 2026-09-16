-- Production credentials prove an app identity; sharing a root key never grants
-- environment ownership or another application's test credential.
CREATE FUNCTION iam_private.honeycomb_testing_application_authority(p_service uuid,p_app uuid,p_env uuid,p_org text,p_kind text,p_import text,p_key_digests bytea[],p_operation uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE app iam.applications%ROWTYPE; env iam.testing_environments%ROWTYPE; organization_handle text;
BEGIN
 IF p_app IS DISTINCT FROM iam_private.current_principal_id() OR p_app IS DISTINCT FROM iam_private.current_application_id() THEN RETURN false; END IF;
 SELECT a.* INTO app FROM iam.applications a JOIN iam.principals principal ON principal.id=a.id AND principal.status='active'
 JOIN iam.organizations org ON org.id=a.organization_id AND org.status='active'
 WHERE a.id=p_app AND a.review_status='verified' AND a.deleted_at IS NULL FOR SHARE OF a,principal,org;
 IF app.id IS NULL OR NOT EXISTS(SELECT 1 FROM iam.applications WHERE id=p_service AND deleted_at IS NULL) THEN RETURN false; END IF;
 SELECT org_id INTO organization_handle FROM iam.organizations WHERE id=app.organization_id;
 SELECT * INTO env FROM iam.testing_environments WHERE id=p_env FOR UPDATE;
 IF env.id IS NULL THEN RETURN p_kind='prepare' AND p_org=organization_handle; END IF;
 IF (env.honeycomb_service_id IS NOT NULL AND env.honeycomb_service_id<>p_service) OR env.managed_state='purged' THEN RETURN false; END IF;
 IF p_kind IN ('import','refresh-import') AND p_import IS DISTINCT FROM app.app_id THEN RETURN false; END IF;
 IF cardinality(p_key_digests)>0 AND NOT env.key_digest=ANY(p_key_digests) THEN RETURN false; END IF;
 IF env.created_by_application_id=app.id THEN RETURN true; END IF;
 RETURN p_kind='import' AND (env.managed_state IN ('active','prepared','cleaned') OR (env.managed_state IN ('importing','importing-active') AND env.lifecycle_operation_id=p_operation)) AND env.key_digest=ANY(p_key_digests);
END $$;

CREATE FUNCTION iam_private.honeycomb_testing_application_import_allowed(p_app uuid,p_org text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT p_app=iam_private.current_application_id() AND p_app=iam_private.current_principal_id() AND EXISTS(
 SELECT 1 FROM iam.applications app JOIN iam.principals principal ON principal.id=app.id AND principal.status='active'
 JOIN iam.organizations org ON org.id=app.organization_id AND org.status='active'
 WHERE app.id=p_app AND app.review_status='verified' AND app.deleted_at IS NULL AND org.org_id=p_org);
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_application_authority(uuid,uuid,uuid,text,text,text,bytea[],uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_application_import_allowed(uuid,text) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_testing_application_authority(uuid,uuid,uuid,text,text,text,bytea[],uuid),iam_private.honeycomb_testing_application_import_allowed(uuid,text) TO silicon_iam_api;
END IF; END $$;

CREATE OR REPLACE FUNCTION iam_private.honeycomb_testing_start(p_environment uuid,p_service uuid,p_actor uuid,p_token uuid,p_operation uuid,p_kind text,p_expected bigint,p_generation bigint,p_input jsonb,p_key jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE env iam.testing_environments%ROWTYPE; org iam.organizations%ROWTYPE; member iam.organization_memberships%ROWTYPE; application_owner uuid;
BEGIN
 IF iam_private.current_principal_id() IS DISTINCT FROM p_actor THEN RAISE EXCEPTION 'actor_required' USING ERRCODE='42501'; END IF;
 -- Same lock used by runtime request leases; commit the blocked state before erasure.
 PERFORM pg_advisory_xact_lock(hashtextextended('testing-runtime:'||p_environment::text,0));
 SELECT * INTO env FROM iam.testing_environments WHERE id=p_environment FOR UPDATE;
 IF env.id IS NULL THEN
  IF p_kind<>'prepare' OR p_expected<>0 OR p_generation<>1 OR (p_actor=p_service AND iam_private.current_application_id() IS DISTINCT FROM p_actor) THEN RAISE EXCEPTION 'environment_not_found' USING ERRCODE='P0002'; END IF;
  SELECT * INTO org FROM iam.organizations WHERE org_id=p_input->>'org_id' AND status='active' FOR SHARE;
 ELSE
  SELECT * INTO org FROM iam.organizations WHERE id=env.organization_id AND status='active' FOR SHARE;
 END IF;
 IF org.id IS NULL THEN RAISE EXCEPTION 'environment_organization_unavailable' USING ERRCODE='42501'; END IF;
 IF p_actor=iam_private.current_application_id() THEN
  IF NOT EXISTS(SELECT 1 FROM iam.applications app JOIN iam.principals principal ON principal.id=app.id AND principal.status='active'
   WHERE app.id=p_actor AND (app.organization_id=org.id OR (p_kind='import' AND env.id IS NOT NULL)) AND app.deleted_at IS NULL AND app.review_status='verified') THEN
   RAISE EXCEPTION 'production_application_required' USING ERRCODE='42501'; END IF;
  IF env.id IS NOT NULL AND env.created_by_application_id IS DISTINCT FROM p_actor AND p_kind<>'import' THEN
   RAISE EXCEPTION 'application_environment_owner_required' USING ERRCODE='42501'; END IF;
  IF p_kind='import' AND NOT EXISTS(SELECT 1 FROM iam.applications WHERE id=p_actor AND app_id=p_input->>'app_id') THEN
   RAISE EXCEPTION 'application_import_identity_required' USING ERRCODE='42501'; END IF;
  application_owner:=p_actor;
  -- This is an existing real organization owner for immutable attribution only;
  -- all control authority remains the credentialed application identity.
  SELECT m.* INTO member FROM iam.organization_memberships m WHERE m.organization_id=org.id AND m.org_role='owner' AND m.status='active';
  IF member.id IS NULL THEN RAISE EXCEPTION 'organization_owner_unavailable' USING ERRCODE='42501'; END IF;
 ELSIF p_actor<>p_service THEN
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
  INSERT INTO iam.testing_environments(id,organization_id,created_by_membership_id,created_by_application_id,name,description,honeycomb_service_id,managed_state,lifecycle_operation_id,
   status,deleted_at,purge_after,key_digest,key_digest_key_version,key_ciphertext,key_nonce,key_encryption_key_version)
  VALUES(p_environment,org.id,member.id,application_owner,p_input->>'name',p_input->>'description',p_service,'prepared',p_operation,
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


CREATE FUNCTION iam_private.honeycomb_configure_testing_application(p jsonb)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE v_environment_id uuid := NULLIF(current_setting('iam.testing_environment_id', true), '')::uuid;
    v_owner_id uuid; v_org_id uuid; v_app_id uuid := (p->>'application_id')::uuid;
    v_endpoint_id uuid := (p->>'endpoint_id')::uuid; item jsonb;
BEGIN
    IF v_environment_id IS NULL OR to_regprocedure('iam_private.current_testing_environment_id()') IS NULL THEN RAISE EXCEPTION 'testing_environment_required' USING ERRCODE = '42501'; END IF;
    IF EXISTS(SELECT 1 FROM iam.applications existing WHERE existing.id=v_app_id AND
       existing.app_id<>p->>'app_id') THEN
       RAISE EXCEPTION 'import_identity_mismatch' USING ERRCODE='42501'; END IF;
    PERFORM id FROM iam.applications WHERE app_id=p->>'app_id' FOR UPDATE;
    IF COALESCE((SELECT version FROM iam.applications WHERE app_id=p->>'app_id'),0)<>(p->>'expected_iam_revision')::bigint
     OR COALESCE((SELECT honeycomb_configuration_revision FROM iam.applications WHERE app_id=p->>'app_id'),0)>=(p->>'configuration_revision')::bigint THEN
     RAISE EXCEPTION 'testing_application_revision_conflict' USING ERRCODE='40001'; END IF;
    -- An uncredentialed, suspended fixture is audit attribution, never a
    -- production identity or a login-capable organization administrator.
    v_owner_id := iam_private.current_principal_id();
    IF v_owner_id IS NULL OR NOT EXISTS (SELECT 1 FROM iam.carbons c JOIN iam.principals identity ON identity.id=c.id
        WHERE c.id=v_owner_id AND identity.status='active') THEN v_owner_id := v_environment_id; END IF;
    IF NOT EXISTS (SELECT 1 FROM iam.carbons WHERE id = v_owner_id) THEN
        INSERT INTO iam.principals(id,kind,status,suspended_at) VALUES(v_owner_id,'carbon','suspended',clock_timestamp());
        INSERT INTO iam.carbons(id,carbon_id,display_name)
        VALUES(v_owner_id, 'test_' || translate(left(replace(v_environment_id::text,'-',''),24),'0','g'), 'Testing environment fixture');
    END IF;
    SELECT organization.id INTO v_org_id FROM iam.organizations organization
    WHERE organization.org_id = p->>'org_id' AND organization.status = 'active';
    IF v_org_id IS NOT NULL AND v_owner_id <> v_environment_id
       AND NOT iam_private.is_active_organization_owner_or_admin(v_org_id,v_owner_id) THEN
        RAISE EXCEPTION 'testing_import_organization_not_managed' USING ERRCODE='42501';
    END IF;
    IF v_org_id IS NULL THEN
        v_org_id := gen_random_uuid();
        INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name,logo_uri,description)
        VALUES(v_org_id,p->>'org_id',v_owner_id,p->>'organization_name',p->>'organization_logo',p->>'organization_description');
        INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role)
        VALUES(gen_random_uuid(),v_org_id,v_owner_id,'carbon','owner');
        INSERT INTO iam.carbon_membership_settings(organization_id,membership_id,carbon_id)
        SELECT v_org_id,membership.id,v_owner_id FROM iam.organization_memberships membership
        WHERE membership.organization_id = v_org_id AND membership.principal_id = v_owner_id;
    END IF;
    INSERT INTO iam.principals(id,kind,status,activated_at) VALUES(v_app_id,'application','active',transaction_timestamp()) ON CONFLICT(id) DO NOTHING;
    UPDATE iam.application_approved_scopes approved SET revoked_at=transaction_timestamp(),revoked_by_carbon_id=v_owner_id WHERE approved.application_id=v_app_id AND approved.revoked_at IS NULL;
    UPDATE iam.access_tokens token SET revoked_at=transaction_timestamp(),revocation_reason='test_configuration_refreshed' WHERE token.client_application_id=v_app_id AND token.revoked_at IS NULL;
    IF (p->>'replace_secret')::boolean THEN
    UPDATE iam.application_secrets secret SET status='retired',retired_at=transaction_timestamp(),retires_at=NULL WHERE secret.application_id=v_app_id AND secret.status IN ('active','retiring');
    END IF;
    UPDATE iam.application_webhook_signing_keys secret SET status='retired',retired_at=transaction_timestamp(),retires_at=NULL WHERE secret.application_id=v_app_id AND secret.status IN ('active','retiring');
    UPDATE iam.application_webhook_endpoints endpoint SET status='retired',retired_at=transaction_timestamp() WHERE endpoint.application_id=v_app_id AND endpoint.status IN ('active','pending_review');
    UPDATE iam.application_obo_endpoints endpoint SET status='retired',retired_at=transaction_timestamp() WHERE endpoint.application_id=v_app_id AND endpoint.status='active';
    INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,app_name,app_logo_uri,base_url,
        review_status,test_imported_from_production,app_scope,webhook_scope,testing_idle_days,visibility)
    VALUES(v_app_id,p->>'app_id',v_org_id,v_owner_id,p->>'app_name',p->>'app_logo',p->>'base_url','verified',true,
        p->'app_scope',ARRAY(SELECT jsonb_array_elements_text(p->'webhook_scope')),(p->>'testing_idle_days')::integer,COALESCE(p->>'visibility','public')) ON CONFLICT(id) DO UPDATE SET app_name=EXCLUDED.app_name,app_logo_uri=EXCLUDED.app_logo_uri,
        base_url=EXCLUDED.base_url,review_status='verified',app_scope=EXCLUDED.app_scope,webhook_scope=EXCLUDED.webhook_scope,
        testing_idle_days=EXCLUDED.testing_idle_days,visibility=EXCLUDED.visibility;
    FOR item IN SELECT * FROM jsonb_array_elements(p->'obo_endpoints') LOOP
        INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical,ttl_seconds)
        VALUES(v_org_id,v_app_id,item->>'endpoint_id',item->>'path',item->'metadata',(item->>'critical')::boolean,COALESCE((item->>'ttl_seconds')::integer,300)) ON CONFLICT ON CONSTRAINT application_obo_endpoints_pkey DO UPDATE
        SET metadata_definition=EXCLUDED.metadata_definition,critical=EXCLUDED.critical,ttl_seconds=EXCLUDED.ttl_seconds,status='active',retired_at=NULL
        WHERE application_obo_endpoints.path=EXCLUDED.path;
        IF NOT FOUND THEN RAISE EXCEPTION 'obo_endpoint_path_immutable' USING ERRCODE='23514'; END IF;
    END LOOP;
    IF (p->>'replace_secret')::boolean THEN
    INSERT INTO iam.application_secrets(id,application_id,secret_version,secret_prefix,secret_digest,pepper_key_version,created_by_carbon_id)
    VALUES((p->>'secret_id')::uuid,v_app_id,(SELECT COALESCE(max(secret_version),0)+1 FROM iam.application_secrets secret WHERE secret.application_id=v_app_id),p->>'secret_prefix',decode(p->>'secret_digest','hex'),(p->>'secret_digest_version')::smallint,v_owner_id);
    END IF;
    INSERT INTO iam.application_webhook_endpoints(id,application_id,url_ciphertext,url_nonce,encryption_key_version,url_digest,status,activated_at)
    VALUES(v_endpoint_id,v_app_id,decode(p->>'url_ciphertext','hex'),decode(p->>'url_nonce','hex'),(p->>'url_key_version')::smallint,
        decode(p->>'url_digest','hex'),'active',transaction_timestamp()) ON CONFLICT(id) DO UPDATE
        SET url_ciphertext=EXCLUDED.url_ciphertext,url_nonce=EXCLUDED.url_nonce,encryption_key_version=EXCLUDED.encryption_key_version,status='active',retired_at=NULL,activated_at=transaction_timestamp();
    INSERT INTO iam.application_webhook_signing_keys(id,application_id,endpoint_id,secret_version,key_prefix,secret_ciphertext,secret_nonce,encryption_key_version,test_inherited_from_production)
    VALUES((p->>'signing_key_id')::uuid,v_app_id,v_endpoint_id,(SELECT greatest(COALESCE(max(secret_version),0)+1,(p->>'webhook_secret_version')::bigint) FROM iam.application_webhook_signing_keys secret WHERE secret.application_id=v_app_id),p->>'webhook_fingerprint',
        decode(p->>'signing_ciphertext','hex'),decode(p->>'signing_nonce','hex'),(p->>'signing_key_version')::smallint,(p->>'webhook_inherited')::boolean);
    IF (p->>'replace_secret')::boolean THEN
    INSERT INTO iam.testing_application_imports(application_id,source_application_id,secret_ciphertext,secret_nonce,secret_key_version,source_revision)
    VALUES(v_app_id,(p->>'source_application_id')::uuid,decode(p->>'secret_ciphertext','hex'),decode(p->>'secret_nonce','hex'),(p->>'secret_key_version')::smallint,COALESCE((p->>'source_revision')::bigint,0))
    ON CONFLICT(application_id) DO UPDATE SET secret_ciphertext=EXCLUDED.secret_ciphertext,secret_nonce=EXCLUDED.secret_nonce,secret_key_version=EXCLUDED.secret_key_version,source_revision=EXCLUDED.source_revision;
    END IF;
    UPDATE iam.applications SET honeycomb_configuration_revision=(p->>'configuration_revision')::bigint,
     review_status=CASE WHEN p->>'availability'='disabled' THEN 'suspended' ELSE 'verified' END,
     test_imported_from_production=CASE WHEN (p->>'local_registration')::boolean THEN false ELSE test_imported_from_production END,
     version=version+1 WHERE id=v_app_id;
    IF (p->>'local_registration')::boolean THEN
     UPDATE iam.testing_application_imports SET source_application_id=v_app_id WHERE application_id=v_app_id;
     UPDATE iam.application_webhook_signing_keys SET test_inherited_from_production=false WHERE application_id=v_app_id;
    END IF;
    RETURN v_app_id;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.honeycomb_configure_testing_application(jsonb) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.honeycomb_configure_testing_application(jsonb) TO silicon_iam_api; END IF; END $$;

-- This read is available only in an explicit isolated plane; it never relies
-- on a production service UUID existing as a test application.
CREATE FUNCTION iam_private.honeycomb_testing_application_record(p_app text)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 IF to_regprocedure('iam_private.current_testing_environment_id()') IS NULL OR NULLIF(current_setting('iam.testing_environment_id',true),'') IS NULL THEN RAISE EXCEPTION 'testing_plane_required' USING ERRCODE='42501'; END IF;
 RETURN (SELECT iam_private.honeycomb_application_record(app.id,app.app_id) FROM iam.applications app WHERE app.app_id=p_app AND app.deleted_at IS NULL);
END $$;

CREATE FUNCTION iam_private.honeycomb_testing_application_webhook(p_app text)
RETURNS TABLE(application_id uuid,endpoint_id uuid,signing_key_id uuid,url_ciphertext bytea,url_nonce bytea,url_key_version smallint,secret_ciphertext bytea,secret_nonce bytea,secret_key_version smallint,inherited boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 IF to_regprocedure('iam_private.current_testing_environment_id()') IS NULL OR NULLIF(current_setting('iam.testing_environment_id',true),'') IS NULL THEN RAISE EXCEPTION 'testing_plane_required' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT app.id,endpoint.id,secret.id,endpoint.url_ciphertext,endpoint.url_nonce,endpoint.encryption_key_version,secret.secret_ciphertext,secret.secret_nonce,secret.encryption_key_version,secret.test_inherited_from_production
 FROM iam.applications app JOIN iam.application_webhook_endpoints endpoint ON endpoint.application_id=app.id AND endpoint.status='active'
 JOIN iam.application_webhook_signing_keys secret ON secret.application_id=app.id AND secret.endpoint_id=endpoint.id AND secret.status='active'
 WHERE app.app_id=p_app AND app.deleted_at IS NULL;
END $$;

CREATE FUNCTION iam_private.honeycomb_rotate_testing_application_secret(p_app text,p_expected bigint,p_secret jsonb)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE app iam.applications%ROWTYPE; next_version bigint;
BEGIN
 IF to_regprocedure('iam_private.current_testing_environment_id()') IS NULL OR NULLIF(current_setting('iam.testing_environment_id',true),'') IS NULL THEN RAISE EXCEPTION 'testing_plane_required' USING ERRCODE='42501'; END IF;
 SELECT * INTO app FROM iam.applications WHERE app_id=p_app AND deleted_at IS NULL FOR UPDATE;
 IF app.id IS NULL THEN RAISE EXCEPTION 'application_not_found' USING ERRCODE='P0002'; END IF;
 IF app.version<>p_expected THEN RAISE EXCEPTION 'testing_application_revision_conflict' USING ERRCODE='40001'; END IF;
 SELECT COALESCE(max(secret_version),0)+1 INTO next_version FROM iam.application_secrets WHERE application_id=app.id;
 UPDATE iam.application_secrets SET status='retired',retired_at=transaction_timestamp(),retires_at=NULL WHERE application_id=app.id AND status IN ('active','retiring');
 INSERT INTO iam.application_secrets(id,application_id,secret_version,secret_prefix,secret_digest,pepper_key_version,created_by_carbon_id)
 VALUES((p_secret->>'secret_id')::uuid,app.id,next_version,p_secret->>'secret_prefix',decode(p_secret->>'secret_digest','hex'),(p_secret->>'secret_digest_version')::smallint,app.created_by_carbon_id);
 UPDATE iam.access_tokens SET revoked_at=transaction_timestamp(),revocation_reason='test_secret_rotated' WHERE client_application_id=app.id AND revoked_at IS NULL;
 UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id=app.id;
 UPDATE iam.applications SET version=version+1 WHERE id=app.id;
 RETURN next_version;
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_application_record(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_application_webhook(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.honeycomb_rotate_testing_application_secret(text,bigint,jsonb) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_testing_application_record(text),iam_private.honeycomb_testing_application_webhook(text),iam_private.honeycomb_rotate_testing_application_secret(text,bigint,jsonb) TO silicon_iam_api;
END IF; END $$;

CREATE FUNCTION iam_private.honeycomb_testing_app_control_ready(p_service uuid,p_env uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 SELECT EXISTS(SELECT 1 FROM iam.testing_environments env JOIN iam.organizations org ON org.id=env.organization_id AND org.status='active' WHERE env.id=p_env AND env.honeycomb_service_id=p_service
 AND env.managed_state IN ('active','prepared','cleaned') AND NOT EXISTS(SELECT 1 FROM iam.honeycomb_operations operation WHERE operation.operation_id=env.lifecycle_operation_id AND NOT operation.completed));
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_app_control_ready(uuid,uuid) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.honeycomb_testing_app_control_ready(uuid,uuid) TO silicon_iam_api; END IF; END $$;

CREATE OR REPLACE FUNCTION iam_private.list_application_testing_environments(p_cursor uuid, p_limit integer, p_status text)
RETURNS TABLE(environment_id uuid, org_id text, name text, description text,
    last_activity_at timestamptz, retention_days integer, status text,
    purge_after timestamptz, version bigint, can_manage boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT env.id, org.org_id, env.name, env.description,
        COALESCE(link.last_activity_at, env.last_activity_at), app.testing_idle_days,
        env.status, env.purge_after, env.version, COALESCE(env.created_by_application_id = app.id, false)
    FROM iam.applications app
    JOIN iam.principals principal ON principal.id = app.id AND principal.status = 'active'
    JOIN iam.testing_environments env ON true
    JOIN iam.organizations org ON org.id = env.organization_id AND org.status = 'active'
    LEFT JOIN iam.application_testing_environments link
        ON link.environment_id = env.id AND link.source_application_id = app.id
    WHERE app.id = iam_private.current_application_id() AND app.id = iam_private.current_principal_id()
      AND app.deleted_at IS NULL AND app.review_status = 'verified'
      AND (env.created_by_application_id = app.id OR (link.environment_id IS NOT NULL AND link.retired_at IS NULL))
      AND (p_status IS NULL OR env.status = p_status) AND (p_cursor IS NULL OR env.id > p_cursor)
    ORDER BY env.id LIMIT LEAST(GREATEST(p_limit, 1), 101);
$$;

-- Immutable source identity prevents a deleted/recreated production handle from
-- inheriting credentials belonging to its predecessor inside a shared test.
CREATE FUNCTION iam_private.honeycomb_testing_application_source(p_app text)
RETURNS TABLE(application_id uuid,source_application_id uuid,imported boolean,retired boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 IF to_regprocedure('iam_private.current_testing_environment_id()') IS NULL OR NULLIF(current_setting('iam.testing_environment_id',true),'') IS NULL THEN RAISE EXCEPTION 'testing_plane_required' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT app.id,source.source_application_id,app.test_imported_from_production,source.retired_at IS NOT NULL OR app.deleted_at IS NOT NULL
 FROM iam.applications app JOIN iam.testing_application_imports source ON source.application_id=app.id WHERE app.app_id=p_app;
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_testing_application_source(text) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.honeycomb_testing_application_source(text) TO silicon_iam_api; END IF; END $$;
