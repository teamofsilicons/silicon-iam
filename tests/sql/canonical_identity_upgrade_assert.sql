-- The runner injects the exact production Rust access-token SQL into the two
-- marked positions, so this exercises runtime queries rather than a copy.
CREATE FUNCTION pg_temp.assert_identity_upgrade(plane integer, testing boolean)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE payload jsonb; rows bigint; actual text; expected_environment uuid;
BEGIN
 expected_environment:=CASE WHEN testing THEN pg_temp.fixture_id(plane,'environment') END;
 PERFORM set_config('iam.testing_environment_id',COALESCE(expected_environment::text,''),true);
 IF (SELECT count(*) FROM pg_proc WHERE pronamespace='iam_private'::regnamespace
  AND proname=ANY(ARRAY['current_principal_id','current_application_id','resolve_honeycomb_application',
   'lock_current_application_client','import_testing_application_configuration',
   'honeycomb_configure_testing_application','honeycomb_publication_accept'])
  AND prorettype='text'::regtype)<>7 THEN
  RAISE EXCEPTION 'identity-returning helper still casts canonical identity to UUID';
 END IF;
 IF EXISTS(SELECT 1 FROM iam.principals WHERE id ~ '^[0-9a-f]{8}-[0-9a-f-]{27}$') THEN
  RAISE EXCEPTION 'legacy UUID principal survived';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM iam.applications app WHERE id='identity-test>app'
  AND (to_jsonb(app)->>'testing_environment_id')::uuid IS NOT DISTINCT FROM expected_environment
  AND encryption_context_id=pg_temp.fixture_id(plane,'app') AND version=1) THEN
  RAISE EXCEPTION 'app identity, encryption context or version changed incorrectly';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM iam.carbons carbon WHERE id='migration-owner' AND version=1
  AND (to_jsonb(carbon)->>'testing_environment_id')::uuid IS NOT DISTINCT FROM expected_environment) OR
 NOT EXISTS(SELECT 1 FROM iam.silicons silicon WHERE id='migration:identity-test' AND version=1
  AND (to_jsonb(silicon)->>'testing_environment_id')::uuid IS NOT DISTINCT FROM expected_environment) THEN
  RAISE EXCEPTION 'identity backfill bumped profile versions';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM iam.organization_memberships WHERE id=pg_temp.fixture_id(plane,'owner') AND job_role='Owner job '||plane)
 OR NOT EXISTS(SELECT 1 FROM iam.organization_memberships WHERE id=pg_temp.fixture_id(plane,'member') AND job_role='Silicon description '||plane AND authz_epoch=1) THEN
  RAISE EXCEPTION 'job description lost prior role or mixed testing environments';
 END IF;
 SELECT event.payload INTO STRICT payload FROM iam.outbox_events event WHERE id=pg_temp.fixture_id(plane,'event');
 IF payload#>>'{actor,id}' <> 'migration:identity-test' OR payload#>>'{actor,principal_id}' <> 'migration:identity-test'
 OR payload->>'application_id'<>'identity-test>app' OR payload->>'resource_id'<>pg_temp.fixture_id(plane,'org')::text
 OR payload->>'encryption_application_id'<>pg_temp.fixture_id(plane,'app')::text THEN
  RAISE EXCEPTION 'historical JSON did not distinguish identities, resources and encryption metadata';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM iam.audit_events WHERE id=pg_temp.fixture_id(plane,'audit')
  AND target_id='migration:identity-test' AND aggregate_id='migration:identity-test' AND actor_principal_id='migration:identity-test') THEN
  RAISE EXCEPTION 'audit history retains private UUID identity';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM iam.audit_events WHERE id=pg_temp.fixture_id(plane,'contact-audit')
  AND target_id=pg_temp.fixture_id(plane,'carbon')::text AND aggregate_id=pg_temp.fixture_id(plane,'carbon')::text)
 OR NOT EXISTS(SELECT 1 FROM iam.outbox_events WHERE id=pg_temp.fixture_id(plane,'contact-event')
  AND aggregate_id=pg_temp.fixture_id(plane,'carbon')::text) THEN
  RAISE EXCEPTION 'resource UUID collision was incorrectly mapped to an identity';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM iam.refresh_tokens token JOIN iam.refresh_token_families family ON family.id=token.family_id
  WHERE token.id=pg_temp.fixture_id(plane,'refresh') AND family.subject_principal_id='migration:identity-test'
  AND family.client_application_id='identity-test>app' AND family.status='active' AND token.consumed_at IS NULL
  AND token.token_digest=decode(repeat(lpad(to_hex(plane+10),2,'0'),32),'hex')) THEN
  RAISE EXCEPTION 'refresh credential or family changed during backfill';
 END IF;
 IF testing AND plane=3 THEN
  BEGIN
   INSERT INTO iam.carbon_contacts(id,carbon_id,kind,ciphertext,nonce,encryption_key_version,verified_at)
   VALUES(pg_temp.fixture_id(plane,'bad-contact'),'exclusive-owner','email',decode(repeat('01',17),'hex'),decode(repeat('01',12),'hex'),1,now());
   RAISE EXCEPTION 'cross-environment identity FK was accepted';
  EXCEPTION WHEN foreign_key_violation THEN NULL;
  END;
  BEGIN
   INSERT INTO iam.refresh_token_families(id,authentication_session_id,subject_principal_id,absolute_expires_at)
   VALUES(pg_temp.fixture_id(plane,'bad-family'),pg_temp.fixture_id(2,'session'),'migration:identity-test',now()+interval '1 day');
   RAISE EXCEPTION 'cross-environment session FK was accepted';
  EXCEPTION WHEN foreign_key_violation THEN NULL;
  END;
 END IF;
 PERFORM set_config('iam.principal_id','',true);
 SET LOCAL ROLE silicon_iam_api;
 SELECT count(*) INTO rows FROM (/* ACCESS_CANDIDATE_QUERY */) candidate;
 IF rows<>1 THEN RAISE EXCEPTION 'pre-cutover opaque access-token digest no longer resolves'; END IF;
 PERFORM set_config('iam.principal_id','migration:identity-test',true);
 PERFORM set_config('iam.application_id','identity-test>app',true);
 PERFORM set_config('iam.organization_id',pg_temp.fixture_id(plane,'org')::text,true);
 SELECT count(*) INTO rows FROM (/* AUTHENTICATE_QUERY */) authenticated;
 IF rows<>1 THEN RAISE EXCEPTION 'pre-cutover application access-token runtime query failed'; END IF;
 SELECT principal_id INTO actual FROM iam_private.resolve_active_carbon_by_handle('migration-owner');
 IF actual<>'migration-owner' THEN RAISE EXCEPTION 'canonical carbon handle lookup failed'; END IF;
 IF iam_private.lock_silicon_self_profile(pg_temp.fixture_id(plane,'org'),'migration:identity-test')<>pg_temp.fixture_id(plane,'member') THEN
  RAISE EXCEPTION 'self-profile locked a different environment';
 END IF;
 IF NOT iam_private.update_silicon_self_profile(pg_temp.fixture_id(plane,'org'),'migration:identity-test',1,NULL,'Asia/Kolkata',false,NULL,false,NULL) THEN
  RAISE EXCEPTION 'existing Silicon cannot update timezone after cutover';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM iam.silicons WHERE id='migration:identity-test' AND timezone_id='Asia/Kolkata' AND version=2)
 OR (SELECT count(*) FROM iam.silicons WHERE id='migration:identity-test')<>1 THEN
  RAISE EXCEPTION 'self timezone did not remain in selected environment';
 END IF;
 IF testing THEN
  SELECT count(*) INTO rows FROM iam.access_tokens WHERE id=pg_temp.fixture_id(CASE WHEN plane=2 THEN 3 ELSE 2 END,'access');
  IF rows<>0 THEN RAISE EXCEPTION 'API reads another environment token'; END IF;
  IF (SELECT count(*) FROM iam.carbons WHERE id='migration-owner')<>1 THEN
   RAISE EXCEPTION 'canonical Carbon collision escaped row security';
  END IF;
 END IF;
 RESET ROLE;
 UPDATE iam.authentication_sessions SET status='revoked',revoked_at=now(),revocation_reason='Regression test'
 WHERE id=pg_temp.fixture_id(plane,'session');
 SET LOCAL ROLE silicon_iam_api;
 SELECT count(*) INTO rows FROM (/* AUTHENTICATE_QUERY */) authenticated;
 IF rows<>0 THEN RAISE EXCEPTION 'revoked parent session still authenticates'; END IF;
 RESET ROLE;
END $$;

CREATE FUNCTION pg_temp.assert_unscoped_metadata(expected integer,testing boolean)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 IF (SELECT count(*) FROM iam_private.application_encryption_contexts())<>expected THEN
  RAISE EXCEPTION 'startup cannot read complete encryption metadata without environment selection';
 END IF;
 IF has_table_privilege(current_user,'iam_private.legacy_application_encryption_contexts','SELECT') THEN
  RAISE EXCEPTION 'runtime API can read encryption snapshot directly';
 END IF;
 IF testing AND EXISTS(SELECT 1 FROM iam.principals) THEN
  RAISE EXCEPTION 'unscoped API can read testing identities';
 END IF;
 IF testing AND EXISTS(SELECT 1 FROM iam_private.resolve_active_carbon_by_handle('migration-owner')) THEN
  RAISE EXCEPTION 'unscoped definer helper can read testing identities';
 END IF;
END $$;
