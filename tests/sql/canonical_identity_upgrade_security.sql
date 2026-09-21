-- Snapshot with the test administrator; 0111 itself runs as the restricted
-- table owner. These rows survive its transaction only in this test session.
CREATE TEMP TABLE upgrade_security_flags AS
SELECT oid,relrowsecurity,relforcerowsecurity FROM pg_class
WHERE relnamespace IN ('iam'::regnamespace,'iam_private'::regnamespace)
 AND relkind IN ('r','p');
CREATE TEMP TABLE upgrade_function_owners AS
SELECT proname,proowner FROM pg_proc WHERE pronamespace='iam_private'::regnamespace;
CREATE TEMP TABLE upgrade_schema_privileges AS
SELECT n.oid,acl.grantor,acl.grantee,acl.privilege_type,acl.is_grantable
FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) acl
WHERE n.nspname IN ('iam','iam_private');
CREATE FUNCTION pg_temp.identity_credential_fingerprint() RETURNS jsonb
LANGUAGE sql STABLE AS $$
 SELECT jsonb_build_object(
  'application_secrets',(SELECT jsonb_agg(jsonb_build_array(id,secret_digest,pepper_key_version,secret_version) ORDER BY id) FROM iam.application_secrets),
  'webhooks',(SELECT jsonb_agg(jsonb_build_array(id,url_ciphertext,url_nonce,encryption_key_version,url_digest) ORDER BY id) FROM iam.application_webhook_endpoints),
  'contacts',(SELECT jsonb_agg(jsonb_build_array(id,ciphertext,nonce,encryption_key_version) ORDER BY id) FROM iam.carbon_contacts),
  'refresh_tokens',(SELECT jsonb_agg(jsonb_build_array(id,token_digest,digest_key_version,consumed_at,expires_at) ORDER BY id) FROM iam.refresh_tokens),
  'access_tokens',(SELECT jsonb_agg(jsonb_build_array(id,token_digest,digest_key_version,expires_at) ORDER BY id) FROM iam.access_tokens)
 )
$$;
CREATE TEMP TABLE upgrade_credential_fingerprint AS
SELECT pg_temp.identity_credential_fingerprint() AS fingerprint;
CREATE TEMP TABLE upgrade_encryption_contexts AS
SELECT app_id,(to_jsonb(app)->>'testing_environment_id')::uuid AS environment,id AS context
FROM iam.applications app;
CREATE FUNCTION pg_temp.assert_identity_migration_security() RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM upgrade_security_flags old LEFT JOIN pg_class current ON current.oid=old.oid
  WHERE current.oid IS NULL OR old.relrowsecurity<>current.relrowsecurity OR old.relforcerowsecurity<>current.relforcerowsecurity) THEN
  RAISE EXCEPTION 'migration changed original table RLS flags';
 END IF;
 IF EXISTS(SELECT 1 FROM upgrade_function_owners old LEFT JOIN pg_proc current
  ON current.pronamespace='iam_private'::regnamespace AND current.proname=old.proname
  WHERE current.oid IS NULL OR old.proowner<>current.proowner) THEN
  RAISE EXCEPTION 'migration changed original security function owners';
 END IF;
 IF EXISTS(
  WITH current AS (
   SELECT n.oid,acl.grantor,acl.grantee,acl.privilege_type,acl.is_grantable
   FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) acl
   WHERE n.nspname IN ('iam','iam_private')
  )
  (SELECT * FROM current EXCEPT SELECT * FROM upgrade_schema_privileges)
  UNION ALL
  (SELECT * FROM upgrade_schema_privileges EXCEPT SELECT * FROM current)
 ) THEN RAISE EXCEPTION 'temporary schema owner-transfer privilege was not restored'; END IF;
 IF (SELECT fingerprint FROM upgrade_credential_fingerprint) IS DISTINCT FROM pg_temp.identity_credential_fingerprint() THEN
  RAISE EXCEPTION 'migration changed encrypted data or existing credential bytes';
 END IF;
 IF EXISTS(
  SELECT 1 FROM upgrade_encryption_contexts old FULL JOIN iam_private.legacy_application_encryption_contexts current
  ON old.app_id=current.application_id AND old.environment IS NOT DISTINCT FROM current.testing_environment_id
  WHERE old.app_id IS NULL OR current.application_id IS NULL OR old.context IS DISTINCT FROM current.context_id
 ) OR EXISTS(
  SELECT 1 FROM upgrade_encryption_contexts old FULL JOIN iam.applications app
  ON old.app_id=app.app_id AND old.environment IS NOT DISTINCT FROM (to_jsonb(app)->>'testing_environment_id')::uuid
  WHERE old.app_id IS NULL OR app.app_id IS NULL OR old.context IS DISTINCT FROM app.encryption_context_id
 ) THEN RAISE EXCEPTION 'legacy application encryption context was omitted or changed'; END IF;
END $$;
