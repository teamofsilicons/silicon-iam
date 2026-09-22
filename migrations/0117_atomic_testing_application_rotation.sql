-- Honeycomb authorizes the selected testing environment in the control plane.
-- Its target transaction has no Carbon principal; the legacy owner-only secret
-- snapshot updater therefore silently did nothing after changing the digest.
-- Keep the encrypted OBO/recovery credential and authentication digest in the
-- same authorized, environment-scoped operation, failing the entire rotation
-- if the import snapshot cannot be replaced.
CREATE OR REPLACE FUNCTION iam_private.honeycomb_rotate_testing_application_secret(
 p_app text,p_expected bigint,p_secret jsonb
)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE app iam.applications%ROWTYPE; next_version bigint;
 ciphertext bytea:=decode(p_secret->>'secret_ciphertext','hex');
 nonce bytea:=decode(p_secret->>'secret_nonce','hex');
 key_version smallint:=(p_secret->>'secret_key_version')::smallint;
BEGIN
 IF to_regprocedure('iam_private.current_testing_environment_id()') IS NULL
  OR NULLIF(current_setting('iam.testing_environment_id',true),'') IS NULL THEN
  RAISE EXCEPTION 'testing_plane_required' USING ERRCODE='42501';
 END IF;
 IF ciphertext IS NULL OR octet_length(ciphertext)<=16
  OR nonce IS NULL OR octet_length(nonce)<>12 OR key_version IS NULL OR key_version<=0 THEN
  RAISE EXCEPTION 'testing_application_secret_snapshot_required' USING ERRCODE='22023';
 END IF;
 SELECT * INTO app FROM iam.applications WHERE app_id=p_app AND deleted_at IS NULL FOR UPDATE;
 IF app.id IS NULL THEN RAISE EXCEPTION 'application_not_found' USING ERRCODE='P0002'; END IF;
 IF app.version<>p_expected THEN
  RAISE EXCEPTION 'testing_application_revision_conflict' USING ERRCODE='40001';
 END IF;
 SELECT COALESCE(max(secret_version),0)+1 INTO next_version
 FROM iam.application_secrets WHERE application_id=app.id;
 UPDATE iam.application_secrets SET status='retired',retired_at=transaction_timestamp(),retires_at=NULL
 WHERE application_id=app.id AND status IN ('active','retiring');
 INSERT INTO iam.application_secrets(id,application_id,secret_version,secret_prefix,secret_digest,pepper_key_version,created_by_carbon_id)
 VALUES((p_secret->>'secret_id')::uuid,app.id,next_version,p_secret->>'secret_prefix',
  decode(p_secret->>'secret_digest','hex'),(p_secret->>'secret_digest_version')::smallint,app.created_by_carbon_id);
 UPDATE iam.testing_application_imports
 SET secret_ciphertext=ciphertext,secret_nonce=nonce,secret_key_version=key_version
 WHERE application_id=app.id;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'testing_application_secret_snapshot_missing' USING ERRCODE='P0002';
 END IF;
 UPDATE iam.access_tokens SET revoked_at=transaction_timestamp(),revocation_reason='test_secret_rotated'
 WHERE client_application_id=app.id AND revoked_at IS NULL;
 UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id=app.id;
 UPDATE iam.applications SET version=version+1 WHERE id=app.id;
 RETURN next_version;
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_rotate_testing_application_secret(text,bigint,jsonb) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_rotate_testing_application_secret(text,bigint,jsonb) TO silicon_iam_api;
END IF; END $$;
