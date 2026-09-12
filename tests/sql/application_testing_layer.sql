-- Run against a disposable migrated database with the testing overlay and runtime grants.
BEGIN; INSERT INTO iam.cryptographic_key_versions(purpose,key_version,status) VALUES('contact_aead',1,'active'),('token_hmac',1,'active');
 SELECT set_config('iam.testing_environment_id','00000000-0000-0000-0000-00000000a001',true);
SELECT iam_private.import_testing_application_configuration('{"application_id": "00000000-0000-0000-0000-00000000b001", "source_application_id": "00000000-0000-0000-0000-000000000011", "app_id": "alpha>test", "org_id": "alpha", "organization_name": "Alpha", "organization_logo": null, "organization_description": null, "app_name": "Test", "app_logo": null, "base_url": "https://example.test", "app_scope": {"iam": ["self.identity.read"], "external": [{"app_id": "beta>test", "endpoint_id": "files.read"}]}, "webhook_scope": ["full"], "testing_idle_days": 30, "obo_endpoints": [{"endpoint_id": "files.read", "path": "/files", "metadata": {}, "critical": true}], "endpoint_id": "00000000-0000-0000-0000-00000000c001", "signing_key_id": "00000000-0000-0000-0000-00000000d001", "webhook_secret_version": 1, "webhook_fingerprint": "whs_abcdefgh", "url_ciphertext": "1111111111111111111111111111111111", "url_nonce": "121212121212121212121212", "url_key_version": 1, "url_digest": "1313131313131313131313131313131313131313131313131313131313131313", "signing_ciphertext": "1414141414141414141414141414141414", "signing_nonce": "151515151515151515151515", "signing_key_version": 1, "secret_id": "00000000-0000-0000-0000-00000000e001", "secret_digest": "1616161616161616161616161616161616161616161616161616161616161616", "secret_digest_version": 1, "secret_prefix": "ask_abcdefgh", "secret_ciphertext": "1717171717171717171717171717171717", "secret_nonce": "181818181818181818181818", "secret_key_version": 1}'::jsonb);
SELECT iam_private.import_testing_application_configuration('{"application_id": "00000000-0000-0000-0000-00000000b002", "source_application_id": "00000000-0000-0000-0000-000000000012", "app_id": "beta>test", "org_id": "beta", "organization_name": "Beta", "organization_logo": null, "organization_description": null, "app_name": "Test", "app_logo": null, "base_url": "https://example.test", "app_scope": {"iam": ["self.identity.read"], "external": [{"app_id": "alpha>test", "endpoint_id": "files.read"}]}, "webhook_scope": ["full"], "testing_idle_days": 30, "obo_endpoints": [{"endpoint_id": "files.read", "path": "/files", "metadata": {}, "critical": true}], "endpoint_id": "00000000-0000-0000-0000-00000000c002", "signing_key_id": "00000000-0000-0000-0000-00000000d002", "webhook_secret_version": 1, "webhook_fingerprint": "whs_abcdefgh", "url_ciphertext": "1111111111111111111111111111111111", "url_nonce": "121212121212121212121212", "url_key_version": 1, "url_digest": "2323232323232323232323232323232323232323232323232323232323232323", "signing_ciphertext": "1414141414141414141414141414141414", "signing_nonce": "151515151515151515151515", "signing_key_version": 1, "secret_id": "00000000-0000-0000-0000-00000000e002", "secret_digest": "2626262626262626262626262626262626262626262626262626262626262626", "secret_digest_version": 1, "secret_prefix": "ask_abcdefgh", "secret_ciphertext": "1717171717171717171717171717171717", "secret_nonce": "181818181818181818181818", "secret_key_version": 1}'::jsonb);

SELECT iam_private.activate_testing_application_scopes(ARRAY['00000000-0000-0000-0000-00000000b001','00000000-0000-0000-0000-00000000b002']::uuid[]);
DO $$ BEGIN
IF (SELECT count(*) FROM iam_private.get_testing_application_secret('alpha>test'))<>1 THEN RAISE EXCEPTION 'missing imported secret'; END IF;
IF (SELECT count(*) FROM iam.application_approved_scopes WHERE scope LIKE 'obo:%')<>2 THEN RAISE EXCEPTION 'cycle scope activation failed'; END IF;
END $$;
UPDATE iam.testing_application_imports SET last_activity_at=now()-interval '45 days';
DO $$ BEGIN
IF (SELECT retired FROM iam_private.retire_idle_testing_application('00000000-0000-0000-0000-00000000b001',60)) THEN RAISE EXCEPTION 'retention override ignored'; END IF;
IF NOT (SELECT retired FROM iam_private.retire_idle_testing_application('00000000-0000-0000-0000-00000000b002',30)) THEN RAISE EXCEPTION 'idle dependency not retired'; END IF;
IF (SELECT status FROM iam.principals WHERE id='00000000-0000-0000-0000-00000000b001')<>'active' THEN RAISE EXCEPTION 'sibling app retired'; END IF;
END $$;
SELECT iam_private.activate_testing_application_scopes(ARRAY['00000000-0000-0000-0000-00000000b002']::uuid[]);
DO $$ BEGIN
IF (SELECT status FROM iam.principals WHERE id='00000000-0000-0000-0000-00000000b002')<>'active' THEN RAISE EXCEPTION 'retired import not reusable'; END IF;
IF (SELECT auth_epoch FROM iam.principals WHERE id='00000000-0000-0000-0000-00000000b002')<>2 THEN RAISE EXCEPTION 'old delegated tokens regained authority'; END IF;
END $$;
SELECT set_config('iam.testing_environment_id','00000000-0000-0000-0000-00000000a002',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
IF EXISTS(SELECT * FROM iam_private.get_testing_application_secret('alpha>test')) THEN RAISE EXCEPTION 'credentials crossed testing environments'; END IF;
END $$;
RESET ROLE;
UPDATE iam.testing_application_imports SET created_at=now()-interval '2 days',last_control_check_at=now()-interval '2 hours';
SELECT set_config('iam.testing_environment_id','',true);
SET LOCAL ROLE silicon_iam_worker;
DO $$ BEGIN
IF (SELECT count(*) FROM iam_private.list_testing_application_orphan_candidates(25))<>1 THEN RAISE EXCEPTION 'orphan candidates missing'; END IF;
IF EXISTS(SELECT * FROM iam_private.list_testing_application_orphan_candidates(25)) THEN RAISE EXCEPTION 'orphan checks failed to rotate'; END IF;
END $$;
RESET ROLE;
ROLLBACK;
