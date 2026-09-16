BEGIN;
INSERT INTO iam.cryptographic_key_versions(purpose,key_version,status) VALUES('contact_aead',1,'active'),('token_hmac',1,'active') ON CONFLICT DO NOTHING;
INSERT INTO iam.testing_environments(id,organization_id,created_by_membership_id,name,key_digest,key_digest_key_version,key_ciphertext,key_nonce,key_encryption_key_version)
VALUES('00000000-0000-0000-0000-00000000a001','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000031','Legacy',decode(repeat('01',32),'hex'),1,decode(repeat('02',32),'hex'),decode(repeat('03',12),'hex'),1);
INSERT INTO iam.application_testing_environments(environment_id,source_application_id,target_application_id) VALUES('00000000-0000-0000-0000-00000000a001','00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-00000000b001');
SELECT set_config('iam.principal_id','00000000-0000-0000-0000-000000000011',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE exported jsonb; BEGIN
exported:=iam_private.honeycomb_adoption_export('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-00000000a001',1);
IF exported->>'state'<>'legacy' OR exported->>'created_by_membership_id'<>'00000000-0000-0000-0000-000000000031' OR exported#>>'{applications,0,target_application_id}'<>'00000000-0000-0000-0000-00000000b001' THEN RAISE EXCEPTION 'adoption identity changed'; END IF;
IF (SELECT key_ciphertext FROM iam_private.honeycomb_adoption_key('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-00000000a001'))<>decode(repeat('02',32),'hex') THEN RAISE EXCEPTION 'adoption credential changed'; END IF;
BEGIN PERFORM iam_private.honeycomb_adoption_export('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-00000000a001',2); RAISE EXCEPTION 'stale revision accepted'; EXCEPTION WHEN serialization_failure THEN NULL; END;
PERFORM set_config('iam.principal_id','00000000-0000-0000-0000-000000000001',true);
BEGIN PERFORM iam_private.honeycomb_adoption_export('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-00000000a001',1); RAISE EXCEPTION 'nonservice exported roots'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
UPDATE iam.testing_environments SET honeycomb_service_id='00000000-0000-0000-0000-000000000011',managed_state='active' WHERE id='00000000-0000-0000-0000-00000000a001';
INSERT INTO iam.honeycomb_operations(operation_id,service_application_id,actor_principal_id,operation_kind,resource_id,idempotency_digest,request_digest,state)
VALUES('00000000-0000-0000-0000-00000000f001','00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000011','testing-retention','00000000-0000-0000-0000-00000000a001',decode(repeat('04',32),'hex'),decode(repeat('05',32),'hex'),'pending');
SELECT set_config('iam.principal_id','00000000-0000-0000-0000-000000000011',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE revision bigint; first_receipt jsonb; second_receipt jsonb; BEGIN
revision:=(iam_private.honeycomb_testing_record('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-00000000a001')->>'iam_revision')::bigint;
BEGIN PERFORM iam_private.honeycomb_retention_start('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-00000000a001','00000000-0000-0000-0000-00000000f001',revision,1,2,ARRAY['test_org>app-alpha']); RAISE EXCEPTION 'stale key accepted'; EXCEPTION WHEN serialization_failure THEN NULL; END;
BEGIN PERFORM iam_private.honeycomb_retention_start('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-00000000a001','00000000-0000-0000-0000-00000000f001',revision,1,1,ARRAY['test_org>app-beta']); RAISE EXCEPTION 'unlinked app accepted'; EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
first_receipt:=iam_private.honeycomb_retention_start('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-00000000a001','00000000-0000-0000-0000-00000000f001',revision,1,1,ARRAY['test_org>app-alpha']);
second_receipt:=iam_private.honeycomb_retention_start('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-00000000a001','00000000-0000-0000-0000-00000000f001',revision,1,1,ARRAY['test_org>app-alpha']);
IF first_receipt<>second_receipt THEN RAISE EXCEPTION 'reservation retry changed revision'; END IF;
PERFORM iam_private.honeycomb_retention_finish('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-00000000a001','00000000-0000-0000-0000-00000000f001',ARRAY['test_org>app-alpha']);
END $$;
ROLLBACK;
