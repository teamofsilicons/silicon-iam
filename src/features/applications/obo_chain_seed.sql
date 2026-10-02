BEGIN;
-- Added after obo_disclosure_seed.sql in a disposable database only.
-- target.files.read declares one downstream call, store.blobs.write, and
-- store.blobs.write declares a call back into target to probe cycles.
INSERT INTO iam.principals(id,kind,status,activated_at) VALUES
('store','application','active',now());
INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,app_name,base_url,review_status) VALUES
('store','store','00000000-0000-0000-0000-000000000023','c:test_admin','Store','https://store.example.test','verified');
INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical,downstream) VALUES
('00000000-0000-0000-0000-000000000023','store','blobs.write','/blobs','{}',false,'[{"audience":"target","endpoint_id":"files.read"}]');
UPDATE iam.application_obo_endpoints
SET downstream='[{"audience":"store","endpoint_id":"blobs.write"}]', downstream_ttl_seconds=600
WHERE application_id='target' AND endpoint_id='files.read';
INSERT INTO iam.oauth_scope_catalog(scope,description) VALUES('obo:store:blobs.write','Write blobs');
INSERT INTO iam.application_requested_scopes(application_id,scope) VALUES('target','obo:store:blobs.write');
INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES('target','obo:store:blobs.write','c:test_carbon');
INSERT INTO iam.application_requested_scopes(application_id,scope)
SELECT 'store', scope FROM unnest(ARRAY['self.identity.read','self.membership.read','self.tags.read','obo:target:files.read']) scope;
INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id)
SELECT 'store', scope, 'c:test_carbon'::text
FROM unnest(ARRAY['self.identity.read','self.membership.read','self.tags.read','obo:target:files.read']) scope;
-- A root proof from app-alpha to target, already consumed by target. Its
-- downstream grant is captured by trigger from the catalog above.
SELECT set_config('iam.principal_id','c:test_carbon',true),set_config('iam.application_id','app-alpha',true),set_config('iam.organization_id','00000000-0000-0000-0000-000000000021',true);
INSERT INTO iam.obo_proofs(id,proof_digest,digest_key_version,proof_prefix,issuer_application_id,audience_application_id,subject_principal_id,subject_kind,organization_id,membership_id,parent_access_token_id,endpoint_id,request_metadata,endpoint_version,request_method,request_path,request_body_sha256,request_signed_at,subject_auth_epoch,membership_authz_epoch,issuer_auth_epoch,audience_auth_epoch,expires_at)
SELECT '00000000-0000-0000-0000-000000000124',decode(repeat('3a',32),'hex'),1,'obo_qrstuvwx','app-alpha','target','c:test_carbon','carbon','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000031','00000000-0000-0000-0000-000000000101','files.read','{}',endpoint.version,'POST','/files',decode(repeat('00',32),'hex'),now(),1,1,1,1,now()+interval '60 seconds'
FROM iam.application_obo_endpoints endpoint WHERE endpoint.application_id='target' AND endpoint.endpoint_id='files.read';
UPDATE iam.obo_proofs SET consumed_at=now(),consumed_by_application_id='target'
WHERE id='00000000-0000-0000-0000-000000000124';

COMMIT;
