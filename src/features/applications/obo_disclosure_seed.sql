BEGIN;
-- Added to the common protocol fixture in a disposable database only.
INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name) VALUES
('00000000-0000-0000-0000-000000000023','other_org','00000000-0000-0000-0000-000000000002','Recipient Organization');
INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES
('00000000-0000-0000-0000-000000000033','00000000-0000-0000-0000-000000000023','00000000-0000-0000-0000-000000000002','carbon','owner');
INSERT INTO iam.principals(id,kind,status,activated_at) VALUES
('00000000-0000-0000-0000-000000000013','application','active',now());
INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,base_url,review_status) VALUES
('00000000-0000-0000-0000-000000000013','other_org>target','00000000-0000-0000-0000-000000000023','00000000-0000-0000-0000-000000000002','https://example.test','verified');
INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical) VALUES
('00000000-0000-0000-0000-000000000023','00000000-0000-0000-0000-000000000013','files.read','/files','{}',false);
UPDATE iam.applications SET app_scope='{"iam":["self.identity.read","self.membership.read","self.tags.read","directory.tags.read"],"external":[{"app_id":"other_org>target","endpoint_id":"files.read"}]}'
WHERE id='00000000-0000-0000-0000-000000000011';
INSERT INTO iam.oauth_scope_catalog(scope,description) VALUES('obo:other_org>target:files.read','Read files');
INSERT INTO iam.application_requested_scopes(application_id,scope)
SELECT app, scope FROM unnest(ARRAY['00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000013']::uuid[]) app
CROSS JOIN unnest(ARRAY['self.identity.read','self.membership.read','self.tags.read','directory.tags.read','obo:other_org>target:files.read']) scope;
INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id)
SELECT app, scope, '00000000-0000-0000-0000-000000000001'::uuid
FROM unnest(ARRAY['00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000013']::uuid[]) app
CROSS JOIN unnest(ARRAY['self.identity.read','self.membership.read','self.tags.read','directory.tags.read','obo:other_org>target:files.read']) scope;
INSERT INTO iam.access_token_scopes(access_token_id,scope)
SELECT '00000000-0000-0000-0000-000000000101',scope
FROM unnest(ARRAY['self.identity.read','self.membership.read','self.tags.read','directory.tags.read','obo:other_org>target:files.read']) scope;
INSERT INTO iam.oauth_consent_grant_scopes(consent_grant_id,scope)
SELECT grant_id,scope FROM unnest(ARRAY['00000000-0000-0000-0000-000000000071','00000000-0000-0000-0000-000000000072']::uuid[]) grant_id
CROSS JOIN unnest(ARRAY['self.identity.read','self.membership.read','self.tags.read','directory.tags.read','obo:other_org>target:files.read']) scope
WHERE grant_id = '00000000-0000-0000-0000-000000000071' OR scope NOT LIKE 'obo:%';
INSERT INTO iam.organization_tags(id,organization_id,name,normalized_name,created_by_membership_id) VALUES
('00000000-0000-0000-0000-000000000151','00000000-0000-0000-0000-000000000021','Design','design','00000000-0000-0000-0000-000000000031');
INSERT INTO iam.membership_tags(organization_id,membership_id,tag_id,assigned_by_membership_id) VALUES
('00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000031','00000000-0000-0000-0000-000000000151','00000000-0000-0000-0000-000000000031');
SELECT set_config('iam.principal_id','00000000-0000-0000-0000-000000000001',true),set_config('iam.application_id','00000000-0000-0000-0000-000000000011',true),set_config('iam.organization_id','00000000-0000-0000-0000-000000000021',true);
INSERT INTO iam.obo_proofs(id,proof_digest,digest_key_version,proof_prefix,issuer_application_id,audience_application_id,subject_principal_id,subject_kind,organization_id,membership_id,parent_access_token_id,endpoint_id,request_metadata,endpoint_version,request_method,request_path,request_body_sha256,request_signed_at,subject_auth_epoch,membership_authz_epoch,issuer_auth_epoch,audience_auth_epoch,expires_at)
VALUES('00000000-0000-0000-0000-000000000123',decode(repeat('39',32),'hex'),1,'obo_ijklmnop','00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000013','00000000-0000-0000-0000-000000000001','carbon','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000031','00000000-0000-0000-0000-000000000101','files.read','{}',1,'POST','/files',decode(repeat('00',32),'hex'),now(),1,1,1,1,now()+interval '60 seconds');

COMMIT;
