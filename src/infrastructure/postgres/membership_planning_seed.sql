-- Extends the common fixture before or after the canonical identity cutover.
BEGIN;
DO $fixture$
DECLARE fixture text := $seed$
INSERT INTO iam.principals(id,kind,status,activated_at) VALUES
('00000000-0000-0000-0000-000000000501','silicon','active',now());
INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES
('00000000-0000-0000-0000-000000000531','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000501','silicon','member');
INSERT INTO iam.silicons(id,organization_id,membership_id,organization_handle,silicon_handle,display_name,provisioning_status) VALUES
('00000000-0000-0000-0000-000000000501','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000531','test_org','planner_silicon','Planner Silicon','active');
INSERT INTO iam.authentication_sessions(id,subject_principal_id,subject_kind,authentication_method,assurance_level,subject_auth_epoch,idle_expires_at,absolute_expires_at) VALUES
('00000000-0000-0000-0000-000000000541','00000000-0000-0000-0000-000000000501','silicon','silicon_credential',1,1,now()+interval '1 day',now()+interval '2 days');
INSERT INTO iam.oauth_consent_grants(id,application_id,subject_principal_id,subject_kind,organization_id,membership_id,parent_authentication_session_id,selected_membership_ids) VALUES
('00000000-0000-0000-0000-000000000571','00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000501','silicon',NULL,NULL,'00000000-0000-0000-0000-000000000541',ARRAY['00000000-0000-0000-0000-000000000531'::uuid]),
('00000000-0000-0000-0000-000000000572','00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000501','silicon','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000531','00000000-0000-0000-0000-000000000541',ARRAY['00000000-0000-0000-0000-000000000531'::uuid]);
-- Preserve the real access/refresh issuance graph for later schema upgrades.
INSERT INTO iam.refresh_token_families(id,authentication_session_id,subject_principal_id,client_application_id,oauth_consent_grant_id,absolute_expires_at) VALUES
('00000000-0000-0000-0000-000000000591','00000000-0000-0000-0000-000000000541','00000000-0000-0000-0000-000000000501','00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000571',now()+interval '30 days');
INSERT INTO iam.refresh_tokens(id,family_id,token_digest,digest_key_version,token_prefix,expires_at) VALUES
('00000000-0000-0000-0000-000000000592','00000000-0000-0000-0000-000000000591',decode(repeat('59',32),'hex'),1,'ort_silicon1',now()+interval '30 days');
INSERT INTO iam.access_tokens(id,token_class,token_digest,digest_key_version,token_prefix,authentication_session_id,subject_principal_id,subject_kind,client_application_id,audience,audience_application_id,organization_id,membership_id,subject_auth_epoch,membership_authz_epoch,client_auth_epoch,expires_at) VALUES
('00000000-0000-0000-0000-000000000551','application_access',decode(repeat('55',32),'hex'),1,'oat_silicon1','00000000-0000-0000-0000-000000000541','00000000-0000-0000-0000-000000000501','silicon','00000000-0000-0000-0000-000000000011','test_org>app-alpha','00000000-0000-0000-0000-000000000011',NULL,NULL,1,NULL,1,now()+interval '15 minutes'),
('00000000-0000-0000-0000-000000000552','application_access',decode(repeat('56',32),'hex'),1,'oat_silicon2','00000000-0000-0000-0000-000000000541','00000000-0000-0000-0000-000000000501','silicon','00000000-0000-0000-0000-000000000011','test_org>app-alpha','00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000531',1,1,1,now()+interval '15 minutes');
$seed$;
BEGIN
 IF (SELECT atttypid='text'::regtype FROM pg_attribute WHERE attrelid='iam.principals'::regclass AND attname='id') THEN
  fixture:=replace(fixture,'00000000-0000-0000-0000-000000000501','planner_silicon:test_org');
  fixture:=replace(fixture,'00000000-0000-0000-0000-000000000011','test_org>app-alpha');
 END IF;
 IF to_regclass('iam_private.public_id_schema_map') IS NOT NULL THEN
  fixture:=replace(fixture,'planner_silicon:test_org','si:planner_silicon');
  fixture:=replace(fixture,'test_org>app-alpha','app-alpha');
 END IF;
 EXECUTE fixture;
END $fixture$;
COMMIT;
