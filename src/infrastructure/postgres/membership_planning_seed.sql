-- Extends the common protocol fixture only in disposable test databases.
BEGIN;
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
INSERT INTO iam.access_tokens(id,token_class,token_digest,digest_key_version,token_prefix,authentication_session_id,subject_principal_id,subject_kind,client_application_id,audience,audience_application_id,organization_id,membership_id,subject_auth_epoch,membership_authz_epoch,client_auth_epoch,expires_at) VALUES
('00000000-0000-0000-0000-000000000551','application_access',decode(repeat('55',32),'hex'),1,'oat_silicon1','00000000-0000-0000-0000-000000000541','00000000-0000-0000-0000-000000000501','silicon','00000000-0000-0000-0000-000000000011','test_org>app-alpha','00000000-0000-0000-0000-000000000011',NULL,NULL,1,NULL,1,now()+interval '15 minutes'),
('00000000-0000-0000-0000-000000000552','application_access',decode(repeat('56',32),'hex'),1,'oat_silicon2','00000000-0000-0000-0000-000000000541','00000000-0000-0000-0000-000000000501','silicon','00000000-0000-0000-0000-000000000011','test_org>app-alpha','00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000531',1,1,1,now()+interval '15 minutes');
COMMIT;
