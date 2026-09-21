-- Loaded before 0111 by scripts/test-canonical-identity-migration.py.
-- The same handles occur in production and both isolated testing environments.
CREATE FUNCTION pg_temp.fixture_id(plane integer, name text) RETURNS uuid
LANGUAGE sql IMMUTABLE AS $$ SELECT md5('canonical-migration/'||plane||'/'||name)::uuid $$;
CREATE FUNCTION pg_temp.seed_identity_upgrade(plane integer, testing boolean)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
 carbon uuid:=pg_temp.fixture_id(plane,'carbon');
 silicon uuid:=pg_temp.fixture_id(plane,'silicon');
 app uuid:=pg_temp.fixture_id(plane,'app');
 org uuid:=pg_temp.fixture_id(plane,'org');
 member uuid:=pg_temp.fixture_id(plane,'member');
 session uuid:=pg_temp.fixture_id(plane,'session');
 consent uuid:=pg_temp.fixture_id(plane,'consent');
 family uuid:=pg_temp.fixture_id(plane,'family');
BEGIN
 PERFORM set_config('iam.testing_environment_id',CASE WHEN testing THEN pg_temp.fixture_id(plane,'environment')::text ELSE '' END,true);
 INSERT INTO iam.cryptographic_key_versions(purpose,key_version,status)
 VALUES('contact_aead',1,'active'),('token_hmac',1,'active') ON CONFLICT DO NOTHING;
 INSERT INTO iam.principals(id,kind,status,activated_at,auth_epoch) VALUES
  (carbon,'carbon','active',now(),plane),(silicon,'silicon','active',now(),plane),(app,'application','active',now(),plane);
 INSERT INTO iam.carbons(id,carbon_id,display_name,description)
 VALUES(carbon,'migration-owner','Owner '||plane,'Carbon description '||plane);
 INSERT INTO iam.carbon_contacts(id,carbon_id,kind,ciphertext,nonce,encryption_key_version,verified_at) VALUES
  (pg_temp.fixture_id(plane,'email'),carbon,'email',decode(repeat('01',17),'hex'),decode(repeat('01',12),'hex'),1,now()),
  (pg_temp.fixture_id(plane,'phone'),carbon,'phone',decode(repeat('02',17),'hex'),decode(repeat('02',12),'hex'),1,now());
 INSERT INTO iam.organizations(id,org_id,name,created_by_carbon_id)
 VALUES(org,'identity-test','Identity test '||plane,carbon);
 INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role,job_role) VALUES
  (pg_temp.fixture_id(plane,'owner'),org,carbon,'carbon','owner','Owner job '||plane),
  (member,org,silicon,'silicon','member','');
 INSERT INTO iam.silicons(id,organization_id,membership_id,organization_handle,silicon_handle,display_name,description)
 VALUES(silicon,org,member,'identity-test','migration','Silicon '||plane,'Silicon description '||plane);
 INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,review_status)
 VALUES(app,'identity-test>app',org,carbon,'verified');
 INSERT INTO iam.application_secrets(id,application_id,secret_version,secret_prefix,secret_digest,pepper_key_version,created_by_carbon_id)
 VALUES(pg_temp.fixture_id(plane,'secret'),app,1,'ask_abcdefgh',decode(repeat(lpad(to_hex(plane),2,'0'),32),'hex'),1,carbon);
 -- The same imported app and URL intentionally recur in both environments;
 -- URL digests are content hashes and cannot make identity keys global.
 INSERT INTO iam.application_webhook_endpoints(id,application_id,url_ciphertext,url_nonce,encryption_key_version,url_digest,status,activated_at)
 VALUES(pg_temp.fixture_id(plane,'endpoint'),app,decode(repeat('04',17),'hex'),decode(repeat('04',12),'hex'),1,decode(repeat('05',32),'hex'),'active',now());
 INSERT INTO iam.authentication_sessions(id,subject_principal_id,subject_kind,authentication_method,assurance_level,subject_auth_epoch,idle_expires_at,absolute_expires_at)
 VALUES(session,silicon,'silicon','silicon_credential',2,plane,now()+interval '900 days',now()+interval '900 days');
 INSERT INTO iam.oauth_consent_grants(id,application_id,subject_principal_id,subject_kind,organization_id,membership_id,parent_authentication_session_id)
 VALUES(consent,app,silicon,'silicon',org,member,session);
 INSERT INTO iam.refresh_token_families(id,authentication_session_id,subject_principal_id,client_application_id,oauth_consent_grant_id,absolute_expires_at)
 VALUES(family,session,silicon,app,consent,now()+interval '900 days');
 INSERT INTO iam.refresh_tokens(id,family_id,token_digest,digest_key_version,token_prefix,expires_at)
 VALUES(pg_temp.fixture_id(plane,'refresh'),family,decode(repeat(lpad(to_hex(plane+10),2,'0'),32),'hex'),1,'ort_abcdefgh',now()+interval '900 days');
 INSERT INTO iam.access_tokens(id,token_class,token_digest,digest_key_version,token_prefix,authentication_session_id,subject_principal_id,subject_kind,
 client_application_id,audience_application_id,audience,organization_id,membership_id,subject_auth_epoch,membership_authz_epoch,client_auth_epoch,expires_at)
 VALUES(pg_temp.fixture_id(plane,'access'),'application_access',decode(repeat(lpad(to_hex(plane+20),2,'0'),32),'hex'),1,'oat_abcdefgh',session,silicon,'silicon',app,app,'identity-test>app',org,member,plane,1,plane,now()+interval '30 minutes');
 INSERT INTO iam.outbox_events(id,aggregate_type,aggregate_id,aggregate_version,event_type,payload)
 VALUES(pg_temp.fixture_id(plane,'event'),'silicon',silicon,1,'silicon.updated',jsonb_build_object(
  'actor',jsonb_build_object('principal_id',silicon,'id',silicon),'application_id',app,'encryption_application_id',app,'resource_id',org));
 INSERT INTO iam.audit_events(id,request_id,actor_principal_id,actor_kind,organization_id,application_id,action,target_type,target_id,aggregate_type,aggregate_id,aggregate_version)
 VALUES(pg_temp.fixture_id(plane,'audit'),pg_temp.fixture_id(plane,'request'),silicon,'silicon',org,app,'silicon.updated','silicon',silicon,'silicon',silicon,1);
 -- UUID uniqueness is local to each resource table; a contact can have the
 -- same bytes as a principal without becoming an identity reference.
 INSERT INTO iam.carbon_contacts(id,carbon_id,kind,ciphertext,nonce,encryption_key_version,verified_at,is_primary)
 VALUES(carbon,carbon,'email',decode(repeat('03',17),'hex'),decode(repeat('03',12),'hex'),1,now(),false);
 INSERT INTO iam.audit_events(id,request_id,actor_principal_id,actor_kind,action,target_type,target_id,aggregate_type,aggregate_id,aggregate_version)
 VALUES(pg_temp.fixture_id(plane,'contact-audit'),pg_temp.fixture_id(plane,'contact-request'),carbon,'carbon','contact.updated','carbon_contact',carbon,'carbon_contact',carbon,1);
 INSERT INTO iam.outbox_events(id,aggregate_type,aggregate_id,aggregate_version,event_type,payload)
 VALUES(pg_temp.fixture_id(plane,'contact-event'),'carbon_contact',carbon,1,'contact.updated','{}');
 IF testing AND plane=2 THEN
  INSERT INTO iam.principals(id,kind,status) VALUES(pg_temp.fixture_id(plane,'exclusive'),'carbon','provisioning');
  INSERT INTO iam.carbons(id,carbon_id,display_name) VALUES(pg_temp.fixture_id(plane,'exclusive'),'exclusive-owner','Environment two only');
 END IF;
END $$;
