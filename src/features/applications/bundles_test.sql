BEGIN;
INSERT INTO iam.principals(id,kind,status,activated_at) VALUES
('bundle_owner','carbon','active',transaction_timestamp()),
('bundle_stranger','carbon','active',transaction_timestamp()),
('bundle_org>alpha','application','active',transaction_timestamp()),
('bundle_org>beta','application','active',transaction_timestamp());
INSERT INTO iam.carbons(id,carbon_id,display_name) VALUES
('bundle_owner','bundle_owner','Bundle owner'),
('bundle_stranger','bundle_stranger','Bundle stranger');
INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name,trusted_org,allow_bundled_applications) VALUES
('01000000-0000-0000-0000-000000000021','bundle_org','bundle_owner','Bundle organization',true,true);
INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role,job_role) VALUES
('01000000-0000-0000-0000-000000000031','01000000-0000-0000-0000-000000000021','bundle_owner','carbon','owner','');
INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,review_status,base_url) VALUES
('bundle_org>alpha','bundle_org>alpha','01000000-0000-0000-0000-000000000021','bundle_owner','verified','https://alpha.example'),
('bundle_org>beta','bundle_org>beta','01000000-0000-0000-0000-000000000021','bundle_owner','verified','https://beta.example');
DO $$ BEGIN IF to_regrole('iam_bundle_test') IS NULL THEN CREATE ROLE iam_bundle_test NOLOGIN; END IF; END $$;
GRANT USAGE ON SCHEMA iam,iam_private TO iam_bundle_test;
GRANT SELECT ON iam.application_bundles TO iam_bundle_test;
GRANT EXECUTE ON FUNCTION iam_private.application_bundle_view(text,boolean,boolean),
iam_private.application_bundle_management_organization(text),
iam_private.mutate_application_bundle(text,text,bigint,text,jsonb),
iam_private.current_application_id(),iam_private.current_principal_id(),
iam_private.is_active_organization_owner_or_admin(uuid,text) TO iam_bundle_test;
SELECT set_config('iam.principal_id','bundle_owner',true);
SET LOCAL ROLE iam_bundle_test;
DO $$
DECLARE result jsonb;
BEGIN
 SELECT document INTO STRICT result FROM iam_private.mutate_application_bundle('bundle_org>workspace','bundle_owner',0,'create',
 '{"org_id":"bundle_org","app_id":"workspace","app_name":"Workspace","app_ids":["bundle_org>beta","bundle_org>alpha"]}');
 ASSERT result->>'bundle_id'='bundle_org>workspace';
 ASSERT result->'app_ids'='["bundle_org>beta","bundle_org>alpha"]'::jsonb;
 ASSERT NOT(result ? 'trusted_org');
 ASSERT (SELECT count(*) FROM iam.application_bundles)=1;
 BEGIN
   PERFORM * FROM iam_private.mutate_application_bundle('bundle_org>workspace','bundle_owner',99,'update','{"app_name":"Changed"}');
   RAISE EXCEPTION 'stale update unexpectedly accepted';
 EXCEPTION WHEN serialization_failure THEN NULL;
 END;
 BEGIN
   PERFORM * FROM iam_private.mutate_application_bundle('bundle_org>workspace','bundle_owner',1,'update','{"app_ids":["outside>app"]}');
   RAISE EXCEPTION 'foreign or unknown member unexpectedly accepted';
 EXCEPTION WHEN invalid_parameter_value THEN NULL;
 END;
 BEGIN
   PERFORM * FROM iam_private.mutate_application_bundle('bundle_org>workspace','bundle_owner',1,'update','{"app_ids":["bundle_org>workspace"]}');
   RAISE EXCEPTION 'nested bundle unexpectedly accepted';
 EXCEPTION WHEN invalid_parameter_value THEN NULL;
 END;
 PERFORM set_config('iam.principal_id','bundle_stranger',true);
 ASSERT (SELECT count(*) FROM iam.application_bundles)=0;
 ASSERT NOT EXISTS(SELECT * FROM iam_private.application_bundle_view('bundle_org>workspace',false,false));
 ASSERT EXISTS(SELECT * FROM iam_private.application_bundle_view('bundle_org>workspace',true,true));
 BEGIN
   PERFORM * FROM iam_private.mutate_application_bundle('bundle_org>workspace','bundle_stranger',1,'update','{"app_name":"Hijacked"}');
   RAISE EXCEPTION 'stranger mutation unexpectedly accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 PERFORM set_config('iam.principal_id','bundle_owner',true);
 SELECT document INTO STRICT result FROM iam_private.mutate_application_bundle('bundle_org>workspace','bundle_owner',1,'update','{"app_ids":["bundle_org>alpha"]}');
 ASSERT result->'app_ids'='["bundle_org>alpha"]'::jsonb;
 ASSERT result->>'version'='2';
END $$;
RESET ROLE;
UPDATE iam.organizations SET allow_bundled_applications=false WHERE org_id='bundle_org';
SET LOCAL ROLE iam_bundle_test;
DO $$
BEGIN
 ASSERT NOT EXISTS(SELECT * FROM iam_private.application_bundle_view('bundle_org>workspace',true,true));
 BEGIN
   PERFORM * FROM iam_private.mutate_application_bundle('bundle_org>other','bundle_owner',0,'create','{"org_id":"bundle_org","app_id":"other","app_ids":["bundle_org>alpha"]}');
   RAISE EXCEPTION 'disabled creation unexpectedly accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 PERFORM * FROM iam_private.mutate_application_bundle('bundle_org>workspace','bundle_owner',2,'delete','{}');
 ASSERT NOT EXISTS(SELECT * FROM iam_private.application_bundle_view('bundle_org>workspace',false,false));
 ASSERT iam_private.application_bundle_management_organization('bundle_org>workspace') IS NOT NULL;
END $$;
RESET ROLE;
DO $$ BEGIN ASSERT (SELECT count(*) FROM iam.applications WHERE organization_id='01000000-0000-0000-0000-000000000021')=2; END $$;
ROLLBACK;
