-- Run as migrator against a disposable production schema through migration0112.
-- The migration and fixtures roll back, leaving the database at0112.
BEGIN;
INSERT INTO iam.principals(id,kind,status,activated_at) VALUES
 ('c:job-owner','carbon','active',now()),('c:job-fallback','carbon','active',now()),
 ('c:job-empty','carbon','active',now()),('si:helper','silicon','active',now());
INSERT INTO iam.carbons(id,carbon_id,display_name,description) VALUES
 ('c:job-owner','c:job-owner','Owner','Do not replace the existing job'),
 ('c:job-fallback','c:job-fallback','Fallback',E'  Fallback carbon description\n'),
 ('c:job-empty','c:job-empty','Empty',NULL);
INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name) VALUES
 ('01130000-0000-0000-0000-000000000010','job-test','c:job-owner','Job Test');
INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role,job_role) VALUES
 ('01130000-0000-0000-0000-000000000011','01130000-0000-0000-0000-000000000010','c:job-owner','carbon','owner','  Existing job text  '),
 ('01130000-0000-0000-0000-000000000012','01130000-0000-0000-0000-000000000010','c:job-fallback','carbon','member',''),
 ('01130000-0000-0000-0000-000000000013','01130000-0000-0000-0000-000000000010','c:job-empty','carbon','member',''),
 ('01130000-0000-0000-0000-000000000014','01130000-0000-0000-0000-000000000010','si:helper','silicon','member','');
INSERT INTO iam.silicons(id,organization_id,membership_id,organization_handle,silicon_handle,display_name,description) VALUES
 ('si:helper','01130000-0000-0000-0000-000000000010','01130000-0000-0000-0000-000000000014','job-test','helper','Helper','Fallback silicon description');
INSERT INTO iam.cryptographic_key_versions(purpose,key_version,status)
VALUES('contact_aead',1,'active') ON CONFLICT DO NOTHING;
INSERT INTO iam.carbon_contacts(id,carbon_id,kind,ciphertext,nonce,encryption_key_version,verified_at)
SELECT gen_random_uuid(), carbon.id, kind::iam.contact_kind, decode(repeat('51',17),'hex'), decode(repeat('52',12),'hex'), 1, now()
FROM iam.carbons carbon CROSS JOIN (VALUES('email'),('phone')) kinds(kind)
WHERE carbon.id IN ('c:job-owner','c:job-fallback','c:job-empty');
INSERT INTO iam.carbon_membership_settings(organization_id,membership_id,carbon_id)
SELECT organization_id,id,principal_id FROM iam.organization_memberships
WHERE organization_id='01130000-0000-0000-0000-000000000010' AND principal_kind='carbon';
SET CONSTRAINTS ALL IMMEDIATE;
\ir ../../migrations/0113_single_job_description.sql
DO $$ BEGIN
 IF (SELECT job_role FROM iam.organization_memberships WHERE principal_id='c:job-owner') IS DISTINCT FROM '  Existing job text  ' THEN
  RAISE EXCEPTION 'Existing nonempty job description was modified'; END IF;
 IF (SELECT job_role FROM iam.organization_memberships WHERE principal_id='c:job-fallback') IS DISTINCT FROM E'  Fallback carbon description\n' THEN
  RAISE EXCEPTION 'Carbon description fallback missing'; END IF;
 IF (SELECT job_role FROM iam.organization_memberships WHERE principal_id='si:helper') IS DISTINCT FROM 'Fallback silicon description' THEN
  RAISE EXCEPTION 'Silicon description fallback missing'; END IF;
 IF (SELECT job_role FROM iam.organization_memberships WHERE principal_id='c:job-empty') IS DISTINCT FROM '' THEN
  RAISE EXCEPTION 'Empty description acquired unexpected text'; END IF;
 IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='iam' AND table_name IN ('carbons','silicons') AND column_name='description') THEN
  RAISE EXCEPTION 'Retired profile description columns remain'; END IF;
 IF EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN ('iam','iam_private') AND p.prokind='f' AND pg_get_functiondef(p.oid) ~ '(carbon|silicon)\.description') THEN
  RAISE EXCEPTION 'Stored profile function still references removed description'; END IF;
END $$;
ROLLBACK;
