-- Disposable migrated database; all fixtures and mutations roll back.
BEGIN;
INSERT INTO iam.principals(id,kind,status,activated_at) VALUES
 ('c:policy-owner','carbon','active',now()),
 ('c:policy-admin','carbon','active',now()),
 ('si:chef','silicon','active',now());
INSERT INTO iam.carbons(id,carbon_id,display_name) VALUES
 ('c:policy-owner','c:policy-owner','Owner'),
 ('c:policy-admin','c:policy-admin','Admin');
INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name) VALUES
 ('01120000-0000-0000-0000-000000000010','policy-test','c:policy-owner','Policy Test');
INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role,role_granted_by_membership_id) VALUES
 ('01120000-0000-0000-0000-000000000011','01120000-0000-0000-0000-000000000010','c:policy-owner','carbon','owner',NULL),
 ('01120000-0000-0000-0000-000000000012','01120000-0000-0000-0000-000000000010','c:policy-admin','carbon','admin','01120000-0000-0000-0000-000000000011'),
 ('01120000-0000-0000-0000-000000000013','01120000-0000-0000-0000-000000000010','si:chef','silicon','member',NULL);
INSERT INTO iam.silicons(id,organization_id,membership_id,organization_handle,silicon_handle,display_name) VALUES
 ('si:chef','01120000-0000-0000-0000-000000000010','01120000-0000-0000-0000-000000000013','policy-test','chef','Chef');
INSERT INTO iam.organization_tags(id,organization_id,name,normalized_name,created_by_membership_id) VALUES
 ('01120000-0000-0000-0000-000000000041','01120000-0000-0000-0000-000000000010','Kitchen','kitchen','01120000-0000-0000-0000-000000000011');
INSERT INTO iam.membership_tags(organization_id,membership_id,tag_id,assigned_by_membership_id) VALUES
 ('01120000-0000-0000-0000-000000000010','01120000-0000-0000-0000-000000000013','01120000-0000-0000-0000-000000000041','01120000-0000-0000-0000-000000000011');
SELECT set_config('iam.organization_id','01120000-0000-0000-0000-000000000010',true),
       set_config('iam.principal_id','si:chef',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE
 v_org constant uuid:='01120000-0000-0000-0000-000000000010';
 v_req constant uuid:='01120000-0000-0000-0000-000000000021';
 v_request jsonb; v_policy jsonb; v_result jsonb;
BEGIN
 v_policy:=iam_private.list_action_policies(v_org);
 IF jsonb_array_length(v_policy->'items')<>14 OR (v_policy->>'can_manage')::boolean THEN
  RAISE EXCEPTION 'member policy catalog or management authority incorrect';
 END IF;
 SELECT item INTO v_result FROM jsonb_array_elements(v_policy->'items') item
 WHERE item->>'action'='membership.job_description.update';
 IF v_result->>'allowed_actors' IS DISTINCT FROM 'any_member'
   OR v_result->>'approval' IS DISTINCT FROM 'none'
   OR v_result#>>'{defaults,approval}' IS DISTINCT FROM 'none'
   OR (v_result->>'version')::bigint IS DISTINCT FROM 0 THEN
  RAISE EXCEPTION 'job description default must allow any member without approval';
 END IF;
 v_result:=iam_private.authorize_sensitive_action(v_org,'membership.job_description.update',decode(repeat('09',32),'hex'),
  'PUT','/members/chef/job-description','{"job_description":"No approval needed"}','"1"','01120000-0000-0000-0000-000000000029',false);
 IF v_result->>'status' IS DISTINCT FROM 'allowed'
   OR jsonb_array_length(iam_private.list_action_approvals(v_org)->'items')<>0 THEN
  RAISE EXCEPTION 'ordinary member job description change requested default approval';
 END IF;

 -- Manual approval remains configurable; explicitly enable it for the checks below.
 PERFORM set_config('iam.principal_id','c:policy-owner',true);
 v_policy:=iam_private.configure_action_policy(v_org,'membership.job_description.update',0,'any_member','admin','{}','{}','{}');
 IF (v_policy->>'version')::bigint<>1 THEN RAISE EXCEPTION 'manual approval policy version did not advance'; END IF;
 PERFORM set_config('iam.principal_id','si:chef',true);
 v_request:=iam_private.authorize_sensitive_action(v_org,'membership.job_description.update',decode(repeat('01',32),'hex'),
  'PUT','/members/chef/job-description','{"job_description":"Chef"}','"1"',v_req,false);
 IF v_request->>'status'<>'pending' OR iam_private.has_organization_capability(v_org,iam_private.current_principal_id(),'roles.approve') THEN
  RAISE EXCEPTION 'manual approval did not stop authority';
 END IF;
 BEGIN
  PERFORM iam_private.decide_action_approval(v_org,v_req,1,'approve');
  RAISE EXCEPTION 'ordinary member approved its own action';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
  PERFORM iam_private.configure_action_policy(v_org,'membership.tags.update',0,'any_member','none','{}','{}','{}');
  RAISE EXCEPTION 'ordinary member configured policy';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;

 -- An admin permitted to verify the action executes immediately.
 PERFORM set_config('iam.principal_id','c:policy-admin',true);
 v_result:=iam_private.authorize_sensitive_action(v_org,'membership.job_description.update',decode(repeat('02',32),'hex'),
  'PUT','/members/chef/job-description','{"job_description":"Chef"}','"1"','01120000-0000-0000-0000-000000000022',false);
 IF v_result->>'status'<>'allowed' THEN RAISE EXCEPTION 'admin was asked to approve its own action'; END IF;
 PERFORM iam_private.decide_action_approval(v_org,v_req,1,'approve');
 BEGIN
  PERFORM iam_private.configure_action_policy(v_org,'membership.tags.update',0,'any_member','none','{}','{}','{}');
  RAISE EXCEPTION 'undelegated admin configured policy';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;

 PERFORM set_config('iam.principal_id','si:chef',true);
 v_result:=iam_private.authorize_sensitive_action(v_org,'membership.job_description.update',decode(repeat('01',32),'hex'),
  'PUT','/members/chef/job-description','{"job_description":"Chef"}','"1"',v_req,true);
 IF v_result->>'status'<>'allowed' OR NOT iam_private.action_execution_allowed(v_org,'membership.job_description.update') THEN
  RAISE EXCEPTION 'approved exact request did not gain transactional authority';
 END IF;
 IF iam_private.replace_membership_job_role_direct(v_org,'01120000-0000-0000-0000-000000000013',
  '01120000-0000-0000-0000-000000000013','01120000-0000-0000-0000-000000000031',1,'Chef')<>2 THEN
  RAISE EXCEPTION 'approved member job mutation failed';
 END IF;
 v_result:=iam_private.authorize_sensitive_action(v_org,'membership.job_description.update',decode(repeat('03',32),'hex'),
  'PUT','/members/other/job-description','{"job_description":"Other"}','"1"','01120000-0000-0000-0000-000000000023',false);
 IF v_result->>'status'<>'pending' THEN RAISE EXCEPTION 'approval authorized a different fingerprint'; END IF;

 -- Owner can narrow an action despite an existing approved request, and the
 -- owner retains authority even under an owner-only/manual owner policy.
 PERFORM set_config('iam.principal_id','c:policy-owner',true);
 v_policy:=iam_private.configure_action_policy(v_org,'membership.job_description.update',1,'only_owner','owner','{}','{}','{}');
 IF (v_policy->>'version')::bigint<>2 THEN RAISE EXCEPTION 'policy version did not advance'; END IF;
 v_result:=iam_private.authorize_sensitive_action(v_org,'membership.job_description.update',decode(repeat('04',32),'hex'),
  'PUT','/members/chef/job-description','{}','"2"','01120000-0000-0000-0000-000000000024',false);
 IF v_result->>'status'<>'allowed' THEN RAISE EXCEPTION 'owner lost authority'; END IF;
 PERFORM set_config('iam.principal_id','si:chef',true);
 BEGIN
  PERFORM iam_private.authorize_sensitive_action(v_org,'membership.job_description.update',decode(repeat('01',32),'hex'),
   'PUT','/members/chef/job-description','{}','"2"',v_req,true);
  RAISE EXCEPTION 'old approval bypassed narrowed policy';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;

 -- Auto rules concern the requesting identity; unmatched actions stay manual.
 PERFORM set_config('iam.principal_id','c:policy-owner',true);
 PERFORM iam_private.configure_action_policy(v_org,'membership.tags.update',0,'any_member','admin','{}',ARRAY['si:chef'],'{}');
 BEGIN
  PERFORM iam_private.configure_action_policy(v_org,'membership.tags.update',0,'any_member','none','{}','{}','{}');
  RAISE EXCEPTION 'stale policy version accepted';
 EXCEPTION WHEN serialization_failure THEN NULL; END;
 PERFORM set_config('iam.principal_id','si:chef',true);
 v_result:=iam_private.authorize_sensitive_action(v_org,'membership.tags.update',decode(repeat('05',32),'hex'),
  'PUT','/members/chef/tags','{"tag_ids":[]}','"2"','01120000-0000-0000-0000-000000000025',false);
 IF v_result->>'status'<>'allowed' THEN RAISE EXCEPTION 'matching requester auto rule failed'; END IF;
 PERFORM set_config('iam.principal_id','c:policy-owner',true);
 PERFORM iam_private.configure_action_policy(v_org,'membership.tags.update',1,'any_member','owner',ARRAY['c:policy-admin'],'{}','{}');
 PERFORM set_config('iam.principal_id','c:policy-admin',true);
 v_result:=iam_private.authorize_sensitive_action(v_org,'membership.tags.update',decode(repeat('06',32),'hex'),
  'PUT','/members/chef/tags','{"tag_ids":[]}','"2"','01120000-0000-0000-0000-000000000026',false);
 IF v_result->>'status'<>'allowed' THEN RAISE EXCEPTION 'matching carbon auto rule failed'; END IF;
 PERFORM set_config('iam.principal_id','c:policy-owner',true);
 PERFORM iam_private.configure_action_policy(v_org,'membership.tags.update',2,'any_member','owner','{}','{}',ARRAY['01120000-0000-0000-0000-000000000041']::uuid[]);
 PERFORM set_config('iam.principal_id','si:chef',true);
 v_result:=iam_private.authorize_sensitive_action(v_org,'membership.tags.update',decode(repeat('07',32),'hex'),
  'PUT','/members/chef/tags','{"tag_ids":[]}','"2"','01120000-0000-0000-0000-000000000027',false);
 IF v_result->>'status'<>'allowed' THEN RAISE EXCEPTION 'matching requester tag auto rule failed'; END IF;

 -- Approved authority and consumption roll back with a failed mutation.
 PERFORM set_config('iam.principal_id','c:policy-owner',true);
 PERFORM iam_private.configure_action_policy(v_org,'trust.rule.create',0,'any_member','admin','{}','{}','{}');
 PERFORM set_config('iam.principal_id','si:chef',true);
 PERFORM iam_private.authorize_sensitive_action(v_org,'trust.rule.create',decode(repeat('08',32),'hex'),
  'POST','/trust/rules','{}',NULL,'01120000-0000-0000-0000-000000000028',false);
 PERFORM set_config('iam.principal_id','c:policy-admin',true);
 PERFORM iam_private.decide_action_approval(v_org,'01120000-0000-0000-0000-000000000028',1,'approve');
 PERFORM set_config('iam.principal_id','si:chef',true);
 BEGIN
  PERFORM iam_private.authorize_sensitive_action(v_org,'trust.rule.create',decode(repeat('08',32),'hex'),
   'POST','/trust/rules','{}',NULL,'01120000-0000-0000-0000-000000000028',true);
  RAISE EXCEPTION 'simulate failed mutation' USING ERRCODE='ZX001';
 EXCEPTION WHEN SQLSTATE 'ZX001' THEN NULL; END;
 IF iam_private.action_execution_allowed(v_org,'trust.rule.create') THEN
  RAISE EXCEPTION 'execution authority survived mutation rollback';
 END IF;
 SELECT item INTO v_request FROM jsonb_array_elements(iam_private.list_action_approvals(v_org)->'items') item
 WHERE item->>'id'='01120000-0000-0000-0000-000000000028';
 IF v_request->>'status'<>'approved' THEN RAISE EXCEPTION 'failed mutation consumed its approval'; END IF;
 BEGIN
  INSERT INTO iam_private.organization_action_executions(transaction_id,organization_id,membership_id,action,capabilities)
  VALUES(pg_current_xact_id()::text::bigint,v_org,'01120000-0000-0000-0000-000000000013','trust.rule.create',ARRAY['trust.manage']);
  RAISE EXCEPTION 'runtime role wrote its own execution authority';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
-- A decision must return its exact record even after the request falls outside
-- the list's newest-200 page.
INSERT INTO iam_private.organization_action_approvals(
 id,organization_id,action,policy_version,requested_by_membership_id,
 request_fingerprint,method,path,request_body,created_at)
VALUES ('01120000-0000-0000-0000-000000000061','01120000-0000-0000-0000-000000000010','trust.rule.create',1,
 '01120000-0000-0000-0000-000000000013',decode(repeat('61',32),'hex'),'POST','/trust/rules','{}',now()-interval '1 hour');
INSERT INTO iam_private.organization_action_approvals(
 id,organization_id,action,policy_version,requested_by_membership_id,
 request_fingerprint,method,path,request_body)
SELECT gen_random_uuid(),'01120000-0000-0000-0000-000000000010','trust.rule.create',1,
 '01120000-0000-0000-0000-000000000013',decode(lpad(to_hex(sequence),64,'0'),'hex'),'POST','/trust/rules','{}'
FROM generate_series(1,201) sequence;
SELECT set_config('iam.principal_id','c:policy-admin',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE v_result jsonb; BEGIN
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(iam_private.list_action_approvals('01120000-0000-0000-0000-000000000010')->'items') item
   WHERE item->>'id'='01120000-0000-0000-0000-000000000061') THEN
  RAISE EXCEPTION 'old decision fixture is still on the newest page';
 END IF;
 v_result:=iam_private.decide_action_approval('01120000-0000-0000-0000-000000000010','01120000-0000-0000-0000-000000000061',1,'approve');
 IF v_result IS NULL OR v_result->>'id'<>'01120000-0000-0000-0000-000000000061'
   OR v_result->>'status'<>'approved' OR (v_result->>'version')::bigint<>2 THEN
  RAISE EXCEPTION 'old approval decision did not return its exact record';
 END IF;
END $$;
RESET ROLE;
INSERT INTO iam.organization_capability_grants(id,organization_id,grantee_membership_id,capability,granted_by_membership_id) VALUES
 ('01120000-0000-0000-0000-000000000051','01120000-0000-0000-0000-000000000010','01120000-0000-0000-0000-000000000012','action_policies.manage','01120000-0000-0000-0000-000000000011');
SELECT set_config('iam.principal_id','c:policy-admin',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
 PERFORM iam_private.configure_action_policy('01120000-0000-0000-0000-000000000010','tag.create',0,'only_owner','owner','{}','{}','{}');
 IF NOT (iam_private.list_action_policies('01120000-0000-0000-0000-000000000010')->>'can_manage')::boolean THEN
  RAISE EXCEPTION 'delegated admin cannot manage policies';
 END IF;
END $$;
ROLLBACK;
