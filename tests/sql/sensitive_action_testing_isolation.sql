-- Shared testing database with the overlays and definer reconciliation applied.
-- The same canonical identities exist in two independent testing environments.
BEGIN;
SELECT set_config('iam.testing_environment_id','01120000-0000-0000-0000-000000000091',true);
INSERT INTO iam.principals(id,kind,status,activated_at) VALUES
 ('c:isolation-owner','carbon','active',now()),('si:chef','silicon','active',now());
INSERT INTO iam.carbons(id,carbon_id,display_name) VALUES('c:isolation-owner','c:isolation-owner','First Owner');
INSERT INTO iam.organizations(id,org_id,name,created_by_carbon_id) VALUES
 ('01120000-0000-0000-0000-000000000101','isolation-test','First Org','c:isolation-owner');
INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES
 ('01120000-0000-0000-0000-000000000111','01120000-0000-0000-0000-000000000101','c:isolation-owner','carbon','owner'),
 ('01120000-0000-0000-0000-000000000112','01120000-0000-0000-0000-000000000101','si:chef','silicon','member');
INSERT INTO iam.silicons(id,organization_id,membership_id,organization_handle,silicon_handle,display_name) VALUES
 ('si:chef','01120000-0000-0000-0000-000000000101','01120000-0000-0000-0000-000000000112','isolation-test','chef','First Chef');
SELECT set_config('iam.testing_environment_id','01120000-0000-0000-0000-000000000092',true);
INSERT INTO iam.principals(id,kind,status,activated_at) VALUES
 ('c:isolation-owner','carbon','active',now()),('si:chef','silicon','active',now());
INSERT INTO iam.carbons(id,carbon_id,display_name) VALUES('c:isolation-owner','c:isolation-owner','Second Owner');
INSERT INTO iam.organizations(id,org_id,name,created_by_carbon_id) VALUES
 ('01120000-0000-0000-0000-000000000201','isolation-test','Second Org','c:isolation-owner');
INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES
 ('01120000-0000-0000-0000-000000000211','01120000-0000-0000-0000-000000000201','c:isolation-owner','carbon','owner'),
 ('01120000-0000-0000-0000-000000000212','01120000-0000-0000-0000-000000000201','si:chef','silicon','member');
INSERT INTO iam.silicons(id,organization_id,membership_id,organization_handle,silicon_handle,display_name) VALUES
 ('si:chef','01120000-0000-0000-0000-000000000201','01120000-0000-0000-0000-000000000212','isolation-test','chef','Second Chef');

SELECT set_config('iam.testing_environment_id','01120000-0000-0000-0000-000000000091',true),
       set_config('iam.organization_id','01120000-0000-0000-0000-000000000101',true),
       set_config('iam.principal_id','c:isolation-owner',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE v_result jsonb; BEGIN
 IF EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles owner ON owner.oid=p.proowner
   WHERE p.pronamespace='iam_private'::regnamespace AND p.proname IN ('authorize_sensitive_action','lock_silicon_self_profile')
   AND (owner.rolsuper OR owner.rolbypassrls OR owner.rolname<>'silicon_iam_testing_definer')) THEN
  RAISE EXCEPTION 'testing helpers must execute under the constrained definer';
 END IF;
 PERFORM iam_private.configure_action_policy('01120000-0000-0000-0000-000000000101','membership.tags.update',0,'only_owner','owner','{}','{}','{}');
 PERFORM iam_private.configure_action_policy('01120000-0000-0000-0000-000000000101','membership.job_description.update',0,'any_member','admin','{}','{}','{}');
 PERFORM iam_private.authorize_sensitive_action('01120000-0000-0000-0000-000000000101','organization.profile.update',decode(repeat('10',32),'hex'),
   'PATCH','/organizations/isolation-test','{"name":"First Org"}','"1"','01120000-0000-0000-0000-000000000120',true);
 PERFORM set_config('iam.principal_id','si:chef',true);
 v_result:=iam_private.authorize_sensitive_action('01120000-0000-0000-0000-000000000101','membership.job_description.update',decode(repeat('11',32),'hex'),
   'PUT','/job-description','{}','"1"','01120000-0000-0000-0000-000000000121',false);
 IF v_result->>'status'<>'pending' THEN RAISE EXCEPTION 'first environment manual request missing'; END IF;
 IF iam_private.lock_silicon_self_profile('01120000-0000-0000-0000-000000000101','si:chef')<>'01120000-0000-0000-0000-000000000112' THEN
  RAISE EXCEPTION 'self-profile helper crossed environments';
 END IF;
 IF NOT iam_private.update_silicon_self_profile('01120000-0000-0000-0000-000000000101','si:chef',1,NULL,'Asia/Kolkata',false,NULL,false,NULL) THEN
  RAISE EXCEPTION 'first environment self-profile update failed';
 END IF;
 BEGIN
  PERFORM iam_private.lock_silicon_self_profile('01120000-0000-0000-0000-000000000201','si:chef');
  RAISE EXCEPTION 'another environment Silicon was locked';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;

 PERFORM set_config('iam.testing_environment_id','01120000-0000-0000-0000-000000000092',true);
 PERFORM set_config('iam.organization_id','01120000-0000-0000-0000-000000000201',true);
 IF NOT EXISTS(SELECT 1 FROM iam.silicons WHERE id='si:chef' AND timezone_id='UTC' AND version=1) THEN
  RAISE EXCEPTION 'first environment mutation changed the second profile';
 END IF;
 SELECT item INTO v_result FROM jsonb_array_elements(iam_private.list_action_policies('01120000-0000-0000-0000-000000000201')->'items') item
  WHERE item->>'action'='membership.tags.update';
 IF v_result->>'allowed_actors'<>'any_member' OR (v_result->>'version')::bigint<>0 THEN
  RAISE EXCEPTION 'first environment policy leaked into second';
 END IF;
 IF jsonb_array_length(iam_private.list_action_approvals('01120000-0000-0000-0000-000000000201')->'items')<>0 THEN
  RAISE EXCEPTION 'first environment request leaked into second';
 END IF;
 SELECT item INTO v_result FROM jsonb_array_elements(iam_private.list_action_policies('01120000-0000-0000-0000-000000000201')->'items') item
  WHERE item->>'action'='membership.job_description.update';
 IF v_result->>'approval' IS DISTINCT FROM 'none' OR (v_result->>'version')::bigint IS DISTINCT FROM 0 THEN
  RAISE EXCEPTION 'first environment manual approval policy changed the second default';
 END IF;
 v_result:=iam_private.authorize_sensitive_action('01120000-0000-0000-0000-000000000201','membership.job_description.update',decode(repeat('13',32),'hex'),
   'PUT','/job-description','{}','"1"','01120000-0000-0000-0000-000000000221',false);
 IF v_result->>'status' IS DISTINCT FROM 'allowed' THEN RAISE EXCEPTION 'second environment default unexpectedly required approval'; END IF;
END $$;
RESET ROLE;
UPDATE iam.principals SET status='suspended',suspended_at=now()
 WHERE id='si:chef' AND testing_environment_id='01120000-0000-0000-0000-000000000091';
SELECT set_config('iam.testing_environment_id','01120000-0000-0000-0000-000000000091',true),
       set_config('iam.organization_id','01120000-0000-0000-0000-000000000101',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
 BEGIN
  PERFORM iam_private.authorize_sensitive_action('01120000-0000-0000-0000-000000000101','silicon.self_profile.update',decode(repeat('12',32),'hex'),
   'PATCH','/silicons/chef','{"timezone":"UTC"}','"2"','01120000-0000-0000-0000-000000000122',true);
  RAISE EXCEPTION 'active identity in another environment authorized a suspended actor';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
  PERFORM iam_private.lock_silicon_self_profile('01120000-0000-0000-0000-000000000101','si:chef');
  RAISE EXCEPTION 'active identity in another environment authorized suspended self profile';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
-- Cleaning an environment also removes private approval state, without
-- following the repeated canonical identity into the other environment.
SELECT iam_private.erase_testing_environment('01120000-0000-0000-0000-000000000091');
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM iam_private.organization_action_policies WHERE organization_id='01120000-0000-0000-0000-000000000101')
   OR EXISTS(SELECT 1 FROM iam_private.organization_action_approvals WHERE organization_id='01120000-0000-0000-0000-000000000101')
   OR EXISTS(SELECT 1 FROM iam_private.organization_action_executions WHERE organization_id='01120000-0000-0000-0000-000000000101') THEN
  RAISE EXCEPTION 'environment cleaning retained private action state';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM iam.silicons WHERE id='si:chef'
   AND testing_environment_id='01120000-0000-0000-0000-000000000092' AND timezone_id='UTC') THEN
  RAISE EXCEPTION 'environment cleaning crossed canonical identity environments';
 END IF;
END $$;
ROLLBACK;
