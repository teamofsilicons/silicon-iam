-- Run after seed_protocol_rows against a disposable migrated database.
-- Every fixture and grant change is rolled back.
BEGIN;
UPDATE iam.organizations SET trusted_org=true WHERE id='00000000-0000-0000-0000-000000000021';
INSERT INTO iam.principals (id, kind, status, activated_at) VALUES
  ('c:new_account', 'carbon', 'active', transaction_timestamp());
INSERT INTO iam.carbons (id, carbon_id, display_name) VALUES
  ('c:new_account', 'c:new_account', 'New Account');
INSERT INTO iam.authentication_sessions (
  id, subject_principal_id, subject_kind, authentication_method, assurance_level,
  subject_auth_epoch, idle_expires_at, absolute_expires_at
) VALUES (
  '00000000-0000-0000-0000-000000000841',
  'c:new_account', 'carbon', 'email_otp', 1, 1,
  transaction_timestamp() + interval '1 day', transaction_timestamp() + interval '2 days'
);
INSERT INTO iam.application_requested_scopes (application_id, scope) VALUES
  ('app-alpha', 'organizations.create');
INSERT INTO iam.application_approved_scopes (application_id, scope, approved_by_carbon_id) VALUES
  ('app-alpha', 'organizations.create', 'c:test_carbon');
SELECT set_config('iam.principal_id','c:new_account',true),
  set_config('iam.application_id','',true), set_config('iam.organization_id','',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'c:new_account','00000000-0000-0000-0000-000000000841',
      '{}'::text[], 'app-alpha');
    RAISE EXCEPTION 'onboarding scope allowed application login without an organization';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'c:new_account','00000000-0000-0000-0000-000000000841',
      '{}'::text[], 'app-beta');
    RAISE EXCEPTION 'ordinary application accepted an empty selection';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  BEGIN
    PERFORM iam_private.lock_login_organization_selection(
      'c:new_account','00000000-0000-0000-0000-000000000841',
      '{}'::text[]);
    RAISE EXCEPTION 'legacy selector lost its nonempty requirement';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'c:new_account','00000000-0000-0000-0000-000000000041',
      '{}'::text[], 'app-alpha');
    RAISE EXCEPTION 'another account session allowed empty selection';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'c:new_account','00000000-0000-0000-0000-000000000841',
      NULL::text[], 'app-alpha');
    RAISE EXCEPTION 'missing explicit selection was accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
SELECT set_config('iam.application_id','app-alpha',true);
DO $$ BEGIN
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'c:new_account','00000000-0000-0000-0000-000000000841',
      '{}'::text[], 'app-alpha');
    RAISE EXCEPTION 'application context was able to authorize itself';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
UPDATE iam.application_approved_scopes SET revoked_at=transaction_timestamp(),
  revoked_by_carbon_id='c:test_carbon'
WHERE application_id='app-alpha' AND scope='organizations.create';
SELECT set_config('iam.application_id','',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'c:new_account','00000000-0000-0000-0000-000000000841',
      '{}'::text[], 'app-alpha');
    RAISE EXCEPTION 'revoked onboarding permission was accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
INSERT INTO iam.application_requested_scopes (application_id, scope) VALUES
  ('app-alpha', 'organizations.join');
INSERT INTO iam.application_approved_scopes (application_id, scope, approved_by_carbon_id) VALUES
  ('app-alpha', 'organizations.join', 'c:test_carbon');
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'c:new_account','00000000-0000-0000-0000-000000000841',
      '{}'::text[], 'app-alpha');
    RAISE EXCEPTION 'join-only scope bypassed the required organization';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
-- First-party identity sessions remain usable for onboarding. Joining does not
-- create application authority; the application must explicitly select one org.
INSERT INTO iam.organization_memberships (id, organization_id, principal_id, principal_kind, org_role)
VALUES ('00000000-0000-0000-0000-000000000831','00000000-0000-0000-0000-000000000021',
  'c:new_account','carbon','member');
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE selected uuid[]; BEGIN
  selected := iam_private.lock_account_login_organization_selection(
    'c:new_account','00000000-0000-0000-0000-000000000841',
    ARRAY['test_org'], 'app-alpha');
  IF selected IS DISTINCT FROM ARRAY['00000000-0000-0000-0000-000000000831'::uuid] THEN
    RAISE EXCEPTION 'first organization was not explicitly selected';
  END IF;
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'c:new_account','00000000-0000-0000-0000-000000000841',
      ARRAY['test_org','test_org'], 'app-alpha');
    RAISE EXCEPTION 'multiple organization selections were accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'c:new_account','00000000-0000-0000-0000-000000000841',
      '{}'::text[], 'app-alpha');
    RAISE EXCEPTION 'joining silently chose an organization';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
ROLLBACK;
