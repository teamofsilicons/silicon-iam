-- Run after seed_protocol_rows against a disposable migrated database.
-- Every fixture and grant change is rolled back.
BEGIN;
UPDATE iam.organizations SET trusted_org=true WHERE id='00000000-0000-0000-0000-000000000021';
INSERT INTO iam.principals (id, kind, status, activated_at) VALUES
  ('new_account', 'carbon', 'active', transaction_timestamp());
INSERT INTO iam.carbons (id, carbon_id, display_name) VALUES
  ('new_account', 'new_account', 'New Account');
INSERT INTO iam.authentication_sessions (
  id, subject_principal_id, subject_kind, authentication_method, assurance_level,
  subject_auth_epoch, idle_expires_at, absolute_expires_at
) VALUES (
  '00000000-0000-0000-0000-000000000841',
  'new_account', 'carbon', 'email_otp', 1, 1,
  transaction_timestamp() + interval '1 day', transaction_timestamp() + interval '2 days'
);
INSERT INTO iam.application_requested_scopes (application_id, scope) VALUES
  ('test_org>app-alpha', 'organizations.create');
INSERT INTO iam.application_approved_scopes (application_id, scope, approved_by_carbon_id) VALUES
  ('test_org>app-alpha', 'organizations.create', 'test_carbon');
SELECT set_config('iam.principal_id','new_account',true),
  set_config('iam.application_id','',true), set_config('iam.organization_id','',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE selected uuid[]; BEGIN
  selected := iam_private.lock_account_login_organization_selection(
    'new_account','00000000-0000-0000-0000-000000000841',
    '{}'::text[], 'test_org>app-alpha');
  IF selected IS DISTINCT FROM '{}'::uuid[] THEN
    RAISE EXCEPTION 'new Carbon account cannot consent without memberships';
  END IF;
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'new_account','00000000-0000-0000-0000-000000000841',
      '{}'::text[], 'test_org>app-beta');
    RAISE EXCEPTION 'ordinary application accepted an empty selection';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  BEGIN
    PERFORM iam_private.lock_login_organization_selection(
      'new_account','00000000-0000-0000-0000-000000000841',
      '{}'::text[]);
    RAISE EXCEPTION 'legacy selector lost its nonempty requirement';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'new_account','00000000-0000-0000-0000-000000000041',
      '{}'::text[], 'test_org>app-alpha');
    RAISE EXCEPTION 'another account session allowed empty selection';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'new_account','00000000-0000-0000-0000-000000000841',
      NULL::text[], 'test_org>app-alpha');
    RAISE EXCEPTION 'missing explicit selection was accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
SELECT set_config('iam.application_id','test_org>app-alpha',true);
DO $$ BEGIN
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'new_account','00000000-0000-0000-0000-000000000841',
      '{}'::text[], 'test_org>app-alpha');
    RAISE EXCEPTION 'application context was able to authorize itself';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
UPDATE iam.application_approved_scopes SET revoked_at=transaction_timestamp(),
  revoked_by_carbon_id='test_carbon'
WHERE application_id='test_org>app-alpha' AND scope='organizations.create';
SELECT set_config('iam.application_id','',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
  BEGIN
    PERFORM iam_private.lock_account_login_organization_selection(
      'new_account','00000000-0000-0000-0000-000000000841',
      '{}'::text[], 'test_org>app-alpha');
    RAISE EXCEPTION 'revoked onboarding permission was accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
INSERT INTO iam.application_requested_scopes (application_id, scope) VALUES
  ('test_org>app-alpha', 'organizations.join');
INSERT INTO iam.application_approved_scopes (application_id, scope, approved_by_carbon_id) VALUES
  ('test_org>app-alpha', 'organizations.join', 'test_carbon');
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
  IF iam_private.lock_account_login_organization_selection(
    'new_account','00000000-0000-0000-0000-000000000841',
    '{}'::text[], 'test_org>app-alpha') IS DISTINCT FROM '{}'::uuid[] THEN
    RAISE EXCEPTION 'join-only onboarding was rejected';
  END IF;
END $$;
RESET ROLE;
INSERT INTO iam.oauth_consent_grants (
  id, application_id, subject_principal_id, subject_kind,
  parent_authentication_session_id, selected_membership_ids
) VALUES (
  '00000000-0000-0000-0000-000000000871', 'test_org>app-alpha',
  'new_account', 'carbon',
  '00000000-0000-0000-0000-000000000841', '{}'
);
INSERT INTO iam.oauth_consent_grant_scopes (consent_grant_id, scope)
SELECT '00000000-0000-0000-0000-000000000871', scope
FROM unnest(ARRAY['self.identity.read','self.profile.read','organizations.join']) scope;
INSERT INTO iam.access_tokens (
  id, token_class, token_digest, digest_key_version, token_prefix,
  authentication_session_id, subject_principal_id, subject_kind,
  client_application_id, audience, audience_application_id,
  subject_auth_epoch, client_auth_epoch, expires_at
) VALUES (
  '00000000-0000-0000-0000-000000000881', 'application_access', decode(repeat('81',32),'hex'), 1, 'oat_onboard1',
  '00000000-0000-0000-0000-000000000841', 'new_account', 'carbon',
  'test_org>app-alpha', 'test_org>app-alpha', 'test_org>app-alpha',
  1, 1, transaction_timestamp() + interval '15 minutes'
);
INSERT INTO iam.access_token_scopes (access_token_id, scope)
SELECT '00000000-0000-0000-0000-000000000881', scope
FROM unnest(ARRAY['self.identity.read','self.profile.read','organizations.join']) scope;
SELECT set_config('iam.principal_id','test_org>app-alpha',true),
  set_config('iam.application_id','test_org>app-alpha',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam_private.lock_current_application_oauth_subject_authority(
    'test_org>app-alpha','00000000-0000-0000-0000-000000000871',
    '00000000-0000-0000-0000-000000000841','new_account',
    'carbon',NULL,NULL) WHERE subject_public_id='new_account' AND org_id IS NULL) THEN
    RAISE EXCEPTION 'exchange/refresh authority required a membership for new Carbon';
  END IF;
END $$;
SELECT set_config('iam.principal_id','new_account',true);
DO $$ BEGIN
  IF iam_private.list_current_application_authorizations(
    '00000000-0000-0000-0000-000000000881','new_account',
    'test_org>app-alpha',1) IS DISTINCT FROM '[]'::jsonb THEN
    RAISE EXCEPTION 'active zero-membership token did not have an empty authorization list';
  END IF;
END $$;
RESET ROLE;
INSERT INTO iam.organization_memberships (id, organization_id, principal_id, principal_kind, org_role)
VALUES ('00000000-0000-0000-0000-000000000831','00000000-0000-0000-0000-000000000021',
  'new_account','carbon','member');
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
  IF iam_private.application_token_allows_membership(
    '00000000-0000-0000-0000-000000000881','00000000-0000-0000-0000-000000000831') THEN
    RAISE EXCEPTION 'joining an organization implicitly granted application access';
  END IF;
  IF iam_private.list_current_application_authorizations(
    '00000000-0000-0000-0000-000000000881','new_account',
    'test_org>app-alpha',1) IS DISTINCT FROM '[]'::jsonb THEN
    RAISE EXCEPTION 'new membership leaked before explicit reconsent';
  END IF;
END $$;
RESET ROLE;
ROLLBACK;
