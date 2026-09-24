-- Run after the application protocol fixture. All changes roll back.
BEGIN;
SELECT set_config('iam.principal_id','c:test_admin',true),
       set_config('iam.organization_id','00000000-0000-0000-0000-000000000021',true),
       set_config('iam.application_id','app-alpha',true);
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM iam_private.list_organization_member_webhook_authorizations(
 '00000000-0000-0000-0000-000000000021',ARRAY['00000000-0000-0000-0000-000000000032'::uuid],transaction_timestamp())) THEN
 RAISE EXCEPTION 'self scopes leaked to a different member'; END IF;
 IF iam_private.application_webhook_has_event_scope('00000000-0000-0000-0000-000000000141','00000000-0000-0000-0000-000000000021','organization.invitation.created.v1',transaction_timestamp()) THEN
 RAISE EXCEPTION 'invitation event bypassed organization permission'; END IF;
END $$;
INSERT INTO iam.application_requested_scopes(application_id,scope) SELECT 'app-alpha',scope FROM unnest(ARRAY['directory.carbons.read','directory.profiles.read','directory.silicons.read','organization.invitations.read']) scope;
INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) SELECT 'app-alpha',scope,'c:test_carbon' FROM unnest(ARRAY['directory.carbons.read','directory.profiles.read','directory.silicons.read','organization.invitations.read']) scope;
INSERT INTO iam.oauth_consent_grant_scopes(consent_grant_id,scope) SELECT '00000000-0000-0000-0000-000000000071',scope FROM unnest(ARRAY['directory.carbons.read','directory.profiles.read','directory.silicons.read','organization.invitations.read']) scope;
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE scopes text[]; BEGIN
 SELECT array_agg(scope ORDER BY scope) INTO scopes FROM iam_private.list_organization_member_webhook_authorizations(
 '00000000-0000-0000-0000-000000000021',ARRAY['00000000-0000-0000-0000-000000000032'::uuid],transaction_timestamp());
 IF scopes IS DISTINCT FROM ARRAY['directory.carbons.read','directory.profiles.read','organization.invitations.read'] THEN
 RAISE EXCEPTION 'directory member scopes incorrect: %',scopes; END IF;
 SELECT array_agg(scope ORDER BY scope) INTO scopes FROM iam_private.list_profile_webhook_authorization_scopes('c:test_admin');
 IF scopes IS DISTINCT FROM ARRAY['directory.carbons.read','directory.profiles.read'] THEN
 RAISE EXCEPTION 'directory profile scopes incorrect: %',scopes; END IF;
 IF NOT EXISTS(SELECT 1 FROM iam_private.current_application_resource_scopes('app-alpha','c:test_admin','00000000-0000-0000-0000-000000000021') scope WHERE scope='directory.profiles.read') THEN
 RAISE EXCEPTION 'directory replay incorrectly rejected'; END IF;
 IF NOT iam_private.application_webhook_has_event_scope('00000000-0000-0000-0000-000000000141','00000000-0000-0000-0000-000000000021','organization.invitation.created.v1',transaction_timestamp()) THEN
 RAISE EXCEPTION 'authorized invitation event rejected'; END IF;
 IF iam_private.application_webhook_has_event_scope('00000000-0000-0000-0000-000000000141','00000000-0000-0000-0000-000000000021','organization.membership.profile_updated.v1',transaction_timestamp()) THEN
 RAISE EXCEPTION 'Silicon-only unfiltered payload admitted to application'; END IF;
END $$;
RESET ROLE;
UPDATE iam.application_approved_scopes SET revoked_at=transaction_timestamp(),revoked_by_carbon_id='c:test_carbon' WHERE application_id='app-alpha' AND scope='directory.profiles.read';
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM iam_private.current_application_resource_scopes('app-alpha','c:test_admin','00000000-0000-0000-0000-000000000021') scope WHERE scope='directory.profiles.read') THEN
 RAISE EXCEPTION 'revoked directory permission survived replay'; END IF;
END $$;
ROLLBACK;
