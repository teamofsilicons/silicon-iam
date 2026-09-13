-- Runs inside the catalog fixture; every change is rolled back.
BEGIN;
SELECT set_config('iam.principal_id','00000000-0000-0000-0000-000000000001',true),
       set_config('iam.organization_id','00000000-0000-0000-0000-000000000021',true),
       set_config('iam.application_id','00000000-0000-0000-0000-000000000011',true);
SET LOCAL ROLE silicon_iam_api;
DO $$
BEGIN
 IF iam_private.application_iam_scope_allowed('00000000-0000-0000-0000-000000000011','organization.invitations.create') THEN
   RAISE EXCEPTION 'untrusted application acquired restricted permission';
 END IF;
 BEGIN
   PERFORM iam_private.configure_application_scopes('00000000-0000-0000-0000-000000000011',
     '{"iam":["self.identity.read","organization.invitations.create"],"external":[]}',
     '00000000-0000-0000-0000-000000000001');
   RAISE EXCEPTION 'untrusted application could request a restricted permission';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 PERFORM iam_private.configure_application_scopes('00000000-0000-0000-0000-000000000011',
   '{"iam":["self.identity.read","organizations.create"],"external":[]}',
   '00000000-0000-0000-0000-000000000001');
 IF EXISTS (SELECT 1 FROM iam.application_approved_scopes WHERE application_id='00000000-0000-0000-0000-000000000011' AND scope='organizations.create' AND revoked_at IS NULL) THEN
   RAISE EXCEPTION 'critical write permission bypassed review';
 END IF;
END $$;
RESET ROLE;
UPDATE iam.organizations SET trusted_org=true WHERE id='00000000-0000-0000-0000-000000000021';
SET LOCAL ROLE silicon_iam_api;
SELECT iam_private.configure_application_scopes('00000000-0000-0000-0000-000000000011',
 '{"iam":["self.identity.read","organization.invitations.create","organization.silicons.create"],"external":[]}',
 '00000000-0000-0000-0000-000000000001');
RESET ROLE;
-- A database-approved grant still requires user consent; policy removal revokes
-- both approval and existing tokens, and cannot be restored by another reviewer.
INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES
 ('00000000-0000-0000-0000-000000000011','organization.invitations.create','00000000-0000-0000-0000-000000000001');
INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES
 ('00000000-0000-0000-0000-000000000101','organization.invitations.create');
UPDATE iam.access_tokens SET revoked_at=NULL,revocation_reason=NULL WHERE id='00000000-0000-0000-0000-000000000101';
UPDATE iam.organizations SET allowed_restricted_iam_scopes=array_remove(allowed_restricted_iam_scopes,'organization.invitations.create')
 WHERE id='00000000-0000-0000-0000-000000000021';
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM iam.application_approved_scopes WHERE application_id='00000000-0000-0000-0000-000000000011' AND scope='organization.invitations.create' AND revoked_at IS NULL) THEN
   RAISE EXCEPTION 'policy removal retained approval';
 END IF;
 IF EXISTS(SELECT 1 FROM iam.access_tokens WHERE id='00000000-0000-0000-0000-000000000101' AND revoked_at IS NULL) THEN
   RAISE EXCEPTION 'policy removal retained token';
 END IF;
 IF NOT iam_private.application_iam_scope_allowed('00000000-0000-0000-0000-000000000011','organization.silicons.create') THEN
   RAISE EXCEPTION 'removing one permission removed another';
 END IF;
 BEGIN
   INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES
     ('00000000-0000-0000-0000-000000000011','organization.invitations.create','00000000-0000-0000-0000-000000000001');
   RAISE EXCEPTION 'approval bypassed narrowed policy';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
UPDATE iam.organizations SET trusted_org=false WHERE id='00000000-0000-0000-0000-000000000021';
DO $$ BEGIN
 IF iam_private.application_iam_scope_allowed('00000000-0000-0000-0000-000000000011','organization.silicons.create') THEN
   RAISE EXCEPTION 'removing trust retained restricted permission';
 END IF;
 IF NOT iam_private.application_iam_scope_allowed('00000000-0000-0000-0000-000000000011','organizations.create') THEN
   RAISE EXCEPTION 'unrestricted scope became unavailable';
 END IF;
END $$;
-- Restoring policy is eligibility only; prior approval and token revocations
-- survive so the application cannot silently regain historical authority.
UPDATE iam.organizations SET trusted_org=true,
 allowed_restricted_iam_scopes=array_append(allowed_restricted_iam_scopes,'organization.invitations.create')
 WHERE id='00000000-0000-0000-0000-000000000021';
DO $$ BEGIN
 IF NOT iam_private.application_iam_scope_allowed('00000000-0000-0000-0000-000000000011','organization.invitations.create') THEN
   RAISE EXCEPTION 'restored policy did not restore request eligibility';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM iam.application_approved_scopes
   WHERE application_id='00000000-0000-0000-0000-000000000011'
   AND scope='organization.invitations.create' AND revoked_at IS NOT NULL
   AND revoked_by_policy AND revoked_by_carbon_id IS NULL) THEN
   RAISE EXCEPTION 'policy revocation lost its system attribution';
 END IF;
 IF EXISTS (SELECT 1 FROM iam.application_approved_scopes
   WHERE application_id='00000000-0000-0000-0000-000000000011'
   AND scope='organization.invitations.create' AND revoked_at IS NULL)
 OR EXISTS (SELECT 1 FROM iam.access_tokens
   WHERE id='00000000-0000-0000-0000-000000000101' AND revoked_at IS NULL) THEN
   RAISE EXCEPTION 'policy restoration resurrected revoked authority';
 END IF;
END $$;
ROLLBACK;
