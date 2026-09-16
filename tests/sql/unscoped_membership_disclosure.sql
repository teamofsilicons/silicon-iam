-- Run after seed_protocol_rows and runtime grants in a disposable database.
-- Fixtures are rolled back. The projection runs under the restricted API role.
BEGIN;
INSERT INTO iam.application_requested_scopes(application_id,scope)
SELECT '00000000-0000-0000-0000-000000000011',unnest(ARRAY['self.membership.read','roles.read']);
INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id)
SELECT '00000000-0000-0000-0000-000000000011',unnest(ARRAY['self.membership.read','roles.read']),'00000000-0000-0000-0000-000000000001';
INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES('00000000-0000-0000-0000-000000000101','roles.read');
INSERT INTO iam.oauth_consent_grant_scopes(consent_grant_id,scope) VALUES('00000000-0000-0000-0000-000000000071','roles.read');
SELECT set_config('iam.principal_id','00000000-0000-0000-0000-000000000001',true),
 set_config('iam.application_id','00000000-0000-0000-0000-000000000011',true),set_config('iam.organization_id','',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000011',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'org_role' IS NOT NULL THEN RAISE EXCEPTION 'legacy roles.read disclosed an organization role'; END IF;
END $$;
RESET ROLE;
INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES('00000000-0000-0000-0000-000000000101','self.membership.read');
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000011',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'org_role' IS NOT NULL THEN RAISE EXCEPTION 'membership disclosure did not require renewed consent'; END IF;
END $$;
RESET ROLE;
INSERT INTO iam.oauth_consent_grant_scopes(consent_grant_id,scope) VALUES('00000000-0000-0000-0000-000000000071','self.membership.read');
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000011',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'org_role' IS DISTINCT FROM 'owner' THEN RAISE EXCEPTION 'consented self.membership.read did not disclose organization role'; END IF;
END $$;
RESET ROLE;
DELETE FROM iam.access_token_scopes WHERE access_token_id='00000000-0000-0000-0000-000000000101' AND scope='self.membership.read';
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000011',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'org_role' IS NOT NULL THEN RAISE EXCEPTION 'scope approval and consent expanded an older token'; END IF;
END $$;
RESET ROLE;
INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES('00000000-0000-0000-0000-000000000101','self.membership.read');
UPDATE iam.application_approved_scopes SET revoked_at=transaction_timestamp(),revoked_by_carbon_id='00000000-0000-0000-0000-000000000001' WHERE application_id='00000000-0000-0000-0000-000000000011' AND scope='self.membership.read';
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000011',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'org_role' IS NOT NULL THEN RAISE EXCEPTION 'revoked application scope retained organization disclosure'; END IF;
END $$;
RESET ROLE;
ROLLBACK;
