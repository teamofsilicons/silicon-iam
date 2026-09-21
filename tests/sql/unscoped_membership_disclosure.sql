-- Run after seed_protocol_rows and runtime grants in a disposable database.
-- Fixtures are rolled back. The projection runs under the restricted API role.
BEGIN;
INSERT INTO iam.application_requested_scopes(application_id,scope)
SELECT 'test_org>app-alpha',unnest(ARRAY['self.membership.read','roles.read']);
INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id)
SELECT 'test_org>app-alpha',unnest(ARRAY['self.membership.read','roles.read']),'test_carbon';
INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES('00000000-0000-0000-0000-000000000101','roles.read');
INSERT INTO iam.oauth_consent_grant_scopes(consent_grant_id,scope) VALUES('00000000-0000-0000-0000-000000000071','roles.read');
SELECT set_config('iam.principal_id','test_carbon',true),
 set_config('iam.application_id','test_org>app-alpha',true),set_config('iam.organization_id','',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','test_carbon','test_org>app-alpha',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'org_role' IS NOT NULL THEN RAISE EXCEPTION 'legacy roles.read disclosed an organization role'; END IF;
END $$;
RESET ROLE;
INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES('00000000-0000-0000-0000-000000000101','self.membership.read');
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','test_carbon','test_org>app-alpha',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'org_role' IS NOT NULL THEN RAISE EXCEPTION 'membership disclosure did not require renewed consent'; END IF;
END $$;
RESET ROLE;
INSERT INTO iam.oauth_consent_grant_scopes(consent_grant_id,scope) VALUES('00000000-0000-0000-0000-000000000071','self.membership.read');
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','test_carbon','test_org>app-alpha',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'org_role' IS DISTINCT FROM 'owner' THEN RAISE EXCEPTION 'consented self.membership.read did not disclose organization role'; END IF;
END $$;
RESET ROLE;
DELETE FROM iam.access_token_scopes WHERE access_token_id='00000000-0000-0000-0000-000000000101' AND scope='self.membership.read';
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','test_carbon','test_org>app-alpha',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'org_role' IS NOT NULL THEN RAISE EXCEPTION 'scope approval and consent expanded an older token'; END IF;
END $$;
RESET ROLE;
INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES('00000000-0000-0000-0000-000000000101','self.membership.read');
UPDATE iam.application_approved_scopes SET revoked_at=transaction_timestamp(),revoked_by_carbon_id='test_carbon' WHERE application_id='test_org>app-alpha' AND scope='self.membership.read';
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','test_carbon','test_org>app-alpha',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'org_role' IS NOT NULL THEN RAISE EXCEPTION 'revoked application scope retained organization disclosure'; END IF;
END $$;
RESET ROLE;
ROLLBACK;

-- Run after seed_protocol_rows and runtime grants in a disposable database.
-- Fixtures are rolled back. The projection runs under the restricted API role.
BEGIN;
INSERT INTO iam.organization_tags(id,organization_id,name,normalized_name,created_by_membership_id)
VALUES('00000000-0000-0000-0000-000000000151','00000000-0000-0000-0000-000000000021','Design','design','00000000-0000-0000-0000-000000000031');
INSERT INTO iam.membership_tags(organization_id,membership_id,tag_id,assigned_by_membership_id)
VALUES('00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000031','00000000-0000-0000-0000-000000000151','00000000-0000-0000-0000-000000000031');
INSERT INTO iam.application_requested_scopes(application_id,scope)
SELECT 'test_org>app-alpha',unnest(ARRAY['self.tags.read','memberships.read']);
INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id)
SELECT 'test_org>app-alpha',unnest(ARRAY['self.tags.read','memberships.read']),'test_carbon';
INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES('00000000-0000-0000-0000-000000000101','memberships.read');
INSERT INTO iam.oauth_consent_grant_scopes(consent_grant_id,scope) VALUES('00000000-0000-0000-0000-000000000071','memberships.read');
SELECT set_config('iam.principal_id','test_carbon',true),
 set_config('iam.application_id','test_org>app-alpha',true),set_config('iam.organization_id','',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','test_carbon','test_org>app-alpha',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'tags' IS NOT NULL THEN RAISE EXCEPTION 'legacy memberships.read disclosed an membership tags'; END IF;
END $$;
RESET ROLE;
INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES('00000000-0000-0000-0000-000000000101','self.tags.read');
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','test_carbon','test_org>app-alpha',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'tags' IS NOT NULL THEN RAISE EXCEPTION 'tag disclosure did not require renewed consent'; END IF;
END $$;
RESET ROLE;
INSERT INTO iam.oauth_consent_grant_scopes(consent_grant_id,scope) VALUES('00000000-0000-0000-0000-000000000071','self.tags.read');
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','test_carbon','test_org>app-alpha',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'tags' IS DISTINCT FROM '[{"id": "00000000-0000-0000-0000-000000000151", "name": "Design"}]' THEN RAISE EXCEPTION 'consented self.tags.read did not disclose membership tags'; END IF;
END $$;
RESET ROLE;
DELETE FROM iam.access_token_scopes WHERE access_token_id='00000000-0000-0000-0000-000000000101' AND scope='self.tags.read';
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','test_carbon','test_org>app-alpha',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'tags' IS NOT NULL THEN RAISE EXCEPTION 'scope approval and consent expanded an older token'; END IF;
END $$;
RESET ROLE;
INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES('00000000-0000-0000-0000-000000000101','self.tags.read');
UPDATE iam.application_approved_scopes SET revoked_at=transaction_timestamp(),revoked_by_carbon_id='test_carbon' WHERE application_id='test_org>app-alpha' AND scope='self.tags.read';
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE listed jsonb; BEGIN
 listed:=iam_private.list_current_application_authorizations('00000000-0000-0000-0000-000000000101','test_carbon','test_org>app-alpha',1);
 IF jsonb_array_length(listed) IS DISTINCT FROM 1 OR listed->0->>'tags' IS NOT NULL THEN RAISE EXCEPTION 'revoked application scope retained organization disclosure'; END IF;
END $$;
RESET ROLE;
ROLLBACK;
