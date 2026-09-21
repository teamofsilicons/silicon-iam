-- Run against a migrated disposable database with runtime-grants.sql applied.
-- Reproduces a Silicon member with no capabilities, as used by ordinary apps.
BEGIN;
INSERT INTO iam.principals(id, kind, status, activated_at) VALUES
 ('self-profile-owner', 'carbon', 'active', now()),
 ('self:self-profile-test', 'silicon', 'active', now()),
 ('peer:self-profile-test', 'silicon', 'active', now());
INSERT INTO iam.carbons(id, carbon_id, display_name) VALUES
 ('self-profile-owner', 'self-profile-owner', 'Owner');
INSERT INTO iam.organizations(id, org_id, created_by_carbon_id, name) VALUES
 ('01090000-0000-0000-0000-000000000010', 'self-profile-test', 'self-profile-owner', 'Self Profile Test');
INSERT INTO iam.organization_memberships(id, organization_id, principal_id, principal_kind, org_role) VALUES
 ('01090000-0000-0000-0000-000000000011', '01090000-0000-0000-0000-000000000010', 'self-profile-owner', 'carbon', 'owner'),
 ('01090000-0000-0000-0000-000000000012', '01090000-0000-0000-0000-000000000010', 'self:self-profile-test', 'silicon', 'member'),
 ('01090000-0000-0000-0000-000000000013', '01090000-0000-0000-0000-000000000010', 'peer:self-profile-test', 'silicon', 'member');
INSERT INTO iam.silicons(id, organization_id, membership_id, organization_handle, silicon_handle, display_name) VALUES
 ('self:self-profile-test', '01090000-0000-0000-0000-000000000010', '01090000-0000-0000-0000-000000000012', 'self-profile-test', 'self', 'Self'),
 ('peer:self-profile-test', '01090000-0000-0000-0000-000000000010', '01090000-0000-0000-0000-000000000013', 'self-profile-test', 'peer', 'Peer');
SELECT set_config('iam.principal_id', 'self:self-profile-test', true),
       set_config('iam.organization_id', '01090000-0000-0000-0000-000000000010', true);
SET LOCAL ROLE silicon_iam_api;
DO $$
DECLARE
    v_org constant uuid := '01090000-0000-0000-0000-000000000010';
    v_self constant text := 'self:self-profile-test';
    v_member constant uuid := '01090000-0000-0000-0000-000000000012';
    v_count integer;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM iam.silicons WHERE id = v_self) THEN
        RAISE EXCEPTION 'fixture must be visible to its own Silicon';
    END IF;
    -- The old path fails before the mutation: locking adds organization-only
    -- UPDATE policies. The fix must not broaden those policies.
    SELECT count(*) INTO v_count FROM (
        SELECT id FROM iam.silicons WHERE id = v_self FOR UPDATE
    ) AS locked;
    IF v_count <> 0 THEN RAISE EXCEPTION 'ordinary Silicon gained directory UPDATE authority'; END IF;
    SELECT count(*) INTO v_count FROM (
        SELECT id FROM iam.organization_memberships WHERE id = v_member FOR UPDATE
    ) AS locked;
    IF v_count <> 0 THEN RAISE EXCEPTION 'ordinary Silicon gained membership UPDATE authority'; END IF;

    IF iam_private.lock_silicon_self_profile(v_org, v_self) <> v_member THEN
        RAISE EXCEPTION 'self lock did not return its exact membership';
    END IF;
    IF NOT iam_private.update_silicon_self_profile(v_org, v_self, 1, 'Maharaj', 'Asia/Kolkata', false, NULL, true, 'https://example.com/chef.png') THEN
        RAISE EXCEPTION 'self profile update failed';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM iam.silicons WHERE id = v_self AND version = 2
        AND timezone_id = 'Asia/Kolkata' AND display_name = 'Maharaj'
        AND profile_photo_override_uri = 'https://example.com/chef.png'
        AND reports_to_membership_id IS NULL AND provisioning_status = 'active') THEN
        RAISE EXCEPTION 'self profile projection incorrect';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM iam.organization_memberships WHERE id = v_member
        AND version = 2 AND authz_epoch = 1 AND org_role = 'member'
        AND COALESCE(to_jsonb(organization_memberships)->>'job_description',to_jsonb(organization_memberships)->>'job_role') = '') THEN
        RAISE EXCEPTION 'membership version or authority changed incorrectly';
    END IF;
    IF iam_private.update_silicon_self_profile(v_org, v_self, 2, NULL, 'Asia/Kolkata', false, NULL, false, NULL) THEN
        RAISE EXCEPTION 'no-op profile update was accepted';
    END IF;
    IF iam_private.update_silicon_self_profile(v_org, v_self, 1, NULL, 'Europe/London', false, NULL, false, NULL) THEN
        RAISE EXCEPTION 'stale version overwrote the profile';
    END IF;
    BEGIN
        PERFORM iam_private.update_silicon_self_profile(v_org, v_self, 2, NULL, 'Invalid/Timezone', false, NULL, false, NULL);
        RAISE EXCEPTION 'invalid timezone was accepted';
    EXCEPTION WHEN invalid_parameter_value THEN NULL;
    END;
    IF NOT iam_private.update_silicon_self_profile(v_org, v_self, 2, NULL, NULL, false, NULL, true, NULL) THEN
        RAISE EXCEPTION 'nullable profile fields could not be cleared';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM iam.silicons WHERE id = v_self AND version = 3
        AND profile_photo_override_uri IS NULL AND timezone_id = 'Asia/Kolkata') THEN
        RAISE EXCEPTION 'cleared profile projection incorrect';
    END IF;
    BEGIN
        PERFORM iam_private.lock_silicon_self_profile(v_org, 'peer:self-profile-test');
        RAISE EXCEPTION 'self helper locked another Silicon';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        PERFORM iam_private.update_silicon_self_profile(v_org, 'peer:self-profile-test', 1, NULL, 'Asia/Kolkata', false, NULL, false, NULL);
        RAISE EXCEPTION 'self helper edited another Silicon';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    PERFORM set_config('iam.organization_id', '', true);
    BEGIN
        PERFORM iam_private.lock_silicon_self_profile(v_org, v_self);
        RAISE EXCEPTION 'self helper ignored selected organization';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    PERFORM set_config('iam.organization_id', v_org::text, true);
END $$;
RESET ROLE;
UPDATE iam.organization_memberships SET status = 'suspended', suspended_at = now()
WHERE id = '01090000-0000-0000-0000-000000000012';
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
    BEGIN
        PERFORM iam_private.lock_silicon_self_profile('01090000-0000-0000-0000-000000000010', 'self:self-profile-test');
        RAISE EXCEPTION 'inactive membership retained self-profile authority';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
END $$;
ROLLBACK;
