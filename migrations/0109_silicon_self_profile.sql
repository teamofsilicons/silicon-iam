-- Self-profile editing must not depend on organization directory authority.
-- PostgreSQL applies UPDATE policies to SELECT FOR UPDATE too, so the API
-- role cannot even lock its own Silicon or membership rows through ordinary
-- directory RLS. Keep that authority limited to these profile-only helpers.
CREATE FUNCTION iam_private.lock_silicon_self_profile(
    p_organization_id uuid,
    p_silicon_id uuid
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    v_membership_id uuid;
BEGIN
    IF p_silicon_id IS NULL OR p_organization_id IS NULL
       OR p_silicon_id IS DISTINCT FROM iam_private.current_principal_id()
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id() THEN
        RAISE EXCEPTION 'silicon_self_profile_forbidden' USING ERRCODE = '42501';
    END IF;

    SELECT membership.id INTO v_membership_id
    FROM iam.silicons AS silicon
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = silicon.organization_id
     AND membership.id = silicon.membership_id
     AND membership.principal_id = silicon.id
     AND membership.principal_kind = 'silicon'
     AND (to_jsonb(membership)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(silicon)->>'testing_environment_id')
    JOIN iam.organizations AS organization ON organization.id = silicon.organization_id
     AND (to_jsonb(organization)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(silicon)->>'testing_environment_id')
    JOIN iam.principals AS principal ON principal.id = silicon.id AND principal.kind = 'silicon'
     AND (to_jsonb(principal)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(silicon)->>'testing_environment_id')
    WHERE silicon.organization_id = p_organization_id
      AND silicon.id = p_silicon_id
      AND silicon.provisioning_status <> 'deleted'
      AND membership.status = 'active'
      AND organization.status = 'active'
      AND principal.status = 'active'
    FOR UPDATE OF silicon, membership;

    IF v_membership_id IS NULL THEN
        RAISE EXCEPTION 'silicon_self_profile_forbidden' USING ERRCODE = '42501';
    END IF;
    RETURN v_membership_id;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.lock_silicon_self_profile(uuid, uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.update_silicon_self_profile(
    p_organization_id uuid,
    p_silicon_id uuid,
    p_expected_version bigint,
    p_display_name text,
    p_timezone text,
    p_set_description boolean,
    p_description text,
    p_set_profile_photo boolean,
    p_profile_photo text
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    v_membership_id uuid;
BEGIN
    -- Recheck authority in this helper too; callers cannot bypass the locking
    -- helper and use the update function against a different identity.
    v_membership_id := iam_private.lock_silicon_self_profile(p_organization_id, p_silicon_id);

    UPDATE iam.silicons
    SET display_name = COALESCE(p_display_name, display_name),
        timezone_id = COALESCE(p_timezone, timezone_id),
        description = CASE WHEN p_set_description THEN p_description ELSE description END,
        profile_photo_override_uri = CASE WHEN p_set_profile_photo THEN p_profile_photo ELSE profile_photo_override_uri END,
        updated_at = transaction_timestamp()
    WHERE organization_id = p_organization_id AND id = p_silicon_id
      AND version = p_expected_version
      AND (
          (p_display_name IS NOT NULL AND display_name IS DISTINCT FROM p_display_name)
          OR (p_timezone IS NOT NULL AND timezone_id IS DISTINCT FROM p_timezone)
          OR (p_set_description AND description IS DISTINCT FROM p_description)
          OR (p_set_profile_photo AND profile_photo_override_uri IS DISTINCT FROM p_profile_photo)
      );
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    -- Profile changes version the membership projection without revoking its
    -- authorization. The API records both snapshots and their events in the
    -- same transaction after this narrowly scoped write.
    UPDATE iam.organization_memberships
    SET updated_at = transaction_timestamp()
    WHERE organization_id = p_organization_id AND id = v_membership_id;
    RETURN true;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.update_silicon_self_profile(uuid, uuid, bigint, text, text, boolean, text, boolean, text) FROM PUBLIC;

DO $$ BEGIN
    IF to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION iam_private.lock_silicon_self_profile(uuid, uuid),
            iam_private.update_silicon_self_profile(uuid, uuid, bigint, text, text, boolean, text, boolean, text)
            TO silicon_iam_api;
    END IF;
END $$;
