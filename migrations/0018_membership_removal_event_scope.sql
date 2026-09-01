-- Capture every directory membership changed as a side effect of a removal
-- while holding the same hierarchy/row locks used by the removal transition.

CREATE FUNCTION iam_private.lock_membership_removal_event_scope(
    p_organization_id uuid,
    p_membership_id uuid
)
RETURNS uuid[]
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_actor_id uuid := iam_private.current_principal_id();
    target_membership iam.organization_memberships%ROWTYPE;
    affected_membership_ids uuid[];
BEGIN
    IF p_organization_id IS NULL
       OR p_membership_id IS NULL
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id()
       OR current_actor_id IS NULL THEN
        RAISE EXCEPTION 'membership_removal_invalid' USING ERRCODE = '22023';
    END IF;

    SELECT membership.*
    INTO target_membership
    FROM iam.organization_memberships AS membership
    WHERE membership.organization_id = p_organization_id
      AND membership.id = p_membership_id
      AND membership.status = 'active';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'membership_version_mismatch' USING ERRCODE = 'P0001';
    END IF;
    IF NOT iam_private.has_organization_capability(
        p_organization_id,
        current_actor_id,
        CASE target_membership.principal_kind
            WHEN 'carbon' THEN 'members.remove'
            WHEN 'silicon' THEN 'silicons.remove'
            ELSE '__unsupported__'
        END
    ) THEN
        RAISE EXCEPTION 'membership_removal_forbidden' USING ERRCODE = '42501';
    END IF;

    IF target_membership.principal_kind = 'silicon' THEN
        SELECT membership.*
        INTO target_membership
        FROM iam.silicons AS silicon
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = silicon.organization_id
         AND membership.id = silicon.membership_id
         AND membership.principal_id = silicon.id
         AND membership.principal_kind = 'silicon'
        WHERE silicon.organization_id = p_organization_id
          AND silicon.membership_id = p_membership_id
          AND silicon.provisioning_status <> 'deleted'
          AND membership.status = 'active'
        FOR UPDATE OF silicon, membership;
    ELSE
        SELECT membership.*
        INTO target_membership
        FROM iam.organization_memberships AS membership
        WHERE membership.organization_id = p_organization_id
          AND membership.id = p_membership_id
          AND membership.principal_kind = 'carbon'
          AND membership.status = 'active'
        FOR UPDATE OF membership;
    END IF;
    IF NOT FOUND OR NOT iam_private.has_organization_capability(
        p_organization_id,
        current_actor_id,
        CASE target_membership.principal_kind
            WHEN 'carbon' THEN 'members.remove'
            WHEN 'silicon' THEN 'silicons.remove'
            ELSE '__unsupported__'
        END
    ) THEN
        RAISE EXCEPTION 'membership_removal_forbidden' USING ERRCODE = '42501';
    END IF;

    IF target_membership.principal_kind = 'silicon' THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(p_organization_id::text, 734921));

        PERFORM report.id
        FROM iam.silicons AS report
        WHERE report.organization_id = p_organization_id
          AND report.reports_to_membership_id = p_membership_id
          AND report.provisioning_status <> 'deleted'
        ORDER BY report.id
        FOR UPDATE OF report;

        PERFORM settings.membership_id
        FROM iam.carbon_membership_settings AS settings
        WHERE settings.organization_id = p_organization_id
          AND settings.first_silicon_membership_id = p_membership_id
        ORDER BY settings.membership_id
        FOR UPDATE OF settings;

        PERFORM access_grant.id
        FROM iam.extra_silicon_access_grants AS access_grant
        WHERE access_grant.organization_id = p_organization_id
          AND access_grant.silicon_membership_id = p_membership_id
          AND access_grant.revoked_at IS NULL
        ORDER BY access_grant.id
        FOR UPDATE OF access_grant;
    END IF;

    SELECT array_agg(affected.membership_id ORDER BY affected.membership_id)
    INTO affected_membership_ids
    FROM (
        SELECT p_membership_id AS membership_id
        UNION
        SELECT report.membership_id
        FROM iam.silicons AS report
        WHERE target_membership.principal_kind = 'silicon'
          AND report.organization_id = p_organization_id
          AND report.reports_to_membership_id = p_membership_id
          AND report.provisioning_status <> 'deleted'
        UNION
        SELECT settings.membership_id
        FROM iam.carbon_membership_settings AS settings
        WHERE target_membership.principal_kind = 'silicon'
          AND settings.organization_id = p_organization_id
          AND settings.first_silicon_membership_id = p_membership_id
        UNION
        SELECT access_grant.carbon_membership_id
        FROM iam.extra_silicon_access_grants AS access_grant
        WHERE target_membership.principal_kind = 'silicon'
          AND access_grant.organization_id = p_organization_id
          AND access_grant.silicon_membership_id = p_membership_id
          AND access_grant.revoked_at IS NULL
    ) AS affected;

    RETURN COALESCE(affected_membership_ids, ARRAY[p_membership_id]::uuid[]);
END;
$$;

REVOKE ALL ON FUNCTION iam_private.lock_membership_removal_event_scope(uuid, uuid) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.lock_membership_removal_event_scope(uuid, uuid) IS
    'Attests removal authority, serializes hierarchy side effects, and returns every membership whose directory relationship will change.';
