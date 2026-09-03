-- Locking the Silicon-webhook audience for a Carbon profile change.
--
-- A Carbon profile update captures, inside the mutation transaction, every
-- organization membership the Carbon holds and the active tags on each, so the
-- Silicon event it emits carries an audience that cannot drift. That capture
-- was written as two locking SELECTs issued by the API role, and neither could
-- work from that role:
--
-- A locking clause makes PostgreSQL apply the table's UPDATE policies on top of
-- its SELECT policies. The membership UPDATE policy requires a selected
-- organization, and a profile update is not organization-scoped -- the route
-- never selects one -- so the lock silently matched no memberships at all and
-- the capture returned an empty audience every time. No error, no event, no
-- Silicon ever told that a member's profile changed.
--
-- Had the loop ever run, its second statement would have failed outright: any
-- locking clause also requires write privilege on the locked table, and the API
-- role holds only SELECT on iam.membership_tags because assignments belong to
-- the governed tag-change machinery.
--
-- Both are the same problem -- a lock the API role cannot take -- so both are
-- answered the same way the rest of this schema answers it, with a fixed-path
-- boundary that owns the lock. The authority is narrow: a Carbon may capture
-- only its own audience.
CREATE FUNCTION iam_private.lock_carbon_profile_silicon_routes(
    p_carbon_id uuid
)
RETURNS TABLE (
    organization_id uuid,
    membership_id uuid,
    affected_tag_ids uuid[]
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    membership_record record;
BEGIN
    IF p_carbon_id IS NULL
       OR iam_private.current_principal_id() IS DISTINCT FROM p_carbon_id THEN
        RAISE EXCEPTION 'carbon_profile_scope_forbidden' USING ERRCODE = '42501';
    END IF;

    -- Memberships before tags, the order every other tag transition takes.
    FOR membership_record IN
        SELECT
            membership.organization_id AS organization_id,
            membership.id AS membership_id
        FROM iam.organization_memberships AS membership
        JOIN iam.organizations AS organization
          ON organization.id = membership.organization_id
         AND organization.status = 'active'
        WHERE membership.principal_id = p_carbon_id
          AND membership.principal_kind = 'carbon'
          AND membership.status = 'active'
        ORDER BY membership.organization_id, membership.id
        FOR SHARE OF membership, organization
    LOOP
        organization_id := membership_record.organization_id;
        membership_id := membership_record.membership_id;

        WITH locked AS (
            SELECT assignment.tag_id
            FROM iam.membership_tags AS assignment
            JOIN iam.organization_tags AS tag
              ON tag.organization_id = assignment.organization_id
             AND tag.id = assignment.tag_id
             AND tag.status = 'active'
            WHERE assignment.organization_id = membership_record.organization_id
              AND assignment.membership_id = membership_record.membership_id
            ORDER BY assignment.tag_id
            FOR SHARE OF assignment, tag
        )
        SELECT COALESCE(array_agg(locked.tag_id ORDER BY locked.tag_id), ARRAY[]::uuid[])
        INTO affected_tag_ids
        FROM locked;

        RETURN NEXT;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION iam_private.lock_carbon_profile_silicon_routes(uuid) IS
    'Locks and returns a Carbon''s own active memberships with their active tag audience.';

REVOKE ALL ON FUNCTION iam_private.lock_carbon_profile_silicon_routes(uuid) FROM PUBLIC;
