-- Deleting an organization tag.
--
-- Deletion is archival, not removal. The tag identifier is the target of
-- foreign keys from governed tag-change history, trust rules, invitations and
-- Silicon webhook subscription filters, all of which are append-only or
-- long-lived; erasing the row would either fail or destroy history. Archiving
-- is also already what the rest of the schema understands: every consumer of a
-- tag -- member projections, trust evaluation, Silicon delivery filters,
-- Silicon access grants -- already requires status = 'active', so archiving a
-- tag is what stops it conferring anything.
--
-- What archiving did not previously do is release the name or clean up after
-- itself, and both matter for a deletion an operator performs deliberately.

-- A deleted tag must not hold its name hostage. The unique constraint was
-- unconditional, so an archived tag permanently blocked recreating a tag by the
-- same name; scoping it to live tags makes a name reusable the moment it is
-- released. The (organization_id, id) key that foreign keys actually reference
-- is untouched.
ALTER TABLE iam.organization_tags
    DROP CONSTRAINT organization_tags_organization_id_normalized_name_key;

CREATE UNIQUE INDEX organization_tags_active_normalized_name_key
    ON iam.organization_tags (organization_id, normalized_name)
    WHERE status = 'active';

COMMENT ON INDEX iam.organization_tags_active_normalized_name_key IS
    'One live tag name per organization; archived tags release their name for reuse.';

-- Locks the audience a tag transition affects.
--
-- Any row-locking clause requires write privilege on the locked table, and the
-- API role deliberately holds only SELECT on iam.membership_tags because
-- assignments belong to the governed tag-change machinery. Taking the lock
-- through a boundary is what the rest of the schema already does for the same
-- reason -- and without it the existing tag rename could not lock its audience
-- at all, so renaming a tag that any member held failed outright.
--
-- Memberships are locked before the tag and then re-read: the second pass
-- catches an assignment that committed before the tag lock was acquired, and
-- any later addition blocks on the tag lock itself.
CREATE FUNCTION iam_private.lock_organization_tag_scope(
    p_organization_id uuid,
    p_tag_id uuid,
    p_expected_version bigint
)
RETURNS uuid[]
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    actor_principal_id uuid;
    assigned_membership_ids uuid[];
    locked_tag_id uuid;
BEGIN
    actor_principal_id := iam_private.current_principal_id();
    IF actor_principal_id IS NULL
       OR NOT iam_private.has_organization_capability(
              p_organization_id, actor_principal_id, 'tags.manage'
          ) THEN
        RAISE EXCEPTION 'tag_scope_forbidden' USING ERRCODE = '42501';
    END IF;

    PERFORM 1
    FROM iam.membership_tags AS assignment
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = assignment.organization_id
     AND membership.id = assignment.membership_id
     AND membership.status = 'active'
    WHERE assignment.organization_id = p_organization_id
      AND assignment.tag_id = p_tag_id
    ORDER BY assignment.membership_id
    FOR SHARE OF assignment, membership;

    SELECT tag.id
    INTO locked_tag_id
    FROM iam.organization_tags AS tag
    WHERE tag.organization_id = p_organization_id
      AND tag.id = p_tag_id
      AND tag.version = p_expected_version
      AND tag.status = 'active'
    FOR UPDATE OF tag;

    IF locked_tag_id IS NULL THEN
        RAISE EXCEPTION 'tag_version_mismatch' USING ERRCODE = 'P0001';
    END IF;

    WITH locked AS (
        SELECT assignment.membership_id
        FROM iam.membership_tags AS assignment
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = assignment.organization_id
         AND membership.id = assignment.membership_id
         AND membership.status = 'active'
        WHERE assignment.organization_id = p_organization_id
          AND assignment.tag_id = p_tag_id
        ORDER BY assignment.membership_id
        FOR SHARE OF assignment, membership
    )
    SELECT array_agg(locked.membership_id ORDER BY locked.membership_id)
    INTO assigned_membership_ids
    FROM locked;

    RETURN COALESCE(assigned_membership_ids, ARRAY[]::uuid[]);
END;
$$;

COMMENT ON FUNCTION iam_private.lock_organization_tag_scope(uuid, uuid, bigint) IS
    'Locks a tag and the active memberships holding it, returning that audience.';

REVOKE ALL ON FUNCTION iam_private.lock_organization_tag_scope(uuid, uuid, bigint) FROM PUBLIC;

-- Archives one tag and everything that hung off it.
--
-- A single fixed-path function because the cascade crosses three tables that
-- the HTTP layer is deliberately not allowed to write directly: membership tag
-- assignments belong to the governed tag-change machinery, and trust rules and
-- membership authorization epochs are authority state. Doing it here keeps the
-- whole transition atomic and keeps those writes behind one reviewed boundary.
--
-- The cascade is what the tag_archived event was always shaped for: its
-- payload carries the affected memberships and the archived trust rules as
-- disjoint sets, which is only meaningful if archiving actually performs both.
--
-- Locks memberships before the tag, matching the order governed tag changes
-- take, so the two cannot deadlock against each other.
CREATE FUNCTION iam_private.archive_organization_tag(
    p_organization_id uuid,
    p_tag_id uuid,
    p_expected_version bigint,
    p_actor_membership_id uuid,
    p_history_ids uuid[]
)
RETURNS TABLE (
    tag_version bigint,
    assignment_membership_ids uuid[],
    archived_trust_rule_ids uuid[]
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    actor_principal_id uuid;
    affected_membership_ids uuid[];
    trust_rule_ids uuid[];
    resulting_tag_version bigint;
BEGIN
    -- Revalidated here rather than trusted from the caller, as every other
    -- governed transition in this schema does.
    actor_principal_id := iam_private.current_principal_id();
    IF actor_principal_id IS NULL
       OR NOT iam_private.has_organization_capability(
              p_organization_id, actor_principal_id, 'tags.manage'
          )
       OR p_actor_membership_id IS DISTINCT FROM
          iam_private.active_organization_membership_id(
              p_organization_id, actor_principal_id
          ) THEN
        RAISE EXCEPTION 'tag_archive_forbidden' USING ERRCODE = '42501';
    END IF;

    WITH locked AS (
        SELECT assignment.membership_id
        FROM iam.membership_tags AS assignment
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = assignment.organization_id
         AND membership.id = assignment.membership_id
         AND membership.status = 'active'
        WHERE assignment.organization_id = p_organization_id
          AND assignment.tag_id = p_tag_id
        ORDER BY assignment.membership_id
        FOR UPDATE OF membership
    )
    SELECT array_agg(locked.membership_id ORDER BY locked.membership_id)
    INTO affected_membership_ids
    FROM locked;
    affected_membership_ids := COALESCE(affected_membership_ids, ARRAY[]::uuid[]);

    -- The caller sized its history identifiers from the audience it observed
    -- under the same tag lock. A mismatch means that view went stale, and
    -- inventing or dropping a history row is not an acceptable recovery.
    IF cardinality(p_history_ids) <> cardinality(affected_membership_ids) THEN
        RAISE EXCEPTION 'tag_archive_audience_changed' USING ERRCODE = 'P0001';
    END IF;

    UPDATE iam.organization_tags AS tag
    SET status = 'archived',
        archived_at = transaction_timestamp()
    WHERE tag.organization_id = p_organization_id
      AND tag.id = p_tag_id
      AND tag.version = p_expected_version
      AND tag.status = 'active'
    RETURNING tag.version INTO resulting_tag_version;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'tag_version_mismatch' USING ERRCODE = 'P0001';
    END IF;

    -- Epoch bump, history and assignment removal in that order: the history
    -- row records the membership version the bump produced, and it has to read
    -- the tag set while the assignment being removed is still there.
    WITH bumped AS (
        UPDATE iam.organization_memberships AS membership
        SET authz_epoch = membership.authz_epoch + 1
        WHERE membership.organization_id = p_organization_id
          AND membership.id = ANY (affected_membership_ids)
          AND membership.status = 'active'
        RETURNING membership.id AS membership_id, membership.version
    ), audience AS (
        SELECT
            bumped.membership_id,
            bumped.version,
            ARRAY(
                SELECT assignment.tag_id
                FROM iam.membership_tags AS assignment
                WHERE assignment.organization_id = p_organization_id
                  AND assignment.membership_id = bumped.membership_id
                ORDER BY assignment.tag_id
            ) AS previous_tag_ids,
            row_number() OVER (ORDER BY bumped.membership_id) AS position
        FROM bumped
    )
    INSERT INTO iam.membership_tag_change_history (
        id,
        organization_id,
        membership_id,
        approval_request_id,
        previous_tag_ids,
        applied_tag_ids,
        membership_version,
        applied_by_membership_id
    )
    SELECT
        p_history_ids[audience.position],
        p_organization_id,
        audience.membership_id,
        NULL,
        audience.previous_tag_ids,
        array_remove(audience.previous_tag_ids, p_tag_id),
        audience.version,
        p_actor_membership_id
    FROM audience;

    -- Assignments held by removed memberships go too. They confer nothing, but
    -- leaving rows pointing at a tag that no longer exists would make the
    -- assignment table lie about what an organization contains.
    DELETE FROM iam.membership_tags AS assignment
    WHERE assignment.organization_id = p_organization_id
      AND assignment.tag_id = p_tag_id;

    WITH archived AS (
        UPDATE iam.trust_rules AS rule
        SET archived_at = transaction_timestamp(),
            updated_by_membership_id = p_actor_membership_id
        WHERE rule.organization_id = p_organization_id
          AND rule.archived_at IS NULL
          AND (rule.subject_tag_id = p_tag_id OR rule.target_tag_id = p_tag_id)
        RETURNING rule.id
    )
    SELECT array_agg(archived.id ORDER BY archived.id)
    INTO trust_rule_ids
    FROM archived;

    RETURN QUERY
    SELECT
        resulting_tag_version,
        affected_membership_ids,
        COALESCE(trust_rule_ids, ARRAY[]::uuid[]);
END;
$$;

COMMENT ON FUNCTION iam_private.archive_organization_tag(
    uuid, uuid, bigint, uuid, uuid[]
) IS
    'Archives one tag, removes its assignments, archives its trust rules, and re-epochs affected members.';

REVOKE ALL ON FUNCTION iam_private.archive_organization_tag(
    uuid, uuid, bigint, uuid, uuid[]
) FROM PUBLIC;
