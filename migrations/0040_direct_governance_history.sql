-- Owners and explicitly authorized Carbon administrators can apply job-role
-- and tag changes without an approval request. Preserve those changes in the
-- same append-only histories while retaining a precise direct actor.

ALTER TABLE iam.job_role_history
    ALTER COLUMN approval_request_id DROP NOT NULL,
    ADD COLUMN applied_by_membership_id uuid,
    ADD CONSTRAINT job_role_history_direct_actor_fk
        FOREIGN KEY (organization_id, applied_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT job_role_history_source CHECK (
        (approval_request_id IS NOT NULL AND applied_by_membership_id IS NULL)
        OR (approval_request_id IS NULL AND applied_by_membership_id IS NOT NULL)
    );

ALTER TABLE iam.membership_tag_change_history
    ALTER COLUMN approval_request_id DROP NOT NULL,
    ADD COLUMN applied_by_membership_id uuid,
    ADD CONSTRAINT membership_tag_history_direct_actor_fk
        FOREIGN KEY (organization_id, applied_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT membership_tag_history_source CHECK (
        (approval_request_id IS NOT NULL AND applied_by_membership_id IS NULL)
        OR (approval_request_id IS NULL AND applied_by_membership_id IS NOT NULL)
    );

COMMENT ON COLUMN iam.job_role_history.applied_by_membership_id IS
    'Carbon owner/admin who applied a direct change; null for governed approval changes.';
COMMENT ON COLUMN iam.membership_tag_change_history.applied_by_membership_id IS
    'Carbon owner/admin who applied a direct change; null for governed approval changes.';

CREATE FUNCTION iam_private.replace_membership_job_role_direct(
    p_organization_id uuid,
    p_membership_id uuid,
    p_actor_membership_id uuid,
    p_history_id uuid,
    p_expected_version bigint,
    p_job_role text
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_actor_principal_id uuid := iam_private.current_principal_id();
    actor_kind iam.principal_kind;
    actor_role iam.organization_role;
    target_status text;
    target_version bigint;
    previous_job_role text;
    resulting_membership_version bigint;
BEGIN
    IF p_organization_id IS NULL
       OR p_membership_id IS NULL
       OR p_actor_membership_id IS NULL
       OR p_history_id IS NULL
       OR p_expected_version IS NULL
       OR p_expected_version <= 0
       OR p_job_role IS NULL
       OR char_length(p_job_role) > 5000
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id()
       OR current_actor_principal_id IS NULL THEN
        RAISE EXCEPTION 'direct_job_role_change_invalid' USING ERRCODE = '22023';
    END IF;

    SELECT actor.principal_kind, actor.org_role
    INTO actor_kind, actor_role
    FROM iam.organization_memberships AS actor
    WHERE actor.organization_id = p_organization_id
      AND actor.id = p_actor_membership_id
      AND actor.principal_id = current_actor_principal_id
      AND actor.status = 'active'
    FOR SHARE OF actor;

    IF NOT FOUND
       OR actor_kind <> 'carbon'
       OR (
            actor_role <> 'owner'
            AND (
                actor_role <> 'admin'
                OR NOT iam_private.has_organization_capability(
                    p_organization_id,
                    current_actor_principal_id,
                    'roles.approve'
                )
            )
       ) THEN
        RAISE EXCEPTION 'direct_job_role_change_forbidden' USING ERRCODE = '42501';
    END IF;

    SELECT membership.status, membership.version, membership.job_role
    INTO target_status, target_version, previous_job_role
    FROM iam.organization_memberships AS membership
    WHERE membership.organization_id = p_organization_id
      AND membership.id = p_membership_id
    FOR UPDATE OF membership;

    IF NOT FOUND OR target_status <> 'active' THEN
        RAISE EXCEPTION 'direct_job_role_change_target_inactive' USING ERRCODE = 'P0001';
    END IF;
    IF target_version <> p_expected_version THEN
        RAISE EXCEPTION 'direct_job_role_change_version_mismatch' USING ERRCODE = 'P0001';
    END IF;
    IF previous_job_role = p_job_role THEN
        RAISE EXCEPTION 'direct_job_role_change_unchanged' USING ERRCODE = 'P0001';
    END IF;

    UPDATE iam.organization_memberships AS membership
    SET job_role = p_job_role
    WHERE membership.organization_id = p_organization_id
      AND membership.id = p_membership_id
      AND membership.version = p_expected_version
      AND membership.status = 'active'
    RETURNING membership.version INTO resulting_membership_version;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'direct_job_role_change_version_mismatch' USING ERRCODE = 'P0001';
    END IF;

    INSERT INTO iam.job_role_history (
        id, organization_id, membership_id, approval_request_id,
        previous_job_role, applied_job_role, membership_version,
        applied_by_membership_id
    ) VALUES (
        p_history_id, p_organization_id, p_membership_id, NULL,
        previous_job_role, p_job_role, resulting_membership_version,
        p_actor_membership_id
    );

    RETURN resulting_membership_version;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.replace_membership_job_role_direct(
    uuid, uuid, uuid, uuid, bigint, text
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.replace_membership_job_role_direct(
    uuid, uuid, uuid, uuid, bigint, text
) IS
    'Reauthorizes a Carbon owner/admin, locks the active target, replaces its descriptive job role, and records immutable direct history atomically.';

CREATE FUNCTION iam_private.replace_membership_tags_direct(
    p_organization_id uuid,
    p_membership_id uuid,
    p_actor_membership_id uuid,
    p_history_id uuid,
    p_expected_version bigint,
    p_tag_ids uuid[]
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_actor_principal_id uuid := iam_private.current_principal_id();
    actor_kind iam.principal_kind;
    actor_role iam.organization_role;
    target_status text;
    target_version bigint;
    previous_tag_ids uuid[];
    active_tag_count integer;
    resulting_membership_version bigint;
BEGIN
    IF p_organization_id IS NULL
       OR p_membership_id IS NULL
       OR p_actor_membership_id IS NULL
       OR p_history_id IS NULL
       OR p_expected_version IS NULL
       OR p_expected_version <= 0
       OR p_tag_ids IS NULL
       OR cardinality(p_tag_ids) > 100
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id()
       OR current_actor_principal_id IS NULL
       OR p_tag_ids <> ARRAY(
            SELECT DISTINCT requested.tag_id
            FROM pg_catalog.unnest(p_tag_ids) AS requested(tag_id)
            ORDER BY requested.tag_id
       ) THEN
        RAISE EXCEPTION 'direct_tag_change_invalid' USING ERRCODE = '22023';
    END IF;

    SELECT actor.principal_kind, actor.org_role
    INTO actor_kind, actor_role
    FROM iam.organization_memberships AS actor
    WHERE actor.organization_id = p_organization_id
      AND actor.id = p_actor_membership_id
      AND actor.principal_id = current_actor_principal_id
      AND actor.status = 'active'
    FOR SHARE OF actor;

    IF NOT FOUND
       OR actor_kind <> 'carbon'
       OR (
            actor_role <> 'owner'
            AND (
                actor_role <> 'admin'
                OR NOT iam_private.has_organization_capability(
                    p_organization_id,
                    current_actor_principal_id,
                    'tags.manage'
                )
            )
       ) THEN
        RAISE EXCEPTION 'direct_tag_change_forbidden' USING ERRCODE = '42501';
    END IF;

    SELECT membership.status, membership.version
    INTO target_status, target_version
    FROM iam.organization_memberships AS membership
    WHERE membership.organization_id = p_organization_id
      AND membership.id = p_membership_id
    FOR UPDATE OF membership;

    IF NOT FOUND OR target_status <> 'active' THEN
        RAISE EXCEPTION 'direct_tag_change_target_inactive' USING ERRCODE = 'P0001';
    END IF;
    IF target_version <> p_expected_version THEN
        RAISE EXCEPTION 'direct_tag_change_version_mismatch' USING ERRCODE = 'P0001';
    END IF;

    SELECT COALESCE(
        array_agg(assignment.tag_id ORDER BY assignment.tag_id),
        ARRAY[]::uuid[]
    )
    INTO previous_tag_ids
    FROM iam.membership_tags AS assignment
    WHERE assignment.organization_id = p_organization_id
      AND assignment.membership_id = p_membership_id;

    IF previous_tag_ids = p_tag_ids THEN
        RAISE EXCEPTION 'direct_tag_change_unchanged' USING ERRCODE = 'P0001';
    END IF;

    PERFORM tag.id
    FROM iam.organization_tags AS tag
    WHERE tag.organization_id = p_organization_id
      AND tag.id = ANY(p_tag_ids)
    ORDER BY tag.id
    FOR SHARE OF tag;

    SELECT count(*)::integer
    INTO active_tag_count
    FROM iam.organization_tags AS tag
    WHERE tag.organization_id = p_organization_id
      AND tag.id = ANY(p_tag_ids)
      AND tag.status = 'active';

    IF active_tag_count <> cardinality(p_tag_ids) THEN
        RAISE EXCEPTION 'direct_tag_change_tag_inactive' USING ERRCODE = 'P0001';
    END IF;

    DELETE FROM iam.membership_tags AS assignment
    WHERE assignment.organization_id = p_organization_id
      AND assignment.membership_id = p_membership_id;

    INSERT INTO iam.membership_tags (
        organization_id, membership_id, tag_id, assigned_by_membership_id
    )
    SELECT p_organization_id, p_membership_id,
           requested.tag_id, p_actor_membership_id
    FROM pg_catalog.unnest(p_tag_ids) AS requested(tag_id)
    ORDER BY requested.tag_id;

    UPDATE iam.organization_memberships AS membership
    SET authz_epoch = membership.authz_epoch + 1
    WHERE membership.organization_id = p_organization_id
      AND membership.id = p_membership_id
      AND membership.version = p_expected_version
      AND membership.status = 'active'
    RETURNING membership.version INTO resulting_membership_version;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'direct_tag_change_version_mismatch' USING ERRCODE = 'P0001';
    END IF;

    INSERT INTO iam.membership_tag_change_history (
        id, organization_id, membership_id, approval_request_id,
        previous_tag_ids, applied_tag_ids, membership_version,
        applied_by_membership_id
    ) VALUES (
        p_history_id, p_organization_id, p_membership_id, NULL,
        previous_tag_ids, p_tag_ids, resulting_membership_version,
        p_actor_membership_id
    );

    RETURN resulting_membership_version;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.replace_membership_tags_direct(
    uuid, uuid, uuid, uuid, bigint, uuid[]
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.replace_membership_tags_direct(
    uuid, uuid, uuid, uuid, bigint, uuid[]
) IS
    'Reauthorizes a Carbon owner/admin, locks the active target and tags, replaces one membership tag set, advances authorization state, and records immutable direct history atomically.';
