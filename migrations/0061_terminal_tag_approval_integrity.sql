-- A tag-change request's `previous_tag_ids` is a pending-state concurrency
-- assertion. Once the approved change is applied, the membership is expected
-- to differ from that snapshot. Keep the complete structural assertion for
-- pending requests, but use a history-safe assertion for terminal tag rows.

ALTER FUNCTION iam_private.assert_approval_request_shape(uuid)
    RENAME TO assert_pending_approval_request_shape;

REVOKE ALL ON FUNCTION iam_private.assert_pending_approval_request_shape(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.assert_approval_request_shape(
    p_approval_request_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    request_kind text;
    request_status text;
    minimum_approvers smallint;
    subtype_count integer;
    target_kind iam.principal_kind;
    target_membership_id uuid;
    previous_ids uuid[];
    added_ids uuid[];
    removed_ids uuid[];
    proposed_ids uuid[];
    requirement_count integer;
    requirements_valid boolean;
BEGIN
    SELECT request.request_kind, request.status,
           request.minimum_distinct_approvers
    INTO request_kind, request_status, minimum_approvers
    FROM iam.approval_requests AS request
    WHERE request.id = p_approval_request_id;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF request_kind NOT IN ('carbon_tag_change', 'silicon_tag_change')
       OR request_status = 'pending' THEN
        PERFORM iam_private.assert_pending_approval_request_shape(
            p_approval_request_id
        );
        RETURN;
    END IF;

    SELECT
        (SELECT count(*) FROM iam.job_role_change_requests
         WHERE approval_request_id = p_approval_request_id)
        + (SELECT count(*) FROM iam.tag_change_requests
           WHERE approval_request_id = p_approval_request_id)
        + (SELECT count(*) FROM iam.silicon_token_rotation_requests
           WHERE approval_request_id = p_approval_request_id)
        + (SELECT count(*) FROM iam.ownership_transfer_requests
           WHERE approval_request_id = p_approval_request_id)
    INTO subtype_count;

    SELECT tag_change.target_principal_kind,
           tag_change.target_membership_id,
           tag_change.previous_tag_ids,
           tag_change.added_tag_ids,
           tag_change.removed_tag_ids,
           tag_change.proposed_tag_ids
    INTO target_kind, target_membership_id, previous_ids,
         added_ids, removed_ids, proposed_ids
    FROM iam.tag_change_requests AS tag_change
    WHERE tag_change.approval_request_id = p_approval_request_id;

    SELECT count(*)
    INTO requirement_count
    FROM iam.approval_requirements
    WHERE approval_request_id = p_approval_request_id;

    requirements_valid := subtype_count = 1
        AND previous_ids = ARRAY(
            SELECT DISTINCT tag_id
            FROM pg_catalog.unnest(previous_ids) AS tag_id
            ORDER BY tag_id
        )
        AND added_ids = ARRAY(
            SELECT DISTINCT tag_id
            FROM pg_catalog.unnest(added_ids) AS tag_id
            ORDER BY tag_id
        )
        AND removed_ids = ARRAY(
            SELECT DISTINCT tag_id
            FROM pg_catalog.unnest(removed_ids) AS tag_id
            ORDER BY tag_id
        )
        AND proposed_ids = ARRAY(
            SELECT DISTINCT tag_id
            FROM pg_catalog.unnest(proposed_ids) AS tag_id
            ORDER BY tag_id
        )
        AND NOT (added_ids && previous_ids)
        AND removed_ids <@ previous_ids
        AND proposed_ids = ARRAY(
            SELECT candidate.tag_id
            FROM (
                (
                    SELECT tag_id
                    FROM pg_catalog.unnest(previous_ids) AS tag_id
                    EXCEPT
                    SELECT tag_id
                    FROM pg_catalog.unnest(removed_ids) AS tag_id
                )
                UNION
                SELECT tag_id
                FROM pg_catalog.unnest(added_ids) AS tag_id
            ) AS candidate
            ORDER BY candidate.tag_id
        );

    IF request_kind = 'carbon_tag_change' THEN
        requirements_valid := requirements_valid
            AND target_kind = 'carbon'
            AND minimum_approvers = 2
            AND requirement_count = 2
            AND EXISTS (
                SELECT 1
                FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'specific_membership'
                  AND specific_membership_id = target_membership_id
                  AND quorum = 1
            )
            AND EXISTS (
                SELECT 1
                FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'current_owner_or_admin'
                  AND required_capability = 'tags.manage'
                  AND quorum = 1
            );
    ELSE
        requirements_valid := requirements_valid
            AND target_kind = 'silicon'
            AND minimum_approvers = 1
            AND requirement_count = 1
            AND EXISTS (
                SELECT 1
                FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'current_owner_or_admin'
                  AND required_capability = 'tags.manage'
                  AND quorum = 1
            );
    END IF;

    IF NOT requirements_valid THEN
        RAISE EXCEPTION
            'approval request % has an invalid terminal tag payload or approver requirement set',
            p_approval_request_id
            USING ERRCODE = '23514';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.assert_approval_request_shape(uuid) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.assert_approval_request_shape(uuid) IS
    'Checks pending governance against live state and terminal tag governance against its immutable structural snapshot.';
