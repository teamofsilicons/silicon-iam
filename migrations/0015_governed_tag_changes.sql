-- Govern every Carbon and Silicon membership-tag mutation through the shared
-- approval state machine while preserving an immutable request and apply log.

ALTER TABLE iam.approval_requests
    DROP CONSTRAINT approval_requests_kind,
    ADD CONSTRAINT approval_requests_kind CHECK (request_kind IN (
        'carbon_job_role_change', 'silicon_job_role_change',
        'carbon_tag_change', 'silicon_tag_change',
        'silicon_token_rotation', 'ownership_transfer'
    ));

CREATE TABLE iam.tag_change_requests (
    approval_request_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    target_membership_id uuid NOT NULL,
    target_principal_kind iam.principal_kind NOT NULL,
    previous_tag_ids uuid[] NOT NULL,
    added_tag_ids uuid[] NOT NULL,
    removed_tag_ids uuid[] NOT NULL,
    proposed_tag_ids uuid[] NOT NULL,
    reason text,
    CONSTRAINT tag_change_requests_request_fk
        FOREIGN KEY (organization_id, approval_request_id)
        REFERENCES iam.approval_requests (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT tag_change_requests_target_fk
        FOREIGN KEY (organization_id, target_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT tag_change_requests_target_kind
        CHECK (target_principal_kind IN ('carbon', 'silicon')),
    CONSTRAINT tag_change_requests_previous_limit
        CHECK (cardinality(previous_tag_ids) BETWEEN 0 AND 100),
    CONSTRAINT tag_change_requests_added_limit
        CHECK (cardinality(added_tag_ids) BETWEEN 0 AND 100),
    CONSTRAINT tag_change_requests_removed_limit
        CHECK (cardinality(removed_tag_ids) BETWEEN 0 AND 100),
    CONSTRAINT tag_change_requests_proposed_limit
        CHECK (cardinality(proposed_tag_ids) BETWEEN 0 AND 100),
    CONSTRAINT tag_change_requests_has_change
        CHECK (cardinality(added_tag_ids) + cardinality(removed_tag_ids) > 0),
    CONSTRAINT tag_change_requests_disjoint_operations
        CHECK (NOT (added_tag_ids && removed_tag_ids)),
    CONSTRAINT tag_change_requests_reason_length
        CHECK (reason IS NULL OR char_length(reason) BETWEEN 1 AND 2000)
);

COMMENT ON TABLE iam.tag_change_requests IS
    'Immutable before/add/remove/after tag snapshot for one governed Carbon or Silicon membership change.';

CREATE TRIGGER tag_change_requests_immutable
BEFORE UPDATE OR DELETE ON iam.tag_change_requests
FOR EACH ROW EXECUTE FUNCTION iam_private.reject_approval_payload_change();

CREATE TABLE iam.membership_tag_change_history (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    approval_request_id uuid NOT NULL,
    previous_tag_ids uuid[] NOT NULL,
    applied_tag_ids uuid[] NOT NULL,
    membership_version bigint NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (organization_id, approval_request_id),
    CONSTRAINT membership_tag_change_history_membership_fk
        FOREIGN KEY (organization_id, membership_id)
        REFERENCES iam.organization_memberships (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT membership_tag_change_history_request_fk
        FOREIGN KEY (organization_id, approval_request_id)
        REFERENCES iam.approval_requests (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT membership_tag_change_history_previous_limit
        CHECK (cardinality(previous_tag_ids) BETWEEN 0 AND 100),
    CONSTRAINT membership_tag_change_history_applied_limit
        CHECK (cardinality(applied_tag_ids) BETWEEN 0 AND 100),
    CONSTRAINT membership_tag_change_history_positive_version
        CHECK (membership_version > 0)
);

CREATE INDEX membership_tag_change_history_member_idx
    ON iam.membership_tag_change_history (organization_id, membership_id, id);

COMMENT ON TABLE iam.membership_tag_change_history IS
    'Append-only record of tag sets atomically applied after their approval requirements were satisfied.';

CREATE TRIGGER membership_tag_change_history_append_only
BEFORE UPDATE OR DELETE ON iam.membership_tag_change_history
FOR EACH ROW EXECUTE FUNCTION iam_private.reject_immutable_history_mutation();

CREATE OR REPLACE FUNCTION iam_private.assert_approval_request_shape(
    p_approval_request_id uuid
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    request_kind text;
    minimum_approvers smallint;
    subtype_count integer;
    role_target_kind iam.principal_kind;
    role_target_membership_id uuid;
    tag_target_kind iam.principal_kind;
    tag_target_membership_id uuid;
    tag_previous_ids uuid[];
    tag_added_ids uuid[];
    tag_removed_ids uuid[];
    tag_proposed_ids uuid[];
    requirement_count integer;
    requirements_valid boolean;
BEGIN
    SELECT request.request_kind, request.minimum_distinct_approvers
    INTO request_kind, minimum_approvers
    FROM iam.approval_requests AS request
    WHERE request.id = p_approval_request_id;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT
        (SELECT count(*) FROM iam.job_role_change_requests WHERE approval_request_id = p_approval_request_id)
        + (SELECT count(*) FROM iam.tag_change_requests WHERE approval_request_id = p_approval_request_id)
        + (SELECT count(*) FROM iam.silicon_token_rotation_requests WHERE approval_request_id = p_approval_request_id)
        + (SELECT count(*) FROM iam.ownership_transfer_requests WHERE approval_request_id = p_approval_request_id)
    INTO subtype_count;

    IF subtype_count <> 1 THEN
        RAISE EXCEPTION 'approval request % must have exactly one payload subtype', p_approval_request_id
            USING ERRCODE = '23514';
    END IF;

    SELECT target_principal_kind, target_membership_id
    INTO role_target_kind, role_target_membership_id
    FROM iam.job_role_change_requests
    WHERE approval_request_id = p_approval_request_id;

    SELECT target_principal_kind, target_membership_id,
           previous_tag_ids, added_tag_ids, removed_tag_ids, proposed_tag_ids
    INTO tag_target_kind, tag_target_membership_id,
         tag_previous_ids, tag_added_ids, tag_removed_ids, tag_proposed_ids
    FROM iam.tag_change_requests
    WHERE approval_request_id = p_approval_request_id;

    SELECT count(*)
    INTO requirement_count
    FROM iam.approval_requirements
    WHERE approval_request_id = p_approval_request_id;

    requirements_valid := CASE request_kind
        WHEN 'carbon_job_role_change' THEN
            role_target_kind = 'carbon'
            AND minimum_approvers = 2
            AND requirement_count = 2
            AND EXISTS (
                SELECT 1 FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'specific_membership'
                  AND specific_membership_id = role_target_membership_id
                  AND quorum = 1
            )
            AND EXISTS (
                SELECT 1 FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'current_owner_or_admin'
                  AND required_capability = 'roles.approve'
                  AND quorum = 1
            )
        WHEN 'silicon_job_role_change' THEN
            role_target_kind = 'silicon'
            AND minimum_approvers = 1
            AND requirement_count = 1
            AND EXISTS (
                SELECT 1 FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'current_owner_or_admin'
                  AND required_capability = 'roles.approve'
                  AND quorum = 1
            )
        WHEN 'carbon_tag_change' THEN
            tag_target_kind = 'carbon'
            AND minimum_approvers = 2
            AND requirement_count = 2
            AND EXISTS (
                SELECT 1 FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'specific_membership'
                  AND specific_membership_id = tag_target_membership_id
                  AND quorum = 1
            )
            AND EXISTS (
                SELECT 1 FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'current_owner_or_admin'
                  AND required_capability = 'tags.manage'
                  AND quorum = 1
            )
        WHEN 'silicon_tag_change' THEN
            tag_target_kind = 'silicon'
            AND minimum_approvers = 1
            AND requirement_count = 1
            AND EXISTS (
                SELECT 1 FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'current_owner_or_admin'
                  AND required_capability = 'tags.manage'
                  AND quorum = 1
            )
        WHEN 'silicon_token_rotation' THEN
            EXISTS (
                SELECT 1 FROM iam.silicon_token_rotation_requests
                WHERE approval_request_id = p_approval_request_id
            )
            AND minimum_approvers = 1
            AND requirement_count = 1
            AND EXISTS (
                SELECT 1 FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'current_owner'
                  AND quorum = 1
            )
        WHEN 'ownership_transfer' THEN
            EXISTS (
                SELECT 1 FROM iam.ownership_transfer_requests
                WHERE approval_request_id = p_approval_request_id
            )
            AND minimum_approvers = 1
            AND requirement_count = 1
            AND EXISTS (
                SELECT 1 FROM iam.approval_requirements
                WHERE approval_request_id = p_approval_request_id
                  AND requirement_kind = 'current_owner'
                  AND quorum = 1
            )
        ELSE false
    END;

    IF request_kind IN ('carbon_tag_change', 'silicon_tag_change') THEN
        requirements_valid := requirements_valid
            AND tag_previous_ids = ARRAY(
                SELECT DISTINCT tag_id
                FROM pg_catalog.unnest(tag_previous_ids) AS tag_id
                ORDER BY tag_id
            )
            AND tag_added_ids = ARRAY(
                SELECT DISTINCT tag_id
                FROM pg_catalog.unnest(tag_added_ids) AS tag_id
                ORDER BY tag_id
            )
            AND tag_removed_ids = ARRAY(
                SELECT DISTINCT tag_id
                FROM pg_catalog.unnest(tag_removed_ids) AS tag_id
                ORDER BY tag_id
            )
            AND tag_proposed_ids = ARRAY(
                SELECT DISTINCT tag_id
                FROM pg_catalog.unnest(tag_proposed_ids) AS tag_id
                ORDER BY tag_id
            )
            AND NOT (tag_added_ids && tag_previous_ids)
            AND tag_removed_ids <@ tag_previous_ids
            AND tag_proposed_ids = ARRAY(
                SELECT candidate.tag_id
                FROM (
                    (
                        SELECT tag_id
                        FROM pg_catalog.unnest(tag_previous_ids) AS tag_id
                        EXCEPT
                        SELECT tag_id
                        FROM pg_catalog.unnest(tag_removed_ids) AS tag_id
                    )
                    UNION
                    SELECT tag_id
                    FROM pg_catalog.unnest(tag_added_ids) AS tag_id
                ) AS candidate
                ORDER BY candidate.tag_id
            )
            AND tag_previous_ids = ARRAY(
                SELECT assignment.tag_id
                FROM iam.membership_tags AS assignment
                WHERE assignment.organization_id = (
                    SELECT organization_id
                    FROM iam.tag_change_requests
                    WHERE approval_request_id = p_approval_request_id
                )
                  AND assignment.membership_id = tag_target_membership_id
                ORDER BY assignment.tag_id
            )
            AND EXISTS (
                SELECT 1
                FROM iam.organization_memberships AS membership
                JOIN iam.tag_change_requests AS tag_change
                  ON tag_change.organization_id = membership.organization_id
                 AND tag_change.target_membership_id = membership.id
                WHERE tag_change.approval_request_id = p_approval_request_id
                  AND membership.status = 'active'
                  AND membership.principal_kind = tag_target_kind
            )
            AND cardinality(tag_proposed_ids) = (
                SELECT count(*)::integer
                FROM iam.organization_tags AS tag
                JOIN iam.tag_change_requests AS tag_change
                  ON tag_change.organization_id = tag.organization_id
                WHERE tag_change.approval_request_id = p_approval_request_id
                  AND tag.id = ANY(tag_proposed_ids)
                  AND tag.status = 'active'
            );
    END IF;

    IF NOT requirements_valid THEN
        RAISE EXCEPTION 'approval request % has an invalid payload or approver requirement set',
            p_approval_request_id USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE CONSTRAINT TRIGGER tag_change_payload_preserves_shape
AFTER INSERT OR UPDATE OR DELETE ON iam.tag_change_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.check_approval_shape_from_payload();

ALTER TABLE iam.tag_change_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.membership_tag_change_history ENABLE ROW LEVEL SECURITY;

DROP POLICY approval_requests_create ON iam.approval_requests;
CREATE POLICY approval_requests_create
ON iam.approval_requests FOR INSERT
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND EXISTS (
        SELECT 1
        FROM iam.organization_memberships AS requester
        WHERE requester.organization_id = approval_requests.organization_id
          AND requester.id = approval_requests.requested_by_membership_id
          AND requester.principal_id = iam_private.current_principal_id()
          AND requester.status = 'active'
          AND (
              (
                  approval_requests.request_kind IN (
                      'carbon_job_role_change', 'silicon_job_role_change'
                  )
                  AND iam_private.has_organization_capability(
                      approval_requests.organization_id,
                      iam_private.current_principal_id(),
                      'roles.request'
                  )
              )
              OR (
                  approval_requests.request_kind IN (
                      'carbon_tag_change', 'silicon_tag_change'
                  )
                  AND requester.principal_kind IN ('carbon', 'silicon')
              )
              OR (
                  approval_requests.request_kind = 'silicon_token_rotation'
                  AND iam_private.has_organization_capability(
                      approval_requests.organization_id,
                      iam_private.current_principal_id(),
                      'silicons.rotate_token'
                  )
              )
              OR (
                  approval_requests.request_kind = 'ownership_transfer'
                  AND requester.principal_kind = 'carbon'
                  AND requester.org_role = 'owner'
              )
          )
    )
);

DROP POLICY approval_requirements_create ON iam.approval_requirements;
CREATE POLICY approval_requirements_create
ON iam.approval_requirements FOR INSERT
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND EXISTS (
        SELECT 1
        FROM iam.approval_requests AS request
        JOIN iam.organization_memberships AS requester
          ON requester.organization_id = request.organization_id
         AND requester.id = request.requested_by_membership_id
         AND requester.principal_id = iam_private.current_principal_id()
         AND requester.status = 'active'
        LEFT JOIN iam.job_role_change_requests AS role_change
          ON role_change.organization_id = request.organization_id
         AND role_change.approval_request_id = request.id
        LEFT JOIN iam.tag_change_requests AS tag_change
          ON tag_change.organization_id = request.organization_id
         AND tag_change.approval_request_id = request.id
        WHERE request.organization_id = approval_requirements.organization_id
          AND request.id = approval_requirements.approval_request_id
          AND (
              (
                  request.request_kind = 'carbon_job_role_change'
                  AND iam_private.has_organization_capability(
                      request.organization_id,
                      iam_private.current_principal_id(),
                      'roles.request'
                  )
                  AND (
                      (
                          approval_requirements.requirement_kind = 'specific_membership'
                          AND approval_requirements.specific_membership_id =
                              role_change.target_membership_id
                          AND approval_requirements.required_capability IS NULL
                          AND approval_requirements.quorum = 1
                      )
                      OR (
                          approval_requirements.requirement_kind = 'current_owner_or_admin'
                          AND approval_requirements.specific_membership_id IS NULL
                          AND approval_requirements.required_capability = 'roles.approve'
                          AND approval_requirements.quorum = 1
                      )
                  )
              )
              OR (
                  request.request_kind = 'silicon_job_role_change'
                  AND iam_private.has_organization_capability(
                      request.organization_id,
                      iam_private.current_principal_id(),
                      'roles.request'
                  )
                  AND approval_requirements.requirement_kind = 'current_owner_or_admin'
                  AND approval_requirements.specific_membership_id IS NULL
                  AND approval_requirements.required_capability = 'roles.approve'
                  AND approval_requirements.quorum = 1
              )
              OR (
                  request.request_kind = 'carbon_tag_change'
                  AND requester.principal_kind IN ('carbon', 'silicon')
                  AND (
                      (
                          approval_requirements.requirement_kind = 'specific_membership'
                          AND approval_requirements.specific_membership_id =
                              tag_change.target_membership_id
                          AND approval_requirements.required_capability IS NULL
                          AND approval_requirements.quorum = 1
                      )
                      OR (
                          approval_requirements.requirement_kind = 'current_owner_or_admin'
                          AND approval_requirements.specific_membership_id IS NULL
                          AND approval_requirements.required_capability = 'tags.manage'
                          AND approval_requirements.quorum = 1
                      )
                  )
              )
              OR (
                  request.request_kind = 'silicon_tag_change'
                  AND requester.principal_kind IN ('carbon', 'silicon')
                  AND approval_requirements.requirement_kind = 'current_owner_or_admin'
                  AND approval_requirements.specific_membership_id IS NULL
                  AND approval_requirements.required_capability = 'tags.manage'
                  AND approval_requirements.quorum = 1
              )
              OR (
                  request.request_kind = 'silicon_token_rotation'
                  AND iam_private.has_organization_capability(
                      request.organization_id,
                      iam_private.current_principal_id(),
                      'silicons.rotate_token'
                  )
                  AND approval_requirements.requirement_kind = 'current_owner'
                  AND approval_requirements.specific_membership_id IS NULL
                  AND approval_requirements.required_capability IS NULL
                  AND approval_requirements.quorum = 1
              )
              OR (
                  request.request_kind = 'ownership_transfer'
                  AND requester.principal_kind = 'carbon'
                  AND requester.org_role = 'owner'
                  AND approval_requirements.requirement_kind = 'current_owner'
                  AND approval_requirements.specific_membership_id IS NULL
                  AND approval_requirements.required_capability IS NULL
                  AND approval_requirements.quorum = 1
              )
          )
    )
);

CREATE POLICY tag_change_requests_member_select
ON iam.tag_change_requests FOR SELECT
USING (
    iam_private.is_active_organization_member(
        organization_id, iam_private.current_principal_id()
    )
);

CREATE POLICY tag_change_requests_create
ON iam.tag_change_requests FOR INSERT
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND EXISTS (
        SELECT 1
        FROM iam.approval_requests AS request
        JOIN iam.organization_memberships AS requester
          ON requester.organization_id = request.organization_id
         AND requester.id = request.requested_by_membership_id
        JOIN iam.organization_memberships AS target
          ON target.organization_id = tag_change_requests.organization_id
         AND target.id = tag_change_requests.target_membership_id
        WHERE request.organization_id = tag_change_requests.organization_id
          AND request.id = tag_change_requests.approval_request_id
          AND request.status = 'pending'
          AND requester.principal_id = iam_private.current_principal_id()
          AND requester.principal_kind IN ('carbon', 'silicon')
          AND requester.status = 'active'
          AND target.status = 'active'
          AND target.principal_kind = tag_change_requests.target_principal_kind
          AND request.request_kind = CASE tag_change_requests.target_principal_kind
              WHEN 'carbon' THEN 'carbon_tag_change'
              WHEN 'silicon' THEN 'silicon_tag_change'
          END
    )
);

CREATE POLICY membership_tag_change_history_member_select
ON iam.membership_tag_change_history FOR SELECT
USING (
    iam_private.is_active_organization_member(
        organization_id, iam_private.current_principal_id()
    )
);

-- Existing memberships no longer have a direct tag write policy. Admission
-- functions run with fixed-path definer authority; the one API-side creation
-- path receives an equally narrow, transaction-bound entry point below.
DROP POLICY membership_tags_manage ON iam.membership_tags;

CREATE FUNCTION iam_private.assign_initial_silicon_tags(
    p_organization_id uuid,
    p_membership_id uuid,
    p_actor_membership_id uuid,
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
    active_tag_count integer;
    inserted_count bigint;
BEGIN
    IF p_organization_id IS NULL
       OR p_membership_id IS NULL
       OR p_actor_membership_id IS NULL
       OR p_tag_ids IS NULL
       OR cardinality(p_tag_ids) > 100
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id()
       OR p_tag_ids <> ARRAY(
            SELECT DISTINCT tag_id
            FROM pg_catalog.unnest(p_tag_ids) AS tag_id
            ORDER BY tag_id
       ) THEN
        RAISE EXCEPTION 'initial_silicon_tags_invalid' USING ERRCODE = '22023';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM iam.organization_memberships AS actor
        WHERE actor.organization_id = p_organization_id
          AND actor.id = p_actor_membership_id
          AND actor.principal_id = current_actor_principal_id
          AND actor.status = 'active'
    )
       OR NOT iam_private.has_organization_capability(
            p_organization_id, current_actor_principal_id, 'silicons.create'
       )
       OR (
            cardinality(p_tag_ids) > 0
            AND NOT iam_private.has_organization_capability(
                p_organization_id, current_actor_principal_id, 'tags.manage'
            )
       ) THEN
        RAISE EXCEPTION 'initial_silicon_tags_forbidden' USING ERRCODE = '42501';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM iam.organization_memberships AS membership
        JOIN iam.silicons AS silicon
          ON silicon.organization_id = membership.organization_id
         AND silicon.membership_id = membership.id
         AND silicon.id = membership.principal_id
        WHERE membership.organization_id = p_organization_id
          AND membership.id = p_membership_id
          AND membership.principal_kind = 'silicon'
          AND membership.status = 'active'
          AND membership.xmin::text::bigint = pg_current_xact_id()::text::bigint
          AND silicon.xmin::text::bigint = pg_current_xact_id()::text::bigint
          AND silicon.provisioning_status <> 'deleted'
    ) THEN
        RAISE EXCEPTION 'initial_silicon_tags_target_invalid' USING ERRCODE = '42501';
    END IF;

    SELECT count(*)::integer
    INTO active_tag_count
    FROM iam.organization_tags AS tag
    WHERE tag.organization_id = p_organization_id
      AND tag.id = ANY(p_tag_ids)
      AND tag.status = 'active';

    IF active_tag_count <> cardinality(p_tag_ids) THEN
        RAISE EXCEPTION 'initial_silicon_tags_inactive' USING ERRCODE = '23514';
    END IF;

    INSERT INTO iam.membership_tags (
        organization_id, membership_id, tag_id, assigned_by_membership_id
    )
    SELECT p_organization_id, p_membership_id, requested.tag_id,
           p_actor_membership_id
    FROM pg_catalog.unnest(p_tag_ids) AS requested(tag_id)
    ORDER BY requested.tag_id;
    GET DIAGNOSTICS inserted_count = ROW_COUNT;
    RETURN inserted_count;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.assign_initial_silicon_tags(
    uuid, uuid, uuid, uuid[]
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.assign_initial_silicon_tags(
    uuid, uuid, uuid, uuid[]
) IS
    'Assigns active tags only to a Silicon and membership inserted by the current transaction; existing memberships must use governed tag approval.';

DROP POLICY silicons_update ON iam.silicons;
CREATE POLICY silicons_update
ON iam.silicons FOR UPDATE
USING (
    organization_id = iam_private.current_organization_id()
    AND (
        iam_private.has_organization_capability(
            organization_id, iam_private.current_principal_id(), 'silicons.update_directory'
        )
        OR iam_private.has_organization_capability(
            organization_id, iam_private.current_principal_id(), 'silicons.manage_hierarchy'
        )
        OR iam_private.has_organization_capability(
            organization_id, iam_private.current_principal_id(), 'silicons.rotate_token'
        )
    )
)
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND (
        iam_private.has_organization_capability(
            organization_id, iam_private.current_principal_id(), 'silicons.update_directory'
        )
        OR iam_private.has_organization_capability(
            organization_id, iam_private.current_principal_id(), 'silicons.manage_hierarchy'
        )
        OR iam_private.has_organization_capability(
            organization_id, iam_private.current_principal_id(), 'silicons.rotate_token'
        )
    )
);

CREATE FUNCTION iam_private.apply_approved_tag_change(
    p_organization_id uuid,
    p_approval_request_id uuid,
    p_expected_version bigint
)
RETURNS TABLE (
    applied_membership_id uuid,
    previous_tags uuid[],
    applied_tags uuid[],
    resulting_membership_version bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_actor_principal_id uuid := iam_private.current_principal_id();
    current_actor_membership_id uuid;
    request_kind text;
    request_status text;
    request_expires_at timestamptz;
    payload iam.tag_change_requests%ROWTYPE;
    target_kind iam.principal_kind;
    target_status text;
    current_tag_ids uuid[];
    active_tag_count integer;
    updated_request_count bigint;
BEGIN
    IF p_organization_id IS NULL
       OR p_approval_request_id IS NULL
       OR p_expected_version IS NULL
       OR p_expected_version <= 0
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id()
       OR current_actor_principal_id IS NULL THEN
        RAISE EXCEPTION 'tag_change_apply_invalid' USING ERRCODE = '22023';
    END IF;

    SELECT membership.id
    INTO current_actor_membership_id
    FROM iam.organization_memberships AS membership
    WHERE membership.organization_id = p_organization_id
      AND membership.principal_id = current_actor_principal_id
      AND membership.principal_kind IN ('carbon', 'silicon')
      AND membership.status = 'active'
    LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'tag_change_apply_forbidden' USING ERRCODE = '42501';
    END IF;

    SELECT request.request_kind, request.status, request.expires_at
    INTO request_kind, request_status, request_expires_at
    FROM iam.approval_requests AS request
    WHERE request.organization_id = p_organization_id
      AND request.id = p_approval_request_id
      AND request.version = p_expected_version
    FOR UPDATE OF request;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'tag_change_approval_version_mismatch' USING ERRCODE = 'P0001';
    END IF;
    IF request_status <> 'pending' OR request_expires_at <= transaction_timestamp() THEN
        RAISE EXCEPTION 'tag_change_approval_closed' USING ERRCODE = 'P0001';
    END IF;
    IF request_kind NOT IN ('carbon_tag_change', 'silicon_tag_change') THEN
        RAISE EXCEPTION 'tag_change_apply_invalid' USING ERRCODE = '22023';
    END IF;

    SELECT tag_change.*
    INTO payload
    FROM iam.tag_change_requests AS tag_change
    WHERE tag_change.organization_id = p_organization_id
      AND tag_change.approval_request_id = p_approval_request_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'tag_change_apply_invalid' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM iam.approval_decisions AS decision
        WHERE decision.organization_id = p_organization_id
          AND decision.approval_request_id = p_approval_request_id
          AND decision.decided_by_membership_id = current_actor_membership_id
          AND decision.decision = 'approve'
    ) THEN
        RAISE EXCEPTION 'tag_change_apply_forbidden' USING ERRCODE = '42501';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM iam.approval_decisions AS decision
        WHERE decision.organization_id = p_organization_id
          AND decision.approval_request_id = p_approval_request_id
          AND decision.decision = 'reject'
    ) OR EXISTS (
        SELECT 1
        FROM iam.approval_requirements AS requirement
        WHERE requirement.organization_id = p_organization_id
          AND requirement.approval_request_id = p_approval_request_id
          AND NOT EXISTS (
              SELECT 1
              FROM iam.approval_decisions AS decision
              JOIN iam.organization_memberships AS decider
                ON decider.organization_id = decision.organization_id
               AND decider.id = decision.decided_by_membership_id
              WHERE decision.organization_id = requirement.organization_id
                AND decision.approval_request_id = requirement.approval_request_id
                AND decision.approval_requirement_id = requirement.id
                AND decision.decision = 'approve'
                AND decider.status = 'active'
                AND (
                    (
                        requirement.requirement_kind = 'specific_membership'
                        AND decider.id = requirement.specific_membership_id
                    )
                    OR (
                        requirement.requirement_kind = 'current_owner_or_admin'
                        AND decider.principal_kind = 'carbon'
                        AND (
                            decider.org_role = 'owner'
                            OR (
                                decider.org_role = 'admin'
                                AND iam_private.has_organization_capability(
                                    requirement.organization_id,
                                    decider.principal_id,
                                    requirement.required_capability
                                )
                            )
                        )
                    )
                )
          )
    ) THEN
        RAISE EXCEPTION 'tag_change_requirements_unsatisfied' USING ERRCODE = '42501';
    END IF;

    SELECT membership.principal_kind, membership.status
    INTO target_kind, target_status
    FROM iam.organization_memberships AS membership
    WHERE membership.organization_id = p_organization_id
      AND membership.id = payload.target_membership_id
    FOR UPDATE OF membership;

    IF NOT FOUND
       OR target_status <> 'active'
       OR target_kind <> payload.target_principal_kind THEN
        RAISE EXCEPTION 'tag_change_target_inactive' USING ERRCODE = 'P0001';
    END IF;

    SELECT COALESCE(array_agg(assignment.tag_id ORDER BY assignment.tag_id), ARRAY[]::uuid[])
    INTO current_tag_ids
    FROM iam.membership_tags AS assignment
    WHERE assignment.organization_id = p_organization_id
      AND assignment.membership_id = payload.target_membership_id;

    IF current_tag_ids <> payload.previous_tag_ids THEN
        RAISE EXCEPTION 'tag_change_snapshot_changed' USING ERRCODE = 'P0001';
    END IF;

    PERFORM tag.id
    FROM iam.organization_tags AS tag
    WHERE tag.organization_id = p_organization_id
      AND tag.id = ANY(payload.proposed_tag_ids)
    ORDER BY tag.id
    FOR SHARE OF tag;

    SELECT count(*)::integer
    INTO active_tag_count
    FROM iam.organization_tags AS tag
    WHERE tag.organization_id = p_organization_id
      AND tag.id = ANY(payload.proposed_tag_ids)
      AND tag.status = 'active';

    IF active_tag_count <> cardinality(payload.proposed_tag_ids) THEN
        RAISE EXCEPTION 'tag_change_tag_inactive' USING ERRCODE = 'P0001';
    END IF;

    DELETE FROM iam.membership_tags AS assignment
    WHERE assignment.organization_id = p_organization_id
      AND assignment.membership_id = payload.target_membership_id;

    INSERT INTO iam.membership_tags (
        organization_id, membership_id, tag_id, assigned_by_membership_id
    )
    SELECT p_organization_id, payload.target_membership_id,
           proposed.tag_id, current_actor_membership_id
    FROM pg_catalog.unnest(payload.proposed_tag_ids) AS proposed(tag_id)
    ORDER BY proposed.tag_id;

    UPDATE iam.organization_memberships AS membership
    SET authz_epoch = membership.authz_epoch + 1
    WHERE membership.organization_id = p_organization_id
      AND membership.id = payload.target_membership_id
      AND membership.status = 'active'
    RETURNING membership.version INTO resulting_membership_version;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'tag_change_target_inactive' USING ERRCODE = 'P0001';
    END IF;

    INSERT INTO iam.membership_tag_change_history (
        id, organization_id, membership_id, approval_request_id,
        previous_tag_ids, applied_tag_ids, membership_version
    ) VALUES (
        p_approval_request_id, p_organization_id,
        payload.target_membership_id, p_approval_request_id,
        payload.previous_tag_ids, payload.proposed_tag_ids,
        resulting_membership_version
    );

    UPDATE iam.approval_requests AS request
    SET status = 'applied', approved_at = transaction_timestamp(),
        applied_at = transaction_timestamp()
    WHERE request.organization_id = p_organization_id
      AND request.id = p_approval_request_id
      AND request.version = p_expected_version
      AND request.status = 'pending';
    GET DIAGNOSTICS updated_request_count = ROW_COUNT;

    IF updated_request_count <> 1 THEN
        RAISE EXCEPTION 'tag_change_approval_version_mismatch' USING ERRCODE = 'P0001';
    END IF;

    applied_membership_id := payload.target_membership_id;
    previous_tags := payload.previous_tag_ids;
    applied_tags := payload.proposed_tag_ids;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.apply_approved_tag_change(
    uuid, uuid, bigint
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.apply_approved_tag_change(uuid, uuid, bigint) IS
    'Attests a satisfied tag-change quorum, locks the target and active tags, compares the immutable baseline, applies the tag set, and records history atomically.';

REVOKE ALL ON FUNCTION iam_private.assert_approval_request_shape(uuid) FROM PUBLIC;
