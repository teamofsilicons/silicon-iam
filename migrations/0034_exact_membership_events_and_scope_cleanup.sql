-- Retire product surfaces that are not part of the strict IAM contract and
-- make membership-removal side effects independently ordered resources.

DROP FUNCTION IF EXISTS iam_private.archive_organization_tag(uuid, uuid, bigint, boolean);

-- Approval requests are durable governance records, not expiring challenges.
-- Preserve timestamps on terminal historical rows, but remove the invented
-- deadline from every request that can still be acted on.
ALTER TABLE iam.approval_requests
    ALTER COLUMN expires_at DROP NOT NULL,
    DROP CONSTRAINT approval_requests_expiry;

UPDATE iam.approval_requests
SET expires_at = NULL
WHERE status IN ('pending', 'approved')
  AND expires_at IS NOT NULL;

DROP INDEX iam.approval_requests_pending_idx;
CREATE INDEX approval_requests_pending_idx
    ON iam.approval_requests (organization_id, status, id)
    WHERE status = 'pending';

COMMENT ON COLUMN iam.approval_requests.expires_at IS
    'Legacy terminal-history field. New and actionable governance requests do not expire.';

DROP FUNCTION iam_private.lock_membership_removal_event_scope(uuid, uuid);

CREATE FUNCTION iam_private.lock_membership_removal_event_scope(
    p_organization_id uuid,
    p_membership_id uuid,
    p_reassign_reports_to uuid
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
    direct_report_count bigint;
    target_level integer;
    replacement_level integer := 0;
    hierarchy_delta integer := 0;
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
      AND membership.status = 'active'
    FOR UPDATE OF membership;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'membership_version_mismatch' USING ERRCODE = 'P0001';
    END IF;
    IF target_membership.org_role = 'owner' THEN
        RAISE EXCEPTION 'owner_cannot_be_removed' USING ERRCODE = 'P0001';
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
        PERFORM pg_advisory_xact_lock(hashtextextended(p_organization_id::text, 734921));

        PERFORM silicon.id
        FROM iam.silicons AS silicon
        WHERE silicon.organization_id = p_organization_id
          AND silicon.membership_id = p_membership_id
          AND silicon.id = target_membership.principal_id
          AND silicon.provisioning_status <> 'deleted'
        FOR UPDATE OF silicon;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'silicon_version_mismatch' USING ERRCODE = 'P0001';
        END IF;

        SELECT count(*)
        INTO direct_report_count
        FROM iam.silicons AS report
        WHERE report.organization_id = p_organization_id
          AND report.reports_to_membership_id = p_membership_id
          AND report.provisioning_status <> 'deleted';

        IF direct_report_count > 0 AND p_reassign_reports_to IS NULL THEN
            RAISE EXCEPTION 'reassign_reports_to_required' USING ERRCODE = 'P0001';
        END IF;
        IF p_reassign_reports_to = p_membership_id
           OR (
                p_reassign_reports_to IS NOT NULL
                AND NOT EXISTS (
                    SELECT 1
                    FROM iam.silicons AS replacement
                    JOIN iam.organization_memberships AS replacement_membership
                      ON replacement_membership.organization_id = replacement.organization_id
                     AND replacement_membership.id = replacement.membership_id
                     AND replacement_membership.status = 'active'
                    JOIN iam.principals AS replacement_principal
                      ON replacement_principal.id = replacement.id
                     AND replacement_principal.kind = 'silicon'
                     AND replacement_principal.status = 'active'
                    WHERE replacement.organization_id = p_organization_id
                      AND replacement.membership_id = p_reassign_reports_to
                      AND replacement.provisioning_status <> 'deleted'
                )
           ) THEN
            RAISE EXCEPTION 'invalid_reporting_hierarchy' USING ERRCODE = 'P0001';
        END IF;

        IF p_reassign_reports_to IS NOT NULL AND EXISTS (
            WITH RECURSIVE descendants AS (
                SELECT child.membership_id
                FROM iam.silicons AS child
                WHERE child.organization_id = p_organization_id
                  AND child.reports_to_membership_id = p_membership_id
                  AND child.provisioning_status <> 'deleted'
                UNION ALL
                SELECT child.membership_id
                FROM iam.silicons AS child
                JOIN descendants AS parent
                  ON child.reports_to_membership_id = parent.membership_id
                WHERE child.organization_id = p_organization_id
                  AND child.provisioning_status <> 'deleted'
            )
            SELECT 1
            FROM descendants
            WHERE membership_id = p_reassign_reports_to
        ) THEN
            RAISE EXCEPTION 'invalid_reporting_hierarchy' USING ERRCODE = 'P0001';
        END IF;

        WITH RECURSIVE ancestors AS (
            SELECT silicon.membership_id, silicon.reports_to_membership_id
            FROM iam.silicons AS silicon
            WHERE silicon.organization_id = p_organization_id
              AND silicon.membership_id = p_membership_id
              AND silicon.provisioning_status <> 'deleted'
            UNION ALL
            SELECT parent.membership_id, parent.reports_to_membership_id
            FROM iam.silicons AS parent
            JOIN ancestors AS child
              ON child.reports_to_membership_id = parent.membership_id
            WHERE parent.organization_id = p_organization_id
              AND parent.provisioning_status <> 'deleted'
        )
        SELECT count(*)::integer INTO target_level FROM ancestors;

        IF p_reassign_reports_to IS NOT NULL THEN
            WITH RECURSIVE ancestors AS (
                SELECT silicon.membership_id, silicon.reports_to_membership_id
                FROM iam.silicons AS silicon
                WHERE silicon.organization_id = p_organization_id
                  AND silicon.membership_id = p_reassign_reports_to
                  AND silicon.provisioning_status <> 'deleted'
                UNION ALL
                SELECT parent.membership_id, parent.reports_to_membership_id
                FROM iam.silicons AS parent
                JOIN ancestors AS child
                  ON child.reports_to_membership_id = parent.membership_id
                WHERE parent.organization_id = p_organization_id
                  AND parent.provisioning_status <> 'deleted'
            )
            SELECT count(*)::integer INTO replacement_level FROM ancestors;
        END IF;
        hierarchy_delta := replacement_level - target_level;

        -- The hierarchy advisory lock prevents the affected descendant set
        -- from changing. Side-table rows and every projected membership are
        -- then locked in deterministic identifier order before Rust captures
        -- their exact before state.
        PERFORM report.id
        FROM iam.silicons AS report
        WHERE report.organization_id = p_organization_id
          AND report.provisioning_status <> 'deleted'
          AND report.membership_id IN (
              WITH RECURSIVE descendants AS (
                  SELECT child.membership_id, 1 AS depth
                  FROM iam.silicons AS child
                  WHERE child.organization_id = p_organization_id
                    AND child.reports_to_membership_id = p_membership_id
                    AND child.provisioning_status <> 'deleted'
                  UNION ALL
                  SELECT child.membership_id, parent.depth + 1
                  FROM iam.silicons AS child
                  JOIN descendants AS parent
                    ON child.reports_to_membership_id = parent.membership_id
                  WHERE child.organization_id = p_organization_id
                    AND child.provisioning_status <> 'deleted'
              )
              SELECT membership_id
              FROM descendants
              WHERE depth = 1 OR hierarchy_delta <> 0
          )
        ORDER BY report.membership_id
        FOR UPDATE OF report;

        PERFORM settings.membership_id
        FROM iam.carbon_membership_settings AS settings
        WHERE settings.organization_id = p_organization_id
          AND settings.first_silicon_membership_id = p_membership_id
        ORDER BY settings.membership_id
        FOR UPDATE OF settings;

        PERFORM access_grant.carbon_membership_id
        FROM iam.extra_silicon_access_grants AS access_grant
        WHERE access_grant.organization_id = p_organization_id
          AND access_grant.silicon_membership_id = p_membership_id
          AND access_grant.revoked_at IS NULL
        ORDER BY access_grant.carbon_membership_id, access_grant.granted_at
        FOR UPDATE OF access_grant;
    ELSIF p_reassign_reports_to IS NOT NULL THEN
        RAISE EXCEPTION 'membership_removal_invalid' USING ERRCODE = '22023';
    END IF;

    WITH RECURSIVE descendants AS (
        SELECT child.membership_id, 1 AS depth
        FROM iam.silicons AS child
        WHERE target_membership.principal_kind = 'silicon'
          AND child.organization_id = p_organization_id
          AND child.reports_to_membership_id = p_membership_id
          AND child.provisioning_status <> 'deleted'
        UNION ALL
        SELECT child.membership_id, parent.depth + 1
        FROM iam.silicons AS child
        JOIN descendants AS parent
          ON child.reports_to_membership_id = parent.membership_id
        WHERE child.organization_id = p_organization_id
          AND child.provisioning_status <> 'deleted'
    ), affected AS (
        SELECT p_membership_id AS membership_id
        UNION
        SELECT membership_id FROM descendants WHERE depth = 1 OR hierarchy_delta <> 0
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
    ), locked AS (
        SELECT membership.id
        FROM iam.organization_memberships AS membership
        JOIN affected ON affected.membership_id = membership.id
        WHERE membership.organization_id = p_organization_id
          AND membership.status = 'active'
        ORDER BY membership.id
        FOR UPDATE OF membership
    )
    SELECT array_agg(id ORDER BY id)
    INTO affected_membership_ids
    FROM locked;

    RETURN COALESCE(affected_membership_ids, ARRAY[p_membership_id]::uuid[]);
END;
$$;

REVOKE ALL ON FUNCTION iam_private.lock_membership_removal_event_scope(uuid, uuid, uuid)
FROM PUBLIC;

COMMENT ON FUNCTION iam_private.lock_membership_removal_event_scope(uuid, uuid, uuid) IS
    'Attests removal authority and locks the exact target and surviving membership projections changed by the transition.';

CREATE OR REPLACE FUNCTION iam_private.remove_organization_membership(
    p_organization_id uuid,
    p_membership_id uuid,
    p_expected_membership_version bigint,
    p_expected_silicon_version bigint,
    p_reassign_reports_to uuid
)
RETURNS TABLE (
    principal_id uuid,
    principal_kind iam.principal_kind,
    membership_version bigint,
    silicon_version bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_actor_id uuid := iam_private.current_principal_id();
    actor_membership_id uuid;
    target_membership iam.organization_memberships%ROWTYPE;
    target_silicon iam.silicons%ROWTYPE;
    resulting_membership_version bigint;
    resulting_silicon_version bigint;
    removal_scope uuid[];
    surviving_membership_ids uuid[];
    access_changed_membership_ids uuid[] := ARRAY[]::uuid[];
    target_level integer;
    replacement_level integer := 0;
    hierarchy_delta integer := 0;
BEGIN
    IF p_organization_id IS NULL
       OR p_membership_id IS NULL
       OR p_expected_membership_version IS NULL
       OR p_expected_membership_version <= 0
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id() THEN
        RAISE EXCEPTION 'membership_removal_invalid' USING ERRCODE = '22023';
    END IF;

    SELECT membership.id
    INTO actor_membership_id
    FROM iam.organization_memberships AS membership
    JOIN iam.principals AS principal
      ON principal.id = membership.principal_id
     AND principal.kind = membership.principal_kind
     AND principal.status = 'active'
    WHERE membership.organization_id = p_organization_id
      AND membership.principal_id = current_actor_id
      AND membership.status = 'active';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'membership_removal_forbidden' USING ERRCODE = '42501';
    END IF;

    removal_scope := iam_private.lock_membership_removal_event_scope(
        p_organization_id,
        p_membership_id,
        p_reassign_reports_to
    );
    SELECT COALESCE(array_agg(scope_id ORDER BY scope_id), ARRAY[]::uuid[])
    INTO surviving_membership_ids
    FROM unnest(removal_scope) AS scope_id
    WHERE scope_id <> p_membership_id;

    SELECT membership.*
    INTO target_membership
    FROM iam.organization_memberships AS membership
    WHERE membership.organization_id = p_organization_id
      AND membership.id = p_membership_id
    FOR UPDATE OF membership;

    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF target_membership.status <> 'active'
       OR target_membership.version <> p_expected_membership_version THEN
        RAISE EXCEPTION 'membership_version_mismatch' USING ERRCODE = 'P0001';
    END IF;

    IF target_membership.principal_kind = 'silicon' THEN
        IF p_expected_silicon_version IS NULL OR p_expected_silicon_version <= 0 THEN
            RAISE EXCEPTION 'silicon_version_mismatch' USING ERRCODE = 'P0001';
        END IF;
        SELECT silicon.*
        INTO target_silicon
        FROM iam.silicons AS silicon
        WHERE silicon.organization_id = p_organization_id
          AND silicon.id = target_membership.principal_id
          AND silicon.membership_id = target_membership.id
        FOR UPDATE OF silicon;

        IF NOT FOUND
           OR target_silicon.provisioning_status = 'deleted'
           OR target_silicon.version <> p_expected_silicon_version THEN
            RAISE EXCEPTION 'silicon_version_mismatch' USING ERRCODE = 'P0001';
        END IF;

        WITH RECURSIVE ancestors AS (
            SELECT silicon.membership_id, silicon.reports_to_membership_id
            FROM iam.silicons AS silicon
            WHERE silicon.organization_id = p_organization_id
              AND silicon.membership_id = p_membership_id
              AND silicon.provisioning_status <> 'deleted'
            UNION ALL
            SELECT parent.membership_id, parent.reports_to_membership_id
            FROM iam.silicons AS parent
            JOIN ancestors AS child
              ON child.reports_to_membership_id = parent.membership_id
            WHERE parent.organization_id = p_organization_id
              AND parent.provisioning_status <> 'deleted'
        )
        SELECT count(*)::integer INTO target_level FROM ancestors;

        IF p_reassign_reports_to IS NOT NULL THEN
            WITH RECURSIVE ancestors AS (
                SELECT silicon.membership_id, silicon.reports_to_membership_id
                FROM iam.silicons AS silicon
                WHERE silicon.organization_id = p_organization_id
                  AND silicon.membership_id = p_reassign_reports_to
                  AND silicon.provisioning_status <> 'deleted'
                UNION ALL
                SELECT parent.membership_id, parent.reports_to_membership_id
                FROM iam.silicons AS parent
                JOIN ancestors AS child
                  ON child.reports_to_membership_id = parent.membership_id
                WHERE parent.organization_id = p_organization_id
                  AND parent.provisioning_status <> 'deleted'
            )
            SELECT count(*)::integer INTO replacement_level FROM ancestors;
        END IF;
        hierarchy_delta := replacement_level - target_level;

        SELECT COALESCE(
            array_agg(DISTINCT access_grant.carbon_membership_id
                      ORDER BY access_grant.carbon_membership_id),
            ARRAY[]::uuid[]
        )
        INTO access_changed_membership_ids
        FROM iam.extra_silicon_access_grants AS access_grant
        WHERE access_grant.organization_id = p_organization_id
          AND access_grant.silicon_membership_id = p_membership_id
          AND access_grant.revoked_at IS NULL;

        UPDATE iam.silicons AS report
        SET reports_to_membership_id = p_reassign_reports_to
        WHERE report.organization_id = p_organization_id
          AND report.reports_to_membership_id = p_membership_id
          AND report.provisioning_status <> 'deleted';

        IF hierarchy_delta <> 0 THEN
            WITH RECURSIVE descendants AS (
                SELECT child.membership_id, 1 AS depth
                FROM iam.silicons AS child
                WHERE child.organization_id = p_organization_id
                  AND child.reports_to_membership_id = p_reassign_reports_to
                  AND child.membership_id = ANY(surviving_membership_ids)
                  AND child.provisioning_status <> 'deleted'
                UNION ALL
                SELECT child.membership_id, parent.depth + 1
                FROM iam.silicons AS child
                JOIN descendants AS parent
                  ON child.reports_to_membership_id = parent.membership_id
                WHERE child.organization_id = p_organization_id
                  AND child.provisioning_status <> 'deleted'
            )
            UPDATE iam.silicons AS descendant
            SET updated_at = transaction_timestamp()
            FROM descendants
            WHERE descendants.depth > 1
              AND descendant.organization_id = p_organization_id
              AND descendant.membership_id = descendants.membership_id
              AND descendant.provisioning_status <> 'deleted';
        END IF;

        UPDATE iam.carbon_membership_settings AS settings
        SET first_silicon_membership_id = NULL
        WHERE settings.organization_id = p_organization_id
          AND settings.first_silicon_membership_id = p_membership_id;

        UPDATE iam.silicon_hooks AS hook
        SET status = 'disabled',
            last_error_code = NULL,
            next_attempt_at = NULL,
            lease_owner = NULL,
            lease_expires_at = NULL
        WHERE hook.organization_id = p_organization_id
          AND hook.silicon_id = target_membership.principal_id
          AND hook.status <> 'disabled';

        UPDATE iam.silicon_credentials AS credential
        SET status = 'retired', retired_at = transaction_timestamp()
        WHERE credential.organization_id = p_organization_id
          AND credential.silicon_id = target_membership.principal_id
          AND credential.status = 'active';

        UPDATE iam.refresh_token_families AS family
        SET status = 'revoked',
            revoked_at = transaction_timestamp(),
            revocation_reason = 'Silicon removed'
        WHERE family.subject_principal_id = target_membership.principal_id
          AND family.status = 'active';

        UPDATE iam.authentication_sessions AS authentication_session
        SET status = 'revoked',
            revoked_at = transaction_timestamp(),
            revocation_reason = 'Silicon removed',
            version = authentication_session.version + 1
        WHERE authentication_session.subject_principal_id = target_membership.principal_id
          AND authentication_session.status = 'active';

        UPDATE iam.access_tokens AS access_token
        SET revoked_at = transaction_timestamp(),
            revocation_reason = 'Silicon removed'
        WHERE access_token.subject_principal_id = target_membership.principal_id
          AND access_token.revoked_at IS NULL;

        UPDATE iam.silicons AS silicon
        SET provisioning_status = 'deleted', deleted_at = transaction_timestamp()
        WHERE silicon.organization_id = p_organization_id
          AND silicon.id = target_membership.principal_id
          AND silicon.version = p_expected_silicon_version
          AND silicon.provisioning_status <> 'deleted'
        RETURNING silicon.version INTO resulting_silicon_version;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'silicon_version_mismatch' USING ERRCODE = 'P0001';
        END IF;

        UPDATE iam.principals AS principal
        SET status = 'deleted',
            auth_epoch = principal.auth_epoch + 1,
            deleted_at = transaction_timestamp()
        WHERE principal.id = target_membership.principal_id
          AND principal.kind = 'silicon'
          AND principal.status <> 'deleted';
    ELSE
        IF p_expected_silicon_version IS NOT NULL OR p_reassign_reports_to IS NOT NULL THEN
            RAISE EXCEPTION 'membership_removal_invalid' USING ERRCODE = '22023';
        END IF;
    END IF;

    UPDATE iam.organization_capability_grants AS capability_grant
    SET revoked_by_membership_id = actor_membership_id,
        revoked_at = transaction_timestamp(),
        reason = 'membership removed'
    WHERE capability_grant.organization_id = p_organization_id
      AND capability_grant.grantee_membership_id = target_membership.id
      AND capability_grant.revoked_at IS NULL;

    DELETE FROM iam.membership_tags AS membership_tag
    WHERE membership_tag.organization_id = p_organization_id
      AND membership_tag.membership_id = target_membership.id;

    UPDATE iam.extra_silicon_access_grants AS access_grant
    SET revoked_by_membership_id = actor_membership_id,
        revoked_at = transaction_timestamp()
    WHERE access_grant.organization_id = p_organization_id
      AND (
          access_grant.carbon_membership_id = target_membership.id
          OR access_grant.silicon_membership_id = target_membership.id
      )
      AND access_grant.revoked_at IS NULL;

    -- Every surviving membership whose public directory/authorization state
    -- changed receives exactly one independent aggregate version. Only loss of
    -- an explicit Silicon-access grant changes its authorization epoch.
    UPDATE iam.organization_memberships AS membership
    SET authz_epoch = membership.authz_epoch
            + CASE WHEN membership.id = ANY(access_changed_membership_ids) THEN 1 ELSE 0 END,
        updated_at = transaction_timestamp()
    WHERE membership.organization_id = p_organization_id
      AND membership.id = ANY(surviving_membership_ids)
      AND membership.status = 'active';

    UPDATE iam.organization_memberships AS membership
    SET status = 'removed',
        removed_at = transaction_timestamp(),
        suspended_at = NULL,
        org_role = 'member',
        role_granted_by_membership_id = NULL,
        authz_epoch = membership.authz_epoch + 1
    WHERE membership.organization_id = p_organization_id
      AND membership.id = target_membership.id
      AND membership.version = p_expected_membership_version
      AND membership.status = 'active'
    RETURNING membership.version INTO resulting_membership_version;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'membership_version_mismatch' USING ERRCODE = 'P0001';
    END IF;

    UPDATE iam.access_tokens AS access_token
    SET revoked_at = transaction_timestamp(),
        revocation_reason = 'organization membership removed'
    WHERE access_token.organization_id = p_organization_id
      AND access_token.membership_id = target_membership.id
      AND access_token.revoked_at IS NULL;

    principal_id := target_membership.principal_id;
    principal_kind := target_membership.principal_kind;
    membership_version := resulting_membership_version;
    silicon_version := resulting_silicon_version;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.remove_organization_membership(
    uuid, uuid, bigint, bigint, uuid
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.remove_organization_membership(uuid, uuid, bigint, bigint, uuid) IS
    'Removes one membership and advances each surviving membership or Silicon aggregate whose projected state changes exactly once.';
