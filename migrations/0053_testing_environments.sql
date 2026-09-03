-- Organization-owned testing environments.
--
-- A testing environment is a disposable replica of Silicon IAM: the same API
-- surface, the same schema, the same rules, pointed at a separate testing
-- database instead of production. This migration defines only the control
-- plane, which belongs in the production database next to the organizations
-- that own the environments. The data plane -- the schema the environments
-- actually run against, and the per-environment isolation applied to it --
-- lives in the testing database and is prepared by migrations/testing.
--
-- Nothing here is reachable from a testing environment: the control plane is
-- deliberately not replicated, so an environment cannot mint, rotate, or
-- destroy environments.

CREATE TABLE iam.testing_environments (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    created_by_membership_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    status text NOT NULL DEFAULT 'active',
    -- The environment key is both a lookup credential and a retrievable
    -- secret: administrators can read it back at any time, so unlike every
    -- other credential in this schema it is stored reversibly under AEAD in
    -- addition to its lookup digest.
    key_generation integer NOT NULL DEFAULT 1,
    key_digest bytea NOT NULL,
    key_digest_key_version smallint NOT NULL,
    key_ciphertext bytea NOT NULL,
    key_nonce bytea NOT NULL,
    key_encryption_key_version smallint NOT NULL,
    key_rotated_at timestamptz,
    last_activity_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    cleaned_at timestamptz,
    deleted_at timestamptz,
    purge_after timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT testing_environments_organization_fk
        FOREIGN KEY (organization_id) REFERENCES iam.organizations (id),
    CONSTRAINT testing_environments_creator_fk
        FOREIGN KEY (organization_id, created_by_membership_id)
        REFERENCES iam.organization_memberships (organization_id, id),
    CONSTRAINT testing_environments_status
        CHECK (status IN ('active', 'deleted')),
    CONSTRAINT testing_environments_name_format
        CHECK (name ~ '^[[:print:]]{1,64}$' AND btrim(name) = name),
    CONSTRAINT testing_environments_description_length
        CHECK (description IS NULL OR length(description) BETWEEN 1 AND 500),
    CONSTRAINT testing_environments_positive_version CHECK (version > 0),
    CONSTRAINT testing_environments_positive_key_generation
        CHECK (key_generation > 0),
    CONSTRAINT testing_environments_key_rotation_consistency
        CHECK ((key_generation > 1) = (key_rotated_at IS NOT NULL)),
    CONSTRAINT testing_environments_key_material_lengths CHECK (
        octet_length(key_digest) = 32
        AND octet_length(key_nonce) = 12
        AND octet_length(key_ciphertext) BETWEEN 17 AND 256
    ),
    CONSTRAINT testing_environments_positive_key_versions
        CHECK (key_digest_key_version > 0 AND key_encryption_key_version > 0),
    -- A deleted environment keeps its row for the recovery window. The two
    -- timestamps move together so a restore cannot leave a stale deadline
    -- behind, and an environment can never be scheduled for purge while it is
    -- still serving traffic.
    CONSTRAINT testing_environments_deletion_consistency CHECK (
        (status = 'deleted') = (deleted_at IS NOT NULL)
        AND (deleted_at IS NULL) = (purge_after IS NULL)
        AND (purge_after IS NULL OR purge_after > deleted_at)
    )
);

COMMENT ON TABLE iam.testing_environments IS
    'Organization-owned replicas of Silicon IAM backed by the separate testing database.';
COMMENT ON COLUMN iam.testing_environments.key_digest IS
    'Peppered lookup digest of the 32-character environment key; never the key itself.';
COMMENT ON COLUMN iam.testing_environments.key_ciphertext IS
    'AEAD-encrypted environment key, retrievable by an environment administrator.';
COMMENT ON COLUMN iam.testing_environments.last_activity_at IS
    'Last observed use of the environment; drives the idle auto-delete sweep.';
COMMENT ON COLUMN iam.testing_environments.purge_after IS
    'Deadline after which a deleted environment and its data are destroyed permanently.';

-- One live name per organization. Deleted environments are excluded so a name
-- becomes reusable the moment it is released, without waiting out the recovery
-- window.
CREATE UNIQUE INDEX testing_environments_active_name_key
    ON iam.testing_environments (organization_id, lower(name))
    WHERE status = 'active';

-- Key resolution happens on every request that carries an environment key, so
-- it must be a single index probe. Uniqueness is a genuine invariant here: two
-- environments cannot share a key.
CREATE UNIQUE INDEX testing_environments_key_digest_key
    ON iam.testing_environments (key_digest);

CREATE INDEX testing_environments_organization_idx
    ON iam.testing_environments (organization_id, id);

CREATE INDEX testing_environments_idle_sweep_idx
    ON iam.testing_environments (last_activity_at, id)
    WHERE status = 'active';

CREATE INDEX testing_environments_purge_sweep_idx
    ON iam.testing_environments (purge_after, id)
    WHERE status = 'deleted';

CREATE TRIGGER testing_environments_bump_aggregate_version
    BEFORE UPDATE ON iam.testing_environments
    FOR EACH ROW
    EXECUTE FUNCTION iam_private.bump_aggregate_version();

CREATE FUNCTION iam_private.prevent_testing_environment_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id <> OLD.id
       OR NEW.organization_id <> OLD.organization_id
       OR NEW.created_by_membership_id <> OLD.created_by_membership_id
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'testing environment identity is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.key_generation < OLD.key_generation THEN
        RAISE EXCEPTION 'testing environment key generation cannot move backwards'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION iam_private.prevent_testing_environment_identity_change() IS
    'Keeps environment ownership, creator attribution, and key generation monotonic.';

REVOKE ALL ON FUNCTION iam_private.prevent_testing_environment_identity_change() FROM PUBLIC;

CREATE TRIGGER testing_environments_immutable_identity
    BEFORE UPDATE ON iam.testing_environments
    FOR EACH ROW
    EXECUTE FUNCTION iam_private.prevent_testing_environment_identity_change();

-- Resolves the caller's own active membership in one organization.
--
-- Row-level security on iam.organization_memberships already hides other
-- tenants, but the environment policies below need the membership identity
-- itself rather than a yes/no answer, and they must keep working while the
-- transaction has not yet selected an organization.
CREATE FUNCTION iam_private.active_organization_membership_id(
    p_organization_id uuid,
    p_principal_id uuid
)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT membership.id
    FROM iam.organization_memberships AS membership
    JOIN iam.organizations AS organization
      ON organization.id = membership.organization_id
     AND organization.status = 'active'
    JOIN iam.principals AS principal
      ON principal.id = membership.principal_id
     AND principal.kind = membership.principal_kind
     AND principal.status = 'active'
    WHERE membership.organization_id = p_organization_id
      AND membership.principal_id = p_principal_id
      AND membership.status = 'active'
$$;

COMMENT ON FUNCTION iam_private.active_organization_membership_id(uuid, uuid) IS
    'Returns the caller''s own active membership identity, or NULL when there is none.';

REVOKE ALL ON FUNCTION iam_private.active_organization_membership_id(uuid, uuid) FROM PUBLIC;

-- Administrative authority over one environment.
--
-- The creator keeps administrative rights for as long as they remain an active
-- member, and every organization owner or administrator has the same authority
-- regardless of who created the environment. Silicons are admissible on both
-- paths: they can create environments, and they hold administrative authority
-- whenever their membership carries the role.
CREATE FUNCTION iam_private.is_testing_environment_administrator(
    p_organization_id uuid,
    p_created_by_membership_id uuid,
    p_principal_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.organization_memberships AS membership
        JOIN iam.organizations AS organization
          ON organization.id = membership.organization_id
         AND organization.status = 'active'
        JOIN iam.principals AS principal
          ON principal.id = membership.principal_id
         AND principal.kind = membership.principal_kind
         AND principal.status = 'active'
        WHERE membership.organization_id = p_organization_id
          AND membership.principal_id = p_principal_id
          AND membership.status = 'active'
          AND (
              membership.id = p_created_by_membership_id
              OR membership.org_role IN ('owner', 'admin')
          )
    )
$$;

COMMENT ON FUNCTION iam_private.is_testing_environment_administrator(uuid, uuid, uuid) IS
    'Grants environment administration to its creator and to every organization owner or admin.';

REVOKE ALL ON FUNCTION iam_private.is_testing_environment_administrator(uuid, uuid, uuid)
    FROM PUBLIC;

ALTER TABLE iam.testing_environments ENABLE ROW LEVEL SECURITY;

-- Every active member can see that an environment exists. The key is a
-- separate, administrator-only projection enforced above this layer; row
-- security only decides which rows are visible at all.
CREATE POLICY testing_environments_member_select
ON iam.testing_environments FOR SELECT
USING (
    iam_private.is_active_organization_member(
        organization_id, iam_private.current_principal_id()
    )
);

-- Any active member may create one, and only as themselves: the stored creator
-- has to be the caller's own membership, so attribution cannot be forged.
CREATE POLICY testing_environments_member_insert
ON iam.testing_environments FOR INSERT
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND created_by_membership_id = iam_private.active_organization_membership_id(
        organization_id, iam_private.current_principal_id()
    )
);

CREATE POLICY testing_environments_administrator_update
ON iam.testing_environments FOR UPDATE
USING (
    organization_id = iam_private.current_organization_id()
    AND iam_private.is_testing_environment_administrator(
        organization_id, created_by_membership_id, iam_private.current_principal_id()
    )
)
WITH CHECK (organization_id = iam_private.current_organization_id());

-- Resolves an environment key digest to its environment.
--
-- Called before any principal is known, on a connection whose row-security
-- context is still empty, so it must run as the owner. It answers only for
-- live environments and returns no key material.
CREATE FUNCTION iam_private.resolve_testing_environment(
    p_key_digests bytea[]
)
RETURNS TABLE (
    testing_environment_id uuid,
    organization_id uuid,
    key_digest_key_version smallint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        environment.id,
        environment.organization_id,
        environment.key_digest_key_version
    FROM iam.testing_environments AS environment
    JOIN iam.organizations AS organization
      ON organization.id = environment.organization_id
     AND organization.status = 'active'
    WHERE environment.status = 'active'
      AND environment.key_digest = ANY (p_key_digests)
    LIMIT 1
$$;

COMMENT ON FUNCTION iam_private.resolve_testing_environment(bytea[]) IS
    'Resolves a presented environment key digest to a live environment; returns no secrets.';

REVOKE ALL ON FUNCTION iam_private.resolve_testing_environment(bytea[]) FROM PUBLIC;

-- Records that an environment was used.
--
-- Called on the request path once a key has been accepted, outside the
-- request's own transaction and without a principal context, so it runs as the
-- owner. The write is coarse on purpose: it moves the idle deadline forward at
-- most once per hour, which keeps a busy environment from turning every
-- request into a row update.
CREATE FUNCTION iam_private.touch_testing_environment(
    p_testing_environment_id uuid
)
RETURNS void
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    UPDATE iam.testing_environments
    SET last_activity_at = transaction_timestamp()
    WHERE id = p_testing_environment_id
      AND status = 'active'
      AND last_activity_at < transaction_timestamp() - interval '1 hour'
$$;

COMMENT ON FUNCTION iam_private.touch_testing_environment(uuid) IS
    'Advances the idle deadline of a live environment at most hourly.';

REVOKE ALL ON FUNCTION iam_private.touch_testing_environment(uuid) FROM PUBLIC;

-- Soft-deletes environments that have gone quiet.
--
-- Idleness is measured from last_activity_at, which every accepted request
-- advances. An auto-deleted environment is indistinguishable from a manually
-- deleted one: it keeps the same recovery window before the purge sweep
-- destroys it.
CREATE FUNCTION iam_private.expire_idle_testing_environments(
    p_idle_days integer,
    p_recovery_days integer,
    p_limit integer
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    expired_count bigint;
BEGIN
    IF p_idle_days < 1 OR p_idle_days > 3650
       OR p_recovery_days < 1 OR p_recovery_days > 3650
       OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'testing environment maintenance arguments are out of range'
            USING ERRCODE = '22023';
    END IF;

    WITH idle AS MATERIALIZED (
        SELECT environment.id
        FROM iam.testing_environments AS environment
        WHERE environment.status = 'active'
          AND environment.last_activity_at
              <= transaction_timestamp() - make_interval(days => p_idle_days)
        ORDER BY environment.last_activity_at, environment.id
        FOR UPDATE SKIP LOCKED
        LIMIT p_limit
    )
    UPDATE iam.testing_environments AS environment
    SET status = 'deleted',
        deleted_at = transaction_timestamp(),
        purge_after = transaction_timestamp() + make_interval(days => p_recovery_days)
    FROM idle
    WHERE environment.id = idle.id;
    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$$;

COMMENT ON FUNCTION iam_private.expire_idle_testing_environments(integer, integer, integer) IS
    'Soft-deletes environments with no activity inside the configured idle window.';

REVOKE ALL ON FUNCTION iam_private.expire_idle_testing_environments(
    integer, integer, integer
) FROM PUBLIC;

-- Lists environments whose recovery window has closed.
--
-- The worker destroys the environment's rows in the testing database before it
-- calls purge_testing_environment, so this returns candidates rather than
-- deleting anything. The two databases cannot share a transaction; ordering
-- the work this way means a crash in between leaves an already-emptied
-- environment that the next sweep picks up again.
CREATE FUNCTION iam_private.list_testing_environments_for_purge(
    p_limit integer
)
RETURNS TABLE (testing_environment_id uuid)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
BEGIN
    IF p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'testing environment purge limit must be between 1 and 1000'
            USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT environment.id
    FROM iam.testing_environments AS environment
    WHERE environment.status = 'deleted'
      AND environment.purge_after <= transaction_timestamp()
    ORDER BY environment.purge_after, environment.id
    LIMIT p_limit;
END;
$$;

COMMENT ON FUNCTION iam_private.list_testing_environments_for_purge(integer) IS
    'Lists soft-deleted environments whose recovery window has elapsed.';

REVOKE ALL ON FUNCTION iam_private.list_testing_environments_for_purge(integer) FROM PUBLIC;

-- Destroys one control-plane row after its data has been erased.
--
-- Re-checks the deadline under the row lock so a restore that landed between
-- listing and purging wins the race.
CREATE FUNCTION iam_private.purge_testing_environment(
    p_testing_environment_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    purged_count bigint;
BEGIN
    WITH purgeable AS MATERIALIZED (
        SELECT environment.id
        FROM iam.testing_environments AS environment
        WHERE environment.id = p_testing_environment_id
          AND environment.status = 'deleted'
          AND environment.purge_after <= transaction_timestamp()
        FOR UPDATE
    )
    DELETE FROM iam.testing_environments AS environment
    USING purgeable
    WHERE environment.id = purgeable.id;
    GET DIAGNOSTICS purged_count = ROW_COUNT;
    RETURN purged_count = 1;
END;
$$;

COMMENT ON FUNCTION iam_private.purge_testing_environment(uuid) IS
    'Removes one environment whose recovery window elapsed and whose data is already erased.';

REVOKE ALL ON FUNCTION iam_private.purge_testing_environment(uuid) FROM PUBLIC;
