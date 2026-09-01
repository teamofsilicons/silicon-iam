-- Bind every usable Application to one immutable organization tenant.
--
-- Historical applications were owned by an individual Carbon. A creator is
-- still retained as provenance, but current authority is derived exclusively
-- from an active owner/admin membership in the owning organization.

ALTER TABLE iam.applications
    RENAME COLUMN owner_carbon_id TO created_by_carbon_id;

ALTER TABLE iam.applications
    RENAME CONSTRAINT applications_owner_fk TO applications_creator_fk;

ALTER INDEX iam.applications_owner_idx
    RENAME TO applications_creator_idx;

ALTER TABLE iam.applications
    ADD COLUMN organization_id uuid;

-- An old application can be assigned automatically only when its creator has
-- exactly one active organization membership. Never guess across tenants.
WITH unambiguous_creator_organizations AS (
    SELECT
        application.id AS application_id,
        (array_agg(membership.organization_id ORDER BY membership.organization_id))[1]
            AS organization_id
    FROM iam.applications AS application
    JOIN iam.organization_memberships AS membership
      ON membership.principal_id = application.created_by_carbon_id
     AND membership.principal_kind = 'carbon'
     AND membership.status = 'active'
    JOIN iam.organizations AS organization
      ON organization.id = membership.organization_id
     AND organization.status = 'active'
    GROUP BY application.id
    HAVING count(*) = 1
)
UPDATE iam.applications AS application
SET organization_id = candidate.organization_id
FROM unambiguous_creator_organizations AS candidate
WHERE application.id = candidate.application_id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM iam.applications
        WHERE organization_id IS NULL
    ) THEN
        RAISE EXCEPTION
            'every legacy Application creator must have exactly one active organization membership before migration 0044'
            USING ERRCODE = 'check_violation';
    END IF;
END;
$$;

ALTER TABLE iam.applications
    ALTER COLUMN organization_id SET NOT NULL,
    ADD CONSTRAINT applications_organization_fk
        FOREIGN KEY (organization_id)
        REFERENCES iam.organizations (id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT applications_organization_id_unique
        UNIQUE (organization_id, id);

CREATE INDEX applications_organization_review_idx
    ON iam.applications (organization_id, review_status, created_at DESC, id)
    WHERE organization_id IS NOT NULL;

COMMENT ON TABLE iam.applications IS
    'Organization-owned OAuth clients and OBO participants. The creating Carbon is retained only as provenance.';
COMMENT ON COLUMN iam.applications.organization_id IS
    'Immutable owning organization and Application tenant boundary.';
COMMENT ON COLUMN iam.applications.created_by_carbon_id IS
    'Carbon that submitted the original registration; never an authorization input.';

CREATE OR REPLACE FUNCTION iam_private.prevent_application_identity_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, iam
AS $$
BEGIN
    IF NEW.id <> OLD.id
       OR NEW.app_id <> OLD.app_id
       OR NEW.created_by_carbon_id <> OLD.created_by_carbon_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
        RAISE EXCEPTION 'application identity, creator, and organization are immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.prevent_application_identity_change() FROM PUBLIC;

CREATE FUNCTION iam_private.is_active_organization_owner_or_admin(
    p_organization_id uuid,
    p_carbon_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.organizations AS organization
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.principal_id = p_carbon_id
         AND membership.principal_kind = 'carbon'
         AND membership.org_role IN ('owner', 'admin')
         AND membership.status = 'active'
        JOIN iam.principals AS principal
          ON principal.id = membership.principal_id
         AND principal.kind = 'carbon'
         AND principal.status = 'active'
        WHERE organization.id = p_organization_id
          AND organization.status = 'active'
    )
$$;

REVOKE ALL ON FUNCTION iam_private.is_active_organization_owner_or_admin(uuid, uuid)
    FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.can_read_application(
    p_application_id uuid,
    p_carbon_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.applications AS application
        WHERE application.id = p_application_id
          AND application.organization_id IS NOT NULL
          AND application.deleted_at IS NULL
          AND iam_private.is_active_organization_owner_or_admin(
              application.organization_id,
              p_carbon_id
          )
    )
$$;

CREATE OR REPLACE FUNCTION iam_private.can_manage_application(
    p_application_id uuid,
    p_carbon_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT iam_private.can_read_application(p_application_id, p_carbon_id)
$$;

CREATE OR REPLACE FUNCTION iam_private.can_manage_application_technical(
    p_application_id uuid,
    p_carbon_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT iam_private.can_read_application(p_application_id, p_carbon_id)
$$;

REVOKE ALL ON FUNCTION iam_private.can_read_application(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.can_manage_application(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.can_manage_application_technical(uuid, uuid) FROM PUBLIC;

DROP POLICY applications_owner_admin_or_verified_select ON iam.applications;
DROP POLICY applications_carbon_insert ON iam.applications;

CREATE POLICY applications_organization_manager_or_verified_select
ON iam.applications FOR SELECT
USING (
    iam_private.can_read_application(id, iam_private.current_principal_id())
    OR iam_private.can_administer_application(id, iam_private.current_principal_id())
    OR (
        iam_private.current_principal_id() IS NOT NULL
        AND organization_id IS NOT NULL
        AND review_status = 'verified'
    )
);

CREATE POLICY applications_organization_manager_insert
ON iam.applications FOR INSERT
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND created_by_carbon_id = iam_private.current_principal_id()
    AND iam_private.is_active_organization_owner_or_admin(
        organization_id,
        iam_private.current_principal_id()
    )
);
