-- Registering an application always answered 404.
--
-- `resolve_creation_organization` reads the organization and the caller's
-- membership with `FOR SHARE`, to hold them still between the authority check
-- and the insert. PostgreSQL applies a table's UPDATE policy to a locking read,
-- and `organizations_authorized_update` requires
-- `id = iam_private.current_organization_id()`. That setting is only chosen
-- once the organization has been resolved, so the lookup had to know its answer
-- before it could produce it: the lock silently matched nothing and the handler
-- reported the organization missing.
--
-- Proven against production: the same statement returns one row without
-- `FOR SHARE` and none with it, while `current_organization_id()` is null.
--
-- Resolving through an owner-rights function keeps the lock — the point of the
-- original query — without asking row security to answer a question that
-- cannot be answered yet. The authority predicate is unchanged and still
-- evaluated here, so this narrows nothing: an owner or admin of an active
-- organization, and nobody else.

CREATE FUNCTION iam_private.lock_application_creation_organization(
    p_organization_handle text,
    p_carbon_id uuid
)
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT organization.id
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
    WHERE organization.org_id = p_organization_handle
      AND organization.status = 'active'
    FOR SHARE OF organization, membership, principal
$$;

REVOKE ALL ON FUNCTION iam_private.lock_application_creation_organization(text, uuid) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.lock_application_creation_organization(text, uuid) IS
    'Resolves and share-locks the organization an application is being registered under, for a Carbon who owns or administers it.';
