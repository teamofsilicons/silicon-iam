-- Expose one derived UI capability for the caller's selected organization.
-- Internal organization policy flags remain private, and mutations/login keep
-- their own authoritative checks at the point of use.
CREATE FUNCTION iam_private.application_bundle_availability(p_org_id text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT organization.status = 'active'
       AND membership.org_role IN ('owner', 'admin')
       AND organization.trusted_org
       AND organization.allow_bundled_applications
    FROM iam.organizations AS organization
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = organization.id
     AND membership.principal_id = iam_private.current_principal_id()
     AND membership.principal_kind = 'carbon'
     AND membership.status = 'active'
    JOIN iam.principals AS principal
      ON principal.id = membership.principal_id
     AND principal.kind = 'carbon'
     AND principal.status = 'active'
    WHERE organization.org_id = p_org_id
      AND iam_private.current_application_id() IS NULL
      AND (iam_private.current_organization_id() IS NULL
           OR organization.id = iam_private.current_organization_id())
$$;
REVOKE ALL ON FUNCTION iam_private.application_bundle_availability(text) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.application_bundle_availability(text) IS
    'Derived bundle availability for an authenticated Carbon member of the selected organization; NULL for inaccessible organizations.';
