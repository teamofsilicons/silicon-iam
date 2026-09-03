-- The invitation notification builds the link the recipient follows, and it
-- had only the organization's display name to work with. It therefore linked
-- to `/invitations/{invitation_id}`, a path no surface serves, so every
-- invitation email led to a not-found page.
--
-- The join screens are addressed by the organization's public handle, so the
-- worker context now returns it alongside the name. Forward-replaced rather
-- than altered: the return type changes, and a fixed-path, PUBLIC-revoked
-- SECURITY DEFINER function is replaced whole so its grants are re-stated in
-- the same migration that changes it.

DROP FUNCTION iam_private.get_worker_invitation_context(uuid, uuid);

CREATE FUNCTION iam_private.get_worker_invitation_context(
    p_invitation_id uuid,
    p_target_carbon_id uuid
)
RETURNS TABLE (
    organization_name text,
    organization_handle text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT organization.name, organization.org_id
    FROM iam.organization_invitations AS invitation
    JOIN iam.organizations AS organization ON organization.id = invitation.organization_id
    WHERE invitation.id = p_invitation_id
      AND invitation.target_carbon_id = p_target_carbon_id
      AND invitation.status = 'pending'
      AND invitation.expires_at > transaction_timestamp()
      AND organization.status = 'active'
$$;

-- The worker's EXECUTE grant is issued by deploy/postgres/runtime-grants.sql,
-- which names this function explicitly. Granting here would fail on a database
-- that has only been migrated, because the runtime roles are provisioned
-- separately and do not exist yet.
REVOKE ALL ON FUNCTION iam_private.get_worker_invitation_context(uuid, uuid) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.get_worker_invitation_context(uuid, uuid) IS
    'Invitation context for the notification worker: the organization display name and the public handle the join screens are addressed by.';
