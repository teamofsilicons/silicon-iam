-- Resolve an authenticated Carbon's pending email invitation without granting
-- the runtime role broad access to contact blind indexes or tenant data.

ALTER TABLE iam.organization_invitations
    ADD COLUMN destination_contact_id uuid,
    ADD COLUMN destination_contact_kind iam.contact_kind
        GENERATED ALWAYS AS ('email'::iam.contact_kind) STORED;

UPDATE iam.organization_invitations AS invitation
SET destination_contact_id = COALESCE(
    (
        SELECT notification.recipient_contact_id
        FROM iam.notification_jobs AS notification
        WHERE notification.notification_kind = 'invitation'
          AND notification.context_type = 'organization_invitation'
          AND notification.context_id = invitation.id
          AND notification.recipient_contact_kind = 'email'
        ORDER BY notification.created_at, notification.id
        LIMIT 1
    ),
    (
        SELECT contact.id
        FROM iam.carbon_contacts AS contact
        WHERE contact.carbon_id = invitation.target_carbon_id
          AND contact.kind = 'email'
        ORDER BY contact.is_primary DESC, contact.created_at, contact.id
        LIMIT 1
    )
);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM iam.organization_invitations AS invitation
        WHERE invitation.destination_contact_id IS NULL
    ) THEN
        RAISE EXCEPTION
            'cannot bind an existing organization invitation to its email contact'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

ALTER TABLE iam.organization_invitations
    ALTER COLUMN destination_contact_id SET NOT NULL,
    ADD CONSTRAINT organization_invitations_destination_carbon_fk
        FOREIGN KEY (target_carbon_id, destination_contact_id)
        REFERENCES iam.carbon_contacts (carbon_id, id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT organization_invitations_destination_kind_fk
        FOREIGN KEY (destination_contact_id, destination_contact_kind)
        REFERENCES iam.carbon_contacts (id, kind)
        ON DELETE RESTRICT;

COMMENT ON COLUMN iam.organization_invitations.destination_contact_id IS
    'Immutable verified email contact selected when the Carbon invitation is created.';

CREATE FUNCTION iam_private.prevent_organization_invitation_target_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, iam
AS $$
BEGIN
    IF NEW.target_carbon_id <> OLD.target_carbon_id
       OR NEW.destination_contact_id <> OLD.destination_contact_id THEN
        RAISE EXCEPTION
            'organization invitation target and destination contact are immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.prevent_organization_invitation_target_change() FROM PUBLIC;

CREATE TRIGGER organization_invitations_immutable_target
BEFORE UPDATE OF target_carbon_id, destination_contact_id
ON iam.organization_invitations
FOR EACH ROW
EXECUTE FUNCTION iam_private.prevent_organization_invitation_target_change();

CREATE FUNCTION iam_private.get_organization_invitation_destination(
    p_organization_id uuid,
    p_invitation_id uuid
)
RETURNS TABLE (
    contact_id uuid,
    contact_kind text,
    contact_ciphertext bytea,
    contact_nonce bytea,
    contact_encryption_key_version smallint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        contact.id,
        contact.kind::text,
        contact.ciphertext,
        contact.nonce,
        contact.encryption_key_version
    FROM iam.organization_invitations AS invitation
    JOIN iam.carbon_contacts AS contact
      ON contact.carbon_id = invitation.target_carbon_id
     AND contact.id = invitation.destination_contact_id
     AND contact.kind = 'email'
     AND contact.verified_at IS NOT NULL
    WHERE invitation.organization_id = p_organization_id
      AND invitation.id = p_invitation_id
      AND p_organization_id = iam_private.current_organization_id()
      AND (
          invitation.target_carbon_id = iam_private.current_principal_id()
          OR iam_private.has_organization_capability(
              p_organization_id,
              iam_private.current_principal_id(),
              'members.invite'
          )
      )
$$;

REVOKE ALL ON FUNCTION iam_private.get_organization_invitation_destination(
    uuid, uuid
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.get_organization_invitation_destination(
    uuid, uuid
) IS
    'Returns only the encrypted immutable invitation email destination to the target Carbon or an authorized invitation manager in the selected tenant.';

CREATE FUNCTION iam_private.resolve_pending_email_join_invitation(
    p_organization_handle text,
    p_email_hmac_key_version smallint,
    p_email_digest bytea
)
RETURNS TABLE (
    organization_id uuid,
    invitation_id uuid,
    invitation_expires_at timestamptz,
    contact_id uuid,
    contact_kind text,
    contact_ciphertext bytea,
    contact_nonce bytea,
    contact_encryption_key_version smallint
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        invitation.organization_id,
        invitation.id,
        invitation.expires_at,
        contact.id,
        contact.kind::text,
        contact.ciphertext,
        contact.nonce,
        contact.encryption_key_version
    FROM iam.contact_blind_indexes AS blind_index
    JOIN iam.carbon_contacts AS contact
      ON contact.id = blind_index.contact_id
     AND contact.kind = blind_index.contact_kind
     AND contact.kind = 'email'
     AND contact.status = 'active'
     AND contact.verified_at IS NOT NULL
    JOIN iam.carbons AS carbon
      ON carbon.id = contact.carbon_id
     AND carbon.deleted_at IS NULL
    JOIN iam.principals AS principal
      ON principal.id = carbon.id
     AND principal.kind = 'carbon'
     AND principal.status = 'active'
     AND principal.id = iam_private.current_principal_id()
    JOIN iam.organization_invitations AS invitation
      ON invitation.target_carbon_id = principal.id
     AND invitation.destination_contact_id = contact.id
     AND invitation.status = 'pending'
     AND invitation.expires_at > transaction_timestamp()
    JOIN iam.organizations AS organization
      ON organization.id = invitation.organization_id
     AND organization.org_id = p_organization_handle
     AND organization.status = 'active'
     AND organization.join_method = 'email'
    WHERE blind_index.contact_kind = 'email'
      AND blind_index.hmac_key_version = p_email_hmac_key_version
      AND blind_index.digest = p_email_digest
      AND octet_length(p_email_digest) = 32
    FOR UPDATE OF invitation
    FOR SHARE OF organization, principal, carbon, contact, blind_index
$$;

REVOKE ALL ON FUNCTION iam_private.resolve_pending_email_join_invitation(
    text, smallint, bytea
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.resolve_pending_email_join_invitation(
    text, smallint, bytea
) IS
    'Locks and returns an authenticated current Carbon pending invitation and exact encrypted verified email destination for an active email-join organization.';
