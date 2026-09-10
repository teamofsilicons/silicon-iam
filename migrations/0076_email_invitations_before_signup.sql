-- Email invitations can precede Carbon registration. The immutable encrypted
-- email is separate from the Carbon contact that is bound after verification.
ALTER TABLE iam.organization_invitations
    ALTER COLUMN target_carbon_id DROP NOT NULL,
    ALTER COLUMN destination_contact_id DROP NOT NULL,
    ADD COLUMN email_ciphertext bytea,
    ADD COLUMN email_nonce bytea,
    ADD COLUMN email_key_version smallint,
    ADD COLUMN email_key_purpose text GENERATED ALWAYS AS ('contact_aead'::text) STORED,
    ADD COLUMN email_blind_indexes text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT invitation_email_key_fk FOREIGN KEY (email_key_purpose, email_key_version)
        REFERENCES iam.cryptographic_key_versions (purpose, key_version),
    ADD CONSTRAINT invitation_email_shape CHECK (
        (email_ciphertext IS NULL AND email_nonce IS NULL AND email_key_version IS NULL
            AND cardinality(email_blind_indexes) = 0)
        OR (email_ciphertext IS NOT NULL AND octet_length(email_ciphertext) BETWEEN 17 AND 336
            AND email_nonce IS NOT NULL AND octet_length(email_nonce) = 12
            AND email_key_version IS NOT NULL AND email_key_version > 0
            AND cardinality(email_blind_indexes) > 0
            AND array_position(email_blind_indexes, NULL) IS NULL)
    ),
    ADD CONSTRAINT invitation_target_shape CHECK (
        (target_carbon_id IS NOT NULL AND destination_contact_id IS NOT NULL)
        OR (target_carbon_id IS NULL AND destination_contact_id IS NULL
            AND email_ciphertext IS NOT NULL AND status <> 'accepted')
    );
COMMENT ON TABLE iam.organization_invitations IS
    '48-hour email invitations; an existing Carbon is optional until verified email binding.';

ALTER TABLE iam.notification_jobs ALTER COLUMN recipient_contact_id DROP NOT NULL;
ALTER TABLE iam.notification_jobs ADD CONSTRAINT notification_unregistered_recipient CHECK (
    recipient_contact_id IS NOT NULL OR
    (notification_kind = 'invitation' AND recipient_contact_kind = 'email'
        AND context_type = 'organization_invitation' AND template_id = 'invitation.created')
);
CREATE UNIQUE INDEX notification_unregistered_invitation_idx
    ON iam.notification_jobs (context_id) WHERE recipient_contact_id IS NULL;

CREATE OR REPLACE FUNCTION iam_private.prevent_organization_invitation_target_change()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, iam AS $$
BEGIN
    IF NEW.email_ciphertext IS DISTINCT FROM OLD.email_ciphertext
       OR NEW.email_nonce IS DISTINCT FROM OLD.email_nonce
       OR NEW.email_key_version IS DISTINCT FROM OLD.email_key_version
       OR NEW.email_blind_indexes IS DISTINCT FROM OLD.email_blind_indexes THEN
        RAISE EXCEPTION 'invitation email is immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.target_carbon_id IS NOT DISTINCT FROM OLD.target_carbon_id
       AND NEW.destination_contact_id IS NOT DISTINCT FROM OLD.destination_contact_id THEN
        RETURN NEW;
    END IF;
    -- The only allowed change is the first binding to the authenticated owner
    -- of an active verified email matching the invitation's blind index.
    IF OLD.target_carbon_id IS NOT NULL OR OLD.destination_contact_id IS NOT NULL
       OR OLD.status <> 'pending' OR OLD.expires_at <= transaction_timestamp()
       OR NEW.target_carbon_id IS DISTINCT FROM iam_private.current_principal_id()
       OR NOT EXISTS (
            SELECT 1 FROM iam.carbon_contacts AS contact
            JOIN iam.contact_blind_indexes AS idx ON idx.contact_id = contact.id
                AND idx.contact_kind = 'email'
            JOIN iam.principals AS principal ON principal.id = contact.carbon_id
                AND principal.kind = 'carbon' AND principal.status = 'active'
            JOIN iam.carbons AS carbon ON carbon.id = principal.id AND carbon.deleted_at IS NULL
            WHERE contact.id = NEW.destination_contact_id
                AND contact.carbon_id = NEW.target_carbon_id
                AND contact.kind = 'email' AND contact.status = 'active'
                AND contact.verified_at IS NOT NULL
                AND (idx.hmac_key_version::text || ':' || encode(idx.digest, 'hex'))
                    = ANY(OLD.email_blind_indexes)
       ) THEN
        RAISE EXCEPTION 'invitation target cannot be changed' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.prevent_organization_invitation_target_change() FROM PUBLIC;
DROP TRIGGER organization_invitations_immutable_target ON iam.organization_invitations;
CREATE TRIGGER organization_invitations_immutable_target BEFORE UPDATE
ON iam.organization_invitations FOR EACH ROW
EXECUTE FUNCTION iam_private.prevent_organization_invitation_target_change();

CREATE OR REPLACE FUNCTION iam_private.resolve_pending_email_join_invitation(
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
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    selected_organization uuid;
    selected_contact uuid;
BEGIN
    SELECT org.id INTO selected_organization FROM iam.organizations AS org
    WHERE org.org_id = p_organization_handle AND org.status = 'active' AND org.join_method = 'email';
    IF selected_organization IS NULL THEN RETURN; END IF;
    -- Creation and binding share a tenant lock, including across signup races.
    PERFORM pg_advisory_xact_lock(hashtextextended(selected_organization::text, 7319));
    SELECT contact.id INTO selected_contact
    FROM iam.contact_blind_indexes AS idx
    JOIN iam.carbon_contacts AS contact ON contact.id = idx.contact_id AND contact.kind = 'email'
        AND contact.status = 'active' AND contact.verified_at IS NOT NULL
    JOIN iam.principals AS principal ON principal.id = contact.carbon_id
        AND principal.kind = 'carbon' AND principal.status = 'active'
    JOIN iam.carbons AS carbon ON carbon.id = principal.id AND carbon.deleted_at IS NULL
    WHERE principal.id = iam_private.current_principal_id()
        AND idx.contact_kind = 'email' AND idx.hmac_key_version = p_email_hmac_key_version
        AND idx.digest = p_email_digest AND octet_length(p_email_digest) = 32
    FOR SHARE OF contact, principal, carbon, idx;
    IF selected_contact IS NULL THEN RETURN; END IF;
    UPDATE iam.organization_invitations AS pending
    SET target_carbon_id = iam_private.current_principal_id(), destination_contact_id = selected_contact
    WHERE pending.organization_id = selected_organization AND pending.target_carbon_id IS NULL
        AND pending.status = 'pending' AND pending.expires_at > transaction_timestamp()
        AND (p_email_hmac_key_version::text || ':' || encode(p_email_digest, 'hex'))
            = ANY(pending.email_blind_indexes);
    RETURN QUERY SELECT
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
    FOR SHARE OF organization, principal, carbon, contact, blind_index;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.resolve_pending_email_join_invitation(
    text, smallint, bytea
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.resolve_pending_email_join_invitation(
    text, smallint, bytea
) IS
    'Locks and returns an authenticated current Carbon pending invitation and exact encrypted verified email destination for an active email-join organization.';

-- An invitation without a Carbon uses only its own encrypted destination.
-- The worker must own a live lease for this exact notification.
CREATE FUNCTION iam_private.get_worker_email_invitation(p_job_id uuid, p_lease_owner text)
RETURNS TABLE (invitation_id uuid, ciphertext bytea, nonce bytea, encryption_key_version smallint,
    organization_name text, organization_handle text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam AS $$
    SELECT invitation.id, invitation.email_ciphertext, invitation.email_nonce,
        invitation.email_key_version, org.name, org.org_id
    FROM iam.notification_jobs AS job
    JOIN iam.organization_invitations AS invitation ON invitation.id = job.context_id
    JOIN iam.organizations AS org ON org.id = invitation.organization_id
    WHERE job.id = p_job_id AND job.lease_owner = p_lease_owner
        AND job.status = 'processing' AND job.lease_expires_at > transaction_timestamp()
        AND job.notification_kind = 'invitation' AND job.context_type = 'organization_invitation'
        AND job.template_id = 'invitation.created' AND job.recipient_contact_id IS NULL
        AND job.recipient_contact_kind = 'email' AND invitation.email_ciphertext IS NOT NULL
        AND invitation.status = 'pending' AND invitation.expires_at > transaction_timestamp()
        AND org.status = 'active'
$$;
REVOKE ALL ON FUNCTION iam_private.get_worker_email_invitation(uuid, text) FROM PUBLIC;
