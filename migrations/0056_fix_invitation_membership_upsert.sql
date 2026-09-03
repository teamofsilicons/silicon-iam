-- Accepting an invitation answered 500 the moment it got far enough to try.
--
-- `0052_lock_invitation_verification_challenge.sql` cleared the 404 that had
-- stopped every acceptance before it reached the real work. What that
-- uncovered was the next failure in the same path, and it is fatal twice over.
--
-- This function returns `RETURNS TABLE (organization_id, membership_id,
-- membership_version)`, which puts all three names in scope as PL/pgSQL
-- variables. Both of its upserts then name an arbiter built from those very
-- words -- `ON CONFLICT (organization_id, principal_id)` on
-- `iam.organization_memberships`, and `ON CONFLICT (membership_id)` on
-- `iam.carbon_membership_settings`. A conflict target is resolved against the
-- function's variables as well as the table's columns, so with
-- `plpgsql.variable_conflict` at its default of `error` each one is
-- unresolvable:
--
--     ERROR:  column reference "organization_id" is ambiguous
--     DETAIL:  It could refer to either a PL/pgSQL variable or a table column.
--     CONTEXT: PL/pgSQL function
--              iam_private.complete_verified_organization_invitation(...)
--              line 149 at SQL statement
--
-- The function has carried this since `0006_audit_outbox_and_rls.sql` first
-- defined it, so no Carbon has ever joined an organization by invitation.
--
-- Naming the constraints takes both arbiters out of name resolution entirely.
-- `organization_memberships_organization_id_principal_id_key` is the
-- `UNIQUE (organization_id, principal_id)` declared inline in
-- `0002_organizations_and_directory.sql`, and `carbon_membership_settings_pkey`
-- is that table's primary key on `(membership_id)`: each is exactly the index
-- its inference clause was already asking for, so which row is arbitrated does
-- not change. Renaming the output columns would have removed the collision at
-- its source, but they are what the caller selects by name, so this keeps the
-- fix inside the function.

CREATE OR REPLACE FUNCTION iam_private.complete_verified_organization_invitation(
    p_organization_handle text,
    p_invitation_id uuid,
    p_new_membership_id uuid,
    p_digest_key_version smallint,
    p_code_digest bytea
)
RETURNS TABLE (
    organization_id uuid,
    membership_id uuid,
    membership_version bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
DECLARE
    current_carbon_id uuid := iam_private.current_principal_id();
    invitation_record iam.organization_invitations%ROWTYPE;
    resolved_membership_id uuid;
    resolved_membership_version bigint;
    expected_tag_count integer;
    active_tag_count integer;
    expected_extra_count integer;
    active_extra_count integer;
    expected_tag_trust_count integer;
    active_tag_trust_count integer;
    expected_silicon_trust_count integer;
    active_silicon_trust_count integer;
BEGIN
    IF current_carbon_id IS NULL
       OR p_new_membership_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_digest_key_version <= 0
       OR octet_length(p_code_digest) <> 32 THEN
        RAISE EXCEPTION 'organization invitation cannot be completed' USING ERRCODE = '22023';
    END IF;

    SELECT invitation.*
    INTO invitation_record
    FROM iam.organization_invitations AS invitation
    JOIN iam.organizations AS organization
      ON organization.id = invitation.organization_id
     AND organization.org_id = p_organization_handle
     AND organization.status = 'active'
    JOIN iam.principals AS principal
      ON principal.id = invitation.target_carbon_id
     AND principal.kind = 'carbon'
     AND principal.status = 'active'
    WHERE invitation.id = p_invitation_id
      AND invitation.target_carbon_id = current_carbon_id
      AND invitation.status = 'pending'
      AND invitation.expires_at > transaction_timestamp()
    FOR UPDATE OF invitation;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization invitation cannot be completed' USING ERRCODE = '23514';
    END IF;

    PERFORM 1
    FROM iam.invitation_verification_challenges AS challenge
    JOIN iam.carbon_contacts AS contact
      ON contact.carbon_id = challenge.target_carbon_id
     AND contact.id = challenge.destination_contact_id
     AND contact.status = 'active'
     AND contact.verified_at IS NOT NULL
    WHERE challenge.organization_id = invitation_record.organization_id
      AND challenge.invitation_id = invitation_record.id
      AND challenge.target_carbon_id = current_carbon_id
      AND challenge.digest_key_version = p_digest_key_version
      AND challenge.code_digest = p_code_digest
      AND challenge.failed_attempts < challenge.max_attempts
      AND challenge.consumed_at IS NULL
      AND challenge.superseded_at IS NULL
      AND challenge.expires_at > transaction_timestamp()
      AND (challenge.cooldown_until IS NULL OR challenge.cooldown_until <= transaction_timestamp())
    FOR UPDATE OF challenge;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization invitation cannot be completed' USING ERRCODE = '23514';
    END IF;

    SELECT count(*) INTO expected_tag_count
    FROM iam.organization_invitation_tags AS tag_assignment
    WHERE tag_assignment.organization_id = invitation_record.organization_id
      AND tag_assignment.invitation_id = invitation_record.id;
    SELECT count(*) INTO active_tag_count
    FROM iam.organization_invitation_tags AS assignment
    JOIN iam.organization_tags AS tag
      ON tag.organization_id = assignment.organization_id
     AND tag.id = assignment.tag_id
     AND tag.status = 'active'
    WHERE assignment.organization_id = invitation_record.organization_id
      AND assignment.invitation_id = invitation_record.id;

    SELECT count(*) INTO expected_extra_count
    FROM iam.organization_invitation_extra_silicons AS extra_assignment
    WHERE extra_assignment.organization_id = invitation_record.organization_id
      AND extra_assignment.invitation_id = invitation_record.id;
    SELECT count(*) INTO active_extra_count
    FROM iam.organization_invitation_extra_silicons AS assignment
    JOIN iam.silicons AS silicon
      ON silicon.organization_id = assignment.organization_id
     AND silicon.membership_id = assignment.silicon_membership_id
     AND silicon.provisioning_status <> 'deleted'
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = silicon.organization_id
     AND membership.id = silicon.membership_id
     AND membership.status = 'active'
    WHERE assignment.organization_id = invitation_record.organization_id
      AND assignment.invitation_id = invitation_record.id;

    SELECT count(*) INTO expected_tag_trust_count
    FROM iam.organization_invitation_tag_trust_overrides AS trust_override
    WHERE trust_override.organization_id = invitation_record.organization_id
      AND trust_override.invitation_id = invitation_record.id;
    SELECT count(*) INTO active_tag_trust_count
    FROM iam.organization_invitation_tag_trust_overrides AS trust_override
    JOIN iam.organization_tags AS tag
      ON tag.organization_id = trust_override.organization_id
     AND tag.id = trust_override.tag_id
     AND tag.status = 'active'
    WHERE trust_override.organization_id = invitation_record.organization_id
      AND trust_override.invitation_id = invitation_record.id;

    SELECT count(*) INTO expected_silicon_trust_count
    FROM iam.organization_invitation_silicon_trust_overrides AS trust_override
    WHERE trust_override.organization_id = invitation_record.organization_id
      AND trust_override.invitation_id = invitation_record.id;
    SELECT count(*) INTO active_silicon_trust_count
    FROM iam.organization_invitation_silicon_trust_overrides AS trust_override
    JOIN iam.silicons AS silicon
      ON silicon.organization_id = trust_override.organization_id
     AND silicon.membership_id = trust_override.silicon_membership_id
     AND silicon.provisioning_status <> 'deleted'
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = silicon.organization_id
     AND membership.id = silicon.membership_id
     AND membership.status = 'active'
    WHERE trust_override.organization_id = invitation_record.organization_id
      AND trust_override.invitation_id = invitation_record.id;

    IF expected_tag_count <> active_tag_count
       OR expected_extra_count <> active_extra_count
       OR expected_tag_trust_count <> active_tag_trust_count
       OR expected_silicon_trust_count <> active_silicon_trust_count
       OR (
            invitation_record.first_silicon_membership_id IS NOT NULL
            AND NOT EXISTS (
                SELECT 1
                FROM iam.silicons AS silicon
                JOIN iam.organization_memberships AS membership
                  ON membership.organization_id = silicon.organization_id
                 AND membership.id = silicon.membership_id
                 AND membership.status = 'active'
                WHERE silicon.organization_id = invitation_record.organization_id
                  AND silicon.membership_id = invitation_record.first_silicon_membership_id
                  AND silicon.provisioning_status <> 'deleted'
            )
       ) THEN
        RAISE EXCEPTION 'organization invitation defaults are no longer active'
            USING ERRCODE = '23514';
    END IF;

    INSERT INTO iam.organization_memberships (
        id, organization_id, principal_id, principal_kind, org_role, job_role
    ) VALUES (
        p_new_membership_id,
        invitation_record.organization_id,
        current_carbon_id,
        'carbon',
        'member',
        invitation_record.job_role
    )
    ON CONFLICT ON CONSTRAINT organization_memberships_organization_id_principal_id_key
    DO UPDATE
    SET status = 'active',
        suspended_at = NULL,
        removed_at = NULL,
        org_role = 'member',
        job_role = EXCLUDED.job_role,
        role_granted_by_membership_id = NULL,
        authz_epoch = iam.organization_memberships.authz_epoch + 1
    WHERE iam.organization_memberships.principal_kind = 'carbon'
      AND iam.organization_memberships.status <> 'active'
    RETURNING id, version
    INTO resolved_membership_id, resolved_membership_version;

    IF resolved_membership_id IS NULL THEN
        RAISE EXCEPTION 'organization membership is already active' USING ERRCODE = '23505';
    END IF;

    UPDATE iam.organization_capability_grants AS capability_grant
    SET revoked_by_membership_id = resolved_membership_id,
        revoked_at = transaction_timestamp(),
        reason = 'membership reactivated from a new invitation'
    WHERE capability_grant.organization_id = invitation_record.organization_id
      AND capability_grant.grantee_membership_id = resolved_membership_id
      AND capability_grant.revoked_at IS NULL;

    INSERT INTO iam.carbon_membership_settings (
        organization_id,
        membership_id,
        carbon_id,
        first_silicon_membership_id,
        default_trust_boundary,
        default_trust_level
    ) VALUES (
        invitation_record.organization_id,
        resolved_membership_id,
        current_carbon_id,
        invitation_record.first_silicon_membership_id,
        invitation_record.default_trust_boundary,
        invitation_record.default_trust_level
    )
    ON CONFLICT ON CONSTRAINT carbon_membership_settings_pkey DO UPDATE
    SET first_silicon_membership_id = EXCLUDED.first_silicon_membership_id,
        default_trust_boundary = EXCLUDED.default_trust_boundary,
        default_trust_level = EXCLUDED.default_trust_level;

    DELETE FROM iam.membership_tags AS membership_tag
    WHERE membership_tag.organization_id = invitation_record.organization_id
      AND membership_tag.membership_id = resolved_membership_id;
    INSERT INTO iam.membership_tags (
        organization_id, membership_id, tag_id, assigned_by_membership_id
    )
    SELECT
        assignment.organization_id,
        resolved_membership_id,
        assignment.tag_id,
        invitation_record.invited_by_membership_id
    FROM iam.organization_invitation_tags AS assignment
    WHERE assignment.organization_id = invitation_record.organization_id
      AND assignment.invitation_id = invitation_record.id;

    UPDATE iam.extra_silicon_access_grants AS access_grant
    SET revoked_by_membership_id = resolved_membership_id,
        revoked_at = transaction_timestamp()
    WHERE access_grant.organization_id = invitation_record.organization_id
      AND access_grant.carbon_membership_id = resolved_membership_id
      AND access_grant.revoked_at IS NULL;
    INSERT INTO iam.extra_silicon_access_grants (
        organization_id,
        carbon_membership_id,
        silicon_membership_id,
        granted_by_membership_id
    )
    SELECT
        assignment.organization_id,
        resolved_membership_id,
        assignment.silicon_membership_id,
        invitation_record.invited_by_membership_id
    FROM iam.organization_invitation_extra_silicons AS assignment
    WHERE assignment.organization_id = invitation_record.organization_id
      AND assignment.invitation_id = invitation_record.id;

    UPDATE iam.trust_rules AS trust_rule
    SET archived_at = transaction_timestamp(),
        updated_by_membership_id = invitation_record.invited_by_membership_id
    WHERE trust_rule.organization_id = invitation_record.organization_id
      AND trust_rule.subject_kind = 'membership'
      AND trust_rule.subject_membership_id = resolved_membership_id
      AND trust_rule.archived_at IS NULL;

    INSERT INTO iam.trust_rules (
        id,
        organization_id,
        subject_kind,
        subject_membership_id,
        target_kind,
        target_tag_id,
        trust_boundary,
        trust_level,
        created_by_membership_id,
        updated_by_membership_id
    )
    SELECT
        trust_override.id,
        trust_override.organization_id,
        'membership',
        resolved_membership_id,
        'tag',
        trust_override.tag_id,
        trust_override.trust_boundary,
        trust_override.trust_level,
        invitation_record.invited_by_membership_id,
        invitation_record.invited_by_membership_id
    FROM iam.organization_invitation_tag_trust_overrides AS trust_override
    WHERE trust_override.organization_id = invitation_record.organization_id
      AND trust_override.invitation_id = invitation_record.id;

    INSERT INTO iam.trust_rules (
        id,
        organization_id,
        subject_kind,
        subject_membership_id,
        target_kind,
        target_silicon_membership_id,
        trust_boundary,
        trust_level,
        created_by_membership_id,
        updated_by_membership_id
    )
    SELECT
        trust_override.id,
        trust_override.organization_id,
        'membership',
        resolved_membership_id,
        'silicon',
        trust_override.silicon_membership_id,
        trust_override.trust_boundary,
        trust_override.trust_level,
        invitation_record.invited_by_membership_id,
        invitation_record.invited_by_membership_id
    FROM iam.organization_invitation_silicon_trust_overrides AS trust_override
    WHERE trust_override.organization_id = invitation_record.organization_id
      AND trust_override.invitation_id = invitation_record.id;

    UPDATE iam.invitation_verification_challenges AS challenge
    SET consumed_at = transaction_timestamp()
    WHERE challenge.organization_id = invitation_record.organization_id
      AND challenge.invitation_id = invitation_record.id
      AND challenge.target_carbon_id = current_carbon_id
      AND challenge.digest_key_version = p_digest_key_version
      AND challenge.code_digest = p_code_digest
      AND challenge.consumed_at IS NULL
      AND challenge.superseded_at IS NULL;
    UPDATE iam.organization_invitations AS invitation
    SET status = 'accepted', accepted_at = transaction_timestamp()
    WHERE invitation.organization_id = invitation_record.organization_id
      AND invitation.id = invitation_record.id
      AND invitation.status = 'pending';

    organization_id := invitation_record.organization_id;
    membership_id := resolved_membership_id;
    membership_version := resolved_membership_version;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.complete_verified_organization_invitation(
    text, uuid, uuid, smallint, bytea
) FROM PUBLIC;
