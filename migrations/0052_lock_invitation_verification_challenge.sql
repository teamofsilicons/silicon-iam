-- Accepting an invitation always answered 404. It has never once succeeded.
--
-- Submitting the code locks the invitation and its verification challenge with
-- `FOR UPDATE`, so the attempt counter and the acceptance cannot race.
-- PostgreSQL applies a table's UPDATE policies to a locking read, and the only
-- policy governing UPDATE on `iam.organization_invitations` is
-- `organization_invitations_manage`, which requires
-- `organization_id = iam_private.current_organization_id()`.
--
-- An invitee has no organization context: they are not a member yet, which is
-- the entire point of holding an invitation. So the row they are explicitly
-- allowed to read — `organization_invitations_authorized_select` grants the
-- target exactly that — could never be locked, and the handler reported the
-- challenge missing.
--
-- Proven against production as the API runtime role with the invitee's
-- principal context:
--
--     selectable : 1
--     lockable   : 0
--     organization_context_unset : t
--
-- Resolved through an owner-rights function so the lock survives. The
-- invitation is still matched on its own id and on the target being the
-- authenticated Carbon, so this grants an invitee nothing beyond the row they
-- could already read.

CREATE FUNCTION iam_private.lock_invitation_verification_challenge(
    p_invitation_id uuid,
    p_target_carbon_id uuid
)
RETURNS TABLE (
    organization_id uuid,
    target_carbon_id uuid,
    invitation_status text,
    invitation_expires_at timestamptz,
    challenge_id uuid,
    code_digest bytea,
    digest_key_version smallint,
    failed_attempts smallint,
    max_attempts smallint,
    delivery_status text,
    cooldown_retry_after_seconds bigint,
    challenge_expires_at timestamptz,
    consumed_at timestamptz,
    superseded_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT invitation.organization_id, invitation.target_carbon_id,
           invitation.status AS invitation_status,
           invitation.expires_at AS invitation_expires_at,
           challenge.id AS challenge_id, challenge.code_digest,
           challenge.digest_key_version, challenge.failed_attempts,
           challenge.max_attempts, challenge.delivery_status,
           CASE
               WHEN challenge.expires_at > transaction_timestamp()
                    AND challenge.consumed_at IS NULL
                    AND challenge.superseded_at IS NULL
                    AND challenge.cooldown_until > transaction_timestamp()
                   THEN GREATEST(
                       1,
                       CEIL(EXTRACT(EPOCH FROM challenge.cooldown_until - transaction_timestamp()))::bigint
                   )
               ELSE 0
           END AS cooldown_retry_after_seconds,
           challenge.expires_at AS challenge_expires_at,
           challenge.consumed_at, challenge.superseded_at
    FROM iam.organization_invitations AS invitation
    JOIN iam.invitation_verification_challenges AS challenge
      ON challenge.organization_id = invitation.organization_id
     AND challenge.invitation_id = invitation.id
     AND challenge.target_carbon_id = invitation.target_carbon_id
    WHERE invitation.id = p_invitation_id
      AND invitation.target_carbon_id = p_target_carbon_id
    ORDER BY challenge.created_at DESC
    LIMIT 1
    FOR UPDATE OF invitation, challenge
$$;

REVOKE ALL ON FUNCTION iam_private.lock_invitation_verification_challenge(uuid, uuid) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.lock_invitation_verification_challenge(uuid, uuid) IS
    'Locks an invitation and its latest verification challenge for the invitee, who holds no organization context and therefore cannot lock the row row security lets them read.';
