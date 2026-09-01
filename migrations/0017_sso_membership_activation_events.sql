-- Preserve the exact pre-completion membership state used to classify an SSO
-- admission as a creation, reactivation, or ordinary authentication.

CREATE FUNCTION iam_private.lock_sso_membership_activation_state(
    p_authentication_session_id uuid,
    p_digest_key_versions smallint[],
    p_state_digests bytea[],
    p_nonce_digests bytea[],
    p_provider_organization_id text,
    p_provider_connection_id text
)
RETURNS TABLE (
    organization_id uuid,
    membership_id uuid,
    prior_status text,
    prior_version bigint,
    activation_kind text,
    invitation_id uuid
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_carbon_id uuid := iam_private.current_principal_id();
    resolved_organization_id uuid;
    membership_record iam.organization_memberships%ROWTYPE;
    membership_found boolean;
    resolved_invitation_id uuid;
BEGIN
    IF current_carbon_id IS NULL
       OR p_provider_organization_id IS NULL
       OR char_length(p_provider_organization_id) NOT BETWEEN 1 AND 255
       OR p_provider_connection_id IS NULL
       OR char_length(p_provider_connection_id) NOT BETWEEN 1 AND 255
       OR NOT iam_private.is_valid_sso_callback_correlation(
            p_authentication_session_id,
            p_digest_key_versions,
            p_state_digests,
            p_nonce_digests
       ) THEN
        RAISE EXCEPTION 'SSO callback correlation is invalid' USING ERRCODE = '23514';
    END IF;

    SELECT authorization_transaction.organization_id
    INTO resolved_organization_id
    FROM iam.sso_authorization_transactions AS authorization_transaction
    JOIN iam.organization_sso_configs AS config
      ON config.organization_id = authorization_transaction.organization_id
     AND config.platform_enabled
     AND config.status = 'active'
     AND config.provider_organization_id = p_provider_organization_id
    JOIN iam.sso_connections AS connection
      ON connection.organization_id = authorization_transaction.organization_id
     AND connection.id = authorization_transaction.connection_id
     AND connection.provider_connection_id = p_provider_connection_id
     AND connection.status = 'active'
    WHERE authorization_transaction.carbon_id = current_carbon_id
      AND authorization_transaction.authentication_session_id = p_authentication_session_id
      AND authorization_transaction.status = 'pending'
      AND authorization_transaction.expires_at > transaction_timestamp()
      AND EXISTS (
          SELECT 1
          FROM generate_subscripts(p_digest_key_versions, 1) AS candidate(index)
          WHERE p_digest_key_versions[candidate.index] =
                    authorization_transaction.digest_key_version
            AND p_state_digests[candidate.index] = authorization_transaction.state_digest
            AND p_nonce_digests[candidate.index] = authorization_transaction.nonce_digest
      )
    FOR UPDATE OF authorization_transaction, config, connection;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'SSO callback correlation is invalid' USING ERRCODE = '23514';
    END IF;

    SELECT membership.*
    INTO membership_record
    FROM iam.organization_memberships AS membership
    WHERE membership.organization_id = resolved_organization_id
      AND membership.principal_id = current_carbon_id
      AND membership.principal_kind = 'carbon'
    FOR UPDATE OF membership;
    membership_found := FOUND;

    organization_id := resolved_organization_id;
    IF membership_found THEN
        membership_id := membership_record.id;
        prior_status := membership_record.status::text;
        prior_version := membership_record.version;
        activation_kind := CASE membership_record.status
            WHEN 'active' THEN 'unchanged'
            ELSE 'reactivated'
        END;
    ELSE
        membership_id := NULL;
        prior_status := NULL;
        prior_version := NULL;
        activation_kind := 'created';
    END IF;

    IF activation_kind <> 'unchanged' THEN
        SELECT invitation.id
        INTO resolved_invitation_id
        FROM iam.organization_invitations AS invitation
        WHERE invitation.organization_id = resolved_organization_id
          AND invitation.target_carbon_id = current_carbon_id
          AND invitation.status = 'pending'
          AND invitation.expires_at > transaction_timestamp()
        ORDER BY invitation.created_at, invitation.id
        LIMIT 1
        FOR UPDATE OF invitation;
    END IF;
    invitation_id := resolved_invitation_id;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.lock_sso_membership_activation_state(
    uuid, smallint[], bytea[], bytea[], text, text
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.lock_sso_membership_activation_state(
    uuid, smallint[], bytea[], bytea[], text, text
) IS
    'Attests and locks one correlated SSO callback plus the Carbon membership so completion can emit an exact lifecycle event.';
