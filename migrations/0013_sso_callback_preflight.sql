-- Reject uncorrelated SSO callbacks before they can consume provider capacity.

CREATE FUNCTION iam_private.is_valid_sso_callback_correlation(
    p_authentication_session_id uuid,
    p_digest_key_versions smallint[],
    p_state_digests bytea[],
    p_nonce_digests bytea[]
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT COALESCE(
        p_authentication_session_id IS NOT NULL
        AND p_authentication_session_id <>
            '00000000-0000-0000-0000-000000000000'::uuid
        AND iam_private.current_principal_id() IS NOT NULL
        AND cardinality(p_digest_key_versions) BETWEEN 1 AND 16
        AND cardinality(p_digest_key_versions) = cardinality(p_state_digests)
        AND cardinality(p_digest_key_versions) = cardinality(p_nonce_digests)
        AND array_position(p_digest_key_versions, NULL) IS NULL
        AND array_position(p_state_digests, NULL) IS NULL
        AND array_position(p_nonce_digests, NULL) IS NULL
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(p_digest_key_versions) AS supplied(key_version)
            WHERE supplied.key_version <= 0
        )
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(p_state_digests) AS supplied(digest)
            WHERE octet_length(supplied.digest) <> 32
        )
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(p_nonce_digests) AS supplied(digest)
            WHERE octet_length(supplied.digest) <> 32
        )
        AND (
            SELECT count(DISTINCT supplied.key_version)
            FROM unnest(p_digest_key_versions) AS supplied(key_version)
        ) = cardinality(p_digest_key_versions)
        AND EXISTS (
            SELECT 1
            FROM iam.sso_authorization_transactions AS authorization_transaction
            JOIN iam.organizations AS organization
              ON organization.id = authorization_transaction.organization_id
             AND organization.status = 'active'
             AND organization.join_method = 'sso'
            JOIN iam.organization_sso_configs AS config
              ON config.organization_id = authorization_transaction.organization_id
             AND config.platform_enabled
             AND config.status = 'active'
             AND config.provider_organization_id IS NOT NULL
            JOIN iam.sso_connections AS connection
              ON connection.organization_id = authorization_transaction.organization_id
             AND connection.id = authorization_transaction.connection_id
             AND connection.status = 'active'
            JOIN iam.principals AS principal
              ON principal.id = authorization_transaction.carbon_id
             AND principal.kind = 'carbon'
             AND principal.status = 'active'
            JOIN iam.authentication_sessions AS authentication_session
              ON authentication_session.id =
                    authorization_transaction.authentication_session_id
             AND authentication_session.subject_principal_id =
                    authorization_transaction.carbon_id
             AND authentication_session.subject_kind = 'carbon'
             AND authentication_session.status = 'active'
             AND authentication_session.idle_expires_at > transaction_timestamp()
             AND authentication_session.absolute_expires_at > transaction_timestamp()
             AND authentication_session.subject_auth_epoch = principal.auth_epoch
            WHERE authorization_transaction.carbon_id =
                    iam_private.current_principal_id()
              AND authorization_transaction.authentication_session_id =
                    p_authentication_session_id
              AND authorization_transaction.status = 'pending'
              AND authorization_transaction.expires_at > transaction_timestamp()
              AND EXISTS (
                  SELECT 1
                  FROM generate_subscripts(p_digest_key_versions, 1) AS candidate(index)
                  WHERE p_digest_key_versions[candidate.index] =
                            authorization_transaction.digest_key_version
                    AND p_state_digests[candidate.index] =
                            authorization_transaction.state_digest
                    AND p_nonce_digests[candidate.index] =
                            authorization_transaction.nonce_digest
              )
        ),
        false
    )
$$;

REVOKE ALL ON FUNCTION iam_private.is_valid_sso_callback_correlation(
    uuid, smallint[], bytea[], bytea[]
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.is_valid_sso_callback_correlation(
    uuid, smallint[], bytea[], bytea[]
) IS
    'Constant-shape browser-session and digest preflight used before an SSO callback may call WorkOS; completion revalidates all authority.';
