-- Retire the public SSO admission-policy feature. An active, tenant-bound
-- WorkOS connection admits an existing Carbon with conservative fixed
-- membership defaults; email invitations remain an independent join flow.

DROP FUNCTION iam_private.complete_sso_authorization(
    uuid, smallint[], bytea[], bytea[], text, text, text, text,
    smallint[], bytea[], text[], uuid, uuid
);

DROP TABLE iam.sso_membership_policy_tags;
DROP TABLE iam.sso_membership_policies;

CREATE FUNCTION iam_private.complete_sso_authorization(
    p_authentication_session_id uuid,
    p_state_digest_key_versions smallint[],
    p_state_digests bytea[],
    p_nonce_digests bytea[],
    p_provider_organization_id text,
    p_provider_connection_id text,
    p_provider_subject text,
    p_contact_digest_key_versions smallint[],
    p_contact_digests bytea[],
    p_new_membership_id uuid,
    p_sso_identity_id uuid
)
RETURNS TABLE (
    organization_id uuid,
    membership_id uuid,
    sso_identity_id uuid,
    membership_created boolean,
    config_version bigint,
    authorization_transaction_id uuid,
    return_uri_ciphertext bytea,
    return_uri_nonce bytea,
    return_uri_encryption_key_version smallint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    current_carbon_id uuid := iam_private.current_principal_id();
    authorization_record iam.sso_authorization_transactions%ROWTYPE;
    membership_record iam.organization_memberships%ROWTYPE;
    membership_found boolean;
    resolved_contact_id uuid;
    resolved_identity_id uuid;
    resolved_config_version bigint;
    was_membership_created boolean := false;
BEGIN
    IF current_carbon_id IS NULL
       OR p_new_membership_id IS NULL
       OR p_new_membership_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_sso_identity_id IS NULL
       OR p_sso_identity_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_provider_organization_id IS NULL
       OR char_length(p_provider_organization_id) NOT BETWEEN 1 AND 255
       OR p_provider_connection_id IS NULL
       OR char_length(p_provider_connection_id) NOT BETWEEN 1 AND 255
       OR p_provider_subject IS NULL
       OR char_length(p_provider_subject) NOT BETWEEN 1 AND 512
       OR p_contact_digest_key_versions IS NULL
       OR p_contact_digests IS NULL
       OR cardinality(p_contact_digest_key_versions) NOT BETWEEN 1 AND 16
       OR cardinality(p_contact_digest_key_versions) <> cardinality(p_contact_digests)
       OR array_position(p_contact_digest_key_versions, NULL) IS NOT NULL
       OR array_position(p_contact_digests, NULL) IS NOT NULL
       OR EXISTS (
            SELECT 1
            FROM unnest(p_contact_digest_key_versions) AS supplied(key_version)
            WHERE supplied.key_version <= 0
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(p_contact_digests) AS supplied(digest)
            WHERE octet_length(supplied.digest) <> 32
       )
       OR (
            SELECT count(DISTINCT supplied.key_version)
            FROM unnest(p_contact_digest_key_versions) AS supplied(key_version)
       ) <> cardinality(p_contact_digest_key_versions) THEN
        RAISE EXCEPTION 'invalid SSO callback input' USING ERRCODE = '22023';
    END IF;

    IF NOT iam_private.is_valid_sso_callback_correlation(
        p_authentication_session_id,
        p_state_digest_key_versions,
        p_state_digests,
        p_nonce_digests
    ) THEN
        RAISE EXCEPTION 'SSO callback correlation is invalid' USING ERRCODE = '23514';
    END IF;

    SELECT authorization_transaction
    INTO authorization_record
    FROM iam.sso_authorization_transactions AS authorization_transaction
    JOIN iam.organizations AS organization
      ON organization.id = authorization_transaction.organization_id
     AND organization.status = 'active'
     AND organization.join_method = 'sso'
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
    JOIN iam.principals AS principal
      ON principal.id = authorization_transaction.carbon_id
     AND principal.kind = 'carbon'
     AND principal.status = 'active'
    JOIN iam.authentication_sessions AS authentication_session
      ON authentication_session.id = authorization_transaction.authentication_session_id
     AND authentication_session.subject_principal_id = authorization_transaction.carbon_id
     AND authentication_session.subject_kind = 'carbon'
     AND authentication_session.status = 'active'
     AND authentication_session.idle_expires_at > transaction_timestamp()
     AND authentication_session.absolute_expires_at > transaction_timestamp()
     AND authentication_session.subject_auth_epoch = principal.auth_epoch
    WHERE authorization_transaction.carbon_id = current_carbon_id
      AND authorization_transaction.authentication_session_id = p_authentication_session_id
      AND authorization_transaction.status = 'pending'
      AND authorization_transaction.expires_at > transaction_timestamp()
      AND EXISTS (
          SELECT 1
          FROM generate_subscripts(p_state_digest_key_versions, 1) AS candidate(index)
          WHERE p_state_digest_key_versions[candidate.index] =
                    authorization_transaction.digest_key_version
            AND p_state_digests[candidate.index] = authorization_transaction.state_digest
            AND p_nonce_digests[candidate.index] = authorization_transaction.nonce_digest
      )
    FOR UPDATE OF authorization_transaction, organization, config, connection;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'SSO callback correlation is invalid' USING ERRCODE = '23514';
    END IF;

    SELECT config.version
    INTO resolved_config_version
    FROM iam.organization_sso_configs AS config
    WHERE config.organization_id = authorization_record.organization_id;

    SELECT contact.id
    INTO resolved_contact_id
    FROM iam.carbon_contacts AS contact
    JOIN iam.contact_blind_indexes AS blind_index
      ON blind_index.contact_id = contact.id
     AND blind_index.contact_kind = contact.kind
    WHERE contact.carbon_id = current_carbon_id
      AND contact.kind = 'email'
      AND contact.status = 'active'
      AND contact.verified_at IS NOT NULL
      AND EXISTS (
          SELECT 1
          FROM generate_subscripts(p_contact_digest_key_versions, 1) AS candidate(index)
          WHERE p_contact_digest_key_versions[candidate.index] = blind_index.hmac_key_version
            AND p_contact_digests[candidate.index] = blind_index.digest
      )
    ORDER BY contact.is_primary DESC, contact.created_at, contact.id
    LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'sso_identity_mismatch' USING ERRCODE = '23514';
    END IF;

    SELECT membership.*
    INTO membership_record
    FROM iam.organization_memberships AS membership
    WHERE membership.organization_id = authorization_record.organization_id
      AND membership.principal_id = current_carbon_id
      AND membership.principal_kind = 'carbon'
    FOR UPDATE OF membership;
    membership_found := FOUND;

    IF NOT membership_found OR membership_record.status <> 'active' THEN
        IF NOT membership_found THEN
            INSERT INTO iam.organization_memberships (
                id, organization_id, principal_id, principal_kind,
                org_role, job_role
            ) VALUES (
                p_new_membership_id,
                authorization_record.organization_id,
                current_carbon_id,
                'carbon',
                'member',
                ''
            )
            RETURNING * INTO membership_record;
            was_membership_created := true;
        ELSE
            UPDATE iam.organization_memberships AS membership
            SET status = 'active',
                suspended_at = NULL,
                removed_at = NULL,
                org_role = 'member',
                role_granted_by_membership_id = NULL,
                job_role = '',
                authz_epoch = membership.authz_epoch + 1
            WHERE membership.organization_id = authorization_record.organization_id
              AND membership.id = membership_record.id
              AND membership.status <> 'active'
            RETURNING membership.* INTO membership_record;
        END IF;

        UPDATE iam.organization_capability_grants AS capability_grant
        SET revoked_by_membership_id = membership_record.id,
            revoked_at = transaction_timestamp(),
            reason = 'membership admitted or reactivated by SSO'
        WHERE capability_grant.organization_id = authorization_record.organization_id
          AND capability_grant.grantee_membership_id = membership_record.id
          AND capability_grant.revoked_at IS NULL;

        INSERT INTO iam.carbon_membership_settings (
            organization_id, membership_id, carbon_id,
            first_silicon_membership_id, default_trust_boundary,
            default_trust_level
        ) VALUES (
            authorization_record.organization_id,
            membership_record.id,
            current_carbon_id,
            NULL,
            'internal',
            'not_trusted'
        )
        ON CONFLICT (membership_id) DO UPDATE
        SET first_silicon_membership_id = NULL,
            default_trust_boundary = 'internal',
            default_trust_level = 'not_trusted';

        DELETE FROM iam.membership_tags AS membership_tag
        WHERE membership_tag.organization_id = authorization_record.organization_id
          AND membership_tag.membership_id = membership_record.id;

        UPDATE iam.extra_silicon_access_grants AS access_grant
        SET revoked_by_membership_id = membership_record.id,
            revoked_at = transaction_timestamp()
        WHERE access_grant.organization_id = authorization_record.organization_id
          AND access_grant.carbon_membership_id = membership_record.id
          AND access_grant.revoked_at IS NULL;
    END IF;

    SELECT identity.id
    INTO resolved_identity_id
    FROM iam.sso_identities AS identity
    WHERE identity.connection_id = authorization_record.connection_id
      AND identity.provider_subject = p_provider_subject
    FOR UPDATE OF identity;

    IF FOUND THEN
        IF EXISTS (
            SELECT 1
            FROM iam.sso_identities AS identity
            WHERE identity.id = resolved_identity_id
              AND identity.carbon_id <> current_carbon_id
        ) THEN
            RAISE EXCEPTION 'sso_identity_conflict' USING ERRCODE = '23505';
        END IF;
        UPDATE iam.sso_identities AS identity
        SET verified_contact_id = resolved_contact_id,
            last_authenticated_at = transaction_timestamp(),
            revoked_at = NULL
        WHERE identity.id = resolved_identity_id;
    ELSE
        IF EXISTS (
            SELECT 1
            FROM iam.sso_identities AS identity
            WHERE identity.connection_id = authorization_record.connection_id
              AND identity.carbon_id = current_carbon_id
        ) THEN
            RAISE EXCEPTION 'sso_identity_conflict' USING ERRCODE = '23505';
        END IF;
        INSERT INTO iam.sso_identities (
            id, organization_id, connection_id, provider_subject,
            carbon_id, verified_contact_id, last_authenticated_at
        ) VALUES (
            p_sso_identity_id,
            authorization_record.organization_id,
            authorization_record.connection_id,
            p_provider_subject,
            current_carbon_id,
            resolved_contact_id,
            transaction_timestamp()
        )
        RETURNING id INTO resolved_identity_id;
    END IF;

    UPDATE iam.sso_authorization_transactions AS authorization_transaction
    SET status = 'completed', consumed_at = transaction_timestamp()
    WHERE authorization_transaction.id = authorization_record.id
      AND authorization_transaction.status = 'pending';

    organization_id := authorization_record.organization_id;
    membership_id := membership_record.id;
    sso_identity_id := resolved_identity_id;
    membership_created := was_membership_created;
    config_version := resolved_config_version;
    authorization_transaction_id := authorization_record.id;
    return_uri_ciphertext := authorization_record.return_uri_ciphertext;
    return_uri_nonce := authorization_record.return_uri_nonce;
    return_uri_encryption_key_version := authorization_record.encryption_key_version;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.complete_sso_authorization(
    uuid, smallint[], bytea[], bytea[], text, text, text,
    smallint[], bytea[], uuid, uuid
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.complete_sso_authorization(
    uuid, smallint[], bytea[], bytea[], text, text, text,
    smallint[], bytea[], uuid, uuid
) IS
    'Completes tenant-bound WorkOS SSO for an existing Carbon and applies conservative fixed defaults on admission or reactivation.';

CREATE OR REPLACE FUNCTION iam_private.lock_sso_membership_activation_state(
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
    invitation_id := NULL;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.lock_sso_membership_activation_state(
    uuid, smallint[], bytea[], bytea[], text, text
) FROM PUBLIC;

COMMENT ON FUNCTION iam_private.lock_sso_membership_activation_state(
    uuid, smallint[], bytea[], bytea[], text, text
) IS
    'Attests and locks one correlated SSO callback plus the Carbon membership before fixed-default admission; invitation admission is handled only by the email join flow.';
