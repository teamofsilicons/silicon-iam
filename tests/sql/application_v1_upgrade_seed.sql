-- Seed at migration 0076, before the v1 scope catalog exists. Compatible with
-- production and a testing database that already applied overlays 9001..9003.
DO $fixture$
DECLARE
    environment_number integer;
    application_number integer;
    fixture_prefix text;
    environment_id uuid;
    creator_id uuid;
    owner_id uuid;
    organization_id uuid;
    owner_membership_id uuid;
    session_id uuid;
    application_id uuid;
    consent_id uuid;
    family_id uuid;
    request_id uuid;
    org_handle text;
    previous_environment text := current_setting('iam.testing_environment_id', true);
    previous_principal text := current_setting('iam.principal_id', true);
BEGIN
    INSERT INTO iam.cryptographic_key_versions(purpose, key_version, status)
    VALUES ('token_hmac', 1, 'active'), ('contact_aead', 1, 'active')
    ON CONFLICT DO NOTHING;
    FOR environment_number IN 1..2 LOOP
        fixture_prefix := 'v1_upgrade_' || environment_number;
        environment_id := md5(fixture_prefix || ':environment')::uuid;
        PERFORM set_config('iam.testing_environment_id', environment_id::text, true);
        creator_id := md5(fixture_prefix || ':creator')::uuid;
        owner_id := md5(fixture_prefix || ':owner')::uuid;
        PERFORM set_config('iam.principal_id', owner_id::text, true);
        organization_id := md5(fixture_prefix || ':organization')::uuid;
        owner_membership_id := md5(fixture_prefix || ':membership')::uuid;
        session_id := md5(fixture_prefix || ':session')::uuid;
        org_handle := fixture_prefix;
        INSERT INTO iam.principals(id, kind, status, activated_at)
        VALUES (creator_id, 'carbon', 'active', transaction_timestamp()),
               (owner_id, 'carbon', 'active', transaction_timestamp());
        INSERT INTO iam.carbons(id, carbon_id, display_name)
        VALUES (creator_id, fixture_prefix || '_creator', 'Original Creator'),
               (owner_id, fixture_prefix || '_owner', 'Current Owner');
        INSERT INTO iam.carbon_contacts(id, carbon_id, kind, ciphertext, nonce,
            encryption_key_version, verified_at)
        SELECT md5(principal.id::text || ':' || contact.kind)::uuid,
               principal.id, contact.kind::iam.contact_kind, decode(repeat('01',17),'hex'),
               decode(repeat('02',12),'hex'), 1, transaction_timestamp()
        FROM (VALUES (creator_id), (owner_id)) AS principal(id)
        CROSS JOIN (VALUES ('email'), ('phone')) AS contact(kind);
        INSERT INTO iam.organizations(id, org_id, created_by_carbon_id, name)
        VALUES (organization_id, org_handle, creator_id, 'Legacy organization');
        INSERT INTO iam.organization_memberships(id, organization_id, principal_id,
            principal_kind, org_role)
        VALUES (owner_membership_id, organization_id, owner_id, 'carbon', 'owner');
        INSERT INTO iam.authentication_sessions(id, subject_principal_id, subject_kind,
            authentication_method, assurance_level, subject_auth_epoch,
            idle_expires_at, absolute_expires_at)
        VALUES (session_id, owner_id, 'carbon', 'email_otp', 1, 1,
            transaction_timestamp() + interval '1 day',
            transaction_timestamp() + interval '2 days');
        INSERT INTO iam.access_tokens(id, token_class, token_digest, digest_key_version,
            token_prefix, authentication_session_id, subject_principal_id, subject_kind,
            audience, subject_auth_epoch, expires_at)
        VALUES (md5(fixture_prefix || ':iam_access')::uuid, 'carbon_access',
            decode(md5(fixture_prefix || ':iam_access') || md5(fixture_prefix),'hex'),
            1, 'cat_abcdefgh', session_id, owner_id, 'carbon', 'iam', 1,
            transaction_timestamp() + interval '15 minutes');
        INSERT INTO iam.refresh_token_families(id, authentication_session_id,
            subject_principal_id, absolute_expires_at)
        VALUES (md5(fixture_prefix || ':iam_family')::uuid, session_id, owner_id,
            transaction_timestamp() + interval '2 days');
        INSERT INTO iam.refresh_tokens(id, family_id, token_digest, digest_key_version,
            token_prefix, expires_at)
        VALUES (md5(fixture_prefix || ':iam_refresh')::uuid,
            md5(fixture_prefix || ':iam_family')::uuid,
            decode(md5(fixture_prefix || ':iam_refresh') || md5(fixture_prefix),'hex'),
            1, 'rft_abcdefgh', transaction_timestamp() + interval '2 days');
        FOR application_number IN 1..3 LOOP
            application_id := md5(fixture_prefix || ':app:' || application_number)::uuid;
            consent_id := md5(application_id::text || ':consent')::uuid;
            family_id := md5(application_id::text || ':family')::uuid;
            request_id := md5(application_id::text || ':request')::uuid;
            INSERT INTO iam.principals(id, kind, status, activated_at)
            VALUES (application_id, 'application', 'active', transaction_timestamp());
            INSERT INTO iam.applications(id, app_id, organization_id, created_by_carbon_id,
                review_status, base_url)
            VALUES (application_id, org_handle || '>' || org_handle || '-app-' || application_number,
                organization_id, creator_id,
                (ARRAY['verified', 'suspended', 'under_review'])[application_number],
                'https://example.test');
            INSERT INTO iam.application_requested_scopes(application_id, scope)
            VALUES (application_id, 'profile');
            INSERT INTO iam.application_approved_scopes(application_id, scope, approved_by_carbon_id)
            VALUES (application_id, 'profile', creator_id);
            INSERT INTO iam.oauth_consent_grants(id, application_id, subject_principal_id,
                subject_kind, parent_authentication_session_id, selected_membership_ids)
            VALUES (consent_id, application_id, owner_id, 'carbon', session_id,
                ARRAY[owner_membership_id]);
            INSERT INTO iam.oauth_consent_grant_scopes(consent_grant_id, scope)
            VALUES (consent_id, 'profile');
            INSERT INTO iam.access_tokens(id, token_class, token_digest, digest_key_version,
                token_prefix, authentication_session_id, subject_principal_id, subject_kind,
                client_application_id, audience, audience_application_id,
                subject_auth_epoch, client_auth_epoch, expires_at)
            VALUES (md5(application_id::text || ':access')::uuid, 'application_access',
                decode(md5(application_id::text || ':access') || md5(fixture_prefix),'hex'),
                1, 'oat_abcdefgh', session_id, owner_id, 'carbon', application_id,
                org_handle || '>' || org_handle || '-app-' || application_number, application_id,
                1, 1,
                transaction_timestamp() + interval '15 minutes');
            INSERT INTO iam.access_token_scopes(access_token_id, scope)
            VALUES (md5(application_id::text || ':access')::uuid, 'profile');
            INSERT INTO iam.refresh_token_families(id, authentication_session_id,
                subject_principal_id, client_application_id, oauth_consent_grant_id,
                absolute_expires_at)
            VALUES (family_id, session_id, owner_id, application_id, consent_id,
                transaction_timestamp() + interval '2 days');
            INSERT INTO iam.refresh_tokens(id, family_id, token_digest, digest_key_version,
                token_prefix, expires_at)
            VALUES (md5(application_id::text || ':refresh')::uuid, family_id,
                decode(md5(application_id::text || ':refresh') || md5(fixture_prefix),'hex'),
                1, 'ort_abcdefgh', transaction_timestamp() + interval '2 days');
            INSERT INTO iam.oauth_authorization_requests(id, application_id,
                authentication_session_id, subject_principal_id, subject_kind,
                status, decided_at, expires_at)
            VALUES (request_id, application_id, session_id, owner_id, 'carbon', 'approved',
                transaction_timestamp(), transaction_timestamp() + interval '5 minutes');
            INSERT INTO iam.oauth_authorization_request_scopes(authorization_request_id,
                application_id, scope, approved_at)
            VALUES (request_id, application_id, 'profile', transaction_timestamp());
            INSERT INTO iam.oauth_authorization_codes(id, authorization_request_id,
                application_id, code_digest, digest_key_version, code_prefix, expires_at)
            VALUES (md5(application_id::text || ':code')::uuid, request_id, application_id,
                decode(md5(application_id::text || ':code') || md5(fixture_prefix),'hex'),
                1, 'oac_abcdefgh', transaction_timestamp() + interval '5 minutes');
            INSERT INTO iam.application_obo_endpoints(organization_id, application_id,
                endpoint_id, path, metadata_definition)
            VALUES (organization_id, application_id, 'legacy.read', '/legacy', '{}');
            -- Only a verified application could legitimately issue an OBO proof.
            IF application_number = 1 THEN
            INSERT INTO iam.obo_proofs(id, proof_digest, digest_key_version, proof_prefix,
                issuer_application_id, audience_application_id, subject_principal_id,
                subject_kind, organization_id, membership_id, parent_access_token_id,
                endpoint_id, request_metadata, endpoint_version, request_method,
                request_path, request_body_sha256, request_signed_at, subject_auth_epoch,
                membership_authz_epoch, issuer_auth_epoch, audience_auth_epoch, expires_at)
            VALUES (md5(application_id::text || ':obo')::uuid,
                decode(md5(application_id::text || ':obo') || md5(fixture_prefix),'hex'),
                1, 'obo_abcdefgh', application_id, application_id, owner_id, 'carbon',
                organization_id, owner_membership_id, md5(application_id::text || ':access')::uuid,
                'legacy.read', '{}', 1, 'POST', '/legacy', decode(repeat('00',32),'hex'),
                transaction_timestamp(), 1, 1, 1, 1,
                transaction_timestamp() + interval '60 seconds');
            END IF;
        END LOOP;
    END LOOP;
    PERFORM set_config('iam.testing_environment_id', COALESCE(previous_environment,''), true);
    PERFORM set_config('iam.principal_id', COALESCE(previous_principal,''), true);
END;
$fixture$;
