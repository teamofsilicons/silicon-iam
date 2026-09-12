-- Run after 0082 against the database populated by application_v1_upgrade_seed.
DO $assertion$
DECLARE
    environment_number integer;
    application_number integer;
    fixture_prefix text;
    expected_environment uuid;
    expected_owner uuid;
    expected_application uuid;
    previous_environment text := current_setting('iam.testing_environment_id', true);
    expected_scopes constant text[] := ARRAY['self.identity.read', 'self.profile.read'];
    actual_scopes text[];
    app_record record;
BEGIN
    FOR environment_number IN 1..2 LOOP
        fixture_prefix := 'v1_upgrade_' || environment_number;
        expected_environment := md5(fixture_prefix || ':environment')::uuid;
        expected_owner := md5(fixture_prefix || ':owner')::uuid;
        PERFORM set_config('iam.testing_environment_id', expected_environment::text, true);
        IF NOT EXISTS (
            SELECT 1 FROM iam.authentication_sessions session
            WHERE session.id = md5(fixture_prefix || ':session')::uuid
              AND session.status = 'active' AND session.revoked_at IS NULL
        ) OR NOT EXISTS (
            SELECT 1 FROM iam.access_tokens token
            WHERE token.id = md5(fixture_prefix || ':iam_access')::uuid AND token.revoked_at IS NULL
        ) OR NOT EXISTS (
            SELECT 1 FROM iam.refresh_token_families family
            WHERE family.id = md5(fixture_prefix || ':iam_family')::uuid
              AND family.status = 'active' AND family.revoked_at IS NULL
        ) OR NOT EXISTS (
            SELECT 1 FROM iam.refresh_tokens token
            WHERE token.id = md5(fixture_prefix || ':iam_refresh')::uuid AND token.revoked_at IS NULL
        ) OR NOT EXISTS (
            SELECT 1 FROM iam.principals principal
            WHERE principal.id = expected_owner AND principal.auth_epoch = 1
        ) THEN RAISE EXCEPTION 'v1 upgrade invalidated a direct IAM session in environment %', environment_number;
        END IF;
        FOR application_number IN 1..3 LOOP
            expected_application := md5(fixture_prefix || ':app:' || application_number)::uuid;
            SELECT * INTO STRICT app_record FROM iam.applications WHERE id = expected_application;
            IF app_record.review_status <> (ARRAY['verified','suspended','under_review'])[application_number]
                OR app_record.version <> 2
                OR app_record.app_scope <> '{"iam":["self.identity.read","self.profile.read"],"external":[]}'::jsonb
            THEN RAISE EXCEPTION 'v1 upgrade changed review state or failed to version defaults for %', expected_application;
            END IF;
            SELECT array_agg(approved.scope ORDER BY approved.scope) INTO actual_scopes
            FROM iam.application_approved_scopes approved
            WHERE approved.application_id = expected_application AND approved.revoked_at IS NULL;
            IF actual_scopes IS DISTINCT FROM expected_scopes OR EXISTS (
                SELECT 1 FROM iam.application_approved_scopes approved
                WHERE approved.application_id = expected_application AND approved.revoked_at IS NULL
                  AND (approved.approved_by_carbon_id <> expected_owner
                    OR (to_jsonb(approved) ? 'testing_environment_id'
                        AND to_jsonb(approved)->>'testing_environment_id' <> expected_environment::text))
            ) THEN RAISE EXCEPTION 'v1 defaults are not owned and isolated correctly for %', expected_application;
            END IF;
            IF (SELECT count(*) FROM iam.application_requested_scopes requested
                WHERE requested.application_id = expected_application) <> 3
                OR NOT EXISTS (SELECT 1 FROM iam.application_approved_scopes approved
                    WHERE approved.application_id = expected_application AND approved.scope = 'profile'
                      AND approved.revoked_at IS NOT NULL AND approved.revoked_by_carbon_id = expected_owner)
                OR (SELECT count(*) FROM iam.oauth_authorization_request_scopes scope
                    WHERE scope.application_id = expected_application AND scope.scope = 'profile') <> 1
                OR (SELECT array_agg(scope.scope) FROM iam.oauth_consent_grant_scopes scope
                    WHERE scope.consent_grant_id = md5(expected_application::text || ':consent')::uuid)
                    IS DISTINCT FROM ARRAY['profile']::text[]
            THEN RAISE EXCEPTION 'v1 upgrade modified immutable scope history or retroactively extended consent for %', expected_application;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM iam.access_tokens token
                    WHERE token.id = md5(expected_application::text || ':access')::uuid
                      AND token.revoked_at IS NOT NULL AND token.revocation_reason = 'application_v1_reconsent')
                OR NOT EXISTS (SELECT 1 FROM iam.refresh_token_families family
                    WHERE family.id = md5(expected_application::text || ':family')::uuid
                      AND family.status = 'revoked' AND family.revocation_reason = 'application_v1_reconsent')
                OR NOT EXISTS (SELECT 1 FROM iam.refresh_tokens token
                    WHERE token.id = md5(expected_application::text || ':refresh')::uuid AND token.revoked_at IS NOT NULL)
                OR (application_number = 1 AND NOT EXISTS (SELECT 1 FROM iam.obo_proofs proof
                    WHERE proof.id = md5(expected_application::text || ':obo')::uuid AND proof.revoked_at IS NOT NULL))
                OR NOT EXISTS (SELECT 1 FROM iam.oauth_authorization_requests request
                    WHERE request.id = md5(expected_application::text || ':request')::uuid AND request.status = 'expired')
                OR NOT EXISTS (SELECT 1 FROM iam.oauth_authorization_codes code
                    WHERE code.id = md5(expected_application::text || ':code')::uuid
                      AND code.consumed_at IS NULL AND code.expires_at <= clock_timestamp())
                OR NOT EXISTS (SELECT 1 FROM iam.oauth_consent_grants consent
                    WHERE consent.id = md5(expected_application::text || ':consent')::uuid
                      AND consent.status = 'revoked' AND consent.revoked_at IS NOT NULL)
            THEN RAISE EXCEPTION 'v1 upgrade left a legacy application credential usable or deleted history for %', expected_application;
            END IF;
        END LOOP;
    END LOOP;
    PERFORM set_config('iam.testing_environment_id', COALESCE(previous_environment,''), true);
END;
$assertion$;
