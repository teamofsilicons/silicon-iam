-- Existing applications predate declared v1 permissions. Their implicit legacy
-- consent cannot authorize the new defaults: retire application credentials and
-- require a new explicit login. Direct IAM sessions and immutable history stay intact.
DO $v1_reconsent$
DECLARE
    application_record record;
    owner_carbon_id uuid;
    previous_environment text := current_setting('iam.testing_environment_id', true);
    default_scopes constant text[] := ARRAY['self.identity.read', 'self.profile.read'];
BEGIN
    -- An incremental testing upgrade already has environment-scoped tenant rows.
    -- Scan all environments as the migration owner, then select each app's own
    -- environment so DEFAULT values and restrictive policies agree on new grants.
    PERFORM set_config('iam.testing_environment_id', '', true);
    LOCK TABLE iam.applications, iam.application_requested_scopes,
        iam.application_approved_scopes IN SHARE ROW EXCLUSIVE MODE;

    -- Materialize before changing the session setting: a lazy cursor over RLS
    -- tables must not start filtering later batches with the previous app's key.
    CREATE TEMP TABLE iam_v1_legacy_application_candidates ON COMMIT DROP AS
        SELECT application.id, application.organization_id,
               to_jsonb(application)->>'testing_environment_id' AS environment_id
        FROM iam.applications AS application
        WHERE application.deleted_at IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM iam.application_requested_scopes AS requested
              WHERE requested.application_id = application.id
                AND (requested.scope LIKE 'self.%'
                     OR requested.scope LIKE 'directory.%'
                     OR requested.scope LIKE 'organization.%'
                     OR requested.scope LIKE 'obo:%')
          )
        ORDER BY application.id;
    FOR application_record IN
        SELECT * FROM pg_temp.iam_v1_legacy_application_candidates ORDER BY id
    LOOP
        PERFORM set_config('iam.testing_environment_id',
            COALESCE(application_record.environment_id, ''), true);
        SELECT membership.principal_id INTO STRICT owner_carbon_id
        FROM iam.organization_memberships AS membership
        WHERE membership.organization_id = application_record.organization_id
          AND membership.principal_kind = 'carbon'
          AND membership.org_role = 'owner' AND membership.status = 'active';

        UPDATE iam.application_approved_scopes
        SET revoked_at = transaction_timestamp(), revoked_by_carbon_id = owner_carbon_id
        WHERE application_id = application_record.id AND revoked_at IS NULL;

        -- Historical scope rows are referenced by immutable issuance snapshots.
        -- Keep them as evidence; only these new declarations are active in v1.
        INSERT INTO iam.application_requested_scopes(application_id, scope)
        SELECT application_record.id, unnest(default_scopes);
        INSERT INTO iam.application_approved_scopes(application_id, scope, approved_by_carbon_id)
        SELECT application_record.id, unnest(default_scopes), owner_carbon_id;

        UPDATE iam.access_tokens
        SET revoked_at = transaction_timestamp(), revocation_reason = 'application_v1_reconsent'
        WHERE token_class = 'application_access' AND revoked_at IS NULL
          AND (client_application_id = application_record.id
               OR audience_application_id = application_record.id);
        UPDATE iam.refresh_token_families
        SET status = 'revoked', revoked_at = transaction_timestamp(),
            revocation_reason = 'application_v1_reconsent'
        WHERE client_application_id = application_record.id AND status = 'active';
        UPDATE iam.refresh_tokens AS token
        SET revoked_at = transaction_timestamp()
        FROM iam.refresh_token_families AS family
        WHERE token.family_id = family.id AND token.revoked_at IS NULL
          AND family.client_application_id = application_record.id;
        UPDATE iam.obo_proofs
        SET revoked_at = transaction_timestamp()
        WHERE revoked_at IS NULL
          AND (issuer_application_id = application_record.id
               OR audience_application_id = application_record.id);
        UPDATE iam.oauth_authorization_requests
        SET status = 'expired', decided_at = COALESCE(decided_at, transaction_timestamp())
        WHERE application_id = application_record.id AND status IN ('pending', 'approved');
        UPDATE iam.oauth_authorization_codes
        SET expires_at = GREATEST(created_at + interval '1 microsecond',
                                 LEAST(expires_at, transaction_timestamp()))
        WHERE application_id = application_record.id AND consumed_at IS NULL;
        UPDATE iam.oauth_consent_grants
        SET status = 'revoked', revoked_at = transaction_timestamp()
        WHERE application_id = application_record.id AND status = 'active';

        -- Touch the aggregate version but preserve its review and suspension state.
        UPDATE iam.applications
        SET app_scope = '{"iam":["self.identity.read","self.profile.read"],"external":[]}'::jsonb
        WHERE id = application_record.id;
    END LOOP;
    DROP TABLE pg_temp.iam_v1_legacy_application_candidates;
    PERFORM set_config('iam.testing_environment_id', COALESCE(previous_environment, ''), true);
END;
$v1_reconsent$;
