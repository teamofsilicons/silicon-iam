-- Worker-only access to the current credential carried by a testing webhook.
--
-- Testing-environment rows live in the production control plane while their
-- outbox and delivery rows live in the shared testing database. The worker
-- cannot join across those databases, and its runtime role intentionally has
-- no direct access to the control-plane table. This fixed-shape function is
-- the only bridge: it returns the encrypted key material for one live
-- environment so the worker can include the current key in a test delivery.

CREATE FUNCTION iam_private.get_worker_testing_environment_webhook_key(
    p_testing_environment_id uuid
)
RETURNS TABLE (
    organization_id uuid,
    key_ciphertext bytea,
    key_nonce bytea,
    key_encryption_key_version smallint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        environment.organization_id,
        environment.key_ciphertext,
        environment.key_nonce,
        environment.key_encryption_key_version
    FROM iam.testing_environments AS environment
    JOIN iam.organizations AS organization
      ON organization.id = environment.organization_id
     AND organization.status = 'active'
    WHERE environment.id = p_testing_environment_id
      AND environment.status = 'active'
$$;

COMMENT ON FUNCTION iam_private.get_worker_testing_environment_webhook_key(uuid) IS
    'Returns encrypted current key material for one live environment so its test webhook can identify its source.';

REVOKE ALL ON FUNCTION iam_private.get_worker_testing_environment_webhook_key(uuid)
    FROM PUBLIC;

-- Cross-database Application reservation check used only while creating an
-- Application in a testing environment. The handler calls this against the
-- production pool; row security cannot perform this comparison because the
-- two planes intentionally share no database transaction.
CREATE FUNCTION iam_private.production_application_id_is_reserved(p_app_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM iam.applications AS application
        WHERE application.app_id = p_app_id
    )
$$;

COMMENT ON FUNCTION iam_private.production_application_id_is_reserved(text) IS
    'Reports whether an Application identifier is reserved in the database on which this function executes, including deleted rows.';

REVOKE ALL ON FUNCTION iam_private.production_application_id_is_reserved(text)
    FROM PUBLIC;

-- Complete production configuration allowed to cross into a test import.
--
-- Secret material remains encrypted here. The API decrypts it under the
-- source row identities and immediately re-encrypts it under fresh test row
-- identities; the plaintext is never serialized in the import response.
CREATE FUNCTION iam_private.get_testing_application_import(p_app_id text)
RETURNS TABLE (
    source_application_id uuid,
    source_webhook_endpoint_id uuid,
    source_webhook_signing_key_id uuid,
    app_id text,
    org_id text,
    organization_name text,
    organization_logo_uri text,
    organization_description text,
    app_name text,
    app_logo_uri text,
    base_url text,
    webhook_url_ciphertext bytea,
    webhook_url_nonce bytea,
    webhook_url_encryption_key_version smallint,
    webhook_secret_ciphertext bytea,
    webhook_secret_nonce bytea,
    webhook_secret_encryption_key_version smallint,
    webhook_secret_version bigint,
    obo_endpoints jsonb
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        application.id,
        endpoint.id,
        signing_key.id,
        application.app_id,
        organization.org_id,
        organization.name,
        organization.logo_uri,
        organization.description,
        application.app_name,
        application.app_logo_uri,
        application.base_url,
        endpoint.url_ciphertext,
        endpoint.url_nonce,
        endpoint.encryption_key_version,
        signing_key.secret_ciphertext,
        signing_key.secret_nonce,
        signing_key.encryption_key_version,
        signing_key.secret_version,
        (
            SELECT COALESCE(
                jsonb_agg(
                    jsonb_build_object(
                        'endpoint_id', obo.endpoint_id,
                        'path', obo.path,
                        'metadata', obo.metadata_definition
                    ) ORDER BY obo.endpoint_id
                ),
                '[]'::jsonb
            )
            FROM iam.application_obo_endpoints AS obo
            WHERE obo.application_id = application.id
              AND obo.organization_id = application.organization_id
              AND obo.status = 'active'
        )
    FROM iam.applications AS application
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
     AND application_principal.status = 'active'
    JOIN iam.organizations AS organization
      ON organization.id = application.organization_id
     AND organization.status = 'active'
    JOIN LATERAL (
        SELECT candidate.*
        FROM iam.application_webhook_endpoints AS candidate
        WHERE candidate.application_id = application.id
          AND candidate.status IN ('active', 'pending_review')
        ORDER BY
            (candidate.status = 'active') DESC,
            candidate.activated_at DESC NULLS LAST,
            candidate.created_at DESC,
            candidate.id DESC
        LIMIT 1
    ) AS endpoint ON true
    JOIN LATERAL (
        SELECT candidate.*
        FROM iam.application_webhook_signing_keys AS candidate
        WHERE candidate.application_id = application.id
          AND candidate.endpoint_id = endpoint.id
          AND candidate.status = 'active'
        ORDER BY candidate.secret_version DESC, candidate.id DESC
        LIMIT 1
    ) AS signing_key ON true
    WHERE application.app_id = p_app_id
      AND application.review_status = 'verified'
      AND application.deleted_at IS NULL
$$;

COMMENT ON FUNCTION iam_private.get_testing_application_import(text) IS
    'Returns one verified production Application configuration, with webhook material still encrypted, for test-only import.';

REVOKE ALL ON FUNCTION iam_private.get_testing_application_import(text) FROM PUBLIC;
