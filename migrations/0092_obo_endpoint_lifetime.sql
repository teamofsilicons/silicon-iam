-- Endpoint TTL changes affect new proofs only. Existing proof expiry remains immutable.
ALTER TABLE iam.application_obo_endpoints ADD COLUMN ttl_seconds integer NOT NULL DEFAULT 300 CHECK (ttl_seconds > 0);

CREATE OR REPLACE FUNCTION iam_private.discover_application_obo_endpoints(p_app_id text)
RETURNS SETOF jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT jsonb_build_object(
        'application', jsonb_build_object('app_id', app.app_id, 'org_id', org.org_id),
        'endpoints', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'endpoint_id', endpoint.endpoint_id, 'path', endpoint.path,
            'metadata', endpoint.metadata_definition, 'critical', endpoint.critical, 'ttl_seconds', endpoint.ttl_seconds
        ) ORDER BY endpoint.endpoint_id)
        FROM iam.application_obo_endpoints endpoint
        WHERE endpoint.application_id = app.id AND endpoint.status = 'active'), '[]'::jsonb)
    )
    FROM iam.applications app
    JOIN iam.principals principal ON principal.id = app.id AND principal.status = 'active'
    JOIN iam.organizations org ON org.id = app.organization_id AND org.status = 'active'
    WHERE app.app_id = p_app_id AND app.review_status = 'verified' AND app.deleted_at IS NULL
      AND iam_private.current_application_id() = iam_private.current_principal_id()
      AND EXISTS (SELECT 1 FROM iam.applications caller
        JOIN iam.principals identity ON identity.id = caller.id AND identity.status = 'active'
        WHERE caller.id = iam_private.current_application_id()
          AND caller.review_status = 'verified' AND caller.deleted_at IS NULL);
$$;

CREATE OR REPLACE FUNCTION iam_private.get_testing_application_import_v1(p_app_ids text[])
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
    obo_endpoints jsonb,
    app_scope jsonb, webhook_scope text[], testing_idle_days integer
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
                        'metadata', obo.metadata_definition, 'critical', obo.critical, 'ttl_seconds', obo.ttl_seconds
                    ) ORDER BY obo.endpoint_id
                ),
                '[]'::jsonb
            )
            FROM iam.application_obo_endpoints AS obo
            WHERE obo.application_id = application.id
              AND obo.organization_id = application.organization_id
              AND obo.status = 'active'
        ), application.app_scope, application.webhook_scope, application.testing_idle_days
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
    WHERE application.app_id = ANY(p_app_ids)
      AND application.review_status = 'verified'
      AND application.deleted_at IS NULL
$$;

CREATE OR REPLACE FUNCTION iam_private.import_testing_application_configuration(p jsonb)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE environment_id uuid := NULLIF(current_setting('iam.testing_environment_id', true), '')::uuid;
    owner_id uuid; org_id uuid; app_id uuid := (p->>'application_id')::uuid;
    endpoint_id uuid := (p->>'endpoint_id')::uuid; item jsonb;
BEGIN
    IF environment_id IS NULL THEN RAISE EXCEPTION 'testing_environment_required' USING ERRCODE = '42501'; END IF;
    -- An uncredentialed, suspended fixture is audit attribution, never a
    -- production identity or a login-capable organization administrator.
    owner_id := iam_private.current_principal_id();
    IF owner_id IS NULL OR NOT EXISTS (SELECT 1 FROM iam.carbons c JOIN iam.principals identity ON identity.id=c.id
        WHERE c.id=owner_id AND identity.status='active') THEN owner_id := environment_id; END IF;
    IF NOT EXISTS (SELECT 1 FROM iam.carbons WHERE id = owner_id) THEN
        INSERT INTO iam.principals(id,kind,status,suspended_at) VALUES(owner_id,'carbon','suspended',clock_timestamp());
        INSERT INTO iam.carbons(id,carbon_id,display_name)
        VALUES(owner_id, 'test_' || translate(left(replace(environment_id::text,'-',''),24),'0','g'), 'Testing environment fixture');
    END IF;
    SELECT organization.id INTO org_id FROM iam.organizations organization
    WHERE organization.org_id = p->>'org_id' AND organization.status = 'active';
    IF org_id IS NOT NULL AND owner_id <> environment_id
       AND NOT iam_private.is_active_organization_owner_or_admin(org_id,owner_id) THEN
        RAISE EXCEPTION 'testing_import_organization_not_managed' USING ERRCODE='42501';
    END IF;
    IF org_id IS NULL THEN
        org_id := gen_random_uuid();
        INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name,logo_uri,description)
        VALUES(org_id,p->>'org_id',owner_id,p->>'organization_name',p->>'organization_logo',p->>'organization_description');
        INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role)
        VALUES(gen_random_uuid(),org_id,owner_id,'carbon','owner');
        INSERT INTO iam.carbon_membership_settings(organization_id,membership_id,carbon_id)
        SELECT org_id,membership.id,owner_id FROM iam.organization_memberships membership
        WHERE membership.organization_id = org_id AND membership.principal_id = owner_id;
    END IF;
    INSERT INTO iam.principals(id,kind,status,activated_at) VALUES(app_id,'application','active',transaction_timestamp());
    INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,app_name,app_logo_uri,base_url,
        review_status,test_imported_from_production,app_scope,webhook_scope,testing_idle_days)
    VALUES(app_id,p->>'app_id',org_id,owner_id,p->>'app_name',p->>'app_logo',p->>'base_url','verified',true,
        p->'app_scope',ARRAY(SELECT jsonb_array_elements_text(p->'webhook_scope')),(p->>'testing_idle_days')::integer);
    FOR item IN SELECT * FROM jsonb_array_elements(p->'obo_endpoints') LOOP
        INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical,ttl_seconds)
        VALUES(org_id,app_id,item->>'endpoint_id',item->>'path',item->'metadata',(item->>'critical')::boolean,COALESCE((item->>'ttl_seconds')::integer,300));
    END LOOP;
    INSERT INTO iam.application_secrets(id,application_id,secret_version,secret_prefix,secret_digest,pepper_key_version,created_by_carbon_id)
    VALUES((p->>'secret_id')::uuid,app_id,1,p->>'secret_prefix',decode(p->>'secret_digest','hex'),(p->>'secret_digest_version')::smallint,owner_id);
    INSERT INTO iam.application_webhook_endpoints(id,application_id,url_ciphertext,url_nonce,encryption_key_version,url_digest,status,activated_at)
    VALUES(endpoint_id,app_id,decode(p->>'url_ciphertext','hex'),decode(p->>'url_nonce','hex'),(p->>'url_key_version')::smallint,
        decode(p->>'url_digest','hex'),'active',transaction_timestamp());
    INSERT INTO iam.application_webhook_signing_keys(id,application_id,endpoint_id,secret_version,key_prefix,secret_ciphertext,secret_nonce,encryption_key_version,test_inherited_from_production)
    VALUES((p->>'signing_key_id')::uuid,app_id,endpoint_id,(p->>'webhook_secret_version')::bigint,p->>'webhook_fingerprint',
        decode(p->>'signing_ciphertext','hex'),decode(p->>'signing_nonce','hex'),(p->>'signing_key_version')::smallint,true);
    INSERT INTO iam.testing_application_imports(application_id,source_application_id,secret_ciphertext,secret_nonce,secret_key_version)
    VALUES(app_id,(p->>'source_application_id')::uuid,decode(p->>'secret_ciphertext','hex'),decode(p->>'secret_nonce','hex'),(p->>'secret_key_version')::smallint);
    RETURN app_id;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.discover_application_obo_endpoints(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.get_testing_application_import_v1(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.import_testing_application_configuration(jsonb) FROM PUBLIC;

-- The v1 authority function retains its wire shape for deployed consumers.
-- Read TTL under its endpoint share lock, within the same protected context.
CREATE FUNCTION iam_private.lock_current_application_obo_exchange_authority_v2(
 p_issuer uuid, p_epoch bigint, p_token uuid, p_subject uuid,
 p_kind iam.principal_kind, p_org uuid, p_membership uuid, p_audience text, p_endpoint text
) RETURNS TABLE(audience_application_id uuid, endpoint_path text, metadata_definition jsonb,
 endpoint_version bigint, audience_auth_epoch bigint, subject_auth_epoch bigint,
 membership_authz_epoch bigint, ttl_seconds integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE authority record;
BEGIN
 SELECT * INTO authority FROM iam_private.lock_current_application_obo_exchange_authority(
  p_issuer,p_epoch,p_token,p_subject,p_kind,p_org,p_membership,p_audience,p_endpoint
 );
 IF NOT FOUND THEN RETURN; END IF;
 -- The locking authority lookup can wait for a concurrent configuration
 -- transaction. Read TTL only after that lock, using a fresh command snapshot.
 RETURN QUERY SELECT authority.audience_application_id,authority.endpoint_path,authority.metadata_definition,
 authority.endpoint_version,authority.audience_auth_epoch,authority.subject_auth_epoch,authority.membership_authz_epoch,endpoint.ttl_seconds
 FROM iam.application_obo_endpoints endpoint
 WHERE endpoint.application_id=authority.audience_application_id AND endpoint.endpoint_id=p_endpoint;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.lock_current_application_obo_exchange_authority_v2(uuid,bigint,uuid,uuid,iam.principal_kind,uuid,uuid,text,text) FROM PUBLIC;
DO $$ BEGIN
 IF to_regrole('silicon_iam_api') IS NOT NULL THEN
  GRANT EXECUTE ON FUNCTION iam_private.lock_current_application_obo_exchange_authority_v2(uuid,bigint,uuid,uuid,iam.principal_kind,uuid,uuid,text,text) TO silicon_iam_api;
 END IF;
END $$;
