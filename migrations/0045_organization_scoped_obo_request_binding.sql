-- Restrict OBO delegation to one Application tenant and bind every proof to
-- the exact downstream HTTP request that the issuer signed.

-- Proofs issued before request binding existed cannot be upgraded safely.
-- Revoke them explicitly even though their maximum lifetime is 60 seconds so
-- a rolling deployment fails closed.
UPDATE iam.obo_proofs
SET revoked_at = COALESCE(revoked_at, transaction_timestamp())
WHERE consumed_at IS NULL;

ALTER TABLE iam.application_obo_endpoints
    ADD COLUMN organization_id uuid;

UPDATE iam.application_obo_endpoints AS endpoint
SET organization_id = application.organization_id
FROM iam.applications AS application
WHERE application.id = endpoint.application_id;

ALTER TABLE iam.application_obo_endpoints
    ALTER COLUMN organization_id SET NOT NULL,
    DROP CONSTRAINT application_obo_endpoints_application_fk,
    ADD CONSTRAINT application_obo_endpoints_application_tenant_fk
        FOREIGN KEY (organization_id, application_id)
        REFERENCES iam.applications (organization_id, id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT application_obo_endpoints_tenant_identity_unique
        UNIQUE (organization_id, application_id, endpoint_id, path);

COMMENT ON COLUMN iam.application_obo_endpoints.organization_id IS
    'Immutable Application tenant used for same-organization OBO discovery and proof constraints.';

CREATE OR REPLACE FUNCTION iam_private.maintain_application_obo_endpoint()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, iam
AS $$
BEGIN
    IF NEW.application_id IS DISTINCT FROM OLD.application_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.endpoint_id IS DISTINCT FROM OLD.endpoint_id
       OR NEW.path IS DISTINCT FROM OLD.path THEN
        RAISE EXCEPTION 'OBO endpoint tenant, identity, and path are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.metadata_definition IS DISTINCT FROM OLD.metadata_definition
       OR NEW.status IS DISTINCT FROM OLD.status THEN
        NEW.version := OLD.version + 1;
        NEW.updated_at := transaction_timestamp();
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.maintain_application_obo_endpoint() FROM PUBLIC;

ALTER TABLE iam.obo_proofs
    ADD COLUMN request_method text,
    ADD COLUMN request_path text,
    ADD COLUMN request_body_sha256 bytea,
    ADD COLUMN request_signed_at timestamptz;

-- These values are deliberately non-authoritative sentinels for revoked
-- legacy rows. The path is copied from the immutable endpoint identity so the
-- new composite foreign key remains truthful.
UPDATE iam.obo_proofs AS proof
SET request_method = 'POST',
    request_path = endpoint.path,
    request_body_sha256 = decode(repeat('00', 32), 'hex'),
    request_signed_at = proof.created_at
FROM iam.application_obo_endpoints AS endpoint
WHERE endpoint.application_id = proof.audience_application_id
  AND endpoint.endpoint_id = proof.endpoint_id;

ALTER TABLE iam.obo_proofs
    ALTER COLUMN request_method SET NOT NULL,
    ALTER COLUMN request_path SET NOT NULL,
    ALTER COLUMN request_body_sha256 SET NOT NULL,
    ALTER COLUMN request_signed_at SET NOT NULL,
    DROP CONSTRAINT obo_proofs_issuer_fk,
    DROP CONSTRAINT obo_proofs_endpoint_fk,
    DROP CONSTRAINT obo_proofs_consumer_fk,
    -- Historical proofs may truthfully record cross-organization delegation
    -- from the retired contract. NOT VALID retains that audit evidence while
    -- PostgreSQL still enforces every constraint for all new proofs.
    ADD CONSTRAINT obo_proofs_issuer_tenant_fk
        FOREIGN KEY (organization_id, issuer_application_id)
        REFERENCES iam.applications (organization_id, id)
        ON DELETE RESTRICT
        NOT VALID,
    ADD CONSTRAINT obo_proofs_audience_tenant_fk
        FOREIGN KEY (organization_id, audience_application_id)
        REFERENCES iam.applications (organization_id, id)
        ON DELETE RESTRICT
        NOT VALID,
    ADD CONSTRAINT obo_proofs_endpoint_tenant_fk
        FOREIGN KEY (
            organization_id, audience_application_id, endpoint_id, request_path
        )
        REFERENCES iam.application_obo_endpoints (
            organization_id, application_id, endpoint_id, path
        )
        ON DELETE RESTRICT
        NOT VALID,
    ADD CONSTRAINT obo_proofs_consumer_tenant_fk
        FOREIGN KEY (organization_id, consumed_by_application_id)
        REFERENCES iam.applications (organization_id, id)
        ON DELETE RESTRICT
        NOT VALID,
    ADD CONSTRAINT obo_proofs_request_method_format CHECK (
        request_method ~ '^[A-Z][A-Z0-9!#$%&''*+.^_`|~-]{0,31}$'
    ),
    ADD CONSTRAINT obo_proofs_request_path_format CHECK (
        octet_length(request_path) BETWEEN 1 AND 2048
        AND request_path LIKE '/%'
        AND request_path NOT LIKE '//%'
        AND position('?' IN request_path) = 0
        AND position('#' IN request_path) = 0
        AND request_path !~ '[[:space:][:cntrl:]]'
        AND request_path !~ '(^|/)\.\.?(/|$)'
    ),
    ADD CONSTRAINT obo_proofs_request_body_sha256_length CHECK (
        octet_length(request_body_sha256) = 32
    ),
    ADD CONSTRAINT obo_proofs_request_signature_freshness CHECK (
        request_signed_at BETWEEN
            created_at - interval '60 seconds'
            AND created_at + interval '60 seconds'
    );

COMMENT ON COLUMN iam.obo_proofs.request_method IS
    'Canonical uppercase downstream HTTP method authenticated by the issuer request signature.';
COMMENT ON COLUMN iam.obo_proofs.request_path IS
    'Exact immutable audience endpoint path authenticated by the issuer request signature.';
COMMENT ON COLUMN iam.obo_proofs.request_body_sha256 IS
    'SHA-256 of the exact downstream request body bytes; the body itself never enters IAM.';
COMMENT ON COLUMN iam.obo_proofs.request_signed_at IS
    'Canonical issuer-provided Unix timestamp accepted within the OBO signature freshness window.';
COMMENT ON TABLE iam.obo_proofs IS
    'Random one-time OBO proofs constrained to same-organization Applications and bound to the exact downstream method, path, body digest, metadata, actor, parent token, endpoint version, and revocation epochs.';
