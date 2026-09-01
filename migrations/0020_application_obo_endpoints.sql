-- Replace IAM capability delegation with application-owned callable endpoints.

-- Proofs issued under the former grant semantics are never valid after this
-- migration. Their maximum lifetime is 60 seconds, but explicit revocation
-- also makes rolling deployment fail closed.
UPDATE iam.obo_proofs
SET revoked_at = COALESCE(revoked_at, transaction_timestamp())
WHERE consumed_at IS NULL;

DROP TABLE iam.obo_application_grants;

ALTER TABLE iam.obo_action_catalog
    RENAME TO application_obo_endpoints;
ALTER TABLE iam.application_obo_endpoints
    RENAME COLUMN audience_application_id TO application_id;
ALTER TABLE iam.application_obo_endpoints
    RENAME COLUMN action TO endpoint_id;

ALTER TABLE iam.application_obo_endpoints
    DROP CONSTRAINT obo_action_catalog_action_catalog,
    DROP CONSTRAINT obo_action_catalog_description_length,
    ADD COLUMN path text,
    ADD COLUMN metadata_definition jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN version bigint NOT NULL DEFAULT 1,
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    ADD COLUMN retired_at timestamptz;

UPDATE iam.application_obo_endpoints
SET path = '/legacy/' || replace(endpoint_id, '.', '/'),
    retired_at = CASE WHEN status = 'retired' THEN transaction_timestamp() END;

ALTER TABLE iam.application_obo_endpoints
    ALTER COLUMN path SET NOT NULL,
    DROP COLUMN description,
    ADD CONSTRAINT application_obo_endpoints_identifier_format
        CHECK (endpoint_id ~ '^[a-z][a-z0-9_.:-]{2,127}$'),
    ADD CONSTRAINT application_obo_endpoints_path_format
        CHECK (
            octet_length(path) BETWEEN 1 AND 2048
            AND path LIKE '/%'
            AND path NOT LIKE '//%'
            AND position('?' IN path) = 0
            AND position('#' IN path) = 0
            AND path !~ '[[:space:][:cntrl:]]'
            AND path !~ '(^|/)\.\.?(/|$)'
        ),
    ADD CONSTRAINT application_obo_endpoints_metadata_object
        CHECK (
            jsonb_typeof(metadata_definition) = 'object'
            AND octet_length(metadata_definition::text) <= 16384
        ),
    ADD CONSTRAINT application_obo_endpoints_positive_version CHECK (version > 0),
    ADD CONSTRAINT application_obo_endpoints_status_timestamps CHECK (
        (status = 'active' AND retired_at IS NULL)
        OR (status = 'retired' AND retired_at IS NOT NULL)
    ),
    ADD CONSTRAINT application_obo_endpoints_application_path_unique
        UNIQUE (application_id, path);

ALTER TABLE iam.application_obo_endpoints
    RENAME CONSTRAINT obo_action_catalog_pkey TO application_obo_endpoints_pkey;
ALTER TABLE iam.application_obo_endpoints
    RENAME CONSTRAINT obo_action_catalog_audience_fk TO application_obo_endpoints_application_fk;
ALTER TABLE iam.application_obo_endpoints
    RENAME CONSTRAINT obo_action_catalog_status TO application_obo_endpoints_status;

CREATE OR REPLACE FUNCTION iam_private.maintain_application_obo_endpoint()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, iam
AS $$
BEGIN
    IF NEW.application_id IS DISTINCT FROM OLD.application_id
       OR NEW.endpoint_id IS DISTINCT FROM OLD.endpoint_id
       OR NEW.path IS DISTINCT FROM OLD.path THEN
        RAISE EXCEPTION 'OBO endpoint identity and path are immutable'
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

CREATE TRIGGER application_obo_endpoints_maintain
BEFORE UPDATE ON iam.application_obo_endpoints
FOR EACH ROW EXECUTE FUNCTION iam_private.maintain_application_obo_endpoint();

ALTER TABLE iam.obo_proofs
    RENAME COLUMN action TO endpoint_id;
ALTER TABLE iam.obo_proofs
    RENAME CONSTRAINT obo_proofs_action_fk TO obo_proofs_endpoint_fk;
ALTER TABLE iam.obo_proofs
    DROP CONSTRAINT obo_proofs_resource_digest_key_fk,
    DROP CONSTRAINT obo_proofs_resource_binding,
    DROP COLUMN resource_digest,
    DROP COLUMN resource_digest_key_version,
    DROP COLUMN resource_digest_purpose,
    ADD COLUMN request_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN endpoint_version bigint;

UPDATE iam.obo_proofs AS proof
SET endpoint_version = endpoint.version
FROM iam.application_obo_endpoints AS endpoint
WHERE endpoint.application_id = proof.audience_application_id
  AND endpoint.endpoint_id = proof.endpoint_id;

ALTER TABLE iam.obo_proofs
    ALTER COLUMN endpoint_version SET NOT NULL,
    ADD CONSTRAINT obo_proofs_metadata_object CHECK (
        jsonb_typeof(request_metadata) = 'object'
        AND octet_length(request_metadata::text) <= 16384
    ),
    ADD CONSTRAINT obo_proofs_positive_endpoint_version CHECK (endpoint_version > 0);

COMMENT ON TABLE iam.application_obo_endpoints IS
    'Stable callable endpoints registered and maintained by their audience application.';
COMMENT ON COLUMN iam.application_obo_endpoints.metadata_definition IS
    'Audience-owned arbitrary JSON object describing the endpoint metadata contract.';
COMMENT ON COLUMN iam.obo_proofs.request_metadata IS
    'Exact request metadata object bound into this single-use proof.';
COMMENT ON TABLE iam.obo_proofs IS
    'Random one-time OBO proofs bound to source app, audience app, subject token, organization, registered endpoint, exact request metadata, and current revocation epochs.';
