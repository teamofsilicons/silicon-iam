-- Durable target-plane outcome: a lost control-plane commit must not rotate a
-- second time. Secret-bearing responses are encrypted and recoverable briefly.
CREATE TABLE iam_private.honeycomb_test_app_receipts (
 environment_id uuid NOT NULL,
 operation_id uuid NOT NULL,
 request_digest bytea NOT NULL,
 response jsonb NOT NULL,
 ciphertext bytea NOT NULL,
 nonce bytea NOT NULL,
 key_version smallint NOT NULL,
 expires_at timestamptz NOT NULL DEFAULT transaction_timestamp()+interval '10 minutes',
 PRIMARY KEY(environment_id,operation_id)
);
REVOKE ALL ON iam_private.honeycomb_test_app_receipts FROM PUBLIC;
CREATE FUNCTION iam_private.honeycomb_test_app_receipt(p_operation uuid,p_digest bytea)
RETURNS TABLE(response jsonb,ciphertext bytea,nonce bytea,key_version smallint,unexpired boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam_private AS $$
DECLARE receipt iam_private.honeycomb_test_app_receipts%ROWTYPE;
BEGIN
 SELECT * INTO receipt FROM iam_private.honeycomb_test_app_receipts WHERE environment_id=iam_private.current_testing_environment_id() AND operation_id=p_operation;
 IF NOT FOUND THEN RETURN; END IF;
 IF receipt.request_digest<>p_digest THEN RAISE EXCEPTION 'operation_body_conflict' USING ERRCODE='40001'; END IF;
 RETURN QUERY SELECT receipt.response,receipt.ciphertext,receipt.nonce,receipt.key_version,receipt.expires_at>clock_timestamp();
END $$;
CREATE FUNCTION iam_private.honeycomb_test_app_complete(p_operation uuid,p_digest bytea,p_response jsonb,p_ciphertext bytea,p_nonce bytea,p_key smallint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam_private AS $$
BEGIN
 IF iam_private.current_testing_environment_id() IS NULL THEN RAISE EXCEPTION 'testing_plane_required' USING ERRCODE='42501'; END IF;
 INSERT INTO iam_private.honeycomb_test_app_receipts(environment_id,operation_id,request_digest,response,ciphertext,nonce,key_version)
 VALUES(iam_private.current_testing_environment_id(),p_operation,p_digest,p_response,p_ciphertext,p_nonce,p_key);
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_test_app_receipt(uuid,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.honeycomb_test_app_complete(uuid,bytea,jsonb,bytea,bytea,smallint) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_test_app_receipt(uuid,bytea),iam_private.honeycomb_test_app_complete(uuid,bytea,jsonb,bytea,bytea,smallint) TO silicon_iam_api;
END IF; END $$;
SELECT iam_private.reconcile_testing_environment_security();
GRANT SELECT,INSERT,UPDATE,DELETE ON iam_private.honeycomb_test_app_receipts TO silicon_iam_testing_definer;

-- Locally authored test applications have no production source UUID; their
-- ordinary test organization policy still applies to every issued scope.
CREATE OR REPLACE FUNCTION iam_private.list_testing_import_iam_scope_sources()
RETURNS TABLE(application_id uuid,source_application_id uuid,org_id text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 IF iam_private.current_testing_environment_id() IS NULL THEN RAISE EXCEPTION 'testing_environment_required' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT app.id,imported.source_application_id,org.org_id FROM iam.testing_application_imports imported
 JOIN iam.applications app ON app.id=imported.application_id JOIN iam.organizations org ON org.id=app.organization_id WHERE app.test_imported_from_production;
END $$;
SELECT iam_private.reconcile_testing_environment_security();

CREATE OR REPLACE FUNCTION iam_private.erase_testing_environment(
    p_testing_environment_id uuid
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    pending regclass[];
    deferred regclass[];
    target regclass;
    deleted_total bigint := 0;
    deleted_rows bigint;
    pass_count integer := 0;
    guard_transaction_id xid8;
BEGIN
    IF p_testing_environment_id IS NULL THEN
        RAISE EXCEPTION 'a testing environment must be identified'
            USING ERRCODE = '22023';
    END IF;

    -- Audit events and the governance histories are append-only, guarded by
    -- triggers that make exactly one exception: a transaction holding the
    -- schema's erasure capability. Retention already uses it to discharge the
    -- same invariant, and reusing it is far safer than replacing two
    -- security-critical trigger functions with testing-only variants. The row
    -- is keyed to this backend, this transaction and this login, so it grants
    -- nothing beyond the statements below and disappears with them.
    guard_transaction_id := pg_current_xact_id();
    INSERT INTO iam_private.worker_retention_guards (
        backend_pid, transaction_id, invoker
    )
    VALUES (pg_backend_pid(), guard_transaction_id, session_user);

    SELECT array_agg(entry.oid::regclass ORDER BY entry.relname)
    INTO pending
    FROM pg_class AS entry
    JOIN pg_namespace AS schema_entry ON schema_entry.oid = entry.relnamespace
    JOIN pg_attribute AS scope_column
      ON scope_column.attrelid = entry.oid
     AND scope_column.attname = 'testing_environment_id'
     AND scope_column.attnum > 0
     AND NOT scope_column.attisdropped
    WHERE schema_entry.nspname = 'iam'
      AND entry.relkind IN ('r', 'p')
      AND NOT entry.relispartition;

    WHILE pending IS NOT NULL AND cardinality(pending) > 0 LOOP
        pass_count := pass_count + 1;
        IF pass_count > 64 THEN
            RAISE EXCEPTION 'testing environment erase did not converge'
                USING ERRCODE = '55000';
        END IF;

        deferred := ARRAY[]::regclass[];
        FOREACH target IN ARRAY pending LOOP
            BEGIN
                EXECUTE format(
                    'DELETE FROM %s WHERE testing_environment_id = $1',
                    target
                ) USING p_testing_environment_id;
                GET DIAGNOSTICS deleted_rows = ROW_COUNT;
                deleted_total := deleted_total + deleted_rows;
            EXCEPTION
                WHEN foreign_key_violation THEN
                    deferred := deferred || target;
            END;
        END LOOP;

        IF cardinality(deferred) = cardinality(pending) THEN
            RAISE EXCEPTION
                'testing environment erase stalled on % dependent tables',
                cardinality(deferred)
                USING ERRCODE = '55000';
        END IF;
        pending := deferred;
    END LOOP;

    DELETE FROM iam_private.worker_retention_guards AS guard
    WHERE guard.backend_pid = pg_backend_pid()
      AND guard.transaction_id = guard_transaction_id
      AND guard.invoker = session_user;

    DELETE FROM iam_private.honeycomb_test_app_receipts WHERE environment_id=p_testing_environment_id;
    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    RETURN deleted_total+deleted_rows;
END;
$$;


SELECT iam_private.reconcile_testing_environment_security();
