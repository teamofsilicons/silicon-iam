-- IAM-local erasure receipts survive deletion of the retired app's rows. The
-- operation receipt and erasure commit together, so crash retries never erase
-- an application that was subsequently imported again.
CREATE TABLE iam_private.testing_application_retention_receipts (
 environment_id uuid NOT NULL, operation_id uuid NOT NULL, applications text[] NOT NULL,
 generation bigint NOT NULL,key_version integer NOT NULL,deleted_rows bigint NOT NULL,
 PRIMARY KEY(environment_id,operation_id)
);
CREATE TABLE iam_private.testing_retention_rows (
 backend_pid integer NOT NULL,transaction_id xid8 NOT NULL,relation_id oid NOT NULL,row_tid tid NOT NULL,
 PRIMARY KEY(backend_pid,transaction_id,relation_id,row_tid)
);
REVOKE ALL ON iam_private.testing_application_retention_receipts,iam_private.testing_retention_rows FROM PUBLIC;
GRANT SELECT,INSERT,DELETE ON iam_private.testing_application_retention_receipts,iam_private.testing_retention_rows TO silicon_iam_testing_definer;
CREATE FUNCTION iam_private.erase_testing_applications(p_environment uuid,p_operation uuid,p_apps text[],p_generation bigint,p_key integer)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private
AS $$
DECLARE previous iam_private.testing_application_retention_receipts%ROWTYPE;
 edge record; target record; join_expression text; added bigint; changed bigint; remaining bigint;
 removed bigint:=0; batch bigint; passes integer:=0; guard_xid xid8:=pg_current_xact_id();
BEGIN
 IF current_testing_environment_id() IS DISTINCT FROM p_environment OR cardinality(p_apps) IS NULL OR cardinality(p_apps) NOT BETWEEN 1 AND 100 THEN
 RAISE EXCEPTION 'environment_and_applications_required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('testing-runtime:'||p_environment::text,0));
 SELECT * INTO previous FROM iam_private.testing_application_retention_receipts WHERE environment_id=p_environment AND operation_id=p_operation;
 IF FOUND THEN
 IF previous.applications IS DISTINCT FROM p_apps OR previous.generation<>p_generation OR previous.key_version<>p_key THEN RAISE EXCEPTION 'retention_operation_conflict' USING ERRCODE='40001'; END IF;
 RETURN previous.deleted_rows;
 END IF;
 IF EXISTS(SELECT 1 FROM iam_private.testing_runtime_state WHERE environment_id=p_environment AND (generation<>p_generation OR key_version<>p_key)) THEN
 RAISE EXCEPTION 'testing_generation_conflict' USING ERRCODE='40001'; END IF;
 INSERT INTO iam_private.worker_retention_guards(backend_pid,transaction_id,invoker) VALUES(pg_backend_pid(),guard_xid,session_user);
 INSERT INTO iam_private.testing_retention_rows
 SELECT pg_backend_pid(),guard_xid,'iam.applications'::regclass,a.ctid FROM iam.applications a WHERE a.testing_environment_id=p_environment AND a.app_id=ANY(p_apps) FOR UPDATE OF a;
 INSERT INTO iam_private.testing_retention_rows
 SELECT pg_backend_pid(),guard_xid,'iam.principals'::regclass,p.ctid FROM iam.principals p JOIN iam.applications a ON a.id=p.id
 WHERE a.testing_environment_id=p_environment AND p.testing_environment_id=p_environment AND a.app_id=ANY(p_apps) FOR UPDATE OF p;
 -- Follow references away from retired applications. Shared identities and
 -- other applications are never seeds; only their app-owned dependent rows
 -- (for example a consent to the retired provider) can be removed.
 LOOP
 changed:=0; passes:=passes+1;
 IF passes>64 THEN RAISE EXCEPTION 'application_erasure_dependency_limit' USING ERRCODE='55000'; END IF;
 FOR edge IN
 SELECT c.oid,c.conrelid,c.confrelid,c.conkey,c.confkey FROM pg_constraint c
 JOIN pg_class child ON child.oid=c.conrelid JOIN pg_namespace n ON n.oid=child.relnamespace
 WHERE c.contype='f' AND n.nspname='iam' AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.conrelid AND a.attname='testing_environment_id' AND NOT a.attisdropped)
 AND EXISTS(SELECT 1 FROM iam_private.testing_retention_rows r WHERE r.backend_pid=pg_backend_pid() AND r.transaction_id=guard_xid AND r.relation_id=c.confrelid)
 LOOP
 SELECT string_agg(format('child.%I=parent.%I',ca.attname,pa.attname),' AND ' ORDER BY key.ordinality) INTO join_expression
 FROM unnest(edge.conkey,edge.confkey) WITH ORDINALITY AS key(child_key,parent_key,ordinality)
 JOIN pg_attribute ca ON ca.attrelid=edge.conrelid AND ca.attnum=key.child_key
 JOIN pg_attribute pa ON pa.attrelid=edge.confrelid AND pa.attnum=key.parent_key;
 EXECUTE format('INSERT INTO iam_private.testing_retention_rows SELECT $1,$2,$3,child.ctid FROM %s child JOIN %s parent ON %s JOIN iam_private.testing_retention_rows selected ON selected.backend_pid=$1 AND selected.transaction_id=$2 AND selected.relation_id=$4 AND selected.row_tid=parent.ctid WHERE child.testing_environment_id=$5 FOR UPDATE OF child ON CONFLICT DO NOTHING',edge.conrelid::regclass,edge.confrelid::regclass,join_expression)
 USING pg_backend_pid(),guard_xid,edge.conrelid,edge.confrelid,p_environment;
 GET DIAGNOSTICS added=ROW_COUNT;changed:=changed+added;
 END LOOP;
 EXIT WHEN changed=0;
 END LOOP;
 LOOP
 changed:=0;
 FOR target IN SELECT DISTINCT relation_id FROM iam_private.testing_retention_rows WHERE backend_pid=pg_backend_pid() AND transaction_id=guard_xid
 LOOP
 BEGIN
 EXECUTE format('DELETE FROM %s child USING iam_private.testing_retention_rows selected WHERE selected.backend_pid=$1 AND selected.transaction_id=$2 AND selected.relation_id=$3 AND child.ctid=selected.row_tid AND child.testing_environment_id=$4',target.relation_id::regclass)
 USING pg_backend_pid(),guard_xid,target.relation_id,p_environment;
 GET DIAGNOSTICS batch=ROW_COUNT;removed:=removed+batch;
 DELETE FROM iam_private.testing_retention_rows WHERE backend_pid=pg_backend_pid() AND transaction_id=guard_xid AND relation_id=target.relation_id;
 GET DIAGNOSTICS batch=ROW_COUNT;changed:=changed+batch;
 EXCEPTION WHEN foreign_key_violation THEN NULL;
 END;
 END LOOP;
 SELECT count(*) INTO remaining FROM iam_private.testing_retention_rows WHERE backend_pid=pg_backend_pid() AND transaction_id=guard_xid;
 EXIT WHEN remaining=0;
 IF changed=0 THEN RAISE EXCEPTION 'application_erasure_dependency_conflict' USING ERRCODE='55000'; END IF;
 END LOOP;
 DELETE FROM iam_private.worker_retention_guards WHERE backend_pid=pg_backend_pid() AND transaction_id=guard_xid AND invoker=session_user;
 DELETE FROM iam_private.honeycomb_test_app_receipts WHERE environment_id=p_environment AND response->>'app_id'=ANY(p_apps);
 INSERT INTO iam_private.testing_application_retention_receipts VALUES(p_environment,p_operation,p_apps,p_generation,p_key,removed);
 RETURN removed;
END $$;
REVOKE ALL ON FUNCTION iam_private.erase_testing_applications(uuid,uuid,text[],bigint,integer) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.erase_testing_applications(uuid,uuid,text[],bigint,integer) TO silicon_iam_api;
END IF; END $$;
SELECT iam_private.reconcile_testing_environment_security();

CREATE FUNCTION iam_private.honeycomb_adoption_imports(p_environment uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private
AS $$
 SELECT COALESCE(jsonb_agg(jsonb_build_object('application_id',app.id,'app_id',app.app_id,
 'source_application_id',import.source_application_id,'source_revision',import.source_revision,
 'iam_revision',app.version,'configuration_revision',app.honeycomb_configuration_revision,
 'imported_from_production',app.test_imported_from_production,'app_scope',app.app_scope,
 'webhook_scope',app.webhook_scope,'visibility',app.visibility,'availability',app.review_status,
 'credential_version',(SELECT max(secret_version) FROM iam.application_secrets WHERE application_id=app.id AND status='active')) ORDER BY app.app_id),'[]'::jsonb)
 FROM iam.applications app LEFT JOIN iam.testing_application_imports import ON import.application_id=app.id
 WHERE app.testing_environment_id=p_environment AND current_testing_environment_id()=p_environment;
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_adoption_imports(uuid) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.honeycomb_adoption_imports(uuid) TO silicon_iam_api; END IF; END $$;
SELECT iam_private.reconcile_testing_environment_security();
