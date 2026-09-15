-- Control metadata survives erasure of iam.* payload rows.
CREATE TABLE iam_private.testing_runtime_state (
 environment_id uuid PRIMARY KEY,generation bigint NOT NULL,key_version integer NOT NULL,active boolean NOT NULL
);
REVOKE ALL ON iam_private.testing_runtime_state FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE,DELETE ON iam_private.testing_runtime_state TO silicon_iam_testing_definer;
CREATE FUNCTION iam_private.set_testing_runtime_state(p_env uuid,p_generation bigint,p_key integer,p_active boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam_private AS $$
BEGIN
 IF current_testing_environment_id() IS DISTINCT FROM p_env THEN RAISE EXCEPTION 'environment_required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('testing-runtime:'||p_env::text,0));
 INSERT INTO iam_private.testing_runtime_state VALUES(p_env,p_generation,p_key,p_active)
 ON CONFLICT(environment_id) DO UPDATE SET generation=EXCLUDED.generation,key_version=EXCLUDED.key_version,active=EXCLUDED.active;
END $$;
CREATE FUNCTION iam_private.lock_testing_runtime_state(p_env uuid,p_generation bigint,p_key integer)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam_private AS $$
BEGIN
 IF current_testing_environment_id() IS DISTINCT FROM p_env THEN RAISE EXCEPTION 'environment_required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('testing-runtime:'||p_env::text,0));
 IF NOT EXISTS(SELECT 1 FROM iam_private.testing_runtime_state WHERE environment_id=p_env AND generation=p_generation AND key_version=p_key AND active) THEN
 RAISE EXCEPTION 'testing_generation_unavailable' USING ERRCODE='42501'; END IF;
END $$;
REVOKE ALL ON FUNCTION iam_private.set_testing_runtime_state(uuid,bigint,integer,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.lock_testing_runtime_state(uuid,bigint,integer) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.set_testing_runtime_state(uuid,bigint,integer,boolean),iam_private.lock_testing_runtime_state(uuid,bigint,integer) TO silicon_iam_api;
END IF; END $$;
SELECT iam_private.reconcile_testing_environment_security();

CREATE FUNCTION iam_private.stamp_testing_outbox_generation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam_private AS $$
BEGIN
 NEW.testing_generation:=COALESCE((SELECT generation FROM iam_private.testing_runtime_state WHERE environment_id=NEW.testing_environment_id),1);
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam_private.stamp_testing_outbox_generation() FROM PUBLIC;
CREATE TRIGGER stamp_testing_outbox_generation BEFORE INSERT ON iam.outbox_events FOR EACH ROW EXECUTE FUNCTION iam_private.stamp_testing_outbox_generation();
SELECT iam_private.reconcile_testing_environment_security();
