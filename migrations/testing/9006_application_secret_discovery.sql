-- Non-authoritative routing index. A match only selects a candidate plane;
-- ordinary scoped ApplicationClient authentication must still verify the secret.
-- SHA-256 is appropriate here because app secrets contain 256 random bits.
CREATE TABLE iam_private.test_application_selectors (
 digest bytea PRIMARY KEY CHECK(octet_length(digest)=32),
 environment_id uuid NOT NULL,
 application_id uuid NOT NULL REFERENCES iam.applications(id) ON DELETE CASCADE
);
REVOKE ALL ON iam_private.test_application_selectors FROM PUBLIC;
CREATE FUNCTION iam_private.register_test_application_selector(p_app uuid,p_digest bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 IF iam_private.current_testing_environment_id() IS NULL OR NOT EXISTS
 (SELECT 1 FROM iam.applications WHERE id=p_app) THEN RAISE EXCEPTION 'test application required'; END IF;
 INSERT INTO iam_private.test_application_selectors VALUES
 (p_digest,iam_private.current_testing_environment_id(),p_app) ON CONFLICT(digest) DO NOTHING;
END $$;
CREATE FUNCTION iam_private.resolve_test_application_selector(p_digest bytea)
RETURNS TABLE(environment_id uuid,application_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam_private AS $$
 SELECT environment_id,application_id FROM iam_private.test_application_selectors WHERE digest=p_digest;
$$;
CREATE FUNCTION iam_private.test_application_selector_backfill()
RETURNS TABLE(application_id uuid,secret_ciphertext bytea,secret_nonce bytea,secret_key_version smallint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT i.application_id,i.secret_ciphertext,i.secret_nonce,i.secret_key_version
 FROM iam.testing_application_imports i WHERE NOT EXISTS
 (SELECT 1 FROM iam_private.test_application_selectors s WHERE s.application_id=i.application_id);
$$;
REVOKE ALL ON FUNCTION iam_private.register_test_application_selector(uuid,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.resolve_test_application_selector(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.test_application_selector_backfill() FROM PUBLIC;
GRANT SELECT,INSERT,DELETE ON iam_private.test_application_selectors TO silicon_iam_testing_definer;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.register_test_application_selector(uuid,bytea),
 iam_private.resolve_test_application_selector(bytea),iam_private.test_application_selector_backfill() TO silicon_iam_api;
END IF; END $$;
SELECT iam_private.reconcile_testing_environment_security();
