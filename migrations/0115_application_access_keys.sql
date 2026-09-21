-- Application identity proofs have independent random secrets. Only keyed
-- digests are persisted; they carry neither user authority nor OBO scopes.
CREATE TABLE iam.application_access_keys (
    id uuid PRIMARY KEY,
    application_id text NOT NULL,
    application_secret_id uuid NOT NULL REFERENCES iam.application_secrets(id) ON DELETE CASCADE,
    application_auth_epoch bigint NOT NULL,
    key_digest bytea NOT NULL CHECK(octet_length(key_digest)=32),
    pepper_key_version smallint NOT NULL,
    pepper_purpose text GENERATED ALWAYS AS ('token_hmac'::text) STORED,
    environment_id uuid,
    testing_generation bigint,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    UNIQUE(pepper_key_version,key_digest),
    FOREIGN KEY(pepper_purpose,pepper_key_version)
        REFERENCES iam.cryptographic_key_versions(purpose,key_version),
    CHECK((environment_id IS NULL)=(testing_generation IS NULL)),
    CHECK(testing_generation IS NULL OR testing_generation>0),
    CHECK(expires_at-issued_at BETWEEN interval '1 minute' AND interval '60 minutes')
);
CREATE INDEX application_access_keys_application ON iam.application_access_keys(application_id)
    WHERE revoked_at IS NULL;
CREATE INDEX application_access_keys_retention ON iam.application_access_keys(expires_at);
ALTER TABLE iam.application_access_keys ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON iam.application_access_keys FROM PUBLIC;

-- Lock the application before its credential, matching management lock order.
-- The extractor's authentication transaction has ended: recheck the exact
-- presented secret so rotation between extraction and handling cannot mint a key.
CREATE FUNCTION iam_private.lock_application_verification_client(
    p_application_id text,p_auth_epoch bigint,p_versions smallint[],p_digests bytea[]
) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE secret_id uuid;
BEGIN
    IF iam_private.lock_current_application_client(p_application_id,p_auth_epoch) IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT secret.id INTO secret_id
    FROM iam.application_secrets secret
    JOIN unnest(p_versions,p_digests) supplied(version,digest)
      ON secret.pepper_key_version=supplied.version AND secret.secret_digest=supplied.digest
    WHERE secret.application_id=p_application_id AND secret.status='active'
    FOR SHARE OF secret;
    RETURN secret_id;
END $$;
REVOKE ALL ON FUNCTION iam_private.lock_application_verification_client(text,bigint,smallint[],bytea[]) FROM PUBLIC;

CREATE FUNCTION iam_private.issue_application_access_key(
    p_secret_id uuid,p_auth_epoch bigint,p_id uuid,p_digest bytea,p_pepper smallint,
    p_ttl_seconds integer,p_generation bigint
) RETURNS TABLE(app_id text,valid_till timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE issued timestamptz; app text:=iam_private.current_application_id();
    environment uuid:=NULLIF(current_setting('iam.testing_environment_id',true),'')::uuid;
BEGIN
    IF app IS NULL OR app IS DISTINCT FROM iam_private.current_principal_id()
       OR p_ttl_seconds NOT BETWEEN 60 AND 3600 OR p_ttl_seconds IS NULL
       OR (environment IS NULL) IS DISTINCT FROM (p_generation IS NULL) THEN
        RAISE EXCEPTION 'application_access_key_context_required' USING ERRCODE='42501';
    END IF;
    IF iam_private.lock_current_application_client(app,p_auth_epoch) IS NULL THEN RETURN; END IF;
    PERFORM 1 FROM iam.application_secrets secret
      WHERE secret.id=p_secret_id AND secret.application_id=app AND secret.status='active'
      FOR SHARE OF secret;
    IF NOT FOUND THEN RETURN; END IF;
    issued:=clock_timestamp();
    RETURN QUERY INSERT INTO iam.application_access_keys(
        id,application_id,application_secret_id,application_auth_epoch,key_digest,
        pepper_key_version,environment_id,testing_generation,issued_at,expires_at
    ) VALUES(p_id,app,p_secret_id,p_auth_epoch,p_digest,p_pepper,environment,p_generation,
             issued,issued+make_interval(secs=>p_ttl_seconds))
      RETURNING application_id,expires_at;
END $$;
REVOKE ALL ON FUNCTION iam_private.issue_application_access_key(uuid,bigint,uuid,bytea,smallint,integer,bigint) FROM PUBLIC;

CREATE FUNCTION iam_private.verify_application_access_key(
    p_app_id text,p_versions smallint[],p_digests bytea[],p_generation bigint
) RETURNS TABLE(app_id text,valid_till timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE caller text; caller_epoch bigint; verified_app text; verified_expiry timestamptz;
    receiver text:=iam_private.current_application_id();
    environment uuid:=NULLIF(current_setting('iam.testing_environment_id',true),'')::uuid;
BEGIN
    IF receiver IS NULL OR receiver IS DISTINCT FROM iam_private.current_principal_id()
       OR (environment IS NULL) IS DISTINCT FROM (p_generation IS NULL) THEN
        RAISE EXCEPTION 'application_access_key_context_required' USING ERRCODE='42501';
    END IF;
    -- No membership or visibility filter: this is identity, not user authority.
    -- Lock issuer authority first so disablement/rotation cannot race the result.
    SELECT application.id,principal.auth_epoch INTO caller,caller_epoch
    FROM iam.applications application JOIN iam.principals principal ON principal.id=application.id
    WHERE application.app_id=p_app_id AND application.review_status='verified'
      AND application.deleted_at IS NULL AND principal.kind='application' AND principal.status='active'
    FOR SHARE OF application,principal;
    IF NOT FOUND THEN RETURN; END IF;
    SELECT key.application_id,key.expires_at INTO verified_app,verified_expiry
    FROM iam.application_access_keys key
    JOIN unnest(p_versions,p_digests) supplied(version,digest)
      ON key.pepper_key_version=supplied.version AND key.key_digest=supplied.digest
    JOIN iam.application_secrets secret ON secret.id=key.application_secret_id
      AND secret.application_id=caller AND secret.status='active'
    WHERE key.application_id=caller AND key.application_auth_epoch=caller_epoch
      AND key.environment_id IS NOT DISTINCT FROM environment
      AND key.testing_generation IS NOT DISTINCT FROM p_generation
      AND key.revoked_at IS NULL AND key.expires_at>clock_timestamp()
    FOR SHARE OF key,secret;
    -- Wall-clock expiry must be evaluated after every authority/key lock wait.
    IF FOUND AND verified_expiry>clock_timestamp() THEN
        RETURN QUERY SELECT verified_app,verified_expiry;
    END IF;
END $$;
REVOKE ALL ON FUNCTION iam_private.verify_application_access_key(text,smallint[],bytea[],bigint) FROM PUBLIC;

CREATE FUNCTION iam_private.revoke_application_access_keys()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
    IF TG_TABLE_NAME='application_secrets' THEN
        IF NEW.status IS DISTINCT FROM OLD.status AND NEW.status<>'active'
           OR NEW.secret_digest IS DISTINCT FROM OLD.secret_digest THEN
            UPDATE iam.application_access_keys SET revoked_at=clock_timestamp()
              WHERE application_secret_id=OLD.id AND revoked_at IS NULL;
        END IF;
    ELSIF TG_TABLE_NAME='principals' THEN
        IF OLD.kind='application' AND (NEW.status<>'active' OR NEW.auth_epoch<>OLD.auth_epoch) THEN
            UPDATE iam.application_access_keys SET revoked_at=clock_timestamp()
              WHERE application_id=OLD.id AND revoked_at IS NULL;
        END IF;
    ELSIF NEW.review_status<>'verified' OR NEW.deleted_at IS NOT NULL THEN
        UPDATE iam.application_access_keys SET revoked_at=clock_timestamp()
          WHERE application_id=OLD.id AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam_private.revoke_application_access_keys() FROM PUBLIC;
CREATE TRIGGER application_access_keys_secret_revocation
AFTER UPDATE OF status,secret_digest ON iam.application_secrets FOR EACH ROW
EXECUTE FUNCTION iam_private.revoke_application_access_keys();
CREATE TRIGGER application_access_keys_principal_revocation
AFTER UPDATE OF status,auth_epoch ON iam.principals FOR EACH ROW
EXECUTE FUNCTION iam_private.revoke_application_access_keys();
CREATE TRIGGER application_access_keys_application_revocation
AFTER UPDATE OF review_status,deleted_at ON iam.applications FOR EACH ROW
EXECUTE FUNCTION iam_private.revoke_application_access_keys();

-- Use the existing bounded worker policy and configurable token metadata
-- retention instead of giving the API deletion access or retaining keys forever.
DO $retention$
DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef('iam_private.run_worker_retention_maintenance_before_profile_projection(text,integer,integer,integer,integer,integer,integer,integer)'::regprocedure)
 INTO definition;
 definition:=replace(definition,E'        ''access_tokens'',',E'        ''application_access_keys'',\n        ''access_tokens'',');
 definition:=replace(definition,E'    IF p_phase <> ''authentication_sessions_delete'' THEN',
 $phase$    IF p_phase = 'application_access_keys' THEN
    RETURN QUERY WITH expired AS MATERIALIZED (
      SELECT id FROM iam.application_access_keys
      WHERE expires_at<clock_timestamp()-make_interval(days=>p_token_metadata_days)
      ORDER BY expires_at,id FOR UPDATE SKIP LOCKED LIMIT p_limit
    ), removed AS (
      DELETE FROM iam.application_access_keys key USING expired WHERE key.id=expired.id RETURNING key.id
    ) SELECT p_phase,count(*) FROM removed;
    RETURN;
    END IF;

    IF p_phase <> 'authentication_sessions_delete' THEN$phase$);
 IF position('DELETE FROM iam.application_access_keys' IN definition)=0 THEN
  RAISE EXCEPTION 'application access key retention phase was not installed';
 END IF;
 EXECUTE definition;
END $retention$;
