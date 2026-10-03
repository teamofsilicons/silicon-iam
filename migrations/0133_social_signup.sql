-- Browser/CLI social enrollment, fixed-provider subjects, and one-use callbacks.
CREATE TABLE iam.social_signup_requests (
 id uuid PRIMARY KEY, provider text NOT NULL CHECK(provider IN ('google','apple')),
 state_digest bytea NOT NULL CHECK(octet_length(state_digest)=32), state_key_version smallint NOT NULL,
 poll_digest bytea NOT NULL CHECK(octet_length(poll_digest)=32), poll_key_version smallint NOT NULL,
 proof_ciphertext bytea, proof_nonce bytea, proof_key_version smallint,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','verified','already_registered','failed')),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT transaction_timestamp()+interval '10 minutes',
 signup_session_id uuid, candidate_id uuid,
 email_ciphertext bytea, email_nonce bytea, email_key_version smallint,
 display_name text CHECK(length(display_name)<=160), subject_digests jsonb,
 UNIQUE(provider,state_key_version,state_digest),
 CHECK(expires_at>created_at),
 CHECK((proof_ciphertext IS NULL)=(proof_nonce IS NULL)),
 CHECK(proof_nonce IS NULL OR octet_length(proof_nonce)=12),
 CHECK(email_nonce IS NULL OR octet_length(email_nonce)=12)
);
CREATE INDEX social_signup_expiry ON iam.social_signup_requests(expires_at);
CREATE TABLE iam.carbon_social_identities (
 provider text NOT NULL CHECK(provider IN ('google','apple')),
 key_version smallint NOT NULL, subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
 principal_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(provider,key_version,subject_digest)
);
ALTER TABLE iam.social_signup_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.carbon_social_identities ENABLE ROW LEVEL SECURITY;
CREATE POLICY social_signup_api ON iam.social_signup_requests USING(true) WITH CHECK(true);

REVOKE ALL ON iam.social_signup_requests,iam.carbon_social_identities FROM PUBLIC;

CREATE FUNCTION iam_private.social_identity_registered(p_provider text,p_key smallint,p_digest bytea)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT EXISTS(SELECT 1 FROM iam.carbon_social_identities s
 JOIN iam.principals p ON p.id=s.principal_id
 WHERE s.provider=p_provider AND s.key_version=p_key AND s.subject_digest=p_digest AND p.status<>'deleted');
$$;
REVOKE ALL ON FUNCTION iam_private.social_identity_registered(text,smallint,bytea) FROM PUBLIC;

CREATE FUNCTION iam_private.bind_completed_social_signup() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE request record; digest record;
BEGIN
 IF NEW.status <> 'completed' OR OLD.status='completed' THEN RETURN NULL; END IF;
 FOR request IN SELECT social.* FROM iam.social_signup_requests social
 JOIN iam.signup_contact_candidates candidate ON candidate.id=social.candidate_id
 WHERE social.signup_session_id=NEW.id AND social.status='verified'
 AND candidate.superseded_at IS NULL AND candidate.verified_at IS NOT NULL
 LOOP
  FOR digest IN SELECT * FROM jsonb_to_recordset(request.subject_digests) AS d(key_version smallint,digest text)
  LOOP
   UPDATE iam.carbon_social_identities s SET principal_id=NEW.completed_carbon_id
   WHERE s.provider=request.provider AND s.key_version=digest.key_version
   AND s.subject_digest=decode(digest.digest,'hex') AND (s.principal_id=NEW.completed_carbon_id OR NOT EXISTS(
     SELECT 1 FROM iam.principals p WHERE p.id=s.principal_id AND p.status<>'deleted'));
   IF NOT FOUND THEN
    INSERT INTO iam.carbon_social_identities(provider,key_version,subject_digest,principal_id)
    VALUES(request.provider,digest.key_version,decode(digest.digest,'hex'),NEW.completed_carbon_id);
   END IF;
  END LOOP;
 END LOOP;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION iam_private.bind_completed_social_signup() FROM PUBLIC;
CREATE TRIGGER signup_social_identity AFTER UPDATE OF status ON iam.signup_sessions
FOR EACH ROW EXECUTE FUNCTION iam_private.bind_completed_social_signup();

ALTER TABLE iam.social_signup_requests ADD COLUMN token_purpose text GENERATED ALWAYS AS ('token_hmac'::text) STORED,
 ADD COLUMN encryption_purpose text GENERATED ALWAYS AS ('contact_aead'::text) STORED,
 ADD FOREIGN KEY(token_purpose,state_key_version) REFERENCES iam.cryptographic_key_versions(purpose,key_version),
 ADD FOREIGN KEY(token_purpose,poll_key_version) REFERENCES iam.cryptographic_key_versions(purpose,key_version),
 ADD FOREIGN KEY(encryption_purpose,proof_key_version) REFERENCES iam.cryptographic_key_versions(purpose,key_version),
 ADD FOREIGN KEY(encryption_purpose,email_key_version) REFERENCES iam.cryptographic_key_versions(purpose,key_version);
ALTER TABLE iam.carbon_social_identities ADD COLUMN token_purpose text GENERATED ALWAYS AS ('token_hmac'::text) STORED,
 ADD FOREIGN KEY(token_purpose,key_version) REFERENCES iam.cryptographic_key_versions(purpose,key_version);

-- When applied to an existing shared testing database, scope the new tables
-- immediately; fresh testing databases receive the same policy in migration9001.
DO $$ DECLARE relation text; BEGIN
 IF to_regprocedure('iam_private.current_testing_environment_id()') IS NOT NULL THEN
  FOREACH relation IN ARRAY ARRAY['social_signup_requests','carbon_social_identities'] LOOP
   EXECUTE format('ALTER TABLE iam.%I ADD COLUMN testing_environment_id uuid NOT NULL DEFAULT iam_private.current_testing_environment_id()',relation);
   EXECUTE format('CREATE POLICY testing_environment_isolation ON iam.%I AS RESTRICTIVE USING(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id()) WITH CHECK(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id())',relation);
   EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',relation);
  END LOOP;
 END IF;
END $$;

-- Keep completed provider-subject bindings, but erase enrollment PII and
-- encrypted callback material after the 48-hour continuation window.
CREATE FUNCTION iam_private.prune_social_signup_requests(p_limit integer)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE affected bigint;
BEGIN
 IF p_limit NOT BETWEEN 1 AND 10000 THEN RAISE EXCEPTION 'invalid_batch_size'; END IF;
 WITH expired AS (
  SELECT id FROM iam.social_signup_requests
  WHERE expires_at < transaction_timestamp()-interval '48 hours'
  ORDER BY expires_at,id LIMIT p_limit FOR UPDATE SKIP LOCKED
 ) DELETE FROM iam.social_signup_requests s USING expired e WHERE s.id=e.id;
 GET DIAGNOSTICS affected=ROW_COUNT;
 RETURN affected;
END $$;
REVOKE ALL ON FUNCTION iam_private.prune_social_signup_requests(integer) FROM PUBLIC;
