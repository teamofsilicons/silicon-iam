-- Complete provider login only from an initiating proof and a stable provider subject.
ALTER TABLE iam.social_signup_requests
 ADD COLUMN intent text NOT NULL DEFAULT 'signup' CHECK(intent IN ('signup','login')),
 ADD COLUMN login_principal_id text,
 ADD COLUMN login_auth_epoch bigint,
 ADD COLUMN completed_at timestamptz,
 DROP CONSTRAINT social_signup_requests_status_check,
 ADD CONSTRAINT social_signup_requests_status_check CHECK(status IN
 ('pending','processing','verified','already_registered','login_ready','link_required','completed','failed'));

ALTER TABLE iam.authentication_sessions DROP CONSTRAINT authentication_sessions_method;
DO $$ BEGIN
 IF to_regprocedure('iam_private.current_testing_environment_id()') IS NULL THEN
  ALTER TABLE iam.authentication_sessions ADD CONSTRAINT authentication_sessions_method CHECK(authentication_method IN
   ('email_otp','phone_otp','silicon_credential','workos_sso','refresh_token','google_oidc','apple_oidc')) NOT VALID;
 ELSE
  ALTER TABLE iam.authentication_sessions ADD CONSTRAINT authentication_sessions_method CHECK(authentication_method IN
   ('email_otp','phone_otp','silicon_credential','workos_sso','refresh_token','google_oidc','apple_oidc','testing_actor_id')) NOT VALID;
 END IF;
END $$;

CREATE FUNCTION iam_private.social_login_identity(p_provider text,p_digests jsonb)
RETURNS TABLE(principal_id text,auth_epoch bigint) LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT p.id,p.auth_epoch FROM iam.principals p
 WHERE p.kind='carbon' AND p.status='active' AND p.id IN (
  SELECT s.principal_id FROM iam.carbon_social_identities s
  JOIN jsonb_to_recordset(p_digests) AS d(key_version smallint,digest text)
   ON s.key_version=d.key_version AND s.subject_digest=decode(d.digest,'hex')
  WHERE s.provider=p_provider
 )
$$;
REVOKE ALL ON FUNCTION iam_private.social_login_identity(text,jsonb) FROM PUBLIC;

-- The first link requires a fresh independent IAM OTP session for the exact account.
-- Email equality alone never allows a provider identity to take over that account.
CREATE FUNCTION iam_private.bind_social_login_identity(p_request uuid,p_principal text,p_session uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE request record; digest record; affected integer;
BEGIN
 IF iam_private.current_principal_id() IS DISTINCT FROM p_principal THEN RETURN false; END IF;
 SELECT r.* INTO request FROM iam.social_signup_requests r
 JOIN iam.principals p ON p.id=r.login_principal_id
 JOIN iam.authentication_sessions s ON s.id=p_session AND s.subject_principal_id=p.id
 WHERE r.id=p_request AND r.intent='login' AND r.status='link_required'
 AND r.login_principal_id=p_principal AND r.expires_at>transaction_timestamp()
 AND p.kind='carbon' AND p.status='active' AND p.auth_epoch=r.login_auth_epoch
 AND s.status='active' AND s.subject_auth_epoch=p.auth_epoch
 AND s.authentication_method IN ('email_otp','phone_otp') AND s.created_at>=r.created_at
 AND s.idle_expires_at>transaction_timestamp() AND s.absolute_expires_at>transaction_timestamp()
 FOR UPDATE OF r FOR SHARE OF p,s;
 IF NOT FOUND THEN RETURN false; END IF;
 FOR digest IN SELECT * FROM jsonb_to_recordset(request.subject_digests) AS d(key_version smallint,digest text)
 LOOP
  INSERT INTO iam.carbon_social_identities(provider,key_version,subject_digest,principal_id)
  VALUES(request.provider,digest.key_version,decode(digest.digest,'hex'),p_principal)
  ON CONFLICT(provider,key_version,subject_digest) DO UPDATE SET principal_id=EXCLUDED.principal_id
  WHERE iam.carbon_social_identities.principal_id=EXCLUDED.principal_id OR NOT EXISTS(
   SELECT 1 FROM iam.principals p WHERE p.id=iam.carbon_social_identities.principal_id AND p.status<>'deleted');
  GET DIAGNOSTICS affected=ROW_COUNT;
  IF affected<>1 THEN RAISE EXCEPTION 'social_identity_already_bound' USING ERRCODE='23505'; END IF;
 END LOOP;
 UPDATE iam.social_signup_requests SET status='completed',completed_at=transaction_timestamp() WHERE id=p_request;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION iam_private.bind_social_login_identity(uuid,text,uuid) FROM PUBLIC;
