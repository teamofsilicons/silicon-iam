-- Application-only delegation. These credentials cannot authorize any user or OBO action.
CREATE TABLE iam.ata_verifications (
 id uuid PRIMARY KEY,
 application_id text NOT NULL,
 organization_id uuid NOT NULL REFERENCES iam.organizations(id) ON DELETE CASCADE,
 application_auth_epoch bigint NOT NULL,
 app_ids text[] NOT NULL CHECK(cardinality(app_ids) BETWEEN 1 AND 64),
 endpoints jsonb NOT NULL CHECK(jsonb_typeof(endpoints)='array'),
 graph jsonb NOT NULL CHECK(jsonb_typeof(graph)='array' AND jsonb_array_length(graph) BETWEEN 1 AND 64),
 signing_principal jsonb NOT NULL CHECK(jsonb_typeof(signing_principal)='object'),
 access_token_validity integer NOT NULL CHECK(access_token_validity BETWEEN 60 AND 86400),
 testing_generation bigint NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz,
 revoked_at timestamptz,
 revocation_reason text,
 CHECK(expires_at IS NULL OR expires_at>=created_at+interval '1 hour')
);
CREATE TABLE iam.ata_access_tokens (
 id uuid PRIMARY KEY,
 verification_id uuid NOT NULL REFERENCES iam.ata_verifications(id) ON DELETE CASCADE,
 token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
 digest_key_version smallint NOT NULL CHECK(digest_key_version>0),
 digest_purpose text GENERATED ALWAYS AS ('token_hmac'::text) STORED,
 FOREIGN KEY(digest_purpose,digest_key_version) REFERENCES iam.cryptographic_key_versions(purpose,key_version),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 UNIQUE(digest_key_version,token_digest)
);
CREATE TABLE iam.ata_refresh_tokens (
 id uuid PRIMARY KEY,
 verification_id uuid NOT NULL REFERENCES iam.ata_verifications(id) ON DELETE CASCADE,
 issued_access_token_id uuid REFERENCES iam.ata_access_tokens(id) ON DELETE CASCADE,
 token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
 digest_key_version smallint NOT NULL CHECK(digest_key_version>0),
 digest_purpose text GENERATED ALWAYS AS ('token_hmac'::text) STORED,
 FOREIGN KEY(digest_purpose,digest_key_version) REFERENCES iam.cryptographic_key_versions(purpose,key_version),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 consumed_at timestamptz,
 UNIQUE(digest_key_version,token_digest)
);
CREATE INDEX ata_verifications_app ON iam.ata_verifications(application_id,created_at DESC);
CREATE INDEX ata_access_verification ON iam.ata_access_tokens(verification_id);
CREATE INDEX ata_refresh_verification ON iam.ata_refresh_tokens(verification_id);
DO $$ DECLARE scoped boolean; relation_name text; BEGIN
 SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.applications'::regclass AND attname='testing_environment_id' AND NOT attisdropped) INTO scoped;
 FOREACH relation_name IN ARRAY ARRAY['ata_verifications','ata_access_tokens','ata_refresh_tokens'] LOOP
  EXECUTE format('ALTER TABLE iam.%I ENABLE ROW LEVEL SECURITY',relation_name);
  EXECUTE format('REVOKE ALL ON iam.%I FROM PUBLIC',relation_name);
  IF scoped THEN
   EXECUTE format('ALTER TABLE iam.%I ADD COLUMN testing_environment_id uuid NOT NULL DEFAULT iam_private.current_testing_environment_id()',relation_name);
   EXECUTE format('CREATE INDEX ON iam.%I(testing_environment_id)',relation_name);
   EXECUTE format('CREATE POLICY testing_environment_isolation ON iam.%I AS RESTRICTIVE USING(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id()) WITH CHECK(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id())',relation_name);
   EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',relation_name);
  END IF;
 END LOOP;
 IF scoped THEN
  ALTER TABLE iam.ata_verifications ADD FOREIGN KEY(testing_environment_id,application_id) REFERENCES iam.applications(testing_environment_id,id) ON DELETE CASCADE;
 ELSE
  ALTER TABLE iam.ata_verifications ADD FOREIGN KEY(application_id) REFERENCES iam.applications(id) ON DELETE CASCADE;
 END IF;
END $$;

CREATE FUNCTION iam_private.ata_verification_metadata(p_id uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,iam AS $$
 SELECT jsonb_build_object('id',v.id,'app_id',app.app_id,'app_ids',v.app_ids,'endpoints',v.endpoints,
  'graph',v.graph,'expires_at',v.expires_at,'access_token_validity',v.access_token_validity,
  'signing_principal',v.signing_principal,'created_at',v.created_at,'revoked_at',v.revoked_at)
 FROM iam.ata_verifications v JOIN iam.applications app ON app.id=v.application_id WHERE v.id=p_id;
$$;
REVOKE ALL ON FUNCTION iam_private.ata_verification_metadata(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.ata_verification_is_live(p_id uuid) RETURNS boolean
LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE v iam.ata_verifications%ROWTYPE; expected jsonb; endpoint iam.application_ata_endpoints%ROWTYPE;
BEGIN
 SELECT * INTO v FROM iam.ata_verifications WHERE id=p_id AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp());
 IF NOT FOUND OR v.testing_generation<>iam_private.obo_testing_generation() THEN RETURN false; END IF;
 PERFORM 1 FROM iam.applications a JOIN iam.principals p ON p.id=a.id
 JOIN iam.organizations org ON org.id=a.organization_id AND org.status='active'
 WHERE a.id=v.application_id AND a.organization_id=v.organization_id AND a.review_status='verified' AND a.deleted_at IS NULL
  AND p.status='active' AND p.auth_epoch=v.application_auth_epoch FOR SHARE OF a,p,org;
 IF NOT FOUND THEN RETURN false; END IF;
 FOR expected IN SELECT value FROM jsonb_array_elements(v.graph) LOOP
  PERFORM 1 FROM iam.applications a JOIN iam.principals p ON p.id=a.id
  JOIN iam.organizations org ON org.id=a.organization_id AND org.status='active'
  WHERE a.id=expected->>'application_id' AND a.app_id=expected->>'app_id'
   AND a.review_status='verified' AND a.deleted_at IS NULL AND p.status='active' AND p.auth_epoch=(expected->>'auth_epoch')::bigint
   AND (a.visibility='public' OR a.organization_id=v.organization_id) FOR SHARE OF a,p,org;
  IF NOT FOUND THEN RETURN false; END IF;
  SELECT * INTO endpoint FROM iam.application_ata_endpoints WHERE application_id=expected->>'application_id'
   AND endpoint_id=expected->>'endpoint_id' AND active AND version=(expected->>'version')::bigint FOR SHARE;
  IF NOT FOUND OR endpoint.definition IS DISTINCT FROM expected-ARRAY['app_id','application_id','ata_id','version','auth_epoch'] THEN RETURN false; END IF;
 END LOOP;
 PERFORM 1 FROM iam.ata_verifications WHERE id=p_id AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION iam_private.ata_verification_is_live(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.ata_verification_create(p_app text,p_id uuid,p_roots jsonb,p_graph jsonb,p_apps text[],p_expires_after bigint,p_access_ttl integer,p_refresh jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE app iam.applications%ROWTYPE; signer jsonb; epoch bigint; expires timestamptz; created timestamptz:=clock_timestamp();
BEGIN
 IF NOT iam_private.can_manage_application(p_app,iam_private.current_principal_id()) THEN RAISE EXCEPTION 'ata_management_forbidden' USING ERRCODE='42501'; END IF;
 IF p_access_ttl NOT BETWEEN 60 AND 86400 OR p_access_ttl IS NULL OR p_expires_after<3600
 OR cardinality(p_apps) NOT BETWEEN 1 AND 64 OR p_apps IS NULL
 OR cardinality(p_apps)<>(SELECT count(DISTINCT a) FROM unnest(p_apps) a)
 OR p_graph IS DISTINCT FROM iam_private.application_ata_graph(p_app,p_roots)
 OR p_graph IS NULL OR jsonb_typeof(p_graph)<>'array' OR jsonb_array_length(p_graph)=0
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(p_graph) node WHERE NOT (node->>'app_id'=ANY(p_apps))) THEN
  RAISE EXCEPTION 'ata_invalid_verification' USING ERRCODE='22023'; END IF;
 SELECT * INTO app FROM iam.applications WHERE id=p_app FOR SHARE;
 SELECT auth_epoch INTO epoch FROM iam.principals WHERE id=p_app AND status='active' FOR SHARE;
 SELECT jsonb_build_object('id',p.id,'kind',p.kind,'display_name',COALESCE(c.display_name,s.display_name,p.id)) INTO signer
 FROM iam.principals p LEFT JOIN iam.carbons c ON c.id=p.id LEFT JOIN iam.silicons s ON s.id=p.id
 WHERE p.id=iam_private.current_principal_id() AND p.kind IN ('carbon','silicon') AND p.status='active' FOR SHARE OF p;
 IF app.id IS NULL OR epoch IS NULL OR signer IS NULL THEN RAISE EXCEPTION 'ata_management_forbidden' USING ERRCODE='42501'; END IF;
 expires:=CASE WHEN p_expires_after IS NULL THEN NULL ELSE created+make_interval(secs=>p_expires_after::double precision) END;
 INSERT INTO iam.ata_verifications(id,application_id,organization_id,application_auth_epoch,app_ids,endpoints,graph,signing_principal,
 access_token_validity,testing_generation,created_at,expires_at)
 VALUES(p_id,p_app,app.organization_id,epoch,p_apps,p_roots,p_graph,signer,p_access_ttl,iam_private.obo_testing_generation(),created,expires);
 INSERT INTO iam.ata_refresh_tokens(id,verification_id,token_digest,digest_key_version)
 VALUES((p_refresh->>'id')::uuid,p_id,decode(p_refresh->>'digest','hex'),(p_refresh->>'key_version')::smallint);
 IF NOT iam_private.ata_verification_is_live(p_id) THEN RAISE EXCEPTION 'ata_graph_changed' USING ERRCODE='P0001'; END IF;
 RETURN iam_private.ata_verification_metadata(p_id);
END $$;
REVOKE ALL ON FUNCTION iam_private.ata_verification_create(text,uuid,jsonb,jsonb,text[],bigint,integer,jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.ata_verifications_list(p_app text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE result jsonb;
BEGIN
 IF NOT iam_private.can_manage_application(p_app,iam_private.current_principal_id()) THEN RAISE EXCEPTION 'ata_management_forbidden' USING ERRCODE='42501'; END IF;
 SELECT COALESCE(jsonb_agg(iam_private.ata_verification_metadata(id)||jsonb_build_object('active',iam_private.ata_verification_is_live(id)) ORDER BY created_at DESC),'[]'::jsonb) INTO result
 FROM iam.ata_verifications WHERE application_id=p_app;
 RETURN jsonb_build_object('items',result);
END $$;
REVOKE ALL ON FUNCTION iam_private.ata_verifications_list(text) FROM PUBLIC;

CREATE FUNCTION iam_private.ata_verification_revoke(p_app text,p_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 IF NOT iam_private.can_manage_application(p_app,iam_private.current_principal_id()) THEN RAISE EXCEPTION 'ata_management_forbidden' USING ERRCODE='42501'; END IF;
 UPDATE iam.ata_verifications SET revoked_at=COALESCE(revoked_at,clock_timestamp()),revocation_reason=COALESCE(revocation_reason,'manager_revoked')
 WHERE id=p_id AND application_id=p_app;
 IF NOT FOUND THEN RAISE EXCEPTION 'ata_verification_not_found' USING ERRCODE='P0001'; END IF;
 RETURN iam_private.ata_verification_metadata(p_id);
END $$;
REVOKE ALL ON FUNCTION iam_private.ata_verification_revoke(text,uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.ata_token_refresh(p_digests jsonb,p_pair jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE token iam.ata_refresh_tokens%ROWTYPE; v iam.ata_verifications%ROWTYPE; expires timestamptz;
 access_id uuid:=(p_pair->'access'->>'id')::uuid; refresh_id uuid:=(p_pair->'refresh'->>'id')::uuid;
BEGIN
 IF iam_private.current_application_id() IS NULL OR iam_private.current_application_id() IS DISTINCT FROM iam_private.current_principal_id() THEN
  RAISE EXCEPTION 'ata_application_required' USING ERRCODE='42501'; END IF;
 SELECT t.* INTO token FROM iam.ata_refresh_tokens t JOIN iam.ata_verifications stored ON stored.id=t.verification_id
 WHERE stored.application_id=iam_private.current_application_id() AND EXISTS(SELECT 1 FROM jsonb_array_elements(p_digests) d
  WHERE (d->>'key_version')::smallint=t.digest_key_version AND decode(d->>'digest','hex')=t.token_digest);
 IF token.id IS NULL THEN RAISE EXCEPTION 'ata_refresh_invalid' USING ERRCODE='P0001'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('ata-refresh:'||token.verification_id::text,0));
 -- Lock configuration/identity authority before the mutable verification row.
 IF NOT iam_private.ata_verification_is_live(token.verification_id) THEN RAISE EXCEPTION 'ata_refresh_invalid' USING ERRCODE='P0001'; END IF;
 SELECT * INTO STRICT v FROM iam.ata_verifications WHERE id=token.verification_id FOR UPDATE;
 SELECT * INTO STRICT token FROM iam.ata_refresh_tokens WHERE id=token.id FOR UPDATE;
 IF v.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'ata_refresh_invalid' USING ERRCODE='P0001'; END IF;
 IF token.consumed_at IS NOT NULL THEN
  UPDATE iam.ata_verifications SET revoked_at=clock_timestamp(),revocation_reason='refresh_reuse' WHERE id=v.id;
  RETURN jsonb_build_object('error','ata_refresh_reused');
 END IF;
 expires:=LEAST(clock_timestamp()+make_interval(secs=>v.access_token_validity),v.expires_at);
 UPDATE iam.ata_refresh_tokens SET consumed_at=clock_timestamp() WHERE id=token.id;
 INSERT INTO iam.ata_access_tokens(id,verification_id,token_digest,digest_key_version,expires_at)
 VALUES(access_id,v.id,decode(p_pair->'access'->>'digest','hex'),(p_pair->'access'->>'key_version')::smallint,expires);
 INSERT INTO iam.ata_refresh_tokens(id,verification_id,issued_access_token_id,token_digest,digest_key_version)
 VALUES(refresh_id,v.id,access_id,decode(p_pair->'refresh'->>'digest','hex'),(p_pair->'refresh'->>'key_version')::smallint);
 RETURN jsonb_build_object('token_id',access_id,'verification_id',v.id,'token_type','Bearer','expires_at',expires,
  'expires_in',GREATEST(0,ceil(extract(epoch FROM expires-clock_timestamp()))::bigint),'refresh_expires_at',v.expires_at);
END $$;
REVOKE ALL ON FUNCTION iam_private.ata_token_refresh(jsonb,jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.ata_token_verify(p_app_id text,p_digests jsonb,p_endpoint text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE token iam.ata_access_tokens%ROWTYPE; v iam.ata_verifications%ROWTYPE; receiver text;
BEGIN
 IF iam_private.current_application_id() IS NULL OR iam_private.current_application_id() IS DISTINCT FROM iam_private.current_principal_id() THEN
  RAISE EXCEPTION 'ata_application_required' USING ERRCODE='42501'; END IF;
 SELECT app_id INTO receiver FROM iam.applications WHERE id=iam_private.current_application_id();
 SELECT t.* INTO token FROM iam.ata_access_tokens t JOIN iam.ata_verifications stored ON stored.id=t.verification_id
 JOIN iam.applications app ON app.id=stored.application_id AND app.app_id=p_app_id
 WHERE t.expires_at>clock_timestamp() AND receiver=ANY(stored.app_ids) AND EXISTS(SELECT 1 FROM jsonb_array_elements(p_digests) d
  WHERE (d->>'key_version')::smallint=t.digest_key_version AND decode(d->>'digest','hex')=t.token_digest);
 IF token.id IS NULL OR NOT iam_private.ata_verification_is_live(token.verification_id) THEN RETURN jsonb_build_object('verified',false); END IF;
 SELECT * INTO STRICT v FROM iam.ata_verifications WHERE id=token.verification_id;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(v.graph) node WHERE node->>'application_id'=iam_private.current_application_id()
  AND node->>'path'=p_endpoint) THEN RETURN jsonb_build_object('verified',false); END IF;
 RETURN jsonb_build_object('verified',true,'valid_till',to_char(token.expires_at AT TIME ZONE 'UTC','YYYYMMDDHH24MISS')::bigint);
END $$;
REVOKE ALL ON FUNCTION iam_private.ata_token_verify(text,jsonb,text) FROM PUBLIC;

CREATE FUNCTION iam_private.ata_token_result_is_live(p_token uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE token iam.ata_access_tokens%ROWTYPE;
BEGIN
 SELECT t.* INTO token FROM iam.ata_access_tokens t JOIN iam.ata_verifications v ON v.id=t.verification_id
 WHERE t.id=p_token AND v.application_id=iam_private.current_application_id() AND iam_private.current_application_id()=iam_private.current_principal_id()
 AND t.expires_at>clock_timestamp();
 RETURN token.id IS NOT NULL AND iam_private.ata_verification_is_live(token.verification_id)
 AND EXISTS(SELECT 1 FROM iam.ata_refresh_tokens WHERE issued_access_token_id=token.id AND consumed_at IS NULL);
END $$;
REVOKE ALL ON FUNCTION iam_private.ata_token_result_is_live(uuid) FROM PUBLIC;
