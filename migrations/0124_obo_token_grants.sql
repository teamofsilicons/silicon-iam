-- Separately consented, reusable, audience-bound OBO credentials. Old login
-- consent and old single-use proofs never become grants in this model.
CREATE TABLE iam.obo_authorization_requests (
 id uuid PRIMARY KEY,
 application_id text NOT NULL,
 subject_principal_id text NOT NULL,
 organization_id uuid NOT NULL REFERENCES iam.organizations(id) ON DELETE CASCADE,
 membership_id uuid NOT NULL REFERENCES iam.organization_memberships(id) ON DELETE CASCADE,
 login_consent_id uuid NOT NULL REFERENCES iam.oauth_consent_grants(id) ON DELETE CASCADE,
 login_family_id uuid NOT NULL REFERENCES iam.refresh_token_families(id) ON DELETE CASCADE,
 login_session_id uuid NOT NULL REFERENCES iam.authentication_sessions(id) ON DELETE CASCADE,
 subject_auth_epoch bigint NOT NULL,
 membership_authz_epoch bigint NOT NULL,
 graphs jsonb NOT NULL CHECK(jsonb_typeof(graphs)='array' AND jsonb_array_length(graphs) BETWEEN 1 AND 100 AND octet_length(graphs::text)<=262144),
 grant_ids uuid[] NOT NULL DEFAULT '{}',
 testing_generation bigint NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','declined','exchanged')),
 version bigint NOT NULL DEFAULT 1 CHECK(version>=1),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '10 minutes'
);
CREATE TABLE iam.obo_grants (
 id uuid PRIMARY KEY,
 application_id text NOT NULL,
 subject_principal_id text NOT NULL,
 organization_id uuid NOT NULL REFERENCES iam.organizations(id) ON DELETE CASCADE,
 membership_id uuid NOT NULL REFERENCES iam.organization_memberships(id) ON DELETE CASCADE,
 audience_application_id text NOT NULL,
 endpoint_id text NOT NULL,
 login_consent_id uuid NOT NULL REFERENCES iam.oauth_consent_grants(id) ON DELETE CASCADE,
 login_family_id uuid NOT NULL REFERENCES iam.refresh_token_families(id) ON DELETE CASCADE,
 login_session_id uuid NOT NULL REFERENCES iam.authentication_sessions(id) ON DELETE CASCADE,
 approving_session_id uuid NOT NULL REFERENCES iam.authentication_sessions(id) ON DELETE CASCADE,
 subject_auth_epoch bigint NOT NULL,
 membership_authz_epoch bigint NOT NULL,
 graph jsonb NOT NULL CHECK(jsonb_typeof(graph)='object'),
 graph_version integer NOT NULL DEFAULT 1 CHECK(graph_version=1),
 testing_generation bigint NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 revocation_reason text
);
CREATE INDEX obo_grants_subject_idx ON iam.obo_grants(subject_principal_id,created_at DESC);
CREATE INDEX obo_grants_consent_idx ON iam.obo_grants(login_consent_id);
CREATE INDEX obo_grants_reuse_idx ON iam.obo_grants(application_id,subject_principal_id,organization_id,audience_application_id,endpoint_id) WHERE revoked_at IS NULL;
CREATE TABLE iam.obo_authorization_codes (
 id uuid PRIMARY KEY,
 request_id uuid NOT NULL UNIQUE REFERENCES iam.obo_authorization_requests(id) ON DELETE CASCADE,
 token_digest bytea NOT NULL UNIQUE CHECK(octet_length(token_digest)=32),
 digest_key_version smallint NOT NULL CHECK(digest_key_version>0),
 digest_purpose text GENERATED ALWAYS AS ('token_hmac'::text) STORED,
 FOREIGN KEY(digest_purpose,digest_key_version) REFERENCES iam.cryptographic_key_versions(purpose,key_version),
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz
);
CREATE TABLE iam.obo_token_families (
 id uuid PRIMARY KEY,
 grant_id uuid NOT NULL REFERENCES iam.obo_grants(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 revocation_reason text
);
CREATE INDEX obo_token_families_grant_idx ON iam.obo_token_families(grant_id);
CREATE TABLE iam.obo_access_tokens (
 id uuid PRIMARY KEY,
 grant_id uuid NOT NULL REFERENCES iam.obo_grants(id) ON DELETE CASCADE,
 family_id uuid NOT NULL REFERENCES iam.obo_token_families(id) ON DELETE CASCADE,
 issuer_application_id text NOT NULL,
 audience_application_id text NOT NULL,
 endpoint_id text NOT NULL,
 parent_token_id uuid REFERENCES iam.obo_access_tokens(id) ON DELETE CASCADE,
 chain jsonb NOT NULL CHECK(jsonb_typeof(chain)='array' AND jsonb_array_length(chain) BETWEEN 1 AND 10),
 token_digest bytea NOT NULL UNIQUE CHECK(octet_length(token_digest)=32),
 digest_key_version smallint NOT NULL CHECK(digest_key_version>0),
 digest_purpose text GENERATED ALWAYS AS ('token_hmac'::text) STORED,
 FOREIGN KEY(digest_purpose,digest_key_version) REFERENCES iam.cryptographic_key_versions(purpose,key_version),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz
);
CREATE INDEX obo_access_tokens_family_idx ON iam.obo_access_tokens(family_id);
CREATE INDEX obo_access_tokens_parent_idx ON iam.obo_access_tokens(parent_token_id);
CREATE TABLE iam.obo_refresh_tokens (
 id uuid PRIMARY KEY,
 family_id uuid NOT NULL REFERENCES iam.obo_token_families(id) ON DELETE CASCADE,
 issued_access_token_id uuid NOT NULL REFERENCES iam.obo_access_tokens(id) ON DELETE CASCADE,
 token_digest bytea NOT NULL UNIQUE CHECK(octet_length(token_digest)=32),
 digest_key_version smallint NOT NULL CHECK(digest_key_version>0),
 digest_purpose text GENERATED ALWAYS AS ('token_hmac'::text) STORED,
 FOREIGN KEY(digest_purpose,digest_key_version) REFERENCES iam.cryptographic_key_versions(purpose,key_version),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz
);
CREATE INDEX obo_refresh_tokens_family_idx ON iam.obo_refresh_tokens(family_id);

-- Canonical identities are unique per environment in an existing testing
-- installation. Add scoped natural-key foreign keys there, ordinary keys in
-- production; UUID resource keys remain globally unique on both planes.
DO $$
DECLARE scoped boolean; relation_name text; binding record;
BEGIN
 SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.applications'::regclass
  AND attname='testing_environment_id' AND NOT attisdropped) INTO scoped;
 IF scoped THEN
  FOREACH relation_name IN ARRAY ARRAY['obo_authorization_requests','obo_grants','obo_authorization_codes','obo_token_families','obo_access_tokens','obo_refresh_tokens'] LOOP
   EXECUTE format('ALTER TABLE iam.%I ADD COLUMN testing_environment_id uuid NOT NULL DEFAULT iam_private.current_testing_environment_id()',relation_name);
   EXECUTE format('CREATE INDEX ON iam.%I(testing_environment_id)',relation_name);
   EXECUTE format('CREATE POLICY testing_environment_isolation ON iam.%I AS RESTRICTIVE USING(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id()) WITH CHECK(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id())',relation_name);
   EXECUTE format('ALTER TABLE iam.%I ENABLE ROW LEVEL SECURITY',relation_name);
   EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',relation_name);
  END LOOP;
 END IF;
 FOR binding IN SELECT * FROM (VALUES
  ('obo_authorization_requests','application_id','applications'),
  ('obo_authorization_requests','subject_principal_id','principals'),
  ('obo_grants','application_id','applications'),
  ('obo_grants','subject_principal_id','principals'),
  ('obo_grants','audience_application_id','applications'),
  ('obo_access_tokens','issuer_application_id','applications'),
  ('obo_access_tokens','audience_application_id','applications')
 ) AS refs(child,column_name,parent) LOOP
  IF scoped THEN
   EXECUTE format('ALTER TABLE iam.%I ADD FOREIGN KEY(testing_environment_id,%I) REFERENCES iam.%I(testing_environment_id,id) ON DELETE CASCADE',binding.child,binding.column_name,binding.parent);
  ELSE
   EXECUTE format('ALTER TABLE iam.%I ADD FOREIGN KEY(%I) REFERENCES iam.%I(id) ON DELETE CASCADE',binding.child,binding.column_name,binding.parent);
  END IF;
 END LOOP;
END $$;

-- Runtime code can use only the caller-bound functions below. The testing
-- overlay adds forced environment policies, including for definer functions.
ALTER TABLE iam.obo_authorization_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.obo_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.obo_authorization_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.obo_token_families ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.obo_access_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.obo_refresh_tokens ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON iam.obo_authorization_requests,iam.obo_grants,iam.obo_authorization_codes,
 iam.obo_token_families,iam.obo_access_tokens,iam.obo_refresh_tokens FROM PUBLIC;

-- Invoker-only internals are reachable solely through the definer entrypoints.
CREATE FUNCTION iam_private.obo_testing_generation() RETURNS bigint
LANGUAGE plpgsql SET search_path=pg_catalog,iam_private AS $$
DECLARE env uuid:=NULLIF(current_setting('iam.testing_environment_id',true),'')::uuid; generation bigint;
BEGIN
 IF env IS NULL THEN RETURN 0; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('testing-runtime:'||env::text,0));
 EXECUTE 'SELECT generation FROM iam_private.testing_runtime_state WHERE environment_id=$1 AND active'
 INTO generation USING env;
 -- Legacy isolated environments have no managed lifecycle row.
 IF generation IS NULL THEN
  EXECUTE 'SELECT CASE WHEN EXISTS(SELECT 1 FROM iam_private.testing_runtime_state WHERE environment_id=$1) THEN -1 ELSE 1 END'
  INTO generation USING env;
 END IF;
 RETURN generation;
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_testing_generation() FROM PUBLIC;

CREATE FUNCTION iam_private.obo_graph_node(p_issuer text,p_audience text,p_endpoint text,p_subject text,p_org uuid,p_seen text[])
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE issuer iam.applications%ROWTYPE; audience iam.applications%ROWTYPE;
 endpoint iam.application_obo_endpoints%ROWTYPE; approval iam.application_approved_scopes%ROWTYPE;
 issuer_epoch bigint; audience_epoch bigint; dependency jsonb; children jsonb:='[]';
BEGIN
 IF cardinality(p_seen)>10 OR p_audience=ANY(p_seen) THEN
  RAISE EXCEPTION 'obo_dependency_cycle_or_depth' USING ERRCODE='P0001'; END IF;
 SELECT * INTO issuer FROM iam.applications WHERE app_id=p_issuer FOR SHARE;
 SELECT * INTO audience FROM iam.applications WHERE app_id=p_audience FOR SHARE;
 IF issuer.id IS NULL OR audience.id IS NULL OR NOT iam_private.application_allows_subject(issuer.id,p_subject,p_org)
 OR NOT iam_private.application_allows_subject(audience.id,p_subject,p_org) THEN
  RAISE EXCEPTION 'obo_application_unavailable' USING ERRCODE='P0001'; END IF;
 SELECT auth_epoch INTO issuer_epoch FROM iam.principals WHERE id=issuer.id AND status='active' FOR SHARE;
 SELECT auth_epoch INTO audience_epoch FROM iam.principals WHERE id=audience.id AND status='active' FOR SHARE;
 SELECT * INTO endpoint FROM iam.application_obo_endpoints
 WHERE application_id=audience.id AND endpoint_id=p_endpoint AND status='active' FOR SHARE;
 SELECT * INTO approval FROM iam.application_approved_scopes
 WHERE application_id=issuer.id AND scope='obo:'||audience.app_id||':'||p_endpoint AND revoked_at IS NULL FOR SHARE;
 IF issuer_epoch IS NULL OR audience_epoch IS NULL OR endpoint.application_id IS NULL OR approval.application_id IS NULL
 OR NOT iam_private.application_scope_names(issuer.app_scope) @> ARRAY[approval.scope]
 OR (endpoint.critical AND issuer.visibility='public' AND approval.approval_basis<>'provider_approval') THEN
  RAISE EXCEPTION 'obo_endpoint_not_approved' USING ERRCODE='P0001'; END IF;
 FOR dependency IN SELECT value FROM jsonb_array_elements(endpoint.downstream) ORDER BY value->>'audience',value->>'endpoint_id' LOOP
  children:=children||jsonb_build_array(iam_private.obo_graph_node(audience.app_id,dependency->>'audience',dependency->>'endpoint_id',p_subject,p_org,p_seen||p_audience));
  IF octet_length(children::text)>262144 THEN RAISE EXCEPTION 'obo_dependency_graph_too_large' USING ERRCODE='22023'; END IF;
 END LOOP;
 RETURN jsonb_build_object('audience',audience.app_id,'app_name',COALESCE(NULLIF(audience.app_name,''),audience.app_id),'endpoint_id',p_endpoint,
  'description',p_endpoint||' ('||endpoint.path||')','critical',endpoint.critical,'downstream',children,
  '_issuer',issuer.id,'_audience',audience.id,'_issuer_epoch',issuer_epoch,'_audience_epoch',audience_epoch,
  '_approval',approval.approved_at,'_path',endpoint.path,'_metadata',endpoint.metadata_definition);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_graph_node(text,text,text,text,uuid,text[]) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_public_node(p_node jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,iam_private AS $$
 SELECT jsonb_build_object('audience',p_node->'audience','app_name',p_node->'app_name',
 'endpoint_id',p_node->'endpoint_id','description',p_node->'description','critical',p_node->'critical',
 'downstream',COALESCE((SELECT jsonb_agg(iam_private.obo_public_node(value)) FROM jsonb_array_elements(p_node->'downstream')),'[]'::jsonb));
$$;
REVOKE ALL ON FUNCTION iam_private.obo_public_node(jsonb) FROM PUBLIC;

-- Compare every approved edge with current authority. New declarations never
-- widen an older snapshot; removed edges/approvals are immediately unusable.
CREATE FUNCTION iam_private.obo_graph_is_current(p_node jsonb,p_subject text,p_org uuid)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE endpoint iam.application_obo_endpoints%ROWTYPE; child jsonb;
BEGIN
 PERFORM 1 FROM iam.applications issuer JOIN iam.principals ip ON ip.id=issuer.id
 JOIN iam.applications audience ON audience.id=p_node->>'_audience'
 JOIN iam.principals ap ON ap.id=audience.id
 JOIN iam.application_approved_scopes approved ON approved.application_id=issuer.id
  AND approved.scope='obo:'||audience.app_id||':'||(p_node->>'endpoint_id')
  AND approved.approved_at=(p_node->>'_approval')::timestamptz AND approved.revoked_at IS NULL
 WHERE issuer.id=p_node->>'_issuer' AND ip.status='active' AND ap.status='active'
  AND ip.auth_epoch=(p_node->>'_issuer_epoch')::bigint AND ap.auth_epoch=(p_node->>'_audience_epoch')::bigint
  AND iam_private.application_allows_subject(issuer.id,p_subject,p_org)
  AND iam_private.application_allows_subject(audience.id,p_subject,p_org)
  AND iam_private.application_scope_names(issuer.app_scope) @> ARRAY[approved.scope]
  AND (NOT (p_node->>'critical')::boolean OR issuer.visibility='private' OR approved.approval_basis='provider_approval')
 FOR SHARE OF issuer,ip,audience,ap,approved;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO endpoint FROM iam.application_obo_endpoints WHERE application_id=p_node->>'_audience'
 AND endpoint_id=p_node->>'endpoint_id' AND status='active' AND path=p_node->>'_path'
 AND critical=(p_node->>'critical')::boolean FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 FOR child IN SELECT value FROM jsonb_array_elements(p_node->'downstream') LOOP
  IF NOT endpoint.downstream @> jsonb_build_array(jsonb_build_object('audience',child->>'audience','endpoint_id',child->>'endpoint_id'))
  OR NOT iam_private.obo_graph_is_current(child,p_subject,p_org) THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_graph_is_current(jsonb,text,uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_user_session(p_token uuid) RETURNS uuid
LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE session_id uuid;
BEGIN
 IF iam_private.current_application_id() IS NOT NULL THEN RAISE EXCEPTION 'obo_direct_iam_user_required' USING ERRCODE='42501'; END IF;
 SELECT session.id INTO session_id FROM iam.access_tokens token
 JOIN iam.principals subject ON subject.id=token.subject_principal_id AND subject.status='active' AND subject.auth_epoch=token.subject_auth_epoch
 JOIN iam.authentication_sessions session ON session.id=token.authentication_session_id AND session.subject_principal_id=subject.id
 AND session.status='active' AND session.subject_auth_epoch=subject.auth_epoch
 AND session.idle_expires_at>clock_timestamp() AND session.absolute_expires_at>clock_timestamp()
 WHERE token.id=p_token AND token.subject_principal_id=iam_private.current_principal_id()
 AND token.revoked_at IS NULL AND token.expires_at>clock_timestamp()
 AND token.client_application_id IS NULL AND token.token_class IN ('carbon_access','silicon_access')
 AND token.audience='silicon-iam' AND EXISTS(SELECT 1 FROM iam.access_token_scopes WHERE access_token_id=token.id AND scope='iam.self')
 FOR SHARE OF token,subject,session;
 IF session_id IS NULL THEN RAISE EXCEPTION 'obo_direct_iam_user_required' USING ERRCODE='42501'; END IF;
 RETURN session_id;
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_user_session(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_grant_is_live(p_grant uuid) RETURNS boolean
LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE g iam.obo_grants%ROWTYPE;
BEGIN
 -- Read immutable bindings first. Administrative revocations lock their
 -- authority row before the grant, so take the grant lock only after those
 -- authority locks to avoid a grant/endpoint or grant/session deadlock.
 SELECT * INTO g FROM iam.obo_grants WHERE id=p_grant AND revoked_at IS NULL AND expires_at>clock_timestamp();
 IF NOT FOUND OR g.testing_generation<>iam_private.obo_testing_generation() THEN RETURN false; END IF;
 PERFORM 1 FROM iam.principals subject
 JOIN iam.organization_memberships member ON member.id=g.membership_id AND member.organization_id=g.organization_id
 AND member.principal_id=subject.id AND member.status='active' AND member.authz_epoch=g.membership_authz_epoch
 JOIN iam.organizations org ON org.id=member.organization_id AND org.status='active'
 JOIN iam.authentication_sessions approving ON approving.id=g.approving_session_id AND approving.subject_principal_id=subject.id
 AND approving.status='active' AND approving.subject_auth_epoch=g.subject_auth_epoch
 AND approving.idle_expires_at>clock_timestamp() AND approving.absolute_expires_at>clock_timestamp()
 JOIN iam.authentication_sessions login ON login.id=g.login_session_id AND login.subject_principal_id=subject.id
 AND login.status='active' AND login.subject_auth_epoch=g.subject_auth_epoch
 AND login.idle_expires_at>clock_timestamp() AND login.absolute_expires_at>clock_timestamp()
 JOIN iam.refresh_token_families family ON family.id=g.login_family_id AND family.status='active'
 AND family.authentication_session_id=login.id AND family.subject_principal_id=subject.id
 AND family.client_application_id=g.application_id AND family.oauth_consent_grant_id=g.login_consent_id AND family.absolute_expires_at>clock_timestamp()
 JOIN iam.oauth_consent_grants consent ON consent.id=g.login_consent_id AND consent.status='active'
 AND consent.application_id=g.application_id AND consent.subject_principal_id=subject.id
 AND consent.parent_authentication_session_id=login.id AND member.id=ANY(consent.selected_membership_ids)
 WHERE subject.id=g.subject_principal_id AND subject.status='active' AND subject.auth_epoch=g.subject_auth_epoch
 AND iam_private.application_private_consent_is_current(g.application_id,consent.id)
 FOR SHARE OF subject,member,org,approving,login,family,consent;
 IF NOT FOUND THEN RETURN false; END IF;
 IF NOT iam_private.obo_graph_is_current(g.graph,g.subject_principal_id,g.organization_id) THEN RETURN false; END IF;
 PERFORM 1 FROM iam.obo_grants WHERE id=g.id AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_grant_is_live(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_access_is_live(p_token uuid) RETURNS boolean
LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE token iam.obo_access_tokens%ROWTYPE; parent iam.obo_access_tokens%ROWTYPE;
BEGIN
 SELECT * INTO token FROM iam.obo_access_tokens WHERE id=p_token AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM iam.obo_token_families WHERE id=token.family_id AND grant_id=token.grant_id AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND OR NOT iam_private.obo_grant_is_live(token.grant_id) THEN RETURN false; END IF;
 IF token.parent_token_id IS NOT NULL THEN
  SELECT * INTO parent FROM iam.obo_access_tokens WHERE id=token.parent_token_id;
  IF parent.grant_id IS DISTINCT FROM token.grant_id OR parent.family_id IS DISTINCT FROM token.family_id
   OR parent.audience_application_id IS DISTINCT FROM token.issuer_application_id
   OR token.expires_at>parent.expires_at OR jsonb_array_length(parent.chain)+1<>jsonb_array_length(token.chain)
   OR NOT iam_private.obo_access_is_live(parent.id) THEN RETURN false; END IF;
 END IF;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_access_is_live(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_request_detail(p_request uuid) RETURNS jsonb
LANGUAGE sql SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT jsonb_build_object('id',request.id,'app_id',app.app_id,'app_name',COALESCE(NULLIF(app.app_name,''),app.app_id),
 'actor',jsonb_build_object('type',subject.kind,'public_id',COALESCE(carbon.carbon_id,silicon.global_silicon_id)),
 'org_id',org.org_id,'status',CASE WHEN request.expires_at<=clock_timestamp() AND request.status='pending' THEN 'expired' ELSE request.status END,
 'version',request.version,'expires_at',request.expires_at,'endpoints',(SELECT jsonb_agg(iam_private.obo_public_node(value)) FROM jsonb_array_elements(request.graphs)))
 FROM iam.obo_authorization_requests request JOIN iam.applications app ON app.id=request.application_id
 JOIN iam.principals subject ON subject.id=request.subject_principal_id
 JOIN iam.organizations org ON org.id=request.organization_id
 LEFT JOIN iam.carbons carbon ON carbon.id=subject.id LEFT JOIN iam.silicons silicon ON silicon.id=subject.id
 WHERE request.id=p_request;
$$;
REVOKE ALL ON FUNCTION iam_private.obo_request_detail(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_authorization_create(p_parent_token uuid,p_org_id text,p_roots jsonb,p_request_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE token iam.access_tokens%ROWTYPE; member iam.organization_memberships%ROWTYPE; consent_id uuid;
 app iam.applications%ROWTYPE; root jsonb; graphs jsonb:='[]'; generation bigint;
BEGIN
 IF iam_private.current_application_id() IS NULL OR iam_private.current_application_id() IS DISTINCT FROM iam_private.current_principal_id() THEN
  RAISE EXCEPTION 'obo_application_required' USING ERRCODE='42501'; END IF;
 IF jsonb_typeof(p_roots) IS DISTINCT FROM 'array' OR jsonb_array_length(p_roots) NOT BETWEEN 1 AND 100
 OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(p_roots))<>jsonb_array_length(p_roots) THEN
  RAISE EXCEPTION 'obo_invalid_endpoints' USING ERRCODE='22023'; END IF;
 SELECT * INTO token FROM iam.access_tokens WHERE id=p_parent_token AND client_application_id=iam_private.current_application_id()
 AND token_class='application_access' AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE;
 SELECT * INTO app FROM iam.applications WHERE id=iam_private.current_application_id() FOR SHARE;
 SELECT m.* INTO member FROM iam.organization_memberships m JOIN iam.organizations org ON org.id=m.organization_id
 WHERE org.org_id=p_org_id AND m.principal_id=token.subject_principal_id AND m.status='active' FOR SHARE OF m,org;
 IF token.id IS NULL OR member.id IS NULL OR token.oauth_refresh_family_id IS NULL
 OR NOT iam_private.application_token_allows_membership(token.id,member.id) THEN
  RAISE EXCEPTION 'obo_subject_login_invalid' USING ERRCODE='P0001'; END IF;
 SELECT consent.id INTO consent_id FROM iam.oauth_consent_grants consent
 WHERE consent.application_id=app.id AND consent.subject_principal_id=token.subject_principal_id
 AND consent.parent_authentication_session_id=token.authentication_session_id
 AND consent.organization_id IS NOT DISTINCT FROM token.organization_id
 AND consent.membership_id IS NOT DISTINCT FROM token.membership_id AND consent.status='active'
 AND member.id=ANY(consent.selected_membership_ids) FOR SHARE;
 PERFORM 1 FROM iam.refresh_token_families WHERE id=token.oauth_refresh_family_id AND oauth_consent_grant_id=consent_id AND status='active' AND absolute_expires_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND OR consent_id IS NULL THEN RAISE EXCEPTION 'obo_subject_login_invalid' USING ERRCODE='P0001'; END IF;
 generation:=iam_private.obo_testing_generation();
 IF generation<0 THEN RAISE EXCEPTION 'obo_testing_generation_unavailable' USING ERRCODE='P0001'; END IF;
 FOR root IN SELECT value FROM jsonb_array_elements(p_roots) LOOP
  graphs:=graphs||jsonb_build_array(iam_private.obo_graph_node(app.app_id,root->>'audience',root->>'endpoint_id',token.subject_principal_id,member.organization_id,ARRAY[app.app_id]));
  IF octet_length(graphs::text)>262144 THEN RAISE EXCEPTION 'obo_dependency_graph_too_large' USING ERRCODE='22023'; END IF;
 END LOOP;
 INSERT INTO iam.obo_authorization_requests(id,application_id,subject_principal_id,organization_id,membership_id,
 login_consent_id,login_family_id,login_session_id,subject_auth_epoch,membership_authz_epoch,graphs,testing_generation)
 VALUES(p_request_id,app.id,token.subject_principal_id,member.organization_id,member.id,consent_id,
 token.oauth_refresh_family_id,token.authentication_session_id,token.subject_auth_epoch,member.authz_epoch,graphs,generation);
 RETURN iam_private.obo_request_detail(p_request_id);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_authorization_create(uuid,text,jsonb,uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_authorization_read(p_request uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE request iam.obo_authorization_requests%ROWTYPE; app_slug text; root jsonb; refreshed_graphs jsonb:='[]';
BEGIN
 SELECT * INTO request FROM iam.obo_authorization_requests WHERE id=p_request AND testing_generation=iam_private.obo_testing_generation()
 AND ((application_id=iam_private.current_principal_id() AND application_id=iam_private.current_application_id())
 OR (subject_principal_id=iam_private.current_principal_id() AND iam_private.current_application_id() IS NULL)) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'obo_authorization_not_found' USING ERRCODE='42501'; END IF;
 -- Reopening a stale pending screen gives the user the current graph and a
 -- fresh comparison version. Neither the request lifetime nor its roots grow.
 IF request.status='pending' AND request.expires_at>clock_timestamp() THEN
  SELECT app_id INTO app_slug FROM iam.applications WHERE id=request.application_id;
  FOR root IN SELECT value FROM jsonb_array_elements(request.graphs) LOOP
   refreshed_graphs:=refreshed_graphs||jsonb_build_array(iam_private.obo_graph_node(app_slug,root->>'audience',root->>'endpoint_id',request.subject_principal_id,request.organization_id,ARRAY[app_slug]));
   IF octet_length(refreshed_graphs::text)>262144 THEN RAISE EXCEPTION 'obo_dependency_graph_too_large' USING ERRCODE='22023'; END IF;
  END LOOP;
  IF refreshed_graphs IS DISTINCT FROM request.graphs THEN
   UPDATE iam.obo_authorization_requests SET graphs=refreshed_graphs,version=version+1 WHERE id=p_request;
  END IF;
 END IF;
 RETURN iam_private.obo_request_detail(p_request);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_authorization_read(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_audit(p_action text,p_grant uuid,p_target uuid,p_metadata jsonb) RETURNS void
LANGUAGE sql SET search_path=pg_catalog,iam,iam_private AS $$
 INSERT INTO iam.audit_events(id,request_id,actor_principal_id,actor_kind,organization_id,application_id,action,target_type,target_id,metadata)
 SELECT gen_random_uuid(),gen_random_uuid(),actor.id,actor.kind,g.organization_id,g.application_id,p_action,'obo_grant',p_target::text,p_metadata
 FROM iam.obo_grants g JOIN iam.principals actor ON actor.id=iam_private.current_principal_id() WHERE g.id=p_grant;
$$;
REVOKE ALL ON FUNCTION iam_private.obo_audit(text,uuid,uuid,jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_authorization_decide(p_request uuid,p_user_token uuid,p_version bigint,p_approve boolean,p_code jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE request iam.obo_authorization_requests%ROWTYPE; session_id uuid; approved_graph jsonb; current_graph jsonb;
 app_id text; grant_id uuid; ids uuid[]:='{}'; expiry timestamptz; code_expiry timestamptz;
BEGIN
 session_id:=iam_private.obo_user_session(p_user_token);
 SELECT * INTO request FROM iam.obo_authorization_requests WHERE id=p_request AND subject_principal_id=iam_private.current_principal_id() FOR UPDATE;
 IF request.id IS NULL OR request.testing_generation<>iam_private.obo_testing_generation() THEN RAISE EXCEPTION 'obo_authorization_not_found' USING ERRCODE='42501'; END IF;
 IF request.version IS DISTINCT FROM p_version THEN RAISE EXCEPTION 'obo_consent_changed' USING ERRCODE='P0001'; END IF;
 IF request.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'obo_request_expired' USING ERRCODE='P0001'; END IF;
 IF request.status<>'pending' THEN RAISE EXCEPTION 'obo_request_decided' USING ERRCODE='P0001'; END IF;
 IF NOT p_approve THEN
  UPDATE iam.obo_authorization_requests SET status='declined' WHERE id=p_request;
  RETURN jsonb_build_object('request_id',p_request,'status','declined','expires_at',request.expires_at);
 END IF;
 SELECT app.app_id INTO app_id FROM iam.applications app WHERE id=request.application_id;
 SELECT LEAST(family.absolute_expires_at,session.absolute_expires_at,login.absolute_expires_at) INTO expiry
 FROM iam.refresh_token_families family JOIN iam.authentication_sessions session ON session.id=session_id
 JOIN iam.authentication_sessions login ON login.id=request.login_session_id
 WHERE family.id=request.login_family_id AND family.status='active'
 AND family.absolute_expires_at>clock_timestamp() AND login.status='active'
 AND login.idle_expires_at>clock_timestamp() AND login.absolute_expires_at>clock_timestamp()
 FOR SHARE OF family,session,login;
 IF expiry IS NULL THEN RAISE EXCEPTION 'obo_subject_login_invalid' USING ERRCODE='P0001'; END IF;
 FOR approved_graph IN SELECT value FROM jsonb_array_elements(request.graphs) LOOP
  current_graph:=iam_private.obo_graph_node(app_id,approved_graph->>'audience',approved_graph->>'endpoint_id',request.subject_principal_id,request.organization_id,ARRAY[app_id]);
  IF current_graph IS DISTINCT FROM approved_graph THEN RAISE EXCEPTION 'obo_consent_changed' USING ERRCODE='P0001'; END IF;
  SELECT g.id INTO grant_id FROM iam.obo_grants g WHERE g.application_id=request.application_id
   AND g.subject_principal_id=request.subject_principal_id AND g.organization_id=request.organization_id
   AND g.audience_application_id=approved_graph->>'_audience' AND g.endpoint_id=approved_graph->>'endpoint_id'
   AND g.approving_session_id=session_id AND g.login_family_id=request.login_family_id
   AND g.graph=approved_graph AND iam_private.obo_grant_is_live(g.id) ORDER BY g.created_at DESC LIMIT 1;
  IF grant_id IS NULL THEN
   grant_id:=gen_random_uuid();
   INSERT INTO iam.obo_grants(id,application_id,subject_principal_id,organization_id,membership_id,audience_application_id,
    endpoint_id,login_consent_id,login_family_id,login_session_id,approving_session_id,subject_auth_epoch,membership_authz_epoch,graph,testing_generation,expires_at)
   VALUES(grant_id,request.application_id,request.subject_principal_id,request.organization_id,request.membership_id,approved_graph->>'_audience',
    approved_graph->>'endpoint_id',request.login_consent_id,request.login_family_id,request.login_session_id,session_id,
    request.subject_auth_epoch,request.membership_authz_epoch,approved_graph,request.testing_generation,expiry);
  END IF;
  IF NOT iam_private.obo_grant_is_live(grant_id) THEN RAISE EXCEPTION 'obo_subject_login_invalid' USING ERRCODE='P0001'; END IF;
  PERFORM iam_private.obo_audit('obo.grant.approved',grant_id,grant_id,jsonb_build_object('request_id',p_request));
  ids:=ids||grant_id;
 END LOOP;
 code_expiry:=LEAST(clock_timestamp()+interval '120 seconds',expiry);
 INSERT INTO iam.obo_authorization_codes(id,request_id,token_digest,digest_key_version,expires_at)
 VALUES((p_code->>'id')::uuid,p_request,decode(p_code->>'digest','hex'),(p_code->>'key_version')::smallint,code_expiry);
 UPDATE iam.obo_authorization_requests SET status='approved',grant_ids=ids WHERE id=p_request;
 RETURN jsonb_build_object('request_id',p_request,'status','approved','expires_at',code_expiry);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_authorization_decide(uuid,uuid,bigint,boolean,jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_token_metadata(p_token uuid) RETURNS jsonb
LANGUAGE sql SET search_path=pg_catalog,iam AS $$
 SELECT jsonb_build_object('token_id',t.id,'grant_id',g.id,'token_type','Bearer','expires_at',t.expires_at,
 'expires_in',GREATEST(0,ceil(extract(epoch FROM t.expires_at-clock_timestamp()))::bigint),
 'audience',app.app_id,'endpoint_id',t.endpoint_id,'org_id',org.org_id,'scope','obo:'||app.app_id||':'||t.endpoint_id)
 FROM iam.obo_access_tokens t JOIN iam.obo_grants g ON g.id=t.grant_id
 JOIN iam.applications app ON app.id=t.audience_application_id JOIN iam.organizations org ON org.id=g.organization_id WHERE t.id=p_token;
$$;
REVOKE ALL ON FUNCTION iam_private.obo_token_metadata(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_issue_pair(p_grant uuid,p_family uuid,p_pair jsonb) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE g iam.obo_grants%ROWTYPE; access_id uuid:=(p_pair->'access'->>'id')::uuid;
 refresh_id uuid:=(p_pair->'refresh'->>'id')::uuid; expiry timestamptz; refresh_expiry timestamptz;
 issuer_app text; audience_app text;
BEGIN
 IF NOT iam_private.obo_grant_is_live(p_grant) THEN RAISE EXCEPTION 'obo_grant_inactive' USING ERRCODE='P0001'; END IF;
 SELECT * INTO STRICT g FROM iam.obo_grants WHERE id=p_grant;
 SELECT LEAST(clock_timestamp()+make_interval(secs=>COALESCE(endpoint.ttl_seconds,300)),g.expires_at,
  family.expires_at,approving.idle_expires_at,login.idle_expires_at),family.expires_at,issuer.app_id,audience.app_id
 INTO expiry,refresh_expiry,issuer_app,audience_app FROM iam.obo_token_families family
 JOIN iam.application_obo_endpoints endpoint ON endpoint.application_id=g.audience_application_id AND endpoint.endpoint_id=g.endpoint_id
 JOIN iam.authentication_sessions approving ON approving.id=g.approving_session_id
 JOIN iam.authentication_sessions login ON login.id=g.login_session_id
 JOIN iam.applications issuer ON issuer.id=g.application_id JOIN iam.applications audience ON audience.id=g.audience_application_id
 WHERE family.id=p_family AND family.grant_id=p_grant AND family.revoked_at IS NULL;
 IF expiry IS NULL OR expiry<=clock_timestamp() THEN RAISE EXCEPTION 'obo_grant_inactive' USING ERRCODE='P0001'; END IF;
 INSERT INTO iam.obo_access_tokens(id,grant_id,family_id,issuer_application_id,audience_application_id,endpoint_id,
 chain,token_digest,digest_key_version,expires_at)
 VALUES(access_id,g.id,p_family,g.application_id,g.audience_application_id,g.endpoint_id,
 jsonb_build_array(jsonb_build_object('app_id',issuer_app,'audience',audience_app,'endpoint_id',g.endpoint_id)),
 decode(p_pair->'access'->>'digest','hex'),(p_pair->'access'->>'key_version')::smallint,expiry);
 INSERT INTO iam.obo_refresh_tokens(id,family_id,token_digest,digest_key_version,expires_at,issued_access_token_id)
 VALUES(refresh_id,p_family,decode(p_pair->'refresh'->>'digest','hex'),(p_pair->'refresh'->>'key_version')::smallint,refresh_expiry,access_id);
 RETURN iam_private.obo_token_metadata(access_id)||jsonb_build_object('refresh_token_id',refresh_id,'refresh_expires_at',refresh_expiry);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_issue_pair(uuid,uuid,jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_authorization_redeem(p_request uuid,p_code_digests jsonb,p_pairs jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE request iam.obo_authorization_requests%ROWTYPE; code iam.obo_authorization_codes%ROWTYPE;
 grant_id uuid; pair jsonb; family_id uuid; result jsonb:='[]'; position integer:=0;
BEGIN
 IF iam_private.current_application_id() IS NULL OR iam_private.current_application_id() IS DISTINCT FROM iam_private.current_principal_id() THEN
  RAISE EXCEPTION 'obo_application_required' USING ERRCODE='42501'; END IF;
 SELECT * INTO request FROM iam.obo_authorization_requests WHERE id=p_request AND application_id=iam_private.current_application_id() FOR UPDATE;
 SELECT * INTO code FROM iam.obo_authorization_codes c WHERE c.request_id=p_request
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(p_code_digests) d WHERE (d->>'key_version')::smallint=c.digest_key_version AND decode(d->>'digest','hex')=c.token_digest) FOR UPDATE;
 IF request.id IS NULL OR request.status<>'approved' OR code.id IS NULL OR code.consumed_at IS NOT NULL OR code.expires_at<=clock_timestamp()
 OR request.testing_generation<>iam_private.obo_testing_generation() THEN RAISE EXCEPTION 'obo_authorization_code_invalid' USING ERRCODE='P0001'; END IF;
 IF jsonb_typeof(p_pairs) IS DISTINCT FROM 'array' OR jsonb_array_length(p_pairs)<>cardinality(request.grant_ids) THEN
  RAISE EXCEPTION 'obo_token_pair_count_invalid' USING ERRCODE='22023'; END IF;
 FOREACH grant_id IN ARRAY request.grant_ids LOOP
  pair:=p_pairs->position; position:=position+1; family_id:=(pair->>'family_id')::uuid;
  IF NOT iam_private.obo_grant_is_live(grant_id) THEN RAISE EXCEPTION 'obo_grant_inactive' USING ERRCODE='P0001'; END IF;
  INSERT INTO iam.obo_token_families(id,grant_id,expires_at) SELECT family_id,grant_id,g.expires_at FROM iam.obo_grants g WHERE id=grant_id;
  result:=result||jsonb_build_array(iam_private.obo_issue_pair(grant_id,family_id,pair));
  PERFORM iam_private.obo_audit('obo.tokens.issued',grant_id,family_id,'{}');
 END LOOP;
 UPDATE iam.obo_authorization_codes SET consumed_at=clock_timestamp() WHERE id=code.id;
 UPDATE iam.obo_authorization_requests SET status='exchanged' WHERE id=p_request;
 RETURN jsonb_build_object('items',result);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_authorization_redeem(uuid,jsonb,jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_token_refresh(p_digests jsonb,p_pair jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE token iam.obo_refresh_tokens%ROWTYPE; family iam.obo_token_families%ROWTYPE; owner text; result jsonb;
BEGIN
 IF iam_private.current_application_id() IS NULL OR iam_private.current_application_id() IS DISTINCT FROM iam_private.current_principal_id() THEN
  RAISE EXCEPTION 'obo_application_required' USING ERRCODE='42501'; END IF;
 SELECT t.* INTO token FROM iam.obo_refresh_tokens t JOIN iam.obo_token_families f ON f.id=t.family_id
 JOIN iam.obo_grants g ON g.id=f.grant_id AND g.application_id=iam_private.current_application_id()
 WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(p_digests) d WHERE (d->>'key_version')::smallint=t.digest_key_version AND decode(d->>'digest','hex')=t.token_digest);
 IF token.id IS NULL THEN RAISE EXCEPTION 'obo_refresh_token_invalid' USING ERRCODE='P0001'; END IF;
 -- Lock family first, then reread token after any concurrent rotation commits.
 SELECT * INTO STRICT family FROM iam.obo_token_families WHERE id=token.family_id FOR UPDATE;
 SELECT * INTO STRICT token FROM iam.obo_refresh_tokens WHERE id=token.id FOR UPDATE;
 IF family.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'obo_refresh_token_invalid' USING ERRCODE='P0001'; END IF;
 IF token.consumed_at IS NOT NULL THEN
  UPDATE iam.obo_token_families SET revoked_at=clock_timestamp(),revocation_reason='refresh_reuse' WHERE id=family.id;
  PERFORM iam_private.obo_audit('obo.refresh.reuse_detected',family.grant_id,family.id,jsonb_build_object('family_id',family.id));
  -- Returning instead of raising is essential: commit the compromise marker.
  RETURN jsonb_build_object('error','obo_refresh_token_reused');
 END IF;
 IF token.expires_at<=clock_timestamp() OR family.expires_at<=clock_timestamp() OR NOT iam_private.obo_grant_is_live(family.grant_id) THEN
  RAISE EXCEPTION 'obo_refresh_token_invalid' USING ERRCODE='P0001'; END IF;
 UPDATE iam.obo_refresh_tokens SET consumed_at=clock_timestamp() WHERE id=token.id;
 result:=iam_private.obo_issue_pair(family.grant_id,family.id,p_pair);
 PERFORM iam_private.obo_audit('obo.refresh.rotated',family.grant_id,family.id,jsonb_build_object('family_id',family.id));
 RETURN jsonb_build_object('items',jsonb_build_array(result));
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_token_refresh(jsonb,jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_node_for_chain(p_graph jsonb,p_chain jsonb) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE node jsonb:=p_graph; hop jsonb; position integer:=0;
BEGIN
 FOR hop IN SELECT value FROM jsonb_array_elements(p_chain) LOOP
  IF position>0 THEN SELECT value INTO node FROM jsonb_array_elements(node->'downstream')
   WHERE value->>'audience'=hop->>'audience' AND value->>'endpoint_id'=hop->>'endpoint_id'; END IF;
  IF node IS NULL OR node->>'audience' IS DISTINCT FROM hop->>'audience' OR node->>'endpoint_id' IS DISTINCT FROM hop->>'endpoint_id' THEN RETURN NULL; END IF;
  position:=position+1;
 END LOOP;
 RETURN node;
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_node_for_chain(jsonb,jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_token_delegate(p_digests jsonb,p_audience text,p_endpoint text,p_access jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE parent iam.obo_access_tokens%ROWTYPE; g iam.obo_grants%ROWTYPE; node jsonb; child jsonb;
 expiry timestamptz; access_id uuid:=(p_access->>'id')::uuid; issuer_app text;
BEGIN
 IF iam_private.current_application_id() IS NULL OR iam_private.current_application_id() IS DISTINCT FROM iam_private.current_principal_id() THEN
  RAISE EXCEPTION 'obo_application_required' USING ERRCODE='42501'; END IF;
 SELECT t.* INTO parent FROM iam.obo_access_tokens t WHERE t.audience_application_id=iam_private.current_application_id()
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(p_digests) d WHERE (d->>'key_version')::smallint=t.digest_key_version AND decode(d->>'digest','hex')=t.token_digest);
 IF parent.id IS NULL OR NOT iam_private.obo_access_is_live(parent.id) THEN RAISE EXCEPTION 'obo_access_token_invalid' USING ERRCODE='P0001'; END IF;
 IF jsonb_array_length(parent.chain)>=10 OR EXISTS(SELECT 1 FROM jsonb_array_elements(parent.chain) link WHERE link->>'app_id'=p_audience OR link->>'audience'=p_audience) THEN
  RAISE EXCEPTION 'obo_dependency_cycle_or_depth' USING ERRCODE='P0001'; END IF;
 SELECT * INTO STRICT g FROM iam.obo_grants WHERE id=parent.grant_id;
 node:=iam_private.obo_node_for_chain(g.graph,parent.chain);
 SELECT value INTO child FROM jsonb_array_elements(node->'downstream') WHERE value->>'audience'=p_audience AND value->>'endpoint_id'=p_endpoint;
 IF child IS NULL THEN RAISE EXCEPTION 'obo_dependency_not_approved' USING ERRCODE='P0001'; END IF;
 SELECT LEAST(parent.expires_at,clock_timestamp()+make_interval(secs=>COALESCE(ttl_seconds,300))) INTO expiry
 FROM iam.application_obo_endpoints WHERE application_id=child->>'_audience' AND endpoint_id=p_endpoint AND status='active' FOR SHARE;
 SELECT app_id INTO issuer_app FROM iam.applications WHERE id=parent.audience_application_id;
 IF expiry IS NULL OR expiry<=clock_timestamp() THEN RAISE EXCEPTION 'obo_access_token_invalid' USING ERRCODE='P0001'; END IF;
 INSERT INTO iam.obo_access_tokens(id,grant_id,family_id,issuer_application_id,audience_application_id,endpoint_id,parent_token_id,
 chain,token_digest,digest_key_version,expires_at)
 VALUES(access_id,g.id,parent.family_id,parent.audience_application_id,child->>'_audience',p_endpoint,parent.id,
 parent.chain||jsonb_build_array(jsonb_build_object('app_id',issuer_app,'audience',p_audience,'endpoint_id',p_endpoint)),
 decode(p_access->>'digest','hex'),(p_access->>'key_version')::smallint,expiry);
 PERFORM iam_private.obo_audit('obo.token.delegated',g.id,access_id,jsonb_build_object('parent_token_id',parent.id,'audience',p_audience,'endpoint_id',p_endpoint));
 RETURN iam_private.obo_token_metadata(access_id);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_token_delegate(jsonb,text,text,jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_token_verify(p_digests jsonb,p_endpoint text,p_method text,p_path text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE token iam.obo_access_tokens%ROWTYPE; g iam.obo_grants%ROWTYPE; node jsonb; actor jsonb;
 authorization_snapshot jsonb; scopes text[]; audience_app text; issuer_app text; origin_app text; org_slug text;
BEGIN
 IF iam_private.current_application_id() IS NULL OR iam_private.current_application_id() IS DISTINCT FROM iam_private.current_principal_id() THEN
  RAISE EXCEPTION 'obo_application_required' USING ERRCODE='42501'; END IF;
 SELECT t.* INTO token FROM iam.obo_access_tokens t WHERE t.audience_application_id=iam_private.current_application_id() AND t.endpoint_id=p_endpoint
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(p_digests) d WHERE (d->>'key_version')::smallint=t.digest_key_version AND decode(d->>'digest','hex')=t.token_digest);
 IF token.id IS NULL OR NOT iam_private.obo_access_is_live(token.id) THEN RAISE EXCEPTION 'obo_access_token_invalid' USING ERRCODE='P0001'; END IF;
 SELECT * INTO STRICT g FROM iam.obo_grants WHERE id=token.grant_id;
 node:=iam_private.obo_node_for_chain(g.graph,token.chain);
 IF p_method IS NULL OR p_method !~ '^[A-Z][A-Z0-9!#$%&''*+.^_`|~-]{0,31}$' OR p_path IS DISTINCT FROM node->>'_path' THEN
  RAISE EXCEPTION 'obo_endpoint_request_mismatch' USING ERRCODE='P0001'; END IF;
 SELECT app_id INTO audience_app FROM iam.applications WHERE id=token.audience_application_id;
 SELECT app_id INTO issuer_app FROM iam.applications WHERE id=token.issuer_application_id;
 SELECT app_id INTO origin_app FROM iam.applications WHERE id=g.application_id;
 -- Only disclosures already consented at login and currently approved for
 -- every participant in this actual path survive; OBO adds only its action.
 SELECT ARRAY['obo:'||audience_app||':'||p_endpoint]||ARRAY(
  SELECT granted.scope FROM iam.oauth_consent_grant_scopes granted WHERE granted.consent_grant_id=g.login_consent_id
  AND granted.scope IN ('self.identity.read','self.membership.read','self.tags.read')
  AND NOT EXISTS(SELECT 1 FROM (
    SELECT link->>'app_id' AS app_id FROM jsonb_array_elements(token.chain) link
    UNION SELECT link->>'audience' FROM jsonb_array_elements(token.chain) link
   ) participant WHERE NOT EXISTS(SELECT 1 FROM iam.applications app
    JOIN iam.application_approved_scopes approved ON approved.application_id=app.id AND approved.scope=granted.scope AND approved.revoked_at IS NULL
    WHERE app.app_id=participant.app_id AND iam_private.application_scope_names(app.app_scope) @> ARRAY[granted.scope])) ORDER BY granted.scope
 ) INTO scopes;
 SELECT jsonb_build_object('type',subject.kind,'public_id',COALESCE(carbon.carbon_id,silicon.global_silicon_id)),org.org_id,
 jsonb_build_object('principal_id',subject.id,'actor_type',subject.kind,'public_id',COALESCE(carbon.carbon_id,silicon.global_silicon_id),
 'organization_id',org.id,'org_id',org.org_id,'membership_id',member.id,'membership_version',member.version,
 'authorization_epoch',member.authz_epoch,'audience',audience_app,
 'testing_environment_id',NULLIF(current_setting('iam.testing_environment_id',true),''),'scopes',to_jsonb(scopes),
 'org_role',CASE WHEN 'self.membership.read'=ANY(scopes) THEN member.org_role::text END,
 'tags',CASE WHEN 'self.tags.read'=ANY(scopes) THEN (SELECT COALESCE(jsonb_agg(jsonb_build_object('id',tag.id,'name',tag.name) ORDER BY tag.id),'[]'::jsonb)
  FROM iam.membership_tags assignment JOIN iam.organization_tags tag ON tag.id=assignment.tag_id AND tag.organization_id=assignment.organization_id
  AND tag.status='active' WHERE assignment.membership_id=member.id AND assignment.organization_id=org.id) END)
 INTO actor,org_slug,authorization_snapshot FROM iam.principals subject JOIN iam.organization_memberships member ON member.id=g.membership_id
 JOIN iam.organizations org ON org.id=g.organization_id LEFT JOIN iam.carbons carbon ON carbon.id=subject.id
 LEFT JOIN iam.silicons silicon ON silicon.id=subject.id WHERE subject.id=g.subject_principal_id;
 IF NOT 'self.identity.read'=ANY(scopes) THEN authorization_snapshot:=authorization_snapshot-ARRAY['actor_type','public_id']; END IF;
 RETURN jsonb_build_object('active',true,'token_id',token.id,'grant_id',g.id,'actor',actor,'org_id',org_slug,
 'issuer_app_id',issuer_app,'originating_app_id',origin_app,'endpoint',jsonb_build_object('app_id',audience_app,'endpoint_id',p_endpoint,'path',p_path),
 'chain',token.chain,'authorization',authorization_snapshot,'expires_at',token.expires_at);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_token_verify(jsonb,text,text,text) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_grants_list(p_user_token uuid,p_before_created_at timestamptz,p_before_id uuid,p_limit integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE result jsonb; page_limit integer:=LEAST(GREATEST(COALESCE(p_limit,10),1),10);
BEGIN
 PERFORM iam_private.obo_user_session(p_user_token);
 IF (p_before_created_at IS NULL) IS DISTINCT FROM (p_before_id IS NULL) THEN
  RAISE EXCEPTION 'obo_invalid_grants_cursor' USING ERRCODE='22023'; END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',g.id,'app_id',app.app_id,'app_name',COALESCE(NULLIF(app.app_name,''),app.app_id),'org_id',org.org_id,
 'audience',audience.app_id,'endpoint_id',g.endpoint_id,'status',CASE WHEN g.revoked_at IS NOT NULL THEN 'revoked'
 WHEN iam_private.obo_grant_is_live(g.id) THEN 'active' ELSE 'inactive' END,'created_at',g.created_at,'expires_at',g.expires_at,
 'endpoints',jsonb_build_array(iam_private.obo_public_node(g.graph))) ORDER BY g.created_at DESC,g.id DESC),'[]'::jsonb) INTO result
 FROM (SELECT * FROM iam.obo_grants WHERE subject_principal_id=iam_private.current_principal_id()
  AND (p_before_created_at IS NULL OR (created_at,id)<(p_before_created_at,p_before_id))
  ORDER BY created_at DESC,id DESC LIMIT page_limit+1) g
 JOIN iam.applications app ON app.id=g.application_id JOIN iam.applications audience ON audience.id=g.audience_application_id
 JOIN iam.organizations org ON org.id=g.organization_id;
 RETURN jsonb_build_object('items',result);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_grants_list(uuid,timestamptz,uuid,integer) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_grant_revoke(p_grant uuid,p_user_token uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 PERFORM iam_private.obo_user_session(p_user_token);
 UPDATE iam.obo_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()),revocation_reason=COALESCE(revocation_reason,'user_revoked')
 WHERE id=p_grant AND subject_principal_id=iam_private.current_principal_id();
 IF NOT FOUND THEN RAISE EXCEPTION 'obo_grant_not_found' USING ERRCODE='42501'; END IF;
 PERFORM iam_private.obo_audit('obo.grant.revoked',p_grant,p_grant,'{}');
 RETURN jsonb_build_object('id',p_grant,'status','revoked');
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_grant_revoke(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_token_result_is_live(p_token_ids uuid[]) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE token_id uuid; token iam.obo_access_tokens%ROWTYPE;
BEGIN
 IF iam_private.current_application_id() IS NULL OR iam_private.current_application_id() IS DISTINCT FROM iam_private.current_principal_id()
 OR cardinality(p_token_ids) NOT BETWEEN 1 AND 100 OR p_token_ids IS NULL THEN RETURN jsonb_build_object('active',false); END IF;
 FOREACH token_id IN ARRAY p_token_ids LOOP
  SELECT * INTO token FROM iam.obo_access_tokens WHERE id=token_id AND issuer_application_id=iam_private.current_application_id();
  IF token.id IS NULL OR NOT iam_private.obo_access_is_live(token.id) THEN RETURN jsonb_build_object('active',false); END IF;
  IF token.parent_token_id IS NULL AND NOT EXISTS(SELECT 1 FROM iam.obo_refresh_tokens
   WHERE issued_access_token_id=token.id AND consumed_at IS NULL AND expires_at>clock_timestamp()) THEN RETURN jsonb_build_object('active',false); END IF;
 END LOOP;
 RETURN jsonb_build_object('active',true);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_token_result_is_live(uuid[]) FROM PUBLIC;

-- Disconnect is permanent for OBO authority even if ordinary login consent is
-- later reactivated in place. Scope approvals and application/member epochs
-- are separately pinned in each grant and graph.
CREATE FUNCTION iam_private.revoke_obo_on_login_consent_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
BEGIN
 UPDATE iam.obo_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()),revocation_reason='login_consent_revoked'
 WHERE login_consent_id=NEW.id AND revoked_at IS NULL AND (NEW.status<>'active' OR NOT membership_id=ANY(NEW.selected_membership_ids));
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam_private.revoke_obo_on_login_consent_change() FROM PUBLIC;
CREATE TRIGGER oauth_consent_grants_revoke_obo AFTER UPDATE OF status,selected_membership_ids ON iam.oauth_consent_grants
FOR EACH ROW EXECUTE FUNCTION iam_private.revoke_obo_on_login_consent_change();

CREATE OR REPLACE FUNCTION iam_private.application_login_scope_policy(p_app text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE snapshot jsonb;
BEGIN
 PERFORM id FROM iam.applications WHERE id=p_app FOR SHARE;
 SELECT jsonb_build_object('scope_version',app.version,'consent_required',NOT(org.trusted_org AND org.skip_application_consent),
 'scopes',COALESCE((SELECT jsonb_agg(jsonb_build_object('scope',approved.scope,'description',catalog.description,'critical',catalog.critical) ORDER BY approved.scope)
 FROM iam.application_approved_scopes approved JOIN iam_private.application_scope_catalog(NULL) catalog ON catalog.scope=approved.scope
 WHERE approved.application_id=app.id AND approved.revoked_at IS NULL AND approved.scope NOT LIKE 'obo:%'),'[]'::jsonb))
 INTO snapshot FROM iam.applications app JOIN iam.organizations org ON org.id=app.organization_id
 WHERE app.id=p_app AND app.review_status='verified' AND app.deleted_at IS NULL;
 RETURN snapshot;
END $$;
REVOKE ALL ON FUNCTION iam_private.application_login_scope_policy(text) FROM PUBLIC;

-- Keep cleanup inside the existing OBO worker phase and its configured token
-- metadata retention. Refresh reuse markers survive for the family's entire
-- lifetime; per-environment and retired-application erasure follow these FKs.
CREATE INDEX obo_authorization_requests_retention_idx ON iam.obo_authorization_requests(expires_at);
CREATE INDEX obo_grants_retention_idx ON iam.obo_grants(expires_at);
CREATE INDEX obo_access_tokens_retention_idx ON iam.obo_access_tokens(expires_at);
ALTER FUNCTION iam_private.run_worker_retention_maintenance(text,integer,integer,integer,integer,integer,integer,integer)
 RENAME TO run_worker_retention_maintenance_before_obo_tokens;
ALTER FUNCTION iam_private.run_worker_retention_maintenance_before_obo_tokens(text,integer,integer,integer,integer,integer,integer,integer) SECURITY INVOKER;
REVOKE ALL ON FUNCTION iam_private.run_worker_retention_maintenance_before_obo_tokens(text,integer,integer,integer,integer,integer,integer,integer) FROM PUBLIC;
DO $$ BEGIN
 IF to_regrole('silicon_iam_worker') IS NOT NULL THEN
  REVOKE ALL ON FUNCTION iam_private.run_worker_retention_maintenance_before_obo_tokens(text,integer,integer,integer,integer,integer,integer,integer) FROM silicon_iam_worker;
 END IF;
END $$;
CREATE FUNCTION iam_private.run_worker_retention_maintenance(
 p_phase text,p_login_history_days integer,p_ephemeral_security_days integer,p_token_metadata_days integer,
 p_compromised_refresh_days integer,p_webhook_attempt_days integer,p_audit_event_days integer,p_limit integer
) RETURNS TABLE(completed_phase text,affected_rows bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE prior bigint; removed bigint:=0; batch bigint; remaining integer; cutoff timestamptz;
BEGIN
 SELECT result.affected_rows INTO STRICT prior FROM iam_private.run_worker_retention_maintenance_before_obo_tokens(
 p_phase,p_login_history_days,p_ephemeral_security_days,p_token_metadata_days,p_compromised_refresh_days,p_webhook_attempt_days,p_audit_event_days,p_limit) result;
 IF p_phase='obo_proofs' THEN
  remaining:=p_limit-LEAST(p_limit::bigint,prior)::integer;
  cutoff:=clock_timestamp()-make_interval(days=>GREATEST(p_token_metadata_days,p_compromised_refresh_days));
  WITH expired AS (SELECT id FROM iam.obo_authorization_requests WHERE expires_at<cutoff ORDER BY expires_at LIMIT remaining FOR UPDATE SKIP LOCKED)
  DELETE FROM iam.obo_authorization_requests request USING expired WHERE request.id=expired.id;
  GET DIAGNOSTICS batch=ROW_COUNT; removed:=removed+batch; remaining:=remaining-batch::integer;
  WITH expired AS (SELECT id FROM iam.obo_grants WHERE expires_at<cutoff ORDER BY expires_at LIMIT remaining FOR UPDATE SKIP LOCKED)
  DELETE FROM iam.obo_grants grant_row USING expired WHERE grant_row.id=expired.id;
  GET DIAGNOSTICS batch=ROW_COUNT; removed:=removed+batch; remaining:=remaining-batch::integer;
  -- Do not erase a root access row while its refresh reuse marker is needed.
  WITH expired AS (SELECT token.id FROM iam.obo_access_tokens token WHERE token.expires_at<cutoff
   AND NOT EXISTS(SELECT 1 FROM iam.obo_refresh_tokens refresh WHERE refresh.issued_access_token_id=token.id AND refresh.expires_at>=cutoff)
   ORDER BY token.expires_at LIMIT remaining FOR UPDATE OF token SKIP LOCKED)
  DELETE FROM iam.obo_access_tokens token USING expired WHERE token.id=expired.id;
  GET DIAGNOSTICS batch=ROW_COUNT; removed:=removed+batch;
 END IF;
 RETURN QUERY SELECT p_phase,prior+removed;
END $$;
REVOKE ALL ON FUNCTION iam_private.run_worker_retention_maintenance(text,integer,integer,integer,integer,integer,integer,integer) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_graph_nodes(p_graph jsonb) RETURNS SETOF jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 WITH RECURSIVE nodes(value) AS (
  SELECT p_graph UNION ALL SELECT child.value FROM nodes
  CROSS JOIN LATERAL jsonb_array_elements(nodes.value->'downstream') child
 ) SELECT value FROM nodes;
$$;
REVOKE ALL ON FUNCTION iam_private.obo_graph_nodes(jsonb) FROM PUBLIC;

-- Revocation is irreversible even if the same declaration/account is later
-- restored. New dependencies leave the already approved subset unaffected.
CREATE FUNCTION iam_private.revoke_obo_on_endpoint_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE allowed jsonb; removed boolean;
BEGIN
 IF TG_OP='DELETE' THEN allowed:='[]'; removed:=true;
 ELSE allowed:=NEW.downstream; removed:=NEW.status<>'active' OR NEW.critical IS DISTINCT FROM OLD.critical;
 END IF;
 UPDATE iam.obo_grants g SET revoked_at=clock_timestamp(),revocation_reason='endpoint_authority_removed'
 WHERE g.revoked_at IS NULL AND EXISTS(SELECT 1 FROM iam_private.obo_graph_nodes(g.graph) node
 WHERE node->>'_audience'=OLD.application_id AND node->>'endpoint_id'=OLD.endpoint_id
 AND (removed OR EXISTS(SELECT 1 FROM jsonb_array_elements(node->'downstream') child
  WHERE NOT allowed @> jsonb_build_array(jsonb_build_object('audience',child->>'audience','endpoint_id',child->>'endpoint_id')))));
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam_private.revoke_obo_on_endpoint_change() FROM PUBLIC;
CREATE TRIGGER application_obo_endpoints_revoke_token_grants AFTER UPDATE OF downstream,status,critical OR DELETE ON iam.application_obo_endpoints
FOR EACH ROW EXECUTE FUNCTION iam_private.revoke_obo_on_endpoint_change();

CREATE FUNCTION iam_private.revoke_obo_on_authority_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 IF TG_TABLE_NAME='applications' THEN
  IF NEW.review_status<>'verified' OR NEW.deleted_at IS NOT NULL THEN
   UPDATE iam.obo_grants g SET revoked_at=clock_timestamp(),revocation_reason='application_unavailable'
   WHERE g.revoked_at IS NULL AND EXISTS(SELECT 1 FROM iam_private.obo_graph_nodes(g.graph) node
    WHERE node->>'_issuer'=NEW.id OR node->>'_audience'=NEW.id);
  END IF;
 ELSIF TG_TABLE_NAME='principals' THEN
  IF NEW.status<>'active' OR NEW.auth_epoch IS DISTINCT FROM OLD.auth_epoch THEN
   UPDATE iam.obo_grants g SET revoked_at=clock_timestamp(),revocation_reason='principal_authority_changed'
   WHERE g.revoked_at IS NULL AND (g.subject_principal_id=NEW.id OR EXISTS(SELECT 1 FROM iam_private.obo_graph_nodes(g.graph) node
    WHERE node->>'_issuer'=NEW.id OR node->>'_audience'=NEW.id));
  END IF;
 ELSIF TG_TABLE_NAME='organization_memberships' THEN
  IF NEW.status<>'active' OR NEW.authz_epoch IS DISTINCT FROM OLD.authz_epoch THEN
   UPDATE iam.obo_grants SET revoked_at=clock_timestamp(),revocation_reason='membership_authority_changed'
   WHERE revoked_at IS NULL AND membership_id=NEW.id;
  END IF;
 ELSIF TG_TABLE_NAME='authentication_sessions' THEN
  IF NEW.status<>'active' THEN
   UPDATE iam.obo_grants SET revoked_at=clock_timestamp(),revocation_reason='session_revoked'
   WHERE revoked_at IS NULL AND (login_session_id=NEW.id OR approving_session_id=NEW.id);
  END IF;
 ELSIF TG_TABLE_NAME='refresh_token_families' THEN
  IF NEW.status<>'active' THEN
   UPDATE iam.obo_grants SET revoked_at=clock_timestamp(),revocation_reason='login_family_revoked'
   WHERE revoked_at IS NULL AND login_family_id=NEW.id;
  END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam_private.revoke_obo_on_authority_change() FROM PUBLIC;
CREATE TRIGGER applications_revoke_obo_token_grants AFTER UPDATE OF review_status,deleted_at ON iam.applications
FOR EACH ROW EXECUTE FUNCTION iam_private.revoke_obo_on_authority_change();
CREATE TRIGGER principals_revoke_obo_token_grants AFTER UPDATE OF status,auth_epoch ON iam.principals
FOR EACH ROW EXECUTE FUNCTION iam_private.revoke_obo_on_authority_change();
CREATE TRIGGER memberships_revoke_obo_token_grants AFTER UPDATE OF status,authz_epoch ON iam.organization_memberships
FOR EACH ROW EXECUTE FUNCTION iam_private.revoke_obo_on_authority_change();
CREATE TRIGGER sessions_revoke_obo_token_grants AFTER UPDATE OF status ON iam.authentication_sessions
FOR EACH ROW EXECUTE FUNCTION iam_private.revoke_obo_on_authority_change();
CREATE TRIGGER refresh_families_revoke_obo_token_grants AFTER UPDATE OF status ON iam.refresh_token_families
FOR EACH ROW EXECUTE FUNCTION iam_private.revoke_obo_on_authority_change();
