-- Durable endpoint consent. Session identifiers remain audit provenance only.
-- Existing narrower, session-bound approvals must be explicitly reapproved.
ALTER TABLE iam.application_obo_endpoints
 ADD COLUMN name text NOT NULL DEFAULT '',
 ADD COLUMN description text NOT NULL DEFAULT '',
 ADD COLUMN note_to_user text,
 ADD COLUMN additional_warnings jsonb NOT NULL DEFAULT '[]'::jsonb,
 ADD CONSTRAINT obo_endpoint_disclosures_valid CHECK(length(name)<=160 AND length(description)<=4000
  AND (note_to_user IS NULL OR length(note_to_user)<=2000)
  AND jsonb_typeof(additional_warnings)='array' AND jsonb_array_length(additional_warnings)<=6
  AND additional_warnings <@ '["uses_credits","incurs_cost","stores_data","shares_data","deletes_data","external_service"]'::jsonb);
UPDATE iam.obo_grants SET revoked_at=clock_timestamp(),revocation_reason='durable_graph_consent_required' WHERE revoked_at IS NULL;
DROP TRIGGER oauth_consent_grants_revoke_obo ON iam.oauth_consent_grants;
DROP TRIGGER sessions_revoke_obo_token_grants ON iam.authentication_sessions;
DROP TRIGGER refresh_families_revoke_obo_token_grants ON iam.refresh_token_families;
-- Deleting expired login/session records must not delete durable permissions.
DO $$ DECLARE item record; BEGIN
 FOR item IN SELECT c.conname,a.attname FROM pg_constraint c JOIN pg_attribute a
  ON a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey)
  WHERE c.conrelid='iam.obo_grants'::regclass AND c.contype='f'
  AND a.attname IN ('login_consent_id','login_family_id','login_session_id','approving_session_id') LOOP
  EXECUTE format('ALTER TABLE iam.obo_grants DROP CONSTRAINT %I',item.conname);
 END LOOP;
END $$;
ALTER TABLE iam.obo_grants
 ALTER COLUMN login_consent_id DROP NOT NULL, ALTER COLUMN login_family_id DROP NOT NULL,
 ALTER COLUMN login_session_id DROP NOT NULL, ALTER COLUMN approving_session_id DROP NOT NULL,
 ADD FOREIGN KEY(login_consent_id) REFERENCES iam.oauth_consent_grants(id) ON DELETE SET NULL,
 ADD FOREIGN KEY(login_family_id) REFERENCES iam.refresh_token_families(id) ON DELETE SET NULL,
 ADD FOREIGN KEY(login_session_id) REFERENCES iam.authentication_sessions(id) ON DELETE SET NULL,
 ADD FOREIGN KEY(approving_session_id) REFERENCES iam.authentication_sessions(id) ON DELETE SET NULL;

CREATE OR REPLACE FUNCTION iam_private.obo_graph_nodes(p_graph jsonb) RETURNS SETOF jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 WITH RECURSIVE nodes(node) AS (
  SELECT p_graph UNION ALL
  SELECT child FROM nodes CROSS JOIN LATERAL jsonb_array_elements(COALESCE(node->'downstream','[]'::jsonb)) child
 ) SELECT node FROM nodes;
$$;
REVOKE ALL ON FUNCTION iam_private.obo_graph_nodes(jsonb) FROM PUBLIC;


CREATE OR REPLACE FUNCTION iam_private.obo_graph_node(p_issuer text,p_audience text,p_endpoint text,p_subject text,p_org uuid,p_seen text[])
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE issuer iam.applications%ROWTYPE; audience iam.applications%ROWTYPE;
 endpoint iam.application_obo_endpoints%ROWTYPE; approval iam.application_approved_scopes%ROWTYPE;
 issuer_epoch bigint; audience_epoch bigint; dependency jsonb; children jsonb:='[]';
BEGIN
 IF cardinality(p_seen)>10 OR p_audience=ANY(p_seen) THEN
  RAISE EXCEPTION 'obo_dependency_cycle_or_depth' USING ERRCODE='P0001'; END IF;
 SELECT * INTO issuer FROM iam.applications WHERE app_id=p_issuer FOR SHARE;
 SELECT * INTO audience FROM iam.applications WHERE app_id=p_audience FOR SHARE;
 IF issuer.id IS NULL OR audience.id IS NULL OR issuer.deleted_at IS NOT NULL OR audience.deleted_at IS NOT NULL
 OR issuer.review_status<>'verified' OR audience.review_status<>'verified' THEN
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
  'caller_app_id',p_issuer,'obo_id','['||audience.app_id||':obo:'||p_endpoint||']','name',COALESCE(NULLIF(endpoint.name,''),p_endpoint),
  'description',COALESCE(NULLIF(endpoint.description,''),p_endpoint||' ('||endpoint.path||')'),
  'note_to_user',endpoint.note_to_user,'additional_warnings',endpoint.additional_warnings,'critical',endpoint.critical,'downstream',children,
  '_issuer',issuer.id,'_audience',audience.id,'_issuer_epoch',issuer_epoch,'_audience_epoch',audience_epoch,
  '_approval',approval.approved_at,'_path',endpoint.path,'_metadata',endpoint.metadata_definition);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_graph_node(text,text,text,text,uuid,text[]) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.obo_public_node(p_node jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,iam_private AS $$
 SELECT jsonb_build_object('audience',p_node->'audience','app_name',p_node->'app_name',
 'endpoint_id',p_node->'endpoint_id','obo_id',p_node->'obo_id','name',p_node->'name',
 'note_to_user',p_node->'note_to_user','additional_warnings',COALESCE(p_node->'additional_warnings','[]'::jsonb),'description',p_node->'description','critical',p_node->'critical',
 'downstream',COALESCE((SELECT jsonb_agg(iam_private.obo_public_node(value)) FROM jsonb_array_elements(p_node->'downstream')),'[]'::jsonb));
$$;
REVOKE ALL ON FUNCTION iam_private.obo_public_node(jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.obo_bind_contexts(p_node jsonb,p_contexts jsonb,p_default_token uuid,p_default_org uuid) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE selected jsonb; token iam.access_tokens%ROWTYPE; member iam.organization_memberships%ROWTYPE;
 children jsonb:='[]'; child jsonb; selected_org uuid;
BEGIN
 SELECT value INTO selected FROM jsonb_array_elements(p_contexts) WHERE value->>'app_id'=p_node->>'audience';
 SELECT t.* INTO token FROM iam.access_tokens t
 JOIN iam.principals subject ON subject.id=t.subject_principal_id AND subject.status='active' AND subject.auth_epoch=t.subject_auth_epoch
 JOIN iam.authentication_sessions session ON session.id=t.authentication_session_id AND session.subject_principal_id=subject.id
  AND session.status='active' AND session.subject_auth_epoch=subject.auth_epoch
  AND session.idle_expires_at>clock_timestamp() AND session.absolute_expires_at>clock_timestamp()
 WHERE t.id=COALESCE((selected->>'token_id')::uuid,p_default_token)
  AND (selected IS NULL OR EXISTS(SELECT 1 FROM jsonb_array_elements(selected->'digests') d
   WHERE (d->>'key_version')::smallint=t.digest_key_version AND decode(d->>'digest','hex')=t.token_digest))
  AND t.client_application_id IS NULL
  AND t.token_class IN ('carbon_access','silicon_access') AND t.audience='silicon-iam'
  AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp()
  AND EXISTS(SELECT 1 FROM iam.access_token_scopes WHERE access_token_id=t.id AND scope='iam.self')
 FOR SHARE OF t,subject,session;
 IF token.id IS NULL THEN RAISE EXCEPTION 'obo_context_account_invalid' USING ERRCODE='P0001'; END IF;
 SELECT m.* INTO member FROM iam.organization_memberships m JOIN iam.organizations org ON org.id=m.organization_id AND org.status='active'
 WHERE m.principal_id=token.subject_principal_id AND m.status='active'
 AND ((selected IS NULL AND org.id=p_default_org) OR (selected IS NOT NULL AND org.org_id=selected->>'org_id'))
 FOR SHARE OF m,org;
 IF member.id IS NULL OR NOT iam_private.application_allows_subject(p_node->>'_audience',token.subject_principal_id,member.organization_id) THEN
  RAISE EXCEPTION 'obo_context_membership_invalid' USING ERRCODE='P0001'; END IF;
 FOR child IN SELECT value FROM jsonb_array_elements(p_node->'downstream') LOOP
  children:=children||jsonb_build_array(iam_private.obo_bind_contexts(child,p_contexts,p_default_token,p_default_org));
 END LOOP;
 RETURN p_node||jsonb_build_object('_subject',token.subject_principal_id,'_organization_id',member.organization_id,
  '_membership_id',member.id,'_subject_auth_epoch',token.subject_auth_epoch,'_membership_epoch',member.authz_epoch,'downstream',children);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_bind_contexts(jsonb,jsonb,uuid,uuid) FROM PUBLIC;


CREATE OR REPLACE FUNCTION iam_private.obo_graph_is_current(p_node jsonb,p_subject text,p_org uuid)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE endpoint iam.application_obo_endpoints%ROWTYPE; child jsonb;
 selected_subject text:=COALESCE(p_node->>'_subject',p_subject);
 selected_org uuid:=COALESCE((p_node->>'_organization_id')::uuid,p_org);
BEGIN
 PERFORM 1 FROM iam.applications issuer JOIN iam.principals ip ON ip.id=issuer.id
 JOIN iam.applications audience ON audience.id=p_node->>'_audience'
 JOIN iam.principals ap ON ap.id=audience.id
 JOIN iam.application_approved_scopes approved ON approved.application_id=issuer.id
  AND approved.scope='obo:'||audience.app_id||':'||(p_node->>'endpoint_id')
  AND approved.approved_at=(p_node->>'_approval')::timestamptz AND approved.revoked_at IS NULL
 WHERE issuer.id=p_node->>'_issuer' AND ip.status='active' AND ap.status='active'
  AND iam_private.application_allows_subject(audience.id,selected_subject,selected_org)
  AND iam_private.application_scope_names(issuer.app_scope) @> ARRAY[approved.scope]
  AND (NOT (p_node->>'critical')::boolean OR issuer.visibility='private' OR approved.approval_basis='provider_approval')
 FOR SHARE OF issuer,ip,audience,ap,approved;
 IF NOT FOUND THEN RETURN false; END IF;
 IF p_node ? '_membership_id' THEN
  PERFORM 1 FROM iam.organization_memberships m JOIN iam.organizations org ON org.id=m.organization_id AND org.status='active'
  JOIN iam.principals p ON p.id=m.principal_id AND p.status='active'
  WHERE m.id=(p_node->>'_membership_id')::uuid AND m.principal_id=selected_subject AND m.organization_id=selected_org
   AND m.status='active' FOR SHARE OF m,org,p;
  IF NOT FOUND THEN RETURN false; END IF;
 END IF;
 SELECT * INTO endpoint FROM iam.application_obo_endpoints WHERE application_id=p_node->>'_audience'
 AND endpoint_id=p_node->>'endpoint_id' AND status='active' AND path=p_node->>'_path'
 AND critical=(p_node->>'critical')::boolean FOR SHARE;
 IF NOT FOUND OR endpoint.metadata_definition IS DISTINCT FROM p_node->'_metadata'
 OR endpoint.additional_warnings IS DISTINCT FROM COALESCE(p_node->'additional_warnings','[]'::jsonb) THEN RETURN false; END IF;
 FOR child IN SELECT value FROM jsonb_array_elements(p_node->'downstream') LOOP
  IF NOT endpoint.downstream @> jsonb_build_array(jsonb_build_object('audience',child->>'audience','endpoint_id',child->>'endpoint_id'))
  OR NOT iam_private.obo_graph_is_current(child,p_subject,p_org) THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_graph_is_current(jsonb,text,uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.obo_grant_is_live(p_grant uuid) RETURNS boolean
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
 AND member.principal_id=subject.id AND member.status='active'
 JOIN iam.organizations org ON org.id=member.organization_id AND org.status='active'

 WHERE subject.id=g.subject_principal_id AND subject.status='active'
 FOR SHARE OF subject,member,org;
 IF NOT FOUND THEN RETURN false; END IF;
 IF NOT iam_private.obo_graph_is_current(g.graph,g.subject_principal_id,g.organization_id) THEN RETURN false; END IF;
 PERFORM 1 FROM iam.obo_grants WHERE id=g.id AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_grant_is_live(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.obo_request_detail(p_request uuid) RETURNS jsonb
LANGUAGE sql SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT jsonb_build_object('id',request.id,'app_id',app.app_id,'app_name',COALESCE(NULLIF(app.app_name,''),app.app_id),
 'actor',jsonb_build_object('type',subject.kind,'public_id',COALESCE(carbon.carbon_id,silicon.global_silicon_id)),
 'org_id',org.org_id,'status',CASE WHEN request.expires_at<=clock_timestamp() AND request.status='pending' THEN 'expired' ELSE request.status END,
 'providers',(SELECT COALESCE(jsonb_agg(provider),'[]'::jsonb) FROM (
  SELECT DISTINCT jsonb_build_object('app_id',node->>'audience','app_name',node->>'app_name','org_id',org.org_id,
   'actor',jsonb_build_object('type',subject.kind,'public_id',COALESCE(carbon.carbon_id,silicon.global_silicon_id))) AS provider
  FROM jsonb_array_elements(request.graphs) root CROSS JOIN LATERAL iam_private.obo_graph_nodes(root) node
 ) providers),'management_url','/obo-grants?app='||app.app_id,
 'version',request.version,'expires_at',request.expires_at,'endpoints',(SELECT jsonb_agg(iam_private.obo_public_node(value)) FROM jsonb_array_elements(request.graphs)))
 FROM iam.obo_authorization_requests request JOIN iam.applications app ON app.id=request.application_id
 JOIN iam.principals subject ON subject.id=request.subject_principal_id
 JOIN iam.organizations org ON org.id=request.organization_id
 LEFT JOIN iam.carbons carbon ON carbon.id=subject.id LEFT JOIN iam.silicons silicon ON silicon.id=subject.id
 WHERE request.id=p_request;
$$;
REVOKE ALL ON FUNCTION iam_private.obo_request_detail(uuid) FROM PUBLIC;

DROP FUNCTION iam_private.obo_authorization_decide(uuid,uuid,bigint,boolean,jsonb);
CREATE OR REPLACE FUNCTION iam_private.obo_authorization_decide(p_request uuid,p_user_token uuid,p_version bigint,p_approve boolean,p_code jsonb,p_contexts jsonb DEFAULT '[]'::jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE request iam.obo_authorization_requests%ROWTYPE; session_id uuid; approved_graph jsonb; current_graph jsonb;
 app_id text; grant_id uuid; ids uuid[]:='{}'; expiry timestamptz; code_expiry timestamptz;
BEGIN
 session_id:=iam_private.obo_user_session(p_user_token);
 IF jsonb_typeof(p_contexts) IS DISTINCT FROM 'array' OR jsonb_array_length(p_contexts)>100
 OR (SELECT count(DISTINCT value->>'app_id') FROM jsonb_array_elements(p_contexts))<>jsonb_array_length(p_contexts) THEN
  RAISE EXCEPTION 'obo_invalid_contexts' USING ERRCODE='22023'; END IF;
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
 expiry:='9999-12-31T23:59:59Z'::timestamptz;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_contexts) chosen WHERE NOT EXISTS(
  SELECT 1 FROM jsonb_array_elements(request.graphs) root CROSS JOIN LATERAL iam_private.obo_graph_nodes(root) node
  WHERE node->>'audience'=chosen->>'app_id')) THEN RAISE EXCEPTION 'obo_invalid_contexts' USING ERRCODE='22023'; END IF;
 FOR approved_graph IN SELECT value FROM jsonb_array_elements(request.graphs) LOOP
  current_graph:=iam_private.obo_graph_node(app_id,approved_graph->>'audience',approved_graph->>'endpoint_id',request.subject_principal_id,request.organization_id,ARRAY[app_id]);
  IF current_graph IS DISTINCT FROM approved_graph THEN RAISE EXCEPTION 'obo_consent_changed' USING ERRCODE='P0001'; END IF;
  approved_graph:=iam_private.obo_bind_contexts(approved_graph,p_contexts,p_user_token,request.organization_id);
  approved_graph:=approved_graph||jsonb_build_object('_disclosure_scopes',COALESCE((SELECT jsonb_agg(scope)
   FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id=request.login_consent_id
   AND scope IN ('self.identity.read','self.membership.read','self.tags.read')),'[]'::jsonb));
  SELECT g.id INTO grant_id FROM iam.obo_grants g WHERE g.application_id=request.application_id
   AND g.subject_principal_id=request.subject_principal_id AND g.organization_id=request.organization_id
   AND g.audience_application_id=approved_graph->>'_audience' AND g.endpoint_id=approved_graph->>'endpoint_id'
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
REVOKE ALL ON FUNCTION iam_private.obo_authorization_decide(uuid,uuid,bigint,boolean,jsonb,jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.obo_issue_pair(p_grant uuid,p_family uuid,p_pair jsonb) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE g iam.obo_grants%ROWTYPE; access_id uuid:=(p_pair->'access'->>'id')::uuid;
 refresh_id uuid:=(p_pair->'refresh'->>'id')::uuid; expiry timestamptz; refresh_expiry timestamptz;
 issuer_app text; audience_app text;
BEGIN
 IF NOT iam_private.obo_grant_is_live(p_grant) THEN RAISE EXCEPTION 'obo_grant_inactive' USING ERRCODE='P0001'; END IF;
 SELECT * INTO STRICT g FROM iam.obo_grants WHERE id=p_grant;
 SELECT LEAST(clock_timestamp()+make_interval(secs=>COALESCE((SELECT min(e.ttl_seconds) FROM iam_private.obo_graph_nodes(g.graph) n JOIN iam.application_obo_endpoints e ON e.application_id=n->>'_audience' AND e.endpoint_id=n->>'endpoint_id'),300)),g.expires_at,
  family.expires_at),family.expires_at,issuer.app_id,audience.app_id
 INTO expiry,refresh_expiry,issuer_app,audience_app FROM iam.obo_token_families family
 JOIN iam.application_obo_endpoints endpoint ON endpoint.application_id=g.audience_application_id AND endpoint.endpoint_id=g.endpoint_id
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

CREATE OR REPLACE FUNCTION iam_private.obo_token_verify(p_digests jsonb,p_endpoint text,p_method text,p_path text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE token iam.obo_access_tokens%ROWTYPE; g iam.obo_grants%ROWTYPE; node jsonb; actor jsonb;
 authorization_snapshot jsonb; scopes text[]; verified_chain jsonb; audience_app text; issuer_app text; origin_app text; org_slug text;
BEGIN
 IF iam_private.current_application_id() IS NULL OR iam_private.current_application_id() IS DISTINCT FROM iam_private.current_principal_id() THEN
  RAISE EXCEPTION 'obo_application_required' USING ERRCODE='42501'; END IF;
 SELECT t.* INTO token FROM iam.obo_access_tokens t WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(p_digests) d WHERE (d->>'key_version')::smallint=t.digest_key_version AND decode(d->>'digest','hex')=t.token_digest);
 IF token.id IS NULL OR NOT iam_private.obo_access_is_live(token.id) THEN RAISE EXCEPTION 'obo_access_token_invalid' USING ERRCODE='P0001'; END IF;
 SELECT * INTO STRICT g FROM iam.obo_grants WHERE id=token.grant_id;
 WITH RECURSIVE routes(item,route) AS (
 SELECT g.graph,jsonb_build_array(jsonb_build_object('app_id',g.graph->>'caller_app_id','audience',g.graph->>'audience','endpoint_id',g.graph->>'endpoint_id'))
 UNION ALL SELECT child,route||jsonb_build_array(jsonb_build_object('app_id',child->>'caller_app_id','audience',child->>'audience','endpoint_id',child->>'endpoint_id'))
 FROM routes CROSS JOIN LATERAL jsonb_array_elements(item->'downstream') child
 ) SELECT item,route INTO node,verified_chain FROM routes
 WHERE item->>'_audience'=iam_private.current_application_id() AND item->>'endpoint_id'=p_endpoint LIMIT 1;
 IF node IS NULL THEN RAISE EXCEPTION 'obo_access_token_invalid' USING ERRCODE='P0001'; END IF;
 IF p_method IS NULL OR p_method !~ '^[A-Z][A-Z0-9!#$%&''*+.^_`|~-]{0,31}$' OR p_path IS DISTINCT FROM node->>'_path' THEN
  RAISE EXCEPTION 'obo_endpoint_request_mismatch' USING ERRCODE='P0001'; END IF;
 SELECT app_id INTO audience_app FROM iam.applications WHERE id=node->>'_audience';
 SELECT app_id INTO issuer_app FROM iam.applications WHERE id=node->>'_issuer';
 SELECT app_id INTO origin_app FROM iam.applications WHERE id=g.application_id;
 -- Only disclosures already consented at login and currently approved for
 -- every participant in this actual path survive; OBO adds only its action.
 SELECT ARRAY['obo:'||audience_app||':'||p_endpoint]||ARRAY(
  SELECT granted.scope FROM jsonb_array_elements_text(COALESCE(g.graph->'_disclosure_scopes','[]'::jsonb)) granted(scope) WHERE COALESCE(node->>'_subject',g.subject_principal_id)=g.subject_principal_id
  AND granted.scope IN ('self.identity.read','self.membership.read','self.tags.read')
  AND NOT EXISTS(SELECT 1 FROM (
    SELECT link->>'app_id' AS app_id FROM jsonb_array_elements(verified_chain) link
    UNION SELECT link->>'audience' FROM jsonb_array_elements(verified_chain) link
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
 INTO actor,org_slug,authorization_snapshot FROM iam.principals subject JOIN iam.organization_memberships member ON member.id=COALESCE((node->>'_membership_id')::uuid,g.membership_id)
 JOIN iam.organizations org ON org.id=COALESCE((node->>'_organization_id')::uuid,g.organization_id) LEFT JOIN iam.carbons carbon ON carbon.id=subject.id
 LEFT JOIN iam.silicons silicon ON silicon.id=subject.id WHERE subject.id=COALESCE(node->>'_subject',g.subject_principal_id);
 IF NOT 'self.identity.read'=ANY(scopes) THEN authorization_snapshot:=authorization_snapshot-ARRAY['actor_type','public_id']; END IF;
 RETURN jsonb_build_object('active',true,'token_id',token.id,'grant_id',g.id,'actor',actor,'org_id',org_slug,
 'issuer_app_id',issuer_app,'originating_app_id',origin_app,'endpoint',jsonb_build_object('app_id',audience_app,'endpoint_id',p_endpoint,'obo_id','['||audience_app||':obo:'||p_endpoint||']','path',p_path),
 'chain',verified_chain,'authorization',authorization_snapshot,'expires_at',token.expires_at);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_token_verify(jsonb,text,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.obo_token_delegate(p_digests jsonb,p_audience text,p_endpoint text,p_access jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE token iam.obo_access_tokens%ROWTYPE; g iam.obo_grants%ROWTYPE;
BEGIN
 IF iam_private.current_application_id() IS NULL OR iam_private.current_application_id() IS DISTINCT FROM iam_private.current_principal_id() THEN
  RAISE EXCEPTION 'obo_application_required' USING ERRCODE='42501'; END IF;
 SELECT t.* INTO token FROM iam.obo_access_tokens t WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(p_digests) d
  WHERE (d->>'key_version')::smallint=t.digest_key_version AND decode(d->>'digest','hex')=t.token_digest);
 IF token.id IS NULL OR NOT iam_private.obo_access_is_live(token.id) THEN RAISE EXCEPTION 'obo_access_token_invalid' USING ERRCODE='P0001'; END IF;
 SELECT * INTO STRICT g FROM iam.obo_grants WHERE id=token.grant_id;
 IF NOT EXISTS(SELECT 1 FROM iam_private.obo_graph_nodes(g.graph) parent CROSS JOIN LATERAL jsonb_array_elements(parent->'downstream') child
  WHERE parent->>'_audience'=iam_private.current_application_id() AND child->>'audience'=p_audience AND child->>'endpoint_id'=p_endpoint) THEN
  RAISE EXCEPTION 'obo_dependency_not_approved' USING ERRCODE='P0001'; END IF;
 RETURN iam_private.obo_token_metadata(token.id);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_token_delegate(jsonb,text,text,jsonb) FROM PUBLIC;


DROP FUNCTION iam_private.obo_grants_list(uuid,timestamptz,uuid,integer);
CREATE FUNCTION iam_private.obo_grants_list(p_user_token uuid,p_before_created_at timestamptz,p_before_id uuid,p_limit integer,p_app_id text DEFAULT NULL) RETURNS jsonb
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
 FROM (SELECT * FROM iam.obo_grants WHERE (subject_principal_id=iam_private.current_principal_id() OR EXISTS(SELECT 1 FROM iam_private.obo_graph_nodes(graph) node WHERE node->>'_subject'=iam_private.current_principal_id()))
  AND (p_app_id IS NULL OR application_id IN (SELECT id FROM iam.applications WHERE app_id=p_app_id))
  AND (p_before_created_at IS NULL OR (created_at,id)<(p_before_created_at,p_before_id))
  ORDER BY created_at DESC,id DESC LIMIT page_limit+1) g
 JOIN iam.applications app ON app.id=g.application_id JOIN iam.applications audience ON audience.id=g.audience_application_id
 JOIN iam.organizations org ON org.id=g.organization_id;
 RETURN jsonb_build_object('items',result);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_grants_list(uuid,timestamptz,uuid,integer,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.obo_grant_revoke(p_grant uuid,p_user_token uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 PERFORM iam_private.obo_user_session(p_user_token);
 UPDATE iam.obo_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()),revocation_reason=COALESCE(revocation_reason,'user_revoked')
 WHERE id=p_grant AND (subject_principal_id=iam_private.current_principal_id() OR EXISTS(SELECT 1 FROM iam_private.obo_graph_nodes(graph) node WHERE node->>'_subject'=iam_private.current_principal_id()));
 IF NOT FOUND THEN RAISE EXCEPTION 'obo_grant_not_found' USING ERRCODE='42501'; END IF;
 PERFORM iam_private.obo_audit('obo.grant.revoked',p_grant,p_grant,'{}');
 RETURN jsonb_build_object('id',p_grant,'status','revoked');
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_grant_revoke(uuid,uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.obo_token_result_is_live(p_token_ids uuid[]) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE token_id uuid; token iam.obo_access_tokens%ROWTYPE;
BEGIN
 IF iam_private.current_application_id() IS NULL OR iam_private.current_application_id() IS DISTINCT FROM iam_private.current_principal_id()
 OR cardinality(p_token_ids) NOT BETWEEN 1 AND 100 OR p_token_ids IS NULL THEN RETURN jsonb_build_object('active',false); END IF;
 FOREACH token_id IN ARRAY p_token_ids LOOP
  SELECT * INTO token FROM iam.obo_access_tokens WHERE id=token_id AND (issuer_application_id=iam_private.current_application_id() OR EXISTS(SELECT 1 FROM iam.obo_grants g CROSS JOIN LATERAL iam_private.obo_graph_nodes(g.graph) node WHERE g.id=obo_access_tokens.grant_id AND node->>'_audience'=iam_private.current_application_id()));
  IF token.id IS NULL OR NOT iam_private.obo_access_is_live(token.id) THEN RETURN jsonb_build_object('active',false); END IF;
  IF token.issuer_application_id=iam_private.current_application_id() AND token.parent_token_id IS NULL AND NOT EXISTS(SELECT 1 FROM iam.obo_refresh_tokens
   WHERE issued_access_token_id=token.id AND consumed_at IS NULL AND expires_at>clock_timestamp()) THEN RETURN jsonb_build_object('active',false); END IF;
 END LOOP;
 RETURN jsonb_build_object('active',true);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_token_result_is_live(uuid[]) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.discover_application_obo_endpoints(p_app_id text)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT jsonb_build_object(
        'application', jsonb_build_object('app_id', app.app_id, 'org_id', org.org_id),
        'endpoints', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'endpoint_id', endpoint.endpoint_id, 'obo_id','['||app.app_id||':obo:'||endpoint.endpoint_id||']',
            'name',endpoint.name,'description',endpoint.description,'note_to_user',endpoint.note_to_user,
            'additional_warnings',endpoint.additional_warnings,'path', endpoint.path,
            'metadata', endpoint.metadata_definition, 'critical', endpoint.critical, 'ttl_seconds', endpoint.ttl_seconds
        ) || CASE WHEN endpoint.downstream = '[]'::jsonb THEN '{}'::jsonb
                  ELSE jsonb_build_object('downstream', endpoint.downstream) END
          || CASE WHEN endpoint.downstream_ttl_seconds IS NULL THEN '{}'::jsonb
                  ELSE jsonb_build_object('downstream_ttl_seconds', endpoint.downstream_ttl_seconds) END
        ORDER BY endpoint.endpoint_id)
        FROM iam.application_obo_endpoints endpoint
        WHERE endpoint.application_id = app.id AND endpoint.status = 'active'), '[]'::jsonb)
    )
    FROM iam.applications app
    JOIN iam.principals principal ON principal.id = app.id AND principal.status = 'active'
    JOIN iam.organizations org ON org.id = app.organization_id AND org.status = 'active'
    WHERE app.app_id = p_app_id AND app.review_status = 'verified' AND app.deleted_at IS NULL
      AND iam_private.application_is_discoverable(app.id,NULL)
      AND iam_private.current_application_id() = iam_private.current_principal_id()
      AND EXISTS (SELECT 1 FROM iam.applications caller
        JOIN iam.principals identity ON identity.id = caller.id AND identity.status = 'active'
        WHERE caller.id = iam_private.current_application_id()
          AND caller.review_status = 'verified' AND caller.deleted_at IS NULL);
$$;
REVOKE ALL ON FUNCTION iam_private.discover_application_obo_endpoints(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.revoke_obo_on_authority_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 IF TG_TABLE_NAME='applications' THEN
  IF NEW.review_status<>'verified' OR NEW.deleted_at IS NOT NULL THEN
   UPDATE iam.obo_grants g SET revoked_at=clock_timestamp(),revocation_reason='application_unavailable'
   WHERE g.revoked_at IS NULL AND EXISTS(SELECT 1 FROM iam_private.obo_graph_nodes(g.graph) node
    WHERE node->>'_issuer'=NEW.id OR node->>'_audience'=NEW.id);
  END IF;
 ELSIF TG_TABLE_NAME='principals' THEN
  IF NEW.status<>'active' THEN
   UPDATE iam.obo_grants g SET revoked_at=clock_timestamp(),revocation_reason='principal_authority_changed'
   WHERE g.revoked_at IS NULL AND (g.subject_principal_id=NEW.id OR EXISTS(SELECT 1 FROM iam_private.obo_graph_nodes(g.graph) node
    WHERE node->>'_issuer'=NEW.id OR node->>'_audience'=NEW.id OR node->>'_subject'=NEW.id));
  END IF;
 ELSIF TG_TABLE_NAME='organization_memberships' THEN
  IF NEW.status<>'active' THEN
   UPDATE iam.obo_grants SET revoked_at=clock_timestamp(),revocation_reason='membership_authority_changed'
   WHERE revoked_at IS NULL AND (membership_id=NEW.id OR EXISTS(SELECT 1 FROM iam_private.obo_graph_nodes(graph) node WHERE node->>'_membership_id'=NEW.id::text));
  END IF;

 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam_private.revoke_obo_on_authority_change() FROM PUBLIC;

-- Consent is durable; credentials are pinned to every participating identity's
-- security epoch. Security resets/secret rotations invalidate credentials only.
ALTER TABLE iam.obo_token_families ADD COLUMN credential_epochs jsonb NOT NULL DEFAULT '[]'::jsonb;
CREATE FUNCTION iam_private.obo_credential_epochs(p_graph jsonb,p_subject text) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',p.id,'epoch',p.auth_epoch) ORDER BY p.id),'[]'::jsonb)
 FROM iam.principals p WHERE p.id IN (
  SELECT p_subject UNION SELECT n->>'_subject' FROM iam_private.obo_graph_nodes(p_graph) n
  UNION SELECT n->>'_issuer' FROM iam_private.obo_graph_nodes(p_graph) n
  UNION SELECT n->>'_audience' FROM iam_private.obo_graph_nodes(p_graph) n
 );
$$;
REVOKE ALL ON FUNCTION iam_private.obo_credential_epochs(jsonb,text) FROM PUBLIC;
CREATE FUNCTION iam_private.obo_family_credentials_live(p_family uuid) RETURNS boolean
LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE family iam.obo_token_families%ROWTYPE; expected jsonb;
BEGIN
 SELECT * INTO family FROM iam.obo_token_families WHERE id=p_family AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND OR jsonb_array_length(family.credential_epochs)=0 THEN RETURN false; END IF;
 FOR expected IN SELECT value FROM jsonb_array_elements(family.credential_epochs) LOOP
  PERFORM 1 FROM iam.principals WHERE id=expected->>'id' AND status='active' AND auth_epoch=(expected->>'epoch')::bigint FOR SHARE;
  IF NOT FOUND THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_family_credentials_live(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.obo_authorization_redeem(p_request uuid,p_code_digests jsonb,p_pairs jsonb) RETURNS jsonb
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
  INSERT INTO iam.obo_token_families(id,grant_id,expires_at,credential_epochs) SELECT family_id,grant_id,g.expires_at,iam_private.obo_credential_epochs(g.graph,g.subject_principal_id) FROM iam.obo_grants g WHERE id=grant_id;
  result:=result||jsonb_build_array(iam_private.obo_issue_pair(grant_id,family_id,pair));
  PERFORM iam_private.obo_audit('obo.tokens.issued',grant_id,family_id,'{}');
 END LOOP;
 UPDATE iam.obo_authorization_codes SET consumed_at=clock_timestamp() WHERE id=code.id;
 UPDATE iam.obo_authorization_requests SET status='exchanged' WHERE id=p_request;
 RETURN jsonb_build_object('items',result);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_authorization_redeem(uuid,jsonb,jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.obo_access_is_live(p_token uuid) RETURNS boolean
LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE token iam.obo_access_tokens%ROWTYPE; parent iam.obo_access_tokens%ROWTYPE;
BEGIN
 SELECT * INTO token FROM iam.obo_access_tokens WHERE id=p_token AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM iam.obo_token_families WHERE id=token.family_id AND grant_id=token.grant_id AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND OR NOT iam_private.obo_family_credentials_live(token.family_id) OR NOT iam_private.obo_grant_is_live(token.grant_id) THEN RETURN false; END IF;
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

CREATE OR REPLACE FUNCTION iam_private.obo_token_refresh(p_digests jsonb,p_pair jsonb) RETURNS jsonb
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
 IF family.revoked_at IS NOT NULL OR NOT iam_private.obo_family_credentials_live(family.id) THEN RAISE EXCEPTION 'obo_refresh_token_invalid' USING ERRCODE='P0001'; END IF;
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

CREATE FUNCTION iam_private.obo_grant_recover(p_grant uuid,p_subject_token uuid,p_pair jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE g iam.obo_grants%ROWTYPE; token iam.access_tokens%ROWTYPE; family_id uuid:=(p_pair->>'family_id')::uuid;
BEGIN
 IF iam_private.current_application_id() IS NULL OR iam_private.current_application_id() IS DISTINCT FROM iam_private.current_principal_id() THEN
  RAISE EXCEPTION 'obo_application_required' USING ERRCODE='42501'; END IF;
 SELECT * INTO g FROM iam.obo_grants WHERE id=p_grant AND application_id=iam_private.current_application_id();
 IF g.id IS NULL OR NOT iam_private.obo_grant_is_live(g.id) THEN RAISE EXCEPTION 'obo_grant_inactive' USING ERRCODE='P0001'; END IF;
 SELECT t.* INTO token FROM iam.access_tokens t
 JOIN iam.principals p ON p.id=t.subject_principal_id AND p.auth_epoch=t.subject_auth_epoch AND p.status='active'
 JOIN iam.authentication_sessions session ON session.id=t.authentication_session_id AND session.status='active'
  AND session.subject_auth_epoch=p.auth_epoch AND session.idle_expires_at>clock_timestamp() AND session.absolute_expires_at>clock_timestamp()
 JOIN iam.refresh_token_families family ON family.id=t.oauth_refresh_family_id AND family.status='active' AND family.absolute_expires_at>clock_timestamp()
 WHERE t.id=p_subject_token AND t.subject_principal_id=g.subject_principal_id AND t.client_application_id=g.application_id
 AND t.token_class='application_access' AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp()
 AND iam_private.application_token_allows_membership(t.id,g.membership_id) FOR SHARE OF t,p,session,family;
 IF token.id IS NULL THEN RAISE EXCEPTION 'obo_subject_login_invalid' USING ERRCODE='P0001'; END IF;
 -- A root login cannot restore another account after that account reset its
 -- credentials. That selected account must authenticate and approve again.
 IF EXISTS(SELECT 1 FROM iam_private.obo_graph_nodes(g.graph) node JOIN iam.principals p ON p.id=node->>'_subject'
  WHERE p.id<>g.subject_principal_id AND p.auth_epoch IS DISTINCT FROM (node->>'_subject_auth_epoch')::bigint) THEN
  RAISE EXCEPTION 'obo_context_reauthentication_required' USING ERRCODE='P0001'; END IF;
 INSERT INTO iam.obo_token_families(id,grant_id,expires_at,credential_epochs)
 VALUES(family_id,g.id,g.expires_at,iam_private.obo_credential_epochs(g.graph,g.subject_principal_id));
 PERFORM iam_private.obo_audit('obo.credentials.recovered',g.id,family_id,'{}');
 RETURN jsonb_build_object('items',jsonb_build_array(iam_private.obo_issue_pair(g.id,family_id,p_pair)));
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_grant_recover(uuid,uuid,jsonb) FROM PUBLIC;

-- Credential metadata identifies the root provider's selected storage organization.
CREATE OR REPLACE FUNCTION iam_private.obo_token_metadata(p_token uuid) RETURNS jsonb
LANGUAGE sql SET search_path=pg_catalog,iam AS $$
 SELECT jsonb_build_object('token_id',t.id,'grant_id',g.id,'token_type','Bearer','expires_at',t.expires_at,
 'expires_in',GREATEST(0,ceil(extract(epoch FROM t.expires_at-clock_timestamp()))::bigint),
 'audience',app.app_id,'endpoint_id',t.endpoint_id,'org_id',org.org_id,'scope','obo:'||app.app_id||':'||t.endpoint_id)
 FROM iam.obo_access_tokens t JOIN iam.obo_grants g ON g.id=t.grant_id
 JOIN iam.applications app ON app.id=t.audience_application_id JOIN iam.organizations org ON org.id=COALESCE((g.graph->>'_organization_id')::uuid,g.organization_id) WHERE t.id=p_token;
$$;
REVOKE ALL ON FUNCTION iam_private.obo_token_metadata(uuid) FROM PUBLIC;
