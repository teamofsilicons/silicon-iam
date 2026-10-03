-- Provider disclosure consent is explicit and bound to each selected account.
-- Never infer another account's IAM disclosures from the origin login.
UPDATE iam.obo_grants SET revoked_at=clock_timestamp(),
 revocation_reason='provider_disclosure_consent_required' WHERE revoked_at IS NULL;

CREATE FUNCTION iam_private.obo_disclosure_review(p_apps text[]) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE scopes jsonb; approvals jsonb;
BEGIN
 IF cardinality(p_apps) NOT BETWEEN 2 AND 11 THEN
  RAISE EXCEPTION 'obo_disclosure_path_invalid' USING ERRCODE='22023'; END IF;
 -- Match graph/authority lock order: applications and their current approvals
 -- are held before a durable grant is locked. No caller-supplied new scopes.
 PERFORM 1 FROM iam.applications app JOIN iam.principals principal ON principal.id=app.id
 WHERE app.app_id=ANY(p_apps) FOR SHARE OF app,principal;
 PERFORM 1 FROM iam.application_approved_scopes approved JOIN iam.applications app ON app.id=approved.application_id
 WHERE app.app_id=ANY(p_apps) AND approved.revoked_at IS NULL
 AND approved.scope=ANY(ARRAY['self.identity.read','self.membership.read','self.tags.read']) FOR SHARE OF approved;
 SELECT COALESCE(jsonb_agg(candidate.scope ORDER BY candidate.scope),'[]'::jsonb) INTO scopes
 FROM unnest(ARRAY['self.identity.read','self.membership.read','self.tags.read']) candidate(scope)
 WHERE NOT EXISTS(SELECT 1 FROM unnest(p_apps) participant(app_id) WHERE NOT EXISTS(
  SELECT 1 FROM iam.applications app JOIN iam.principals principal ON principal.id=app.id
  JOIN iam.application_approved_scopes approved ON approved.application_id=app.id
   AND approved.scope=candidate.scope AND approved.revoked_at IS NULL
  WHERE app.app_id=participant.app_id AND principal.status='active' AND app.deleted_at IS NULL
   AND app.review_status='verified' AND iam_private.application_scope_names(app.app_scope) @> ARRAY[candidate.scope]));
 SELECT COALESCE(jsonb_agg(jsonb_build_object('app_id',app.app_id,'scope',approved.scope,'approved_at',approved.approved_at)
  ORDER BY app.app_id,approved.scope),'[]'::jsonb) INTO approvals
 FROM iam.application_approved_scopes approved JOIN iam.applications app ON app.id=approved.application_id
 WHERE app.app_id=ANY(p_apps) AND approved.revoked_at IS NULL AND scopes ? approved.scope;
 RETURN jsonb_build_object('scopes',scopes,'approvals',approvals);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_disclosure_review(text[]) FROM PUBLIC;
CREATE OR REPLACE FUNCTION iam_private.obo_graph_node(p_issuer text,p_audience text,p_endpoint text,p_subject text,p_org uuid,p_seen text[])
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE issuer iam.applications%ROWTYPE; audience iam.applications%ROWTYPE;
 endpoint iam.application_obo_endpoints%ROWTYPE; approval iam.application_approved_scopes%ROWTYPE;
 issuer_epoch bigint; audience_epoch bigint; dependency jsonb; children jsonb:='[]'; disclosures jsonb;
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
 disclosures:=iam_private.obo_disclosure_review(p_seen||p_audience);
 RETURN jsonb_build_object('iam_disclosures',disclosures->'scopes','_disclosure_review',disclosures,
  '_disclosure_participants',to_jsonb(p_seen||p_audience),'audience',audience.app_id,'app_name',COALESCE(NULLIF(audience.app_name,''),audience.app_id),'endpoint_id',p_endpoint,
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
 'iam_disclosures',COALESCE(p_node->'iam_disclosures','[]'::jsonb),'endpoint_id',p_node->'endpoint_id','obo_id',p_node->'obo_id','name',p_node->'name',
 'note_to_user',p_node->'note_to_user','additional_warnings',COALESCE(p_node->'additional_warnings','[]'::jsonb),'description',p_node->'description','critical',p_node->'critical',
 'downstream',COALESCE((SELECT jsonb_agg(iam_private.obo_public_node(value)) FROM jsonb_array_elements(p_node->'downstream')),'[]'::jsonb));
$$;
REVOKE ALL ON FUNCTION iam_private.obo_public_node(jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.obo_bind_contexts(p_node jsonb,p_contexts jsonb,p_default_token uuid,p_default_org uuid) RETURNS jsonb
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
  '_membership_id',member.id,'_disclosure_consent',jsonb_build_object('version',1,
  'scopes',p_node->'iam_disclosures','subject',token.subject_principal_id,'organization_id',member.organization_id,
  'membership_id',member.id,'subject_auth_epoch',token.subject_auth_epoch,'membership_epoch',member.authz_epoch),
  '_subject_auth_epoch',token.subject_auth_epoch,'_membership_epoch',member.authz_epoch,'downstream',children);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_bind_contexts(jsonb,jsonb,uuid,uuid) FROM PUBLIC;

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
  IF EXISTS(SELECT 1 FROM iam_private.obo_graph_nodes(approved_graph) node
   WHERE jsonb_array_length(COALESCE(node->'iam_disclosures','[]'::jsonb))>0)
   AND p_code->'iam_disclosures_reviewed' IS DISTINCT FROM 'true'::jsonb THEN
   RAISE EXCEPTION 'obo_disclosure_review_required' USING ERRCODE='P0001'; END IF;
  approved_graph:=iam_private.obo_bind_contexts(approved_graph,p_contexts,p_user_token,request.organization_id);

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

CREATE OR REPLACE FUNCTION iam_private.obo_graph_is_current(p_node jsonb,p_subject text,p_org uuid)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE endpoint iam.application_obo_endpoints%ROWTYPE; child jsonb;
 selected_subject text:=COALESCE(p_node->>'_subject',p_subject);
 selected_org uuid:=COALESCE((p_node->>'_organization_id')::uuid,p_org);
BEGIN
 IF p_node->'_disclosure_consent'->>'version' IS DISTINCT FROM '1'
 OR p_node->'_disclosure_consent'->'scopes' IS DISTINCT FROM p_node->'iam_disclosures'
 OR p_node->'_disclosure_consent'->>'subject' IS DISTINCT FROM selected_subject
 OR p_node->'_disclosure_consent'->>'organization_id' IS DISTINCT FROM selected_org::text
 OR p_node->'_disclosure_consent'->>'membership_id' IS DISTINCT FROM p_node->>'_membership_id'
 OR p_node->'_disclosure_review' IS DISTINCT FROM iam_private.obo_disclosure_review(ARRAY(
  SELECT jsonb_array_elements_text(COALESCE(p_node->'_disclosure_participants','[]'::jsonb)))) THEN RETURN false; END IF;
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
 -- The graph liveness check has revalidated the exact displayed approval
 -- snapshot for this path. Selected-account authentication alone grants none.
 SELECT ARRAY['obo:'||audience_app||':'||p_endpoint]||ARRAY(
  SELECT scope FROM jsonb_array_elements_text(COALESCE(node->'_disclosure_consent'->'scopes','[]'::jsonb)) scope
  WHERE scope=ANY(ARRAY['self.identity.read','self.membership.read','self.tags.read']) ORDER BY scope
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
