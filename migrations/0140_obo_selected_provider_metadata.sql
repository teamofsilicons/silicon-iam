-- Shared credentials retain their identity while each provider gets its selected context.
CREATE FUNCTION iam_private.obo_provider_token_metadata(p_token uuid,p_audience text,p_endpoint text) RETURNS jsonb
LANGUAGE sql SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT jsonb_build_object('token_id',t.id,'grant_id',g.id,'token_type','Bearer','expires_at',t.expires_at,
 'expires_in',GREATEST(0,ceil(extract(epoch FROM t.expires_at-clock_timestamp()))::bigint),
 'audience',app.app_id,'endpoint_id',node->>'endpoint_id','org_id',org.org_id,
 'actor',jsonb_build_object('type',subject.kind,'public_id',COALESCE(carbon.carbon_id,silicon.global_silicon_id)),
 'scope','obo:'||app.app_id||':'||(node->>'endpoint_id'))
 FROM iam.obo_access_tokens t JOIN iam.obo_grants g ON g.id=t.grant_id
 CROSS JOIN LATERAL iam_private.obo_graph_nodes(g.graph) node
 JOIN iam.applications app ON app.id=node->>'_audience'
 JOIN iam.organizations org ON org.id=COALESCE((node->>'_organization_id')::uuid,g.organization_id)
 JOIN iam.principals subject ON subject.id=COALESCE(node->>'_subject',g.subject_principal_id)
 LEFT JOIN iam.carbons carbon ON carbon.id=subject.id LEFT JOIN iam.silicons silicon ON silicon.id=subject.id
 WHERE t.id=p_token AND app.app_id=p_audience AND node->>'endpoint_id'=p_endpoint LIMIT 1;
$$;
REVOKE ALL ON FUNCTION iam_private.obo_provider_token_metadata(uuid,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.obo_token_metadata(p_token uuid) RETURNS jsonb
LANGUAGE sql SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT iam_private.obo_provider_token_metadata(t.id,app.app_id,t.endpoint_id)
 FROM iam.obo_access_tokens t JOIN iam.applications app ON app.id=t.audience_application_id WHERE t.id=p_token;
$$;
REVOKE ALL ON FUNCTION iam_private.obo_token_metadata(uuid) FROM PUBLIC;

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
 RETURN iam_private.obo_provider_token_metadata(token.id,p_audience,p_endpoint);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_token_delegate(jsonb,text,text,jsonb) FROM PUBLIC;
