-- Show the caller's current scopes for this reviewing provider only.
-- This is display context; the immutable r.scopes array remains the decision boundary.
CREATE OR REPLACE FUNCTION iam_private.application_scope_request_view(p_id uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT jsonb_build_object('id',r.id,'app_id',app.app_id,'target_app_id',target.app_id,'scopes',r.scopes,'status',r.status,
 'version',r.version,'created_at',r.created_at,'updated_at',r.updated_at,
 'current_scope_context',COALESCE((
   SELECT jsonb_agg(jsonb_build_object('scope',names.scope,'description',catalog.description,
     'critical',catalog.critical,'in_review',names.scope=ANY(r.scopes)) ORDER BY names.scope)
   FROM unnest(iam_private.application_scope_names(app.app_scope)) names(scope)
   LEFT JOIN iam_private.application_scope_catalog(NULL) catalog ON catalog.scope=names.scope
   WHERE CASE WHEN r.target_application_id IS NULL THEN names.scope NOT LIKE 'obo:%'
     ELSE starts_with(names.scope,'obo:' || target.app_id || ':') END
 ),'[]'::jsonb),
 'can_decide',iam_private.can_review_application_scopes(r.target_application_id,iam_private.current_principal_id()),
 'messages',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',m.id,'message',m.message,'created_at',m.created_at,
 'is_own',COALESCE(m.author_carbon_id=iam_private.current_principal_id(),false),
 'author',jsonb_build_object('principal_id',COALESCE(m.author_carbon_id,'00000000-0000-0000-0000-000000000000'::uuid),'type',CASE WHEN m.author_carbon_id IS NULL THEN 'system' ELSE 'carbon' END,
 'public_id',COALESCE(c.carbon_id,'iam'))) ORDER BY m.created_at,m.id)
 FROM iam.application_scope_messages m LEFT JOIN iam.carbons c ON c.id=m.author_carbon_id WHERE m.request_id=r.id),'[]'::jsonb))
 FROM iam.application_scope_requests r JOIN iam.applications app ON app.id=r.application_id
 LEFT JOIN iam.applications target ON target.id=r.target_application_id
 WHERE r.id=p_id AND
 (iam_private.can_manage_application(r.application_id,iam_private.current_principal_id()) OR iam_private.can_review_application_scopes(r.target_application_id,iam_private.current_principal_id()))
$$;
REVOKE ALL ON FUNCTION iam_private.application_scope_request_view(uuid) FROM PUBLIC;
