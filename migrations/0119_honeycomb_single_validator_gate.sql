-- Keep exactly one Honeycomb validator gate in a publication plan.
--
-- honeycomb_publication_plan kept every gate whose provider is 'honeycomb' so the
-- scope-less validator gate always survives. Since the public-identifier migration
-- renamed the Honeycomb application from 'tos>honeycomb' to 'honeycomb', a gate for
-- Honeycomb-provided scopes (for example obo:honeycomb:honeycomb.apps.list) has the
-- same provider name. Once its scopes are all reused from existing approvals, that
-- emptied gate was retained beside the validator, producing two 'honeycomb' gates.
-- Honeycomb rejects such a plan and activation cannot match one decision to both.
--
-- The validator is the catalog gate with no scopes; a Honeycomb scope gate is kept
-- only while it still has scopes to review. Every other provider is unchanged.
-- CREATE OR REPLACE preserves the function's owner and EXECUTE grants.
CREATE OR REPLACE FUNCTION iam_private.honeycomb_publication_plan(p_service text, p_actor text, p_request uuid, p_app text, p_revision bigint, p_digest bytea, p_scope jsonb)

RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $function$
DECLARE app iam.applications%ROWTYPE; plan iam.honeycomb_publication_plans%ROWTYPE; gates jsonb; catalogue jsonb; evidence jsonb;
BEGIN
 IF p_actor IS DISTINCT FROM iam_private.current_principal_id() OR NOT EXISTS(SELECT 1 FROM iam.applications WHERE id=p_service AND deleted_at IS NULL) THEN
  RAISE EXCEPTION 'publication_actor_required' USING ERRCODE='42501';
 END IF;
 SELECT * INTO STRICT app FROM iam.applications WHERE app_id=p_app AND deleted_at IS NULL FOR UPDATE;
 IF NOT iam_private.can_manage_application(app.id,p_actor) THEN RAISE EXCEPTION 'application_manager_required' USING ERRCODE='42501'; END IF;
 SELECT * INTO plan FROM iam.honeycomb_publication_plans WHERE service_application_id=p_service AND request_id=p_request;
 IF FOUND THEN
  IF plan.application_id<>app.id OR plan.configuration_revision<>p_revision OR plan.configuration_digest<>p_digest OR plan.requested_scope<>p_scope THEN
   RAISE EXCEPTION 'publication_request_conflict' USING ERRCODE='40001';
  END IF;
 ELSE
  IF p_revision<app.honeycomb_configuration_revision OR (p_revision=app.honeycomb_configuration_revision AND app.visibility<>'private') THEN RAISE EXCEPTION 'configuration_revision_conflict' USING ERRCODE='40001'; END IF;
  catalogue:=iam_private.honeycomb_publication_gates(p_scope);
  SELECT COALESCE(jsonb_agg(jsonb_build_object('scope',approval.scope,'provider',COALESCE(catalog.app_id,'iam'),
   'approved_at',approval.approved_at,'reviewer_id',approval.approved_by_carbon_id) ORDER BY approval.scope),'[]'::jsonb)
  INTO evidence FROM iam.application_approved_scopes approval JOIN iam_private.application_scope_catalog(NULL) catalog ON catalog.scope=approval.scope
  WHERE approval.application_id=app.id AND approval.revoked_at IS NULL AND approval.approval_basis='provider_approval' AND catalog.critical
   AND approval.scope=ANY(iam_private.application_scope_names(p_scope))
   AND iam_private.honeycomb_reviewer_eligible(approval.approved_by_carbon_id,COALESCE(catalog.app_id,'iam'));
  SELECT COALESCE(jsonb_agg(jsonb_build_object('provider',gate->>'provider','scopes',remaining.scopes) ORDER BY CASE WHEN gate->>'provider'='honeycomb' THEN 1 ELSE 0 END,gate->>'provider'),'[]'::jsonb)
  INTO gates FROM jsonb_array_elements(catalogue) gate CROSS JOIN LATERAL (
   SELECT COALESCE(jsonb_agg(scope ORDER BY scope),'[]'::jsonb) AS scopes FROM jsonb_array_elements_text(gate->'scopes') scope
   WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(evidence) accepted WHERE accepted->>'scope'=scope)
  ) remaining WHERE (gate->>'provider'='honeycomb' AND jsonb_array_length(gate->'scopes')=0) OR jsonb_array_length(remaining.scopes)>0;
  INSERT INTO iam.honeycomb_publication_plans(plan_id,service_application_id,request_id,application_id,configuration_revision,configuration_digest,requested_scope,catalog_gates,reused_approvals,gates,created_by_carbon_id)
   VALUES(gen_random_uuid(),p_service,p_request,app.id,p_revision,p_digest,p_scope,catalogue,evidence,gates,p_actor) RETURNING * INTO plan;
 END IF;
 RETURN jsonb_build_object('state','accepted','request_id',plan.request_id,'plan_id',plan.plan_id,'app_id',app.app_id,'configuration_revision',plan.configuration_revision,'visibility','public','gates',plan.gates,'reused_approvals',plan.reused_approvals);
END $function$;
