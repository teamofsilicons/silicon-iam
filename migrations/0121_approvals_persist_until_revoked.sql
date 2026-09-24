-- An accepted scope approval stands until it is explicitly revoked.
--
-- Publication currency, approval reuse and activation re-checked that each past
-- approver was still an eligible reviewer. Losing a reviewer role (or the
-- 2026-09-23 public-identifier rename changing which role counts) silently
-- invalidated approvals nobody revoked, turning published applications private.
--
-- Eligibility is now checked only when a decision is recorded
-- (honeycomb_publication_decide, unchanged). Currency, reuse and activation keep
-- every other check, including explicit revocation (revoked_at) of the approved
-- scopes. Reviewer notification (honeycomb_publication_recipients) still targets
-- current reviewers. CREATE OR REPLACE preserves owners and EXECUTE grants.

CREATE OR REPLACE FUNCTION iam_private.honeycomb_publication_reused_current(p_app text, p_evidence jsonb)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $function$
 SELECT NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_evidence) evidence WHERE NOT EXISTS(
  SELECT 1 FROM iam.application_approved_scopes approval WHERE approval.application_id=p_app
  AND approval.scope=evidence->>'scope' AND approval.approved_at=(evidence->>'approved_at')::timestamptz
  AND approval.approved_by_carbon_id=(evidence->>'reviewer_id')::text AND approval.approval_basis='provider_approval'
  AND approval.revoked_at IS NULL
 ));
$function$;

CREATE OR REPLACE FUNCTION iam_private.honeycomb_publication_is_current(p_app text)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $function$
DECLARE current boolean;
BEGIN
 SELECT EXISTS(SELECT 1 FROM iam.applications app JOIN iam.honeycomb_publication_plans plan
 ON plan.application_id=app.id AND plan.request_id=app.honeycomb_publication_request_id
 WHERE app.id=p_app AND app.visibility='public' AND app.review_status='verified' AND app.deleted_at IS NULL
 AND app.honeycomb_configuration_revision=plan.configuration_revision
 AND plan.catalog_gates=iam_private.honeycomb_publication_gates(plan.requested_scope)
 AND iam_private.honeycomb_publication_reused_current(app.id,plan.reused_approvals)
 AND app.honeycomb_publication_approval_evidence IS NOT NULL
 AND iam_private.honeycomb_publication_reused_current(app.id,app.honeycomb_publication_approval_evidence)
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(plan.gates) gate WHERE NOT EXISTS(
  SELECT 1 FROM iam.honeycomb_publication_decisions decision WHERE decision.plan_id=plan.plan_id AND decision.provider=gate->>'provider'
  AND decision.ordinal=(SELECT max(current_decision.ordinal) FROM iam.honeycomb_publication_decisions current_decision WHERE current_decision.plan_id=plan.plan_id AND current_decision.provider=decision.provider)
  AND decision.decision='approve'
  AND NOT EXISTS(SELECT unnest(decision.scopes) EXCEPT SELECT approved.scope FROM iam.application_approved_scopes approved WHERE approved.application_id=app.id AND approved.revoked_at IS NULL AND approved.approval_basis='provider_approval')
 ))) INTO current;
 RETURN current;
 EXCEPTION WHEN invalid_parameter_value THEN RETURN false;
END $function$;

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
   AND approval.scope=ANY(iam_private.application_scope_names(p_scope));
  -- Honeycomb-provided scopes share the validator's provider name, so they are
  -- reviewed on the single validator gate. Other providers keep one gate each
  -- while scopes remain to review; the validator gate is always present.
  SELECT COALESCE(jsonb_agg(item.gate ORDER BY item.validator,item.gate->>'provider'),'[]'::jsonb)
  INTO gates FROM (
   SELECT 0 AS validator,jsonb_build_object('provider',gate->>'provider','scopes',remaining.scopes) AS gate
   FROM jsonb_array_elements(catalogue) gate CROSS JOIN LATERAL (
    SELECT COALESCE(jsonb_agg(scope ORDER BY scope),'[]'::jsonb) AS scopes FROM jsonb_array_elements_text(gate->'scopes') scope
    WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(evidence) accepted WHERE accepted->>'scope'=scope)
   ) remaining WHERE gate->>'provider'<>'honeycomb' AND jsonb_array_length(remaining.scopes)>0
   UNION ALL
   SELECT 1,jsonb_build_object('provider','honeycomb','scopes',COALESCE((
    SELECT jsonb_agg(DISTINCT scope ORDER BY scope) FROM jsonb_array_elements(catalogue) gate
    CROSS JOIN LATERAL jsonb_array_elements_text(gate->'scopes') scope
    WHERE gate->>'provider'='honeycomb'
     AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(evidence) accepted WHERE accepted->>'scope'=scope)
   ),'[]'::jsonb))
  ) item;
  INSERT INTO iam.honeycomb_publication_plans(plan_id,service_application_id,request_id,application_id,configuration_revision,configuration_digest,requested_scope,catalog_gates,reused_approvals,gates,created_by_carbon_id)
   VALUES(gen_random_uuid(),p_service,p_request,app.id,p_revision,p_digest,p_scope,catalogue,evidence,gates,p_actor) RETURNING * INTO plan;
 END IF;
 RETURN jsonb_build_object('state','accepted','request_id',plan.request_id,'plan_id',plan.plan_id,'app_id',app.app_id,'configuration_revision',plan.configuration_revision,'visibility','public','gates',plan.gates,'reused_approvals',plan.reused_approvals);
END $function$;

CREATE OR REPLACE FUNCTION iam_private.honeycomb_publication_accept(p_service text, p_actor text, p_request uuid, p_plan uuid, p_app text, p_revision bigint, p_expected bigint, p_digest bytea, p_decisions uuid[], p_pending uuid[], p_scope jsonb)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $function$
DECLARE plan iam.honeycomb_publication_plans%ROWTYPE; app iam.applications%ROWTYPE; gate jsonb; decision iam.honeycomb_publication_decisions%ROWTYPE; scope_name text; pending uuid;
BEGIN
 IF p_actor IS DISTINCT FROM iam_private.current_principal_id() THEN RAISE EXCEPTION 'publication_actor_required' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT plan FROM iam.honeycomb_publication_plans WHERE plan_id=p_plan AND service_application_id=p_service;
 SELECT * INTO STRICT app FROM iam.applications WHERE id=plan.application_id AND deleted_at IS NULL FOR UPDATE;
 PERFORM plan_id FROM iam.honeycomb_publication_plans WHERE plan_id=p_plan FOR UPDATE;
 IF NOT iam_private.can_manage_application(app.id,p_actor) THEN RAISE EXCEPTION 'application_manager_required' USING ERRCODE='42501'; END IF;
 IF plan.request_id<>p_request OR app.app_id<>p_app OR plan.configuration_revision<>p_revision OR plan.configuration_digest<>p_digest OR plan.requested_scope<>p_scope
  OR (app.honeycomb_configuration_revision>p_revision OR (app.honeycomb_configuration_revision=p_revision AND app.visibility<>'private')) OR app.version<>p_expected THEN RAISE EXCEPTION 'publication_plan_conflict' USING ERRCODE='40001'; END IF;
 -- Pin providers before checking current criticality and availability.
 PERFORM id FROM iam.applications WHERE app_id IN (SELECT value->>'provider' FROM jsonb_array_elements(plan.catalog_gates)) ORDER BY id FOR SHARE;
 PERFORM scope FROM iam.application_approved_scopes WHERE application_id=app.id AND scope IN(SELECT value->>'scope' FROM jsonb_array_elements(plan.reused_approvals)) FOR SHARE;
 PERFORM id FROM iam.principals WHERE id IN(SELECT (value->>'reviewer_id')::text FROM jsonb_array_elements(plan.reused_approvals)) ORDER BY id FOR SHARE;
 PERFORM id FROM iam.platform_role_grants WHERE carbon_id IN(SELECT (value->>'reviewer_id')::text FROM jsonb_array_elements(plan.reused_approvals)) AND revoked_at IS NULL ORDER BY id FOR SHARE;
 PERFORM id FROM iam.organization_memberships WHERE principal_id IN(SELECT (value->>'reviewer_id')::text FROM jsonb_array_elements(plan.reused_approvals)) ORDER BY id FOR SHARE;
 PERFORM id FROM iam.organizations WHERE id IN(SELECT organization_id FROM iam.organization_memberships WHERE principal_id IN(SELECT (value->>'reviewer_id')::text FROM jsonb_array_elements(plan.reused_approvals))) ORDER BY id FOR SHARE;
 IF plan.catalog_gates<>iam_private.honeycomb_publication_gates(plan.requested_scope) OR NOT iam_private.honeycomb_publication_reused_current(app.id,plan.reused_approvals) THEN RAISE EXCEPTION 'publication_plan_stale' USING ERRCODE='40001'; END IF;
 IF cardinality(p_decisions)<>jsonb_array_length(plan.gates) OR cardinality(p_decisions)<>(SELECT count(DISTINCT id) FROM unnest(p_decisions) id) THEN
  RAISE EXCEPTION 'publication_decisions_incomplete' USING ERRCODE='22023';
 END IF;
 FOR gate IN SELECT value FROM jsonb_array_elements(plan.gates) LOOP
  SELECT * INTO decision FROM iam.honeycomb_publication_decisions WHERE plan_id=p_plan AND provider=gate->>'provider' ORDER BY ordinal DESC LIMIT 1;
  IF decision.decision_id IS NULL OR NOT(decision.decision_id=ANY(p_decisions)) OR decision.decision<>'approve' OR to_jsonb(decision.scopes)<>gate->'scopes' THEN
   RAISE EXCEPTION 'publication_decisions_incomplete' USING ERRCODE='42501';
  END IF;
  PERFORM id FROM iam.principals WHERE id=decision.reviewer_carbon_id FOR SHARE;
  PERFORM id FROM iam.platform_role_grants WHERE carbon_id=decision.reviewer_carbon_id AND revoked_at IS NULL FOR SHARE;
  PERFORM id FROM iam.organization_memberships WHERE principal_id=decision.reviewer_carbon_id FOR SHARE;
  PERFORM id FROM iam.organizations WHERE id IN(SELECT organization_id FROM iam.organization_memberships WHERE principal_id=decision.reviewer_carbon_id) ORDER BY id FOR SHARE;
  IF EXISTS(SELECT 1 FROM iam.application_approved_scopes approved WHERE approved.application_id=app.id AND approved.scope=ANY(decision.scopes) AND approved.revoked_at>=decision.created_at) THEN
   RAISE EXCEPTION 'publication_scope_revoked' USING ERRCODE='42501';
  END IF;
 END LOOP;
 FOREACH pending IN ARRAY p_pending LOOP
  IF NOT EXISTS(SELECT 1 FROM iam.honeycomb_operations WHERE operation_id=pending AND service_application_id=p_service AND operation_kind='configure'
   AND resource_id=p_app AND state='pending' AND (result->>'configuration_revision')::bigint=p_revision
   AND result->>'configuration_digest'=encode(p_digest,'hex')) THEN RAISE EXCEPTION 'publication_pending_operation_mismatch' USING ERRCODE='40001'; END IF;
 END LOOP;
 -- Grant only after every gate succeeds. Everything, including configuration,
 -- commits in the caller's single transaction; failures roll these writes back.
 PERFORM iam_private.configure_application_scopes(app.id,p_scope,p_actor);
 FOR decision IN SELECT * FROM iam.honeycomb_publication_decisions WHERE decision_id=ANY(p_decisions) LOOP
  FOREACH scope_name IN ARRAY decision.scopes LOOP
   UPDATE iam.application_approved_scopes SET revoked_at=transaction_timestamp(),revoked_by_carbon_id=p_actor
    WHERE application_id=app.id AND scope=scope_name AND revoked_at IS NULL;
   INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id,approval_basis,approved_at)
    SELECT app.id,scope_name,decision.reviewer_carbon_id,'provider_approval',clock_timestamp() WHERE NOT EXISTS(
     SELECT 1 FROM iam.application_approved_scopes WHERE application_id=app.id AND scope=scope_name AND revoked_at IS NULL);
  END LOOP;
 END LOOP;
 UPDATE iam.applications SET honeycomb_publication_request_id=p_request,honeycomb_publication_approval_evidence=(
  SELECT COALESCE(jsonb_agg(jsonb_build_object('scope',approval.scope,'provider',COALESCE(catalog.app_id,'iam'),
   'approved_at',approval.approved_at,'reviewer_id',approval.approved_by_carbon_id) ORDER BY approval.scope),'[]'::jsonb)
  FROM iam.application_approved_scopes approval JOIN iam_private.application_scope_catalog(NULL) catalog ON catalog.scope=approval.scope
  WHERE approval.application_id=app.id AND approval.revoked_at IS NULL AND approval.approval_basis='provider_approval' AND catalog.critical
   AND approval.scope=ANY(iam_private.application_scope_names(p_scope))) WHERE id=app.id;
 RETURN app.id;
END $function$;
