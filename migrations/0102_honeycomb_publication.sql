-- Honeycomb publication is a separate, immutable review of one exact desired
-- configuration. No service-supplied boolean can manufacture reviewer authority.
INSERT INTO iam.platform_capability_catalog(capability,description)
 VALUES('honeycomb.applications.review','Validate Honeycomb publication independently of organization administration.');
INSERT INTO iam.platform_role_catalog(role,description)
 VALUES('honeycomb_validator','Review Honeycomb application publication without unrelated platform authority.');
INSERT INTO iam.platform_role_capabilities(role,capability)
 VALUES('honeycomb_validator','honeycomb.applications.review');
-- Deliberately do not auto-grant this new capability to platform administrators.
ALTER TABLE iam.applications ADD COLUMN honeycomb_publication_request_id uuid,
 ADD COLUMN honeycomb_publication_approval_evidence jsonb;

CREATE TABLE iam.honeycomb_publication_plans (
 plan_id uuid PRIMARY KEY,
 service_application_id uuid NOT NULL REFERENCES iam.applications(id),
 request_id uuid NOT NULL,
 application_id uuid NOT NULL REFERENCES iam.applications(id),
 configuration_revision bigint NOT NULL CHECK(configuration_revision>0),
 configuration_digest bytea NOT NULL CHECK(octet_length(configuration_digest)=32),
 requested_scope jsonb NOT NULL,
 catalog_gates jsonb NOT NULL,
 reused_approvals jsonb NOT NULL,
 gates jsonb NOT NULL,
 created_by_carbon_id uuid NOT NULL REFERENCES iam.carbons(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(service_application_id,request_id)
);
CREATE TABLE iam.honeycomb_publication_decisions (
 decision_id uuid PRIMARY KEY REFERENCES iam.honeycomb_operations(operation_id),
 plan_id uuid NOT NULL REFERENCES iam.honeycomb_publication_plans(plan_id),
 ordinal bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 provider text NOT NULL,
 scopes text[] NOT NULL,
 decision text NOT NULL CHECK(decision IN ('approve','deny')),
 reviewer_carbon_id uuid NOT NULL REFERENCES iam.carbons(id),
 reason text CHECK(reason IS NULL OR char_length(reason) BETWEEN 1 AND 2000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX honeycomb_publication_decisions_latest ON iam.honeycomb_publication_decisions(plan_id,provider,ordinal DESC);
ALTER TABLE iam.honeycomb_publication_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.honeycomb_publication_plans FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.honeycomb_publication_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.honeycomb_publication_decisions FORCE ROW LEVEL SECURITY;
DO $owner_policies$
DECLARE entry record;
BEGIN
 FOR entry IN SELECT relation.oid,pg_catalog.pg_get_userbyid(relation.relowner) owner_name FROM pg_catalog.pg_class relation
 JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
 WHERE namespace.nspname='iam' AND relation.relname IN('honeycomb_publication_plans','honeycomb_publication_decisions') LOOP
 EXECUTE format('CREATE POLICY publication_owner ON %s TO %I USING(true) WITH CHECK(true)',entry.oid::regclass,entry.owner_name);
 END LOOP;
END $owner_policies$;
-- Runtime roles have no direct access. Narrow definer functions bind each read
-- and mutation to its configured service, live actor and exact plan.
CREATE TRIGGER honeycomb_publication_plans_immutable BEFORE UPDATE OR DELETE ON iam.honeycomb_publication_plans
 FOR EACH ROW EXECUTE FUNCTION iam_private.reject_immutable_history_mutation();
CREATE TRIGGER honeycomb_publication_decisions_immutable BEFORE UPDATE OR DELETE ON iam.honeycomb_publication_decisions
 FOR EACH ROW EXECUTE FUNCTION iam_private.reject_immutable_history_mutation();

CREATE FUNCTION iam_private.honeycomb_publication_gates(p_scope jsonb)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE names text[]; result jsonb;
BEGIN
 names:=iam_private.application_scope_names(p_scope);
 IF cardinality(names) NOT BETWEEN 1 AND 100 OR EXISTS(SELECT unnest(names) EXCEPT SELECT scope FROM iam_private.application_scope_catalog(NULL)) THEN
  RAISE EXCEPTION 'invalid_application_scope' USING ERRCODE='22023';
 END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('provider',provider,'scopes',scopes) ORDER BY provider),'[]'::jsonb)
 INTO result FROM (
  SELECT COALESCE(catalog.app_id,'iam') AS provider,jsonb_agg(catalog.scope ORDER BY catalog.scope) AS scopes
  FROM iam_private.application_scope_catalog(NULL) catalog WHERE catalog.critical AND catalog.scope=ANY(names)
  GROUP BY COALESCE(catalog.app_id,'iam')
 ) grouped;
 RETURN result||jsonb_build_array(jsonb_build_object('provider','honeycomb','scopes','[]'::jsonb));
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_publication_gates(jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_reviewer_eligible(p_actor uuid,p_provider text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT CASE p_provider
 WHEN 'iam' THEN iam_private.has_platform_capability(p_actor,'applications.review')
 WHEN 'honeycomb' THEN iam_private.has_platform_capability(p_actor,'honeycomb.applications.review')
 ELSE EXISTS(SELECT 1 FROM iam.applications app WHERE app.app_id=p_provider AND app.deleted_at IS NULL
  AND iam_private.can_manage_application(app.id,p_actor)) END;
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_reviewer_eligible(uuid,text) FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_publication_reused_current(p_app uuid,p_evidence jsonb)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_evidence) evidence WHERE NOT EXISTS(
  SELECT 1 FROM iam.application_approved_scopes approval WHERE approval.application_id=p_app
  AND approval.scope=evidence->>'scope' AND approval.approved_at=(evidence->>'approved_at')::timestamptz
  AND approval.approved_by_carbon_id=(evidence->>'reviewer_id')::uuid AND approval.approval_basis='provider_approval'
  AND approval.revoked_at IS NULL AND iam_private.honeycomb_reviewer_eligible(approval.approved_by_carbon_id,evidence->>'provider')
 ));
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_publication_reused_current(uuid,jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_publication_plan(p_service uuid,p_actor uuid,p_request uuid,p_app text,p_revision bigint,p_digest bytea,p_scope jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
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
  ) remaining WHERE gate->>'provider'='honeycomb' OR jsonb_array_length(remaining.scopes)>0;
  INSERT INTO iam.honeycomb_publication_plans(plan_id,service_application_id,request_id,application_id,configuration_revision,configuration_digest,requested_scope,catalog_gates,reused_approvals,gates,created_by_carbon_id)
   VALUES(gen_random_uuid(),p_service,p_request,app.id,p_revision,p_digest,p_scope,catalogue,evidence,gates,p_actor) RETURNING * INTO plan;
 END IF;
 RETURN jsonb_build_object('state','accepted','request_id',plan.request_id,'plan_id',plan.plan_id,'app_id',app.app_id,'configuration_revision',plan.configuration_revision,'visibility','public','gates',plan.gates,'reused_approvals',plan.reused_approvals);
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_publication_plan(uuid,uuid,uuid,text,bigint,bytea,jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_publication_read(p_service uuid,p_plan uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam AS $$
 SELECT jsonb_build_object('state','accepted','request_id',plan.request_id,'plan_id',plan.plan_id,'app_id',app.app_id,
  'configuration_revision',plan.configuration_revision,'visibility','public','gates',plan.gates,'reused_approvals',plan.reused_approvals)
 FROM iam.honeycomb_publication_plans plan JOIN iam.applications app ON app.id=plan.application_id
 WHERE plan.plan_id=p_plan AND plan.service_application_id=p_service AND app.deleted_at IS NULL;
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_publication_read(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_publication_decide(p_service uuid,p_actor uuid,p_operation uuid,p_request uuid,p_plan uuid,p_app text,p_revision bigint,p_provider text,p_scopes text[],p_decision text,p_reason text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE plan iam.honeycomb_publication_plans%ROWTYPE; app iam.applications%ROWTYPE; gate jsonb;
BEGIN
 IF p_actor IS DISTINCT FROM iam_private.current_principal_id() THEN RAISE EXCEPTION 'publication_actor_required' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT plan FROM iam.honeycomb_publication_plans WHERE plan_id=p_plan AND service_application_id=p_service;
 SELECT * INTO STRICT app FROM iam.applications WHERE id=plan.application_id AND deleted_at IS NULL FOR UPDATE;
 PERFORM plan_id FROM iam.honeycomb_publication_plans WHERE plan_id=p_plan FOR UPDATE;
 IF plan.request_id<>p_request OR app.app_id<>p_app OR plan.configuration_revision<>p_revision OR (app.honeycomb_configuration_revision>p_revision OR (app.honeycomb_configuration_revision=p_revision AND app.visibility<>'private')) THEN
  RAISE EXCEPTION 'publication_plan_conflict' USING ERRCODE='40001';
 END IF;
 IF plan.catalog_gates<>iam_private.honeycomb_publication_gates(plan.requested_scope) OR NOT iam_private.honeycomb_publication_reused_current(app.id,plan.reused_approvals) THEN RAISE EXCEPTION 'publication_plan_stale' USING ERRCODE='40001'; END IF;
 SELECT value INTO gate FROM jsonb_array_elements(plan.gates) WHERE value->>'provider'=p_provider;
 IF gate IS NULL OR gate->'scopes'<>to_jsonb(p_scopes) OR p_decision NOT IN('approve','deny') THEN
  RAISE EXCEPTION 'publication_gate_mismatch' USING ERRCODE='22023';
 END IF;
 -- Locks serialize grants and membership revocation with the decision.
 PERFORM id FROM iam.principals WHERE id=p_actor FOR SHARE;
 PERFORM id FROM iam.platform_role_grants WHERE carbon_id=p_actor AND revoked_at IS NULL FOR SHARE;
 PERFORM id FROM iam.organization_memberships WHERE principal_id=p_actor FOR SHARE;
 PERFORM id FROM iam.organizations WHERE id IN(SELECT organization_id FROM iam.organization_memberships WHERE principal_id=p_actor) ORDER BY id FOR SHARE;
 IF NOT iam_private.honeycomb_reviewer_eligible(p_actor,p_provider) THEN RAISE EXCEPTION 'publication_reviewer_required' USING ERRCODE='42501'; END IF;
 INSERT INTO iam.honeycomb_publication_decisions(decision_id,plan_id,provider,scopes,decision,reviewer_carbon_id,reason)
 VALUES(p_operation,p_plan,p_provider,p_scopes,p_decision,p_actor,p_reason);
 RETURN jsonb_build_object('operation_id',p_operation,'decision_id',p_operation,'state','accepted','request_id',p_request,'plan_id',p_plan,
 'app_id',p_app,'configuration_revision',p_revision,'provider',p_provider,'scopes',p_scopes,'decision',p_decision,'reason',p_reason);
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_publication_decide(uuid,uuid,uuid,uuid,uuid,text,bigint,text,text[],text,text) FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_publication_accept(p_service uuid,p_actor uuid,p_request uuid,p_plan uuid,p_app text,p_revision bigint,p_expected bigint,p_digest bytea,p_decisions uuid[],p_pending uuid[],p_scope jsonb)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
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
 PERFORM id FROM iam.principals WHERE id IN(SELECT (value->>'reviewer_id')::uuid FROM jsonb_array_elements(plan.reused_approvals)) ORDER BY id FOR SHARE;
 PERFORM id FROM iam.platform_role_grants WHERE carbon_id IN(SELECT (value->>'reviewer_id')::uuid FROM jsonb_array_elements(plan.reused_approvals)) AND revoked_at IS NULL ORDER BY id FOR SHARE;
 PERFORM id FROM iam.organization_memberships WHERE principal_id IN(SELECT (value->>'reviewer_id')::uuid FROM jsonb_array_elements(plan.reused_approvals)) ORDER BY id FOR SHARE;
 PERFORM id FROM iam.organizations WHERE id IN(SELECT organization_id FROM iam.organization_memberships WHERE principal_id IN(SELECT (value->>'reviewer_id')::uuid FROM jsonb_array_elements(plan.reused_approvals))) ORDER BY id FOR SHARE;
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
  IF NOT iam_private.honeycomb_reviewer_eligible(decision.reviewer_carbon_id,decision.provider) THEN RAISE EXCEPTION 'publication_reviewer_revoked' USING ERRCODE='42501'; END IF;
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
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_publication_accept(uuid,uuid,uuid,uuid,text,bigint,bigint,bytea,uuid[],uuid[],jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_publication_complete_pending(p_service uuid,p_pending uuid[],p_result jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
BEGIN
 -- Only the same current owner/admin can finalize matching pending writes.
 IF NOT EXISTS(SELECT 1 FROM iam.applications app WHERE app.app_id=p_result->>'app_id'
  AND app.honeycomb_publication_request_id=(p_result->>'request_id')::uuid
  AND iam_private.can_manage_application(app.id,iam_private.current_principal_id())) THEN RAISE EXCEPTION 'publication_actor_required' USING ERRCODE='42501'; END IF;
 UPDATE iam.honeycomb_operations SET state='accepted',completed=true,iam_revision=(p_result->>'iam_revision')::bigint,
  result=p_result||jsonb_build_object('operation_id',operation_id),updated_at=transaction_timestamp()
 WHERE operation_id=ANY(p_pending) AND service_application_id=p_service AND state='pending' AND operation_kind='configure'
  AND resource_id=p_result->>'app_id' AND result->>'configuration_revision'=p_result->>'configuration_revision';
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_publication_complete_pending(uuid,uuid[],jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_publication_recipients(p_service uuid,p_plan uuid,p_provider text,p_after uuid DEFAULT NULL,p_limit integer DEFAULT 100)
RETURNS TABLE(principal_id uuid,contact_id uuid,ciphertext bytea,nonce bytea,encryption_key_version smallint)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT contact.carbon_id,contact.id,contact.ciphertext,contact.nonce,contact.encryption_key_version
 FROM iam.honeycomb_publication_plans plan JOIN iam.applications app ON app.id=plan.application_id
 JOIN iam.carbon_contacts contact ON contact.kind='email' AND contact.status='active' AND contact.is_primary
 JOIN iam.principals principal ON principal.id=contact.carbon_id AND principal.status='active'
 WHERE plan.plan_id=p_plan AND plan.service_application_id=p_service AND app.deleted_at IS NULL
 AND (p_provider='owners' OR EXISTS(SELECT 1 FROM jsonb_array_elements(plan.gates) gate WHERE gate->>'provider'=p_provider))
 AND (p_after IS NULL OR contact.carbon_id>p_after)
 AND CASE WHEN p_provider='owners' THEN iam_private.is_active_organization_owner_or_admin(app.organization_id,contact.carbon_id)
  ELSE iam_private.honeycomb_reviewer_eligible(contact.carbon_id,p_provider) END
 ORDER BY contact.carbon_id LIMIT LEAST(1000,GREATEST(1,p_limit))+1;
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_publication_recipients(uuid,uuid,text,uuid,integer) FROM PUBLIC;

DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_publication_plan(uuid,uuid,uuid,text,bigint,bytea,jsonb),
 iam_private.honeycomb_publication_read(uuid,uuid),iam_private.honeycomb_reviewer_eligible(uuid,text),
 iam_private.honeycomb_publication_decide(uuid,uuid,uuid,uuid,uuid,text,bigint,text,text[],text,text),
 iam_private.honeycomb_publication_accept(uuid,uuid,uuid,uuid,text,bigint,bigint,bytea,uuid[],uuid[],jsonb),
 iam_private.honeycomb_publication_complete_pending(uuid,uuid[],jsonb),
 iam_private.honeycomb_publication_recipients(uuid,uuid,text,uuid,integer) TO silicon_iam_api;
END IF; END $$;

CREATE FUNCTION iam_private.honeycomb_publication_is_current(p_app uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
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
  AND decision.decision='approve' AND iam_private.honeycomb_reviewer_eligible(decision.reviewer_carbon_id,decision.provider)
  AND NOT EXISTS(SELECT unnest(decision.scopes) EXCEPT SELECT approved.scope FROM iam.application_approved_scopes approved WHERE approved.application_id=app.id AND approved.revoked_at IS NULL AND approved.approval_basis='provider_approval')
 ))) INTO current;
 RETURN current;
 EXCEPTION WHEN invalid_parameter_value THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_publication_is_current(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.honeycomb_application_record(p_service uuid,p_app_id text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT jsonb_build_object('app_id',app.app_id,'application_id',app.id,'org_id',org.org_id,
 'app_name',app.app_name,'app_logo',app.app_logo_uri,'base_url',NULLIF(app.base_url,''),
 'visibility',app.visibility,'availability',app.review_status,'iam_revision',app.version,
 'configuration_revision',app.honeycomb_configuration_revision,
 'publication_request_id',CASE WHEN iam_private.honeycomb_publication_is_current(app.id) THEN app.honeycomb_publication_request_id END,
 'pending_webhook_endpoint_id',(SELECT id FROM iam.application_webhook_endpoints WHERE application_id=app.id AND status='pending_review'),
 'app_scope',app.app_scope,'webhook_scope',app.webhook_scope,'obo_review_message',app.obo_review_message,
 'effective_scopes',COALESCE((SELECT jsonb_agg(jsonb_build_object('scope',approved.scope,'basis',approved.approval_basis) ORDER BY approved.scope)
   FROM iam.application_approved_scopes approved WHERE approved.application_id=app.id AND approved.revoked_at IS NULL),'[]'::jsonb),
 'obo_endpoints',COALESCE((SELECT jsonb_agg(jsonb_build_object('endpoint_id',endpoint_id,'path',path,
   'metadata',metadata_definition,'critical',critical,'ttl_seconds',ttl_seconds) ORDER BY endpoint_id)
   FROM iam.application_obo_endpoints WHERE application_id=app.id AND status='active'),'[]'::jsonb),
 'credential_version',(SELECT max(secret_version) FROM iam.application_secrets WHERE application_id=app.id AND status='active'),
 'testing_idle_days',app.testing_idle_days)
 FROM iam.applications app JOIN iam.organizations org ON org.id=app.organization_id
 WHERE app.app_id=p_app_id AND EXISTS(SELECT 1 FROM iam.applications service WHERE service.id=p_service);
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_application_record(uuid,text) FROM PUBLIC;


-- Operational notices do not require a publication plan. Only the requested
-- organization's current owners/admins and verified primary emails are exposed.
CREATE FUNCTION iam_private.honeycomb_organization_recipients(p_service uuid,p_org text,p_after uuid DEFAULT NULL,p_limit integer DEFAULT 100)
RETURNS TABLE(principal_id uuid,contact_id uuid,ciphertext bytea,nonce bytea,encryption_key_version smallint)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT contact.carbon_id,contact.id,contact.ciphertext,contact.nonce,contact.encryption_key_version
 FROM iam.organizations org JOIN iam.carbon_contacts contact ON contact.kind='email' AND contact.status='active' AND contact.is_primary
 JOIN iam.principals principal ON principal.id=contact.carbon_id AND principal.status='active'
 WHERE org.org_id=p_org AND org.status='active'
 AND EXISTS(SELECT 1 FROM iam.applications service WHERE service.id=p_service AND service.deleted_at IS NULL)
 AND iam_private.is_active_organization_owner_or_admin(org.id,contact.carbon_id)
 AND (p_after IS NULL OR contact.carbon_id>p_after)
 ORDER BY contact.carbon_id LIMIT LEAST(1000,GREATEST(1,p_limit))+1;
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_organization_recipients(uuid,text,uuid,integer) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_organization_recipients(uuid,text,uuid,integer) TO silicon_iam_api;
END IF; END $$;
