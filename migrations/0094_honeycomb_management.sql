-- Empty origin represents an absent optional backend URL in legacy wire models.
ALTER TABLE iam.applications ALTER COLUMN base_url SET DEFAULT '',
 DROP CONSTRAINT applications_base_url_length, DROP CONSTRAINT applications_base_url_shape,
 ADD COLUMN honeycomb_configuration_revision bigint NOT NULL DEFAULT 0 CHECK(honeycomb_configuration_revision>=0),
 ADD CONSTRAINT applications_base_url_length CHECK(base_url='' OR char_length(base_url) BETWEEN 8 AND 2048),
 ADD CONSTRAINT applications_base_url_shape CHECK(base_url='' OR (base_url ~ '^https?://[^[:space:]]+$' AND base_url !~ '[?#]' AND base_url !~ '^https?://[^/]*@' AND (base_url ~ '^https://' OR base_url ~ '^http://(localhost|127[.]0[.]0[.]1|\[::1\])([:/]|$)')));

-- Dedicated operation history survives response expiry. Never store raw request
-- bodies, application credentials or user tokens in reconciliation records.
CREATE TABLE iam.honeycomb_operations (
 operation_id uuid PRIMARY KEY,
 service_application_id uuid NOT NULL REFERENCES iam.applications(id),
 actor_principal_id uuid NOT NULL REFERENCES iam.principals(id),
 operation_kind text NOT NULL,
 resource_id text NOT NULL,
 environment_id uuid,
 idempotency_digest bytea NOT NULL CHECK (octet_length(idempotency_digest)=32),
 request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
 state text NOT NULL CHECK (state IN ('pending','accepted','rejected')),
 completed boolean NOT NULL DEFAULT false,
 iam_revision bigint,
 result jsonb NOT NULL DEFAULT '{}',
 response_ciphertext bytea,
 response_nonce bytea,
 response_key_version smallint,
 response_expires_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 UNIQUE NULLS NOT DISTINCT (service_application_id,environment_id,idempotency_digest)
);
ALTER TABLE iam.honeycomb_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.honeycomb_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY honeycomb_operation_actor ON iam.honeycomb_operations
 USING (actor_principal_id=iam_private.current_principal_id())
 WITH CHECK (actor_principal_id=iam_private.current_principal_id());

CREATE TABLE iam.honeycomb_management_events (
 event_id uuid PRIMARY KEY,
 operation_id uuid NOT NULL REFERENCES iam.honeycomb_operations(operation_id),
 service_application_id uuid NOT NULL REFERENCES iam.applications(id),
 resource_id text NOT NULL,
 environment_id uuid,
 revision bigint NOT NULL,
 event_type text NOT NULL,
 payload jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 delivered_at timestamptz,
 attempt_count integer NOT NULL DEFAULT 0,
 next_attempt_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 UNIQUE(operation_id,event_type,revision)
);
ALTER TABLE iam.honeycomb_management_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.honeycomb_management_events FORCE ROW LEVEL SECURITY;
CREATE POLICY honeycomb_event_actor ON iam.honeycomb_management_events
 USING (EXISTS(SELECT 1 FROM iam.honeycomb_operations operation WHERE operation.operation_id=honeycomb_management_events.operation_id))
 WITH CHECK (EXISTS(SELECT 1 FROM iam.honeycomb_operations operation WHERE operation.operation_id=honeycomb_management_events.operation_id));

CREATE FUNCTION iam_private.resolve_honeycomb_application(p_app_id text)
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam AS $$
 SELECT app.id FROM iam.applications app
 WHERE app.app_id=p_app_id;
$$;
REVOKE ALL ON FUNCTION iam_private.resolve_honeycomb_application(text) FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_operation_status(p_service uuid,p_operation uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam AS $$
 SELECT jsonb_build_object('operation_id',operation_id,'state',state,'completed',completed,'operation_kind',operation_kind,
 'resource_id',resource_id,'environment_id',environment_id,'iam_revision',iam_revision,
 'result',result,'created_at',created_at,'updated_at',updated_at)
 FROM iam.honeycomb_operations WHERE operation_id=p_operation AND service_application_id=p_service;
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_operation_status(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.honeycomb_application_record(p_service uuid,p_app_id text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT jsonb_build_object('app_id',app.app_id,'application_id',app.id,'org_id',org.org_id,
 'app_name',app.app_name,'app_logo',app.app_logo_uri,'base_url',NULLIF(app.base_url,''),
 'visibility',app.visibility,'availability',app.review_status,'iam_revision',app.version,
 'configuration_revision',app.honeycomb_configuration_revision,
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

DO $$ BEGIN
 IF to_regrole('silicon_iam_api') IS NOT NULL THEN
  GRANT EXECUTE ON FUNCTION iam_private.resolve_honeycomb_application(text),
   iam_private.honeycomb_operation_status(uuid,uuid),
   iam_private.honeycomb_application_record(uuid,text) TO silicon_iam_api;
 END IF;
END $$;

CREATE FUNCTION iam_private.honeycomb_scope_decision(p_app_id text,p_actor uuid,p_revision bigint,p_provider text,p_scopes text[],p_decision text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE app iam.applications%ROWTYPE; provider_id uuid; requested text; result bigint;
BEGIN
 IF p_actor IS DISTINCT FROM iam_private.current_principal_id() OR p_decision NOT IN ('approve','revoke')
  OR cardinality(p_scopes) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'scope_decision_forbidden' USING ERRCODE='42501'; END IF;
 IF p_provider IS NULL THEN
  IF NOT iam_private.has_platform_capability(p_actor,'applications.review') THEN RAISE EXCEPTION 'scope_reviewer_required' USING ERRCODE='42501'; END IF;
 ELSE
  SELECT id INTO provider_id FROM iam.applications WHERE app_id=p_provider AND deleted_at IS NULL FOR SHARE;
  IF provider_id IS NULL OR NOT iam_private.can_manage_application(provider_id,p_actor) THEN RAISE EXCEPTION 'scope_provider_required' USING ERRCODE='42501'; END IF;
 END IF;
 SELECT * INTO STRICT app FROM iam.applications WHERE app_id=p_app_id AND deleted_at IS NULL FOR UPDATE;
 IF app.version<>p_revision THEN RAISE EXCEPTION 'iam_revision_conflict' USING ERRCODE='40001'; END IF;
 FOREACH requested IN ARRAY p_scopes LOOP
  IF requested IS NULL OR NOT(requested=ANY(iam_private.application_scope_names(app.app_scope)))
   OR NOT EXISTS(SELECT 1 FROM iam_private.application_scope_catalog(p_provider) catalog
     WHERE catalog.scope=requested AND catalog.critical
      AND ((p_provider IS NULL AND catalog.app_id IS NULL) OR catalog.app_id=p_provider)) THEN
   RAISE EXCEPTION 'scope_not_requested_from_provider' USING ERRCODE='22023';
  END IF;
  UPDATE iam.application_approved_scopes SET revoked_at=transaction_timestamp(),revoked_by_carbon_id=p_actor
   WHERE application_id=app.id AND scope=requested AND revoked_at IS NULL;
  IF p_decision='approve' THEN
   INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id,approval_basis)
   VALUES(app.id,requested,p_actor,'provider_approval');
  ELSE
   UPDATE iam.access_tokens token SET revoked_at=transaction_timestamp(),revocation_reason='provider_scope_revoked'
   WHERE token.client_application_id=app.id AND token.revoked_at IS NULL AND EXISTS(
    SELECT 1 FROM iam.access_token_scopes granted WHERE granted.access_token_id=token.id AND granted.scope=requested);
  END IF;
 END LOOP;
 UPDATE iam.applications SET updated_at=transaction_timestamp() WHERE id=app.id RETURNING version INTO result;
 RETURN result;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_scope_decision(text,uuid,bigint,text,text[],text) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.honeycomb_scope_decision(text,uuid,bigint,text,text[],text) TO silicon_iam_api;
END IF; END $$;

-- Leasing is atomic and bounded; acknowledgements cannot finish a newer lease.
CREATE FUNCTION iam_private.claim_honeycomb_management_events(p_app_id text)
RETURNS TABLE(event_id uuid,attempt_count integer,envelope jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 WITH candidates AS (
 SELECT event.event_id FROM iam.honeycomb_management_events event JOIN iam.applications app ON app.id=event.service_application_id
 WHERE app.app_id=p_app_id AND event.delivered_at IS NULL AND event.next_attempt_at<=transaction_timestamp()
 ORDER BY event.created_at,event.event_id LIMIT 10 FOR UPDATE OF event SKIP LOCKED
 ), claimed AS (
 UPDATE iam.honeycomb_management_events event SET attempt_count=event.attempt_count+1,next_attempt_at=transaction_timestamp()+interval '2 minutes'
 FROM candidates WHERE event.event_id=candidates.event_id RETURNING event.*)
 SELECT event_id,attempt_count,jsonb_build_object('event_id',event_id,'operation_id',operation_id,'resource_id',resource_id,
 'environment_id',environment_id,'revision',revision,'event_type',event_type,'data',payload) FROM claimed;
$$;
CREATE FUNCTION iam_private.finish_honeycomb_management_event(p_event uuid,p_attempt integer,p_delivered boolean)
RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 UPDATE iam.honeycomb_management_events SET delivered_at=CASE WHEN p_delivered THEN transaction_timestamp() ELSE NULL END,
 next_attempt_at=transaction_timestamp()+least(3600,5*power(2,least(p_attempt,9))) * interval '1 second'
 WHERE event_id=p_event AND attempt_count=p_attempt AND delivered_at IS NULL;
$$;
CREATE FUNCTION iam_private.replay_honeycomb_management_event(p_service uuid,p_event uuid)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 WITH updated AS (UPDATE iam.honeycomb_management_events SET delivered_at=NULL,next_attempt_at=transaction_timestamp()
 WHERE event_id=p_event AND service_application_id=p_service RETURNING 1) SELECT EXISTS(SELECT 1 FROM updated);
$$;
CREATE FUNCTION iam_private.honeycomb_management_events(p_service uuid,p_after uuid)
RETURNS SETOF jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 SELECT jsonb_build_object('event_id',event_id,'operation_id',operation_id,'resource_id',resource_id,'environment_id',environment_id,
 'revision',revision,'event_type',event_type,'data',payload,'delivered_at',delivered_at,'attempt_count',attempt_count)
 FROM iam.honeycomb_management_events WHERE service_application_id=p_service AND (p_after IS NULL OR event_id>p_after) ORDER BY event_id LIMIT 100;
$$;
REVOKE ALL ON FUNCTION iam_private.claim_honeycomb_management_events(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.finish_honeycomb_management_event(uuid,integer,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.replay_honeycomb_management_event(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.honeycomb_management_events(uuid,uuid) FROM PUBLIC;
DO $$ BEGIN
 IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.replay_honeycomb_management_event(uuid,uuid),iam_private.honeycomb_management_events(uuid,uuid) TO silicon_iam_api;
 END IF;
 IF to_regrole('silicon_iam_worker') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.claim_honeycomb_management_events(text),iam_private.finish_honeycomb_management_event(uuid,integer,boolean) TO silicon_iam_worker;
 END IF;
END $$;

ALTER TABLE iam.application_bundles ADD COLUMN honeycomb_configuration_revision bigint NOT NULL DEFAULT 0 CHECK(honeycomb_configuration_revision>=0);

CREATE FUNCTION iam_private.honeycomb_bundle_revision(p_bundle text,p_revision bigint)
RETURNS TABLE(version bigint,configuration_revision bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE bundle iam.application_bundles%ROWTYPE;
BEGIN
 SELECT * INTO bundle FROM iam.application_bundles WHERE bundle_id=p_bundle FOR UPDATE;
 IF bundle.id IS NULL THEN RETURN; END IF;
 IF NOT iam_private.is_active_organization_owner_or_admin(bundle.organization_id,iam_private.current_principal_id()) THEN RAISE EXCEPTION 'bundle_manager_required' USING ERRCODE='42501'; END IF;
 IF p_revision IS NOT NULL THEN
  IF p_revision<=bundle.honeycomb_configuration_revision THEN RAISE EXCEPTION 'configuration_revision_conflict' USING ERRCODE='40001'; END IF;
  UPDATE iam.application_bundles SET honeycomb_configuration_revision=p_revision WHERE id=bundle.id RETURNING * INTO bundle;
 END IF;
 RETURN QUERY SELECT bundle.version,bundle.honeycomb_configuration_revision;
END $$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_bundle_revision(text,bigint) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.honeycomb_bundle_revision(text,bigint) TO silicon_iam_api; END IF; END $$;

CREATE FUNCTION iam_private.organization_iam_scope_allowed(p_org uuid, p_scope text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT CASE WHEN p_scope = ANY(ARRAY['organization.silicons.credentials.rotate', 'organization.sso.read', 'organization.sso.manage', 'organization.invitations.create', 'organization.silicons.create', 'organization.member_tags.update', 'organization.job_roles.update', 'organization.silicon_access.update', 'organization.trust.update', 'organization.admins.promote', 'organization.capabilities.update', 'organization.change_requests.decide', 'organizations.join']::text[]) THEN EXISTS (
   SELECT 1 FROM iam.organizations org
   WHERE org.id = p_org AND org.status = 'active' AND org.trusted_org
     AND p_scope = ANY(org.allowed_restricted_iam_scopes)
 ) ELSE true END
$$;
REVOKE ALL ON FUNCTION iam_private.organization_iam_scope_allowed(uuid,text) FROM PUBLIC;
CREATE FUNCTION iam_private.honeycomb_scope_catalog(p_service uuid,p_provider text,p_org text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(jsonb_build_object('scope',catalog.scope,'description',catalog.description,'critical',catalog.critical,
 'reviewer',CASE WHEN catalog.critical THEN CASE WHEN catalog.app_id IS NULL THEN 'iam:applications.review' ELSE catalog.app_id||':owner_or_admin' END END,
 'private_app_exemption',catalog.critical,'eligible',CASE WHEN p_org IS NULL THEN NULL WHEN catalog.app_id IS NOT NULL THEN true ELSE iam_private.organization_iam_scope_allowed((SELECT id FROM iam.organizations WHERE org_id=p_org),catalog.scope) END) ORDER BY catalog.scope)
 FROM iam_private.application_scope_catalog(p_provider) catalog WHERE (p_provider IS NOT NULL OR catalog.app_id IS NULL)),'[]'::jsonb),
 'bundle_eligible',CASE WHEN p_org IS NULL THEN NULL ELSE EXISTS(SELECT 1 FROM iam.organizations WHERE org_id=p_org AND status='active' AND trusted_org AND allow_bundled_applications) END)
 WHERE EXISTS(SELECT 1 FROM iam.applications WHERE id=p_service);
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_scope_catalog(uuid,text,text) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.honeycomb_scope_catalog(uuid,text,text) TO silicon_iam_api; END IF; END $$;

CREATE FUNCTION iam_private.honeycomb_bundle_record(p_service uuid,p_id text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 SELECT jsonb_build_object('bundle_id',bundle.bundle_id,'id',bundle.id,'org_id',org.org_id,
 'app_name',bundle.app_name,'app_logo',bundle.app_logo,'iam_revision',bundle.version,
 'configuration_revision',bundle.honeycomb_configuration_revision,'deleted',bundle.deleted_at IS NOT NULL,
 'app_ids',COALESCE((SELECT jsonb_agg(app.app_id ORDER BY member.position) FROM iam.application_bundle_members member
 JOIN iam.applications app ON app.id=member.application_id WHERE member.bundle_id=bundle.id),'[]'::jsonb))
 FROM iam.application_bundles bundle JOIN iam.organizations org ON org.id=bundle.organization_id
 WHERE bundle.bundle_id=p_id AND EXISTS(SELECT 1 FROM iam.applications WHERE id=p_service);
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_bundle_record(uuid,text) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.honeycomb_bundle_record(uuid,text) TO silicon_iam_api; END IF; END $$;
