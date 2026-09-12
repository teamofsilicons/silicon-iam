-- Official v1: declared authority, explicit user consent and independently reviewed critical scopes.
ALTER TABLE iam.organizations
    ADD COLUMN trusted_org boolean NOT NULL DEFAULT false,
    ADD COLUMN allow_bundled_applications boolean NOT NULL DEFAULT false,
    ADD COLUMN skip_application_consent boolean NOT NULL DEFAULT false;
ALTER TABLE iam.applications
    ADD COLUMN app_scope jsonb NOT NULL DEFAULT '{"iam":["self.identity.read","self.profile.read"],"external":[]}',
    ADD COLUMN webhook_scope text[] NOT NULL DEFAULT ARRAY['full'],
    ADD COLUMN obo_review_message text,
    ADD COLUMN testing_idle_days integer NOT NULL DEFAULT 30 CHECK (testing_idle_days BETWEEN 1 AND 36500),
    ADD CONSTRAINT applications_app_scope_object CHECK (jsonb_typeof(app_scope) = 'object'),
    ADD CONSTRAINT applications_webhook_scope_valid CHECK (cardinality(webhook_scope) > 0 AND webhook_scope <@ ARRAY['full','membership','updates','trust']::text[]),
    ADD CONSTRAINT applications_obo_review_message_length CHECK (char_length(obo_review_message) BETWEEN 1 AND 10000);
ALTER TABLE iam.application_obo_endpoints ADD COLUMN critical boolean NOT NULL DEFAULT false;
ALTER TABLE iam.access_token_scopes DROP CONSTRAINT access_token_scopes_scope_format;
ALTER TABLE iam.access_token_scopes ADD CONSTRAINT access_token_scopes_scope_format CHECK (scope ~ '^[a-z][a-z0-9_.:>\-]{0,255}$');
ALTER TABLE iam.oauth_scope_catalog DROP CONSTRAINT oauth_scope_catalog_format;
ALTER TABLE iam.oauth_scope_catalog ADD CONSTRAINT oauth_scope_catalog_format CHECK (scope ~ '^[a-z][a-z0-9_.:>\-]{0,255}$');
INSERT INTO iam.oauth_scope_catalog(scope,description,sensitive) VALUES
('self.identity.read','Your Carbon or Silicon ID and account type.',false),
('self.profile.read','Your name, photo, description and timezone.',false),
('self.email.read','Your verified email address.',false),
('self.phone.read','Your verified phone number.',false),
('self.organizations.read','Your selected organizations and their profiles.',false),
('self.membership.read','Your membership status and organization role.',false),
('self.capabilities.read','Your explicitly delegated organization capabilities.',false),
('self.job_role.read','Your descriptive job role.',false),
('self.tags.read','Your assigned tags.',false),
('self.silicon_access.read','Your first, extra and accessible Silicons.',false),
('self.hierarchy.read','Your own Silicon reporting relationship.',false),
('self.trust.read','Effective trust from your perspective.',false),
('directory.carbons.read','List, search and look up Carbons in selected organizations.',true),
('directory.silicons.read','List, search and look up Silicons in selected organizations.',true),
('directory.profiles.read','Other members names, photos, descriptions and timezones.',true),
('directory.memberships.read','Other members membership status and organization roles.',true),
('directory.capabilities.read','Other members delegated organization capabilities.',true),
('directory.job_roles.read','Other members descriptive job roles.',true),
('directory.tags.read','Other members tags and tag membership.',true),
('directory.silicon_access.read','Other Carbons first, extra and accessible Silicons.',true),
('directory.hierarchy.read','Silicon reporting relationships across selected organizations.',true),
('organization.tags.read','Complete organization tag catalogs.',true),
('organization.trust.read','Organization trust defaults, rules, overrides and matrices.',true),
('organization.invitations.read','Organization invitations and their details.',true),
('organization.governance.read','Role and tag requests, decisions and history.',true);

CREATE FUNCTION iam_private.application_scope_names(p_scope jsonb) RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
 SELECT ARRAY(SELECT value FROM (
 SELECT jsonb_array_elements_text(p_scope->'iam') AS value
 UNION SELECT 'obo:' || (item->>'app_id') || ':' || (item->>'endpoint_id')
 FROM jsonb_array_elements(p_scope->'external') item
 ) names ORDER BY value)
$$;
REVOKE ALL ON FUNCTION iam_private.application_scope_names(jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.application_scope_catalog(p_app_id text DEFAULT NULL)
RETURNS TABLE(scope text,description text,critical boolean,app_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT catalog.scope,catalog.description,catalog.sensitive,NULL::text
 FROM iam.oauth_scope_catalog catalog WHERE p_app_id IS NULL
 AND (catalog.scope LIKE 'self.%' OR catalog.scope LIKE 'directory.%' OR catalog.scope LIKE 'organization.%')
 UNION ALL
 SELECT 'obo:' || app.app_id || ':' || endpoint.endpoint_id,
 endpoint.endpoint_id || ' (' || endpoint.path || ')',endpoint.critical,app.app_id
 FROM iam.application_obo_endpoints endpoint JOIN iam.applications app ON app.id=endpoint.application_id
 WHERE app.deleted_at IS NULL AND app.review_status='verified' AND endpoint.status='active'
 AND (p_app_id IS NULL OR app.app_id=p_app_id)
$$;
REVOKE ALL ON FUNCTION iam_private.application_scope_catalog(text) FROM PUBLIC;

CREATE FUNCTION iam_private.configure_application_scopes(p_app uuid,p_scope jsonb,p_actor uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE names text[]; previous_status text;
BEGIN
 IF p_actor IS DISTINCT FROM iam_private.current_principal_id()
 OR NOT iam_private.can_manage_application(p_app,p_actor) THEN RAISE EXCEPTION 'scope_configuration_forbidden' USING ERRCODE='42501'; END IF;
 SELECT review_status INTO STRICT previous_status FROM iam.applications WHERE id=p_app FOR UPDATE;
 names:=iam_private.application_scope_names(p_scope);
 IF cardinality(names) NOT BETWEEN 1 AND 100 OR EXISTS (
 SELECT unnest(names) EXCEPT SELECT scope FROM iam_private.application_scope_catalog(NULL)
 ) THEN RAISE EXCEPTION 'invalid_application_scope' USING ERRCODE='22023'; END IF;
 INSERT INTO iam.oauth_scope_catalog(scope,description,sensitive)
 SELECT catalog.scope,catalog.description,catalog.critical FROM iam_private.application_scope_catalog(NULL) catalog
 WHERE catalog.scope=ANY(names) ON CONFLICT(scope) DO UPDATE SET description=EXCLUDED.description,sensitive=EXCLUDED.sensitive;
 INSERT INTO iam.application_requested_scopes(application_id,scope)
 SELECT p_app,unnest(names) ON CONFLICT DO NOTHING;
 UPDATE iam.application_approved_scopes SET revoked_at=transaction_timestamp(),revoked_by_carbon_id=p_actor
 WHERE application_id=p_app AND revoked_at IS NULL AND NOT(scope=ANY(names));
 UPDATE iam.access_tokens token SET revoked_at=transaction_timestamp(),revocation_reason='application_scope_revoked'
 WHERE token.client_application_id=p_app AND token.revoked_at IS NULL AND EXISTS (
 SELECT 1 FROM iam.access_token_scopes scope WHERE scope.access_token_id=token.id AND NOT(scope.scope=ANY(names)));
 INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id)
 SELECT p_app,catalog.scope,p_actor FROM iam_private.application_scope_catalog(NULL) catalog
 WHERE catalog.scope=ANY(names) AND NOT catalog.critical AND NOT EXISTS (
 SELECT 1 FROM iam.application_approved_scopes approved WHERE approved.application_id=p_app AND approved.scope=catalog.scope AND approved.revoked_at IS NULL);
 UPDATE iam.applications SET app_scope=p_scope,review_status=CASE
 WHEN previous_status='under_review' AND NOT EXISTS (
 SELECT unnest(names) EXCEPT SELECT scope FROM iam.application_approved_scopes WHERE application_id=p_app AND revoked_at IS NULL
 ) THEN 'verified' ELSE previous_status END WHERE id=p_app;
END $$;
REVOKE ALL ON FUNCTION iam_private.configure_application_scopes(uuid,jsonb,uuid) FROM PUBLIC;

-- The former blanket-grant entry point is retired instead of preserving an authority bypass.
CREATE OR REPLACE FUNCTION iam_private.grant_application_scope_catalogue(p_application_id uuid,p_approved_by_carbon_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
BEGIN
 PERFORM iam_private.configure_application_scopes(p_application_id,
 '{"iam":["self.identity.read","self.profile.read"],"external":[]}'::jsonb,p_approved_by_carbon_id);
END $$;
REVOKE ALL ON FUNCTION iam_private.grant_application_scope_catalogue(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.application_login_scope_policy(p_app uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE snapshot jsonb;
BEGIN
 PERFORM id FROM iam.applications WHERE id=p_app FOR SHARE;
 SELECT jsonb_build_object('scope_version',app.version,
 'consent_required',NOT (org.trusted_org AND org.skip_application_consent),
 'scopes',COALESCE((SELECT jsonb_agg(jsonb_build_object('scope',approved.scope,'description',catalog.description,'critical',catalog.critical,
 'app_id',CASE WHEN approved.scope LIKE 'obo:%' THEN split_part(approved.scope,':',2) END) ORDER BY approved.scope)
 FROM iam.application_approved_scopes approved JOIN iam_private.application_scope_catalog(NULL) catalog ON catalog.scope=approved.scope
 WHERE approved.application_id=app.id AND approved.revoked_at IS NULL),'[]'::jsonb))
 INTO snapshot FROM iam.applications app JOIN iam.organizations org ON org.id=app.organization_id
 WHERE app.id=p_app AND app.review_status='verified' AND app.deleted_at IS NULL;
 RETURN snapshot;
END $$;
REVOKE ALL ON FUNCTION iam_private.application_login_scope_policy(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.application_token_allows_external_scope(p_token uuid,p_audience uuid,p_endpoint text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT EXISTS(SELECT 1 FROM iam.access_tokens token
 JOIN iam.applications issuer ON issuer.id=token.client_application_id AND issuer.review_status='verified' AND issuer.deleted_at IS NULL
 JOIN iam.applications audience ON audience.id=p_audience AND audience.review_status='verified' AND audience.deleted_at IS NULL
 JOIN iam.application_obo_endpoints endpoint ON endpoint.application_id=audience.id AND endpoint.endpoint_id=p_endpoint AND endpoint.status='active'
 JOIN iam.access_token_scopes token_scope ON token_scope.access_token_id=token.id AND token_scope.scope='obo:'||audience.app_id||':'||endpoint.endpoint_id
 JOIN iam.application_approved_scopes approved ON approved.application_id=issuer.id AND approved.scope=token_scope.scope AND approved.revoked_at IS NULL
 JOIN iam.oauth_consent_grants consent ON consent.application_id=issuer.id AND consent.subject_principal_id=token.subject_principal_id
 AND consent.parent_authentication_session_id=token.authentication_session_id AND consent.status='active'
 JOIN iam.oauth_consent_grant_scopes granted ON granted.consent_grant_id=consent.id AND granted.scope=token_scope.scope
 JOIN iam.authentication_sessions session ON session.id=token.authentication_session_id AND session.status='active'
 AND session.absolute_expires_at>clock_timestamp() AND session.idle_expires_at>clock_timestamp()
 JOIN iam.principals subject ON subject.id=token.subject_principal_id AND subject.status='active' AND subject.auth_epoch=token.subject_auth_epoch
 WHERE token.id=p_token AND token.token_class='application_access' AND token.revoked_at IS NULL AND token.expires_at>clock_timestamp()
 AND token.audience_application_id=issuer.id AND token.audience=issuer.app_id
 AND (iam_private.current_principal_id()=token.subject_principal_id OR
 (iam_private.current_principal_id()=issuer.id AND iam_private.current_application_id()=issuer.id)))
$$;
REVOKE ALL ON FUNCTION iam_private.application_token_allows_external_scope(uuid,uuid,text) FROM PUBLIC;

CREATE TABLE iam.application_scope_requests (
 id uuid PRIMARY KEY,application_id uuid NOT NULL REFERENCES iam.applications(id),
 target_application_id uuid REFERENCES iam.applications(id),scopes text[] NOT NULL CHECK(cardinality(scopes)>0),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN('pending','approved','denied','superseded')),
 created_by_carbon_id uuid NOT NULL REFERENCES iam.carbons(id),
 version bigint NOT NULL DEFAULT 1,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);
CREATE UNIQUE INDEX application_scope_requests_pending ON iam.application_scope_requests(application_id,target_application_id) NULLS NOT DISTINCT WHERE status='pending';
CREATE INDEX application_scope_requests_inbox ON iam.application_scope_requests(target_application_id,status,created_at DESC,id);
CREATE TRIGGER application_scope_requests_version BEFORE UPDATE ON iam.application_scope_requests FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();
CREATE TABLE iam.application_scope_messages (
 id uuid PRIMARY KEY,request_id uuid NOT NULL REFERENCES iam.application_scope_requests(id),
 author_carbon_id uuid REFERENCES iam.carbons(id),message text NOT NULL CHECK(char_length(message) BETWEEN 1 AND 10000),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);
CREATE INDEX application_scope_messages_thread ON iam.application_scope_messages(request_id,created_at,id);
ALTER TABLE iam.application_scope_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.application_scope_messages ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION iam_private.can_review_application_scopes(p_target uuid,p_actor uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT p_actor=iam_private.current_principal_id() AND
 CASE WHEN p_target IS NULL THEN iam_private.has_platform_capability(p_actor,'applications.review')
 ELSE iam_private.can_manage_application(p_target,p_actor) END
$$;
REVOKE ALL ON FUNCTION iam_private.can_review_application_scopes(uuid,uuid) FROM PUBLIC;
CREATE FUNCTION iam_private.application_scope_request_view(p_id uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT jsonb_build_object('id',r.id,'app_id',app.app_id,'target_app_id',target.app_id,'scopes',r.scopes,'status',r.status,
 'version',r.version,'created_at',r.created_at,'updated_at',r.updated_at,
 'can_decide',iam_private.can_review_application_scopes(r.target_application_id,iam_private.current_principal_id()),
 'messages',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',m.id,'message',m.message,'created_at',m.created_at,
 'author',jsonb_build_object('principal_id',COALESCE(m.author_carbon_id,'00000000-0000-0000-0000-000000000000'::uuid),'type',CASE WHEN m.author_carbon_id IS NULL THEN 'system' ELSE 'carbon' END,
 'public_id',COALESCE(c.carbon_id,'iam'))) ORDER BY m.created_at,m.id)
 FROM iam.application_scope_messages m LEFT JOIN iam.carbons c ON c.id=m.author_carbon_id WHERE m.request_id=r.id),'[]'::jsonb))
 FROM iam.application_scope_requests r JOIN iam.applications app ON app.id=r.application_id
 LEFT JOIN iam.applications target ON target.id=r.target_application_id
 WHERE r.id=p_id AND
 (iam_private.can_manage_application(r.application_id,iam_private.current_principal_id()) OR iam_private.can_review_application_scopes(r.target_application_id,iam_private.current_principal_id()))
$$;
REVOKE ALL ON FUNCTION iam_private.application_scope_request_view(uuid) FROM PUBLIC;
CREATE POLICY application_scope_requests_read ON iam.application_scope_requests FOR SELECT USING (iam_private.application_scope_request_view(id) IS NOT NULL);
CREATE POLICY application_scope_messages_read ON iam.application_scope_messages FOR SELECT USING (iam_private.application_scope_request_view(request_id) IS NOT NULL);

ALTER TABLE iam.notification_jobs DROP CONSTRAINT notification_jobs_kind;
ALTER TABLE iam.notification_jobs ADD CONSTRAINT notification_jobs_kind CHECK(notification_kind IN('invitation','security_notice','application_scope_review'));
CREATE FUNCTION iam_private.enqueue_application_scope_notice(p_request uuid,p_message uuid,p_ack boolean DEFAULT false)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
BEGIN
 INSERT INTO iam.notification_jobs(id,notification_kind,provider,recipient_contact_id,recipient_contact_kind,template_id,context_type,context_id)
 SELECT gen_random_uuid(),'application_scope_review','postmark',contact.id,'email','application.scope_review','application_scope_message',p_message
 FROM iam.application_scope_requests r JOIN iam.applications app ON app.id=r.application_id
 LEFT JOIN iam.applications target ON target.id=r.target_application_id
 JOIN iam.carbon_contacts contact ON contact.kind='email' AND contact.status='active' AND contact.is_primary
 JOIN iam.principals principal ON principal.id=contact.carbon_id AND principal.status='active'
 WHERE r.id=p_request AND (
 (iam_private.is_active_organization_owner_or_admin(app.organization_id,contact.carbon_id) AND
 (p_ack OR NOT iam_private.can_manage_application(app.id,iam_private.current_principal_id()))) OR
 ((p_ack OR iam_private.can_manage_application(app.id,iam_private.current_principal_id())) AND
 ((target.id IS NOT NULL AND iam_private.is_active_organization_owner_or_admin(target.organization_id,contact.carbon_id)) OR
 (target.id IS NULL AND iam_private.has_platform_capability(contact.carbon_id,'applications.review')))))
 ON CONFLICT DO NOTHING;
END $$;
REVOKE ALL ON FUNCTION iam_private.enqueue_application_scope_notice(uuid,uuid,boolean) FROM PUBLIC;

CREATE FUNCTION iam_private.submit_application_scope_requests(p_app uuid,p_actor uuid,p_message text)
RETURNS uuid[] LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE grouped record; request_id uuid; message_id uuid; request_ids uuid[]:='{}'; instruction text;
BEGIN
 IF p_actor IS DISTINCT FROM iam_private.current_principal_id()
 OR NOT iam_private.can_manage_application(p_app,p_actor) THEN RAISE EXCEPTION 'scope_request_forbidden' USING ERRCODE='42501'; END IF;
 PERFORM id FROM iam.applications WHERE id=p_app FOR UPDATE;
 UPDATE iam.application_scope_requests SET status='superseded' WHERE application_id=p_app AND status='pending';
 FOR grouped IN SELECT target.id AS target_id,array_agg(catalog.scope ORDER BY catalog.scope) AS scopes
 FROM iam.applications app CROSS JOIN LATERAL unnest(iam_private.application_scope_names(app.app_scope)) names(scope)
 JOIN iam_private.application_scope_catalog(NULL) catalog ON catalog.scope=names.scope AND catalog.critical
 LEFT JOIN iam.applications target ON catalog.scope LIKE 'obo:%' AND target.app_id=split_part(catalog.scope,':',2)
 WHERE app.id=p_app AND NOT EXISTS(SELECT 1 FROM iam.application_approved_scopes approved WHERE approved.application_id=p_app AND approved.scope=catalog.scope AND approved.revoked_at IS NULL)
 GROUP BY target.id LOOP
 request_id:=gen_random_uuid(); message_id:=gen_random_uuid();
 INSERT INTO iam.application_scope_requests(id,application_id,target_application_id,scopes,created_by_carbon_id)
 VALUES(request_id,p_app,grouped.target_id,grouped.scopes,p_actor);
 instruction:=NULL;
 IF grouped.target_id IS NOT NULL THEN SELECT obo_review_message INTO instruction FROM iam.applications WHERE id=grouped.target_id; END IF;
 instruction:=COALESCE(instruction,'Define the need of each and every one of the critical scopes, why you wanna use them and what''s the exact purpose they are gonna serve your application. Also give a detailed description of what exactly is it that you are building.');
 INSERT INTO iam.application_scope_messages(id,request_id,author_carbon_id,message) VALUES(gen_random_uuid(),request_id,NULL,instruction),(message_id,request_id,p_actor,p_message);
 PERFORM iam_private.enqueue_application_scope_notice(request_id,message_id,true);
 request_ids:=array_append(request_ids,request_id);
 END LOOP;
 RETURN request_ids;
END $$;
REVOKE ALL ON FUNCTION iam_private.submit_application_scope_requests(uuid,uuid,text) FROM PUBLIC;

CREATE FUNCTION iam_private.mutate_application_scope_request(p_id uuid,p_actor uuid,p_version bigint,p_action text,p_message text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE request iam.application_scope_requests; message_id uuid:=gen_random_uuid(); names text[];
BEGIN
 IF iam_private.application_scope_request_view(p_id) IS NULL OR p_actor IS DISTINCT FROM iam_private.current_principal_id()
 THEN RAISE EXCEPTION 'scope_request_forbidden' USING ERRCODE='42501'; END IF;
 -- Always take application locks before request locks, matching submission.
 PERFORM app.id FROM iam.applications app JOIN iam.application_scope_requests r ON r.application_id=app.id WHERE r.id=p_id FOR UPDATE OF app;
 SELECT * INTO STRICT request FROM iam.application_scope_requests WHERE id=p_id FOR UPDATE;
 IF request.version<>p_version THEN RAISE EXCEPTION 'scope_request_version' USING ERRCODE='40001'; END IF;
 IF p_action NOT IN('message','approve','deny') OR (p_action<>'message' AND request.status<>'pending') THEN RAISE EXCEPTION 'scope_request_state' USING ERRCODE='22023'; END IF;
 IF p_action<>'message' THEN
 IF NOT iam_private.can_review_application_scopes(request.target_application_id,p_actor) THEN RAISE EXCEPTION 'scope_review_forbidden' USING ERRCODE='42501'; END IF;
 SELECT iam_private.application_scope_names(app_scope) INTO names FROM iam.applications WHERE id=request.application_id;
 IF NOT(request.scopes<@names) THEN RAISE EXCEPTION 'scope_request_superseded' USING ERRCODE='22023'; END IF;
 IF p_action='approve' THEN
 INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id)
 SELECT request.application_id,names.scope,p_actor FROM unnest(request.scopes) AS names(scope) WHERE NOT EXISTS(
 SELECT 1 FROM iam.application_approved_scopes approved WHERE approved.application_id=request.application_id AND approved.scope=names.scope AND approved.revoked_at IS NULL);
 END IF;
 UPDATE iam.application_scope_requests SET status=CASE WHEN p_action='approve' THEN 'approved' ELSE 'denied' END WHERE id=p_id;
 IF p_action='approve' THEN
 UPDATE iam.applications app SET review_status=CASE WHEN app.review_status='under_review' AND NOT EXISTS(
 SELECT unnest(names) EXCEPT SELECT scope FROM iam.application_approved_scopes WHERE application_id=app.id AND revoked_at IS NULL
 ) THEN 'verified' ELSE app.review_status END WHERE app.id=request.application_id;
 END IF;
 ELSE UPDATE iam.application_scope_requests SET updated_at=transaction_timestamp() WHERE id=p_id;
 END IF;
 INSERT INTO iam.application_scope_messages(id,request_id,author_carbon_id,message) VALUES(message_id,p_id,p_actor,p_message);
 PERFORM iam_private.enqueue_application_scope_notice(p_id,message_id,false);
 RETURN iam_private.application_scope_request_view(p_id);
END $$;
REVOKE ALL ON FUNCTION iam_private.mutate_application_scope_request(uuid,uuid,bigint,text,text) FROM PUBLIC;

CREATE FUNCTION iam_private.get_worker_application_scope_notice(p_job uuid,p_lease text)
RETURNS TABLE(app_id text,request_id uuid,message text,status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT app.app_id,r.id,m.message,r.status FROM iam.notification_jobs job
 JOIN iam.application_scope_messages m ON m.id=job.context_id
 JOIN iam.application_scope_requests r ON r.id=m.request_id
 JOIN iam.applications app ON app.id=r.application_id
 WHERE job.id=p_job AND job.notification_kind='application_scope_review' AND job.status='processing'
 AND job.lease_owner=p_lease AND job.lease_expires_at>clock_timestamp()
$$;
REVOKE ALL ON FUNCTION iam_private.get_worker_application_scope_notice(uuid,text) FROM PUBLIC;

CREATE FUNCTION iam_private.invalidate_upgraded_obo_endpoint_scope()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE scope_name text;
BEGIN
 IF NEW.critical AND NOT OLD.critical THEN
 SELECT 'obo:'||app_id||':'||NEW.endpoint_id INTO scope_name FROM iam.applications WHERE id=NEW.application_id;
 UPDATE iam.application_approved_scopes approved SET revoked_at=transaction_timestamp(),revoked_by_carbon_id=iam_private.current_principal_id()
 WHERE approved.scope=scope_name AND approved.revoked_at IS NULL;
 UPDATE iam.access_tokens token SET revoked_at=transaction_timestamp(),revocation_reason='obo_endpoint_became_critical'
 WHERE token.revoked_at IS NULL AND EXISTS(SELECT 1 FROM iam.access_token_scopes s WHERE s.access_token_id=token.id AND s.scope=scope_name);
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam_private.invalidate_upgraded_obo_endpoint_scope() FROM PUBLIC;
CREATE TRIGGER application_obo_endpoint_scope_upgrade AFTER UPDATE OF critical ON iam.application_obo_endpoints
FOR EACH ROW EXECUTE FUNCTION iam_private.invalidate_upgraded_obo_endpoint_scope();

CREATE FUNCTION iam_private.application_scope_request_context(p_request uuid)
RETURNS TABLE(application_id uuid,organization_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT app.id,app.organization_id FROM iam.application_scope_requests request JOIN iam.applications app ON app.id=request.application_id
 WHERE request.id=p_request AND iam_private.application_scope_request_view(p_request) IS NOT NULL
$$;
REVOKE ALL ON FUNCTION iam_private.application_scope_request_context(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.application_webhook_accepts_event(p_endpoint uuid,p_event text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT EXISTS(SELECT 1 FROM iam.application_webhook_endpoints endpoint JOIN iam.applications app ON app.id=endpoint.application_id
 WHERE endpoint.id=p_endpoint AND (
 p_event='session.logout' OR p_event LIKE 'application.%' OR 'full'=ANY(app.webhook_scope) OR
 CASE WHEN p_event LIKE '%trust%' THEN 'trust'
 WHEN p_event LIKE '%.membership.created.%' OR p_event LIKE '%.membership.removed.%' OR p_event LIKE '%.membership.reactivated.%'
 OR p_event LIKE '%.silicon.created.%' OR p_event LIKE '%.silicon.removed.%' THEN 'membership'
 ELSE 'updates' END =ANY(app.webhook_scope)))
$$;
REVOKE ALL ON FUNCTION iam_private.application_webhook_accepts_event(uuid,text) FROM PUBLIC;
