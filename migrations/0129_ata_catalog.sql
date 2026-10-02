-- ATA definitions never confer user delegation authority. Managed only through
-- the authenticated Honeycomb configuration transaction.
CREATE TABLE iam.application_ata_endpoints (
    application_id text NOT NULL,
    endpoint_id text NOT NULL CHECK(endpoint_id ~ '^[a-z0-9_.-]{1,128}$'),
    definition jsonb NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(application_id,endpoint_id),
    CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=32768),
    CHECK(definition->>'endpoint_id'=endpoint_id),
    CHECK(char_length(definition->>'name') BETWEEN 1 AND 160),
    CHECK(char_length(definition->>'description') BETWEEN 1 AND 4000),
    CHECK(jsonb_typeof(definition->'downstream')='array' AND jsonb_array_length(definition->'downstream')<=16)
);
CREATE UNIQUE INDEX application_ata_endpoint_path ON iam.application_ata_endpoints(application_id,(definition->>'path'));
ALTER TABLE iam.application_ata_endpoints ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON iam.application_ata_endpoints FROM PUBLIC;

DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.applications'::regclass AND attname='testing_environment_id' AND NOT attisdropped) THEN
  ALTER TABLE iam.application_ata_endpoints ADD COLUMN testing_environment_id uuid NOT NULL DEFAULT iam_private.current_testing_environment_id();
  ALTER TABLE iam.application_ata_endpoints DROP CONSTRAINT application_ata_endpoints_pkey;
  ALTER TABLE iam.application_ata_endpoints ADD PRIMARY KEY(testing_environment_id,application_id,endpoint_id);
  DROP INDEX iam.application_ata_endpoint_path;
  CREATE UNIQUE INDEX application_ata_endpoint_path ON iam.application_ata_endpoints(testing_environment_id,application_id,(definition->>'path'));
  ALTER TABLE iam.application_ata_endpoints ADD FOREIGN KEY(testing_environment_id,application_id) REFERENCES iam.applications(testing_environment_id,id) ON DELETE RESTRICT;
  CREATE POLICY testing_environment_isolation ON iam.application_ata_endpoints AS RESTRICTIVE USING(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id()) WITH CHECK(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id());
  ALTER TABLE iam.application_ata_endpoints FORCE ROW LEVEL SECURITY;
 ELSE
  ALTER TABLE iam.application_ata_endpoints ADD FOREIGN KEY(application_id) REFERENCES iam.applications(id) ON DELETE RESTRICT;
 END IF;
END $$;

CREATE FUNCTION iam_private.configure_application_ata_endpoints(p_app text,p_definitions jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE item jsonb;
BEGIN
 IF NOT iam_private.can_manage_application(p_app,iam_private.current_principal_id())
 THEN RAISE EXCEPTION 'ata_configuration_forbidden' USING ERRCODE='42501'; END IF;
 IF jsonb_typeof(p_definitions)<>'array' OR jsonb_array_length(p_definitions)>100
 THEN RAISE EXCEPTION 'invalid_ata_endpoints' USING ERRCODE='22023'; END IF;
 UPDATE iam.application_ata_endpoints SET active=false,version=version+1,updated_at=transaction_timestamp()
 WHERE application_id=p_app AND active AND endpoint_id NOT IN(SELECT value->>'endpoint_id' FROM jsonb_array_elements(p_definitions));
 FOR item IN SELECT value FROM jsonb_array_elements(p_definitions) LOOP
  IF EXISTS(SELECT 1 FROM iam.application_ata_endpoints WHERE application_id=p_app
    AND endpoint_id=item->>'endpoint_id' AND definition->>'path' IS DISTINCT FROM item->>'path')
  THEN RAISE EXCEPTION 'ata_endpoint_path_immutable' USING ERRCODE='22023'; END IF;
  UPDATE iam.application_ata_endpoints
  SET definition=item,active=COALESCE((item->>'enabled')::boolean,true),
      version=version+CASE WHEN definition IS DISTINCT FROM item OR active IS DISTINCT FROM COALESCE((item->>'enabled')::boolean,true) THEN 1 ELSE 0 END,
      updated_at=transaction_timestamp()
  WHERE application_id=p_app AND endpoint_id=item->>'endpoint_id';
  IF NOT FOUND THEN
   INSERT INTO iam.application_ata_endpoints(application_id,endpoint_id,definition,active)
   VALUES(p_app,item->>'endpoint_id',item,COALESCE((item->>'enabled')::boolean,true));
  END IF;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION iam_private.configure_application_ata_endpoints(text,jsonb) FROM PUBLIC;

CREATE FUNCTION iam_private.discover_application_ata_endpoints(p_app_id text)
RETURNS SETOF jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT jsonb_build_object('application',jsonb_build_object('app_id',app.app_id,'org_id',org.org_id),
   'endpoints',COALESCE((SELECT jsonb_agg(endpoint.definition||jsonb_build_object(
    'ata_id','['||app.app_id||':ata:'||endpoint.endpoint_id||']','version',endpoint.version) ORDER BY endpoint.endpoint_id)
    FROM iam.application_ata_endpoints endpoint WHERE endpoint.application_id=app.id AND endpoint.active),'[]'::jsonb))
 FROM iam.applications app JOIN iam.principals principal ON principal.id=app.id AND principal.status='active'
 JOIN iam.organizations org ON org.id=app.organization_id AND org.status='active'
 WHERE app.app_id=p_app_id AND app.review_status='verified' AND app.deleted_at IS NULL
 AND iam_private.application_is_discoverable(app.id,NULL)
 AND iam_private.current_application_id()=iam_private.current_principal_id()
 AND EXISTS(SELECT 1 FROM iam.applications caller JOIN iam.principals identity ON identity.id=caller.id AND identity.status='active'
   WHERE caller.id=iam_private.current_application_id() AND caller.review_status='verified' AND caller.deleted_at IS NULL);
$$;
REVOKE ALL ON FUNCTION iam_private.discover_application_ata_endpoints(text) FROM PUBLIC;

-- Snapshot includes the complete recursive authority, sorted deterministically.
-- Rebuilding before mint/verification makes withdrawn or expanded graphs deny
-- existing authority instead of silently granting additional endpoints.
CREATE FUNCTION iam_private.application_ata_graph(p_origin text,p_roots jsonb)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE queue jsonb:=p_roots; item jsonb; entry jsonb; dep jsonb; graph jsonb:='[]';
 visited text[]:='{}'; trail text[]; key text; origin_org uuid; provider iam.applications%ROWTYPE;
 endpoint iam.application_ata_endpoints%ROWTYPE; provider_epoch bigint; remaining jsonb; reduced jsonb;
BEGIN
 IF p_origin IS DISTINCT FROM iam_private.current_application_id()
   AND NOT iam_private.can_manage_application(p_origin,iam_private.current_principal_id())
 THEN RAISE EXCEPTION 'ata_graph_forbidden' USING ERRCODE='42501'; END IF;
 SELECT organization_id INTO origin_org FROM iam.applications a JOIN iam.principals p ON p.id=a.id
 WHERE a.id=p_origin AND a.review_status='verified' AND a.deleted_at IS NULL AND p.status='active';
 IF origin_org IS NULL OR jsonb_typeof(p_roots)<>'array' OR jsonb_array_length(p_roots) NOT BETWEEN 1 AND 64
 THEN RETURN NULL; END IF;
 WHILE jsonb_array_length(queue)>0 LOOP
  item:=queue->0; queue:=queue-0;
  key:=(item->>'audience')||':'||(item->>'endpoint_id');
  SELECT COALESCE(array_agg(value),'{}') INTO trail FROM jsonb_array_elements_text(COALESCE(item->'trail','[]'));
  IF key IS NULL OR key=ANY(trail) OR cardinality(trail)>16 THEN RETURN NULL; END IF;
  IF key=ANY(visited) THEN CONTINUE; END IF;
  visited:=array_append(visited,key);
  IF cardinality(visited)>64 THEN RETURN NULL; END IF;
  SELECT a.* INTO provider FROM iam.applications a JOIN iam.principals p ON p.id=a.id
   JOIN iam.organizations o ON o.id=a.organization_id AND o.status='active'
   WHERE a.app_id=item->>'audience' AND a.review_status='verified' AND a.deleted_at IS NULL AND p.status='active'
    AND (a.visibility='public' OR a.organization_id=origin_org);
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT * INTO endpoint FROM iam.application_ata_endpoints WHERE application_id=provider.id AND endpoint_id=item->>'endpoint_id' AND active;
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT auth_epoch INTO provider_epoch FROM iam.principals WHERE id=provider.id;
  entry:=endpoint.definition||jsonb_build_object('app_id',provider.app_id,'application_id',provider.id,
    'ata_id','['||provider.app_id||':ata:'||endpoint.endpoint_id||']','version',endpoint.version,'auth_epoch',provider_epoch);
  graph:=graph||jsonb_build_array(entry);
  FOR dep IN SELECT value FROM jsonb_array_elements(endpoint.definition->'downstream') LOOP
   queue:=queue||jsonb_build_array(dep||jsonb_build_object('trail',array_append(trail,key)));
  END LOOP;
 END LOOP;
 -- Remove sinks repeatedly. A nonempty fixed point contains a cycle, including
 -- cycles reached from several roots whose traversal reused visited nodes.
 remaining:=graph;
 WHILE jsonb_array_length(remaining)>0 LOOP
  SELECT COALESCE(jsonb_agg(node.value),'[]'::jsonb) INTO reduced
  FROM jsonb_array_elements(remaining) node
  WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(node.value->'downstream') dep
    JOIN jsonb_array_elements(remaining) target
    ON target.value->>'app_id'=dep.value->>'audience' AND target.value->>'endpoint_id'=dep.value->>'endpoint_id');
  IF reduced=remaining THEN RETURN NULL; END IF;
  remaining:=reduced;
 END LOOP;
 SELECT jsonb_agg(value ORDER BY value->>'app_id',value->>'endpoint_id') INTO graph FROM jsonb_array_elements(graph);
 RETURN graph;
END $$;
REVOKE ALL ON FUNCTION iam_private.application_ata_graph(text,jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.honeycomb_application_record(p_service text, p_app_id text)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
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
   'metadata',metadata_definition,'critical',critical,'ttl_seconds',ttl_seconds,
   'name',name,'description',description,'note_to_user',note_to_user,'additional_warnings',additional_warnings)
   || CASE WHEN downstream='[]'::jsonb THEN '{}'::jsonb ELSE jsonb_build_object('downstream',downstream) END
   || CASE WHEN downstream_ttl_seconds IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('downstream_ttl_seconds',downstream_ttl_seconds) END
   ORDER BY endpoint_id)
   FROM iam.application_obo_endpoints WHERE application_id=app.id AND status='active'),'[]'::jsonb),
 'ata_endpoints',COALESCE((SELECT jsonb_agg(definition ORDER BY endpoint_id) FROM iam.application_ata_endpoints WHERE application_id=app.id AND active),'[]'::jsonb),
 'credential_version',(SELECT max(secret_version) FROM iam.application_secrets WHERE application_id=app.id AND status='active'),
 'testing_idle_days',app.testing_idle_days)
 FROM iam.applications app JOIN iam.organizations org ON org.id=app.organization_id
 WHERE app.app_id=p_app_id AND EXISTS(SELECT 1 FROM iam.applications service WHERE service.id=p_service);
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_application_record(text, text) FROM PUBLIC;
