-- Canonical, immutable Carbon, Silicon, Application and Service IDs become
-- the database identity keys. Organization, membership and resource UUIDs stay.
-- This migration is transactional: no old-to-new identity lookup survives it.
SET LOCAL check_function_bodies = false;
-- A production migrator is a table owner, not a superuser or BYPASSRLS role.
-- Testing tables also FORCE RLS. Read every source row before removing any
-- policy, retaining the original flags for restoration in this transaction.
-- ALTER TABLE holds its exclusive lock until commit, so no other transaction
-- can observe the temporary suspension of row security.
CREATE TEMP TABLE identity_row_security ON COMMIT DROP AS
SELECT oid AS relation_id,relrowsecurity,relforcerowsecurity
FROM pg_class
WHERE relnamespace IN ('iam'::regnamespace,'iam_private'::regnamespace)
 AND relkind IN ('r','p');
DO $$ DECLARE item record; BEGIN
 FOR item IN SELECT * FROM identity_row_security WHERE relrowsecurity ORDER BY relation_id LOOP
  EXECUTE format('ALTER TABLE ONLY %s DISABLE ROW LEVEL SECURITY',item.relation_id::regclass);
 END LOOP;
END $$;
CREATE TEMP TABLE identity_key_map(old_id uuid PRIMARY KEY,new_id text NOT NULL) ON COMMIT DROP;
INSERT INTO identity_key_map
SELECT principal.id, CASE principal.kind
 WHEN 'carbon' THEN carbon.carbon_id WHEN 'silicon' THEN silicon.global_silicon_id
 WHEN 'application' THEN application.app_id WHEN 'service' THEN 'service/'||service.service_id END
FROM iam.principals principal
LEFT JOIN iam.carbons carbon ON carbon.id=principal.id
LEFT JOIN iam.silicons silicon ON silicon.id=principal.id
LEFT JOIN iam.applications application ON application.id=principal.id
LEFT JOIN iam.service_principals service ON service.id=principal.id;
CREATE FUNCTION pg_temp.identity_key(value uuid) RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE result text;
BEGIN
 IF value IS NULL THEN RETURN NULL; END IF;
 SELECT new_id INTO STRICT result FROM pg_temp.identity_key_map WHERE old_id=value;
 RETURN result;
END $$;
CREATE FUNCTION pg_temp.resource_key(value uuid,resource_type text) RETURNS text LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN resource_type IN ('carbon','silicon','application','service','principal')
  THEN COALESCE((SELECT new_id FROM pg_temp.identity_key_map WHERE old_id=value),value::text)
  ELSE value::text END
$$;
CREATE TEMP TABLE identity_functions ON COMMIT DROP AS
SELECT proname,pg_get_functiondef(oid) AS definition,pg_get_userbyid(proowner) AS owner,proacl,
       obj_description(oid,'pg_proc') AS description
FROM pg_proc WHERE pronamespace='iam_private'::regnamespace;
CREATE TEMP TABLE identity_changed_columns ON COMMIT DROP AS
SELECT attrelid,attnum FROM pg_attribute
WHERE attrelid IN(SELECT oid FROM pg_class WHERE relnamespace IN('iam'::regnamespace,'iam_private'::regnamespace))
 AND atttypid='uuid'::regtype AND NOT attisdropped;
CREATE TEMP TABLE identity_defaults ON COMMIT DROP AS
SELECT adrelid::regclass::text AS relation,attname,pg_get_expr(adbin,adrelid) AS definition
FROM pg_attrdef JOIN pg_attribute ON attrelid=adrelid AND attnum=adnum
WHERE attgenerated='' AND attrelid IN(SELECT oid FROM pg_class WHERE relnamespace IN('iam'::regnamespace,'iam_private'::regnamespace));
CREATE TEMP TABLE identity_constraints ON COMMIT DROP AS
SELECT conrelid,confrelid,conkey,confkey,conrelid::regclass::text AS relation,conname,contype,pg_get_constraintdef(oid) AS definition
FROM pg_constraint WHERE connamespace IN ('iam'::regnamespace,'iam_private'::regnamespace)
 AND contype<>'t' AND conparentid=0 AND conislocal;
CREATE TEMP TABLE identity_triggers ON COMMIT DROP AS
SELECT tgrelid::regclass::text AS relation,tgname,pg_get_triggerdef(oid) AS definition,tgenabled
FROM pg_trigger WHERE NOT tgisinternal AND tgparentid=0
 AND tgrelid IN (SELECT oid FROM pg_class WHERE relnamespace IN ('iam'::regnamespace,'iam_private'::regnamespace));
CREATE TEMP TABLE identity_policies ON COMMIT DROP AS
SELECT schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check
FROM pg_policies WHERE schemaname IN ('iam','iam_private');
CREATE TEMP TABLE identity_views ON COMMIT DROP AS
SELECT c.oid::regclass::text AS relation,pg_get_viewdef(c.oid) AS definition,c.reloptions,c.relacl,pg_get_userbyid(c.relowner) AS owner
FROM pg_class c WHERE c.relnamespace IN ('iam'::regnamespace,'iam_private'::regnamespace) AND c.relkind='v';
-- PostgreSQL requires the destination owner to have schema CREATE during an
-- ownership transfer. Restricted testing definers intentionally lack it.
-- Record only missing privileges, grant them for reconstruction, then revoke
-- precisely those grants after all original owners have been restored.
CREATE TEMP TABLE identity_owner_schema_grants ON COMMIT DROP AS
SELECT DISTINCT namespace,owner FROM (
 SELECT 'iam_private'::text AS namespace,owner FROM identity_functions
 UNION
 SELECT n.nspname,pg_get_userbyid(c.relowner)
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE c.relnamespace IN ('iam'::regnamespace,'iam_private'::regnamespace) AND c.relkind='v'
) owners WHERE NOT has_schema_privilege(owner,namespace,'CREATE');
DO $$ DECLARE item record; BEGIN
 FOR item IN SELECT * FROM identity_owner_schema_grants LOOP
  EXECUTE format('GRANT CREATE ON SCHEMA %I TO %I',item.namespace,item.owner);
 END LOOP;
END $$;
CREATE TEMP TABLE identity_indexes ON COMMIT DROP AS
SELECT schemaname,indexname,indexdef,index_entry.indrelid,index_entry.indkey FROM pg_indexes JOIN pg_index index_entry ON index_entry.indexrelid=(quote_ident(schemaname)||'.'||quote_ident(indexname))::regclass
WHERE schemaname IN ('iam','iam_private') AND NOT (SELECT relispartition FROM pg_class WHERE oid=index_entry.indexrelid) AND NOT EXISTS
 (SELECT 1 FROM pg_constraint WHERE conindid=(quote_ident(schemaname)||'.'||quote_ident(indexname))::regclass);
DO $$ DECLARE item record; BEGIN
 FOR item IN SELECT * FROM identity_triggers LOOP EXECUTE format('DROP TRIGGER %I ON %s',item.tgname,item.relation); END LOOP;
 FOR item IN SELECT * FROM identity_policies LOOP EXECUTE format('DROP POLICY %I ON %I.%I',item.policyname,item.schemaname,item.tablename); END LOOP;
 FOR item IN SELECT * FROM identity_views LOOP EXECUTE format('DROP VIEW %s',item.relation); END LOOP;
 FOR item IN SELECT * FROM identity_constraints ORDER BY (contype='f') DESC LOOP
  EXECUTE format('ALTER TABLE %s DROP CONSTRAINT IF EXISTS %I CASCADE',item.relation,item.conname);
 END LOOP;
 FOR item IN SELECT * FROM identity_indexes LOOP EXECUTE format('DROP INDEX IF EXISTS %I.%I',item.schemaname,item.indexname); END LOOP;
 FOR item IN SELECT oid::regprocedure::text AS signature FROM pg_proc WHERE pronamespace='iam_private'::regnamespace LOOP
  EXECUTE format('DROP FUNCTION IF EXISTS %s CASCADE',item.signature);
 END LOOP;
END $$;
-- These bytes are authenticated by the legacy encryption context. This is
-- cryptographic metadata only; it is not an alternate identity or lookup key.
ALTER TABLE iam.applications ADD COLUMN encryption_context_id uuid;
UPDATE iam.applications SET encryption_context_id=id;
DO $$ DECLARE relation text; BEGIN
 FOREACH relation IN ARRAY ARRAY['iam_private.test_application_selectors','iam_private.honeycomb_testing_pending_apps','iam_private.honeycomb_testing_source_snapshots'] LOOP
  IF to_regclass(relation) IS NOT NULL THEN EXECUTE format('ALTER TABLE %s ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id)',relation); END IF;
 END LOOP;
END $$;
ALTER TABLE iam.application_testing_environments ALTER COLUMN target_application_id TYPE text USING pg_temp.identity_key(source_application_id);
ALTER TABLE iam.testing_application_imports ALTER COLUMN source_application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.access_tokens ALTER COLUMN audience_application_id TYPE text USING pg_temp.identity_key(audience_application_id);
ALTER TABLE iam.access_tokens ALTER COLUMN client_application_id TYPE text USING pg_temp.identity_key(client_application_id);
ALTER TABLE iam.access_tokens ALTER COLUMN subject_principal_id TYPE text USING pg_temp.identity_key(subject_principal_id);
ALTER TABLE iam.application_approved_scopes ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.application_approved_scopes ALTER COLUMN approved_by_carbon_id TYPE text USING pg_temp.identity_key(approved_by_carbon_id);
ALTER TABLE iam.application_approved_scopes ALTER COLUMN revoked_by_carbon_id TYPE text USING pg_temp.identity_key(revoked_by_carbon_id);
ALTER TABLE iam.application_bundle_members ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.application_bundles ALTER COLUMN created_by_carbon_id TYPE text USING pg_temp.identity_key(created_by_carbon_id);
ALTER TABLE iam.application_obo_endpoints ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.application_requested_scopes ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.application_reviews ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.application_reviews ALTER COLUMN reviewer_carbon_id TYPE text USING pg_temp.identity_key(reviewer_carbon_id);
ALTER TABLE iam.application_scope_messages ALTER COLUMN author_carbon_id TYPE text USING pg_temp.identity_key(author_carbon_id);
ALTER TABLE iam.application_scope_requests ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.application_scope_requests ALTER COLUMN created_by_carbon_id TYPE text USING pg_temp.identity_key(created_by_carbon_id);
ALTER TABLE iam.application_scope_requests ALTER COLUMN target_application_id TYPE text USING pg_temp.identity_key(target_application_id);
ALTER TABLE iam.application_secrets ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.application_secrets ALTER COLUMN created_by_carbon_id TYPE text USING pg_temp.identity_key(created_by_carbon_id);
ALTER TABLE iam.application_testing_environments ALTER COLUMN source_application_id TYPE text USING pg_temp.identity_key(source_application_id);
ALTER TABLE iam.application_webhook_endpoints ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.application_webhook_event_projections ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.application_webhook_signing_keys ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.applications ALTER COLUMN created_by_carbon_id TYPE text USING pg_temp.identity_key(created_by_carbon_id);
ALTER TABLE iam.applications ALTER COLUMN id TYPE text USING pg_temp.identity_key(id);
ALTER TABLE iam.audit_events ALTER COLUMN actor_principal_id TYPE text USING pg_temp.identity_key(actor_principal_id);
ALTER TABLE iam.audit_events ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.authentication_events ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.authentication_events ALTER COLUMN subject_principal_id TYPE text USING pg_temp.identity_key(subject_principal_id);
ALTER TABLE iam.authentication_sessions ALTER COLUMN subject_principal_id TYPE text USING pg_temp.identity_key(subject_principal_id);
ALTER TABLE iam.carbon_contacts ALTER COLUMN carbon_id TYPE text USING pg_temp.identity_key(carbon_id);
ALTER TABLE iam.carbon_membership_settings ALTER COLUMN carbon_id TYPE text USING pg_temp.identity_key(carbon_id);
ALTER TABLE iam.carbons ALTER COLUMN id TYPE text USING pg_temp.identity_key(id);
ALTER TABLE iam.extra_silicon_access_grants ALTER COLUMN revoked_by_platform_carbon_id TYPE text USING pg_temp.identity_key(revoked_by_platform_carbon_id);
ALTER TABLE iam.honeycomb_management_events ALTER COLUMN service_application_id TYPE text USING pg_temp.identity_key(service_application_id);
ALTER TABLE iam.honeycomb_operations ALTER COLUMN actor_principal_id TYPE text USING pg_temp.identity_key(actor_principal_id);
ALTER TABLE iam.honeycomb_operations ALTER COLUMN service_application_id TYPE text USING pg_temp.identity_key(service_application_id);
ALTER TABLE iam.honeycomb_publication_decisions ALTER COLUMN reviewer_carbon_id TYPE text USING pg_temp.identity_key(reviewer_carbon_id);
ALTER TABLE iam.honeycomb_publication_plans ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.honeycomb_publication_plans ALTER COLUMN created_by_carbon_id TYPE text USING pg_temp.identity_key(created_by_carbon_id);
ALTER TABLE iam.honeycomb_publication_plans ALTER COLUMN service_application_id TYPE text USING pg_temp.identity_key(service_application_id);
ALTER TABLE iam.invitation_verification_challenges ALTER COLUMN target_carbon_id TYPE text USING pg_temp.identity_key(target_carbon_id);
ALTER TABLE iam.login_challenge_channels ALTER COLUMN carbon_id TYPE text USING pg_temp.identity_key(carbon_id);
ALTER TABLE iam.login_challenges ALTER COLUMN carbon_id TYPE text USING pg_temp.identity_key(carbon_id);
ALTER TABLE iam.oauth_authorization_codes ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.oauth_authorization_request_scopes ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.oauth_authorization_requests ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.oauth_authorization_requests ALTER COLUMN subject_principal_id TYPE text USING pg_temp.identity_key(subject_principal_id);
ALTER TABLE iam.oauth_consent_grants ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.oauth_consent_grants ALTER COLUMN subject_principal_id TYPE text USING pg_temp.identity_key(subject_principal_id);
ALTER TABLE iam.obo_proofs ALTER COLUMN audience_application_id TYPE text USING pg_temp.identity_key(audience_application_id);
ALTER TABLE iam.obo_proofs ALTER COLUMN consumed_by_application_id TYPE text USING pg_temp.identity_key(consumed_by_application_id);
ALTER TABLE iam.obo_proofs ALTER COLUMN issuer_application_id TYPE text USING pg_temp.identity_key(issuer_application_id);
ALTER TABLE iam.obo_proofs ALTER COLUMN subject_principal_id TYPE text USING pg_temp.identity_key(subject_principal_id);
ALTER TABLE iam.organization_capability_grants ALTER COLUMN revoked_by_platform_carbon_id TYPE text USING pg_temp.identity_key(revoked_by_platform_carbon_id);
ALTER TABLE iam.organization_invitations ALTER COLUMN redirect_application_principal_id TYPE text USING pg_temp.identity_key(redirect_application_principal_id);
ALTER TABLE iam.organization_invitations ALTER COLUMN target_carbon_id TYPE text USING pg_temp.identity_key(target_carbon_id);
ALTER TABLE iam.organization_memberships ALTER COLUMN principal_id TYPE text USING pg_temp.identity_key(principal_id);
ALTER TABLE iam.organizations ALTER COLUMN created_by_carbon_id TYPE text USING pg_temp.identity_key(created_by_carbon_id);
ALTER TABLE iam.platform_role_grants ALTER COLUMN carbon_id TYPE text USING pg_temp.identity_key(carbon_id);
ALTER TABLE iam.platform_role_grants ALTER COLUMN granted_by_carbon_id TYPE text USING pg_temp.identity_key(granted_by_carbon_id);
ALTER TABLE iam.platform_role_grants ALTER COLUMN revoked_by_carbon_id TYPE text USING pg_temp.identity_key(revoked_by_carbon_id);
ALTER TABLE iam.principals ALTER COLUMN id TYPE text USING pg_temp.identity_key(id);
ALTER TABLE iam.refresh_token_families ALTER COLUMN client_application_id TYPE text USING pg_temp.identity_key(client_application_id);
ALTER TABLE iam.refresh_token_families ALTER COLUMN subject_principal_id TYPE text USING pg_temp.identity_key(subject_principal_id);
ALTER TABLE iam.service_principals ALTER COLUMN id TYPE text USING pg_temp.identity_key(id);
ALTER TABLE iam.signup_sessions ALTER COLUMN completed_carbon_id TYPE text USING pg_temp.identity_key(completed_carbon_id);
ALTER TABLE iam.silicon_credential_history ALTER COLUMN silicon_id TYPE text USING pg_temp.identity_key(silicon_id);
ALTER TABLE iam.silicon_credentials ALTER COLUMN silicon_id TYPE text USING pg_temp.identity_key(silicon_id);
ALTER TABLE iam.silicon_hooks ALTER COLUMN silicon_id TYPE text USING pg_temp.identity_key(silicon_id);
ALTER TABLE iam.silicon_token_rotation_requests ALTER COLUMN silicon_id TYPE text USING pg_temp.identity_key(silicon_id);
ALTER TABLE iam.silicon_webhook_endpoints ALTER COLUMN silicon_id TYPE text USING pg_temp.identity_key(silicon_id);
ALTER TABLE iam.silicon_webhook_signing_keys ALTER COLUMN silicon_id TYPE text USING pg_temp.identity_key(silicon_id);
ALTER TABLE iam.silicon_webhook_subscriptions ALTER COLUMN silicon_id TYPE text USING pg_temp.identity_key(silicon_id);
ALTER TABLE iam.silicons ALTER COLUMN id TYPE text USING pg_temp.identity_key(id);
ALTER TABLE iam.sso_authorization_transactions ALTER COLUMN carbon_id TYPE text USING pg_temp.identity_key(carbon_id);
ALTER TABLE iam.sso_identities ALTER COLUMN carbon_id TYPE text USING pg_temp.identity_key(carbon_id);
ALTER TABLE iam.step_up_assertions ALTER COLUMN carbon_id TYPE text USING pg_temp.identity_key(carbon_id);
ALTER TABLE iam.step_up_challenges ALTER COLUMN carbon_id TYPE text USING pg_temp.identity_key(carbon_id);
ALTER TABLE iam.testing_application_imports ALTER COLUMN application_id TYPE text USING pg_temp.identity_key(application_id);
ALTER TABLE iam.testing_environments ALTER COLUMN created_by_application_id TYPE text USING pg_temp.identity_key(created_by_application_id);
ALTER TABLE iam.testing_environments ALTER COLUMN honeycomb_service_id TYPE text USING pg_temp.identity_key(honeycomb_service_id);
ALTER TABLE iam_private.honeycomb_testing_root_operations ALTER COLUMN service_application_id TYPE text USING pg_temp.identity_key(service_application_id);
ALTER TABLE iam.audit_events ALTER COLUMN aggregate_id TYPE text USING pg_temp.resource_key(aggregate_id,aggregate_type);
ALTER TABLE iam.audit_events ALTER COLUMN target_id TYPE text USING pg_temp.resource_key(target_id,target_type);
ALTER TABLE iam.outbox_events ALTER COLUMN aggregate_id TYPE text USING pg_temp.resource_key(aggregate_id,aggregate_type);
ALTER TABLE iam.step_up_challenges ALTER COLUMN resource_id TYPE text USING pg_temp.resource_key(resource_id,
 CASE WHEN purpose IN ('account.sessions_revoke_all','application.client_secret.rotate',
  'application.webhook_secret.rotate','application.webhook.approve','silicon.rotate_token',
  'platform_admin.application_review') THEN 'principal' ELSE 'resource' END);
DELETE FROM identity_changed_columns saved
WHERE NOT EXISTS(SELECT 1 FROM pg_attribute current
 WHERE current.attrelid=saved.attrelid AND current.attnum=saved.attnum AND current.atttypid='text'::regtype);

ALTER TABLE identity_constraints ADD COLUMN scoped boolean NOT NULL DEFAULT false;
ALTER TABLE identity_constraints ADD COLUMN scope_column text;
UPDATE identity_constraints c SET scope_column=CASE
 WHEN EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=c.conrelid AND attname='testing_environment_id' AND NOT attisdropped) THEN 'testing_environment_id'
 WHEN c.relation LIKE 'iam_private.%' AND EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=c.conrelid AND attname='environment_id' AND NOT attisdropped) THEN 'environment_id' END;
UPDATE identity_constraints c SET scoped=true
WHERE c.contype IN ('p','u')
AND c.scope_column IS NOT NULL
AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=c.conrelid AND attnum=ANY(c.conkey)
 AND attnotnull AND atttypid='uuid'::regtype)
AND (NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=c.conrelid AND attnum=ANY(c.conkey)
 AND attnotnull AND atttypid='bytea'::regtype)
 OR EXISTS(SELECT 1 FROM identity_changed_columns changed WHERE changed.attrelid=c.conrelid AND changed.attnum=ANY(c.conkey)));
-- Resource UUIDs remain globally unique. Add a companion scoped key for
-- identity-bearing references so a token cannot attach its own environment's
-- canonical subject to a different environment's UUID session/membership.
CREATE TEMP TABLE identity_scoped_resource_keys ON COMMIT DROP AS
SELECT key.conrelid,key.conkey,key.relation,key.scope_column,
 left(key.conname,45)||'_env_'||left(md5(key.conrelid::text||key.conkey::text),8) AS conname,
 regexp_replace(replace(key.definition,'PRIMARY KEY','UNIQUE'),'\(','('||key.scope_column||', ') AS definition
FROM identity_constraints key
WHERE key.contype IN ('p','u') AND NOT key.scoped AND key.scope_column IS NOT NULL
 AND EXISTS(SELECT 1 FROM identity_changed_columns changed WHERE changed.attrelid=key.conrelid AND changed.attnum=ANY(key.conkey))
 AND EXISTS(SELECT 1 FROM identity_constraints fk WHERE fk.contype='f' AND fk.confrelid=key.conrelid AND fk.confkey=key.conkey);
UPDATE identity_constraints f SET scoped=true
WHERE f.contype='f' AND EXISTS(SELECT 1 FROM identity_constraints key
 WHERE key.conrelid=f.confrelid AND key.contype IN ('p','u') AND key.conkey=f.confkey
 AND (key.scoped OR EXISTS(SELECT 1 FROM identity_scoped_resource_keys companion WHERE companion.conrelid=key.conrelid AND companion.conkey=key.conkey)));
UPDATE identity_constraints SET definition=regexp_replace(definition,'\(','('||scope_column||', ') WHERE scoped AND contype IN ('p','u');
UPDATE identity_constraints f SET definition=regexp_replace(
 regexp_replace(f.definition,'\(','('||f.scope_column||', '),
 '(REFERENCES [^(]+\()','\1'||(SELECT scope_column FROM identity_constraints key WHERE key.conrelid=f.confrelid AND key.contype IN ('p','u') AND key.conkey=f.confkey LIMIT 1)||', ')
WHERE f.scoped AND f.contype='f';


CREATE FUNCTION pg_temp.canonical_identity_json(value jsonb,field text DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE result jsonb; item record; mapped text; scalar text;
BEGIN
 IF jsonb_typeof(value)='object' THEN
  result:='{}';
  FOR item IN SELECT * FROM jsonb_each(value) LOOP
   -- A resource UUID can have the same bytes as a principal UUID. Only
   -- identity objects may translate their generic id; typed FK field names
   -- remain translated recursively everywhere.
   IF item.key='id' AND NOT (
      COALESCE(value->>'actor_type',value->>'type','') IN ('carbon','silicon','application','service')
      OR (COALESCE(value->>'type','')='' AND (
          COALESCE(field,'') IN ('actor','subject','principal','recipient')
          OR value ? 'carbon_id' OR value ? 'silicon_id' OR value ? 'app_id'))
   ) THEN
    result:=result||jsonb_build_object(item.key,item.value);
   ELSE
    result:=result||jsonb_build_object(item.key,pg_temp.canonical_identity_json(item.value,item.key));
   END IF;
  END LOOP;
  RETURN result;
 ELSIF jsonb_typeof(value)='array' THEN
  SELECT COALESCE(jsonb_agg(pg_temp.canonical_identity_json(element,field)),'[]') INTO result FROM jsonb_array_elements(value) AS elements(element);
  RETURN result;
 ELSIF jsonb_typeof(value)='string' AND field !~ '^encryption_' AND
  (field='id' OR field ~ '(^|_)(principal|carbon|silicon|application|actor|reviewer|subject|service)(_ids?)?$') THEN
  scalar:=value#>>'{}';
  SELECT new_id INTO mapped FROM pg_temp.identity_key_map WHERE old_id::text=scalar;
  RETURN COALESCE(to_jsonb(mapped),value);
 END IF;
 RETURN value;
END $$;
DO $$ DECLARE item record; BEGIN
 FOR item IN SELECT a.attrelid::regclass AS relation,a.attname
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
 WHERE c.relnamespace IN ('iam'::regnamespace,'iam_private'::regnamespace)
 AND c.relkind IN ('r','p') AND NOT c.relispartition AND a.atttypid='jsonb'::regtype AND a.attnum>0 AND NOT a.attisdropped LOOP
  EXECUTE format('UPDATE %s SET %I=pg_temp.canonical_identity_json(%I) WHERE %I IS NOT NULL',item.relation,item.attname,item.attname,item.attname);
 END LOOP;
END $$;


-- Preserve installed production/testing implementations while changing only
-- declared identity parameters, columns and locals. Resource IDs stay UUIDs.
DO $rewrite_identity_functions$
DECLARE item record; key record; definition text; names text[]; name text; columns_pattern text; table_pattern text;
BEGIN
 FOR item IN SELECT * FROM identity_functions LOOP
  definition:=item.definition;

-- Testing conflict targets for canonical identity keys are adjusted below.

  names:=ARRAY['actor_principal_id','application_id','application_owner','audience_application_id','carbon_id','current_actor_id','current_actor_principal_id','current_carbon_id','current_id','endpoint_silicon_id','family_client_application_id','issuer_application_id','p_actor','p_actor_principal_id','p_app','p_app_ids','p_application','p_application_id','p_approved_by_carbon_id','p_audience','p_audience_application_id','p_carbon_id','p_issuer','p_issuer_application_id','p_principal_id','p_service','p_silicon_id','p_subject','p_subject_id','p_subject_principal_id','p_target_carbon_id','principal_id','provider_id','resolved_silicon_id','silicon_id','source_application_id','subject_principal_id','target_application_id','target_carbon_id','v_app_id','v_issuer_application_id','v_owner_id'];
  IF item.proname='can_review_application_scopes' THEN names:=names||ARRAY['p_target']; END IF;
  IF item.proname='touch_application_testing_environment' THEN names:=names||ARRAY['p_target_id']; END IF;
  IF item.proname='update_testing_application_secret' THEN names:=names||ARRAY['p_id']; END IF;
  IF item.proname='link_application_testing_environment' THEN names:=names||ARRAY['p_source_id','p_target_id']; END IF;
  IF item.proname='get_testing_source_iam_scope_policies' THEN names:=names||ARRAY['p_sources']; END IF;
  IF item.proname='authorize_scoped_testing_environment_creation' THEN names:=names||ARRAY['subject','app']; END IF;
  IF item.proname='honeycomb_inventory' THEN names:=names||ARRAY['p_after']; END IF;
  IF item.proname='honeycomb_publication_recipients' THEN names:=names||ARRAY['p_after']; END IF;
  IF item.proname='honeycomb_organization_recipients' THEN names:=names||ARRAY['p_after']; END IF;
  IF item.proname='honeycomb_testing_link_imports' THEN names:=names||ARRAY['target','source']; END IF;
  FOREACH name IN ARRAY names LOOP
   definition:=regexp_replace(definition,'\m('||name||')\M uuid(\[\])?','\1 text\2','gi');
   definition:=regexp_replace(definition,'\m('||name||')\M text(\[\])?\s+DEFAULT NULL::uuid','\1 text\2 DEFAULT NULL::text','gi');
   definition:=regexp_replace(definition,'\m('||name||')\M\s*=\s*''00000000-0000-0000-0000-000000000000''::uuid','\1 = ''''','g');
  END LOOP;

  IF item.proname=ANY(ARRAY['resolve_honeycomb_application','current_principal_id','current_application_id','import_testing_application_configuration','lock_current_application_client','honeycomb_configure_testing_application','honeycomb_publication_accept']) THEN definition:=replace(definition,E'RETURNS uuid\n',E'RETURNS text\n'); END IF;
  IF item.proname IN ('current_principal_id','current_application_id') THEN definition:=replace(definition,'::uuid','::text'); END IF;
  definition:=regexp_replace(definition,'(->>\s*''(?:application_id|source_application_id|target_application_id|subject_principal_id|actor_principal_id|principal_id|carbon_id|silicon_id|reviewer_id)''\s*\))::uuid','\1::text','g');
  IF item.proname IN ('import_testing_application_configuration','honeycomb_configure_testing_application') THEN
   definition:=replace(definition,'v_owner_id := v_environment_id;','v_owner_id := ''test_'' || translate(left(replace(v_environment_id::text,''-'',''''),24),''0'',''g'');');
   definition:=replace(definition,'v_owner_id:=v_environment_id;','v_owner_id:=''test_'' || translate(left(replace(v_environment_id::text,''-'',''''),24),''0'',''g'');');
   definition:=replace(definition,'v_owner_id <> v_environment_id','v_owner_id <> (''test_'' || translate(left(replace(v_environment_id::text,''-'',''''),24),''0'',''g''))');
  END IF;
  IF item.proname='honeycomb_inventory' THEN
   definition:=replace(definition,'SELECT id,app_id AS resource_id','SELECT id::text AS id,app_id AS resource_id');
   definition:=replace(definition,'UNION ALL SELECT id,bundle_id','UNION ALL SELECT id::text,bundle_id');
   definition:=replace(definition,'UNION ALL SELECT id,id::text','UNION ALL SELECT id::text,id::text');
  END IF;
  IF item.proname='application_scope_request_view' THEN definition:=replace(definition,'COALESCE(m.author_carbon_id,''00000000-0000-0000-0000-000000000000''::uuid)','COALESCE(m.author_carbon_id,''system'')'); END IF;
  IF item.proname='application_obo_exchange_replay_is_live' THEN definition:=replace(definition,'(uuid, uuid, uuid)','(uuid, text, uuid)'); END IF;
  IF item.proname='lookup_application_obo_proof' THEN definition:=replace(definition,'(smallint[], bytea[], uuid)','(smallint[], bytea[], text)'); END IF;
  IF item.proname='application_obo_load_current_context' THEN definition:=replace(definition,'(uuid, uuid, uuid, uuid, uuid, uuid, text, bigint, text, text)','(text, uuid, uuid, text, text, uuid, text, bigint, text, text)'); END IF;
  FOR key IN SELECT * FROM identity_constraints WHERE scoped AND contype IN ('p','u') LOOP
   SELECT string_agg(quote_ident(attname), '\s*,\s*' ORDER BY ord) INTO columns_pattern
   FROM unnest(key.conkey) WITH ORDINALITY keys(num,ord)
   JOIN pg_attribute ON attrelid=key.conrelid AND attnum=num;
   table_pattern:=replace(key.relation,'.','\.');
   definition:=regexp_replace(definition,
    '(INSERT\s+INTO\s+'||table_pattern||'\M[^;]*?ON\s+CONFLICT\s*\()\s*('||columns_pattern||')\s*(\))',
    '\1'||key.scope_column||', \2\3','gi');
  END LOOP;
  IF item.proname='honeycomb_testing_app_readiness' THEN definition:=replace(definition,'p_apps uuid[]','p_apps text[]'); END IF;
  IF item.proname='honeycomb_testing_activate_apps' THEN
   definition:=replace(replace(definition,'ids uuid[]','ids text[]'),'''{}''::uuid[]','''{}''::text[]');
  END IF;
  EXECUTE definition;
 END LOOP;
END $rewrite_identity_functions$;

-- Restore every previous privilege explicitly; CREATE FUNCTION's PUBLIC
-- default must never widen the API/worker security-definer boundary.
DO $$ DECLARE item record; privilege record; signature text; BEGIN
 FOR item IN SELECT * FROM identity_functions LOOP
  SELECT p.oid::regprocedure::text INTO STRICT signature FROM pg_proc p
   WHERE p.pronamespace='iam_private'::regnamespace AND p.proname=item.proname;
  EXECUTE format('ALTER FUNCTION %s OWNER TO %I',signature,item.owner);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
  FOR privilege IN SELECT * FROM aclexplode(COALESCE(item.proacl,acldefault('f',(SELECT oid FROM pg_roles WHERE rolname=item.owner)))) LOOP
   EXECUTE format('GRANT %s ON FUNCTION %s TO %s%s',privilege.privilege_type,signature,
     CASE WHEN privilege.grantee=0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(privilege.grantee)) END,
     CASE WHEN privilege.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END);
  END LOOP;
  IF item.description IS NOT NULL THEN EXECUTE format('COMMENT ON FUNCTION %s IS %L',signature,item.description); END IF;
 END LOOP;
 FOR item IN SELECT * FROM identity_constraints WHERE contype<>'f' LOOP
  IF item.relation='iam.principals' AND item.conname='principals_non_nil_id' THEN
   item.definition:='CHECK (id <> '''' AND id <> ''00000000-0000-0000-0000-000000000000'')';
  END IF;
  EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',item.relation,item.conname,item.definition);
 END LOOP;
 FOR item IN SELECT * FROM identity_scoped_resource_keys LOOP
  EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',item.relation,item.conname,item.definition);
 END LOOP;
 FOR item IN SELECT * FROM identity_constraints WHERE contype='f' LOOP
  EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',item.relation,item.conname,item.definition);
 END LOOP;
 FOR item IN SELECT * FROM identity_defaults LOOP
  EXECUTE format('ALTER TABLE %s ALTER COLUMN %I SET DEFAULT %s',item.relation,item.attname,item.definition);
 END LOOP;
 FOR item IN SELECT * FROM identity_indexes LOOP
  IF item.indexdef LIKE 'CREATE UNIQUE INDEX%' AND EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=item.indrelid AND attname='testing_environment_id' AND NOT attisdropped)
  AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=item.indrelid AND attnum=ANY(item.indkey) AND attnotnull AND atttypid='uuid'::regtype)
  AND (NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=item.indrelid AND attnum=ANY(item.indkey) AND attnotnull AND atttypid='bytea'::regtype)
   OR EXISTS(SELECT 1 FROM identity_changed_columns changed WHERE changed.attrelid=item.indrelid AND changed.attnum=ANY(item.indkey))) THEN
   item.indexdef:=replace(item.indexdef,' USING btree (',' USING btree (testing_environment_id, ');
  END IF;
  IF to_regclass(quote_ident(item.schemaname)||'.'||quote_ident(item.indexname)) IS NULL THEN EXECUTE item.indexdef; END IF;
 END LOOP;
 FOR item IN SELECT * FROM identity_views LOOP
  EXECUTE format('CREATE VIEW %s%s AS %s',item.relation,
    CASE WHEN item.reloptions IS NULL THEN '' ELSE ' WITH ('||array_to_string(item.reloptions,',')||')' END,item.definition);
  EXECUTE format('ALTER VIEW %s OWNER TO %I',item.relation,item.owner);
  FOR privilege IN SELECT * FROM aclexplode(COALESCE(item.relacl,acldefault('r',(SELECT oid FROM pg_roles WHERE rolname=item.owner)))) LOOP
   EXECUTE format('GRANT %s ON %s TO %s%s',privilege.privilege_type,item.relation,
    CASE WHEN privilege.grantee=0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(privilege.grantee)) END,
    CASE WHEN privilege.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END);
  END LOOP;
 END LOOP;
 FOR item IN SELECT * FROM identity_policies LOOP
  EXECUTE format('CREATE POLICY %I ON %I.%I AS %s FOR %s TO %s%s%s',item.policyname,item.schemaname,item.tablename,item.permissive,item.cmd,
    (SELECT string_agg(quote_ident(role),',') FROM unnest(item.roles) role),
    CASE WHEN item.qual IS NULL THEN '' ELSE ' USING ('||item.qual||')' END,
    CASE WHEN item.with_check IS NULL THEN '' ELSE ' WITH CHECK ('||item.with_check||')' END);
 END LOOP;
 FOR item IN SELECT * FROM identity_triggers LOOP
  EXECUTE item.definition;
  IF item.tgenabled='D' THEN EXECUTE format('ALTER TABLE %s DISABLE TRIGGER %I',item.relation,item.tgname);
  ELSIF item.tgenabled='A' THEN EXECUTE format('ALTER TABLE %s ENABLE ALWAYS TRIGGER %I',item.relation,item.tgname);
  ELSIF item.tgenabled='R' THEN EXECUTE format('ALTER TABLE %s ENABLE REPLICA TRIGGER %I',item.relation,item.tgname); END IF;
 END LOOP;
END $$;
ALTER TABLE iam.carbons ADD CONSTRAINT carbons_canonical_identity CHECK (id=carbon_id);
ALTER TABLE iam.silicons ADD CONSTRAINT silicons_canonical_identity CHECK (id=global_silicon_id);
ALTER TABLE iam.applications ADD CONSTRAINT applications_canonical_identity CHECK (id=app_id);
ALTER TABLE iam.service_principals ADD CONSTRAINT services_canonical_identity CHECK (id='service/'||service_id);
COMMENT ON TABLE iam.principals IS
 'Security identity supertype keyed directly by immutable Carbon, Silicon, Application or namespaced Service identifiers.';
COMMENT ON COLUMN iam.applications.encryption_context_id IS
 'Legacy application UUID retained only to authenticate pre-cutover ciphertext; never an identity lookup or foreign key.';
-- Startup needs the finite set of legacy AAD contexts before an environment
-- is selected. Keep only encryption metadata here, outside identity-table RLS;
-- API/worker roles cannot query it directly or use it as an identity lookup.
CREATE TABLE iam_private.legacy_application_encryption_contexts (
 application_id text NOT NULL,
 testing_environment_id uuid,
 context_id uuid NOT NULL,
 UNIQUE NULLS NOT DISTINCT(application_id,testing_environment_id)
);
INSERT INTO iam_private.legacy_application_encryption_contexts
 SELECT app.id,(to_jsonb(app)->>'testing_environment_id')::uuid,app.encryption_context_id
 FROM iam.applications app WHERE app.encryption_context_id IS NOT NULL;
REVOKE ALL ON iam_private.legacy_application_encryption_contexts FROM PUBLIC;
CREATE FUNCTION iam_private.application_encryption_contexts()
RETURNS TABLE(application_id text,testing_environment_id uuid,context_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam_private AS $$
 SELECT application_id,testing_environment_id,context_id
 FROM iam_private.legacy_application_encryption_contexts
$$;
REVOKE ALL ON FUNCTION iam_private.application_encryption_contexts() FROM PUBLIC;
DO $$ BEGIN
 IF to_regrole('silicon_iam_api') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.application_encryption_contexts() TO silicon_iam_api; END IF;
 IF to_regrole('silicon_iam_worker') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.application_encryption_contexts() TO silicon_iam_worker; END IF;
 IF to_regrole('silicon_iam_testing_definer') IS NOT NULL THEN GRANT SELECT ON iam_private.legacy_application_encryption_contexts TO silicon_iam_testing_definer; END IF;
END $$;
-- Restore the exact pre-migration security boundary only after all data,
-- policies and encryption metadata have been reconstructed successfully.
DO $$ DECLARE item record; BEGIN
 FOR item IN SELECT * FROM identity_owner_schema_grants LOOP
  EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM %I',item.namespace,item.owner);
 END LOOP;
 FOR item IN SELECT * FROM identity_row_security ORDER BY relation_id LOOP
  EXECUTE format('ALTER TABLE ONLY %s %s ROW LEVEL SECURITY',item.relation_id::regclass,
   CASE WHEN item.relrowsecurity THEN 'ENABLE' ELSE 'DISABLE' END);
  EXECUTE format('ALTER TABLE ONLY %s %s FORCE ROW LEVEL SECURITY',item.relation_id::regclass,
   CASE WHEN item.relforcerowsecurity THEN '' ELSE 'NO' END);
 END LOOP;
END $$;
SET LOCAL check_function_bodies = true;
