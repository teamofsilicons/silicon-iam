-- Breaking public-ID cutover: Carbon c:<handle>, Silicon si:<handle>, bare apps.
-- Organizations, membership/resource UUIDs, credentials and cryptographic bytes stay.
-- Run under maintenance after snapshot/export, queue drain and replay-window expiry.
-- This transaction aborts on any cross-organization handle collision; never merge.
SET LOCAL check_function_bodies = false;
CREATE TEMP TABLE schema_id_security ON COMMIT DROP AS
SELECT oid,relrowsecurity,relforcerowsecurity FROM pg_class
WHERE relnamespace IN ('iam'::regnamespace,'iam_private'::regnamespace) AND relkind IN ('r','p');
DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT * FROM schema_id_security ORDER BY oid LOOP
  EXECUTE format('LOCK TABLE ONLY %s IN ACCESS EXCLUSIVE MODE',r.oid::regclass);
  IF r.relrowsecurity THEN EXECUTE format('ALTER TABLE ONLY %s DISABLE ROW LEVEL SECURITY',r.oid::regclass); END IF;
 END LOOP;
END $$;
CREATE TABLE iam_private.public_id_schema_map (
 scope_key text NOT NULL, old_id text NOT NULL, new_id text NOT NULL,
 actor_type text NOT NULL, org_id text,
 PRIMARY KEY(scope_key,old_id), UNIQUE(scope_key,new_id)
);
REVOKE ALL ON iam_private.public_id_schema_map FROM PUBLIC;
-- Export this table after migration to update consumers by exact, scoped identity.
-- It is deliberately not consulted by authentication as an old-ID alias table.
INSERT INTO iam_private.public_id_schema_map(scope_key,old_id,new_id,actor_type,org_id)
SELECT COALESCE(to_jsonb(p)->>'testing_environment_id',''),p.id,
 CASE p.kind WHEN 'carbon' THEN 'c:'||c.carbon_id WHEN 'silicon' THEN 'si:'||s.silicon_handle
 WHEN 'application' THEN split_part(a.app_id,'>',2) ELSE p.id END,
 p.kind::text, COALESCE(s.organization_handle,o.org_id)
FROM iam.principals p
LEFT JOIN iam.carbons c ON c.id=p.id AND COALESCE(to_jsonb(c)->>'testing_environment_id','')=COALESCE(to_jsonb(p)->>'testing_environment_id','')
LEFT JOIN iam.silicons s ON s.id=p.id AND COALESCE(to_jsonb(s)->>'testing_environment_id','')=COALESCE(to_jsonb(p)->>'testing_environment_id','')
LEFT JOIN iam.applications a ON a.id=p.id AND COALESCE(to_jsonb(a)->>'testing_environment_id','')=COALESCE(to_jsonb(p)->>'testing_environment_id','')
LEFT JOIN iam.organizations o ON o.id=a.organization_id;
-- The unique constraint above is a fail-closed collision preflight including
-- removed accounts. Existing Carbon handles containing 0 stay readable.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM iam_private.public_id_schema_map WHERE new_id='' OR
  (actor_type='carbon' AND new_id!~'^c:[a-z0-9_-]{3,30}$') OR
  (actor_type='silicon' AND new_id!~'^si:[a-z0-9_-]{3,50}$') OR
  (actor_type='application' AND new_id!~'^[a-z][a-z0-9_-]{0,79}$')) THEN
  RAISE EXCEPTION 'invalid source identity; resolve the migration inventory before cutover';
 END IF;
 IF EXISTS(SELECT 1 FROM iam.idempotency_records WHERE expires_at>clock_timestamp()) THEN
  RAISE EXCEPTION 'public ID cutover requires expired idempotency replay windows; stop writes and wait; do not delete live records';
 END IF;
 IF EXISTS(SELECT 1 FROM iam_private.organization_action_approvals WHERE status IN ('pending','approved') AND expires_at>clock_timestamp()) THEN
  RAISE EXCEPTION 'public ID cutover requires completed or expired sensitive-action approvals; signed request bytes cannot be rebound';
 END IF;
 IF EXISTS(SELECT 1 FROM iam.honeycomb_operations WHERE NOT completed OR response_expires_at>clock_timestamp()) THEN
  RAISE EXCEPTION 'public ID cutover requires completed Honeycomb operations and expired secret responses';
 END IF;
END $$;
CREATE TEMP TABLE schema_membership_map ON COMMIT DROP AS
SELECT mapping.scope_key, member.membership_id old_id,
       mapping.new_id||'['||organization.org_id||']' new_id
FROM iam_private.membership_identifiers member
JOIN iam.organization_memberships membership ON membership.id=member.membership_key
JOIN iam.organizations organization ON organization.id=membership.organization_id
JOIN iam_private.public_id_schema_map mapping ON mapping.old_id=membership.principal_id AND mapping.scope_key=member.scope_key;
CREATE TEMP TABLE schema_identity_map ON COMMIT DROP AS
SELECT DISTINCT old_id,new_id FROM iam_private.public_id_schema_map;
CREATE UNIQUE INDEX ON schema_identity_map(old_id);
CREATE FUNCTION pg_temp.schema_id(value text) RETURNS text LANGUAGE sql STABLE AS $$
 SELECT COALESCE((SELECT new_id FROM pg_temp.schema_identity_map WHERE old_id=value),value)
$$;
CREATE FUNCTION pg_temp.schema_scope(value text) RETURNS text LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN value LIKE 'obo:%' THEN
  'obo:'||pg_temp.schema_id(split_part(value,':',2))||substr(value,length(split_part(value,':',2))+5)
 ELSE value END
$$;
-- Preserve the pre-cutover text application AAD separately from old UUID AAD.
CREATE TABLE iam_private.public_id_application_contexts (
 application_id text NOT NULL, testing_environment_id uuid, context_id text NOT NULL,
 UNIQUE NULLS NOT DISTINCT(application_id,testing_environment_id)
);
INSERT INTO iam_private.public_id_application_contexts
SELECT new_id,NULLIF(scope_key,'')::uuid,old_id FROM iam_private.public_id_schema_map WHERE actor_type='application';
REVOKE ALL ON iam_private.public_id_application_contexts FROM PUBLIC;
CREATE FUNCTION iam_private.public_id_application_contexts()
RETURNS TABLE(application_id text,testing_environment_id uuid,context_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam_private AS $$
 SELECT application_id,testing_environment_id,context_id FROM iam_private.public_id_application_contexts
$$;
REVOKE ALL ON FUNCTION iam_private.public_id_application_contexts() FROM PUBLIC;
DO $$ BEGIN
 IF to_regrole('silicon_iam_api') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.public_id_application_contexts() TO silicon_iam_api; END IF;
 IF to_regrole('silicon_iam_worker') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.public_id_application_contexts() TO silicon_iam_worker; END IF;
 IF to_regrole('silicon_iam_testing_definer') IS NOT NULL THEN GRANT SELECT ON iam_private.public_id_application_contexts TO silicon_iam_testing_definer; END IF;
END $$;
CREATE TEMP TABLE schema_id_fks ON COMMIT DROP AS
SELECT conrelid,conname,pg_get_constraintdef(oid) definition FROM pg_constraint
WHERE connamespace IN ('iam'::regnamespace,'iam_private'::regnamespace) AND contype='f' AND conparentid=0;
CREATE TEMP TABLE schema_id_triggers ON COMMIT DROP AS
SELECT tgrelid,tgname,tgenabled FROM pg_trigger WHERE NOT tgisinternal AND tgparentid=0
AND tgrelid IN (SELECT oid FROM schema_id_security);
DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT * FROM schema_id_fks LOOP EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',r.conrelid::regclass,r.conname); END LOOP;
 FOR r IN SELECT * FROM schema_id_triggers LOOP EXECUTE format('ALTER TABLE %s DISABLE TRIGGER %I',r.tgrelid::regclass,r.tgname); END LOOP;
END $$;
ALTER TABLE iam.carbons DROP CONSTRAINT carbons_canonical_identity, DROP CONSTRAINT carbons_carbon_id_format;
ALTER TABLE iam.silicons DROP CONSTRAINT silicons_canonical_identity;
ALTER TABLE iam.applications DROP CONSTRAINT applications_canonical_identity, DROP CONSTRAINT applications_app_id_format;
-- PostgreSQL 16 cannot replace a generated expression in place; use an enforced
-- computed field with the same projection column, without dropping dependencies.
ALTER TABLE iam.silicons ALTER COLUMN global_silicon_id DROP EXPRESSION;
DO $$ DECLARE r record; BEGIN
 -- Update all identity columns on a row together. For example, a consumed OBO
 -- proof requires its consumer and audience to remain equal throughout cutover.
 FOR r IN SELECT c.oid::regclass relation,
 string_agg(format('%I=pg_temp.schema_id(%I)',a.attname,a.attname),',' ORDER BY a.attnum) assignments,
 string_agg(format('%I IN (SELECT old_id FROM pg_temp.schema_identity_map)',a.attname),' OR ' ORDER BY a.attnum) predicate
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
 WHERE c.relnamespace IN ('iam'::regnamespace,'iam_private'::regnamespace) AND c.relkind IN ('r','p') AND NOT c.relispartition
 AND a.atttypid='text'::regtype AND a.attnum>0 AND NOT a.attisdropped AND a.attgenerated=''
 AND c.relname NOT IN ('public_id_schema_map','public_id_application_contexts')
 AND (a.attname ~ '(^|_)(principal|carbon|silicon|application|actor|reviewer|subject|service)_id$'
  OR a.attname IN ('app_id','global_silicon_id','audience','public_id')
  OR (a.attname='id' AND c.relname IN ('principals','carbons','silicons','applications','service_principals')))
 GROUP BY c.oid
 LOOP
  EXECUTE format('UPDATE %s SET %s WHERE %s',r.relation,r.assignments,r.predicate);
 END LOOP;
END $$;
-- Policy selectors are typed identity arrays, not arbitrary user strings.
DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT c.oid::regclass relation,a.attname FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
 WHERE c.relnamespace IN ('iam'::regnamespace,'iam_private'::regnamespace) AND c.relkind IN ('r','p') AND NOT c.relispartition
 AND a.atttypid='text[]'::regtype AND a.attnum>0 AND NOT a.attisdropped
 AND a.attname ~ '(^|_)(principal|carbon|silicon|application|actor|reviewer|subject|service)_ids$' LOOP
  EXECUTE format('UPDATE %s SET %I=ARRAY(SELECT pg_temp.schema_id(v) FROM unnest(%I) v) WHERE %I IS NOT NULL',r.relation,r.attname,r.attname,r.attname);
 END LOOP;
END $$;
UPDATE iam_private.membership_identifiers m SET membership_id=mapping.new_id
FROM schema_membership_map mapping WHERE m.scope_key=mapping.scope_key AND m.membership_id=mapping.old_id;
-- Aggregate/target IDs are tagged unions: never reinterpret unrelated resources.
UPDATE iam.audit_events SET aggregate_id=pg_temp.schema_id(aggregate_id) WHERE aggregate_type IN ('carbon','silicon','application','principal','service');
UPDATE iam.audit_events SET target_id=pg_temp.schema_id(target_id) WHERE target_type IN ('carbon','silicon','application','principal','service');
UPDATE iam.outbox_events SET aggregate_id=pg_temp.schema_id(aggregate_id) WHERE aggregate_type IN ('carbon','silicon','application','principal','service');
UPDATE iam.honeycomb_operations SET resource_id=pg_temp.schema_id(resource_id) WHERE operation_kind<>'bundle-configure';
UPDATE iam.honeycomb_management_events SET resource_id=pg_temp.schema_id(resource_id) WHERE event_type NOT LIKE 'bundle.%';
-- OBO scope values contain exactly the provider app ID between delimiters.
DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT c.oid::regclass relation,a.attname,a.atttypid FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
 WHERE c.relnamespace IN ('iam'::regnamespace,'iam_private'::regnamespace) AND c.relkind IN ('r','p') AND NOT c.relispartition AND a.attnum>0 AND NOT a.attisdropped
 AND a.attname IN ('scope','scopes','approved_scopes','requested_scopes') LOOP
  IF r.atttypid='text'::regtype THEN EXECUTE format('UPDATE %s SET %I=pg_temp.schema_scope(%I) WHERE %I LIKE ''obo:%%''',r.relation,r.attname,r.attname,r.attname);
  ELSIF r.atttypid='text[]'::regtype THEN EXECUTE format('UPDATE %s SET %I=ARRAY(SELECT pg_temp.schema_scope(v) FROM unnest(%I) v) WHERE %I IS NOT NULL',r.relation,r.attname,r.attname,r.attname); END IF;
 END LOOP;
END $$;
CREATE FUNCTION pg_temp.schema_json(value jsonb, field text DEFAULT '') RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE result jsonb; item record; scalar text; mapped text;
BEGIN
 IF field LIKE 'encryption_%' THEN RETURN value; END IF;
 IF jsonb_typeof(value)='object' THEN
  result:='{}';
  FOR item IN SELECT * FROM jsonb_each(value) LOOP
   IF item.key='id' AND NOT (value ? 'carbon_id' OR value ? 'silicon_id' OR value ? 'app_id' OR COALESCE(value->>'type',value->>'actor_type','') IN ('carbon','silicon','application','service') OR field IN ('actor','subject','principal')) THEN
    result:=result||jsonb_build_object(item.key,item.value);
   ELSE result:=result||jsonb_build_object(item.key,pg_temp.schema_json(item.value,item.key)); END IF;
  END LOOP;
  RETURN result;
 ELSIF jsonb_typeof(value)='array' THEN
  SELECT COALESCE(jsonb_agg(pg_temp.schema_json(v,field)),'[]') INTO result FROM jsonb_array_elements(value) v; RETURN result;
 ELSIF jsonb_typeof(value)='string' THEN
  scalar:=value#>>'{}';
  IF field IN ('scope','scopes','approved_scopes','requested_scopes') THEN RETURN to_jsonb(pg_temp.schema_scope(scalar)); END IF;
  IF field ~ '(^|_)membership_ids?$' THEN
   SELECT new_id INTO mapped FROM schema_membership_map WHERE old_id=scalar LIMIT 1; RETURN COALESCE(to_jsonb(mapped),value);
  ELSIF field IN ('id','app_id','app_ids','carbon_id','carbon_ids','silicon_id','silicon_ids','public_id','provider','audience') OR field ~ '(^|_)(principal|application|actor|reviewer|subject|service)_ids?$' THEN
   RETURN to_jsonb(pg_temp.schema_id(scalar));
  END IF;
 END IF;
 RETURN value;
END $$;
DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT c.oid::regclass relation,a.attname FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
 WHERE c.relnamespace IN ('iam'::regnamespace,'iam_private'::regnamespace) AND c.relkind IN ('r','p') AND NOT c.relispartition
 AND c.relname NOT IN ('idempotency_records','organization_action_approvals','honeycomb_operations')
 AND a.atttypid='jsonb'::regtype AND a.attnum>0 AND NOT a.attisdropped LOOP
  EXECUTE format('UPDATE %s SET %I=pg_temp.schema_json(%I) WHERE %I IS NOT NULL',r.relation,r.attname,r.attname,r.attname);
 END LOOP;
END $$;
ALTER TABLE iam.carbons ADD CONSTRAINT carbons_canonical_identity CHECK(id=carbon_id),
 ADD CONSTRAINT carbons_carbon_id_format CHECK(carbon_id~'^c:[a-z0-9_-]{3,30}$');
ALTER TABLE iam.silicons ADD CONSTRAINT silicons_canonical_identity CHECK(id=global_silicon_id AND global_silicon_id='si:'||silicon_handle);
ALTER TABLE iam.applications ADD CONSTRAINT applications_canonical_identity CHECK(id=app_id),
 ADD CONSTRAINT applications_app_id_format CHECK(app_id~'^[a-z][a-z0-9_-]{0,79}$');
CREATE FUNCTION iam_private.compute_public_silicon_id() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$ BEGIN NEW.global_silicon_id:='si:'||NEW.silicon_handle; RETURN NEW; END $$;
REVOKE ALL ON FUNCTION iam_private.compute_public_silicon_id() FROM PUBLIC;
CREATE TRIGGER silicons_compute_public_id BEFORE INSERT OR UPDATE ON iam.silicons
FOR EACH ROW EXECUTE FUNCTION iam_private.compute_public_silicon_id();
-- Existing helper privileges/owners survive CREATE OR REPLACE, including the
-- restricted testing definer. Only known identity syntax and synthetic IDs change.
DO $$ DECLARE r record; definition text; BEGIN
 FOR r IN SELECT oid,proname FROM pg_proc WHERE pronamespace='iam_private'::regnamespace LOOP
  definition:=pg_get_functiondef(r.oid);
  definition:=replace(definition,'''^[a-z0-9_-]{3,50}:[a-z0-9_-]{3,50}$''','''^si:[a-z0-9_-]{3,50}$''');
  IF r.proname='create_testing_actor_login' THEN definition:=replace(definition,'''^[a-z1-9_-]{3,30}$''','''^c:[a-z0-9_-]{3,30}$'''); END IF;
  IF r.proname IN ('import_testing_application_configuration','honeycomb_configure_testing_application') THEN definition:=replace(definition,'''test_''','''c:test_'''); END IF;
  IF r.proname IN ('resolve_scoped_iam_application','resolve_testing_scoped_iam_application') THEN definition:=replace(definition,'''tos>iam''','''iam'''); END IF;
  IF definition IS DISTINCT FROM pg_get_functiondef(r.oid) THEN EXECUTE definition; END IF;
 END LOOP;
 FOR r IN SELECT * FROM schema_id_fks LOOP EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',r.conrelid::regclass,r.conname,r.definition); END LOOP;
 FOR r IN SELECT * FROM schema_id_triggers LOOP
  EXECUTE format('ALTER TABLE %s %s TRIGGER %I',r.tgrelid::regclass,CASE r.tgenabled WHEN 'D' THEN 'DISABLE' WHEN 'A' THEN 'ENABLE ALWAYS' WHEN 'R' THEN 'ENABLE REPLICA' ELSE 'ENABLE' END,r.tgname);
 END LOOP;
 FOR r IN SELECT * FROM schema_id_security ORDER BY oid LOOP
  EXECUTE format('ALTER TABLE ONLY %s %s ROW LEVEL SECURITY',r.oid::regclass,CASE WHEN r.relrowsecurity THEN 'ENABLE' ELSE 'DISABLE' END);
  EXECUTE format('ALTER TABLE ONLY %s %s FORCE ROW LEVEL SECURITY',r.oid::regclass,CASE WHEN r.relforcerowsecurity THEN '' ELSE 'NO' END);
 END LOOP;
END $$;
SET LOCAL check_function_bodies = true;
