-- Bundles have no principal or credential of their own. Each member remains a
-- separately authorized application, scoped by immutable UUID foreign keys.
CREATE TABLE iam.application_bundles (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES iam.organizations(id) ON DELETE RESTRICT,
    bundle_id text NOT NULL UNIQUE CHECK (bundle_id ~ '^[a-z0-9_-]{3,50}>[a-z][a-z0-9_-]{0,79}$'),
    app_name text CHECK (char_length(app_name) BETWEEN 1 AND 200),
    app_logo text CHECK (char_length(app_logo) <= 2048),
    created_by_carbon_id uuid NOT NULL REFERENCES iam.carbons(id) ON DELETE RESTRICT,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    deleted_at timestamptz,
    UNIQUE (organization_id,id)
);
CREATE TABLE iam.application_bundle_members (
    bundle_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    application_id uuid NOT NULL,
    position smallint NOT NULL CHECK (position BETWEEN 0 AND 99),
    PRIMARY KEY(bundle_id,application_id),
    UNIQUE(bundle_id,position),
    FOREIGN KEY(organization_id,bundle_id) REFERENCES iam.application_bundles(organization_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(organization_id,application_id) REFERENCES iam.applications(organization_id,id) ON DELETE RESTRICT
);
CREATE INDEX application_bundles_organization_page ON iam.application_bundles(organization_id,created_at DESC,id DESC) WHERE deleted_at IS NULL;
CREATE INDEX application_bundle_members_application ON iam.application_bundle_members(application_id);
CREATE TRIGGER application_bundles_version BEFORE UPDATE ON iam.application_bundles
FOR EACH ROW EXECUTE FUNCTION iam_private.bump_aggregate_version();
CREATE FUNCTION iam_private.prevent_application_bundle_identity_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
 IF (NEW.id,NEW.organization_id,NEW.bundle_id,NEW.created_by_carbon_id) IS DISTINCT FROM
    (OLD.id,OLD.organization_id,OLD.bundle_id,OLD.created_by_carbon_id) THEN
    RAISE EXCEPTION 'bundle_identity_immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam_private.prevent_application_bundle_identity_change() FROM PUBLIC;
CREATE TRIGGER application_bundles_immutable BEFORE UPDATE ON iam.application_bundles
FOR EACH ROW EXECUTE FUNCTION iam_private.prevent_application_bundle_identity_change();

CREATE FUNCTION iam_private.application_bundle_view(p_id text,p_login boolean DEFAULT false,p_lock boolean DEFAULT false)
RETURNS TABLE(organization_id uuid,document jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE bundle iam.application_bundles; org iam.organizations; apps text[];
BEGIN
 IF iam_private.current_principal_id() IS NULL OR iam_private.current_application_id() IS NOT NULL THEN RETURN; END IF;
 SELECT b.* INTO bundle FROM iam.application_bundles b WHERE b.bundle_id=p_id AND b.deleted_at IS NULL;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT o.* INTO org FROM iam.organizations o WHERE o.id=bundle.organization_id AND o.status='active';
 IF NOT FOUND THEN RETURN; END IF;
 IF p_login THEN
   IF NOT (org.trusted_org AND org.allow_bundled_applications) THEN RETURN; END IF;
 ELSIF NOT iam_private.is_active_organization_owner_or_admin(org.id,iam_private.current_principal_id()) THEN RETURN;
 END IF;
 IF p_lock THEN
   -- Stable bundle membership and eligibility throughout atomic token issuance.
   PERFORM o.id FROM iam.organizations o WHERE o.id=org.id FOR SHARE;
   SELECT b.* INTO bundle FROM iam.application_bundles b WHERE b.id=bundle.id AND b.deleted_at IS NULL FOR SHARE;
   IF NOT FOUND THEN RETURN; END IF;
   IF p_login AND NOT EXISTS(SELECT 1 FROM iam.organizations o WHERE o.id=org.id AND o.status='active' AND o.trusted_org AND o.allow_bundled_applications) THEN RETURN; END IF;
 END IF;
 SELECT array_agg(a.app_id ORDER BY m.position) INTO apps
 FROM iam.application_bundle_members m JOIN iam.applications a ON a.id=m.application_id
 WHERE m.bundle_id=bundle.id;
 IF p_login AND (COALESCE(cardinality(apps),0)=0 OR EXISTS(
   SELECT 1 FROM iam.application_bundle_members m JOIN iam.applications a ON a.id=m.application_id
   JOIN iam.principals p ON p.id=a.id WHERE m.bundle_id=bundle.id
   AND (a.deleted_at IS NOT NULL OR a.review_status<>'verified' OR p.status<>'active')
 )) THEN RETURN; END IF;
 RETURN QUERY SELECT org.id,jsonb_build_object('id',bundle.id,'bundle_id',bundle.bundle_id,'org_id',org.org_id,
 'app_name',bundle.app_name,'app_logo',bundle.app_logo,'app_ids',COALESCE(apps,'{}'::text[]),'version',bundle.version,
 'created_at',bundle.created_at,'updated_at',bundle.updated_at);
END $$;
REVOKE ALL ON FUNCTION iam_private.application_bundle_view(text,boolean,boolean) FROM PUBLIC;

ALTER TABLE iam.application_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.application_bundle_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY application_bundles_read ON iam.application_bundles FOR SELECT USING (
 iam_private.current_application_id() IS NULL AND iam_private.is_active_organization_owner_or_admin(organization_id,iam_private.current_principal_id())
);

CREATE FUNCTION iam_private.application_bundle_management_organization(p_id text)
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT b.organization_id FROM iam.application_bundles b
 WHERE b.bundle_id=p_id AND iam_private.current_application_id() IS NULL
 AND iam_private.is_active_organization_owner_or_admin(b.organization_id,iam_private.current_principal_id())
$$;
REVOKE ALL ON FUNCTION iam_private.application_bundle_management_organization(text) FROM PUBLIC;

CREATE FUNCTION iam_private.mutate_application_bundle(p_id text,p_actor uuid,p_version bigint,p_action text,p_input jsonb)
RETURNS TABLE(organization_id uuid,document jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE bundle iam.application_bundles; org iam.organizations; apps text[]; matched integer;
BEGIN
 IF p_actor IS DISTINCT FROM iam_private.current_principal_id() OR iam_private.current_application_id() IS NOT NULL THEN
 RAISE EXCEPTION 'bundle_management_forbidden' USING ERRCODE='42501'; END IF;
 IF p_action='create' THEN
   SELECT o.* INTO org FROM iam.organizations o WHERE o.org_id=p_input->>'org_id' AND o.status='active' FOR SHARE;
 ELSE
   SELECT b.* INTO bundle FROM iam.application_bundles b WHERE b.bundle_id=p_id AND b.deleted_at IS NULL;
   IF NOT FOUND THEN RAISE EXCEPTION 'bundle_not_found' USING ERRCODE='P0002'; END IF;
   SELECT o.* INTO org FROM iam.organizations o WHERE o.id=bundle.organization_id AND o.status='active' FOR SHARE;
 END IF;
 IF org.id IS NULL OR NOT iam_private.is_active_organization_owner_or_admin(org.id,p_actor) THEN
 RAISE EXCEPTION 'bundle_management_forbidden' USING ERRCODE='42501'; END IF;
 PERFORM m.id FROM iam.organization_memberships m JOIN iam.principals p ON p.id=m.principal_id
 WHERE m.organization_id=org.id AND m.principal_id=p_actor AND m.status='active'
 AND m.principal_kind='carbon' AND m.org_role IN('owner','admin') AND p.status='active' FOR SHARE OF m,p;
 IF NOT FOUND THEN RAISE EXCEPTION 'bundle_management_forbidden' USING ERRCODE='42501'; END IF;
 IF p_action<>'delete' AND NOT(org.trusted_org AND org.allow_bundled_applications) THEN
 RAISE EXCEPTION 'application_bundles_unavailable' USING ERRCODE='42501'; END IF;
 IF p_action<>'create' THEN
   SELECT b.* INTO bundle FROM iam.application_bundles b WHERE b.id=bundle.id AND b.deleted_at IS NULL FOR UPDATE;
   IF NOT FOUND THEN RAISE EXCEPTION 'bundle_not_found' USING ERRCODE='P0002'; END IF;
   IF bundle.version<>p_version THEN RAISE EXCEPTION 'bundle_version_mismatch' USING ERRCODE='40001'; END IF;
 END IF;
 IF p_action NOT IN('create','update','delete') THEN RAISE EXCEPTION 'invalid_bundle_action' USING ERRCODE='22023'; END IF;
 IF p_action='delete' THEN
   UPDATE iam.application_bundles b SET deleted_at=transaction_timestamp() WHERE b.id=bundle.id RETURNING b.* INTO bundle;
   RETURN QUERY SELECT org.id,jsonb_build_object('id',bundle.id,'bundle_id',bundle.bundle_id,'version',bundle.version,'deleted',true);
   RETURN;
 END IF;
 IF p_input ? 'app_ids' THEN
   apps:=ARRAY(SELECT jsonb_array_elements_text(p_input->'app_ids'));
   IF cardinality(apps) NOT BETWEEN 1 AND 100 OR cardinality(apps)<>(SELECT count(DISTINCT value) FROM unnest(apps) value) THEN
   RAISE EXCEPTION 'invalid_bundle_members' USING ERRCODE='22023'; END IF;
   PERFORM a.id FROM iam.applications a JOIN iam.principals p ON p.id=a.id
   WHERE a.app_id=ANY(apps) AND a.organization_id=org.id AND a.deleted_at IS NULL AND a.review_status='verified' AND p.status='active'
   ORDER BY a.app_id FOR SHARE OF a,p;
   GET DIAGNOSTICS matched=ROW_COUNT;
   IF matched<>cardinality(apps) THEN RAISE EXCEPTION 'invalid_bundle_members' USING ERRCODE='22023'; END IF;
 END IF;
 IF p_action='create' THEN
   IF apps IS NULL THEN RAISE EXCEPTION 'invalid_bundle_members' USING ERRCODE='22023'; END IF;
   INSERT INTO iam.application_bundles(id,organization_id,bundle_id,app_name,app_logo,created_by_carbon_id)
   VALUES(gen_random_uuid(),org.id,org.org_id||'>'||(p_input->>'app_id'),p_input->>'app_name',p_input->>'app_logo',p_actor) RETURNING * INTO bundle;
 ELSE
   UPDATE iam.application_bundles b SET app_name=CASE WHEN p_input?'app_name' THEN p_input->>'app_name' ELSE b.app_name END,
   app_logo=CASE WHEN p_input?'app_logo' THEN p_input->>'app_logo' ELSE b.app_logo END WHERE b.id=bundle.id RETURNING b.* INTO bundle;
 END IF;
 IF apps IS NOT NULL THEN
   DELETE FROM iam.application_bundle_members m WHERE m.bundle_id=bundle.id;
   INSERT INTO iam.application_bundle_members(bundle_id,organization_id,application_id,position)
   SELECT bundle.id,org.id,a.id,(names.ordinality-1)::smallint FROM unnest(apps) WITH ORDINALITY names(app_id,ordinality)
   JOIN iam.applications a ON a.app_id=names.app_id AND a.organization_id=org.id;
 END IF;
 RETURN QUERY SELECT * FROM iam_private.application_bundle_view(bundle.bundle_id,false,false);
END $$;
REVOKE ALL ON FUNCTION iam_private.mutate_application_bundle(text,uuid,bigint,text,jsonb) FROM PUBLIC;
