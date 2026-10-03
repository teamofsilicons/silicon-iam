-- Carbon and Silicon membership roles share organization authority. The creator
-- column retains its historical wire/database name; it now references an actor.
ALTER TABLE iam.organizations DROP CONSTRAINT organizations_creator_fk;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.principals'::regclass AND attname='testing_environment_id' AND NOT attisdropped) THEN
 ALTER TABLE iam.organizations ADD CONSTRAINT organizations_creator_fk FOREIGN KEY(testing_environment_id,created_by_carbon_id) REFERENCES iam.principals(testing_environment_id,id) ON DELETE RESTRICT;
 ELSE
 ALTER TABLE iam.organizations ADD CONSTRAINT organizations_creator_fk FOREIGN KEY(created_by_carbon_id) REFERENCES iam.principals(id) ON DELETE RESTRICT;
 END IF;
END $$;
ALTER TABLE iam.organization_memberships DROP CONSTRAINT organization_memberships_human_admin_roles;
UPDATE iam.organization_capability_catalog SET allowed_for_silicon=allowed_for_carbon WHERE capability<>'audit.read';

CREATE FUNCTION iam_private.principal_can_create_organizations() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT EXISTS(SELECT 1 FROM iam.principals p WHERE p.id=iam_private.current_principal_id() AND p.status='active'
 AND (p.kind='carbon' OR (p.kind='silicon' AND EXISTS(SELECT 1 FROM iam.silicon_custodians c WHERE c.silicon_id=p.id AND c.can_create_organizations))))
$$;
REVOKE ALL ON FUNCTION iam_private.principal_can_create_organizations() FROM PUBLIC;
DROP POLICY organizations_creator_insert ON iam.organizations;
CREATE POLICY organizations_creator_insert ON iam.organizations FOR INSERT WITH CHECK(
 created_by_carbon_id=iam_private.current_principal_id() AND iam_private.principal_can_create_organizations());

CREATE FUNCTION iam_private.create_identity_organization(p_org uuid,p_owner uuid,p_handle text,p_name text,p_logo text,p_description text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE actor text:=iam_private.current_principal_id(); actor_kind iam.principal_kind;
BEGIN
 SELECT kind INTO actor_kind FROM iam.principals WHERE id=actor AND status='active' FOR SHARE;
 IF actor_kind NOT IN('carbon','silicon') OR NOT iam_private.principal_can_create_organizations() THEN
 RAISE EXCEPTION 'organization_creation_not_allowed' USING ERRCODE='42501'; END IF;
 -- Serialize custody setting changes with Silicon-created organizations.
 IF actor_kind='silicon' THEN
 PERFORM 1 FROM iam.silicon_custodians WHERE silicon_id=actor AND can_create_organizations FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'organization_creation_not_allowed' USING ERRCODE='42501'; END IF;
 END IF;
 INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name,logo_uri,description) VALUES(p_org,p_handle,actor,p_name,p_logo,p_description);
 INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES(p_owner,p_org,actor,actor_kind,'owner');
 IF actor_kind='carbon' THEN INSERT INTO iam.carbon_membership_settings(organization_id,membership_id,carbon_id) VALUES(p_org,p_owner,actor); END IF;
END $$;
REVOKE ALL ON FUNCTION iam_private.create_identity_organization(uuid,uuid,text,text,text,text) FROM PUBLIC;

-- Keep the existing row locks, role transition invariants and capability checks.
DO $$
DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef('iam_private.set_organization_admin_role(uuid,uuid,bigint,boolean)'::regprocedure) INTO definition;
 definition:=replace(definition,'AND membership.principal_kind = ''carbon''','AND membership.principal_kind IN (''carbon'',''silicon'')');
 definition:=replace(definition,'target_membership.principal_kind <> ''carbon''','target_membership.principal_kind NOT IN (''carbon'',''silicon'')');
 EXECUTE definition;
END $$;

CREATE OR REPLACE FUNCTION iam_private.lock_application_creation_organization(p_organization_handle text,p_carbon_id text)
RETURNS uuid LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 SELECT organization.id FROM iam.organizations organization
 JOIN iam.organization_memberships membership ON membership.organization_id=organization.id AND membership.principal_id=p_carbon_id
 AND membership.principal_kind IN('carbon','silicon') AND membership.org_role IN('owner','admin') AND membership.status='active'
 JOIN iam.principals principal ON principal.id=membership.principal_id AND principal.kind=membership.principal_kind AND principal.status='active'
 WHERE organization.org_id=p_organization_handle AND organization.status='active' FOR SHARE OF organization,membership,principal
$$;
REVOKE ALL ON FUNCTION iam_private.lock_application_creation_organization(text,text) FROM PUBLIC;

-- Application configuration provenance can be a Silicon manager. This does not
-- change human platform review or Carbon contact/SSO authority.
DO $$
DECLARE c record; definition text;
BEGIN
 FOR c IN SELECT con.oid,con.conname,con.conrelid::regclass AS table_id FROM pg_constraint con
 WHERE con.contype='f' AND con.confrelid='iam.carbons'::regclass
 AND con.conrelid IN('iam.applications'::regclass,'iam.application_secrets'::regclass,to_regclass('iam.application_collaborators'),
 to_regclass('iam.application_approved_scopes'))
 LOOP
  definition:=replace(pg_get_constraintdef(c.oid),'REFERENCES iam.carbons(','REFERENCES iam.principals(');
  EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',c.table_id,c.conname);
  EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',c.table_id,c.conname,definition);
 END LOOP;
END $$;
