-- Organization custodians control only their own seeded Silicon identities.
CREATE FUNCTION iam_private.organization_silicon_custody(p_org uuid,p_silicon text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 IF NOT iam_private.has_organization_capability(p_org,iam_private.current_principal_id(),'organization.update') THEN
  RAISE EXCEPTION 'organization_custody_forbidden' USING ERRCODE='42501';
 END IF;
 RETURN (SELECT jsonb_build_object('silicon_id',s.global_silicon_id,
  'display_name',coalesce(s.display_name,s.silicon_handle),'can_create_organizations',c.can_create_organizations,'version',c.version)
  FROM iam.silicon_custodians c JOIN iam.silicons s ON s.id=c.silicon_id AND s.deleted_at IS NULL
  WHERE c.organization_id=p_org AND c.carbon_id IS NULL AND c.silicon_id=p_silicon);
END $$;
REVOKE ALL ON FUNCTION iam_private.organization_silicon_custody(uuid,text) FROM PUBLIC;

CREATE FUNCTION iam_private.update_organization_silicon_custody(p_org uuid,p_silicon text,p_version bigint,p_allowed boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 IF iam_private.organization_silicon_custody(p_org,p_silicon) IS NULL THEN RETURN NULL; END IF;
 UPDATE iam.silicon_custodians SET can_create_organizations=p_allowed,version=version+1
 WHERE organization_id=p_org AND carbon_id IS NULL AND silicon_id=p_silicon AND version=p_version;
 IF NOT FOUND THEN RETURN NULL; END IF;
 RETURN iam_private.organization_silicon_custody(p_org,p_silicon);
END $$;
REVOKE ALL ON FUNCTION iam_private.update_organization_silicon_custody(uuid,text,bigint,boolean) FROM PUBLIC;
