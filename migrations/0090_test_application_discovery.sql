-- Secret-free control metadata used only after a test application authenticates.
CREATE FUNCTION iam_private.test_application_environment(p_id uuid)
RETURNS TABLE(environment_id uuid, organization_id uuid, org_id text, name text,
 description text, version bigint, key_generation integer, cleaned_at timestamptz,
 created_at timestamptz, creator_type text, creator_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT e.id,e.organization_id,o.org_id,e.name,e.description,e.version,e.key_generation,
 e.cleaned_at,e.created_at,m.principal_kind::text,
 CASE m.principal_kind WHEN 'carbon' THEN c.carbon_id ELSE s.global_silicon_id END
 FROM iam.testing_environments e JOIN iam.organizations o ON o.id=e.organization_id
 JOIN iam.organization_memberships m ON m.id=e.created_by_membership_id
 LEFT JOIN iam.carbons c ON c.id=m.principal_id
 LEFT JOIN iam.silicons s ON s.id=m.principal_id
 WHERE e.id=p_id AND e.status='active' AND o.status='active';
$$;
CREATE FUNCTION iam_private.test_application_backfill_environments()
RETURNS TABLE(id uuid, organization_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam AS $$
 SELECT id,organization_id FROM iam.testing_environments ORDER BY id;
$$;
REVOKE ALL ON FUNCTION iam_private.test_application_environment(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.test_application_backfill_environments() FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.test_application_environment(uuid),
 iam_private.test_application_backfill_environments() TO silicon_iam_api;
END IF; END $$;
