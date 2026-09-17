-- Canonical public membership identifiers. The existing UUID is a private row
-- key: retaining it preserves foreign keys, issued credentials and audit history.
CREATE TABLE iam_private.membership_identifiers (
    membership_key uuid PRIMARY KEY REFERENCES iam.organization_memberships(id) ON DELETE CASCADE,
    scope_key text NOT NULL,
    membership_id text NOT NULL,
    UNIQUE (scope_key, membership_id)
);
REVOKE ALL ON iam_private.membership_identifiers FROM PUBLIC;

-- Include inactive and removed memberships, and preserve testing-world isolation
-- when applying this forward migration to an already populated testing database.
INSERT INTO iam_private.membership_identifiers(membership_key, scope_key, membership_id)
SELECT member.id, COALESCE(to_jsonb(member)->>'testing_environment_id', ''),
       COALESCE(carbon.carbon_id, silicon.global_silicon_id) || '[' || organization.org_id || ']'
FROM iam.organization_memberships member
JOIN iam.organizations organization ON organization.id = member.organization_id
LEFT JOIN iam.carbons carbon ON carbon.id = member.principal_id AND member.principal_kind = 'carbon'
LEFT JOIN iam.silicons silicon ON silicon.id = member.principal_id AND member.principal_kind = 'silicon';

-- Deferred because a Silicon's membership is inserted before its profile.
CREATE FUNCTION iam_private.register_membership_identifier()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    INSERT INTO iam_private.membership_identifiers(membership_key, scope_key, membership_id)
    SELECT member.id, COALESCE(to_jsonb(member)->>'testing_environment_id', ''),
           COALESCE(carbon.carbon_id, silicon.global_silicon_id) || '[' || organization.org_id || ']'
    FROM iam.organization_memberships member
    JOIN iam.organizations organization ON organization.id = member.organization_id
    LEFT JOIN iam.carbons carbon ON carbon.id = member.principal_id AND member.principal_kind = 'carbon'
    LEFT JOIN iam.silicons silicon ON silicon.id = member.principal_id AND member.principal_kind = 'silicon'
    WHERE member.id = NEW.id;
    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.register_membership_identifier() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER register_membership_identifier
AFTER INSERT ON iam.organization_memberships DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam_private.register_membership_identifier();

-- Identifier translation conveys no authority. Every handler still applies its
-- existing identity, tenant, consent and resource checks to the private row key.
CREATE FUNCTION iam_private.resolve_membership_identifiers(p_ids text[], p_keys uuid[])
RETURNS TABLE(membership_key uuid, membership_id text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam_private
AS $$
    SELECT mapping.membership_key, mapping.membership_id
    FROM iam_private.membership_identifiers mapping
    WHERE mapping.scope_key = COALESCE(current_setting('iam.testing_environment_id', true), '')
      AND (mapping.membership_id = ANY(p_ids) OR mapping.membership_key = ANY(p_keys))
$$;
REVOKE ALL ON FUNCTION iam_private.resolve_membership_identifiers(text[], uuid[]) FROM PUBLIC;
DO $$ BEGIN
    IF to_regrole('silicon_iam_api') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION iam_private.resolve_membership_identifiers(text[], uuid[]) TO silicon_iam_api;
    END IF;
    IF to_regrole('silicon_iam_worker') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION iam_private.resolve_membership_identifiers(text[], uuid[]) TO silicon_iam_worker;
    END IF;
END $$;
