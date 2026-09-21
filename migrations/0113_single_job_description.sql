-- Job Description is the organization's single descriptive job field.
-- Existing nonblank job roles win; the old identity profile description is a
-- fallback only. Organization and application descriptions remain independent.
UPDATE iam.organization_memberships AS member
SET job_role = COALESCE(
    CASE WHEN NULLIF(btrim(member.job_role), '') IS NOT NULL THEN member.job_role END,
    CASE WHEN NULLIF(btrim(carbon.description), '') IS NOT NULL THEN carbon.description END,
    CASE WHEN NULLIF(btrim(silicon.description), '') IS NOT NULL THEN silicon.description END,
    ''
)
FROM iam.principals AS principal
LEFT JOIN iam.carbons AS carbon ON carbon.id = principal.id
    AND (to_jsonb(carbon)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(principal)->>'testing_environment_id')
LEFT JOIN iam.silicons AS silicon ON silicon.id = principal.id
    AND (to_jsonb(silicon)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(principal)->>'testing_environment_id')
WHERE member.principal_id = principal.id
  AND (to_jsonb(member)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(principal)->>'testing_environment_id')
  AND NULLIF(btrim(member.job_role), '') IS NULL
  AND COALESCE(NULLIF(btrim(carbon.description), ''), NULLIF(btrim(silicon.description), '')) IS NOT NULL;

-- Keep callable signatures stable for already prepared server statements;
-- retired description argument slots are ignored. Rebuild stored definitions
-- before dropping the columns, including projections used by signed events.
DO $$
DECLARE entry record; definition text;
BEGIN
    FOR entry IN
        SELECT procedure.oid, procedure.proname
        FROM pg_proc AS procedure
        JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname IN ('iam', 'iam_private')
          AND procedure.prokind = 'f'
    LOOP
        definition := pg_get_functiondef(entry.oid);
        IF entry.proname = 'complete_verified_signup' THEN
            definition := replace(definition, E'        description,\n', '');
            definition := replace(definition, E'        p_description,\n', '');
        END IF;
        IF entry.proname = 'update_silicon_self_profile' THEN
            definition := replace(definition, E'        description = CASE WHEN p_set_description THEN p_description ELSE description END,\n', '');
            definition := replace(definition, E'          OR (p_set_description AND description IS DISTINCT FROM p_description)\n', '');
        END IF;
        definition := regexp_replace(definition,
            $pattern$'description', CASE\s+WHEN membership.principal_kind = 'carbon' THEN carbon.description\s+ELSE silicon.description\s+END,$pattern$,
            '', 'g');
        definition := replace(definition, '''job_role'',', '''job_description'',');
        IF definition IS DISTINCT FROM pg_get_functiondef(entry.oid) THEN
            EXECUTE definition;
        END IF;
    END LOOP;
END $$;

ALTER TABLE iam.carbons DROP COLUMN description;
ALTER TABLE iam.silicons DROP COLUMN description;
COMMENT ON COLUMN iam.organization_memberships.job_role IS
    'The single Job Description for this organization membership; exposed as job_description.';
UPDATE iam.oauth_scope_catalog
SET description = CASE scope
    WHEN 'self.profile.read' THEN 'Your name, photo and timezone.'
    WHEN 'directory.profiles.read' THEN 'Other members names, photos and timezones.'
    WHEN 'self.job_role.read' THEN 'Your job description in the selected organization.'
    WHEN 'directory.job_roles.read' THEN 'Other members job descriptions.'
    ELSE description END
WHERE scope IN ('self.profile.read','directory.profiles.read','self.job_role.read','directory.job_roles.read');
