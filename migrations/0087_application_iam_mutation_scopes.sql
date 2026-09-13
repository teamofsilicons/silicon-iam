-- Application mutation scopes; approval, user consent and actor authority remain independent.
INSERT INTO iam.oauth_scope_catalog(scope, description, sensitive) VALUES
('organizations.create','Create an organization on behalf of a Carbon; that Carbon becomes its owner',true),
('organization.profile.update','Change organization name, logo, description',true),
('organization.invitations.create','Invite Carbons with the permitted invitation settings',true),
('organization.invitations.revoke','Revoke pending Carbon invitations',true),
('organization.silicons.create','Create a Silicon account in the organization',true),
('organization.silicons.update','Update Silicon profile details and reporting relationships',true),
('organization.carbons.remove','Remove Carbons from the organization',true),
('organization.silicons.remove','Remove Silicons from the organization',true),
('organization.tags.create','Create tags',true),
('organization.tags.update','Edit tag definitions',true),
('organization.tags.delete','Delete tags',true),
('organization.member_tags.update','Assign or remove members’ tags',true),
('organization.job_roles.update','Change members’ descriptive job roles',true),
('organization.silicon_access.update','Change first Silicon and extra Silicon assignments',true),
('organization.trust.update','Change trust defaults and rules',true),
('organization.admins.promote','Promote a Carbon member to admin',true),
('organization.admins.demote','Remove a Carbon’s admin status',true),
('organization.capabilities.update','Change an admin’s explicitly assigned capabilities',true),
('organization.change_requests.read','List and fetch role/tag change requests, including their decisions',true),
('organization.job_role_changes.request','Submit a role-change request',true),
('organization.tag_changes.request','Submit a tag-change request',true),
('organization.change_requests.decide','Approve or reject a request the represented user is eligible to decide',true),
('organization.job_role_history.read','View job-role change history',true),
('organization.tag_history.read','View tag-assignment history',true),
('organizations.join','Complete invitation verification and join; still require a valid invitation or successful SSO',true),
('organization.sso.read','View and configure SSO, including join-method settings',true),
('organization.sso.manage','View and configure SSO, including join-method settings',true),
('organization.silicons.credentials.rotate','Rotate Silicon credentials separately from editing their profile',true);

ALTER TABLE iam.organizations ADD COLUMN allowed_restricted_iam_scopes text[] NOT NULL DEFAULT ARRAY['organization.silicons.credentials.rotate', 'organization.sso.read', 'organization.sso.manage', 'organization.invitations.create', 'organization.silicons.create', 'organization.member_tags.update', 'organization.job_roles.update', 'organization.silicon_access.update', 'organization.trust.update', 'organization.admins.promote', 'organization.capabilities.update', 'organization.change_requests.decide', 'organizations.join']::text[],
 ADD CONSTRAINT organizations_restricted_iam_scopes_valid CHECK (array_position(allowed_restricted_iam_scopes, NULL) IS NULL AND allowed_restricted_iam_scopes <@ ARRAY['organization.silicons.credentials.rotate', 'organization.sso.read', 'organization.sso.manage', 'organization.invitations.create', 'organization.silicons.create', 'organization.member_tags.update', 'organization.job_roles.update', 'organization.silicon_access.update', 'organization.trust.update', 'organization.admins.promote', 'organization.capabilities.update', 'organization.change_requests.decide', 'organizations.join']::text[]);

CREATE FUNCTION iam_private.application_iam_scope_allowed(p_app uuid, p_scope text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT CASE WHEN p_scope = ANY(ARRAY['organization.silicons.credentials.rotate', 'organization.sso.read', 'organization.sso.manage', 'organization.invitations.create', 'organization.silicons.create', 'organization.member_tags.update', 'organization.job_roles.update', 'organization.silicon_access.update', 'organization.trust.update', 'organization.admins.promote', 'organization.capabilities.update', 'organization.change_requests.decide', 'organizations.join']::text[]) THEN EXISTS (
   SELECT 1 FROM iam.applications app JOIN iam.organizations org ON org.id = app.organization_id
   WHERE app.id = p_app AND org.status = 'active' AND org.trusted_org
     AND p_scope = ANY(org.allowed_restricted_iam_scopes)
 ) ELSE true END
$$;
REVOKE ALL ON FUNCTION iam_private.application_iam_scope_allowed(uuid,text) FROM PUBLIC;

CREATE FUNCTION iam_private.enforce_application_iam_scope_policy()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE policy_scopes text[];
BEGIN
 IF TG_TABLE_NAME = 'application_scope_requests' THEN
   policy_scopes := NEW.scopes;
 ELSIF TG_TABLE_NAME = 'application_approved_scopes' THEN
   IF NEW.revoked_at IS NOT NULL THEN
     -- The policy revoker already holds the organization and application locks.
     RETURN NEW;
   END IF;
   policy_scopes := ARRAY[NEW.scope];
 ELSE
   policy_scopes := ARRAY[NEW.scope];
 END IF;
 IF policy_scopes && ARRAY['organization.silicons.credentials.rotate', 'organization.sso.read', 'organization.sso.manage', 'organization.invitations.create', 'organization.silicons.create', 'organization.member_tags.update', 'organization.job_roles.update', 'organization.silicon_access.update', 'organization.trust.update', 'organization.admins.promote', 'organization.capabilities.update', 'organization.change_requests.decide', 'organizations.join']::text[] THEN
   -- A concurrent new/imported application is not visible to the policy
   -- revoker's application scan. Keep its organization policy stable until
   -- the grant commits, so revocation must observe that application afterward.
   -- Existing application-first configuration can deadlock with an
   -- organization-first policy change; PostgreSQL aborts one transaction,
   -- which must be retried rather than allowing authority to survive.
   PERFORM organization.id
   FROM iam.organizations organization
   JOIN iam.applications application ON application.organization_id = organization.id
   WHERE application.id = NEW.application_id
   FOR SHARE OF organization;
 END IF;
 IF EXISTS (
   SELECT 1 FROM unnest(policy_scopes) scope
   WHERE NOT iam_private.application_iam_scope_allowed(NEW.application_id, scope)
 ) THEN
   RAISE EXCEPTION 'application_scope_unavailable' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam_private.enforce_application_iam_scope_policy() FROM PUBLIC;
CREATE TRIGGER application_requested_iam_scope_policy BEFORE INSERT OR UPDATE ON iam.application_requested_scopes FOR EACH ROW EXECUTE FUNCTION iam_private.enforce_application_iam_scope_policy();
CREATE TRIGGER application_approved_iam_scope_policy BEFORE INSERT OR UPDATE ON iam.application_approved_scopes FOR EACH ROW EXECUTE FUNCTION iam_private.enforce_application_iam_scope_policy();
CREATE TRIGGER application_scope_request_iam_policy BEFORE INSERT OR UPDATE OF scopes ON iam.application_scope_requests FOR EACH ROW EXECUTE FUNCTION iam_private.enforce_application_iam_scope_policy();

-- Policy changes are system revocations, never attributed to an unrelated Carbon.
ALTER TABLE iam.application_approved_scopes
 ADD COLUMN revoked_by_policy boolean NOT NULL DEFAULT false,
 DROP CONSTRAINT application_approved_scopes_revocation_consistency,
 ADD CONSTRAINT application_approved_scopes_revocation_consistency CHECK (
   (revoked_at IS NULL AND revoked_by_carbon_id IS NULL AND NOT revoked_by_policy)
   OR (revoked_at IS NOT NULL AND (revoked_by_carbon_id IS NOT NULL OR revoked_by_policy))
 );

CREATE FUNCTION iam_private.revoke_unavailable_iam_scopes()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
BEGIN
 IF NEW.trusted_org IS NOT DISTINCT FROM OLD.trusted_org AND NEW.allowed_restricted_iam_scopes IS NOT DISTINCT FROM OLD.allowed_restricted_iam_scopes AND NEW.status IS NOT DISTINCT FROM OLD.status THEN RETURN NEW; END IF;
 -- Configuration and review acquire application locks before changing grants.
 -- Wait for those transactions before taking fresh snapshots of their grants
 -- and tokens; scanning first can permanently miss an uncommitted approval.
 PERFORM application.id FROM iam.applications application
 WHERE application.organization_id = NEW.id
 ORDER BY application.id FOR UPDATE;
 UPDATE iam.application_approved_scopes approved SET revoked_at=transaction_timestamp(), revoked_by_policy=true
 FROM iam.applications app WHERE app.id=approved.application_id AND app.organization_id=NEW.id
 AND approved.revoked_at IS NULL AND NOT iam_private.application_iam_scope_allowed(app.id,approved.scope);
 UPDATE iam.access_tokens token SET revoked_at=transaction_timestamp(),revocation_reason='application_scope_unavailable'
 FROM iam.applications app WHERE app.id=token.client_application_id AND app.organization_id=NEW.id
 AND token.revoked_at IS NULL AND EXISTS (SELECT 1 FROM iam.access_token_scopes scope
 WHERE scope.access_token_id=token.id AND NOT iam_private.application_iam_scope_allowed(app.id,scope.scope));
 UPDATE iam.applications SET updated_at=transaction_timestamp() WHERE organization_id=NEW.id;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam_private.revoke_unavailable_iam_scopes() FROM PUBLIC;
CREATE TRIGGER organization_iam_scope_policy_changed AFTER UPDATE OF trusted_org, allowed_restricted_iam_scopes, status ON iam.organizations FOR EACH ROW EXECUTE FUNCTION iam_private.revoke_unavailable_iam_scopes();

CREATE OR REPLACE FUNCTION iam_private.application_scope_catalog(p_app_id text DEFAULT NULL)
RETURNS TABLE(scope text,description text,critical boolean,app_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT catalog.scope,catalog.description,catalog.sensitive,NULL::text
 FROM iam.oauth_scope_catalog catalog WHERE p_app_id IS NULL
 AND (catalog.scope LIKE 'self.%' OR catalog.scope LIKE 'directory.%' OR catalog.scope LIKE 'organization.%' OR catalog.scope LIKE 'organizations.%')
 UNION ALL
 SELECT 'obo:' || app.app_id || ':' || endpoint.endpoint_id,
 endpoint.endpoint_id || ' (' || endpoint.path || ')',endpoint.critical,app.app_id
 FROM iam.application_obo_endpoints endpoint JOIN iam.applications app ON app.id=endpoint.application_id
 WHERE app.deleted_at IS NULL AND app.review_status='verified' AND endpoint.status='active'
 AND (p_app_id IS NULL OR app.app_id=p_app_id)
$$;
REVOKE ALL ON FUNCTION iam_private.application_scope_catalog(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.iam_scope_catalog()
RETURNS TABLE(scope text, description text, critical boolean, app_id text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam AS $$
    SELECT catalog.scope, catalog.description, catalog.sensitive, NULL::text
    FROM iam.oauth_scope_catalog AS catalog
    WHERE catalog.scope = ANY(ARRAY[
        'self.identity.read',
        'self.profile.read',
        'self.email.read',
        'self.phone.read',
        'self.organizations.read',
        'self.membership.read',
        'self.capabilities.read',
        'self.job_role.read',
        'self.tags.read',
        'self.silicon_access.read',
        'self.hierarchy.read',
        'self.trust.read',
        'directory.carbons.read',
        'directory.silicons.read',
        'directory.profiles.read',
        'directory.memberships.read',
        'directory.capabilities.read',
        'directory.job_roles.read',
        'directory.tags.read',
        'directory.silicon_access.read',
        'directory.hierarchy.read',
        'organization.tags.read',
        'organization.trust.read',
        'organization.invitations.read',
        'organization.governance.read',
        'organizations.create',
        'organization.profile.update',
        'organization.invitations.create',
        'organization.invitations.revoke',
        'organization.silicons.create',
        'organization.silicons.update',
        'organization.carbons.remove',
        'organization.silicons.remove',
        'organization.tags.create',
        'organization.tags.update',
        'organization.tags.delete',
        'organization.member_tags.update',
        'organization.job_roles.update',
        'organization.silicon_access.update',
        'organization.trust.update',
        'organization.admins.promote',
        'organization.admins.demote',
        'organization.capabilities.update',
        'organization.change_requests.read',
        'organization.job_role_changes.request',
        'organization.tag_changes.request',
        'organization.change_requests.decide',
        'organization.job_role_history.read',
        'organization.tag_history.read',
        'organizations.join',
        'organization.sso.read',
        'organization.sso.manage',
        'organization.silicons.credentials.rotate'
    ]::text[])
$$;
REVOKE ALL ON FUNCTION iam_private.iam_scope_catalog() FROM PUBLIC;

COMMENT ON FUNCTION iam_private.iam_scope_catalog() IS
    'Public IAM permission definitions only; excludes external application scope history and testing-environment data.';
