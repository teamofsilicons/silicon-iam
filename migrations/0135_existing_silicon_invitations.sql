-- Existing Silicons join as themselves. Custody and credential ownership are
-- independent of membership and never transfer with an invitation.
CREATE TABLE iam.organization_silicon_invitations(
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES iam.organizations(id) ON DELETE CASCADE,
 silicon_id text NOT NULL, invited_by_membership_id uuid NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN('pending','accepted','declined','revoked')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '7 days',decided_at timestamptz,
 FOREIGN KEY(organization_id,invited_by_membership_id) REFERENCES iam.organization_memberships(organization_id,id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX organization_silicon_invitation_pending ON iam.organization_silicon_invitations(organization_id,silicon_id) WHERE status='pending';
ALTER TABLE iam.organization_silicon_invitations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON iam.organization_silicon_invitations FROM PUBLIC;
DO $$ BEGIN
 IF to_regprocedure('iam_private.current_testing_environment_id()') IS NOT NULL THEN
  ALTER TABLE iam.organization_silicon_invitations ADD COLUMN testing_environment_id uuid NOT NULL DEFAULT iam_private.current_testing_environment_id();
  CREATE POLICY testing_environment_isolation ON iam.organization_silicon_invitations AS RESTRICTIVE USING(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id()) WITH CHECK(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id());
  ALTER TABLE iam.organization_silicon_invitations FORCE ROW LEVEL SECURITY;
  ALTER TABLE iam.organization_silicon_invitations ADD FOREIGN KEY(testing_environment_id,silicon_id) REFERENCES iam.silicons(testing_environment_id,id) ON DELETE CASCADE;
 ELSE
  ALTER TABLE iam.organization_silicon_invitations ADD FOREIGN KEY(silicon_id) REFERENCES iam.silicons(id) ON DELETE CASCADE;
 END IF;
END $$;
CREATE FUNCTION iam_private.silicon_invitation_source_allowed(p_actor text,p_target text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 PERFORM 1 FROM iam.organization_memberships actor JOIN iam.organization_memberships target ON target.organization_id=actor.organization_id
 JOIN iam.organizations org ON org.id=actor.organization_id AND org.status='active'
 JOIN iam.principals principal ON principal.id=target.principal_id AND principal.kind='silicon' AND principal.status='active'
 JOIN iam.silicons silicon ON silicon.id=principal.id AND silicon.provisioning_status='active' AND silicon.deleted_at IS NULL
 WHERE actor.principal_id=p_actor AND actor.status='active' AND target.principal_id=p_target AND target.status='active'
 AND iam_private.directory_member_visible(p_actor,org.id,target.id) FOR SHARE OF actor,target,org,principal,silicon;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION iam_private.silicon_invitation_source_allowed(text,text) FROM PUBLIC;
CREATE FUNCTION iam_private.silicon_invitation_json(p_id uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,iam AS $$
 SELECT jsonb_build_object('id',invite.id,'org_id',org.org_id,'organization_name',org.name,'silicon_id',invite.silicon_id,
 'display_name',silicon.display_name,'invited_by',inviter.principal_id,'status',CASE WHEN invite.status='pending' AND invite.expires_at<=clock_timestamp() THEN 'expired' ELSE invite.status END,
 'created_at',invite.created_at,'expires_at',invite.expires_at,'decided_at',invite.decided_at)
 FROM iam.organization_silicon_invitations invite JOIN iam.organizations org ON org.id=invite.organization_id
 JOIN iam.silicons silicon ON silicon.id=invite.silicon_id JOIN iam.organization_memberships inviter ON inviter.id=invite.invited_by_membership_id WHERE invite.id=p_id;
$$;
REVOKE ALL ON FUNCTION iam_private.silicon_invitation_json(uuid) FROM PUBLIC;
CREATE FUNCTION iam_private.silicon_invitation_audit(p_id uuid,p_action text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 INSERT INTO iam.audit_events(id,request_id,actor_principal_id,actor_kind,organization_id,action,target_type,target_id,after_state)
 SELECT gen_random_uuid(),COALESCE(NULLIF(current_setting('iam.request_id',true),'')::uuid,gen_random_uuid()),p.id,p.kind,invite.organization_id,
 p_action,'silicon_invitation',invite.id,iam_private.silicon_invitation_json(invite.id)
 FROM iam.organization_silicon_invitations invite JOIN iam.principals p ON p.id=iam_private.current_principal_id() WHERE invite.id=p_id;
$$;
REVOKE ALL ON FUNCTION iam_private.silicon_invitation_audit(uuid,text) FROM PUBLIC;
CREATE FUNCTION iam_private.silicon_invitation_candidates(p_org uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE result jsonb;
BEGIN
 IF iam_private.current_application_id() IS NOT NULL OR NOT iam_private.has_organization_capability(p_org,iam_private.current_principal_id(),'members.invite') THEN RAISE EXCEPTION 'silicon_invitation_forbidden' USING ERRCODE='42501'; END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('silicon_id',s.id,'display_name',s.display_name,'source_org_ids',
 (SELECT jsonb_agg(DISTINCT org.org_id) FROM iam.organization_memberships target JOIN iam.organizations org ON org.id=target.organization_id
 JOIN iam.organization_memberships actor ON actor.organization_id=target.organization_id AND actor.principal_id=iam_private.current_principal_id() AND actor.status='active'
 WHERE target.principal_id=s.id AND target.status='active' AND org.status='active' AND iam_private.directory_member_visible(actor.principal_id,org.id,target.id))) ORDER BY s.id),'[]'::jsonb) INTO result
 FROM iam.silicons s WHERE iam_private.silicon_invitation_source_allowed(iam_private.current_principal_id(),s.id)
 AND NOT EXISTS(SELECT 1 FROM iam.organization_memberships m WHERE m.organization_id=p_org AND m.principal_id=s.id AND m.status='active');
 RETURN jsonb_build_object('items',result);
END $$;
REVOKE ALL ON FUNCTION iam_private.silicon_invitation_candidates(uuid) FROM PUBLIC;
CREATE FUNCTION iam_private.silicon_invitation_create(p_org uuid,p_silicon text,p_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE inviter uuid;
BEGIN
 IF iam_private.current_application_id() IS NOT NULL OR NOT iam_private.has_organization_capability(p_org,iam_private.current_principal_id(),'members.invite')
 OR NOT iam_private.silicon_invitation_source_allowed(iam_private.current_principal_id(),p_silicon) THEN RAISE EXCEPTION 'silicon_invitation_forbidden' USING ERRCODE='42501'; END IF;
 SELECT id INTO inviter FROM iam.organization_memberships WHERE organization_id=p_org AND principal_id=iam_private.current_principal_id() AND status='active' FOR SHARE;
 PERFORM id FROM iam.organizations WHERE id=p_org AND status='active' FOR UPDATE;
 IF NOT FOUND OR inviter IS NULL THEN RAISE EXCEPTION 'silicon_invitation_forbidden' USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT 1 FROM iam.organization_memberships WHERE organization_id=p_org AND principal_id=p_silicon AND status='active') THEN RAISE EXCEPTION 'silicon_already_member' USING ERRCODE='23505'; END IF;
 UPDATE iam.organization_silicon_invitations SET status='revoked',decided_at=clock_timestamp() WHERE organization_id=p_org AND silicon_id=p_silicon AND status='pending' AND expires_at<=clock_timestamp();
 INSERT INTO iam.organization_silicon_invitations(id,organization_id,silicon_id,invited_by_membership_id) VALUES(p_id,p_org,p_silicon,inviter);
 PERFORM iam_private.silicon_invitation_audit(p_id,'silicon.invitation_created');
 RETURN iam_private.silicon_invitation_json(p_id);
END $$;
REVOKE ALL ON FUNCTION iam_private.silicon_invitation_create(uuid,text,uuid) FROM PUBLIC;
CREATE FUNCTION iam_private.silicon_invitations_list(p_org uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE result jsonb;
BEGIN
 IF iam_private.current_application_id() IS NOT NULL THEN RAISE EXCEPTION 'silicon_invitation_forbidden' USING ERRCODE='42501'; END IF;
 IF p_org IS NOT NULL AND NOT iam_private.has_organization_capability(p_org,iam_private.current_principal_id(),'members.invite') THEN RAISE EXCEPTION 'silicon_invitation_forbidden' USING ERRCODE='42501'; END IF;
 SELECT COALESCE(jsonb_agg(iam_private.silicon_invitation_json(id) ORDER BY created_at DESC),'[]'::jsonb) INTO result
 FROM iam.organization_silicon_invitations WHERE (p_org IS NULL AND silicon_id=iam_private.current_principal_id()) OR organization_id=p_org;
 RETURN jsonb_build_object('items',result);
END $$;
REVOKE ALL ON FUNCTION iam_private.silicon_invitations_list(uuid) FROM PUBLIC;
CREATE FUNCTION iam_private.silicon_invitation_decide(p_id uuid,p_decision text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE invite iam.organization_silicon_invitations%ROWTYPE; inviter text; member_id uuid;
BEGIN
 IF iam_private.current_application_id() IS NOT NULL OR p_decision NOT IN('accept','decline') THEN RAISE EXCEPTION 'silicon_invitation_forbidden' USING ERRCODE='42501'; END IF;
 SELECT * INTO invite FROM iam.organization_silicon_invitations WHERE id=p_id AND silicon_id=iam_private.current_principal_id() FOR UPDATE;
 IF invite.id IS NULL THEN RAISE EXCEPTION 'silicon_invitation_not_found' USING ERRCODE='P0001'; END IF;
 IF invite.status<>'pending' OR invite.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'silicon_invitation_inactive' USING ERRCODE='P0001'; END IF;
 IF p_decision='accept' THEN
  SELECT principal_id INTO inviter FROM iam.organization_memberships WHERE id=invite.invited_by_membership_id AND status='active' FOR SHARE;
  IF inviter IS NULL OR NOT iam_private.has_organization_capability(invite.organization_id,inviter,'members.invite') OR NOT iam_private.silicon_invitation_source_allowed(inviter,invite.silicon_id) THEN
   RAISE EXCEPTION 'silicon_invitation_forbidden' USING ERRCODE='42501'; END IF;
  PERFORM id FROM iam.organizations WHERE id=invite.organization_id AND status='active' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'silicon_invitation_inactive' USING ERRCODE='P0001'; END IF;
  INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role,role_granted_by_membership_id)
  VALUES(gen_random_uuid(),invite.organization_id,invite.silicon_id,'silicon','member',invite.invited_by_membership_id)
  ON CONFLICT(organization_id,principal_id) DO UPDATE SET status='active',removed_at=NULL,suspended_at=NULL,org_role='member',role_granted_by_membership_id=excluded.role_granted_by_membership_id
  WHERE organization_memberships.status<>'active' RETURNING id INTO member_id;
  IF member_id IS NULL THEN RAISE EXCEPTION 'silicon_already_member' USING ERRCODE='23505'; END IF;
 END IF;
 UPDATE iam.organization_silicon_invitations SET status=CASE p_decision WHEN 'accept' THEN 'accepted' ELSE 'declined' END,decided_at=clock_timestamp() WHERE id=p_id;
 PERFORM iam_private.silicon_invitation_audit(p_id,'silicon.invitation_'||CASE p_decision WHEN 'accept' THEN 'accepted' ELSE 'declined' END);
 RETURN iam_private.silicon_invitation_json(p_id)||jsonb_build_object('membership_id',CASE WHEN member_id IS NULL THEN NULL ELSE invite.silicon_id||'['||(SELECT org_id FROM iam.organizations WHERE id=invite.organization_id)||']' END);
END $$;
REVOKE ALL ON FUNCTION iam_private.silicon_invitation_decide(uuid,text) FROM PUBLIC;

CREATE FUNCTION iam_private.silicon_invitation_revoke(p_org uuid,p_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 IF iam_private.current_application_id() IS NOT NULL OR NOT iam_private.has_organization_capability(p_org,iam_private.current_principal_id(),'members.invite') THEN RAISE EXCEPTION 'silicon_invitation_forbidden' USING ERRCODE='42501'; END IF;
 UPDATE iam.organization_silicon_invitations SET status='revoked',decided_at=clock_timestamp() WHERE id=p_id AND organization_id=p_org AND status='pending';
 IF NOT FOUND THEN RAISE EXCEPTION 'silicon_invitation_not_found' USING ERRCODE='P0001'; END IF;
 PERFORM iam_private.silicon_invitation_audit(p_id,'silicon.invitation_revoked');
 RETURN iam_private.silicon_invitation_json(p_id);
END $$;
REVOKE ALL ON FUNCTION iam_private.silicon_invitation_revoke(uuid,uuid) FROM PUBLIC;
-- Application logins for Silicons bind the selected active membership, including
-- independently registered and invited accounts, rather than a historical home.
DO $$ DECLARE definition text;updated text; BEGIN
 SELECT pg_get_functiondef('iam_private.lock_current_application_oauth_subject_authority(text,uuid,uuid,text,iam.principal_kind,uuid,uuid)'::regprocedure) INTO definition;
 updated:=replace(replace(definition,'AND (p_organization_id IS NULL OR silicon.organization_id = p_organization_id)','AND p_organization_id IS NOT NULL'),'AND (p_membership_id IS NULL OR silicon.membership_id = p_membership_id)','AND p_membership_id IS NOT NULL');
 updated:=replace(replace(updated,'organization.id = silicon.organization_id','organization.id = p_organization_id'),'membership.id = silicon.membership_id','membership.id = p_membership_id');
 IF updated=definition THEN RAISE EXCEPTION 'silicon application membership binding patch did not match'; END IF;
 EXECUTE updated;
END $$;
-- A Silicon profile is shared by its memberships. Its historical custody/home
-- organization is not the authority for directory reads in another organization.
CREATE POLICY silicons_associated_member_select ON iam.silicons FOR SELECT USING(
 EXISTS(SELECT 1 FROM iam.organization_memberships m WHERE m.principal_id=silicons.id AND m.status='active'
  AND (iam_private.current_organization_id() IS NULL OR m.organization_id=iam_private.current_organization_id())
  AND iam_private.directory_member_visible(iam_private.current_principal_id(),m.organization_id,m.id))
);
DO $$ DECLARE definition text;updated text; BEGIN
 SELECT pg_get_functiondef(oid) INTO definition FROM pg_proc WHERE pronamespace='iam_private'::regnamespace AND proname='get_organization_member_webhook_projection_sources';
 IF definition IS NOT NULL THEN
  updated:=replace(replace(definition,'AND silicon.organization_id = membership.organization_id',''),'AND silicon.membership_id = membership.id','');
  IF updated<>definition THEN EXECUTE updated; END IF;
 END IF;
END $$;
