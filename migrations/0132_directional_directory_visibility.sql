-- Directional directory visibility belongs to the viewing membership. It does
-- not grant capabilities, and a visible member need not be able to see back.
ALTER TABLE iam.organizations ADD COLUMN directory_visibility_epoch bigint NOT NULL DEFAULT 1;
CREATE TABLE iam.organization_directory_policies (
 organization_id uuid PRIMARY KEY REFERENCES iam.organizations(id) ON DELETE CASCADE,
 mode text NOT NULL CHECK(mode IN('all','self','selected')),
 visible_membership_ids uuid[] NOT NULL DEFAULT '{}', version bigint NOT NULL DEFAULT 1,
 CHECK(cardinality(visible_membership_ids)<=1000), CHECK(mode='selected' OR cardinality(visible_membership_ids)=0)
);
CREATE TABLE iam.membership_directory_visibility (
 membership_id uuid PRIMARY KEY REFERENCES iam.organization_memberships(id) ON DELETE CASCADE,
 organization_id uuid NOT NULL REFERENCES iam.organizations(id) ON DELETE CASCADE,
 mode text NOT NULL CHECK(mode IN('inherit','all','self','selected')),
 visible_membership_ids uuid[] NOT NULL DEFAULT '{}', version bigint NOT NULL DEFAULT 1,
 FOREIGN KEY(organization_id,membership_id) REFERENCES iam.organization_memberships(organization_id,id) ON DELETE CASCADE,
 CHECK(cardinality(visible_membership_ids)<=1000), CHECK(mode='selected' OR cardinality(visible_membership_ids)=0)
);
DO $$ DECLARE relation_name text; BEGIN
 FOREACH relation_name IN ARRAY ARRAY['organization_directory_policies','membership_directory_visibility'] LOOP
  EXECUTE format('ALTER TABLE iam.%I ENABLE ROW LEVEL SECURITY',relation_name);
  EXECUTE format('REVOKE ALL ON iam.%I FROM PUBLIC',relation_name);
  IF to_regprocedure('iam_private.current_testing_environment_id()') IS NOT NULL THEN
   EXECUTE format('ALTER TABLE iam.%I ADD COLUMN testing_environment_id uuid NOT NULL DEFAULT iam_private.current_testing_environment_id()',relation_name);
   EXECUTE format('CREATE POLICY testing_environment_isolation ON iam.%I AS RESTRICTIVE USING(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id()) WITH CHECK(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id())',relation_name);
   EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',relation_name);
  END IF;
 END LOOP;
END $$;
CREATE FUNCTION iam_private.directory_member_visible(p_viewer text,p_org uuid,p_target uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT EXISTS(SELECT 1 FROM iam.organization_memberships viewer JOIN iam.organization_memberships target ON target.organization_id=viewer.organization_id
 LEFT JOIN iam.organization_directory_policies defaults ON defaults.organization_id=viewer.organization_id
 LEFT JOIN iam.membership_directory_visibility overrides ON overrides.membership_id=viewer.id
 WHERE viewer.principal_id=p_viewer AND viewer.organization_id=p_org AND viewer.status='active' AND target.id=p_target
 AND (viewer.id=target.id OR CASE COALESCE(NULLIF(overrides.mode,'inherit'),defaults.mode,'all')
  WHEN 'all' THEN true WHEN 'self' THEN false
  ELSE target.id=ANY(CASE WHEN overrides.mode='selected' THEN overrides.visible_membership_ids ELSE COALESCE(defaults.visible_membership_ids,'{}'::uuid[]) END) END));
$$;
REVOKE ALL ON FUNCTION iam_private.directory_member_visible(text,uuid,uuid) FROM PUBLIC;
-- The isolated testing definer must read memberships to evaluate this predicate;
-- its independent testing-environment RLS remains enforced. Public projection
-- definers and notification paths check directory visibility explicitly.
-- Existing membership/invitation policies still establish the surrounding
-- authority. Nonmembers gain nothing; legitimate invitation previews survive.
CREATE POLICY directory_visibility_filter ON iam.organization_memberships AS RESTRICTIVE FOR SELECT
 USING(current_user='silicon_iam_testing_definer' OR NOT iam_private.is_active_organization_member(organization_id,iam_private.current_principal_id())
 OR iam_private.directory_member_visible(iam_private.current_principal_id(),organization_id,id));
CREATE POLICY directory_settings_visibility_filter ON iam.carbon_membership_settings AS RESTRICTIVE FOR SELECT
 USING(current_user='silicon_iam_testing_definer' OR iam_private.directory_member_visible(iam_private.current_principal_id(),organization_id,membership_id));
CREATE POLICY directory_tags_visibility_filter ON iam.membership_tags AS RESTRICTIVE FOR SELECT
 USING(current_user='silicon_iam_testing_definer' OR iam_private.directory_member_visible(iam_private.current_principal_id(),organization_id,membership_id));

CREATE FUNCTION iam_private.directory_visibility_get(p_org uuid,p_member uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE current_mode text; targets uuid[]; current_version bigint; effective text; effective_targets uuid[];
BEGIN
 IF NOT iam_private.has_organization_capability(p_org,iam_private.current_principal_id(),CASE WHEN p_member IS NULL THEN 'organization.update' ELSE 'members.update_directory' END) THEN
  RAISE EXCEPTION 'directory_visibility_forbidden' USING ERRCODE='42501'; END IF;
 IF p_member IS NOT NULL AND NOT EXISTS(SELECT 1 FROM iam.organization_memberships WHERE id=p_member AND organization_id=p_org) THEN
  RAISE EXCEPTION 'directory_member_not_found' USING ERRCODE='P0001'; END IF;
 SELECT COALESCE(mode,'all'),COALESCE(visible_membership_ids,'{}'::uuid[]) INTO effective,effective_targets FROM iam.organization_directory_policies WHERE organization_id=p_org;
 effective:=COALESCE(effective,'all'); effective_targets:=COALESCE(effective_targets,'{}'::uuid[]);
 IF p_member IS NULL THEN
  SELECT mode,visible_membership_ids,version INTO current_mode,targets,current_version FROM iam.organization_directory_policies WHERE organization_id=p_org;
  current_mode:=COALESCE(current_mode,'all');
 ELSE
  SELECT mode,visible_membership_ids,version INTO current_mode,targets,current_version FROM iam.membership_directory_visibility WHERE membership_id=p_member;
  current_mode:=COALESCE(current_mode,'inherit');
 END IF;
 targets:=COALESCE(targets,'{}'::uuid[]);
 IF current_mode<>'inherit' THEN effective:=current_mode; effective_targets:=targets; END IF;
 RETURN jsonb_build_object('version',COALESCE(current_version,1),'mode',current_mode,'effective_mode',effective,
 'visible_membership_ids',COALESCE((SELECT jsonb_agg(mapping.membership_id ORDER BY mapping.membership_id) FROM iam_private.resolve_membership_identifiers('{}',targets) mapping),'[]'::jsonb),
 'effective_visible_membership_ids',COALESCE((SELECT jsonb_agg(mapping.membership_id ORDER BY mapping.membership_id) FROM iam_private.resolve_membership_identifiers('{}',effective_targets) mapping),'[]'::jsonb));
END $$;
REVOKE ALL ON FUNCTION iam_private.directory_visibility_get(uuid,uuid) FROM PUBLIC;
CREATE FUNCTION iam_private.directory_visibility_replace(p_org uuid,p_member uuid,p_mode text,p_targets text[],p_version bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE before jsonb; ids uuid[]; expected integer;
BEGIN
 before:=iam_private.directory_visibility_get(p_org,p_member);
 PERFORM id FROM iam.organizations WHERE id=p_org FOR UPDATE;
 before:=iam_private.directory_visibility_get(p_org,p_member);
 IF (before->>'version')::bigint<>p_version THEN RAISE EXCEPTION 'directory_visibility_changed' USING ERRCODE='40001'; END IF;
 IF p_mode NOT IN('all','self','selected','inherit') OR (p_member IS NULL AND p_mode='inherit') OR p_targets IS NULL
 OR cardinality(p_targets)>1000 OR (p_mode<>'selected' AND cardinality(p_targets)>0)
 OR cardinality(p_targets)<>(SELECT count(DISTINCT t) FROM unnest(p_targets)t) THEN
  RAISE EXCEPTION 'directory_visibility_invalid' USING ERRCODE='22023'; END IF;
 SELECT COALESCE(array_agg(member.id ORDER BY member.id),'{}'::uuid[]) INTO ids
 FROM iam.organization_memberships member
 WHERE member.organization_id=p_org AND member.status='active' AND (member.id::text=ANY(p_targets) OR member.id IN(SELECT membership_key FROM iam_private.resolve_membership_identifiers(p_targets,'{}')));
 IF cardinality(ids)<>cardinality(p_targets) THEN RAISE EXCEPTION 'directory_visibility_invalid' USING ERRCODE='22023'; END IF;
 IF p_member IS NULL THEN
  INSERT INTO iam.organization_directory_policies(organization_id,mode,visible_membership_ids,version) VALUES(p_org,p_mode,ids,p_version+1)
  ON CONFLICT(organization_id) DO UPDATE SET mode=excluded.mode,visible_membership_ids=excluded.visible_membership_ids,version=excluded.version;
 ELSE
  INSERT INTO iam.membership_directory_visibility(organization_id,membership_id,mode,visible_membership_ids,version) VALUES(p_org,p_member,p_mode,ids,p_version+1)
  ON CONFLICT(membership_id) DO UPDATE SET mode=excluded.mode,visible_membership_ids=excluded.visible_membership_ids,version=excluded.version;
 END IF;
 UPDATE iam.organizations SET directory_visibility_epoch=directory_visibility_epoch+1 WHERE id=p_org;
 RETURN iam_private.directory_visibility_get(p_org,p_member);
END $$;
REVOKE ALL ON FUNCTION iam_private.directory_visibility_replace(uuid,uuid,text,text[],bigint) FROM PUBLIC;

-- Security-definer webhook projections must respect the consenting account's
-- view, independently of the identity performing the mutation.
DO $$ DECLARE definition text; updated text; BEGIN
 SELECT pg_get_functiondef('iam_private.list_organization_member_webhook_authorizations(uuid,uuid[],timestamptz)'::regprocedure) INTO definition;
 updated:=replace(definition,'AND membership.id = ANY(p_membership_ids)', 'AND membership.id = ANY(p_membership_ids) AND iam_private.directory_member_visible(consent.subject_principal_id,p_organization_id,membership.id)');
 IF updated=definition THEN RAISE EXCEPTION 'directory webhook authorization patch did not match'; END IF;
 EXECUTE updated;
END $$;
-- Invalidate queued snapshots after a visibility change. Re-reading the live
-- policy before delivery cannot safely redact an already encrypted snapshot.
ALTER TABLE iam.application_webhook_event_projections ADD COLUMN directory_visibility_epoch bigint;
CREATE FUNCTION iam_private.stamp_projection_directory_visibility() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
BEGIN
 SELECT org.directory_visibility_epoch INTO NEW.directory_visibility_epoch FROM iam.outbox_events event JOIN iam.organizations org ON org.id=event.organization_id WHERE event.id=NEW.outbox_event_id;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam_private.stamp_projection_directory_visibility() FROM PUBLIC;
CREATE TRIGGER application_projection_directory_visibility BEFORE INSERT ON iam.application_webhook_event_projections FOR EACH ROW EXECUTE FUNCTION iam_private.stamp_projection_directory_visibility();
DO $$ DECLARE signature text; definition text; updated text; BEGIN
 FOREACH signature IN ARRAY ARRAY['iam_private.get_worker_application_webhook_event_projection(uuid,text)','iam_private.list_worker_captured_application_webhook_recipients(uuid)'] LOOP
  SELECT pg_get_functiondef(signature::regprocedure) INTO definition;
  updated:=replace(definition,'projection.outbox_event_id = p_outbox_event_id', 'projection.outbox_event_id = p_outbox_event_id AND (event.organization_id IS NULL OR projection.directory_visibility_epoch=(SELECT o.directory_visibility_epoch FROM iam.organizations o WHERE o.id=event.organization_id))');
  IF updated=definition THEN RAISE EXCEPTION 'directory webhook delivery patch did not match %',signature; END IF;
  EXECUTE updated;
 END LOOP;
END $$;

-- Silicon notifications are checked at delivery time against the receiver's
-- current view. Multi-member events are withheld if any represented member is hidden.
DO $$ DECLARE definition text; updated text; BEGIN
 SELECT pg_get_functiondef('iam_private.list_worker_silicon_webhook_recipients(uuid)'::regprocedure) INTO definition;
 updated:=replace(definition,'AND event.silicon_webhook_routable', 'AND event.silicon_webhook_routable AND (event.affected_membership_id IS NULL OR iam_private.directory_member_visible(silicon.id,event.organization_id,event.affected_membership_id)) AND NOT EXISTS(SELECT 1 FROM iam.outbox_event_own_tag_memberships visible_target WHERE visible_target.outbox_event_id=event.id AND NOT iam_private.directory_member_visible(silicon.id,event.organization_id,visible_target.membership_id))');
 IF updated=definition THEN RAISE EXCEPTION 'directory silicon notification patch did not match'; END IF;
 EXECUTE updated;
END $$;

-- Managers need a deliberate settings picker even if their ordinary directory
-- is restricted. This route is separate from every ordinary directory projection.
CREATE FUNCTION iam_private.directory_visibility_candidates(p_org uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE items jsonb;
BEGIN
 IF NOT iam_private.has_organization_capability(p_org,iam_private.current_principal_id(),'organization.update')
 AND NOT iam_private.has_organization_capability(p_org,iam_private.current_principal_id(),'members.update_directory') THEN
  RAISE EXCEPTION 'directory_visibility_forbidden' USING ERRCODE='42501'; END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('membership_id',member.principal_id||'['||org.org_id||']','public_id',member.principal_id,
 'display_name',COALESCE(carbon.display_name,silicon.display_name,member.principal_id),'type',member.principal_kind) ORDER BY member.principal_id),'[]'::jsonb) INTO items
 FROM iam.organization_memberships member JOIN iam.organizations org ON org.id=member.organization_id
 JOIN iam.principals principal ON principal.id=member.principal_id AND principal.status='active'
 LEFT JOIN iam.carbons carbon ON carbon.id=member.principal_id LEFT JOIN iam.silicons silicon ON silicon.id=member.principal_id
 WHERE member.organization_id=p_org AND member.status='active';
 RETURN jsonb_build_object('items',items);
END $$;
REVOKE ALL ON FUNCTION iam_private.directory_visibility_candidates(uuid) FROM PUBLIC;

-- An organization remains discoverable when its viewer hides the owner profile.
-- Only the existing owner membership reference in organization metadata is exposed.
CREATE FUNCTION iam_private.organization_owner_reference(p_org uuid) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT owner.id FROM iam.organization_memberships owner
 WHERE owner.organization_id=p_org AND owner.org_role='owner' AND owner.status='active'
 AND EXISTS(SELECT 1 FROM iam.organization_memberships viewer WHERE viewer.organization_id=p_org
  AND viewer.principal_id=iam_private.current_principal_id() AND viewer.status='active');
$$;
REVOKE ALL ON FUNCTION iam_private.organization_owner_reference(uuid) FROM PUBLIC;

-- Retain the existing API name while supporting either account's own history.
DO $$ DECLARE definition text; updated text; BEGIN
 SELECT pg_get_functiondef('iam_private.list_removed_organizations_for_current_carbon(uuid,integer)'::regprocedure) INTO definition;
 updated:=replace(definition,E'JOIN iam.carbons AS carbon\n      ON carbon.id = caller.id\n     AND carbon.deleted_at IS NULL',E'LEFT JOIN iam.carbons AS carbon ON carbon.id = caller.id\n    LEFT JOIN iam.silicons AS silicon ON silicon.id = caller.id');
 updated:=replace(updated,'caller_membership.principal_kind = ''carbon''','caller_membership.principal_kind = caller.kind');
 updated:=replace(updated,'caller.kind = ''carbon''','((caller.kind = ''carbon'' AND carbon.deleted_at IS NULL) OR (caller.kind = ''silicon'' AND silicon.provisioning_status = ''active'' AND silicon.deleted_at IS NULL))');
 IF updated=definition THEN RAISE EXCEPTION 'removed organization identity patch did not match'; END IF;
 EXECUTE updated;
END $$;
