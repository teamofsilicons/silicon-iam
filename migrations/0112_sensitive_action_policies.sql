-- Owner-configurable sensitive actions. Execution grants live only for the
-- exact database transaction in which the checked mutation is applied.
CREATE TABLE iam_private.action_policy_catalog (
    action text PRIMARY KEY,
    label text NOT NULL,
    default_allowed_actors text NOT NULL CHECK (default_allowed_actors IN ('any_member', 'only_admins', 'only_owner')),
    default_approval text NOT NULL CHECK (default_approval IN ('none', 'admin', 'owner')),
    capabilities text[] NOT NULL
);
INSERT INTO iam_private.action_policy_catalog VALUES
 ('membership.job_description.update', 'Change a member job description', 'any_member', 'none', ARRAY['roles.approve','members.update_directory','silicons.update_directory']),
 ('membership.tags.update', 'Change member tags', 'any_member', 'admin', ARRAY['tags.manage','members.update_directory','silicons.update_directory']),
 ('membership.directory.update', 'Change member Silicon access', 'only_admins', 'none', ARRAY['members.update_directory','silicons.update_directory']),
 ('silicon.self_profile.update', 'Change your own Silicon profile', 'any_member', 'none', ARRAY['silicons.update_directory']),
 ('silicon.profile.update', 'Change another Silicon profile', 'only_admins', 'none', ARRAY['silicons.update_directory','members.update_directory']),
 ('silicon.hierarchy.update', 'Change Silicon reporting hierarchy', 'only_admins', 'admin', ARRAY['silicons.manage_hierarchy','silicons.update_directory','members.update_directory']),
 ('organization.profile.update', 'Change organization profile', 'only_admins', 'none', ARRAY['organization.update']),
 ('tag.create', 'Create a tag', 'only_admins', 'none', ARRAY['tags.manage']),
 ('tag.update', 'Edit a tag', 'only_admins', 'none', ARRAY['tags.manage']),
 ('tag.delete', 'Delete a tag', 'only_admins', 'none', ARRAY['tags.manage']),
 ('trust.default.update', 'Change default trust', 'only_admins', 'none', ARRAY['trust.manage','members.update_directory']),
 ('trust.rule.create', 'Create a trust rule', 'only_admins', 'none', ARRAY['trust.manage']),
 ('trust.rule.update', 'Edit a trust rule', 'only_admins', 'none', ARRAY['trust.manage']),
 ('trust.rule.delete', 'Delete a trust rule', 'only_admins', 'none', ARRAY['trust.manage']);

CREATE TABLE iam_private.organization_action_policies (
    organization_id uuid NOT NULL REFERENCES iam.organizations(id) ON DELETE CASCADE,
    action text NOT NULL REFERENCES iam_private.action_policy_catalog(action),
    allowed_actors text NOT NULL CHECK (allowed_actors IN ('any_member', 'only_admins', 'only_owner')),
    approval text NOT NULL CHECK (approval IN ('none', 'admin', 'owner')),
    auto_carbon_ids text[] NOT NULL DEFAULT '{}',
    auto_silicon_ids text[] NOT NULL DEFAULT '{}',
    auto_tag_ids uuid[] NOT NULL DEFAULT '{}',
    version bigint NOT NULL DEFAULT 1,
    updated_by_membership_id uuid NOT NULL REFERENCES iam.organization_memberships(id) ON DELETE CASCADE,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, action)
);
CREATE TABLE iam_private.organization_action_approvals (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES iam.organizations(id) ON DELETE CASCADE,
    action text NOT NULL REFERENCES iam_private.action_policy_catalog(action),
    policy_version bigint NOT NULL,
    requested_by_membership_id uuid NOT NULL REFERENCES iam.organization_memberships(id) ON DELETE CASCADE,
    request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    method text NOT NULL,
    path text NOT NULL,
    request_body jsonb NOT NULL,
    expected_version text,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','consumed')),
    decided_by_membership_id uuid REFERENCES iam.organization_memberships(id) ON DELETE SET NULL,
    decided_at timestamptz,
    consumed_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT transaction_timestamp() + interval '12 hours'
);
CREATE INDEX organization_action_approvals_request_idx ON iam_private.organization_action_approvals
    (organization_id, action, requested_by_membership_id, request_fingerprint, policy_version, created_at DESC);
CREATE TABLE iam_private.organization_action_executions (
    transaction_id bigint NOT NULL,
    organization_id uuid NOT NULL REFERENCES iam.organizations(id) ON DELETE CASCADE,
    membership_id uuid NOT NULL REFERENCES iam.organization_memberships(id) ON DELETE CASCADE,
    action text NOT NULL,
    capabilities text[] NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (transaction_id, organization_id, membership_id, action)
);
CREATE INDEX organization_action_executions_cleanup_idx ON iam_private.organization_action_executions(created_at);
REVOKE ALL ON iam_private.action_policy_catalog, iam_private.organization_action_policies,
    iam_private.organization_action_approvals, iam_private.organization_action_executions FROM PUBLIC;

-- Pending requests from the replaced fixed-approval workflow must not bypass
-- newly configured policies. Their immutable payload/history remains readable.
UPDATE iam.approval_requests SET status='cancelled',cancelled_at=transaction_timestamp()
WHERE status IN ('pending','approved') AND request_kind IN
    ('carbon_job_role_change','silicon_job_role_change','carbon_tag_change','silicon_tag_change');

INSERT INTO iam.organization_capability_catalog(capability, description, delegable, allowed_for_carbon, allowed_for_silicon)
VALUES ('action_policies.manage', 'Configure sensitive-action permissions and approval rules', true, true, false)
ON CONFLICT (capability) DO NOTHING;

CREATE FUNCTION iam_private.action_execution_allowed(p_organization_id uuid, p_action text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT EXISTS (
        SELECT 1 FROM iam_private.organization_action_executions execution
        JOIN iam.organization_memberships member ON member.organization_id = execution.organization_id
            AND member.id = execution.membership_id
        WHERE execution.transaction_id = pg_current_xact_id()::text::bigint
          AND execution.organization_id = p_organization_id AND execution.action = p_action
          AND p_organization_id = iam_private.current_organization_id()
          AND member.principal_id = iam_private.current_principal_id() AND member.status = 'active'
    )
$$;
REVOKE ALL ON FUNCTION iam_private.action_execution_allowed(uuid, text) FROM PUBLIC;

CREATE FUNCTION iam_private.action_execution_capability(p_organization_id uuid, p_capability text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT EXISTS (
        SELECT 1 FROM iam_private.organization_action_executions execution
        JOIN iam.organization_memberships member ON member.organization_id = execution.organization_id
            AND member.id = execution.membership_id
        WHERE execution.transaction_id = pg_current_xact_id()::text::bigint
          AND execution.organization_id = p_organization_id
          AND p_capability = ANY(execution.capabilities)
          AND p_organization_id = iam_private.current_organization_id()
          AND member.principal_id = iam_private.current_principal_id() AND member.status = 'active'
    )
$$;
REVOKE ALL ON FUNCTION iam_private.action_execution_capability(uuid, text) FROM PUBLIC;

-- Preserve current identity argument types across the canonical-ID migration.
DO $$ DECLARE v_definition text; v_oid oid; BEGIN
    SELECT proc.oid INTO STRICT v_oid FROM pg_proc proc JOIN pg_namespace ns ON ns.oid=proc.pronamespace
    WHERE ns.nspname='iam_private' AND proc.proname='has_organization_capability';
    v_definition := pg_get_functiondef(v_oid);
    IF position('membership.org_role = ''owner''' IN v_definition) = 0 THEN
        RAISE EXCEPTION 'organization capability definition changed unexpectedly';
    END IF;
    v_definition := replace(v_definition, 'membership.org_role = ''owner''',
        'membership.org_role = ''owner'' OR iam_private.action_execution_capability(p_organization_id, p_capability)');
    EXECUTE v_definition;
END $$;

CREATE FUNCTION iam_private.list_action_policies(p_organization_id uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE v_member iam.organization_memberships%ROWTYPE; v_items jsonb;
BEGIN
    SELECT * INTO v_member FROM iam.organization_memberships
    WHERE organization_id=p_organization_id AND principal_id=iam_private.current_principal_id() AND status='active';
    IF NOT FOUND OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id() THEN
        RAISE EXCEPTION 'action_policy_forbidden' USING ERRCODE='42501';
    END IF;
    SELECT jsonb_agg(jsonb_build_object('action', catalog.action, 'label', catalog.label,
        'allowed_actors', COALESCE(policy.allowed_actors,catalog.default_allowed_actors),
        'approval', COALESCE(policy.approval,catalog.default_approval),
        'auto_approve', jsonb_build_object('carbon_ids',COALESCE(policy.auto_carbon_ids,'{}'),
            'silicon_ids',COALESCE(policy.auto_silicon_ids,'{}'),'tag_ids',COALESCE(policy.auto_tag_ids,'{}')),
        'version',COALESCE(policy.version,0),
        'defaults',jsonb_build_object('allowed_actors',catalog.default_allowed_actors,'approval',catalog.default_approval))
        ORDER BY catalog.action) INTO v_items
    FROM iam_private.action_policy_catalog catalog LEFT JOIN iam_private.organization_action_policies policy
    ON policy.organization_id=p_organization_id AND policy.action=catalog.action;
    RETURN jsonb_build_object('items',v_items,'can_manage',v_member.org_role='owner' OR
        (v_member.org_role='admin' AND iam_private.has_organization_capability(p_organization_id,iam_private.current_principal_id(),'action_policies.manage')));
END $$;
REVOKE ALL ON FUNCTION iam_private.list_action_policies(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.configure_action_policy(p_organization_id uuid,p_action text,p_expected_version bigint,
    p_allowed_actors text,p_approval text,p_carbon_ids text[],p_silicon_ids text[],p_tag_ids uuid[])
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE v_member iam.organization_memberships%ROWTYPE; v_version bigint;
BEGIN
    SELECT * INTO v_member FROM iam.organization_memberships
    WHERE organization_id=p_organization_id AND principal_id=iam_private.current_principal_id() AND status='active';
    IF NOT FOUND OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id()
       OR NOT (v_member.org_role='owner' OR (v_member.org_role='admin' AND
         iam_private.has_organization_capability(p_organization_id,iam_private.current_principal_id(),'action_policies.manage'))) THEN
        RAISE EXCEPTION 'action_policy_forbidden' USING ERRCODE='42501';
    END IF;
    IF p_allowed_actors NOT IN ('any_member','only_admins','only_owner') OR p_approval NOT IN ('none','admin','owner')
       OR p_carbon_ids IS NULL OR p_silicon_ids IS NULL OR p_tag_ids IS NULL
       OR cardinality(p_carbon_ids)+cardinality(p_silicon_ids)+cardinality(p_tag_ids)>300
       OR NOT EXISTS(SELECT 1 FROM iam_private.action_policy_catalog WHERE action=p_action) THEN
        RAISE EXCEPTION 'action_policy_invalid' USING ERRCODE='22023';
    END IF;
    -- Auto-approval selectors refer only to active identities/tags in this org.
    IF EXISTS(SELECT 1 FROM unnest(p_carbon_ids) AS selector(id) WHERE NOT EXISTS (
        SELECT 1 FROM iam.organization_memberships member JOIN iam.carbons carbon ON carbon.id=member.principal_id
        AND (to_jsonb(carbon)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(member)->>'testing_environment_id')
        WHERE member.organization_id=p_organization_id AND member.status='active' AND carbon.carbon_id=selector.id))
       OR EXISTS(SELECT 1 FROM unnest(p_silicon_ids) AS selector(id) WHERE NOT EXISTS (
        SELECT 1 FROM iam.silicons silicon JOIN iam.organization_memberships member ON member.id=silicon.membership_id
        AND (to_jsonb(silicon)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(member)->>'testing_environment_id')
        WHERE member.organization_id=p_organization_id AND member.status='active' AND silicon.global_silicon_id=selector.id AND silicon.provisioning_status<>'deleted'))
       OR EXISTS(SELECT 1 FROM unnest(p_tag_ids) AS selector(id) WHERE NOT EXISTS (
        SELECT 1 FROM iam.organization_tags tag WHERE tag.organization_id=p_organization_id AND tag.id=selector.id AND tag.status='active')) THEN
        RAISE EXCEPTION 'action_policy_selectors_invalid' USING ERRCODE='22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_organization_id::text||':'||p_action,112));
    SELECT version INTO v_version FROM iam_private.organization_action_policies WHERE organization_id=p_organization_id AND action=p_action FOR UPDATE;
    IF COALESCE(v_version,0) IS DISTINCT FROM p_expected_version THEN
        RAISE EXCEPTION 'action_policy_version_mismatch' USING ERRCODE='40001';
    END IF;
    INSERT INTO iam_private.organization_action_policies(organization_id,action,allowed_actors,approval,auto_carbon_ids,auto_silicon_ids,auto_tag_ids,updated_by_membership_id)
    VALUES(p_organization_id,p_action,p_allowed_actors,p_approval,p_carbon_ids,p_silicon_ids,p_tag_ids,v_member.id)
    ON CONFLICT (organization_id,action) DO UPDATE SET allowed_actors=EXCLUDED.allowed_actors,approval=EXCLUDED.approval,
        auto_carbon_ids=EXCLUDED.auto_carbon_ids,auto_silicon_ids=EXCLUDED.auto_silicon_ids,auto_tag_ids=EXCLUDED.auto_tag_ids,
        version=organization_action_policies.version+1,updated_by_membership_id=EXCLUDED.updated_by_membership_id,updated_at=transaction_timestamp();
    RETURN (SELECT item FROM jsonb_array_elements(iam_private.list_action_policies(p_organization_id)->'items') item WHERE item->>'action'=p_action);
END $$;
REVOKE ALL ON FUNCTION iam_private.configure_action_policy(uuid,text,bigint,text,text,text[],text[],uuid[]) FROM PUBLIC;

CREATE FUNCTION iam_private.authorize_sensitive_action(p_organization_id uuid,p_action text,p_fingerprint bytea,
    p_method text,p_path text,p_body jsonb,p_expected_version text,p_request_id uuid,p_consume boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE
    v_actor iam.organization_memberships%ROWTYPE; v_policy iam_private.organization_action_policies%ROWTYPE;
    v_catalog iam_private.action_policy_catalog%ROWTYPE; v_request iam_private.organization_action_approvals%ROWTYPE;
    v_allowed text; v_approval text; v_version bigint; v_public_id text; v_immediate boolean;
BEGIN
    SELECT member.* INTO v_actor FROM iam.organization_memberships member
    JOIN iam.organizations organization ON organization.id=member.organization_id AND organization.status='active'
      AND (to_jsonb(organization)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(member)->>'testing_environment_id')
    JOIN iam.principals principal ON principal.id=member.principal_id AND principal.kind=member.principal_kind AND principal.status='active'
      AND (to_jsonb(principal)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(member)->>'testing_environment_id')
    WHERE member.organization_id=p_organization_id AND member.principal_id=iam_private.current_principal_id() AND member.status='active'
    FOR SHARE OF member, organization, principal;
    IF NOT FOUND OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id() THEN
        RAISE EXCEPTION 'sensitive_action_forbidden' USING ERRCODE='42501';
    END IF;
    SELECT * INTO STRICT v_catalog FROM iam_private.action_policy_catalog WHERE action=p_action;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_organization_id::text||':'||p_action,112));
    SELECT * INTO v_policy FROM iam_private.organization_action_policies WHERE organization_id=p_organization_id AND action=p_action;
    v_allowed := COALESCE(v_policy.allowed_actors,v_catalog.default_allowed_actors);
    v_approval := COALESCE(v_policy.approval,v_catalog.default_approval);
    v_version := COALESCE(v_policy.version,0);
    IF v_actor.org_role<>'owner' AND NOT (v_allowed='any_member' OR (v_allowed='only_admins' AND v_actor.org_role='admin')) THEN
        RAISE EXCEPTION 'sensitive_action_forbidden' USING ERRCODE='42501';
    END IF;
    SELECT COALESCE(carbon.carbon_id,silicon.global_silicon_id) INTO v_public_id
    FROM iam.organization_memberships member LEFT JOIN iam.carbons carbon ON carbon.id=member.principal_id
      AND (to_jsonb(carbon)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(member)->>'testing_environment_id')
    LEFT JOIN iam.silicons silicon ON silicon.id=member.principal_id
      AND (to_jsonb(silicon)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(member)->>'testing_environment_id')
    WHERE member.id=v_actor.id;
    v_immediate := v_actor.org_role='owner' OR v_approval='none' OR (v_actor.org_role='admin' AND v_approval='admin')
        OR (v_actor.principal_kind='carbon' AND v_public_id=ANY(COALESCE(v_policy.auto_carbon_ids,'{}')))
        OR (v_actor.principal_kind='silicon' AND v_public_id=ANY(COALESCE(v_policy.auto_silicon_ids,'{}')))
        OR EXISTS(SELECT 1 FROM iam.membership_tags assignment JOIN iam.organization_tags tag ON tag.id=assignment.tag_id
            WHERE assignment.organization_id=p_organization_id AND assignment.membership_id=v_actor.id
              AND tag.status='active' AND assignment.tag_id=ANY(COALESCE(v_policy.auto_tag_ids,'{}')));
    IF NOT v_immediate THEN
        SELECT * INTO v_request FROM iam_private.organization_action_approvals
        WHERE organization_id=p_organization_id AND action=p_action AND requested_by_membership_id=v_actor.id
          AND request_fingerprint=p_fingerprint AND policy_version=v_version AND expires_at>clock_timestamp()
        ORDER BY created_at DESC LIMIT 1 FOR UPDATE;
        IF NOT FOUND THEN
            INSERT INTO iam_private.organization_action_approvals(id,organization_id,action,policy_version,requested_by_membership_id,
                request_fingerprint,method,path,request_body,expected_version)
            VALUES(p_request_id,p_organization_id,p_action,v_version,v_actor.id,p_fingerprint,p_method,p_path,p_body,p_expected_version)
            RETURNING * INTO v_request;
        END IF;
        IF v_request.status='rejected' THEN RAISE EXCEPTION 'sensitive_action_rejected' USING ERRCODE='42501'; END IF;
        IF v_request.status='pending' THEN RETURN jsonb_build_object('status','pending','request_id',v_request.id); END IF;
        PERFORM reviewer.id FROM iam.organization_memberships reviewer
            JOIN iam.principals principal ON principal.id=reviewer.principal_id AND principal.status='active'
              AND (to_jsonb(principal)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(reviewer)->>'testing_environment_id')
            WHERE reviewer.id=v_request.decided_by_membership_id
            AND reviewer.organization_id=p_organization_id AND reviewer.status='active'
            AND (reviewer.org_role='owner' OR (reviewer.org_role='admin' AND v_approval='admin'))
            FOR SHARE OF reviewer, principal;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'sensitive_action_reviewer_inactive' USING ERRCODE='42501';
        END IF;
        IF p_consume AND v_request.status='approved' THEN
            UPDATE iam_private.organization_action_approvals SET status='consumed',consumed_at=transaction_timestamp(),version=version+1 WHERE id=v_request.id;
        END IF;
    END IF;
    IF p_consume THEN
        INSERT INTO iam_private.organization_action_executions(transaction_id,organization_id,membership_id,action,capabilities)
        VALUES(pg_current_xact_id()::text::bigint,p_organization_id,v_actor.id,p_action,v_catalog.capabilities) ON CONFLICT DO NOTHING;
        DELETE FROM iam_private.organization_action_executions WHERE created_at<transaction_timestamp()-interval '1 day';
    END IF;
    RETURN jsonb_build_object('status','allowed','capabilities',v_catalog.capabilities);
END $$;
REVOKE ALL ON FUNCTION iam_private.authorize_sensitive_action(uuid,text,bytea,text,text,jsonb,text,uuid,boolean) FROM PUBLIC;

CREATE FUNCTION iam_private.list_action_approvals(p_organization_id uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE v_member iam.organization_memberships%ROWTYPE; v_items jsonb;
BEGIN
    SELECT * INTO v_member FROM iam.organization_memberships WHERE organization_id=p_organization_id
        AND principal_id=iam_private.current_principal_id() AND status='active';
    IF NOT FOUND OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id() THEN
        RAISE EXCEPTION 'action_approval_forbidden' USING ERRCODE='42501';
    END IF;
    SELECT COALESCE(jsonb_agg(item ORDER BY created_at DESC),'[]') INTO v_items FROM (
        SELECT request.created_at,jsonb_build_object('id',request.id,'action',request.action,'status',request.status,
            'requested_by',jsonb_build_object('actor_type',requester.principal_kind,'public_id',COALESCE(carbon.carbon_id,silicon.global_silicon_id)),
            'method',request.method,'path',request.path,'request_body',request.request_body,'expected_version',request.expected_version,
            'created_at',request.created_at,'expires_at',request.expires_at,'version',request.version,
            'can_decide',request.status='pending' AND request.expires_at>clock_timestamp()
                AND request.policy_version=COALESCE(policy.version,0)
                AND (v_member.org_role='owner' OR (v_member.org_role='admin' AND COALESCE(policy.approval,catalog.default_approval)='admin'))) item
        FROM iam_private.organization_action_approvals request
        JOIN iam.organization_memberships requester ON requester.id=request.requested_by_membership_id
        LEFT JOIN iam.carbons carbon ON carbon.id=requester.principal_id
          AND (to_jsonb(carbon)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(requester)->>'testing_environment_id')
        LEFT JOIN iam.silicons silicon ON silicon.id=requester.principal_id
          AND (to_jsonb(silicon)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(requester)->>'testing_environment_id')
        JOIN iam_private.action_policy_catalog catalog ON catalog.action=request.action
        LEFT JOIN iam_private.organization_action_policies policy ON policy.organization_id=request.organization_id AND policy.action=request.action
        WHERE request.organization_id=p_organization_id AND (request.requested_by_membership_id=v_member.id OR v_member.org_role IN ('owner','admin'))
        ORDER BY request.created_at DESC LIMIT 200
    ) requests;
    RETURN jsonb_build_object('items',v_items);
END $$;
REVOKE ALL ON FUNCTION iam_private.list_action_approvals(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.decide_action_approval(p_organization_id uuid,p_request_id uuid,p_expected_version bigint,p_decision text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE v_member iam.organization_memberships%ROWTYPE; v_request iam_private.organization_action_approvals%ROWTYPE; v_policy_version bigint; v_approval text;
BEGIN
    SELECT * INTO v_member FROM iam.organization_memberships WHERE organization_id=p_organization_id
        AND principal_id=iam_private.current_principal_id() AND status='active';
    IF NOT FOUND OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id() THEN
        RAISE EXCEPTION 'action_approval_forbidden' USING ERRCODE='42501';
    END IF;
    SELECT * INTO v_request FROM iam_private.organization_action_approvals WHERE organization_id=p_organization_id AND id=p_request_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'action_approval_missing' USING ERRCODE='P0002'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_organization_id::text||':'||v_request.action,112));
    SELECT * INTO v_request FROM iam_private.organization_action_approvals WHERE id=p_request_id FOR UPDATE;
    SELECT COALESCE(policy.version,0),COALESCE(policy.approval,catalog.default_approval) INTO v_policy_version,v_approval
    FROM iam_private.action_policy_catalog catalog LEFT JOIN iam_private.organization_action_policies policy
        ON policy.organization_id=p_organization_id AND policy.action=catalog.action WHERE catalog.action=v_request.action;
    IF NOT (v_member.org_role='owner' OR (v_member.org_role='admin' AND v_approval='admin')) THEN
        RAISE EXCEPTION 'action_approval_forbidden' USING ERRCODE='42501';
    END IF;
    IF v_request.version<>p_expected_version OR v_request.policy_version<>v_policy_version OR v_request.status<>'pending'
       OR v_request.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'action_approval_version_mismatch' USING ERRCODE='40001'; END IF;
    IF p_decision NOT IN ('approve','reject') THEN RAISE EXCEPTION 'action_approval_invalid' USING ERRCODE='22023'; END IF;
    UPDATE iam_private.organization_action_approvals SET status=CASE WHEN p_decision='approve' THEN 'approved' ELSE 'rejected' END,
        decided_by_membership_id=v_member.id,decided_at=transaction_timestamp(),version=version+1 WHERE id=p_request_id
        RETURNING * INTO v_request;
    -- Return this exact decision even when it is older than the list's page.
    RETURN (SELECT jsonb_build_object('id',v_request.id,'action',v_request.action,'status',v_request.status,
        'requested_by',jsonb_build_object('actor_type',requester.principal_kind,'public_id',COALESCE(carbon.carbon_id,silicon.global_silicon_id)),
        'method',v_request.method,'path',v_request.path,'request_body',v_request.request_body,'expected_version',v_request.expected_version,
        'created_at',v_request.created_at,'expires_at',v_request.expires_at,'version',v_request.version,'can_decide',false)
        FROM iam.organization_memberships requester
        LEFT JOIN iam.carbons carbon ON carbon.id=requester.principal_id
          AND (to_jsonb(carbon)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(requester)->>'testing_environment_id')
        LEFT JOIN iam.silicons silicon ON silicon.id=requester.principal_id
          AND (to_jsonb(silicon)->>'testing_environment_id') IS NOT DISTINCT FROM (to_jsonb(requester)->>'testing_environment_id')
        WHERE requester.id=v_request.requested_by_membership_id AND requester.organization_id=p_organization_id);
END $$;
REVOKE ALL ON FUNCTION iam_private.decide_action_approval(uuid,uuid,bigint,text) FROM PUBLIC;

-- Keep the existing exact-write/history helpers, adding only the checked
-- execution grant as an alternative to their old owner/admin restriction.
DO $$ DECLARE v_function text; v_action text; v_definition text; v_old text; v_new text; v_oid oid; v_start integer; BEGIN
    FOR v_function,v_action IN SELECT * FROM (VALUES
        ('replace_membership_job_role_direct','membership.job_description.update'),
        ('replace_membership_tags_direct','membership.tags.update')) entries LOOP
        SELECT proc.oid INTO STRICT v_oid FROM pg_proc proc JOIN pg_namespace ns ON ns.oid=proc.pronamespace
        WHERE ns.nspname='iam_private' AND proc.proname=v_function;
        v_definition:=pg_get_functiondef(v_oid);
        v_start:=position(E'IF NOT FOUND\n       OR actor_kind' IN v_definition);
        IF v_start=0 THEN RAISE EXCEPTION 'direct governance definition changed unexpectedly: %',v_function; END IF;
        v_old:=substring(v_definition FROM v_start);
        v_old:=substring(v_old FROM 1 FOR position('THEN' IN v_old)+3);
        v_new:='IF NOT FOUND OR (NOT iam_private.action_execution_allowed(p_organization_id, '||quote_literal(v_action)||') AND ('||
            substring(v_old FROM position('actor_kind' IN v_old) FOR length(v_old)-position('actor_kind' IN v_old)-4)||')) THEN';
        EXECUTE replace(v_definition,v_old,v_new);
    END LOOP;
END $$;

DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN
    GRANT EXECUTE ON FUNCTION iam_private.action_execution_allowed(uuid,text),iam_private.action_execution_capability(uuid,text),
        iam_private.list_action_policies(uuid),iam_private.configure_action_policy(uuid,text,bigint,text,text,text[],text[],uuid[]),
        iam_private.authorize_sensitive_action(uuid,text,bytea,text,text,jsonb,text,uuid,boolean),iam_private.list_action_approvals(uuid),
        iam_private.decide_action_approval(uuid,uuid,bigint,text) TO silicon_iam_api;
END IF; END $$;
