-- Application credentials are bound to exactly one account membership. Direct
-- IAM authentication remains account-scoped so first-organization setup works.
CREATE OR REPLACE FUNCTION iam_private.lock_account_login_organization_selection(
 p_subject_id text,p_session_id uuid,p_org_ids text[],p_application_id text
) RETURNS uuid[] LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 IF p_subject_id IS NULL OR p_session_id IS NULL OR p_application_id IS NULL
 OR p_subject_id IS DISTINCT FROM iam_private.current_principal_id()
 OR iam_private.current_application_id() IS NOT NULL OR p_org_ids IS NULL OR cardinality(p_org_ids)<>1 THEN
  RAISE EXCEPTION 'login_selection_forbidden' USING ERRCODE='42501'; END IF;
 PERFORM app.id FROM iam.applications app JOIN iam.principals p ON p.id=app.id
 WHERE app.id=p_application_id AND app.review_status='verified' AND app.deleted_at IS NULL AND p.status='active' FOR SHARE OF app,p;
 IF NOT FOUND THEN RAISE EXCEPTION 'login_selection_forbidden' USING ERRCODE='42501'; END IF;
 IF NOT EXISTS(SELECT 1 FROM iam.organizations org WHERE org.org_id=p_org_ids[1]
   AND iam_private.application_allows_subject(p_application_id,p_subject_id,org.id)) THEN
  RAISE EXCEPTION 'private_application_organization_required' USING ERRCODE='42501'; END IF;
 RETURN iam_private.lock_login_organization_selection(p_subject_id,p_session_id,p_org_ids);
END $$;
REVOKE ALL ON FUNCTION iam_private.lock_account_login_organization_selection(text,uuid,text[],text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.application_login_scope_policy(p_app text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE snapshot jsonb;
BEGIN
 PERFORM id FROM iam.applications WHERE id=p_app FOR SHARE;
 SELECT jsonb_build_object('scope_version',app.version,
 'consent_required',COALESCE((SELECT bool_or(catalog.critical)
 FROM iam.application_approved_scopes approved JOIN iam_private.iam_scope_catalog() catalog ON catalog.scope=approved.scope
 WHERE approved.application_id=app.id AND approved.revoked_at IS NULL),false),
 'scopes',COALESCE((SELECT jsonb_agg(jsonb_build_object('scope',approved.scope,'description',catalog.description,'critical',catalog.critical) ORDER BY approved.scope)
 FROM iam.application_approved_scopes approved JOIN iam_private.iam_scope_catalog() catalog ON catalog.scope=approved.scope
 WHERE approved.application_id=app.id AND approved.revoked_at IS NULL),'[]'::jsonb))
 INTO snapshot FROM iam.applications app WHERE app.id=p_app AND app.review_status='verified' AND app.deleted_at IS NULL;
 RETURN snapshot;
END $$;
REVOKE ALL ON FUNCTION iam_private.application_login_scope_policy(text) FROM PUBLIC;

-- Existing unscoped application sessions cannot silently pick an organization.
-- They must repeat SLT login; direct IAM sessions and durable OBO grants remain.
UPDATE iam.oauth_consent_grants SET status='revoked',revoked_at=clock_timestamp()
 WHERE status='active' AND (organization_id IS NULL OR membership_id IS NULL OR cardinality(selected_membership_ids)<>1);
UPDATE iam.refresh_token_families SET status='revoked',revoked_at=clock_timestamp(),revocation_reason='single_organization_login_required'
 WHERE status='active' AND client_application_id IS NOT NULL AND oauth_consent_grant_id IN (SELECT id FROM iam.oauth_consent_grants WHERE organization_id IS NULL);
UPDATE iam.access_tokens SET revoked_at=clock_timestamp()
 WHERE revoked_at IS NULL AND client_application_id IS NOT NULL AND organization_id IS NULL;
UPDATE iam.oauth_authorization_requests SET status='expired'
 WHERE status IN('pending','approved') AND organization_id IS NULL;

-- The legacy test-only helper remains inert in production. The wrapper narrows
-- its result before any application credential can be issued. Omitted org_id is
-- accepted only for actors with exactly one currently reachable organization.
CREATE FUNCTION iam_private.create_testing_actor_organization_login(
 p_application_id text,p_application_epoch bigint,p_public_id text,p_session_id uuid,p_consent_id uuid,p_lifetime_seconds bigint,p_org_id text
) RETURNS TABLE(principal_id text,subject_kind text,subject_auth_epoch bigint,subject_public_id text,scopes text[],
 organization_id uuid,membership_id uuid,membership_authz_epoch bigint,org_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE actor record; selected record; matches integer;
BEGIN
 SELECT * INTO actor FROM iam_private.create_testing_actor_login(p_application_id,p_application_epoch,p_public_id,p_session_id,p_consent_id,p_lifetime_seconds);
 IF NOT FOUND THEN RETURN; END IF;
 SELECT count(*) INTO matches FROM iam.organization_memberships m JOIN iam.organizations o ON o.id=m.organization_id
 WHERE m.principal_id=actor.principal_id AND m.status='active' AND o.status='active'
  AND (p_org_id IS NULL OR o.org_id=p_org_id)
  AND iam_private.application_allows_subject(p_application_id,actor.principal_id,o.id);
 IF matches<>1 THEN RAISE EXCEPTION 'testing_organization_required' USING ERRCODE='22023'; END IF;
 SELECT m.id,m.organization_id,m.authz_epoch,o.org_id INTO selected
 FROM iam.organization_memberships m JOIN iam.organizations o ON o.id=m.organization_id
 WHERE m.principal_id=actor.principal_id AND m.status='active' AND o.status='active'
  AND (p_org_id IS NULL OR o.org_id=p_org_id)
  AND iam_private.application_allows_subject(p_application_id,actor.principal_id,o.id) FOR SHARE OF m,o;
 IF NOT FOUND THEN RAISE EXCEPTION 'testing_organization_required' USING ERRCODE='22023'; END IF;
 UPDATE iam.oauth_consent_grants SET organization_id=selected.organization_id,membership_id=selected.id,selected_membership_ids=ARRAY[selected.id] WHERE id=p_consent_id;
 DELETE FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id=p_consent_id AND scope LIKE 'obo:%';
 RETURN QUERY SELECT actor.principal_id,actor.subject_kind,actor.subject_auth_epoch,actor.subject_public_id,
  ARRAY(SELECT scope FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id=p_consent_id ORDER BY scope),
  selected.organization_id,selected.id,selected.authz_epoch,selected.org_id;
END $$;
REVOKE ALL ON FUNCTION iam_private.create_testing_actor_organization_login(text,bigint,text,uuid,uuid,bigint,text) FROM PUBLIC;
