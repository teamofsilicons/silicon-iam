-- Preserve deployed applications as public. Only accepted configuration may
-- change visibility; requesting publication is not an activation decision.
ALTER TABLE iam.applications ADD COLUMN visibility text NOT NULL DEFAULT 'public'
    CHECK (visibility IN ('private', 'public'));
ALTER TABLE iam.application_approved_scopes ADD COLUMN approval_basis text NOT NULL DEFAULT 'provider_approval'
    CHECK (approval_basis IN ('provider_approval', 'noncritical', 'private_exemption'));

CREATE FUNCTION iam_private.application_allows_subject(p_app uuid, p_subject uuid, p_org uuid DEFAULT NULL)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT EXISTS (
  SELECT 1 FROM iam.applications app
  JOIN iam.organizations org ON org.id=app.organization_id AND org.status='active'
  WHERE app.id=p_app AND app.deleted_at IS NULL AND app.review_status='verified'
  AND (app.visibility='public' OR (
    (p_org IS NULL OR p_org=app.organization_id)
    AND EXISTS (SELECT 1 FROM iam.organization_memberships member
      JOIN iam.principals principal ON principal.id=member.principal_id AND principal.status='active'
      WHERE member.organization_id=app.organization_id AND member.principal_id=p_subject
        AND member.status='active')
  ))
 );
$$;
REVOKE ALL ON FUNCTION iam_private.application_allows_subject(uuid,uuid,uuid) FROM PUBLIC;

-- For private apps an unscoped token still has exactly one selected membership.
-- A stale or foreign selection must not survive a public-to-private transition.
CREATE FUNCTION iam_private.application_private_consent_is_current(p_app uuid, p_consent uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT EXISTS (
  SELECT 1 FROM iam.applications app
  WHERE app.id=p_app AND (app.visibility='public' OR EXISTS (
   SELECT 1 FROM iam.oauth_consent_grants consent
   JOIN iam.organization_memberships member ON member.id=ANY(consent.selected_membership_ids)
     AND member.principal_id=consent.subject_principal_id AND member.principal_kind=consent.subject_kind
     AND member.organization_id=app.organization_id AND member.status='active'
   JOIN iam.organizations org ON org.id=member.organization_id AND org.status='active'
   WHERE consent.id=p_consent AND consent.application_id=app.id AND consent.status='active'
    AND cardinality(consent.selected_membership_ids)=1
    AND (consent.organization_id IS NULL OR consent.organization_id=app.organization_id)
    AND (consent.membership_id IS NULL OR consent.membership_id=member.id)
  ))
 );
$$;
REVOKE ALL ON FUNCTION iam_private.application_private_consent_is_current(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.application_private_token_is_current(p_token uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT EXISTS (
  SELECT 1 FROM iam.access_tokens token
  WHERE token.id=p_token AND (token.client_application_id IS NULL OR EXISTS (
   SELECT 1 FROM iam.oauth_consent_grants consent
   WHERE consent.application_id=token.client_application_id
    AND consent.subject_principal_id=token.subject_principal_id
    AND consent.parent_authentication_session_id=token.authentication_session_id
    AND consent.organization_id IS NOT DISTINCT FROM token.organization_id
    AND consent.membership_id IS NOT DISTINCT FROM token.membership_id
    AND consent.status='active'
    AND iam_private.application_private_consent_is_current(token.client_application_id,consent.id)
  ))
 );
$$;
REVOKE ALL ON FUNCTION iam_private.application_private_token_is_current(uuid) FROM PUBLIC;

-- Hold membership and application authority through exchange, refresh and
-- introspection. A removal and a token issuance serialize on this membership.
CREATE FUNCTION iam_private.lock_application_private_consent(p_app uuid, p_consent uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE private_app boolean;
BEGIN
 SELECT visibility='private' INTO private_app FROM iam.applications WHERE id=p_app FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 IF NOT private_app THEN RETURN true; END IF;
 PERFORM member.id FROM iam.oauth_consent_grants consent
 JOIN iam.organization_memberships member ON member.id=ANY(consent.selected_membership_ids)
 JOIN iam.organizations org ON org.id=member.organization_id
 WHERE consent.id=p_consent ORDER BY member.id FOR SHARE OF consent, member, org;
 RETURN iam_private.application_private_consent_is_current(p_app,p_consent);
END;
$$;
REVOKE ALL ON FUNCTION iam_private.lock_application_private_consent(uuid,uuid) FROM PUBLIC;

-- An exemption is explicit evidence of private access, never provider consent.
CREATE FUNCTION iam_private.enforce_private_application_activation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
BEGIN
 IF OLD.visibility='private' AND NEW.visibility='public' AND EXISTS (
   SELECT 1 FROM iam.application_approved_scopes scope
   WHERE scope.application_id=NEW.id AND scope.revoked_at IS NULL AND scope.approval_basis<>'provider_approval' AND scope.scope=ANY(iam_private.application_scope_names(NEW.app_scope)) AND EXISTS(SELECT 1 FROM iam_private.application_scope_catalog(NULL) catalog WHERE catalog.scope=scope.scope AND catalog.critical)
 ) THEN
  RAISE EXCEPTION 'private_exemption_is_not_public_approval' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.enforce_private_application_activation() FROM PUBLIC;
CREATE TRIGGER applications_private_activation BEFORE UPDATE OF visibility ON iam.applications
FOR EACH ROW EXECUTE FUNCTION iam_private.enforce_private_application_activation();


CREATE OR REPLACE FUNCTION iam_private.lock_account_login_organization_selection(
    p_subject_id uuid, p_session_id uuid, p_org_ids text[], p_application_id uuid
)
RETURNS uuid[]
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF p_subject_id IS NULL OR p_session_id IS NULL OR p_org_ids IS NULL
       OR p_application_id IS NULL
       OR p_subject_id IS DISTINCT FROM iam_private.current_principal_id()
       OR iam_private.current_application_id() IS NOT NULL
       OR cardinality(p_org_ids) NOT BETWEEN 0 AND 1000 THEN
        RAISE EXCEPTION 'login_selection_forbidden' USING ERRCODE = '42501';
    END IF;
    PERFORM id FROM iam.applications WHERE id=p_application_id FOR SHARE;
    IF EXISTS (SELECT 1 FROM iam.applications WHERE id=p_application_id AND visibility='private')
       AND (cardinality(p_org_ids) <> 1 OR NOT EXISTS (
        SELECT 1 FROM iam.applications app JOIN iam.organizations org ON org.id=app.organization_id
        WHERE app.id=p_application_id AND org.org_id=p_org_ids[1]
          AND iam_private.application_allows_subject(app.id,p_subject_id,org.id)
       )) THEN
      RAISE EXCEPTION 'private_application_organization_required' USING ERRCODE='42501';
    END IF;
    IF cardinality(p_org_ids) > 0 THEN
        RETURN iam_private.lock_login_organization_selection(
            p_subject_id, p_session_id, p_org_ids
        );
    END IF;

    -- Match application administration's lock order before locking the subject.
    PERFORM application.id
    FROM iam.applications application
    JOIN iam.principals client ON client.id = application.id
      AND client.kind = 'application' AND client.status = 'active'
    WHERE application.id = p_application_id AND application.review_status = 'verified'
      AND application.deleted_at IS NULL
    FOR SHARE OF application, client;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'login_selection_forbidden' USING ERRCODE = '42501';
    END IF;
    PERFORM approved.scope FROM iam.application_approved_scopes approved
    WHERE approved.application_id = p_application_id AND approved.revoked_at IS NULL
      AND approved.scope IN ('organizations.create', 'organizations.join')
    ORDER BY approved.scope FOR SHARE OF approved;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'login_selection_forbidden' USING ERRCODE = '42501';
    END IF;
    PERFORM session.id FROM iam.authentication_sessions session
    JOIN iam.principals subject ON subject.id = session.subject_principal_id
      AND subject.kind = 'carbon' AND subject.status = 'active'
      AND subject.auth_epoch = session.subject_auth_epoch
    JOIN iam.carbons carbon ON carbon.id = subject.id AND carbon.deleted_at IS NULL
    WHERE session.id = p_session_id AND session.subject_principal_id = p_subject_id
      AND session.subject_kind = 'carbon' AND session.status = 'active'
      AND session.idle_expires_at > clock_timestamp()
      AND session.absolute_expires_at > clock_timestamp()
    FOR SHARE OF session, subject, carbon;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'login_selection_forbidden' USING ERRCODE = '42501';
    END IF;
    RETURN '{}'::uuid[];
END;
$$;

CREATE OR REPLACE FUNCTION iam_private.lock_current_application_oauth_subject_authority(
    p_application_id uuid,
    p_consent_grant_id uuid,
    p_authentication_session_id uuid,
    p_subject_principal_id uuid,
    p_subject_kind iam.principal_kind,
    p_organization_id uuid,
    p_membership_id uuid
)
RETURNS TABLE (
    subject_auth_epoch bigint,
    membership_authz_epoch bigint,
    org_id text,
    subject_public_id text,
    session_idle_expires_at timestamptz,
    session_absolute_expires_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF p_application_id IS NULL
       OR p_application_id IS DISTINCT FROM iam_private.current_application_id()
       OR p_application_id IS DISTINCT FROM iam_private.current_principal_id() THEN
        RAISE EXCEPTION 'application_oauth_subject_authority_forbidden'
            USING ERRCODE = '42501';
    END IF;

    IF (p_organization_id IS NULL) IS DISTINCT FROM (p_membership_id IS NULL)
       OR p_subject_kind NOT IN ('carbon', 'silicon') THEN
        RETURN;
    END IF;

    IF NOT iam_private.lock_application_private_consent(p_application_id,p_consent_grant_id) THEN
        RETURN;
    END IF;
    IF p_organization_id IS NULL AND p_subject_kind = 'carbon' THEN
        RETURN QUERY
        SELECT principal.auth_epoch,
               NULL::bigint,
               NULL::text,
               carbon.carbon_id,
               authentication_session.idle_expires_at,
               authentication_session.absolute_expires_at
        FROM iam.principals AS principal
        JOIN iam.carbons AS carbon
          ON carbon.id = principal.id
         AND principal.kind = 'carbon'
         AND carbon.deleted_at IS NULL
        JOIN iam.authentication_sessions AS authentication_session
          ON authentication_session.id = p_authentication_session_id
         AND authentication_session.subject_principal_id = principal.id
         AND authentication_session.subject_kind = principal.kind
         AND authentication_session.subject_auth_epoch = principal.auth_epoch
         AND authentication_session.status = 'active'
         AND authentication_session.idle_expires_at > transaction_timestamp()
         AND authentication_session.absolute_expires_at > transaction_timestamp()
        JOIN iam.oauth_consent_grants AS consent
          ON consent.id = p_consent_grant_id
         AND consent.application_id = p_application_id
         AND consent.subject_principal_id = principal.id
         AND consent.subject_kind = principal.kind
         AND consent.organization_id IS NULL
         AND consent.membership_id IS NULL
         AND consent.parent_authentication_session_id = authentication_session.id
         AND consent.status = 'active'
        WHERE principal.id = p_subject_principal_id
          AND principal.kind = p_subject_kind
          AND principal.status = 'active'
        FOR SHARE OF principal, carbon, authentication_session, consent;
    ELSIF p_subject_kind = 'carbon' THEN
        RETURN QUERY
        SELECT principal.auth_epoch,
               membership.authz_epoch,
               organization.org_id,
               carbon.carbon_id,
               authentication_session.idle_expires_at,
               authentication_session.absolute_expires_at
        FROM iam.principals AS principal
        JOIN iam.carbons AS carbon
          ON carbon.id = principal.id
         AND principal.kind = 'carbon'
         AND carbon.deleted_at IS NULL
        JOIN iam.authentication_sessions AS authentication_session
          ON authentication_session.id = p_authentication_session_id
         AND authentication_session.subject_principal_id = principal.id
         AND authentication_session.subject_kind = principal.kind
         AND authentication_session.subject_auth_epoch = principal.auth_epoch
         AND authentication_session.status = 'active'
         AND authentication_session.idle_expires_at > transaction_timestamp()
         AND authentication_session.absolute_expires_at > transaction_timestamp()
        JOIN iam.organizations AS organization
          ON organization.id = p_organization_id
         AND organization.status = 'active'
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.id = p_membership_id
         AND membership.principal_id = principal.id
         AND membership.principal_kind = principal.kind
         AND membership.status = 'active'
        JOIN iam.oauth_consent_grants AS consent
          ON consent.id = p_consent_grant_id
         AND consent.application_id = p_application_id
         AND consent.subject_principal_id = principal.id
         AND consent.subject_kind = principal.kind
         AND consent.organization_id = organization.id
         AND consent.membership_id = membership.id
         AND consent.parent_authentication_session_id = authentication_session.id
         AND consent.status = 'active'
        WHERE principal.id = p_subject_principal_id
          AND principal.kind = p_subject_kind
          AND principal.status = 'active'
        FOR SHARE OF principal, carbon, authentication_session, organization,
                     membership, consent;
    ELSE
        RETURN QUERY
        SELECT principal.auth_epoch,
               CASE WHEN p_membership_id IS NULL THEN NULL ELSE membership.authz_epoch END,
               CASE WHEN p_organization_id IS NULL THEN NULL ELSE organization.org_id END,
               silicon.global_silicon_id,
               authentication_session.idle_expires_at,
               authentication_session.absolute_expires_at
        FROM iam.principals AS principal
        JOIN iam.silicons AS silicon
          ON silicon.id = principal.id
         AND principal.kind = 'silicon'
         AND (p_organization_id IS NULL OR silicon.organization_id = p_organization_id)
         AND (p_membership_id IS NULL OR silicon.membership_id = p_membership_id)
         AND silicon.provisioning_status = 'active'
         AND silicon.deleted_at IS NULL
        JOIN iam.authentication_sessions AS authentication_session
          ON authentication_session.id = p_authentication_session_id
         AND authentication_session.subject_principal_id = principal.id
         AND authentication_session.subject_kind = principal.kind
         AND authentication_session.subject_auth_epoch = principal.auth_epoch
         AND authentication_session.status = 'active'
         AND authentication_session.idle_expires_at > transaction_timestamp()
         AND authentication_session.absolute_expires_at > transaction_timestamp()
        JOIN iam.organizations AS organization
          ON organization.id = silicon.organization_id
         AND organization.status = 'active'
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.id = silicon.membership_id
         AND membership.principal_id = principal.id
         AND membership.principal_kind = principal.kind
         AND membership.status = 'active'
        JOIN iam.oauth_consent_grants AS consent
          ON consent.id = p_consent_grant_id
         AND consent.application_id = p_application_id
         AND consent.subject_principal_id = principal.id
         AND consent.subject_kind = principal.kind
         AND consent.organization_id IS NOT DISTINCT FROM p_organization_id
         AND consent.membership_id IS NOT DISTINCT FROM p_membership_id
         AND consent.parent_authentication_session_id = authentication_session.id
         AND consent.status = 'active'
        WHERE principal.id = p_subject_principal_id
          AND principal.kind = p_subject_kind
          AND principal.status = 'active'
        FOR SHARE OF principal, silicon, authentication_session, organization,
                     membership, consent;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION iam_private.application_token_allows_membership(
    p_access_token_id uuid, p_membership_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT EXISTS (
        SELECT 1 FROM iam.access_tokens token
        JOIN iam.oauth_consent_grants consent
          ON consent.application_id = token.client_application_id
         AND consent.subject_principal_id = token.subject_principal_id
         AND consent.subject_kind = token.subject_kind
         AND consent.parent_authentication_session_id = token.authentication_session_id
         AND consent.organization_id IS NOT DISTINCT FROM token.organization_id
         AND consent.membership_id IS NOT DISTINCT FROM token.membership_id
         AND consent.status = 'active'
        JOIN iam.organization_memberships membership
          ON membership.id = p_membership_id
         AND membership.id = ANY(consent.selected_membership_ids)
         AND membership.principal_id = token.subject_principal_id
         AND membership.principal_kind = token.subject_kind
         AND membership.status = 'active'
        JOIN iam.organizations organization
          ON organization.id = membership.organization_id AND organization.status = 'active'
        JOIN iam.principals subject
          ON subject.id = token.subject_principal_id AND subject.status = 'active'
         AND subject.auth_epoch = token.subject_auth_epoch
        JOIN iam.authentication_sessions session
          ON session.id = token.authentication_session_id AND session.status = 'active'
         AND session.subject_principal_id = subject.id
         AND session.subject_auth_epoch = subject.auth_epoch
         AND session.idle_expires_at > statement_timestamp()
         AND session.absolute_expires_at > statement_timestamp()
        JOIN iam.applications application
          ON application.id = token.client_application_id
         AND application.id = token.audience_application_id
         AND application.app_id = token.audience
         AND application.review_status = 'verified' AND application.deleted_at IS NULL
         AND iam_private.application_allows_subject(application.id,token.subject_principal_id,membership.organization_id)
         AND iam_private.application_private_consent_is_current(application.id,consent.id)
        JOIN iam.principals client
          ON client.id = application.id AND client.status = 'active'
         AND client.auth_epoch = token.client_auth_epoch
        WHERE token.id = p_access_token_id AND token.token_class = 'application_access'
          AND token.revoked_at IS NULL AND token.expires_at > statement_timestamp()
          AND (iam_private.current_principal_id() = subject.id
               OR (iam_private.current_principal_id() = application.id
                   AND iam_private.current_application_id() = application.id))
          AND (token.organization_id IS NULL OR (
              token.organization_id = membership.organization_id
              AND token.membership_id = membership.id
              AND token.membership_authz_epoch = membership.authz_epoch))
    );
$$;

CREATE OR REPLACE FUNCTION iam_private.application_token_allows_external_scope(p_token uuid,p_audience uuid,p_endpoint text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT EXISTS(SELECT 1 FROM iam.access_tokens token
 JOIN iam.applications issuer ON issuer.id=token.client_application_id AND issuer.review_status='verified' AND issuer.deleted_at IS NULL
 JOIN iam.applications audience ON audience.id=p_audience AND audience.review_status='verified' AND audience.deleted_at IS NULL
 JOIN iam.application_obo_endpoints endpoint ON endpoint.application_id=audience.id AND endpoint.endpoint_id=p_endpoint AND endpoint.status='active'
 JOIN iam.access_token_scopes token_scope ON token_scope.access_token_id=token.id AND token_scope.scope='obo:'||audience.app_id||':'||endpoint.endpoint_id
 JOIN iam.application_approved_scopes approved ON approved.application_id=issuer.id AND approved.scope=token_scope.scope AND approved.revoked_at IS NULL
 JOIN iam.oauth_consent_grants consent ON consent.application_id=issuer.id AND consent.subject_principal_id=token.subject_principal_id
 AND consent.parent_authentication_session_id=token.authentication_session_id AND consent.status='active'
 JOIN iam.oauth_consent_grant_scopes granted ON granted.consent_grant_id=consent.id AND granted.scope=token_scope.scope
 JOIN iam.authentication_sessions session ON session.id=token.authentication_session_id AND session.status='active'
 AND session.absolute_expires_at>clock_timestamp() AND session.idle_expires_at>clock_timestamp()
 JOIN iam.principals subject ON subject.id=token.subject_principal_id AND subject.status='active' AND subject.auth_epoch=token.subject_auth_epoch
 WHERE token.id=p_token AND token.token_class='application_access' AND token.revoked_at IS NULL AND token.expires_at>clock_timestamp()
 AND iam_private.application_private_consent_is_current(issuer.id,consent.id)
 AND iam_private.application_allows_subject(audience.id,token.subject_principal_id,iam_private.current_organization_id())
 AND token.audience_application_id=issuer.id AND token.audience=issuer.app_id
 AND (iam_private.current_principal_id()=token.subject_principal_id OR
 (iam_private.current_principal_id()=issuer.id AND iam_private.current_application_id()=issuer.id)))
$$;

CREATE OR REPLACE FUNCTION iam_private.configure_application_scopes(p_app uuid,p_scope jsonb,p_actor uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE names text[]; previous_status text;
BEGIN
 IF p_actor IS DISTINCT FROM iam_private.current_principal_id()
 OR NOT iam_private.can_manage_application(p_app,p_actor) THEN RAISE EXCEPTION 'scope_configuration_forbidden' USING ERRCODE='42501'; END IF;
 SELECT review_status INTO STRICT previous_status FROM iam.applications WHERE id=p_app FOR UPDATE;
 names:=iam_private.application_scope_names(p_scope);
 IF cardinality(names) NOT BETWEEN 1 AND 100 OR EXISTS (
 SELECT unnest(names) EXCEPT SELECT scope FROM iam_private.application_scope_catalog(NULL)
 ) THEN RAISE EXCEPTION 'invalid_application_scope' USING ERRCODE='22023'; END IF;
 INSERT INTO iam.oauth_scope_catalog(scope,description,sensitive)
 SELECT catalog.scope,catalog.description,catalog.critical FROM iam_private.application_scope_catalog(NULL) catalog
 WHERE catalog.scope=ANY(names) ON CONFLICT(scope) DO UPDATE SET description=EXCLUDED.description,sensitive=EXCLUDED.sensitive;
 INSERT INTO iam.application_requested_scopes(application_id,scope)
 SELECT p_app,unnest(names) ON CONFLICT DO NOTHING;
 UPDATE iam.application_approved_scopes SET revoked_at=transaction_timestamp(),revoked_by_carbon_id=p_actor
 WHERE application_id=p_app AND revoked_at IS NULL AND NOT(scope=ANY(names));
 UPDATE iam.access_tokens token SET revoked_at=transaction_timestamp(),revocation_reason='application_scope_revoked'
 WHERE token.client_application_id=p_app AND token.revoked_at IS NULL AND EXISTS (
 SELECT 1 FROM iam.access_token_scopes scope WHERE scope.access_token_id=token.id AND NOT(scope.scope=ANY(names)));
 INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id,approval_basis)
 SELECT p_app,catalog.scope,p_actor,CASE WHEN catalog.critical THEN 'private_exemption' ELSE 'noncritical' END FROM iam_private.application_scope_catalog(NULL) catalog
 WHERE catalog.scope=ANY(names) AND (NOT catalog.critical OR EXISTS(SELECT 1 FROM iam.applications WHERE id=p_app AND visibility='private')) AND NOT EXISTS (
 SELECT 1 FROM iam.application_approved_scopes approved WHERE approved.application_id=p_app AND approved.scope=catalog.scope AND approved.revoked_at IS NULL);
 UPDATE iam.applications SET app_scope=p_scope,review_status=CASE
 WHEN previous_status='under_review' AND NOT EXISTS (
 SELECT unnest(names) EXCEPT SELECT scope FROM iam.application_approved_scopes WHERE application_id=p_app AND revoked_at IS NULL
 ) THEN 'verified' ELSE previous_status END WHERE id=p_app;
END $$;

CREATE OR REPLACE FUNCTION iam_private.invalidate_upgraded_obo_endpoint_scope()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE scope_name text;
BEGIN
 IF NEW.critical AND NOT OLD.critical THEN
 SELECT 'obo:'||app_id||':'||NEW.endpoint_id INTO scope_name FROM iam.applications WHERE id=NEW.application_id;
 UPDATE iam.application_approved_scopes approved SET approval_basis='private_exemption'
 WHERE approved.scope=scope_name AND approved.revoked_at IS NULL
 AND EXISTS (SELECT 1 FROM iam.applications app WHERE app.id=approved.application_id AND app.visibility='private');
 UPDATE iam.application_approved_scopes approved SET revoked_at=transaction_timestamp(),revoked_by_carbon_id=iam_private.current_principal_id()
 WHERE approved.scope=scope_name AND approved.revoked_at IS NULL
 AND EXISTS (SELECT 1 FROM iam.applications app WHERE app.id=approved.application_id AND app.visibility='public');
 UPDATE iam.access_tokens token SET revoked_at=transaction_timestamp(),revocation_reason='obo_endpoint_became_critical'
 WHERE token.revoked_at IS NULL
 AND EXISTS (SELECT 1 FROM iam.applications app WHERE app.id=token.client_application_id AND app.visibility='public')
 AND EXISTS(SELECT 1 FROM iam.access_token_scopes s WHERE s.access_token_id=token.id AND s.scope=scope_name);
 END IF;
 RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION iam_private.lock_account_login_organization_selection(uuid,uuid,text[],uuid) FROM PUBLIC;

REVOKE ALL ON FUNCTION iam_private.lock_current_application_oauth_subject_authority(uuid,uuid,uuid,uuid,iam.principal_kind,uuid,uuid) FROM PUBLIC;

REVOKE ALL ON FUNCTION iam_private.application_token_allows_membership(uuid,uuid) FROM PUBLIC;

REVOKE ALL ON FUNCTION iam_private.application_token_allows_external_scope(uuid,uuid,text) FROM PUBLIC;

REVOKE ALL ON FUNCTION iam_private.configure_application_scopes(uuid,jsonb,uuid) FROM PUBLIC;

REVOKE ALL ON FUNCTION iam_private.invalidate_upgraded_obo_endpoint_scope() FROM PUBLIC;

DO $$ BEGIN
 IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.application_allows_subject(uuid,uuid,uuid),
 iam_private.application_private_token_is_current(uuid),
 iam_private.application_private_consent_is_current(uuid,uuid) TO silicon_iam_api;
 END IF;
END $$;

CREATE FUNCTION iam_private.application_is_discoverable(p_app uuid, p_access_token uuid DEFAULT NULL)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT EXISTS(SELECT 1 FROM iam.applications app WHERE app.id=p_app AND (
  app.visibility='public' OR (
   iam_private.current_principal_id() IS DISTINCT FROM iam_private.current_application_id()
   AND EXISTS(SELECT 1 FROM iam.organization_memberships member
    JOIN iam.principals subject ON subject.id=member.principal_id AND subject.status='active'
    JOIN iam.organizations org ON org.id=member.organization_id AND org.status='active'
    WHERE member.organization_id=app.organization_id AND member.principal_id=iam_private.current_principal_id()
      AND member.status='active'
      AND (iam_private.current_application_id() IS NULL OR
           iam_private.application_token_allows_membership(p_access_token,member.id)))
  ) OR (
   iam_private.current_principal_id()=iam_private.current_application_id()
   AND EXISTS(SELECT 1 FROM iam.applications caller
    JOIN iam.principals principal ON principal.id=caller.id AND principal.status='active'
    WHERE caller.id=iam_private.current_application_id() AND caller.review_status='verified'
      AND caller.deleted_at IS NULL AND caller.organization_id=app.organization_id
      AND (caller.id=app.id OR EXISTS(
       SELECT 1 FROM iam.application_approved_scopes approved
       JOIN iam.application_obo_endpoints endpoint ON endpoint.application_id=app.id AND endpoint.status='active'
       WHERE approved.application_id=caller.id AND approved.revoked_at IS NULL
        AND approved.scope='obo:'||app.app_id||':'||endpoint.endpoint_id
        AND approved.scope=ANY(iam_private.application_scope_names(caller.app_scope)))))
  )
 ));
$$;
REVOKE ALL ON FUNCTION iam_private.application_is_discoverable(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.discover_application_origin(p_app_id text, p_access_token uuid DEFAULT NULL)
RETURNS TABLE(app_id text, base_url text) LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT app.app_id, app.base_url FROM iam.applications app
 JOIN iam.principals principal ON principal.id=app.id AND principal.status='active'
 JOIN iam.organizations org ON org.id=app.organization_id AND org.status='active'
 WHERE app.app_id=p_app_id AND app.review_status='verified' AND app.deleted_at IS NULL
  AND app.base_url IS NOT NULL AND app.base_url<>''
  AND iam_private.application_is_discoverable(app.id,p_access_token);
$$;
REVOKE ALL ON FUNCTION iam_private.discover_application_origin(text,uuid) FROM PUBLIC;
DO $$ BEGIN
 IF to_regrole('silicon_iam_api') IS NOT NULL THEN
 GRANT EXECUTE ON FUNCTION iam_private.application_is_discoverable(uuid,uuid),
 iam_private.discover_application_origin(text,uuid) TO silicon_iam_api;
 END IF;
END $$;


CREATE OR REPLACE FUNCTION iam_private.list_organization_member_webhook_authorizations(
    p_organization_id uuid,
    p_membership_ids uuid[],
    p_event_occurred_at timestamptz
)
RETURNS TABLE (
    application_id uuid,
    membership_id uuid,
    scope text,
    authorized_after boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF p_organization_id IS NULL
       OR p_membership_ids IS NULL
       OR cardinality(p_membership_ids) NOT BETWEEN 1 AND 100000
       OR p_event_occurred_at IS NULL
       OR iam_private.current_principal_id() IS NULL
       OR NOT EXISTS (
            SELECT 1
            FROM iam.organization_memberships AS actor_membership
            JOIN iam.principals AS actor_principal
              ON actor_principal.id = actor_membership.principal_id
             AND actor_principal.kind = actor_membership.principal_kind
             AND actor_principal.status = 'active'
            WHERE actor_membership.organization_id = p_organization_id
              AND actor_membership.principal_id = iam_private.current_principal_id()
              AND actor_membership.status = 'active'
       ) THEN
        RAISE EXCEPTION 'organization member webhook authorization scope is invalid'
            USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT
        consent.application_id,
        membership.id,
        consent_scope.scope,
        (
            consent.status = 'active'
            AND approved_scope.revoked_at IS NULL
            AND membership.status = 'active'
            AND subject_principal.status = 'active'
            AND selected.status = 'active' AND grant_subject.status = 'active'
        ) AS authorized_after
    FROM iam.organization_memberships AS membership
    JOIN iam.principals AS subject_principal
      ON subject_principal.id = membership.principal_id
     AND subject_principal.kind = membership.principal_kind
    JOIN iam.organization_memberships AS selected
      ON selected.organization_id = membership.organization_id
    JOIN iam.oauth_consent_grants AS consent
      ON consent.subject_principal_id = selected.principal_id
     AND consent.subject_kind = selected.principal_kind
     AND selected.id = ANY(consent.selected_membership_ids)
    JOIN iam.principals AS grant_subject
      ON grant_subject.id = selected.principal_id
     AND grant_subject.kind = selected.principal_kind
    JOIN iam.oauth_consent_grant_scopes AS consent_scope
      ON consent_scope.consent_grant_id = consent.id
    JOIN iam.application_approved_scopes AS approved_scope
      ON approved_scope.application_id = consent.application_id
     AND approved_scope.scope = consent_scope.scope
    JOIN iam.applications AS application
      ON application.id = consent.application_id
     AND application.review_status = 'verified'
     AND application.deleted_at IS NULL
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
     AND application_principal.status = 'active'
    WHERE membership.organization_id = p_organization_id
      AND (application.visibility='public' OR application.organization_id=p_organization_id)
      AND membership.id = ANY(p_membership_ids)
      AND (consent_scope.scope LIKE 'self.%' OR consent_scope.scope LIKE 'directory.%' OR consent_scope.scope LIKE 'organization.%')
      AND (membership.principal_id = consent.subject_principal_id
           OR consent_scope.scope LIKE 'directory.%' OR consent_scope.scope LIKE 'organization.%')
      AND (consent_scope.scope <> 'directory.carbons.read' OR membership.principal_kind = 'carbon')
      AND (consent_scope.scope <> 'directory.silicons.read' OR membership.principal_kind = 'silicon')
      AND (selected.status = 'active' OR selected.removed_at >= p_event_occurred_at OR selected.suspended_at >= p_event_occurred_at)
      AND (grant_subject.status = 'active' OR grant_subject.deleted_at >= p_event_occurred_at OR grant_subject.suspended_at >= p_event_occurred_at)
      AND (
          consent.status = 'active'
          OR consent.revoked_at >= p_event_occurred_at
      )
      AND (
          approved_scope.revoked_at IS NULL
          OR approved_scope.revoked_at >= p_event_occurred_at
      )
      AND (
          membership.status = 'active'
          OR membership.removed_at >= p_event_occurred_at
          OR membership.suspended_at >= p_event_occurred_at
      )
      AND (
          subject_principal.status = 'active'
          OR subject_principal.deleted_at >= p_event_occurred_at
          OR subject_principal.suspended_at >= p_event_occurred_at
      )
    ORDER BY consent.application_id, membership.id, consent_scope.scope
    FOR SHARE OF membership, subject_principal, consent, consent_scope,
                 approved_scope, application, application_principal, selected, grant_subject;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.list_organization_member_webhook_authorizations(uuid,uuid[],timestamptz) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.list_profile_webhook_authorization_scopes(
    p_carbon_id uuid
)
RETURNS TABLE (
    application_id uuid,
    scope text
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT consent.application_id, consent_scope.scope
    FROM iam.oauth_consent_grants AS consent
    JOIN iam.oauth_consent_grant_scopes AS consent_scope
      ON consent_scope.consent_grant_id = consent.id
    JOIN iam.application_approved_scopes AS approved_scope
      ON approved_scope.application_id = consent.application_id
     AND approved_scope.scope = consent_scope.scope
     AND approved_scope.revoked_at IS NULL
    JOIN iam.applications AS application
      ON application.id = consent.application_id
     AND application.review_status = 'verified'
     AND application.deleted_at IS NULL
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
     AND application_principal.status = 'active'
    JOIN iam.principals AS subject_principal
      ON subject_principal.id = consent.subject_principal_id
     AND subject_principal.kind = consent.subject_kind
     AND subject_principal.status = 'active'
    WHERE iam_private.current_principal_id() = p_carbon_id
      AND (consent.subject_principal_id = p_carbon_id OR (
          consent_scope.scope IN ('directory.carbons.read','directory.profiles.read')
          AND EXISTS (SELECT 1 FROM iam.organization_memberships selected
              JOIN iam.organization_memberships affected ON affected.organization_id=selected.organization_id
                  AND affected.principal_id=p_carbon_id AND affected.principal_kind='carbon' AND affected.status='active'
              WHERE selected.id=ANY(consent.selected_membership_ids) AND selected.principal_id=consent.subject_principal_id
                  AND selected.principal_kind=consent.subject_kind AND selected.status='active')
      ))
      AND consent.status = 'active'
      AND iam_private.application_private_consent_is_current(application.id,consent.id)
      AND iam_private.application_allows_subject(application.id,p_carbon_id,NULL)
    ORDER BY consent.application_id, consent_scope.scope
    FOR SHARE OF consent, consent_scope, approved_scope, application, application_principal
$$;

REVOKE ALL ON FUNCTION iam_private.list_profile_webhook_authorization_scopes(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.current_application_resource_scopes(p_application uuid,p_subject uuid,p_organization uuid)
RETURNS SETOF text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT DISTINCT granted.scope
 FROM iam.oauth_consent_grants consent
 JOIN iam.principals subject ON subject.id=consent.subject_principal_id AND subject.kind=consent.subject_kind AND subject.status='active'
 JOIN iam.oauth_consent_grant_scopes granted ON granted.consent_grant_id=consent.id
 JOIN iam.application_approved_scopes approved ON approved.application_id=consent.application_id AND approved.scope=granted.scope AND approved.revoked_at IS NULL
 WHERE consent.application_id=p_application AND consent.status='active'
 AND iam_private.application_private_consent_is_current(p_application,consent.id)
 AND iam_private.application_allows_subject(p_application,p_subject,p_organization)
 AND (iam_private.can_manage_application(p_application,iam_private.current_principal_id()) OR iam_private.has_platform_capability(iam_private.current_principal_id(),'applications.review'))
 AND (p_organization IS NULL OR EXISTS(SELECT 1 FROM iam.organization_memberships selected WHERE selected.id=ANY(consent.selected_membership_ids)
     AND selected.organization_id=p_organization AND selected.principal_id=consent.subject_principal_id AND selected.status='active'))
 AND (p_subject IS NULL OR p_subject=consent.subject_principal_id OR (
     (granted.scope LIKE 'directory.%' OR granted.scope LIKE 'organization.%')
     AND EXISTS(SELECT 1 FROM iam.organization_memberships selected
         JOIN iam.organization_memberships affected ON affected.organization_id=selected.organization_id AND affected.principal_id=p_subject AND affected.status='active'
         JOIN iam.principals affected_principal ON affected_principal.id=affected.principal_id AND affected_principal.status='active'
         WHERE selected.id=ANY(consent.selected_membership_ids) AND selected.principal_id=consent.subject_principal_id AND selected.status='active'
         AND (p_organization IS NULL OR selected.organization_id=p_organization)
         AND (granted.scope<>'directory.carbons.read' OR affected.principal_kind='carbon')
         AND (granted.scope<>'directory.silicons.read' OR affected.principal_kind='silicon'))
 ))
$$;

REVOKE ALL ON FUNCTION iam_private.current_application_resource_scopes(uuid,uuid,uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.application_webhook_has_event_scope(p_endpoint uuid,p_organization uuid,p_event text,p_at timestamptz)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT p_event='session.logout' OR p_event LIKE 'application.%' OR EXISTS(
 SELECT 1 FROM iam.application_webhook_endpoints endpoint
 JOIN iam.oauth_consent_grants consent ON consent.application_id=endpoint.application_id
 JOIN iam.oauth_consent_grant_scopes granted ON granted.consent_grant_id=consent.id AND granted.scope=iam_private.application_webhook_event_scope(p_event)
 JOIN iam.application_approved_scopes approved ON approved.application_id=consent.application_id AND approved.scope=granted.scope
 JOIN iam.organization_memberships selected ON selected.id=ANY(consent.selected_membership_ids) AND selected.principal_id=consent.subject_principal_id
 JOIN iam.principals subject ON subject.id=selected.principal_id AND subject.kind=selected.principal_kind
 WHERE EXISTS (SELECT 1 FROM iam.applications app WHERE app.id=endpoint.application_id
 AND (app.visibility='public' OR app.organization_id=p_organization))
 AND endpoint.id=p_endpoint AND selected.organization_id=p_organization AND consent.granted_at<=p_at AND approved.approved_at<=p_at
 AND (consent.status='active' OR consent.revoked_at>=p_at)
 AND (approved.revoked_at IS NULL OR approved.revoked_at>=p_at)
 AND (selected.status='active' OR selected.removed_at>=p_at OR selected.suspended_at>=p_at)
 AND (subject.status='active' OR subject.deleted_at>=p_at OR subject.suspended_at>=p_at))
$$;

REVOKE ALL ON FUNCTION iam_private.application_webhook_has_event_scope(uuid,uuid,text,timestamptz) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.list_organization_webhook_scope_authorizations(p_organization uuid,p_scope text,p_at timestamptz)
RETURNS TABLE(application_id uuid,authorized_after boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM iam.organization_memberships actor JOIN iam.principals principal ON principal.id=actor.principal_id AND principal.status='active'
     WHERE actor.organization_id=p_organization AND actor.principal_id=iam_private.current_principal_id() AND actor.status='active') THEN
 RAISE EXCEPTION 'organization event capture requires an active member' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT consent.application_id,
 consent.status='active' AND approved.revoked_at IS NULL AND selected.status='active' AND subject.status='active'
 FROM iam.oauth_consent_grants consent
 JOIN iam.oauth_consent_grant_scopes granted ON granted.consent_grant_id=consent.id AND granted.scope=p_scope
 JOIN iam.application_approved_scopes approved ON approved.application_id=consent.application_id AND approved.scope=granted.scope
 JOIN iam.organization_memberships selected ON selected.id=ANY(consent.selected_membership_ids) AND selected.principal_id=consent.subject_principal_id
 JOIN iam.principals subject ON subject.id=selected.principal_id AND subject.kind=selected.principal_kind
 JOIN iam.applications app ON app.id=consent.application_id AND app.review_status='verified' AND app.deleted_at IS NULL
 JOIN iam.principals app_principal ON app_principal.id=app.id AND app_principal.status='active'
 WHERE EXISTS (SELECT 1 FROM iam.applications app WHERE app.id=consent.application_id
 AND (app.visibility='public' OR app.organization_id=p_organization))
 AND selected.organization_id=p_organization AND consent.granted_at<=p_at AND approved.approved_at<=p_at
 AND (consent.status='active' OR consent.revoked_at>=p_at)
 AND (approved.revoked_at IS NULL OR approved.revoked_at>=p_at)
 AND (selected.status='active' OR selected.removed_at>=p_at OR selected.suspended_at>=p_at)
 AND (subject.status='active' OR subject.deleted_at>=p_at OR subject.suspended_at>=p_at)
 ORDER BY consent.application_id
 FOR SHARE OF consent,granted,approved,selected,subject,app,app_principal;
END $$;

REVOKE ALL ON FUNCTION iam_private.list_organization_webhook_scope_authorizations(uuid,text,timestamptz) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.list_worker_captured_application_webhook_recipients(
    p_outbox_event_id uuid
)
RETURNS TABLE (
    endpoint_id uuid,
    signing_key_id uuid
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT endpoint.id, signing_key.id
    FROM iam.application_webhook_event_projections AS projection
    JOIN iam.outbox_events AS event
      ON event.id = projection.outbox_event_id
     AND event.event_type IN (
        'carbon.updated.v1',
        'organization.created.v1',
        'organization.tag_created.v1',
        'organization.invitation.created.v1',
        'organization.invitation.accepted.v1',
        'organization.invitation.revoked.v1',
        'organization.role_change.requested.v1',
        'organization.tag_change.requested.v1',
        'organization.approval.decided.v1',

        'organization.updated.v1',
        'organization.ownership_transferred.v1',
        'organization.tag_updated.v1',
        'organization.tag_archived.v1',
        'organization.trust.default_updated.v1',
        'organization.trust.rule_created.v1',
        'organization.trust.rule_updated.v1',
        'organization.trust.rule_archived.v1',
        'organization.membership.created.v1',
        'organization.membership.reactivated.v1',
        'organization.membership.removed.v1',
        'organization.membership.updated.v1',
        'organization.membership.authorization_updated.v1',
        'organization.admin.promoted.v1',
        'organization.admin.demoted.v1',
        'organization.silicon.created.v1',
        'organization.silicon.updated.v1',
        'organization.silicon.removed.v1',
        'organization.silicon.credential_rotated.v1'
     )
    JOIN iam.applications AS application
      ON application.id = projection.application_id
     AND application.review_status = 'verified'
     AND application.deleted_at IS NULL
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
     AND application_principal.status = 'active'
    JOIN iam.application_webhook_endpoints AS endpoint
      ON endpoint.application_id = application.id
     AND endpoint.status = 'active'
    JOIN LATERAL (
        SELECT candidate.id
        FROM iam.application_webhook_signing_keys AS candidate
        WHERE candidate.application_id = application.id
          AND candidate.endpoint_id = endpoint.id
          AND candidate.status IN ('active', 'retiring')
          AND (
              candidate.retires_at IS NULL
              OR candidate.retires_at > transaction_timestamp()
          )
        ORDER BY (candidate.status = 'active') DESC, candidate.secret_version DESC
        LIMIT 1
    ) AS signing_key ON true
    WHERE EXISTS (SELECT 1 FROM iam.applications app WHERE app.id=projection.application_id
        AND (app.visibility='public' OR event.organization_id IS NULL OR app.organization_id=event.organization_id))
      AND projection.outbox_event_id = p_outbox_event_id
      AND (event.organization_id IS NULL OR EXISTS (
          SELECT 1 FROM iam.oauth_consent_grants consent
          JOIN iam.organization_memberships membership
            ON membership.id = ANY(consent.selected_membership_ids)
           AND membership.principal_id = consent.subject_principal_id
           AND membership.organization_id = event.organization_id
          WHERE consent.application_id = projection.application_id
            AND (consent.status = 'active' OR consent.revoked_at >= event.created_at)
            AND (membership.status = 'active' OR membership.removed_at >= event.created_at
                 OR membership.suspended_at >= event.created_at)
      ))
    ORDER BY endpoint.id
$$;

REVOKE ALL ON FUNCTION iam_private.list_worker_captured_application_webhook_recipients(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.get_worker_application_webhook_event_projection(
    p_outbox_event_id uuid,
    p_application_id uuid
)
RETURNS TABLE (
    projection_id uuid,
    payload_ciphertext bytea,
    payload_nonce bytea,
    encryption_key_version smallint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        projection.id,
        projection.payload_ciphertext,
        projection.payload_nonce,
        projection.encryption_key_version
    FROM iam.application_webhook_event_projections AS projection
    JOIN iam.outbox_events AS event
      ON event.id = projection.outbox_event_id
     AND event.event_type IN (
        'carbon.updated.v1',
        'organization.created.v1',
        'organization.tag_created.v1',
        'organization.invitation.created.v1',
        'organization.invitation.accepted.v1',
        'organization.invitation.revoked.v1',
        'organization.role_change.requested.v1',
        'organization.tag_change.requested.v1',
        'organization.approval.decided.v1',

        'organization.updated.v1',
        'organization.ownership_transferred.v1',
        'organization.tag_updated.v1',
        'organization.tag_archived.v1',
        'organization.trust.default_updated.v1',
        'organization.trust.rule_created.v1',
        'organization.trust.rule_updated.v1',
        'organization.trust.rule_archived.v1',
        'organization.membership.created.v1',
        'organization.membership.reactivated.v1',
        'organization.membership.removed.v1',
        'organization.membership.updated.v1',
        'organization.membership.authorization_updated.v1',
        'organization.admin.promoted.v1',
        'organization.admin.demoted.v1',
        'organization.silicon.created.v1',
        'organization.silicon.updated.v1',
        'organization.silicon.removed.v1',
        'organization.silicon.credential_rotated.v1'
     )
    WHERE EXISTS (SELECT 1 FROM iam.applications app WHERE app.id=projection.application_id
        AND (app.visibility='public' OR event.organization_id IS NULL OR app.organization_id=event.organization_id))
      AND projection.outbox_event_id = p_outbox_event_id
      AND (event.organization_id IS NULL OR EXISTS (
          SELECT 1 FROM iam.oauth_consent_grants consent
          JOIN iam.organization_memberships membership
            ON membership.id = ANY(consent.selected_membership_ids)
           AND membership.principal_id = consent.subject_principal_id
           AND membership.organization_id = event.organization_id
          WHERE consent.application_id = projection.application_id
            AND (consent.status = 'active' OR consent.revoked_at >= event.created_at)
            AND (membership.status = 'active' OR membership.removed_at >= event.created_at
                 OR membership.suspended_at >= event.created_at)
      ))
      AND projection.application_id = p_application_id
$$;

REVOKE ALL ON FUNCTION iam_private.get_worker_application_webhook_event_projection(uuid,uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.discover_application_obo_endpoints(p_app_id text)
RETURNS SETOF jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private AS $$
    SELECT jsonb_build_object(
        'application', jsonb_build_object('app_id', app.app_id, 'org_id', org.org_id),
        'endpoints', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'endpoint_id', endpoint.endpoint_id, 'path', endpoint.path,
            'metadata', endpoint.metadata_definition, 'critical', endpoint.critical, 'ttl_seconds', endpoint.ttl_seconds
        ) ORDER BY endpoint.endpoint_id)
        FROM iam.application_obo_endpoints endpoint
        WHERE endpoint.application_id = app.id AND endpoint.status = 'active'), '[]'::jsonb)
    )
    FROM iam.applications app
    JOIN iam.principals principal ON principal.id = app.id AND principal.status = 'active'
    JOIN iam.organizations org ON org.id = app.organization_id AND org.status = 'active'
    WHERE app.app_id = p_app_id AND app.review_status = 'verified' AND app.deleted_at IS NULL
      AND iam_private.application_is_discoverable(app.id,NULL)
      AND iam_private.current_application_id() = iam_private.current_principal_id()
      AND EXISTS (SELECT 1 FROM iam.applications caller
        JOIN iam.principals identity ON identity.id = caller.id AND identity.status = 'active'
        WHERE caller.id = iam_private.current_application_id()
          AND caller.review_status = 'verified' AND caller.deleted_at IS NULL);
$$;

REVOKE ALL ON FUNCTION iam_private.discover_application_obo_endpoints(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.get_testing_application_import_v2(p_app_ids text[])
RETURNS TABLE (
    source_application_id uuid,
    source_webhook_endpoint_id uuid,
    source_webhook_signing_key_id uuid,
    app_id text,
    org_id text,
    organization_name text,
    organization_logo_uri text,
    organization_description text,
    app_name text,
    app_logo_uri text,
    base_url text,
    webhook_url_ciphertext bytea,
    webhook_url_nonce bytea,
    webhook_url_encryption_key_version smallint,
    webhook_secret_ciphertext bytea,
    webhook_secret_nonce bytea,
    webhook_secret_encryption_key_version smallint,
    webhook_secret_version bigint,
    obo_endpoints jsonb,
    app_scope jsonb, webhook_scope text[], testing_idle_days integer, visibility text, source_revision bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        application.id,
        endpoint.id,
        signing_key.id,
        application.app_id,
        organization.org_id,
        organization.name,
        organization.logo_uri,
        organization.description,
        application.app_name,
        application.app_logo_uri,
        application.base_url,
        endpoint.url_ciphertext,
        endpoint.url_nonce,
        endpoint.encryption_key_version,
        signing_key.secret_ciphertext,
        signing_key.secret_nonce,
        signing_key.encryption_key_version,
        signing_key.secret_version,
        (
            SELECT COALESCE(
                jsonb_agg(
                    jsonb_build_object(
                        'endpoint_id', obo.endpoint_id,
                        'path', obo.path,
                        'metadata', obo.metadata_definition, 'critical', obo.critical, 'ttl_seconds', obo.ttl_seconds
                    ) ORDER BY obo.endpoint_id
                ),
                '[]'::jsonb
            )
            FROM iam.application_obo_endpoints AS obo
            WHERE obo.application_id = application.id
              AND obo.organization_id = application.organization_id
              AND obo.status = 'active'
        ), application.app_scope, application.webhook_scope, application.testing_idle_days, application.visibility, application.version
    FROM iam.applications AS application
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
     AND application_principal.status = 'active'
    JOIN iam.organizations AS organization
      ON organization.id = application.organization_id
     AND organization.status = 'active'
    JOIN LATERAL (
        SELECT candidate.*
        FROM iam.application_webhook_endpoints AS candidate
        WHERE candidate.application_id = application.id
          AND candidate.status IN ('active', 'pending_review')
        ORDER BY
            (candidate.status = 'active') DESC,
            candidate.activated_at DESC NULLS LAST,
            candidate.created_at DESC,
            candidate.id DESC
        LIMIT 1
    ) AS endpoint ON true
    JOIN LATERAL (
        SELECT candidate.*
        FROM iam.application_webhook_signing_keys AS candidate
        WHERE candidate.application_id = application.id
          AND candidate.endpoint_id = endpoint.id
          AND candidate.status = 'active'
        ORDER BY candidate.secret_version DESC, candidate.id DESC
        LIMIT 1
    ) AS signing_key ON true
    WHERE application.app_id = ANY(p_app_ids)
      AND application.review_status = 'verified'
      AND application.deleted_at IS NULL
$$;
REVOKE ALL ON FUNCTION iam_private.get_testing_application_import_v2(text[]) FROM PUBLIC;

ALTER TABLE iam.testing_application_imports ADD COLUMN source_revision bigint NOT NULL DEFAULT 0;

CREATE OR REPLACE FUNCTION iam_private.import_testing_application_configuration(p jsonb)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE v_environment_id uuid := NULLIF(current_setting('iam.testing_environment_id', true), '')::uuid;
    v_owner_id uuid; v_org_id uuid; v_app_id uuid := (p->>'application_id')::uuid;
    v_endpoint_id uuid := (p->>'endpoint_id')::uuid; item jsonb;
BEGIN
    IF v_environment_id IS NULL THEN RAISE EXCEPTION 'testing_environment_required' USING ERRCODE = '42501'; END IF;
    IF EXISTS(SELECT 1 FROM iam.applications existing WHERE existing.id=v_app_id AND
       (NOT existing.test_imported_from_production OR existing.app_id<>p->>'app_id')) THEN
       RAISE EXCEPTION 'import_identity_mismatch' USING ERRCODE='42501'; END IF;
    -- An uncredentialed, suspended fixture is audit attribution, never a
    -- production identity or a login-capable organization administrator.
    v_owner_id := iam_private.current_principal_id();
    IF v_owner_id IS NULL OR NOT EXISTS (SELECT 1 FROM iam.carbons c JOIN iam.principals identity ON identity.id=c.id
        WHERE c.id=v_owner_id AND identity.status='active') THEN v_owner_id := v_environment_id; END IF;
    IF NOT EXISTS (SELECT 1 FROM iam.carbons WHERE id = v_owner_id) THEN
        INSERT INTO iam.principals(id,kind,status,suspended_at) VALUES(v_owner_id,'carbon','suspended',clock_timestamp());
        INSERT INTO iam.carbons(id,carbon_id,display_name)
        VALUES(v_owner_id, 'test_' || translate(left(replace(v_environment_id::text,'-',''),24),'0','g'), 'Testing environment fixture');
    END IF;
    SELECT organization.id INTO v_org_id FROM iam.organizations organization
    WHERE organization.org_id = p->>'org_id' AND organization.status = 'active';
    IF v_org_id IS NOT NULL AND v_owner_id <> v_environment_id
       AND NOT iam_private.is_active_organization_owner_or_admin(v_org_id,v_owner_id) THEN
        RAISE EXCEPTION 'testing_import_organization_not_managed' USING ERRCODE='42501';
    END IF;
    IF v_org_id IS NULL THEN
        v_org_id := gen_random_uuid();
        INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name,logo_uri,description)
        VALUES(v_org_id,p->>'org_id',v_owner_id,p->>'organization_name',p->>'organization_logo',p->>'organization_description');
        INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role)
        VALUES(gen_random_uuid(),v_org_id,v_owner_id,'carbon','owner');
        INSERT INTO iam.carbon_membership_settings(organization_id,membership_id,carbon_id)
        SELECT v_org_id,membership.id,v_owner_id FROM iam.organization_memberships membership
        WHERE membership.organization_id = v_org_id AND membership.principal_id = v_owner_id;
    END IF;
    INSERT INTO iam.principals(id,kind,status,activated_at) VALUES(v_app_id,'application','active',transaction_timestamp()) ON CONFLICT(id) DO NOTHING;
    UPDATE iam.application_approved_scopes approved SET revoked_at=transaction_timestamp(),revoked_by_carbon_id=v_owner_id WHERE approved.application_id=v_app_id AND approved.revoked_at IS NULL;
    UPDATE iam.access_tokens token SET revoked_at=transaction_timestamp(),revocation_reason='test_configuration_refreshed' WHERE token.client_application_id=v_app_id AND token.revoked_at IS NULL;
    UPDATE iam.application_secrets secret SET status='retired',retired_at=transaction_timestamp(),retires_at=NULL WHERE secret.application_id=v_app_id AND secret.status IN ('active','retiring');
    UPDATE iam.application_webhook_signing_keys secret SET status='retired',retired_at=transaction_timestamp(),retires_at=NULL WHERE secret.application_id=v_app_id AND secret.status IN ('active','retiring');
    UPDATE iam.application_webhook_endpoints endpoint SET status='retired',retired_at=transaction_timestamp() WHERE endpoint.application_id=v_app_id AND endpoint.status IN ('active','pending_review');
    UPDATE iam.application_obo_endpoints endpoint SET status='retired',retired_at=transaction_timestamp() WHERE endpoint.application_id=v_app_id AND endpoint.status='active';
    INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,app_name,app_logo_uri,base_url,
        review_status,test_imported_from_production,app_scope,webhook_scope,testing_idle_days,visibility)
    VALUES(v_app_id,p->>'app_id',v_org_id,v_owner_id,p->>'app_name',p->>'app_logo',p->>'base_url','verified',true,
        p->'app_scope',ARRAY(SELECT jsonb_array_elements_text(p->'webhook_scope')),(p->>'testing_idle_days')::integer,COALESCE(p->>'visibility','public')) ON CONFLICT(id) DO UPDATE SET app_name=EXCLUDED.app_name,app_logo_uri=EXCLUDED.app_logo_uri,
        base_url=EXCLUDED.base_url,review_status='verified',app_scope=EXCLUDED.app_scope,webhook_scope=EXCLUDED.webhook_scope,
        testing_idle_days=EXCLUDED.testing_idle_days,visibility=EXCLUDED.visibility;
    FOR item IN SELECT * FROM jsonb_array_elements(p->'obo_endpoints') LOOP
        INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical,ttl_seconds)
        VALUES(v_org_id,v_app_id,item->>'endpoint_id',item->>'path',item->'metadata',(item->>'critical')::boolean,COALESCE((item->>'ttl_seconds')::integer,300)) ON CONFLICT ON CONSTRAINT application_obo_endpoints_pkey DO UPDATE
        SET metadata_definition=EXCLUDED.metadata_definition,critical=EXCLUDED.critical,ttl_seconds=EXCLUDED.ttl_seconds,status='active',retired_at=NULL
        WHERE application_obo_endpoints.path=EXCLUDED.path;
        IF NOT FOUND THEN RAISE EXCEPTION 'obo_endpoint_path_immutable' USING ERRCODE='23514'; END IF;
    END LOOP;
    INSERT INTO iam.application_secrets(id,application_id,secret_version,secret_prefix,secret_digest,pepper_key_version,created_by_carbon_id)
    VALUES((p->>'secret_id')::uuid,v_app_id,(SELECT COALESCE(max(secret_version),0)+1 FROM iam.application_secrets secret WHERE secret.application_id=v_app_id),p->>'secret_prefix',decode(p->>'secret_digest','hex'),(p->>'secret_digest_version')::smallint,v_owner_id);
    INSERT INTO iam.application_webhook_endpoints(id,application_id,url_ciphertext,url_nonce,encryption_key_version,url_digest,status,activated_at)
    VALUES(v_endpoint_id,v_app_id,decode(p->>'url_ciphertext','hex'),decode(p->>'url_nonce','hex'),(p->>'url_key_version')::smallint,
        decode(p->>'url_digest','hex'),'active',transaction_timestamp()) ON CONFLICT(id) DO UPDATE
        SET url_ciphertext=EXCLUDED.url_ciphertext,url_nonce=EXCLUDED.url_nonce,encryption_key_version=EXCLUDED.encryption_key_version,status='active',retired_at=NULL,activated_at=transaction_timestamp();
    INSERT INTO iam.application_webhook_signing_keys(id,application_id,endpoint_id,secret_version,key_prefix,secret_ciphertext,secret_nonce,encryption_key_version,test_inherited_from_production)
    VALUES((p->>'signing_key_id')::uuid,v_app_id,v_endpoint_id,(SELECT greatest(COALESCE(max(secret_version),0)+1,(p->>'webhook_secret_version')::bigint) FROM iam.application_webhook_signing_keys secret WHERE secret.application_id=v_app_id),p->>'webhook_fingerprint',
        decode(p->>'signing_ciphertext','hex'),decode(p->>'signing_nonce','hex'),(p->>'signing_key_version')::smallint,true);
    INSERT INTO iam.testing_application_imports(application_id,source_application_id,secret_ciphertext,secret_nonce,secret_key_version,source_revision)
    VALUES(v_app_id,(p->>'source_application_id')::uuid,decode(p->>'secret_ciphertext','hex'),decode(p->>'secret_nonce','hex'),(p->>'secret_key_version')::smallint,COALESCE((p->>'source_revision')::bigint,0))
    ON CONFLICT(application_id) DO UPDATE SET secret_ciphertext=EXCLUDED.secret_ciphertext,secret_nonce=EXCLUDED.secret_nonce,secret_key_version=EXCLUDED.secret_key_version,source_revision=EXCLUDED.source_revision;
    RETURN v_app_id;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.import_testing_application_configuration(jsonb) FROM PUBLIC;
DO $$ BEGIN
 IF to_regrole('silicon_iam_api') IS NOT NULL THEN
  GRANT EXECUTE ON FUNCTION iam_private.get_testing_application_import_v2(text[]) TO silicon_iam_api;
 END IF;
END $$;

CREATE FUNCTION iam_private.testing_import_revision(p_app uuid)
RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 SELECT source_revision FROM iam.testing_application_imports WHERE application_id=p_app;
$$;
REVOKE ALL ON FUNCTION iam_private.testing_import_revision(uuid) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.testing_import_revision(uuid) TO silicon_iam_api; END IF; END $$;

CREATE FUNCTION iam_private.testing_import_webhook_endpoint(p_app uuid,p_digest bytea)
RETURNS uuid LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam AS $$
 BEGIN RETURN (SELECT endpoint.id FROM iam.application_webhook_endpoints endpoint JOIN iam.applications app ON app.id=endpoint.application_id
 WHERE endpoint.application_id=p_app AND endpoint.url_digest=p_digest AND app.test_imported_from_production
 AND NULLIF(current_setting('iam.testing_environment_id',true),'') IS NOT NULL); END;
$$;
REVOKE ALL ON FUNCTION iam_private.testing_import_webhook_endpoint(uuid,bytea) FROM PUBLIC;
DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NOT NULL THEN GRANT EXECUTE ON FUNCTION iam_private.testing_import_webhook_endpoint(uuid,bytea) TO silicon_iam_api; END IF; END $$;
