-- Apply directory grants only inside selected organizations; self grants never cross subjects.
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
    ORDER BY consent.application_id, consent_scope.scope
    FOR SHARE OF consent, consent_scope, approved_scope, application, application_principal
$$;

REVOKE ALL ON FUNCTION iam_private.list_profile_webhook_authorization_scopes(uuid)
    FROM PUBLIC;


-- Replay reads must re-evaluate the affected resource, even when another member granted directory access.
CREATE FUNCTION iam_private.current_application_resource_scopes(p_application uuid,p_subject uuid,p_organization uuid)
RETURNS SETOF text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT DISTINCT granted.scope
 FROM iam.oauth_consent_grants consent
 JOIN iam.principals subject ON subject.id=consent.subject_principal_id AND subject.kind=consent.subject_kind AND subject.status='active'
 JOIN iam.oauth_consent_grant_scopes granted ON granted.consent_grant_id=consent.id
 JOIN iam.application_approved_scopes approved ON approved.application_id=consent.application_id AND approved.scope=granted.scope AND approved.revoked_at IS NULL
 WHERE consent.application_id=p_application AND consent.status='active'
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

-- Raw configuration events have no member projection. Require their specific organization grant.
CREATE FUNCTION iam_private.application_webhook_event_scope(p_event text)
RETURNS text LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
 SELECT CASE WHEN p_event LIKE 'organization.invitation.%' THEN 'organization.invitations.read'
 WHEN p_event LIKE 'organization.role_change.%' OR p_event LIKE 'organization.tag_change.%' OR p_event LIKE 'organization.approval.%' THEN 'organization.governance.read'
 WHEN p_event LIKE 'organization.tag_%' THEN 'organization.tags.read'
 WHEN p_event LIKE 'organization.trust.%' THEN 'organization.trust.read'
 WHEN p_event IN ('organization.created.v1','organization.updated.v1') THEN 'self.organizations.read'
 ELSE NULL END
$$;
REVOKE ALL ON FUNCTION iam_private.application_webhook_event_scope(text) FROM PUBLIC;
CREATE FUNCTION iam_private.application_webhook_has_event_scope(p_endpoint uuid,p_organization uuid,p_event text,p_at timestamptz)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT p_event='session.logout' OR p_event LIKE 'application.%' OR EXISTS(
 SELECT 1 FROM iam.application_webhook_endpoints endpoint
 JOIN iam.oauth_consent_grants consent ON consent.application_id=endpoint.application_id
 JOIN iam.oauth_consent_grant_scopes granted ON granted.consent_grant_id=consent.id AND granted.scope=iam_private.application_webhook_event_scope(p_event)
 JOIN iam.application_approved_scopes approved ON approved.application_id=consent.application_id AND approved.scope=granted.scope
 JOIN iam.organization_memberships selected ON selected.id=ANY(consent.selected_membership_ids) AND selected.principal_id=consent.subject_principal_id
 JOIN iam.principals subject ON subject.id=selected.principal_id AND subject.kind=selected.principal_kind
 WHERE endpoint.id=p_endpoint AND selected.organization_id=p_organization AND consent.granted_at<=p_at AND approved.approved_at<=p_at
 AND (consent.status='active' OR consent.revoked_at>=p_at)
 AND (approved.revoked_at IS NULL OR approved.revoked_at>=p_at)
 AND (selected.status='active' OR selected.removed_at>=p_at OR selected.suspended_at>=p_at)
 AND (subject.status='active' OR subject.deleted_at>=p_at OR subject.suspended_at>=p_at))
$$;
REVOKE ALL ON FUNCTION iam_private.application_webhook_has_event_scope(uuid,uuid,text,timestamptz) FROM PUBLIC;

-- Capture organization-wide disclosure in the mutation transaction, including unassigned tags/rules.
CREATE FUNCTION iam_private.list_organization_webhook_scope_authorizations(p_organization uuid,p_scope text,p_at timestamptz)
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
 WHERE selected.organization_id=p_organization AND consent.granted_at<=p_at AND approved.approved_at<=p_at
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
    WHERE projection.outbox_event_id = p_outbox_event_id
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
    WHERE projection.outbox_event_id = p_outbox_event_id
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

REVOKE ALL ON FUNCTION iam_private.list_worker_captured_application_webhook_recipients(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.get_worker_application_webhook_event_projection(uuid,uuid) FROM PUBLIC;
