-- Immutable, scope-filtered Application projections for organization member
-- and directory mutations. Reuse the encrypted row format introduced in 0030
-- while broadening only the closed event family captured by the API.

COMMENT ON TABLE iam.application_webhook_event_projections IS
    'Row-bound encrypted, immutable per-Application payloads captured in the domain transaction for the union of authorization recipients immediately before or after an explicitly supported identity or directory event.';

CREATE FUNCTION iam_private.list_organization_member_webhook_authorizations(
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
        ) AS authorized_after
    FROM iam.organization_memberships AS membership
    JOIN iam.principals AS subject_principal
      ON subject_principal.id = membership.principal_id
     AND subject_principal.kind = membership.principal_kind
    JOIN iam.oauth_consent_grants AS consent
      ON consent.subject_principal_id = membership.principal_id
     AND consent.subject_kind = membership.principal_kind
     AND (
          (consent.organization_id IS NULL AND consent.membership_id IS NULL)
          OR (
              consent.organization_id = membership.organization_id
              AND consent.membership_id = membership.id
          )
     )
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
                 approved_scope, application, application_principal;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.list_organization_member_webhook_authorizations(
    uuid, uuid[], timestamptz
) FROM PUBLIC;

CREATE FUNCTION iam_private.list_organization_member_webhook_projection_sources(
    p_organization_id uuid,
    p_membership_ids uuid[]
)
RETURNS TABLE (
    membership_id uuid,
    principal_id uuid,
    principal_kind text,
    current_state jsonb,
    email_contact_id uuid,
    email_ciphertext bytea,
    email_nonce bytea,
    email_encryption_key_version smallint,
    phone_contact_id uuid,
    phone_ciphertext bytea,
    phone_nonce bytea,
    phone_encryption_key_version smallint
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
        RAISE EXCEPTION 'organization member webhook projection scope is invalid'
            USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT
        membership.id,
        membership.principal_id,
        membership.principal_kind::text,
        jsonb_build_object(
            'resource', jsonb_build_object(
                'type', 'organization_membership',
                'id', membership.id,
                'principal_id', membership.principal_id,
                'principal_type', membership.principal_kind::text,
                'version', membership.version,
                'status', CASE
                    WHEN membership.status = 'active'
                         AND subject_principal.status = 'active'
                         AND (silicon.id IS NULL OR silicon.provisioning_status <> 'deleted')
                    THEN 'active'
                    ELSE 'removed'
                END
            ),
            'principal', jsonb_build_object(
                'principal_id', membership.principal_id,
                'type', membership.principal_kind::text,
                'public_id', CASE
                    WHEN membership.principal_kind = 'carbon' THEN carbon.carbon_id
                    ELSE silicon.global_silicon_id
                END,
                'display_name', CASE
                    WHEN membership.principal_kind = 'carbon' THEN carbon.display_name
                    ELSE silicon.display_name
                END,
                'timezone', CASE
                    WHEN membership.principal_kind = 'carbon' THEN carbon.timezone_id
                    ELSE silicon.timezone_id
                END,
                'description', CASE
                    WHEN membership.principal_kind = 'carbon' THEN carbon.description
                    ELSE silicon.description
                END,
                'profile_photo', CASE
                    WHEN membership.principal_kind = 'carbon' THEN carbon.profile_photo_uri
                    ELSE silicon.profile_photo_override_uri
                END,
                'status', subject_principal.status::text,
                'version', CASE
                    WHEN membership.principal_kind = 'carbon' THEN carbon.version
                    ELSE silicon.version
                END,
                'created_at', CASE
                    WHEN membership.principal_kind = 'carbon' THEN carbon.created_at
                    ELSE silicon.created_at
                END,
                'updated_at', CASE
                    WHEN membership.principal_kind = 'carbon' THEN carbon.updated_at
                    ELSE silicon.updated_at
                END
            ),
            'organization', jsonb_build_object(
                'id', organization.id,
                'org_id', organization.org_id,
                'name', organization.name,
                'logo', organization.logo_uri,
                'description', organization.description,
                'join_method', organization.join_method::text,
                'status', organization.status::text,
                'version', organization.version,
                'created_at', organization.created_at,
                'updated_at', organization.updated_at
            ),
            'membership', jsonb_build_object(
                'id', membership.id,
                'status', CASE WHEN membership.status = 'active' THEN 'active' ELSE 'removed' END,
                'tags', COALESCE((
                    SELECT jsonb_agg(
                        jsonb_build_object('id', tag.id, 'name', tag.name)
                        ORDER BY tag.id
                    )
                    FROM iam.membership_tags AS assignment
                    JOIN iam.organization_tags AS tag
                      ON tag.organization_id = assignment.organization_id
                     AND tag.id = assignment.tag_id
                     AND tag.status = 'active'
                    WHERE assignment.organization_id = membership.organization_id
                      AND assignment.membership_id = membership.id
                ), '[]'::jsonb),
                'first_silicon_membership_id', carbon_settings.first_silicon_membership_id,
                'extra_silicon_membership_ids', CASE
                    WHEN membership.principal_kind = 'carbon' THEN COALESCE((
                        SELECT jsonb_agg(access_grant.silicon_membership_id ORDER BY access_grant.silicon_membership_id)
                        FROM iam.extra_silicon_access_grants AS access_grant
                        WHERE access_grant.organization_id = membership.organization_id
                          AND access_grant.carbon_membership_id = membership.id
                          AND access_grant.revoked_at IS NULL
                    ), '[]'::jsonb)
                    ELSE '[]'::jsonb
                END,
                'reports_to_membership_id', silicon.reports_to_membership_id,
                'hierarchy_level', CASE WHEN silicon.id IS NULL THEN NULL ELSE (
                    WITH RECURSIVE ancestors AS (
                        SELECT parent.membership_id, parent.reports_to_membership_id
                        FROM iam.silicons AS parent
                        WHERE parent.organization_id = membership.organization_id
                          AND parent.membership_id = silicon.membership_id
                        UNION
                        SELECT parent.membership_id, parent.reports_to_membership_id
                        FROM iam.silicons AS parent
                        JOIN ancestors
                          ON ancestors.reports_to_membership_id = parent.membership_id
                        WHERE parent.organization_id = membership.organization_id
                    )
                    SELECT count(*)::integer FROM ancestors
                ) END,
                'authorization_epoch', membership.authz_epoch,
                'removed_at', membership.removed_at,
                'created_at', membership.joined_at,
                'updated_at', membership.updated_at,
                'version', membership.version,
                'trust', jsonb_build_object(
                    'organization_default', jsonb_build_object(
                        'boundary', organization.default_trust_boundary::text,
                        'level', organization.default_trust_level::text
                    ),
                    'subject_default', jsonb_build_object(
                        'boundary', COALESCE(
                            carbon_settings.default_trust_boundary::text,
                            organization.default_trust_boundary::text
                        ),
                        'level', COALESCE(
                            carbon_settings.default_trust_level::text,
                            organization.default_trust_level::text
                        )
                    ),
                    'applicable_rules', COALESCE((
                        SELECT jsonb_agg(
                            jsonb_build_object(
                                'id', trust_rule.id,
                                'trust', jsonb_build_object(
                                    'boundary', trust_rule.trust_boundary::text,
                                    'level', trust_rule.trust_level::text
                                ),
                                'specificity',
                                    (trust_rule.subject_kind = 'membership')::integer
                                    + (trust_rule.target_kind = 'silicon')::integer,
                                'version', trust_rule.version
                            ) ORDER BY trust_rule.id
                        )
                        FROM iam.trust_rules AS trust_rule
                        WHERE trust_rule.organization_id = membership.organization_id
                          AND trust_rule.archived_at IS NULL
                          AND (
                              trust_rule.subject_membership_id = membership.id
                              OR EXISTS (
                                  SELECT 1
                                  FROM iam.membership_tags AS subject_assignment
                                  WHERE subject_assignment.organization_id = membership.organization_id
                                    AND subject_assignment.membership_id = membership.id
                                    AND subject_assignment.tag_id = trust_rule.subject_tag_id
                              )
                              OR (
                                  membership.principal_kind = 'silicon'
                                  AND (
                                      trust_rule.target_silicon_membership_id = membership.id
                                      OR EXISTS (
                                          SELECT 1
                                          FROM iam.membership_tags AS target_assignment
                                          WHERE target_assignment.organization_id = membership.organization_id
                                            AND target_assignment.membership_id = membership.id
                                            AND target_assignment.tag_id = trust_rule.target_tag_id
                                      )
                                  )
                              )
                          )
                    ), '[]'::jsonb)
                )
            ),
            'roles', jsonb_build_object(
                'org_role', membership.org_role::text,
                'job_role', membership.job_role,
                'capabilities', CASE
                    WHEN membership.principal_kind = 'carbon' THEN COALESCE((
                        SELECT jsonb_agg(capability_grant.capability ORDER BY capability_grant.capability)
                        FROM iam.organization_capability_grants AS capability_grant
                        WHERE capability_grant.organization_id = membership.organization_id
                          AND capability_grant.grantee_membership_id = membership.id
                          AND capability_grant.revoked_at IS NULL
                          AND capability_grant.capability <> 'audit.read'
                    ), '[]'::jsonb)
                    ELSE '[]'::jsonb
                END
            )
        ) AS current_state,
        email_contact.id,
        email_contact.ciphertext,
        email_contact.nonce,
        email_contact.encryption_key_version,
        phone_contact.id,
        phone_contact.ciphertext,
        phone_contact.nonce,
        phone_contact.encryption_key_version
    FROM iam.organization_memberships AS membership
    JOIN iam.organizations AS organization
      ON organization.id = membership.organization_id
    JOIN iam.principals AS subject_principal
      ON subject_principal.id = membership.principal_id
     AND subject_principal.kind = membership.principal_kind
    LEFT JOIN iam.carbons AS carbon
      ON carbon.id = membership.principal_id
     AND membership.principal_kind = 'carbon'
    LEFT JOIN iam.silicons AS silicon
      ON silicon.id = membership.principal_id
     AND silicon.organization_id = membership.organization_id
     AND silicon.membership_id = membership.id
     AND membership.principal_kind = 'silicon'
    LEFT JOIN iam.carbon_membership_settings AS carbon_settings
      ON carbon_settings.organization_id = membership.organization_id
     AND carbon_settings.membership_id = membership.id
    LEFT JOIN LATERAL (
        SELECT contact.id, contact.ciphertext, contact.nonce, contact.encryption_key_version
        FROM iam.carbon_contacts AS contact
        WHERE contact.carbon_id = membership.principal_id
          AND membership.principal_kind = 'carbon'
          AND contact.kind = 'email'
          AND contact.status = 'active'
          AND contact.is_primary
        ORDER BY contact.created_at, contact.id
        LIMIT 1
    ) AS email_contact ON true
    LEFT JOIN LATERAL (
        SELECT contact.id, contact.ciphertext, contact.nonce, contact.encryption_key_version
        FROM iam.carbon_contacts AS contact
        WHERE contact.carbon_id = membership.principal_id
          AND membership.principal_kind = 'carbon'
          AND contact.kind = 'phone'
          AND contact.status = 'active'
          AND contact.is_primary
        ORDER BY contact.created_at, contact.id
        LIMIT 1
    ) AS phone_contact ON true
    WHERE membership.organization_id = p_organization_id
      AND membership.id = ANY(p_membership_ids)
    ORDER BY membership.id
    FOR SHARE OF membership, organization, subject_principal;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.list_organization_member_webhook_projection_sources(
    uuid, uuid[]
) FROM PUBLIC;

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
      AND projection.application_id = p_application_id
$$;

REVOKE ALL ON FUNCTION iam_private.list_worker_captured_application_webhook_recipients(uuid)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.get_worker_application_webhook_event_projection(uuid, uuid)
    FROM PUBLIC;

COMMENT ON FUNCTION iam_private.list_organization_member_webhook_authorizations(
    uuid, uuid[], timestamptz
) IS
    'API-only, set-based temporal union of effective Application scopes for exact affected organization memberships; removed/revoked-at-boundary authority remains eligible only as before-authorized.';

COMMENT ON FUNCTION iam_private.list_organization_member_webhook_projection_sources(
    uuid, uuid[]
) IS
    'API-only complete secret-free member projection source plus still-encrypted primary Carbon contacts for immediate per-scope projection and re-encryption in the mutation transaction.';
