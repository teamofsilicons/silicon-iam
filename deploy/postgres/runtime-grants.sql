\set ON_ERROR_STOP on

BEGIN;

DO $roles$
BEGIN
    IF pg_catalog.to_regrole('silicon_iam_api') IS NULL THEN
        RAISE EXCEPTION 'required database role silicon_iam_api does not exist';
    END IF;
    IF pg_catalog.to_regrole('silicon_iam_worker') IS NULL THEN
        RAISE EXCEPTION 'required database role silicon_iam_worker does not exist';
    END IF;
    IF pg_catalog.to_regrole('silicon_iam_key_operator') IS NULL THEN
        RAISE EXCEPTION 'required database role silicon_iam_key_operator does not exist';
    END IF;
END;
$roles$;

REVOKE ALL ON SCHEMA iam FROM PUBLIC;
REVOKE ALL ON SCHEMA iam_private FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA iam_private FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA iam FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA iam_private FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA iam_private FROM PUBLIC;

-- Rebuild privileges from zero on every run. Without these revokes, a
-- privilege removed from this allowlist would survive an upgrade.
REVOKE ALL ON SCHEMA iam
    FROM silicon_iam_api, silicon_iam_worker, silicon_iam_key_operator;
REVOKE ALL ON SCHEMA iam_private
    FROM silicon_iam_api, silicon_iam_worker, silicon_iam_key_operator;
REVOKE ALL ON ALL TABLES IN SCHEMA iam
    FROM silicon_iam_api, silicon_iam_worker, silicon_iam_key_operator;
REVOKE ALL ON ALL TABLES IN SCHEMA iam_private
    FROM silicon_iam_api, silicon_iam_worker, silicon_iam_key_operator;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA iam
    FROM silicon_iam_api, silicon_iam_worker, silicon_iam_key_operator;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA iam_private
    FROM silicon_iam_api, silicon_iam_worker, silicon_iam_key_operator;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA iam_private
    FROM silicon_iam_api, silicon_iam_worker, silicon_iam_key_operator;

GRANT USAGE ON SCHEMA iam TO silicon_iam_api;
GRANT USAGE ON SCHEMA iam_private TO silicon_iam_api;
GRANT USAGE ON SCHEMA public TO silicon_iam_api;

-- Every API table capability is derived from production SQL. The SELECT list
-- also includes the relations read by invoker-rights deferred trigger helpers.
-- Relations absent from the manifest remain inaccessible, and partitions are
-- always accessed through their explicitly listed parent table.
DO $api_tables$
DECLARE
    table_name text;
    matched_table_count integer;
    unclassified_table_names text[];
    select_table_names text[] := ARRAY[
        'access_token_scopes',
        'access_tokens',
        'application_approved_scopes',
        'application_obo_endpoints',
        'application_redirect_uris',
        'application_requested_scopes',
        'application_reviews',
        'application_secrets',
        'application_webhook_endpoints',
        'application_webhook_event_projections',
        'application_webhook_signing_keys',
        'applications',
        'approval_decisions',
        'approval_requests',
        'approval_requirements',
        'audit_events',
        'authentication_events',
        'authentication_sessions',
        'carbon_contacts',
        'carbon_membership_settings',
        'carbons',
        'extra_silicon_access_grants',
        'idempotency_records',
        'invitation_verification_challenges',
        'job_role_change_requests',
        'job_role_history',
        'login_challenge_channels',
        'login_challenges',
        'membership_tag_change_history',
        'membership_tags',
        'notification_jobs',
        'oauth_authorization_codes',
        'oauth_authorization_request_scopes',
        'oauth_authorization_requests',
        'oauth_consent_grant_scopes',
        'oauth_consent_grants',
        'oauth_refresh_family_scopes',
        'oauth_scope_catalog',
        'obo_proofs',
        'organization_capability_catalog',
        'organization_capability_grants',
        'organization_invitation_extra_silicons',
        'organization_invitation_silicon_trust_overrides',
        'organization_invitation_tag_trust_overrides',
        'organization_invitation_tags',
        'organization_invitations',
        'organization_memberships',
        'organization_sso_configs',
        'organization_tags',
        'organizations',
        'outbox_event_affected_tags',
        'outbox_event_own_tag_memberships',
        'outbox_event_recipients',
        'outbox_event_topics',
        'outbox_events',
        'ownership_transfer_requests',
        'platform_role_grants',
        'principals',
        'rate_limit_buckets',
        'refresh_token_families',
        'refresh_tokens',
        'service_principals',
        'signup_candidate_blind_indexes',
        'signup_contact_candidates',
        'signup_otp_challenges',
        'signup_sessions',
        'silicon_credential_history',
        'silicon_credentials',
        'silicon_token_rotation_requests',
        'silicon_webhook_endpoints',
        'silicon_webhook_signing_keys',
        'silicon_webhook_subscription_extra_tags',
        'silicon_webhook_subscription_topics',
        'silicon_webhook_subscriptions',
        'silicons',
        'sso_authorization_transactions',
        'sso_connections',
        'sso_setup_sessions',
        'step_up_assertions',
        'step_up_challenges',
        'tag_change_requests',
        'testing_environments',
        'trust_rules',
        'webhook_deliveries'
    ];
    insert_table_names text[] := ARRAY[
        'access_token_scopes',
        'access_tokens',
        'application_approved_scopes',
        'application_obo_endpoints',
        'application_redirect_uris',
        'application_requested_scopes',
        'application_reviews',
        'application_secrets',
        'application_webhook_endpoints',
        'application_webhook_event_projections',
        'application_webhook_signing_keys',
        'applications',
        'approval_decisions',
        'approval_requests',
        'approval_requirements',
        'audit_events',
        'authentication_events',
        'authentication_sessions',
        'carbon_membership_settings',
        'extra_silicon_access_grants',
        'idempotency_records',
        'invitation_verification_challenges',
        'job_role_change_requests',
        'job_role_history',
        'login_challenge_channels',
        'login_challenges',
        'notification_jobs',
        'oauth_authorization_codes',
        'oauth_authorization_request_scopes',
        'oauth_authorization_requests',
        'oauth_consent_grant_scopes',
        'oauth_consent_grants',
        'oauth_refresh_family_scopes',
        'obo_proofs',
        'organization_capability_grants',
        'organization_invitation_extra_silicons',
        'organization_invitation_silicon_trust_overrides',
        'organization_invitation_tag_trust_overrides',
        'organization_invitation_tags',
        'organization_invitations',
        'organization_memberships',
        'organization_tags',
        'organizations',
        'outbox_event_affected_tags',
        'outbox_event_own_tag_memberships',
        'outbox_event_topics',
        'outbox_events',
        'principals',
        'rate_limit_buckets',
        'refresh_token_families',
        'refresh_tokens',
        'signup_candidate_blind_indexes',
        'signup_contact_candidates',
        'signup_otp_challenges',
        'signup_sessions',
        'silicon_credential_history',
        'silicon_credentials',
        'silicon_token_rotation_requests',
        'silicon_webhook_endpoints',
        'silicon_webhook_signing_keys',
        'silicon_webhook_subscription_extra_tags',
        'silicon_webhook_subscription_topics',
        'silicon_webhook_subscriptions',
        'silicons',
        'sso_setup_sessions',
        'step_up_assertions',
        'step_up_challenges',
        'tag_change_requests',
        'testing_environments',
        'trust_rules'
    ];
    update_table_names text[] := ARRAY[
        'access_tokens',
        'application_approved_scopes',
        'application_obo_endpoints',
        'application_redirect_uris',
        'application_secrets',
        'application_webhook_endpoints',
        'application_webhook_signing_keys',
        'applications',
        'approval_requests',
        'authentication_sessions',
        'carbon_membership_settings',
        'carbons',
        'extra_silicon_access_grants',
        'idempotency_records',
        'invitation_verification_challenges',
        'login_challenge_channels',
        'login_challenges',
        'notification_jobs',
        'oauth_authorization_codes',
        'oauth_authorization_requests',
        'oauth_consent_grants',
        'obo_proofs',
        'organization_capability_grants',
        'organization_invitations',
        'organization_memberships',
        'organization_sso_configs',
        'organization_tags',
        'organizations',
        'outbox_event_recipients',
        'principals',
        'rate_limit_buckets',
        'refresh_token_families',
        'refresh_tokens',
        'signup_contact_candidates',
        'signup_otp_challenges',
        'signup_sessions',
        'silicon_credentials',
        'silicon_token_rotation_requests',
        'silicon_webhook_endpoints',
        'silicon_webhook_signing_keys',
        'silicon_webhook_subscriptions',
        'silicons',
        'sso_authorization_transactions',
        'sso_connections',
        'sso_setup_sessions',
        'step_up_assertions',
        'step_up_challenges',
        'testing_environments',
        'trust_rules',
        'webhook_deliveries'
    ];
    delete_table_names text[] := ARRAY[
        'application_requested_scopes',
        'idempotency_records',
        'oauth_consent_grant_scopes',
        'silicon_webhook_subscription_extra_tags',
        'silicon_webhook_subscription_topics',
        'silicon_webhook_subscriptions'
    ];
    denied_table_names text[] := ARRAY[
        'contact_blind_indexes',
        'cryptographic_key_versions',
        'external_webhook_receipts',
        'platform_capability_catalog',
        'platform_role_capabilities',
        'platform_role_catalog',
        'runtime_key_activations',
        'silicon_hooks',
        'sso_identities',
        'webhook_delivery_attempts'
    ];
BEGIN
    IF pg_catalog.cardinality(select_table_names) <> (
        SELECT pg_catalog.count(DISTINCT listed_name)
        FROM pg_catalog.unnest(select_table_names) AS listed_name
    ) OR pg_catalog.cardinality(insert_table_names) <> (
        SELECT pg_catalog.count(DISTINCT listed_name)
        FROM pg_catalog.unnest(insert_table_names) AS listed_name
    ) OR pg_catalog.cardinality(update_table_names) <> (
        SELECT pg_catalog.count(DISTINCT listed_name)
        FROM pg_catalog.unnest(update_table_names) AS listed_name
    ) OR pg_catalog.cardinality(delete_table_names) <> (
        SELECT pg_catalog.count(DISTINCT listed_name)
        FROM pg_catalog.unnest(delete_table_names) AS listed_name
    ) OR pg_catalog.cardinality(denied_table_names) <> (
        SELECT pg_catalog.count(DISTINCT listed_name)
        FROM pg_catalog.unnest(denied_table_names) AS listed_name
    ) THEN
        RAISE EXCEPTION 'API table capability manifest contains a duplicate';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.unnest(
            insert_table_names || update_table_names || delete_table_names
        ) AS writable_name
        WHERE writable_name <> ALL (select_table_names)
    ) THEN
        RAISE EXCEPTION 'every writable API table must also be SELECT-authorized';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.unnest(denied_table_names) AS denied_name
        WHERE denied_name = ANY (select_table_names)
    ) THEN
        RAISE EXCEPTION 'API table capability and deny manifests overlap';
    END IF;

    FOREACH table_name IN ARRAY select_table_names || denied_table_names
    LOOP
        SELECT pg_catalog.count(*)
        INTO matched_table_count
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'iam'
          AND relation.relname = table_name
          AND relation.relkind IN ('r', 'p')
          AND NOT relation.relispartition;

        IF matched_table_count <> 1 THEN
            RAISE EXCEPTION
                'API table manifest expected one non-partition iam.%, found %',
                table_name,
                matched_table_count;
        END IF;
    END LOOP;

    FOREACH table_name IN ARRAY select_table_names
    LOOP
        EXECUTE pg_catalog.format(
            'GRANT SELECT ON TABLE %I.%I TO silicon_iam_api',
            'iam',
            table_name
        );
    END LOOP;
    FOREACH table_name IN ARRAY insert_table_names
    LOOP
        EXECUTE pg_catalog.format(
            'GRANT INSERT ON TABLE %I.%I TO silicon_iam_api',
            'iam',
            table_name
        );
    END LOOP;
    FOREACH table_name IN ARRAY update_table_names
    LOOP
        EXECUTE pg_catalog.format(
            'GRANT UPDATE ON TABLE %I.%I TO silicon_iam_api',
            'iam',
            table_name
        );
    END LOOP;
    FOREACH table_name IN ARRAY delete_table_names
    LOOP
        EXECUTE pg_catalog.format(
            'GRANT DELETE ON TABLE %I.%I TO silicon_iam_api',
            'iam',
            table_name
        );
    END LOOP;

    SELECT pg_catalog.array_agg(relation.relname ORDER BY relation.relname)
    INTO unclassified_table_names
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'iam'
      AND relation.relkind IN ('r', 'p')
      AND NOT relation.relispartition
      AND relation.relname <> ALL (select_table_names || denied_table_names);

    IF unclassified_table_names IS NOT NULL THEN
        RAISE EXCEPTION
            'unclassified IAM tables exist: %',
            unclassified_table_names;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'iam'
          AND relation.relispartition
          AND (
              pg_catalog.has_table_privilege(
                  'silicon_iam_api', relation.oid, 'SELECT'
              )
              OR pg_catalog.has_table_privilege(
                  'silicon_iam_api', relation.oid, 'INSERT'
              )
              OR pg_catalog.has_table_privilege(
                  'silicon_iam_api', relation.oid, 'UPDATE'
              )
              OR pg_catalog.has_table_privilege(
                  'silicon_iam_api', relation.oid, 'DELETE'
              )
          )
    ) THEN
        RAISE EXCEPTION 'API table capability manifest granted a partition directly';
    END IF;
END;
$api_tables$;

DO $api_sequences$
DECLARE
    sequence_name text;
    matched_sequence_count integer;
    unclassified_sequence_names text[];
    usage_sequence_names text[] := ARRAY[
        'audit_events_global_sequence_seq',
        'outbox_events_global_sequence_seq'
    ];
    denied_sequence_names text[] := ARRAY[
        'runtime_key_activations_id_seq'
    ];
BEGIN
    IF pg_catalog.cardinality(usage_sequence_names) <> (
        SELECT pg_catalog.count(DISTINCT listed_name)
        FROM pg_catalog.unnest(usage_sequence_names) AS listed_name
    ) OR pg_catalog.cardinality(denied_sequence_names) <> (
        SELECT pg_catalog.count(DISTINCT listed_name)
        FROM pg_catalog.unnest(denied_sequence_names) AS listed_name
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.unnest(denied_sequence_names) AS denied_name
        WHERE denied_name = ANY (usage_sequence_names)
    ) THEN
        RAISE EXCEPTION 'API sequence capability manifest is invalid';
    END IF;

    FOREACH sequence_name IN ARRAY usage_sequence_names || denied_sequence_names
    LOOP
        SELECT pg_catalog.count(*)
        INTO matched_sequence_count
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'iam'
          AND relation.relname = sequence_name
          AND relation.relkind = 'S';

        IF matched_sequence_count <> 1 THEN
            RAISE EXCEPTION
                'API sequence manifest expected one iam.%, found %',
                sequence_name,
                matched_sequence_count;
        END IF;
    END LOOP;

    FOREACH sequence_name IN ARRAY usage_sequence_names
    LOOP
        EXECUTE pg_catalog.format(
            'GRANT USAGE ON SEQUENCE %I.%I TO silicon_iam_api',
            'iam',
            sequence_name
        );
    END LOOP;

    SELECT pg_catalog.array_agg(relation.relname ORDER BY relation.relname)
    INTO unclassified_sequence_names
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'iam'
      AND relation.relkind = 'S'
      AND relation.relname <> ALL (
          usage_sequence_names || denied_sequence_names
      );

    IF unclassified_sequence_names IS NOT NULL THEN
        RAISE EXCEPTION
            'unclassified IAM sequences exist: %',
            unclassified_sequence_names;
    END IF;
END;
$api_sequences$;

GRANT SELECT ON public._sqlx_migrations TO silicon_iam_api;

DO $api_functions$
DECLARE
    allowed_function_name text;
    matched_function_count integer;
    function_record record;
    api_function_names text[] := ARRAY[
        'active_organization_membership_id',
        'apply_approved_tag_change',
        'apply_workos_connection_event',
        'assert_active_carbon_contacts',
        'assert_active_principal_subtype',
        'assert_approval_request_shape',
        'assert_exactly_one_organization_owner',
        'assert_platform_administrator_present',
        'assign_initial_silicon_tags',
        'begin_sso_authorization',
        'can_administer_application',
        'can_manage_application',
        'can_manage_application_technical',
        'can_read_application',
        'cancel_silicon_webhook_deliveries',
        'carbon_handle_is_available',
        'complete_sso_authorization',
        'complete_verified_organization_invitation',
        'complete_verified_signup',
        'current_application_id',
        'current_organization_id',
        'current_principal_id',
        'deactivate_silicon_webhook_for_removal',
        'describe_testing_environment',
        'get_organization_invitation_destination',
        'has_organization_capability',
        'has_platform_capability',
        'is_active_organization_member',
        'is_active_organization_owner_or_admin',
        'is_organization_creator',
        'is_testing_environment_administrator',
        'is_valid_sso_callback_correlation',
        'list_active_carbon_login_contacts',
        'list_organization_member_webhook_authorizations',
        'list_organization_member_webhook_projection_sources',
        'list_profile_webhook_authorization_scopes',
        'lock_application_creation_organization',
        'lock_invitation_verification_challenge',
        'lock_membership_removal_event_scope',
        'lock_silicon_webhook_delivery_scope',
        'lock_silicon_webhook_own_tag_audience',
        'lock_silicon_webhook_target',
        'lock_sso_membership_activation_state',
        'non_deleted_carbon_contact_exists',
        'organization_handle_is_available',
        'reconcile_runtime_keyring',
        'record_testing_environment_cleaning',
        'record_ignored_workos_event',
        'remove_organization_membership',
        'replace_membership_job_role_direct',
        'replace_membership_tags_direct',
        'replace_organization_sso_entitlement',
        'resolve_active_carbon_by_contact_digest',
        'resolve_active_carbon_by_handle',
        'resolve_active_silicon_credential',
        'resolve_authorized_application_organization',
        'resolve_organization_invitation_tenant',
        'resolve_pending_email_join_invitation',
        'resolve_platform_sso_organization',
        'resolve_silicon_webhook_replay_target',
        'resolve_testing_environment',
        'set_organization_admin_role',
        'touch_testing_environment'
    ];
    non_api_definer_names text[] := ARRAY[
        'activate_runtime_key_version',
        'assert_active_carbon_contacts',
        'assert_active_principal_subtype',
        'assert_approval_request_shape',
        'assert_exactly_one_organization_owner',
        'assert_outbox_event_affected_tag_tenant',
        'assert_outbox_event_own_tag_membership_tenant',
        'assert_silicon_webhook_subscription_topics',
        'check_approval_shape_from_payload',
        'check_approval_shape_from_request',
        'check_carbon_contacts_from_contact',
        'check_carbon_contacts_from_principal',
        'check_owner_after_membership_change',
        'check_owner_after_organization_change',
        'check_principal_subtype_from_principal',
        'check_principal_subtype_from_subtype',
        'complete_worker_silicon_hook',
        'expire_idle_testing_environments',
        'erase_testing_environment',
        'fail_worker_silicon_hook',
        'get_audit_public_identifiers',
        'get_worker_application_webhook_event_projection',
        'get_worker_application_webhook_material',
        'get_worker_invitation_context',
        'get_worker_notification_contact',
        'get_worker_security_notice_contact',
        'get_worker_silicon_hook_identity',
        'get_worker_silicon_webhook_material',
        'list_testing_environments_for_purge',
        'list_worker_application_webhook_recipients',
        'list_worker_captured_application_webhook_recipients',
        'list_worker_silicon_webhook_recipients',
        'prevent_oauth_refresh_family_scope_mutation',
        'prevent_silicon_reporting_cycle',
        'purge_testing_environment',
        'reconcile_worker_contact_aead_keyring',
        'reject_audit_mutation',
        'reject_immutable_history_mutation',
        'run_worker_ephemeral_maintenance',
        'run_worker_retention_maintenance'
    ];
BEGIN
    FOREACH allowed_function_name IN ARRAY api_function_names
    LOOP
        SELECT pg_catalog.count(*)
        INTO matched_function_count
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'iam_private'
          AND procedure.proname = allowed_function_name;

        IF matched_function_count <> 1 THEN
            RAISE EXCEPTION
                'API allowlist expected exactly one iam_private.%, found %',
                allowed_function_name,
                matched_function_count;
        END IF;

        SELECT
            namespace.nspname,
            procedure.proname,
            pg_catalog.pg_get_function_identity_arguments(procedure.oid) AS arguments
        INTO STRICT function_record
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'iam_private'
          AND procedure.proname = allowed_function_name;

        EXECUTE pg_catalog.format(
            'GRANT EXECUTE ON FUNCTION %I.%I(%s) TO silicon_iam_api',
            function_record.nspname,
            function_record.proname,
            function_record.arguments
        );
    END LOOP;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'iam_private'
          AND procedure.prosecdef
          AND procedure.proname <> ALL (
              api_function_names || non_api_definer_names
          )
    ) THEN
        RAISE EXCEPTION
            'unclassified SECURITY DEFINER function exists in iam_private';
    END IF;
END;
$api_functions$;

GRANT USAGE ON SCHEMA iam TO silicon_iam_worker;
GRANT USAGE ON SCHEMA iam_private TO silicon_iam_worker;
GRANT SELECT, UPDATE ON iam.outbox_events TO silicon_iam_worker;
GRANT SELECT, INSERT ON iam.outbox_event_recipients TO silicon_iam_worker;
GRANT SELECT, INSERT, UPDATE ON iam.webhook_deliveries TO silicon_iam_worker;
GRANT SELECT, INSERT, UPDATE ON iam.webhook_delivery_attempts TO silicon_iam_worker;
GRANT SELECT, UPDATE ON iam.notification_jobs TO silicon_iam_worker;
GRANT SELECT ON public._sqlx_migrations TO silicon_iam_worker;

-- Worker policy roles are bound only after deployment has provisioned the
-- fixed NOLOGIN roles. Keeping role names out of migrations makes a schema
-- bootstrap portable while preventing worker sessions from evaluating API
-- policy helpers whose EXECUTE privilege they intentionally do not receive.
ALTER POLICY silicons_member_select
    ON iam.silicons TO silicon_iam_api;
ALTER POLICY silicon_webhook_endpoints_manage
    ON iam.silicon_webhook_endpoints TO silicon_iam_api;
ALTER POLICY silicon_webhook_signing_keys_manage
    ON iam.silicon_webhook_signing_keys TO silicon_iam_api;
ALTER POLICY silicon_webhook_subscriptions_manage
    ON iam.silicon_webhook_subscriptions TO silicon_iam_api;
ALTER POLICY silicon_webhook_subscription_topics_manage
    ON iam.silicon_webhook_subscription_topics TO silicon_iam_api;
ALTER POLICY silicon_webhook_subscription_extra_tags_manage
    ON iam.silicon_webhook_subscription_extra_tags TO silicon_iam_api;
ALTER POLICY tag_change_requests_member_select
    ON iam.tag_change_requests TO silicon_iam_api;
ALTER POLICY tag_change_requests_create
    ON iam.tag_change_requests TO silicon_iam_api;
ALTER POLICY membership_tag_change_history_member_select
    ON iam.membership_tag_change_history TO silicon_iam_api;

-- Remove stale worker policies from deployments that previously provisioned
-- provider-managed Silicon Hooks. Table privileges are rebuilt from zero above.
DROP POLICY IF EXISTS silicons_worker_select ON iam.silicons;
DROP POLICY IF EXISTS silicon_hooks_worker_select ON iam.silicon_hooks;
DROP POLICY IF EXISTS silicon_hooks_worker_update ON iam.silicon_hooks;

DO $worker_functions$
DECLARE
    allowed_function_name text;
    matched_function_count integer;
    function_record record;
    worker_function_names text[] := ARRAY[
        'expire_idle_testing_environments',
        'get_worker_application_webhook_material',
        'get_worker_application_webhook_event_projection',
        'get_worker_invitation_context',
        'get_worker_notification_contact',
        'get_worker_security_notice_contact',
        'get_worker_silicon_webhook_material',
        'list_worker_application_webhook_recipients',
        'list_worker_captured_application_webhook_recipients',
        'list_worker_silicon_webhook_recipients',
        'list_testing_environments_for_purge',
        'lock_silicon_webhook_delivery_scope',
        'purge_testing_environment',
        'reconcile_worker_contact_aead_keyring',
        'run_worker_ephemeral_maintenance',
        'run_worker_retention_maintenance'
    ];
BEGIN
    FOREACH allowed_function_name IN ARRAY worker_function_names
    LOOP
        SELECT pg_catalog.count(*)
        INTO matched_function_count
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'iam_private'
          AND procedure.proname = allowed_function_name;

        IF matched_function_count <> 1 THEN
            RAISE EXCEPTION
                'worker allowlist expected exactly one iam_private.%, found %',
                allowed_function_name,
                matched_function_count;
        END IF;

        SELECT
            namespace.nspname,
            procedure.proname,
            pg_catalog.pg_get_function_identity_arguments(procedure.oid) AS arguments
        INTO STRICT function_record
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'iam_private'
          AND procedure.proname = allowed_function_name;

        EXECUTE pg_catalog.format(
            'GRANT EXECUTE ON FUNCTION %I.%I(%s) TO silicon_iam_worker',
            function_record.nspname,
            function_record.proname,
            function_record.arguments
        );
    END LOOP;
END;
$worker_functions$;

-- Functions that exist only in a testing database.
--
-- The testing overlay in migrations/testing adds per-environment row scoping
-- on top of the identical production schema. Its helpers are absent from a
-- production database, so each grant here is conditional: applying this file
-- to either database must succeed unchanged.
--
-- current_testing_environment_id is what every environment policy calls, so
-- both runtime roles need EXECUTE on it or nothing in that database is
-- readable at all. erase_testing_environment backs the API's "clean this
-- environment" operation and the worker's final purge.
DO $testing_plane_functions$
DECLARE
    allowed_function_name text;
    function_record record;
    testing_plane_function_names text[] := ARRAY[
        'current_testing_environment_id',
        'erase_testing_environment'
    ];
BEGIN
    FOREACH allowed_function_name IN ARRAY testing_plane_function_names
    LOOP
        SELECT
            namespace.nspname,
            procedure.proname,
            pg_catalog.pg_get_function_identity_arguments(procedure.oid) AS arguments
        INTO function_record
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'iam_private'
          AND procedure.proname = allowed_function_name;

        CONTINUE WHEN NOT FOUND;

        EXECUTE pg_catalog.format(
            'GRANT EXECUTE ON FUNCTION %I.%I(%s) TO silicon_iam_api, silicon_iam_worker',
            function_record.nspname,
            function_record.proname,
            function_record.arguments
        );
    END LOOP;
END;
$testing_plane_functions$;

-- The operator role has no IAM table access. Its only authority is the
-- compare-and-swap transition implemented by this fixed-path definer function.
GRANT USAGE ON SCHEMA iam_private TO silicon_iam_key_operator;
GRANT EXECUTE ON FUNCTION iam_private.activate_runtime_key_version(
    text, smallint, smallint
) TO silicon_iam_key_operator;

COMMIT;
