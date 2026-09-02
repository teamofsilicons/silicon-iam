#!/usr/bin/env ruby
# frozen_string_literal: true

migration_paths = Dir["migrations/*.sql"].sort
raise "no SQL migrations found" if migration_paths.empty?

source = migration_paths.map do |path|
  "-- source: #{path}\n#{File.read(path)}"
end.join("\n")

function_starts = []
source.to_enum(:scan, /CREATE(?: OR REPLACE)? FUNCTION iam_private\.([a-z0-9_]+)\s*\(/).each do
  match = Regexp.last_match
  function_starts << [match[1], match.begin(0)]
end

issues = []
security_definer_count = 0
function_starts.each_with_index do |(name, start_at), index|
  finish_at = if index + 1 < function_starts.length
                function_starts[index + 1][1]
              else
                source.length
              end
  definition = source[start_at...finish_at]
  next unless definition.include?("SECURITY DEFINER")

  security_definer_count += 1
  search_path = definition[/SET search_path\s*=\s*([^\n]+)/, 1]
  if search_path.nil?
    issues << "iam_private.#{name}: SECURITY DEFINER is missing SET search_path"
  else
    entries = search_path.delete_suffix(";").split(",").map(&:strip)
    if entries.first != "pg_catalog" || (entries & ["public", "pg_temp", '"$user"']).any?
      issues << "iam_private.#{name}: search_path must start with pg_catalog and exclude mutable schemas"
    end
  end

  revoke_pattern = /REVOKE ALL ON FUNCTION iam_private\.#{Regexp.escape(name)}\s*\([^;]*\)\s*FROM PUBLIC\s*;/m
  unless source.match?(revoke_pattern)
    issues << "iam_private.#{name}: PUBLIC EXECUTE is not explicitly revoked"
  end
end

if source.match?(/\bGRANT\s+EXECUTE\b[^;]*\bTO\s+PUBLIC\b/im)
  issues << "migration grants function execution to PUBLIC"
end
if source.match?(/\bBYPASSRLS\b/i)
  issues << "migration grants or references BYPASSRLS"
end

retention_path = "migrations/0012_configurable_retention_maintenance.sql"
retention_cleanup_path = "migrations/0021_remove_out_of_scope_auth_surfaces.sql"
if File.exist?(retention_path) && File.exist?(retention_cleanup_path)
  retention = File.read(retention_path)
  active_retention = File.read(retention_cleanup_path)
  retention_history = "#{retention}\n#{active_retention}"
  retention_requirements = {
    "checks the original login's worker-role membership" =>
      /pg_has_role\(session_user, worker_role, 'member'\)/m,
    "uses a transaction-scoped capability instead of a custom GUC" =>
      /worker_retention_guards[\s\S]*pg_current_xact_id\(\)/,
    "bounds the database batch size" => /p_limit > 1000/,
    "bounds whole-day retention settings" => /NOT BETWEEN 1 AND 36500/,
    "claims cleanup work with skip-locked row locks" => /FOR UPDATE[\s\S]*SKIP LOCKED/,
    "revokes Public execution of the worker entry point" =>
      /REVOKE ALL ON FUNCTION iam_private\.run_worker_retention_maintenance\([\s\S]*?\) FROM PUBLIC;/,
    "guards retained-skeleton erasure transitions" =>
      /reject_immutable_history_mutation\('worker_retention_purge'\)/,
    "prevents purged session metadata from being restored" =>
      /authentication_sessions_retention_purge_consistency CHECK \(\s*retention_purged_at IS NULL\s*OR \(ip_fingerprint IS NULL\s*AND user_agent_fingerprint IS NULL\s*AND revocation_reason IS NULL\)\s*\)/m
  }
  retention_requirements.each do |description, pattern|
    issues << "retention migration #{description}" unless retention_history.match?(pattern)
  end
  if retention_history.match?(/\b(?:current_setting|set_config)\s*\(/i)
    issues << "retention migration trusts a caller-settable custom GUC"
  end

  declared_phase_source = active_retention[
    /IF p_phase IS NULL OR p_phase NOT IN \((.*?)\) THEN/m, 1
  ]
  declared_phases = declared_phase_source&.scan(/'([a-z0-9_]+)'/)&.flatten
  worker_source = File.read("src/worker/maintenance.rs")
  worker_phase_source = worker_source[/const RETENTION_PHASES:.*?= \[(.*?)\];/m, 1]
  worker_phases = worker_phase_source&.scan(/"([a-z0-9_]+)"/)&.flatten
  unless declared_phases&.length == 18 && declared_phases == worker_phases
    issues << "active retention migration and worker must share one exact 18-phase vocabulary"
  end
  cleanup_requirements = {
    "makes the retired retention core invoker-rights" =>
      /run_worker_retention_maintenance_core\([\s\S]*?\) SECURITY INVOKER;/,
    "revokes the worker's inherited access to the retired retention core" =>
      /REVOKE ALL ON FUNCTION iam_private\.run_worker_retention_maintenance_core\([\s\S]*?FROM silicon_iam_worker/,
    "implements session deletion without retired auth tables" =>
      /p_phase <> 'authentication_sessions_delete'[\s\S]*ELSIF|p_phase <> 'authentication_sessions_delete'[\s\S]*WITH expired AS MATERIALIZED/m,
    "removes the account-deletion worker entry point" =>
      /DROP FUNCTION iam_private\.run_worker_account_deletion_finalization/,
    "discharges deferred Carbon invariants before principal DDL" =>
      /status = 'deletion_pending';[\s\S]*SET CONSTRAINTS ALL IMMEDIATE;[\s\S]*ALTER TABLE iam\.principals/,
    "removes retired authentication tables explicitly" =>
      /DROP TABLE iam\.contact_change_blind_indexes;[\s\S]*DROP TABLE iam\.contact_change_sessions;[\s\S]*DROP TABLE iam\.account_deletion_requests;[\s\S]*DROP TABLE iam\.webauthn_ceremonies;[\s\S]*DROP TABLE iam\.webauthn_credentials;/
  }
  cleanup_requirements.each do |description, pattern|
    issues << "auth-surface cleanup #{description}" unless active_retention.match?(pattern)
  end
end

key_rotation = File.read("migrations/0010_runtime_key_rotation.sql")
unless key_rotation.match?(
  /reconcile_worker_contact_aead_keyring[\s\S]*pg_auth_members[\s\S]*PERFORM iam_private\.reconcile_runtime_keyring\(\s*'contact_aead'/
)
  issues << "worker keyring wrapper must attest the login and fix purpose to contact_aead"
end

silicon_webhooks = [
  "migrations/0014_configurable_silicon_webhooks.sql",
  "migrations/0027_harden_silicon_webhook_lifecycle.sql",
  "migrations/0032_exact_silicon_webhook_topics.sql"
].map { |path| File.read(path) }.join("\n")
silicon_webhook_requirements = {
  "keeps routing topics outside the webhook payload" =>
    /CREATE TABLE iam\.outbox_event_topics[\s\S]*control routing only and are never serialized into webhook payloads/,
  "keeps affected-tag routing data outside the webhook payload" =>
    /CREATE TABLE iam\.outbox_event_affected_tags[\s\S]*never enter webhook payloads/,
  "fails closed for organization-wide own-tag subscriptions" =>
    /subscription\.own_tags_only[\s\S]*NOT event\.organization_wide[\s\S]*active_tag\.status = 'active'/,
  "distinguishes explicitly routed Full-only events from unrouted events" =>
    /ADD COLUMN silicon_webhook_routable boolean NOT NULL DEFAULT false[\s\S]*CHECK \(NOT silicon_webhook_routable OR organization_id IS NOT NULL\)/,
  "requires the explicit routing marker before any Silicon delivery" =>
    /WHERE event\.id = p_outbox_event_id[\s\S]*event\.silicon_webhook_routable/,
  "delivers every routed event to Full and exact topics only to selected subscribers" =>
    /subscription\.mode = 'all'[\s\S]*subscription\.mode = 'selected'[\s\S]*selected_topic\.topic = event_topic\.topic/,
  "uses a closed three-topic subscription vocabulary" =>
    /topic IN \('membership_lifecycle', 'member_updates', 'trust_updates'\)/,
  "activates new Silicons without legacy Hook provisioning" =>
    /ALTER COLUMN provisioning_status SET DEFAULT 'active'/,
  "activates Silicons stranded by legacy Hook provisioning" =>
    /SET provisioning_status = 'active'[\s\S]*IN \('pending_hook', 'hook_error'\)/,
  "disables every legacy provider-managed Silicon Hook" =>
    /UPDATE iam\.silicon_hooks[\s\S]*SET status = 'disabled'/,
  "cancels in-flight legacy Silicon Hook deliveries" =>
    /recipient\.recipient_kind = 'silicon_hook'[\s\S]*delivery\.status IN \('pending', 'processing'\)/,
  "revokes Public access to the Silicon recipient reader" =>
    /REVOKE ALL ON FUNCTION iam_private\.list_worker_silicon_webhook_recipients\(uuid\) FROM PUBLIC;/,
  "revokes Public access to Silicon delivery material" =>
    /REVOKE ALL ON FUNCTION iam_private\.get_worker_silicon_webhook_material\(uuid, uuid\) FROM PUBLIC;/,
  "attests self-or-directory-manager authority before locking a webhook target" =>
    /lock_silicon_webhook_target[\s\S]*current_organization_id\(\)[\s\S]*current_principal_id\(\)[\s\S]*'silicons\.update_directory'[\s\S]*FOR UPDATE OF silicon, membership/,
  "revokes Public access to the webhook target lock" =>
    /REVOKE ALL ON FUNCTION iam_private\.lock_silicon_webhook_target\(uuid, text\) FROM PUBLIC;/,
  "defines a transaction-scoped endpoint delivery lock" =>
    /lock_silicon_webhook_delivery_scope[\s\S]*pg_advisory_xact_lock[\s\S]*hashtextextended/,
  "revokes Public access to the endpoint delivery lock" =>
    /REVOKE ALL ON FUNCTION iam_private\.lock_silicon_webhook_delivery_scope\(uuid\) FROM PUBLIC;/,
  "attests removal authority before deactivating a Silicon webhook" =>
    /deactivate_silicon_webhook_for_removal[\s\S]*current_organization_id\(\)[\s\S]*'silicons\.remove'/,
  "locks the Silicon and membership before webhook removal cleanup" =>
    /deactivate_silicon_webhook_for_removal[\s\S]*FROM iam\.silicons AS silicon[\s\S]*JOIN iam\.organization_memberships AS membership[\s\S]*FOR UPDATE OF silicon, membership[\s\S]*SELECT endpoint\.id/,
  "atomically retires webhook state during Silicon removal" =>
    /deactivate_silicon_webhook_for_removal[\s\S]*lock_silicon_webhook_delivery_scope\(resolved_endpoint_id\)[\s\S]*DELETE FROM iam\.silicon_webhook_subscriptions[\s\S]*last_error_code = 'silicon_removed'[\s\S]*signing_key\.status IN \('active', 'retiring'\)[\s\S]*SET status = 'disabled'/,
  "revokes Public access to Silicon removal deactivation" =>
    /REVOKE ALL ON FUNCTION iam_private\.deactivate_silicon_webhook_for_removal\(uuid, uuid\) FROM PUBLIC;/
}
silicon_webhook_requirements.each do |description, pattern|
  issues << "configurable Silicon webhook migration #{description}" unless silicon_webhooks.match?(pattern)
end

exact_silicon_topics = File.read("migrations/0032_exact_silicon_webhook_topics.sql")
exact_silicon_topic_requirements = {
  "stores a tenant-checked event-time own-tag membership snapshot" =>
    /CREATE TABLE iam\.outbox_event_own_tag_memberships[\s\S]*outbox_event_own_tag_memberships_event_fk[\s\S]*ON DELETE CASCADE[\s\S]*outbox_event_own_tag_memberships_membership_fk[\s\S]*assert_outbox_event_own_tag_membership_tenant/,
  "bounds own-tag snapshots to their outbox retention lifecycle" =>
    /outbox_event_own_tag_memberships_event_fk[\s\S]*REFERENCES iam\.outbox_events \(id\)[\s\S]*ON DELETE CASCADE/,
  "uses only the captured event-time tag audience at expansion" =>
    /subscription\.own_tags_only[\s\S]*FROM iam\.outbox_event_own_tag_memberships AS own_tag_audience[\s\S]*own_tag_audience\.membership_id = silicon\.membership_id/,
  "attests the organization actor and serializes subscriber tag state" =>
    /lock_silicon_webhook_own_tag_audience[\s\S]*current_principal_id\(\)[\s\S]*is_active_organization_member[\s\S]*FOR SHARE OF subscription, endpoint, silicon, principal, membership/,
  "revokes Public access to the event-time audience lock" =>
    /REVOKE ALL ON FUNCTION iam_private\.lock_silicon_webhook_own_tag_audience\([\s\S]*uuid, uuid\[\], uuid\[\][\s\S]*\) FROM PUBLIC;/,
  "does not hydrate later membership tags in the active recipient resolver" =>
    /CREATE OR REPLACE FUNCTION iam_private\.list_worker_silicon_webhook_recipients[\s\S]*FROM iam\.outbox_event_own_tag_memberships/
}
exact_silicon_topic_requirements.each do |description, pattern|
  issues << "exact Silicon topic migration #{description}" unless exact_silicon_topics.match?(pattern)
end
recipient_definition = exact_silicon_topics[
  /CREATE OR REPLACE FUNCTION iam_private\.list_worker_silicon_webhook_recipients.*?\$\$;/m
]
if recipient_definition&.match?(/JOIN iam\.membership_tags|JOIN iam\.organization_tags/)
  issues << "exact Silicon recipient resolver must not hydrate a later own-tag state"
end

governed_tag_changes = File.read("migrations/0015_governed_tag_changes.sql")
governed_tag_change_requirements = {
  "admits only active Carbon and Silicon requesters" =>
    /approval_requests_create[\s\S]*carbon_tag_change[\s\S]*silicon_tag_change[\s\S]*requester\.principal_kind IN \('carbon', 'silicon'\)/,
  "requires the affected Carbon and a tag manager for Carbon targets" =>
    /WHEN 'carbon_tag_change'[\s\S]*specific_membership[\s\S]*tag_target_membership_id[\s\S]*current_owner_or_admin[\s\S]*tags\.manage/,
  "requires a tag manager for Silicon targets" =>
    /WHEN 'silicon_tag_change'[\s\S]*current_owner_or_admin[\s\S]*tags\.manage/,
  "stores immutable before and proposed tag snapshots" =>
    /CREATE TABLE iam\.tag_change_requests[\s\S]*previous_tag_ids uuid\[\][\s\S]*proposed_tag_ids uuid\[\][\s\S]*tag_change_requests_immutable/,
  "keeps applied tag history append-only" =>
    /CREATE TABLE iam\.membership_tag_change_history[\s\S]*membership_tag_change_history_append_only[\s\S]*reject_immutable_history_mutation/,
  "compares the immutable baseline while holding the membership lock" =>
    /apply_approved_tag_change[\s\S]*FOR UPDATE OF membership[\s\S]*current_tag_ids <> payload\.previous_tag_ids/,
  "locks every proposed tag before checking active state" =>
    /payload\.proposed_tag_ids[\s\S]*ORDER BY tag\.id[\s\S]*FOR SHARE OF tag[\s\S]*tag\.status = 'active'/,
  "revalidates every approver requirement inside the definer" =>
    /apply_approved_tag_change[\s\S]*approval_requirements[\s\S]*specific_membership[\s\S]*current_owner_or_admin[\s\S]*has_organization_capability/,
  "applies tags, membership epoch, history, and approval state in one function" =>
    /apply_approved_tag_change[\s\S]*DELETE FROM iam\.membership_tags[\s\S]*INSERT INTO iam\.membership_tags[\s\S]*authz_epoch[\s\S]*INSERT INTO iam\.membership_tag_change_history[\s\S]*status = 'applied'/,
  "revokes Public execution of the tag apply entry point" =>
    /REVOKE ALL ON FUNCTION iam_private\.apply_approved_tag_change\(\s*uuid, uuid, bigint\s*\) FROM PUBLIC;/,
  "removes direct existing-membership tag writes" =>
    /DROP POLICY membership_tags_manage ON iam\.membership_tags/,
  "binds initial Silicon tags to rows inserted by the current transaction" =>
    /assign_initial_silicon_tags[\s\S]*membership\.xmin::text::bigint = pg_current_xact_id\(\)::text::bigint[\s\S]*silicon\.xmin::text::bigint = pg_current_xact_id\(\)::text::bigint/,
  "revokes Public execution of initial Silicon tag assignment" =>
    /REVOKE ALL ON FUNCTION iam_private\.assign_initial_silicon_tags\(\s*uuid, uuid, uuid, uuid\[\]\s*\) FROM PUBLIC;/
}
governed_tag_change_requirements.each do |description, pattern|
  issues << "governed tag-change migration #{description}" unless governed_tag_changes.match?(pattern)
end

organization_tag_write_source = %w[
  src/features/organizations/directory.rs
  src/features/organizations/governance.rs
  src/features/organizations/silicons.rs
].map { |path| File.read(path) }.join("\n")
if organization_tag_write_source.match?(/(?:INSERT INTO|DELETE FROM) iam\.membership_tags/)
  issues << "organization HTTP code must mediate membership-tag writes through fixed-path functions"
end

profile_timezones = File.read("migrations/0016_profile_timezones.sql")
profile_timezone_requirements = {
  "backfills both principal kinds to UTC without nullable time zones" =>
    /ALTER TABLE iam\.carbons[\s\S]*timezone_id text NOT NULL DEFAULT 'UTC'[\s\S]*ALTER TABLE iam\.silicons[\s\S]*timezone_id text NOT NULL DEFAULT 'UTC'/,
  "backfills legacy Silicon display names from immutable local handles" =>
    /UPDATE iam\.silicons[\s\S]*display_name = local_silicon_id[\s\S]*ALTER COLUMN display_name SET NOT NULL/,
  "validates persisted identifiers against the PostgreSQL TZDB catalog" =>
    /reject_unknown_profile_timezone[\s\S]*pg_catalog\.pg_timezone_names[\s\S]*carbons_validate_timezone[\s\S]*silicons_validate_timezone/,
  "revokes Public execution of the time-zone trigger" =>
    /REVOKE ALL ON FUNCTION iam_private\.reject_unknown_profile_timezone\(\) FROM PUBLIC;/,
  "forward-replaces signup with a required time-zone argument" =>
    /DROP FUNCTION iam_private\.complete_verified_signup\([\s\S]*CREATE FUNCTION iam_private\.complete_verified_signup\([\s\S]*p_timezone_id text[\s\S]*timezone_id[\s\S]*p_timezone_id/,
  "revokes Public execution of the replacement signup function" =>
    /REVOKE ALL ON FUNCTION iam_private\.complete_verified_signup\(\s*uuid, uuid, text, text, text, text, text, uuid, uuid\s*\) FROM PUBLIC;/
}
profile_timezone_requirements.each do |description, pattern|
  issues << "profile time-zone migration #{description}" unless profile_timezones.match?(pattern)
end

sso_activation = File.read("migrations/0017_sso_membership_activation_events.sql")
sso_activation_requirements = {
  "revalidates the callback correlation before exposing membership state" =>
    /lock_sso_membership_activation_state[\s\S]*is_valid_sso_callback_correlation/,
  "locks the correlated authorization transaction before the membership" =>
    /FOR UPDATE OF authorization_transaction, config, connection;[\s\S]*FOR UPDATE OF membership;/,
  "classifies creation, reactivation, and unchanged authentication explicitly" =>
    /activation_kind := CASE membership_record\.status[\s\S]*'unchanged'[\s\S]*'reactivated'[\s\S]*activation_kind := 'created'/,
  "revokes Public execution of the SSO activation lock" =>
    /REVOKE ALL ON FUNCTION iam_private\.lock_sso_membership_activation_state\([\s\S]*?\) FROM PUBLIC;/
}
sso_activation_requirements.each do |description, pattern|
  issues << "SSO activation migration #{description}" unless sso_activation.match?(pattern)
end

sso_scope_cleanup = File.read("migrations/0029_remove_sso_admission_policy.sql")
sso_scope_cleanup_requirements = {
  "drops policy-tag data before the retired policy table" =>
    /DROP TABLE iam\.sso_membership_policy_tags;[\s\S]*DROP TABLE iam\.sso_membership_policies;/,
  "revalidates active tenant-bound WorkOS authority at completion" =>
    /complete_sso_authorization[\s\S]*organization\.join_method = 'sso'[\s\S]*config\.platform_enabled[\s\S]*config\.status = 'active'[\s\S]*connection\.status = 'active'/,
  "admits or reactivates Carbons with conservative fixed defaults" =>
    /complete_sso_authorization[\s\S]*'member',[\s\S]*''[\s\S]*first_silicon_membership_id[\s\S]*NULL,[\s\S]*'internal',[\s\S]*'not_trusted'/,
  "removes stale tag and extra-Silicon assignments on reactivation" =>
    /DELETE FROM iam\.membership_tags[\s\S]*UPDATE iam\.extra_silicon_access_grants/,
  "keeps email invitations out of the SSO admission lock" =>
    /lock_sso_membership_activation_state[\s\S]*invitation_id := NULL;/,
  "revokes Public execution of the replacement completion function" =>
    /REVOKE ALL ON FUNCTION iam_private\.complete_sso_authorization\([\s\S]*?\) FROM PUBLIC;/
}
sso_scope_cleanup_requirements.each do |description, pattern|
  issues << "SSO scope cleanup migration #{description}" unless sso_scope_cleanup.match?(pattern)
end
if sso_scope_cleanup.match?(/p_provider_groups|p_normalized_email|organization_invitations/)
  issues << "SSO scope cleanup must not retain group/domain policy or invitation admission inputs"
end

sso_runtime_source = %w[
  src/features/sso/mod.rs
  src/features/sso/model.rs
  src/features/sso/configuration.rs
  src/features/sso/authorization.rs
  src/features/sso/validation.rs
  src/features/organizations/handlers.rs
].map { |path| File.read(path) }.join("\n")
if sso_runtime_source.match?(/sso\/policy|SsoAdmissionPolicy|sso_membership_policies|allow_policy_admission/)
  issues << "SSO runtime must not retain the retired admission-policy surface"
end

removal_scope = File.read("migrations/0018_membership_removal_event_scope.sql")
removal_scope_requirements = {
  "attests tenant and principal removal authority" =>
    /lock_membership_removal_event_scope[\s\S]*current_principal_id\(\)[\s\S]*current_organization_id\(\)[\s\S]*members\.remove[\s\S]*silicons\.remove/,
  "serializes Silicon hierarchy side effects with the removal transition" =>
    /lock_membership_removal_event_scope[\s\S]*pg_advisory_xact_lock[\s\S]*FOR UPDATE OF report[\s\S]*FOR UPDATE OF settings[\s\S]*FOR UPDATE OF access_grant/,
  "captures every relationship changed by Silicon removal" =>
    /reports_to_membership_id = p_membership_id[\s\S]*first_silicon_membership_id = p_membership_id[\s\S]*silicon_membership_id = p_membership_id/,
  "revokes Public execution of the removal-scope lock" =>
    /REVOKE ALL ON FUNCTION iam_private\.lock_membership_removal_event_scope\(uuid, uuid\) FROM PUBLIC;/
}
removal_scope_requirements.each do |description, pattern|
  issues << "membership removal scope migration #{description}" unless removal_scope.match?(pattern)
end

otp_cooldowns = File.read("migrations/0019_otp_attempt_cooldowns.sql")
otp_cooldown_requirements = {
  "lifts signup attempts to ten without rewriting history" =>
    /signup_otp_challenges_attempts[\s\S]*max_attempts BETWEEN 1 AND 10[\s\S]*failed_attempts BETWEEN 0 AND max_attempts/,
  "lifts login attempts to ten without rewriting history" =>
    /login_challenge_channels_attempts[\s\S]*max_attempts BETWEEN 1 AND 10[\s\S]*failed_attempts BETWEEN 0 AND max_attempts/,
  "lifts invitation attempts to ten without rewriting history" =>
    /invitation_verification_attempts[\s\S]*max_attempts BETWEEN 1 AND 10[\s\S]*failed_attempts BETWEEN 0 AND max_attempts/,
  "adds reusable cooldown state to verified-channel step-up" =>
    /ALTER TABLE iam\.step_up_challenges[\s\S]*ADD COLUMN cooldown_until timestamptz/,
  "lifts step-up attempts to ten" =>
    /step_up_challenges_attempts[\s\S]*max_attempts BETWEEN 1 AND 10[\s\S]*attempt_count BETWEEN 0 AND max_attempts/,
  "adopts ten attempts for every still-usable challenge kind" =>
    /UPDATE iam\.signup_otp_challenges[\s\S]*UPDATE iam\.login_challenge_channels[\s\S]*UPDATE iam\.invitation_verification_challenges[\s\S]*UPDATE iam\.step_up_challenges/
}
otp_cooldown_requirements.each do |description, pattern|
  issues << "OTP cooldown migration #{description}" unless otp_cooldowns.match?(pattern)
end
unless otp_cooldowns.scan(/ALTER COLUMN max_attempts SET DEFAULT 10/).length == 4
  issues << "OTP cooldown migration must set every shared challenge default to ten"
end

otp_runtime_sources = %w[
  src/features/authentication/signup.rs
  src/features/authentication/login.rs
  src/features/authentication/step_up.rs
  src/features/organizations/invitations.rs
].to_h { |path| [path, File.read(path)] }
otp_runtime_sources.each do |path, runtime_source|
  unless runtime_source.match?(/(?:failed_attempts|attempt_count) \+ 1 >= max_attempts[\s\S]*THEN 0[\s\S]*OTP_COOLDOWN_SECONDS/)
    issues << "#{path} must reset the exhausted attempt window and apply the shared cooldown"
  end
end
if otp_runtime_sources.values.any? { |runtime_source| runtime_source.match?(/interval '30 seconds'/) }
  issues << "OTP verification cooldowns must not retain the obsolete 30-second policy"
end

profile_webhook_projections = File.read(
  "migrations/0030_application_profile_webhook_projections.sql"
)
profile_webhook_projection_requirements = {
  "persists only encrypted, row-identified recipient projections" =>
    /CREATE TABLE iam\.application_webhook_event_projections[\s\S]*id uuid PRIMARY KEY[\s\S]*payload_ciphertext bytea NOT NULL[\s\S]*payload_nonce bytea NOT NULL[\s\S]*encryption_key_version smallint NOT NULL/,
  "bounds projection ciphertext size" =>
    /application_webhook_event_projections_ciphertext_length[\s\S]*BETWEEN 17 AND 1048592/,
  "derives effective disclosure from active consent and platform-approved scopes" =>
    /list_profile_webhook_authorization_scopes[\s\S]*oauth_consent_grant_scopes[\s\S]*application_approved_scopes[\s\S]*approved_scope\.revoked_at IS NULL[\s\S]*consent\.status = 'active'/,
  "locks authorization authority while the profile transaction captures it" =>
    /list_profile_webhook_authorization_scopes[\s\S]*FOR SHARE OF consent, consent_scope, approved_scope, application, application_principal/,
  "expands profile recipients only from captured projection rows" =>
    /list_worker_captured_application_webhook_recipients[\s\S]*FROM iam\.application_webhook_event_projections AS projection[\s\S]*event\.event_type = 'carbon\.updated\.v1'/,
  "retrieves a projection only through its exact event and Application binding" =>
    /get_worker_application_webhook_event_projection[\s\S]*projection\.outbox_event_id = p_outbox_event_id[\s\S]*projection\.application_id = p_application_id/,
  "purges old projections within the bounded webhook retention phase" =>
    /p_phase = 'webhook_delivery_attempts'[\s\S]*projection\.created_at < webhook_projection_cutoff[\s\S]*delivery\.status IN \('pending', 'processing'\)[\s\S]*LIMIT projection_limit/,
  "revokes Public execution of every projection boundary" =>
    /REVOKE ALL ON FUNCTION iam_private\.list_profile_webhook_authorization_scopes\(uuid\)[\s\S]*REVOKE ALL ON FUNCTION iam_private\.list_worker_captured_application_webhook_recipients\(uuid\)[\s\S]*REVOKE ALL ON FUNCTION iam_private\.get_worker_application_webhook_event_projection\(uuid, uuid\)/
}
profile_webhook_projection_requirements.each do |description, pattern|
  unless profile_webhook_projections.match?(pattern)
    issues << "Application profile webhook migration #{description}"
  end
end

organization_webhook_projections = File.read(
  "migrations/0031_application_organization_member_webhook_projections.sql"
)
organization_webhook_projection_requirements = {
  "captures the before/after authorization union at the mutation timestamp" =>
    /list_organization_member_webhook_authorizations[\s\S]*authorized_after boolean[\s\S]*consent\.revoked_at >= p_event_occurred_at[\s\S]*membership\.removed_at >= p_event_occurred_at/,
  "supports global and organization-bound consent for an affected principal" =>
    /consent\.subject_principal_id = membership\.principal_id[\s\S]*consent\.organization_id IS NULL[\s\S]*consent\.organization_id = membership\.organization_id/,
  "locks every row that supplies recipient authority" =>
    /FOR SHARE OF membership, subject_principal, consent, consent_scope,[\s\S]*approved_scope, application, application_principal/,
  "returns encrypted Carbon contact material rather than plaintext PII" =>
    /list_organization_member_webhook_projection_sources[\s\S]*email_ciphertext bytea[\s\S]*phone_ciphertext bytea[\s\S]*contact\.ciphertext/,
  "filters retired audit authority from complete role projections" =>
    /capability_grant\.capability <> 'audit\.read'/,
  "keeps the worker projection vocabulary closed" =>
    /event\.event_type IN \([\s\S]*'organization\.membership\.authorization_updated\.v1'[\s\S]*'organization\.silicon\.credential_rotated\.v1'[\s\S]*\)/,
  "does not admit the duplicate Silicon-only member profile event" =>
    /organization\.membership\.profile_updated\.v1/.then { |pattern| !organization_webhook_projections.match?(pattern) },
  "revokes Public execution from both new API boundaries" =>
    /REVOKE ALL ON FUNCTION iam_private\.list_organization_member_webhook_authorizations\([\s\S]*FROM PUBLIC;[\s\S]*REVOKE ALL ON FUNCTION iam_private\.list_organization_member_webhook_projection_sources\([\s\S]*FROM PUBLIC;/
}
organization_webhook_projection_requirements.each do |description, requirement|
  satisfied = requirement.is_a?(Regexp) ? organization_webhook_projections.match?(requirement) : requirement
  issues << "Application organization-member webhook migration #{description}" unless satisfied
end

organization_webhook_api = File.read("src/features/application_webhook_projections.rs")
unless organization_webhook_api.match?(
  /EncryptionContext::tenant\([\s\S]*ProtectedField::ApplicationWebhookEventPayload,[\s\S]*application_id,[\s\S]*projection_id[\s\S]*INSERT INTO iam\.application_webhook_event_projections/
)
  issues << "Application organization-member projections must use row- and recipient-bound authenticated encryption"
end
unless organization_webhook_api.match?(
  /if !authorization\.authorized_after[\s\S]*"authorization"[\s\S]*"removed"[\s\S]*return Ok/
)
  issues << "before-only Application authority must produce only a stable removal tombstone"
end

profile_webhook_api = File.read("src/api/me.rs")
unless profile_webhook_api.match?(
  /authorizations_before\s*=[\s\S]*profile_webhook_authorizations[\s\S]*authorizations_after\s*=[\s\S]*profile_webhook_authorizations[\s\S]*capture_profile_webhook_projections/
)
  issues << "Carbon profile updates must capture authorization immediately before and after mutation"
end
unless profile_webhook_api.match?(
  /ProtectedField::ApplicationWebhookEventPayload[\s\S]*projection_id[\s\S]*INSERT INTO iam\.application_webhook_event_projections/
)
  issues << "Carbon profile webhook projections must use row-bound authenticated encryption"
end

carbon_profile_silicon_events = File.read(
  "src/features/organizations/carbon_profile_events.rs"
)
carbon_profile_silicon_requirements = {
  "locks active membership and tag scope before profile mutation" =>
    /capture_carbon_profile_silicon_routes[\s\S]*FOR SHARE OF membership, organization[\s\S]*FOR SHARE OF assignment, tag/,
  "captures the complete current same-organization directory state" =>
    /directory::fetch_member\([\s\S]*membership\.membership_id/,
  "uses a distinct per-membership aggregate at the exact Carbon version" =>
    /aggregate_type: "organization_membership_profile"[\s\S]*aggregate_id: route\.membership_id[\s\S]*version: profile_version[\s\S]*event_ordinal: 1[\s\S]*event_type: EVENT_TYPE/,
  "routes profile changes only as member updates with the locked tag audience" =>
    /topics: vec!\[SiliconWebhookTopic::MemberUpdates\][\s\S]*affected_membership_id: Some\(route\.membership_id\)[\s\S]*affected_tag_ids: route\.affected_tag_ids\.clone\(\)[\s\S]*organization_wide: false/,
  "carries exact before, after, and current state without later delivery hydration" =>
    /"before": before,[\s\S]*"after": current,[\s\S]*"current": current/
}
carbon_profile_silicon_requirements.each do |description, pattern|
  issues << "Carbon profile Silicon webhook #{description}" unless carbon_profile_silicon_events.match?(pattern)
end

authorized_profile_projection = carbon_profile_silicon_events[
  /fn authorized_profile_state\(.*?\n\}/m
]
if authorized_profile_projection.nil?
  issues << "Carbon profile Silicon webhook must define a closed profile projection"
elsif authorized_profile_projection.match?(/"(?:email|phone|phone_number)"/)
  issues << "Carbon profile Silicon webhook projection must exclude contact fields"
end

unless profile_webhook_api.match?(
  /capture_carbon_profile_silicon_routes[\s\S]*UPDATE iam\.carbons[\s\S]*enqueue_carbon_profile_silicon_events/
)
  issues << "Carbon profile Silicon routes and projections must be captured in the profile mutation transaction"
end

silicon_routing_source = File.read("src/infrastructure/postgres/events.rs")
unless silicon_routing_source.match?(
  /silicon_webhook_routable\s*=\s*[\s\S]*silicon_webhook_routing\.as_ref\(\)[\s\S]*INSERT INTO iam\.outbox_events[\s\S]*silicon_webhook_routable[\s\S]*\.bind\(silicon_webhook_routable\)/
)
  issues << "outbox insertion must persist the explicit Some-routing marker, including empty Full-only topics"
end
unless silicon_routing_source.match?(/lock_silicon_webhook_own_tag_audience/) &&
       silicon_routing_source.match?(/INSERT INTO iam\.outbox_event_own_tag_memberships/)
  issues << "outbox insertion must persist the transaction-locked event-time own-tag audience"
end

application_webhook_worker = File.read("src/worker/webhook.rs")
unless application_webhook_worker.match?(
  /get_worker_application_webhook_event_projection[\s\S]*ProtectedField::ApplicationWebhookEventPayload[\s\S]*projection\.projection_id/
)
  issues << "Application webhook delivery must decrypt the captured row-bound projection"
end

worker_outbox = File.read("src/worker/outbox.rs")
unless worker_outbox.scan(/load_silicon_recipients\(transaction, event\.id\)/).length >= 2 &&
       worker_outbox.match?(/lock_silicon_webhook_delivery_scope/)
  issues << "Silicon webhook expansion must lock candidates and re-read current subscriptions"
end
unless worker_outbox.match?(
  /uses_captured_application_webhook_projection\(&event\.event_type\)[\s\S]*list_worker_captured_application_webhook_recipients[\s\S]*return Ok\(\(\)\)/
)
  issues << "captured Application events must not fall through to later-state recipient discovery"
end

provider_managed_digest = File.read("migrations/0048_provider_managed_phone_digest.sql")
provider_managed_digest_requirements = {
  "admits an absent local digest on all three challenge tables" =>
    /iam\.signup_otp_challenges[\s\S]*ALTER COLUMN code_digest DROP NOT NULL[\s\S]*iam\.login_challenge_channels[\s\S]*ALTER COLUMN code_digest DROP NOT NULL[\s\S]*iam\.step_up_challenges[\s\S]*ALTER COLUMN challenge_digest DROP NOT NULL/,
  "keeps a digest and its key version inseparable" =>
    /\(code_digest IS NULL\) = \(digest_key_version IS NULL\)[\s\S]*\(code_digest IS NULL\) = \(digest_key_version IS NULL\)[\s\S]*\(challenge_digest IS NULL\) = \(digest_key_version IS NULL\)/,
  "permits the absence only on a phone challenge" =>
    /code_digest IS NOT NULL OR contact_kind = 'phone'[\s\S]*code_digest IS NOT NULL OR contact_kind = 'phone'[\s\S]*challenge_digest IS NOT NULL OR channel = 'phone'/
}
provider_managed_digest_requirements.each do |description, pattern|
  issues << "provider-managed digest migration #{description}" unless provider_managed_digest.match?(pattern)
end

# The local-digest fallback must never be reachable for a challenge that stored
# no digest: each flow has to fail closed rather than treat absence as a match.
%w[signup login step_up].each do |flow|
  source = File.read("src/features/authentication/#{flow}.rs")
  unless source.match?(/#{flow}_otp_digest_missing/)
    issues << "#{flow} verification must fail closed when no local digest was stored"
  end
end

# Row-level security hides rows from an integrity assertion that runs as the
# invoking role, so every assertion trigger chain must run as the owner with a
# pinned search_path. Signup completion was impossible until this held.
row_security_assertions = File.read("migrations/0049_integrity_assertions_bypass_row_security.sql")
%w[
  assert_active_carbon_contacts
  assert_active_principal_subtype
  assert_approval_request_shape
  assert_exactly_one_organization_owner
  assert_outbox_event_affected_tag_tenant
  assert_outbox_event_own_tag_membership_tenant
  assert_silicon_webhook_subscription_topics
  check_approval_shape_from_payload
  check_approval_shape_from_request
  check_carbon_contacts_from_contact
  check_carbon_contacts_from_principal
  check_owner_after_membership_change
  check_owner_after_organization_change
  check_principal_subtype_from_principal
  check_principal_subtype_from_subtype
  prevent_silicon_reporting_cycle
].each do |name|
  unless row_security_assertions.match?(/ALTER FUNCTION iam_private\.#{name}\([^)]*\) SECURITY DEFINER;/)
    issues << "iam_private.#{name} must run as the owner so row-level security cannot hide the rows it asserts"
  end
  unless row_security_assertions.match?(
    /ALTER FUNCTION iam_private\.#{name}\([^)]*\)\s*\n?\s*SET search_path TO 'pg_catalog', 'iam';/
  )
    issues << "iam_private.#{name} is SECURITY DEFINER and must pin its search_path"
  end
  unless File.read("deploy/postgres/runtime-grants.sql").include?("'#{name}'")
    issues << "iam_private.#{name} must be classified in the runtime-grants definer allowlist"
  end
end

unless issues.empty?
  issues.each { |issue| warn issue }
  exit 1
end

puts "Validated #{security_definer_count} fixed-path, PUBLIC-revoked SECURITY DEFINER functions."
