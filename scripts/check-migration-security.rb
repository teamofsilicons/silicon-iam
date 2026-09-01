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
if File.exist?(retention_path)
  retention = File.read(retention_path)
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
    issues << "retention migration #{description}" unless retention.match?(pattern)
  end
  if retention.match?(/\b(?:current_setting|set_config)\s*\(/i)
    issues << "retention migration trusts a caller-settable custom GUC"
  end

  declared_phase_source = retention[
    /IF p_phase IS NULL OR p_phase NOT IN \((.*?)\) THEN/m, 1
  ]
  declared_phases = declared_phase_source&.scan(/'([a-z0-9_]+)'/)&.flatten
  branch_phases = retention.scan(/(?:IF|ELSIF) p_phase = '([a-z0-9_]+)' THEN/).flatten
  worker_source = File.read("src/worker/maintenance.rs")
  worker_phase_source = worker_source[/const RETENTION_PHASES:.*?= \[(.*?)\];/m, 1]
  worker_phases = worker_phase_source&.scan(/"([a-z0-9_]+)"/)&.flatten
  unless declared_phases&.length == 21 && declared_phases == branch_phases &&
         declared_phases == worker_phases
    issues << "retention migration and worker must share one exact 21-phase vocabulary"
  end
end

key_rotation = File.read("migrations/0010_runtime_key_rotation.sql")
unless key_rotation.match?(
  /reconcile_worker_contact_aead_keyring[\s\S]*pg_auth_members[\s\S]*PERFORM iam_private\.reconcile_runtime_keyring\(\s*'contact_aead'/
)
  issues << "worker keyring wrapper must attest the login and fix purpose to contact_aead"
end

account_deletion = File.read("migrations/0007_auth_account_and_passkeys.sql")
unless account_deletion.match?(
  /run_worker_account_deletion_finalization[\s\S]*SET CONSTRAINTS ALL IMMEDIATE;[\s\S]*REVOKE ALL ON FUNCTION iam_private\.run_worker_account_deletion_finalization/
)
  issues << "account-deletion finalization must discharge deferred invariants inside its definer"
end

silicon_webhooks = File.read("migrations/0014_configurable_silicon_webhooks.sql")
silicon_webhook_requirements = {
  "keeps routing topics outside the webhook payload" =>
    /CREATE TABLE iam\.outbox_event_topics[\s\S]*control routing only and are never serialized into webhook payloads/,
  "keeps affected-tag routing data outside the webhook payload" =>
    /CREATE TABLE iam\.outbox_event_affected_tags[\s\S]*never enter webhook payloads/,
  "fails closed for organization-wide own-tag subscriptions" =>
    /subscription\.own_tags_only[\s\S]*NOT event\.organization_wide[\s\S]*active_tag\.status = 'active'/,
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
    /REVOKE ALL ON FUNCTION iam_private\.get_worker_silicon_webhook_material\(uuid, uuid\) FROM PUBLIC;/
}
silicon_webhook_requirements.each do |description, pattern|
  issues << "configurable Silicon webhook migration #{description}" unless silicon_webhooks.match?(pattern)
end

unless issues.empty?
  issues.each { |issue| warn issue }
  exit 1
end

puts "Validated #{security_definer_count} fixed-path, PUBLIC-revoked SECURITY DEFINER functions."
