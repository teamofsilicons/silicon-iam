#!/usr/bin/env ruby
# frozen_string_literal: true

require "set"

RUNTIME_GRANTS_PATH = "deploy/postgres/runtime-grants.sql"
MIGRATION_GLOB = "migrations/*.sql"
API_BINARY_PATH = "src/bin/iam_api.rs"
WORKER_BINARY_PATH = "src/bin/iam_worker.rs"

# These files contain database setup or live-database tests, not production API
# queries. Inline `mod tests` modules are removed separately below.
EXCLUDED_TEST_PATHS = %w[
  src/features/applications/live_tests.rs
  src/infrastructure/postgres/key_rotation_tests.rs
].freeze

# The API capability derivation intentionally excludes every non-API process.
# Each process receives its own database role and independently reviewed grants.
EXCLUDED_NON_API_BINARY_PATHS = %w[
  src/bin/iam_activate_key_version.rs
  src/bin/iam_bootstrap_admin.rs
  src/bin/iam_migrate.rs
  src/bin/iam_worker.rs
].freeze

# These tables are not queried directly by the API. They are read by the named
# invoker-rights helpers during deferred constraint-trigger execution, so the
# API role still requires SELECT on them when a transaction reaches commit.
TRIGGER_ONLY_SELECT_EXCEPTIONS = {
  "platform_role_grants" => "assert_platform_administrator_present",
  "service_principals" => "assert_active_principal_subtype"
}.freeze

EXPECTED_DELETE_TABLES = Set.new(%w[
  application_requested_scopes
  idempotency_records
  oauth_consent_grant_scopes
  silicon_webhook_subscription_extra_tags
  silicon_webhook_subscription_topics
  silicon_webhook_subscriptions
]).freeze

# These relations deliberately stay outside the API table capability manifest.
# Access must remain mediated by narrow fixed-path functions or another process.
CRITICAL_DENIED_TABLES = Set.new(%w[
  contact_blind_indexes
  cryptographic_key_versions
  external_webhook_receipts
  ownership_transfer_requests
  platform_capability_catalog
  platform_role_capabilities
  platform_role_catalog
  runtime_key_activations
  silicon_hooks
  sso_identities
  webhook_delivery_attempts
]).freeze

DML_VERBS = %w[SELECT INSERT UPDATE DELETE].freeze

def strip_test_modules(path)
  source = File.read(path)
  source = source.gsub(
    /^[ \t]*#\[cfg\(test\)\][ \t]*\r?\n[ \t]*mod[ \t]+[a-zA-Z0-9_]+[ \t]*;[ \t]*$/,
    ""
  )
  source = source.sub(
    /^[ \t]*#\[cfg\(test\)\][ \t]*\r?\n[ \t]*mod[ \t]+tests[ \t]*\{.*\z/m,
    ""
  )
  return source unless source.match?(/#\[cfg\(test\)\]/)

  raise "#{path}: unsupported cfg(test) shape; update the grant checker instead of scanning tests"
end

def production_api_paths
  all_paths = Dir["src/**/*.rs"].sort
  all_paths.reject do |path|
    path.start_with?("src/worker/") ||
      EXCLUDED_TEST_PATHS.include?(path) ||
      (path.start_with?("src/bin/") && path != API_BINARY_PATH)
  end
end

def production_worker_paths
  Dir["src/worker/**/*.rs"].sort + [WORKER_BINARY_PATH]
end

def combined_source(paths)
  paths.map { |path| "// source: #{path}\n#{strip_test_modules(path)}" }.join("\n")
end

def extract_manifest(source, name, issues)
  body = source[
    /\b#{Regexp.escape(name)}\s+text\[\]\s*:=\s*ARRAY\[(.*?)\];/m,
    1
  ]
  if body.nil?
    issues << "runtime grants are missing the #{name} manifest"
    return Set.new
  end

  entries = body.scan(/'([a-z0-9_]+)'/).flatten
  duplicates = entries.group_by(&:itself)
    .select { |_entry, occurrences| occurrences.length > 1 }
    .keys
    .sort
  unless duplicates.empty?
    issues << "#{name} contains duplicate entries: #{duplicates.join(', ')}"
  end
  entries.to_set
end

def rust_string_bodies(source)
  raw_ranges = []
  bodies = []
  raw_pattern = /\b(?:br|r)(?<hashes>\#*)"(?<body>.*?)"\k<hashes>/m
  source.to_enum(:scan, raw_pattern).each do
    match = Regexp.last_match
    raw_ranges << (match.begin(0)...match.end(0))
    bodies << match[:body]
  end

  without_raw_strings = source.dup
  raw_ranges.reverse_each do |range|
    without_raw_strings[range] = " " * (range.end - range.begin)
  end
  without_raw_strings.scan(/"((?:\\.|[^"\\])*)"/m) do |match|
    bodies << match.first
  end
  bodies
end

def upsert_update_targets(source)
  rust_string_bodies(source).each_with_object(Set.new) do |body, targets|
    inserts = []
    body.to_enum(:scan, /\bINSERT\s+INTO\s+iam\.([a-z0-9_]+)\b/i).each do
      match = Regexp.last_match
      inserts << [match[1].downcase, match.begin(0)]
    end
    inserts.each_with_index do |(table_name, start_at), index|
      finish_at = inserts.fetch(index + 1, [nil, body.length])[1]
      statement = body[start_at...finish_at]
      if statement.match?(/\bON\s+CONFLICT\b.*?\bDO\s+UPDATE\b/im)
        targets << table_name
      end
    end
  end
end

def derive_operations(source, table_names, issues, label)
  known_tables = table_names.to_set
  referenced_tables = source.scan(/\biam\.([a-z0-9_]+)\b/i)
    .flatten
    .map(&:downcase)
    .to_set
    .intersection(known_tables)

  inserts = source.scan(/\bINSERT\s+INTO\s+iam\.([a-z0-9_]+)\b/i)
    .flatten
    .map(&:downcase)
    .to_set
  updates = source.scan(/\bUPDATE\s+iam\.([a-z0-9_]+)\b/i)
    .flatten
    .map(&:downcase)
    .to_set
    .union(upsert_update_targets(source))
  deletes = source.scan(/\bDELETE\s+FROM\s+iam\.([a-z0-9_]+)\b/i)
    .flatten
    .map(&:downcase)
    .to_set

  unknown_write_targets = inserts.union(updates).union(deletes) - known_tables
  unless unknown_write_targets.empty?
    issues << "#{label} SQL writes unknown IAM tables: #{unknown_write_targets.to_a.sort.join(', ')}"
  end

  {
    "SELECT" => referenced_tables,
    "INSERT" => inserts.intersection(known_tables),
    "UPDATE" => updates.intersection(known_tables),
    "DELETE" => deletes.intersection(known_tables)
  }
end

def compare_capability(label, required, granted, issues)
  missing = required - granted
  excess = granted - required
  unless missing.empty?
    issues << "#{label} is missing: #{missing.to_a.sort.join(', ')}"
  end
  unless excess.empty?
    issues << "#{label} is excessive or stale: #{excess.to_a.sort.join(', ')}"
  end
end

def worker_table_grants(source, issues)
  grants = Hash.new { |tables, table_name| tables[table_name] = Set.new }
  grant_counts = Hash.new(0)
  pattern = /\bGRANT\s+((?:SELECT|INSERT|UPDATE|DELETE)(?:\s*,\s*(?:SELECT|INSERT|UPDATE|DELETE))*)\s+ON\s+(?:TABLE\s+)?iam\.([a-z0-9_]+)\s+TO\s+silicon_iam_worker\s*;/im
  source.scan(pattern) do |verb_list, table_name|
    normalized_table_name = table_name.downcase
    grant_counts[normalized_table_name] += 1
    verb_list.upcase.split(/\s*,\s*/).each do |verb|
      grants[normalized_table_name] << verb
    end
  end
  duplicate_grants = grant_counts.select { |_table_name, count| count > 1 }.keys.sort
  unless duplicate_grants.empty?
    issues << "worker table grants contain duplicate statements: #{duplicate_grants.join(', ')}"
  end
  grants
end

def check_trigger_only_exceptions(migration_source, direct_selects, issues)
  function_starts = []
  function_pattern = /CREATE(?: OR REPLACE)? FUNCTION iam_private\.([a-z0-9_]+)\s*\(/
  migration_source.to_enum(:scan, function_pattern).each do
    match = Regexp.last_match
    function_starts << [match[1], match.begin(0)]
  end
  definitions = function_starts.each_with_index.to_h do |(name, start_at), index|
    finish_at = function_starts.fetch(index + 1, [nil, migration_source.length])[1]
    [name, migration_source[start_at...finish_at]]
  end

  TRIGGER_ONLY_SELECT_EXCEPTIONS.each do |table_name, helper_name|
    if direct_selects.include?(table_name)
      issues << "#{table_name} is now read directly; remove its trigger-only exception"
    end
    definition = definitions[helper_name]
    if definition.nil?
      issues << "trigger-only helper iam_private.#{helper_name} no longer exists"
      next
    end
    unless definition.match?(/\biam\.#{Regexp.escape(table_name)}\b/)
      issues << "iam_private.#{helper_name} no longer reads iam.#{table_name}"
    end
    if definition.match?(/\bSECURITY\s+DEFINER\b/i)
      issues << "iam_private.#{helper_name} became SECURITY DEFINER; re-evaluate its SELECT exception"
    end
  end
end

def check_shared_migration_table_grants(source, issues)
  %w[silicon_iam_api silicon_iam_worker].each do |role|
    pattern = /\bGRANT\s+((?:SELECT|INSERT|UPDATE|DELETE)(?:\s*,\s*(?:SELECT|INSERT|UPDATE|DELETE))*)\s+ON\s+(?:TABLE\s+)?public\._sqlx_migrations\s+TO\s+#{role}\s*;/i
    granted_verbs = source.scan(pattern).flatten.flat_map { |verbs| verbs.upcase.split(/\s*,\s*/) }.to_set
    compare_capability(
      "#{role} public._sqlx_migrations privileges",
      Set.new(["SELECT"]),
      granted_verbs,
      issues
    )
  end
end

def check_keyring_function_boundary(source, issues)
  api_functions = extract_manifest(source, "api_function_names", issues)
  non_api_definers = extract_manifest(source, "non_api_definer_names", issues)
  worker_functions = extract_manifest(source, "worker_function_names", issues)

  unless api_functions.include?("reconcile_runtime_keyring")
    issues << "API function manifest is missing reconcile_runtime_keyring"
  end
  if api_functions.include?("reconcile_worker_contact_aead_keyring")
    issues << "API function manifest must not include the worker-only keyring reconciler"
  end
  unless worker_functions.include?("reconcile_worker_contact_aead_keyring")
    issues << "worker function manifest is missing reconcile_worker_contact_aead_keyring"
  end
  if worker_functions.include?("reconcile_runtime_keyring")
    issues << "worker function manifest must not include the generic keyring reconciler"
  end
  unless non_api_definers.include?("reconcile_worker_contact_aead_keyring")
    issues << "worker-only keyring reconciler is missing from non_api_definer_names"
  end
end

def check_sso_connection_event_boundary(migration_source, api_source, grant_source, issues)
  api_functions = extract_manifest(grant_source, "api_function_names", issues)
  unless api_functions.include?("apply_workos_connection_event")
    issues << "API function manifest is missing apply_workos_connection_event"
  end

  unless migration_source.match?(
    /ALTER TABLE iam\.sso_connections[\s\S]*ADD COLUMN version bigint NOT NULL DEFAULT 1/
  )
    issues << "sso_connections are missing an independently persisted event version"
  end
  unless migration_source.match?(
    /ADD CONSTRAINT sso_connections_positive_version CHECK \(version > 0\)/
  )
    issues << "sso_connections event versions are missing a positive-value constraint"
  end
  unless migration_source.match?(
    /CREATE TRIGGER sso_connections_bump_aggregate_version[\s\S]*BEFORE UPDATE ON iam\.sso_connections[\s\S]*iam_private\.bump_aggregate_version\(\)/
  )
    issues << "sso_connections are missing the aggregate-version bump trigger"
  end
  unless migration_source.match?(
    /DROP FUNCTION iam_private\.apply_workos_connection_event\([\s\S]*CREATE FUNCTION iam_private\.apply_workos_connection_event\([\s\S]*RETURNS TABLE \([\s\S]*connection_version bigint[\s\S]*SECURITY DEFINER/
  )
    issues << "WorkOS connection mutation boundary must return per-connection versions"
  end
  unless api_source.match?(
    /aggregate_type: "sso_connection"[\s\S]*aggregate_id: connection_id[\s\S]*aggregate_version: connection_version/
  )
    issues << "WorkOS connection events must use their independently versioned aggregate"
  end
end

issues = []
required_paths = [
  RUNTIME_GRANTS_PATH,
  API_BINARY_PATH,
  WORKER_BINARY_PATH,
  *EXCLUDED_TEST_PATHS,
  *EXCLUDED_NON_API_BINARY_PATHS
]
required_paths.each do |path|
  issues << "expected path is missing: #{path}" unless File.file?(path)
end

migration_paths = Dir[MIGRATION_GLOB].sort
issues << "no SQL migrations found" if migration_paths.empty?

unless issues.empty?
  issues.each { |issue| warn issue }
  exit 1
end

runtime_grants = File.read(RUNTIME_GRANTS_PATH)
migration_source = migration_paths.map { |path| File.read(path) }.join("\n")
all_table_names = migration_source.scan(
  /\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?iam\.([a-z0-9_]+)\b/i
).flatten.map(&:downcase).to_set
partition_table_names = migration_source.scan(
  /\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?iam\.([a-z0-9_]+)\s+PARTITION\s+OF\s+iam\./i
).flatten.map(&:downcase).to_set
migration_source.scan(
  /\bALTER\s+TABLE\s+iam\.([a-z0-9_]+)\s+RENAME\s+TO\s+([a-z0-9_]+)\b/i
).each do |old_name, new_name|
  old_name = old_name.downcase
  new_name = new_name.downcase
  all_table_names.delete(old_name)
  all_table_names.add(new_name)
  if partition_table_names.delete?(old_name)
    partition_table_names.add(new_name)
  end
end
migration_source.scan(/\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?iam\.([a-z0-9_]+)\b/i)
  .flatten
  .each do |table_name|
    all_table_names.delete(table_name.downcase)
    partition_table_names.delete(table_name.downcase)
  end
base_table_names = all_table_names - partition_table_names

api_paths = production_api_paths
worker_paths = production_worker_paths
api_source = combined_source(api_paths)
worker_source = combined_source(worker_paths)
api_operations = derive_operations(api_source, all_table_names, issues, "API")
worker_operations = derive_operations(worker_source, all_table_names, issues, "worker")

api_manifests = {
  "SELECT" => extract_manifest(runtime_grants, "select_table_names", issues),
  "INSERT" => extract_manifest(runtime_grants, "insert_table_names", issues),
  "UPDATE" => extract_manifest(runtime_grants, "update_table_names", issues),
  "DELETE" => extract_manifest(runtime_grants, "delete_table_names", issues)
}
denied_tables = extract_manifest(runtime_grants, "denied_table_names", issues)

check_trigger_only_exceptions(migration_source, api_operations.fetch("SELECT"), issues)
required_api_selects = api_operations.fetch("SELECT")
  .union(TRIGGER_ONLY_SELECT_EXCEPTIONS.keys.to_set)
compare_capability("API SELECT manifest", required_api_selects, api_manifests.fetch("SELECT"), issues)
%w[INSERT UPDATE DELETE].each do |verb|
  compare_capability(
    "API #{verb} manifest",
    api_operations.fetch(verb),
    api_manifests.fetch(verb),
    issues
  )
end

compare_capability("API DELETE critical allowlist", EXPECTED_DELETE_TABLES, api_manifests.fetch("DELETE"), issues)
compare_capability("API critical deny manifest", CRITICAL_DENIED_TABLES, denied_tables, issues)

classified_tables = api_manifests.fetch("SELECT").union(denied_tables)
compare_capability("API base-table classification", base_table_names, classified_tables, issues)
partition_grants = partition_table_names.intersection(
  api_manifests.values.reduce(Set.new, :union).union(denied_tables)
)
unless partition_grants.empty?
  issues << "partition tables must not be granted directly: #{partition_grants.to_a.sort.join(', ')}"
end

all_api_capabilities = api_manifests.values.reduce(Set.new, :union)
deny_overlap = denied_tables.intersection(all_api_capabilities)
unless deny_overlap.empty?
  issues << "API capability and deny manifests overlap: #{deny_overlap.to_a.sort.join(', ')}"
end
%w[INSERT UPDATE DELETE].each do |verb|
  without_select = api_manifests.fetch(verb) - api_manifests.fetch("SELECT")
  unless without_select.empty?
    issues << "API #{verb} tables without SELECT: #{without_select.to_a.sort.join(', ')}"
  end
end

granted_worker_operations = worker_table_grants(runtime_grants, issues)
required_worker_tables = DML_VERBS.each_with_object({}) do |verb, tables|
  worker_operations.fetch(verb).each do |table_name|
    tables[table_name] ||= Set.new
    tables[table_name] << verb
  end
end
worker_table_names = required_worker_tables.keys.to_set.union(granted_worker_operations.keys.to_set)
worker_table_names.each do |table_name|
  compare_capability(
    "worker iam.#{table_name} privileges",
    required_worker_tables.fetch(table_name, Set.new),
    granted_worker_operations.fetch(table_name, Set.new),
    issues
  )
end
unless worker_operations.fetch("DELETE").empty?
  issues << "worker production SQL must not directly delete IAM rows"
end

check_shared_migration_table_grants(runtime_grants, issues)
check_keyring_function_boundary(runtime_grants, issues)
check_sso_connection_event_boundary(migration_source, api_source, runtime_grants, issues)

unless issues.empty?
  issues.each { |issue| warn issue }
  exit 1
end

puts format(
  "Validated runtime grants: API %<select>d SELECT / %<insert>d INSERT / " \
  "%<update>d UPDATE / %<delete>d DELETE tables; worker %<worker>d IAM tables.",
  select: api_manifests.fetch("SELECT").length,
  insert: api_manifests.fetch("INSERT").length,
  update: api_manifests.fetch("UPDATE").length,
  delete: api_manifests.fetch("DELETE").length,
  worker: granted_worker_operations.length
)
