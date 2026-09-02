#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

HTTP_METHODS = %w[get put post delete options head patch trace].freeze
ROUTE_START = /\.route\(\s*"([^"]+)"\s*,/m

def route_methods(source, body_start)
  depth = 1
  quoted = false
  escaped = false
  cursor = body_start

  while cursor < source.length && depth.positive?
    character = source[cursor]
    if quoted
      if escaped
        escaped = false
      elsif character == "\\"
        escaped = true
      elsif character == '"'
        quoted = false
      end
    elsif character == '"'
      quoted = true
    elsif character == "("
      depth += 1
    elsif character == ")"
      depth -= 1
    end
    cursor += 1
  end

  raise "unclosed Axum route call" if depth.positive?

  source[body_start...(cursor - 1)]
    .scan(/(?:\b|\.)(get|put|post|delete|options|head|patch|trace)\s*\(/)
    .flatten
    .uniq
end

def extract_routes(path)
  source = File.read(path)
  routes = {}
  source.to_enum(:scan, ROUTE_START).each do
    match = Regexp.last_match
    route = match[1]
    methods = route_methods(source, match.end(0))
    raise "#{path}: duplicate route #{route}" if routes.key?(route)

    routes[route] = methods
  end
  routes
end

document = YAML.safe_load(File.read("openapi.yaml"), aliases: true)
unless document.fetch("openapi").start_with?("3.")
  raise "OpenAPI 3 document is required"
end

expected = document.fetch("paths").each_with_object({}) do |(path, path_item), routes|
  routes[path] = HTTP_METHODS.select { |method| path_item.key?(method) }
end

operation_ids = document.fetch("paths").values.flat_map do |path_item|
  HTTP_METHODS.map { |method| path_item.dig(method, "operationId") }.compact
end
duplicate_operation_ids = operation_ids
  .group_by(&:itself)
  .select { |_operation_id, values| values.length > 1 }
  .keys
unless duplicate_operation_ids.empty?
  raise "duplicate operationId values: #{duplicate_operation_ids.join(", ")}"
end

idempotency_parameter = "#/components/parameters/IdempotencyKey"
replay_header = "Idempotency-Replayed"
idempotent_responses_missing_replay_header = []
document.fetch("paths").each do |path, path_item|
  HTTP_METHODS.each do |method|
    operation = path_item[method]
    next unless operation

    parameters = Array(path_item["parameters"]) + Array(operation["parameters"])
    next unless parameters.any? { |parameter| parameter["$ref"] == idempotency_parameter }

    operation.fetch("responses").each do |status, response|
      next unless status.match?(/\A[23]\d\d\z/)

      if response["$ref"]
        response_name = response.fetch("$ref").delete_prefix("#/components/responses/")
        response = document.dig("components", "responses", response_name)
        raise "unknown response reference for #{method.upcase} #{path}: #{response_name}" unless response
      end
      next if response.fetch("headers", {}).key?(replay_header)

      idempotent_responses_missing_replay_header << "#{method.upcase} #{path} #{status}"
    end
  end
end
unless idempotent_responses_missing_replay_header.empty?
  raise "idempotent success responses missing #{replay_header}: " \
    "#{idempotent_responses_missing_replay_header.join(", ")}"
end

# The HTML surfaces in src/web are deliberately outside the JSON contract:
# /admin is an interface and /docs/api is a document, and neither belongs in
# openapi.yaml. That exemption is only safe while it stays narrow, so it is
# policed rather than assumed — every route declared there must sit under one
# of these prefixes, and none of them may appear in the specification.
WEB_ROUTER = "src/web/mod.rs"
WEB_ALLOWED_PREFIXES = %w[/admin /docs /_static /openapi.yaml].freeze

if File.exist?(WEB_ROUTER)
  web_routes = extract_routes(WEB_ROUTER)
  misplaced = web_routes.keys.reject do |route|
    WEB_ALLOWED_PREFIXES.any? { |prefix| route == prefix || route.start_with?("#{prefix}/") }
  end
  unless misplaced.empty?
    misplaced.each do |route|
      warn "#{WEB_ROUTER}: #{route} is outside the HTML surface prefixes " \
        "(#{WEB_ALLOWED_PREFIXES.join(", ")})"
    end
    warn "Contract routes belong in src/api/mod.rs or a feature router, and in openapi.yaml."
    exit 1
  end

  documented = web_routes.keys.select { |route| document.fetch("paths").key?(route) }
  unless documented.empty?
    documented.each do |route|
      warn "#{WEB_ROUTER}: #{route} is an HTML surface but is declared in openapi.yaml"
    end
    exit 1
  end
end

router_files = Dir["src/features/*/mod.rs"].sort + ["src/api/mod.rs"]
actual = router_files.each_with_object({}) do |path, routes|
  extract_routes(path).each do |route, methods|
    raise "duplicate Axum route #{route}" if routes.key?(route)

    routes[route] = methods
  end
end

expected_operations = expected.flat_map do |path, methods|
  methods.map { |method| [path, method] }
end
actual_operations = actual.flat_map do |path, methods|
  methods.map { |method| [path, method] }
end

missing = expected_operations - actual_operations
extra = actual_operations - expected_operations

root_router = File.read("src/api/mod.rs")
unmerged_features = Dir["src/features/*/mod.rs"].sort.map do |path|
  feature = File.basename(File.dirname(path))
  feature if File.read(path).include?("fn router()") &&
    !root_router.include?(".merge(crate::features::#{feature}::router())")
end.compact

unless missing.empty? && extra.empty? && unmerged_features.empty?
  missing.each { |path, method| warn "missing route: #{method.upcase} #{path}" }
  extra.each { |path, method| warn "undocumented route: #{method.upcase} #{path}" }
  unmerged_features.each { |feature| warn "feature router is not merged: #{feature}" }
  exit 1
end

web_route_count = File.exist?(WEB_ROUTER) ? extract_routes(WEB_ROUTER).length : 0
puts "OpenAPI and Axum agree on #{expected.length} paths and #{expected_operations.length} " \
  "operations; idempotent success responses expose replay state; " \
  "#{web_route_count} HTML surface routes are correctly outside the contract."
