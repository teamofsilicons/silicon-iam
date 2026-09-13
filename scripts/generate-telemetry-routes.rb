#!/usr/bin/env ruby
# Derive safe route templates from the public contract; never record resource IDs.
require 'json'
root = File.expand_path('..', __dir__)
paths = File.read("#{root}/docs/openapi.yaml").scan(/^  (\/[^\s]+):$/).flatten
paths += %w[/api/config /api/session /api/web/telemetry /api/telemetry/settings /healthz /readyz /api/version]
body = JSON.pretty_generate(paths.uniq.sort) + "\n"
%w[crates/client/src/telemetry_routes.json frontend/src/telemetry-routes.json].each do |file|
  path = "#{root}/#{file}"
  if ARGV.include?('--check')
    abort "Telemetry route templates are stale: #{file}" unless File.exist?(path) && File.read(path) == body
  else
    File.write(path, body)
  end
end
puts "Telemetry templates match #{paths.uniq.length} routes."
