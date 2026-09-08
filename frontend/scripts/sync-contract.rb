# Usage: ruby scripts/sync-contract.rb ../docs/openapi.yaml
# Copies public schemas only; no credentials or runtime data.
require 'yaml'
require 'json'
document = YAML.load_file(ARGV.fetch(0))
File.write(File.join(__dir__, '../src/contracts.json'), JSON.pretty_generate(document.fetch('components').fetch('schemas')) + "\n")
