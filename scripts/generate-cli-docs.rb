#!/usr/bin/env ruby
# frozen_string_literal: true

# Package-safe, offline manuals for the installed CLI. Canonical documents stay
# under docs/; publishing never needs Ruby or paths outside the CLI crate.
# Run after documentation edits; pass --check in verification/CI to detect drift.

require "cgi"
require "digest"
require "fileutils"
require "rexml/document"

ROOT = File.expand_path("..", __dir__)
MANIFEST = "crates/cli/src/manual_data.rs"
ASSETS = "crates/cli/src/manual_assets"

CATALOG = [
  ["overview", "Integration documentation index", "docs/README.md", %w[index]],
  ["cli", "Complete CLI guide and command reference", "docs/cli/README.md", %w[commands]],
  ["storage", "CLI credential storage and concurrent sessions", "docs/cli/storage.md", %w[cli/storage]],
  ["api", "Complete HTTP API reference", "docs/API_DOCS.md", %w[http]],
  ["openapi", "Normative OpenAPI wire contract", "docs/openapi.yaml", %w[schema]],
  ["client", "Complete Rust client guide", "docs/client/README.md", %w[sdk rust]],
  ["api/overview", "API overview", "docs/api/overview.html", []],
  ["api/conventions", "HTTP conventions, versions and pagination", "docs/api/conventions.html", %w[conventions]],
  ["api/authentication", "Authentication, SLTs and credentials", "docs/api/authentication.html", %w[authentication login]],
  ["api/carbons", "Carbon accounts and sessions", "docs/api/carbons.html", %w[carbons]],
  ["api/organizations", "Organizations, membership and SSO", "docs/api/organizations.html", %w[organizations members sso]],
  ["api/silicons", "Silicon identities and credentials", "docs/api/silicons.html", %w[silicons]],
  ["api/governance", "Tags, trust and approvals", "docs/api/governance.html", %w[governance tags trust approvals]],
  ["api/applications", "Applications, registration and current authorization", "docs/api/applications.html", %w[applications apps authorization]],
  ["api/obo", "On-behalf-of proofs and delegated authority", "docs/api/obo.html", %w[obo]],
  ["api/webhooks", "Signed webhook delivery and verification", "docs/api/webhooks.html", %w[webhooks]],
  ["api/testing-environments", "Testing environments and isolation", "docs/api/testing-environments.html", %w[testing environments]],
  ["api/errors", "API error codes and recovery", "docs/api/errors.html", %w[errors]],
  ["client/overview", "Rust client capabilities and design", "docs/client/overview.html", []],
  ["client/connecting", "Configure the Rust client and credentials", "docs/client/connecting.html", %w[connecting]],
  ["client/login", "Application login using short-lived tokens", "docs/client/login.html", []],
  ["client/tokens", "Application tokens and authorization snapshots", "docs/client/tokens.html", %w[tokens]],
  ["client/obo", "Rust client OBO signing and verification", "docs/client/obo.html", []],
  ["client/webhooks", "Rust client webhook verification", "docs/client/webhooks.html", []],
  ["client/testing-environments", "Rust client testing environment workflow", "docs/client/testing-environments.html", []],
  ["client/errors", "Rust client errors and safe retry policy", "docs/client/errors.html", []],
  ["client/updates", "Client and CLI automatic updates", "docs/client/updates.html", %w[updates]]
].freeze

# The HTML guides are controlled fragments rather than complete browser pages.
# Parse their structure instead of stripping tags, preserving code whitespace,
# table columns, links and the distinction between inline and fenced code.
def markdown(node, preformatted = false)
  return preformatted ? node.value : node.value.gsub(/\s+/, " ") if node.is_a?(REXML::Text)
  return "" unless node.is_a?(REXML::Element)

  children = -> { node.children.map { |child| markdown(child, preformatted) }.join }
  case node.name
  when "p", "blockquote", "div"
    "\n\n#{children.call.strip}\n\n"
  when /\Ah([1-6])\z/
    "\n\n#{'#' * Regexp.last_match(1).to_i} #{children.call.strip}\n\n"
  when "pre"
    code = node.children.map { |child| markdown(child, true) }.join.strip
    fence = "`" * [3, code.scan(/`+/).map(&:length).max.to_i + 1].max
    "\n\n#{fence}\n#{code}\n#{fence}\n\n"
  when "code"
    content = children.call
    return content if preformatted

    fence = content.include?("`") ? "``" : "`"
    "#{fence}#{content}#{fence}"
  when "strong"
    "**#{children.call.strip}**"
  when "em"
    "*#{children.call.strip}*"
  when "a"
    content = children.call.strip
    href = node.attributes["href"]
    if href&.start_with?("/docs/api/", "/docs/client/")
      destination = href.delete_prefix("/docs/").split("#").first
      return "#{content} (`iam docs #{destination}`)"
    end
    href ? "[#{content}](#{CGI.unescapeHTML(href)})" : content
  when "ul", "ol"
    rows = node.get_elements("li").each_with_index.map do |item, index|
      prefix = node.name == "ol" ? "#{index + 1}. " : "- "
      content = item.children.map { |child| markdown(child) }.join.strip
      "#{prefix}#{content.gsub("\n", "\n  ")}"
    end
    "\n\n#{rows.join("\n\n")}\n\n"
  when "table"
    rows = node.get_elements(".//tr").map do |row|
      row.elements.to_a.select { |cell| %w[td th].include?(cell.name) }.map do |cell|
        cell.children.map { |child| markdown(child) }.join.strip.gsub(/\s+/, " ").gsub("|", "\\|")
      end
    end
    return "" if rows.empty?

    lines = rows.map { |row| "| #{row.join(' | ')} |" }
    lines.insert(1, "| #{Array.new(rows.first.length, '---').join(' | ')} |")
    "\n\n#{lines.join("\n")}\n\n"
  else
    children.call
  end
end

def render_html(source, title)
  # HTML tolerates a raw ampersand in code examples; XML does not. Preserve it.
  normalized = source.gsub(/&(?!#\d+;|#x[\da-fA-F]+;|(?:amp|lt|gt|quot|apos);)/, "&amp;")
  document = REXML::Document.new("<manual>#{normalized}</manual>")
  body = markdown(document.root).gsub(/\n[ \t]+\n/, "\n\n").gsub(/\n{3,}/, "\n\n").strip
  "# #{title}\n\n#{body}\n"
end

unless ARGV.empty? || ARGV == ["--check"]
  warn "Usage: ruby scripts/generate-cli-docs.rb [--check]"
  exit 2
end

# New consumer guides must receive a discoverable topic, not silently disappear
# from installed CLI builds. This dated report is evidence, not a user manual.
excluded = %w[docs/INTEGRATION_FIXES_2026-09-05.md]
canonical = Dir[File.join(ROOT, "docs/**/*.{md,html,yaml}")].map do |path|
  path.delete_prefix("#{ROOT}/")
end
unlisted = canonical - CATALOG.map { |entry| entry[2] } - excluded
unless unlisted.empty?
  warn "Add a documentation topic to scripts/generate-cli-docs.rb for:"
  unlisted.each { |path| warn "  #{path}" }
  exit 1
end

outputs = {}
entries = CATALOG.map do |topic, title, source_path, aliases|
  source = File.read(File.join(ROOT, source_path))
  format = File.extname(source_path) == ".yaml" ? "yaml" : "markdown"
  content = File.extname(source_path) == ".html" ? render_html(source, title) : source
  asset = "#{topic.tr('/', '-')}.#{format == 'yaml' ? 'yaml' : 'md'}"
  outputs["#{ASSETS}/#{asset}"] = content
  <<~RUST.chomp
      Document {
          topic: #{topic.dump},
          title: #{title.dump},
          source: #{source_path.dump},
          source_sha256: #{Digest::SHA256.hexdigest(source).dump},
          format: #{format.dump},
          aliases: &[#{aliases.map(&:dump).join(', ')}],
          content: include_str!("manual_assets/#{asset}"),
      },
  RUST
end
outputs[MANIFEST] = <<~RUST
  // @generated by scripts/generate-cli-docs.rb; edit canonical files under docs/.
  // Source hashes make each embedded document's provenance inspectable offline.

  use super::Document;

  #[rustfmt::skip]
  pub(super) static DOCUMENTS: &[Document] = &[
  #{entries.map { |entry| entry.lines.map { |line| "    #{line}" }.join }.join("\n")}
  ];
RUST

changed = outputs.select do |path, expected|
  absolute = File.join(ROOT, path)
  !File.file?(absolute) || File.binread(absolute) != expected.b
end
if ARGV == ["--check"]
  unless changed.empty?
    warn "Bundled CLI documentation is stale:"
    changed.each_key { |path| warn "  #{path}" }
    warn "Run ruby scripts/generate-cli-docs.rb after editing docs/."
    exit 1
  end
  puts "Bundled CLI documentation matches #{CATALOG.length} canonical documents."
else
  changed.each do |path, expected|
    absolute = File.join(ROOT, path)
    FileUtils.mkdir_p(File.dirname(absolute))
    File.write(absolute, expected)
  end
  puts "Bundled #{CATALOG.length} documents (#{changed.length} generated files updated)."
end
