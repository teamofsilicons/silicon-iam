#!/usr/bin/env ruby
# frozen_string_literal: true

# Generates the client crate's wire types from the OpenAPI document.
#
# The client's job is to speak the contract exactly, so its types are derived
# from the contract rather than transcribed by hand. The output is committed as
# ordinary source: a published crate should not need a build-time generator,
# and the diff is what makes a contract change reviewable.
#
# Run after editing docs/openapi.yaml:
#
#   ruby scripts/generate-client-models.rb
#
# String enums gain an `Other(String)` variant so a value the service adds
# later deserializes instead of failing the whole response.

require "yaml"

OUTPUT = "crates/client/src/models.rs"

# Operator and browser surfaces. The client exposes caller actions only, and
# the error envelope has a hand-written equivalent in `error`.
EXCLUDED = %w[
  AdminApplication
  AdminApplicationPage
  ApplicationAdminDecision
  ErrorEnvelope
  OAuthConsentDecision
  OAuthConsentFormDecision
  SsoEntitlement
].freeze

# Shapes a generator would get wrong, written by hand in `models_manual`.
HAND_WRITTEN = %w[TrustSelector].freeze

RUST_KEYWORDS = %w[
  as break const continue crate dyn else enum extern false fn for if impl in let loop match mod
  move mut pub ref return self static struct super trait true type unsafe use where while
].freeze

def rust_type_name(name)
  name.gsub(/[^A-Za-z0-9]/, "").sub(/\A[a-z]/) { |c| c.upcase }
end

def field_name(name)
  candidate = name.gsub(/[^A-Za-z0-9_]/, "_")
  candidate = "#{candidate}_field" if RUST_KEYWORDS.include?(candidate)
  candidate
end

def variant_name(value)
  value.to_s.split(/[^A-Za-z0-9]+/).map { |part| part.sub(/\A[a-z]/) { |c| c.upcase } }.join
end

def wrap(text, indent, width = 78)
  words = text.to_s.split(/\s+/)
  lines = []
  current = ""
  words.each do |word|
    candidate = current.empty? ? word : "#{current} #{word}"
    if candidate.length + indent.length + 4 > width
      lines << current unless current.empty?
      current = word
    else
      current = candidate
    end
  end
  lines << current unless current.empty?
  lines
end

def doc_lines(text, indent, fallback)
  source = (text.nil? || text.to_s.strip.empty?) ? fallback : text.to_s.strip
  wrap(source, indent).map { |line| "#{indent}/// #{line}" }
end

class Generator
  def initialize(schemas)
    @schemas = schemas
    @aliases = {}
    @enums = {}
    @structs = {}
    @resolved = {}
  end

  attr_reader :aliases, :enums, :structs

  def run
    @schemas.each do |name, schema|
      next if EXCLUDED.include?(name) || HAND_WRITTEN.include?(name)

      classify(rust_type_name(name), schema)
    end
    # Field types are resolved before anything is emitted, because resolving
    # one can name a new inline enum, and every enum has to be declared.
    @structs.each do |name, schema|
      (schema["properties"] || {}).each do |property, property_schema|
        @resolved[[name, property]] = field_type(property_schema || {}, name, property)
      end
    end
    self
  end

  def resolved(name, property)
    @resolved.fetch([name, property])
  end

  private

  def classify(name, schema)
    merged = merge_all_of(schema)
    if merged["enum"] && scalar?(merged)
      @enums[name] = { values: merged["enum"], description: merged["description"] }
    elsif merged["properties"]
      @structs[name] = merged
    elsif merged["type"] == "array"
      @aliases[name] = { rust: "Vec<#{field_type(merged['items'], name, 'item')}>", description: merged["description"] }
    else
      @aliases[name] = { rust: scalar_type(merged), description: merged["description"] }
    end
  end

  def scalar?(schema)
    types = Array(schema["type"])
    types.include?("string") || types.include?("integer")
  end

  def merge_all_of(schema)
    return schema unless schema["allOf"]

    schema["allOf"].each_with_object({ "properties" => {}, "required" => [] }) do |part, merged|
      part = resolve(part)
      part = merge_all_of(part)
      merged["properties"].merge!(part["properties"] || {})
      merged["required"] |= Array(part["required"])
      merged["description"] ||= part["description"]
    end
  end

  def resolve(schema)
    ref = schema["$ref"]
    return schema unless ref

    @schemas.fetch(ref.split("/").last)
  end

  def scalar_type(schema)
    types = Array(schema["type"])
    nullable = types.include?("null")
    base =
      if types.include?("integer") then "i64"
      elsif types.include?("number") then "f64"
      elsif types.include?("boolean") then "bool"
      elsif types.include?("object") then "serde_json::Value"
      elsif schema["format"] == "uuid" then "Uuid"
      elsif schema["format"] == "date-time" then "OffsetDateTime"
      elsif types.include?("string") then "String"
      else "serde_json::Value"
      end
    nullable ? "Option<#{base}>" : base
  end

  # Names an inline enum after the struct and field that carry it, then
  # registers it so the field can refer to it by name.
  def inline_enum(schema, owner, field)
    name = "#{owner}#{variant_name(field)}"
    name = "#{name}Value" if @structs.key?(name) || @aliases.key?(name)
    @enums[name] ||= { values: schema["enum"], description: schema["description"] }
    name
  end

  def field_type(schema, owner, field)
    return "serde_json::Value" if schema.nil?

    if schema["$ref"]
      return rust_type_name(schema["$ref"].split("/").last)
    end

    types = Array(schema["type"])
    if types.include?("array")
      inner = field_type(schema["items"], owner, field)
      return "Vec<#{inner}>"
    end
    if schema["enum"] && scalar?(schema) && !types.include?("null")
      return inline_enum(schema, owner, field)
    end
    if types.include?("object") && schema["properties"]
      # An inline object with its own shape: keep it as free-form JSON rather
      # than invent a name the contract never gave it.
      return "serde_json::Value"
    end
    scalar_type(schema)
  end
end

document = YAML.safe_load(File.read("docs/openapi.yaml"), aliases: true)
generator = Generator.new(document.fetch("components").fetch("schemas")).run

out = +<<~HEADER
  //! Wire types for the Silicon IAM contract.
  //!
  //! Generated from `docs/openapi.yaml` by `scripts/generate-client-models.rb`.
  //! Edit the contract and regenerate rather than editing this file; the shapes
  //! that a generator cannot express live in `models_manual` instead.
  //!
  //! Every string enum carries an `Other` variant, so a value the service adds
  //! after this crate was published still deserializes.

  // The doc comments here are the contract's own prose, which names fields and
  // routes in running text. Rewriting it to satisfy a Rust documentation lint
  // would mean the generated docs no longer match the contract they came from.
  #![allow(clippy::doc_markdown)]

  use serde::{Deserialize, Serialize};
  use time::OffsetDateTime;
  use uuid::Uuid;

  pub use super::models_manual::*;
HEADER

generator.aliases.sort.each do |name, alias_info|
  out << "\n"
  out << doc_lines(alias_info[:description], "", "Contract alias for `#{name}`.").join("\n")
  out << "\npub type #{name} = #{alias_info[:rust]};\n"
end

generator.enums.sort.each do |name, info|
  out << "\n"
  out << doc_lines(info[:description], "", "Closed vocabulary from the contract.").join("\n")
  out << "\n#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]\n"
  out << "#[serde(rename_all = \"snake_case\")]\n"
  out << "pub enum #{name} {\n"
  info[:values].each do |value|
    out << "    /// `#{value}`\n"
    variant = variant_name(value)
    out << "    #[serde(rename = \"#{value}\")]\n" if variant.gsub(/([a-z0-9])([A-Z])/, '\1_\2').downcase != value.to_s
    out << "    #{variant},\n"
  end
  out << "    /// A value this crate predates. Held verbatim rather than\n"
  out << "    /// failing the response it arrived in.\n"
  out << "    #[serde(untagged)]\n"
  out << "    Other(String),\n"
  out << "}\n"
end

generator.structs.sort.each do |name, schema|
  required = Array(schema["required"])
  out << "\n"
  out << doc_lines(schema["description"], "", "Contract type `#{name}`.").join("\n")
  out << "\n#[derive(Clone, Debug, Serialize, Deserialize)]\n"
  out << "pub struct #{name} {\n"
  (schema["properties"] || {}).each do |property, property_schema|
    property_schema = property_schema || {}
    rust = generator.resolved(name, property)
    optional = !required.include?(property)
    nullable = rust.start_with?("Option<")
    rust = "Option<#{rust}>" if optional && !nullable
    ident = field_name(property)

    out << doc_lines(property_schema["description"], "    ", "The contract's `#{property}`.").join("\n")
    out << "\n"
    attributes = []
    attributes << "rename = \"#{property}\"" if ident != property
    if rust.include?("OffsetDateTime")
      serde_with = rust.start_with?("Option<") ? "time::serde::rfc3339::option" : "time::serde::rfc3339"
      attributes << "with = \"#{serde_with}\""
    end
    if optional
      attributes << "default"
      attributes << "skip_serializing_if = \"Option::is_none\""
    end
    out << "    #[serde(#{attributes.join(', ')})]\n" unless attributes.empty?
    out << "    pub #{ident}: #{rust},\n"
  end
  out << "}\n"
end

File.write(OUTPUT, out)
puts "Wrote #{OUTPUT}: #{generator.aliases.length} aliases, " \
     "#{generator.enums.length} enums, #{generator.structs.length} structs."
