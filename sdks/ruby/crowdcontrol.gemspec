# frozen_string_literal: true

require_relative "lib/crowdcontrol/version"

Gem::Specification.new do |spec|
  spec.name          = "crowdcontrol"
  spec.version       = CrowdControl::VERSION
  spec.authors       = ["CrowdControl Contributors"]
  spec.email         = ["noreply@example.com"]

  spec.summary       = "Ruby SDK for the CrowdControl policy language"
  spec.description   = <<~DESC
    A pure-Ruby implementation of the CrowdControl policy language — a small,
    readable DSL for gating actions on structured data. Zero gem dependencies;
    passes the shared conformance suite used by the Go reference and all other
    language SDKs.
  DESC
  spec.homepage      = "https://github.com/mikemackintosh/crowdcontrol"
  spec.license       = "Apache-2.0"

  spec.required_ruby_version = ">= 3.0.0"

  spec.files = Dir[
    "lib/**/*.rb",
    "README.md",
    "crowdcontrol.gemspec"
  ]

  spec.require_paths = ["lib"]

  # Zero runtime dependencies. Only stdlib is used (json, set, etc).
  # Development-only tooling would go here via add_development_dependency,
  # but we keep even that empty — tests use stdlib minitest.
end
