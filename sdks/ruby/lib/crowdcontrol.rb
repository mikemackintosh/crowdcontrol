# frozen_string_literal: true

# CrowdControl — pure-Ruby implementation of the CrowdControl policy language.
#
# Quick start:
#
#     require "crowdcontrol"
#
#     engine = CrowdControl.from_source([
#       <<~POLICY
#         forbid "no-interns-in-prod" {
#           user.role == "intern"
#           resource.environment == "production"
#           message "{user.name} cannot touch production"
#         }
#       POLICY
#     ])
#
#     results = engine.evaluate(
#       "user" => {"name" => "alex", "role" => "intern"},
#       "resource" => {"environment" => "production"}
#     )
#     results.each do |r|
#       puts [r.rule, r.kind, r.passed, r.message].inspect
#     end
#
module CrowdControl; end

require_relative "crowdcontrol/version"
require_relative "crowdcontrol/types"
require_relative "crowdcontrol/lexer"
require_relative "crowdcontrol/parser"
require_relative "crowdcontrol/evaluator"
require_relative "crowdcontrol/validate"

module CrowdControl
  class << self
    # Create an Engine from in-memory policy source strings.
    def from_source(sources, default_effect: DEFAULT_ALLOW, explain: false)
      Engine.from_source(sources, default_effect: default_effect, explain: explain)
    end

    # Create an Engine by loading every .cc file from the given directories.
    def from_directory(policy_dirs, default_effect: DEFAULT_ALLOW, explain: false)
      Engine.from_directory(policy_dirs, default_effect: default_effect, explain: explain)
    end

    # Parse a single source string into a Policy AST.
    def parse(source)
      Parser.parse(source)
    end
  end
end
