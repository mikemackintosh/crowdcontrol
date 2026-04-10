#!/usr/bin/env ruby
# frozen_string_literal: true

# Runnable demo for the CrowdControl Ruby SDK.
#
#   cd sdks/ruby && ruby -Ilib examples/demo.rb

require "crowdcontrol"

POLICY = <<~CC
  forbid "no-interns-in-prod" {
    description "interns are not allowed to touch production"
    owner "security-team"
    user.role == "intern"
    resource.environment == "production"
    message "{user.name} is an intern and cannot touch {resource.environment}"
  }

  forbid "too-many-deletes" {
    count(plan.deletes) > 5
    message "plan deletes {count(plan.deletes)} resources — gate required"
  }

  permit "admins-always-ok" {
    user.role == "admin"
    message "admin override"
  }
CC

INPUTS = [
  {
    "label" => "intern hitting prod",
    "doc" => {
      "user" => { "name" => "alex", "role" => "intern" },
      "resource" => { "environment" => "production" },
      "plan" => { "deletes" => [] }
    }
  },
  {
    "label" => "dev with huge delete plan",
    "doc" => {
      "user" => { "name" => "sam", "role" => "developer" },
      "resource" => { "environment" => "staging" },
      "plan" => { "deletes" => %w[a b c d e f g] }
    }
  },
  {
    "label" => "admin on prod",
    "doc" => {
      "user" => { "name" => "root", "role" => "admin" },
      "resource" => { "environment" => "production" },
      "plan" => { "deletes" => [] }
    }
  }
]

engine = CrowdControl.from_source([POLICY])

INPUTS.each do |scenario|
  puts "=== #{scenario['label']} ==="
  results = engine.evaluate(scenario["doc"])
  results.each do |r|
    status = r.passed ? "pass" : "FAIL"
    msg = r.message == "" ? "(no message)" : r.message
    puts "  [#{status}] #{r.kind} #{r.rule}: #{msg}"
  end
  puts
end
