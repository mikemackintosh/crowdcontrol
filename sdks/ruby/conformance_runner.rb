#!/usr/bin/env ruby
# frozen_string_literal: true

# Ruby SDK conformance runner.
#
# Reads every *.json case in the shared conformance suite
# (../../conformance/suite/*.json by default) and runs each one through
# the pure-Ruby implementation. Prints PASS/FAIL per case and a summary.
# Exits 0 on full pass, 1 on any failure.

require "json"

$LOAD_PATH.unshift(File.expand_path("lib", __dir__))
require "crowdcontrol"

DEFAULT_SUITE = File.expand_path("../../conformance/suite", __dir__)

def load_case(path)
  JSON.parse(File.read(path))
end

def run_case(c)
  default_effect = c["default_effect"] || "allow"
  unless %w[allow deny].include?(default_effect)
    return [false, "unknown default_effect #{default_effect.inspect}"]
  end

  begin
    eng = CrowdControl.from_source([c["policy"]], default_effect: default_effect)
  rescue CrowdControl::ParseError => e
    return [false, "parse error: #{e.message}"]
  end

  results  = eng.evaluate(c["input"] || {})
  expected = (c["expect"] || {})["decisions"] || []

  if results.length != expected.length
    summary = results.map { |r| "[#{r.rule}/#{r.kind} passed=#{r.passed}]" }.join(" ")
    return [false, "expected #{expected.length} decisions, got #{results.length} (results: #{summary})"]
  end

  expected.each_with_index do |want, i|
    got = results[i]
    return [false, "decision[#{i}]: rule = #{got.rule.inspect}, want #{want['rule'].inspect}"] if got.rule != want["rule"]
    return [false, "decision[#{i}] (#{got.rule}): kind = #{got.kind.inspect}, want #{want['kind'].inspect}"] if got.kind != want["kind"]
    return [false, "decision[#{i}] (#{got.rule}): passed = #{got.passed}, want #{want['passed']}"] if got.passed != want["passed"]

    if want.key?("message_exact") && want["message_exact"] != "" && got.message != want["message_exact"]
      return [false, "decision[#{i}] (#{got.rule}): message = #{got.message.inspect}, want exact #{want['message_exact'].inspect}"]
    end
    if want.key?("message_contains") && want["message_contains"] != "" && !got.message.include?(want["message_contains"])
      return [false, "decision[#{i}] (#{got.rule}): message = #{got.message.inspect}, want contains #{want['message_contains'].inspect}"]
    end
  end

  [true, ""]
end

def main(argv)
  suite_dir = argv[0] || DEFAULT_SUITE
  verbose   = argv.include?("-v") || argv.include?("--verbose")
  filter_i  = argv.index("-f") || argv.index("--filter")
  filter    = filter_i ? argv[filter_i + 1] : ""

  unless File.directory?(suite_dir)
    warn "suite dir not found: #{suite_dir}"
    return 2
  end

  files = Dir.children(suite_dir)
              .select { |f| f.end_with?(".json") }
              .reject { |f| File.directory?(File.join(suite_dir, f)) }
              .sort
              .map { |f| File.join(suite_dir, f) }

  if files.empty?
    warn "no conformance cases in #{suite_dir}"
    return 2
  end

  passed = 0
  failed = 0

  files.each do |path|
    begin
      c = load_case(path)
    rescue StandardError => e
      puts "FAIL: #{File.basename(path)} — load error: #{e.message}"
      failed += 1
      next
    end

    name = c["name"] || File.basename(path, ".json")
    next if filter && filter != "" && !name.include?(filter)

    ok, msg = run_case(c)
    if ok
      passed += 1
      puts "PASS: #{name}" if verbose
    else
      failed += 1
      puts "FAIL: #{name} — #{msg}"
    end
  end

  puts
  puts "#{passed} passed, #{failed} failed"
  failed > 0 ? 1 : 0
end

exit(main(ARGV)) if __FILE__ == $PROGRAM_NAME
