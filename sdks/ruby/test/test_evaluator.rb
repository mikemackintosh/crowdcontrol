# frozen_string_literal: true

require "minitest/autorun"
require "crowdcontrol"

class TestEvaluator < Minitest::Test
  def run_policy(src, input, default_effect: "allow")
    eng = CrowdControl.from_source([src], default_effect: default_effect)
    eng.evaluate(input)
  end

  def test_forbid_fires_on_match
    results = run_policy(
      'forbid "r" { user.role == "admin" message "nope" }',
      { "user" => { "role" => "admin" } }
    )
    assert_equal 1, results.length
    refute results[0].passed
    assert_equal "forbid", results[0].kind
    assert_equal "nope", results[0].message
  end

  def test_forbid_does_not_fire_when_mismatch
    results = run_policy(
      'forbid "r" { user.role == "admin" message "nope" }',
      { "user" => { "role" => "dev" } }
    )
    assert results[0].passed
    assert_equal "", results[0].message
  end

  def test_permit_fires
    results = run_policy(
      'permit "ok" { user.role == "admin" message "fine" }',
      { "user" => { "role" => "admin" } }
    )
    assert results[0].passed
    assert_equal "fine", results[0].message
  end

  def test_unless_saves_rule
    results = run_policy(
      'forbid "r" { user.role == "admin" unless user.name == "alice" message "bad" }',
      { "user" => { "role" => "admin", "name" => "alice" } }
    )
    assert results[0].passed
  end

  def test_numeric_comparison
    results = run_policy(
      'forbid "r" { plan.adds > 5 message "too many" }',
      { "plan" => { "adds" => 10 } }
    )
    refute results[0].passed
  end

  def test_numeric_strict_no_string_coercion
    results = run_policy(
      'forbid "r" { plan.adds > 5 message "too many" }',
      { "plan" => { "adds" => "10" } }
    )
    # Strings should not numeric-coerce per spec.
    assert results[0].passed
  end

  def test_in_operator
    results = run_policy(
      'forbid "r" { user.role in ["admin","root"] message "no" }',
      { "user" => { "role" => "root" } }
    )
    refute results[0].passed
  end

  def test_contains_on_list
    results = run_policy(
      'forbid "r" { user.tags contains "red" message "red" }',
      { "user" => { "tags" => %w[blue red green] } }
    )
    refute results[0].passed
  end

  def test_contains_on_string
    results = run_policy(
      'forbid "r" { user.name contains "bob" message "bob" }',
      { "user" => { "name" => "alicebobcarol" } }
    )
    refute results[0].passed
  end

  def test_intersects
    results = run_policy(
      'forbid "r" { user.roles intersects ["admin","root"] message "x" }',
      { "user" => { "roles" => %w[dev root] } }
    )
    refute results[0].passed
  end

  def test_is_subset_true
    results = run_policy(
      'forbid "r" { user.roles is_subset ["a","b","c"] message "x" }',
      { "user" => { "roles" => %w[a b] } }
    )
    refute results[0].passed
  end

  def test_any_quantifier_empty_list_is_false
    results = run_policy(
      'forbid "r" { any user.tags == "bad" message "x" }',
      { "user" => { "tags" => [] } }
    )
    assert results[0].passed
  end

  def test_all_quantifier_empty_list_is_true
    results = run_policy(
      'forbid "r" { all user.tags == "bad" message "x" }',
      { "user" => { "tags" => [] } }
    )
    refute results[0].passed
  end

  def test_count_aggregate
    results = run_policy(
      'forbid "r" { count(plan.deletes) > 2 message "x" }',
      { "plan" => { "deletes" => [1, 2, 3, 4] } }
    )
    refute results[0].passed
  end

  def test_arithmetic_condition
    results = run_policy(
      'forbid "r" { plan.adds + plan.deletes > 10 message "x" }',
      { "plan" => { "adds" => 6, "deletes" => 7 } }
    )
    refute results[0].passed
  end

  def test_transform_lower_equality
    results = run_policy(
      'forbid "r" { lower(user.name) == "alice" message "x" }',
      { "user" => { "name" => "ALICE" } }
    )
    refute results[0].passed
  end

  def test_transform_len_string
    results = run_policy(
      'forbid "r" { len(user.name) > 3 message "x" }',
      { "user" => { "name" => "alice" } }
    )
    refute results[0].passed
  end

  def test_message_interpolation
    results = run_policy(
      'forbid "r" { user.role == "intern" message "{user.name} is intern" }',
      { "user" => { "name" => "alex", "role" => "intern" } }
    )
    assert_equal "alex is intern", results[0].message
  end

  def test_message_interpolation_count
    results = run_policy(
      'forbid "r" { count(plan.deletes) > 1 message "{count(plan.deletes)} deletes" }',
      { "plan" => { "deletes" => [1, 2, 3] } }
    )
    assert_equal "3 deletes", results[0].message
  end

  def test_default_deny_appends_result_when_nothing_fires
    results = run_policy(
      'permit "a" { user.role == "admin" message "ok" }',
      { "user" => { "role" => "dev" } },
      default_effect: "deny"
    )
    assert_equal 2, results.length
    last = results[-1]
    assert_equal "(default-deny)", last.rule
    assert_equal "forbid", last.kind
    refute last.passed
  end

  def test_default_deny_does_not_append_when_permit_fires
    results = run_policy(
      'permit "a" { user.role == "admin" message "ok" }',
      { "user" => { "role" => "admin" } },
      default_effect: "deny"
    )
    assert_equal 1, results.length
    assert_equal "a", results[0].rule
  end

  def test_negation
    results = run_policy(
      'forbid "r" { not user.role == "admin" message "x" }',
      { "user" => { "role" => "dev" } }
    )
    refute results[0].passed
  end

  def test_or_group
    results = run_policy(
      'forbid "r" { user.role == "admin" or user.role == "root" message "x" }',
      { "user" => { "role" => "root" } }
    )
    refute results[0].passed
  end

  def test_resolve_field_returns_nil_on_missing
    assert_nil CrowdControl.resolve_field("a.b.c", { "a" => 1 })
    assert_nil CrowdControl.resolve_field("x", nil)
  end

  def test_interpolate_unresolved_placeholder_kept
    msg = CrowdControl.interpolate_message("hi {user.name}", {})
    assert_equal "hi {user.name}", msg
  end

  def test_interpolate_empty_message_gives_default
    assert_equal "policy violation", CrowdControl.interpolate_message("", {})
  end

  def test_format_results_passing_summary
    results = run_policy(
      'forbid "r" { user.role == "admin" message "x" }',
      { "user" => { "role" => "dev" } }
    )
    text, passed = CrowdControl.format_results(results)
    assert passed
    assert_includes text, "PASS:"
  end
end
