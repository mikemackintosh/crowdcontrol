# frozen_string_literal: true

require "minitest/autorun"
require "crowdcontrol"

class TestParser < Minitest::Test
  include CrowdControl

  def p(src)
    Parser.parse(src)
  end

  def test_empty_source_yields_empty_policy
    pol = p("")
    assert_equal 0, pol.rules.length
  end

  def test_simple_forbid_rule
    pol = p('forbid "r1" { user.role == "admin" }')
    assert_equal 1, pol.rules.length
    r = pol.rules[0]
    assert_equal "forbid", r.kind
    assert_equal "r1", r.name
    assert_equal 1, r.conditions.length
    c = r.conditions[0]
    assert_equal ConditionType::FIELD, c.type
    assert_equal "user.role", c.field
    assert_equal "==", c.op
    assert_equal "admin", c.value
  end

  def test_multiple_conditions_are_anded
    pol = p('forbid "r" { user.a == "x"  user.b == "y" }')
    assert_equal 2, pol.rules[0].conditions.length
  end

  def test_metadata_and_message
    src = <<~CC
      forbid "m" {
        description "d"
        owner "team"
        link "https://x.test"
        user.x == "1"
        message "bad"
      }
    CC
    r = p(src).rules[0]
    assert_equal "d", r.description
    assert_equal "team", r.owner
    assert_equal "https://x.test", r.link
    assert_equal "bad", r.message
  end

  def test_unless_clause
    r = p('forbid "u" { user.x == "1" unless user.y == "2" }').rules[0]
    assert_equal 1, r.unlesses.length
    assert_equal "user.y", r.unlesses[0].field
  end

  def test_has_condition
    r = p('forbid "h" { has user.x }').rules[0]
    c = r.conditions[0]
    assert_equal ConditionType::HAS, c.type
    assert_equal "user.x", c.field
  end

  def test_count_aggregate
    r = p('forbid "c" { count(plan.deletes) > 5 }').rules[0]
    c = r.conditions[0]
    assert_equal ConditionType::AGGREGATE, c.type
    assert_equal "plan.deletes", c.aggregate_target
    assert_equal ">", c.op
    assert_equal 5, c.value
  end

  def test_any_quantifier
    r = p('forbid "q" { any tags.list == "prod" }').rules[0]
    c = r.conditions[0]
    assert_equal ConditionType::ANY, c.type
    assert_equal "tags.list", c.list_field
    refute_nil c.predicate
    assert_equal "==", c.predicate.op
    assert_equal "prod", c.predicate.value
  end

  def test_all_quantifier_with_in
    r = p('forbid "q" { all items in ["a","b","c"] }').rules[0]
    c = r.conditions[0]
    assert_equal ConditionType::ALL, c.type
    assert_equal "in", c.predicate.op
    assert_equal %w[a b c], c.predicate.value
  end

  def test_or_group
    r = p('forbid "o" { user.x == "a" or user.x == "b" }').rules[0]
    c = r.conditions[0]
    assert_equal ConditionType::OR, c.type
    assert_equal 2, c.or_group.length
  end

  def test_negation
    r = p('forbid "n" { not user.x == "a" }').rules[0]
    c = r.conditions[0]
    assert c.negated
  end

  def test_transform_lower
    r = p('forbid "l" { lower(user.name) == "alice" }').rules[0]
    c = r.conditions[0]
    assert_equal "lower", c.transform
    assert_equal "user.name", c.field
  end

  def test_string_list_operators
    r = p('forbid "i" { user.role in ["admin","root"] }').rules[0]
    assert_equal "in", r.conditions[0].op
    assert_equal %w[admin root], r.conditions[0].value
  end

  def test_matches_pattern
    r = p('forbid "m" { file.name matches "*.go" }').rules[0]
    assert_equal "matches", r.conditions[0].op
    assert_equal "*.go", r.conditions[0].value
  end

  def test_arithmetic_expression
    r = p('forbid "a" { plan.adds + plan.deletes > 10 }').rules[0]
    c = r.conditions[0]
    assert_equal ConditionType::EXPR, c.type
    assert_equal ">", c.op
    refute_nil c.left_expr
    assert_equal ExprKind::BINARY, c.left_expr.kind
  end

  def test_parse_error_on_missing_brace
    assert_raises(ParseError) { p('forbid "r" { user.x == "a" ') }
  end

  def test_parse_error_on_bad_rule_kind
    assert_raises(ParseError) { p('wrong "r" { }') }
  end
end
