# frozen_string_literal: true

require "minitest/autorun"
require "crowdcontrol"

class TestValidate < Minitest::Test
  include CrowdControl

  def validate(src, schema_fields)
    pol = Parser.parse(src)
    schema = Schema.new(fields: schema_fields)
    CrowdControl.validate_policies([pol], schema)
  end

  def test_unknown_field_reference_warns
    w = validate('forbid "r" { user.typo == "x" }', { "user.name" => FIELD_STRING })
    assert_equal 1, w.length
    assert_includes w[0].message, "not found in schema"
  end

  def test_numeric_op_on_string_warns
    w = validate('forbid "r" { user.name > 3 }', { "user.name" => FIELD_STRING })
    assert_equal 1, w.length
    assert_includes w[0].message, "operator > used on field"
  end

  def test_known_field_no_warning
    w = validate('forbid "r" { user.name == "alice" }', { "user.name" => FIELD_STRING })
    assert_equal 0, w.length
  end

  def test_count_on_non_list_warns
    w = validate('forbid "r" { count(user.name) > 1 }', { "user.name" => FIELD_STRING })
    assert_equal 1, w.length
    assert_includes w[0].message, "count()"
  end

  def test_quantifier_on_non_list_warns
    w = validate('forbid "r" { any user.name == "x" }', { "user.name" => FIELD_STRING })
    assert_equal 1, w.length
    assert_includes w[0].message, "quantifier"
  end

  def test_has_unknown_field_warns
    w = validate('forbid "r" { has user.typo }', { "user.name" => FIELD_STRING })
    assert_equal 1, w.length
    assert_includes w[0].message, "'has'"
  end

  def test_contains_on_bool_warns
    w = validate('forbid "r" { user.ok contains "x" }', { "user.ok" => FIELD_BOOL })
    assert_equal 1, w.length
  end

  def test_in_on_list_warns
    w = validate('forbid "r" { user.tags in ["a","b"] }', { "user.tags" => FIELD_LIST })
    assert_equal 1, w.length
    assert_includes w[0].message, "'in'"
  end

  def test_message_interpolation_unknown_field_warns
    w = validate(
      'forbid "r" { user.name == "alice" message "hi {user.nope}" }',
      { "user.name" => FIELD_STRING }
    )
    assert_equal 1, w.length
    assert_includes w[0].message, "interpolation"
  end

  def test_map_prefix_allows_any_subfield
    w = validate(
      'forbid "r" { user.anything == "x" }',
      { "user" => FIELD_MAP }
    )
    assert_equal 0, w.length
  end

  def test_arithmetic_on_non_number_warns
    w = validate(
      'forbid "r" { user.name + 1 > 5 }',
      { "user.name" => FIELD_STRING }
    )
    assert w.length >= 1
    assert(w.any? { |warning| warning.message.include?("arithmetic") })
  end

  def test_format_warnings
    w = validate('forbid "r" { user.typo == "x" }', {})
    text = CrowdControl.format_warnings(w)
    assert_includes text, "r:"
    assert text.end_with?("\n")
  end
end
