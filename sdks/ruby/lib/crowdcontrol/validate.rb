# frozen_string_literal: true

require_relative "types"

module CrowdControl
  class << self
    # Run schema validation across every loaded policy. Returns a list of
    # non-fatal SchemaWarning values.
    def validate_policies(policies, schema)
      warnings = []
      policies.each do |policy|
        policy.rules.each do |rule|
          rule.conditions.each do |cond|
            warnings.concat(validate_condition(cond, schema, rule.name))
          end
          rule.unlesses.each do |u|
            warnings.concat(validate_condition(u, schema, rule.name))
          end
          warnings.concat(validate_interpolations(rule.message, schema, rule.name)) if rule.message && rule.message != ""
        end
      end
      warnings
    end

    def format_warnings(warnings)
      return "" if warnings.nil? || warnings.empty?

      warnings.map { |w| "  #{w.rule}: #{w.message}" }.join("\n") + "\n"
    end

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def validate_condition(cond, schema, rule_name)
      warnings = []
      case cond.type
      when ConditionType::FIELD
        warnings.concat(check_field(cond.field, schema, rule_name, cond)) unless cond.field.nil? || cond.field == ""
      when ConditionType::HAS
        warnings.concat(check_field_exists(cond.field, schema, rule_name)) unless cond.field.nil? || cond.field == ""
      when ConditionType::AGGREGATE
        warnings.concat(check_aggregate_field(cond.aggregate_target, schema, rule_name)) unless cond.aggregate_target.nil? || cond.aggregate_target == ""
      when ConditionType::ANY, ConditionType::ALL
        warnings.concat(check_list_field(cond.list_field, schema, rule_name)) unless cond.list_field.nil? || cond.list_field == ""
        warnings.concat(validate_condition(cond.predicate, schema, rule_name)) if cond.predicate
      when ConditionType::OR
        cond.or_group.each { |sub| warnings.concat(validate_condition(sub, schema, rule_name)) }
      when ConditionType::EXPR
        warnings.concat(check_expr_fields(cond.left_expr, schema, rule_name))  if cond.left_expr
        warnings.concat(check_expr_fields(cond.right_expr, schema, rule_name)) if cond.right_expr
      end
      warnings
    end

    def check_field(field, schema, rule_name, cond)
      warnings = []
      expected = lookup_field(schema, field)
      if expected.nil?
        warnings << SchemaWarning.new(
          rule: rule_name,
          field: field,
          message: "field #{field.inspect} not found in schema"
        )
        return warnings
      end

      op = cond.op
      case op
      when "<", ">", "<=", ">="
        unless [FIELD_NUMBER, FIELD_ANY].include?(expected)
          warnings << SchemaWarning.new(
            rule: rule_name,
            field: field,
            message: "operator #{op} used on field #{field.inspect} of type #{expected}"
          )
        end
      when "contains", "intersects", "is_subset"
        unless [FIELD_LIST, FIELD_STRING, FIELD_ANY].include?(expected)
          warnings << SchemaWarning.new(
            rule: rule_name,
            field: field,
            message: "operator #{op} used on field #{field.inspect} of type #{expected}"
          )
        end
      when "in"
        unless [FIELD_STRING, FIELD_ANY].include?(expected)
          warnings << SchemaWarning.new(
            rule: rule_name,
            field: field,
            message: "operator 'in' used on field #{field.inspect} of type #{expected}"
          )
        end
      end
      warnings
    end

    def check_field_exists(field, schema, rule_name)
      return [] unless lookup_field(schema, field).nil?

      [SchemaWarning.new(
        rule: rule_name,
        field: field,
        message: "field #{field.inspect} not found in schema (used with 'has')"
      )]
    end

    def check_aggregate_field(field, schema, rule_name)
      expected = lookup_field(schema, field)
      if expected.nil?
        return [SchemaWarning.new(
          rule: rule_name,
          field: field,
          message: "field #{field.inspect} not found in schema (used with 'count')"
        )]
      end
      return [] if [FIELD_LIST, FIELD_NUMBER, FIELD_ANY].include?(expected)

      [SchemaWarning.new(
        rule: rule_name,
        field: field,
        message: "count() used on field #{field.inspect} of type #{expected}, expected list or number"
      )]
    end

    def check_list_field(field, schema, rule_name)
      expected = lookup_field(schema, field)
      if expected.nil?
        return [SchemaWarning.new(
          rule: rule_name,
          field: field,
          message: "field #{field.inspect} not found in schema (used with quantifier)"
        )]
      end
      return [] if [FIELD_LIST, FIELD_ANY].include?(expected)

      [SchemaWarning.new(
        rule: rule_name,
        field: field,
        message: "quantifier used on field #{field.inspect} of type #{expected}, expected list"
      )]
    end

    def check_expr_fields(expr, schema, rule_name)
      warnings = []
      case expr.kind
      when ExprKind::FIELD
        return warnings if expr.field.nil? || expr.field == ""

        expected = lookup_field(schema, expr.field)
        if expected.nil?
          warnings << SchemaWarning.new(
            rule: rule_name,
            field: expr.field,
            message: "field #{expr.field.inspect} not found in schema (used in arithmetic)"
          )
        elsif ![FIELD_NUMBER, FIELD_ANY].include?(expected)
          warnings << SchemaWarning.new(
            rule: rule_name,
            field: expr.field,
            message: "arithmetic used on field #{expr.field.inspect} of type #{expected}, expected number"
          )
        end
      when ExprKind::COUNT
        warnings.concat(check_aggregate_field(expr.agg_target, schema, rule_name)) unless expr.agg_target.nil? || expr.agg_target == ""
      when ExprKind::LEN
        return warnings if expr.field.nil? || expr.field == ""

        expected = lookup_field(schema, expr.field)
        if expected.nil?
          warnings << SchemaWarning.new(
            rule: rule_name,
            field: expr.field,
            message: "field #{expr.field.inspect} not found in schema (used with len)"
          )
        end
      when ExprKind::BINARY
        warnings.concat(check_expr_fields(expr.left, schema, rule_name))  if expr.left
        warnings.concat(check_expr_fields(expr.right, schema, rule_name)) if expr.right
      end
      warnings
    end

    def validate_interpolations(msg, schema, rule_name)
      warnings = []
      msg.scan(/\{([^}]+)\}/) do |m|
        expr = m[0]
        next if expr.start_with?("count(") && expr.end_with?(")")
        next unless lookup_field(schema, expr).nil?

        warnings << SchemaWarning.new(
          rule: rule_name,
          field: expr,
          message: "message interpolation references unknown field #{expr.inspect}"
        )
      end
      warnings
    end

    def lookup_field(schema, field)
      return schema.fields[field] if schema.fields.key?(field)

      parts = field.split(".")
      (parts.length - 1).downto(1) do |i|
        prefix = parts[0...i].join(".")
        if schema.fields.key?(prefix) && schema.fields[prefix] == FIELD_MAP
          return FIELD_ANY
        end
      end
      nil
    end
  end
end
