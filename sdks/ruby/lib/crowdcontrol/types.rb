# frozen_string_literal: true

module CrowdControl
  # ------------------------------------------------------------------
  # Default effect constants
  # ------------------------------------------------------------------
  DEFAULT_ALLOW = "allow"
  DEFAULT_DENY  = "deny"

  # ------------------------------------------------------------------
  # Schema field type constants
  # ------------------------------------------------------------------
  FIELD_STRING = "string"
  FIELD_NUMBER = "number"
  FIELD_BOOL   = "bool"
  FIELD_LIST   = "list"
  FIELD_MAP    = "map"
  FIELD_ANY    = "any"

  # ------------------------------------------------------------------
  # Condition types
  # ------------------------------------------------------------------
  module ConditionType
    FIELD     = :field
    AGGREGATE = :aggregate
    OR        = :or
    ANY       = :any
    ALL       = :all
    HAS       = :has
    EXPR      = :expr
  end

  # ------------------------------------------------------------------
  # Expression kinds (arithmetic AST)
  # ------------------------------------------------------------------
  module ExprKind
    FIELD   = :field
    LITERAL = :literal
    COUNT   = :count
    LEN     = :len
    BINARY  = :binary
  end

  # ------------------------------------------------------------------
  # Expr — arithmetic / transform expression node
  # ------------------------------------------------------------------
  class Expr
    attr_accessor :kind, :field, :value, :agg_target, :transform, :op, :left, :right

    def initialize(kind: ExprKind::LITERAL, field: "", value: 0.0, agg_target: "",
                   transform: "", op: "", left: nil, right: nil)
      @kind       = kind
      @field      = field
      @value      = value
      @agg_target = agg_target
      @transform  = transform
      @op         = op
      @left       = left
      @right      = right
    end
  end

  # ------------------------------------------------------------------
  # Condition — single condition in a rule body or unless clause
  # ------------------------------------------------------------------
  class Condition
    attr_accessor :type, :negated, :field, :op, :value, :transform,
                  :aggregate_func, :aggregate_target, :or_group,
                  :quantifier, :list_field, :predicate,
                  :left_expr, :right_expr

    def initialize(type: ConditionType::FIELD, negated: false, field: "", op: "",
                   value: nil, transform: "", aggregate_func: "", aggregate_target: "",
                   or_group: nil, quantifier: "", list_field: "", predicate: nil,
                   left_expr: nil, right_expr: nil)
      @type             = type
      @negated          = negated
      @field            = field
      @op               = op
      @value            = value
      @transform        = transform
      @aggregate_func   = aggregate_func
      @aggregate_target = aggregate_target
      @or_group         = or_group || []
      @quantifier       = quantifier
      @list_field       = list_field
      @predicate        = predicate
      @left_expr        = left_expr
      @right_expr       = right_expr
    end
  end

  # ------------------------------------------------------------------
  # Rule — single policy rule
  # ------------------------------------------------------------------
  class Rule
    attr_accessor :kind, :name, :conditions, :unlesses,
                  :message, :description, :owner, :link

    def initialize(kind: "", name: "", conditions: nil, unlesses: nil,
                   message: "", description: "", owner: "", link: "")
      @kind        = kind
      @name        = name
      @conditions  = conditions || []
      @unlesses    = unlesses || []
      @message     = message
      @description = description
      @owner       = owner
      @link        = link
    end
  end

  # ------------------------------------------------------------------
  # Policy — a parsed policy file
  # ------------------------------------------------------------------
  class Policy
    attr_accessor :rules

    def initialize(rules: nil)
      @rules = rules || []
    end
  end

  # ------------------------------------------------------------------
  # ConditionTrace — per-condition explain output
  # ------------------------------------------------------------------
  class ConditionTrace
    attr_accessor :expr, :result, :actual, :children

    def initialize(expr: "", result: false, actual: "", children: nil)
      @expr     = expr
      @result   = result
      @actual   = actual
      @children = children || []
    end
  end

  # ------------------------------------------------------------------
  # RuleTrace — per-rule explain output
  # ------------------------------------------------------------------
  class RuleTrace
    attr_accessor :conditions, :unlesses, :all_conditions_matched, :saved_by_unless

    def initialize(conditions: nil, unlesses: nil,
                   all_conditions_matched: false, saved_by_unless: false)
      @conditions             = conditions || []
      @unlesses               = unlesses || []
      @all_conditions_matched = all_conditions_matched
      @saved_by_unless        = saved_by_unless
    end
  end

  # ------------------------------------------------------------------
  # Result — single decision emitted by the engine
  # ------------------------------------------------------------------
  class Result
    attr_accessor :rule, :kind, :passed, :message, :description, :owner, :link, :trace

    def initialize(rule: "", kind: "", passed: true, message: "",
                   description: "", owner: "", link: "", trace: nil)
      @rule        = rule
      @kind        = kind
      @passed      = passed
      @message     = message
      @description = description
      @owner       = owner
      @link        = link
      @trace       = trace
    end
  end

  # ------------------------------------------------------------------
  # Schema — static schema for validation
  # ------------------------------------------------------------------
  class Schema
    attr_accessor :fields

    def initialize(fields: nil)
      @fields = fields || {}
    end
  end

  # ------------------------------------------------------------------
  # SchemaWarning — non-fatal validation warning
  # ------------------------------------------------------------------
  class SchemaWarning
    attr_accessor :rule, :field, :message

    def initialize(rule: "", field: "", message: "")
      @rule    = rule
      @field   = field
      @message = message
    end
  end
end
