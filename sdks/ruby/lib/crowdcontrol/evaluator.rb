# frozen_string_literal: true

require "set"
require_relative "types"
require_relative "parser"

module CrowdControl
  POLICY_EXT = ".cc"

  # Compiled regex cache, shared across calls to `matches_regex`.
  REGEX_CACHE = {} # rubocop:disable Style/MutableConstant

  # ==========================================================================
  # Engine — loads and runs CrowdControl policies against JSON-like documents.
  # ==========================================================================
  class Engine
    attr_reader :policies

    def initialize(policies: nil, default_effect: DEFAULT_ALLOW, explain: false)
      @policies       = policies || []
      @default_effect = default_effect
      @explain        = explain
    end

    # ---- construction ------------------------------------------------------

    def self.from_directory(policy_dirs, default_effect: DEFAULT_ALLOW, explain: false)
      policies = []
      Array(policy_dirs).each do |d|
        next unless Dir.exist?(d)

        Dir.children(d).sort.each do |name|
          path = File.join(d, name)
          next unless File.file?(path) && name.end_with?(POLICY_EXT)

          src = File.read(path, encoding: "UTF-8")
          policies << Parser.parse(src)
        end
      end
      new(policies: policies, default_effect: default_effect, explain: explain)
    end

    def self.from_source(sources, default_effect: DEFAULT_ALLOW, explain: false)
      policies = Array(sources).map { |src| Parser.parse(src) }
      new(policies: policies, default_effect: default_effect, explain: explain)
    end

    # ---- evaluation --------------------------------------------------------

    def evaluate(doc)
      doc = doc || {}
      results       = []
      permit_fired  = false
      forbid_fired  = false

      @policies.each do |policy|
        policy.rules.each do |rule|
          r = eval_rule(rule, doc)
          results << r
          permit_fired = true if r.kind == "permit" && r.message != ""
          forbid_fired = true if r.kind == "forbid" && !r.passed
        end
      end

      if @default_effect == DEFAULT_DENY && !permit_fired && !forbid_fired
        results << Result.new(
          rule: "(default-deny)",
          kind: "forbid",
          passed: false,
          message: "no permit rule matched — denied by default"
        )
      end

      results
    end

    # Schema validation wrapper — delegates to validate_policies.
    def validate(schema)
      require_relative "validate"
      CrowdControl.validate_policies(@policies, schema)
    end

    # ---- rule evaluation ---------------------------------------------------

    private

    def eval_rule(rule, doc)
      result = Result.new(
        rule: rule.name,
        kind: rule.kind,
        passed: true,
        description: rule.description,
        owner: rule.owner,
        link: rule.link
      )

      trace = @explain ? RuleTrace.new : nil

      all_match = true
      rule.conditions.each do |cond|
        matched = CrowdControl.eval_condition(cond, doc)
        trace.conditions << CrowdControl.trace_condition(cond, doc, matched) if trace
        next if matched

        all_match = false
        break unless trace
      end

      trace.all_conditions_matched = all_match if trace

      unless all_match
        result.trace = trace if trace
        return result
      end

      saved = false
      rule.unlesses.each do |u|
        matched = CrowdControl.eval_condition(u, doc)
        trace.unlesses << CrowdControl.trace_condition(u, doc, matched) if trace
        next unless matched

        saved = true
        break unless trace
      end

      trace.saved_by_unless = saved if trace

      if saved
        result.trace = trace if trace
        return result
      end

      # Rule fires
      if rule.kind == "permit"
        result.passed  = true
        result.message = CrowdControl.interpolate_message(rule.message, doc)
      else
        result.passed  = false
        result.message = CrowdControl.interpolate_message(rule.message, doc)
      end

      result.trace = trace if trace
      result
    end
  end

  # Keep the older "Evaluator" name as an alias for Engine so the public
  # API spec (`CrowdControl::Engine` / `CrowdControl::Evaluator`) works
  # either way.
  Evaluator = Engine

  # ==========================================================================
  # Condition evaluation (module-level functions, mirrors Python layout)
  # ==========================================================================

  class << self
    def eval_condition(cond, doc)
      result = eval_condition_inner(cond, doc)
      cond.negated ? !result : result
    end

    def resolve_field(path, doc)
      return nil if doc.nil?

      current = doc
      path.split(".").each do |part|
        if current.is_a?(Hash)
          current = current[part]
        else
          return nil
        end
      end
      current
    end

    def interpolate_message(msg, doc)
      return "policy violation" if msg.nil? || msg == ""

      msg.gsub(/\{([^}]+)\}/) do
        expr = Regexp.last_match(1)
        if expr.start_with?("count(") && expr.end_with?(")")
          target = expr[6..-2]
          val = resolve_field(target, doc)
          if val.is_a?(Array)
            val.length.to_s
          elsif val.is_a?(Integer)
            val.to_s
          elsif val.is_a?(Float) && !val.nan?
            val == val.to_i ? val.to_i.to_s : val.to_s
          else
            "{#{expr}}"
          end
        else
          val = resolve_field(expr, doc)
          if val.nil?
            "{#{expr}}"
          else
            fmt_v(val)
          end
        end
      end
    end

    def format_results(results)
      all_passed = true
      lines      = []
      results.each do |r|
        next if r.passed

        prefix = "DENY"
        if r.kind == "warn"
          prefix = "WARN"
        else
          all_passed = false
        end
        line = "#{prefix}: #{r.message} (#{r.rule})"
        meta = []
        meta << "owner: #{r.owner}" unless r.owner.nil? || r.owner == ""
        meta << "link: #{r.link}"   unless r.link.nil?  || r.link  == ""
        line += " [#{meta.join(', ')}]" unless meta.empty?
        lines << line
      end
      if all_passed
        passed = results.count(&:passed)
        lines << "PASS: #{passed} rules evaluated, all passed"
      end
      text = lines.join("\n")
      text += "\n" unless lines.empty?
      [text, all_passed]
    end

    # ------------------------------------------------------------------
    # Internal helpers (public so Engine can reach them; prefix with eval_)
    # ------------------------------------------------------------------

    def eval_condition_inner(cond, doc)
      case cond.type
      when ConditionType::AGGREGATE
        eval_aggregate(cond, doc)
      when ConditionType::FIELD
        eval_field_condition(cond, doc)
      when ConditionType::OR
        cond.or_group.any? { |sub| eval_condition(sub, doc) }
      when ConditionType::ANY
        eval_quantifier(cond, doc, require_all: false)
      when ConditionType::ALL
        eval_quantifier(cond, doc, require_all: true)
      when ConditionType::HAS
        !resolve_field(cond.field, doc).nil?
      when ConditionType::EXPR
        eval_expr_condition(cond, doc)
      else
        false
      end
    end

    def eval_quantifier(cond, doc, require_all:)
      val = resolve_field(cond.list_field, doc)
      items = val.is_a?(Array) ? val : nil
      return require_all if items.nil?
      return require_all if items.empty?
      return false if cond.predicate.nil?

      items.each do |item|
        matched = eval_element_predicate(cond.predicate, doc, item)
        return false if require_all && !matched
        return true  if !require_all && matched
      end
      require_all
    end

    def eval_element_predicate(pred, _doc, element)
      return false unless pred.type == ConditionType::FIELD

      elem_str = fmt_v(element)
      op       = pred.op
      case op
      when "=="
        elem_str == fmt_v(pred.value)
      when "!="
        elem_str != fmt_v(pred.value)
      when "in"
        return false unless pred.value.is_a?(Array)

        pred.value.any? { |item| elem_str == item }
      when "matches"
        return false unless pred.value.is_a?(String)

        glob_match(pred.value, elem_str)
      when "matches_regex"
        return false unless pred.value.is_a?(String)

        regex_match(pred.value, elem_str)
      when "contains"
        eval_contains(element, pred.value)
      else
        compare_values(element, op, pred.value)
      end
    end

    def eval_expr_condition(cond, doc)
      return false if cond.left_expr.nil? || cond.right_expr.nil?

      left, lok  = eval_expr(cond.left_expr, doc)
      right, rok = eval_expr(cond.right_expr, doc)
      return false unless lok && rok

      compare_floats(left, cond.op, right)
    end

    def eval_expr(expr, doc)
      case expr.kind
      when ExprKind::LITERAL
        [expr.value.to_f, true]
      when ExprKind::FIELD
        val = resolve_field(expr.field, doc)
        f   = to_float(val)
        f.nil? ? [0.0, false] : [f, true]
      when ExprKind::COUNT
        val = resolve_field(expr.agg_target, doc)
        if val.is_a?(Array)
          [val.length.to_f, true]
        elsif val.is_a?(Integer) || val.is_a?(Float)
          [val.to_f, true]
        else
          [0.0, false]
        end
      when ExprKind::LEN
        val = resolve_field(expr.field, doc)
        if val.is_a?(String) || val.is_a?(Array)
          [val.length.to_f, true]
        elsif val.nil?
          [0.0, true]
        else
          [0.0, false]
        end
      when ExprKind::BINARY
        return [0.0, false] if expr.left.nil? || expr.right.nil?

        left, lok  = eval_expr(expr.left, doc)
        right, rok = eval_expr(expr.right, doc)
        return [0.0, false] unless lok && rok

        case expr.op
        when "+" then [left + right, true]
        when "-" then [left - right, true]
        when "*" then [left * right, true]
        when "/"
          right == 0 ? [0.0, false] : [left / right, true]
        else
          [0.0, false]
        end
      else
        [0.0, false]
      end
    end

    def eval_aggregate(cond, doc)
      val = resolve_field(cond.aggregate_target, doc)
      count =
        if val.is_a?(Array)
          val.length
        elsif val.is_a?(Integer)
          val
        elsif val.is_a?(Float)
          val.to_i
        else
          return false
        end

      return false unless cond.value.is_a?(Integer)

      compare_floats(count.to_f, cond.op, cond.value.to_f)
    end

    def eval_field_condition(cond, doc)
      val = resolve_field(cond.field, doc)
      val = apply_transform(cond.transform, val) unless cond.transform.nil? || cond.transform == ""

      op = cond.op
      case op
      when "=="
        fmt_v(val) == fmt_v(cond.value)
      when "!="
        fmt_v(val) != fmt_v(cond.value)
      when "<", ">", "<=", ">="
        compare_values(val, op, cond.value)
      when "in"
        return false unless cond.value.is_a?(Array)

        s = fmt_v(val)
        cond.value.any? { |item| s == item }
      when "matches"
        return false unless cond.value.is_a?(String)

        glob_match(cond.value, fmt_v(val))
      when "matches_regex"
        return false unless cond.value.is_a?(String)

        regex_match(cond.value, fmt_v(val))
      when "contains"
        eval_contains(val, cond.value)
      when "intersects"
        eval_intersects(val, cond.value)
      when "is_subset"
        eval_is_subset(val, cond.value)
      else
        false
      end
    end

    def eval_contains(val, target)
      target_str = fmt_v(target)
      if val.is_a?(Array)
        val.any? { |item| fmt_v(item) == target_str }
      elsif val.is_a?(String)
        val.include?(target_str)
      else
        false
      end
    end

    def eval_intersects(val, target)
      return false unless target.is_a?(Array)

      rhs = target.to_set
      if val.is_a?(Array)
        val.any? { |item| rhs.include?(fmt_v(item)) }
      else
        false
      end
    end

    def eval_is_subset(val, target)
      return false unless target.is_a?(Array)

      rhs = target.to_set
      if val.is_a?(Array)
        return true if val.empty?

        val.all? { |item| rhs.include?(fmt_v(item)) }
      else
        false
      end
    end

    # ------------------------------------------------------------------
    # Trace / explain
    # ------------------------------------------------------------------

    def trace_condition(cond, doc, result)
      ct = ConditionTrace.new(
        expr: condition_expr_string(cond),
        result: result,
        actual: resolve_actual(cond, doc)
      )
      if cond.type == ConditionType::OR
        cond.or_group.each do |sub|
          sub_res = eval_condition(sub, doc)
          ct.children << trace_condition(sub, doc, sub_res)
        end
      end
      ct
    end

    def condition_expr_string(cond)
      prefix = cond.negated ? "not " : ""
      case cond.type
      when ConditionType::FIELD
        field = cond.field
        field = "#{cond.transform}(#{cond.field})" if cond.transform && cond.transform != ""
        "#{prefix}#{field} #{cond.op} #{format_value(cond.value)}"
      when ConditionType::AGGREGATE
        "#{prefix}count(#{cond.aggregate_target}) #{cond.op} #{cond.value}"
      when ConditionType::HAS
        "#{prefix}has #{cond.field}"
      when ConditionType::ANY
        if cond.predicate
          "#{prefix}any #{cond.list_field} #{cond.predicate.op} #{format_value(cond.predicate.value)}"
        else
          "#{prefix}any #{cond.list_field} <predicate>"
        end
      when ConditionType::ALL
        if cond.predicate
          "#{prefix}all #{cond.list_field} #{cond.predicate.op} #{format_value(cond.predicate.value)}"
        else
          "#{prefix}all #{cond.list_field} <predicate>"
        end
      when ConditionType::OR
        prefix + cond.or_group.map { |sub| condition_expr_string(sub) }.join(" or ")
      when ConditionType::EXPR
        "#{prefix}#{expr_string(cond.left_expr)} #{cond.op} #{expr_string(cond.right_expr)}"
      else
        "#{prefix}<unknown>"
      end
    end

    def expr_string(expr)
      return "<nil>" if expr.nil?

      case expr.kind
      when ExprKind::FIELD
        expr.field
      when ExprKind::LITERAL
        v = expr.value
        v == v.to_i ? v.to_i.to_s : v.to_s
      when ExprKind::COUNT
        "count(#{expr.agg_target})"
      when ExprKind::LEN
        "len(#{expr.field})"
      when ExprKind::BINARY
        "#{expr_string(expr.left)} #{expr.op} #{expr_string(expr.right)}"
      else
        "<unknown>"
      end
    end

    def resolve_actual(cond, doc)
      case cond.type
      when ConditionType::FIELD
        format_actual(resolve_field(cond.field, doc))
      when ConditionType::AGGREGATE
        val = resolve_field(cond.aggregate_target, doc)
        if val.is_a?(Array)
          val.length.to_s
        elsif val.is_a?(Integer)
          val.to_s
        elsif val.is_a?(Float)
          val.to_i.to_s
        else
          "<nil>"
        end
      when ConditionType::HAS
        val = resolve_field(cond.field, doc)
        val.nil? ? "<nil>" : "exists"
      when ConditionType::ANY, ConditionType::ALL
        val = resolve_field(cond.list_field, doc)
        items = val.is_a?(Array) ? val : nil
        items.nil? ? "<nil>" : "[#{items.length} items]"
      when ConditionType::EXPR
        if cond.left_expr && cond.right_expr
          lv, lok = eval_expr(cond.left_expr, doc)
          rv, rok = eval_expr(cond.right_expr, doc)
          return "#{lv} vs #{rv}" if lok && rok
        end
        ""
      else
        ""
      end
    end

    def format_value(v)
      return "\"#{v}\"" if v.is_a?(String)

      if v.is_a?(Array) && v.all? { |x| x.is_a?(String) }
        return "[" + v.map { |x| "\"#{x}\"" }.join(", ") + "]"
      end

      fmt_v(v)
    end

    def format_actual(v)
      return "<nil>" if v.nil?

      if v.is_a?(Array)
        if v.length <= 5
          return "[" + v.map { |item| fmt_v(item) }.join(", ") + "]"
        end

        return "[#{v.length} items]"
      end
      return "\"#{v}\"" if v.is_a?(String)

      fmt_v(v)
    end

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------

    def regex_match(pattern, s)
      cache = CrowdControl::REGEX_CACHE
      if cache.key?(pattern)
        compiled = cache[pattern]
      else
        compiled =
          begin
            Regexp.new(pattern)
          rescue RegexpError
            nil
          end
        cache[pattern] = compiled
      end
      return false if compiled.nil?

      !(compiled =~ s).nil?
    end

    def glob_match(pattern, s)
      return true if pattern == "*"

      if pattern.end_with?("*") && !pattern.start_with?("*")
        return s.start_with?(pattern[0..-2])
      end
      if pattern.start_with?("*") && !pattern.end_with?("*")
        return s.end_with?(pattern[1..])
      end

      star = pattern.index("*")
      if star
        prefix = pattern[0...star]
        suffix = pattern[(star + 1)..]
        return s.start_with?(prefix) && s.end_with?(suffix)
      end

      pattern == s
    end

    def to_float(v)
      return nil if v.is_a?(TrueClass) || v.is_a?(FalseClass)
      return v.to_f if v.is_a?(Integer) || v.is_a?(Float)

      nil
    end

    def compare_values(a, op, b)
      af = to_float(a)
      bf = to_float(b)
      return false if af.nil? || bf.nil?

      compare_floats(af, op, bf)
    end

    def compare_floats(a, op, b)
      case op
      when "<"  then a < b
      when ">"  then a > b
      when "<=" then a <= b
      when ">=" then a >= b
      when "==" then a == b
      when "!=" then a != b
      else           false
      end
    end

    def apply_transform(transform, val)
      case transform
      when "lower"
        val.is_a?(String) ? val.downcase : fmt_v(val).downcase
      when "upper"
        val.is_a?(String) ? val.upcase : fmt_v(val).upcase
      when "len"
        return val.length if val.is_a?(String) || val.is_a?(Array)
        return 0 if val.nil?

        0
      else
        val
      end
    end

    # Format a value the way Go's fmt.Sprintf("%v", v) would.
    # Notably: bool -> "true"/"false", nil -> "<nil>",
    # integer floats -> "42" not "42.0".
    def fmt_v(v)
      return "<nil>" if v.nil?
      return (v ? "true" : "false") if v == true || v == false
      if v.is_a?(Float)
        return v.to_i.to_s if v == v.to_i

        return v.to_s
      end
      v.to_s
    end
  end
end
