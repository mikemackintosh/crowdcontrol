# frozen_string_literal: true

require_relative "lexer"
require_relative "types"

module CrowdControl
  # Raised when the parser encounters invalid syntax.
  class ParseError < StandardError; end

  # Parser — builds an AST from a token stream.
  class Parser
    COMPARISON_TOKEN_TYPES = [
      TokenType::EQ, TokenType::NEQ, TokenType::LT,
      TokenType::GT, TokenType::LTE, TokenType::GTE
    ].freeze

    KEYWORD_OPS = %w[in matches matches_regex contains intersects is_subset].freeze

    def self.parse(source)
      begin
        tokens = Lexer.lex(source)
      rescue LexError => e
        raise ParseError, e.message
      end
      new(tokens).parse_policy
    end

    def initialize(tokens)
      @tokens = tokens
      @pos    = 0
    end

    def parse_policy
      policy = Policy.new
      policy.rules << parse_rule until at_end?
      policy
    end

    private

    def parse_rule
      kind_tok = advance
      raise errorf("expected forbid, warn, or permit, got #{kind_tok}") if kind_tok.type != TokenType::IDENT

      kind = kind_tok.val
      unless %w[forbid warn permit].include?(kind)
        raise errorf("expected forbid, warn, or permit, got #{kind.inspect}")
      end

      name_tok = advance
      raise errorf("expected rule name string, got #{name_tok}") if name_tok.type != TokenType::STRING

      expect(TokenType::LBRACE)

      rule = Rule.new(kind: kind, name: name_tok.val)

      parse_clause(rule) while !check(TokenType::RBRACE) && !at_end?

      expect(TokenType::RBRACE)
      rule
    end

    def parse_clause(rule)
      tok = peek
      val = tok.val

      if val == "unless"
        parse_unless(rule)
        return
      end
      if val == "message"
        parse_message(rule)
        return
      end
      if %w[description owner link].include?(val)
        parse_metadata(rule, val)
        return
      end

      cond =
        case val
        when "not"              then parse_negated_condition
        when "any", "all"       then parse_quantifier
        when "has"              then parse_has_condition
        when "count"            then parse_aggregate_condition
        when "lower", "upper", "len"
          parse_transform_condition
        else
          parse_field_cond
        end

      rule.conditions << wrap_or(cond)
    end

    # ----- or-chaining ----------------------------------------------

    def wrap_or(first)
      return first unless check_ident("or")

      group = [first]
      while check_ident("or")
        advance # consume 'or'
        begin
          cond = parse_single_condition
        rescue ParseError
          break
        end
        group << cond
      end
      Condition.new(type: ConditionType::OR, or_group: group)
    end

    def parse_single_condition
      val = peek.val
      case val
      when "not"              then parse_negated_condition
      when "any", "all"       then parse_quantifier
      when "has"              then parse_has_condition
      when "count"            then parse_aggregate_condition
      when "lower", "upper", "len"
        parse_transform_condition
      else
        parse_field_cond
      end
    end

    # ----- individual conditions ------------------------------------

    def parse_negated_condition
      advance # consume 'not'
      cond = parse_single_condition
      cond.negated = !cond.negated
      cond
    end

    def parse_has_condition
      advance # consume 'has'
      field = parse_dotted_path
      Condition.new(type: ConditionType::HAS, field: field)
    end

    def parse_quantifier
      quant_tok  = advance # consume 'any' or 'all'
      list_field = parse_dotted_path
      predicate  = parse_element_predicate
      cond_type  = quant_tok.val == "all" ? ConditionType::ALL : ConditionType::ANY
      Condition.new(
        type: cond_type,
        quantifier: quant_tok.val,
        list_field: list_field,
        predicate: predicate
      )
    end

    def parse_element_predicate
      tok = peek

      if tok.type == TokenType::IDENT && tok.val == "in"
        advance
        nxt = peek
        raise errorf("expected list after 'in', got #{nxt}") unless nxt.type == TokenType::LBRACKET

        vals = parse_string_list
        return Condition.new(type: ConditionType::FIELD, op: "in", value: vals)
      end

      if tok.type == TokenType::IDENT && %w[matches matches_regex].include?(tok.val)
        op = tok.val
        advance
        val_tok = advance
        raise errorf("#{op} expects a string pattern, got #{val_tok}") if val_tok.type != TokenType::STRING

        return Condition.new(type: ConditionType::FIELD, op: op, value: val_tok.val)
      end

      if tok.type == TokenType::IDENT && tok.val == "contains"
        advance
        val = parse_value
        return Condition.new(type: ConditionType::FIELD, op: "contains", value: val)
      end

      op_tok = advance
      unless COMPARISON_TOKEN_TYPES.include?(op_tok.type)
        raise errorf("expected operator in quantifier predicate, got #{op_tok}")
      end

      val = parse_value
      Condition.new(type: ConditionType::FIELD, op: op_tok.val, value: val)
    end

    def parse_field_cond
      field = parse_dotted_path

      if arith_op?
        left = Expr.new(kind: ExprKind::FIELD, field: field)
        return parse_expr_condition_from_left(left)
      end

      op_tok = advance
      op     = op_tok.val

      unless COMPARISON_TOKEN_TYPES.include?(op_tok.type)
        if op_tok.type == TokenType::IDENT && KEYWORD_OPS.include?(op_tok.val)
          op = op_tok.val
        else
          raise errorf("expected operator, got #{op_tok}")
        end
      end

      cond = Condition.new(type: ConditionType::FIELD, field: field, op: op)

      case op
      when "in", "intersects", "is_subset"
        cond.value = parse_string_list
      when "matches", "matches_regex"
        val_tok = advance
        raise errorf("#{op} expects a string pattern, got #{val_tok}") if val_tok.type != TokenType::STRING

        cond.value = val_tok.val
      else
        cond.value = parse_value
      end

      cond
    end

    def arith_op?
      t = peek.type
      t == TokenType::PLUS || t == TokenType::MINUS ||
        t == TokenType::STAR || t == TokenType::SLASH
    end

    def parse_expr_condition_from_left(left)
      expr = parse_arith_expr_from(left)

      op_tok = advance
      unless COMPARISON_TOKEN_TYPES.include?(op_tok.type)
        raise errorf("expected comparison operator in expression, got #{op_tok}")
      end

      right = parse_arith_expr
      Condition.new(
        type: ConditionType::EXPR,
        op: op_tok.val,
        left_expr: expr,
        right_expr: right
      )
    end

    def parse_arith_expr
      left = parse_expr_term
      parse_arith_expr_from(left)
    end

    def parse_arith_expr_from(left)
      while arith_op?
        op_tok = advance
        right  = parse_expr_term
        left = Expr.new(kind: ExprKind::BINARY, op: op_tok.val, left: left, right: right)
      end
      left
    end

    def parse_expr_term
      tok = peek

      if tok.type == TokenType::NUMBER
        advance
        begin
          return Expr.new(kind: ExprKind::LITERAL, value: Float(tok.val))
        rescue ArgumentError => e
          raise errorf("invalid number: #{tok.val} (#{e.message})")
        end
      end

      if tok.type == TokenType::IDENT && %w[count len].include?(tok.val)
        func_name = tok.val
        advance
        expect(TokenType::LPAREN)
        path = parse_dotted_path
        expect(TokenType::RPAREN)
        return Expr.new(kind: ExprKind::COUNT, agg_target: path) if func_name == "count"

        return Expr.new(kind: ExprKind::LEN, field: path, transform: "len")
      end

      if tok.type == TokenType::IDENT
        path = parse_dotted_path
        return Expr.new(kind: ExprKind::FIELD, field: path)
      end

      raise errorf("expected number, field, count(), or len() in expression, got #{tok}")
    end

    def parse_unless(rule)
      advance # consume 'unless'
      val = peek.val
      cond =
        case val
        when "not"              then parse_negated_condition
        when "any", "all"       then parse_quantifier
        when "has"              then parse_has_condition
        when "lower", "upper", "len"
          parse_transform_condition
        when "count"            then parse_aggregate_condition
        else                         parse_field_cond
        end
      rule.unlesses << cond
    end

    def parse_transform_condition
      func_tok = advance
      expect(TokenType::LPAREN)
      field = parse_dotted_path
      expect(TokenType::RPAREN)

      if func_tok.val == "len" && arith_op?
        left = Expr.new(kind: ExprKind::LEN, field: field, transform: "len")
        return parse_expr_condition_from_left(left)
      end

      op_tok = advance
      op     = op_tok.val
      unless COMPARISON_TOKEN_TYPES.include?(op_tok.type)
        if op_tok.type == TokenType::IDENT && %w[in matches matches_regex contains].include?(op_tok.val)
          op = op_tok.val
        else
          raise errorf("expected operator after #{func_tok.val}(), got #{op_tok}")
        end
      end

      cond = Condition.new(type: ConditionType::FIELD, field: field, op: op, transform: func_tok.val)

      case op
      when "in"
        cond.value = parse_string_list
      when "matches", "matches_regex"
        val_tok = advance
        raise errorf("#{op} expects a string pattern, got #{val_tok}") if val_tok.type != TokenType::STRING

        cond.value = val_tok.val
      else
        cond.value = parse_value
      end
      cond
    end

    def parse_aggregate_condition
      advance # consume 'count'
      expect(TokenType::LPAREN)
      target = parse_dotted_path
      expect(TokenType::RPAREN)

      if arith_op?
        left = Expr.new(kind: ExprKind::COUNT, agg_target: target)
        return parse_expr_condition_from_left(left)
      end

      op_tok = advance
      unless COMPARISON_TOKEN_TYPES.include?(op_tok.type)
        raise errorf("expected comparison operator after count(), got #{op_tok}")
      end

      val_tok = advance
      raise errorf("expected number after operator, got #{val_tok}") if val_tok.type != TokenType::NUMBER

      num =
        begin
          Integer(val_tok.val)
        rescue ArgumentError
          begin
            Float(val_tok.val).to_i
          rescue ArgumentError => e
            raise errorf("invalid number: #{val_tok.val} (#{e.message})")
          end
        end

      Condition.new(
        type: ConditionType::AGGREGATE,
        aggregate_func: "count",
        aggregate_target: target,
        op: op_tok.val,
        value: num
      )
    end

    def parse_message(rule)
      advance
      msg_tok = advance
      raise errorf("expected message string, got #{msg_tok}") if msg_tok.type != TokenType::STRING

      rule.message = msg_tok.val
    end

    def parse_metadata(rule, keyword)
      advance
      val_tok = advance
      raise errorf("expected string after #{keyword}, got #{val_tok}") if val_tok.type != TokenType::STRING

      case keyword
      when "description" then rule.description = val_tok.val
      when "owner"       then rule.owner       = val_tok.val
      when "link"        then rule.link        = val_tok.val
      end
    end

    # ----- helpers --------------------------------------------------

    def parse_dotted_path
      tok = advance
      raise errorf("expected identifier, got #{tok}") if tok.type != TokenType::IDENT

      parts = [tok.val]
      while check(TokenType::DOT)
        advance
        nxt = advance
        raise errorf("expected identifier after '.', got #{nxt}") if nxt.type != TokenType::IDENT

        parts << nxt.val
      end
      parts.join(".")
    end

    def parse_string_list
      expect(TokenType::LBRACKET)
      vals = []
      until check(TokenType::RBRACKET) || at_end?
        tok = advance
        raise errorf("expected string in list, got #{tok}") if tok.type != TokenType::STRING

        vals << tok.val
        advance if check(TokenType::COMMA)
      end
      expect(TokenType::RBRACKET)
      vals
    end

    def parse_value
      tok = advance
      case tok.type
      when TokenType::STRING
        return tok.val
      when TokenType::NUMBER
        begin
          return Integer(tok.val)
        rescue ArgumentError
          begin
            return Float(tok.val)
          rescue ArgumentError => e
            raise errorf("invalid number: #{tok.val} (#{e.message})")
          end
        end
      when TokenType::IDENT
        return true  if tok.val == "true"
        return false if tok.val == "false"

        raise errorf("unexpected identifier #{tok.val.inspect} in value position")
      end
      raise errorf("expected value, got #{tok}")
    end

    def peek
      return Token.new(TokenType::EOF) if @pos >= @tokens.length

      @tokens[@pos]
    end

    def advance
      tok = peek
      @pos += 1 if tok.type != TokenType::EOF
      tok
    end

    def check(type)
      peek.type == type
    end

    def check_ident(val)
      tok = peek
      tok.type == TokenType::IDENT && tok.val == val
    end

    def at_end?
      peek.type == TokenType::EOF
    end

    def expect(type)
      tok = advance
      raise errorf("expected #{type}, got #{tok}") if tok.type != type

      tok
    end

    def errorf(msg)
      tok = peek
      ParseError.new("line #{tok.line} col #{tok.col}: #{msg}")
    end
  end
end
