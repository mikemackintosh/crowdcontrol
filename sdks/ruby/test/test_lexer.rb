# frozen_string_literal: true

require "minitest/autorun"
require "crowdcontrol"

class TestLexer < Minitest::Test
  include CrowdControl

  def lex(src)
    Lexer.lex(src)
  end

  def types(tokens)
    tokens.map(&:type)
  end

  def test_empty_source_yields_only_eof
    toks = lex("")
    assert_equal 1, toks.length
    assert_equal TokenType::EOF, toks[0].type
  end

  def test_whitespace_is_ignored
    toks = lex("   \n\t  ")
    assert_equal 1, toks.length
    assert_equal TokenType::EOF, toks[0].type
  end

  def test_hash_comment
    toks = lex("# line comment\nforbid")
    assert_equal [TokenType::IDENT, TokenType::EOF], types(toks)
    assert_equal "forbid", toks[0].val
  end

  def test_double_slash_comment
    toks = lex("// line comment\npermit")
    assert_equal [TokenType::IDENT, TokenType::EOF], types(toks)
    assert_equal "permit", toks[0].val
  end

  def test_simple_string_literal
    toks = lex('"hello"')
    assert_equal TokenType::STRING, toks[0].type
    assert_equal "hello", toks[0].val
  end

  def test_string_with_escape
    toks = lex('"a\\nb\\tc"')
    assert_equal "a\nb\tc", toks[0].val
  end

  def test_unknown_escape_passthrough
    toks = lex('"a\\qb"')
    assert_equal 'a\qb', toks[0].val
  end

  def test_number_integer_and_float
    toks = lex("42 3.14")
    assert_equal [TokenType::NUMBER, TokenType::NUMBER, TokenType::EOF], types(toks)
    assert_equal "42", toks[0].val
    assert_equal "3.14", toks[1].val
  end

  def test_identifier_and_keyword_share_type
    toks = lex("forbid myRule1 _x")
    assert_equal [TokenType::IDENT, TokenType::IDENT, TokenType::IDENT, TokenType::EOF], types(toks)
    assert_equal %w[forbid myRule1 _x], toks[0..2].map(&:val)
  end

  def test_two_char_operators
    toks = lex("== != <= >=")
    assert_equal(
      [TokenType::EQ, TokenType::NEQ, TokenType::LTE, TokenType::GTE, TokenType::EOF],
      types(toks)
    )
  end

  def test_single_char_operators_and_punct
    toks = lex("{}[]().,+-*/<>")
    assert_equal(
      [
        TokenType::LBRACE, TokenType::RBRACE,
        TokenType::LBRACKET, TokenType::RBRACKET,
        TokenType::LPAREN, TokenType::RPAREN,
        TokenType::DOT, TokenType::COMMA,
        TokenType::PLUS, TokenType::MINUS, TokenType::STAR, TokenType::SLASH,
        TokenType::LT, TokenType::GT,
        TokenType::EOF
      ],
      types(toks)
    )
  end

  def test_dotted_path_sequence
    toks = lex("user.name")
    assert_equal(
      [TokenType::IDENT, TokenType::DOT, TokenType::IDENT, TokenType::EOF],
      types(toks)
    )
  end

  def test_unterminated_string_raises
    assert_raises(LexError) { lex('"oops') }
  end

  def test_unknown_character_raises
    assert_raises(LexError) { lex("?") }
  end

  def test_basic_rule_tokenization
    src = <<~CC
      forbid "r1" {
        user.role == "admin"
      }
    CC
    toks = lex(src)
    tt = types(toks)
    assert_includes tt, TokenType::LBRACE
    assert_includes tt, TokenType::RBRACE
    assert_includes tt, TokenType::EQ
  end
end
