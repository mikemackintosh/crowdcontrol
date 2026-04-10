/**
 * @file Tree-sitter grammar for the CrowdControl policy language.
 * @author Mike Mackintosh
 * @license MIT
 *
 * This is the *syntactic* grammar — its job is to produce a parse
 * tree good enough for editor features (syntax highlighting, folding,
 * symbol outlining, bracket matching). It is intentionally looser
 * than the reference Go parser so that in-progress edits still
 * highlight cleanly. The authoritative parser is parser/parser.go;
 * if your editor highlights something one way but the reference
 * parser disagrees at runtime, the reference parser wins.
 */

/// <reference types="tree-sitter-cli/dsl" />

module.exports = grammar({
  name: 'crowdcontrol',

  extras: $ => [
    /\s/,
    $.comment,
  ],

  word: $ => $.identifier,

  rules: {
    // A source file is a sequence of rule blocks. Top-level whitespace
    // and comments are skipped by `extras`.
    source_file: $ => repeat($.rule),

    // rule_kind "name" { clauses }
    rule: $ => seq(
      field('kind', $.rule_kind),
      field('name', $.string),
      '{',
      repeat($._rule_clause),
      '}',
    ),

    rule_kind: _ => choice('forbid', 'warn', 'permit'),

    _rule_clause: $ => choice(
      $.metadata_clause,
      $.message_clause,
      $.unless_clause,
      $.condition,
    ),

    metadata_clause: $ => seq(
      field('key', choice('description', 'owner', 'link')),
      field('value', $.string),
    ),

    message_clause: $ => seq(
      'message',
      field('template', $.string),
    ),

    unless_clause: $ => seq(
      'unless',
      field('condition', $.condition),
    ),

    // A condition line. The grammar flattens the many variants so
    // highlighting can recognize keywords and field paths without
    // having to commit to a specific AST shape. The arithmetic form
    // subsumes aggregate checks (count(x) > N) — a generic
    // comparison between two arith_exprs covers both cases.
    condition: $ => prec.left(choice(
      $.not_condition,
      $.or_condition,
      $.has_condition,
      $.quantifier_condition,
      $.arithmetic_condition,
      $.field_condition,
    )),

    not_condition: $ => seq('not', $.condition),

    // a OR b [OR c ...]
    or_condition: $ => prec.left(1, seq(
      $._simple_condition,
      repeat1(seq('or', $._simple_condition)),
    )),

    _simple_condition: $ => choice(
      $.has_condition,
      $.quantifier_condition,
      $.arithmetic_condition,
      $.field_condition,
    ),

    has_condition: $ => seq('has', field('path', $.field_path)),

    quantifier_condition: $ => seq(
      field('quantifier', choice('any', 'all')),
      field('list', $.field_path),
      $.predicate,
    ),

    // Predicate is always (cmp_op, value). The cmp_op rule already
    // covers matches / matches_regex / contains / intersects /
    // is_subset / in, so we don't need separate branches here.
    predicate: $ => seq($.cmp_op, $._value),

    call_expression: $ => seq(
      field('function', choice('count', 'len', 'lower', 'upper')),
      '(',
      $.field_path,
      ')',
    ),

    // Arithmetic comparisons: expr op expr where either side can be
    // a number, field, count(), len(), or a binary op. Higher prec
    // than field_condition so "count(x) > 5" is recognized as an
    // arithmetic comparison (covering the former aggregate case).
    arithmetic_condition: $ => prec(3, seq(
      $._arith_expr,
      $.cmp_op,
      $._arith_expr,
    )),

    _arith_expr: $ => choice(
      $.number,
      $.field_path,
      $.call_expression,
      $.binary_expression,
    ),

    binary_expression: $ => choice(
      prec.left(4, seq($._arith_expr, choice('+', '-'), $._arith_expr)),
      prec.left(5, seq($._arith_expr, choice('*', '/'), $._arith_expr)),
    ),

    field_condition: $ => prec(1, seq(
      field('lhs', choice($.field_path, $.call_expression)),
      $.cmp_op,
      field('rhs', $._value),
    )),

    cmp_op: _ => choice(
      '==', '!=', '<=', '>=', '<', '>',
      'in', 'matches', 'matches_regex',
      'contains', 'intersects', 'is_subset',
    ),

    field_path: $ => seq(
      $.identifier,
      repeat(seq('.', $.identifier)),
    ),

    _value: $ => choice(
      $.string,
      $.number,
      $.boolean,
      $.list,
      $.field_path,
    ),

    list: $ => seq(
      '[',
      optional(seq($._value, repeat(seq(',', $._value)), optional(','))),
      ']',
    ),

    boolean: _ => choice('true', 'false'),

    // Tokens ----------------------------------------------------------
    string: _ => token(seq(
      '"',
      repeat(choice(
        /[^"\\\n]/,
        /\\./,
      )),
      '"',
    )),

    number: _ => /\d+(\.\d+)?/,

    // Identifiers must not clash with the keyword set. tree-sitter
    // handles this automatically via the `word` rule above: a token
    // matching $.identifier that happens to be a keyword will be
    // re-classified as the keyword.
    identifier: _ => /[a-zA-Z_][a-zA-Z0-9_]*/,

    comment: _ => token(choice(
      seq('#', /[^\n]*/),
      seq('//', /[^\n]*/),
    )),
  },
});
