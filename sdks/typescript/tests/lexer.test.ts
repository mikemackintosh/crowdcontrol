import { test } from "node:test";
import assert from "node:assert/strict";

import { lex, TokenType, LexError } from "../src/lexer.js";

test("lex: empty input yields single EOF", () => {
  const toks = lex("");
  assert.equal(toks.length, 1);
  assert.equal(toks[0]!.type, TokenType.EOF);
});

test("lex: whitespace and comments are skipped", () => {
  const toks = lex("  # a comment\n// another\n  \t\n");
  assert.equal(toks.length, 1);
  assert.equal(toks[0]!.type, TokenType.EOF);
});

test("lex: identifiers and keywords", () => {
  const toks = lex("forbid warn permit foo_bar BAZ");
  assert.equal(toks[0]!.type, TokenType.IDENT);
  assert.equal(toks[0]!.val, "forbid");
  assert.equal(toks[1]!.val, "warn");
  assert.equal(toks[2]!.val, "permit");
  assert.equal(toks[3]!.val, "foo_bar");
  assert.equal(toks[4]!.val, "BAZ");
});

test("lex: string with escapes", () => {
  const toks = lex('"hello \\"world\\" \\n\\t\\\\"');
  assert.equal(toks[0]!.type, TokenType.STRING);
  assert.equal(toks[0]!.val, 'hello "world" \n\t\\');
});

test("lex: unknown escape passes through literally", () => {
  const toks = lex('"a\\qb"');
  assert.equal(toks[0]!.val, "a\\qb");
});

test("lex: unterminated string throws", () => {
  assert.throws(() => lex('"oops'), LexError);
});

test("lex: numbers integer and float", () => {
  const toks = lex("42 3.14 100");
  assert.equal(toks[0]!.type, TokenType.NUMBER);
  assert.equal(toks[0]!.val, "42");
  assert.equal(toks[1]!.val, "3.14");
  assert.equal(toks[2]!.val, "100");
});

test("lex: two-character operators", () => {
  const toks = lex("== != <= >=");
  assert.equal(toks[0]!.type, TokenType.EQ);
  assert.equal(toks[1]!.type, TokenType.NEQ);
  assert.equal(toks[2]!.type, TokenType.LTE);
  assert.equal(toks[3]!.type, TokenType.GTE);
});

test("lex: single-character punctuation", () => {
  const toks = lex("{}[](),.<>+-*/");
  const kinds = toks.slice(0, -1).map((t) => t.type);
  assert.deepEqual(kinds, [
    TokenType.LBRACE,
    TokenType.RBRACE,
    TokenType.LBRACKET,
    TokenType.RBRACKET,
    TokenType.LPAREN,
    TokenType.RPAREN,
    TokenType.COMMA,
    TokenType.DOT,
    TokenType.LT,
    TokenType.GT,
    TokenType.PLUS,
    TokenType.MINUS,
    TokenType.STAR,
    TokenType.SLASH,
  ]);
});

test("lex: dotted path", () => {
  const toks = lex("user.role.name");
  assert.equal(toks[0]!.val, "user");
  assert.equal(toks[1]!.type, TokenType.DOT);
  assert.equal(toks[2]!.val, "role");
  assert.equal(toks[3]!.type, TokenType.DOT);
  assert.equal(toks[4]!.val, "name");
});

test("lex: unexpected character throws", () => {
  assert.throws(() => lex("@"), LexError);
});

test("lex: line/column tracking across newlines", () => {
  const toks = lex("a\n  b");
  assert.equal(toks[0]!.line, 1);
  assert.equal(toks[1]!.line, 2);
  assert.equal(toks[1]!.col, 3);
});

test("lex: complete rule tokenizes", () => {
  const src = 'forbid "r" { user.role == "admin" }';
  const toks = lex(src);
  const types = toks.map((t) => t.type);
  assert.deepEqual(types, [
    TokenType.IDENT,
    TokenType.STRING,
    TokenType.LBRACE,
    TokenType.IDENT,
    TokenType.DOT,
    TokenType.IDENT,
    TokenType.EQ,
    TokenType.STRING,
    TokenType.RBRACE,
    TokenType.EOF,
  ]);
});
