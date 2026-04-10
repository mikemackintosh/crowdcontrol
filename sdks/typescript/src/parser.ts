/**
 * Parser for CrowdControl policy source.
 *
 * Ports github.com/mikemackintosh/crowdcontrol/parser/parser.go to TypeScript.
 */

import {
  LexError,
  Token,
  TokenType,
  lex,
  tokenDisplay,
  tokenName,
} from "./lexer.js";
import {
  Condition,
  ConditionType,
  Expr,
  ExprKind,
  Policy,
  Rule,
  newCondition,
  newExpr,
  newPolicy,
  newRule,
} from "./types.js";

export class ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ParseError";
  }
}

/** Parse CrowdControl source into a Policy AST. */
export function parse(source: string): Policy {
  let tokens: Token[];
  try {
    tokens = lex(source);
  } catch (e) {
    if (e instanceof LexError) {
      throw new ParseError(e.message);
    }
    throw e;
  }
  const p = new Parser(tokens);
  return p.parsePolicy();
}

const COMPARISON_TOKENS = new Set<TokenType>([
  TokenType.EQ,
  TokenType.NEQ,
  TokenType.LT,
  TokenType.GT,
  TokenType.LTE,
  TokenType.GTE,
]);

const ARITH_TOKENS = new Set<TokenType>([
  TokenType.PLUS,
  TokenType.MINUS,
  TokenType.STAR,
  TokenType.SLASH,
]);

class Parser {
  private tokens: Token[];
  private pos = 0;

  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }

  // ----- top level -------------------------------------------------------

  parsePolicy(): Policy {
    const policy = newPolicy();
    while (!this.atEnd()) {
      policy.rules.push(this.parseRule());
    }
    return policy;
  }

  private parseRule(): Rule {
    const kindTok = this.advance();
    if (kindTok.type !== TokenType.IDENT) {
      throw this.errorf(`expected forbid, warn, or permit, got ${tokenDisplay(kindTok)}`);
    }
    const kind = kindTok.val;
    if (kind !== "forbid" && kind !== "warn" && kind !== "permit") {
      throw this.errorf(`expected forbid, warn, or permit, got ${JSON.stringify(kind)}`);
    }

    const nameTok = this.advance();
    if (nameTok.type !== TokenType.STRING) {
      throw this.errorf(`expected rule name string, got ${tokenDisplay(nameTok)}`);
    }

    this.expect(TokenType.LBRACE);

    const rule = newRule({ kind, name: nameTok.val });

    while (!this.check(TokenType.RBRACE) && !this.atEnd()) {
      this.parseClause(rule);
    }

    this.expect(TokenType.RBRACE);
    return rule;
  }

  private parseClause(rule: Rule): void {
    const tok = this.peek();
    const val = tok.val;

    if (val === "unless") {
      this.parseUnless(rule);
      return;
    }
    if (val === "message") {
      this.parseMessage(rule);
      return;
    }
    if (val === "description" || val === "owner" || val === "link") {
      this.parseMetadata(rule, val);
      return;
    }

    let cond: Condition;
    if (val === "not") {
      cond = this.parseNegatedCondition();
    } else if (val === "any" || val === "all") {
      cond = this.parseQuantifier();
    } else if (val === "has") {
      cond = this.parseHasCondition();
    } else if (val === "count") {
      cond = this.parseAggregateCondition();
    } else if (val === "lower" || val === "upper" || val === "len") {
      cond = this.parseTransformCondition();
    } else {
      cond = this.parseFieldCond();
    }

    rule.conditions.push(this.wrapOr(cond));
  }

  // ----- or-chaining -----------------------------------------------------

  private wrapOr(first: Condition): Condition {
    if (!this.checkIdent("or")) {
      return first;
    }
    const group: Condition[] = [first];
    while (this.checkIdent("or")) {
      this.advance(); // consume "or"
      try {
        const cond = this.parseSingleCondition();
        group.push(cond);
      } catch (e) {
        if (e instanceof ParseError) {
          break;
        }
        throw e;
      }
    }
    return newCondition({ type: ConditionType.OR, orGroup: group });
  }

  private parseSingleCondition(): Condition {
    const val = this.peek().val;
    if (val === "not") return this.parseNegatedCondition();
    if (val === "any" || val === "all") return this.parseQuantifier();
    if (val === "has") return this.parseHasCondition();
    if (val === "count") return this.parseAggregateCondition();
    if (val === "lower" || val === "upper" || val === "len") {
      return this.parseTransformCondition();
    }
    return this.parseFieldCond();
  }

  // ----- individual conditions -------------------------------------------

  private parseNegatedCondition(): Condition {
    this.advance(); // consume "not"
    const cond = this.parseSingleCondition();
    cond.negated = !cond.negated;
    return cond;
  }

  private parseHasCondition(): Condition {
    this.advance(); // consume "has"
    const field = this.parseDottedPath();
    return newCondition({ type: ConditionType.HAS, field });
  }

  private parseQuantifier(): Condition {
    const quantTok = this.advance(); // "any" or "all"
    const listField = this.parseDottedPath();
    const predicate = this.parseElementPredicate();
    const condType =
      quantTok.val === "all" ? ConditionType.ALL : ConditionType.ANY;
    return newCondition({
      type: condType,
      quantifier: quantTok.val,
      listField,
      predicate,
    });
  }

  private parseElementPredicate(): Condition {
    const tok = this.peek();

    if (tok.type === TokenType.IDENT && tok.val === "in") {
      this.advance();
      const nxt = this.peek();
      if (nxt.type === TokenType.LBRACKET) {
        const vals = this.parseStringList();
        return newCondition({ type: ConditionType.FIELD, op: "in", value: vals });
      }
      throw this.errorf(`expected list after 'in', got ${tokenDisplay(nxt)}`);
    }

    if (
      tok.type === TokenType.IDENT &&
      (tok.val === "matches" || tok.val === "matches_regex")
    ) {
      const op = tok.val;
      this.advance();
      const valTok = this.advance();
      if (valTok.type !== TokenType.STRING) {
        throw this.errorf(`${op} expects a string pattern, got ${tokenDisplay(valTok)}`);
      }
      return newCondition({ type: ConditionType.FIELD, op, value: valTok.val });
    }

    if (tok.type === TokenType.IDENT && tok.val === "contains") {
      this.advance();
      const val = this.parseValue();
      return newCondition({ type: ConditionType.FIELD, op: "contains", value: val });
    }

    const opTok = this.advance();
    if (!COMPARISON_TOKENS.has(opTok.type)) {
      throw this.errorf(
        `expected operator in quantifier predicate, got ${tokenDisplay(opTok)}`,
      );
    }
    const val = this.parseValue();
    return newCondition({ type: ConditionType.FIELD, op: opTok.val, value: val });
  }

  private parseFieldCond(): Condition {
    const field = this.parseDottedPath();

    if (this.isArithOp()) {
      const left = newExpr({ kind: ExprKind.FIELD, field });
      return this.parseExprConditionFromLeft(left);
    }

    const opTok = this.advance();
    let op = opTok.val;

    if (!COMPARISON_TOKENS.has(opTok.type)) {
      if (
        opTok.type === TokenType.IDENT &&
        (op === "in" ||
          op === "matches" ||
          op === "matches_regex" ||
          op === "contains" ||
          op === "intersects" ||
          op === "is_subset")
      ) {
        // keep op
      } else {
        throw this.errorf(`expected operator, got ${tokenDisplay(opTok)}`);
      }
    }

    const cond = newCondition({ type: ConditionType.FIELD, field, op });

    if (op === "in" || op === "intersects" || op === "is_subset") {
      cond.value = this.parseStringList();
    } else if (op === "matches" || op === "matches_regex") {
      const valTok = this.advance();
      if (valTok.type !== TokenType.STRING) {
        throw this.errorf(`${op} expects a string pattern, got ${tokenDisplay(valTok)}`);
      }
      cond.value = valTok.val;
    } else {
      cond.value = this.parseValue();
    }

    return cond;
  }

  private isArithOp(): boolean {
    return ARITH_TOKENS.has(this.peek().type);
  }

  private parseExprConditionFromLeft(left: Expr): Condition {
    const leftExpr = this.parseArithExprFrom(left);

    const opTok = this.advance();
    if (!COMPARISON_TOKENS.has(opTok.type)) {
      throw this.errorf(
        `expected comparison operator in expression, got ${tokenDisplay(opTok)}`,
      );
    }

    const rightExpr = this.parseArithExpr();
    return newCondition({
      type: ConditionType.EXPR,
      op: opTok.val,
      leftExpr,
      rightExpr,
    });
  }

  private parseArithExpr(): Expr {
    const left = this.parseExprTerm();
    return this.parseArithExprFrom(left);
  }

  private parseArithExprFrom(left: Expr): Expr {
    let current = left;
    while (this.isArithOp()) {
      const opTok = this.advance();
      const right = this.parseExprTerm();
      current = newExpr({
        kind: ExprKind.BINARY,
        op: opTok.val,
        left: current,
        right,
      });
    }
    return current;
  }

  private parseExprTerm(): Expr {
    const tok = this.peek();

    if (tok.type === TokenType.NUMBER) {
      this.advance();
      const num = Number(tok.val);
      if (Number.isNaN(num)) {
        throw this.errorf(`invalid number: ${tok.val}`);
      }
      return newExpr({ kind: ExprKind.LITERAL, value: num });
    }

    if (tok.type === TokenType.IDENT && (tok.val === "count" || tok.val === "len")) {
      const funcName = tok.val;
      this.advance();
      this.expect(TokenType.LPAREN);
      const path = this.parseDottedPath();
      this.expect(TokenType.RPAREN);
      if (funcName === "count") {
        return newExpr({ kind: ExprKind.COUNT, aggTarget: path });
      }
      return newExpr({ kind: ExprKind.LEN, field: path, transform: "len" });
    }

    if (tok.type === TokenType.IDENT) {
      const path = this.parseDottedPath();
      return newExpr({ kind: ExprKind.FIELD, field: path });
    }

    throw this.errorf(
      `expected number, field, count(), or len() in expression, got ${tokenDisplay(tok)}`,
    );
  }

  private parseUnless(rule: Rule): void {
    this.advance(); // consume "unless"
    const val = this.peek().val;
    let cond: Condition;
    if (val === "not") {
      cond = this.parseNegatedCondition();
    } else if (val === "any" || val === "all") {
      cond = this.parseQuantifier();
    } else if (val === "has") {
      cond = this.parseHasCondition();
    } else if (val === "lower" || val === "upper" || val === "len") {
      cond = this.parseTransformCondition();
    } else if (val === "count") {
      cond = this.parseAggregateCondition();
    } else {
      cond = this.parseFieldCond();
    }
    rule.unlesses.push(cond);
  }

  private parseTransformCondition(): Condition {
    const funcTok = this.advance();
    this.expect(TokenType.LPAREN);
    const field = this.parseDottedPath();
    this.expect(TokenType.RPAREN);

    if (funcTok.val === "len" && this.isArithOp()) {
      const left = newExpr({ kind: ExprKind.LEN, field, transform: "len" });
      return this.parseExprConditionFromLeft(left);
    }

    const opTok = this.advance();
    let op = opTok.val;
    if (!COMPARISON_TOKENS.has(opTok.type)) {
      if (
        opTok.type === TokenType.IDENT &&
        (op === "in" || op === "matches" || op === "matches_regex" || op === "contains")
      ) {
        // ok
      } else {
        throw this.errorf(
          `expected operator after ${funcTok.val}(), got ${tokenDisplay(opTok)}`,
        );
      }
    }

    const cond = newCondition({
      type: ConditionType.FIELD,
      field,
      op,
      transform: funcTok.val,
    });

    if (op === "in") {
      cond.value = this.parseStringList();
    } else if (op === "matches" || op === "matches_regex") {
      const valTok = this.advance();
      if (valTok.type !== TokenType.STRING) {
        throw this.errorf(`${op} expects a string pattern, got ${tokenDisplay(valTok)}`);
      }
      cond.value = valTok.val;
    } else {
      cond.value = this.parseValue();
    }
    return cond;
  }

  private parseAggregateCondition(): Condition {
    this.advance(); // consume "count"
    this.expect(TokenType.LPAREN);
    const target = this.parseDottedPath();
    this.expect(TokenType.RPAREN);

    if (this.isArithOp()) {
      const left = newExpr({ kind: ExprKind.COUNT, aggTarget: target });
      return this.parseExprConditionFromLeft(left);
    }

    const opTok = this.advance();
    if (!COMPARISON_TOKENS.has(opTok.type)) {
      throw this.errorf(
        `expected comparison operator after count(), got ${tokenDisplay(opTok)}`,
      );
    }

    const valTok = this.advance();
    if (valTok.type !== TokenType.NUMBER) {
      throw this.errorf(`expected number after operator, got ${tokenDisplay(valTok)}`);
    }
    const num = Number.parseInt(valTok.val, 10);
    if (Number.isNaN(num)) {
      throw this.errorf(`invalid number: ${valTok.val}`);
    }

    return newCondition({
      type: ConditionType.AGGREGATE,
      aggregateFunc: "count",
      aggregateTarget: target,
      op: opTok.val,
      value: num,
    });
  }

  private parseMessage(rule: Rule): void {
    this.advance();
    const msgTok = this.advance();
    if (msgTok.type !== TokenType.STRING) {
      throw this.errorf(`expected message string, got ${tokenDisplay(msgTok)}`);
    }
    rule.message = msgTok.val;
  }

  private parseMetadata(rule: Rule, keyword: string): void {
    this.advance();
    const valTok = this.advance();
    if (valTok.type !== TokenType.STRING) {
      throw this.errorf(`expected string after ${keyword}, got ${tokenDisplay(valTok)}`);
    }
    if (keyword === "description") rule.description = valTok.val;
    else if (keyword === "owner") rule.owner = valTok.val;
    else if (keyword === "link") rule.link = valTok.val;
  }

  // ----- helpers ---------------------------------------------------------

  private parseDottedPath(): string {
    const tok = this.advance();
    if (tok.type !== TokenType.IDENT) {
      throw this.errorf(`expected identifier, got ${tokenDisplay(tok)}`);
    }
    const parts: string[] = [tok.val];
    while (this.check(TokenType.DOT)) {
      this.advance();
      const nxt = this.advance();
      if (nxt.type !== TokenType.IDENT) {
        throw this.errorf(`expected identifier after '.', got ${tokenDisplay(nxt)}`);
      }
      parts.push(nxt.val);
    }
    return parts.join(".");
  }

  private parseStringList(): string[] {
    this.expect(TokenType.LBRACKET);
    const vals: string[] = [];
    while (!this.check(TokenType.RBRACKET) && !this.atEnd()) {
      const tok = this.advance();
      if (tok.type !== TokenType.STRING) {
        throw this.errorf(`expected string in list, got ${tokenDisplay(tok)}`);
      }
      vals.push(tok.val);
      if (this.check(TokenType.COMMA)) {
        this.advance();
      }
    }
    this.expect(TokenType.RBRACKET);
    return vals;
  }

  private parseValue(): unknown {
    const tok = this.advance();
    if (tok.type === TokenType.STRING) return tok.val;
    if (tok.type === TokenType.NUMBER) {
      // Preserve integer-vs-float the way the Python port does: ints parse
      // to JS number (integer), floats also parse to number. Aggregate
      // count() target will re-parse as int. For equality via _fmtV, ints
      // print without decimal which is what we want.
      const num = Number(tok.val);
      if (Number.isNaN(num)) {
        throw this.errorf(`invalid number: ${tok.val}`);
      }
      return num;
    }
    if (tok.type === TokenType.IDENT) {
      if (tok.val === "true") return true;
      if (tok.val === "false") return false;
      throw this.errorf(`unexpected identifier ${JSON.stringify(tok.val)} in value position`);
    }
    throw this.errorf(`expected value, got ${tokenDisplay(tok)}`);
  }

  private peek(): Token {
    if (this.pos >= this.tokens.length) {
      return { type: TokenType.EOF, val: "", line: 0, col: 0 };
    }
    return this.tokens[this.pos]!;
  }

  private advance(): Token {
    const tok = this.peek();
    if (tok.type !== TokenType.EOF) {
      this.pos++;
    }
    return tok;
  }

  private check(t: TokenType): boolean {
    return this.peek().type === t;
  }

  private checkIdent(val: string): boolean {
    const tok = this.peek();
    return tok.type === TokenType.IDENT && tok.val === val;
  }

  private atEnd(): boolean {
    return this.peek().type === TokenType.EOF;
  }

  private expect(t: TokenType): Token {
    const tok = this.advance();
    if (tok.type !== t) {
      throw this.errorf(`expected ${tokenName(t)}, got ${tokenDisplay(tok)}`);
    }
    return tok;
  }

  private errorf(msg: string): ParseError {
    const tok = this.peek();
    return new ParseError(`line ${tok.line} col ${tok.col}: ${msg}`);
  }
}
