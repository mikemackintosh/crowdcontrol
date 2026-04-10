import { test } from "node:test";
import assert from "node:assert/strict";

import { parse, ParseError } from "../src/parser.js";
import { ConditionType, ExprKind } from "../src/types.js";

test("parse: empty source yields empty policy", () => {
  const p = parse("");
  assert.equal(p.rules.length, 0);
});

test("parse: basic forbid rule", () => {
  const p = parse('forbid "no-public" { resource.acl == "public-read" message "bad" }');
  assert.equal(p.rules.length, 1);
  const r = p.rules[0]!;
  assert.equal(r.kind, "forbid");
  assert.equal(r.name, "no-public");
  assert.equal(r.conditions.length, 1);
  assert.equal(r.message, "bad");
  const c = r.conditions[0]!;
  assert.equal(c.type, ConditionType.FIELD);
  assert.equal(c.field, "resource.acl");
  assert.equal(c.op, "==");
  assert.equal(c.value, "public-read");
});

test("parse: permit and warn rules", () => {
  const p = parse('permit "p" { a == 1 } warn "w" { b == 2 }');
  assert.equal(p.rules[0]!.kind, "permit");
  assert.equal(p.rules[1]!.kind, "warn");
});

test("parse: metadata clauses", () => {
  const p = parse(
    'forbid "r" { description "d" owner "o" link "l" a == 1 message "m" }',
  );
  const r = p.rules[0]!;
  assert.equal(r.description, "d");
  assert.equal(r.owner, "o");
  assert.equal(r.link, "l");
  assert.equal(r.message, "m");
});

test("parse: unless clause", () => {
  const p = parse('forbid "r" { a == 1 unless b == 2 }');
  const r = p.rules[0]!;
  assert.equal(r.unlesses.length, 1);
  assert.equal(r.unlesses[0]!.field, "b");
});

test("parse: has condition", () => {
  const p = parse('forbid "r" { has user.role }');
  const c = p.rules[0]!.conditions[0]!;
  assert.equal(c.type, ConditionType.HAS);
  assert.equal(c.field, "user.role");
});

test("parse: count aggregate", () => {
  const p = parse('forbid "r" { count(plan.deletes) > 5 }');
  const c = p.rules[0]!.conditions[0]!;
  assert.equal(c.type, ConditionType.AGGREGATE);
  assert.equal(c.aggregateFunc, "count");
  assert.equal(c.aggregateTarget, "plan.deletes");
  assert.equal(c.op, ">");
  assert.equal(c.value, 5);
});

test("parse: any quantifier", () => {
  const p = parse('forbid "r" { any labels == "prod" }');
  const c = p.rules[0]!.conditions[0]!;
  assert.equal(c.type, ConditionType.ANY);
  assert.equal(c.listField, "labels");
  assert.ok(c.predicate);
  assert.equal(c.predicate!.op, "==");
  assert.equal(c.predicate!.value, "prod");
});

test("parse: all quantifier with in list", () => {
  const p = parse('forbid "r" { all labels in ["a", "b"] }');
  const c = p.rules[0]!.conditions[0]!;
  assert.equal(c.type, ConditionType.ALL);
  assert.deepEqual(c.predicate!.value, ["a", "b"]);
});

test("parse: not negation", () => {
  const p = parse('forbid "r" { not user.role == "admin" }');
  const c = p.rules[0]!.conditions[0]!;
  assert.equal(c.negated, true);
});

test("parse: or group", () => {
  const p = parse('forbid "r" { a == 1 or b == 2 or c == 3 }');
  const c = p.rules[0]!.conditions[0]!;
  assert.equal(c.type, ConditionType.OR);
  assert.equal(c.orGroup.length, 3);
});

test("parse: arithmetic expression condition", () => {
  const p = parse('forbid "r" { plan.adds + plan.deletes > 10 }');
  const c = p.rules[0]!.conditions[0]!;
  assert.equal(c.type, ConditionType.EXPR);
  assert.ok(c.leftExpr);
  assert.equal(c.leftExpr!.kind, ExprKind.BINARY);
  assert.equal(c.leftExpr!.op, "+");
});

test("parse: in, matches, intersects operators", () => {
  const p = parse(
    'forbid "r" { user.role in ["admin"] resource.name matches "prod-*" tags intersects ["a"] }',
  );
  const conds = p.rules[0]!.conditions;
  assert.equal(conds[0]!.op, "in");
  assert.equal(conds[1]!.op, "matches");
  assert.equal(conds[2]!.op, "intersects");
});

test("parse: error on missing brace", () => {
  assert.throws(() => parse('forbid "r" a == 1'), ParseError);
});

test("parse: transform lower() in field condition", () => {
  const p = parse('forbid "r" { lower(user.name) == "alex" }');
  const c = p.rules[0]!.conditions[0]!;
  assert.equal(c.transform, "lower");
  assert.equal(c.field, "user.name");
});
