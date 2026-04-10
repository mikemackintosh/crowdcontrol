import { test } from "node:test";
import assert from "node:assert/strict";

import {
  Evaluator,
  fmtV,
  formatResults,
  fromSource,
  interpolateMessage,
  resolveField,
} from "../src/evaluator.js";
import { DEFAULT_DENY } from "../src/types.js";

function evalPolicy(src: string, doc: Record<string, unknown>) {
  return fromSource([src]).evaluate(doc);
}

test("eval: basic forbid fires when condition true", () => {
  const results = evalPolicy(
    'forbid "x" { user.role == "admin" message "blocked" }',
    { user: { role: "admin" } },
  );
  assert.equal(results.length, 1);
  assert.equal(results[0]!.passed, false);
  assert.equal(results[0]!.message, "blocked");
});

test("eval: forbid does not fire when condition false", () => {
  const results = evalPolicy(
    'forbid "x" { user.role == "admin" message "blocked" }',
    { user: { role: "dev" } },
  );
  assert.equal(results[0]!.passed, true);
  assert.equal(results[0]!.message, "");
});

test("eval: permit result has passed true and message set when fired", () => {
  const results = evalPolicy(
    'permit "ok" { user.role == "admin" message "allowed" }',
    { user: { role: "admin" } },
  );
  assert.equal(results[0]!.kind, "permit");
  assert.equal(results[0]!.passed, true);
  assert.equal(results[0]!.message, "allowed");
});

test("eval: unless saves rule", () => {
  const results = evalPolicy(
    'forbid "r" { a == 1 unless b == 2 message "fail" }',
    { a: 1, b: 2 },
  );
  assert.equal(results[0]!.passed, true);
});

test("eval: multiple conditions are ANDed", () => {
  const results = evalPolicy(
    'forbid "r" { a == 1 b == 2 message "x" }',
    { a: 1, b: 3 },
  );
  assert.equal(results[0]!.passed, true); // b mismatch → rule does not fire
});

test("eval: any quantifier true when an element matches", () => {
  const results = evalPolicy(
    'forbid "r" { any labels == "prod" message "prod" }',
    { labels: ["dev", "prod", "test"] },
  );
  assert.equal(results[0]!.passed, false);
});

test("eval: all quantifier on empty list is vacuously true", () => {
  const results = evalPolicy(
    'forbid "r" { all labels == "x" message "fail" }',
    { labels: [] },
  );
  assert.equal(results[0]!.passed, false);
});

test("eval: count aggregate", () => {
  const results = evalPolicy(
    'forbid "r" { count(deletes) > 3 message "too many" }',
    { deletes: [1, 2, 3, 4, 5] },
  );
  assert.equal(results[0]!.passed, false);
});

test("eval: matches glob", () => {
  const results = evalPolicy(
    'forbid "r" { name matches "prod-*" message "prod" }',
    { name: "prod-db" },
  );
  assert.equal(results[0]!.passed, false);
});

test("eval: matches_regex", () => {
  const results = evalPolicy(
    'forbid "r" { name matches_regex "^[a-z]+$" message "lower" }',
    { name: "abc" },
  );
  assert.equal(results[0]!.passed, false);
});

test("eval: in list", () => {
  const results = evalPolicy(
    'forbid "r" { role in ["admin", "root"] message "priv" }',
    { role: "admin" },
  );
  assert.equal(results[0]!.passed, false);
});

test("eval: contains on list and string", () => {
  const r1 = evalPolicy('forbid "a" { tags contains "x" message "m" }', {
    tags: ["a", "x", "b"],
  });
  assert.equal(r1[0]!.passed, false);
  const r2 = evalPolicy('forbid "a" { name contains "abc" message "m" }', {
    name: "xabcx",
  });
  assert.equal(r2[0]!.passed, false);
});

test("eval: intersects and is_subset", () => {
  const r1 = evalPolicy('forbid "r" { tags intersects ["x", "y"] message "m" }', {
    tags: ["y"],
  });
  assert.equal(r1[0]!.passed, false);
  const r2 = evalPolicy('forbid "r" { tags is_subset ["a", "b", "c"] message "m" }', {
    tags: ["a", "b"],
  });
  assert.equal(r2[0]!.passed, false);
});

test("eval: message interpolation", () => {
  const msg = interpolateMessage("hello {user.name}", { user: { name: "ana" } });
  assert.equal(msg, "hello ana");
});

test("eval: message interpolation with count()", () => {
  const msg = interpolateMessage("{count(items)} items", { items: [1, 2, 3] });
  assert.equal(msg, "3 items");
});

test("eval: default-deny appended when no rules match", () => {
  const eng = fromSource(['permit "p" { user.role == "admin" message "ok" }'], {
    defaultEffect: DEFAULT_DENY,
  });
  const results = eng.evaluate({ user: { role: "dev" } });
  assert.equal(results.length, 2);
  assert.equal(results[1]!.rule, "(default-deny)");
  assert.equal(results[1]!.passed, false);
});

test("eval: default-deny suppressed when permit fires", () => {
  const eng = fromSource(['permit "p" { user.role == "admin" message "ok" }'], {
    defaultEffect: DEFAULT_DENY,
  });
  const results = eng.evaluate({ user: { role: "admin" } });
  assert.equal(results.length, 1);
});

test("eval: resolveField navigates nested maps", () => {
  assert.equal(resolveField("a.b.c", { a: { b: { c: 42 } } }), 42);
  assert.equal(resolveField("a.x", { a: {} }), null);
  assert.equal(resolveField("a.b", { a: "not a map" }), null);
});

test("eval: fmtV matches Go %v semantics", () => {
  assert.equal(fmtV(true), "true");
  assert.equal(fmtV(false), "false");
  assert.equal(fmtV(null), "<nil>");
  assert.equal(fmtV(undefined), "<nil>");
  assert.equal(fmtV(42), "42");
  assert.equal(fmtV(3.14), "3.14");
  assert.equal(fmtV("hi"), "hi");
});

test("eval: format_results denies and passes", () => {
  const results = evalPolicy(
    'forbid "x" { a == 1 message "boom" }',
    { a: 1 },
  );
  const { text, allPassed } = formatResults(results);
  assert.equal(allPassed, false);
  assert.ok(text.includes("DENY: boom (x)"));
});

test("eval: arithmetic expression condition", () => {
  const results = evalPolicy(
    'forbid "r" { plan.adds + plan.deletes > 10 message "m" }',
    { plan: { adds: 6, deletes: 5 } },
  );
  assert.equal(results[0]!.passed, false);
});

test("eval: transform lower()", () => {
  const results = evalPolicy(
    'forbid "r" { lower(user.name) == "alex" message "m" }',
    { user: { name: "ALEX" } },
  );
  assert.equal(results[0]!.passed, false);
});

test("eval: Evaluator class methods", () => {
  const eng = new Evaluator();
  assert.deepEqual(eng.policies(), []);
  assert.deepEqual(eng.evaluate({}), []);
});
