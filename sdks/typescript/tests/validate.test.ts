import { test } from "node:test";
import assert from "node:assert/strict";

import { parse } from "../src/parser.js";
import { formatWarnings, validatePolicies } from "../src/validate.js";
import { Schema } from "../src/types.js";

function schemaOf(fields: Record<string, string>): Schema {
  return { fields: fields as Schema["fields"] };
}

test("validate: unknown field produces a warning", () => {
  const p = parse('forbid "r" { user.name == "alex" }');
  const schema = schemaOf({ "user.role": "string" });
  const warnings = validatePolicies([p], schema);
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0]!.field, "user.name");
  assert.match(warnings[0]!.message, /not found in schema/);
});

test("validate: numeric op on string field warns", () => {
  const p = parse('forbid "r" { user.name < "z" }');
  const schema = schemaOf({ "user.name": "string" });
  const warnings = validatePolicies([p], schema);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!.message, /operator < used on field/);
});

test("validate: contains on bool field warns", () => {
  const p = parse('forbid "r" { user.active contains "x" }');
  const schema = schemaOf({ "user.active": "bool" });
  const warnings = validatePolicies([p], schema);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!.message, /operator contains/);
});

test("validate: has with unknown field warns", () => {
  const p = parse('forbid "r" { has user.xyz }');
  const schema = schemaOf({ "user.name": "string" });
  const warnings = validatePolicies([p], schema);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!.message, /used with 'has'/);
});

test("validate: count on non-list non-number warns", () => {
  const p = parse('forbid "r" { count(user.name) > 0 }');
  const schema = schemaOf({ "user.name": "string" });
  const warnings = validatePolicies([p], schema);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!.message, /expected list or number/);
});

test("validate: quantifier on non-list warns", () => {
  const p = parse('forbid "r" { any user.name == "x" }');
  const schema = schemaOf({ "user.name": "string" });
  const warnings = validatePolicies([p], schema);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!.message, /expected list/);
});

test("validate: arithmetic on string field warns", () => {
  const p = parse('forbid "r" { user.name + 1 > 0 }');
  const schema = schemaOf({ "user.name": "string" });
  const warnings = validatePolicies([p], schema);
  assert.ok(warnings.length >= 1);
  assert.match(warnings[0]!.message, /arithmetic used on field/);
});

test("validate: unknown field in message interpolation warns", () => {
  const p = parse('forbid "r" { a == 1 message "{user.nope}" }');
  const schema = schemaOf({ a: "number" });
  const warnings = validatePolicies([p], schema);
  assert.ok(warnings.some((w) => w.field === "user.nope"));
});

test("validate: map prefix allows nested lookups", () => {
  const p = parse('forbid "r" { user.xyz == "a" }');
  const schema = schemaOf({ user: "map" });
  const warnings = validatePolicies([p], schema);
  assert.equal(warnings.length, 0);
});

test("validate: any type accepts anything", () => {
  const p = parse('forbid "r" { user.x < 5 }');
  const schema = schemaOf({ "user.x": "any" });
  const warnings = validatePolicies([p], schema);
  assert.equal(warnings.length, 0);
});

test("validate: formatWarnings returns indented lines", () => {
  const out = formatWarnings([
    { rule: "r", field: "f", message: "m1" },
    { rule: "r2", field: "f2", message: "m2" },
  ]);
  assert.equal(out, "  r: m1\n  r2: m2\n");
  assert.equal(formatWarnings([]), "");
});
