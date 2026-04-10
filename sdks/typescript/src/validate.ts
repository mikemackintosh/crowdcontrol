/**
 * Static schema validation for CrowdControl policies.
 *
 * Ports github.com/mikemackintosh/crowdcontrol/evaluator/validate.go to
 * TypeScript. Produces non-fatal warnings for typos, type mismatches, and
 * other issues — schema validation never raises, it only reports.
 */

import {
  Condition,
  ConditionType,
  Expr,
  ExprKind,
  FIELD_ANY,
  FIELD_BOOL,
  FIELD_LIST,
  FIELD_MAP,
  FIELD_NUMBER,
  FIELD_STRING,
  FieldType,
  Policy,
  Schema,
  SchemaWarning,
} from "./types.js";

/** Run schema validation across every loaded policy. */
export function validatePolicies(policies: Policy[], schema: Schema): SchemaWarning[] {
  const warnings: SchemaWarning[] = [];
  for (const policy of policies) {
    for (const rule of policy.rules) {
      for (const cond of rule.conditions) {
        warnings.push(...validateCondition(cond, schema, rule.name));
      }
      for (const u of rule.unlesses) {
        warnings.push(...validateCondition(u, schema, rule.name));
      }
      if (rule.message) {
        warnings.push(...validateInterpolations(rule.message, schema, rule.name));
      }
    }
  }
  return warnings;
}

function validateCondition(
  cond: Condition,
  schema: Schema,
  ruleName: string,
): SchemaWarning[] {
  const warnings: SchemaWarning[] = [];

  switch (cond.type) {
    case ConditionType.FIELD:
      if (cond.field) {
        warnings.push(...checkField(cond.field, schema, ruleName, cond));
      }
      break;
    case ConditionType.HAS:
      if (cond.field) {
        warnings.push(...checkFieldExists(cond.field, schema, ruleName));
      }
      break;
    case ConditionType.AGGREGATE:
      if (cond.aggregateTarget) {
        warnings.push(...checkAggregateField(cond.aggregateTarget, schema, ruleName));
      }
      break;
    case ConditionType.ANY:
    case ConditionType.ALL:
      if (cond.listField) {
        warnings.push(...checkListField(cond.listField, schema, ruleName));
      }
      if (cond.predicate !== null) {
        warnings.push(...validateCondition(cond.predicate, schema, ruleName));
      }
      break;
    case ConditionType.OR:
      for (const sub of cond.orGroup) {
        warnings.push(...validateCondition(sub, schema, ruleName));
      }
      break;
    case ConditionType.EXPR:
      if (cond.leftExpr !== null) {
        warnings.push(...checkExprFields(cond.leftExpr, schema, ruleName));
      }
      if (cond.rightExpr !== null) {
        warnings.push(...checkExprFields(cond.rightExpr, schema, ruleName));
      }
      break;
  }

  return warnings;
}

function checkField(
  field: string,
  schema: Schema,
  ruleName: string,
  cond: Condition,
): SchemaWarning[] {
  const warnings: SchemaWarning[] = [];
  const expected = lookupField(schema, field);
  if (expected === null) {
    warnings.push({
      rule: ruleName,
      field,
      message: `field '${field}' not found in schema`,
    });
    return warnings;
  }

  const op = cond.op;
  if (op === "<" || op === ">" || op === "<=" || op === ">=") {
    if (expected !== FIELD_NUMBER && expected !== FIELD_ANY) {
      warnings.push({
        rule: ruleName,
        field,
        message: `operator ${op} used on field '${field}' of type ${expected}`,
      });
    }
  } else if (op === "contains" || op === "intersects" || op === "is_subset") {
    if (expected !== FIELD_LIST && expected !== FIELD_STRING && expected !== FIELD_ANY) {
      warnings.push({
        rule: ruleName,
        field,
        message: `operator ${op} used on field '${field}' of type ${expected}`,
      });
    }
  } else if (op === "in") {
    if (expected !== FIELD_STRING && expected !== FIELD_ANY) {
      warnings.push({
        rule: ruleName,
        field,
        message: `operator 'in' used on field '${field}' of type ${expected}`,
      });
    }
  }
  // Silence unused import warnings for types we keep around for parity.
  void FIELD_BOOL;
  void FIELD_MAP;
  return warnings;
}

function checkFieldExists(field: string, schema: Schema, ruleName: string): SchemaWarning[] {
  if (lookupField(schema, field) === null) {
    return [
      {
        rule: ruleName,
        field,
        message: `field '${field}' not found in schema (used with 'has')`,
      },
    ];
  }
  return [];
}

function checkAggregateField(field: string, schema: Schema, ruleName: string): SchemaWarning[] {
  const expected = lookupField(schema, field);
  if (expected === null) {
    return [
      {
        rule: ruleName,
        field,
        message: `field '${field}' not found in schema (used with 'count')`,
      },
    ];
  }
  if (expected !== FIELD_LIST && expected !== FIELD_NUMBER && expected !== FIELD_ANY) {
    return [
      {
        rule: ruleName,
        field,
        message: `count() used on field '${field}' of type ${expected}, expected list or number`,
      },
    ];
  }
  return [];
}

function checkListField(field: string, schema: Schema, ruleName: string): SchemaWarning[] {
  const expected = lookupField(schema, field);
  if (expected === null) {
    return [
      {
        rule: ruleName,
        field,
        message: `field '${field}' not found in schema (used with quantifier)`,
      },
    ];
  }
  if (expected !== FIELD_LIST && expected !== FIELD_ANY) {
    return [
      {
        rule: ruleName,
        field,
        message: `quantifier used on field '${field}' of type ${expected}, expected list`,
      },
    ];
  }
  return [];
}

function checkExprFields(expr: Expr, schema: Schema, ruleName: string): SchemaWarning[] {
  const warnings: SchemaWarning[] = [];
  switch (expr.kind) {
    case ExprKind.FIELD:
      if (expr.field) {
        const expected = lookupField(schema, expr.field);
        if (expected === null) {
          warnings.push({
            rule: ruleName,
            field: expr.field,
            message: `field '${expr.field}' not found in schema (used in arithmetic)`,
          });
        } else if (expected !== FIELD_NUMBER && expected !== FIELD_ANY) {
          warnings.push({
            rule: ruleName,
            field: expr.field,
            message: `arithmetic used on field '${expr.field}' of type ${expected}, expected number`,
          });
        }
      }
      break;
    case ExprKind.COUNT:
      if (expr.aggTarget) {
        warnings.push(...checkAggregateField(expr.aggTarget, schema, ruleName));
      }
      break;
    case ExprKind.LEN:
      if (expr.field) {
        const expected = lookupField(schema, expr.field);
        if (expected === null) {
          warnings.push({
            rule: ruleName,
            field: expr.field,
            message: `field '${expr.field}' not found in schema (used with len)`,
          });
        }
      }
      break;
    case ExprKind.BINARY:
      if (expr.left !== null) warnings.push(...checkExprFields(expr.left, schema, ruleName));
      if (expr.right !== null) warnings.push(...checkExprFields(expr.right, schema, ruleName));
      break;
  }
  return warnings;
}

const INTERP_RE = /\{([^}]+)\}/g;

function validateInterpolations(msg: string, schema: Schema, ruleName: string): SchemaWarning[] {
  const warnings: SchemaWarning[] = [];
  for (const match of msg.matchAll(INTERP_RE)) {
    const expr = match[1]!;
    if (expr.startsWith("count(") && expr.endsWith(")")) continue;
    if (lookupField(schema, expr) === null) {
      warnings.push({
        rule: ruleName,
        field: expr,
        message: `message interpolation references unknown field '${expr}'`,
      });
    }
  }
  return warnings;
}

function lookupField(schema: Schema, field: string): FieldType | null {
  if (field in schema.fields) {
    return schema.fields[field]!;
  }
  const parts = field.split(".");
  for (let i = parts.length - 1; i > 0; i--) {
    const prefix = parts.slice(0, i).join(".");
    if (prefix in schema.fields && schema.fields[prefix] === FIELD_MAP) {
      return FIELD_ANY;
    }
  }
  return null;
}

export function formatWarnings(warnings: SchemaWarning[]): string {
  if (warnings.length === 0) return "";
  const lines = warnings.map((w) => `  ${w.rule}: ${w.message}`);
  return lines.join("\n") + "\n";
}
