/**
 * AST, Schema, and Result types for CrowdControl.
 *
 * This module mirrors the Go reference implementation at
 * github.com/mikemackintosh/crowdcontrol/types — pure data, no behavior.
 */

export enum ConditionType {
  FIELD = 0,
  AGGREGATE = 1,
  OR = 2,
  ANY = 3,
  ALL = 4,
  HAS = 5,
  EXPR = 6,
}

export enum ExprKind {
  FIELD = 0,
  LITERAL = 1,
  COUNT = 2,
  LEN = 3,
  BINARY = 4,
}

/** Default effect controls what happens when no rule matches a document. */
export type DefaultEffect = "allow" | "deny";

export const DEFAULT_ALLOW: DefaultEffect = "allow";
export const DEFAULT_DENY: DefaultEffect = "deny";

/** Numeric expression node (field, count, literal, len, or binary op). */
export interface Expr {
  kind: ExprKind;
  field: string;
  value: number;
  aggTarget: string;
  transform: string;
  op: string;
  left: Expr | null;
  right: Expr | null;
}

export function newExpr(init: Partial<Expr> = {}): Expr {
  return {
    kind: ExprKind.LITERAL,
    field: "",
    value: 0,
    aggTarget: "",
    transform: "",
    op: "",
    left: null,
    right: null,
    ...init,
  };
}

/** A single evaluable clause. */
export interface Condition {
  type: ConditionType;
  negated: boolean;
  field: string;
  op: string;
  value: unknown;
  transform: string;
  aggregateFunc: string;
  aggregateTarget: string;
  orGroup: Condition[];
  quantifier: string;
  listField: string;
  predicate: Condition | null;
  leftExpr: Expr | null;
  rightExpr: Expr | null;
}

export function newCondition(init: Partial<Condition> = {}): Condition {
  return {
    type: ConditionType.FIELD,
    negated: false,
    field: "",
    op: "",
    value: null,
    transform: "",
    aggregateFunc: "",
    aggregateTarget: "",
    orGroup: [],
    quantifier: "",
    listField: "",
    predicate: null,
    leftExpr: null,
    rightExpr: null,
    ...init,
  };
}

/** A single forbid/warn/permit block. */
export interface Rule {
  kind: string; // "forbid" | "warn" | "permit"
  name: string;
  conditions: Condition[];
  unlesses: Condition[];
  message: string;
  description: string;
  owner: string;
  link: string;
}

export function newRule(init: Partial<Rule> = {}): Rule {
  return {
    kind: "",
    name: "",
    conditions: [],
    unlesses: [],
    message: "",
    description: "",
    owner: "",
    link: "",
    ...init,
  };
}

/** A parsed CrowdControl policy file (collection of rules). */
export interface Policy {
  rules: Rule[];
}

export function newPolicy(): Policy {
  return { rules: [] };
}

export interface ConditionTrace {
  expr: string;
  result: boolean;
  actual: string;
  children: ConditionTrace[];
}

export interface RuleTrace {
  conditions: ConditionTrace[];
  unlesses: ConditionTrace[];
  allConditionsMatched: boolean;
  savedByUnless: boolean;
}

export function newRuleTrace(): RuleTrace {
  return {
    conditions: [],
    unlesses: [],
    allConditionsMatched: false,
    savedByUnless: false,
  };
}

export interface Result {
  rule: string;
  kind: string; // "forbid" | "warn" | "permit"
  passed: boolean;
  message: string;
  description: string;
  owner: string;
  link: string;
  trace: RuleTrace | null;
}

export function newResult(init: Partial<Result> = {}): Result {
  return {
    rule: "",
    kind: "",
    passed: true,
    message: "",
    description: "",
    owner: "",
    link: "",
    trace: null,
    ...init,
  };
}

// ----- Schema validation -----

export type FieldType = "string" | "number" | "bool" | "list" | "map" | "any";

export const FIELD_STRING: FieldType = "string";
export const FIELD_NUMBER: FieldType = "number";
export const FIELD_BOOL: FieldType = "bool";
export const FIELD_LIST: FieldType = "list";
export const FIELD_MAP: FieldType = "map";
export const FIELD_ANY: FieldType = "any";

export interface Schema {
  fields: Record<string, FieldType>;
}

export interface SchemaWarning {
  rule: string;
  field: string;
  message: string;
}
