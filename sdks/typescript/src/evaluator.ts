/**
 * Evaluator for CrowdControl policies.
 *
 * Ports github.com/mikemackintosh/crowdcontrol/evaluator/evaluator.go to
 * TypeScript. Pure stdlib (JavaScript RegExp for regex matching).
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { parse } from "./parser.js";
import { validatePolicies } from "./validate.js";
import {
  Condition,
  ConditionTrace,
  ConditionType,
  DEFAULT_ALLOW,
  DEFAULT_DENY,
  DefaultEffect,
  Expr,
  ExprKind,
  Policy,
  Result,
  Rule,
  RuleTrace,
  Schema,
  SchemaWarning,
  newResult,
  newRuleTrace,
} from "./types.js";

export const POLICY_EXT = ".cc";

export interface EvaluatorOptions {
  defaultEffect?: DefaultEffect;
  explain?: boolean;
}

/** Loads and runs CrowdControl policies against JSON-like documents. */
export class Evaluator {
  private readonly _policies: Policy[];
  private readonly _defaultEffect: DefaultEffect;
  private readonly _explain: boolean;

  constructor(policies: Policy[] = [], options: EvaluatorOptions = {}) {
    this._policies = policies;
    this._defaultEffect = options.defaultEffect ?? DEFAULT_ALLOW;
    this._explain = options.explain ?? false;
  }

  // ----- construction ----------------------------------------------------

  static fromSource(sources: string[], options: EvaluatorOptions = {}): Evaluator {
    const policies = sources.map((src) => parse(src));
    return new Evaluator(policies, options);
  }

  static fromDirectory(policyDirs: string[], options: EvaluatorOptions = {}): Evaluator {
    const policies: Policy[] = [];
    for (const d of policyDirs) {
      let stat: fs.Stats;
      try {
        stat = fs.statSync(d);
      } catch {
        continue;
      }
      if (!stat.isDirectory()) continue;
      const entries = fs.readdirSync(d).sort();
      for (const name of entries) {
        const fp = path.join(d, name);
        let fstat: fs.Stats;
        try {
          fstat = fs.statSync(fp);
        } catch {
          continue;
        }
        if (!fstat.isFile()) continue;
        if (!name.endsWith(POLICY_EXT)) continue;
        const src = fs.readFileSync(fp, "utf-8");
        policies.push(parse(src));
      }
    }
    return new Evaluator(policies, options);
  }

  policies(): Policy[] {
    return this._policies;
  }

  // ----- evaluation ------------------------------------------------------

  evaluate(doc: Record<string, unknown>): Result[] {
    const results: Result[] = [];
    let permitFired = false;
    let forbidFired = false;

    for (const policy of this._policies) {
      for (const rule of policy.rules) {
        const r = this.evalRule(rule, doc);
        results.push(r);
        if (r.kind === "permit" && r.message !== "") {
          permitFired = true;
        }
        if (r.kind === "forbid" && !r.passed) {
          forbidFired = true;
        }
      }
    }

    if (this._defaultEffect === DEFAULT_DENY && !permitFired && !forbidFired) {
      results.push(
        newResult({
          rule: "(default-deny)",
          kind: "forbid",
          passed: false,
          message: "no permit rule matched — denied by default",
        }),
      );
    }

    return results;
  }

  validate(schema: Schema): SchemaWarning[] {
    return validatePolicies(this._policies, schema);
  }

  // ----- rule evaluation -------------------------------------------------

  private evalRule(rule: Rule, doc: Record<string, unknown>): Result {
    const result = newResult({
      rule: rule.name,
      kind: rule.kind,
      passed: true,
      description: rule.description,
      owner: rule.owner,
      link: rule.link,
    });

    const trace: RuleTrace | null = this._explain ? newRuleTrace() : null;

    let allMatch = true;
    for (const cond of rule.conditions) {
      const matched = evalCondition(cond, doc);
      if (trace !== null) {
        trace.conditions.push(traceCondition(cond, doc, matched));
      }
      if (!matched) {
        allMatch = false;
        if (trace === null) break;
      }
    }

    if (trace !== null) {
      trace.allConditionsMatched = allMatch;
    }

    if (!allMatch) {
      if (trace !== null) result.trace = trace;
      return result;
    }

    let saved = false;
    for (const u of rule.unlesses) {
      const matched = evalCondition(u, doc);
      if (trace !== null) {
        trace.unlesses.push(traceCondition(u, doc, matched));
      }
      if (matched) {
        saved = true;
        if (trace === null) break;
      }
    }

    if (trace !== null) {
      trace.savedByUnless = saved;
    }

    if (saved) {
      if (trace !== null) result.trace = trace;
      return result;
    }

    // Rule fires.
    if (rule.kind === "permit") {
      result.passed = true;
      result.message = interpolateMessage(rule.message, doc);
    } else {
      result.passed = false;
      result.message = interpolateMessage(rule.message, doc);
    }

    if (trace !== null) result.trace = trace;
    return result;
  }
}

// ===========================================================================
// Condition evaluation
// ===========================================================================

export function evalCondition(cond: Condition, doc: Record<string, unknown>): boolean {
  const result = evalConditionInner(cond, doc);
  return cond.negated ? !result : result;
}

function evalConditionInner(cond: Condition, doc: Record<string, unknown>): boolean {
  switch (cond.type) {
    case ConditionType.AGGREGATE:
      return evalAggregate(cond, doc);
    case ConditionType.FIELD:
      return evalFieldCondition(cond, doc);
    case ConditionType.OR:
      for (const sub of cond.orGroup) {
        if (evalCondition(sub, doc)) return true;
      }
      return false;
    case ConditionType.ANY:
      return evalQuantifier(cond, doc, false);
    case ConditionType.ALL:
      return evalQuantifier(cond, doc, true);
    case ConditionType.HAS:
      return resolveField(cond.field, doc) !== null;
    case ConditionType.EXPR:
      return evalExprCondition(cond, doc);
    default:
      return false;
  }
}

function evalQuantifier(
  cond: Condition,
  doc: Record<string, unknown>,
  requireAll: boolean,
): boolean {
  const raw = resolveField(cond.listField, doc);
  const items = toList(raw);
  if (items === null) return requireAll;
  if (items.length === 0) return requireAll;
  if (cond.predicate === null) return false;
  for (const item of items) {
    const matched = evalElementPredicate(cond.predicate, doc, item);
    if (requireAll && !matched) return false;
    if (!requireAll && matched) return true;
  }
  return requireAll;
}

function evalElementPredicate(
  pred: Condition,
  _doc: Record<string, unknown>,
  element: unknown,
): boolean {
  const elemStr = fmtV(element);
  if (pred.type !== ConditionType.FIELD) return false;
  const op = pred.op;
  if (op === "==") return elemStr === fmtV(pred.value);
  if (op === "!=") return elemStr !== fmtV(pred.value);
  if (op === "in") {
    if (!Array.isArray(pred.value)) return false;
    for (const item of pred.value) {
      if (elemStr === item) return true;
    }
    return false;
  }
  if (op === "matches") {
    if (typeof pred.value !== "string") return false;
    return globMatch(pred.value, elemStr);
  }
  if (op === "matches_regex") {
    if (typeof pred.value !== "string") return false;
    return regexMatch(pred.value, elemStr);
  }
  if (op === "contains") {
    return evalContains(element, pred.value);
  }
  return compareValues(element, op, pred.value);
}

function evalExprCondition(cond: Condition, doc: Record<string, unknown>): boolean {
  if (cond.leftExpr === null || cond.rightExpr === null) return false;
  const [left, lok] = evalExpr(cond.leftExpr, doc);
  const [right, rok] = evalExpr(cond.rightExpr, doc);
  if (!lok || !rok) return false;
  return compareFloats(left, cond.op, right);
}

function evalExpr(expr: Expr, doc: Record<string, unknown>): [number, boolean] {
  switch (expr.kind) {
    case ExprKind.LITERAL:
      return [expr.value, true];
    case ExprKind.FIELD: {
      const val = resolveField(expr.field, doc);
      const f = toFloat(val);
      if (f === null) return [0, false];
      return [f, true];
    }
    case ExprKind.COUNT: {
      const val = resolveField(expr.aggTarget, doc);
      if (Array.isArray(val)) return [val.length, true];
      if (typeof val === "number") return [val, true];
      return [0, false];
    }
    case ExprKind.LEN: {
      const val = resolveField(expr.field, doc);
      if (typeof val === "string") return [val.length, true];
      if (Array.isArray(val)) return [val.length, true];
      if (val === null || val === undefined) return [0, true];
      return [0, false];
    }
    case ExprKind.BINARY: {
      if (expr.left === null || expr.right === null) return [0, false];
      const [l, lok] = evalExpr(expr.left, doc);
      const [r, rok] = evalExpr(expr.right, doc);
      if (!lok || !rok) return [0, false];
      if (expr.op === "+") return [l + r, true];
      if (expr.op === "-") return [l - r, true];
      if (expr.op === "*") return [l * r, true];
      if (expr.op === "/") {
        if (r === 0) return [0, false];
        return [l / r, true];
      }
      return [0, false];
    }
    default:
      return [0, false];
  }
}

function evalAggregate(cond: Condition, doc: Record<string, unknown>): boolean {
  const val = resolveField(cond.aggregateTarget, doc);
  let count: number;
  if (Array.isArray(val)) {
    count = val.length;
  } else if (typeof val === "number") {
    count = Math.trunc(val);
  } else {
    return false;
  }
  const target = cond.value;
  if (typeof target !== "number") return false;
  return compareFloats(count, cond.op, target);
}

function evalFieldCondition(cond: Condition, doc: Record<string, unknown>): boolean {
  let val = resolveField(cond.field, doc);
  if (cond.transform) {
    val = applyTransform(cond.transform, val);
  }

  const op = cond.op;
  if (op === "==") return fmtV(val) === fmtV(cond.value);
  if (op === "!=") return fmtV(val) !== fmtV(cond.value);
  if (op === "<" || op === ">" || op === "<=" || op === ">=") {
    return compareValues(val, op, cond.value);
  }
  if (op === "in") {
    if (!Array.isArray(cond.value)) return false;
    const s = fmtV(val);
    for (const item of cond.value) {
      if (s === item) return true;
    }
    return false;
  }
  if (op === "matches") {
    if (typeof cond.value !== "string") return false;
    return globMatch(cond.value, fmtV(val));
  }
  if (op === "matches_regex") {
    if (typeof cond.value !== "string") return false;
    return regexMatch(cond.value, fmtV(val));
  }
  if (op === "contains") return evalContains(val, cond.value);
  if (op === "intersects") return evalIntersects(val, cond.value);
  if (op === "is_subset") return evalIsSubset(val, cond.value);
  return false;
}

function evalContains(val: unknown, target: unknown): boolean {
  const targetStr = fmtV(target);
  if (Array.isArray(val)) {
    for (const item of val) {
      if (fmtV(item) === targetStr) return true;
    }
    return false;
  }
  if (typeof val === "string") {
    return val.includes(targetStr);
  }
  return false;
}

function evalIntersects(val: unknown, target: unknown): boolean {
  if (!Array.isArray(target)) return false;
  const rhsSet = new Set<string>(target.map((x) => fmtV(x)));
  if (Array.isArray(val)) {
    for (const item of val) {
      if (rhsSet.has(fmtV(item))) return true;
    }
    return false;
  }
  return false;
}

function evalIsSubset(val: unknown, target: unknown): boolean {
  if (!Array.isArray(target)) return false;
  const rhsSet = new Set<string>(target.map((x) => fmtV(x)));
  if (Array.isArray(val)) {
    if (val.length === 0) return true;
    for (const item of val) {
      if (!rhsSet.has(fmtV(item))) return false;
    }
    return true;
  }
  return false;
}

// ===========================================================================
// Trace / explain
// ===========================================================================

export function traceCondition(
  cond: Condition,
  doc: Record<string, unknown>,
  result: boolean,
): ConditionTrace {
  const ct: ConditionTrace = {
    expr: conditionExpr(cond),
    result,
    actual: resolveActual(cond, doc),
    children: [],
  };
  if (cond.type === ConditionType.OR) {
    for (const sub of cond.orGroup) {
      const subResult = evalCondition(sub, doc);
      ct.children.push(traceCondition(sub, doc, subResult));
    }
  }
  return ct;
}

function conditionExpr(cond: Condition): string {
  const prefix = cond.negated ? "not " : "";
  switch (cond.type) {
    case ConditionType.FIELD: {
      let field = cond.field;
      if (cond.transform) field = `${cond.transform}(${cond.field})`;
      return `${prefix}${field} ${cond.op} ${formatValue(cond.value)}`;
    }
    case ConditionType.AGGREGATE:
      return `${prefix}count(${cond.aggregateTarget}) ${cond.op} ${cond.value}`;
    case ConditionType.HAS:
      return `${prefix}has ${cond.field}`;
    case ConditionType.ANY: {
      if (cond.predicate !== null) {
        return `${prefix}any ${cond.listField} ${cond.predicate.op} ${formatValue(cond.predicate.value)}`;
      }
      return `${prefix}any ${cond.listField} <predicate>`;
    }
    case ConditionType.ALL: {
      if (cond.predicate !== null) {
        return `${prefix}all ${cond.listField} ${cond.predicate.op} ${formatValue(cond.predicate.value)}`;
      }
      return `${prefix}all ${cond.listField} <predicate>`;
    }
    case ConditionType.OR:
      return prefix + cond.orGroup.map((sub) => conditionExpr(sub)).join(" or ");
    case ConditionType.EXPR:
      return `${prefix}${exprString(cond.leftExpr)} ${cond.op} ${exprString(cond.rightExpr)}`;
    default:
      return prefix + "<unknown>";
  }
}

function exprString(expr: Expr | null): string {
  if (expr === null) return "<nil>";
  switch (expr.kind) {
    case ExprKind.FIELD:
      return expr.field;
    case ExprKind.LITERAL:
      if (expr.value === Math.trunc(expr.value)) return String(Math.trunc(expr.value));
      return String(expr.value);
    case ExprKind.COUNT:
      return `count(${expr.aggTarget})`;
    case ExprKind.LEN:
      return `len(${expr.field})`;
    case ExprKind.BINARY:
      return `${exprString(expr.left)} ${expr.op} ${exprString(expr.right)}`;
    default:
      return "<unknown>";
  }
}

function resolveActual(cond: Condition, doc: Record<string, unknown>): string {
  switch (cond.type) {
    case ConditionType.FIELD:
      return formatActual(resolveField(cond.field, doc));
    case ConditionType.AGGREGATE: {
      const val = resolveField(cond.aggregateTarget, doc);
      if (Array.isArray(val)) return String(val.length);
      if (typeof val === "number") return String(Math.trunc(val));
      return "<nil>";
    }
    case ConditionType.HAS: {
      const val = resolveField(cond.field, doc);
      return val !== null ? "exists" : "<nil>";
    }
    case ConditionType.ANY:
    case ConditionType.ALL: {
      const val = resolveField(cond.listField, doc);
      const items = toList(val);
      if (items === null) return "<nil>";
      return `[${items.length} items]`;
    }
    case ConditionType.EXPR: {
      if (cond.leftExpr !== null && cond.rightExpr !== null) {
        const [lv, lok] = evalExpr(cond.leftExpr, doc);
        const [rv, rok] = evalExpr(cond.rightExpr, doc);
        if (lok && rok) return `${lv} vs ${rv}`;
      }
      return "";
    }
    default:
      return "";
  }
}

function formatValue(v: unknown): string {
  if (typeof v === "string") return `"${v}"`;
  if (Array.isArray(v) && v.every((x) => typeof x === "string")) {
    return "[" + v.map((x) => `"${x}"`).join(", ") + "]";
  }
  return fmtV(v);
}

function formatActual(v: unknown): string {
  if (v === null || v === undefined) return "<nil>";
  if (Array.isArray(v)) {
    if (v.length <= 5) return "[" + v.map((item) => fmtV(item)).join(", ") + "]";
    return `[${v.length} items]`;
  }
  if (typeof v === "string") return `"${v}"`;
  return fmtV(v);
}

// ===========================================================================
// Helpers
// ===========================================================================

const regexCache = new Map<string, RegExp | null>();

function regexMatch(pattern: string, s: string): boolean {
  if (!regexCache.has(pattern)) {
    try {
      regexCache.set(pattern, new RegExp(pattern));
    } catch {
      regexCache.set(pattern, null);
    }
  }
  const compiled = regexCache.get(pattern);
  if (!compiled) return false;
  return compiled.test(s);
}

function globMatch(pattern: string, s: string): boolean {
  if (pattern === "*") return true;
  const endsStar = pattern.endsWith("*");
  const startsStar = pattern.startsWith("*");
  if (endsStar && !startsStar) return s.startsWith(pattern.slice(0, -1));
  if (startsStar && !endsStar) return s.endsWith(pattern.slice(1));
  const star = pattern.indexOf("*");
  if (star >= 0) {
    const prefix = pattern.slice(0, star);
    const suffix = pattern.slice(star + 1);
    return s.startsWith(prefix) && s.endsWith(suffix);
  }
  return pattern === s;
}

/** Resolve a dotted path against a document. Returns null if missing. */
export function resolveField(path: string, doc: unknown): unknown {
  if (doc === null || doc === undefined) return null;
  let current: unknown = doc;
  for (const part of path.split(".")) {
    if (current !== null && typeof current === "object" && !Array.isArray(current)) {
      current = (current as Record<string, unknown>)[part];
      if (current === undefined) return null;
    } else {
      return null;
    }
  }
  if (current === undefined) return null;
  return current;
}

function toList(v: unknown): unknown[] | null {
  if (Array.isArray(v)) return v;
  return null;
}

function toFloat(v: unknown): number | null {
  if (typeof v === "boolean") return null;
  if (typeof v === "number") return v;
  return null;
}

function compareValues(a: unknown, op: string, b: unknown): boolean {
  const af = toFloat(a);
  const bf = toFloat(b);
  if (af !== null && bf !== null) {
    return compareFloats(af, op, bf);
  }
  return false;
}

function compareFloats(a: number, op: string, b: number): boolean {
  switch (op) {
    case "<":
      return a < b;
    case ">":
      return a > b;
    case "<=":
      return a <= b;
    case ">=":
      return a >= b;
    case "==":
      return a === b;
    case "!=":
      return a !== b;
    default:
      return false;
  }
}

function applyTransform(transform: string, val: unknown): unknown {
  if (transform === "lower") {
    if (typeof val === "string") return val.toLowerCase();
    return fmtV(val).toLowerCase();
  }
  if (transform === "upper") {
    if (typeof val === "string") return val.toUpperCase();
    return fmtV(val).toUpperCase();
  }
  if (transform === "len") {
    if (typeof val === "string") return val.length;
    if (Array.isArray(val)) return val.length;
    if (val === null || val === undefined) return 0;
    return 0;
  }
  return val;
}

/**
 * Format a value the way Go's fmt.Sprintf("%v", v) would — lowercase
 * booleans, integers without a decimal point, and "<nil>" for null.
 */
export function fmtV(v: unknown): string {
  if (v === null || v === undefined) return "<nil>";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (Number.isFinite(v) && v === Math.trunc(v)) return String(Math.trunc(v));
    return String(v);
  }
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return "[" + v.map((x) => fmtV(x)).join(" ") + "]";
  return String(v);
}

// ===========================================================================
// Message interpolation
// ===========================================================================

const INTERP_RE = /\{([^}]+)\}/g;

export function interpolateMessage(msg: string, doc: Record<string, unknown>): string {
  if (msg === "") return "policy violation";
  return msg.replace(INTERP_RE, (whole, expr: string) => {
    if (expr.startsWith("count(") && expr.endsWith(")")) {
      const target = expr.slice(6, -1);
      const val = resolveField(target, doc);
      if (Array.isArray(val)) return String(val.length);
      if (typeof val === "number") return String(Math.trunc(val));
      return whole;
    }
    const val = resolveField(expr, doc);
    if (val === null || val === undefined) return whole;
    return fmtV(val);
  });
}

// ===========================================================================
// Output formatting
// ===========================================================================

export interface FormatOutput {
  text: string;
  allPassed: boolean;
}

export function formatResults(results: Result[]): FormatOutput {
  let allPassed = true;
  const lines: string[] = [];
  for (const r of results) {
    if (r.passed) continue;
    let prefix = "DENY";
    if (r.kind === "warn") {
      prefix = "WARN";
    } else {
      allPassed = false;
    }
    let line = `${prefix}: ${r.message} (${r.rule})`;
    const meta: string[] = [];
    if (r.owner) meta.push(`owner: ${r.owner}`);
    if (r.link) meta.push(`link: ${r.link}`);
    if (meta.length > 0) line += " [" + meta.join(", ") + "]";
    lines.push(line);
  }
  if (allPassed) {
    const passedCount = results.filter((r) => r.passed).length;
    lines.push(`PASS: ${passedCount} rules evaluated, all passed`);
  }
  return { text: lines.join("\n") + (lines.length > 0 ? "\n" : ""), allPassed };
}

// ----- top-level convenience constructors --------------------------------

export function fromSource(sources: string[], options: EvaluatorOptions = {}): Evaluator {
  return Evaluator.fromSource(sources, options);
}

export function fromDirectory(dirs: string[], options: EvaluatorOptions = {}): Evaluator {
  return Evaluator.fromDirectory(dirs, options);
}
