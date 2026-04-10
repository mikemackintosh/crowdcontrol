"""Static schema validation for CrowdControl policies.

Ports github.com/mikemackintosh/crowdcontrol/evaluator/validate.go to Python.
Produces non-fatal warnings for typos, type mismatches, and other issues.
"""

from __future__ import annotations

import re

from .types import (
    FIELD_ANY,
    FIELD_BOOL,
    FIELD_LIST,
    FIELD_MAP,
    FIELD_NUMBER,
    FIELD_STRING,
    Condition,
    ConditionType,
    Expr,
    ExprKind,
    Policy,
    Schema,
    SchemaWarning,
)


def validate_policies(policies: list[Policy], schema: Schema) -> list[SchemaWarning]:
    """Run schema validation across every loaded policy."""
    warnings: list[SchemaWarning] = []
    for policy in policies:
        for rule in policy.rules:
            for cond in rule.conditions:
                warnings.extend(_validate_condition(cond, schema, rule.name))
            for u in rule.unlesses:
                warnings.extend(_validate_condition(u, schema, rule.name))
            if rule.message:
                warnings.extend(_validate_interpolations(rule.message, schema, rule.name))
    return warnings


def _validate_condition(cond: Condition, schema: Schema, rule_name: str) -> list[SchemaWarning]:
    warnings: list[SchemaWarning] = []
    t = cond.type

    if t == ConditionType.FIELD:
        if cond.field:
            warnings.extend(_check_field(cond.field, schema, rule_name, cond))
    elif t == ConditionType.HAS:
        if cond.field:
            warnings.extend(_check_field_exists(cond.field, schema, rule_name))
    elif t == ConditionType.AGGREGATE:
        if cond.aggregate_target:
            warnings.extend(_check_aggregate_field(cond.aggregate_target, schema, rule_name))
    elif t in (ConditionType.ANY, ConditionType.ALL):
        if cond.list_field:
            warnings.extend(_check_list_field(cond.list_field, schema, rule_name))
        if cond.predicate is not None:
            warnings.extend(_validate_condition(cond.predicate, schema, rule_name))
    elif t == ConditionType.OR:
        for sub in cond.or_group:
            warnings.extend(_validate_condition(sub, schema, rule_name))
    elif t == ConditionType.EXPR:
        if cond.left_expr is not None:
            warnings.extend(_check_expr_fields(cond.left_expr, schema, rule_name))
        if cond.right_expr is not None:
            warnings.extend(_check_expr_fields(cond.right_expr, schema, rule_name))

    return warnings


def _check_field(field: str, schema: Schema, rule_name: str, cond: Condition) -> list[SchemaWarning]:
    warnings: list[SchemaWarning] = []
    expected = _lookup_field(schema, field)
    if expected is None:
        warnings.append(
            SchemaWarning(
                rule=rule_name,
                field=field,
                message=f"field {field!r} not found in schema",
            )
        )
        return warnings

    op = cond.op
    if op in ("<", ">", "<=", ">="):
        if expected not in (FIELD_NUMBER, FIELD_ANY):
            warnings.append(
                SchemaWarning(
                    rule=rule_name,
                    field=field,
                    message=f"operator {op} used on field {field!r} of type {expected}",
                )
            )
    elif op in ("contains", "intersects", "is_subset"):
        if expected not in (FIELD_LIST, FIELD_STRING, FIELD_ANY):
            warnings.append(
                SchemaWarning(
                    rule=rule_name,
                    field=field,
                    message=f"operator {op} used on field {field!r} of type {expected}",
                )
            )
    elif op == "in":
        if expected not in (FIELD_STRING, FIELD_ANY):
            warnings.append(
                SchemaWarning(
                    rule=rule_name,
                    field=field,
                    message=f"operator 'in' used on field {field!r} of type {expected}",
                )
            )
    return warnings


def _check_field_exists(field: str, schema: Schema, rule_name: str) -> list[SchemaWarning]:
    if _lookup_field(schema, field) is None:
        return [
            SchemaWarning(
                rule=rule_name,
                field=field,
                message=f"field {field!r} not found in schema (used with 'has')",
            )
        ]
    return []


def _check_aggregate_field(field: str, schema: Schema, rule_name: str) -> list[SchemaWarning]:
    expected = _lookup_field(schema, field)
    if expected is None:
        return [
            SchemaWarning(
                rule=rule_name,
                field=field,
                message=f"field {field!r} not found in schema (used with 'count')",
            )
        ]
    if expected not in (FIELD_LIST, FIELD_NUMBER, FIELD_ANY):
        return [
            SchemaWarning(
                rule=rule_name,
                field=field,
                message=f"count() used on field {field!r} of type {expected}, expected list or number",
            )
        ]
    return []


def _check_list_field(field: str, schema: Schema, rule_name: str) -> list[SchemaWarning]:
    expected = _lookup_field(schema, field)
    if expected is None:
        return [
            SchemaWarning(
                rule=rule_name,
                field=field,
                message=f"field {field!r} not found in schema (used with quantifier)",
            )
        ]
    if expected not in (FIELD_LIST, FIELD_ANY):
        return [
            SchemaWarning(
                rule=rule_name,
                field=field,
                message=f"quantifier used on field {field!r} of type {expected}, expected list",
            )
        ]
    return []


def _check_expr_fields(expr: Expr, schema: Schema, rule_name: str) -> list[SchemaWarning]:
    warnings: list[SchemaWarning] = []
    k = expr.kind
    if k == ExprKind.FIELD and expr.field:
        expected = _lookup_field(schema, expr.field)
        if expected is None:
            warnings.append(
                SchemaWarning(
                    rule=rule_name,
                    field=expr.field,
                    message=f"field {expr.field!r} not found in schema (used in arithmetic)",
                )
            )
        elif expected not in (FIELD_NUMBER, FIELD_ANY):
            warnings.append(
                SchemaWarning(
                    rule=rule_name,
                    field=expr.field,
                    message=f"arithmetic used on field {expr.field!r} of type {expected}, expected number",
                )
            )
    elif k == ExprKind.COUNT and expr.agg_target:
        warnings.extend(_check_aggregate_field(expr.agg_target, schema, rule_name))
    elif k == ExprKind.LEN and expr.field:
        expected = _lookup_field(schema, expr.field)
        if expected is None:
            warnings.append(
                SchemaWarning(
                    rule=rule_name,
                    field=expr.field,
                    message=f"field {expr.field!r} not found in schema (used with len)",
                )
            )
    elif k == ExprKind.BINARY:
        if expr.left is not None:
            warnings.extend(_check_expr_fields(expr.left, schema, rule_name))
        if expr.right is not None:
            warnings.extend(_check_expr_fields(expr.right, schema, rule_name))
    return warnings


_interp_re = re.compile(r"\{([^}]+)\}")


def _validate_interpolations(msg: str, schema: Schema, rule_name: str) -> list[SchemaWarning]:
    warnings: list[SchemaWarning] = []
    for match in _interp_re.finditer(msg):
        expr = match.group(1)
        if expr.startswith("count(") and expr.endswith(")"):
            continue
        if _lookup_field(schema, expr) is None:
            warnings.append(
                SchemaWarning(
                    rule=rule_name,
                    field=expr,
                    message=f"message interpolation references unknown field {expr!r}",
                )
            )
    return warnings


def _lookup_field(schema: Schema, field: str):
    if field in schema.fields:
        return schema.fields[field]
    parts = field.split(".")
    for i in range(len(parts) - 1, 0, -1):
        prefix = ".".join(parts[:i])
        if prefix in schema.fields and schema.fields[prefix] == FIELD_MAP:
            return FIELD_ANY
    return None


def format_warnings(warnings: list[SchemaWarning]) -> str:
    if not warnings:
        return ""
    lines = [f"  {w.rule}: {w.message}" for w in warnings]
    return "\n".join(lines) + "\n"
