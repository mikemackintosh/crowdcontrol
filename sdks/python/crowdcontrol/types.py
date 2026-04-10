"""AST, Schema, and Result types for CrowdControl.

This is a pure-data module: no behavior, just dataclasses that mirror the
shape of the Go reference implementation at ``github.com/mikemackintosh/crowdcontrol/types``.
"""

from __future__ import annotations

from dataclasses import dataclass, field as _dc_field
from enum import IntEnum
from typing import Any, Optional


class ConditionType(IntEnum):
    FIELD = 0
    AGGREGATE = 1
    OR = 2
    ANY = 3
    ALL = 4
    HAS = 5
    EXPR = 6


class ExprKind(IntEnum):
    FIELD = 0
    LITERAL = 1
    COUNT = 2
    LEN = 3
    BINARY = 4


# Default effect constants (match Go's types.DefaultEffect).
DEFAULT_ALLOW = "allow"
DEFAULT_DENY = "deny"


@dataclass
class Expr:
    kind: ExprKind = ExprKind.LITERAL
    field: str = ""
    value: float = 0.0
    agg_target: str = ""
    transform: str = ""
    op: str = ""
    left: Optional["Expr"] = None
    right: Optional["Expr"] = None


@dataclass
class Condition:
    type: ConditionType = ConditionType.FIELD
    negated: bool = False
    field: str = ""
    op: str = ""
    value: Any = None
    transform: str = ""
    aggregate_func: str = ""
    aggregate_target: str = ""
    or_group: list["Condition"] = _dc_field(default_factory=list)
    quantifier: str = ""
    list_field: str = ""
    predicate: Optional["Condition"] = None
    left_expr: Optional[Expr] = None
    right_expr: Optional[Expr] = None


@dataclass
class Rule:
    kind: str = ""  # "forbid" | "warn" | "permit"
    name: str = ""
    conditions: list[Condition] = _dc_field(default_factory=list)
    unlesses: list[Condition] = _dc_field(default_factory=list)
    message: str = ""
    description: str = ""
    owner: str = ""
    link: str = ""


@dataclass
class Policy:
    rules: list[Rule] = _dc_field(default_factory=list)


@dataclass
class ConditionTrace:
    expr: str = ""
    result: bool = False
    actual: str = ""
    children: list["ConditionTrace"] = _dc_field(default_factory=list)


@dataclass
class RuleTrace:
    conditions: list[ConditionTrace] = _dc_field(default_factory=list)
    unlesses: list[ConditionTrace] = _dc_field(default_factory=list)
    all_conditions_matched: bool = False
    saved_by_unless: bool = False


@dataclass
class Result:
    rule: str = ""
    kind: str = ""
    passed: bool = True
    message: str = ""
    description: str = ""
    owner: str = ""
    link: str = ""
    trace: Optional[RuleTrace] = None


# Schema for static validation.

FIELD_STRING = "string"
FIELD_NUMBER = "number"
FIELD_BOOL = "bool"
FIELD_LIST = "list"
FIELD_MAP = "map"
FIELD_ANY = "any"


@dataclass
class Schema:
    fields: dict[str, str] = _dc_field(default_factory=dict)


@dataclass
class SchemaWarning:
    rule: str = ""
    field: str = ""
    message: str = ""
