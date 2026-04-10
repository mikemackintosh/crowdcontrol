"""CrowdControl policy language — Python SDK.

A small, readable policy language for gating actions on structured data.
This package is a pure-Python port of the Go reference implementation at
https://github.com/mikemackintosh/crowdcontrol — zero runtime dependencies,
idiomatic Python API.

Quick start::

    import crowdcontrol

    eng = crowdcontrol.from_source([
        '''
        forbid "no-interns-in-prod" {
            user.role == "intern"
            resource.environment == "production"
            message "{user.name} cannot touch production"
        }
        '''
    ])
    results = eng.evaluate({
        "user": {"name": "alex", "role": "intern"},
        "resource": {"environment": "production"},
    })
    for r in results:
        print(r.rule, r.kind, r.passed, r.message)
"""

from .evaluator import (
    POLICY_EXT,
    Evaluator,
    format_results,
    interpolate_message,
    resolve_field,
)
from .parser import ParseError, parse
from .types import (
    DEFAULT_ALLOW,
    DEFAULT_DENY,
    FIELD_ANY,
    FIELD_BOOL,
    FIELD_LIST,
    FIELD_MAP,
    FIELD_NUMBER,
    FIELD_STRING,
    Condition,
    ConditionTrace,
    ConditionType,
    Expr,
    ExprKind,
    Policy,
    Result,
    Rule,
    RuleTrace,
    Schema,
    SchemaWarning,
)
from .validate import format_warnings, validate_policies

VERSION = "0.1.0"

__all__ = [
    "VERSION",
    "POLICY_EXT",
    "DEFAULT_ALLOW",
    "DEFAULT_DENY",
    "FIELD_ANY",
    "FIELD_BOOL",
    "FIELD_LIST",
    "FIELD_MAP",
    "FIELD_NUMBER",
    "FIELD_STRING",
    "Condition",
    "ConditionTrace",
    "ConditionType",
    "Evaluator",
    "Expr",
    "ExprKind",
    "ParseError",
    "Policy",
    "Result",
    "Rule",
    "RuleTrace",
    "Schema",
    "SchemaWarning",
    "format_results",
    "format_warnings",
    "from_directory",
    "from_source",
    "interpolate_message",
    "parse",
    "resolve_field",
    "validate_policies",
]


def from_directory(policy_dirs, default_effect: str = DEFAULT_ALLOW, explain: bool = False) -> Evaluator:
    """Create an Evaluator by loading every ``*.cc`` file from the given directories."""
    return Evaluator.from_directory(policy_dirs, default_effect=default_effect, explain=explain)


def from_source(sources, default_effect: str = DEFAULT_ALLOW, explain: bool = False) -> Evaluator:
    """Create an Evaluator from in-memory policy source strings."""
    return Evaluator.from_source(sources, default_effect=default_effect, explain=explain)
