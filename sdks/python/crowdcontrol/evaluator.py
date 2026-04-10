"""Evaluator for CrowdControl policies.

Ports github.com/mikemackintosh/crowdcontrol/evaluator/evaluator.go to Python.
Pure stdlib (re for regex).
"""

from __future__ import annotations

import os
import re
from typing import Any, Optional

from .parser import parse
from .types import (
    DEFAULT_ALLOW,
    DEFAULT_DENY,
    Condition,
    ConditionTrace,
    ConditionType,
    Expr,
    ExprKind,
    Policy,
    Result,
    Rule,
    RuleTrace,
)

POLICY_EXT = ".cc"


class Evaluator:
    """Loads and runs CrowdControl policies against JSON-like documents."""

    def __init__(
        self,
        policies: Optional[list[Policy]] = None,
        default_effect: str = DEFAULT_ALLOW,
        explain: bool = False,
    ) -> None:
        self._policies: list[Policy] = policies or []
        self._default_effect = default_effect
        self._explain = explain

    # ----- construction ----------------------------------------------------

    @classmethod
    def from_directory(
        cls,
        policy_dirs: list[str],
        default_effect: str = DEFAULT_ALLOW,
        explain: bool = False,
    ) -> "Evaluator":
        """Load every ``*.cc`` file from each of the given directories."""
        policies: list[Policy] = []
        for d in policy_dirs:
            if not os.path.isdir(d):
                continue
            for name in sorted(os.listdir(d)):
                path = os.path.join(d, name)
                if not os.path.isfile(path) or not name.endswith(POLICY_EXT):
                    continue
                with open(path, "r", encoding="utf-8") as f:
                    src = f.read()
                policies.append(parse(src))
        return cls(policies=policies, default_effect=default_effect, explain=explain)

    @classmethod
    def from_source(
        cls,
        sources: list[str],
        default_effect: str = DEFAULT_ALLOW,
        explain: bool = False,
    ) -> "Evaluator":
        """Parse each source string as a standalone policy file."""
        policies = [parse(src) for src in sources]
        return cls(policies=policies, default_effect=default_effect, explain=explain)

    @property
    def policies(self) -> list[Policy]:
        return self._policies

    # ----- evaluation ------------------------------------------------------

    def evaluate(self, doc: dict) -> list[Result]:
        results: list[Result] = []
        permit_fired = False
        forbid_fired = False

        for policy in self._policies:
            for rule in policy.rules:
                r = self._eval_rule(rule, doc)
                results.append(r)
                if r.kind == "permit" and r.message != "":
                    permit_fired = True
                if r.kind == "forbid" and not r.passed:
                    forbid_fired = True

        if (
            self._default_effect == DEFAULT_DENY
            and not permit_fired
            and not forbid_fired
        ):
            results.append(
                Result(
                    rule="(default-deny)",
                    kind="forbid",
                    passed=False,
                    message="no permit rule matched — denied by default",
                )
            )

        return results

    # ----- rule evaluation -------------------------------------------------

    def _eval_rule(self, rule: Rule, doc: dict) -> Result:
        result = Result(
            rule=rule.name,
            kind=rule.kind,
            passed=True,
            description=rule.description,
            owner=rule.owner,
            link=rule.link,
        )

        trace: Optional[RuleTrace] = RuleTrace() if self._explain else None

        all_match = True
        for cond in rule.conditions:
            matched = eval_condition(cond, doc)
            if trace is not None:
                trace.conditions.append(trace_condition(cond, doc, matched))
            if not matched:
                all_match = False
                if trace is None:
                    break

        if trace is not None:
            trace.all_conditions_matched = all_match

        if not all_match:
            if trace is not None:
                result.trace = trace
            return result

        saved = False
        for u in rule.unlesses:
            matched = eval_condition(u, doc)
            if trace is not None:
                trace.unlesses.append(trace_condition(u, doc, matched))
            if matched:
                saved = True
                if trace is None:
                    break

        if trace is not None:
            trace.saved_by_unless = saved

        if saved:
            if trace is not None:
                result.trace = trace
            return result

        # Rule fires
        if rule.kind == "permit":
            result.passed = True
            result.message = interpolate_message(rule.message, doc)
        else:
            result.passed = False
            result.message = interpolate_message(rule.message, doc)

        if trace is not None:
            result.trace = trace
        return result

    # ----- schema validation wrapper --------------------------------------

    def validate(self, schema) -> list:
        from .validate import validate_policies
        return validate_policies(self._policies, schema)


# ===========================================================================
# Condition evaluation
# ===========================================================================


def eval_condition(cond: Condition, doc: dict) -> bool:
    result = _eval_condition_inner(cond, doc)
    if cond.negated:
        return not result
    return result


def _eval_condition_inner(cond: Condition, doc: dict) -> bool:
    t = cond.type
    if t == ConditionType.AGGREGATE:
        return _eval_aggregate(cond, doc)
    if t == ConditionType.FIELD:
        return _eval_field_condition(cond, doc)
    if t == ConditionType.OR:
        return any(eval_condition(sub, doc) for sub in cond.or_group)
    if t == ConditionType.ANY:
        return _eval_quantifier(cond, doc, require_all=False)
    if t == ConditionType.ALL:
        return _eval_quantifier(cond, doc, require_all=True)
    if t == ConditionType.HAS:
        return resolve_field(cond.field, doc) is not None
    if t == ConditionType.EXPR:
        return _eval_expr_condition(cond, doc)
    return False


def _eval_quantifier(cond: Condition, doc: dict, require_all: bool) -> bool:
    items = _to_list(resolve_field(cond.list_field, doc))
    if items is None:
        return require_all
    if len(items) == 0:
        return require_all
    if cond.predicate is None:
        return False
    for item in items:
        matched = _eval_element_predicate(cond.predicate, doc, item)
        if require_all and not matched:
            return False
        if not require_all and matched:
            return True
    return require_all


def _eval_element_predicate(pred: Condition, doc: dict, element: Any) -> bool:
    elem_str = _fmt_v(element)
    if pred.type != ConditionType.FIELD:
        return False
    op = pred.op
    if op == "==":
        return elem_str == _fmt_v(pred.value)
    if op == "!=":
        return elem_str != _fmt_v(pred.value)
    if op == "in":
        lst = pred.value if isinstance(pred.value, list) else None
        if lst is None:
            return False
        return any(elem_str == item for item in lst)
    if op == "matches":
        pattern = pred.value
        if not isinstance(pattern, str):
            return False
        return _glob_match(pattern, elem_str)
    if op == "matches_regex":
        pattern = pred.value
        if not isinstance(pattern, str):
            return False
        return _regex_match(pattern, elem_str)
    if op == "contains":
        return _eval_contains(element, pred.value)
    return _compare_values(element, op, pred.value)


def _eval_expr_condition(cond: Condition, doc: dict) -> bool:
    if cond.left_expr is None or cond.right_expr is None:
        return False
    left, lok = _eval_expr(cond.left_expr, doc)
    right, rok = _eval_expr(cond.right_expr, doc)
    if not lok or not rok:
        return False
    return _compare_floats(left, cond.op, right)


def _eval_expr(expr: Expr, doc: dict) -> tuple[float, bool]:
    k = expr.kind
    if k == ExprKind.LITERAL:
        return expr.value, True
    if k == ExprKind.FIELD:
        val = resolve_field(expr.field, doc)
        f = _to_float(val)
        if f is None:
            return 0.0, False
        return f, True
    if k == ExprKind.COUNT:
        val = resolve_field(expr.agg_target, doc)
        if isinstance(val, list):
            return float(len(val)), True
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return float(val), True
        return 0.0, False
    if k == ExprKind.LEN:
        val = resolve_field(expr.field, doc)
        if isinstance(val, str):
            return float(len(val)), True
        if isinstance(val, list):
            return float(len(val)), True
        if val is None:
            return 0.0, True
        return 0.0, False
    if k == ExprKind.BINARY:
        if expr.left is None or expr.right is None:
            return 0.0, False
        left, lok = _eval_expr(expr.left, doc)
        right, rok = _eval_expr(expr.right, doc)
        if not lok or not rok:
            return 0.0, False
        if expr.op == "+":
            return left + right, True
        if expr.op == "-":
            return left - right, True
        if expr.op == "*":
            return left * right, True
        if expr.op == "/":
            if right == 0:
                return 0.0, False
            return left / right, True
    return 0.0, False


def _eval_aggregate(cond: Condition, doc: dict) -> bool:
    val = resolve_field(cond.aggregate_target, doc)
    if isinstance(val, list):
        count = len(val)
    elif isinstance(val, (int, float)) and not isinstance(val, bool):
        count = int(val)
    else:
        return False
    target = cond.value
    if not isinstance(target, int):
        return False
    return _compare_ints(count, cond.op, target)


def _eval_field_condition(cond: Condition, doc: dict) -> bool:
    val = resolve_field(cond.field, doc)
    if cond.transform:
        val = _apply_transform(cond.transform, val)

    op = cond.op
    if op == "==":
        return _fmt_v(val) == _fmt_v(cond.value)
    if op == "!=":
        return _fmt_v(val) != _fmt_v(cond.value)
    if op in ("<", ">", "<=", ">="):
        return _compare_values(val, op, cond.value)
    if op == "in":
        lst = cond.value if isinstance(cond.value, list) else None
        if lst is None:
            return False
        s = _fmt_v(val)
        return any(s == item for item in lst)
    if op == "matches":
        pattern = cond.value
        if not isinstance(pattern, str):
            return False
        return _glob_match(pattern, _fmt_v(val))
    if op == "matches_regex":
        pattern = cond.value
        if not isinstance(pattern, str):
            return False
        return _regex_match(pattern, _fmt_v(val))
    if op == "contains":
        return _eval_contains(val, cond.value)
    if op == "intersects":
        return _eval_intersects(val, cond.value)
    if op == "is_subset":
        return _eval_is_subset(val, cond.value)
    return False


def _eval_contains(val: Any, target: Any) -> bool:
    target_str = _fmt_v(target)
    if isinstance(val, list):
        return any(_fmt_v(item) == target_str for item in val)
    if isinstance(val, str):
        return target_str in val
    return False


def _eval_intersects(val: Any, target: Any) -> bool:
    if not isinstance(target, list):
        return False
    rhs_set = set(target)
    if isinstance(val, list):
        return any(_fmt_v(item) in rhs_set for item in val)
    return False


def _eval_is_subset(val: Any, target: Any) -> bool:
    if not isinstance(target, list):
        return False
    rhs_set = set(target)
    if isinstance(val, list):
        if len(val) == 0:
            return True
        return all(_fmt_v(item) in rhs_set for item in val)
    return False


# ===========================================================================
# Trace / explain
# ===========================================================================


def trace_condition(cond: Condition, doc: dict, result: bool) -> ConditionTrace:
    ct = ConditionTrace(
        expr=_condition_expr(cond),
        result=result,
        actual=_resolve_actual(cond, doc),
    )
    if cond.type == ConditionType.OR:
        for sub in cond.or_group:
            sub_result = eval_condition(sub, doc)
            ct.children.append(trace_condition(sub, doc, sub_result))
    return ct


def _condition_expr(cond: Condition) -> str:
    prefix = "not " if cond.negated else ""
    t = cond.type
    if t == ConditionType.FIELD:
        field = cond.field
        if cond.transform:
            field = f"{cond.transform}({cond.field})"
        return f"{prefix}{field} {cond.op} {_format_value(cond.value)}"
    if t == ConditionType.AGGREGATE:
        return f"{prefix}count({cond.aggregate_target}) {cond.op} {cond.value}"
    if t == ConditionType.HAS:
        return f"{prefix}has {cond.field}"
    if t == ConditionType.ANY:
        if cond.predicate is not None:
            return f"{prefix}any {cond.list_field} {cond.predicate.op} {_format_value(cond.predicate.value)}"
        return f"{prefix}any {cond.list_field} <predicate>"
    if t == ConditionType.ALL:
        if cond.predicate is not None:
            return f"{prefix}all {cond.list_field} {cond.predicate.op} {_format_value(cond.predicate.value)}"
        return f"{prefix}all {cond.list_field} <predicate>"
    if t == ConditionType.OR:
        return prefix + " or ".join(_condition_expr(sub) for sub in cond.or_group)
    if t == ConditionType.EXPR:
        return f"{prefix}{_expr_string(cond.left_expr)} {cond.op} {_expr_string(cond.right_expr)}"
    return prefix + "<unknown>"


def _expr_string(expr: Optional[Expr]) -> str:
    if expr is None:
        return "<nil>"
    k = expr.kind
    if k == ExprKind.FIELD:
        return expr.field
    if k == ExprKind.LITERAL:
        if expr.value == int(expr.value):
            return str(int(expr.value))
        return f"{expr.value}"
    if k == ExprKind.COUNT:
        return f"count({expr.agg_target})"
    if k == ExprKind.LEN:
        return f"len({expr.field})"
    if k == ExprKind.BINARY:
        return f"{_expr_string(expr.left)} {expr.op} {_expr_string(expr.right)}"
    return "<unknown>"


def _resolve_actual(cond: Condition, doc: dict) -> str:
    t = cond.type
    if t == ConditionType.FIELD:
        return _format_actual(resolve_field(cond.field, doc))
    if t == ConditionType.AGGREGATE:
        val = resolve_field(cond.aggregate_target, doc)
        if isinstance(val, list):
            return str(len(val))
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return str(int(val))
        return "<nil>"
    if t == ConditionType.HAS:
        val = resolve_field(cond.field, doc)
        return "exists" if val is not None else "<nil>"
    if t in (ConditionType.ANY, ConditionType.ALL):
        val = resolve_field(cond.list_field, doc)
        items = _to_list(val)
        if items is None:
            return "<nil>"
        return f"[{len(items)} items]"
    if t == ConditionType.EXPR:
        if cond.left_expr is not None and cond.right_expr is not None:
            lv, lok = _eval_expr(cond.left_expr, doc)
            rv, rok = _eval_expr(cond.right_expr, doc)
            if lok and rok:
                return f"{lv} vs {rv}"
        return ""
    return ""


def _format_value(v: Any) -> str:
    if isinstance(v, str):
        return f'"{v}"'
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return "[" + ", ".join(f'"{x}"' for x in v) + "]"
    return _fmt_v(v)


def _format_actual(v: Any) -> str:
    if v is None:
        return "<nil>"
    if isinstance(v, list):
        if len(v) <= 5:
            return "[" + ", ".join(_fmt_v(item) for item in v) + "]"
        return f"[{len(v)} items]"
    if isinstance(v, str):
        return f'"{v}"'
    return _fmt_v(v)


# ===========================================================================
# Helpers
# ===========================================================================


_regex_cache: dict[str, Optional[re.Pattern]] = {}


def _regex_match(pattern: str, s: str) -> bool:
    if pattern not in _regex_cache:
        try:
            _regex_cache[pattern] = re.compile(pattern)
        except re.error:
            _regex_cache[pattern] = None
    compiled = _regex_cache[pattern]
    if compiled is None:
        return False
    return compiled.search(s) is not None


def _glob_match(pattern: str, s: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*") and not pattern.startswith("*"):
        return s.startswith(pattern[:-1])
    if pattern.startswith("*") and not pattern.endswith("*"):
        return s.endswith(pattern[1:])
    star = pattern.find("*")
    if star >= 0:
        prefix = pattern[:star]
        suffix = pattern[star + 1 :]
        return s.startswith(prefix) and s.endswith(suffix)
    return pattern == s


def resolve_field(path: str, doc: dict) -> Any:
    """Resolve a dotted path against a document. Returns None if missing."""
    if doc is None:
        return None
    current: Any = doc
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _to_list(v: Any) -> Optional[list]:
    if isinstance(v, list):
        return v
    return None


def _to_float(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    return None


def _compare_ints(a: int, op: str, b: int) -> bool:
    return _compare_floats(float(a), op, float(b))


def _compare_values(a: Any, op: str, b: Any) -> bool:
    af = _to_float(a)
    bf = _to_float(b)
    if af is not None and bf is not None:
        return _compare_floats(af, op, bf)
    return False


def _compare_floats(a: float, op: str, b: float) -> bool:
    if op == "<":
        return a < b
    if op == ">":
        return a > b
    if op == "<=":
        return a <= b
    if op == ">=":
        return a >= b
    if op == "==":
        return a == b
    if op == "!=":
        return a != b
    return False


def _apply_transform(transform: str, val: Any) -> Any:
    if transform == "lower":
        if isinstance(val, str):
            return val.lower()
        return _fmt_v(val).lower()
    if transform == "upper":
        if isinstance(val, str):
            return val.upper()
        return _fmt_v(val).upper()
    if transform == "len":
        if isinstance(val, (str, list)):
            return len(val)
        if val is None:
            return 0
        return 0
    return val


def _fmt_v(v: Any) -> str:
    """Format a value the way Go's fmt.Sprintf("%v", v) would.

    The only subtlety is bools: Go prints ``true``/``false`` (lowercase),
    Python's ``str(True)`` is ``"True"``. Within a single Python SDK that
    doesn't matter because both sides of a comparison go through the same
    formatter. But for consistency with the Go reference (and so that the
    conformance suite behaves identically when booleans appear in policies
    or inputs), we lower-case booleans explicitly.
    """
    if v is None:
        return "<nil>"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        if v == int(v):
            return str(int(v))
        return str(v)
    return str(v)


# ===========================================================================
# Message interpolation
# ===========================================================================

_interp_re = re.compile(r"\{([^}]+)\}")


def interpolate_message(msg: str, doc: dict) -> str:
    if msg == "":
        return "policy violation"

    def replace(match: re.Match) -> str:
        expr = match.group(1)
        if expr.startswith("count(") and expr.endswith(")"):
            target = expr[6:-1]
            val = resolve_field(target, doc)
            if isinstance(val, list):
                return str(len(val))
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                return str(int(val))
            return match.group(0)
        val = resolve_field(expr, doc)
        if val is None:
            return match.group(0)
        return _fmt_v(val)

    return _interp_re.sub(replace, msg)


# ===========================================================================
# Output formatting
# ===========================================================================


def format_results(results: list[Result]) -> tuple[str, bool]:
    all_passed = True
    lines: list[str] = []
    for r in results:
        if r.passed:
            continue
        prefix = "DENY"
        if r.kind == "warn":
            prefix = "WARN"
        else:
            all_passed = False
        line = f"{prefix}: {r.message} ({r.rule})"
        meta = []
        if r.owner:
            meta.append(f"owner: {r.owner}")
        if r.link:
            meta.append(f"link: {r.link}")
        if meta:
            line += " [" + ", ".join(meta) + "]"
        lines.append(line)
    if all_passed:
        passed = sum(1 for r in results if r.passed)
        lines.append(f"PASS: {passed} rules evaluated, all passed")
    return "\n".join(lines) + ("\n" if lines else ""), all_passed
