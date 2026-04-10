"""Unit tests for the CrowdControl parser."""

import os
import sys
import unittest

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), "..")))

from crowdcontrol.parser import ParseError, parse  # noqa: E402
from crowdcontrol.types import ConditionType, ExprKind  # noqa: E402


class TestParser(unittest.TestCase):
    def test_empty_policy(self):
        p = parse("")
        self.assertEqual(len(p.rules), 0)

    def test_simple_forbid(self):
        src = 'forbid "r" { x.y == "z" message "m" }'
        p = parse(src)
        self.assertEqual(len(p.rules), 1)
        r = p.rules[0]
        self.assertEqual(r.kind, "forbid")
        self.assertEqual(r.name, "r")
        self.assertEqual(r.message, "m")
        self.assertEqual(len(r.conditions), 1)
        c = r.conditions[0]
        self.assertEqual(c.type, ConditionType.FIELD)
        self.assertEqual(c.field, "x.y")
        self.assertEqual(c.op, "==")
        self.assertEqual(c.value, "z")

    def test_warn_and_permit(self):
        src = '''
        warn "w" { a == 1 }
        permit "p" { b == 2 }
        '''
        p = parse(src)
        self.assertEqual([r.kind for r in p.rules], ["warn", "permit"])

    def test_metadata_clauses(self):
        src = '''
        forbid "r" {
          description "d"
          owner "o"
          link "l"
          x == "y"
        }
        '''
        p = parse(src)
        r = p.rules[0]
        self.assertEqual(r.description, "d")
        self.assertEqual(r.owner, "o")
        self.assertEqual(r.link, "l")

    def test_unless(self):
        src = '''
        forbid "r" {
          x == "a"
          unless y == "b"
        }
        '''
        p = parse(src)
        r = p.rules[0]
        self.assertEqual(len(r.conditions), 1)
        self.assertEqual(len(r.unlesses), 1)

    def test_has_condition(self):
        src = 'forbid "r" { has foo.bar }'
        p = parse(src)
        c = p.rules[0].conditions[0]
        self.assertEqual(c.type, ConditionType.HAS)
        self.assertEqual(c.field, "foo.bar")

    def test_not_negation(self):
        src = 'forbid "r" { not x == "y" }'
        p = parse(src)
        c = p.rules[0].conditions[0]
        self.assertTrue(c.negated)

    def test_quantifier_any(self):
        src = 'forbid "r" { any tags == "prod" }'
        p = parse(src)
        c = p.rules[0].conditions[0]
        self.assertEqual(c.type, ConditionType.ANY)
        self.assertEqual(c.list_field, "tags")
        self.assertIsNotNone(c.predicate)

    def test_quantifier_all(self):
        src = 'forbid "r" { all ports < 1024 }'
        p = parse(src)
        c = p.rules[0].conditions[0]
        self.assertEqual(c.type, ConditionType.ALL)

    def test_count_aggregate(self):
        src = 'forbid "r" { count(items) > 5 }'
        p = parse(src)
        c = p.rules[0].conditions[0]
        self.assertEqual(c.type, ConditionType.AGGREGATE)
        self.assertEqual(c.aggregate_target, "items")
        self.assertEqual(c.op, ">")
        self.assertEqual(c.value, 5)

    def test_in_list(self):
        src = 'forbid "r" { x in ["a", "b", "c"] }'
        p = parse(src)
        c = p.rules[0].conditions[0]
        self.assertEqual(c.op, "in")
        self.assertEqual(c.value, ["a", "b", "c"])

    def test_matches_and_matches_regex(self):
        p = parse('forbid "r" { name matches "foo-*" }')
        self.assertEqual(p.rules[0].conditions[0].op, "matches")
        p = parse('forbid "r" { name matches_regex "^v[0-9]+$" }')
        self.assertEqual(p.rules[0].conditions[0].op, "matches_regex")

    def test_transforms(self):
        for tr in ("lower", "upper", "len"):
            src = f'forbid "r" {{ {tr}(x.y) == "z" }}'
            p = parse(src)
            c = p.rules[0].conditions[0]
            self.assertEqual(c.transform, tr)

    def test_arithmetic_expression(self):
        src = 'forbid "r" { a + b > c }'
        p = parse(src)
        c = p.rules[0].conditions[0]
        self.assertEqual(c.type, ConditionType.EXPR)
        self.assertEqual(c.op, ">")
        self.assertIsNotNone(c.left_expr)
        self.assertEqual(c.left_expr.kind, ExprKind.BINARY)

    def test_or_group(self):
        src = 'forbid "r" { a == 1 or b == 2 or c == 3 }'
        p = parse(src)
        c = p.rules[0].conditions[0]
        self.assertEqual(c.type, ConditionType.OR)
        self.assertEqual(len(c.or_group), 3)

    def test_parse_error_missing_brace(self):
        with self.assertRaises(ParseError):
            parse('forbid "r" x == "y"')

    def test_parse_error_bad_kind(self):
        with self.assertRaises(ParseError):
            parse('deny "r" { x == "y" }')

    def test_boolean_literals(self):
        src = 'forbid "r" { x == true }'
        p = parse(src)
        self.assertEqual(p.rules[0].conditions[0].value, True)

    def test_numeric_literal(self):
        src = 'forbid "r" { x == 42 }'
        p = parse(src)
        self.assertEqual(p.rules[0].conditions[0].value, 42)

    def test_contains(self):
        p = parse('forbid "r" { tags contains "prod" }')
        self.assertEqual(p.rules[0].conditions[0].op, "contains")
        self.assertEqual(p.rules[0].conditions[0].value, "prod")

    def test_intersects(self):
        p = parse('forbid "r" { tags intersects ["a", "b"] }')
        self.assertEqual(p.rules[0].conditions[0].op, "intersects")
        self.assertEqual(p.rules[0].conditions[0].value, ["a", "b"])


if __name__ == "__main__":
    unittest.main()
