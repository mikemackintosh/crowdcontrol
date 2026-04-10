"""Unit tests for the CrowdControl evaluator."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), "..")))

import crowdcontrol  # noqa: E402


class TestEvaluator(unittest.TestCase):
    def _eval(self, policy_src, doc, default_effect="allow"):
        eng = crowdcontrol.from_source([policy_src], default_effect=default_effect)
        return eng.evaluate(doc)

    def test_forbid_fires(self):
        results = self._eval(
            'forbid "r" { x == "y" message "m" }',
            {"x": "y"},
        )
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].passed)
        self.assertEqual(results[0].message, "m")

    def test_forbid_does_not_fire(self):
        results = self._eval(
            'forbid "r" { x == "y" message "m" }',
            {"x": "z"},
        )
        self.assertTrue(results[0].passed)
        self.assertEqual(results[0].message, "")

    def test_unless_saves(self):
        src = '''
        forbid "r" {
          x == "a"
          unless y == "b"
          message "blocked"
        }
        '''
        r_saved = self._eval(src, {"x": "a", "y": "b"})
        self.assertTrue(r_saved[0].passed)
        r_blocked = self._eval(src, {"x": "a", "y": "c"})
        self.assertFalse(r_blocked[0].passed)

    def test_has_condition(self):
        results = self._eval(
            'forbid "r" { has x.y message "m" }',
            {"x": {"y": 1}},
        )
        self.assertFalse(results[0].passed)

    def test_has_missing(self):
        results = self._eval(
            'forbid "r" { has x.y message "m" }',
            {"x": {}},
        )
        self.assertTrue(results[0].passed)

    def test_numeric_comparison(self):
        src = 'forbid "r" { size > 100 message "big" }'
        self.assertFalse(self._eval(src, {"size": 200})[0].passed)
        self.assertTrue(self._eval(src, {"size": 50})[0].passed)

    def test_in_list(self):
        src = 'forbid "r" { t in ["a", "b", "c"] message "x" }'
        self.assertFalse(self._eval(src, {"t": "b"})[0].passed)
        self.assertTrue(self._eval(src, {"t": "d"})[0].passed)

    def test_matches_glob(self):
        src = 'forbid "r" { name matches "prod-*" message "x" }'
        self.assertFalse(self._eval(src, {"name": "prod-api"})[0].passed)
        self.assertTrue(self._eval(src, {"name": "stg-api"})[0].passed)

    def test_matches_regex(self):
        src = 'forbid "r" { v matches_regex "^v[0-9]+$" message "x" }'
        self.assertFalse(self._eval(src, {"v": "v42"})[0].passed)
        self.assertTrue(self._eval(src, {"v": "release"})[0].passed)

    def test_contains_list(self):
        src = 'forbid "r" { tags contains "prod" message "x" }'
        self.assertFalse(self._eval(src, {"tags": ["dev", "prod"]})[0].passed)
        self.assertTrue(self._eval(src, {"tags": ["dev"]})[0].passed)

    def test_intersects(self):
        src = 'forbid "r" { tags intersects ["a", "b"] message "x" }'
        self.assertFalse(self._eval(src, {"tags": ["x", "a"]})[0].passed)
        self.assertTrue(self._eval(src, {"tags": ["x", "y"]})[0].passed)

    def test_is_subset(self):
        src = 'forbid "r" { not actions is_subset ["read"] message "x" }'
        self.assertFalse(self._eval(src, {"actions": ["read", "write"]})[0].passed)
        self.assertTrue(self._eval(src, {"actions": ["read"]})[0].passed)

    def test_any_quantifier(self):
        src = 'forbid "r" { any ports == 22 message "x" }'
        self.assertFalse(self._eval(src, {"ports": [80, 22, 443]})[0].passed)
        self.assertTrue(self._eval(src, {"ports": [80, 443]})[0].passed)

    def test_all_quantifier(self):
        src = 'forbid "r" { not all tags matches "prod-*" message "x" }'
        self.assertFalse(self._eval(src, {"tags": ["prod-a", "stg-b"]})[0].passed)
        self.assertTrue(self._eval(src, {"tags": ["prod-a", "prod-b"]})[0].passed)

    def test_count_aggregate(self):
        src = 'forbid "r" { count(items) > 3 message "x" }'
        self.assertFalse(self._eval(src, {"items": [1, 2, 3, 4]})[0].passed)
        self.assertTrue(self._eval(src, {"items": [1]})[0].passed)

    def test_arithmetic_expression(self):
        src = 'forbid "r" { a + b > c message "x" }'
        self.assertFalse(self._eval(src, {"a": 10, "b": 5, "c": 12})[0].passed)
        self.assertTrue(self._eval(src, {"a": 1, "b": 1, "c": 100})[0].passed)

    def test_lower_transform(self):
        src = 'forbid "r" { lower(name) == "admin" message "x" }'
        self.assertFalse(self._eval(src, {"name": "ADMIN"})[0].passed)

    def test_upper_transform(self):
        src = 'forbid "r" { upper(env) == "PROD" message "x" }'
        self.assertFalse(self._eval(src, {"env": "prod"})[0].passed)

    def test_len_transform(self):
        src = 'forbid "r" { len(name) == 0 message "x" }'
        self.assertFalse(self._eval(src, {"name": ""})[0].passed)

    def test_or_group(self):
        src = 'forbid "r" { x == "a" or x == "b" message "x" }'
        self.assertFalse(self._eval(src, {"x": "b"})[0].passed)
        self.assertTrue(self._eval(src, {"x": "c"})[0].passed)

    def test_message_interpolation(self):
        src = 'forbid "r" { role == "intern" message "{name} is intern" }'
        r = self._eval(src, {"role": "intern", "name": "alex"})[0]
        self.assertEqual(r.message, "alex is intern")

    def test_count_interpolation(self):
        src = 'forbid "r" { count(xs) > 2 message "{count(xs)} items" }'
        r = self._eval(src, {"xs": [1, 2, 3]})[0]
        self.assertEqual(r.message, "3 items")

    def test_default_deny_with_permit(self):
        src = 'permit "admins" { role == "admin" message "ok" }'
        results = self._eval(src, {"role": "admin"}, default_effect="deny")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].passed)

    def test_default_deny_without_match(self):
        src = 'permit "admins" { role == "admin" message "ok" }'
        results = self._eval(src, {"role": "user"}, default_effect="deny")
        self.assertEqual(len(results), 2)
        self.assertEqual(results[1].rule, "(default-deny)")
        self.assertFalse(results[1].passed)

    def test_warn_kind(self):
        src = 'warn "w" { draft == true message "draft pr" }'
        r = self._eval(src, {"draft": True})[0]
        self.assertEqual(r.kind, "warn")
        self.assertFalse(r.passed)
        self.assertEqual(r.message, "draft pr")

    def test_permit_kind_passed_stays_true(self):
        src = 'permit "p" { role == "admin" message "ok" }'
        r = self._eval(src, {"role": "admin"})[0]
        self.assertTrue(r.passed)
        self.assertEqual(r.message, "ok")

    def test_from_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "rules.cc"), "w") as f:
                f.write('forbid "r" { x == "y" message "m" }')
            eng = crowdcontrol.from_directory([tmp])
            self.assertEqual(len(eng.policies), 1)
            r = eng.evaluate({"x": "y"})
            self.assertFalse(r[0].passed)


if __name__ == "__main__":
    unittest.main()
