"""Unit tests for schema validation."""

import os
import sys
import unittest

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), "..")))

import crowdcontrol  # noqa: E402
from crowdcontrol.validate import validate_policies  # noqa: E402


class TestValidate(unittest.TestCase):
    def test_unknown_field(self):
        policies = [crowdcontrol.parse('forbid "r" { unknown.field == "x" }')]
        schema = crowdcontrol.Schema(fields={"resource.type": "string"})
        warnings = validate_policies(policies, schema)
        self.assertTrue(any("unknown.field" in w.field for w in warnings))

    def test_known_field_no_warning(self):
        policies = [crowdcontrol.parse('forbid "r" { resource.type == "x" }')]
        schema = crowdcontrol.Schema(fields={"resource.type": "string"})
        warnings = validate_policies(policies, schema)
        self.assertEqual(warnings, [])

    def test_operator_type_mismatch(self):
        policies = [crowdcontrol.parse('forbid "r" { user.name < 5 }')]
        schema = crowdcontrol.Schema(fields={"user.name": "string"})
        warnings = validate_policies(policies, schema)
        self.assertTrue(any("<" in w.message for w in warnings))

    def test_count_on_non_list(self):
        policies = [crowdcontrol.parse('forbid "r" { count(x) > 3 }')]
        schema = crowdcontrol.Schema(fields={"x": "string"})
        warnings = validate_policies(policies, schema)
        self.assertTrue(any("count" in w.message for w in warnings))

    def test_interpolation_unknown_field(self):
        src = 'forbid "r" { y == "x" message "hi {user.name}" }'
        policies = [crowdcontrol.parse(src)]
        schema = crowdcontrol.Schema(fields={"y": "string"})
        warnings = validate_policies(policies, schema)
        self.assertTrue(any(w.field == "user.name" for w in warnings))


if __name__ == "__main__":
    unittest.main()
