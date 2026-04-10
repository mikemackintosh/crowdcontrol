"""Demo: load policies from a directory and evaluate an input document.

Run from the Python SDK root::

    python examples/demo.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), "..")))

import crowdcontrol

POLICY_SOURCE = """
forbid "no-prod-deletes-by-interns" {
    description "Interns may not delete production resources"
    owner       "platform-security"

    user.role == "intern"
    request.action == "delete"
    resource.environment == "production"

    message "{user.name} is an intern and cannot delete production resources"
}

warn "large-changeset" {
    count(plan.changes) > 5
    message "this change touches {count(plan.changes)} resources"
}

permit "emergency-override" {
    user.groups contains "oncall"
    request.labels contains "emergency"
    message "approved as emergency override"
}
"""

INPUT = {
    "user": {"name": "alex", "role": "intern", "groups": ["dev"]},
    "request": {"action": "delete", "labels": ["bugfix"]},
    "resource": {"environment": "production"},
    "plan": {"changes": [1, 2, 3, 4, 5, 6, 7]},
}


def main() -> int:
    eng = crowdcontrol.from_source([POLICY_SOURCE])
    results = eng.evaluate(INPUT)

    print("Input:")
    print(json.dumps(INPUT, indent=2))
    print()
    print("Decisions:")
    for r in results:
        tag = "PASS" if r.passed else ("WARN" if r.kind == "warn" else "DENY")
        msg = f": {r.message}" if r.message else ""
        print(f"  [{tag}] {r.rule} ({r.kind}){msg}")

    output, all_passed = crowdcontrol.format_results(results)
    print()
    print("Summary:")
    print(output, end="")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
