#!/usr/bin/env python3
"""Python SDK conformance runner.

Reads every case file in the shared conformance suite
(``../../conformance/suite/*.json``), runs it through the Python
implementation, and verifies the results match the expected decisions.

Usage::

    python conformance_runner.py [SUITE_DIR]

Exits 0 on full pass, 1 on any failure.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

# Allow running directly from the package dir without install.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import crowdcontrol  # noqa: E402

DEFAULT_SUITE = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "conformance", "suite")
)


def load_case(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_case(case: dict[str, Any]) -> tuple[bool, str]:
    default_effect = case.get("default_effect") or "allow"
    if default_effect not in ("allow", "deny"):
        return False, f"unknown default_effect {default_effect!r}"

    try:
        eng = crowdcontrol.from_source([case["policy"]], default_effect=default_effect)
    except crowdcontrol.ParseError as e:
        return False, f"parse error: {e}"

    results = eng.evaluate(case.get("input", {}))
    expected = case.get("expect", {}).get("decisions", [])

    if len(results) != len(expected):
        summary = " ".join(
            f"[{r.rule}/{r.kind} passed={r.passed}]" for r in results
        )
        return False, f"expected {len(expected)} decisions, got {len(results)} (results: {summary})"

    for i, want in enumerate(expected):
        got = results[i]
        if got.rule != want["rule"]:
            return False, f"decision[{i}]: rule = {got.rule!r}, want {want['rule']!r}"
        if got.kind != want["kind"]:
            return False, f"decision[{i}] ({got.rule}): kind = {got.kind!r}, want {want['kind']!r}"
        if got.passed != want["passed"]:
            return False, f"decision[{i}] ({got.rule}): passed = {got.passed}, want {want['passed']}"
        if "message_exact" in want and want["message_exact"] != "" and got.message != want["message_exact"]:
            return False, (
                f"decision[{i}] ({got.rule}): message = {got.message!r}, "
                f"want exact {want['message_exact']!r}"
            )
        if "message_contains" in want and want["message_contains"] != "" and want["message_contains"] not in got.message:
            return False, (
                f"decision[{i}] ({got.rule}): message = {got.message!r}, "
                f"want contains {want['message_contains']!r}"
            )

    return True, ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the CrowdControl conformance suite against the Python SDK")
    parser.add_argument("suite", nargs="?", default=DEFAULT_SUITE, help="path to conformance/suite directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="print passing cases too")
    parser.add_argument("-f", "--filter", default="", help="only run cases whose name contains this substring")
    args = parser.parse_args()

    if not os.path.isdir(args.suite):
        print(f"suite dir not found: {args.suite}", file=sys.stderr)
        return 2

    files = sorted(
        os.path.join(args.suite, f)
        for f in os.listdir(args.suite)
        if f.endswith(".json") and not os.path.isdir(os.path.join(args.suite, f))
    )
    if not files:
        print(f"no conformance cases in {args.suite}", file=sys.stderr)
        return 2

    passed = 0
    failed = 0
    for path in files:
        try:
            case = load_case(path)
        except Exception as e:
            print(f"FAIL: {os.path.basename(path)} — load error: {e}")
            failed += 1
            continue

        name = case.get("name") or os.path.splitext(os.path.basename(path))[0]
        if args.filter and args.filter not in name:
            continue

        ok, msg = run_case(case)
        if ok:
            passed += 1
            if args.verbose:
                print(f"PASS: {name}")
        else:
            failed += 1
            print(f"FAIL: {name} — {msg}")

    print()
    print(f"{passed} passed, {failed} failed")
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
