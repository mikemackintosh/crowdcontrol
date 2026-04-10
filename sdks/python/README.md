# crowdcontrol-python

Pure-Python SDK for the [CrowdControl](https://github.com/mikemackintosh/crowdcontrol)
policy language. Zero runtime dependencies — only the Python standard library.

## Install

From the repo (editable):

```bash
cd sdks/python
pip install -e .
```

Once published (Stage 2 release):

```bash
pip install crowdcontrol
```

## Quickstart

```python
import crowdcontrol

eng = crowdcontrol.from_source(["""
forbid "no-prod-deletes-by-interns" {
    user.role == "intern"
    request.action == "delete"
    resource.environment == "production"
    message "{user.name} is an intern and cannot delete production resources"
}
"""])

results = eng.evaluate({
    "user":     {"name": "alex", "role": "intern"},
    "request":  {"action": "delete"},
    "resource": {"environment": "production"},
})

for r in results:
    print(r.rule, r.kind, r.passed, r.message)
```

Load from a directory of `.cc` files:

```python
eng = crowdcontrol.from_directory(["./policies"])
results = eng.evaluate(my_input_dict)
```

## Public API

| Function / Class              | Purpose                                               |
| ----------------------------- | ----------------------------------------------------- |
| `crowdcontrol.from_source`    | Build an `Evaluator` from in-memory policy strings    |
| `crowdcontrol.from_directory` | Build an `Evaluator` from a directory of `.cc` files  |
| `crowdcontrol.parse`          | Parse a single source string into a `Policy` AST      |
| `crowdcontrol.Evaluator`      | Core engine (`evaluate`, `validate`, `policies`)      |
| `crowdcontrol.Result`         | One decision per rule                                 |
| `crowdcontrol.Schema`         | Static validation schema                              |
| `crowdcontrol.format_results` | Human-readable result printer                         |
| `crowdcontrol.DEFAULT_ALLOW` / `DEFAULT_DENY` | Default-effect constants              |

See [`crowdcontrol/__init__.py`](crowdcontrol/__init__.py) for the full surface.

## Running the tests

```bash
python -m unittest discover -s tests -v
```

## Conformance

Every CrowdControl SDK ships a runner that consumes the shared conformance
suite at [`../../conformance/suite/`](../../conformance/suite/). The runner
evaluates each case and verifies the results match the Go reference.

```bash
python conformance_runner.py              # runs all 30 cases
python conformance_runner.py -v           # show passing cases too
python conformance_runner.py -f permit    # only run cases matching "permit"
```

Current status: **30 / 30 passing** against the shared suite.

## Differences from the Go reference

None, semantically. The Python SDK produces identical decisions for identical
inputs — this is enforced by the conformance suite. A few representation
notes:

- Python booleans are normalized to the strings `"true"`/`"false"` during
  string-coerced equality comparison, matching Go's `fmt.Sprintf("%v", b)`
  behavior. This keeps `field == true` in a policy compatible with both
  Python `True` and JSON `true` input.
- `None` is treated the same as an absent field.
- `int` and `float` are both valid numeric inputs; the evaluator uses `float`
  internally for all arithmetic.

## License

MIT — see the repo-level [LICENSE](../../LICENSE).
