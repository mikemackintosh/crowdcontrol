# CrowdControl Conformance Suite

This directory holds language-agnostic conformance test cases. Every CrowdControl
SDK must run them and produce identical decisions to the Go reference. The suite
is the single source of truth for what "matches the spec" means — when behavior
diverges between SDKs, the suite is what we update first, then port the change
out to every implementation.

## Format

Each `suite/*.json` file is one self-contained test case:

```json
{
  "name": "001_basic_forbid",
  "description": "forbid rule fires when condition matches",
  "policy": "forbid \"no-public-s3\" {\n  resource.type == \"aws_s3_bucket\"\n  resource.acl == \"public-read\"\n  message \"bucket {resource.name} would be public\"\n}\n",
  "input": {
    "resource": {
      "type": "aws_s3_bucket",
      "name": "logs",
      "acl": "public-read"
    }
  },
  "default_effect": "allow",
  "expect": {
    "decisions": [
      {
        "rule": "no-public-s3",
        "kind": "forbid",
        "passed": false,
        "message_contains": "logs would be public"
      }
    ]
  }
}
```

### Fields

| Field            | Required | Meaning                                                                            |
| ---------------- | -------- | ---------------------------------------------------------------------------------- |
| `name`           | yes      | Stable identifier matching the filename stem                                       |
| `description`    | no       | Human-readable summary                                                             |
| `policy`         | yes      | Inline policy source (one or more rules) — newlines as `\n` in JSON                |
| `input`          | yes      | The document to evaluate against                                                   |
| `default_effect` | no       | `"allow"` (default) or `"deny"`                                                    |
| `expect.decisions` | yes    | Ordered list of expected results, one per rule                                     |

### Expected decision shape

Every entry in `expect.decisions` is matched against the actual results
returned by the engine. A test passes when:

1. The number of expected decisions matches the number of actual results.
2. For each expected decision: `rule`, `kind`, and `passed` must match exactly.
3. If `message_contains` is non-empty, `actual.message` must contain that substring.
4. If `message_exact` is set, `actual.message` must equal it exactly.

## Running

### Go reference runner

```bash
cd /Users/duppster/crowdcontrol
go run ./conformance/runners/go -suite ./conformance/suite
```

Exit code 0 = all cases passed. Exit code 1 = at least one case failed.

### Per-SDK runners

Each SDK in `/Users/duppster/crowdcontrol/sdks/<lang>/` is expected to ship
its own runner that consumes the same `suite/*.json` files and produces the
same `PASS`/`FAIL` output. Stage 2 (the SDK port milestone) defines exactly
what each runner looks like.

## Adding a case

1. Create `suite/NNN_short_name.json` where `NNN` is the next sequential number.
2. Run the Go reference runner to confirm it passes.
3. Commit. CI will fail if any other runner regresses.

A new feature is not considered "implemented in CrowdControl" until it has
at least one conformance case covering it.
