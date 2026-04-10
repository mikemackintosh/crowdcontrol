# CrowdControl Policy Language

CrowdControl is a generic, dependency-free policy language for evaluating rules against
arbitrary JSON documents. It uses Cedar-like syntax with support for aggregate
checks, quantifiers, and dynamic field resolution.

## Design Goals

1. Cedar's readability — `permit`, `forbid`, `warn`, `unless`
2. Generic flat input model — evaluate any `map[string]any` document
3. Aggregate support — count resources, blast radius checks
4. Zero external dependencies — parser and evaluator are pure Go
5. Compile-time validation — catch errors before runtime
6. Caller-controlled input shape — no domain concepts baked into the language

## Syntax

```crowdcontrol
# Block comments
// Line comments

# Simple team gate using flat fields
forbid "okta-author-gate" {
  description "Prevents unauthorized Okta modifications"
  owner "enterprise-security"
  link "https://wiki.example.com/okta-policy"
  resource.type matches "okta_*"
  unless author.teams contains "enterprise-security"
  message "{author.name} cannot modify {resource.type}.{resource.name}"
}

# Approval gate using flat approver teams
forbid "route53-approval" {
  resource.type in ["aws_route53_record", "aws_route53_zone"]
  unless approver.teams contains "enterprise-security"
  message "{resource.type}.{resource.name} requires approval from enterprise-security"
}

# Label check via contains
forbid "sensitive-resources" {
  resource.type in [
    "aws_iam_role", "aws_iam_policy", "aws_iam_user",
    "aws_kms_key", "aws_secretsmanager_secret"
  ]
  unless author.teams contains "enterprise-security"
  unless labels contains "security-approved"
  message "{resource.type} requires enterprise-security or security-approved label"
}

# Blast radius — aggregate check across all changes
forbid "blast-radius" {
  count(plan.destroys) > 5
  unless author.teams contains "platform-team"
  message "too many destroys ({count(plan.destroys)}) — requires platform-team"
}

# PR hygiene
forbid "no-draft-production" {
  pr.draft == true
  project.workspace == "production"
  message "draft PRs cannot target production"
}

forbid "production-approval" {
  project.workspace == "production"
  pr.approvals < 1
  message "production requires at least 1 approval (currently {pr.approvals})"
}

# Warn (non-blocking)
warn "large-change" {
  count(plan.creates) > 20
  message "large change: {count(plan.creates)} resources — consider splitting"
}

# User blocklist
forbid "no-deletes-by-interns" {
  resource.action == "delete"
  author.name in ["intern-dave", "intern-jane"]
  message "{author.name} cannot delete {resource.address}"
}

# Boolean OR — multiple types in a single condition
forbid "iam-or-kms" {
  resource.type == "aws_iam_role" or resource.type == "aws_kms_key"
  unless author.teams contains "security"
  message "sensitive resource"
}

# Negation
forbid "aws-only" {
  not resource.type matches "aws_*"
  message "only AWS resources are allowed in this repo"
}

# List quantifiers
forbid "infra-file-gate" {
  any pr.changed_files matches "infra/*"
  unless author.teams contains "platform-team"
  message "infra file changes require platform-team"
}

forbid "all-authors-approved" {
  not all pr.commit_authors in ["alice", "bob", "charlie"]
  message "all commit authors must be in the approved list"
}

# Nested resource field access
forbid "no-public-buckets" {
  resource.type == "aws_s3_bucket"
  resource.change.after.acl == "public-read"
  message "{resource.name} must not be public"
}

# Field existence check
forbid "acl-must-be-set" {
  resource.type == "aws_s3_bucket"
  not has resource.change.after.acl
  message "{resource.name} must have an explicit ACL"
}

# Branch gating
forbid "release-branches-only" {
  not pr.branch matches "release/*"
  project.workspace == "production"
  message "production deploys must come from release branches (got {pr.branch})"
}

# Permit overrides forbid for specific resource+action combinations
permit "security-iam-override" {
  resource.type matches "aws_iam_*"
  author.teams contains "enterprise-security"
  message "permitted by enterprise-security team"
}

# Regex matching
forbid "naming-convention" {
  not resource.name matches_regex "^[a-z][a-z0-9_-]+$"
  message "{resource.name} does not follow naming convention"
}

# List intersection — at least one team must overlap
forbid "team-gate" {
  not author.teams intersects ["security", "platform-team"]
  message "author must be in security or platform-team"
}

# Subset check — all labels must be recognized
forbid "unknown-labels" {
  not labels is_subset ["approved", "reviewed", "urgent", "security-approved"]
  message "unknown label detected"
}

# Builtin transforms — case-insensitive comparison
forbid "admin-check" {
  lower(author.name) == "admin"
  message "admin cannot perform this action"
}

# len() transform as a condition
forbid "short-title" {
  len(pr.title) < 10
  message "PR title too short"
}

# Arithmetic expressions
forbid "risk-score" {
  count(plan.destroys) * 3 + count(plan.creates) > 20
  message "risk score exceeded"
}
```

## Language Reference

### Policy Blocks

- `forbid "name" { ... }` — denies if all conditions match (unless an `unless` saves it)
- `warn "name" { ... }` — same as forbid but non-blocking
- `permit "name" { ... }` — explicitly allows; overrides `forbid` for the same resource+action

### Metadata (optional)

- `description "text"` — human-readable explanation (appears in output)
- `owner "team-or-person"` — who owns/maintains this policy (appears in output)
- `link "url"` — link to documentation or runbook (appears in output)

### Conditions

All conditions within a block are AND'd — all must be true for the rule to fire.

- `field.path == "value"` — exact match
- `field.path != "value"` — not equal
- `field.path < 2` — numeric comparison (`<`, `>`, `<=`, `>=`)
- `field.path in ["a", "b", "c"]` — set membership
- `field.path matches "pattern_*"` — glob pattern matching
- `field.path matches_regex "^abc[0-9]+$"` — regular expression matching (Go `regexp` syntax)
- `field.path contains "value"` — list membership or substring check
- `field.path intersects ["a", "b"]` — true if any element in the LHS list appears in the RHS list
- `field.path is_subset ["a", "b", "c"]` — true if every element in the LHS list appears in the RHS list
- `has field.path` — field existence check

### Boolean Operators

- `not <condition>` — negates a single condition
- `<condition> or <condition>` — OR within a single line (can chain: `a or b or c`)
- Lines are AND'd, `or` binds within a line

### Escape Clauses

- `unless <condition>` — if ANY unless clause is true, the forbid does not fire
- Multiple `unless` clauses are OR'd (any one can save you)
- Supports all condition types including `not`, `any`, `all`

### Quantifiers

- `any <list_field> <predicate>` — true if any element in the list matches
- `all <list_field> <predicate>` — true if all elements match

Predicates: `matches "pattern"`, `matches_regex "pattern"`, `in ["a", "b"]`, `== "value"`, `contains "value"`

Examples:
```crowdcontrol
any pr.changed_files matches "infra/*"
all pr.commit_authors in ["alice", "bob"]
any pr.changed_files in ["secrets.tf", "iam.tf"]
```

### Aggregates

- `count(path)` — counts elements in a list, or uses a numeric field directly

### String Interpolation

In `message` strings, `{expr}` is dynamically resolved:
- `{field.path}` — any dotted field path from the input document
- `{count(path)}` — aggregate counts

### The `contains` Operator

The `contains` operator checks membership:
- On a **list/array**: returns true if the value is in the list
- On a **string**: returns true if the value is a substring

```crowdcontrol
# Check if a team is in the author's team list
author.teams contains "security"

# Check if a label exists
labels contains "approved"
```

### The `matches_regex` Operator

The `matches_regex` operator tests a string field against a regular expression
using Go's standard library `regexp` package. Invalid patterns evaluate to false
(no panic). Compiled patterns are cached for performance.

```crowdcontrol
# Match resource types with a regex
resource.type matches_regex "^aws_(iam|kms)_.*"

# Validate naming conventions
resource.name matches_regex "^[a-z][a-z0-9_-]+$"
```

### The `intersects` Operator

The `intersects` operator checks whether any element in the left-hand list
appears in the right-hand list. Returns false if the LHS is not a list.

```crowdcontrol
# At least one author team must be in the allowed set
author.teams intersects ["security", "platform-team"]

# Check for overlap between changed files and protected paths
pr.changed_files intersects ["main.tf", "variables.tf"]
```

### The `is_subset` Operator

The `is_subset` operator checks whether every element in the left-hand list
appears in the right-hand list. An empty LHS is always a subset. Returns false
if the LHS is not a list.

```crowdcontrol
# All author teams must be in the known-teams list
author.teams is_subset ["security", "platform-team", "dev"]

# All labels must be from the allowed set
labels is_subset ["approved", "reviewed", "urgent"]
```

### Builtin Transforms

CrowdControl supports builtin functions that transform a field value before comparison.
Write them as `function(field.path)` on the left-hand side of a condition.

- `lower(field)` — converts a string to lowercase before comparison
- `upper(field)` — converts a string to uppercase before comparison
- `len(field)` — returns the length of a string or the number of elements in a list

```crowdcontrol
# Case-insensitive comparison
lower(author.name) == "admin"

# Reject short descriptions
len(pr.title) < 10
message "PR title too short"

# Uppercase check
upper(resource.provider) == "AWS"

# Require at least 2 labels
len(labels) >= 2
```

### Arithmetic Expressions

Conditions can use arithmetic expressions (`+`, `-`, `*`, `/`) on either side
of a comparison operator. Expression terms can be numeric literals, field
references (resolved to numbers), `count(path)`, or `len(path)`. Parenthesized
sub-expressions are supported. Division by zero evaluates to false.

```crowdcontrol
# Combined aggregate check
count(plan.creates) + count(plan.destroys) > 10
message "too many total changes"

# Weighted risk score
count(plan.destroys) * 3 + count(plan.creates) > 20
message "risk score exceeded"

# Field arithmetic
pr.approvals * 2 >= count(plan.destroys)

# len() in expressions
len(labels) + pr.approvals < 3
message "not enough labels or approvals"
```

### The `has` Operator

The `has` operator checks if a field exists (is not nil) in the input document:

```crowdcontrol
# Only fire if the field exists
has resource.change.after.acl

# Fire if field is missing
not has config.required_field
```

## Input Model

CrowdControl evaluates policies against a generic `map[string]any` document. The engine
has **no built-in knowledge** of any domain (Terraform, GitHub, etc.). All field
resolution is via dotted paths against nested maps.

### Example: Terraform/GitHub gating (Thera)

[Thera](https://github.com/mikemackintosh/thera) wraps CrowdControl with an
adapter that flattens enriched PR/plan data into a flat document before
evaluation. CrowdControl itself has no awareness of Terraform or GitHub —
the flattening happens entirely outside the engine. A typical flattened
input shape looks like:

```json
{
  "author": { "name": "username", "teams": ["team1", "team2"] },
  "approver": { "teams": ["team3"] },
  "labels": ["label1", "label2"],
  "pr": { "draft": false, "approvals": 1, "branch": "...", "changed_files": [...] },
  "project": { "workspace": "production", "dir": "infra" },
  "plan": { "resource_changes": [...], "destroys": [...], "creates": [...] },
  "resource": { "type": "aws_s3_bucket", "name": "logs", "action": "create", "change": {...} }
}
```

The "permit overrides forbid for the same resource" semantic is implemented in
the Thera adapter, not in CrowdControl itself. Other adapters can choose
different override semantics or none at all.

### For Other Domains

Pass any `map[string]any` to the evaluator. Write policies using whatever field
paths your document contains:

```crowdcontrol
forbid "order-limit" {
  order.total > 200
  customer.tier == "free"
  message "free tier limited to $200"
}
```

## Evaluation Model

1. Each `forbid`/`warn` block is evaluated against the document
2. All conditions in a block are AND'd
3. All `unless` clauses are OR'd — any one passing skips the forbid
4. If a forbid fires, the action is denied
5. `warn` blocks fire but don't block
6. Aggregate blocks (`count(plan.*)`) evaluate once against the full plan
7. `permit` blocks override `forbid` denials for the same resource+action
8. `not` inverts a single condition's result
9. `or` creates a disjunction within a single line

### Default Effect

The evaluator supports two modes via `WithDefaultEffect()`:

**DefaultAllow** (default): actions pass unless a `forbid` fires.

**DefaultDeny**: actions are denied unless a `permit` fires. If no `permit` fires
and no `forbid` already denied the document, an implicit denial is added.

```go
eng := evaluator.NewFromPolicies(policies,
    evaluator.WithDefaultEffect(types.DefaultDeny),
)
```

### Permit Semantics

A `permit` rule fires when all its conditions match and no `unless` clause saves
it. The difference from `forbid` is in the effect:

- **forbid** fires → deny (Passed=false)
- **permit** fires → explicit allow (Passed=true, Message set)
- **permit** doesn't fire → no effect (Passed=true, Message empty)

**Note:** the core CrowdControl engine does NOT have permit-overrides-forbid
semantics. A `permit` rule emits a message but does not change the result of a
sibling `forbid` rule. Permit-overrides-forbid is a higher-level semantic
implemented by adapters (like Thera's) that group results by resource and
collapse them into a single decision per resource.

## Explain / Trace Mode

CrowdControl includes an explain mode for debugging and auditing policy evaluation.
When enabled, each `Result` includes a `Trace` field with per-condition
evaluation details: what expression was tested, whether it matched, and what
the actual resolved value was.

### Enabling Explain Mode

**Go API:**

```go
eng := evaluator.NewFromPolicies(policies,
    evaluator.WithExplain(true),
)
results := eng.Evaluate(doc)

// Pretty-print the trace
fmt.Print(evaluator.FormatExplain(results))
```

**CLI:**

```
crowdcontrol test --explain policies/ input.json
```

### Trace Output

`FormatExplain()` produces human-readable output showing each rule's evaluation.
Each condition is annotated with `+` (matched) or `-` (did not match), along
with the actual value resolved from the document:

```
RULE "blast-radius" [forbid] -> DENIED
  + condition: count(plan.destroys) > 5 -> true (got 8)
  - unless: author.teams contains "platform-team" -> false (got [dev, backend])
  -> too many destroys (8) — requires platform-team

RULE "sensitive-resources" [forbid] -> PASSED
  + condition: resource.type in ["aws_iam_role", ...] -> true (got "aws_iam_role")
  + unless: author.teams contains "enterprise-security" -> true (got [enterprise-security, dev])
  -> saved by unless clause
```

When conditions do not all match, the trace shows which ones failed:

```
RULE "no-draft-production" [forbid] -> PASSED
  + condition: pr.draft == true -> true (got true)
  - condition: project.workspace == "production" -> false (got "staging")
  -> conditions not met, rule did not fire
```

In explain mode the evaluator continues evaluating all conditions and unless
clauses even after a mismatch, so the trace is always complete.

## Schema Validation

CrowdControl supports static validation of policies against a schema. This catches
field typos, type mismatches, and incorrect operator usage before any document
is evaluated — a compile-time safety net.

### Defining a Schema

A schema maps dotted field paths to expected types:

```go
schema := &types.Schema{
    Fields: map[string]types.FieldType{
        "author.name":    types.FieldString,
        "author.teams":   types.FieldList,
        "pr.draft":       types.FieldBool,
        "pr.approvals":   types.FieldNumber,
        "pr.branch":      types.FieldString,
        "resource.type":  types.FieldString,
        "resource.name":  types.FieldString,
        "resource.change": types.FieldMap,
        "labels":         types.FieldList,
        "plan.destroys":  types.FieldList,
        "plan.creates":   types.FieldList,
    },
}
```

Supported field types: `string`, `number`, `bool`, `list`, `map`, `any`.
Fields typed as `map` allow arbitrary nested access beyond the schema (e.g.
`resource.change.after.acl` is valid when `resource.change` is `map`).
Fields typed as `any` skip all type checks.

### Running Validation

**Go API:**

```go
warnings := evaluator.ValidatePolicy(policies, schema)
if len(warnings) > 0 {
    fmt.Print(evaluator.FormatWarnings(warnings))
}
```

**CLI:**

```
crowdcontrol validate --schema schema.json policies/
```

### What It Catches

- **Unknown fields** — a field path that does not appear in the schema and whose
  parent is not a `map`. Likely a typo: `authro.name` instead of `author.name`.
- **Type mismatches** — using a numeric operator (`<`, `>`, `<=`, `>=`) on a
  string field, `contains` on a bool field, `intersects`/`is_subset` on a
  non-list field, `matches`/`matches_regex` on a non-string field, etc.
- **Aggregate target errors** — `count(field)` where the schema says the field
  is neither a list nor a number.
- **Quantifier target errors** — `any field ...` or `all field ...` where the
  field is not a list.
- **Arithmetic type errors** — a field used in an arithmetic expression (`+`,
  `-`, `*`, `/`) that the schema says is not a number.
- **Message interpolation errors** — `{field.path}` references in `message`
  strings that do not exist in the schema.

### Warning Output

Each warning includes the rule name, the offending field, and a description:

```
  WARN [blast-radius]: unknown field "plan.destorys" — not in schema (typo?)
  WARN [production-approval]: pr.approvals < used with numeric operator, schema says string
```
