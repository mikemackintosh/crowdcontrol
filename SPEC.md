# CrowdControl Language Specification

This document is the **normative reference** for the CrowdControl language.
Every SDK port (Go, Python, TypeScript, Ruby, Kotlin, PHP) must implement
the grammar and semantics described here, and must pass every case in
`conformance/suite/`.

For design rationale and longer examples, see [DESIGN.md](./DESIGN.md).
For the conformance test format, see [conformance/README.md](./conformance/README.md).

---

## 1. Lexical Grammar

### Comments

```
# line comment to end of line
// line comment to end of line
```

There are no block comments.

### Whitespace

Whitespace (`U+0020`, `\t`, `\r`, `\n`) is insignificant except as a token
separator. Newlines do not terminate statements.

### Identifiers

```
IDENT  = (LETTER | "_") { LETTER | DIGIT | "_" }
```

`LETTER` is any Unicode letter (`unicode.IsLetter`). Field paths are dotted
sequences of identifiers: `a.b.c`.

### String literals

```
STRING = '"' { CHAR | ESC } '"'
ESC    = '\\"' | '\\\\' | '\\n' | '\\t'
```

Unrecognized escape sequences pass through literally (e.g. `\q` becomes `\q`).
Strings cannot span newlines.

### Number literals

```
NUMBER = DIGIT { DIGIT } [ "." DIGIT { DIGIT } ]
```

Both integers and floats parse to a single `number` value (Go: `float64`).

### Boolean literals

```
true | false
```

### Operators and punctuation

| Token | Meaning |
|-------|---------|
| `==` `!=` | equality / inequality |
| `<` `>` `<=` `>=` | numeric comparison |
| `+` `-` `*` `/` | arithmetic |
| `{` `}` | block |
| `[` `]` | list |
| `(` `)` | grouping (used in `count()`, `lower()`, etc.) |
| `.` | field separator |
| `,` | list element separator |

### Keywords

```
forbid warn permit
unless
has not any all in
matches matches_regex contains intersects is_subset
count lower upper len
description owner link message
or
true false
```

Keywords are reserved and may not be used as identifiers.

---

## 2. Syntactic Grammar

```
Policy        := { Rule }

Rule          := RuleKind STRING "{" { RuleClause } "}"
RuleKind      := "forbid" | "warn" | "permit"

RuleClause    := MetadataClause
              |  Condition
              |  UnlessClause
              |  MessageClause

MetadataClause := ("description" | "owner" | "link") STRING
MessageClause  := "message" STRING
UnlessClause   := "unless" Condition

Condition     := [ "not" ] ConditionInner
              |  Condition "or" ConditionInner            (* OR group *)

ConditionInner := HasCondition
              |  AggregateCondition
              |  QuantifierCondition
              |  ExprCondition
              |  FieldCondition
              |  ArithmeticCondition

HasCondition         := "has" FieldPath
AggregateCondition   := "count" "(" FieldPath ")" CmpOp NUMBER
QuantifierCondition  := ("any" | "all") FieldPath Predicate
Predicate            := CmpOp Value
                     |  "matches" STRING
                     |  "matches_regex" STRING
                     |  "in" List
                     |  "contains" STRING
FieldCondition       := [Transform "(" ] FieldPath [ ")" ] CmpOp Value
ArithmeticCondition  := Expr CmpOp Expr

Transform     := "lower" | "upper" | "len"

CmpOp         := "==" | "!=" | "<" | ">" | "<=" | ">="
              |  "in" | "matches" | "matches_regex"
              |  "contains" | "intersects" | "is_subset"

Expr          := Term { ("+" | "-") Term }
Term          := Factor { ("*" | "/") Factor }
Factor        := NUMBER
              |  FieldPath
              |  "count" "(" FieldPath ")"
              |  "len" "(" FieldPath ")"

FieldPath     := IDENT { "." IDENT }
Value         := STRING | NUMBER | "true" | "false" | List
List          := "[" [ Value { "," Value } ] "]"
```

The grammar is intentionally LL(1)-ish and parses cleanly with single-token
lookahead in every implementation.

---

## 3. Evaluation Semantics

### Inputs

A document is a JSON value, conventionally an object (map). All evaluation is
performed against this single document. Field resolution traverses dotted
paths through nested maps. If any segment is missing or non-map, the path
resolves to "absent."

### Rule firing

A rule **fires** when:
1. **Every** condition in its body is true, AND
2. **No** `unless` clause is true.

| Rule kind | If fires                       | If does not fire     |
|-----------|--------------------------------|----------------------|
| `forbid`  | `Result.Passed = false`, message set | `Result.Passed = true`, message empty |
| `warn`    | `Result.Passed = false`, message set | `Result.Passed = true`, message empty |
| `permit`  | `Result.Passed = true`,  message set | `Result.Passed = true`, message empty |

The only difference between `forbid` and `warn` is presentation: tooling SHOULD
treat warns as non-blocking. The engine itself reports both with `Passed=false`.

### Conditions

- Multiple conditions in a rule body are **AND'd**.
- Multiple `unless` clauses are **OR'd** — any one being true saves the rule.
- Within a single condition line, `or` creates a disjunction: each subexpression
  is evaluated and the result is true if any subexpression is true.
- `not` negates the boolean result of a single condition.

### Operators

| Operator | LHS type | RHS type | Result |
|----------|----------|----------|--------|
| `==` `!=` | any | any | string-coerced equality |
| `<` `>` `<=` `>=` | number | number | numeric comparison |
| `in` | string | list of strings | LHS appears in RHS |
| `contains` | list \| string | string | RHS appears in LHS |
| `intersects` | list | list | LHS and RHS share at least one element |
| `is_subset` | list | list | every element of LHS appears in RHS |
| `matches` | string | string (glob) | glob match (`*` wildcards) |
| `matches_regex` | string | string (regex) | RE2 regex match |
| `has` | n/a | field path | path exists in document |

Numeric coercion: when a comparison expects a number, strings that look like
numbers are coerced via `strconv.ParseFloat`.

### Quantifiers

`any FIELD PREDICATE` is true if any element of `FIELD` (resolved as a list)
satisfies the predicate. Empty list → false.

`all FIELD PREDICATE` is true if every element of `FIELD` satisfies the
predicate. Empty list → true (vacuous).

### Aggregates

`count(FIELD)` returns the cardinality of `FIELD` if it is a list, or its
numeric value if it is a number, or 0 if absent. It can be used in comparisons:

```
count(plan.deletes) > 5
```

### Transforms

`lower(FIELD)`, `upper(FIELD)`, and `len(FIELD)` apply to the resolved field
value before comparison:

- `lower` / `upper` — lowercase / uppercase string
- `len` — length of string or list (0 for absent)

### Arithmetic

`Expr` is a tree of `+`, `-`, `*`, `/` over field paths, numeric literals,
`count()`, and `len()`. Evaluation uses `float64`. Operator precedence
follows mathematical convention (`*` and `/` bind tighter than `+` and `-`).

### Default effects

The engine accepts a default effect option:

- **DefaultAllow** (default): no implicit denial; results contain only what
  rules emitted.
- **DefaultDeny**: if no `permit` fired AND no `forbid` already denied the
  document, an implicit `(default-deny)` forbid result is appended.

### Message interpolation

`message` strings may contain `{field.path}` placeholders that are replaced
with the resolved value at result-emission time. `{count(field.path)}` is
also recognized. Unresolved placeholders are left literally.

---

## 4. Result Model

Every rule produces one `Result`:

```
Result {
  rule:        string   // rule name
  kind:        string   // "forbid" | "warn" | "permit"
  passed:      bool     // false = denied (forbid/warn fired); true otherwise
  message:     string   // interpolated message, empty if rule did not fire
  description: string   // from rule metadata
  owner:       string   // from rule metadata
  link:        string   // from rule metadata
  trace:       Trace?   // populated only when explain mode is enabled
}
```

When DefaultDeny is in effect and no rule explicitly handles the document,
an additional synthetic result is appended:

```
{rule: "(default-deny)", kind: "forbid", passed: false,
 message: "no permit rule matched — denied by default"}
```

---

## 5. Schema Validation (Static)

A `Schema` maps dotted field paths to expected types:

```json
{
  "fields": {
    "user.name": "string",
    "user.groups": "list",
    "request.approved": "bool",
    "plan.changes": "list"
  }
}
```

Valid types: `string`, `number`, `bool`, `list`, `map`, `any`.

`ValidatePolicy(policies, schema)` returns `[]SchemaWarning` for:

- Unknown field references (typos)
- Type mismatches between operator and field (e.g. `<` on a string)
- Aggregate targets that aren't lists or numbers
- Quantifier targets that aren't lists
- Arithmetic operands that aren't numbers
- `{field.path}` references in messages that don't exist

Schema validation is **non-fatal** — it produces warnings, never errors.

---

## 6. Conformance

A SDK is considered "spec-compliant" when:

1. It implements every construct in §1–§4 above.
2. It passes every case in `conformance/suite/`.
3. Its result objects (rule, kind, passed, message) match the Go reference
   exactly for the same input.
4. Its trace output is a structural superset of what the spec defines (extra
   fields are allowed; missing fields are not).

When the spec changes, the conformance suite is updated first. SDKs must be
updated to match. The Go implementation is the reference for all behavior
not explicitly nailed down by this document.
