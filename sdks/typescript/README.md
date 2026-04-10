# crowdcontrol — TypeScript SDK

TypeScript / Node.js SDK for the **CrowdControl** policy language.

A pure TypeScript port of the Go reference implementation at
<https://github.com/mikemackintosh/crowdcontrol>. Zero runtime dependencies,
ships plain ES2022 JavaScript plus declaration files, works on Node 18+.

- **Language spec:** [`../../SPEC.md`](../../SPEC.md)
- **Conformance suite:** [`../../conformance/suite/`](../../conformance/suite/) (30/30 passing)
- **Reference impl:** Go, at `../../` (root of the repository)

## Installation

```bash
npm install crowdcontrol
```

For local development within this repository:

```bash
cd sdks/typescript
npm install        # installs typescript as a devDependency only
npm run build      # compiles to dist/
npm test           # runs node:test unit tests
npm run conformance  # runs the shared conformance suite
npm run demo       # runs examples/demo.ts
```

## Zero runtime dependencies

The `dependencies` block of `package.json` is empty. The only development
dependencies are `typescript` (for compilation) and `@types/node` (for types).
The compiled JavaScript under `dist/` has no external imports — it runs on
plain Node with just the stdlib (`node:fs`, `node:path`, `node:test`).

## Quick start

```ts
import { fromSource, formatResults } from "crowdcontrol";

const eng = fromSource([`
  forbid "no-interns-in-prod" {
    user.role == "intern"
    resource.environment == "production"
    message "{user.name} cannot touch production"
  }
`]);

const results = eng.evaluate({
  user: { name: "alex", role: "intern" },
  resource: { environment: "production" },
});

for (const r of results) {
  console.log(r.rule, r.kind, r.passed, r.message);
}

const { text, allPassed } = formatResults(results);
process.stdout.write(text);
```

## Public API

### Constructors

```ts
import { fromSource, fromDirectory, Evaluator } from "crowdcontrol";

// In-memory policy sources.
const e1 = fromSource([policySrc1, policySrc2], { defaultEffect: "deny" });

// Load every *.cc file from one or more directories.
const e2 = fromDirectory(["./policies"], { explain: true });

// Low-level constructor takes pre-parsed Policy[] objects.
const e3 = new Evaluator(policies, { defaultEffect: "allow" });
```

### Evaluation

```ts
eng.evaluate(doc: Record<string, unknown>): Result[]
eng.validate(schema: Schema): SchemaWarning[]
eng.policies(): Policy[]
```

`Result` shape:

```ts
interface Result {
  rule: string;
  kind: "forbid" | "warn" | "permit";
  passed: boolean;
  message: string;
  description: string;
  owner: string;
  link: string;
  trace: RuleTrace | null; // populated only when { explain: true }
}
```

### Helpers

```ts
import {
  parse,               // parse(source) -> Policy
  resolveField,        // resolveField("a.b.c", doc) -> unknown | null
  interpolateMessage,  // interpolateMessage("hi {user.name}", doc) -> string
  formatResults,       // formatResults(results) -> { text, allPassed }
  validatePolicies,    // validatePolicies(policies, schema) -> SchemaWarning[]
  formatWarnings,      // formatWarnings(warnings) -> string
  POLICY_EXT,          // ".cc"
  VERSION,             // "0.1.0"
  DEFAULT_ALLOW,
  DEFAULT_DENY,
} from "crowdcontrol";
```

### Types

All AST types (`Policy`, `Rule`, `Condition`, `Expr`, `ConditionType`,
`ExprKind`, `Result`, `RuleTrace`, `ConditionTrace`, `Schema`,
`SchemaWarning`, `FieldType`, `DefaultEffect`) are re-exported from the
package root. Strict TypeScript with no `any` in the public surface — the
input document is typed as `Record<string, unknown>`.

## Conformance

This SDK passes **30/30** cases in the shared conformance suite at
`../../conformance/suite/`. Run it yourself:

```bash
npm run conformance
```

All language features are implemented:

- `forbid` / `warn` / `permit` rules with `unless` escape clauses
- `==`, `!=`, `<`, `>`, `<=`, `>=` comparison operators
- `in`, `matches` (glob), `matches_regex`, `contains`, `intersects`, `is_subset`
- `any` / `all` quantifiers over lists
- `count()` aggregates and arithmetic expressions (`+`, `-`, `*`, `/`)
- `lower()` / `upper()` / `len()` transforms
- `has` field existence check
- `not` negation and `or` disjunction
- `description` / `owner` / `link` rule metadata
- `{field.path}` and `{count(path)}` message interpolation
- `default_effect: "deny"` with synthetic `(default-deny)` result

## Testing

```bash
npm test    # 62 unit tests across lexer / parser / evaluator / validate
```

Unit tests use the Node stdlib `node:test` runner (Node 18+). No jest,
mocha, or vitest — the test suite runs on the same binary you ship.

## Semantics notes

String-coerced equality follows Go's `fmt.Sprintf("%v", v)` conventions:
booleans normalize to lowercase `"true"` / `"false"`, null/undefined to
`"<nil>"`, integer floats print without a decimal. This keeps decisions
byte-identical to the Go reference.

Numeric comparisons (`<`, `>`, `<=`, `>=`) only succeed when both sides
are already numbers — strings are *not* auto-coerced, matching the
reference behavior.

The `matches` glob supports `*` at the prefix, suffix, or as a single
internal wildcard. For regex matching, use `matches_regex` with any
JavaScript-compatible pattern (patterns are compiled once and cached).
