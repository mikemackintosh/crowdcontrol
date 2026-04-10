# crowdcontrol-kotlin

Kotlin / JVM SDK for the [CrowdControl](https://github.com/mikemackintosh/crowdcontrol)
policy language.

A small, readable policy language for gating actions on structured data.
This package is a pure-Kotlin port of the [Go reference implementation](https://github.com/mikemackintosh/crowdcontrol),
and it passes the same [conformance suite](../../conformance/suite/) as
the Go, Python, and TypeScript SDKs.

## Goals

- **Pure Kotlin**, only `kotlin-stdlib`. No Jackson, no kotlinx.serialization,
  no Gson — JSON is parsed by a small hand-written reader.
- **Kotlin 1.9+**, **JVM 11+**.
- **Identical decisions** to the Go reference (verified by the shared
  conformance suite).
- **Idiomatic Kotlin API** with top-level functions, data classes, and
  default parameters.
- **Java interop-friendly**: the public API is usable from Java without
  any Kotlin-specific tooling — every top-level function and class carries
  `@JvmStatic` / `@JvmOverloads` where it matters.

## Install

Add the SDK to your Gradle project:

```kotlin
// build.gradle.kts — inside your project, not this repo
dependencies {
    implementation("io.github.mikemackintosh:crowdcontrol-kotlin:0.1.0")
}
```

Or build from source (see [Building without Gradle](#building-without-gradle) below).

## Quick start

```kotlin
import io.github.mikemackintosh.crowdcontrol.DefaultEffect
import io.github.mikemackintosh.crowdcontrol.formatResults
import io.github.mikemackintosh.crowdcontrol.fromSource

fun main() {
    val engine = fromSource(listOf("""
        forbid "no-interns-in-prod" {
            user.role == "intern"
            resource.environment == "production"
            message "{user.name} cannot touch production"
        }
    """.trimIndent()))

    val results = engine.evaluate(mapOf(
        "user"     to mapOf("name" to "alex", "role" to "intern"),
        "resource" to mapOf("environment" to "production"),
    ))

    print(formatResults(results).text)
    // DENY: alex cannot touch production (no-interns-in-prod)
}
```

From Java:

```java
import io.github.mikemackintosh.crowdcontrol.*;
import java.util.List;
import java.util.Map;

public class Example {
    public static void main(String[] args) {
        Engine engine = Engine.fromSource(List.of(
            "forbid \"no-root\" { user.name == \"root\" message \"nope\" }"
        ));

        List<Result> results = engine.evaluate(Map.of(
            "user", Map.of("name", "root")
        ));
        for (Result r : results) {
            System.out.println(r.getRule() + " -> " + r.getPassed() + " " + r.getMessage());
        }
    }
}
```

## Public API

All public surface lives under `io.github.mikemackintosh.crowdcontrol`.

### Top-level functions

| Function | Description |
|----------|-------------|
| `fromSource(sources, defaultEffect, explain)` | Build an `Engine` from in-memory policy source strings. |
| `fromDirectory(dirs, defaultEffect, explain)` | Load every `*.cc` file from each directory. |
| `parse(source)` | Parse a single source string into a `Policy` AST. |
| `formatResults(results)` | Render a list of `Result` as a plain-text summary. |
| `formatWarnings(warnings)` | Render a list of `SchemaWarning`. |
| `validatePolicies(policies, schema)` | Run static schema validation. |
| `interpolateMessage(msg, doc)` | Expand `{field.path}` placeholders in a message. |
| `resolveField(path, doc)` | Resolve a dotted path against a document. |
| `fmtV(value)` | Go-style `%v` formatter — lowercase booleans, integer-valued doubles without decimals, `<nil>` for null. |
| `parseJson(text)` | Stdlib-only JSON reader used by the conformance runner. |

### Core classes

| Class | Role |
|-------|------|
| `Engine` | Holds parsed policies, runs `evaluate(doc)` and `validate(schema)`. |
| `Policy`, `Rule`, `Condition`, `Expr` | AST produced by `parse()`. |
| `Result` | Data class describing a single rule's outcome. |
| `RuleTrace`, `ConditionTrace` | Populated when `explain = true`. |
| `Schema`, `SchemaWarning`, `FieldType` | Static validation. |
| `DefaultEffect` (`ALLOW`, `DENY`) | Controls implicit deny behavior. |
| `ParseError` | Thrown on syntax or lex errors. |
| `JsonParseError` | Thrown by the bundled JSON reader. |

### Result shape

```kotlin
data class Result(
    val rule: String,
    val kind: String,          // "forbid" | "warn" | "permit"
    val passed: Boolean,       // false = denied
    val message: String,       // interpolated; empty if rule did not fire
    val description: String,
    val owner: String,
    val link: String,
    val trace: RuleTrace? = null,
)
```

## Language reference

The Kotlin SDK implements the full [CrowdControl language specification](../../SPEC.md).
Supported constructs:

- `forbid`, `warn`, `permit` rules with `message`, `description`, `owner`, `link`
- `unless` escape clauses
- Comparison operators: `== != < > <= >=`
- List operators: `in`, `contains`, `intersects`, `is_subset`
- Pattern operators: `matches` (glob), `matches_regex` (Java `Pattern`)
- Quantifiers: `any`, `all`
- Aggregates: `count(path)`, `len(path)`
- Transforms: `lower(path)`, `upper(path)`, `len(path)`
- Arithmetic: `+ - * /` over fields, literals, `count()`, `len()`
- Field existence: `has path`
- Boolean glue: `not`, `or` (single-line disjunction), AND (implicit)
- Message interpolation: `{field.path}`, `{count(field.path)}`
- Default effects: `DefaultEffect.ALLOW` (default) or `DefaultEffect.DENY`

## Building without Gradle

Gradle is the preferred way to consume this SDK, but the repo also ships
a plain `kotlinc` build script so you can hack on the SDK with nothing
but the Kotlin compiler installed.

```bash
cd sdks/kotlin
./build.sh                  # produces crowdcontrol.jar
./test.sh                   # runs unit tests via junit-4 that ships with kotlinc

# Run the conformance suite:
java -cp crowdcontrol.jar io.github.mikemackintosh.crowdcontrol.ConformanceRunner

# Run the demo:
java -cp crowdcontrol.jar io.github.mikemackintosh.crowdcontrol.Demo
```

Install `kotlinc` with:

```bash
brew install kotlin         # macOS
sdk install kotlin          # SDKMAN on Linux / macOS
```

### With Gradle

```bash
cd sdks/kotlin
gradle build                # compile + run unit tests
gradle conformance          # run the conformance suite
gradle demo                 # run the demo
```

## Conformance

The Kotlin SDK is verified against the shared conformance suite at
`../../conformance/suite/*.json`. Every case that passes in the Go,
Python, and TypeScript ports must also pass here.

Run locally:

```bash
./build.sh
java -cp crowdcontrol.jar io.github.mikemackintosh.crowdcontrol.ConformanceRunner
# => 30 passed, 0 failed
```

## Tests

Unit tests live under `src/test/kotlin/` and use `kotlin.test` (stdlib).
Coverage:

- `LexerTest` — tokenizer
- `ParserTest` — AST construction
- `EvaluatorTest` — semantics, default effects, quantifiers, arithmetic
- `ValidateTest` — schema validation warnings
- `JsonTest` — bundled JSON reader

## License

Same as the parent CrowdControl repo (MIT).
