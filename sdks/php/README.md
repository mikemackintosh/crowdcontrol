# crowdcontrol-php

Pure-PHP SDK for the [CrowdControl](https://github.com/mikemackintosh/crowdcontrol)
policy language. Zero Composer runtime dependencies — only PHP 8.1+ is required.

> **Status:** spec-compliant. All 30 cases in the shared
> [conformance suite](../../conformance/suite/) pass against this SDK.

## Why

CrowdControl is intentionally *less* powerful and *more* readable than CEL,
Cedar, or Rego. A security engineer seeing a `.cc` file for the first time
should be able to read one and understand it in under 30 seconds. See
[SPEC.md](../../SPEC.md) for the language reference.

## Requirements

- **PHP 8.1 or newer.**
- **No runtime dependencies** — `composer.json` only declares the PHP version.
- Uses only the PHP standard library (`json_decode`, `preg_match`, `spl_autoload_register`, etc.).

## Install

### With Composer (recommended)

```bash
composer require mikemackintosh/crowdcontrol
```

### Without Composer

Everything you need is under `src/`. Require the tiny bootstrap file:

```php
require_once '/path/to/sdks/php/src/autoload.php';

use MikeMackintosh\CrowdControl\CrowdControl;
```

## Quickstart

```php
<?php

require_once __DIR__ . '/sdks/php/src/autoload.php';

use MikeMackintosh\CrowdControl\CrowdControl;

$engine = CrowdControl::fromSource([<<<'CC'
    forbid "no-interns-in-prod" {
        user.role == "intern"
        resource.environment == "production"
        message "{user.name} cannot touch production"
    }
CC]);

$results = $engine->evaluate([
    'user' => ['name' => 'alex', 'role' => 'intern'],
    'resource' => ['environment' => 'production'],
]);

foreach ($results as $r) {
    printf("%s %s passed=%s msg=%s\n",
        $r->kind, $r->rule, $r->passed ? 'true' : 'false', $r->message);
}
```

Load policies from a directory:

```php
$engine = CrowdControl::fromDirectory(['./policies'], 'deny');
```

## Public API

Top-level static methods on `MikeMackintosh\CrowdControl\CrowdControl`:

| Method | Description |
|--------|-------------|
| `CrowdControl::fromSource($sources, $defaultEffect = 'allow', $explain = false)` | Build an engine from in-memory source strings. |
| `CrowdControl::fromDirectory($dirs, $defaultEffect = 'allow', $explain = false)` | Load every `*.cc` file from the given directories. |
| `CrowdControl::parse($source)` | Parse a single source string into a `Policy` AST. |

`CrowdControl\Engine`:

| Method | Description |
|--------|-------------|
| `evaluate(array $doc)` | Run policies against an input array, returns `Result[]`. |
| `validate(Schema $schema)` | Static schema validation, returns `SchemaWarning[]`. |
| `policies()` | The parsed `Policy` objects. |

`CrowdControl\Result` has: `rule`, `kind`, `passed`, `message`, `description`, `owner`, `link`, `trace`.

`CrowdControl\Evaluator::formatResults($results)` returns `[string, bool]` for a human-readable summary.

## Language semantics

The PHP SDK produces decisions identical to the Go reference. Notable
behaviors (all handled by our `fmtV` helper, all covered by the conformance
suite):

- **String-coerced equality**: booleans normalize to lowercase `"true"`/`"false"`
  (PHP's `(string) true` is `"1"` — we override this), `null` to `"<nil>"`,
  integer-valued floats omit the decimal.
- **Numeric comparisons** (`<`, `>`, `<=`, `>=`) only succeed when both sides
  are already numeric (strings are *not* auto-coerced).
- **`in`** expects a list of strings on the RHS.
- **`contains`** works on lists (element equality) and strings (substring).
- **`intersects` / `is_subset`** are list-vs-list operations.
- **Quantifiers** (`any` / `all`): empty list → `any=false`, `all=true`.
- **Default deny**: appends a synthetic `(default-deny)` forbid if no rule matched.

## Running the tests

PHP has no stdlib test framework and PHPUnit would violate the zero-deps
rule. The suite uses a tiny bespoke runner under `tests/` and assertion
helpers in `tests/helpers.php`.

```bash
cd sdks/php
php tests/run.php
```

67 tests across lexer / parser / evaluator / validate.

## Conformance

```bash
cd sdks/php
php conformance_runner.php           # 30 passed, 0 failed
php conformance_runner.php -v        # print passing cases too
php conformance_runner.php -f permit # only run cases matching 'permit'
```

Current status: **30 / 30** against the shared suite.

## Demo

```bash
cd sdks/php
php examples/demo.php
```

## Layout

```
sdks/php/
├── composer.json                 # require only {"php": ">=8.1"}
├── README.md
├── conformance_runner.php
├── src/
│   ├── autoload.php              # tiny require-based bootstrap
│   ├── Types.php                 # AST, Schema, Result, enums
│   ├── Lexer.php
│   ├── Parser.php
│   ├── Evaluator.php             # Engine + static helpers
│   ├── Validate.php              # schema validation
│   └── CrowdControl.php          # top-level static API
├── tests/
│   ├── helpers.php               # assert_* helpers
│   ├── run.php                   # test discovery/runner
│   ├── lexer_test.php
│   ├── parser_test.php
│   ├── evaluator_test.php
│   └── validate_test.php
└── examples/
    └── demo.php
```

## License

MIT — see the [parent LICENSE](../../LICENSE).
