# crowdcontrol (Ruby)

Pure-Ruby implementation of the [CrowdControl][cc] policy language — a small,
readable DSL for gating actions on structured data. Zero gem dependencies;
passes the shared conformance suite used by the Go reference and every other
language SDK.

> **Status:** spec-compliant. All 30 cases in the shared
> [conformance suite](../../conformance/suite/) pass against this SDK.

## Why

CrowdControl is intentionally *less* powerful and *more* readable than CEL,
Cedar, or Rego. If a security engineer has never seen a CrowdControl policy
before, they should be able to read one and understand what it does in under
30 seconds. See [SPEC.md](../../SPEC.md) for the language reference.

## Requirements

- Ruby **3.0** or newer.
- **No runtime gems.** `json` and `set` from stdlib are the only requirements.

## Install

Until the gem is published to RubyGems, install directly from the repo:

```bash
cd sdks/ruby
gem build crowdcontrol.gemspec
gem install crowdcontrol-0.1.0.gem
```

Or just add `sdks/ruby/lib` to your `$LOAD_PATH`:

```ruby
$LOAD_PATH.unshift("/path/to/crowdcontrol/sdks/ruby/lib")
require "crowdcontrol"
```

## Quickstart

```ruby
require "crowdcontrol"

engine = CrowdControl.from_source([
  <<~CC
    forbid "no-interns-in-prod" {
      description "interns are not allowed to touch production"
      owner "security-team"
      user.role == "intern"
      resource.environment == "production"
      message "{user.name} is an intern and cannot touch {resource.environment}"
    }
  CC
])

results = engine.evaluate(
  "user"     => { "name" => "alex", "role" => "intern" },
  "resource" => { "environment" => "production" }
)

results.each do |r|
  puts "#{r.kind} #{r.rule} passed=#{r.passed} msg=#{r.message.inspect}"
end
```

Load policies from a directory of `.cc` files:

```ruby
engine = CrowdControl.from_directory(["./policies"], default_effect: "deny")
```

## Public API

Top-level module methods:

| Method | Description |
|--------|-------------|
| `CrowdControl.from_source(sources, default_effect:, explain:)` | Build an engine from in-memory source strings. |
| `CrowdControl.from_directory(dirs, default_effect:, explain:)` | Build an engine by loading every `*.cc` file from the given dirs. |
| `CrowdControl.parse(source)` | Parse a single source string into a `Policy` AST. |

Engine (`CrowdControl::Engine`, alias `CrowdControl::Evaluator`):

| Method | Description |
|--------|-------------|
| `#evaluate(input)` | Run all loaded policies against an input hash, returns `Array<Result>`. |
| `#validate(schema)` | Static schema validation; returns `Array<SchemaWarning>`. |
| `#policies` | The parsed `Policy` objects. |

`CrowdControl::Result` has: `rule`, `kind`, `passed`, `message`,
`description`, `owner`, `link`, `trace`.

## Defaults and semantics

- **Default allow** (default): no implicit denial; only rules that fire emit
  denial results.
- **Default deny**: if no `permit` fired and no `forbid` already denied the
  document, an implicit `(default-deny)` forbid result is appended.
- String-coerced equality matches the Go reference exactly (booleans
  normalize to lowercase `"true"`/`"false"`, `nil` → `"<nil>"`, integer
  floats omit the decimal).
- `<`, `>`, `<=`, `>=` only succeed when both sides are already numeric
  (strings are not coerced).

## Tests

Unit tests use **minitest from stdlib** — no rspec, no test-unit, no gems:

```bash
cd sdks/ruby
ruby -Ilib -Itest test/test_lexer.rb
ruby -Ilib -Itest test/test_parser.rb
ruby -Ilib -Itest test/test_evaluator.rb
ruby -Ilib -Itest test/test_validate.rb
```

Or use the stdlib rake task:

```bash
rake test
```

## Conformance

Run every case in the shared suite at `../../conformance/suite`:

```bash
ruby conformance_runner.rb
# or
rake conformance
```

## Demo

```bash
ruby -Ilib examples/demo.rb
```

## Layout

```
sdks/ruby/
├── crowdcontrol.gemspec      # no runtime deps
├── Rakefile                  # stdlib-only targets
├── README.md
├── conformance_runner.rb
├── lib/
│   ├── crowdcontrol.rb
│   └── crowdcontrol/
│       ├── version.rb
│       ├── types.rb
│       ├── lexer.rb
│       ├── parser.rb
│       ├── evaluator.rb
│       └── validate.rb
├── test/
│   ├── test_lexer.rb
│   ├── test_parser.rb
│   ├── test_evaluator.rb
│   └── test_validate.rb
└── examples/
    └── demo.rb
```

## License

Apache-2.0 — see [../../LICENSE](../../LICENSE).

[cc]: https://github.com/mikemackintosh/crowdcontrol
