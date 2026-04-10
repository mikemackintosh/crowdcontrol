# CrowdControl

> A small, readable policy language for gating actions on structured data.

CrowdControl is a domain-agnostic policy language. You write rules using
plain forbid/warn/permit blocks, hand it a JSON document, and it tells you
which rules fired. It is intentionally less powerful than CEL, Cedar, or
Rego — the design goal is that a security engineer who has never seen a
`.cc` file before can read a policy and understand it in under 30 seconds.

```crowdcontrol
forbid "no-public-prod-storage" {
  description "Production storage must not be public"
  owner       "platform-security"

  resource.type == "storage_bucket"
  resource.environment == "production"
  resource.acl in ["public-read", "public-read-write"]

  unless user.groups contains "platform-oncall"

  message "{user.name} cannot make {resource.name} public in prod"
}
```

## Features

- **Three rule kinds:** `forbid`, `warn`, `permit`
- **Conditions:** field comparisons, list membership, glob patterns, regex,
  numeric arithmetic, list quantifiers (`any`/`all`), aggregate counts
- **Escape clauses:** `unless` for exceptions
- **Schema validation:** static lint catches typos and type mismatches before runtime
- **Explain mode:** per-condition trace for auditing decisions
- **Two default modes:** allow-by-default or deny-by-default
- **Zero dependencies:** the Go reference implementation is pure stdlib

## Getting Started

### Install the CLI

```bash
# Pre-built binary (recommended — Linux / macOS / Windows × amd64 / arm64)
curl -L https://github.com/mikemackintosh/crowdcontrol/releases/latest/download/crowdcontrol_0.1.0_$(uname -s)_$(uname -m).tar.gz | tar xz cc
sudo mv cc /usr/local/bin/

# Or via go install
go install github.com/mikemackintosh/crowdcontrol/cmd/cc@latest

# Or via Docker
docker run --rm ghcr.io/mikemackintosh/crowdcontrol:latest version
```

### Your first policy

```bash
mkdir -p policies
cat > policies/rules.cc <<'EOF'
forbid "no-admin-deletes-by-interns" {
  user.role == "intern"
  request.action == "delete"
  resource.environment == "production"
  message "{user.name} is an intern and cannot delete production resources"
}
EOF

cat > input.json <<'EOF'
{
  "user":     {"name": "alex", "role": "intern"},
  "request":  {"action": "delete"},
  "resource": {"environment": "production"}
}
EOF

cc evaluate --policy ./policies --input ./input.json
```

Output:

```
DENY: alex is an intern and cannot delete production resources (no-admin-deletes-by-interns)
```

Exit code is `1` because at least one forbid rule denied the input.

### Embedding in Go

```go
import "github.com/mikemackintosh/crowdcontrol"

eng, err := crowdcontrol.New([]string{"./policies"})
if err != nil { panic(err) }

results := eng.Evaluate(map[string]any{
    "user":    map[string]any{"name": "alex", "role": "intern"},
    "request": map[string]any{"action": "delete"},
    "resource": map[string]any{"environment": "production"},
})

for _, r := range results {
    fmt.Printf("%s [%s] passed=%v: %s\n", r.Rule, r.Kind, r.Passed, r.Message)
}
```

## CLI Commands

| Command          | Purpose                                                          |
| ---------------- | ---------------------------------------------------------------- |
| `cc evaluate`    | Run policies against an input document                          |
| `cc validate`    | Syntax-check `.cc` files; optional schema validation             |
| `cc test`        | Run JSON test suites against policies                            |
| `cc parse`       | Print the rule summary for one or more `.cc` files               |
| `cc version`     | Print the cc version                                             |

Run `cc <command> --help` for command-specific options.

## SDKs

CrowdControl ships native parser+evaluator implementations in multiple
languages. Every SDK passes the same conformance suite (`conformance/suite/`)
and produces identical decisions for identical inputs.

| Language       | Status               | Location                  |
| -------------- | -------------------- | ------------------------- |
| **Go**         | reference (this repo) | top of repo              |
| **Python**     | planned (Stage 2)    | `sdks/python/`            |
| **TypeScript** | planned (Stage 2)    | `sdks/typescript/`        |
| **Ruby**       | planned (Stage 2)    | `sdks/ruby/`              |
| **Kotlin**     | planned (Stage 2)    | `sdks/kotlin/`            |
| **PHP**        | planned (Stage 2)    | `sdks/php/`               |

Every SDK uses only its host language's standard library — no external runtime
dependencies.

## Editor support

| Editor | Repo | Status |
| --- | --- | --- |
| **VS Code** | [mikemackintosh/vscode-crowdcontrol](https://github.com/mikemackintosh/vscode-crowdcontrol) | Syntax highlighting + LSP diagnostics |
| **Zed** | [mikemackintosh/zed-crowdcontrol](https://github.com/mikemackintosh/zed-crowdcontrol) | Tree-sitter highlighting + LSP diagnostics |
| **Neovim / Helix / Emacs** | [mikemackintosh/tree-sitter-crowdcontrol](https://github.com/mikemackintosh/tree-sitter-crowdcontrol) | Tree-sitter grammar (drop in via your editor's parser config) |

All editor support uses the same `cc-lsp` language server that ships
in this repo (`cmd/cc-lsp`). Install it with `go install
github.com/mikemackintosh/crowdcontrol/cmd/cc-lsp@latest` or grab a
pre-built binary from the
[releases page](https://github.com/mikemackintosh/crowdcontrol/releases).

## File extension

CrowdControl policies use the `.cc` extension. **Note:** `.cc` is
also a common extension for C++ source files. The editor extensions
above register themselves for `.cc` and each one documents how to
pin the language per-workspace when there's a conflict with the
built-in C++ support.

## Project Layout

```
crowdcontrol/
├── crowdcontrol.go      # top-level public API (Engine, Evaluate, etc.)
├── types/               # AST, Schema, Result definitions
├── parser/              # lexer + parser
├── evaluator/           # evaluation engine + schema validator
├── cmd/cc/              # reference CLI (includes `cc serve` HTTP PDP)
├── cmd/cc-lsp/          # LSP server consumed by the editor extensions
├── cmd/cc-wasm/         # WebAssembly shim for the docs playground
├── examples/            # quickstart and example policies
├── conformance/         # language-agnostic test suite (every SDK runs this)
└── sdks/                # native ports in 6 languages (Python, TS, Ruby, Kotlin, PHP, Go)
```

## Comparison with Other Policy Languages

There is no shortage of authorization and policy languages in the wild —
CEDAR, Cerbos, Rego/OPA, Casbin, XACML, and others. They all solve real
problems and they all make trade-offs. CrowdControl optimizes hard for
**readability** and **embedding simplicity**. Everything else in this
section is downstream of that choice.

### Feature matrix

| Feature                       | CrowdControl       | CEDAR              | Cerbos             | Rego / OPA         | Casbin             | XACML              |
| ----------------------------- | ------------------ | ------------------ | ------------------ | ------------------ | ------------------ | ------------------ |
| Syntax                        | dedicated DSL      | dedicated DSL      | YAML + CEL         | logic programming  | model + CSV/DB     | XML                |
| Paradigm                      | rules over a doc   | principal/action/resource | resource-scoped  | declarative logic  | model-driven       | attribute-based    |
| Input model                   | single JSON doc    | entity graph       | principal/resource/aux | any JSON       | request tuple      | XACML request      |
| Turing-complete               | no (by design)     | no (by design)     | no                 | effectively yes    | no                 | no                 |
| Formal semantics + proofs     | no                 | **yes** (Lean/Dafny) | no                 | partial            | no                 | standardized       |
| Static type checking          | opt-in schema      | **yes** (entities) | **yes** (schemas)  | no                 | no                 | schema-based       |
| Escape clause (`unless`)      | **yes**            | no direct form     | via conditions     | via negation       | via `matcher`      | via obligations    |
| Explain / trace mode          | **yes**            | yes                | yes                | yes (pretty deep)  | no                 | vendor-dependent   |
| Default-deny option           | opt-in             | yes                | yes                | n/a (you write it) | n/a                | yes                |
| Runtime shape                 | embedded library   | lib or service     | **sidecar/service**| **sidecar/service**| embedded library   | big engines        |
| External runtime deps         | zero               | Rust runtime       | Go binary          | Go binary / WASM   | varies             | JVM typically      |
| First-party SDKs              | Go, Py, TS, Rb, Kt, PHP | Rust, Java, JS, Go, Python | many       | many               | many               | Java-heavy         |
| Learning curve (new reader)   | minutes            | an hour            | an afternoon       | days               | an afternoon       | a lifetime         |

"Learning curve" is the most important row. Pick the tool whose shape
matches your problem; every row above exists to let you discard candidates
quickly.

### On "not Turing-complete"

Both CrowdControl and CEDAR list "not Turing-complete" as a feature, not a
limitation. The reasons are the same: bounded evaluation (every policy
terminates in time proportional to the input), decidability (you can
answer questions about the policy itself, not just run it), and a small
enough surface area that a human can hold the whole language in their
head.

Rego made the other trade. It gained recursive rules, comprehensions,
partial evaluation, and the ability to express almost any policy you can
describe — at the cost of a steeper learning curve and the need for
evaluation timeouts. Neither choice is wrong; they're just different bets.

CrowdControl could be made Turing-complete by adding recursion, rule
references, or user-defined functions. None of those are in the grammar
on purpose.

### On "CEDAR has proofs, CrowdControl has tests"

This phrase gets thrown around a lot, so it's worth being concrete.

**CEDAR has a formal semantics** — a mathematical definition of what every
policy construct means — and AWS has used [Lean](https://lean-lang.org/)
and [Dafny](https://dafny.org/) (machine-checked proof assistants) to
prove theorems *about CEDAR itself*. Examples of things they have proven:

- **Validator soundness.** If CEDAR's type checker accepts your policy,
  the runtime is mathematically guaranteed to never throw a type error
  on that policy — for *any* possible input, not just tested ones.
- **Determinism.** Same policy + same input ⇒ same decision. No hidden
  non-determinism.
- **Spec ↔ implementation equivalence.** The Rust code you actually run
  has been proven to match the mathematical spec.
- **Analyzer correctness.** CEDAR can answer *"is policy A strictly more
  permissive than policy B?"* with a proof, not a guess.

These are proofs checked by a theorem prover. They cover *every possible
input*, including the ones nobody thought of. See the
[cedar-spec](https://github.com/cedar-policy/cedar-spec) repo.

**CrowdControl has a conformance suite** — `conformance/suite/*.json`,
every SDK runs it, every SDK must produce identical decisions on every
case. Plus parser/evaluator unit tests in each port. This gives high
confidence for the cases in the suite and nothing for cases outside it.

The practical difference:

| Question | CEDAR | CrowdControl |
| --- | --- | --- |
| "Will this policy ever crash at runtime?" | **Provably** no if it type-checks | Probably not — bounded grammar, covered by tests |
| "Do my Go and Python SDKs agree on all inputs?" | Provably yes (single verified spec) | On every input in the conformance suite, yes |
| "Is my new policy strictly stricter than the old one?" | Provably answerable by the analyzer | Enumerate test cases and hope |
| "Can the engine hang on malicious input?" | Provably no (decidable evaluation) | Probably not — bounded grammar — but not proven |

If your policy engine serves trillions of authorization decisions for a
global cloud provider, the difference matters a lot and the investment in
formal verification pays for itself. If it's gating Terraform plans in CI,
a conformance suite you can actually read is probably the right bar.

### CrowdControl vs CEDAR

[CEDAR](https://www.cedarpolicy.com/) is AWS's open-source policy language,
built around a principal/action/resource/context model with an entity
store, and the only production policy language with machine-checked
proofs about its semantics.

- **Data model.** CEDAR models a world of *entities* (users, groups,
  resources) with attributes and relationships. CrowdControl evaluates a
  single flat JSON document and has no notion of entities. This is a
  structural difference, not a maturity gap.
- **Scope.** CEDAR answers *"can this principal perform this action on
  this resource?"*. CrowdControl answers *"is this structured document
  acceptable under these rules?"*. Very different shapes.
- **Rigor.** CEDAR has machine-checked proofs (see above). CrowdControl
  has a conformance suite. Real gap if you need certainty; not a gap for
  most gating use cases.
- **Use CEDAR when:** you're building fine-grained SaaS authorization
  with users, groups, roles, and resources, especially if correctness
  really has to be provable.
- **Use CrowdControl when:** you want to gate a plan, a PR, a config
  file, or any other structured document with rules a security engineer
  can review on their first day.

### CrowdControl vs Cerbos

[Cerbos](https://cerbos.dev/) is a stateless policy decision point.
Policies are YAML, conditions are [CEL](https://github.com/google/cel-spec),
and the engine runs as a sidecar or service next to your app.

- **Syntax.** Cerbos splits into two languages: YAML for structure and
  CEL for conditions. CrowdControl is one purpose-built language.
- **Deployment.** Both ship a deployable PDP now. `cc serve` exposes
  `POST /v1/evaluate`, streams structured JSON audit logs, supports
  shadow mode, and reloads policies atomically on SIGHUP. Cerbos still
  has more mature rollout controls (percentage rollout, per-rule
  enable/disable) and richer policy bundle distribution — maturity
  delta, not a missing capability.
- **Scope.** Cerbos policies are scoped to a resource kind and assume a
  principal/action/resource request. CrowdControl rules operate on any
  document shape you choose.
- **Use Cerbos when:** you need an always-on policy decision point with
  production-grade operational surface sitting next to a fleet of
  microservices, *today*.
- **Use CrowdControl when:** you want something you can call inline from
  a binary — no service to deploy, no sidecar to babysit.

### CrowdControl vs Rego / OPA

[Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) is
the language of [Open Policy Agent](https://www.openpolicyagent.org/). It
is a declarative, Datalog-inspired logic language, and probably the most
powerful policy language in wide production use.

- **Expressiveness.** Rego can express basically any policy you can
  describe. CrowdControl can't — and won't try. The readability pitch
  depends on a bounded grammar.
- **Learning curve.** Rego requires you to understand partial rules,
  comprehensions, unification, and the "every rule is a set" mental
  model. CrowdControl reads like bullet points.
- **Tooling.** OPA has a mature ecosystem: REPL, Playground, WASM
  compilation, Gatekeeper, conftest, Styra DAS. CrowdControl has a CLI,
  LSP, and VS Code extension — enough to be productive, nowhere near the
  OPA ecosystem.
- **Debuggability.** OPA's trace shows a full evaluation tree.
  CrowdControl's trace is a flat per-condition list annotated with `+` /
  `-` and the resolved value — easier to skim, less powerful.
- **Use Rego/OPA when:** you need a general-purpose policy engine that
  scales from admission control to feature flags to data filtering, and
  the learning curve is worth it.
- **Use CrowdControl when:** your rules are simple enough that the Rego
  learning curve is the biggest thing standing between "idea" and "rule
  in CI".

### CrowdControl vs Casbin

[Casbin](https://casbin.org/) is a widely-used authorization library with
a model-driven approach — you pick a model (ACL, RBAC, ABAC, RESTful) and
provide rules in CSV or a database.

- **Indirection.** Casbin has a separate model definition file that
  shapes how policies are interpreted. CrowdControl has no model layer;
  rules are what they say they are.
- **Storage.** Casbin is usually backed by a store (CSV/DB). CrowdControl
  loads `.cc` files at startup and keeps everything in memory.
- **Scope.** Casbin is tightly focused on access control. CrowdControl
  is a general rule engine for arbitrary JSON documents.
- **Use Casbin when:** you're wiring RBAC/ABAC into an app and you want
  a well-trodden library with DB-backed policy storage.
- **Use CrowdControl when:** you want CI-style gates, lint rules, or
  change-review checks on structured data.

### CrowdControl vs XACML

[XACML](https://en.wikipedia.org/wiki/XACML) is the OASIS standard for
attribute-based access control. It's comprehensive, standardized, and
famously verbose.

- **Syntax.** XACML is XML. CrowdControl is not. This is the entire
  section.
- **Use XACML when:** you have a compliance requirement that names XACML.
- **Use CrowdControl when:** you don't.

### Honourable mentions

- **[SpiceDB](https://authzed.com/spicedb) / Zanzibar** —
  relationship-based authorization (`document:1#viewer@user:alice`). A
  completely different paradigm; use it when your questions are of the
  form *"who has access to what, transitively?"*. CrowdControl has
  nothing to say about graph traversal. Structural difference.
- **[OpenFGA](https://openfga.dev/) / [Warrant](https://warrant.dev/)** —
  more Zanzibar-style relationship engines. Same answer as SpiceDB.
- **[Styra DAS](https://www.styra.com/styra-das/)** — commercial control
  plane on top of OPA. If you're already on Rego, this is the tool for
  operating it at scale.

### When to choose CrowdControl

Pick CrowdControl when most of these are true:

- Rules should be reviewable by people who don't write code every day.
- The thing you're gating is a **document** (a Terraform plan, a GitHub
  event, a Kubernetes manifest, a config file) — not a runtime request.
- You want the fastest path from *"new rule idea"* to *"new rule in CI"*.
- You want a dependency-free embed, not another service to run.

Pick something else when there's a real **structural** gap:

- You need entity-based authorization across a user/resource graph →
  **CEDAR**, **SpiceDB**, or **OpenFGA**.
- You need relationship/Zanzibar-style authorization queries →
  **SpiceDB**, **OpenFGA**.
- You need machine-checked proofs about policy semantics → **CEDAR**.
- You need a Turing-complete policy engine and the readability cost is
  acceptable → **Rego / OPA**.

### What CrowdControl doesn't have yet (roadmap, not limitation)

Operational / tooling gaps. None are precluded by the language or
engine design.

- Percentage rollout and per-rule enable/disable (whole-server shadow
  mode exists via `cc serve --shadow`)
- Signed policy bundle distribution (sign, ship, verify)
- gRPC transport on `cc serve` (HTTP+JSON exists today)
- Rich web playground (planned — WASM build)
- Formal verification of semantics

**Recently shipped:**

- **`cc serve`** — HTTP PDP mode with structured audit logs, shadow
  mode, SIGHUP reload, bearer-token auth, CORS, and Prometheus metrics.
  See [docs/serve.html](https://mikemackintosh.github.io/crowdcontrol/serve.html).
- **Docker conformance runners** — every SDK ships a `Dockerfile` so
  you can verify it without installing its runtime locally.

If any gap above is a blocker for you, open an issue.

## Documentation

- **[Online docs](https://mikemackintosh.github.io/crowdcontrol/)** — full docs site (GitHub Pages)
- [DESIGN.md](./DESIGN.md) — language design rationale and full feature reference
- [SPEC.md](./SPEC.md) — normative language specification
- [conformance/README.md](./conformance/README.md) — conformance suite format and how to run it
- [vscode-crowdcontrol](https://github.com/mikemackintosh/vscode-crowdcontrol) — VS Code extension (separate repo)
- [zed-crowdcontrol](https://github.com/mikemackintosh/zed-crowdcontrol) — Zed extension (separate repo)
- [tree-sitter-crowdcontrol](https://github.com/mikemackintosh/tree-sitter-crowdcontrol) — tree-sitter grammar (separate repo)

## License

MIT — see [LICENSE](./LICENSE).
