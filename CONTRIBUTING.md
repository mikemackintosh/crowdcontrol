# Contributing to CrowdControl

Thanks for your interest! CrowdControl is intentionally small and tries to
stay that way. The simplest contributions are usually the most welcome.

## Guiding principle

> A security engineer who has never seen a `.cc` file before should be able to
> read a policy and understand it in under 30 seconds.

If a feature makes that harder, it probably doesn't belong in CrowdControl —
which exists *because* it is less powerful than CEL/Cedar/Rego. For complex
policy needs, those engines remain the right tool.

## Project layout

See the [README](./README.md#project-layout) for the directory tree.

The Go implementation under `parser/`, `evaluator/`, `types/`, and the top-level
`crowdcontrol.go` is the **reference**. Every other SDK in `sdks/` must produce
the same decisions for the same inputs, verified by the conformance suite.

## Local dev

```bash
go build ./...
go test ./...
go run ./conformance/runners/go -suite ./conformance/suite -v
```

The conformance suite must always pass on `main`.

## Changing the language

If you want to add or change a language feature, the order is:

1. **Open an issue** describing the change and your reasoning. Cite the
   "30-second rule" — does the change keep policies skimmable?
2. **Update [SPEC.md](./SPEC.md).** The spec is the normative reference; if
   the spec doesn't say it, no SDK should implement it.
3. **Add at least one conformance case** in `conformance/suite/`. A change
   without conformance coverage is not considered "done."
4. **Update the Go reference** (lexer/parser/evaluator/tests).
5. **Update every SDK** in `sdks/` to match. CI runs the conformance suite
   against each SDK and will fail if any diverges.

## Adding a new SDK port

See `sdks/README.md` (Stage 2). The short version:

- Use only your host language's standard library.
- Implement the lexer, parser, and evaluator from `SPEC.md`.
- Ship a `conformance_runner` script/binary.
- All conformance cases must pass.

## Code style

- Go: `go fmt`, `go vet`, `golangci-lint run` must all be clean.
- Tests: prefer table-driven where it helps; avoid mocks of internal packages.
- Comments: explain *why*, not *what*. Reading the code is supposed to be easy.

## License

By contributing, you agree your contribution is licensed under the [MIT license](./LICENSE).
