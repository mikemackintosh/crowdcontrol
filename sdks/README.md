# CrowdControl SDKs

This directory holds native ports of the CrowdControl engine in other
languages. Every SDK is a **full lexer + parser + evaluator** in its host
language, using only that language's standard library — no external runtime
dependencies, no FFI, no shared binary.

## Why native ports

The Go implementation in the repo root is the reference. SDKs exist so other
ecosystems (Python services, Node tooling, Ruby gems, JVM apps, PHP apps)
can evaluate `.cc` policies without spawning a Go binary or making a network
call. The "stdlib only" constraint keeps installation trivial — `pip install`,
`gem install`, `npm install` — with zero native build steps on every platform.

## Status

| Language       | Status                | Stdlib testing framework  |
| -------------- | --------------------- | ------------------------- |
| **Python**     | planned (Stage 2)     | `unittest`                |
| **TypeScript** | planned (Stage 2)     | `node:test` (Node 18+)    |
| **Ruby**       | planned (Stage 2)     | `minitest`                |
| **Kotlin**     | planned (Stage 2)     | `kotlin.test`             |
| **PHP**        | planned (Stage 2)     | bespoke runner (no stdlib testing) |

## Conformance

Every SDK must:

1. Implement the full grammar and semantics in [`../SPEC.md`](../SPEC.md).
2. Ship a `conformance_runner` (script or binary) that consumes
   [`../conformance/suite/*.json`](../conformance/suite/) and prints `PASS`/`FAIL`
   per case, exiting non-zero on any failure.
3. Be wired into [`../.github/workflows/conformance.yml`](../.github/workflows/conformance.yml)
   so CI runs the suite on every PR.

A new feature is not considered "implemented in CrowdControl" until **every SDK
in this directory passes** the conformance case for that feature.

## Public API per SDK

Each SDK should expose roughly the same surface, idiomatic to its host language:

```
crowdcontrol.parse(source: string) -> Policy
crowdcontrol.load_directory(path: string) -> Engine
crowdcontrol.from_source(sources: list<string>) -> Engine
engine.evaluate(input: dict) -> list<Result>
engine.validate(schema: Schema) -> list<Warning>
```

The exact naming follows host conventions — `loadDirectory` in TypeScript,
`load_directory` in Python and Ruby, `loadDirectory` in Kotlin, etc.

## Adding an SDK

1. Read [`../SPEC.md`](../SPEC.md) end-to-end.
2. Create `sdks/<lang>/` and lay out an idiomatic project for that language.
3. Implement lexer → parser → evaluator → schema validator.
4. Write unit tests for each component.
5. Write `conformance_runner` and verify all cases pass.
6. Add a job to `../.github/workflows/conformance.yml`.
7. Open a PR.
