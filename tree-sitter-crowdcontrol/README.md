# tree-sitter-crowdcontrol

A [tree-sitter](https://tree-sitter.github.io/tree-sitter/) grammar
for the [CrowdControl](https://mikemackintosh.github.io/crowdcontrol/)
policy language.

Tree-sitter powers incremental parsing and syntax highlighting for
modern editors (Zed, Neovim, Helix, Emacs, GitHub code search). This
grammar is the canonical source of `.cc` highlighting for all of
them.

## Status

Initial version. Covers the full language surface — rule kinds
(forbid/warn/permit), metadata (description/owner/link), conditions,
operators, quantifiers (any/all), built-in functions (count, len,
lower, upper), field paths, arithmetic, `unless` escape clauses, and
both comment styles (`#` and `//`).

## Layout

```
tree-sitter-crowdcontrol/
├── grammar.js                  # grammar rules in tree-sitter DSL
├── package.json                # npm metadata (scope + file types)
├── queries/
│   └── highlights.scm          # editor highlight query
├── src/                        # generated parser — commit this
│   ├── grammar.json
│   ├── node-types.json
│   ├── parser.c                # ~3000 lines of generated C
│   └── tree_sitter/
│       ├── alloc.h
│       ├── array.h
│       └── parser.h
└── test/
    └── corpus/
        └── basic.txt           # tree-sitter test corpus
```

## Developing

```bash
# Regenerate parser.c from grammar.js after edits
tree-sitter generate

# Parse a real .cc file and dump the tree
tree-sitter parse ../examples/policies/global.cc

# Run the test corpus
tree-sitter test
```

All tests should pass before any change lands. The test corpus is
under `test/corpus/basic.txt` — one test per block, each with an
input snippet and an expected S-expression tree.

## Highlight captures

`queries/highlights.scm` uses the standard tree-sitter capture
names so any editor theme that ships with sensible defaults will
pick up reasonable colors without per-editor configuration:

| Capture              | What it marks                                      |
| -------------------- | -------------------------------------------------- |
| `@keyword.control`   | `forbid`, `warn`, `permit`                         |
| `@keyword.operator`  | `unless`, `not`, `or`, `has`, `any`, `all`, `in`, set operators |
| `@operator`          | comparison + arithmetic operators                  |
| `@property`          | metadata keys (`description`, `owner`, `link`, `message`) |
| `@function.builtin`  | `count`, `len`, `lower`, `upper`                   |
| `@string`            | string literals including rule names and messages  |
| `@number`            | numeric literals                                   |
| `@boolean`           | `true`, `false`                                    |
| `@comment`           | `#` and `//` line comments                         |
| `@variable`          | identifiers inside field paths                     |
| `@punctuation.bracket` | `{`, `}`, `[`, `]`, `(`, `)`                     |
| `@punctuation.delimiter` | `,`, `.`                                       |

## Where it's consumed

- **Zed editor** — via [`editors/zed/`](../editors/zed) in the
  crowdcontrol repo. The extension references this grammar.
- **Neovim / Helix / Emacs** — once this grammar is published to
  its own git repo (Phase B of the editor roadmap), any editor
  using `nvim-treesitter`, Helix's tree-sitter integration, or
  `treesit-auto` can pick it up.

## Relationship to the reference Go parser

This tree-sitter grammar is the *syntactic* grammar — its job is
to produce a parse tree good enough for editor features (syntax
highlighting, folding, symbol outlining, bracket matching). It is
intentionally looser than the reference Go parser (see
[`parser/parser.go`](../parser/parser.go)) so that in-progress
edits still highlight cleanly. The authoritative parser is the Go
reference; if your editor highlights something one way but the
reference parser disagrees at runtime, the reference parser wins.

## License

MIT. Same as the rest of the CrowdControl project.
