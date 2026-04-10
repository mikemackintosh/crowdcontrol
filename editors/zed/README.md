# CrowdControl — Zed extension

A [Zed](https://zed.dev) editor extension for the CrowdControl
policy language. Provides:

- **Tree-sitter syntax highlighting** — forbid/warn/permit rule kinds,
  operators, strings, comments, function calls, and field paths all
  get semantic highlights via a dedicated grammar (see
  [`tree-sitter-crowdcontrol/`](../../tree-sitter-crowdcontrol) in
  this repo).
- **LSP integration** — live diagnostics (parse errors), hover
  documentation, and completion via the `cc-lsp` binary.
- **Smart brackets + comments** — auto-close for `{` `[` `(` `"`,
  line comment toggle for `#` and `//`.

## Status

**Phase A** — local dev install only. The grammar lives in a
subdirectory of the main crowdcontrol repo, which Zed's extension
registry doesn't support directly. Until we split the grammar into
its own repo (Phase B → Phase C: publish to Zed's official
extension registry), installation is manual via `Install Dev
Extension`.

## Install

Prerequisites:

1. **Go 1.23+** (for the `cc-lsp` binary)
2. **tree-sitter CLI** (`brew install tree-sitter-cli` on macOS)
3. **Zed** installed

Build the LSP server and put it on your PATH:

```bash
go install github.com/mikemackintosh/crowdcontrol/cmd/cc-lsp@latest
# or build from source:
go build -o /usr/local/bin/cc-lsp ./cmd/cc-lsp
```

Stage and install the extension:

```bash
./scripts/install-zed-extension.sh
```

The script:

1. Regenerates the tree-sitter parser if needed
2. Stages `editors/zed/` to `.zed-dev-extension/`
3. Rewrites the grammar reference to a local `file://` URL
4. Initialises a git repo inside `tree-sitter-crowdcontrol/` (Zed
   requires the grammar location to be a git repo, even for local
   file:// URLs)

Then in Zed:

1. Open the command palette (`Cmd+Shift+P`)
2. Run `zed: install dev extension`
3. Browse to the `.zed-dev-extension/` directory the script printed
4. Open any `.cc` file and you should see syntax highlighting and
   LSP diagnostics

## File extension conflict with C++

`.cc` is also a common C++ source extension, and Zed's built-in
C++ support claims it too. Extension load order determines which
one wins. If you work with both C++ and CrowdControl in the same
project:

- Use the command palette `zed: select language` → `CrowdControl`
  to manually switch a file
- Or add a workspace setting to your Zed config:

  ```json
  {
    "file_types": {
      "CrowdControl": ["cc"]
    }
  }
  ```

  which forces `.cc` → CrowdControl project-wide.

## Troubleshooting

**"cc-lsp not found on PATH"** — the extension's error message
tells you exactly what to do. Run `which cc-lsp` to verify the
binary is in your PATH. If you installed via `go install`, make
sure `$(go env GOPATH)/bin` is in `$PATH`.

**Grammar fails to build** — make sure `tree-sitter generate`
succeeds from inside `tree-sitter-crowdcontrol/`. The install
script runs this automatically, but you can run it manually to
see errors.

**Highlighting works but diagnostics don't** — that means the
grammar loaded fine but the LSP server couldn't start. Check
Zed's log (`View → Debug → Open Log`) for the LSP error.

## What's in here

```
editors/zed/
├── extension.toml                 # manifest: languages, grammar ref, LSP binding
├── Cargo.toml                     # Rust crate that compiles to extension.wasm
├── src/
│   └── crowdcontrol.rs            # LSP launch logic
└── languages/
    └── crowdcontrol/
        ├── config.toml            # file extensions, brackets, comments
        └── highlights.scm         # tree-sitter highlight queries
```

## Roadmap

- **Phase B** — split `tree-sitter-crowdcontrol/` into its own git
  repo so the extension can reference it by URL + commit SHA. Add
  `injections.scm`, `indents.scm`, `brackets.scm`, `outline.scm`,
  and `textobjects.scm` for full Zed feature parity with
  first-party languages.
- **Phase C** — submit to Zed's [official extension
  registry](https://github.com/zed-industries/extensions) so users
  can install from Zed's built-in extension picker without any
  command-line steps.
- Auto-download `cc-lsp` from GitHub Releases if it isn't found on
  PATH, pinned to the extension's version.
