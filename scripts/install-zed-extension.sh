#!/usr/bin/env bash
#
# Build and stage the CrowdControl Zed extension as a pre-compiled,
# drop-in bundle — no cargo, no tree-sitter CLI, and no external
# git clones needed at install time.
#
# What this script does:
#
#   1. Regenerates the tree-sitter parser if grammar.js is newer than
#      src/parser.c, and runs the test corpus as a sanity check.
#   2. Compiles tree-sitter-crowdcontrol to a WASM grammar module
#      (uses tree-sitter's bundled wasi-sdk — one-time ~100 MB
#      download on first run, cached afterwards).
#   3. Compiles the Zed extension Rust crate to wasm32-wasip1 using
#      the rustup cargo (falls back to whichever cargo is first on
#      PATH if rustup isn't present, but rustup is strongly
#      recommended since Homebrew rustc can't install wasm targets).
#   4. Assembles a drop-in extension bundle at .zed-dev-extension/
#      containing only extension.toml, extension.wasm, grammars/
#      crowdcontrol.wasm, and languages/. No src/, no Cargo.toml,
#      no target/ — Zed never needs to build anything.
#   5. Rewrites the [grammars.crowdcontrol] block in the bundled
#      extension.toml to drop the repository/commit fields, because
#      the grammar is already compiled into grammars/ so Zed doesn't
#      need to clone or build it.
#
# After the script runs, open Zed and:
#     > zed: install dev extension
#     browse to .zed-dev-extension/
#
# Zed's "install dev extension" checks:
#     - Cargo.toml present → invokes cargo → fails if rustc can't hit
#       wasm32-wasip1 (common with Homebrew rust).
#     - Only extension.wasm present → uses it directly, no cargo.
# This script deliberately produces the second shape.

set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT=$(pwd)

GRAMMAR_SRC="$REPO_ROOT/tree-sitter-crowdcontrol"
EXT_SRC="$REPO_ROOT/editors/zed"
STAGING="$REPO_ROOT/.zed-dev-extension"

# Prefer the rustup toolchain if present. Homebrew rust can't
# install rustup targets, so the wasm32-wasip1 std library is only
# available via rustup. We prepend ~/.cargo/bin to PATH so cargo
# resolves rustc from rustup instead of falling through to
# /opt/homebrew/bin/rustc.
if [ -d "$HOME/.cargo/bin" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
fi

CARGO=$(command -v cargo || true)
RUSTC=$(command -v rustc || true)
if [ -z "$CARGO" ] || [ -z "$RUSTC" ]; then
    echo "error: cargo or rustc not found on PATH." >&2
    echo "Install rustup from https://rustup.rs and run:" >&2
    echo "    rustup target add wasm32-wasip1" >&2
    exit 1
fi

# Double-check the wasm target is installed. Only rustup's rustc
# knows about this flag; Homebrew's rustc prints an error.
if ! rustup target list --installed 2>/dev/null | grep -q "^wasm32-wasip1$"; then
    echo "warning: wasm32-wasip1 target not installed in the active toolchain."
    echo "         attempting: rustup target add wasm32-wasip1"
    rustup target add wasm32-wasip1 2>&1 | tail -5 || {
        echo "error: could not install wasm32-wasip1 target." >&2
        echo "       your active rustc is: $RUSTC" >&2
        echo "       your active cargo is: $CARGO" >&2
        rustc --version >&2
        exit 1
    }
fi

if ! command -v tree-sitter >/dev/null 2>&1; then
    echo "error: tree-sitter CLI not found. Install with: brew install tree-sitter-cli" >&2
    exit 1
fi

if [ ! -f "$GRAMMAR_SRC/grammar.js" ]; then
    echo "error: $GRAMMAR_SRC/grammar.js not found" >&2
    exit 1
fi

# 1. Regenerate parser.c if grammar.js changed.
if [ ! -f "$GRAMMAR_SRC/src/parser.c" ] || [ "$GRAMMAR_SRC/grammar.js" -nt "$GRAMMAR_SRC/src/parser.c" ]; then
    echo "-> regenerating tree-sitter parser"
    (cd "$GRAMMAR_SRC" && tree-sitter generate)
fi

echo "-> running tree-sitter test corpus"
(cd "$GRAMMAR_SRC" && tree-sitter test)

# 2. Compile the grammar to WASM. This uses tree-sitter's bundled
#    wasi-sdk which it downloads to ~/.cache/tree-sitter on first
#    run (~100 MB one-time cost, cached afterwards).
echo "-> compiling grammar to WASM"
GRAMMAR_WASM="$GRAMMAR_SRC/crowdcontrol.wasm"
(cd "$GRAMMAR_SRC" && tree-sitter build --wasm -o "$GRAMMAR_WASM")

# 3. Compile the Rust extension to wasm32-wasip1 using rustup cargo.
echo "-> compiling Rust extension (${CARGO##*/})"
(
    cd "$EXT_SRC"
    "$CARGO" build --target wasm32-wasip1 --release 2>&1 | \
        grep -E "(Compiling zed-crowdcontrol|Finished|error)" || true
)

EXT_WASM="$EXT_SRC/target/wasm32-wasip1/release/zed_crowdcontrol.wasm"
if [ ! -f "$EXT_WASM" ]; then
    echo "error: extension wasm not produced at $EXT_WASM" >&2
    echo "try: $CARGO build --target wasm32-wasip1 --release (from $EXT_SRC)" >&2
    exit 1
fi

# 4. Assemble a drop-in bundle. Install-ready structure matches what
#    Zed writes into ~/Library/Application Support/Zed/extensions/
#    installed/<id>/ for registry-installed extensions:
#
#        extension.toml
#        extension.wasm
#        grammars/<grammar>.wasm
#        languages/<lang>/config.toml + highlights.scm + ...
echo "-> assembling bundle at $STAGING"
rm -rf "$STAGING"
mkdir -p "$STAGING/grammars" "$STAGING/languages"

cp "$EXT_SRC/extension.toml" "$STAGING/extension.toml"
cp "$EXT_SRC/README.md"      "$STAGING/README.md" 2>/dev/null || true
cp -R "$EXT_SRC/languages/." "$STAGING/languages/"

cp "$EXT_WASM"     "$STAGING/extension.wasm"
cp "$GRAMMAR_WASM" "$STAGING/grammars/crowdcontrol.wasm"

# 5. Strip the [grammars.crowdcontrol] block's repository / commit
#    keys since we already shipped the compiled wasm. Keeping the
#    block itself (just empty) tells Zed the grammar exists.
python3 - "$STAGING/extension.toml" <<'PY'
import re, sys
path = sys.argv[1]
with open(path) as f:
    body = f.read()

# Replace the grammar block with a bare marker: Zed looks up the
# compiled wasm at grammars/<name>.wasm and uses that directly.
new_block = "[grammars.crowdcontrol]\n"
body = re.sub(
    r"\[grammars\.crowdcontrol\].*?(?=\n\[|\Z)",
    new_block.rstrip(),
    body,
    count=1,
    flags=re.DOTALL,
)
with open(path, "w") as f:
    f.write(body)
PY

echo
echo "=== staged extension.toml ==="
cat "$STAGING/extension.toml"
echo
echo "=== bundle contents ==="
find "$STAGING" -type f | sed "s|$STAGING/||" | sort

echo
echo "================================================================"
echo "  Zed dev extension bundle ready at:"
echo "    $STAGING"
echo "================================================================"
echo
echo "Next steps:"
echo "  1. Install cc-lsp (if you haven't already):"
echo "       go install github.com/mikemackintosh/crowdcontrol/cmd/cc-lsp@latest"
echo "     and make sure \$(go env GOPATH)/bin is on your PATH."
echo
echo "  2. Open Zed."
echo "  3. Command palette (Cmd+Shift+P): 'zed: install dev extension'"
echo "  4. Browse to: $STAGING"
echo "  5. Open any .cc file. You should see syntax highlighting and"
echo "     parse error diagnostics."
echo
echo "  Debugging: tail -f ~/Library/Logs/Zed/Zed.log"
