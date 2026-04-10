#!/usr/bin/env bash
#
# Prepare a copy of editors/zed/ with the grammar reference rewritten
# to a local file:// URL, ready to be loaded via Zed's "Install Dev
# Extension" flow.
#
# Why this script exists: Zed extensions reference their tree-sitter
# grammar via a git repository URL. The CrowdControl grammar lives in
# the same repo as the extension (under tree-sitter-crowdcontrol/),
# and Zed's loader doesn't support subdirectories in grammar repos.
# So for local development we rewrite extension.toml to use a file://
# URL pointing at the absolute path of tree-sitter-crowdcontrol/ on
# this machine. Phase C will split the grammar into its own repo and
# this script will become unnecessary.
#
# Usage:
#     ./scripts/install-zed-extension.sh
#
# After it runs, open Zed and use the command palette:
#     > Install Dev Extension
# then browse to the path printed at the end.

set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT=$(pwd)

GRAMMAR_DIR="$REPO_ROOT/tree-sitter-crowdcontrol"
EXT_SRC="$REPO_ROOT/editors/zed"
STAGING="$REPO_ROOT/.zed-dev-extension"

if [ ! -f "$GRAMMAR_DIR/grammar.js" ]; then
    echo "error: $GRAMMAR_DIR/grammar.js not found" >&2
    exit 1
fi

if [ ! -f "$GRAMMAR_DIR/src/parser.c" ]; then
    echo "-> regenerating tree-sitter parser"
    (cd "$GRAMMAR_DIR" && tree-sitter generate)
fi

echo "-> staging extension to $STAGING"
rm -rf "$STAGING"
mkdir -p "$STAGING"
cp -R "$EXT_SRC"/* "$STAGING"/

# Copy the grammar into the staging dir so we can initialise a
# throwaway git repo there without polluting the source tree with
# a nested .git/ directory.
GRAMMAR_STAGING="$STAGING/grammar"
mkdir -p "$GRAMMAR_STAGING"
rsync -a --exclude '.git' "$GRAMMAR_DIR/" "$GRAMMAR_STAGING/"

# Rewrite the grammar block to use a file:// URL pointing at the
# staging copy. Zed expects the repository field to be a URL, and
# file:// URLs must be absolute.
python3 - "$STAGING/extension.toml" "$GRAMMAR_STAGING" <<'PY'
import sys, re
path = sys.argv[1]
grammar = sys.argv[2]
with open(path, "r") as f:
    body = f.read()

# Replace the repository URL in the [grammars.crowdcontrol] block
# with a file:// URL pointing at the local grammar directory.
new_block = (
    "[grammars.crowdcontrol]\n"
    f'repository = "file://{grammar}"\n'
    'rev = "HEAD"\n'
)
body = re.sub(
    r"\[grammars\.crowdcontrol\].*?(?=\n\[|\Z)",
    new_block.rstrip(),
    body,
    count=1,
    flags=re.DOTALL,
)
with open(path, "w") as f:
    f.write(body)
print("rewrote", path)
PY

# Zed loads grammars from git repos, so the grammar directory must
# be a git repo (even if it's a sub-repo/clone of the main one).
# Initialise one if needed.
# Zed's grammar loader uses git under the hood, so the grammar
# directory has to be a git repo with at least one commit. We
# initialise that inside the staging copy (never in the source
# tree) and disable signing for the single throwaway commit so
# your global git signing config is untouched.
echo "-> initialising git in staging grammar copy (dev scaffolding only)"
(
    cd "$GRAMMAR_STAGING"
    git init -q
    git add -A
    git \
        -c user.email=local@dev \
        -c user.name="Dev" \
        -c commit.gpgsign=false \
        commit -q -m "local dev snapshot"
)

echo
echo "================================================================"
echo "  Zed dev extension staged at:"
echo "    $STAGING"
echo "================================================================"
echo
echo "Next steps:"
echo "  1. Open Zed"
echo "  2. Command palette (Cmd+Shift+P): 'zed: install dev extension'"
echo "  3. Browse to: $STAGING"
echo "  4. Open any .cc file and confirm diagnostics / highlighting work"
echo
echo "Note: cc-lsp must be on your PATH. Install with:"
echo "    go install github.com/mikemackintosh/crowdcontrol/cmd/cc-lsp@latest"
