#!/usr/bin/env bash
#
# Rebuild the CrowdControl WASM module that powers the docs playground.
# CI runs this via .github/workflows/pages.yml on every push to main,
# so you only need to run it locally if you're iterating on the
# playground UI or the cc-wasm shim and want to see changes live.
#
# Usage:
#     ./scripts/build-playground-wasm.sh
#
# Then serve docs/ with any static file server, e.g.:
#     python3 -m http.server --directory docs 8000
#     open http://localhost:8000/playground.html

set -euo pipefail

cd "$(dirname "$0")/.."

OUT_DIR="docs/assets/wasm"
mkdir -p "$OUT_DIR"

echo "-> building cc.wasm"
GOOS=js GOARCH=wasm go build \
    -ldflags="-s -w" \
    -trimpath \
    -o "$OUT_DIR/cc.wasm" \
    ./cmd/cc-wasm

echo "-> copying wasm_exec.js from $(go env GOROOT)/lib/wasm"
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$OUT_DIR/wasm_exec.js"

size=$(du -h "$OUT_DIR/cc.wasm" | cut -f1)
gzsize=$(gzip -c "$OUT_DIR/cc.wasm" | wc -c | awk '{printf "%.1f KiB\n", $1/1024}')
echo "   cc.wasm: $size uncompressed, $gzsize gzipped"
echo "   wasm_exec.js: $(du -h "$OUT_DIR/wasm_exec.js" | cut -f1)"

echo "done. serve with: python3 -m http.server --directory docs 8000"
