#!/usr/bin/env bash
#
# Build the CrowdControl Kotlin SDK without Gradle.
#
# Produces a single self-contained jar (crowdcontrol.jar) at the repo root
# that you can run with:
#
#   java -cp crowdcontrol.jar io.github.mikemackintosh.crowdcontrol.ConformanceRunner
#   java -cp crowdcontrol.jar io.github.mikemackintosh.crowdcontrol.Demo
#
# Requires `kotlinc` (the command-line Kotlin compiler) on your PATH.

set -euo pipefail

cd "$(dirname "$0")"

if ! command -v kotlinc >/dev/null 2>&1; then
    echo "error: kotlinc not found on PATH" >&2
    echo "install with: brew install kotlin  (or via SDKMAN: sdk install kotlin)" >&2
    exit 1
fi

SRC_MAIN="src/main/kotlin"
EXAMPLE="examples/Demo.kt"
OUT="crowdcontrol.jar"

echo "compiling main sources + demo ..."
kotlinc -include-runtime \
    -d "$OUT" \
    "$SRC_MAIN" \
    "$EXAMPLE"

echo
echo "built: $OUT"
echo
echo "run conformance: java -cp $OUT io.github.mikemackintosh.crowdcontrol.ConformanceRunner"
echo "run demo:        java -cp $OUT io.github.mikemackintosh.crowdcontrol.Demo"
