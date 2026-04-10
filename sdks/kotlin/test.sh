#!/usr/bin/env bash
#
# Compile and run the CrowdControl Kotlin SDK unit tests without Gradle.
# Requires `kotlinc` and, transitively, the `kotlin-test-junit` runtime,
# which ships with the standard Kotlin compiler distribution under
# `$KOTLIN_HOME/lib/kotlin-test.jar`.

set -euo pipefail

cd "$(dirname "$0")"

if ! command -v kotlinc >/dev/null 2>&1; then
    echo "error: kotlinc not found on PATH" >&2
    exit 1
fi

# Locate the directory containing the Kotlin stdlib + test libraries.
KOTLIN_BIN=$(command -v kotlinc)
KOTLIN_HOME=$(cd "$(dirname "$KOTLIN_BIN")/.." && pwd)
KOTLIN_LIB="$KOTLIN_HOME/libexec/lib"
if [[ ! -d "$KOTLIN_LIB" ]]; then
    KOTLIN_LIB="$KOTLIN_HOME/lib"
fi

MAIN_JAR="crowdcontrol.jar"
TEST_CLASSES="build/test-classes"
mkdir -p "$TEST_CLASSES"

# 1. Build main jar if missing or stale.
if [[ ! -f "$MAIN_JAR" || "src/main/kotlin" -nt "$MAIN_JAR" ]]; then
    ./build.sh
fi

# 2. Compile test sources against the main jar + kotlin-test + kotlin-test-junit.
#
# kotlin-test.jar provides the multiplatform kotlin.test.* annotations, but on
# JVM the actual `kotlin.test.Test` type-alias lives in kotlin-test-junit.jar
# (which maps it to org.junit.Test at runtime). Both must be on the compile
# classpath or the tests won't see @Test at all.
KOTLIN_TEST_JAR="$KOTLIN_LIB/kotlin-test.jar"
if [[ ! -f "$KOTLIN_TEST_JAR" ]]; then
    KOTLIN_TEST_JAR=$(find "$KOTLIN_LIB" -name 'kotlin-test.jar' -o -name 'kotlin-test-*.jar' ! -name 'kotlin-test-junit*' ! -name 'kotlin-test-testng*' ! -name 'kotlin-test-js*' | head -n1)
fi

KOTLIN_TEST_JUNIT_JAR="$KOTLIN_LIB/kotlin-test-junit.jar"
if [[ ! -f "$KOTLIN_TEST_JUNIT_JAR" ]]; then
    KOTLIN_TEST_JUNIT_JAR=$(find "$KOTLIN_LIB" -name 'kotlin-test-junit.jar' -o -name 'kotlin-test-junit-*.jar' ! -name '*sources*' | head -n1)
fi

JUNIT4_JAR_PRECHECK=$(find "$KOTLIN_LIB" -name 'junit-4*.jar' -o -name 'junit.jar' | head -n1 || true)
HAMCREST_JAR_PRECHECK=$(find "$KOTLIN_LIB" -name 'hamcrest*.jar' | head -n1 || true)

COMPILE_CP="$MAIN_JAR:$KOTLIN_TEST_JAR:$KOTLIN_TEST_JUNIT_JAR:$JUNIT4_JAR_PRECHECK:$HAMCREST_JAR_PRECHECK"

echo "compiling tests ..."
kotlinc \
    -cp "$COMPILE_CP" \
    -d "$TEST_CLASSES" \
    src/test/kotlin

# 3. Run each test class via kotlin.test's JUnit runner if available.
#    The kotlin-test-junit.jar bundles a JUnit 4 runner we can invoke directly.
JUNIT_JAR="$KOTLIN_LIB/kotlin-test-junit.jar"
if [[ ! -f "$JUNIT_JAR" ]]; then
    JUNIT_JAR=$(find "$KOTLIN_LIB" -name 'kotlin-test-junit*.jar' | head -n1)
fi

# Kotlin's kotlin-test-junit depends on junit-4; Kotlin dist bundles it too.
JUNIT4_JAR=$(find "$KOTLIN_LIB" -name 'junit*.jar' ! -name 'kotlin-test-junit*' | head -n1 || true)
HAMCREST_JAR=$(find "$KOTLIN_LIB" -name 'hamcrest*.jar' | head -n1 || true)

if [[ -z "$JUNIT4_JAR" ]]; then
    echo "warning: bundled junit.jar not found in $KOTLIN_LIB" >&2
    echo "         you may need to drop junit-4.x.jar + hamcrest-core.jar into $KOTLIN_LIB" >&2
fi

CP="$MAIN_JAR:$TEST_CLASSES:$KOTLIN_TEST_JAR:$JUNIT_JAR:$JUNIT4_JAR:$HAMCREST_JAR"

# Discover test classes.
TEST_CLASS_NAMES=$(cd "$TEST_CLASSES" && find . -name '*Test.class' | sed 's|^\./||;s|\.class$||;s|/|.|g')

echo
echo "running tests ..."
java -cp "$CP" org.junit.runner.JUnitCore $TEST_CLASS_NAMES
