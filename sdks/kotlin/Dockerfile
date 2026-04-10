# CrowdControl Kotlin SDK — conformance runner image
#
# Build from the *repo root*:
#
#   docker build -f sdks/kotlin/Dockerfile -t crowdcontrol-kotlin .
#   docker run --rm crowdcontrol-kotlin
#
# Uses the eclipse-temurin JDK 11 image because the SDK's
# build.gradle.kts pins `jvmToolchain(11)`. A JDK 17 image also works
# but requires disabling gradle's toolchain auto-download.

FROM gradle:8.7-jdk11

LABEL org.opencontainers.image.source="https://github.com/mikemackintosh/crowdcontrol"
LABEL org.opencontainers.image.description="CrowdControl Kotlin SDK conformance runner"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /crowdcontrol/sdks/kotlin

# Copy gradle config first for better build cache behavior.
COPY sdks/kotlin/build.gradle.kts sdks/kotlin/settings.gradle.kts sdks/kotlin/gradle.properties ./

# Warm the dependency cache (ignore errors — this just primes the layer).
RUN gradle --no-daemon --quiet dependencies >/dev/null 2>&1 || true

# Copy sources and the conformance suite.
COPY conformance /crowdcontrol/conformance
COPY sdks/kotlin/src ./src
COPY sdks/kotlin/examples ./examples

# Pre-compile so runtime is fast. We explicitly run compileKotlin here
# because the `classes` task alone only triggers compileJava (which has
# no sources in this Kotlin-only project).
RUN gradle --no-daemon compileKotlin

# Run both tasks in a single invocation so gradle resolves the
# conformance task's classpath against the freshly-compiled classes.
CMD ["sh", "-c", "gradle --no-daemon --quiet compileKotlin conformance"]
