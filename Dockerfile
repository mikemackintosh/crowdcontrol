# CrowdControl Go reference — conformance runner image
#
# The Go implementation is the reference for the language. This image
# runs the full test suite (unit tests + conformance suite) against it.
#
#   docker build -t crowdcontrol-go .
#   docker run --rm crowdcontrol-go
#
# For individual SDK conformance images, see sdks/<lang>/Dockerfile.

FROM golang:1.23-alpine AS build

LABEL org.opencontainers.image.source="https://github.com/mikemackintosh/crowdcontrol"
LABEL org.opencontainers.image.description="CrowdControl Go reference implementation"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /crowdcontrol

# Go module metadata first for better caching.
COPY go.mod ./
# (no go.sum — zero external dependencies)

# Sources.
COPY crowdcontrol.go crowdcontrol_test.go ./
COPY types ./types
COPY parser ./parser
COPY evaluator ./evaluator
COPY cmd ./cmd
COPY conformance ./conformance
COPY examples ./examples

# Build the CLI so it's available in the runtime image.
RUN CGO_ENABLED=0 go build -o /out/cc ./cmd/cc
RUN CGO_ENABLED=0 go build -o /out/cc-lsp ./cmd/cc-lsp

# Runtime stage — minimal image with just the binaries and tests.
FROM golang:1.23-alpine AS runtime
WORKDIR /crowdcontrol
COPY --from=build /crowdcontrol /crowdcontrol
COPY --from=build /out/cc /usr/local/bin/cc
COPY --from=build /out/cc-lsp /usr/local/bin/cc-lsp

# Default: run unit tests and the Go conformance runner.
CMD ["sh", "-c", "go test ./... && go run ./conformance/runners/go -suite ./conformance/suite"]
