# Release image for cc (the CrowdControl CLI) + cc-lsp.
#
# This file is consumed by goreleaser's dockers block, not by
# `docker build` directly. Goreleaser cross-compiles the binaries
# first and then invokes `docker build` with the binary + extra_files
# already staged in the build context.
#
# Distroless static is ~2 MiB, has no shell / package manager, and
# works with pure-Go static binaries (which cc is, because
# CGO_ENABLED=0 in .goreleaser.yml).

FROM gcr.io/distroless/static-debian12:nonroot

COPY cc /usr/local/bin/cc
COPY cc-lsp /usr/local/bin/cc-lsp
COPY LICENSE /LICENSE
COPY README.md /README.md

# Distroless nonroot user: UID 65532.
USER 65532:65532
WORKDIR /workdir

# Default to the policy CLI. Override with another command name
# (e.g. "cc-lsp") if you need the LSP server instead.
ENTRYPOINT ["/usr/local/bin/cc"]
CMD ["version"]
