# CrowdControl Python SDK — conformance runner image
#
# Build from the *repo root* so the conformance suite is in context:
#
#   docker build -f sdks/python/Dockerfile -t crowdcontrol-python .
#   docker run --rm crowdcontrol-python
#
# Exits 0 on full pass, 1 on any failure.

FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/mikemackintosh/crowdcontrol"
LABEL org.opencontainers.image.description="CrowdControl Python SDK conformance runner"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /crowdcontrol/sdks/python

# Conformance suite lives at ../../conformance/suite relative to the runner.
COPY conformance /crowdcontrol/conformance
COPY sdks/python /crowdcontrol/sdks/python

# No runtime deps — stdlib only.
CMD ["python", "conformance_runner.py"]
