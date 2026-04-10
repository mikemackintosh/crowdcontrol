# CrowdControl Ruby SDK — conformance runner image
#
# Build from the *repo root*:
#
#   docker build -f sdks/ruby/Dockerfile -t crowdcontrol-ruby .
#   docker run --rm crowdcontrol-ruby

FROM ruby:3.2-alpine

LABEL org.opencontainers.image.source="https://github.com/mikemackintosh/crowdcontrol"
LABEL org.opencontainers.image.description="CrowdControl Ruby SDK conformance runner"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /crowdcontrol/sdks/ruby

COPY conformance /crowdcontrol/conformance
COPY sdks/ruby /crowdcontrol/sdks/ruby

# No runtime deps — stdlib only.
CMD ["ruby", "conformance_runner.rb"]
