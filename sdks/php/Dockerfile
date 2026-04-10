# CrowdControl PHP SDK — conformance runner image
#
# Build from the *repo root*:
#
#   docker build -f sdks/php/Dockerfile -t crowdcontrol-php .
#   docker run --rm crowdcontrol-php

FROM php:8.2-cli-alpine

LABEL org.opencontainers.image.source="https://github.com/mikemackintosh/crowdcontrol"
LABEL org.opencontainers.image.description="CrowdControl PHP SDK conformance runner"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /crowdcontrol/sdks/php

COPY conformance /crowdcontrol/conformance
COPY sdks/php /crowdcontrol/sdks/php

# No runtime deps — stdlib only. We don't even need composer autoload
# since the SDK ships its own src/autoload.php.
CMD ["php", "conformance_runner.php"]
