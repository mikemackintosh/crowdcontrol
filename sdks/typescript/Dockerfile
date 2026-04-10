# CrowdControl TypeScript SDK — conformance runner image
#
# Build from the *repo root*:
#
#   docker build -f sdks/typescript/Dockerfile -t crowdcontrol-typescript .
#   docker run --rm crowdcontrol-typescript

FROM node:20-alpine AS build

LABEL org.opencontainers.image.source="https://github.com/mikemackintosh/crowdcontrol"
LABEL org.opencontainers.image.description="CrowdControl TypeScript SDK conformance runner"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /crowdcontrol/sdks/typescript

# Install build deps (TypeScript is the only dev dep; no runtime deps).
COPY sdks/typescript/package.json sdks/typescript/package-lock.json ./
RUN npm ci

# Copy sources and compile.
COPY sdks/typescript/tsconfig.json ./
COPY sdks/typescript/src ./src
COPY sdks/typescript/tests ./tests
COPY sdks/typescript/examples ./examples
COPY sdks/typescript/conformance-runner.ts ./
RUN npx tsc

# Runtime stage — smaller image, no build toolchain.
FROM node:20-alpine AS runtime
WORKDIR /crowdcontrol/sdks/typescript
COPY --from=build /crowdcontrol/sdks/typescript/dist ./dist
COPY conformance /crowdcontrol/conformance

CMD ["node", "dist/conformance-runner.js"]
