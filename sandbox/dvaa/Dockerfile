# Build stage: clone pinned DVAA commit and apply provider-baseurl patch
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
WORKDIR /app
RUN apk add --no-cache git
RUN git clone --quiet https://github.com/opena2a-org/damn-vulnerable-ai-agent.git . && \
    git checkout --quiet 57918267d8d529ceec6d40fc9836ab09d128eee4
COPY provider-baseurl.patch ./
RUN git apply provider-baseurl.patch
RUN npm install --omit=dev --no-audit --no-fund

# Runtime stage: reuse approach from .research/dvaa/Dockerfile
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/src ./src
COPY --from=build /app/public ./public
COPY --from=build /app/scenarios ./scenarios
RUN mkdir -p /app/.hackmyagent-cache && \
    HMA_VER=$(node_modules/.bin/hackmyagent --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) && \
    node_modules/.bin/hackmyagent check-metadata \
      > "/app/.hackmyagent-cache/check-metadata-v${HMA_VER}.json" || true
RUN chown -R node:node /app
USER node
ENV DVAA_HOST=0.0.0.0
ENV OPENAI_BASE_URL=http://host.docker.internal:11434/v1
# LLM mode is configured at runtime via POST /api/llm/configure (dashboard port)
EXPOSE 7001 7002 7003 7004 7005 7006 7007 7008 7010 7011 7012 7013 7014 7015 7016 7017 7018 7020 7021 7022 7023 9000
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s \
  CMD wget -qO- http://127.0.0.1:9000/stats || exit 1
CMD ["node", "src/index.js"]
