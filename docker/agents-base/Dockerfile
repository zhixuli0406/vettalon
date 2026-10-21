# Published base of the agents image: Node and the codex CLI, no grok.
# grok is proprietary (xAI's terms grant no redistribution), so it is never
# part of a published image; `vettalon agents build|pull` adds it locally
# (docker/agents/Dockerfile). Versions are pinned; bump them deliberately and
# refresh licenses/ with them (the build checks the versions match).
FROM node:26-bookworm-slim@sha256:298992629d69bbd5b2b03ad57094d8e4fcb3a8eeb7c4e25d29de656519568913

ARG CODEX_VERSION=0.162.1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g "@openai/codex@${CODEX_VERSION}" && npm cache clean --force

# License texts the upstream packages do not ship themselves, and the
# inventory of every component with its license.
COPY licenses/ /usr/share/licenses/
COPY inventory.js /tmp/inventory.js
RUN test "$(node --version)" = "$(cat /usr/share/licenses/node/VERSION)" \
 && test "rust-v${CODEX_VERSION}" = "$(cat /usr/share/licenses/codex/VERSION)" \
 && node /tmp/inventory.js > /usr/share/licenses/INVENTORY.txt \
 && rm /tmp/inventory.js

RUN useradd --create-home --uid 10001 agent
USER agent
WORKDIR /work
