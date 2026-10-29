# Published base of the agents image: Node and the codex CLI, no grok.
# grok is proprietary (xAI's terms grant no redistribution), so it is never
# part of a published image; `vettalon agents build|pull` adds it locally
# (docker/agents/Dockerfile). Versions are pinned; bump them deliberately and
# refresh licenses/ with them (the build checks the versions match).
FROM node:26-bookworm-slim@sha256:28147155d47dc31abe0a46e0d12b59b2fb3d0a2dcc5dc65fce76a074180b16fe

ARG CODEX_VERSION=0.162.1
ARG CODEX_TARBALL_SHA512=NWZdi/kxyjv/8EUGFupziGU38YyleugZRM4JXgY5XFH7FUmaFA33NZS2Bmq0HPazf7S3jJQQWsZ/jAK9jsrV3Q==

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN node -e ' \
      const fs = require("fs"); \
      const crypto = require("crypto"); \
      const { Readable } = require("stream"); \
      const { pipeline } = require("stream/promises"); \
      const [url, dest, expected] = process.argv.slice(1); \
      (async () => { \
        const r = await fetch(url); \
        if (!r.ok) throw new Error(`GET ${url}: HTTP ${r.status}`); \
        await pipeline(Readable.fromWeb(r.body), fs.createWriteStream(dest, { mode: 0o600 })); \
        const actual = crypto.createHash("sha512").update(fs.readFileSync(dest)).digest("base64"); \
        if (actual !== expected) throw new Error(`sha512 mismatch: ${actual}`); \
      })().catch((e) => { console.error(e.message); process.exit(1); });' \
      "https://registry.npmjs.org/@openai/codex/-/codex-${CODEX_VERSION}.tgz" \
      /tmp/codex.tgz "${CODEX_TARBALL_SHA512}" \
 && npm install -g /tmp/codex.tgz \
 && rm /tmp/codex.tgz \
 && npm cache clean --force

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
