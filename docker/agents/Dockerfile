# Local layer of the agents image: the grok CLI on top of the published,
# grok-free base. grok is proprietary, so it is downloaded from x.ai by the
# machine that builds this layer and never published. `vettalon agents
# build|pull` always passes BASE_IMAGE (the verified base, by digest when
# pulled); the default only keeps BuildKit's InvalidDefaultArgInFrom check quiet.
ARG BASE_IMAGE=vettalon-agents-base
FROM ${BASE_IMAGE}

ARG GROK_VERSION=1.0.50
ARG TARGETARCH

USER root
# node's fetch instead of curl, so the base needs no download tool.
RUN case "${TARGETARCH:-$(uname -m)}" in \
      arm64|aarch64) arch=aarch64 ;; \
      amd64|x86_64) arch=x86_64 ;; \
      *) echo "unsupported arch" >&2; exit 1 ;; \
    esac \
 && node -e ' \
      const fs = require("fs"); \
      const { Readable } = require("stream"); \
      const { pipeline } = require("stream/promises"); \
      const [url, dest] = process.argv.slice(1); \
      (async () => { \
        const r = await fetch(url); \
        if (!r.ok) throw new Error(`GET ${url}: HTTP ${r.status}`); \
        await pipeline(Readable.fromWeb(r.body), fs.createWriteStream(dest, { mode: 0o755 })); \
      })().catch((e) => { console.error(e.message); process.exit(1); });' \
      "https://x.ai/cli/grok-${GROK_VERSION}-linux-${arch}" /usr/local/bin/grok \
 && /usr/local/bin/grok --version

USER agent
WORKDIR /work
