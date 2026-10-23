# Credential-free local layer of the agents image: the grok CLI on top of the
# published, grok-free base. Reusable auth files are rejected until a
# non-exportable credential broker exists. grok is proprietary, so it is
# downloaded from x.ai by the machine that builds this layer and never
# published. `vettalon agents build|pull` always passes BASE_IMAGE (the
# verified base, by digest when pulled); the default only keeps BuildKit's
# InvalidDefaultArgInFrom check quiet.
ARG BASE_IMAGE=vettalon-agents-base
FROM ${BASE_IMAGE}

ARG GROK_VERSION=1.0.50
ARG GROK_AARCH64_SHA256=947eea63e52393e00778d651d22e0dad22d30e9ee5b2af7944efc3fd4438ecc0
ARG GROK_X86_64_SHA256=c80de0155706ff2d995623887b102f2d0abd2c62b2643dea3a0cebaf7dd724d5
ARG TARGETARCH

USER root
# node's fetch instead of curl, so the base needs no download tool.
RUN case "${TARGETARCH:-$(uname -m)}" in \
      arm64|aarch64) arch=aarch64; expected_sha256="${GROK_AARCH64_SHA256}" ;; \
      amd64|x86_64) arch=x86_64; expected_sha256="${GROK_X86_64_SHA256}" ;; \
      *) echo "unsupported arch" >&2; exit 1 ;; \
    esac \
 && node -e ' \
      const fs = require("fs"); \
      const crypto = require("crypto"); \
      const { Readable } = require("stream"); \
      const { pipeline } = require("stream/promises"); \
      const [url, dest, expected] = process.argv.slice(1); \
      (async () => { \
        const r = await fetch(url); \
        if (!r.ok) throw new Error(`GET ${url}: HTTP ${r.status}`); \
        await pipeline(Readable.fromWeb(r.body), fs.createWriteStream(dest, { mode: 0o755 })); \
        const actual = crypto.createHash("sha256").update(fs.readFileSync(dest)).digest("hex"); \
        if (actual !== expected) throw new Error(`sha256 mismatch: ${actual}`); \
      })().catch((e) => { console.error(e.message); process.exit(1); });' \
      "https://x.ai/cli/grok-${GROK_VERSION}-linux-${arch}" /usr/local/bin/grok "${expected_sha256}" \
 && /usr/local/bin/grok --version

USER agent
WORKDIR /work
