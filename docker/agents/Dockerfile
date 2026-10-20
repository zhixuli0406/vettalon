# Agent CLIs that cannot fully disable their own tools (codex, grok) run
# in this image, so their tools see only an empty workspace and a copy of
# one auth file. Versions are pinned; bump them deliberately.
FROM node:26-bookworm-slim@sha256:298992629d69bbd5b2b03ad57094d8e4fcb3a8eeb7c4e25d29de656519568913

ARG CODEX_VERSION=0.162.1
ARG GROK_VERSION=1.0.50
ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g "@openai/codex@${CODEX_VERSION}" && npm cache clean --force

RUN case "${TARGETARCH:-$(uname -m)}" in \
      arm64|aarch64) arch=aarch64 ;; \
      amd64|x86_64) arch=x86_64 ;; \
      *) echo "unsupported arch" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /usr/local/bin/grok "https://x.ai/cli/grok-${GROK_VERSION}-linux-${arch}" \
 && chmod 0755 /usr/local/bin/grok \
 && /usr/local/bin/grok --version

# curl is only needed at build time.
RUN apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 agent
USER agent
WORKDIR /work
