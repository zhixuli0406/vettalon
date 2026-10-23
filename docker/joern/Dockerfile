# Joern (Apache-2.0, https://github.com/joernio/joern) for the experimental
# `verify --joern-keep` evidence and `vettalon joern check`. Built only on
# this machine by `vettalon joern build`; never published, never pulled.
#
# Supply chain (network boundaries: docs/DATA-FLOW.md):
# - the base image is pinned by digest;
# - the Joern release is pinned to one version and checked against the
#   SHA-256 GitHub reports for the asset AND the release's own .sha512, both
#   written here; a mismatch fails the build. The official install script
#   (downloads `latest`, checks nothing) is never used;
# - php-cli comes from the Ubuntu archive (apt verifies its signatures; the
#   version is whatever the pinned base's archive serves and is recorded in
#   /usr/share/doc/vettalon-joern/INVENTORY.txt).
# Network is used only while building. Analysis runs with --network=none.
# To bump Joern: change the version and all four hashes together.
FROM eclipse-temurin:21-jdk-noble@sha256:107215954359f1ab0be058a247d7c64ed6e69c71c1682d471d38ef751ec8e964

ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip php-cli \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      arm64) asset=joern-cli-linux-arm64.zip; \
             sha256=52cf3ef6a1df920292c95111f9b20f07ad318e37c5842b5beb51ac9fe7a231d1; \
             sha512=4aea29df3203d1a84857a66067e2ec34026f436aece40a37d3bc7073e75f55d462b916d6ee5d364eeea5658d6fc7bd7394a4bb545e8f23d0fed4e87703ee8303 ;; \
      amd64) asset=joern-cli-linux-x86_64.zip; \
             sha256=f354ac82f3ab7196f42032b2267e4a6ffb1852f5195bc7cbe6b5628c842f486e; \
             sha512=95efb99ee825930d327b079b473a78f958c670065e10c238c5db1533353e9d81a4feefcd06840f00350e23ff2056b04ba5de2dc0f804a301b41da5eea0f44333 ;; \
      *) echo "unsupported architecture" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o /tmp/joern.zip \
      "https://github.com/joernio/joern/releases/download/v4.0.663/${asset}"; \
    echo "${sha256}  /tmp/joern.zip" | sha256sum -c -; \
    echo "${sha512}  /tmp/joern.zip" | sha512sum -c -; \
    unzip -q /tmp/joern.zip -d /opt; \
    rm /tmp/joern.zip; \
    test -x /opt/joern-cli/joern; \
    mkdir -p /usr/share/doc/vettalon-joern; \
    { echo "joern v4.0.663 ${asset} sha256=${sha256}"; \
      echo "license: Apache-2.0 (https://github.com/joernio/joern/blob/v4.0.663/LICENSE)"; \
      dpkg-query -W -f '${Package} ${Version}\n' php-cli 'php*-cli' openjdk-21-jdk-headless 2>/dev/null || true; \
      java -version 2>&1 | head -1; \
    } > /usr/share/doc/vettalon-joern/INVENTORY.txt

# The analysis user; the container runs read-only with HOME on a tmpfs.
RUN useradd --no-create-home --uid 10002 joern
USER joern
WORKDIR /work
