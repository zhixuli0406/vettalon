# Local-only PoC image for JavaScript/TypeScript execution proof.
# Keep the base digest aligned with docker/agents-base/Dockerfile.
FROM node:26-bookworm-slim@sha256:28147155d47dc31abe0a46e0d12b59b2fb3d0a2dcc5dc65fce76a074180b16fe

# The trusted PID-1 runner needs Python's ctypes and sqlite3 stdlib modules.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /root/.npm /home/node/.npm

# Fail the build if the pinned runtime lacks any required execution feature.
RUN node --version \
 && python3 -c 'import ctypes, sqlite3' \
 && probe_dir="$(mktemp -d)" \
 && printf 'export const value: number = 42;\n' > "$probe_dir/probe.mts" \
 && printf 'export const value = 43;\n' > "$probe_dir/probe.mjs" \
 && node --no-addons --max-old-space-size=320 --disable-warning=ExperimentalWarning -e ' \
      const assert = require("node:assert/strict"); \
      assert.equal(process.versions.node.split(".")[0], "26"); \
      assert.equal(typeof require("node:module").registerHooks, "function"); \
      assert.equal(require(process.argv[1] + "/probe.mts").value, 42); \
      assert.equal(require(process.argv[1] + "/probe.mjs").value, 43); \
      const { DatabaseSync } = require("node:sqlite"); \
      const db = new DatabaseSync(":memory:"); \
      assert.equal(db.prepare("SELECT 1 AS value").get().value, 1); \
      db.close();' "$probe_dir" \
 && rm -r "$probe_dir"

# Match the existing PoC sandbox's nobody uid/gid; no global npm installs.
USER 65534:65534
WORKDIR /workspace
