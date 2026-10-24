import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  createDryRunEnvironment,
  normalizeDryRunResult,
  verifyPublishDryRun,
} from "../publish-dry-run.mjs";

const testDir = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = join(testDir, "..", "..", "..");
const packageDir = join(repositoryRoot, "npm", "vettalon");

test("dry-run environment removes npm and GitHub OIDC credentials", () => {
  const environment = createDryRunEnvironment(
    {
      PATH: process.env.PATH,
      ACTIONS_ID_TOKEN_REQUEST_URL: "http://127.0.0.1:9/should-not-be-called",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "oidc-token",
      NPM_ID_TOKEN: "npm-id-token",
      NODE_AUTH_TOKEN: "node-auth-token",
      NPM_TOKEN: "npm-token",
      NPM_CONFIG_PROVENANCE: "true",
    },
    "/tmp/cache",
    "/tmp/empty-npmrc",
  );

  assert.equal(environment.PATH, process.env.PATH);
  assert.equal(environment.ACTIONS_ID_TOKEN_REQUEST_URL, undefined);
  assert.equal(environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN, undefined);
  assert.equal(environment.NPM_ID_TOKEN, undefined);
  assert.equal(environment.NODE_AUTH_TOKEN, undefined);
  assert.equal(environment.NPM_TOKEN, undefined);
  assert.equal(environment.NPM_CONFIG_PROVENANCE, undefined);
  assert.equal(environment.npm_config_cache, "/tmp/cache");
  assert.equal(environment.npm_config_userconfig, "/tmp/empty-npmrc");
  assert.equal(environment.npm_config_provenance, "false");
});

test("normalizes npm 11.12 and 11.15 publish JSON shapes", () => {
  const result = { name: "vettalon", version: "0.0.0-dry-run", files: [] };

  assert.equal(normalizeDryRunResult(result), result);
  assert.equal(normalizeDryRunResult({ vettalon: result }), result);
  assert.equal(normalizeDryRunResult([result]), result);
  assert.throws(() => normalizeDryRunResult({}), /publish dry-run JSON/);
});

test("npm publish dry-run contains the README and runtime entrypoints", () => {
  const result = verifyPublishDryRun(packageDir);

  assert.equal(result.name, "vettalon");
  assert.equal(result.version, "0.0.0-dry-run");
  assert.ok(result.files.get("README.md") > 100);
  assert.ok(result.files.has("package.json"));
  assert.ok(result.files.has("bin/vettalon"));
  assert.ok(result.files.has("scripts/install.js"));
});
