import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const modulePath = fileURLToPath(import.meta.url);
const scriptDir = dirname(modulePath);
const SAFE_ENVIRONMENT_KEYS = new Set([
  "COMSPEC",
  "LANG",
  "LC_ALL",
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "TMPDIR",
  "WINDIR",
]);

export function createDryRunEnvironment(baseEnvironment, cacheDir, userConfig) {
  const environment = {};

  for (const [key, value] of Object.entries(baseEnvironment)) {
    if (value !== undefined && (SAFE_ENVIRONMENT_KEYS.has(key) || key.startsWith("LC_"))) {
      environment[key] = value;
    }
  }

  return {
    ...environment,
    npm_config_cache: cacheDir,
    npm_config_ignore_scripts: "true",
    npm_config_offline: "true",
    npm_config_provenance: "false",
    npm_config_userconfig: userConfig,
  };
}

export function normalizeDryRunResult(payload) {
  if (payload && Array.isArray(payload.files)) {
    return payload;
  }

  const candidates = Array.isArray(payload)
    ? payload
    : payload && typeof payload === "object"
      ? Object.values(payload)
      : [];
  const packageResults = candidates.filter((candidate) => Array.isArray(candidate?.files));

  if (packageResults.length !== 1) {
    throw new Error("npm publish dry-run JSON must describe exactly one package");
  }
  return packageResults[0];
}

export function verifyPublishDryRun(packageDir) {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "vettalon-npm-dry-run-"));
  const stagedPackageDir = join(temporaryRoot, "package");
  const cacheDir = join(temporaryRoot, "cache");
  const userConfig = join(temporaryRoot, "empty-npmrc");

  try {
    cpSync(packageDir, stagedPackageDir, { recursive: true });
    writeFileSync(userConfig, "");

    const stagedManifestPath = join(stagedPackageDir, "package.json");
    const stagedManifest = JSON.parse(readFileSync(stagedManifestPath, "utf8"));
    stagedManifest.version = "0.0.0-dry-run";
    writeFileSync(stagedManifestPath, `${JSON.stringify(stagedManifest, null, 2)}\n`);

    const child = spawnSync(
      "npm",
      [
        "publish",
        "--dry-run",
        "--offline",
        "--json",
        "--ignore-scripts",
        "--provenance=false",
        "--access",
        "public",
        "--tag",
        "dry-run",
      ],
      {
        cwd: stagedPackageDir,
        encoding: "utf8",
        env: createDryRunEnvironment(process.env, cacheDir, userConfig),
      },
    );

    if (child.error) {
      throw child.error;
    }
    if (child.status !== 0) {
      throw new Error(`npm publish dry-run failed (${child.status}): ${child.stderr.trim()}`);
    }

    const result = normalizeDryRunResult(JSON.parse(child.stdout));
    const files = new Map(result.files.map(({ path, size }) => [path, size]));
    const requiredFiles = ["README.md", "package.json", "bin/vettalon", "scripts/install.js"];

    for (const path of requiredFiles) {
      if (!files.has(path)) {
        throw new Error(`npm tarball must include ${path}`);
      }
    }
    if (files.get("README.md") <= 100) {
      throw new Error("packaged README.md must contain useful content");
    }

    return { name: result.name, version: result.version, files };
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === modulePath) {
  const result = verifyPublishDryRun(join(scriptDir, "..", "vettalon"));
  console.log(
    `verified npm publish dry-run: ${result.name}@${result.version}, ${result.files.size} files`,
  );
}
