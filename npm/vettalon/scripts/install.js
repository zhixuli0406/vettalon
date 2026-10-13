"use strict";
// The real binary ships in the platform-specific optionalDependency. If npm
// skipped it (e.g. --no-optional or an unsupported platform), say so clearly.
const PLATFORM_PACKAGES = {
  "darwin-arm64": "@vettalon/darwin-arm64",
  "darwin-x64": "@vettalon/darwin-x64",
  "linux-x64": "@vettalon/linux-x64",
  "linux-arm64": "@vettalon/linux-arm64",
};
const key = `${process.platform}-${process.arch}`;
const pkg = PLATFORM_PACKAGES[key];
if (!pkg) {
  console.warn(`\n[vettalon] Unsupported platform ${key}. Build from source: https://github.com/zhixuli0406/vettalon\n`);
  process.exit(0);
}
try { require.resolve(`${pkg}/package.json`); }
catch { console.warn(`\n[vettalon] Platform package ${pkg} not installed (e.g. --no-optional). Try: npm install -g vettalon\n`); }
