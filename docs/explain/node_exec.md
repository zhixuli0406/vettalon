# node_exec: Execution proof for JavaScript and TypeScript targets in a Node sandbox

## What it means

`vettalon reproduce`, `vettalon fix check --target` and `vettalon retest` run a TargetCall whose file ends in `.js`, `.cjs`, `.mjs`, `.ts`, `.cts` or `.mts` in a local Node sandbox. The runtime comes from the file extension only. Python targets (`.py`) are unchanged.

The protocol is the one Python targets use: an attack phase, a benign control and a fresh-nonce rerun, each in a fresh container with external networking disabled. The outcome set (`effect_observed`, `effect_absent`, `inconclusive`), `--replays`, the fix-check verdicts (`original`, `variants`, `benign`, `tests`), blockers and policy `vettalon-fix-check-v4` are the same. The effect is decided by the harness runner, a Python process that is PID 1 of the container, from per-run secret evidence. Text the target prints does not count.

On top of that, a preload hook inside the Node process records which sink the code called and with what argument ("reach"). Reach can only make a result weaker, never stronger (see "What this does not show").

Node receipts are `TargetPocReceipt` version 3. They add `runtime` (`language`, `module_kind`, `export_kind`, `node_version`, `lockfile_sha256`, `lockfile_summary_sha256`, `deps_sha256`, `fixture_sha256`, `driver`, `hook_bundle_sha256`), a `harness_sha256`, and per phase `reached`, `reach_source: "in_process_hook"`, `reach_sha256`, a masked `reach` summary and `executable`. `image_id` holds the immutable ID of the Node image. Python receipts stay version 2 and are byte-for-byte what they were. Every stored receipt is re-derived from its phases before it is signed or attached to a disclosure.

## Prerequisites

Docker, and the Node PoC image built on your machine. The image is never pulled automatically and is not published to a registry in 0.8:

```sh
vettalon poc-node build
vettalon poc-node image   # prints the expected tag, vettalon-poc-node:<12 hex digits>
```

`poc-node build` builds the Dockerfile embedded in the binary: a digest-pinned `node:26-bookworm-slim` base plus `python3` from Debian apt (the apt packages are not version-pinned). Building needs network access once. The build fails if Node 26, `module.registerHooks`, type stripping or `node:sqlite` is missing.

`reproduce`, `fix check` and `retest` take `--node-image <TAG>` (default: the tag above). `--poc-image` still selects the Python image only. A missing Node image gives `node_runtime_unavailable` with a hint to run `vettalon poc-node build`.

## Supported targets

- Module format: ESM and CommonJS, decided by Node from the extension and the nearest `package.json` `type`. The adapter loads the file with `import()`.
- `function`: an exported binding name (ASCII identifier, not a reserved word, not `__proto__`, `constructor` or `prototype`), or `default` for the default export. A CommonJS `module.exports` object is searched when the namespace has no such export. Top-level functions only; class methods and HTTP handlers are not supported.
- `args`: exactly one `{"kind":"payload"}`, bounded JSON literals, and for Node at most one `{"kind":"callback"}`. The adapter passes a function for the callback and takes its `(err, value)` as the result. A returned promise is awaited.
- TypeScript: Node's built-in type stripping only. No `tsc`, esbuild or project build step runs. `enum`, `namespace`, parameter properties, legacy decorators, JSX/TSX and `tsconfig` path aliases are not supported (`node_ts_unsupported_syntax`). A relative `./x.js` import maps to `./x.ts` only when `x.js` does not exist and `x.ts` does.
- Scan-time `--poc` and the scan-time fix check stay Python-only.

Example, a CommonJS target with a callback:

```json
{"file":"app.cjs","function":"run","args":[{"kind":"payload"},{"kind":"callback"}]}
```

## Classes and sinks

| Class | Sinks the hook records | Effect evidence |
|---|---|---|
| Command injection (CWE-78/77) | `child_process.exec`, `execSync`, `execFile`, `execFileSync`, `spawn`, `spawnSync`, `fork` | the secret written to `/tmp/vtl_out`, read by the runner |
| Path traversal (CWE-22/73) | `fs.readFile`, `readFileSync`, `createReadStream`, `open`, `openSync`, `fs.promises.readFile`, `fs.promises.open` | the secret file's content in the returned result |
| SSRF (CWE-918), Node target mode only | `fetch`, `http.request`, `http.get`, `https.request`, `https.get` | an HTTP request line or TLS ClientHello at the protected runner's loopback listener |
| SQL injection (CWE-89) | `sqlite3` (Vettalon's shim backed by `node:sqlite` on the fixture database); `pg` and `mysql2` query text, reach only | the secret row in the returned result |

`sqlite3` imports resolve to the shim, so no native driver is built. The shim supports a listed subset of the `Database` and `Statement` API; calling a listed but unimplemented method gives `node_driver_api_unsupported`. `pg` and `mysql2` queries are recorded and then rejected: there is no database server in the sandbox, and running their SQL on SQLite would give false positives. A `pg` or `mysql2` target is therefore always `inconclusive` with `sql_dialect_not_executable`, decided on the host from the driver, never from a hook event.

Fix check uses the Node variant set `variants-node/1`. Command and SQL inputs equal `variants/1`; the path set drops the absolute-path input, because `path.join('/tmp/vtl_base', '/tmp/vtl_secret')` stays under the base.

## SSRF loopback oracle

For CWE-918 Node targets, the protected runner listens on ports 80 and 443 inside
the same `--network=none` container. A request line or TLS ClientHello is the
effect; a connection alone, a hook event, or text printed by the target is not.
Attack phases report this listener effect as `surfaced=true`. No external server
is contacted. The VIR uses `loopback_http_request`, effect kind `network_egress`
and capability `loopback_network`.

The benign input is `https://example.com/vtl_benign`. It cannot complete in the
offline sandbox. Instead, the adapter reads a bounded error/cause chain for a
recognized network code (for example `EAI_AGAIN` or `ENOTFOUND`), and the runner
uses that as the functional control. Preserve the original error's `code` or
`cause` when rejecting DNS failures. This is a target-reported diagnostic, not
independent proof that public networking works. A fixed copy that raises a policy
error or returns normally without a network error gets benign `inconclusive`,
reason `ssrf_benign_unconfirmed`, and cannot be `fix_verified`. A block-everything
patch is therefore unverified.

The SSRF `variants-node/1` set has 16 loopback-encoding inputs, 14 scored. The
IPv4-mapped input scores; pure IPv6 loopback and userinfo are non-scoring probes.
IPv6 listener sockets are optional: containers with IPv6 disabled can still run
the IPv4 oracle. A fix passes only for these tested inputs and variants.

Python SSRF targets and scan-time SSRF oracles remain unsupported. SSRF
`--emit-test` is refused with `ssrf_emit_test_unsupported`, with no file written.
Cloud metadata addresses (including `169.254.169.254`), real internal services,
redirect chains and DNS rebinding are outside this loopback proof's scope.

## Dependencies

Only npm is supported, and only from the repository root:

- `npm-shrinkwrap.json` (preferred, as npm does) or `package-lock.json`, `lockfileVersion` 2 or 3, strict JSON, at most 32 MiB and 20,000 packages.
- Every package must come from `https://registry.npmjs.org/` at the exact canonical tarball URL for its name and version, with one `sha512` integrity. `git`, `file:`, `link`, `http:`, other hosts, aliases, bundled packages, nested shrinkwraps and workspaces are refused.
- Required dependencies and peers, and root `devDependencies`, must resolve to a validated entry.
- yarn, pnpm and bun lockfiles, monorepos and private registries are not supported. The repository's `.npmrc` is excluded.

A project with no dependencies (or no `package.json`) skips the install. A project with dependencies and no lockfile gives `node_lockfile_missing`. Any other violation gives `node_lockfile_refused` with one reason token, for example `remote_url`, `resolved_mismatch`, `integrity`, `git`, `file`, `workspace`, `dependency_unresolved`, `legacy_tree_in_v3` or `too_many_packages`. The detail names the package path and field, never a URL.

Dependencies are installed once per command (`reproduce` for all replays, `fix check` from the original copy, `retest` per revision) in the only container with network access. It receives only `package.json` and the lockfile, no source code, and runs `npm ci --ignore-scripts`: install scripts never run, so packages that need a native build or a postinstall step (for example `bcrypt`, `sharp`) fail to load. The installed tree is size-checked, walked on the host (symlinks and special files refused), digested into `deps_sha256`, and mounted read-only. Every execution phase and the project test command run with `--network=none`. An install that fails gives `node_deps_install_failed`; one over the size caps gives `node_deps_too_large`.

A fix diff that touches `package.json`, `package-lock.json`, `npm-shrinkwrap.json` or anything under `node_modules` is refused with `diff_changes_dependencies` (no blocker). A dependency change needs a new baseline.

## Fixtures (`--fixture`)

Code that needs a token or a table to reach its sink can take a private fixture file:

```json
{"schema":"vettalon.node-fixture/1","env":{"API_TOKEN":"test-only"},"sql_setup":"CREATE TABLE users(id INTEGER, name TEXT);"}
```

- `env` (at most 32 names matching `[A-Z][A-Z0-9_]{0,63}`, values at most 4 KiB) and `sql_setup` (at most 64 KiB, run on the fixture database before the secret rows are added) are both optional. No other key is allowed. The file is at most 64 KiB.
- Names that change how Node, npm, the loader, a shell, a proxy or the harness behave are refused (for example `PATH`, `HOME`, `NODE_*`, `NPM_*`, `LD_*`, `VTL_*`, `HTTP_PROXY`). The full list is in `audit/node/fixture.rs`.
- The file must be a regular, non-symlink file outside the repository. Otherwise, or when it fails validation, the command exits 2 with `node_fixture_refused` and does not print its contents.
- The fixture is sent to the runner over stdin and never staged as a file in the container. Only `env` reaches the code under test.
- Receipts store only `runtime.fixture_sha256`. Reach text that came from the fixture is redacted.

## Outcomes and blockers

Per phase, Node adds a reach condition to the Python rule:

| Effect | Reach | Phase result | Reason |
|---|---|---|---|
| yes | reached | effect | none |
| yes | not reached or unknown | inconclusive | `effect_without_reach` |
| no | reached | no effect | none |
| no | not reached or unknown, attack phase | inconclusive | `sink_not_reached` |
| no | not reached or unknown, benign phase | inconclusive | `benign_not_reached` |
| any | `pg`/`mysql2` | inconclusive | `sql_dialect_not_executable` |

So a Node `effect_absent` means: no effect was observed with these inputs, the benign call worked, and the in-process hook reported reaching the sink. Reach is `unknown` when the event record is missing, truncated or malformed. Sinks reached only in forked children, workers or other child processes are not recorded, so such targets end as inconclusive.

Fix-check blockers for Node:

| Token | Blocker |
|---|---|
| `node_runtime_unavailable`, `node_lockfile_missing`, `node_lockfile_refused`, `node_deps_install_failed`, `node_deps_too_large`, `sql_dialect_not_executable`, `ssrf_listener_unavailable` | environment |
| `node_hook_failed`, `node_ts_unsupported_syntax`, `node_driver_api_unsupported`, `original_sink_not_reached`, `original_effect_without_reach` | harness |

A blocker means the check could not judge the fix; it is never a verdict that the fix failed. On the fixed copy, no effect counts as blocked whatever reach says. In `retest`, the environment tokens map to `environment_unavailable`, and a missing export maps to `target_missing`. The positive fix-check labels say only that no effect was observed at this revision with these inputs and variants.

## Regression test (`--emit-test`)

For a non-SSRF Node target that reached `effect_observed`, `reproduce --emit-test PATH` writes a standalone `node:test` file (`.mjs`) with no Vettalon dependency. Run it from the repository root, or set `VETTALON_REPO_ROOT`:

```sh
node --test vettalon-FINDING.test.mjs
```

It needs Node 24 or later on a POSIX host, uses the project's real drivers, and creates and removes `/tmp/vtl_*`, so run these tests one at a time. If reproduction used `--fixture`, set `VETTALON_FIXTURE` to the same private file; the test checks its digest. It has two tests: the attack input has no effect, and the benign input still works.

Before the file is written, the sandbox runs the emitted file with `node --test`, read-only installed dependencies and no network, hook, event fd or shims; it requires an attack assertion failure and a passing benign test, plus independent canary checks by the protected parent using the embedded child with real drivers. Missing real drivers cannot confirm red. The receipt's `regression_test` records `red_check: "emitted_test_with_parent_canary"`. No test is written for `pg` or `mysql2` targets, because they never reach `effect_observed`. A green run covers this one input. It does not show the issue is gone, and it does not change the finding's status. `vettalon bisect` does not run Node tests in 0.8.

## What this does not show

- SSRF proves only that the tested loopback request reached the listener. It does not establish access to metadata IPs, production networks or external services. The benign network-error control is reported by the target process.
- Reach is an in-process record. The hook runs inside the target's Node process, so the code under test can forge, suppress or garble reach events. That is why reach can only downgrade a result. Receipts report it as `reach_source: "in_process_hook"`, never as a fact that the sink ran.
- `pg` and `mysql2` targets never show an effect. They stop at reach-only `inconclusive`.
- `not_observed` and `effect_absent` do not mean safe or fixed. They mean no effect was observed at this revision with these inputs and variants. Other inputs, call paths or entry points may still trigger the issue, and code can detect the instrumentation and behave differently.
- No claim holds against code written to fool the oracle. The target runs as the same user as the runner and can read the per-run secret and write the evidence file itself, so such code can produce `effect_observed`, or `effect_absent` by never calling the sink. The threat model is hostile inputs to the project's own code. The sandbox still protects the host; the verdict is not evidence against forged code. This holds for Python targets too.
- The install container's network is not limited to the npm registry. Lockfile URLs are checked before it starts, but npm follows redirects. No package code runs during the install, and no source code is present.
- Signatures over receipts confirm the receipt bytes and the signer, not that the outcome is correct.

## Why you see it

You ran `reproduce`, `fix check --target` or `retest` with a TargetCall that names a JavaScript or TypeScript file, or a receipt shows `runtime`, `reach_source` or a `node_*` reason.

## What to do

- `node_runtime_unavailable`: run `vettalon poc-node build`, or pass `--node-image` for an image you built.
- `node_lockfile_missing` or `node_lockfile_refused`: commit an npm lockfile generated against `https://registry.npmjs.org/` (`npm install --package-lock-only --ignore-scripts`), and remove git, file or other-host dependencies.
- `sink_not_reached` or `benign_not_reached`: check that the TargetCall names the function that calls the sink, and add a `--fixture` if the code needs a token or tables first.
- `sql_dialect_not_executable`: there is no execution proof for `pg` or `mysql2` in 0.8. Review the query by hand.
- `node_ts_unsupported_syntax`: the target uses TypeScript that Node cannot strip; point the TargetCall at a file with erasable syntax only.

## Related

[poc_oracle](poc_oracle.md), [fix_check](fix_check.md), [retest](retest.md), [replay_inconsistent](replay_inconsistent.md), [receipt_signing](receipt_signing.md), [bisect](bisect.md).
