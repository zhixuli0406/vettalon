# Node CLI execution fixtures

These six small projects exercise `reproduce`, `fix check --target`, and Node
runtime selection. They are deliberately vulnerable test programs. The report
helper writes **synthetic test input**, not scanner findings or execution proof.
Docker execution is reserved for the reviewer. In the reviewer's live run on
2026-11-12 (Docker on macOS) the original `cjs-command`, `esm-path` and
`ts-sqlite` projects gave `effect_observed`
and their fix checks passed, and `pg-reach` gave `inconclusive` with
`sql_dialect_not_executable`.

| Project | Target | Original reproduce | Fix check with `--test-command true` |
|---|---|---|---|
| `cjs-command` | CJS `child_process.exec`, callback argument, CWE-78 | `effect_observed` | `fix_verified` |
| `esm-path` | ESM `fs.readFileSync(path.join(base, x))`, CWE-22 | `effect_observed` | `fix_verified`; attack blocked before sink |
| `ts-sqlite` | Erasable `.ts`, concatenated sqlite3 query, CWE-89 | `effect_observed` | `fix_verified`; parameterized query |
| `esm-ssrf` | ESM `fetch(url)`, CWE-918 | `effect_observed` | `fix_verified`; private-address check |
| `cjs-ssrf-get` | CJS `http(s).get(url, callback)`, CWE-918 | `effect_observed` | `fix_verified`; private-address check |
| `pg-reach` | ESM `pg.Client.query`, CWE-89 | `inconclusive`, `sql_dialect_not_executable` | No executable database backend |

`fix_verified` is the machine key: it means no effect was observed with the tested
inputs and variants, plus a passing configured test command. `true` below only
exercises the project-test dispatch; it is not a functional test suite. Hook reach
is an untrusted in-process diagnostic. No result establishes safety against target
code deliberately written to forge the oracle.

Live run on 2026-11-13 (Docker on macOS, pinned `docker/poc-node` image), both SSRF
projects gave the same results:

- `reproduce --replays 2`: `effect_observed` (2 of 2 replays), `surfaced=true` on
  both attack phases; the benign control reached only a DNS failure.
- `fix.patch` with `--test-command true`: `fix_verified`; all 16 variants ran,
  `ids_not_blocked` empty, `ssrf-userinfo` not applicable (Node `fetch` refuses URLs
  with credentials on both copies). IPv4-mapped loopback scores; pure IPv6 loopback
  and userinfo are non-scoring probes. IPv6 is disabled in containers on the Linux
  acceptance host, so `[::1]` is never required to reach the listener.
- `naive.patch`: `fix_rejected`, `fixed_copy_shows_effect`, with
  `variant_set.ids_not_blocked` = `ssrf-localhost-upper`, `ssrf-decimal`, `ssrf-hex`,
  `ssrf-octal`, `ssrf-short`, `ssrf-other-loopback`, `ssrf-unspecified`, `ssrf-zero`,
  `ssrf-pct-host`. The raw substring blocklist misses these host encodings
  (`[::ffff:127.0.0.1]` contains the blocked substring, so it is blocked).
- A patch that rejects every URL (`esm-ssrf`): `fix_unverified`, benign
  `inconclusive`, reason `ssrf_benign_unconfirmed`. A normal return without a network
  error also cannot confirm the SSRF benign control. Such patches are never verified.
- `retest` of `cjs-ssrf-get` with the receipt above: `still_observed` (exit 1).
- The canary did not appear in any receipt or log.

The full end-to-end run was on macOS only. On the Linux acceptance host (Docker
24.0.7) the listener primitives were probed with the same image and flags (ports
80/443 bind as uid 65534, every scored variant reached the listener, benign DNS
failure), but `vettalon` itself was not run there.

The correct fixes parse the URL, check the protocol, resolve all addresses, and
reject non-public addresses before calling the sink. DNS errors propagate unchanged
(with `code`, or `cause` for fetch errors). In the offline sandbox, the benign
`https://example.com/vtl_benign` reaches DNS and fails with `EAI_AGAIN` or
`ENOTFOUND`; that error confirms the network-layer control. These are oracle
fixtures, not a complete production URL-fetch policy (for example DNS rebinding
requires binding the connection to the validated address).

For `esm-path`, expect `inputs=5/5` and `decoding=0/0/2`: the two percent-encoded
paths are literal missing files, so they raise without an effect on both copies
and are not applicable, regardless of original-copy sink reach. An original-copy
decoding effect without confirmed reach remains inconclusive with
`original_effect_without_reach`; it receives no applicable or blocked credit.
Scored inputs retain their original-copy reach gate, and runner errors still stop
checks. The reach exemption applies only to no-effect decoding probes.
On the fixed copy, a checked-code exception without an effect counts as blocked
when the input is applicable; runner errors remain `fixed_copy_no_verdict`.
The benign control must succeed, so an always-raising fix is rejected.

The five executable projects have no external dependencies and include empty v3
lockfiles. `sqlite3` is resolved to Vettalon's bundled shim backed by `node:sqlite`;
no native sqlite3 package is installed. The pg fixture declares a pinned real npm
package so it also exercises one networked install followed by offline phases.

Run from the repository root. Use a fresh output directory on every run because
receipt creation refuses to overwrite files:

```sh
cargo build -p vettalon --bin vettalon
VTL_BIN="$PWD/target/debug/vettalon"
VTL_FIXTURES="$PWD/crates/vettalon/tests/fixtures/node-e2e"
VTL_RUN="$(mktemp -d /tmp/vettalon-node-e2e.XXXXXX)"
"$VTL_BIN" poc-node build
VTL_NODE_IMAGE="$("$VTL_BIN" poc-node image)"
```

Generate real npm lockfiles with Node/npm available on the reviewer's host. The
five dependency-free commands are optional refreshes of their supplied empty
lockfiles.
The pg command is required before its live run. `--ignore-scripts` also applies to
lock generation:

```sh
npm --prefix "$VTL_FIXTURES/cjs-command" install --package-lock-only --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org/
npm --prefix "$VTL_FIXTURES/esm-path" install --package-lock-only --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org/
npm --prefix "$VTL_FIXTURES/ts-sqlite" install --package-lock-only --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org/
npm --prefix "$VTL_FIXTURES/esm-ssrf" install --package-lock-only --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org/
npm --prefix "$VTL_FIXTURES/cjs-ssrf-get" install --package-lock-only --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org/
npm --prefix "$VTL_FIXTURES/pg-reach" install --package-lock-only --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org/
```

Run all five executable projects. Each `reproduce` invocation performs two
three-phase replays. Each `fix check` applies `fix.patch` to a private snapshot;
it does not change `app.*`. The complete fixed app is also supplied in `fixed/`.

```sh
for VTL_CASE in cjs-command esm-path ts-sqlite esm-ssrf cjs-ssrf-get; do
  VTL_PROJECT="$VTL_FIXTURES/$VTL_CASE"
  python3 "$VTL_FIXTURES/make-report.py" "$VTL_PROJECT" "$VTL_RUN/$VTL_CASE-report.json"
  "$VTL_BIN" validate "$VTL_RUN/$VTL_CASE-report.json"
  "$VTL_BIN" reproduce "$VTL_PROJECT" \
    --report "$VTL_RUN/$VTL_CASE-report.json" --finding node-e2e \
    --target "$VTL_PROJECT/target.json" --node-image "$VTL_NODE_IMAGE" \
    --replays 2 --out "$VTL_RUN/$VTL_CASE-reproduce.json"
  "$VTL_BIN" fix check "$VTL_PROJECT" \
    --report "$VTL_RUN/$VTL_CASE-report.json" --finding node-e2e \
    --target "$VTL_PROJECT/target.json" --diff "$VTL_PROJECT/fix.patch" \
    --node-image "$VTL_NODE_IMAGE" --test-command true \
    --out "$VTL_RUN/$VTL_CASE-fix.json" \
    --report-out "$VTL_RUN/$VTL_CASE-checked-report.json"
done
```

Exercise the naive fixes and a block-everything patch (the reports above must
already exist). These are reviewer commands, not recorded live results:

```sh
for VTL_CASE in esm-ssrf cjs-ssrf-get; do
  VTL_PROJECT="$VTL_FIXTURES/$VTL_CASE"
  for VTL_PATCH in naive block-all; do
    if [ "$VTL_PATCH" = block-all ]; then
      python3 - "$VTL_PROJECT" "$VTL_RUN/$VTL_CASE-block-all.patch" <<'PYBLOCK'
import difflib, json, pathlib, sys
project, output = map(pathlib.Path, sys.argv[1:])
file = json.loads((project / 'target.json').read_text())['file']
source = (project / file).read_text()
fixed = ("export async function run(url) { throw new Error('Blocked'); }\n"
         if file.endswith('.mjs') else
         "exports.run = function (url, callback) { callback(new Error('Blocked')); };\n")
output.write_text(''.join(difflib.unified_diff(
    source.splitlines(True), fixed.splitlines(True),
    fromfile='a/' + file, tofile='b/' + file)))
PYBLOCK
      VTL_DIFF="$VTL_RUN/$VTL_CASE-block-all.patch"
    else
      VTL_DIFF="$VTL_PROJECT/naive.patch"
    fi
    "$VTL_BIN" fix check "$VTL_PROJECT" \
      --report "$VTL_RUN/$VTL_CASE-report.json" --finding node-e2e \
      --target "$VTL_PROJECT/target.json" --diff "$VTL_DIFF" \
      --node-image "$VTL_NODE_IMAGE" --test-command true \
      --out "$VTL_RUN/$VTL_CASE-$VTL_PATCH.json" \
      --report-out "$VTL_RUN/$VTL_CASE-$VTL_PATCH-report.json"
  done
done
```

Run the PostgreSQL case; exit 2 is expected. The real `pg` package is installed
once, but its queries are intercepted by the reach-only shim; no server runs:

```sh
python3 "$VTL_FIXTURES/make-report.py" "$VTL_FIXTURES/pg-reach" "$VTL_RUN/pg-report.json"
"$VTL_BIN" reproduce "$VTL_FIXTURES/pg-reach" \
  --report "$VTL_RUN/pg-report.json" --finding node-e2e \
  --target "$VTL_FIXTURES/pg-reach/target.json" --node-image "$VTL_NODE_IMAGE" \
  --replays 2 --out "$VTL_RUN/pg-reproduce.json"
```

To exercise fixture handling, the private fixture **must be outside** the project;
add `--fixture "$VTL_RUN/auth.json"` to any of the executable project commands. Values are
validated, sent only to the protected runner over stdin, and omitted from receipts. Fixture-backed
reach text is redacted; `runtime.fixture_sha256` binds the canonical fixture.

The Node runner receives two stdin frames: `<decimal byte count>\n<bytes>` for
the marker, then the canonical fixture JSON (zero bytes when absent), followed by
EOF. It becomes non-dumpable before reading them. No fixture file is staged or
mounted, and only the validated fixture environment is passed to the child.
Repository paths are resolved before fixture reads; an in-project fixture or a
fixture symlink is refused with exit 2 without printing its contents.

Install manifests also travel as two stdin frames, `package.json` first and
`package-lock.json` second. The Node-specific staging helper writes them under
umask 077 in the container's uid-65534-owned 0700 `/work` tmpfs, as 0600 files.
There are no host manifest copies or input bind mounts; this avoids requiring
uid 65534 to read a host-owned 0600 file.

Live review still needs to verify installation under uid 65534, successful
fixture-backed replay, the absence of `/workspace/fixture.json`, and refusal of
child access to the runner's `/proc/1/{environ,fd,mem}`. These container checks
are not established by the host-side fake-run tests.

```sh
(umask 077; printf '%s\n' '{"schema":"vettalon.node-fixture/1","env":{"TEST_TOKEN":"review-only-auth"}}' > "$VTL_RUN/auth.json")
```

Retest needs an old report with a recorded differential PoC. The following uses
the actual CJS receipt just produced to add that evidence to the synthetic report,
then retests the same project and should yield `still_observed` (exit 1). It does
not invent an observed result when reproduce failed:

```sh
python3 - "$VTL_RUN" "$VTL_FIXTURES" <<'PY'
import json, pathlib, sys
out, fixtures = map(pathlib.Path, sys.argv[1:])
receipt = json.loads((out / 'cjs-command-reproduce.json').read_text())
assert receipt['outcome'] == 'effect_observed'
assert receipt['replays']['observed'] == receipt['replays']['requested'] == 2
report = json.loads((out / 'cjs-command-report.json').read_text())
assert receipt['target_file_sha256'] == report['findings'][0]['file_hash']
report['findings'][0]['evidence'].append({
    'kind': 'poc_oracle', 'source': 'node-e2e-live-reproduce',
    'detail': 'poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected=none',
    'recorded_at': '2026-11-12T00:00:00Z',
})
with (out / 'retest-old.json').open('x') as f:
    json.dump(report, f)
with (out / 'targets.json').open('x') as f:
    json.dump({'node-e2e': json.loads((fixtures / 'cjs-command/target.json').read_text())}, f)
PY
"$VTL_BIN" retest "$VTL_FIXTURES/cjs-command" \
  --report "$VTL_RUN/retest-old.json" --targets "$VTL_RUN/targets.json" \
  --node-image "$VTL_NODE_IMAGE" --replays 2 --max-findings 1 \
  --out "$VTL_RUN/retest.json"
```

`--poc-image` continues to select Python only. Missing local Node images produce
`node_runtime_unavailable` and the `vettalon poc-node build` hint; they are never
pulled automatically. Dependency-free projects skip installation; missing locks
with dependencies produce `node_lockfile_missing`. Invalid or mismatched npm
inputs produce `node_lockfile_refused`. Installs and image version probes are
command-scoped; all execution phases run with networking disabled. Retest shares
one Node dependency context across findings of the same revision and uses a
separate Python image session.

Fixes touching `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, or
`node_modules` anywhere in the tree are refused with `diff_changes_dependencies`
(content refusal, no environment blocker). Dependency changes need a new baseline.
SSRF `--emit-test` is refused with `ssrf_emit_test_unsupported`; no file is written.
For the other executable classes, Node `--emit-test` (D10) writes a `node:test` file; its red check runs the file's
embedded target child under the protected runner. The commands above do not
request it; add `--emit-test "$VTL_RUN/$VTL_CASE.test.mjs"` to a `reproduce`
command to exercise it.
