# Query refinement public V2

This opt-in source experiment revises a Python query from finite oracle/scanner
disagreements, then records one sealed holdout event, replay and minimization.
It uses self-authored fixtures and never executes their code. The
[oracle contract](ORACLE-CONTRACT.md) defines the narrow input-dependency relation;
it does not decide vulnerability truth. R27 remains **PARTIAL**, with
`adoption_eligible=false` and `budget-control-incomplete`.

Updated 2026-10-17. This public V2 phase has not yet run a real scanner or model.
Offline parser, self-authored fake-CLI and clean public-stage checks establish
source/runtime binding and delivery contracts only; they are not real-scanner
method validation.
The versioned entry point removes private historical runtime paths; it does not
promise to reproduce the historical private eight-call batch. The frozen
`refine.py` is a helper/reference, not the public launch entry point. The original
oracle, helper, tests, six dev files and oracle contract retain their bytes.

## Prerequisites

Run from an independently reviewed checkout. The controller uses Python standard
library code and the exported generic process helper under
`benchmarks/reachability/`; it does not invoke Go or Rust analysis paths.

For an opt-in real scanner run, prepare an existing reviewed macOS (`darwin`)
Semgrep **1.181.0** installation, launcher Python, controller Python, venv tree
and `/usr/bin/sandbox-exec`. Review the exact exported
`deny-network-public-v2.sb` policy. No download, installation, PATH lookup,
version substitution or fallback is provided. Missing or changed inputs fail
closed. The OS network policy is not a filesystem sandbox or a guarantee about
all dependencies, CPU, memory or disk writes.

A separate reviewer must seal four self-authored holdout sources before query
selection. Keep profile, lock, seal, holdout and generated outputs outside the
public source export. They are local inputs/results, not bundled examples or
permission to process third-party source.

## Runtime profile and approved lock

Copy [runtime-profile.example.json](runtime-profile.example.json) to a private
location and replace every placeholder after review. The untouched template is
intentionally invalid and must fail closed. It contains no real user path or
digest. Use canonical absolute paths with no symlink ancestors and lowercase
64-character SHA-256 values. The sandbox binding must be `/usr/bin/sandbox-exec`;
the policy bytes must exactly match the exported V2 policy, not merely a
self-selected policy with a matching caller-supplied hash.

The profile has exact schema 2, kind `public-query-runtime-v2`, platform `darwin`,
scanner version `1.181.0`, `python_minor`, `controller_python_version`, `venv_root`,
`bindings` and `runtime_files`. Binding roles are `launcher`, `core`, `policy`,
`sandbox`, `launcher_python` and `controller_python`, each with `path` and `sha256`.
`runtime_files` maps explicit absolute file paths to hashes and must include:

- `<venv>/pyvenv.cfg`

- `<venv>/lib/pythonX.Y/site-packages/semgrep/__init__.py`
- `<venv>/lib/pythonX.Y/site-packages/semgrep/console_scripts/entrypoint.py`
- `<venv>/lib/pythonX.Y/site-packages/semgrep/semgrep_core.py`
- `<venv>/lib/pythonX.Y/site-packages/semgrep-1.181.0.dist-info/METADATA`
- `<venv>/lib/pythonX.Y/site-packages/semgrep-1.181.0.dist-info/entry_points.txt`

The locked `pyvenv.cfg` must declare exactly one
`include-system-site-packages=false` and one full `version` whose major/minor
matches `python_minor` and the declared layout. These are configuration
declarations, not an actual launcher-runtime version probe. The launcher's
shebang may name only `<venv>/bin/python`, `<venv>/bin/python3` or
`<venv>/bin/pythonX.Y`, without `env` or extra arguments. This final Python leaf
may be a symlink resolving to the canonical `launcher_python` binding; its
ancestors must not be symlinks. Other reviewed binding paths remain canonical.
The controller checks its own actual `sys.version.split()[0]` against
`controller_python_version` and its canonical `Path(sys.executable).resolve()`
against the `controller_python` binding. Review all executable paths, bytes and relevant
runtime files independently. Matching hashes bind reviewed files; they do not
prove authenticity, provenance, a complete venv or all dynamic dependencies.

The separately approved lock has exact shape:

```json
{"schema": 2, "kind": "public-query-lock-v2", "files": {"/REPLACE_WITH_ABSOLUTE_FILE": "REPLACE_WITH_REVIEWED_FILE_SHA256"}}
```

Its `files` must cover `runtime_profile.required_paths()`, the profile and seal,
all six binding files and every declared runtime file. The lock does not contain
its own hash. Compute the SHA-256 of the exact raw profile and lock bytes after
review; both expected hashes are mandatory command arguments. Formatting or
newline changes alter those hashes. Binding checks are repeated through the
finite flow; an input change must remain an incomplete failure. Profile input is
limited to 64 KiB and the lock to 256 KiB, with at most 256 bound files, 256 MiB
per file and 512 MiB combined. These read/hash limits do not establish a runtime
memory or disk sandbox.

The seal retains schema 1:

```json
{"schema": 1, "created_by": "REPLACE_WITH_CHECKER_ID", "split": "holdout", "cases": [{"id": "REPLACE_WITH_UNIQUE_ID", "name": "cases/REPLACE_WITH_UNIQUE_ID.py", "sha256": "REPLACE_WITH_SOURCE_SHA256"}]}
```

Supply exactly four distinct entries, not the one-entry shape illustration.
For JSON materialization, seal metadata has a 64 KiB read limit, is bound by its
approved raw SHA-256, then parsed as a strict JSON object. Generic binding
load/verification separately streams the seal hash under the 256 MiB per-file
hashing cap; the 64 KiB limit does not cover all seal I/O. A caller-supplied descriptor
must match that approved descriptor semantically; an unbound descriptor cannot
replace it. Holdout source is read only after the immutable dev selection and
single-use holdout event. Shared filesystem sealing
is not cryptographic blinding or an external OSS holdout.

## Explicit entry point

The following is an argument template, not a previously executed command. All
five paths must be absolute; the output directory must be new. Reviewed tool
setup and approval of new real scanner execution remain separate from offline
test discovery.

```text
python3 benchmarks/query-refinement/refine_public_v2.py --run-dir /NEW_ABSOLUTE_RUN_DIR --profile /REVIEWED_PROFILE.json --profile-sha256 PROFILE_RAW_SHA256 --approved-lock /APPROVED_LOCK.json --approved-lock-sha256 LOCK_RAW_SHA256 --seal /CHECKER_SEAL.json --holdout-dir /SEALED_HOLDOUT_DIR
```

All seven flags are required. No implicit private reports directory, historical
lock or historical tool venv is selected. An invalid profile, hash, lock, seal,
missing file or unsupported runtime must fail closed without a replacement run.

The flow preserves the baseline query, compares dev observations with the
independent AST oracle, accepts only a finite improving query revision, then
performs the sealed holdout, baseline/selected replay and bounded AST
minimization. Selection never learns from holdout/replay/minimization results.
Unsupported or incomplete observations remain unknown, not safe. Holdout
validation can be complete only when its non-regression result is explicitly
true; a complete scanner invocation alone cannot satisfy that condition.

## Output and limits

A fresh run retains raw `runtime-profile.json`, `approved-lock.json`,
`runtime-binding.json`, `holdout-seal.json`, dev manifest/source bytes, the budget
contract, queries, scans, attempts, selection, holdout event, replay,
minimization and summary artifacts. The runtime binding identifies
`controller_contract=query-refinement-public-v2` and explicitly labels dependency
attestation as explicit-files-only. `summary.json` retains schema 1 and adds the
controller contract and runtime-binding hash. Failures retain `failed-run.json`
with the reason, attempts and scheduled/complete/unknown/not-attempted stage
denominators. Preserve failed attempts and raw output; do not overwrite a run or
reset its denominator to seek a successful result.

Execution is serial: at most 15 scanner attempts, zero outer retries, at most
15 seconds per admission and a shared 120-second admission deadline. An
immutable ledger debits before invocation, including failed attempts. Saved
stdout is capped at 1 MiB and stderr at 256 KiB. Each source is at most 2 KiB,
source bytes total at most 64 KiB and query bytes at most 8 KiB; managed immutable
artifacts have a 16 MiB cap. No fixture, operand or target code is executed.

These are admission/capture controls. Blocking spawn and OS termination lack a
hard wall-clock guarantee; CPU, process peak RSS and scanner HOME/cache/other
writes are not bounded by the managed artifact cap. Keep
`budget-control-incomplete` even if the finite run completes. No result changes
product rules, finding status, default behavior or adoption eligibility. Human
oracle, true OSS effectiveness, unique real roots, cost per confirmed finding,
C/CodeQL and full ARQ remain unverified.

## Offline tests and CI

After review, the offline discovery command is:

```bash
python3 -m unittest discover -s benchmarks/query-refinement -p 'test_*.py'
```

It exercises the real parser with self-authored fake CLI/process fixtures, not a
real scanner or model. The CI configuration adds this discovery only to the
existing macOS matrix leg with Python 3.12; it does not install Semgrep or run its
real workflow. No CI execution or pass result is claimed here. Public source
staging must separately check exact file mappings and private-data gates.

## License

New self-authored source uses the repository [Apache-2.0 license](../../LICENSE).
No scanner binaries or private runtime files are redistributed. External tool
licensing and redistribution requirements require their own review.
