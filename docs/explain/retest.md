# retest: An old report's differential PoCs re-run on a new revision

## What it means

`vettalon retest <PATH> --targets plans.json --out retest.json` takes an old report (from `--report`, or the newest saved report the `scan --since-last` rules trust for this repository) and re-runs each `poc_differential` finding that has an operator TargetCall plan against the repository as it is now. `--targets` is required. An explicit `--report` must carry a full hex `repo_commit`, like an automatically selected baseline. The finding is re-bound to the bytes now at the same file, so `rebound: true` with both `old_file_sha256` and `new_file_sha256` shows the file changed. Each result has one status:

- `still_observed`: every replay observed the effect on this revision.
- `not_observed`: every replay ran and none observed the effect. This means "not observed on this revision with these inputs". It does not mean the issue is fixed or the code is safe.
- `inconclusive`: the replays disagreed or gave no differential result (the reason says which). A target that hangs until the container hard timeout is `inconclusive` with reason `target_timeout`; no further replay of that finding is started.
- `environment_unavailable`: the sandbox could not run or capture the replays (reasons `sandbox_unavailable`, `invalid_image_identity`, `incomplete_sandbox_capture`, `target_poc_budget_exhausted`).
- `target_missing`: the target file or the target function is gone on this revision.
- `not_reproducible_before`: the old report has no plan for this finding (reason `no_target_plan`, or `evidence_level_*` when it has no re-runnable differential PoC). Not run.
- `retest_cap_reached`: beyond `--max-findings` (reason `retest_cap_reached`), or `--deadline` passed before it ran or between its replays (reason `deadline_exceeded`; a partial receipt is kept). Not (fully) run. This holds even when an earlier replay of that finding already observed the effect; that observation is only in the partial receipt.

Plans may name Python (`.py`) or JavaScript/TypeScript (`.js`, `.cjs`, `.mjs`, `.ts`, `.cts`, `.mts`) targets in the same run. Node targets run in the local Node image (`--node-image`, built with `vettalon poc-node build`; `--fixture` as for `reproduce`), with one dependency install per repository revision shared by the Node findings. Their receipts are version 3 with a `runtime` block and per-phase reach fields; Python receipts stay version 2. For Node, a missing export is `target_missing`, and the Node environment reasons (`node_runtime_unavailable`, `node_lockfile_missing`, `node_lockfile_refused`, `node_deps_install_failed`, `node_deps_too_large`, `sql_dialect_not_executable`) are `environment_unavailable`. A `pg` or `mysql2` target therefore never reaches `still_observed`. See [node_exec](node_exec.md).

A plan that names a finding not in the old report, a finding without a recorded differential PoC, a finding in a different file (`target_plan_file_mismatch`), or an unsupported oracle class (`unsupported_oracle_class`) refuses the whole run before anything starts. A plan is never silently skipped.

## Limits

- `--replays N` (1-20) and `--max-findings M` (1-20): `N * M * 3` containers must not exceed 120, or the command is refused before anything is read (for example `--replays 3` with the default `--max-findings 20` is 180).
- `--deadline SECONDS` (1-86400, default 3600): a wall-clock budget checked before each finding and before each replay. A replay that has started is not stopped, so a run can pass the deadline by up to one replay (three containers of up to 120 s each) plus the snapshot check.
- Every replay takes a fresh tree snapshot, verified against the hashed bytes before and after its containers run.

## Exit codes

The first matching rule wins:

| Code | Meaning |
|---|---|
| 1 | Some finding is `still_observed`. |
| 2 | Some finding is `inconclusive` or `environment_unavailable`, or the run was refused (bad arguments, container cap, report or plan error). |
| 3 | Nothing ran (for example every finding is `not_reproducible_before`), or some finding is `target_missing` or `retest_cap_reached` (including `deadline_exceeded`). |
| 0 | At least one finding ran and every finding that ran is `not_observed`. |

`not_reproducible_before` findings never make a run exit 0 on their own.

## Why you see it

You asked whether findings proven on an earlier revision still reproduce. The command never edits the old report and never changes a finding's status. Old-report text (finding ids, paths) is printed with control characters escaped.

## What to do

Treat `still_observed` as a live issue. For `not_observed`, review the change that removed the effect and keep a regression test; other inputs may still trigger it. For `target_missing`, check whether the code moved and give a new plan. For `environment_unavailable`, make the local sandbox image available and run again. For `target_timeout`, check whether the change made the target block. For `retest_cap_reached`, raise `--deadline` or `--max-findings`, or run the remaining findings separately.

## Related

[poc_differential](poc_differential.md), [replay_inconsistent](replay_inconsistent.md), [since_last](since_last.md).
