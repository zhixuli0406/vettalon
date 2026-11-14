# bisect: The first commit where a regression test fails

## What it means

`vettalon bisect` runs one regression test, written by `vettalon reproduce --emit-test`, against earlier commits on the first-parent history. It reports the first commit where that test fails. That is the first commit where this test detects the behaviour. It is not necessarily the commit where the vulnerability was introduced: the code may have been vulnerable earlier in a form this test does not reach, or the history may change back and forth.

The receipt (`version` 1) records `repo_commit_bad`, `good`, `outcome`, `non_monotonic`, every test run in `steps`, `max_steps` and `test_sha256`. `outcome.kind` is one of:

- `introduced_in`: `commit` is the first failing commit; `last_passing` is the newest commit seen without the behaviour (the `--good` revision when it decided the answer). The `--good` revision is assumed to pass and is never run, so a wrong `--good` gives a wrong answer.
- `present_since_oldest`: without `--good`, the oldest first-parent commit already fails.
- `not_reproducible_at_bad`: the test does not fail at the `--bad` revision, so there is nothing to search.
- `inconclusive`: three consecutive commits could not run the test, or every commit between the bounds was unrunnable. `lo` and `hi` are the narrowed bounds.
- `step_cap_reached`: `--max-steps` ran out first. `lo` and `hi` are the narrowed bounds.
- `empty_range`: there were no commits to test.

Each step is `fails`, `passes` or `unrunnable` with a short reason (lowercase ASCII `a-z0-9_:-`, at most 64 characters). `target_missing` means the finding's file is not in that commit's tree and counts as "behaviour absent". The path is matched by name only: if the file was renamed or moved, commits before the rename are `target_missing`, so the reported commit moves to the rename even when the old file already had the behaviour. `target_not_regular` means the path is in the tree but as a symbolic link, inside a submodule or under a symlinked directory; it was not exported, and the step is an ordinary unrunnable skip, not "behaviour absent". (`target_unverified`, also a skip, means the file is absent but the commit had more than 10,000 symlinks and submodules, so the two cases could not be told apart.) A failing attack check with a passing benign check is `fails`; both passing is `passes`. A failing benign control, an attack test that errors, a missing or malformed verdict and a sandbox error are `unrunnable`. When a commit without the behaviour is seen after one with it, `non_monotonic` is true and the answer is one transition, not necessarily the first. `non_monotonic` false does not mean the history was checked: binary search tests only a few commits, and the two consistency checks (one commit on each side of the answer) run only when steps are left over within `--max-steps`.

The repository is only read. Each commit's tree is listed with `git ls-tree` and its file contents are read as raw blobs with one `git cat-file --batch` into a new private temporary directory; nothing is checked out and the working tree and index are not touched. `git archive` is not used. No attributes apply (neither the repository's `.gitattributes` nor your own `core.attributesFile` or `$GIT_DIR/info/attributes`), and no filters or line-ending conversion run, so `export-subst` cannot expand `$Format:...$` and `export-ignore` cannot hide files. Only regular files are written (mode 0644, or 0755 for executables). Symbolic links and submodules are skipped, so a test that depends on them sees them as missing; when the finding's own file is one of them (or lies under one), the step is `target_not_regular`. An export with an unsupported entry type, an unsafe path (absolute, `..`, empty component, a `.git` component, not UTF-8; on Windows also `\`, `:`, a device name such as `CON`, `NUL`, `COM1` or `LPT1` in any case and with any extension, or a component ending in `.` or a space), more than 200,000 entries or more than 512 MiB of file contents is refused, and that commit is `unrunnable` (`export_failed`). The `--good` and `--bad` revisions are resolved to commit ids once, and those ids are the ones searched and recorded in the receipt. First-parent ancestry is read from the commit objects with commit-graph files disabled.

The result reflects code written by the history's authors. The test runs that commit's own code, and code at any commit can force its own test outcome (for example by detecting the test and behaving differently), so a commit can be made to look clean or to look like the introduction point. Treat the answer as a lead to review, not as attribution.

The test runs in the same sandbox as the `reproduce` red check: no network, read-only root, all capabilities dropped, an unprivileged user, memory and CPU limits, and a local image that is never pulled. Each test run starts one container. The search itself makes at most `--max-steps` runs (1 to 40, default 20), including up to two consistency checks made only from spare budget. The sandbox refuses more than `--max-steps` + 3 containers as a hard backstop.

## Why you see it

You ran `vettalon bisect` with a report, a finding and its regression test.

## What to do

Read the result as "first commit where this test fails". Exit status 0 means `introduced_in` or `present_since_oldest`, 1 means `not_reproducible_at_bad`, and 2 means `inconclusive`, `step_cap_reached`, `empty_range` or a refused input. On `step_cap_reached`, pass `--good` closer to the answer or raise `--max-steps`. On `inconclusive`, check the reasons in `steps`. When `non_monotonic` is true, inspect the history around the reported commit yourself.

## Related

[fix_check](fix_check.md), [poc_oracle](poc_oracle.md).
