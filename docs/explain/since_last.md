# since_last: Automatic incremental scan baseline

## What it means

The optional top-level `since_last` record identifies `base_report`, `base_commit` and whether this scan was `skipped`. Optional `carried_findings` counts baseline findings carried into this run and is omitted when zero. Schema version remains 3. Optional `repo_commit` and `repo_tree_clean` describe Git state at scan start; unavailable state is omitted. Optional top-level `attack_classes` records the configured methodology mode even when no modules were submitted.

## Why you see it

`scan --since-last` selects the newest validated saved report for this repo with matching profile and attack-class settings, a clean starting tree, and an ancestor commit. Complete scans and completed incremental scans can advance the baseline. Incomplete scans cannot. Missing or unusable baselines cause a full scan with no `since_last` record.

Changed files are excluded from baseline carry for every finding status. The prior-run index and finding carry also include the five newest by RFC3339 `started_at` among all validated reports rejected as baselines for run status or dirty trees, when repo, profile and attack classes match, the full commit OID is an ancestor of HEAD, and `started_at` is later than the base report. Supplements preserve coverage gaps and findings and never advance the baseline; only another Confirmed copy can replace a Confirmed finding. The prior-run path handles missing open Candidate and NeedsHuman findings in changed files: it reopens them when the source is unchanged, and lists them in `prior_run.changed_unrediscovered` when the source changed or is unavailable. Findings in unchanged files carry open Candidate, NeedsHuman and Confirmed statuses. Refuted and Suppressed findings in unchanged files carry only when a stored `file_hash` matches the current source hash. Hashing uses the prior-run file and byte budget; unreadable files and exhausted budgets prevent closed carry. A closed finding with a missing or mismatched hash prevents an unchanged skip and forces a full scan. Carried findings preserve status, severity, evidence and ID, with the run-specific `outside_diff_scope` marker removed. A current finding with the same ID wins unless it has `outside_diff_scope`; the baseline then replaces it. Carrying performs no model work and prints a count on stderr. Coverage describes this run only; completed incremental runs remain `partial_by_design`.

Before either an unchanged skip or a changed incremental run, Git-ignored paths are listed with the hardened, bounded Git runner and checked with intake's file predicate. Any file intake would read forces a full scan. Count overflow and Git failures also force a full scan. The diagnostic gives a count without file names. Any assume-unchanged or skip-worktree index entry also forces a full scan on both paths.

At the start of an incremental run, a bounded digest records sorted changed paths and their content hashes, the ignored intake count, and Git commit and clean state. After final diff reconciliation, any snapshot difference, read failure or exhausted hash budget makes the report `incomplete` with `scope_not_fully_reviewed`. This includes further edits to paths already changed and ignored intake files appearing during scanning. It cannot advance the baseline and uses the existing incomplete exit handling. Plain `--diff-base` keeps its existing behavior.

## What to do

Use deep mode and `--save` on trusted scheduled scans. Preserve `VETTALON_HOME/reports` between runs. Keep it outside the scanned checkout. The baseline is trusted local state under: untrusted CI must avoid this option and its cache. A skipped run performs no scanner, model or sandbox work, writes requested outputs, recomputes current severity and policy gates from the reused findings, and omits `--save` to preserve history. Git read failures and index flags hiding worktree changes force a full scan. Avoid concurrent checkout writes.

## Related

- [Diff scope](diff_scope.md)
- [Incomplete](incomplete.md)
- [Partial by design](partial_by_design.md)
- [Prior gap](prior_gap.md)
