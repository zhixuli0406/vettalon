# outside_diff_scope: A scanner finding sits in a file the diff did not change

## What it means

In a `--diff-base` scan, the repository-wide scanners (Semgrep, Gitleaks, cargo-audit, OSV-Scanner) still look at everything. Findings in files outside the changed set get a `scope_note` item with this text. They stay in the report, but they are left out of the severity counts, `--fail-on` and `--gate`. A leaked secret in an untouched file will not fail the build.

## Why you see it

You passed `--diff-base <ref>` to a deep scan.

The changed set is the union of snapshots taken at the start and after review and PoC. A changed dependency manifest or lockfile keeps dependency advisories in scope. An advisory whose manifest or lockfile is untracked in either snapshot also stays in scope, including an ignored, generated `Cargo.lock`. Unknown path shapes stay in scope.

## What to do

Read these findings as background. To have them count, scan without `--diff-base`: `vettalon scan . --profile deep`.

## Related

[scope_note](scope_note.md), [diff_scope](diff_scope.md), [out_of_scope](out_of_scope.md).
