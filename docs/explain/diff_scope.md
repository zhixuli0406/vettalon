# diff_scope: The module has no changed files, so a diff scan skipped it

## What it means

You ran a deep scan with `--diff-base <ref>`. Vettalon compares `HEAD` with its merge base against that ref, and only modules containing changed files are reviewed. This module has none, so it is listed as `out_of_scope` with this reason. It has no attempts or checks and does not count as covered.

## Why you see it

The module sits outside the changed-file list for the diff.

Module selection uses the initial snapshot. Before summary and gates, Vettalon recomputes the diff and includes scanner findings from the union of both changed-file sets. `scope.changed_during_scan` counts added paths; those additional changes were not part of initial module selection. A moved HEAD or base, a changed merge-base, or a failed recomputation stops the scan without writing a report.

## What to do

Drop `--diff-base` to review the whole repository: `vettalon scan . --profile deep`.

## Related

[out_of_scope](out_of_scope.md), [partial_by_design](partial_by_design.md).
