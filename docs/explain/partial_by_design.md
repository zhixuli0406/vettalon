# partial_by_design: The scan finished, but only on the part you asked for

## What it means

`run_status: partial_by_design` means the scan completed its requested scope, and that scope was a subset of the repository. A scan with `--diff-base` ends this way. Modules outside the diff are listed as `out_of_scope` and are not claimed as reviewed.

## Why you see it

You used `--diff-base <ref>` and nothing else went wrong. If something did, the status is `incomplete` instead.

## What to do

Use it for pull request checks. For repository-wide assurance, run `vettalon scan . --profile deep` without `--diff-base`.

## Related

[out_of_scope](out_of_scope.md), [diff_scope](diff_scope.md), [incomplete](incomplete.md).
