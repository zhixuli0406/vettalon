# out_of_scope: The module was left out of the diff scan on purpose

## What it means

In the `coverage` list, `out_of_scope` is the status of a module that has no changed files in a `--diff-base` scan. It has no attempts, checks or findings, and it never counts as covered just because it was excluded. The `reason` on it is `diff_scope`.

## Why you see it

You ran `vettalon scan . --profile deep --diff-base <ref>`, and none of this module's files differ between the merge base with that ref and `HEAD`.

## What to do

Nothing, if you only care about the changed code. For the rest of the repository, scan without `--diff-base`.

## Related

[diff_scope](diff_scope.md), [partial_by_design](partial_by_design.md), [outside_diff_scope](outside_diff_scope.md).
