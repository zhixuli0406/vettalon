# scope_note: A note from Vettalon about where a finding sits in the scan scope

## What it means

This evidence kind holds scope information that Vettalon itself added. Today the only text is `outside_diff_scope`. It is not a verdict on the finding and it adds no proof.

## Why you see it

A scanner finding was in a file outside the changed set of a `--diff-base` scan.

## What to do

Read the note before you interpret counts or gate results. Findings with it are excluded from `--fail-on` and `--gate`. Scan without `--diff-base` to include them.

## Related

[outside_diff_scope](outside_diff_scope.md), [out_of_scope](out_of_scope.md).
