# complete: The run did everything it was asked to do

## What it means

`run_status: complete` means no incompleteness reason was recorded and the scan was not limited to a diff. In a deep scan that includes: no module deferred or failed, and no engine, budget or refusal problem. It describes the scan's work, and it does not say the repository is free of vulnerabilities.

## Why you see it

Every requested step finished. A scan with `--diff-base` reports `partial_by_design` instead.

## What to do

Read the findings, the `coverage` list and each finding's `evidence_level` before you decide anything. The status has no effect on the exit code, which depends only on `--fail-on` and `--gate`.

## Related

[partial_by_design](partial_by_design.md), [incomplete](incomplete.md).
