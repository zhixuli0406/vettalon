# incomplete: Part of the requested work did not finish

## What it means

`run_status: incomplete` means the scan left something undone. The `incomplete_reason` field names the highest-priority cause, such as a time budget, an unavailable model or a model refusal. Findings found so far stay in the report. An incomplete run can still exit 0, so do not read a passing exit code as a clean result.

## Why you see it

A budget ran out, a model failed or refused, files were cut off, or some candidates never got a verdict.

## What to do

Read `incomplete_reason`, then run `vettalon explain <reason>`. Check `coverage` for the unfinished modules, fix the cause and rerun.

## Related

[scope_not_fully_reviewed](scope_not_fully_reviewed.md), [units_failed](units_failed.md), [time_budget_exhausted](time_budget_exhausted.md).
