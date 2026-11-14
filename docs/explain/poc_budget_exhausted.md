# poc_budget_exhausted: The 20-run PoC counter was spent before every eligible PoC ran

## What it means

`incomplete_reason: poc_budget_exhausted` means the scan stopped starting PoCs because the run-wide counter `POC_MAX_RUNS` (20) was spent. This is a count of sandbox runs, not a clock. Findings already recorded stay in the report. A fix check in that scan does not draw this counter: each one has its own container budget. Raising `--poc-budget` does not raise the counter.

The same token on a fix-check detail means the budget given to that one check could not cover it, or a claim failed mid-check. A short budget passed in by a caller is that case. It is not the scan's 20-run counter. An older report that stored `time_budget_exhausted` for a run-count skip still deserializes.

## Why you see it

You used `--poc`, and the scan had already started 20 PoC sandbox runs. Later eligible PoCs are recorded as skipped.

## What to do

Narrow the scan, or rerun the findings that were skipped. A time cap is [time_budget_exhausted](time_budget_exhausted.md). A cap on harness fix checks is [fix_check_cap_reached](fix_check_cap_reached.md).

## Related

[poc_skipped](poc_skipped.md), [time_budget_exhausted](time_budget_exhausted.md), [fix_check](fix_check.md), [incomplete](incomplete.md).
