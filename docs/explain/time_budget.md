# time_budget: The module ran out of time

## What it means

The scan's wall-clock budget ended before this module was reviewed, or a model call for it timed out. Either the module is `deferred` with this reason, or one of its attempts is marked timed out.

## Why you see it

You set `--time-budget`, `--finder-budget` or similar, and the scan hit it. The run is marked `incomplete` with `time_budget_exhausted`.

## What to do

Raise the budget, for example `vettalon scan . --profile deep --time-budget 3600`, or scan less with `--max-modules` or `--diff-base <ref>`. If you set none, the scan has no overall time budget.

## Related

[time_budget_exhausted](time_budget_exhausted.md), [deferred](deferred.md), [llm_failed](llm_failed.md).
