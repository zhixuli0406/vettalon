# deferred: The module was ranked but never sent to a model

## What it means

The module appears in the `coverage` list, but no review took place. Its `reason` field says why: `max_modules`, `prescreen_cut`, `candidate_cap`, `time_budget` or `engine_unavailable`. A deferred module is not a clean module, and it normally makes the run `incomplete`.

## Why you see it

A selection limit, a budget or a model failure stopped the scan before it reached this module.

## What to do

Read the `reason` and open its page with `vettalon explain <reason>`. Then change the matching limit, for example `--max-modules`, and rescan.

## Related

[max_modules](max_modules.md), [prescreen_cut](prescreen_cut.md), [candidate_cap](candidate_cap.md), [time_budget](time_budget.md), [engine_unavailable](engine_unavailable.md).
