# deferred: The module has unfinished review work

## What it means

The module appears in the `coverage` list with unfinished work. Its `reason` field says why: `max_modules`, `prescreen_cut`, `candidate_cap`, `time_budget`, `engine_unavailable` or `provider_usage_limit`. A provider usage limit can interrupt a later phase or another finder share after a successful finder reply; existing reviewed paths and attempt evidence are retained. A deferred module is not a clean module, and it normally makes the run `incomplete`.

## Why you see it

A selection limit, a budget or a model failure stopped the scan before it reached this module.

## What to do

Read the `reason` and open its page with `vettalon explain <reason>`. Then change the matching limit, for example `--max-modules`, and rescan.

## Related

[max_modules](max_modules.md), [prescreen_cut](prescreen_cut.md), [candidate_cap](candidate_cap.md), [time_budget](time_budget.md), [engine_unavailable](engine_unavailable.md), [provider_usage_limit](provider_usage_limit.md).
