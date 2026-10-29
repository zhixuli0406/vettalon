# llm_failed: The model call for this module failed

## What it means

Vettalon sent the module to a model, and the call returned an error or timed out. The module has no review. It counts as failed in the coverage summary and normally makes the run `incomplete` with `units_failed`.

## Why you see it

The model call returned an error or timed out. The module's `reason` field has the error text.

## What to do

Read the `reason`, restore the model, and rerun. Add `--trace trace.jsonl` to get one line per model call with its outcome and latency.

## Related

[engine_unavailable](engine_unavailable.md), [units_failed](units_failed.md), [time_budget](time_budget.md).
