# scope_not_fully_reviewed: Some of the code you asked about was not fully reviewed

## What it means

The coverage summary still shows work undone: modules that were deferred or failed, files cut off by the prompt size limit, or modules reviewed only in part. Reading a few modules cannot back a claim about the whole scope. This `incomplete_reason` is only used when no higher-priority cause, like a time budget or refusal, applies.

## Why you see it

The default `--max-modules 5` on a larger repository produces this often.

## What to do

Open the `coverage` list and find entries that are not `covered`, `candidate` or `out_of_scope`. Raise `--max-modules`, or split large modules, then rescan.

## Related

[partially_reviewed](partially_reviewed.md), [max_modules](max_modules.md), [prompt_byte_budget](prompt_byte_budget.md).
