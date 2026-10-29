# units_failed: Some pieces of the scan produced no usable result

## What it means

A unit is a scanner run, a module review or a finding's verification. At least one unit failed: a scanner crashed, a model call failed, a reply was malformed, or a candidate never got a refuter verdict. Findings already produced are still valid. The run is `incomplete`.

## Why you see it

Nothing with a higher priority, such as a time budget or a refusal, explains the failure.

## What to do

Find the failed units: engine results in `engines_run`, module `attempts`, and `verify_error` items on findings. Fix the cause and rerun. `--trace trace.jsonl` records every model call's outcome.

## Related

[llm_failed](llm_failed.md), [parse_failed](parse_failed.md), [unreadable](unreadable.md), [verify_error](verify_error.md).
