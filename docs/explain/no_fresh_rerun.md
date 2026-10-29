# no_fresh_rerun: The effect was not reproduced in a fresh container

## What it means

After a PoC shows an effect, the harness reruns it in a new container with a different one-time secret. This gap means the report has no oracle record with `rerun=true`, so the result is not shown to be repeatable.

## Why you see it

The rerun failed, did not run, or its result was not recorded.

## What to do

Open the `poc_oracle` item and read its `rerun` field. Run the scan again with `--poc` and check that Docker works.

## Related

[poc_effect_no_control](poc_effect_no_control.md), [poc_differential](poc_differential.md).
