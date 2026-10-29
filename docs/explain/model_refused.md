# model_refused: A model declined to review part of the code

## What it means

At least one model refused a request. The module or finding it was asked about has no review from that model. Vettalon does not hand the work to another model on its own, and a refusal is never counted as a clean result or as a verdict.

## Why you see it

The model declined the request, for example because a provider filter blocked the prompt. The refusals are listed in `ensemble.refusals`, and the run is marked `incomplete`.

## What to do

Read each refusal excerpt. Then pick a different model for that role, for example `--finders` or `--verifiers`, and rescan, or review those parts by hand.

## Related

[incomplete](incomplete.md), [units_failed](units_failed.md).
