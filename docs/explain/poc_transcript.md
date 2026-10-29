# poc_transcript: A proof-of-concept script really ran in the sandbox

## What it means

The evidence holds the masked, size-limited output of a PoC that was executed in the Docker sandbox (no network, read-only filesystem). A transcript alone never raises the evidence level, because a script can print anything. Only a `poc_oracle` item, where the harness watched for the effect, does.

## Why you see it

You ran with `--poc` on an AI finding of High or above.

## What to do

Read the transcript with the oracle item next to it. If there is no oracle item, the finding's class has none, and the transcript only shows a pattern. Judge it by hand.

## Related

[poc_oracle](poc_oracle.md), [poc_not_harness_judged](poc_not_harness_judged.md).
