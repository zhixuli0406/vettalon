# no_poc: No PoC was run for this finding

## What it means

The evidence has neither a sandbox transcript nor a valid oracle record. A PoC that was attempted but skipped does not count as a run.

## Why you see it

PoCs only run with `--poc`, and only for AI findings of High or above that are in `needs_human`. Everything else shows this gap. A sandbox or model failure also leaves it.

## What to do

To get PoC evidence, run `vettalon scan . --profile deep --poc` (it needs Docker and the image pulled with `docker pull python:3.12-slim`). Otherwise reproduce the claim yourself in an isolated test environment.

## Related

[poc_skipped](poc_skipped.md), [poc_transcript](poc_transcript.md).
