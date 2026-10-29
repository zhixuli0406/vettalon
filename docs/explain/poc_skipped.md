# poc_skipped: A PoC was attempted, but nothing ran in the sandbox

## What it means

The PoC step tried to test this finding and stopped before any real execution. The `detail` text says why. Typical reasons: the sandbox is unavailable (Docker not running or the image not pulled), the model call failed, the claim could not be demonstrated, the code excerpt could not be read, or the time budget ran out. A skipped PoC is not evidence for or against the finding.

## Why you see it

You used `--poc`.

## What to do

Read the detail. For a Docker problem, run `docker pull python:3.12-slim` and rescan with `--poc`. For a time problem, raise `--poc-budget`.

## Related

[no_poc](no_poc.md), [poc_transcript](poc_transcript.md).
