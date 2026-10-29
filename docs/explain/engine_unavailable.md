# engine_unavailable: A model or tool the scan needed could not be used

## What it means

Vettalon could not reach a configured engine, for example a model CLI that is not installed, a missing container image or an unreachable provider. On a module, it means the module was deferred after the finder failed. On the run, it means part of the work was never done. If no AI engine ran in a deep scan, the exit code is 4. With only some engines down, the exit code follows `--fail-on` and `--gate`.

## Why you see it

An engine failed its first call.

## What to do

Open `engines_missing` in the JSON report for the reason, fix it, and rerun. To exit on the gate result anyway, add `--allow-incomplete`.

## Related

[deferred](deferred.md), [llm_failed](llm_failed.md), [incomplete](incomplete.md).
